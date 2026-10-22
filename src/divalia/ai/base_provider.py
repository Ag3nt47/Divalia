"""Unified asynchronous inference interface with an explicit privacy boundary."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    pass


class BaseProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str, *, system: str = "", role: str = "heavy") -> str:
        """Return bounded text. Never execute model output or follow its tool requests."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError("inference endpoint redirects are forbidden")


def validate_endpoint(url: str, *, remote: bool = False) -> str:
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("inference endpoint must not contain credentials/query/fragment")
    if not parsed.hostname or parsed.scheme not in {"https", "http"}:
        raise ValueError("inference endpoint must be HTTP(S)")
    if remote:
        if parsed.scheme != "https":
            raise ValueError("remote inference requires HTTPS")
    else:
        # Literal loopback avoids DNS rebinding and accidental LAN/cloud disclosure.
        try:
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = False
        if not local:
            raise ValueError("local inference requires literal 127.0.0.1 or ::1")
    return url.rstrip("/")


class HTTPProvider(BaseProvider):
    def __init__(
        self,
        endpoint: str,
        *,
        light_model: str,
        heavy_model: str,
        allow_remote: bool = False,
        key_env: str = "",
        timeout: float = 120,
    ) -> None:
        self.endpoint = validate_endpoint(endpoint, remote=allow_remote)
        self.light_model = light_model
        self.heavy_model = heavy_model
        if not light_model or not heavy_model:
            raise ValueError("both light_model and heavy_model must be configured")
        if not 1 <= timeout <= 600:
            raise ValueError("inference timeout must be 1..600 seconds")
        self.timeout = timeout
        self.key_env = key_env
        self.allow_remote = allow_remote
        self._semaphore = asyncio.Semaphore(1)

    def _request_sync(
        self,
        path: str,
        payload: dict[str, Any] | None,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        body = json.dumps(payload, allow_nan=False).encode() if payload is not None else None
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        if self.key_env and "x-goog-api-key" not in request_headers:
            secret = os.environ.get(self.key_env)
            if not secret:
                raise ProviderError(
                    f"required credential environment variable missing: {self.key_env}"
                )
            request_headers.setdefault("Authorization", f"Bearer {secret}")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        req = urllib.request.Request(self.endpoint + path, data=body, headers=request_headers)
        try:
            with opener.open(req, timeout=timeout or self.timeout) as response:
                content = response.read(1024 * 1024 + 1)
                if len(content) > 1024 * 1024:
                    raise ProviderError("inference response exceeds 1 MiB")
            return json.loads(content)
        except urllib.error.HTTPError as exc:
            # Do not echo server bodies, URLs, prompts, headers, or secrets.
            raise ProviderError(f"inference request failed (HTTP {exc.code})") from None
        except (OSError, ValueError) as exc:
            raise ProviderError(f"inference transport/JSON failure: {type(exc).__name__}") from None

    async def request(self, path: str, payload: dict[str, Any] | None) -> Any:
        async with self._semaphore:
            return await asyncio.to_thread(self._request_sync, path, payload)

    def model(self, role: str) -> str:
        if role not in {"light", "heavy"}:
            raise ValueError("model role must be light or heavy")
        return self.light_model if role == "light" else self.heavy_model


class CompatibleProvider(HTTPProvider):
    """LM Studio, llama.cpp and explicitly enabled compatible custom endpoints."""

    async def generate(self, prompt: str, *, system: str = "", role: str = "heavy") -> str:
        if len(prompt) > 100_000 or len(system) > 20_000:
            raise ProviderError("inference input exceeds limit")
        value = await self.request(
            "/chat/completions",
            {
                "model": self.model(role),
                "stream": False,
                "temperature": 0,
                "max_tokens": 4096,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        try:
            output = value["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ProviderError("compatible endpoint returned an invalid response") from None
        if not isinstance(output, str) or len(output) > 100_000:
            raise ProviderError("compatible endpoint returned invalid/oversized text")
        return output


def create_provider(config: dict[str, Any]) -> BaseProvider:
    from divalia.ai.ollama_provider import OllamaProvider

    kind = config.get("provider", "ollama")
    kwargs = {
        "light_model": str(config.get("light_model", "")),
        "heavy_model": str(config.get("heavy_model", "")),
        "allow_remote": config.get("allow_remote", False) is True,
        "key_env": str(config.get("key_env", "")),
        "timeout": float(config.get("timeout", 120)),
    }
    if kind == "ollama":
        return OllamaProvider(str(config.get("endpoint", "http://127.0.0.1:11434")), **kwargs)
    if kind in {"lmstudio", "llamacpp", "compatible"}:
        return CompatibleProvider(str(config.get("endpoint", "http://127.0.0.1:1234/v1")), **kwargs)
    if kind in {"openai", "anthropic", "gemini"}:
        from divalia.ai.remote_provider import RemoteProvider

        return RemoteProvider(kind, **kwargs)
    raise ValueError(f"unsupported provider: {kind}; use an installed BaseProvider adapter")
