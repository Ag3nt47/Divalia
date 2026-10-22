"""Unified asynchronous inference interface with an explicit privacy boundary."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import math
import os
import re
import ssl
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
    if (
        not isinstance(url, str)
        or len(url) > 2048
        or not url.isascii()
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url)
    ):
        raise ValueError("inference endpoint must be a bounded ASCII HTTP(S) URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ValueError("inference endpoint has an invalid host or port") from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("inference endpoint has an invalid port")
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
        if type(allow_remote) is not bool:
            raise ValueError("allow_remote must be a boolean")
        self.endpoint = validate_endpoint(endpoint, remote=allow_remote)
        self.light_model = light_model
        self.heavy_model = heavy_model
        for model in (light_model, heavy_model):
            if (
                not isinstance(model, str)
                or not 1 <= len(model) <= 160
                or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in model)
            ):
                raise ValueError("both model names must contain 1..160 non-whitespace characters")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 1 <= timeout <= 600
            or not math.isfinite(timeout)
        ):
            raise ValueError("inference timeout must be 1..600 seconds")
        if not isinstance(key_env, str) or (
            key_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key_env)
        ):
            raise ValueError("key_env must name an environment variable")
        self.timeout = timeout
        self.key_env = key_env
        self.allow_remote = allow_remote
        self._semaphore = asyncio.Semaphore(1)

    async def _request_async(
        self,
        path: str,
        payload: dict[str, Any] | None,
        *,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """One HTTP/1.1 exchange; caller bounds the entire operation, including reads.

        Native async sockets let cancellation close the connection immediately. A
        canceled blocking worker would otherwise outlive the semaphore and permit
        accumulating requests; socket inactivity timeouts also do not bound drips.
        """
        body = json.dumps(payload, allow_nan=False).encode() if payload is not None else None
        request_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
            **(headers or {}),
        }
        if self.key_env and not ({"x-goog-api-key", "x-api-key"} & request_headers.keys()):
            secret = os.environ.get(self.key_env)
            if not secret:
                raise ProviderError(
                    f"required credential environment variable missing: {self.key_env}"
                )
            request_headers.setdefault("Authorization", f"Bearer {secret}")
        endpoint = urlsplit(self.endpoint)
        host = endpoint.hostname
        assert host is not None  # Construction validated the endpoint.
        port = endpoint.port or (443 if endpoint.scheme == "https" else 80)
        request_headers["Host"] = endpoint.netloc
        if body is not None:
            request_headers["Content-Length"] = str(len(body))
        # Internal paths and environment credentials must never inject HTTP headers.
        target = endpoint.path + path
        if (
            not target.startswith("/")
            or not target.isascii()
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in target)
            or any(
                any(ord(char) < 32 or ord(char) > 255 or ord(char) == 127 for char in value)
                for value in request_headers.values()
            )
        ):
            raise ProviderError("invalid inference request path or credential header")
        message = (
            f"{'POST' if body is not None else 'GET'} {target} HTTP/1.1\r\n"
            + "".join(f"{name}: {value}\r\n" for name, value in request_headers.items())
            + "\r\n"
        ).encode("latin-1") + (body or b"")
        tls = ssl.create_default_context() if endpoint.scheme == "https" else None
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.open_connection(
                host, port, ssl=tls, limit=65536,
                **({"server_hostname": host} if tls else {}),
            )
            writer.write(message)
            await writer.drain()
            raw_headers = await reader.readuntil(b"\r\n\r\n")
            if len(raw_headers) > 16384:
                raise ProviderError("inference response headers exceed 16 KiB")
            lines = raw_headers[:-4].split(b"\r\n")
            status = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?", lines[0])
            if status is None:
                raise ProviderError("inference endpoint returned invalid HTTP status")
            code = int(status[1])
            if not 200 <= code < 300:
                # Never follow redirects or echo server bodies, headers, or URLs.
                raise ProviderError(f"inference request failed (HTTP {code})")
            response_headers: dict[bytes, bytes] = {}
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                name = name.lower()
                if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9a-z-]+", name):
                    raise ProviderError("inference endpoint returned invalid HTTP headers")
                if name in {b"content-length", b"transfer-encoding"} and name in response_headers:
                    raise ProviderError("inference endpoint returned ambiguous HTTP framing")
                response_headers[name] = value.strip()
            content = await self._read_body(reader, response_headers)
            return json.loads(content, parse_constant=_reject_json_constant)
        except (OSError, ValueError, RecursionError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError) as exc:
            raise ProviderError(f"inference transport/JSON failure: {type(exc).__name__}") from None
        finally:
            if writer is not None:
                writer.close()

    @staticmethod
    async def _read_body(reader: asyncio.StreamReader, headers: dict[bytes, bytes]) -> bytes:
        limit = 1024 * 1024
        encoding = headers.get(b"transfer-encoding")
        length = headers.get(b"content-length")
        if encoding is not None:
            if encoding.lower() != b"chunked" or length is not None:
                raise ProviderError("inference endpoint returned unsupported HTTP framing")
            content = bytearray()
            while True:
                line = await reader.readuntil(b"\r\n")
                size = line[:-2].partition(b";")[0]
                if len(line) > 4096 or not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", size):
                    raise ProviderError("inference endpoint returned invalid HTTP chunk")
                count = int(size, 16)
                if len(content) + count > limit:
                    raise ProviderError("inference response exceeds 1 MiB")
                if count == 0:
                    trailers = 0
                    while True:
                        line = await reader.readuntil(b"\r\n")
                        trailers += len(line)
                        if trailers > 16384:
                            raise ProviderError("inference response trailers exceed 16 KiB")
                        if line == b"\r\n":
                            return bytes(content)
                content.extend(await reader.readexactly(count))
                if await reader.readexactly(2) != b"\r\n":
                    raise ProviderError("inference endpoint returned invalid HTTP chunk")
        if length is not None:
            if not re.fullmatch(rb"[0-9]{1,16}", length):
                raise ProviderError("inference endpoint returned invalid content length")
            count = int(length)
            if count > limit:
                raise ProviderError("inference response exceeds 1 MiB")
            return await reader.readexactly(count)
        content = bytearray()
        while chunk := await reader.read(min(65536, limit + 1 - len(content))):
            content.extend(chunk)
            if len(content) > limit:
                raise ProviderError("inference response exceeds 1 MiB")
        return bytes(content)

    async def request(
        self, path: str, payload: dict[str, Any] | None, *,
        headers: dict[str, str] | None = None,
    ) -> Any:
        try:
            async with asyncio.timeout(self.timeout):
                async with self._semaphore:
                    return await self._request_async(path, payload, headers=headers)
        except TimeoutError:
            raise ProviderError("inference request exceeded configured timeout") from None

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
                "max_tokens": 256 if role == "light" else 4096,
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
        if not isinstance(output, str) or not output or len(output) > 100_000:
            raise ProviderError("compatible endpoint returned invalid/oversized text")
        return output


def create_provider(config: dict[str, Any]) -> BaseProvider:
    from divalia.ai.ollama_provider import OllamaProvider

    if not isinstance(config, dict):
        raise ValueError("AI configuration must be a table")
    kind = config.get("provider", "ollama")
    if not isinstance(kind, str):
        raise ValueError("AI provider must be a string")
    timeout = config.get("timeout", 120)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("inference timeout must be 1..600 seconds")
    kwargs = {
        "light_model": config.get("light_model", ""),
        "heavy_model": config.get("heavy_model", ""),
        "allow_remote": config.get("allow_remote", False) is True,
        "key_env": config.get("key_env", ""),
        "timeout": timeout,
    }
    if kind == "ollama":
        return OllamaProvider(config.get("endpoint", "http://127.0.0.1:11434"), **kwargs)
    if kind in {"lmstudio", "llamacpp", "compatible"}:
        return CompatibleProvider(config.get("endpoint", "http://127.0.0.1:1234/v1"), **kwargs)
    if kind in {"openai", "anthropic", "gemini"}:
        from divalia.ai.remote_provider import RemoteProvider

        return RemoteProvider(kind, **kwargs)
    raise ValueError(f"unsupported provider: {kind}; use an installed BaseProvider adapter")


def _reject_json_constant(value: str) -> None:
    raise ValueError("non-finite JSON constant")
