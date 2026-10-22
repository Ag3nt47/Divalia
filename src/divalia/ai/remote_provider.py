"""Optional remote providers. Keys are read only when the operator requests inference."""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any

from divalia.ai.base_provider import HTTPProvider, ProviderError


class RemoteProvider(HTTPProvider):
    ENDPOINTS = {
        "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
        "anthropic": ("https://api.anthropic.com/v1", "ANTHROPIC_API_KEY"),
        "gemini": ("https://generativelanguage.googleapis.com/v1beta", "GEMINI_API_KEY"),
    }

    def __init__(self, kind: str, **kwargs: Any) -> None:
        if kwargs.get("allow_remote") is not True:
            raise PermissionError("remote providers require allow_remote = true")
        endpoint, env = self.ENDPOINTS[kind]
        kwargs["key_env"] = kwargs.get("key_env") or env
        super().__init__(endpoint, **kwargs)
        self.kind = kind

    async def generate(self, prompt: str, *, system: str = "", role: str = "heavy") -> str:
        if len(prompt) > 100_000 or len(system) > 20_000:
            raise ProviderError("inference input exceeds limit")
        model = self.model(role)
        if not re.fullmatch(r"[a-zA-Z0-9_.:/-]{1,160}", model):
            raise ValueError("invalid remote model identifier")
        headers: dict[str, str] = {}
        if self.kind == "openai":
            path = "/chat/completions"
            payload = {
                "model": model,
                "stream": False,
                "store": False,
                "max_completion_tokens": 4096,
                "messages": [
                    {"role": "developer", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
        elif self.kind == "anthropic":
            path = "/messages"
            headers = {"anthropic-version": "2023-06-01"}
            payload = {
                "model": model,
                "max_tokens": 4096,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }
        else:
            if "/" in model or ":" in model:
                raise ValueError("Gemini model must be a plain model identifier")
            path = f"/models/{model}:generateContent"
            secret = os.environ.get(self.key_env)
            if not secret:
                raise ProviderError(
                    f"required credential environment variable missing: {self.key_env}"
                )
            headers = {"x-goog-api-key": secret}
            payload = {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "maxOutputTokens": 4096,
                    "responseMimeType": "application/json",
                },
            }
        async with self._semaphore:
            value = await asyncio.to_thread(self._request_sync, path, payload, headers=headers)
        try:
            if self.kind == "openai":
                output = value["choices"][0]["message"]["content"]
            elif self.kind == "anthropic":
                output = "".join(
                    part["text"] for part in value["content"] if part.get("type") == "text"
                )
            else:
                output = "".join(
                    part["text"]
                    for part in value["candidates"][0]["content"]["parts"]
                    if "text" in part
                )
        except (KeyError, IndexError, TypeError, AttributeError):
            raise ProviderError(f"{self.kind} returned an invalid response") from None
        if not isinstance(output, str) or not output or len(output) > 100_000:
            raise ProviderError("remote provider returned invalid/oversized text")
        return output
