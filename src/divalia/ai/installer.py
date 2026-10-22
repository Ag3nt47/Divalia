"""Opt-in runtime setup. Never execute downloaded scripts or silently install engines."""

from __future__ import annotations

import asyncio
import hashlib
import platform
import shutil
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from divalia.ai.base_provider import ProviderError, _NoRedirect
from divalia.ai.ollama_provider import OllamaProvider
from divalia.storage import atomic_write


async def check_runtime(
    provider: OllamaProvider, *, roles: tuple[str, ...] = ("light", "heavy")
) -> dict[str, Any]:
    required = {role: provider.model(role) for role in roles}
    try:
        # Readiness probes should finish promptly even if inference is allowed
        # several minutes. Native async transport closes the socket on timeout.
        async with asyncio.timeout(5):
            status = await provider.status()
        models = [row["name"] for row in status["models"]
                  if isinstance(row, dict) and isinstance(row.get("name"), str)]
        missing = [model for model in dict.fromkeys(required.values())
                   if model not in models and f"{model}:latest" not in models]
        result = {
            "ready": not missing,
            "engine_ready": True,
            "executable_present": shutil.which("ollama") is not None,
            "models": models,
            "configured_models": required,
            "missing_models": missing,
        }
        if missing:
            result["message"] = (
                "Configured models are missing; run `divalia runtime --pull MODEL --consent` "
                "for each missing model, or select an installed model in your configuration."
            )
        return result
    except (ProviderError, TimeoutError):
        return {
            "ready": False,
            "engine_ready": False,
            "executable_present": shutil.which("ollama") is not None,
            "models": [],
            "configured_models": required,
            "missing_models": list(dict.fromkeys(required.values())),
            "download_page": "https://ollama.com/download",
            "platform": platform.system(),
            "message": "Install/start Ollama or verify its endpoint; health checks wait at most 5s.",
        }


def download_runtime(url: str, destination: Path, expected_sha256: str, *, consent: bool) -> Path:
    """Download a maintainer-selected, digest-pinned installer; operator launches it separately."""
    if not consent:
        raise PermissionError("runtime download requires explicit consent")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "ollama.com"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("runtime download must use a literal official ollama.com HTTPS URL")
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
        raise ValueError("runtime installer requires a SHA-256 digest")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    # Redirected vendor/CDN locations require separate explicit vetting; fail closed.
    with opener.open(url, timeout=60) as response:
        payload = response.read(256 * 1024 * 1024 + 1)
    if len(payload) > 256 * 1024 * 1024:
        raise ValueError("installer exceeds 256 MiB; download manually from official site")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("runtime installer digest mismatch")
    atomic_write(destination, payload)
    return destination
