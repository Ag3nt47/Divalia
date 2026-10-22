"""Opt-in runtime setup. Never execute downloaded scripts or silently install engines."""

from __future__ import annotations

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


async def check_runtime(provider: OllamaProvider) -> dict[str, Any]:
    try:
        status = await provider.status()
        return {
            "ready": True,
            "executable_present": shutil.which("ollama") is not None,
            "models": [
                str(row.get("name", "")) for row in status["models"] if isinstance(row, dict)
            ],
        }
    except ProviderError:
        return {
            "ready": False,
            "executable_present": shutil.which("ollama") is not None,
            "models": [],
            "download_page": "https://ollama.com/download",
            "platform": platform.system(),
            "message": "Install/start Ollama or select another provider.",
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
