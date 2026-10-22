"""Opt-in source download hook for external applications. Never executes code."""
from __future__ import annotations

import asyncio
import hashlib
import io
import os
import re
import shutil
import stat
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from divalia.storage import check_path

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXTRACTED_BYTES = 64 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("companion downloads may not redirect")


def extract_verified_archive(payload: bytes, destination: Path | str,
                             expected_sha256: str) -> Path:
    """Verify an operator-pinned hash, safely extract into a new destination.

    Reject symlinks, Windows device/alternate-stream paths, duplicate entries,
    absolute paths, path traversal, oversized archives and unexpected zip roots.
    """
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("a lowercase pinned archive SHA-256 is required")
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds 16 MiB")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("archive SHA-256 mismatch")
    destination = check_path(Path(destination))
    if destination.exists():
        raise FileExistsError("companion destination must be new")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".divalia-download-", dir=destination.parent))
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > 2000:
                raise ValueError("archive entry count is invalid")
            total, root, seen = 0, None, set()
            for entry in entries:
                name = entry.filename
                parts = PurePosixPath(name).parts
                if (not parts or name.startswith(("/", "\\")) or "\\" in name
                        or any(part.casefold() in {".", "..", ".git"} or ":" in part
                               or part.rstrip(". ") != part for part in parts)):
                    raise ValueError("unsafe archive member path")
                if any(re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)
                       for part in parts):
                    raise ValueError("Windows device path in archive")
                if root is None:
                    root = parts[0]
                if parts[0] != root or not root.startswith("Divalia-"):
                    raise ValueError("archive must contain one Divalia source root")
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                    raise ValueError("archive contains a special file")
                relative = parts[1:]
                if not relative:
                    if entry.is_dir():
                        continue
                    raise ValueError("invalid archive root entry")
                key = "/".join(relative).casefold()
                if key in seen:
                    raise ValueError("duplicate archive member")
                seen.add(key)
                total += entry.file_size
                if (total > MAX_EXTRACTED_BYTES or entry.file_size > 16 * 1024 * 1024
                        or entry.flag_bits & 1):
                    raise ValueError("archive is encrypted or exceeds extraction limits")
                target = check_path(temporary.joinpath(*relative))
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, target.open("xb") as output:
                    copied = 0
                    while chunk := source.read(64 * 1024):
                        copied += len(chunk)
                        if copied > entry.file_size:
                            raise ValueError("archive member exceeds declared size")
                        output.write(chunk)
            if not (temporary / "pyproject.toml").is_file():
                raise ValueError("archive does not contain a Python project")
        check_path(destination)
        if destination.exists():
            raise FileExistsError("destination appeared during download")
        os.rename(temporary, destination)
        return destination
    finally:
        # This path is an absolute, verified child created by mkdtemp above.
        checked = check_path(temporary)
        if checked.parent != destination.parent or not checked.name.startswith(".divalia-download-"):
            raise ValueError("unexpected temporary extraction path")
        if checked.exists():
            shutil.rmtree(checked)


async def download_companion(commit: str, expected_sha256: str,
                             destination: Path | str) -> Path:
    """Download exactly one pinned canonical GitHub source archive on demand."""
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("a full GitHub commit SHA is required")
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("a pinned archive SHA-256 is required")
    url = f"https://codeload.github.com/Ag3nt47/Divalia/zip/{commit}"

    def fetch() -> Path:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        request = urllib.request.Request(url, headers={"User-Agent": "Divalia-optional-installer/2.0"})
        with opener.open(request, timeout=30) as response:
            payload = response.read(MAX_ARCHIVE_BYTES + 1)
        return extract_verified_archive(payload, destination, expected_sha256)

    return await asyncio.to_thread(fetch)
