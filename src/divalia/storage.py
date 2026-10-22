"""Confined atomic artifact storage and append-only operator audit events."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,79}$")


def check_path(path: Path) -> Path:
    """Reject symlinks and Windows junctions, including parent components."""
    path = path.absolute()
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            details = part.lstat()
            if part.is_symlink() or getattr(details, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ):
                raise ValueError(f"redirected artifact path: {part}")
    return path


def atomic_write(path: Path, payload: bytes) -> None:
    check_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    check_path(path)
    handle, filename = tempfile.mkstemp(prefix=".divalia-", dir=path.parent)
    temp = Path(filename)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        check_path(path)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(source: str) -> str:
    return hashlib.sha256(source.encode()).hexdigest()


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = check_path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, category: str, identifier: str) -> Path:
        if not IDENTIFIER.fullmatch(category) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError("invalid artifact identifier")
        return check_path(self.root / category / f"{identifier}.json")

    def save(self, category: str, identifier: str, value: dict[str, Any]) -> None:
        payload = canonical(value)
        if len(payload) > 2 * 1024 * 1024:
            raise ValueError("artifact exceeds 2 MiB")
        atomic_write(self.path(category, identifier), payload)

    def load(self, category: str, identifier: str) -> dict[str, Any]:
        path = self.path(category, identifier)
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("artifact exceeds 2 MiB")
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError("artifact must be an object")
        return value

    def list(self, category: str) -> list[dict[str, Any]]:
        if not IDENTIFIER.fullmatch(category):
            raise ValueError("invalid artifact category")
        directory = check_path(self.root / category)
        return [self.load(category, p.stem) for p in sorted(directory.glob("*.json"))]

    def audit(self, action: str, **details: Any) -> None:
        event = {"time": datetime.now(timezone.utc).isoformat(), "action": action, **details}
        path = check_path(self.root / "audit.jsonl")
        with path.open("ab") as stream:
            stream.write(canonical(event) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
