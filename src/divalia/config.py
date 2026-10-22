"""Explicit configuration; no environment secrets or network calls at import time."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Config:
    state_dir: Path = field(default_factory=lambda: Path.home() / ".divalia")
    feeds: tuple[dict[str, Any], ...] = ()
    ai: dict[str, Any] = field(default_factory=dict)
    sandbox_image: str = ""
    poll_seconds: int = 900
    angerona_data_dir: Path | None = None
    angerona_python: str = ""

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        data: dict[str, Any] = {}
        if path is not None:
            if path.stat().st_size > 256 * 1024:
                raise ValueError("configuration exceeds 256 KiB")
            with path.open("rb") as stream:
                data = tomllib.load(stream)
        app = data.get("app", {})
        ai = data.get("ai", {})
        sandbox = data.get("sandbox", {})
        integration = data.get("angerona", {})
        feeds = data.get("feeds", [])
        if not all(isinstance(x, dict) for x in (app, ai, sandbox, integration)):
            raise ValueError("configuration sections must be tables")
        if not isinstance(feeds, list) or len(feeds) > 64:
            raise ValueError("feeds must be an array of at most 64 tables")
        interval = app.get("poll_seconds", 900)
        if type(interval) is not int or not 60 <= interval <= 86400:
            raise ValueError("poll_seconds must be between 60 and 86400")
        root = Path(os.path.expandvars(str(app.get("state_dir", "~/.divalia")))).expanduser()
        if not root.is_absolute():
            root = (path.parent if path else Path.cwd()) / root
        target = integration.get("data_dir")
        return cls(
            state_dir=root.absolute(),
            feeds=tuple(feeds),
            ai=ai,
            sandbox_image=str(sandbox.get("image", "")),
            poll_seconds=interval,
            angerona_data_dir=Path(target).expanduser().absolute() if target else None,
            angerona_python=str(integration.get("python", "")),
        )
