"""Explicit configuration; no environment secrets or network calls at import time."""

from __future__ import annotations

import os
import math
import re
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
        from divalia.core.ingestion import FeedConfig

        for feed in feeds:
            if not isinstance(feed, dict) or not isinstance(feed.get("kind"), str):
                raise ValueError("each feed must be a table with a string kind")
            FeedConfig.from_dict(feed)
        _validate_ai(ai)
        interval = app.get("poll_seconds", 900)
        if type(interval) is not int or not 60 <= interval <= 86400:
            raise ValueError("poll_seconds must be between 60 and 86400")
        root = Path(os.path.expandvars(_path_value(app, "state_dir", "~/.divalia"))).expanduser()
        if not root.is_absolute():
            root = (path.parent if path else Path.cwd()) / root
        target = integration.get("data_dir")
        if target is not None:
            target = Path(os.path.expandvars(_path_value(integration, "data_dir"))).expanduser()
            if not target.is_absolute():
                target = (path.parent if path else Path.cwd()) / target
        image = sandbox.get("image", "")
        python = integration.get("python", "")
        if not isinstance(image, str) or len(image) > 512:
            raise ValueError("sandbox.image must be a string of at most 512 characters")
        if not isinstance(python, str) or len(python) > 4096 or "\x00" in python:
            raise ValueError("angerona.python must be a string path")
        return cls(
            state_dir=root.absolute(),
            feeds=tuple(feeds),
            ai=ai,
            sandbox_image=image,
            poll_seconds=interval,
            angerona_data_dir=target.absolute() if target is not None else None,
            angerona_python=python,
        )


def _path_value(table: dict[str, Any], name: str, default: str = "") -> str:
    value = table.get(name, default)
    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or "\x00" in value:
        raise ValueError(f"{name} must be a nonempty string path of at most 4096 characters")
    return value


def _validate_ai(ai: dict[str, Any]) -> None:
    """Reject malformed TOML before model routing or CLI processing can crash."""
    for role in ("light", "heavy"):
        if not isinstance(ai.get(role, {}), dict):
            raise ValueError(f"ai.{role} must be a table")
    for label, settings in [("ai", ai), ("ai.light", ai.get("light", {})),
                            ("ai.heavy", ai.get("heavy", {}))]:
        for key, limit in (("provider", 40), ("endpoint", 2048), ("light_model", 160),
                           ("heavy_model", 160), ("key_env", 128)):
            if key in settings and (
                not isinstance(settings[key], str) or len(settings[key]) > limit
            ):
                raise ValueError(f"{label}.{key} must be a string of at most {limit} characters")
        key_env = settings.get("key_env", "")
        if key_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key_env):
            raise ValueError(f"{label}.key_env must name an environment variable")
        if "allow_remote" in settings and type(settings["allow_remote"]) is not bool:
            raise ValueError(f"{label}.allow_remote must be a boolean")
        timeout = settings.get("timeout", 120)
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 1 <= timeout <= 600 or not math.isfinite(timeout)):
            raise ValueError(f"{label}.timeout must be a finite number in 1..600 seconds")
