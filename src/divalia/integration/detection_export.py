"""Portable, declarative Angerona DetectionForge package export.

Implements a deliberately narrower subset of Angerona's schema version 1.
Angerona must independently import, trust, evaluate and promote every package.
No native module or activation state is written by this exporter.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from divalia.storage import atomic_write, check_path

_TOP = {"schema_version", "id", "version", "owner", "description", "telemetry", "attack",
        "severity", "confidence", "logic", "fixtures", "performance", "rollback", "expires_at", "digest"}
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,79}$")
_SELECTOR = re.compile(r"^[a-z][a-z0-9_-]{0,79}$")
_FIELD = re.compile(r"^[A-Za-z0-9_.-]{1,80}(?:\|(contains|startswith|endswith))?$")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _text(value: Any, name: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} must be a non-empty bounded string")
    return value


def _scalar(value: Any) -> None:
    if not isinstance(value, (str, int, float, bool, type(None))):
        raise ValueError("events may contain only scalar values")
    if isinstance(value, str) and len(value) > 4096:
        raise ValueError("scalar string exceeds 4096 characters")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("scalar must be finite")


def _condition(condition: str, selections: dict[str, Any]) -> tuple[str, str | None]:
    """Validate only grammar supported by both package and Sigma admissions."""
    if condition != condition.strip().lower() or len(condition) > 512:
        raise ValueError("condition must be normalized lowercase")
    if condition.count(" and not ") > 1:
        raise ValueError("at most one trailing negation is supported")
    base, sep, negated = condition.partition(" and not ")
    if sep:
        # Current Angerona package validation has a narrower condition parser
        # than its matcher. Refuse negation to satisfy both admission layers.
        raise ValueError("negation is outside the portable package export subset")
    if base in {"all of them", "1 of them", "any of them"}:
        # Angerona's package schema admits these only without a negated suffix.
        if sep:
            raise ValueError("quantifiers with negation are not exportable")
        return base, None
    if " and " in base and " or " in base:
        raise ValueError("mixed conjunction/disjunction is unsupported")
    tokens = base.split(" and " if " and " in base else " or " if " or " in base else "\0")
    if any(token not in selections for token in tokens):
        raise ValueError("condition references unknown or unsupported selectors")
    return base, negated if sep else None


def _matches(detection: dict[str, Any], event: dict[str, Any]) -> bool:
    fields = {"module": "", "message": "", "severity": "", **event}
    # DetectionPackage._event wraps severity in a name namespace using str().
    # In particular explicit JSON null becomes "None", while missing stays "".
    fields["severity"] = str(event.get("severity", ""))

    def selection_matches(selection: Any) -> bool:
        if isinstance(selection, list):
            return any(selection_matches(branch) for branch in selection)
        for field, expected in selection.items():
            name, _, modifier = field.partition("|")
            actual = "" if fields.get(name) is None else str(fields.get(name))
            choices = expected if isinstance(expected, list) else [expected]

            def value_matches(value: Any) -> bool:
                value = str(value)
                left, right = actual.lower(), value.lower()
                if modifier == "contains":
                    return right in left
                if modifier == "startswith":
                    return left.startswith(right)
                if modifier == "endswith":
                    return left.endswith(right)
                return left == right

            if not any(value_matches(value) for value in choices):
                return False
        return True

    selections = {key: value for key, value in detection.items() if key != "condition"}
    base, negated = _condition(detection["condition"], selections)
    result = {key: selection_matches(value) for key, value in selections.items()}
    if base == "all of them":
        matched = all(result.values())
    elif base in {"1 of them", "any of them"}:
        matched = any(result.values())
    elif " and " in base:
        matched = all(result[name] for name in base.split(" and "))
    elif " or " in base:
        matched = any(result[name] for name in base.split(" or "))
    else:
        matched = result[base]
    return matched and (not result[negated] if negated else True)


def validate_detection(document: dict[str, Any]) -> dict[str, Any]:
    """Validate schema, integrity, expiry, benign fixtures and local timing budget.

    No claim of full Sigma compatibility is made. Regex, wildcards, floats/null
    in selections, uppercase selectors and quantifier negations are refused.
    """
    if not isinstance(document, dict) or set(document) != _TOP:
        raise ValueError("package must contain exactly the Angerona schema v1 fields")
    if len(_canonical(document)) > 256 * 1024:
        raise ValueError("package exceeds 256 KiB")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("unsupported schema_version")
    if not _ID.fullmatch(_text(document["id"], "id", 80)):
        raise ValueError("invalid package id")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?", _text(document["version"], "version", 80)):
        raise ValueError("invalid semantic version")
    _text(document["owner"], "owner", 160)
    _text(document["description"], "description")
    if document["severity"] not in {"informational", "low", "medium", "high", "critical"}:
        raise ValueError("invalid severity")
    if type(document["confidence"]) is not int or not 0 <= document["confidence"] <= 100:
        raise ValueError("confidence must be an integer from 0 through 100")
    for name, pattern in (("telemetry", _ID), ("attack", re.compile(r"^T\d{4}(?:\.\d{3})?$"))):
        values = document[name]
        if (not isinstance(values, list) or not 1 <= len(values) <= 32
                or any(not isinstance(value, str) or not pattern.fullmatch(value) for value in values)):
            raise ValueError(f"invalid {name}")
    logic = document["logic"]
    if (not isinstance(logic, dict) or set(logic) != {"type", "detection"}
            or logic["type"] != "sigma-subset" or not isinstance(logic["detection"], dict)):
        raise ValueError("logic must be a sigma-subset detection")
    detection = logic["detection"]
    selections = {key: value for key, value in detection.items() if key != "condition"}
    if not 1 <= len(selections) <= 32:
        raise ValueError("invalid selection count")
    for name, selection in selections.items():
        if not isinstance(name, str) or not _SELECTOR.fullmatch(name):
            raise ValueError("selector must be a lowercase simple identifier")
        branches = selection if isinstance(selection, list) else [selection]
        if not 1 <= len(branches) <= 32:
            raise ValueError("invalid selection branch count")
        for branch in branches:
            if not isinstance(branch, dict) or not 1 <= len(branch) <= 24:
                raise ValueError("selection must contain a bounded field map")
            for field, expected in branch.items():
                if not isinstance(field, str) or not _FIELD.fullmatch(field):
                    raise ValueError("invalid field modifier")
                choices = expected if isinstance(expected, list) else [expected]
                if not 1 <= len(choices) <= 32:
                    raise ValueError("invalid selection value count")
                for value in choices:
                    if type(value) not in (str, int, bool):
                        raise ValueError("selection values must be strings, integers or booleans")
                    if isinstance(value, str):
                        if not value or len(value) > 4096:
                            raise ValueError("selection string must be non-empty and bounded")
                        if "|" not in field and any(char in value for char in "*?"):
                            raise ValueError("wildcards are unsupported")
    _condition(_text(detection.get("condition"), "condition", 512), selections)
    performance = document["performance"]
    if not isinstance(performance, dict) or set(performance) != {"max_eval_ms", "max_events_per_second"}:
        raise ValueError("invalid performance fields")
    if (type(performance["max_eval_ms"]) not in (int, float)
            or not 0.05 <= performance["max_eval_ms"] <= 1000
            or type(performance["max_events_per_second"]) is not int
            or not 1 <= performance["max_events_per_second"] <= 1_000_000):
        raise ValueError("invalid performance limits")
    rollback = document["rollback"]
    if not isinstance(rollback, dict) or set(rollback) != {"previous_digest", "instructions"}:
        raise ValueError("invalid rollback fields")
    if rollback["previous_digest"] is not None and (
            not isinstance(rollback["previous_digest"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", rollback["previous_digest"])):
        raise ValueError("invalid previous_digest")
    _text(rollback["instructions"], "rollback.instructions", 1000)
    expires = datetime.fromisoformat(_text(document["expires_at"], "expires_at", 40).replace("Z", "+00:00"))
    if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
        raise ValueError("package expiry must be a future timestamp with timezone")
    unsigned = {key: value for key, value in document.items() if key != "digest"}
    expected = "sha256:" + hashlib.sha256(_canonical(unsigned)).hexdigest()
    if document["digest"] != expected:
        raise ValueError("package digest verification failed")
    fixtures = document["fixtures"]
    if not isinstance(fixtures, list) or not 1 <= len(fixtures) <= 64:
        raise ValueError("package needs 1-64 fixtures")
    expected_results: list[bool] = []
    for fixture in fixtures:
        if not isinstance(fixture, dict) or set(fixture) != {"name", "event", "expected_match"}:
            raise ValueError("invalid fixture fields")
        _text(fixture["name"], "fixture.name", 160)
        event = fixture["event"]
        if not isinstance(event, dict) or len(event) > 128:
            raise ValueError("invalid fixture event")
        for field, value in event.items():
            if not isinstance(field, str) or not _FIELD.fullmatch(field):
                raise ValueError("invalid fixture event field")
            _scalar(value)
        if type(fixture["expected_match"]) is not bool:
            raise ValueError("expected_match must be boolean")
        expected_results.append(fixture["expected_match"])
    if set(expected_results) != {True, False}:
        raise ValueError("export requires both matching and non-matching fixtures")
    started = time.perf_counter()
    for fixture in fixtures:
        if _matches(detection, fixture["event"]) is not fixture["expected_match"]:
            raise ValueError(f"fixture failed: {fixture['name']}")
    if (time.perf_counter() - started) * 1000 / len(fixtures) > performance["max_eval_ms"]:
        raise ValueError("local fixture evaluation exceeded performance budget")
    return document


def export_detection(document: dict[str, Any], destination: Path | str,
                     private_key_path: Path | str | None = None, key_id: str = "") -> dict[str, Any]:
    """Seal and export JSON plus optional ``<name>.sig.json`` exact-byte signature.

    The private key is an unencrypted PKCS8 Ed25519 PEM file. Publisher trust
    enrollment and Angerona's promotion gates remain explicit operator actions.
    """
    sealed = json.loads(_canonical(document))
    sealed.pop("digest", None)
    sealed["digest"] = "sha256:" + hashlib.sha256(_canonical(sealed)).hexdigest()
    validate_detection(sealed)
    payload = _canonical(sealed) + b"\n"
    destination = check_path(Path(destination))
    signature_path = destination.with_suffix(".sig.json")
    signature: bytes | None = None
    if private_key_path is not None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", key_id):
            raise ValueError("a bounded signing key_id is required")
        key_path = check_path(Path(private_key_path))
        if not key_path.is_file() or key_path.stat().st_size > 16 * 1024:
            raise ValueError("invalid private key file")
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("signing key must be Ed25519")
        signature = _canonical({"key_id": key_id,
                                "signature": base64.b64encode(key.sign(payload)).decode()})
    # Refuse replacing existing outputs so a stale detached signature cannot survive.
    if destination.exists() or check_path(signature_path).exists():
        raise FileExistsError("export destination or detached signature already exists")
    atomic_write(destination, payload)
    if signature is not None:
        atomic_write(signature_path, signature + b"\n")
    return {"path": str(destination), "digest": sealed["digest"],
            "signature_path": str(signature_path) if signature is not None else None,
            "signed": signature is not None, "activation": "requires Angerona human import and promotion"}
