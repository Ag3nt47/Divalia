"""Explicit approvals and atomic versions for Divalia's isolated plugin runtime.

No Python source is imported by this process or installed as an Angerona native
module. Angerona integration uses separately reviewed declarative packages.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from divalia.harness.ast_validator import validate_source
from divalia.harness.sandbox import SandboxRunner, normalize_telemetry, test_fingerprint
from divalia.storage import ArtifactStore, IDENTIFIER, atomic_write, canonical, check_path, digest


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _copy(value: dict[str, Any]) -> dict[str, Any]:
    raw = canonical(value)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("candidate exceeds 2 MiB")
    return json.loads(raw)


def _telemetry_digest(events: list[dict[str, Any]]) -> str:
    raw = json.dumps(events, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


class Publisher:
    """Own reviewed plugin state. Local state administrators remain trusted.

    The filesystem lock is fail-closed and never automatically broken: after a
    crash an operator must verify no Divalia writer is running before removing
    ``publisher.lock``. Local filesystem atomic rename is required.
    """

    def __init__(self, state_dir: Path | str, sandbox_image: str = "", *,
                 probation_seconds: float = 60, probation_events: int = 3) -> None:
        if not 0 <= probation_seconds <= 86400 or not 1 <= probation_events <= 1000:
            raise ValueError("invalid probation window")
        self.store = ArtifactStore(Path(state_dir))
        self.root = self.store.root
        self.sandbox_image = sandbox_image
        self.probation_seconds = probation_seconds
        self.probation_events = probation_events
        self.runner = SandboxRunner(image=sandbox_image or None)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        path = check_path(self.root / "publisher.lock")
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise RuntimeError("publisher is busy; a stale lock requires operator recovery") from exc
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(str(os.getpid()).encode())
            yield
        finally:
            check_path(path).unlink()

    def _key(self) -> bytes:
        path = check_path(self.root / "approval.key")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
        check_path(path)
        if path.stat().st_size != 32:
            raise ValueError("approval key is invalid")
        return path.read_bytes()

    @staticmethod
    def _validate(candidate: dict[str, Any]) -> tuple[str, str]:
        identifier = candidate.get("id")
        source = candidate.get("source")
        events = candidate.get("telemetry")
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError("invalid candidate id")
        if not isinstance(source, str) or not source or len(source.encode()) > 128 * 1024:
            raise ValueError("invalid source")
        if (not isinstance(events, list) or not events or len(events) > 32
                or any(not isinstance(event, dict) for event in events)):
            raise ValueError("candidate requires 1-32 telemetry objects")
        expectations = candidate.get("expected_matches")
        if (not isinstance(expectations, list) or len(expectations) != len(events)
                or any(type(value) is not bool for value in expectations)
                or set(expectations) != {True, False}):
            raise ValueError("candidate requires matching and non-matching boolean fixture expectations")
        actual = digest(source)
        audit = candidate.get("audit")
        sandbox = candidate.get("sandbox")
        if (not isinstance(audit, dict) or audit.get("passed") is not True
                or audit.get("source_sha256") != actual):
            raise ValueError("candidate lacks a passing source-bound AST audit")
        if (not isinstance(sandbox, dict) or sandbox.get("passed") is not True
                or sandbox.get("source_sha256") != actual
                or sandbox.get("telemetry_sha256") != _telemetry_digest(events)):
            raise ValueError("candidate lacks a passing source/telemetry-bound sandbox result")
        checked = validate_source(source)
        if not checked.passed:
            raise ValueError("current AST policy rejects the candidate")
        return identifier, actual

    async def approve(self, candidate: dict[str, Any], reviewer: str,
                      expected_sha256: str) -> dict[str, Any]:
        """Record explicit review only after independently repeating isolated tests.

        An LLM-supplied ``passed`` field is never evidence of execution. The
        source digest must be copied from the human-visible review by the caller.
        """
        reviewed = _copy(candidate)
        identifier, source_hash = self._validate(reviewed)
        if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 160:
            raise ValueError("reviewer must be a non-empty name of at most 160 characters")
        if not hmac.compare_digest(source_hash, expected_sha256):
            raise ValueError("reviewed source digest does not match")
        with self._locked():
            if self.store.path("quarantine", f"q-{source_hash}").exists():
                raise ValueError("source version is quarantined")
            result = await self.runner.run(reviewed["source"], reviewed["telemetry"])
            if (not result.passed or result.source_sha256 != source_hash
                    or result.status != "passed"
                    or result.telemetry_sha256 != _telemetry_digest(reviewed["telemetry"])
                    or result.test_sha256 != test_fingerprint(reviewed["telemetry"])):
                raise ValueError("independent approval sandbox did not pass")
            if ([output is not None for output in result.outputs]
                    != reviewed["expected_matches"]):
                raise ValueError("independent approval sandbox failed expected detection fixtures")
            receipt = {
                "id": secrets.token_hex(16), "candidate_id": identifier,
                "candidate_sha256": hashlib.sha256(canonical(reviewed)).hexdigest(),
                "source_sha256": source_hash,
                "telemetry_sha256": result.telemetry_sha256,
                "reviewer": reviewer.strip(), "approved_at": _now(),
                "sandbox": result.to_dict(),
            }
            receipt["mac"] = hmac.new(self._key(), canonical(receipt), hashlib.sha256).hexdigest()
            self.store.save("approvals", receipt["id"], receipt)
            self.store.audit("candidate_approved", candidate_id=identifier,
                             source_sha256=source_hash, receipt_id=receipt["id"],
                             reviewer=reviewer.strip())
            return receipt

    def _receipt(self, candidate: dict[str, Any], receipt: dict[str, Any], *,
                 require_unused: bool = True) -> None:
        persisted = self.store.load("approvals", str(receipt.get("id", "")))
        if not hmac.compare_digest(canonical(persisted), canonical(receipt)):
            raise ValueError("approval receipt differs from recorded review")
        unsigned = {key: value for key, value in receipt.items() if key != "mac"}
        actual = hmac.new(self._key(), canonical(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(actual, str(receipt.get("mac", ""))):
            raise ValueError("approval receipt authentication failed")
        if (receipt.get("candidate_id") != candidate.get("id")
                or receipt.get("candidate_sha256") != hashlib.sha256(canonical(candidate)).hexdigest()):
            raise ValueError("candidate changed after review")
        if require_unused and self.store.path("consumed", receipt["id"]).exists():
            raise ValueError("approval has already been used")

    def _version_path(self, identifier: str, version: str, receipt_id: str | None = None) -> Path:
        if not IDENTIFIER.fullmatch(identifier) or not re.fullmatch(r"[a-f0-9]{64}", version):
            raise ValueError("invalid plugin version")
        if receipt_id is not None and not re.fullmatch(r"[a-f0-9]{32}", receipt_id):
            raise ValueError("invalid approval receipt id")
        suffix = f".{receipt_id}" if receipt_id is not None else ""
        return check_path(self.root / "versions" / identifier / f"{version}{suffix}.json")

    def _version(self, identifier: str, version: str, receipt_id: str | None = None) -> dict[str, Any]:
        # Original installations stored one snapshot per source hash. A later
        # review of identical source may have new evidence/fixtures/timestamps;
        # retain each review independently so rollback never changes its consent.
        path = self._version_path(identifier, version, receipt_id)
        if receipt_id is not None and not path.exists():
            path = self._version_path(identifier, version)
        if self.store.path("quarantine", f"q-{version}").exists():
            raise ValueError("stored plugin version is quarantined")
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("plugin version exceeds 2 MiB")
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict) or value.get("id") != identifier:
            raise ValueError("plugin version identity mismatch")
        _, actual = self._validate(value)
        if actual != version:
            raise ValueError("stored source differs from approved version")
        receipt_path = check_path(path.with_suffix(".approval.json"))
        if receipt_path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("stored approval is oversized")
        receipt = json.loads(receipt_path.read_bytes())
        if receipt_id is not None and receipt.get("id") != receipt_id:
            raise ValueError("stored version approval identity mismatch")
        self._receipt(value, receipt, require_unused=False)
        return value

    def activate(self, candidate: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
        """Atomically point the isolated runtime at a reviewed version."""
        candidate, receipt = _copy(candidate), _copy(receipt)
        identifier, version = self._validate(candidate)
        with self._locked():
            self._receipt(candidate, receipt)
            if self.store.path("quarantine", f"q-{version}").exists():
                raise ValueError("source version is quarantined")
            prior = self.store.load("plugins", identifier) if self.store.path("plugins", identifier).exists() else {}
            previous = prior.get("active")
            if previous == version:
                raise ValueError("version is already active")
            if previous:
                self._version(identifier, previous, prior.get("receipt_id"))
                if prior.get("probation") is not False:
                    raise ValueError("active version must finish probation before replacement")
            path = self._version_path(identifier, version)
            if path.exists():
                path = self._version_path(identifier, version, receipt["id"])
            # All activation preconditions pass before writing any version data.
            # Fresh review snapshots never overwrite an existing active/rollback
            # record, including when the generated source is byte-identical.
            if path.exists():
                raise ValueError("reviewed version snapshot already exists")
            atomic_write(path, canonical(candidate))
            atomic_write(path.with_suffix(".approval.json"), canonical(receipt))
            # Consume first: a crash may require a new review, but cannot replay consent.
            self.store.save("consumed", receipt["id"], {"time": _now(), "candidate_id": identifier})
            pointer = {"id": identifier, "active": version, "previous": previous,
                       "probation": True, "activated_at": _now(), "receipt_id": receipt["id"],
                       "previous_receipt_id": prior.get("receipt_id"), "passed_events": 0,
                       "probation_seconds": self.probation_seconds,
                       "probation_events": self.probation_events}
            self.store.save("plugins", identifier, pointer)
            self.store.audit("plugin_activated", **pointer)
            return pointer

    def _rollback(self, pointer: dict[str, Any], reason: str) -> dict[str, Any]:
        identifier, failed = pointer["id"], pointer.get("active")
        previous = pointer.get("previous")
        if previous:
            try:
                self._version(identifier, previous, pointer.get("previous_receipt_id"))
                if self.store.path("quarantine", f"q-{previous}").exists():
                    previous = None
            except (ValueError, OSError, json.JSONDecodeError):
                previous = None
        if failed:
            self.store.save("quarantine", f"q-{failed}", {
                "id": identifier, "version": failed, "reason": reason[:1000], "time": _now(),
            })
        updated = {"id": identifier, "active": previous, "previous": None,
                   "probation": False, "rolled_back_at": _now(), "reason": reason[:1000],
                   "receipt_id": pointer.get("previous_receipt_id") if previous else None}
        self.store.save("plugins", identifier, updated)
        self.store.audit("plugin_rolled_back", **updated)
        return updated

    def rollback(self, plugin_id: str, reason: str = "manual rollback") -> dict[str, Any]:
        with self._locked():
            return self._rollback(self.store.load("plugins", plugin_id), reason)

    async def run_active(self, plugin_id: str, event: dict[str, Any]) -> dict[str, Any]:
        """Execute only inside the configured container; failures disable the version.

        Every event is isolated. The elapsed-time and successful-event thresholds
        must both pass probation; later execution failures also trigger rollback.
        """
        if not isinstance(event, dict):
            raise ValueError("telemetry event must be an object")
        event = normalize_telemetry([event])[0]
        with self._locked():
            pointer = self.store.load("plugins", plugin_id)
            version = pointer.get("active")
            if not version:
                raise ValueError("plugin has no active version")
            try:
                candidate = self._version(plugin_id, version, pointer.get("receipt_id"))
                # Bind even the stored metadata to the original authenticated review.
                receipt = self.store.load("approvals", pointer["receipt_id"])
                unsigned = {key: value for key, value in receipt.items() if key != "mac"}
                mac = hmac.new(self._key(), canonical(unsigned), hashlib.sha256).hexdigest()
                if (not hmac.compare_digest(mac, str(receipt.get("mac", "")))
                        or receipt["candidate_sha256"] != hashlib.sha256(canonical(candidate)).hexdigest()):
                    raise ValueError("active plugin approval binding failed")
                result = await self.runner.run(candidate["source"], [event])
                if (not result.passed or result.status != "passed"
                        or result.source_sha256 != version
                        or result.telemetry_sha256 != _telemetry_digest([event])
                        or result.test_sha256 != test_fingerprint([event])):
                    raise ValueError(f"sandbox failed: {result.status}")
            except Exception as exc:
                rollback = self._rollback(pointer, str(exc))
                return {"passed": False, "status": "rolled_back", "reason": str(exc),
                        "plugin": rollback}
            pointer["passed_events"] = pointer.get("passed_events", 0) + 1
            if pointer.get("probation"):
                elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(pointer["activated_at"])).total_seconds()
                if (elapsed >= pointer["probation_seconds"]
                        and pointer["passed_events"] >= pointer["probation_events"]):
                    pointer["probation"] = False
            pointer["last_passed_at"] = _now()
            self.store.save("plugins", plugin_id, pointer)
            return result.to_dict()

    def reject(self, candidate: dict[str, Any], reason: str = "human rejection") -> None:
        candidate = _copy(candidate)
        identifier = candidate.get("id")
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError("invalid candidate id")
        with self._locked():
            self.store.save("rejected", identifier, {"candidate": candidate, "reason": reason[:1000],
                                                      "time": _now()})
            source = candidate.get("source")
            if isinstance(source, str) and source:
                self.store.save("quarantine", f"q-{digest(source)}", {
                    "id": identifier, "version": digest(source), "reason": reason[:1000],
                    "time": _now(),
                })
            # This is the mutable development record only. Active versions and
            # their authenticated review snapshots remain immutable.
            self.store.save("candidates", identifier, {**candidate, "state": "rejected"})
            self.store.audit("candidate_rejected", candidate_id=identifier, reason=reason[:1000])
