from __future__ import annotations

import base64
import asyncio
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from divalia.harness.ast_validator import validate_source
from divalia.harness.sandbox import SandboxResult, canonical_json, test_fingerprint as fingerprint
from divalia.integration.detection_export import export_detection, validate_detection
from divalia.integration.downloader import extract_verified_archive
from divalia.integration.publisher import Publisher
from divalia.integration.review import render_html, render_review
from divalia.storage import canonical, digest

SOURCE = 'def detect(event):\n    if event.get("suspicious"):\n        return {"rule_id": "example", "severity": "medium"}\n    return None\n'
EVENTS = [{"suspicious": False}, {"suspicious": True, "message": "fixturé"}]


def result(source: str = SOURCE, events: list | None = None, passed: bool = True) -> SandboxResult:
    events = EVENTS if events is None else events
    outputs = [{"rule_id": "example"} if event.get("suspicious") else None for event in events]
    return SandboxResult(passed, "passed" if passed else "execution_error", [], outputs,
                         digest(source), hashlib.sha256(canonical_json(events)).hexdigest(),
                         fingerprint(events), {"executions": len(events) * 8})


def candidate(source: str = SOURCE) -> dict:
    return {"id": "example", "source": source, "explanation": "Detect suspicious activity",
            "briefing_id": "briefing-1", "audit": validate_source(source).to_dict(),
            "sandbox": result(source).to_dict(), "telemetry": EVENTS,
            "expected_matches": [False, True], "created_at": "now",
            "state": "tested"}


def detection() -> dict:
    return {"schema_version": 1, "id": "divalia.example", "version": "1.0.0", "owner": "reviewer",
            "description": "Detect a test marker", "telemetry": ["process"], "attack": ["T1059"],
            "severity": "medium", "confidence": 60,
            "logic": {"type": "sigma-subset", "detection": {"selection": {"message|contains": "test marker"},
                                                               "condition": "selection"}},
            "fixtures": [{"name": "positive", "event": {"message": "A TEST MARKER"}, "expected_match": True},
                         {"name": "negative", "event": {"message": "normal"}, "expected_match": False}],
            "performance": {"max_eval_ms": 10, "max_events_per_second": 1000},
            "rollback": {"previous_digest": None, "instructions": "Disable through DetectionForge"},
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()}


class PublisherTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.publisher = Publisher(self.root, probation_seconds=0, probation_events=1)
        self.publisher.runner.run = AsyncMock(side_effect=lambda source, events: result(source, events))

    def tearDown(self):
        self.temporary.cleanup()

    async def approve_and_activate(self, value):
        receipt = await self.publisher.approve(value, "human", digest(value["source"]))
        pointer = self.publisher.activate(value, receipt)
        await self.publisher.run_active(value["id"], {"suspicious": False})
        return pointer

    async def test_review_is_bound_to_source_and_repeated_real_test(self):
        value = candidate()
        with self.assertRaisesRegex(ValueError, "digest"):
            await self.publisher.approve(value, "human", "0" * 64)
        self.publisher.runner.run.assert_not_called()
        receipt = await self.publisher.approve(value, "human", digest(SOURCE))
        self.publisher.runner.run.assert_awaited_once_with(SOURCE, EVENTS)
        value["explanation"] = "Changed after human review"
        with self.assertRaisesRegex(ValueError, "changed"):
            self.publisher.activate(value, receipt)

    async def test_spoofed_passing_report_cannot_bypass_independent_sandbox(self):
        self.publisher.runner.run.return_value = None
        self.publisher.runner.run.side_effect = lambda source, events: result(source, events, passed=False)
        with self.assertRaisesRegex(ValueError, "independent approval sandbox"):
            await self.publisher.approve(candidate(), "human", digest(SOURCE))
        self.assertFalse(self.publisher.store.list("approvals"))

    async def test_metadata_and_telemetry_changes_are_rejected(self):
        value = candidate()
        value["telemetry"] = [{"different": True}, {"different": False}]
        with self.assertRaisesRegex(ValueError, "telemetry"):
            await self.publisher.approve(value, "human", digest(SOURCE))
        hostile = candidate('import os\ndef detect(event):\n    return None\n')
        hostile["audit"]["passed"] = True
        with self.assertRaisesRegex(ValueError, "AST policy"):
            await self.publisher.approve(hostile, "human", digest(hostile["source"]))

    async def test_receipt_tampering_and_replay_fail(self):
        value = candidate()
        receipt = await self.publisher.approve(value, "human", digest(SOURCE))
        tampered = {**receipt, "reviewer": "attacker"}
        with self.assertRaisesRegex(ValueError, "differs"):
            self.publisher.activate(value, tampered)
        self.publisher.activate(value, receipt)
        with self.assertRaisesRegex(ValueError, "already been used"):
            self.publisher.activate(value, receipt)

    async def test_positive_fixture_semantics_are_independently_enforced(self):
        self.publisher.runner.run.side_effect = lambda source, events: SandboxResult(
            True, "passed", [], [None] * len(events), digest(source),
            hashlib.sha256(canonical_json(events)).hexdigest(), fingerprint(events), {})
        with self.assertRaisesRegex(ValueError, "expected detection fixtures"):
            await self.publisher.approve(candidate(), "human", digest(SOURCE))

    async def test_probation_requires_elapsed_window_and_successful_event_count(self):
        publisher = Publisher(self.root / "probation", probation_seconds=60, probation_events=2)
        publisher.runner.run = AsyncMock(side_effect=lambda source, events: result(source, events))
        value = candidate()
        receipt = await publisher.approve(value, "human", digest(SOURCE))
        publisher.activate(value, receipt)
        await publisher.run_active("example", {})
        self.assertTrue(publisher.store.load("plugins", "example")["probation"])
        changed = candidate(SOURCE + "# new reviewed version\n")
        receipt2 = await publisher.approve(changed, "human", digest(changed["source"]))
        with self.assertRaisesRegex(ValueError, "finish probation"):
            publisher.activate(changed, receipt2)
        await publisher.run_active("example", {})
        self.assertTrue(publisher.store.load("plugins", "example")["probation"])
        pointer = publisher.store.load("plugins", "example")
        pointer["activated_at"] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        publisher.store.save("plugins", "example", pointer)
        await publisher.run_active("example", {})
        self.assertFalse(publisher.store.load("plugins", "example")["probation"])
        publisher.activate(changed, receipt2)

    async def test_failure_rolls_back_and_previous_version_can_execute(self):
        stable = candidate()
        await self.approve_and_activate(stable)
        changed = candidate(SOURCE.replace('"medium"', '"high"'))
        await self.approve_and_activate(changed)
        self.publisher.runner.run.side_effect = lambda source, events: result(source, events, passed=False)
        report = await self.publisher.run_active("example", {"suspicious": True})
        self.assertEqual(report["status"], "rolled_back")
        self.assertEqual(report["plugin"]["active"], digest(SOURCE))
        self.assertTrue(self.publisher.store.path("quarantine", "q-" + digest(changed["source"])).exists())
        self.publisher.runner.run.side_effect = lambda source, events: result(source, events)
        successful = await self.publisher.run_active("example", {"suspicious": False})
        self.assertTrue(successful["passed"])

    async def test_disk_tampering_disables_version_without_host_execution(self):
        await self.approve_and_activate(candidate())
        path = self.root / "versions" / "example" / f"{digest(SOURCE)}.json"
        altered = candidate()
        altered["explanation"] = "A changed metadata record"
        path.write_bytes(canonical(altered))
        self.publisher.runner.run.reset_mock()
        report = await self.publisher.run_active("example", {})
        self.assertEqual(report["status"], "rolled_back")
        self.assertIsNone(report["plugin"]["active"])
        self.publisher.runner.run.assert_not_called()

    async def test_path_traversal_fails_and_lock_is_exclusive(self):
        value = candidate()
        value["id"] = "../outside"
        with self.assertRaisesRegex(ValueError, "id"):
            await self.publisher.approve(value, "human", digest(SOURCE))
        with self.publisher._locked():
            with self.assertRaisesRegex(RuntimeError, "busy"):
                self.publisher.rollback("example")

    async def test_missing_sandbox_never_creates_receipt(self):
        publisher = Publisher(self.root / "unconfigured")
        with self.assertRaisesRegex(ValueError, "independent approval sandbox"):
            await publisher.approve(candidate(), "human", digest(SOURCE))

    async def test_human_rejection_quarantines_source_before_approval(self):
        value = candidate()
        self.publisher.reject(value, "insufficient evidence")
        self.assertTrue(self.publisher.store.path("quarantine", "q-" + digest(SOURCE)).exists())
        with self.assertRaisesRegex(ValueError, "quarantined"):
            await self.publisher.approve(value, "human", digest(SOURCE))
        self.publisher.runner.run.assert_not_called()

    async def test_same_source_can_be_reviewed_again_without_changing_old_snapshots(self):
        original = candidate()
        await self.approve_and_activate(original)
        original_path = self.publisher._version_path("example", digest(SOURCE))
        original_record = original_path.read_bytes()
        original_approval = original_path.with_suffix(".approval.json").read_bytes()
        second = candidate(SOURCE + "# second stable version\n")
        await self.approve_and_activate(second)
        fresh = candidate()
        fresh.update(created_at="later", explanation="New review of the same implementation")
        receipt = await self.publisher.approve(fresh, "second human", digest(SOURCE))
        self.publisher.activate(fresh, receipt)
        self.assertTrue((await self.publisher.run_active("example", {}))["passed"])
        self.assertEqual(original_path.read_bytes(), original_record)
        self.assertEqual(original_path.with_suffix(".approval.json").read_bytes(), original_approval)
        reviewed_path = self.publisher._version_path("example", digest(SOURCE), receipt["id"])
        self.assertEqual(json.loads(reviewed_path.read_bytes()), fresh)
        self.publisher.runner.run.side_effect = lambda source, events: result(source, events, False)
        report = await self.publisher.run_active("example", {})
        self.assertEqual(report["plugin"]["active"], digest(second["source"]))
        self.publisher.runner.run.side_effect = lambda source, events: result(source, events)
        self.assertTrue((await self.publisher.run_active("example", {}))["passed"])

    async def test_failed_reactivation_never_overwrites_active_review(self):
        value = candidate()
        await self.approve_and_activate(value)
        path = self.publisher._version_path("example", digest(SOURCE))
        before = path.with_suffix(".approval.json").read_bytes()
        receipt = await self.publisher.approve(value, "another human", digest(SOURCE))
        with self.assertRaisesRegex(ValueError, "already active"):
            self.publisher.activate(value, receipt)
        self.assertEqual(path.with_suffix(".approval.json").read_bytes(), before)
        self.assertTrue((await self.publisher.run_active("example", {}))["passed"])

    async def test_invalid_runtime_event_does_not_quarantine_healthy_version(self):
        await self.approve_and_activate(candidate())
        before = self.publisher.store.load("plugins", "example")
        self.publisher.runner.run.reset_mock()
        nested = {}
        for _ in range(14):
            nested = {"child": nested}
        for event in [{"value": float("nan")}, {"value": "x" * 65_537}, nested]:
            with self.subTest(event=str(event)[:60]), self.assertRaises(ValueError):
                await self.publisher.run_active("example", event)
        self.assertEqual(self.publisher.store.load("plugins", "example"), before)
        self.assertFalse(self.publisher.store.list("quarantine"))
        self.publisher.runner.run.assert_not_called()

    async def test_cancelled_review_releases_lock_without_creating_consent(self):
        started = asyncio.Event()

        async def waiting(source, events):
            started.set()
            await asyncio.Event().wait()

        self.publisher.runner.run.side_effect = waiting
        task = asyncio.create_task(self.publisher.approve(candidate(), "human", digest(SOURCE)))
        await asyncio.wait_for(started.wait(), 2)
        with self.assertRaisesRegex(RuntimeError, "busy"):
            self.publisher.reject(candidate())
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse((self.root / "publisher.lock").exists())
        self.assertFalse(self.publisher.store.list("approvals"))
        self.assertFalse(self.publisher.store.list("rejected"))

    async def test_cancelled_runtime_event_keeps_the_approved_version_usable(self):
        await self.approve_and_activate(candidate())
        before = self.publisher.store.load("plugins", "example")
        started = asyncio.Event()

        async def waiting(source, events):
            started.set()
            await asyncio.Event().wait()

        self.publisher.runner.run.side_effect = waiting
        task = asyncio.create_task(self.publisher.run_active("example", {}))
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.publisher.store.load("plugins", "example"), before)
        self.assertFalse(self.publisher.store.list("quarantine"))
        self.assertFalse((self.root / "publisher.lock").exists())
        self.publisher.runner.run.side_effect = lambda source, events: result(source, events)
        self.assertTrue((await self.publisher.run_active("example", {}))["passed"])


class ExportTests(unittest.TestCase):
    def test_signed_export_verifies_exact_bytes_and_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = Ed25519PrivateKey.generate()
            key_path = root / "signing.pem"
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            target = root / "example.json"
            receipt = export_detection(detection(), target, key_path, "reviewer-key")
            metadata = json.loads(Path(receipt["signature_path"]).read_bytes())
            key.public_key().verify(base64.b64decode(metadata["signature"]), target.read_bytes())
            validate_detection(json.loads(target.read_bytes()))
            self.assertEqual(metadata["key_id"], "reviewer-key")
            with self.assertRaises(FileExistsError):
                export_detection(detection(), target)

    def test_invalid_fixtures_and_schema_are_rejected_before_export(self):
        with tempfile.TemporaryDirectory() as directory:
            for variant in ("fixture", "wildcard", "expired", "unknown", "negation"):
                value = detection()
                if variant == "fixture":
                    value["fixtures"][0]["expected_match"] = False
                elif variant == "wildcard":
                    value["logic"]["detection"]["selection"] = {"message": "*marker*"}
                elif variant == "expired":
                    value["expires_at"] = "2000-01-01T00:00:00Z"
                elif variant == "unknown":
                    value["python"] = "print('unsafe')"
                else:
                    value["logic"]["detection"]["condition"] = "selection and not selection"
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    export_detection(value, Path(directory) / f"{variant}.json")
                self.assertFalse((Path(directory) / f"{variant}.json").exists())

    def test_review_escapes_untrusted_html_and_terminal_control(self):
        value = candidate()
        value["explanation"] = '<script>alert(1)</script>\x1b[2J'
        value["source"] += '# <img src=x onerror=alert(1)>\x1b[2J\n'
        rendered = render_html(value)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img src=x", rendered)
        self.assertNotIn("\x1b", render_review(value))


class DownloadTests(unittest.TestCase):
    def archive(self, extra: str = "Divalia-abcdef/src/divalia/__init__.py") -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("Divalia-abcdef/pyproject.toml", "[project]\nname='divalia'\n")
            archive.writestr(extra, "# inert source\n")
        return stream.getvalue()

    def test_hash_and_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("Divalia-abcdef/../escape", "Divalia-abcdef/CON.txt",
                         "Divalia-abcdef/evil:stream", "Divalia-abcdef/..\\escape"):
                payload = self.archive(name)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    extract_verified_archive(payload, root / "download", hashlib.sha256(payload).hexdigest())
            payload = self.archive()
            with self.assertRaisesRegex(ValueError, "mismatch"):
                extract_verified_archive(payload, root / "download", "0" * 64)
            output = extract_verified_archive(payload, root / "download", hashlib.sha256(payload).hexdigest())
            self.assertTrue((output / "pyproject.toml").is_file())
            self.assertFalse((root / "escape").exists())


if __name__ == "__main__":
    unittest.main()
