"""Opt-in real module-development lifecycle; never execute detector code on the host."""

from __future__ import annotations

import base64
import asyncio
import json
import os
import tempfile
import time
import unittest
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from divalia.cli import example_detection
from divalia.harness.ast_validator import validate_source
from divalia.harness.sandbox import SandboxRunner
from divalia.integration.detection_export import export_detection, validate_detection
from divalia.integration.publisher import Publisher
from divalia.integration.review import render_html
from divalia.storage import digest

STABLE_SOURCE = """def detect(event):
    command = str(event.get("cmdline", "")).lower()
    if "divalia_test_marker" in command:
        return {"severity": "informational", "rule_id": "divalia-live-workflow"}
    return None
"""
# The fixtures pass, but null telemetry exposes a realistic type-assumption bug.
REPLACEMENT_SOURCE = STABLE_SOURCE.replace(
    'str(event.get("cmdline", ""))', 'event.get("cmdline", "")'
)
EVENTS = [{"cmdline": "echo hello"}, {"cmdline": "echo DIVALIA_TEST_MARKER"}]
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "encoded-powershell"


@unittest.skipUnless(
    os.environ.get("DIVALIA_TEST_SANDBOX_IMAGE"),
    "set DIVALIA_TEST_SANDBOX_IMAGE to a built immutable worker image",
)
class LiveWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_cli_manual_module_creation_review_execution_and_export(self):
        with tempfile.TemporaryDirectory(prefix="divalia-live-cli-") as directory:
            root = Path(directory)
            config = root / "divalia.toml"
            config.write_text(
                '[app]\nstate_dir = "state"\n[sandbox]\nimage = '
                + json.dumps(os.environ["DIVALIA_TEST_SANDBOX_IMAGE"])
                + "\n",
                encoding="utf-8",
            )
            source = root / "module.py"
            source_text = (EXAMPLE / "detector.py").read_text(encoding="utf-8")
            source.write_text(source_text, encoding="utf-8")
            fixtures = root / "fixtures.json"
            example_fixtures = json.loads((EXAMPLE / "fixtures.json").read_bytes())
            fixtures.write_text(json.dumps(example_fixtures), encoding="utf-8")
            package = root / "package.json"
            package.write_bytes((EXAMPLE / "detection.json").read_bytes())
            timings = {}

            async def command(*arguments):
                started = time.perf_counter()
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-m",
                    "divalia",
                    "--config",
                    str(config),
                    *map(str, arguments),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=root,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), 90)
                finally:
                    if process.returncode is None:
                        process.kill()
                        await process.wait()
                self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
                timings.setdefault(str(arguments[0]), []).append(time.perf_counter() - started)
                return stdout.decode("utf-8")

            created = json.loads(
                await command(
                    "create",
                    source,
                    "--id",
                    "manual-live",
                    "--fixtures",
                    fixtures,
                    "--explanation",
                    "An observe-only marker module for development validation.",
                    "--detection",
                    package,
                )
            )
            self.assertEqual(created["id"], "manual-live")
            self.assertEqual(created["state"], "pending")
            self.assertTrue(created["sandbox"]["passed"])
            self.assertTrue(created["detection_audit"]["passed"])
            self.assertEqual(len(created["sandbox"]["outputs"]), len(example_fixtures))
            retested = json.loads(await command("retest", "manual-live"))
            self.assertEqual(retested["source_sha256"], digest(source_text))
            self.assertEqual(retested["state"], "pending")
            review = root / "review.html"
            await command("review", "manual-live", "--html", review)
            self.assertIn(digest(source_text), review.read_text(encoding="utf-8"))
            await command(
                "approve",
                "manual-live",
                "--reviewer",
                "CLI workflow reviewer",
                "--sha256",
                digest(source_text),
            )
            for index, expected in enumerate([False, True]):
                event = next(
                    item["event"] for item in example_fixtures if item["expected_match"] is expected
                )
                event_path = root / f"event-{index}.json"
                event_path.write_text(json.dumps(event), encoding="utf-8")
                result = json.loads(await command("run-event", "manual-live", event_path))
                self.assertTrue(result["passed"], result)
                self.assertEqual(result["outputs"][0] is not None, expected)
            exported_path = root / "exported.json"
            exported = json.loads(await command("export", "manual-live", "--output", exported_path))
            self.assertEqual(exported["path"], str(exported_path))
            validate_detection(json.loads(exported_path.read_bytes()))
            print("live_cli_workflow_metrics=" + json.dumps(timings, sort_keys=True))

    async def test_real_module_review_activation_replacement_rollback_and_signed_export(self):
        image = os.environ["DIVALIA_TEST_SANDBOX_IMAGE"]
        timings = {}

        async def candidate(source, runner):
            started = time.perf_counter()
            audit = validate_source(source)
            self.assertTrue(audit.passed, audit.issues)
            tested = await runner.run(source, EVENTS)
            self.assertTrue(tested.passed, tested.to_dict())
            self.assertEqual([item is not None for item in tested.outputs], [False, True])
            self.assertEqual(tested.metrics["executions"], 16)
            timings[digest(source)[:12]] = {
                "container_validation_seconds": time.perf_counter() - started,
                "worker": tested.metrics,
            }
            return {
                "id": "live-workflow",
                "source": source,
                "source_sha256": digest(source),
                "explanation": "Observe-only marker detector; review telemetry type assumptions.",
                "briefing_id": "live-fixture",
                "audit": audit.to_dict(),
                "sandbox": tested.to_dict(),
                "telemetry": EVENTS,
                "expected_matches": [False, True],
                "created_at": "live-test",
                "state": "pending",
                "detection": example_detection(),
            }

        with tempfile.TemporaryDirectory(prefix="divalia-live-workflow-") as directory:
            root = Path(directory)
            publisher = Publisher(root / "state", image, probation_seconds=0, probation_events=2)
            stable = await candidate(STABLE_SOURCE, SandboxRunner(image))
            review = root / "review.html"
            review.write_text(render_html(stable), encoding="utf-8")
            rendered = review.read_text(encoding="utf-8")
            self.assertIn(digest(STABLE_SOURCE), rendered)
            self.assertIn("Angerona", rendered)
            self.assertIn("Human review required", rendered)

            # A second runner, invoked by approval, must independently re-test.
            started = time.perf_counter()
            receipt = await publisher.approve(
                stable, "live-workflow reviewer", digest(STABLE_SOURCE)
            )
            timings["independent_approval_seconds"] = time.perf_counter() - started
            tampered = {**stable, "explanation": "Changed after the review"}
            with self.assertRaisesRegex(ValueError, "changed after review"):
                publisher.activate(tampered, receipt)
            with self.assertRaisesRegex(ValueError, "differs"):
                publisher.activate(stable, {**receipt, "reviewer": "unapproved replacement"})
            publisher.activate(stable, receipt)
            with self.assertRaisesRegex(ValueError, "already been used"):
                publisher.activate(stable, receipt)
            self.assertTrue(publisher.store.load("plugins", "live-workflow")["probation"])

            started = time.perf_counter()
            miss = await publisher.run_active("live-workflow", EVENTS[0])
            self.assertTrue(miss["passed"], miss)
            self.assertEqual(miss["outputs"], [None])
            self.assertTrue(publisher.store.load("plugins", "live-workflow")["probation"])
            hit = await publisher.run_active("live-workflow", EVENTS[1])
            self.assertTrue(hit["passed"], hit)
            self.assertEqual(hit["outputs"][0]["rule_id"], "divalia-live-workflow")
            self.assertFalse(publisher.store.load("plugins", "live-workflow")["probation"])
            timings["two_isolated_runtime_events_seconds"] = time.perf_counter() - started

            replacement = await candidate(REPLACEMENT_SOURCE, SandboxRunner(image))
            replacement_receipt = await publisher.approve(
                replacement, "live-workflow reviewer", digest(REPLACEMENT_SOURCE)
            )
            publisher.activate(replacement, replacement_receipt)
            self.assertTrue((await publisher.run_active("live-workflow", EVENTS[0]))["passed"])
            self.assertTrue((await publisher.run_active("live-workflow", EVENTS[1]))["passed"])
            self.assertFalse(publisher.store.load("plugins", "live-workflow")["probation"])

            # A real container exception after probation must restore the stable
            # version and prevent another approval of the failing source.
            failed = await publisher.run_active("live-workflow", {"cmdline": None})
            self.assertFalse(failed["passed"])
            self.assertEqual(failed["status"], "rolled_back")
            self.assertEqual(failed["plugin"]["active"], digest(STABLE_SOURCE))
            self.assertTrue(
                publisher.store.path("quarantine", "q-" + digest(REPLACEMENT_SOURCE)).exists()
            )
            with self.assertRaisesRegex(ValueError, "quarantined"):
                await publisher.approve(replacement, "reviewer", digest(REPLACEMENT_SOURCE))
            restored = await publisher.run_active("live-workflow", {"cmdline": None})
            self.assertTrue(restored["passed"], restored)
            self.assertEqual(restored["outputs"], [None])

            # Human-controlled export uses exact-byte Ed25519 signatures; it does
            # not enroll a key or promote anything inside an Angerona installation.
            key = Ed25519PrivateKey.generate()
            key_path = root / "reviewer.pem"
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            exported = export_detection(
                stable["detection"], root / "detection.json", key_path, "live-reviewer"
            )
            payload = Path(exported["path"]).read_bytes()
            validate_detection(json.loads(payload))
            detached = json.loads(Path(exported["signature_path"]).read_bytes())
            signature = base64.b64decode(detached["signature"], validate=True)
            key.public_key().verify(signature, payload)
            with self.assertRaises(InvalidSignature):
                key.public_key().verify(signature, payload + b" ")
            self.assertFalse((publisher.root / "publisher.lock").exists())

        print("live_workflow_metrics=" + json.dumps(timings, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
