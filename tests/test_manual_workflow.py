"""Real offline operator entry points for authoring modules without an AI backend."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from divalia.cli import example_detection, main
from divalia.integration.detection_export import validate_detection
from divalia.storage import ArtifactStore, digest

SOURCE = """def detect(event):
    if "DIVALIA_TEST_MARKER" in event.get("cmdline", ""):
        return {"severity": "informational", "message": "test marker"}
    return None
"""
FIXTURES = [
    {"event": {"cmdline": "echo hello"}, "expected_match": False},
    {"event": {"cmdline": "echo DIVALIA_TEST_MARKER"}, "expected_match": True},
]


class ManualWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="divalia-manual-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "divalia.toml"
        # An unusable provider proves manual authoring does not require model
        # configuration; the empty image and PATH prohibit execution fallback.
        self.config.write_text(
            '[app]\nstate_dir="state"\n[ai]\nprovider="not-a-real-provider"\n[sandbox]\nimage=""\n',
            encoding="utf-8",
        )
        self.source = self.root / "module.py"
        self.source.write_text(SOURCE, encoding="utf-8")
        self.fixtures = self.root / "fixtures.json"
        self.fixtures.write_text(json.dumps(FIXTURES), encoding="utf-8")
        self.store = ArtifactStore(self.root / "state")

    def run_cli(self, *arguments):
        environment = {**os.environ, "PATH": "", "DIVALIA_SANDBOX_IMAGE": ""}
        return subprocess.run(
            [sys.executable, "-m", "divalia", "--config", str(self.config), *map(str, arguments)],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def create(self, *extra):
        return self.run_cli(
            "create",
            self.source,
            "--id",
            "manual-example",
            "--fixtures",
            self.fixtures,
            "--explanation",
            "An observe-only developer module; <script>untrusted</script>",
            *extra,
        )

    def assert_error(self, outcome):
        self.assertEqual(outcome.returncode, 2, outcome.stderr)
        self.assertIn("Divalia:", outcome.stderr)
        self.assertNotIn("Traceback", outcome.stderr)

    def test_manual_creation_is_reviewable_but_blocked_without_isolation(self):
        created = self.create()
        self.assertEqual(created.returncode, 2, created.stderr)
        candidate = json.loads(created.stdout)
        self.assertEqual(candidate["origin"], "operator")
        self.assertEqual(candidate["state"], "blocked")
        self.assertTrue(candidate["audit"]["passed"])
        self.assertFalse(candidate["sandbox"]["passed"])
        self.assertEqual(candidate["sandbox"]["status"], "unavailable")
        self.assertEqual(candidate["source_sha256"], digest(SOURCE))
        self.assertEqual(candidate["expected_matches"], [False, True])
        self.assertEqual(self.store.load("candidates", "manual-example"), candidate)
        report = self.root / "review.html"
        reviewed = self.run_cli("review", "manual-example", "--html", report)
        self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
        rendered = report.read_text(encoding="utf-8")
        self.assertIn(digest(SOURCE), rendered)
        self.assertIn("Angerona", rendered)
        self.assertIn("Human review required", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertFalse(self.store.list("approvals"))
        self.assertFalse(self.store.list("plugins"))

    def test_retest_preserves_prior_source_diff_and_never_creates_a_model_provider(self):
        def invoke(*arguments):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = main(["--config", str(self.config), *map(str, arguments)])
            self.assertEqual(status, 2, stderr.getvalue())
            return json.loads(stdout.getvalue())

        previous_level = logging.getLogger().level
        self.addCleanup(logging.getLogger().setLevel, previous_level)
        with (
            patch.dict(os.environ, {"DIVALIA_SANDBOX_IMAGE": ""}),
            patch(
                "divalia.cli._pipeline", side_effect=AssertionError("AI must not be used")
            ) as pipeline,
            patch(
                "divalia.cli.create_provider", side_effect=AssertionError("AI must not be used")
            ) as provider,
            patch(
                "divalia.cli.ModelRouter", side_effect=AssertionError("AI must not be used")
            ) as router,
        ):
            arguments = (
                "create",
                self.source,
                "--id",
                "manual-example",
                "--fixtures",
                self.fixtures,
                "--explanation",
                "Review an operator-authored module",
            )
            original = invoke(*arguments)
            changed_source = SOURCE + "# A reviewed second revision\n"
            self.source.write_text(changed_source, encoding="utf-8")
            changed = invoke(*arguments)
            retested = invoke("retest", "manual-example")
            pipeline.assert_not_called()
            provider.assert_not_called()
            router.assert_not_called()
        self.assertEqual(changed["previous_source"], original["source"])
        self.assertEqual(retested["previous_source"], SOURCE)
        self.assertEqual(retested["supersedes_sha256"], digest(SOURCE))
        self.assertEqual(retested["source_sha256"], digest(changed_source))
        self.assertEqual(retested["telemetry"], original["telemetry"])
        self.assertEqual(retested["state"], "blocked")

    def test_rejection_quarantines_source_and_approval_creates_no_runtime_state(self):
        self.assertEqual(self.create().returncode, 2)
        rejected = self.run_cli("reject", "manual-example", "--reason", "Needs stronger evidence")
        self.assertEqual(rejected.returncode, 0, rejected.stderr)
        self.assertEqual(json.loads(rejected.stdout)["state"], "rejected")
        record = self.store.load("rejected", "manual-example")
        self.assertEqual(record["reason"], "Needs stronger evidence")
        self.assertEqual(record["candidate"]["state"], "blocked")
        self.assertEqual(self.store.load("candidates", "manual-example")["state"], "rejected")
        listing = self.run_cli("list", "candidates")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual(json.loads(listing.stdout)[0]["state"], "rejected")
        quarantine = self.store.load("quarantine", "q-" + digest(SOURCE))
        self.assertEqual(quarantine["version"], digest(SOURCE))
        approval = self.run_cli(
            "approve",
            "manual-example",
            "--reviewer",
            "human",
            "--sha256",
            digest(SOURCE),
        )
        self.assert_error(approval)
        self.assertFalse(self.store.list("approvals"))
        self.assertFalse(self.store.list("consumed"))
        self.assertFalse(self.store.list("plugins"))
        self.assertFalse((self.store.root / "publisher.lock").exists())

    def test_manual_declarative_export_has_a_valid_exact_byte_signature(self):
        package = self.root / "declaration.json"
        package.write_text(json.dumps(example_detection()), encoding="utf-8")
        created = self.create("--detection", package)
        self.assertEqual(created.returncode, 2, created.stderr)
        self.assertTrue(json.loads(created.stdout)["detection_audit"]["passed"])
        key = Ed25519PrivateKey.generate()
        key_path = self.root / "reviewer.pem"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        target = self.root / "signed-package.json"
        exported = self.run_cli(
            "export",
            "manual-example",
            "--output",
            target,
            "--private-key",
            key_path,
            "--key-id",
            "manual-reviewer",
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        receipt = json.loads(exported.stdout)
        self.assertTrue(receipt["signed"])
        payload = target.read_bytes()
        validate_detection(json.loads(payload))
        detached = json.loads(Path(receipt["signature_path"]).read_bytes())
        signature = base64.b64decode(detached["signature"], validate=True)
        key.public_key().verify(signature, payload)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(signature, payload + b" ")
        self.assertFalse(self.store.list("plugins"))
        candidate = self.store.load("candidates", "manual-example")
        candidate["telemetry"][1]["cmdline"] = "unrelated command"
        self.store.save("candidates", "manual-example", candidate)
        inconsistent_output = self.root / "inconsistent.json"
        refused = self.run_cli("export", "manual-example", "--output", inconsistent_output)
        self.assert_error(refused)
        self.assertIn("disagrees", refused.stderr)
        self.assertFalse(inconsistent_output.exists())

    def test_malformed_nonfinite_and_oversized_inputs_return_bounded_cli_errors(self):
        bad_inputs = {
            "malformed": "{",
            "fixture-schema": json.dumps([{"event": {}, "expected_match": "true"}] * 2),
            "nonfinite": json.dumps(
                [
                    {"event": {"value": float("nan")}, "expected_match": False},
                    FIXTURES[1],
                ]
            ),
            "oversized-json": " " * (1024 * 1024 + 1),
        }
        for name, data in bad_inputs.items():
            with self.subTest(name=name):
                self.fixtures.write_text(data, encoding="utf-8")
                self.assert_error(self.create())
                self.assertFalse(self.store.path("candidates", "manual-example").exists())
        self.fixtures.write_text(json.dumps(FIXTURES), encoding="utf-8")
        self.source.write_text(SOURCE + "#" * 32768, encoding="utf-8")
        self.assert_error(self.create())
        self.assertFalse(self.store.path("candidates", "manual-example").exists())


if __name__ == "__main__":
    unittest.main()
