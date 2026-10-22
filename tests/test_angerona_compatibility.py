"""Opt-in compatibility checks against an independent Angerona source checkout.

Set DIVALIA_ANGERONA_SRC to that checkout's ``src`` directory. These tests import
only the declarative package validator and matcher, and never start Angerona.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from divalia.integration.detection_export import export_detection


def representative_package() -> dict:
    """Exercise real field, modifier, scalar, Unicode and branch semantics."""
    return {
        "schema_version": 1,
        "id": "divalia.compatibility",
        "version": "2.0.0",
        "owner": "Équipe sécurité — 安全",
        "description": "Synthetic benign fixtures for the portable detection subset",
        "telemetry": ["process", "network"],
        "attack": ["T1059.001"],
        "severity": "medium",
        "confidence": 65,
        "logic": {
            "type": "sigma-subset",
            "detection": {
                "selection": [
                    {
                        "module": "PROCESS",
                        "message|contains": "audit marker",
                        "image|endswith": ["pwsh.exe", "powershell.exe"],
                        "pid": 123,
                        "signed": False,
                    },
                    {
                        "module": "network",
                        "destination|startswith": "example.",
                        "destination|endswith": ".invalid",
                    },
                ],
                "condition": "selection",
            },
        },
        "fixtures": [
            {
                "name": "mixed-case process fields and scalar coercion",
                "event": {
                    "module": "process",
                    "message": "Benign AUDIT MARKER fixture",
                    "image": "C:/Windows/System32/PowerShell.EXE",
                    "pid": "123",
                    "signed": "False",
                    "severity": "HIGH",
                },
                "expected_match": True,
            },
            {
                "name": "alternate branch and case-insensitive modifier",
                "event": {"module": "NETWORK", "destination": "EXAMPLE.TEST.INVALID"},
                "expected_match": True,
            },
            {
                "name": "different image misses",
                "event": {
                    "module": "process",
                    "message": "audit marker",
                    "image": "harmless.exe",
                    "pid": 123,
                    "signed": False,
                },
                "expected_match": False,
            },
            {
                "name": "absent fields miss",
                "event": {},
                "expected_match": False,
            },
        ],
        "performance": {"max_eval_ms": 100, "max_events_per_second": 1000},
        "rollback": {
            "previous_digest": None,
            "instructions": "Disable through Angerona DetectionForge after human review",
        },
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    }


@unittest.skipUnless(
    os.environ.get("DIVALIA_ANGERONA_SRC"),
    "set DIVALIA_ANGERONA_SRC for independent Angerona compatibility checks",
)
class AngeronaCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = Path(os.environ["DIVALIA_ANGERONA_SRC"]).resolve(strict=True)
        if not (cls.source / "angerona" / "core" / "detection_packages.py").is_file():
            raise ValueError("DIVALIA_ANGERONA_SRC must name an Angerona source src directory")
        cls.previous_path = list(sys.path)
        sys.path.insert(0, str(cls.source))
        try:
            cls.packages = importlib.import_module("angerona.core.detection_packages")
            if not Path(cls.packages.__file__).resolve().is_relative_to(cls.source):
                raise ValueError("Angerona was imported from a different source checkout")
        except BaseException:
            sys.path[:] = cls.previous_path
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        sys.path[:] = cls.previous_path

    def test_exported_seal_bytes_signature_and_all_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            private_key = Ed25519PrivateKey.generate()
            private_path = directory / "reviewer.pem"
            private_path.write_bytes(
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            path = directory / "package.json"
            receipt = export_detection(
                representative_package(), path, private_path, "compatibility-reviewer"
            )
            payload = path.read_bytes()
            document = json.loads(payload)
            self.assertEqual(document["digest"], self.packages.package_digest(document))
            expected_unsigned = json.dumps(
                {key: value for key, value in document.items() if key != "digest"},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
            self.assertEqual(self.packages.canonical_bytes(document), expected_unsigned)
            self.assertIn("安全".encode(), payload)
            self.packages.validate_package(document)
            package = self.packages.load_package(path)
            for fixture in document["fixtures"]:
                with self.subTest(fixture=fixture["name"]):
                    self.assertIs(package.evaluate(fixture["event"]), fixture["expected_match"])
            signature = json.loads(Path(receipt["signature_path"]).read_bytes())
            signature_bytes = base64.b64decode(signature["signature"], validate=True)
            private_key.public_key().verify(signature_bytes, payload)
            with self.assertRaises(InvalidSignature):
                private_key.public_key().verify(signature_bytes, payload + b" ")

    def test_digest_tampering_and_resealed_false_fixtures_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "package.json"
            export_detection(representative_package(), path)
            document = json.loads(path.read_bytes())
            document["owner"] = "tampered owner"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(self.packages.PackageValidationError, "digest"):
                self.packages.load_package(path)
            document["fixtures"][0]["expected_match"] = False
            document = self.packages.seal_package(document)
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(self.packages.PackageValidationError, "fixture failed"):
                self.packages.load_package(path)

    def test_severity_null_uses_angerona_event_normalization(self) -> None:
        document = representative_package()
        document["logic"]["detection"] = {
            "selection": {"severity": "none"},
            "condition": "selection",
        }
        document["fixtures"] = [
            {
                "name": "explicit null becomes None severity name",
                "event": {"severity": None},
                "expected_match": True,
            },
            {"name": "missing severity stays empty", "event": {}, "expected_match": False},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "package.json"
            export_detection(document, path)
            package = self.packages.load_package(path)
            self.assertTrue(package.evaluate({"severity": None}))
            self.assertFalse(package.evaluate({}))


if __name__ == "__main__":
    unittest.main()
