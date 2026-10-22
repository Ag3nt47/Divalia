"""Offline operator flows run in fresh processes and unrelated working directories."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
from importlib.resources import files
from pathlib import Path

import divalia


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.config = self.root / "offline.toml"
        self.config.write_text('[app]\nstate_dir="state"\n\n[sandbox]\nimage=""\n', encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def run_cli(self, *arguments: str, env: dict | None = None) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment["PATH"] = ""  # No Docker or external runtime is discoverable.
        if env:
            environment.update(env)
        return subprocess.run([sys.executable, "-m", "divalia", *arguments], cwd=self.root,
                              env=environment, capture_output=True, text=True, timeout=30)

    def test_version_and_demo_need_no_configuration_network_or_runtime(self):
        version = self.run_cli("--version")
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertEqual(version.stdout.strip(), divalia.__version__)
        demo = self.run_cli("--config", str(self.config), "demo")
        self.assertEqual(demo.returncode, 0, demo.stderr)
        report = json.loads(demo.stdout)
        self.assertEqual(report["offline_demo"], "passed")
        self.assertTrue(report["ast"]["passed"])
        self.assertIn("not attempted", report["python_execution"])
        self.assertFalse((self.root / "state").exists())

    def test_init_loads_resource_from_zip_installed_package_and_refuses_overwrite(self):
        # A zip-imported package has no ordinary repository-relative config path.
        # This catches accidental replacement of importlib.resources with Path(...).
        package_root = Path(divalia.__file__).parent
        bundle = self.root / "installed.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            for path in package_root.rglob("*"):
                if path.is_file() and path.suffix in {".py", ".toml"}:
                    archive.write(path, "divalia/" + path.relative_to(package_root).as_posix())
        output = self.root / "new-config.toml"
        invoked = self.run_cli("init", "--output", str(output), env={"PYTHONPATH": str(bundle)})
        self.assertEqual(invoked.returncode, 0, invoked.stderr)
        self.assertEqual(output.read_bytes(), files("divalia").joinpath("default_config.toml").read_bytes())
        parsed = tomllib.loads(output.read_text(encoding="utf-8"))
        self.assertIs(parsed["ai"]["allow_remote"], False)
        self.assertEqual(parsed["sandbox"]["image"], "")
        original = output.read_bytes()
        again = self.run_cli("init", "--output", str(output))
        self.assertEqual(again.returncode, 2)
        self.assertIn("already exists", again.stderr)
        self.assertEqual(output.read_bytes(), original)

    def test_validation_without_container_fails_closed_and_never_executes_source(self):
        source = self.root / "detector.py"
        source.write_text('def detect(event):\n    return None\n', encoding="utf-8")
        checked = self.run_cli("--config", str(self.config), "validate", str(source))
        self.assertEqual(checked.returncode, 2, checked.stderr)
        report = json.loads(checked.stdout)
        self.assertTrue(report["audit"]["passed"])
        self.assertFalse(report["sandbox"]["passed"])
        self.assertEqual(report["sandbox"]["status"], "unavailable")
        source.write_text('import pathlib\npathlib.Path("HOST_EXECUTED").write_text("bad")\n', encoding="utf-8")
        rejected = self.run_cli("--config", str(self.config), "validate", str(source))
        self.assertEqual(rejected.returncode, 2, rejected.stderr)
        report = json.loads(rejected.stdout)
        self.assertFalse(report["audit"]["passed"])
        self.assertIsNone(report["sandbox"])
        self.assertFalse((self.root / "HOST_EXECUTED").exists())

    def test_missing_malformed_and_invalid_config_errors_are_bounded(self):
        invalid_section = self.root / "bad.toml"
        invalid_section.write_text('app = "not a table"\n', encoding="utf-8")
        malformed = self.root / "malformed.toml"
        malformed.write_text('[app\n', encoding="utf-8")
        for config in (self.root / "missing.toml", invalid_section, malformed):
            with self.subTest(config=config.name):
                outcome = self.run_cli("--config", str(config), "providers")
                self.assertEqual(outcome.returncode, 2)
                self.assertIn("Divalia:", outcome.stderr)
                self.assertNotIn("Traceback", outcome.stderr)
        unknown_command = self.run_cli("unknown-command")
        self.assertEqual(unknown_command.returncode, 2)
        self.assertIn("invalid choice", unknown_command.stderr)
        invalid_limit = self.run_cli("--config", str(self.config), "once", "--limit", "0")
        self.assertEqual(invalid_limit.returncode, 2)
        self.assertIn("--limit", invalid_limit.stderr)


if __name__ == "__main__":
    unittest.main()
