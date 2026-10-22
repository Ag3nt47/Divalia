from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import unittest
from unittest.mock import AsyncMock, patch

from divalia.harness.ast_validator import validate_source
from divalia.harness.sandbox import (
    REPETITIONS,
    SandboxRunner,
    _CommandResult,
    _OutputLimit,
    _run_bounded,
    canonical_json,
    test_fingerprint as fixture_fingerprint,
)

SOURCE = """def detect(event: dict[str, Any]) -> dict | None:
    command = event.get("command_line", "").lower()
    if "-encodedcommand" in command:
        return {"rule_id": "encoded-command", "severity": "medium"}
    return None
"""
IMAGE = "registry.example/divalia-worker@sha256:" + "a" * 64


class AstPolicyTests(unittest.TestCase):
    def test_accepts_small_read_only_detector_and_binds_source(self):
        audit = validate_source(SOURCE)
        self.assertTrue(audit.passed, audit.issues)
        self.assertEqual(audit.source_sha256, hashlib.sha256(SOURCE.encode()).hexdigest())
        self.assertEqual(audit.to_dict()["score"], 100)

    def test_blocks_hostile_and_unbounded_constructs(self):
        hostile = [
            "import os\ndef detect(event):\n    return None",
            'def detect(event):\n    import subprocess\n    return subprocess.run(["whoami"])',
            'def detect(event):\n    return __import__("os").system("whoami")',
            'def detect(event):\n    return eval(event.get("code", ""))',
            'def detect(event):\n    return exec("pass")',
            'def detect(event):\n    return open("file", "w")',
            'def detect(event):\n    return getattr(event, "get")("x")',
            "def detect(event):\n    return event.__class__.__mro__",
            "def detect(event):\n    return event.get",
            'def detect(event):\n    return (event.get("callback"))()',
            'def detect(event):\n    return event.update({"x": 1})',
            'def detect(event):\n    event["x"] = 1\n    return None',
            "def detect(event):\n    event = {}\n    return event",
            'def detect(event):\n    str = event.get("x")\n    return str()',
            "def detect(event):\n    return detect(event)",
            "def detect(event):\n    return lambda: 1",
            "def detect(event):\n    return [x for x in event]",
            "def detect(event):\n    while True:\n        pass",
            "def detect(event):\n    for x in event:\n        pass",
            "def detect(event):\n    global flag\n    return None",
            "def detect(event):\n    def nested():\n        return None\n    return None",
            "class Escape:\n    pass\ndef detect(event):\n    return None",
            "@str\ndef detect(event):\n    return None",
            'def detect(event=eval("danger")):\n    return None',
            'def detect(event: eval("danger")):\n    return None',
            "async def detect(event):\n    return None",
            "def detect(event):\n    return str(**event)",
            "def detect(event):\n    return max(*event)",
            "def detect(event):\n    return {**event}",
            'def detect(event):\n    return "x" * 100000000000',
            "def detect(event):\n    return 9 ** 99999999999",
            'def detect(event):\n    return f"{1:10000000000}"',
        ]
        for source in hostile:
            with self.subTest(source=source):
                self.assertFalse(validate_source(source).passed)

    def test_caps_source_literals_nodes_and_depth(self):
        oversized = "def detect(event):\n    return None\n" + "# padding\n" * 4000
        literal = 'def detect(event):\n    return {"message": "' + "x" * 4097 + '"}'
        nodes = "def detect(event):\n" + "    x = 1\n" * 600 + "    return None\n"
        deep = "def detect(event):\n    return " + "[" * 50 + "0" + "]" * 50
        for source in [oversized, literal, nodes, deep, "not python ???"]:
            with self.subTest(source=source[:80]):
                self.assertFalse(validate_source(source).passed)

    def test_go_is_explicitly_unsupported(self):
        result = validate_source("package main", language="go")
        self.assertFalse(result.passed)
        self.assertIn("native sandbox", result.issues[0])


class DockerHarnessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.calls: list[tuple[list[str], bytes]] = []

    async def fake_command(self, args, payload=b"", timeout=5):
        self.calls.append((args, payload))
        if args[1] == "info":
            return _CommandResult(0, b"linux\n", b"")
        if args[1] == "image":
            return _CommandResult(0, b"sha256:" + b"b" * 64, b"")
        if args[1] == "rm":
            return _CommandResult(0, b"", b"")
        self.assertEqual(args[1], "run")
        request = json.loads(payload)
        response = {
            key: request[key]
            for key in ["protocol", "source_sha256", "telemetry_sha256", "test_sha256"]
        }
        response.update(
            passed=True,
            status="passed",
            outputs=[None for _ in request["events"]],
            metrics={"executions": len(request["events"]) * REPETITIONS},
        )
        return _CommandResult(0, canonical_json(response), b"")

    async def run_mocked(self, callback=None, telemetry=None):
        with (
            patch("divalia.harness.sandbox.shutil.which", return_value="docker.exe"),
            patch(
                "divalia.harness.sandbox._run_bounded", side_effect=callback or self.fake_command
            ),
        ):
            return await SandboxRunner(image=IMAGE).run(SOURCE, telemetry)

    async def test_container_command_is_hardened_and_fingerprints_bind_fixtures(self):
        fixtures = [{"event_type": "test"}, {"command_line": "normal"}]
        result = await self.run_mocked(telemetry=fixtures)
        self.assertTrue(result.passed, result.details)
        self.assertEqual(result.outputs, [None, None])
        self.assertEqual(
            result.telemetry_sha256, hashlib.sha256(canonical_json(fixtures)).hexdigest()
        )
        self.assertEqual(result.test_sha256, fixture_fingerprint(fixtures))
        self.assertEqual(result.source_sha256, validate_source(SOURCE).source_sha256)
        command = next(args for args, _ in self.calls if args[1] == "run")
        for flag, value in [
            ("--network", "none"),
            ("--cap-drop", "ALL"),
            ("--security-opt", "no-new-privileges=true"),
            ("--user", "65534:65534"),
            ("--memory", "128m"),
            ("--memory-swap", "128m"),
            ("--cpus", "1"),
            ("--pids-limit", "16"),
            ("--pull", "never"),
            ("--ipc", "none"),
        ]:
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn("--read-only", command)
        self.assertIn(IMAGE, command)
        self.assertNotIn("--mount", command)
        self.assertNotIn("--volume", command)
        self.assertEqual(command[-4:], ["-I", "-S", "-B", "/app/container_worker.py"])
        self.assertEqual(self.calls[-1][0][1:3], ["rm", "--force"])

    async def test_no_digest_or_no_docker_is_unavailable_without_execution(self):
        with patch("divalia.harness.sandbox._run_bounded", new_callable=AsyncMock) as command:
            missing = await SandboxRunner(image="python:latest").run(SOURCE)
            self.assertFalse(missing.passed)
            self.assertEqual(missing.status, "unavailable")
            command.assert_not_called()
            with patch("divalia.harness.sandbox.shutil.which", return_value=None):
                missing = await SandboxRunner(image=IMAGE).run(SOURCE)
            self.assertEqual(missing.status, "unavailable")
            command.assert_not_called()

    async def test_immutable_local_image_id_is_accepted(self):
        with (
            patch("divalia.harness.sandbox.shutil.which", return_value="docker.exe"),
            patch("divalia.harness.sandbox._run_bounded", side_effect=self.fake_command),
        ):
            result = await SandboxRunner(image="sha256:" + "b" * 64).run(SOURCE)
        self.assertTrue(result.passed, result.details)

    async def test_rejected_ast_does_not_call_docker(self):
        with patch("divalia.harness.sandbox._run_bounded", new_callable=AsyncMock) as command:
            result = await SandboxRunner(image=IMAGE).run("import os")
            self.assertEqual(result.status, "rejected")
            command.assert_not_called()

    async def test_empty_bad_or_non_json_fixtures_do_not_execute(self):
        for telemetry in [[], ["text"], [{"x": float("nan")}], [{"x": object()}], [{}] * 33]:
            with (
                self.subTest(telemetry=repr(telemetry)[:80]),
                patch("divalia.harness.sandbox._run_bounded", new_callable=AsyncMock) as command,
            ):
                result = await SandboxRunner(image=IMAGE).run(SOURCE, telemetry)
                self.assertEqual(result.status, "invalid_telemetry")
                command.assert_not_called()

    async def test_non_linux_engine_and_absent_image_fail_closed(self):
        async def no_linux(args, payload=b"", timeout=5):
            return _CommandResult(0, b"windows\n", b"")

        self.assertEqual((await self.run_mocked(no_linux)).status, "unavailable")

        async def missing_image(args, payload=b"", timeout=5):
            if args[1] == "image":
                return _CommandResult(1, b"", b"image absent")
            return await self.fake_command(args, payload, timeout)

        self.assertEqual((await self.run_mocked(missing_image)).status, "unavailable")
        self.assertFalse(any(args[1] == "run" for args, _ in self.calls))

    async def test_source_test_digest_and_output_count_mismatches_fail(self):
        for field, bad in [
            ("source_sha256", "0" * 64),
            ("test_sha256", "1" * 64),
            ("telemetry_sha256", "2" * 64),
            ("outputs", []),
            ("passed", False),
        ]:

            async def mismatched(args, payload=b"", timeout=5):
                result = await self.fake_command(args, payload, timeout)
                if args[1] == "run":
                    response = json.loads(result.stdout)
                    response[field] = bad
                    return _CommandResult(0, canonical_json(response), b"")
                return result

            with self.subTest(field=field):
                result = await self.run_mocked(mismatched)
                self.assertFalse(result.passed)
                self.assertEqual(result.status, "protocol_error")

    async def test_timeout_output_limit_and_crash_remove_container(self):
        for outcome, expected in [
            (TimeoutError(), "timeout"),
            (_OutputLimit("too much"), "output_limit"),
            (_CommandResult(137, b"", b"killed"), "failed"),
        ]:
            self.calls.clear()

            async def fail(args, payload=b"", timeout=5):
                if args[1] == "run":
                    self.calls.append((args, payload))
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome
                return await self.fake_command(args, payload, timeout)

            with self.subTest(expected=expected):
                result = await self.run_mocked(fail)
                self.assertFalse(result.passed)
                self.assertEqual(result.status, expected)
                self.assertEqual(self.calls[-1][0][1:3], ["rm", "--force"])

    async def test_cancellation_removes_container_and_propagates(self):
        started = asyncio.Event()

        async def block(args, payload=b"", timeout=5):
            if args[1] == "run":
                started.set()
                await asyncio.Event().wait()
            return await self.fake_command(args, payload, timeout)

        with (
            patch("divalia.harness.sandbox.shutil.which", return_value="docker.exe"),
            patch("divalia.harness.sandbox._run_bounded", side_effect=block),
        ):
            task = asyncio.create_task(SandboxRunner(image=IMAGE).run(SOURCE))
            await asyncio.wait_for(started.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(self.calls[-1][0][1:3], ["rm", "--force"])


class BoundedCommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_trusted_test_child_output_and_wall_clock_are_bounded(self):
        # These are fixed, trusted test helpers, never detector source.
        with self.assertRaises(_OutputLimit):
            await _run_bounded(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 300000)"], timeout=3
            )
        with self.assertRaises(TimeoutError):
            await _run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2)


if __name__ == "__main__":
    unittest.main()
