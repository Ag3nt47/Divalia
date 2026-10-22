"""Opt-in real-container checks; ordinary offline checks do not need Docker."""

import os
import unittest

from divalia.harness.sandbox import SandboxRunner


@unittest.skipUnless(
    os.environ.get("DIVALIA_TEST_SANDBOX_IMAGE"),
    "set DIVALIA_TEST_SANDBOX_IMAGE to a built immutable worker image",
)
class LiveSandboxTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_worker_accepts_a_detector_and_preserves_fixture_order(self):
        source = """def detect(event):
    if event.get("marker") == "alert":
        return {"severity": "high", "rule_id": "fixture"}
    return None
"""
        result = await SandboxRunner(image=os.environ["DIVALIA_TEST_SANDBOX_IMAGE"]).run(
            source, [{"marker": "clear"}, {"marker": "alert"}]
        )
        self.assertTrue(result.passed, result.to_dict())
        self.assertEqual(result.outputs, [None, {"severity": "high", "rule_id": "fixture"}])
        self.assertEqual(result.metrics["executions"], 16)

    async def test_real_worker_fails_on_detector_exception(self):
        source = 'def detect(event):\n    return event["missing_required_field"]\n'
        result = await SandboxRunner(image=os.environ["DIVALIA_TEST_SANDBOX_IMAGE"]).run(
            source, [{}]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.status, "failed")


if __name__ == "__main__":
    unittest.main()
