"""Streaming archive access preserves confinement and bounded JSON reads."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from divalia.storage import ArtifactStore


class ArtifactIterationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ArtifactStore(Path(self.temporary.name))
        for identifier in ("c", "a", "b"):
            self.store.save("briefings", identifier, {"id": identifier})

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_id_iteration_sorts_without_reading_json(self) -> None:
        with patch.object(self.store, "load", side_effect=AssertionError("unexpected JSON read")):
            self.assertEqual(list(self.store.iter_ids("briefings")), ["a", "b", "c"])

    def test_limited_values_load_only_requested_records(self) -> None:
        with patch.object(self.store, "load", wraps=self.store.load) as load:
            self.assertEqual(list(self.store.iter_values("briefings", limit=1)), [{"id": "a"}])
            load.assert_called_once_with("briefings", "a")
        self.assertEqual(self.store.list("briefings"), [{"id": "a"}, {"id": "b"}, {"id": "c"}])
        with patch.object(self.store, "load", side_effect=AssertionError("unexpected JSON read")):
            self.assertEqual(list(self.store.iter_values("briefings", limit=0)), [])

    def test_invalid_limits_categories_and_filenames_are_rejected(self) -> None:
        for value in (-1, True, 1.5, "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                list(self.store.iter_values("briefings", limit=value))
        with self.assertRaises(ValueError):
            list(self.store.iter_ids("../escape"))
        (self.store.root / "briefings" / "Bad-Name.json").write_text("{}")
        with self.assertRaises(ValueError):
            list(self.store.iter_ids("briefings"))

    def test_selected_symlink_is_rejected_before_read(self) -> None:
        target = self.store.root / "outside.json"
        target.write_text("{}")
        linked = self.store.root / "briefings" / "linked.json"
        try:
            linked.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("this account cannot create symlinks")
        with self.assertRaisesRegex(ValueError, "redirected"):
            list(self.store.iter_ids("briefings"))

    def test_unselected_malformed_content_is_not_loaded(self) -> None:
        self.store.path("briefings", "c").write_text("invalid JSON")
        self.assertEqual(len(list(self.store.iter_values("briefings", limit=2))), 2)
        with self.assertRaises(ValueError):
            self.store.list("briefings")


if __name__ == "__main__":
    unittest.main()
