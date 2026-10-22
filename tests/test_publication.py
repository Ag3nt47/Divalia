"""Offline completion gates; these tests never contact GitHub."""

import importlib.util
import subprocess
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "divalia_publication",
    Path(__file__).resolve().parents[1] / "tools" / "publish_github_update.py",
)
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)


def result(output="", status=0):
    return subprocess.CompletedProcess([], status, output, "")


def test_dirty_tree_prevents_any_network(monkeypatch):
    monkeypatch.setattr(publication, "git", lambda *args, **kw: result(" M source.py\n"))
    monkeypatch.setattr(publication, "http", lambda *a, **k: pytest.fail("network attempted"))
    with pytest.raises(publication.PublicationError, match="clean worktree"):
        publication.publish()


@pytest.mark.parametrize(
    "bad_remote",
    [
        "git@github.com:Ag3nt47/Divalia.git",
        "https://github.com/attacker/Divalia.git",
        "https://github.com/Ag3nt47/Divalia.git\nhttps://example.invalid/repo.git",
    ],
)
def test_noncanonical_origin_prevents_publish(monkeypatch, bad_remote):
    monkeypatch.setattr(
        publication, "git", lambda *args, **kw: result("" if args[0] == "status" else bad_remote)
    )
    with pytest.raises(publication.PublicationError, match="origin must"):
        publication.publish()


def test_divergence_never_pushes(monkeypatch):
    calls = []

    def fake_git(*args, **kw):
        calls.append(args)
        if args[0] == "status":
            return result()
        if args[0] == "remote":
            return result(publication.ORIGIN)
        if args[0] == "branch":
            return result("main")
        if args[0] == "rev-parse":
            return result("a" * 40)
        if args[0] == "ls-remote":
            return result("b" * 40 + "\trefs/heads/main\n")
        if args[0] == "merge-base":
            return result(status=1)
        if args[0] == "rev-list":
            return result("3\t2")
        return result()

    monkeypatch.setattr(publication, "git", fake_git)
    monkeypatch.setattr(publication, "relative_images", lambda: [])
    with pytest.raises(
        publication.PublicationError, match="main diverged: local=.*local/public-only=3"
    ):
        publication.publish()
    assert not any(args[0] == "push" for args in calls)


def test_readme_assets_are_never_silently_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(publication, "ROOT", tmp_path)
    (tmp_path / "README.md").write_text("![missing](missing.png)", encoding="utf-8")
    with pytest.raises(publication.PublicationError, match="invalid README image"):
        publication.relative_images()
