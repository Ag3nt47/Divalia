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


@pytest.fixture
def image_repo(tmp_path, monkeypatch):
    from PIL import Image

    monkeypatch.setattr(publication, "ROOT", tmp_path)
    image = tmp_path / "docs" / "images" / "review.png"
    image.parent.mkdir(parents=True)
    Image.new("RGB", (16, 12), color="#336699").save(image, format="PNG")
    (tmp_path / "README.md").write_text(
        "![Review](docs/images/review.png)\n", encoding="utf-8"
    )
    publication.git("init", "--quiet")
    publication.git("add", "README.md", "docs/images/review.png")
    commit_images()
    return image


def commit_images():
    publication.git(
        "-c", "user.name=Offline test", "-c", "user.email=offline@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Reviewed image fixture",
    )


def test_tracked_decodable_head_png_is_accepted(image_repo):
    assert publication.relative_images() == [image_repo]


def test_duplicate_readme_images_are_verified_once(image_repo):
    with (publication.ROOT / "README.md").open("a", encoding="utf-8") as readme:
        readme.write('<img alt="Review again" src="docs/images/review.png">\n')
    assert publication.relative_images() == [image_repo]


def test_untracked_png_is_rejected(image_repo):
    publication.git("rm", "--cached", "--quiet", "docs/images/review.png")
    with pytest.raises(publication.PublicationError, match="untracked"):
        publication.relative_images()


def test_staged_image_different_from_head_is_rejected(image_repo):
    from PIL import Image

    Image.new("RGB", (16, 12), color="#993366").save(image_repo, format="PNG")
    publication.git("add", "docs/images/review.png")
    with pytest.raises(publication.PublicationError, match="reviewed HEAD bytes"):
        publication.relative_images()


@pytest.mark.parametrize("damage", ["invalid", "truncated", "checksum"])
def test_committed_corrupt_or_truncated_png_is_rejected(image_repo, damage):
    original = image_repo.read_bytes()
    if damage == "invalid":
        data = b"This is not a PNG image."
    elif damage == "truncated":
        data = original[:-12]
    else:
        # Preserve the header and dimensions but corrupt the IDAT checksum.
        data = bytearray(original)
        data[-13] ^= 0xFF
    image_repo.write_bytes(data)
    publication.git("add", "docs/images/review.png")
    commit_images()
    with pytest.raises(publication.PublicationError, match="corrupt or truncated"):
        publication.relative_images()


@pytest.mark.parametrize(
    "reference",
    [
        "../outside.png",
        "docs/../docs/images/review.png",
        "docs/%2e%2e/docs/images/review.png",
        "C:/outside.png",
        "/outside.png",
        "docs%5cimages%5creview.png",
        "docs/images/review.png?not-reviewed=1",
        "docs/images/%00review.png",
    ],
)
def test_unsafe_readme_path_is_rejected(image_repo, reference):
    (publication.ROOT / "README.md").write_text(
        f"![Unsafe]({reference})\n", encoding="utf-8"
    )
    with pytest.raises(publication.PublicationError, match="invalid README image path"):
        publication.relative_images()


def test_symlink_image_path_is_rejected(image_repo):
    alias = image_repo.with_name("alias.png")
    try:
        alias.symlink_to(image_repo.name)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this host")
    (publication.ROOT / "README.md").write_text(
        "![Alias](docs/images/alias.png)\n", encoding="utf-8"
    )
    with pytest.raises(publication.PublicationError, match="symlink"):
        publication.relative_images()


def test_image_byte_budget_is_enforced(image_repo, monkeypatch):
    monkeypatch.setattr(publication, "MAX_IMAGE_BYTES", len(image_repo.read_bytes()) - 1)
    with pytest.raises(publication.PublicationError, match="byte budget"):
        publication.relative_images()


def test_image_dimension_budget_is_enforced(image_repo, monkeypatch):
    monkeypatch.setattr(publication, "MAX_IMAGE_DIMENSION", 15)
    with pytest.raises(publication.PublicationError, match="dimensions are invalid"):
        publication.relative_images()


def test_missing_decoder_blocks_publication(image_repo, monkeypatch):
    import builtins

    original_import = builtins.__import__

    def without_pillow(name, *args, **kwargs):
        if name == "PIL":
            raise ImportError("No image decoder installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_pillow)
    with pytest.raises(publication.PublicationError, match="requires Pillow"):
        publication.relative_images()
