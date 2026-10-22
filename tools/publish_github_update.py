"""Publish only a clean, reviewed Divalia main commit; prove public visibility."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Ag3nt47/Divalia"
ORIGIN = f"https://github.com/{REPOSITORY}.git"
MAX_IMAGE_BYTES = 16 * 1024 * 1024
MAX_IMAGE_DIMENSION = 8192
MAX_IMAGE_PIXELS = 32 * 1024 * 1024


class PublicationError(RuntimeError):
    pass


def git(
    *args: str, check: bool = True, binary: bool = False
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    executable = shutil.which("git")
    if not executable:
        raise PublicationError("Git is unavailable")
    env = dict(os.environ)
    env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
    result = subprocess.run(
        [executable, "-c", "core.hooksPath=", "-C", str(ROOT), *args],
        env=env,
        capture_output=True,
        text=not binary,
        timeout=120,
        check=False,
    )
    if check and result.returncode:
        # Avoid echoing arbitrary transport output or credential-helper messages.
        raise PublicationError(f"Git command failed: {args[0]} (exit {result.returncode})")
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PublicationError("publication HTTP redirects are forbidden")


def http(
    url: str, *, token: str = "", body: dict | None = None, method: str | None = None
) -> bytes:
    if urlsplit(url).hostname not in {"api.github.com", "raw.githubusercontent.com"}:
        raise PublicationError("noncanonical publication HTTP destination")
    headers = {
        "User-Agent": "Divalia-publication-verifier",
        "Accept": "application/vnd.github+json",
    }
    if token:
        if urlsplit(url).hostname != "api.github.com":
            raise PublicationError("credentials must never be sent to an asset host")
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    with opener.open(req, timeout=60) as response:
        value = response.read(16 * 1024 * 1024 + 1)
    if len(value) > 16 * 1024 * 1024:
        raise PublicationError("publication HTTP response exceeds byte budget")
    return value


def github_token() -> str:
    """Read an existing OS credential in memory; never log it or persist it."""
    executable = shutil.which("git")
    if not executable:
        raise PublicationError("Git credential manager unavailable")
    env = dict(os.environ)
    env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
    result = subprocess.run(
        [executable, "credential", "fill"],
        input="protocol=https\nhost=github.com\nusername=Ag3nt47\n\n",
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if result.returncode or not fields.get("password"):
        raise PublicationError("no existing GitHub OS credential available")
    return fields["password"]


def create_repository() -> None:
    token = github_token()
    user = json.loads(http("https://api.github.com/user", token=token))
    if user.get("login") != "Ag3nt47":
        raise PublicationError("GitHub credential owner must equal Ag3nt47")
    try:
        metadata = json.loads(http(f"https://api.github.com/repos/{REPOSITORY}", token=token))
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise PublicationError(f"GitHub repository lookup failed (HTTP {exc.code})") from None
        metadata = json.loads(
            http(
                "https://api.github.com/user/repos",
                token=token,
                body={
                    "name": "Divalia",
                    "private": False,
                    "auto_init": False,
                    "description": "Standalone, optional module development and deployment tool for Angerona Security Suite, with AI synthesis, validation and human review.",
                    "has_issues": True,
                    "has_wiki": False,
                },
            )
        )
    if metadata.get("full_name") != REPOSITORY or metadata.get("private") is not False:
        raise PublicationError("repository identity or public visibility is incorrect")


def relative_images() -> list[Path]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    urls = re.findall(r"!\[[^\]]*\]\(([^)\s]+)\)", text)
    urls += re.findall(r"<img\b[^>]*\bsrc=[\"\']([^\"\']+)[\"\']", text, re.I)
    paths = []
    for url in urls:
        if re.match(r"^[A-Za-z]:", url):
            raise PublicationError(f"invalid README image path: {url}")
        if urlsplit(url).scheme or url.startswith("//"):
            continue
        parsed = urlsplit(url)
        decoded = unquote(parsed.path)
        if (
            not decoded
            or "\\" in decoded
            or "\x00" in decoded
            or parsed.query
        ):
            raise PublicationError(f"invalid README image path: {url}")
        relative = Path(decoded)
        resolved = (ROOT / relative).resolve()
        if (
            ".." in relative.parts
            or relative.drive
            or relative.is_absolute()
            or not resolved.is_relative_to(ROOT.resolve())
            or not resolved.is_file()
        ):
            raise PublicationError(f"invalid README image path: {url}")
        component = ROOT
        for part in relative.parts:
            component = component / part
            if component.is_symlink():
                raise PublicationError(f"README image path contains a symlink: {url}")
        if relative.suffix.lower() != ".png":
            raise PublicationError(f"README images must be static PNG files: {url}")
        tracked = git("ls-files", "--error-unmatch", "--", relative.as_posix(), check=False)
        if tracked.returncode:
            raise PublicationError(f"README image is untracked: {url}")
        with resolved.open("rb") as image_file:
            data = image_file.read(MAX_IMAGE_BYTES + 1)
        if not data or len(data) > MAX_IMAGE_BYTES:
            raise PublicationError(f"README image exceeds the byte budget or is empty: {url}")
        reviewed = git("show", f"HEAD:{relative.as_posix()}", binary=True).stdout
        if reviewed != data:
            raise PublicationError(f"README image differs from reviewed HEAD bytes: {url}")
        _validate_png(data, url)
        if resolved not in paths:
            paths.append(resolved)
    return paths


def _validate_png(data: bytes, url: str) -> None:
    """Decode both PNG structure and pixels before any publication can begin."""
    try:
        from PIL import Image, ImageFile
    except ImportError:
        raise PublicationError(
            "README image validation requires Pillow; install the project's dev dependencies"
        ) from None
    # A caller must not silently weaken the decoder's truncated-file checks.
    if ImageFile.LOAD_TRUNCATED_IMAGES:
        raise PublicationError("README image validation requires strict truncated-image checks")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as candidate:
                width, height = candidate.size
                if (
                    candidate.format != "PNG"
                    or getattr(candidate, "n_frames", 1) != 1
                    or width < 1
                    or height < 1
                    or width > MAX_IMAGE_DIMENSION
                    or height > MAX_IMAGE_DIMENSION
                    or width * height > MAX_IMAGE_PIXELS
                ):
                    raise PublicationError(f"README image format or dimensions are invalid: {url}")
                candidate.verify()
            with Image.open(io.BytesIO(data)) as candidate:
                candidate.load()
    except PublicationError:
        raise
    except (
        OSError,
        SyntaxError,
        ValueError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ):
        raise PublicationError(f"README image is corrupt or truncated: {url}") from None


def publish(*, create: bool = False) -> dict:
    if git("status", "--porcelain=v1", "--untracked-files=all").stdout.strip():
        raise PublicationError("publication requires a clean worktree")
    for args in (
        ("remote", "get-url", "--all", "origin"),
        ("remote", "get-url", "--push", "--all", "origin"),
    ):
        if git(*args).stdout.strip() != ORIGIN:
            raise PublicationError(f"origin must be exactly {ORIGIN}")
    branch = git("branch", "--show-current").stdout.strip()
    if branch != "main":
        raise PublicationError("reviewed current branch must be main")
    head = git("rev-parse", "HEAD").stdout.strip()
    images = relative_images()
    if create:
        create_repository()
    before = git("ls-remote", ORIGIN, "refs/heads/main").stdout.strip()
    previous = before.split()[0] if before else None
    if previous:
        git("fetch", "--no-tags", ORIGIN, "refs/heads/main")
        if git("merge-base", "--is-ancestor", previous, head, check=False).returncode:
            counts = git(
                "rev-list", "--left-right", "--count", f"{head}...{previous}"
            ).stdout.strip()
            raise PublicationError(
                f"main diverged: local={head}, public={previous}, local/public-only={counts}"
            )
    git("push", "--atomic", "origin", f"{head}:refs/heads/main")
    metadata = json.loads(http(f"https://api.github.com/repos/{REPOSITORY}"))
    if metadata.get("default_branch") != "main" or metadata.get("private") is not False:
        raise PublicationError("GitHub must expose public default main")
    remote = git("ls-remote", "--symref", ORIGIN, "HEAD", "refs/heads/main").stdout
    if "ref: refs/heads/main\tHEAD" not in remote:
        raise PublicationError("GitHub HEAD does not name main")
    main_lines = [line for line in remote.splitlines() if line.endswith("\trefs/heads/main")]
    if main_lines != [f"{head}\trefs/heads/main"]:
        raise PublicationError("public main differs from reviewed HEAD")
    readme = http(f"https://raw.githubusercontent.com/{REPOSITORY}/main/README.md")
    if readme != (ROOT / "README.md").read_bytes():
        raise PublicationError("public README differs from checked-out bytes")
    for path in images:
        url = f"https://raw.githubusercontent.com/{REPOSITORY}/main/{path.relative_to(ROOT).as_posix()}"
        if http(url) != path.read_bytes():
            raise PublicationError("public README image differs from checked-out bytes")
    final_main = git("ls-remote", ORIGIN, "refs/heads/main").stdout.strip()
    if (
        git("rev-parse", "HEAD").stdout.strip() != head
        or git("branch", "--show-current").stdout.strip() != branch
        or final_main != f"{head}\trefs/heads/main"
        or git("status", "--porcelain=v1", "--untracked-files=all").stdout.strip()
    ):
        raise PublicationError("worktree or HEAD changed during publication")
    return {
        "repository": f"https://github.com/{REPOSITORY}",
        "branch": branch,
        "head": head,
        "previous_main": previous,
        "fast_forward": True,
        "public_default_main_verified": True,
        "clean": True,
        "readme_sha256": hashlib.sha256(readme).hexdigest(),
        "readme_images_verified": len(images),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create-repository", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(publish(create=args.create_repository), indent=2))
        return 0
    except (PublicationError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Publication incomplete: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
