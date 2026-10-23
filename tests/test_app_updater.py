"""Offline source-updater tests: real temporary Git, injected metadata/transport."""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from divalia.integration import app_updater as updater


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        [shutil.which("git"), *args],
        cwd=root,
        capture_output=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )
    return result.stdout.decode().strip()


class Checkout:
    def __init__(self, directory: Path):
        self.upstream = directory / "upstream"
        self.upstream.mkdir()
        git(self.upstream, "init", "-b", "main")
        git(self.upstream, "config", "user.name", "Offline tests")
        git(self.upstream, "config", "user.email", "tests@example.invalid")
        (self.upstream / "detector.txt").write_text("original\n")
        (self.upstream / ".gitignore").write_text("ignored/\n")
        (self.upstream / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["setuptools>=75"]\nbuild-backend = "setuptools.build_meta"\n'
            '[project]\nname = "example"\nversion = "1.0.0"\nrequires-python = ">=3.11"\n'
            'dependencies = []\n[project.scripts]\nexample = "example:main"\n'
        )
        git(self.upstream, "add", ".")
        git(self.upstream, "commit", "-m", "initial")
        self.root = directory / "checkout"
        git(directory, "clone", str(self.upstream), str(self.root))
        git(self.root, "config", "user.name", "Offline tests")
        git(self.root, "config", "user.email", "tests@example.invalid")
        git(self.root, "remote", "set-url", "origin", updater.ORIGIN)
        self.base = git(self.root, "rev-parse", "HEAD")
        self.target = self.base
        self.clock = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)
        self.requests = 0
        self.fetches = 0
        self.commands: list[list[str]] = []
        self.offline = False
        self.manager = updater.UpdateManager(
            self.root,
            fetcher=self.fetcher,
            runner=self.runner,
            now=lambda: self.clock,
        )

    def commit(self, name: str = "detector.txt", text: str = "updated\n") -> str:
        path = self.upstream / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(text)
        git(self.upstream, "add", ".")
        git(self.upstream, "commit", "-m", "update")
        self.target = git(self.upstream, "rev-parse", "HEAD")
        return self.target

    def fetcher(self) -> str:
        self.requests += 1
        # The attempt is persisted before any network request.
        state = json.loads((self.root / ".git/divalia-updater/check.json").read_text())
        assert state["target"] == ""
        if self.offline:
            raise updater.UpdateError("offline")
        return self.target

    def runner(self, command: list[str], **kwargs) -> bytes:
        self.commands.append(command)
        if "fetch" in command:
            self.fetches += 1
            assert updater.ORIGIN in command
            command = [str(self.upstream) if item == updater.ORIGIN else item for item in command]
            command = [
                "protocol.file.allow=always" if item == "protocol.file.allow=never" else item
                for item in command
            ]
        return updater._run(command, **kwargs)


@pytest.fixture
def checkout(tmp_path: Path) -> Checkout:
    if not shutil.which("git"):
        pytest.skip("Git is required for offline updater tests")
    return Checkout(tmp_path)


def test_daily_metadata_cache_force_floor_and_new_day(checkout: Checkout):
    first = checkout.manager.check()
    assert first.state == "current"
    assert not first.checked_today
    assert checkout.manager.check().checked_today
    assert checkout.manager.check(force=True).checked_today
    assert checkout.requests == 1
    assert checkout.fetches == 0
    checkout.clock += dt.timedelta(minutes=16)
    assert not checkout.manager.check(force=True).checked_today
    assert checkout.requests == 2
    checkout.clock += dt.timedelta(days=1)
    checkout.manager.check()
    assert checkout.requests == 3


def test_outage_and_crash_attempt_consume_daily_check(checkout: Checkout):
    checkout.offline = True
    assert checkout.manager.check().state == "unavailable"
    checkout.offline = False
    assert checkout.manager.check().state == "unavailable"
    assert checkout.requests == 1
    checkout.clock += dt.timedelta(days=1)
    assert checkout.manager.check().state == "current"
    assert checkout.requests == 2


def test_exact_fast_forward_updates_and_releases_gate(checkout: Checkout):
    target = checkout.commit()
    status = checkout.manager.check()
    assert target in status.compare_url and checkout.base in status.compare_url
    assert checkout.fetches == 0
    result = checkout.manager.apply(status, approved_sha=target)
    assert result.state == "updated"
    assert git(checkout.root, "rev-parse", "HEAD") == target
    assert not git(checkout.root, "status", "--porcelain")
    assert checkout.fetches == 1
    # No lingering updater lock prevents the next normal application command.
    with updater.application_use(checkout.root):
        pass


def test_decline_noninteractive_and_explicit_check_download_nothing(checkout: Checkout, capsys):
    checkout.commit()
    for options, interactive, answer in [
        ([], False, "must-not-prompt"),
        (["--check-only"], True, "must-not-prompt"),
        ([], True, ""),
        ([], True, "yes"),
        ([], True, "update " + checkout.target[:12]),
    ]:

        def respond(_):
            assert answer != "must-not-prompt"
            return answer

        assert (
            updater.main(
                options,
                root=checkout.root,
                manager_factory=lambda _: checkout.manager,
                input_fn=respond,
                interactive=interactive,
            )
            == 0
        )
    assert checkout.fetches == 0
    assert git(checkout.root, "rev-parse", "HEAD") == checkout.base
    assert "Observed main:" in capsys.readouterr().out


def test_full_commit_approval_applies(checkout: Checkout):
    checkout.commit()
    assert (
        updater.main(
            [],
            root=checkout.root,
            manager_factory=lambda _: checkout.manager,
            input_fn=lambda _: "update " + checkout.target,
            interactive=True,
        )
        == 0
    )
    assert checkout.fetches == 1
    assert git(checkout.root, "rev-parse", "HEAD") == checkout.target


@pytest.mark.parametrize("mutation", ["approval", "base", "target"])
def test_changed_approval_identity_never_fetches(checkout: Checkout, mutation: str):
    target = checkout.commit()
    status = checkout.manager.check()
    approval = target
    if mutation == "approval":
        approval = "0" * 40
    elif mutation == "base":
        status = dataclasses.replace(status, current_sha="0" * 40)
    else:
        checkout.clock += dt.timedelta(minutes=16)
        checkout.commit(text="another update\n")
        checkout.manager.check(force=True)
    with pytest.raises(updater.UpdateError, match="Approval|changed"):
        checkout.manager.apply(status, approved_sha=approval)
    assert checkout.fetches == 0


@pytest.mark.parametrize(
    "mutation",
    [
        "tracked",
        "untracked",
        "origin",
        "branch",
        "filter",
        "rewrite",
        "include",
        "submodule",
        "hidden-index",
    ],
)
def test_unsafe_or_dirty_checkout_refuses_before_code_download(checkout: Checkout, mutation: str):
    checkout.commit()
    status = checkout.manager.check()
    if mutation == "tracked":
        (checkout.root / "detector.txt").write_text("user changes\n")
    elif mutation == "untracked":
        (checkout.root / "user-notes.txt").write_text("private\n")
    elif mutation == "origin":
        git(checkout.root, "remote", "set-url", "origin", "https://example.invalid/other.git")
    elif mutation == "branch":
        git(checkout.root, "checkout", "-b", "feature")
    elif mutation == "filter":
        git(checkout.root, "config", "filter.trick.smudge", "bad-command")
    elif mutation == "rewrite":
        git(
            checkout.root, "config", "url.https://example.invalid/.insteadOf", "https://github.com/"
        )
    elif mutation == "include":
        git(checkout.root, "config", "include.path", "not-loaded")
    elif mutation == "submodule":
        (checkout.root / ".gitmodules").write_text("[submodule x]\npath = x\n")
    else:
        git(checkout.root, "update-index", "--assume-unchanged", "detector.txt")
    with pytest.raises(updater.UpdateError):
        checkout.manager.apply(status, approved_sha=checkout.target)
    assert checkout.fetches == 0
    assert git(checkout.root, "rev-parse", "HEAD") == checkout.base


def test_divergence_is_not_merged_or_reset(checkout: Checkout):
    checkout.commit()
    (checkout.root / "local.txt").write_text("local commit\n")
    git(checkout.root, "add", ".")
    git(checkout.root, "commit", "-m", "local")
    local = git(checkout.root, "rev-parse", "HEAD")
    status = checkout.manager.check()
    with pytest.raises(updater.UpdateError, match="diverged"):
        checkout.manager.apply(status, approved_sha=checkout.target)
    assert git(checkout.root, "rev-parse", "HEAD") == local
    assert (checkout.root / "local.txt").exists()


@pytest.mark.parametrize(
    "filename",
    [
        "requirements.txt",
        "requirements/dev.in",
        "uv.lock",
        "setup.cfg",
        "Dockerfile",
        "harness/Containerfile",
        ".dockerignore",
        "pylock.toml",
        ".python-version",
    ],
)
def test_dependency_inputs_are_held_after_approved_fetch(checkout: Checkout, filename: str):
    checkout.commit(filename, "changed setup\n")
    status = checkout.manager.check()
    result = checkout.manager.apply(status, approved_sha=checkout.target)
    assert result.state == "manual_setup"
    assert "reinstall" in result.message
    assert checkout.fetches == 1
    assert git(checkout.root, "rev-parse", "HEAD") == checkout.base


@pytest.mark.parametrize("field", ["dependency", "entrypoint", "python", "build"])
def test_pyproject_setup_changes_are_held(checkout: Checkout, field: str):
    text = (checkout.upstream / "pyproject.toml").read_text()
    replacements = {
        "dependency": ("dependencies = []", 'dependencies = ["new-package"]'),
        "entrypoint": ('example = "example:main"', 'example = "example:new_main"'),
        "python": ('requires-python = ">=3.11"', 'requires-python = ">=3.13"'),
        "build": ("setuptools>=75", "setuptools>=99"),
    }
    text = text.replace(*replacements[field])
    checkout.commit("pyproject.toml", text)
    result = checkout.manager.apply(checkout.manager.check(), approved_sha=checkout.target)
    assert result.state == "manual_setup"
    assert git(checkout.root, "rev-parse", "HEAD") == checkout.base


def test_pyproject_version_and_metadata_only_can_update(checkout: Checkout):
    text = (
        (checkout.upstream / "pyproject.toml")
        .read_text()
        .replace('version = "1.0.0"', 'version = "1.0.1"')
    )
    checkout.commit("pyproject.toml", text)
    result = checkout.manager.apply(checkout.manager.check(), approved_sha=checkout.target)
    assert result.state == "updated"


def test_active_runtime_lease_refuses_then_normal_exit_allows_update(checkout: Checkout):
    checkout.commit()
    status = checkout.manager.check()
    with updater.application_use(checkout.root):
        with pytest.raises(updater.UpdateError, match="running"):
            checkout.manager.apply(status, approved_sha=checkout.target)
        assert checkout.fetches == 0
    assert not list((checkout.root / ".git/divalia-updater/leases").iterdir())
    assert checkout.manager.apply(status, approved_sha=checkout.target).state == "updated"


def test_dead_lease_is_recognized_by_os_lock_not_pid(checkout: Checkout):
    checkout.commit()
    status = checkout.manager.check()
    directory = checkout.root / ".git/divalia-updater/leases"
    # Simulates a process killed after creating/acquiring its lease. The unlocked
    # file intentionally has no PID or clock heuristics.
    abandoned = directory / ("a" * 32 + ".lock")
    abandoned.write_bytes(b"\0")
    assert checkout.manager.apply(status, approved_sha=checkout.target).state == "updated"
    assert not abandoned.exists()


def test_gate_blocks_new_application_startup(checkout: Checkout):
    checkout.manager.check()
    with updater._gate(checkout.manager.state_dir):
        with pytest.raises(updater.UpdateError, match="progress"):
            with updater.application_use(checkout.root):
                pytest.fail("must not enter the running application")


def test_real_child_lease_survives_until_process_exit(checkout: Checkout):
    checkout.commit()
    status = checkout.manager.check()
    code = (
        "import sys; from pathlib import Path; "
        "from divalia.integration.app_updater import application_use; "
        "lease=application_use(Path(sys.argv[1])); lease.__enter__(); "
        "print('ready', flush=True); sys.stdin.read()"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(updater.__file__).parents[2])}
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(checkout.root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "ready"
        with pytest.raises(updater.UpdateError, match="running"):
            checkout.manager.apply(status, approved_sha=checkout.target)
        child.kill()  # Only this test-owned process; simulates abnormal termination.
        child.communicate(timeout=10)
        assert checkout.manager.apply(status, approved_sha=checkout.target).state == "updated"
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)


def test_launcher_forwards_argv_after_updater_unlock(checkout: Checkout):
    checkout.commit()
    forwarded = []

    def launch(arguments):
        with updater.application_use(checkout.root):
            assert git(checkout.root, "rev-parse", "HEAD") == checkout.target
            forwarded.extend(arguments)
        return 37

    result = updater.main(
        ["--run", "--config", "a path/divalia.toml", "daemon", "--interval", "180"],
        root=checkout.root,
        manager_factory=lambda _: checkout.manager,
        input_fn=lambda _: "update " + checkout.target,
        interactive=True,
        launch=launch,
    )
    assert result == 37
    assert forwarded == ["--config", "a path/divalia.toml", "daemon", "--interval", "180"]


def test_noncheckout_gets_manual_reinstall_guidance(tmp_path: Path):
    manager = updater.UpdateManager(tmp_path, fetcher=lambda: pytest.fail("must not query GitHub"))
    with pytest.raises(updater.UpdateError, match="Reinstall"):
        manager.check()
    with updater.application_use(tmp_path):
        pass


def test_symlinked_state_is_rejected(checkout: Checkout, tmp_path: Path):
    other = tmp_path / "other"
    other.mkdir()
    try:
        (checkout.root / ".git/divalia-updater").symlink_to(other, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is not permitted on this host")
    with pytest.raises(updater.UpdateError, match="symlinks"):
        checkout.manager.check()


def test_linked_worktree_can_run_but_requires_manual_updates(checkout: Checkout, tmp_path: Path):
    linked = tmp_path / "linked"
    git(checkout.root, "worktree", "add", "-b", "linked-test", str(linked))
    assert (linked / ".git").is_file()
    with updater.application_use(linked):
        assert not (linked / ".git/divalia-updater").exists()
    with pytest.raises(updater.UpdateError, match="directory"):
        updater.UpdateManager(linked).check()


def test_ignored_user_file_collision_is_not_overwritten(checkout: Checkout):
    remote_file = checkout.upstream / "ignored/user.txt"
    remote_file.parent.mkdir()
    remote_file.write_text("new tracked content\n")
    git(checkout.upstream, "add", "-f", "ignored/user.txt")
    git(checkout.upstream, "commit", "-m", "new tracked file")
    checkout.target = git(checkout.upstream, "rev-parse", "HEAD")
    user_file = checkout.root / "ignored/user.txt"
    user_file.parent.mkdir()
    user_file.write_bytes(b"private original user content\x00")
    assert not git(checkout.root, "status", "--porcelain")
    with pytest.raises(updater.UpdateError):
        checkout.manager.apply(checkout.manager.check(), approved_sha=checkout.target)
    assert user_file.read_bytes() == b"private original user content\x00"
    assert git(checkout.root, "rev-parse", "HEAD") == checkout.base


def test_local_autostash_setting_never_stashes_concurrent_user_edit(checkout: Checkout):
    checkout.commit()
    git(checkout.root, "config", "merge.autoStash", "true")
    status = checkout.manager.check()

    def concurrent_edit(command, **kwargs):
        if "merge" in command:
            (checkout.root / "detector.txt").write_text("concurrent user edit\n")
        return checkout.runner(command, **kwargs)

    checkout.manager.runner = concurrent_edit
    with pytest.raises(updater.UpdateError):
        checkout.manager.apply(status, approved_sha=checkout.target)
    assert git(checkout.root, "rev-parse", "HEAD") == checkout.base
    assert (checkout.root / "detector.txt").read_text() == "concurrent user edit\n"
    assert not git(checkout.root, "stash", "list")


@pytest.mark.parametrize("timestamp", [True, False, float("nan"), float("inf"), 0, -1])
def test_invalid_saved_timestamp_never_triggers_a_request(checkout: Checkout, timestamp):
    checkout.manager.check()
    path = checkout.root / ".git/divalia-updater/check.json"
    record = json.loads(path.read_text())
    record["checked_at"] = timestamp
    path.write_text(json.dumps(record))
    with pytest.raises(updater.UpdateError, match="Invalid updater state"):
        checkout.manager.check(force=True)
    assert checkout.requests == 1


@pytest.mark.parametrize(
    "status,payload,length",
    [
        (200, b'{"commit":{"sha":"' + b"a" * 40 + b'"}}', None),
        (302, b"{}", None),
        (200, b'{"commit":{"sha":"bad"}}', None),
        (200, b"x" * (updater.MAX_STATE_BYTES + 1), None),
        (200, b"{}", str(updater.MAX_STATE_BYTES + 1)),
        (200, b"{}", "-1"),
    ],
    ids=["valid", "redirect", "bad-sha", "oversized-body", "oversized-length", "negative-length"],
)
def test_github_response_is_bounded_and_redirects_are_not_followed(
    monkeypatch, status, payload, length
):
    class Response:
        def __init__(self):
            self.status = status
            self.offset = 0

        def getheader(self, _):
            return length

        def read1(self, amount):
            result = payload[self.offset : self.offset + amount]
            self.offset += len(result)
            return result

    calls = []

    class Connection:
        sock = None

        def __init__(self, host, timeout):
            assert host == "api.github.com" and timeout == 12

        def request(self, method, path, headers):
            calls.append((method, path))

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(updater.http.client, "HTTPSConnection", Connection)
    if status == 200 and payload.startswith(b'{"commit":{"sha":"aaaa'):
        assert updater._github_head_http() == "a" * 40
    else:
        with pytest.raises(updater.UpdateError):
            updater._github_head_http()
    assert calls == [("GET", updater.METADATA_PATH)]


def test_git_subprocess_timeout_is_bounded_and_owned_process_is_reaped(tmp_path: Path):
    with pytest.raises(updater.UpdateError, match="timed out"):
        updater._run(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=1,
        )


def test_git_subprocess_output_is_bounded(tmp_path: Path):
    with pytest.raises(updater.UpdateError, match="size limit"):
        updater._run(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * (9 * 1024 * 1024))"],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=10,
        )


def test_owned_descendant_is_retired_even_when_parent_exits_and_closes_stdout(tmp_path: Path):
    marker = tmp_path / "escaped.txt"
    child_code = (
        "import time; from pathlib import Path; time.sleep(1); "
        f"Path({str(marker)!r}).write_text('escaped')"
    )
    parent_code = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
    )
    assert (
        updater._run(
            [sys.executable, "-c", parent_code], cwd=tmp_path, env=dict(os.environ), timeout=10
        )
        == b""
    )
    time.sleep(1.3)
    assert not marker.exists()


def test_filesystem_error_during_apply_never_launches_unverified_app(checkout: Checkout):
    checkout.commit()

    def fail(*_, **__):
        raise OSError("private filesystem detail")

    checkout.manager.apply = fail
    assert (
        updater.main(
            ["--run", "doctor"],
            root=checkout.root,
            manager_factory=lambda _: checkout.manager,
            input_fn=lambda _: "update " + checkout.target,
            interactive=True,
            launch=lambda _: pytest.fail("an unverified update must not launch"),
        )
        == 2
    )


def test_first_start_on_new_calendar_day_checks_even_after_recent_check(checkout: Checkout):
    checkout.clock = dt.datetime(2026, 10, 23, 23, 59, tzinfo=dt.timezone.utc)
    checkout.manager.check()
    checkout.clock += dt.timedelta(minutes=2)
    assert not checkout.manager.check().checked_today
    assert checkout.requests == 2
    assert checkout.manager.check(force=True).checked_today
    assert checkout.requests == 2


def _slow_metadata_worker(channel):
    time.sleep(60)


def _valid_metadata_worker(channel):
    channel.send_bytes(b"a" * 40)
    channel.close()


def _oversized_metadata_worker(channel):
    channel.send_bytes(b"x" * 1024)
    channel.close()


def test_metadata_deadline_retires_owned_worker_even_during_dns():
    before = {child.pid for child in multiprocessing.active_children()}
    started = time.monotonic()
    with pytest.raises(updater.UpdateError, match="timed out"):
        updater._bounded_metadata(_slow_metadata_worker, seconds=0.3)
    assert time.monotonic() - started < 8
    assert {child.pid for child in multiprocessing.active_children()} == before


def test_metadata_worker_returns_only_bounded_commit_identity():
    assert updater._bounded_metadata(_valid_metadata_worker) == "a" * 40
    with pytest.raises(updater.UpdateError, match="failed"):
        updater._bounded_metadata(_oversized_metadata_worker)
