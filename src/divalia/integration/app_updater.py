"""Consent-bound GitHub updates for a clean, editable Divalia source checkout.

Checking downloads JSON metadata only. Applying is deliberately conservative:
the reviewed commit must fast-forward an idle checkout without changing setup
inputs. Runtime leases are OS locks, so crashed processes cannot block forever.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import http.client
import json
import math
import multiprocessing
import os
import re
import signal
import shutil
import socket
import stat
import subprocess
import sys
import time
import threading
import tomllib
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, BinaryIO

ORIGIN = "https://github.com/Ag3nt47/Divalia.git"
METADATA_PATH = "/repos/Ag3nt47/Divalia/branches/main"
SHA = re.compile(r"[0-9a-f]{40}\Z")
FORCE_FLOOR_SECONDS = 15 * 60
MAX_STATE_BYTES = 65536
MAX_LEASES = 4096


class UpdateError(RuntimeError):
    """A safe update precondition or bounded operation failed."""


@dataclasses.dataclass(frozen=True)
class UpdateStatus:
    state: str
    current_sha: str = ""
    target_sha: str = ""
    compare_url: str = ""
    message: str = ""
    checked_today: bool = False
    check_id: str = ""


def source_root() -> Path:
    return Path(__file__).absolute().parents[3]


def _safe_path(path: Path, *, directory: bool = False) -> None:
    """Reject symlinks and Windows reparse points in every existing component."""
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise UpdateError("Updater paths must not contain symlinks or junctions.")
    if directory and not path.is_dir():
        raise UpdateError("A normal source checkout directory is required.")


def _open_file(path: Path) -> BinaryIO:
    _safe_path(path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    handle = os.fdopen(descriptor, "r+b", buffering=0)
    info = os.fstat(handle.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        handle.close()
        raise UpdateError("Updater lock is not a regular file.")
    if os.fstat(handle.fileno()).st_size == 0:
        handle.write(b"\0")
    return handle


def _try_lock(handle: BinaryIO) -> bool:
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (BlockingIOError, OSError):
        return False


def _unlock(handle: BinaryIO) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _state_dir(root: Path) -> Path:
    _safe_path(root, directory=True)
    git_dir = root / ".git"
    _safe_path(git_dir, directory=True)
    state_dir = git_dir / "divalia-updater"
    _safe_path(state_dir)
    state_dir.mkdir(mode=0o700, exist_ok=True)
    _safe_path(state_dir, directory=True)
    for name in ("leases", "empty-hooks"):
        child = state_dir / name
        _safe_path(child)
        child.mkdir(mode=0o700, exist_ok=True)
        _safe_path(child, directory=True)
    return state_dir


@contextlib.contextmanager
def _gate(state_dir: Path) -> Iterator[None]:
    handle = _open_file(state_dir / "gate.lock")
    if not _try_lock(handle):
        handle.close()
        raise UpdateError("Another updater or application startup is in progress; try again later.")
    try:
        yield
    finally:
        _unlock(handle)


def _lease_files(state_dir: Path) -> list[Path]:
    result = []
    for path in (state_dir / "leases").iterdir():
        if len(result) >= MAX_LEASES:
            raise UpdateError("Too many runtime leases; inspect updater state manually.")
        if not re.fullmatch(r"[0-9a-f]{32}\.lock", path.name):
            raise UpdateError("Unrecognized runtime lease file; inspect updater state manually.")
        _safe_path(path)
        result.append(path)
    return result


def _assert_idle(state_dir: Path) -> None:
    active = False
    for path in _lease_files(state_dir):
        handle = _open_file(path)
        if not _try_lock(handle):
            active = True
            handle.close()
        else:
            _unlock(handle)
            path.unlink(missing_ok=True)
    if active:
        raise UpdateError("Divalia is running. Close it normally, then approve the update again.")


@contextlib.contextmanager
def application_use(root: Path | None = None) -> Iterator[None]:
    """Hold for an entire CLI invocation; wheels have no managed checkout lease."""
    checkout = Path(root) if root is not None else source_root()
    if not os.path.lexists(checkout / ".git"):
        yield
        return
    _safe_path(checkout)
    _safe_path(checkout / ".git")
    if (checkout / ".git").is_file():
        # Linked worktrees are valid application installations, but are never
        # mutated by this updater because their Git storage is redirected.
        yield
        return
    state_dir = _state_dir(checkout)
    lease = state_dir / "leases" / f"{uuid.uuid4().hex}.lock"
    with _gate(state_dir):
        if len(_lease_files(state_dir)) >= MAX_LEASES:
            raise UpdateError("Too many runtime leases; inspect updater state before retrying.")
        handle = _open_file(lease)
        if not _try_lock(handle):
            handle.close()
            raise UpdateError("Cannot acquire application runtime lease.")
    try:
        yield
    finally:
        _unlock(handle)
        # A checker may already have removed this now-abandoned lease.
        lease.unlink(missing_ok=True)


def _github_head_http() -> str:
    """Fetch a bounded JSON response over verified TLS, without redirects."""
    deadline = time.monotonic() + 12
    connection = http.client.HTTPSConnection("api.github.com", timeout=12)
    response: http.client.HTTPResponse | None = None

    def abort() -> None:
        # A slow header/body drip must not keep an update check alive forever.
        transport = connection.sock
        if transport is None and response is not None:
            transport = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
        if transport is not None:
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()

    timer = threading.Timer(12, abort)
    timer.daemon = True
    timer.start()
    try:
        connection.request(
            "GET",
            METADATA_PATH,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "Divalia/1.0-updater"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise UpdateError("GitHub metadata is unavailable; retry on the next day or later.")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_STATE_BYTES):
            raise UpdateError("GitHub metadata exceeds its size limit.")
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpdateError("GitHub metadata check timed out.")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(8192, MAX_STATE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_STATE_BYTES:
                raise UpdateError("GitHub metadata exceeds its size limit.")
        value = json.loads(b"".join(chunks))
        target = value["commit"]["sha"]
        if not isinstance(target, str) or not SHA.fullmatch(target):
            raise UpdateError("GitHub returned an invalid commit identity.")
        return target
    except UpdateError:
        raise
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        raise UpdateError(
            "GitHub metadata check failed; installed files were not changed."
        ) from None
    finally:
        timer.cancel()
        connection.close()
        timer.join(timeout=0.2)


def _metadata_worker(channel: Any) -> None:
    try:
        target = _github_head_http()
        channel.send_bytes(target.encode("ascii"))
    except Exception:
        # Transport/server details may contain sensitive host configuration.
        # The only data allowed back are a fixed marker or one full commit SHA.
        try:
            channel.send_bytes(b"unavailable")
        except OSError:
            pass
    finally:
        channel.close()


def _bounded_metadata(worker: Callable[[Any], None], *, seconds: float = 15) -> str:
    """Bound DNS as well as sockets, and retire precisely this owned worker."""
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(sender,), daemon=True)
    deadline = time.monotonic() + seconds
    started = False
    try:
        process.start()
        started = True
        sender.close()
        if not receiver.poll(max(0, deadline - time.monotonic())):
            raise UpdateError("GitHub metadata check timed out; no update code was downloaded.")
        payload = receiver.recv_bytes(maxlength=128)
        target = payload.decode("ascii")
        if not SHA.fullmatch(target):
            raise UpdateError(
                "GitHub metadata check was unavailable; installed files were not changed."
            )
        return target
    except (OSError, ValueError, EOFError, UnicodeError):
        raise UpdateError(
            "GitHub metadata check failed; installed files were not changed."
        ) from None
    finally:
        sender.close()
        receiver.close()
        if started:
            # Process owns a retained native handle / unreaped child identity;
            # no process discovery, PID heuristics or unrelated termination.
            process.join(timeout=0.2)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
            if process.is_alive():
                process.kill()
                process.join(timeout=2)
            if process.is_alive():
                raise UpdateError("The owned metadata worker could not be retired; retry manually.")
            process.close()


def github_head() -> str:
    """The complete metadata operation, including DNS, has a parent deadline."""
    return _bounded_metadata(_metadata_worker)


class _WindowsJob:
    """An OS-owned kill-on-close group for precisely this Git subprocess tree."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_int64),
                ("job_time", ctypes.c_int64),
                ("flags", wintypes.DWORD),
                ("min_working_set", ctypes.c_size_t),
                ("max_working_set", ctypes.c_size_t),
                ("active_processes", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD),
            ]

        class Counters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_uint64)
                for name in (
                    "read_operations",
                    "write_operations",
                    "other_operations",
                    "read_bytes",
                    "write_bytes",
                    "other_bytes",
                )
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimits),
                ("io", Counters),
                ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t),
                ("peak_process", ctypes.c_size_t),
                ("peak_job", ctypes.c_size_t),
            ]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self._close_lock = threading.Lock()
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise UpdateError("Cannot isolate Git subprocess ownership; update manually.")
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(
            self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            self.close()
            raise UpdateError("Cannot isolate Git subprocess ownership; update manually.")

    def attach(self, process: subprocess.Popen) -> None:
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            process.kill()
            process.wait(timeout=10)
            raise UpdateError("Cannot isolate Git subprocess ownership; update manually.")

    def resume(self, process: subprocess.Popen) -> None:
        import ctypes
        from ctypes import wintypes

        native = ctypes.WinDLL("ntdll")
        native.NtResumeProcess.argtypes = [wintypes.HANDLE]
        native.NtResumeProcess.restype = ctypes.c_long
        if native.NtResumeProcess(int(process._handle)) < 0:
            raise UpdateError("Cannot start the owned Git subprocess safely; update manually.")

    def close(self) -> None:
        with self._close_lock:
            if self.handle:
                self.kernel.CloseHandle(self.handle)
                self.handle = None


def _run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> bytes:
    if os.name != "nt" and not hasattr(os, "waitid"):
        raise UpdateError("This platform cannot retain process ownership safely; update manually.")
    job = _WindowsJob() if os.name == "nt" else None
    process = None
    chunks: list[bytes] = []
    too_large = threading.Event()
    reader = None
    retired = False
    stop_lock = threading.Lock()

    def stop() -> None:
        nonlocal retired
        with stop_lock:
            if retired:
                return
            retired = True
            if job is not None:
                job.close()
            elif process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NO_WINDOW | 0x00000004) if os.name == "nt" else 0,
        )
        if job is not None:
            job.attach(process)
            job.resume(process)

        def read() -> None:
            total = 0
            assert process.stdout is not None
            while data := process.stdout.read(65536):
                total += len(data)
                if total > 8 * 1024 * 1024:
                    too_large.set()
                    stop()
                    return
                chunks.append(data)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        if os.name == "nt":
            process.wait(timeout=timeout)
        else:
            # WNOWAIT retains the exact group leader as a zombie until its
            # descendants are retired. Its PID/group cannot be recycled first.
            while not os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG):
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(0.02)
        reader.join(max(0, deadline - time.monotonic()))
        if reader.is_alive():
            stop()
            raise subprocess.TimeoutExpired(command, timeout)
        if too_large.is_set():
            raise UpdateError("Git inventory exceeds the updater's size limit.")
        stop()
        process.wait(timeout=10)
        if process.returncode:
            raise UpdateError(
                "Git operation failed; no automatic recovery or overwrite was attempted."
            )
        return b"".join(chunks)
    except (OSError, subprocess.TimeoutExpired):
        raise UpdateError(
            "Git operation failed or timed out; inspect the checkout manually."
        ) from None
    finally:
        if process is not None:
            stop()
        elif job is not None:
            job.close()
        if process is not None:
            process.wait(timeout=10)
        if reader is not None:
            reader.join(timeout=10)
        if process is not None and process.stdout is not None:
            process.stdout.close()


class UpdateManager:
    def __init__(
        self,
        root: Path,
        *,
        fetcher: Callable[[], str] | None = None,
        runner: Callable[..., bytes] | None = None,
        now: Callable[[], dt.datetime] | None = None,
    ):
        self.root = Path(os.path.abspath(root))
        self.fetcher = fetcher or github_head
        self.runner = runner or _run
        self.now = now or (lambda: dt.datetime.now().astimezone())
        self.git = shutil.which("git")
        self.state_dir: Path | None = None

    def _prepare(self) -> None:
        if not os.path.lexists(self.root / ".git"):
            raise UpdateError(
                "This installation is not a managed source checkout. Reinstall its wheel/package "
                "using your original installer; no files were changed."
            )
        self.state_dir = _state_dir(self.root)
        if not self.git:
            raise UpdateError("Git is required for source updates; install it manually first.")

    def _git(self, *args: str, timeout: int = 30) -> str:
        assert self.state_dir is not None and self.git is not None
        # Ignore global/system Git configuration and all inherited GIT_* controls.
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith(("GIT_", "GCM_"))
        }
        env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_TERMINAL_PROMPT="0",
            GCM_INTERACTIVE="Never",
            GIT_NO_REPLACE_OBJECTS="1",
        )
        command = [
            self.git,
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.protectNTFS=true",
            "-c",
            "core.protectHFS=true",
            "-c",
            "merge.autoStash=false",
            "-c",
            "submodule.recurse=false",
            "-c",
            "credential.helper=",
            "-c",
            "credential.interactive=false",
            "-c",
            "core.askpass=",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.proxy=",
            "-c",
            "http.extraHeader=",
            "-c",
            "http.sslVerify=true",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            *args,
        ]
        try:
            return self.runner(command, cwd=self.root, env=env, timeout=timeout).decode("utf-8")
        except UnicodeError:
            raise UpdateError(
                "Git returned unsupported text; update this checkout manually."
            ) from None

    def _validate_checkout(self, *, clean: bool) -> str:
        assert self.state_dir is not None
        # No indirection through linked worktrees, object alternates or grafts.
        for name in ("commondir", "shallow", "objects/info/alternates", "info/grafts"):
            if (self.root / ".git" / name).exists():
                raise UpdateError("Indirect or shallow Git storage requires a manual update.")
        for name in (
            "config",
            "objects",
            "objects/pack",
            "objects/info",
            "HEAD",
            "index",
            "refs",
            "refs/heads",
            "refs/heads/main",
            "packed-refs",
            "FETCH_HEAD",
            "ORIG_HEAD",
            "logs",
            "logs/HEAD",
            "logs/refs/heads/main",
            "info/attributes",
            "info/exclude",
        ):
            _safe_path(self.root / ".git" / name)
        if (self.root / ".git" / "config").stat().st_size > MAX_STATE_BYTES:
            raise UpdateError("Git configuration exceeds the updater's size limit.")
        settings = self._git("config", "--no-includes", "--local", "--null", "--list")
        origins = []
        forbidden = (
            "filter.",
            "url.",
            "include.",
            "includeif.",
            "submodule.",
            "extensions.",
            "http.",
            "https.",
            "credential.",
            "protocol.",
        )
        for entry in settings.split("\0"):
            if not entry:
                continue
            key, _, value = entry.partition("\n")
            lower = key.lower()
            if lower.startswith(forbidden) or lower in {
                "core.worktree",
                "core.sshcommand",
                "core.gitproxy",
                "core.sparsecheckout",
                "core.sparsecheckoutcone",
                "core.hookspath",
                "core.attributesfile",
            }:
                raise UpdateError(
                    "Custom Git execution, filters or redirected storage require manual updates."
                )
            if lower == "core.fsmonitor" and value.lower() not in ("false", "0", "no", "off"):
                raise UpdateError("Custom Git execution requires manual updates.")
            if lower.startswith("remote.") and lower.rsplit(".", 1)[-1] not in {
                "url",
                "fetch",
                "pushurl",
                "tagopt",
            }:
                raise UpdateError("Custom Git transport requires manual updates.")
            if lower == "remote.origin.url":
                origins.append(value)
        if origins != [ORIGIN]:
            raise UpdateError("Origin must be exactly https://github.com/Ag3nt47/Divalia.git.")
        if (
            self._git("rev-parse", "--show-toplevel").strip().casefold()
            != str(self.root).replace("\\", "/").casefold()
        ):
            raise UpdateError("Git resolved a different checkout directory.")
        if self._git("symbolic-ref", "--short", "HEAD").strip() != "main":
            raise UpdateError("Switch to main manually before using the updater.")
        if (self.root / ".gitmodules").exists():
            raise UpdateError("Submodule checkouts require manual updates.")
        if self._git("for-each-ref", "--format=%(refname)", "refs/replace").strip():
            raise UpdateError("Replacement objects require manual updates.")
        head = self._git("rev-parse", "--verify", "HEAD^{commit}").strip()
        if not SHA.fullmatch(head):
            raise UpdateError("Current commit identity is invalid.")
        if clean:
            if self._git(
                "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"
            ):
                raise UpdateError(
                    "Local changes or untracked files exist; preserve them and update manually."
                )
            if any(
                entry and (entry[0].islower() or entry[0] == "S")
                for entry in self._git("ls-files", "-v", "-z").split("\0")
            ):
                raise UpdateError("Hidden index changes require a manual update.")
        return head

    def _read_state(self) -> dict[str, Any]:
        assert self.state_dir is not None
        path = self.state_dir / "check.json"
        _safe_path(path)
        if not path.exists():
            return {}
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_STATE_BYTES:
            raise UpdateError("Invalid updater state; inspect it manually.")
        try:
            value = json.loads(path.read_bytes())
            if not isinstance(value, dict):
                raise ValueError
            if type(value.get("checked_at")) not in (int, float):
                raise ValueError
            if not math.isfinite(value["checked_at"]) or value["checked_at"] <= 0:
                raise ValueError
            if not isinstance(value.get("day"), str) or not re.fullmatch(
                r"[0-9a-f]{32}", value.get("id", "")
            ):
                raise ValueError
            if value.get("target") and not SHA.fullmatch(value["target"]):
                raise ValueError
            return value
        except (ValueError, TypeError):
            raise UpdateError("Invalid updater state; inspect it manually.") from None

    def _save_state(self, value: dict[str, Any]) -> None:
        assert self.state_dir is not None
        destination = self.state_dir / "check.json"
        _safe_path(destination)
        temporary = self.state_dir / f"{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(json.dumps(value, allow_nan=False).encode())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _status(current: str, record: dict[str, Any], *, cached: bool) -> UpdateStatus:
        target = record.get("target", "")
        if not target:
            return UpdateStatus(
                "unavailable",
                current_sha=current,
                checked_today=cached,
                message="GitHub check was unavailable; no update was downloaded.",
            )
        state = "current" if target == current else "available"
        return UpdateStatus(
            state,
            current,
            target,
            f"https://github.com/Ag3nt47/Divalia/compare/{current}...{target}",
            "Already at the observed main commit."
            if state == "current"
            else "A different main commit is available for review; fast-forward eligibility is checked after approval.",
            cached,
            record["id"],
        )

    def check(self, *, force: bool = False) -> UpdateStatus:
        self._prepare()
        assert self.state_dir is not None
        with _gate(self.state_dir):
            current = self._validate_checkout(clean=False)
            record = self._read_state()
            now = self.now()
            elapsed = now.timestamp() - record.get("checked_at", 0)
            if record and (
                (not force and record["day"] == now.date().isoformat())
                or (force and elapsed < FORCE_FLOOR_SECONDS)
            ):
                return self._status(current, record, cached=True)
            record = {
                "day": now.date().isoformat(),
                "checked_at": now.timestamp(),
                "id": uuid.uuid4().hex,
                "target": "",
            }
            # An outage still consumes today's automatic request, including process crashes.
            self._save_state(record)
            try:
                target = self.fetcher()
                if not isinstance(target, str) or not SHA.fullmatch(target):
                    raise UpdateError("Invalid GitHub commit identity.")
            except (UpdateError, OSError, ValueError):
                return self._status(current, record, cached=False)
            record["target"] = target
            self._save_state(record)
            return self._status(current, record, cached=False)

    def apply(self, status: UpdateStatus, *, approved_sha: str) -> UpdateStatus:
        if (
            status.state != "available"
            or not SHA.fullmatch(approved_sha)
            or approved_sha != status.target_sha
        ):
            raise UpdateError("Approval must identify the exact full commit shown by the check.")
        self._prepare()
        assert self.state_dir is not None
        with _gate(self.state_dir):
            _assert_idle(self.state_dir)
            current = self._validate_checkout(clean=True)
            record = self._read_state()
            if (
                current != status.current_sha
                or record.get("target") != approved_sha
                or record.get("id") != status.check_id
            ):
                raise UpdateError("Checkout or observed target changed; check and approve again.")
            # First code download happens here, after exact consent and idle/clean checks.
            self._git(
                "fetch", "--no-tags", "--no-recurse-submodules", ORIGIN, approved_sha, timeout=120
            )
            if self._git("rev-parse", "--verify", "FETCH_HEAD^{commit}").strip() != approved_sha:
                raise UpdateError("Fetched commit does not match the approved identity.")
            try:
                self._git("merge-base", "--is-ancestor", current, approved_sha)
            except UpdateError:
                raise UpdateError(
                    "Local main and approved main diverged; reconcile manually."
                ) from None
            changed = self._git(
                "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", current, approved_sha
            ).split("\0")
            setup_names = {
                "setup.py",
                "setup.cfg",
                "manifest.in",
                "uv.lock",
                "poetry.lock",
                "pipfile",
                "pipfile.lock",
                "pdm.lock",
                ".gitmodules",
                "pylock.toml",
                ".python-version",
                "dockerfile",
                "containerfile",
                ".dockerignore",
            }
            setup_changed = any(
                Path(name).name.lower() in setup_names
                or Path(name).name.lower().startswith(("requirements", "constraints"))
                or name.lower().startswith("requirements/")
                for name in changed
                if name
            )
            if "pyproject.toml" in changed:
                setup_changed = setup_changed or self._pyproject_setup(
                    current
                ) != self._pyproject_setup(approved_sha)
            if setup_changed:
                return dataclasses.replace(
                    status,
                    state="manual_setup",
                    message="Update changes dependency/build inputs. Close Divalia, review the commit, "
                    "then fast-forward and reinstall with your original setup procedure manually. "
                    "The running installation was not changed.",
                )
            if self._validate_checkout(clean=True) != current:
                raise UpdateError("Checkout changed while downloading; check and approve again.")
            self._git(
                "merge",
                "--ff-only",
                "--no-edit",
                "--no-verify",
                "--no-autostash",
                "--no-overwrite-ignore",
                approved_sha,
            )
            if self._validate_checkout(clean=True) != approved_sha:
                raise UpdateError(
                    "Update could not be verified; inspect the checkout before launching."
                )
            return dataclasses.replace(
                status,
                state="updated",
                current_sha=approved_sha,
                message="Approved update applied. The next launch uses this commit.",
            )

    def _pyproject_setup(self, commit: str) -> tuple[Any, ...]:
        try:
            raw = self._git("show", f"{commit}:pyproject.toml")
            if len(raw.encode()) > MAX_STATE_BYTES:
                raise ValueError
            document = tomllib.loads(raw)
            project = document.get("project", {})
            return (
                document.get("build-system"),
                *(
                    project.get(key)
                    for key in (
                        "dependencies",
                        "optional-dependencies",
                        "requires-python",
                        "scripts",
                        "gui-scripts",
                        "entry-points",
                        "dynamic",
                    )
                ),
                document.get("tool", {}).get("setuptools"),
            )
        except (ValueError, TypeError, AttributeError, UpdateError):
            raise UpdateError(
                "Build configuration cannot be compared safely; review and reinstall manually."
            ) from None


def format_status(status: UpdateStatus) -> str:
    lines = [f"Divalia update: {status.state}", status.message]
    if status.current_sha:
        lines.append(f"Installed: {status.current_sha}")
    if status.target_sha:
        lines.append(f"Observed main: {status.target_sha}")
    if status.compare_url:
        lines.append(f"Review: {status.compare_url}")
    if status.checked_today:
        lines.append(
            "Using the saved daily check (forced checks are limited to once per 15 minutes)."
        )
    return "\n".join(lines)


def _launch(arguments: list[str]) -> int:
    # All updater locks have been released before the application starts.
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(source_root() / "src") + (
        os.pathsep + existing if existing else ""
    )
    command = [sys.executable, "-m", "divalia", *arguments]
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == "nt":
        # Windows CRT exec does not preserve the outer process's wait/output
        # contract. Keep this launcher alive until its exact application child
        # exits, inheriting the console/pipes and returning the real exit code.
        return subprocess.call(command, env=environment)
    os.execve(sys.executable, command, environment)
    return 0  # pragma: no cover


def main(
    argv: list[str] | None = None,
    *,
    root: Path | None = None,
    manager_factory: Callable[[Path], UpdateManager] = UpdateManager,
    input_fn: Callable[[str], str] = input,
    interactive: bool | None = None,
    launch: Callable[[list[str]], int] = _launch,
) -> int:
    parser = argparse.ArgumentParser(
        description="Check Divalia main daily; apply only after exact approval."
    )
    parser.add_argument(
        "--check-only", action="store_true", help="Never prompt or download update code"
    )
    parser.add_argument(
        "--force", action="store_true", help="Refresh metadata, at most once per 15 minutes"
    )
    parser.add_argument(
        "--run",
        nargs=argparse.REMAINDER,
        help="Start Divalia afterward, forwarding these arguments",
    )
    args = parser.parse_args(argv)
    manager = manager_factory(root or source_root())
    result = 0
    apply_started = False
    try:
        status = manager.check(force=args.force)
        print(format_status(status))
        may_prompt = (
            sys.stdin.isatty() and sys.stdout.isatty() if interactive is None else interactive
        )
        if status.state == "available" and not args.check_only and may_prompt:
            expected = f"update {status.target_sha}"
            answer = input_fn(f"Type '{expected}' to approve this exact commit (Enter declines): ")
            if answer.strip() == expected:
                apply_started = True
                status = manager.apply(status, approved_sha=status.target_sha)
                print(format_status(status))
                if status.state == "manual_setup":
                    result = 2
            else:
                print("Update declined. Installed files were not changed.")
        if status.state == "unavailable":
            result = 1
    except UpdateError as exc:
        print(f"Divalia update was held: {exc}")
        # A failed apply may have left Git requiring operator review. Never launch
        # an unverified mixture of source files automatically.
        return 2
    except (OSError, EOFError):
        print("Divalia update was held. Check checkout/setup and retry manually.")
        if apply_started:
            return 2
        result = 2
    if args.run is not None:
        # A declined, unavailable or setup-held update can still launch the installed version.
        try:
            return launch(args.run)
        except OSError:
            print(
                "Divalia could not be started. Check the Python installation and launch manually.",
                file=sys.stderr,
            )
            return 2
    return result
