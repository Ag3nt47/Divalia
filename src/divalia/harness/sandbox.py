"""Run eligible detector source only in an explicitly configured Docker image.

No local-Python fallback exists. A pinned, reviewed image containing the supplied
worker is an operator prerequisite; Docker availability alone is insufficient.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from .ast_validator import validate_source

PROTOCOL = "divalia-sandbox-v1"
REPETITIONS = 8
MAX_STDOUT = 262_144
MAX_STDERR = 16_384
_IMAGE = re.compile(r"^(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[0-9a-f]{64}$")
DEFAULT_TELEMETRY: list[dict[str, Any]] = [
    {
        "event_type": "process",
        "process_name": "browser.exe",
        "command_line": "browser --private",
        "pid": 100,
    },
    {
        "event_type": "network",
        "destination_ip": "192.0.2.10",
        "destination_port": 443,
        "protocol": "tcp",
    },
    {
        "event_type": "authentication",
        "username": "example",
        "success": False,
        "source_ip": "198.51.100.4",
    },
    {
        "event_type": "process",
        "process_name": "powershell.exe",
        "command_line": "powershell -EncodedCommand TEST",
        "pid": 101,
    },
    {},
]


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def test_fingerprint(events: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        canonical_json({"protocol": PROTOCOL, "events": events, "repetitions": REPETITIONS})
    ).hexdigest()


@dataclass(frozen=True)
class SandboxResult:
    passed: bool
    status: str
    details: list[str]
    outputs: list[dict[str, Any] | None] = field(default_factory=list)
    source_sha256: str = ""
    telemetry_sha256: str = ""
    test_sha256: str = ""
    metrics: dict[str, int | float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _OutputLimit(Exception):
    pass


class _BoundedProtocol(asyncio.SubprocessProtocol):
    """Own all pipe transports so overflow cannot leave a paused reader alive."""

    def __init__(self) -> None:
        self.transport: asyncio.SubprocessTransport | None = None
        self.finished = asyncio.get_running_loop().create_future()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.error: Exception | None = None

    def connection_made(self, transport: asyncio.SubprocessTransport) -> None:
        self.transport = transport

    def pipe_data_received(self, fd: int, data: bytes) -> None:
        if fd not in {1, 2} or self.error is not None:
            return
        target, maximum = (self.stdout, MAX_STDOUT) if fd == 1 else (self.stderr, MAX_STDERR)
        remaining = maximum - len(target)
        target.extend(data[:remaining])
        if len(data) > remaining:
            self.error = _OutputLimit("container output exceeded the configured byte limit")
            if self.transport is not None:
                try:
                    self.transport.kill()
                except ProcessLookupError:
                    pass

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.finished.done():
            self.finished.set_result(None)


async def _run_bounded(
    args: list[str], payload: bytes = b"", timeout: float = 5.0
) -> _CommandResult:
    """Bound subprocess lifetime, input, and both output pipes; never invoke a shell."""
    protocol = _BoundedProtocol()
    transport, _ = await asyncio.get_running_loop().subprocess_exec(
        lambda: protocol,
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdin = transport.get_pipe_transport(0)
        if stdin is not None:
            stdin.write(payload)
            stdin.close()
        await asyncio.wait_for(asyncio.shield(protocol.finished), timeout=timeout)
        if protocol.error is not None:
            raise protocol.error
        return _CommandResult(
            transport.get_returncode(), bytes(protocol.stdout), bytes(protocol.stderr)
        )
    finally:
        # Reap explicitly before closing pipes. Transport.close() alone kills a
        # running child but emits asyncio warnings and may defer process cleanup.
        if transport.get_returncode() is None:
            try:
                transport.kill()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(asyncio.shield(protocol.finished), timeout=3)
        except (TimeoutError, ProcessLookupError):
            pass
        finally:
            transport.close()


def _validate_json_tree(value: Any, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError("telemetry nesting exceeds 12 levels")
    if isinstance(value, dict):
        if len(value) > 256 or any(not isinstance(key, str) or len(key) > 256 for key in value):
            raise ValueError("telemetry dictionaries require at most 256 short string keys")
        for child in value.values():
            _validate_json_tree(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 512:
            raise ValueError("telemetry array exceeds 512 entries")
        for child in value:
            _validate_json_tree(child, depth + 1)
    elif isinstance(value, str):
        if len(value) > 65_536:
            raise ValueError("telemetry string exceeds the size limit")
    elif value is not None and type(value) not in {bool, int, float}:
        raise ValueError("telemetry must contain only JSON values")


def normalize_telemetry(telemetry: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate bounded input before serialization and return an isolated snapshot.

    Callers can distinguish malformed input from a detector execution failure;
    invalid events must not quarantine an otherwise healthy detector.
    """
    if (not isinstance(telemetry, list) or not 1 <= len(telemetry) <= 32
            or any(not isinstance(event, dict) for event in telemetry)):
        raise ValueError("provide between 1 and 32 telemetry dictionaries")
    _validate_json_tree(telemetry)
    serialized = canonical_json(telemetry)
    if len(serialized) > 262_144:
        raise ValueError("telemetry exceeds 256 KiB")
    return json.loads(serialized)


class SandboxRunner:
    def __init__(self, image: str | None = None, timeout_seconds: float = 15) -> None:
        self.image = image if image is not None else os.environ.get("DIVALIA_SANDBOX_IMAGE", "")
        if not 1 <= timeout_seconds <= 60:
            raise ValueError("sandbox timeout must be between 1 and 60 seconds")
        self.timeout_seconds = timeout_seconds

    async def _remove_container(self, docker: str, name: str) -> None:
        try:
            await _run_bounded([docker, "rm", "--force", name], timeout=5)
        except (OSError, TimeoutError, _OutputLimit):
            # Preserve the original failure; the result will never be passed.
            pass

    async def run(
        self, source: str, telemetry: list[dict[str, Any]] | None = None
    ) -> SandboxResult:
        audit = validate_source(source)
        base: dict[str, Any] = {"source_sha256": audit.source_sha256}
        if not audit.passed:
            return SandboxResult(False, "rejected", audit.issues, **base)
        try:
            events = normalize_telemetry(DEFAULT_TELEMETRY if telemetry is None else telemetry)
            serialized = canonical_json(events)
            base.update(
                telemetry_sha256=hashlib.sha256(serialized).hexdigest(),
                test_sha256=test_fingerprint(events),
            )
        except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError) as exc:
            return SandboxResult(False, "invalid_telemetry", [str(exc)[:500]], **base)
        if not _IMAGE.fullmatch(self.image):
            return SandboxResult(
                False,
                "unavailable",
                [
                    "configure a reviewed Docker worker image using repository@sha256:<64 hex digits> or immutable local sha256:<64 hex digits>"
                ],
                **base,
            )
        docker = shutil.which("docker")
        if not docker:
            return SandboxResult(
                False,
                "unavailable",
                ["Docker CLI is unavailable; host execution is forbidden"],
                **base,
            )
        try:
            engine = await _run_bounded([docker, "info", "--format", "{{.OSType}}"], timeout=5)
            if engine.returncode or engine.stdout.strip() != b"linux":
                return SandboxResult(
                    False, "unavailable", ["a running Linux Docker engine is required"], **base
                )
            inspected = await _run_bounded(
                [docker, "image", "inspect", self.image, "--format", "{{.Id}}"], timeout=5
            )
            if inspected.returncode:
                return SandboxResult(
                    False,
                    "unavailable",
                    [
                        "the pinned worker image is not installed; no automatic image pull is performed"
                    ],
                    **base,
                )
        except (OSError, TimeoutError, _OutputLimit) as exc:
            return SandboxResult(
                False, "unavailable", [f"Docker preflight failed: {type(exc).__name__}"], **base
            )
        name = "divalia-test-" + uuid.uuid4().hex
        payload = canonical_json(
            {
                "protocol": PROTOCOL,
                "source": source,
                "events": events,
                "repetitions": REPETITIONS,
                **base,
            }
        )
        args = [
            docker,
            "run",
            "--rm",
            "--pull",
            "never",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--user",
            "65534:65534",
            "--memory",
            "128m",
            "--memory-swap",
            "128m",
            "--cpus",
            "1",
            "--pids-limit",
            "16",
            "--ulimit",
            "nofile=64:64",
            "--ulimit",
            "nproc=16:16",
            "--ulimit",
            "core=0",
            "--log-driver",
            "none",
            "--ipc",
            "none",
            "--stop-timeout",
            "1",
            "--entrypoint",
            "/usr/local/bin/python",
            "-i",
            self.image,
            "-I",
            "-S",
            "-B",
            "/app/container_worker.py",
        ]
        try:
            result = await _run_bounded(args, payload, timeout=self.timeout_seconds)
            if result.returncode:
                return SandboxResult(
                    False,
                    "failed",
                    [
                        f"container exited with status {result.returncode}",
                        result.stderr.decode("utf-8", errors="replace")[:2_000],
                    ],
                    **base,
                )
            try:
                response = json.loads(result.stdout)
                if (
                    not isinstance(response, dict)
                    or any(response.get(key) != value for key, value in base.items())
                    or response.get("protocol") != PROTOCOL
                ):
                    raise ValueError(
                        "worker response is not bound to this source and fixture suite"
                    )
                outputs = response.get("outputs")
                if (
                    response.get("passed") is not True
                    or response.get("status") != "passed"
                    or not isinstance(outputs, list)
                    or len(outputs) != len(events)
                    or any(
                        output is not None and not isinstance(output, dict) for output in outputs
                    )
                ):
                    raise ValueError("worker reported invalid detector behavior")
                metrics = response.get("metrics", {})
                if not isinstance(metrics, dict) or any(
                    type(value) not in {float, int} or not math.isfinite(value) or value < 0
                    for value in metrics.values()
                ):
                    raise ValueError("invalid resource metrics")
                canonical_json(outputs)
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                return SandboxResult(False, "protocol_error", [str(exc)[:500]], **base)
            return SandboxResult(
                True,
                "passed",
                [
                    f"{len(events)} synthetic fixtures repeated {REPETITIONS} times in the isolated worker",
                    "bounded resource checks are observations, not an exhaustive proof of leak or deadlock freedom",
                ],
                outputs=outputs,
                metrics=metrics,
                **base,
            )
        except TimeoutError:
            return SandboxResult(
                False, "timeout", ["container test exceeded its wall-clock limit"], **base
            )
        except _OutputLimit as exc:
            return SandboxResult(False, "output_limit", [str(exc)], **base)
        except OSError as exc:
            return SandboxResult(
                False, "unavailable", [f"container could not start: {type(exc).__name__}"], **base
            )
        finally:
            # Killing a Docker CLI alone does not stop its container.
            await asyncio.shield(self._remove_container(docker, name))
