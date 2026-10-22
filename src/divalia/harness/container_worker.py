"""Trusted Linux-container entry point. Never invoke on the host with untrusted input."""

from __future__ import annotations

import __future__
import hashlib
import json
import resource
import signal
import sys
import time

# Only the reviewed files copied into the immutable worker image are importable.
sys.path.insert(0, "/app")
from ast_validator import SAFE_BUILTINS, validate_source  # noqa: E402

PROTOCOL = "divalia-sandbox-v1"


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def main() -> int:
    resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    resource.setrlimit(resource.RLIMIT_AS, (96 * 1024 * 1024, 96 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.alarm(6)
    request = json.loads(sys.stdin.buffer.read(524_289))
    source = request["source"]
    events = request["events"]
    repetitions = request["repetitions"]
    if (
        request.get("protocol") != PROTOCOL
        or repetitions != 8
        or not isinstance(events, list)
        or not 1 <= len(events) <= 32
    ):
        raise ValueError("invalid worker protocol")
    audit = validate_source(source)
    if not audit.passed:
        raise ValueError("worker rejected the AST")
    telemetry_digest = hashlib.sha256(canonical(events)).hexdigest()
    test_digest = hashlib.sha256(
        canonical({"protocol": PROTOCOL, "events": events, "repetitions": repetitions})
    ).hexdigest()
    if (
        request.get("source_sha256") != audit.source_sha256
        or request.get("telemetry_sha256") != telemetry_digest
        or request.get("test_sha256") != test_digest
    ):
        raise ValueError("request fingerprint mismatch")
    allowed = {name: getattr(__builtins__, name) for name in SAFE_BUILTINS}
    namespace = {"__builtins__": allowed}
    code = compile(
        source,
        "<divalia-detector>",
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    started = time.monotonic()
    exec(code, namespace, namespace)
    detect = namespace["detect"]
    outputs: list[dict | None] = []
    baseline = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    for repetition in range(repetitions):
        for index, event in enumerate(events):
            # A fresh JSON value prevents a test from accidentally sharing state.
            result = detect(json.loads(canonical(event)))
            if result is not None and not isinstance(result, dict):
                raise ValueError("detect(event) must return dict or None")
            encoded = canonical(result)
            if len(encoded) > 16_384:
                raise ValueError("detector output exceeds 16 KiB")
            normalized = json.loads(encoded)
            if repetition == 0:
                outputs.append(normalized)
            elif normalized != outputs[index]:
                raise ValueError("detector outputs changed across repeated fixtures")
    report = {
        "protocol": PROTOCOL,
        "passed": True,
        "status": "passed",
        "outputs": outputs,
        "source_sha256": audit.source_sha256,
        "telemetry_sha256": telemetry_digest,
        "test_sha256": test_digest,
        "metrics": {
            "executions": len(events) * repetitions,
            "wall_seconds": time.monotonic() - started,
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "peak_rss_growth_kib": max(
                0, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - baseline
            ),
        },
    }
    encoded_report = canonical(report)
    if len(encoded_report) > 262_144:
        raise ValueError("aggregate report exceeds output limit")
    sys.stdout.buffer.write(encoded_report)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, MemoryError) as exc:
        # Do not disclose telemetry or arbitrary detector exception strings.
        sys.stderr.write(f"isolated detector test failed: {type(exc).__name__}\n")
        raise SystemExit(1)
