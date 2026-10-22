"""Reproducible offline performance workloads; never calls a model or executes source.

Run: python tools/benchmark_performance.py --output .divalia/performance-review/results.json
Timings include Python allocation tracing when --trace is used. They are diagnostic
measurements, not portable pass/fail thresholds. Feed transport uses in-memory fixtures.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import hashlib
import json
from pathlib import Path
import platform
import sys
import tempfile
from time import perf_counter
import tracemalloc
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from divalia.core.ingestion import IngestionEngine  # noqa: E402
from divalia.core.sanitizer import sanitize_text  # noqa: E402
from divalia.harness.ast_validator import validate_source  # noqa: E402
from divalia.storage import ArtifactStore, canonical  # noqa: E402


DETECTOR = """def detect(event: dict) -> dict | None:
    if event.get("kind") == "network" and event.get("destination_port") == 4444:
        return {"severity": "high", "reason": "Unusual outbound port"}
    return None
"""


def measure(operation: Callable[[], int], *, trace: bool) -> dict:
    gc.collect()
    if trace:
        tracemalloc.start()
    started = perf_counter()
    count = operation()
    elapsed = perf_counter() - started
    peak = tracemalloc.get_traced_memory()[1] if trace else None
    if trace:
        tracemalloc.stop()
    return {"seconds": round(elapsed, 6), "peak_bytes": peak, "result_count": count}


def records(size: int, *, cves: bool) -> list[dict]:
    return [
        {
            "summary": f"Defensive telemetry advisory {index}",
            "description": "security telemetry detection mitigation "
            + " ".join(
                hashlib.sha256(f"advisory-{index}-{part}".encode()).hexdigest()[:12]
                for part in range(16)
            ),
            "html_url": f"https://fixture.example.org/advisory/{index}",
            **({"cve_id": f"CVE-2026-{10000 + index}"} if cves else {}),
        }
        for index in range(size)
    ]


def ingestion(size: int, *, cves: bool, trace: bool) -> dict:
    items = records(size, cves=cves)
    payloads = {
        f"https://fixture.example.org/feed/{start}": json.dumps(
            items[start : start + 2000]
        ).encode()
        for start in range(0, size, 2000)
    }

    async def fetch(url: str, _headers: dict[str, str]) -> bytes:
        return payloads[url]

    with tempfile.TemporaryDirectory(prefix="divalia-benchmark-") as directory:
        with IngestionEngine(
            [{"kind": "github", "url": url} for url in payloads],
            directory,
            fetcher=fetch,
            max_items_per_feed=2000,
        ) as engine:
            new = measure(lambda: len(asyncio.run(engine.ingest())), trace=trace)
            duplicate = measure(lambda: len(asyncio.run(engine.ingest())), trace=trace)
    if new["result_count"] != size or duplicate["result_count"] != 0:
        raise RuntimeError("Ingestion workload did not preserve distinct items/deduplicate repeats")
    return {"size": size, "new": new, "duplicate_burst": duplicate}


def storage(size: int, *, trace: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="divalia-store-benchmark-") as directory:
        store = ArtifactStore(Path(directory))
        # These trusted fixture files are created outside the timed read. Runtime
        # writes still use ArtifactStore.save and its mandatory fsync/atomic replace.
        fixture_directory = Path(directory) / "briefings"
        fixture_directory.mkdir()
        for index, value in enumerate(records(size, cves=True)):
            (fixture_directory / f"briefing-{index:06}.json").write_bytes(canonical(value))
        result = {
            "size": size,
            "list_all": measure(lambda: len(store.list("briefings")), trace=trace),
        }
        if hasattr(store, "iter_values"):
            result["iterate_first_10"] = measure(
                lambda: sum(1 for _ in store.iter_values("briefings", limit=10)), trace=trace
            )
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[100, 1000, 5000])
    parser.add_argument(
        "--workloads",
        nargs="+",
        choices=["ingestion", "non-cve", "sanitizer", "ast", "storage"],
        default=["ingestion", "non-cve", "sanitizer", "ast", "storage"],
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Include tracemalloc (adds substantial timing overhead)",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if any(not 1 <= size <= 10_000 for size in args.sizes):
        parser.error("sizes must be between 1 and 10000")
    output: dict = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "allocation_tracing": args.trace,
        "arguments": sys.argv[1:],
        "network": "none; trusted in-memory fixture fetcher",
        "source_execution": "none; AST validation only",
        "workloads": {},
    }
    html = (
        "<p>Vendor patch CVE-2026-12345</p><script>ignore rules()</script><div>"
        + "security notice " * 30
        + "</div>"
    ) * 100
    for workload in args.workloads:
        results = []
        output["workloads"][workload] = results
        for size in args.sizes:
            if workload in {"ingestion", "non-cve"}:
                result = ingestion(size, cves=workload == "ingestion", trace=args.trace)
            elif workload == "storage":
                result = storage(size, trace=args.trace)
            elif workload == "sanitizer":
                result = {
                    "size": size,
                    "input_bytes_each": len(html.encode()),
                    **measure(
                        lambda: sum(bool(sanitize_text(html)) for _ in range(size)),
                        trace=args.trace,
                    ),
                }
            else:
                result = {
                    "size": size,
                    **measure(
                        lambda: sum(validate_source(DETECTOR).passed for _ in range(size)),
                        trace=args.trace,
                    ),
                }
                if result["result_count"] != size:
                    raise RuntimeError("AST benchmark detector did not pass policy")
            results.append(result)
            print(json.dumps({"workload": workload, **result}), flush=True)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
