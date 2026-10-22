"""Operator CLI: autonomous collection and synthesis, explicit review and activation."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import logging.handlers
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from divalia import __version__
from divalia.ai.base_provider import create_provider
from divalia.ai.installer import check_runtime, download_runtime
from divalia.ai.ollama_provider import OllamaProvider
from divalia.ai.router import ModelRouter
from divalia.config import Config
from divalia.core.ingestion import IngestionEngine
from divalia.core.models import ThreatBriefing
from divalia.harness.ast_validator import validate_source
from divalia.harness.sandbox import SandboxRunner
from divalia.integration.detection_export import export_detection, seal_detection
from divalia.integration.publisher import Publisher
from divalia.integration.review import render_html, render_review
from divalia.pipeline import Pipeline, prepare_candidate
from divalia.storage import IDENTIFIER, ArtifactStore, atomic_write, check_path, digest

logger = logging.getLogger(__name__)


def _json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False))


def _read_json(path: Path) -> Any:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("input JSON exceeds 1 MiB")
    return json.loads(path.read_bytes())


def _pipeline(config: Config, store: ArtifactStore) -> Pipeline:
    return Pipeline(
        store, ModelRouter(config.ai), SandboxRunner(image=config.sandbox_image or None)
    )


def _round_robin_briefings(store: ArtifactStore, after: str) -> Iterator[str]:
    """Rotate filenames without decoding archived, rejected or already-built items."""
    earlier = []
    for identifier in store.iter_ids("briefings"):
        if identifier <= after:
            earlier.append(identifier)
        else:
            yield identifier
    yield from earlier


async def _cycle(config: Config, store: ArtifactStore, *, synthesize: bool, limit: int) -> dict:
    # Retain every briefing before generation; model/network failures do not consume it.
    engine = IngestionEngine(config.feeds, config.state_dir / "intelligence")
    try:
        briefs = await engine.ingest()
    finally:
        engine.close()
    for brief in briefs:
        store.save("briefings", brief.id, brief.to_dict())
    generated = []
    if synthesize:
        pipeline = _pipeline(config, store)
        cursor = ""
        if store.path("queue-state", "synthesis").exists():
            cursor = store.load("queue-state", "synthesis").get("after", "")
            if not isinstance(cursor, str) or (cursor and not IDENTIFIER.fullmatch(cursor)):
                raise ValueError("invalid synthesis queue cursor")
        pending = []
        for briefing_id in _round_robin_briefings(store, cursor):
            identifier = "candidate-" + digest(briefing_id)[:24]
            if store.path("candidates", identifier).exists():
                continue
            relevant = None
            if store.path("filter-decisions", briefing_id).exists():
                try:
                    decision = store.load("filter-decisions", briefing_id)
                    relevant = decision.get("relevant")
                except (ValueError, OSError, RecursionError) as exc:
                    # This is a cache, not authority. Re-filter malformed cache
                    # entries instead of letting one damaged file stop the queue.
                    store.audit(
                        "filter_cache_invalid",
                        briefing_id=briefing_id,
                        error_type=type(exc).__name__,
                    )
                if relevant is False:
                    continue
            pending.append((briefing_id, relevant is True))
            if len(pending) >= limit:
                break
        failures = []
        for briefing_id, already_relevant in pending:
            # Persist before model calls: an interrupted or repeatedly failing
            # briefing must not monopolize the next bounded watch cycle.
            store.save("queue-state", "synthesis", {"after": briefing_id})
            try:
                brief = ThreatBriefing.from_dict(store.load("briefings", briefing_id))
                if brief.id != briefing_id:
                    raise ValueError("briefing identity differs from its stored filename")
                if already_relevant or await pipeline.filter(brief):
                    candidate = await pipeline.synthesize(brief)
                    generated.append({"id": candidate["id"], "state": candidate["state"]})
            except (ValueError, OSError, RuntimeError, KeyError, TypeError, RecursionError) as exc:
                logger.warning(
                    "Candidate synthesis failed for %s (%s)", briefing_id, type(exc).__name__
                )
                store.audit(
                    "synthesis_failed", briefing_id=briefing_id, error_type=type(exc).__name__
                )
                failures.append({"briefing_id": briefing_id, "error_type": type(exc).__name__})
        return {"ingested": len(briefs), "generated": generated, "failures": failures}
    return {"ingested": len(briefs), "generated": generated, "failures": []}


def example_detection() -> dict[str, Any]:
    """Benign, explicit marker fixture. This demonstrates the format, not a real threat."""
    return {
        "schema_version": 1,
        "id": "divalia.example",
        "version": __version__,
        "owner": "Divalia",
        "description": "Observe-only demonstration detecting an explicit DIVALIA_TEST_MARKER.",
        "telemetry": ["process.creation"],
        "attack": ["T1059"],
        "severity": "informational",
        "confidence": 50,
        "logic": {
            "type": "sigma-subset",
            "detection": {
                "selection": {"cmdline|contains": "DIVALIA_TEST_MARKER"},
                "condition": "selection",
            },
        },
        "fixtures": [
            {
                "name": "marker",
                "event": {"cmdline": "echo DIVALIA_TEST_MARKER"},
                "expected_match": True,
            },
            {"name": "benign", "event": {"cmdline": "echo hello"}, "expected_match": False},
        ],
        "performance": {"max_eval_ms": 50, "max_events_per_second": 1000},
        "rollback": {
            "previous_digest": None,
            "instructions": "Use Angerona DetectionForge reviewed rollback.",
        },
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
    }


async def dispatch(args: argparse.Namespace, config: Config) -> int:
    if args.command == "providers":
        _json(
            {
                "local": ["ollama", "lmstudio", "llamacpp", "compatible"],
                "remote_opt_in": ["openai", "anthropic", "gemini"],
                "roles": ["light", "heavy"],
                "credentials": "environment variable names via key_env",
                "extension": "implement BaseProvider; pass it to Pipeline or extend create_provider",
            }
        )
        return 0
    if args.command == "init":
        if args.output.exists():
            raise FileExistsError("configuration already exists")
        from importlib.resources import files

        template = files("divalia").joinpath("default_config.toml").read_bytes()
        atomic_write(args.output, template)
        _json({"config": str(args.output.absolute()), "remote_inference": "disabled"})
        return 0
    if args.command == "doctor":
        import shutil

        status = {
            "version": __version__,
            "python": sys.version.split()[0],
            "docker_cli": shutil.which("docker") is not None,
            "sandbox_image_configured": bool(config.sandbox_image),
            "native_go_execution": "unsupported; blocked",
            "remote_inference": config.ai.get("allow_remote", False) is True,
        }
        try:
            router = ModelRouter(config.ai)
            status["roles"] = {}
            for role, provider in router.providers.items():
                role_status = {"model": provider.model(role), "remote": provider.allow_remote}
                if isinstance(provider, OllamaProvider):
                    role_status.update(await check_runtime(provider, roles=(role,)))
                else:
                    role_status["readiness"] = "configured; no remote request performed"
                status["roles"][role] = role_status
            status["remote_inference"] = any(row["remote"] for row in status["roles"].values())
        except (ValueError, PermissionError) as exc:
            status["provider_configuration"] = str(exc)
        _json(status)
        return 0
    if args.command == "runtime":
        provider = create_provider(config.ai)
        if not isinstance(provider, OllamaProvider):
            raise ValueError("runtime setup applies to Ollama; configure other engines separately")
        if args.pull:
            if not args.consent:
                raise PermissionError("model downloads require --consent")
            _json(await provider.pull(args.pull, consent=True))
            status = await check_runtime(provider)
            models = status.get("models", [])
            if args.pull not in models and f"{args.pull}:latest" not in models:
                raise RuntimeError(
                    "model pull succeeded but readiness listing did not include that model"
                )
            _json(status)
        elif args.download_url:
            if not args.destination or not args.sha256:
                raise ValueError("installer download requires --destination and --sha256")
            path = await asyncio.to_thread(
                download_runtime,
                args.download_url,
                args.destination,
                args.sha256,
                consent=args.consent,
            )
            _json(
                {
                    "installer": str(path),
                    "execution": "launch manually after reviewing vendor signature",
                }
            )
        else:
            _json(await check_runtime(provider))
        return 0
    if args.command == "demo":
        with tempfile.TemporaryDirectory(prefix="divalia-demo-") as directory:
            target = Path(directory) / "example.json"
            exported = export_detection(example_detection(), target)
            source = 'def detect(event):\n    if "DIVALIA_TEST_MARKER" in event.get("cmdline", ""):\n        return {"severity": "informational", "message": "test marker"}\n    return None\n'
            audit = validate_source(source)
            _json(
                {
                    "version": __version__,
                    "offline_demo": "passed",
                    "ast": audit.to_dict(),
                    "declarative_fixture_export": exported["digest"],
                    "python_execution": "not attempted; configure a pinned Linux container worker to validate candidates",
                    "activation": "requires explicit human review",
                }
            )
        return 0
    store = ArtifactStore(config.state_dir)
    if args.command == "ingest":
        _json(await _cycle(config, store, synthesize=False, limit=0))
    elif args.command in {"once", "watch"}:
        if args.command == "once":
            result = await _cycle(config, store, synthesize=True, limit=args.limit)
            _json(result)
            return (
                2
                if result["failures"]
                or any(row["state"] != "pending" for row in result["generated"])
                else 0
            )
        else:
            while True:
                _json(await _cycle(config, store, synthesize=True, limit=args.limit))
                await asyncio.sleep(config.poll_seconds)
    elif args.command == "list":
        values = store.iter_values(args.category, limit=args.limit)
        _json(
            [
                {
                    k: v.get(k)
                    for k in ("id", "title", "state", "source_sha256", "active", "probation")
                    if k in v
                }
                for v in values
            ]
        )
    elif args.command == "synthesize":
        brief = ThreatBriefing.from_dict(store.load("briefings", args.briefing_id))
        candidate = await _pipeline(config, store).synthesize(brief, feedback=args.feedback)
        _json(candidate)
        return 0 if candidate["state"] == "pending" else 2
    elif args.command == "create":
        if args.source.stat().st_size > 32768:
            raise ValueError("source exceeds 32 KiB")
        document = seal_detection(_read_json(args.detection)) if args.detection else None
        candidate = await prepare_candidate(
            store,
            SandboxRunner(image=config.sandbox_image or None),
            identifier=args.id,
            source=args.source.read_text(encoding="utf-8"),
            explanation=args.explanation,
            fixtures=_read_json(args.fixtures),
            detection=document,
        )
        _json(candidate)
        return 0 if candidate["state"] == "pending" else 2
    elif args.command == "retest":
        previous = store.load("candidates", args.candidate_id)
        candidate = await prepare_candidate(
            store,
            SandboxRunner(image=config.sandbox_image or None),
            identifier=args.candidate_id,
            source=previous["source"],
            explanation=previous["explanation"],
            fixtures=[
                {"event": event, "expected_match": expected}
                for event, expected in zip(
                    previous["telemetry"], previous["expected_matches"], strict=True
                )
            ],
            briefing_id=previous.get("briefing_id", ""),
            detection=previous.get("detection"),
            origin=previous.get("origin", "operator"),
        )
        _json(candidate)
        return 0 if candidate["state"] == "pending" else 2
    elif args.command == "validate":
        if args.source.stat().st_size > 32768:
            raise ValueError("source exceeds 32 KiB")
        source = args.source.read_text(encoding="utf-8")
        telemetry = _read_json(args.telemetry) if args.telemetry else None
        audit = validate_source(source, language=args.language)
        result = (
            await SandboxRunner(image=config.sandbox_image or None).run(source, telemetry)
            if audit.passed
            else None
        )
        _json({"audit": audit.to_dict(), "sandbox": result.to_dict() if result else None})
        return 0 if result and result.passed else 2
    elif args.command in {"review", "approve", "reject", "reprompt", "export"}:
        candidate = store.load("candidates", args.candidate_id)
        publisher = Publisher(config.state_dir, sandbox_image=config.sandbox_image)
        if args.command == "review":
            previous = candidate.get("previous_source", "")
            print(render_review(candidate, previous))
            if args.html:
                atomic_write(args.html, render_html(candidate, previous).encode())
            if args.interactive:
                if not sys.stdin.isatty():
                    raise ValueError("interactive review requires an attached terminal")
                choice = input("Choose approve, modify, reject, or leave: ").strip().lower()
                if choice == "approve":
                    reviewer = input("Reviewer name: ").strip()
                    reviewed_hash = input("Paste the reviewed source SHA-256: ").strip()
                    receipt = await publisher.approve(candidate, reviewer, reviewed_hash)
                    _json(publisher.activate(candidate, receipt))
                elif choice == "reject":
                    publisher.reject(candidate, input("Reason: ").strip())
                elif choice == "modify":
                    if not candidate.get("briefing_id"):
                        raise ValueError(
                            "Edit this operator-authored source and run create again; retest repeats validation without AI"
                        )
                    brief = ThreatBriefing.from_dict(
                        store.load("briefings", candidate["briefing_id"])
                    )
                    _json(
                        await _pipeline(config, store).synthesize(
                            brief, feedback=input("Requested changes: ")
                        )
                    )
        elif args.command == "approve":
            print(render_review(candidate, candidate.get("previous_source", "")))
            receipt = await publisher.approve(candidate, args.reviewer, args.sha256)
            _json(publisher.activate(candidate, receipt))
        elif args.command == "reject":
            publisher.reject(candidate, args.reason)
            _json({"id": args.candidate_id, "state": "rejected"})
        elif args.command == "reprompt":
            if not candidate.get("briefing_id"):
                raise ValueError(
                    "Edit this operator-authored source and run create again; retest repeats validation without AI"
                )
            brief = ThreatBriefing.from_dict(store.load("briefings", candidate["briefing_id"]))
            replacement = await _pipeline(config, store).synthesize(brief, feedback=args.feedback)
            _json(replacement)
            return 0 if replacement["state"] == "pending" else 2
        else:
            document = candidate.get("detection")
            if not isinstance(document, dict):
                raise ValueError(
                    "candidate has no declarative Angerona detection; use export-file with a reviewed package"
                )
            from divalia.integration.detection_export import validate_fixture_agreement

            validate_fixture_agreement(
                seal_detection(document),
                [
                    {"event": event, "expected_match": expected}
                    for event, expected in zip(
                        candidate["telemetry"], candidate["expected_matches"], strict=True
                    )
                ],
            )
            _json(export_detection(document, args.output, args.private_key, args.key_id))
    elif args.command == "export-file":
        _json(export_detection(_read_json(args.source), args.output, args.private_key, args.key_id))
    elif args.command == "run-event":
        result = await Publisher(config.state_dir, config.sandbox_image).run_active(
            args.plugin_id, _read_json(args.event)
        )
        _json(result)
        return 0 if result.get("passed") is True else 2
    elif args.command == "rollback":
        _json(Publisher(config.state_dir, config.sandbox_image).rollback(args.plugin_id))
    elif args.command == "download-companion":
        from divalia.integration.downloader import download_companion

        _json(
            {
                "downloaded": str(
                    await download_companion(args.commit, args.sha256, args.destination)
                ),
                "execution": "not started; review source and install in a separate environment",
            }
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="divalia",
        description="Divalia: standalone, optional module development and deployment tool for Angerona Security Suite",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--state-dir", type=Path, help="override only Divalia's artifact directory")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("providers")
    subs.add_parser("doctor")
    init = subs.add_parser("init")
    init.add_argument("--output", type=Path, default=Path("divalia.toml"))
    subs.add_parser("demo")
    subs.add_parser("ingest")
    for command in ("once", "watch"):
        child = subs.add_parser(command)
        child.add_argument("--limit", type=int, default=3)
    listing = subs.add_parser("list")
    listing.add_argument("category", choices=["briefings", "candidates", "plugins"])
    listing.add_argument(
        "--limit", type=int, default=100, help="load at most this many records (default: 100)"
    )
    synth = subs.add_parser("synthesize")
    synth.add_argument("briefing_id")
    synth.add_argument("--feedback", default="")
    creation = subs.add_parser(
        "create", help="validate your own detector and create a reviewable module candidate"
    )
    creation.add_argument("source", type=Path)
    creation.add_argument("--id", required=True)
    creation.add_argument("--fixtures", type=Path, required=True)
    creation.add_argument("--explanation", required=True)
    creation.add_argument("--detection", type=Path)
    retest = subs.add_parser(
        "retest", help="repeat a candidate's validation without generating new code"
    )
    retest.add_argument("candidate_id")
    validation = subs.add_parser("validate")
    validation.add_argument("source", type=Path)
    validation.add_argument("--telemetry", type=Path)
    validation.add_argument("--language", default="python", choices=["python", "go"])
    for command in ("review", "approve", "reject", "reprompt", "export"):
        child = subs.add_parser(command)
        child.add_argument("candidate_id")
        if command == "review":
            child.add_argument("--html", type=Path)
            child.add_argument("--interactive", action="store_true")
        elif command == "approve":
            child.add_argument("--reviewer", required=True)
            child.add_argument("--sha256", required=True)
        elif command == "reject":
            child.add_argument("--reason", default="human rejection")
        elif command == "reprompt":
            child.add_argument("--feedback", required=True)
        else:
            child.add_argument("--output", required=True, type=Path)
            child.add_argument("--private-key", type=Path)
            child.add_argument("--key-id", default="")
    export = subs.add_parser("export-file")
    export.add_argument("source", type=Path)
    export.add_argument("--output", required=True, type=Path)
    export.add_argument("--private-key", type=Path)
    export.add_argument("--key-id", default="")
    event = subs.add_parser("run-event")
    event.add_argument("plugin_id")
    event.add_argument("event", type=Path)
    rollback = subs.add_parser("rollback")
    rollback.add_argument("plugin_id")
    runtime = subs.add_parser("runtime")
    runtime.add_argument("--pull")
    runtime.add_argument("--download-url")
    runtime.add_argument("--sha256")
    runtime.add_argument("--destination", type=Path)
    runtime.add_argument("--consent", action="store_true")
    download = subs.add_parser("download-companion")
    download.add_argument("--commit", required=True)
    download.add_argument("--sha256", required=True)
    download.add_argument("--destination", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    maximum_limit = 10000 if args.command == "list" else 20
    if hasattr(args, "limit") and not 1 <= args.limit <= maximum_limit:
        print(f"Divalia: --limit must be 1..{maximum_limit}", file=sys.stderr)
        return 2
    handler = None
    try:
        path = args.config or (Path("divalia.toml") if Path("divalia.toml").is_file() else None)
        config = Config.load(path)
        if args.state_dir:
            from dataclasses import replace

            config = replace(config, state_dir=args.state_dir.expanduser().absolute())
        if args.command not in {"providers", "init", "demo"}:
            log_path = check_path(config.state_dir / "logs" / "divalia.log")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            )
            logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)
        return asyncio.run(dispatch(args, config))
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, RecursionError) as exc:
        # Error messages may contain untrusted source; JSON quoting neutralizes terminal escapes.
        print("Divalia: " + json.dumps(str(exc), ensure_ascii=True), file=sys.stderr)
        return 2
    finally:
        if handler is not None:
            logging.getLogger().removeHandler(handler)
            handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
