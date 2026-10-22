"""Capture documentation images from Divalia's real offline CLI and review HTML.

Uses an installed Chromium browser. No model is contacted and detector source
is never executed on the host. All intermediate state stays under .divalia/.
"""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SOURCE = (
    "def detect(event):\n"
    '    if "DIVALIA_TEST_MARKER" in event.get("cmdline", ""):\n'
    '        return {"severity": "informational", "message": "test marker"}\n'
    "    return None\n"
)
TELEMETRY = [{"cmdline": "echo DIVALIA_TEST_MARKER"}, {"cmdline": "echo hello"}]

STYLE = """
:root{color-scheme:dark;font-family:Segoe UI,Arial,sans-serif;color:#e8edf5;background:#0b1220}
*{box-sizing:border-box}body{margin:0}main{max-width:1600px;margin:auto;padding:38px 44px 40px}
header{display:flex;justify-content:space-between;gap:20px;align-items:center;
border-bottom:1px solid #28364e;padding-bottom:22px}
.brand{font-size:25px;font-weight:750;letter-spacing:.16em}
.tag{font-size:12px;color:#a7b7cb;letter-spacing:.08em}
.eyebrow{color:#66d9cc;letter-spacing:.13em;font-size:12px;font-weight:700;margin:28px 0 12px}
h1{font-size:37px;letter-spacing:-.035em;margin:0 0 12px}
.intro{color:#a9b8cc;font-size:16px;line-height:1.6;margin:0 0 24px}
.grid{display:grid;grid-template-columns:1.25fr 1fr;gap:20px;align-items:start}
.export-grid{grid-template-columns:.85fr 1.5fr}
.panel{background:#111c2d;border:1px solid #293850;border-radius:12px;overflow:hidden}
h2{font-size:15px;margin:0;padding:17px 22px;background:#17243a;color:#d9e5f4}
pre{font-family:Consolas,Menlo,monospace;font-size:12px;line-height:1.55;white-space:pre-wrap;
overflow-wrap:anywhere;color:#b9cbe0;padding:20px 22px;margin:0;tab-size:4}
.command{font-size:12px;color:#6ce3ba;background:#0c1728;padding:14px 22px;
font-family:Consolas,Menlo,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.note{color:#a6b8ce;font-size:13px;line-height:1.7;margin:20px 0 0}
.notice{margin-top:20px;padding:20px 22px;border-left:3px solid #66d9cc;background:#111c2d;
color:#bdccdf;font-size:14px;line-height:1.7;border-radius:0 8px 8px 0}
.notice strong{color:#e8edf5}.pill{color:#ffc884;font-size:12px;font-weight:650}
.package pre{font-size:11px;line-height:1.35;padding:16px 22px}
footer{font-size:12px;line-height:1.7;color:#8fa1b9;margin-top:22px}
"""


def browser_path(requested: str | None) -> str:
    """Find an existing Chrome, Chromium, or Edge binary; never install one."""
    candidates = [requested] if requested else []
    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        base = os.environ.get(variable)
        if base:
            candidates.extend(
                str(Path(base) / relative)
                for relative in (
                    "Google/Chrome/Application/chrome.exe",
                    "Microsoft/Edge/Application/msedge.exe",
                )
            )
    candidates.extend(
        shutil.which(name)
        for name in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge")
    )
    candidates.append("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    for value in candidates:
        if value and Path(value).is_file():
            return str(Path(value).resolve())
    raise RuntimeError("No Chromium browser found; provide --browser /path/to/browser")


def cli(work: Path, *arguments: str) -> str:
    """Collect actual stdout, with no shell and a source-checkout import path."""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "divalia", *arguments],
        cwd=work, env=environment, capture_output=True, text=True,
        encoding="utf-8", check=True, timeout=30, shell=False,
    )
    if result.stderr.strip():
        raise RuntimeError("CLI emitted unexpected stderr during offline capture")
    return result.stdout


def transcript(title: str, command: str, output: str, *, package: bool = False) -> str:
    return (
        f'<section class="panel{" package" if package else ""}">'
        f"<h2>{html.escape(title)}</h2>"
        f'<div class="command">$ {html.escape(command)}</div>'
        f"<pre>{html.escape(output)}</pre></section>"
    )


def document(title: str, introduction: str, content: str, footer: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{html.escape(title)}</title><style>{STYLE}</style></head><body><main>
<header><div class="brand">DIVALIA <span class="tag">/ 2.0</span></div>
<div class="tag">STANDALONE MODULE TOOLING FOR ANGERONA SECURITY SUITE</div></header>
<p class="eyebrow">MODULE DEVELOPMENT &amp; DEPLOYMENT</p>
<h1>{html.escape(title)}</h1><p class="intro">{html.escape(introduction)}</p>
{content}<footer>{html.escape(footer)}</footer></main></body></html>"""


def capture(browser: str, work: Path, source: Path, output: Path, height: int) -> dict:
    """Use a separate, hidden headless profile; preserve existing browser state."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="browser-", dir=work) as profile:
        result = subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--no-first-run",
             "--no-default-browser-check", "--disable-background-networking",
             "--hide-scrollbars", "--force-device-scale-factor=1",
             f"--user-data-dir={profile}", f"--window-size=1600,{height}",
             f"--screenshot={output}", source.as_uri()],
            cwd=work, capture_output=True, timeout=45, shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    if result.returncode or not output.is_file():
        raise RuntimeError(f"Browser failed to capture {output.name}")
    payload = output.read_bytes()
    if payload[:8] != b"\x89PNG\r\n\x1a\n":
        raise RuntimeError(f"Browser did not write a PNG: {output.name}")
    dimensions = struct.unpack(">II", payload[16:24])
    if dimensions != (1600, height):
        raise RuntimeError(f"Unexpected screenshot dimensions: {dimensions}")
    return {"file": output.relative_to(ROOT).as_posix(), "dimensions": list(dimensions),
            "bytes": len(payload)}


async def prepare(work: Path) -> dict[str, Path]:
    """Seed an explicitly benign example and run the real offline operations."""
    from divalia.cli import example_detection
    from divalia.harness.ast_validator import validate_source
    from divalia.harness.sandbox import SandboxRunner
    from divalia.storage import ArtifactStore, digest

    state = work / "state"
    audit = validate_source(SOURCE)
    sandbox = await SandboxRunner(image="").run(SOURCE, TELEMETRY)
    if not audit.passed or sandbox.status != "unavailable" or sandbox.passed:
        raise RuntimeError("The example must show AST eligibility with isolation unavailable")
    candidate = {
        "id": "candidate-marker-demo", "state": "blocked",
        "source": SOURCE, "source_sha256": digest(SOURCE),
        "explanation": (
            "Benign demonstration: flag only the explicit DIVALIA_TEST_MARKER in process "
            "telemetry. The AST policy passed. No pinned container image is configured, "
            "so isolated testing is unavailable and approval remains blocked. "
            "This fixture is not a real threat detection."
        ),
        "audit": audit.to_dict(), "sandbox": sandbox.to_dict(),
        "telemetry": TELEMETRY, "expected_matches": [True, False],
        "detection": example_detection(),
    }
    ArtifactStore(state).save("candidates", candidate["id"], candidate)
    # A dedicated empty config prevents loading a developer's real configuration.
    (work / "capture.toml").write_text('[app]\nstate_dir = "state"\n', encoding="utf-8")
    common = ("--config", "capture.toml", "--state-dir", "state")
    review_output = cli(work, *common, "review", candidate["id"], "--html", "module-review.html")
    (work / "review-output.txt").write_text(review_output, encoding="utf-8")

    help_output = cli(work, "--help")
    providers_output = cli(work, *common, "providers")
    (work / "help-output.txt").write_text(help_output, encoding="utf-8")
    (work / "providers-output.txt").write_text(providers_output, encoding="utf-8")
    workflow = document(
        "Develop modules with your preferred models",
        "Rendered CLI transcript · Actual command output captured offline from this checkout.",
        '<div class="grid">'
        + transcript("Discover the module workflow", "python -m divalia --help", help_output)
        + '<div>'
        + transcript("Available provider adapters", "python -m divalia providers", providers_output)
        + '<div class="notice"><strong>Configure each model role</strong><br>'
        'Use light models for filtering and heavy models for synthesis. Add provider, '
        'endpoint, model and key_env settings in your local configuration. Remote inference '
        'requires explicit opt-in; API keys stay in environment variables.</div></div></div>',
        "Rendered transcript, not a native terminal screenshot. No provider was contacted; "
        "this view does not claim installed runtimes, downloaded models or configured credentials.",
    )
    (work / "cli-workflow.html").write_text(workflow, encoding="utf-8")

    (work / "marker-package.json").write_text(
        json.dumps(candidate["detection"], indent=2) + "\n", encoding="utf-8"
    )
    destination = work / "exported" / "angerona-marker.json"
    # A fresh run has its own private directory, so an existing output is never replaced.
    export_output = cli(work, *common, "export-file", "marker-package.json",
                        "--output", "exported/angerona-marker.json")
    package_result = subprocess.run(
        [sys.executable, "-m", "json.tool", "exported/angerona-marker.json"],
        cwd=work, capture_output=True, text=True, encoding="utf-8", check=True,
        timeout=10, shell=False,
    )
    package_output = package_result.stdout
    (work / "export-output.txt").write_text(export_output, encoding="utf-8")
    (work / "package-output.txt").write_text(package_output, encoding="utf-8")
    if not destination.is_file():
        raise RuntimeError("CLI did not produce the deployment package")
    # The receipt is otherwise verbatim; do not publish machine-specific paths.
    display_receipt = export_output.replace(
        json.dumps(str(work))[1:-1], "[demo-workspace]"
    ).replace(str(work), "[demo-workspace]")
    deployment = document(
        "Prepare an Angerona deployment package",
        "Rendered CLI transcript · A real declarative export prepared for DetectionForge review; no activation.",
        '<div class="grid export-grid"><div>'
        + transcript("Actual export receipt",
                     "python -m divalia export-file marker-package.json "
                     "--output exported/angerona-marker.json", display_receipt)
        + '<div class="notice"><strong>Next: Angerona DetectionForge</strong><br>'
        'Import the package, review its fixtures and evidence, and apply Angerona\'s trust '
        'and promotion gates. This example is unsigned and observes a benign marker only.'
        '<br><span class="pill">No Angerona activation was performed.</span></div>'
        '<p class="note">The transient absolute workspace path in the receipt is redacted '
        'as [demo-workspace]. All other command output is unchanged.</p></div>'
        + transcript("Exported package · complete JSON",
                     "python -m json.tool exported/angerona-marker.json", package_output,
                     package=True)
        + '</div>',
        "Rendered transcript, not a native terminal screenshot. Divalia exports a declarative "
        "package; Angerona independently owns import, trust, evaluation and promotion.",
    )
    (work / "deployment-package.html").write_text(deployment, encoding="utf-8")
    return {name: work / f"{name}.html" for name in
            ("module-review", "cli-workflow", "deployment-package")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", help="existing Chrome, Chromium or Edge executable")
    args = parser.parse_args()
    browser = browser_path(args.browser)
    private = ROOT / ".divalia" / "screenshots"
    private.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="capture-", dir=private)).resolve()
    pages = asyncio.run(prepare(work))
    heights = {"module-review": 1100, "cli-workflow": 1100, "deployment-package": 1240}
    results = [capture(browser, work, source, ROOT / "docs" / "images" / f"{name}.png",
                       heights[name]) for name, source in pages.items()]
    (work / "capture-manifest.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps({"screenshots": results,
                      "intermediates": work.relative_to(ROOT).as_posix(),
                      "network_inference": False, "host_detector_execution": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
