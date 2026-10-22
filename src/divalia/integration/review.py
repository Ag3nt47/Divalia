"""Human-readable evidence. All generated prose and source remain untrusted."""

from __future__ import annotations

import difflib
import html
import json
from typing import Any


def render_review(candidate: dict[str, Any], previous_source: str = "") -> str:
    """Render a plain-text review with a digest and a unified source diff."""
    from divalia.storage import digest

    source = str(candidate.get("source", ""))
    # JSON quoting keeps control characters and forged terminal escape codes inert.
    explanation = json.dumps(candidate.get("explanation", ""), ensure_ascii=True)
    report = json.dumps(
        {
            "audit": candidate.get("audit"),
            "sandbox": candidate.get("sandbox"),
            "telemetry": candidate.get("telemetry"),
            "expected_matches": candidate.get("expected_matches"),
            "angerona_detection": candidate.get("detection"),
            "detection_audit": candidate.get("detection_audit"),
            "quarantine_reason": candidate.get("quarantine_reason"),
        },
        indent=2,
        ensure_ascii=True,
    )
    diff = "\n".join(
        difflib.unified_diff(
            previous_source.splitlines(),
            source.splitlines(),
            fromfile="previous.py",
            tofile="candidate.py",
            lineterm="",
        )
    )
    # Quote unusual characters in source so malicious comments cannot control a terminal.
    safe_diff = "".join(
        ch if ch in "\n\t" or 32 <= ord(ch) < 127 else f"\\u{ord(ch):04x}" for ch in diff
    )
    return (
        f"Divalia Angerona module candidate {json.dumps(candidate.get('id', ''))}\n"
        f"Candidate state: {json.dumps(candidate.get('state', 'unknown'))}\n"
        f"Source SHA-256: {digest(source)}\nExplanation: {explanation}\n"
        f"Validation evidence:\n{report}\n\n{safe_diff}\n"
    )


def render_html(candidate: dict[str, Any], previous_source: str = "") -> str:
    """Return a standalone side-by-side diff without scripts or external assets."""
    from divalia import __version__
    from divalia.storage import digest

    display_version = ".".join(__version__.split(".")[:2])
    source = str(candidate.get("source", ""))
    diff = difflib.HtmlDiff(wrapcolumn=88).make_table(
        previous_source.splitlines(),
        source.splitlines(),
        fromdesc="Previous source",
        todesc="Candidate source",
        context=False,
    )
    evidence = html.escape(render_review(candidate, previous_source))
    audit = candidate.get("audit") if isinstance(candidate.get("audit"), dict) else {}
    sandbox = candidate.get("sandbox") if isinstance(candidate.get("sandbox"), dict) else {}
    audit_passed = audit.get("passed") is True
    sandbox_passed = sandbox.get("passed") is True
    audit_label = "Policy passed" if audit_passed else "Needs attention"
    isolation_label = html.escape(str(sandbox.get("status", "not run")))
    identifier = html.escape(str(candidate.get("id", "unknown")))
    state = html.escape(str(candidate.get("state", "unknown")))
    explanation = html.escape(str(candidate.get("explanation", "No explanation provided.")))
    ast_class = "passed" if audit_passed else "blocked"
    sandbox_class = "passed" if sandbox_passed else "blocked"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Divalia | Angerona module development and deployment review</title>
<style>
:root{{color-scheme:dark;font-family:Segoe UI,Arial,sans-serif;color:#e8edf5;background:#0b1220}}
*{{box-sizing:border-box}}body{{margin:0}}main{{max-width:1520px;margin:auto;padding:38px 44px 48px}}
header{{display:flex;justify-content:space-between;gap:20px;align-items:center;border-bottom:1px solid #28364e;padding-bottom:22px}}
.brand{{font-size:25px;font-weight:750;letter-spacing:.16em}}.tag{{font-size:12px;color:#a7b7cb;letter-spacing:.08em}}
.eyebrow{{color:#66d9cc;letter-spacing:.13em;font-size:12px;font-weight:700;margin:30px 0 12px}}
h1{{font-size:37px;letter-spacing:-.035em;margin:0 0 12px}}.intro{{color:#a9b8cc;font-size:16px;line-height:1.6;margin:0}}
.status-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:15px;margin:25px 0}}
.card,.panel{{background:#111c2d;border:1px solid #293850;border-radius:12px}}
.card{{padding:18px 22px}}.label{{color:#91a3bb;font-size:11px;letter-spacing:.10em;text-transform:uppercase}}
.value{{font-size:18px;font-weight:650;margin:9px 0 6px}}.passed{{color:#6ce3ba}}.blocked{{color:#ffc884}}
.note{{font-size:12px;color:#9bacc2;line-height:1.5}}.panel{{padding:22px 24px;margin:18px 0}}
h2{{font-size:18px;margin:0 0 14px}}.explanation{{font-size:14px;line-height:1.7;color:#ccd5e4;white-space:pre-wrap;margin:0}}
.identity{{display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin:0 0 16px}}
code,pre,table.diff{{font-family:Consolas,Menlo,monospace}}code{{font-size:12px;color:#a6b8ce;overflow-wrap:anywhere}}
.diff-wrap{{overflow-x:auto;border:1px solid #31425d;border-radius:8px;background:#0c1524}}
table.diff{{border-collapse:collapse;width:100%;font-size:12px;line-height:1.9}}
table.diff th{{background:#1b2a40;color:#dae5f2;font-weight:600;padding:10px 12px;text-align:left}}
table.diff td{{vertical-align:top;padding:2px 8px;white-space:nowrap}}
.diff_header{{background:#142137;color:#8fa3bd}}.diff_next{{background:#18263a;width:18px}}
table.diff a{{color:#8fb8dd}}.diff_add{{background:#164637;color:#c0f6d8}}
.diff_sub{{background:#522d38;color:#ffd4d9}}.diff_chg{{background:#5b4a28;color:#ffe3ad}}
summary{{cursor:pointer;font-size:14px;font-weight:650}}pre{{font-size:12px;line-height:1.6;white-space:pre-wrap;overflow-wrap:anywhere;color:#b5c5d9}}
.deployment{{border-left:3px solid #66d9cc}}.deployment p{{font-size:14px;color:#bdccdf;line-height:1.7;margin:0}}
footer{{font-size:12px;line-height:1.7;color:#8fa1b9;margin-top:22px}}
@media(max-width:800px){{main{{padding:24px 18px}}header{{align-items:flex-start;flex-direction:column}}h1{{font-size:29px}}.status-grid{{grid-template-columns:1fr}}}}
</style></head><body><main>
<header><div class="brand">DIVALIA <span class="tag">/ {html.escape(display_version)}</span></div>
<div class="tag">STANDALONE MODULE TOOLING FOR ANGERONA SECURITY SUITE</div></header>
<p class="eyebrow">MODULE DEVELOPMENT &amp; DEPLOYMENT</p>
<h1>Review an Angerona module candidate</h1>
<p class="intro">Inspect the code, validation evidence and telemetry before approving a version or preparing a deployment package.</p>
<section class="status-grid" aria-label="Validation status">
<div class="card"><div class="label">AST security policy</div><div class="value {ast_class}">{audit_label}</div>
<div class="note">Allowlist compliance; not a security guarantee.</div></div>
<div class="card"><div class="label">Isolated Python testing</div><div class="value {sandbox_class}">{isolation_label}</div>
<div class="note">A passing container test is required for approval.</div></div>
<div class="card"><div class="label">Deployment authority</div><div class="value">Human review required</div>
<div class="note">Angerona retains its trust and promotion gates.</div></div></section>
<section class="panel"><h2>Module purpose &amp; evidence limits</h2><p class="explanation">{explanation}</p></section>
<section class="panel"><h2>Source changes</h2><div class="identity"><span class="note">Candidate: {identifier} · State: {state}</span>
<code>SHA-256 {digest(source)}</code></div><div class="diff-wrap">{diff}</div></section>
<details class="panel"><summary>Validation evidence, telemetry fixtures and package details</summary><pre>{evidence}</pre></details>
<section class="panel deployment"><h2>Deploy through Angerona DetectionForge</h2>
<p>Export the reviewed declarative detection package, then import, review and promote it in Angerona.
Python version activation and probation rollback apply to Divalia's isolated runtime.</p></section>
<footer>This is a read-only review report. Use the Divalia CLI to approve, modify or reject a candidate.
No module is activated by opening this page. Source review and deployment approval remain explicit operator actions.</footer>
</main></body></html>"""
