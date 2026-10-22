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
    report = json.dumps({"audit": candidate.get("audit"), "sandbox": candidate.get("sandbox"),
                         "telemetry": candidate.get("telemetry"),
                         "expected_matches": candidate.get("expected_matches"),
                         "angerona_detection": candidate.get("detection")},
                        indent=2, ensure_ascii=True)
    diff = "\n".join(difflib.unified_diff(
        previous_source.splitlines(), source.splitlines(),
        fromfile="previous.py", tofile="candidate.py", lineterm="",
    ))
    # Quote unusual characters in source so malicious comments cannot control a terminal.
    safe_diff = "".join(ch if ch in "\n\t" or 32 <= ord(ch) < 127 else
                        f"\\u{ord(ch):04x}" for ch in diff)
    return (f"Divalia candidate {json.dumps(candidate.get('id', ''))}\n"
            f"Source SHA-256: {digest(source)}\nExplanation: {explanation}\n"
            f"Validation evidence:\n{report}\n\n{safe_diff}\n")


def render_html(candidate: dict[str, Any], previous_source: str = "") -> str:
    """Return a standalone side-by-side diff without scripts or external assets."""
    diff = difflib.HtmlDiff(wrapcolumn=88).make_table(
        previous_source.splitlines(), str(candidate.get("source", "")).splitlines(),
        fromdesc="Previous source", todesc="Candidate source", context=False,
    )
    evidence = html.escape(render_review(candidate, previous_source))
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
            "style-src 'unsafe-inline'\"><title>Divalia review</title>"
            "<style>body{font:14px monospace}table{border-collapse:collapse;width:100%}"
            "td{vertical-align:top}.diff_add{background:#cfc}.diff_sub{background:#fcc}"
            ".diff_chg{background:#ffc}pre{white-space:pre-wrap}</style>"
            f"<body><h1>Divalia candidate review</h1><pre>{evidence}</pre>{diff}</body></html>")
