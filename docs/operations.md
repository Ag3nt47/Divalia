# Operator workflow

Use a dedicated virtual environment and a private Divalia state directory.
Create configuration with `divalia init`, edit the two model roles, and run
`divalia --config divalia.toml doctor`. The config template includes KEV and
GitHub collectors; add RSS/Atom, NVD and curated social endpoints explicitly.
Social collection uses Mastodon-compatible JSON, not arbitrary scraping.

Model names are not hard-coded in adapters. Set any name your engine supports.
`[ai.light]` and `[ai.heavy]` may independently override provider, endpoint,
model names, timeout, `key_env` and `allow_remote`. Set API credentials through
your process environment or secret manager before starting Divalia. Select
custom hosted chat-completions services with `compatible` and HTTPS plus
`allow_remote = true`. Local endpoints require literal loopback addresses.

Check or pull models with the `runtime` command. Pulling requires an explicit
model name and `--consent`; weights may be large. An offline model server or a
missing model produces a logged failure and leaves the briefing available for
later synthesis. Configure and build the pinned worker described in README
before expecting Python tests or approvals to pass.

```powershell
# Collection only: no model or Docker needed.
divalia --config divalia.toml ingest
divalia --config divalia.toml list briefings

# Filter and synthesize a bounded batch; no automatic approval.
divalia --config divalia.toml once --limit 3
divalia --config divalia.toml watch --limit 3
divalia --config divalia.toml list candidates

# Review source, rationale, digests and test evidence.
divalia --config divalia.toml review CANDIDATE_ID --html review.html
divalia --config divalia.toml review CANDIDATE_ID --interactive

# Explicit noninteractive operator approval requires the exact reviewed digest.
divalia --config divalia.toml approve CANDIDATE_ID --reviewer YOUR_NAME --sha256 REVIEWED_SHA256

# Editing/re-prompting invalidates prior approval; review again.
divalia --config divalia.toml reprompt CANDIDATE_ID --feedback "Add a benign administrator case"
divalia --config divalia.toml reject CANDIDATE_ID --reason "Insufficient evidence"
```

CLI approval activates only the Divalia isolated plugin. Submit a telemetry JSON
object with `run-event CANDIDATE_ID event.json`. Probation needs at least three
successful events and 60 seconds since activation. It advances only when events
arrive; no host execution or background telemetry capture occurs. A failing run
returns a nonzero exit status and rolls back or disables the version. Use
`rollback CANDIDATE_ID` for explicit quarantine and rollback.

Re-prompting the same briefing retains the plugin identity, stores the prior
source for a diff, and requires fresh approval for changed content. Unreviewed
source is never imported. Logs rotate under `state_dir/logs`; artifacts,
receipts, quarantines, versions and `audit.jsonl` remain under `state_dir`.

## Export to Angerona

If synthesis includes a valid declarative package:

```powershell
divalia --config divalia.toml export CANDIDATE_ID --output reviewed-rule.json
# Optional exact-byte signature with a separately managed Ed25519 PKCS8 PEM key:
divalia --config divalia.toml export CANDIDATE_ID --output signed-rule.json --private-key publisher.pem --key-id YOUR_PUBLISHER_ID
```

Exports are candidates for Angerona review, not activation receipts. Output
files must be new to prevent stale detached signatures. `export-file input.json
--output reviewed-rule.json` accepts an operator-authored package. The
declarative exporter supports a strict subset of Angerona's schema and requires
both matching and nonmatching fixtures. Do not edit a signed export afterward.

Import the JSON and optional `.sig.json` in Angerona's DetectionForge. Enroll
the publisher through its existing trust workflow and obtain its own replay
and promotion approvals. Angerona owns live activation and rollback. Selecting
an Angerona data directory in Divalia does not grant permission to edit registry
files, bypass signatures or hot-load external source.

## Optional companion download hook

`download_companion(commit, expected_sha256, destination)` fetches the canonical
GitHub ZIP at a full commit SHA, verifies a separately trusted archive digest,
rejects traversal/symlinks/special files and extracts into a new directory.
The CLI exposes it as `download-companion --commit SHA --sha256 HASH
--destination PATH`. This is an on-demand library/CLI hook for a future settings
integration; there is no web listener or automatic execution. Review the source
and install into its own environment after download.

## Recovery and limits

- Missing Docker, worker image, model or credentials is an unavailable state;
  there is no permissive fallback.
- After a process crash, a remaining `publisher.lock` blocks writers. Confirm
  no Divalia process owns it, back up state, and remove only that lock. Never
  delete approval receipts or consumed markers to reuse consent.
- Preserve `approval.key` with the private state directory. Losing it makes
  existing receipt authentication fail closed. Create fresh reviewed state
  rather than forging replacement receipts.
- Exported detections do not authorize automatic mitigations. Test quality and
  operational policy remain separate human decisions.
