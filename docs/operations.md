# Angerona module development and deployment workflow

Use Divalia to develop and test modules for Angerona, then prepare reviewed
detection packages for deployment through Angerona DetectionForge. Divalia is a
standalone, optional tool; its isolated Python module runtime is separate from
Angerona's live activation authority.

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

`doctor` reports light and heavy roles independently after applying their
overrides. Ollama roles list the models available on their configured runtime
and identify missing models for that role. Other providers are reported as
configured without a remote inference request. Inspect the report: the Docker
CLI being present and an image being configured do not establish that the
daemon is usable or that a candidate passed its tests.

Check or pull models with the `runtime` command. Pulling requires an explicit
model name and `--consent`; weights may be large. An offline model server or a
missing model produces a logged failure and leaves the briefing available for
later synthesis. Configure and build the pinned worker described in README
before expecting Python tests or approvals to pass.

```powershell
# Collection only: no model or Docker needed.
divalia --config divalia.toml ingest
divalia --config divalia.toml list briefings --limit 20

# Filter and synthesize a bounded batch; no automatic approval.
divalia --config divalia.toml once --limit 3
divalia --config divalia.toml watch --limit 3
divalia --config divalia.toml list candidates --limit 20

# Review source, rationale, digests and test evidence.
divalia --config divalia.toml review CANDIDATE_ID --html review.html
divalia --config divalia.toml review CANDIDATE_ID --interactive

# Explicit noninteractive operator approval requires the exact reviewed digest.
divalia --config divalia.toml approve CANDIDATE_ID --reviewer YOUR_NAME --sha256 REVIEWED_SHA256

# Editing/re-prompting invalidates prior approval; review again.
divalia --config divalia.toml reprompt CANDIDATE_ID --feedback "Add a benign administrator case"
divalia --config divalia.toml reject CANDIDATE_ID --reason "Insufficient evidence"
```

`list` defaults to 100 artifacts and accepts `--limit 1..10000`, in identifier
filename order. Only selected records are decoded. `once` and `watch` accept a
batch limit of 1..20; they check existing candidates and negative filter
decisions before loading pending briefing content. A persisted round-robin
cursor advances before each attempted briefing and wraps after the final
identifier, so one failing early record does not monopolize later batches.
Cached positive filter decisions avoid repeating the light-model call when
heavy synthesis needs a retry. Malformed filter-cache entries are audited and
re-filtered. Failed requests leave the briefing available and appear in the
result's `failures` array. `once` returns exit status 2 for synthesis failures or
any generated candidate that is not `pending`, including blocked or quarantined
candidates.

## Write a module without AI

Create `marker_detector.py` with a small, observe-only detector. This fixture
checks an explicit test marker; it is not a real threat signature:

```python
def detect(event):
    if "DIVALIA_TEST_MARKER" in event.get("cmdline", ""):
        return {"severity": "informational", "message": "test marker"}
    return None
```

Save `fixtures.json` with both a benign event and a matching event:

```json
[
  {"event": {"cmdline": "echo hello"}, "expected_match": false},
  {"event": {"cmdline": "echo DIVALIA_TEST_MARKER"}, "expected_match": true}
]
```

Create and review the candidate:

```powershell
divalia --config divalia.toml create marker_detector.py --id marker-observer --fixtures fixtures.json --explanation "Observe an explicit marker in process command lines"
divalia --config divalia.toml review marker-observer --html review.html
divalia --config divalia.toml retest marker-observer
```

`create` and `retest` do not contact an AI provider. They use the same AST,
container protocol and hit/miss checks as model-generated candidates. Source
must fit in 32 KiB, the explanation in 12,000 characters, and the suite must
contain 2..16 fixtures with real boolean labels and both matching and
nonmatching events. The sandbox result must bind to the exact source and
fixture suite; a claimed `passed` field is insufficient.

A successful candidate is `pending` human review. A missing worker or failed
test produces a reviewable `blocked` candidate and exit status 2. Retesting a
quarantined source preserves quarantine. No approval or activation happens
during either command.

Edit your source or fixtures and run `create` again with the same ID to make a
revision. Divalia retains the prior source for a diff and requires fresh
approval. `retest` repeats the stored source and fixtures without changing the
module or asking a model to revise it. Use `reprompt` only for candidates
associated with an ingested briefing.

Optionally append `--detection reviewed-rule.json` to `create` to attach a
declarative Angerona package. The package is validated separately and receives
its own `detection_audit`. Source code is not automatically translated into an
Angerona rule. Export and DetectionForge promotion remain separate review steps.

For a practical module with an accompanying declarative package, use the
[encoded PowerShell example](../examples/encoded-powershell/README.md). Its 14
synthetic fixtures cover mixed case, quoted executable paths, benign scripts,
missing/null/numeric fields and lookalike switches. It requires an executable
basename in `process_name` and ordinary-space-normalized `cmdline` arguments;
raw process paths and tab-separated switches deliberately do not match. Review
the example's coverage and false positives before mapping real sensor events.

## Review and activate in Divalia

CLI approval activates only the Divalia isolated plugin. Submit a telemetry JSON
object with `run-event CANDIDATE_ID event.json`. Probation needs at least three
successful events and 60 seconds since activation. It advances only when events
arrive; no host execution or background telemetry capture occurs. A failing run
returns a nonzero exit status and rolls back or disables the version. Use
`rollback CANDIDATE_ID` for explicit quarantine and rollback.

Malformed telemetry is checked before entering the active-module execution
path; input rejected by that validation does not quarantine a healthy module.
A valid telemetry object that exposes a detector exception still triggers
rollback. Canceling a test propagates cancellation while reaping its subprocess
and attempting bounded cleanup of its named container.

Re-prompting the same briefing retains the plugin identity, stores the prior
source for a diff, and requires fresh approval for changed content. Unreviewed
source is never imported. Logs rotate under `state_dir/logs`; artifacts,
receipts, quarantines, versions and `audit.jsonl` remain under `state_dir`.

For operator-authored candidates, use the same `approve` command shown above
with the ID and exact SHA-256 displayed in review. Passing tests and receipt
checks are repeated at approval; retesting alone never authorizes deployment.

Activation checks the receipt, quarantine state, existing active version and
probation before writing version data. Review snapshots remain immutable,
including a fresh review of byte-identical source: receipt-specific records
preserve the exact evidence and consent used for activation and rollback.
Rejecting a candidate updates its development record to `rejected`, visible in
`list candidates`, and quarantines its source without overwriting those review
snapshots. Retesting cannot clear that quarantine.

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

An attached package is also evaluated against the Python prototype's declared
fixtures during candidate preparation and again during candidate export. A
package that passes its own tests but disagrees with those labels fails this
agreement check. Passing shared fixtures is evidence for those cases; it does
not prove equivalence for all telemetry. Declarative comparisons run locally;
Python detector source still runs only inside the restricted worker.

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

Diagnostic performance workloads and review findings are documented in
[the performance review](performance-review.md). On CPU-only inference,
choose models and per-role timeouts for the available hardware; model loading
and code generation can take substantially longer than local AST/fixture setup.
