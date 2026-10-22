# Validation record

The initial 2.0.0 implementation was validated on Windows with CPython 3.12.10.
Final local result with Angerona compatibility enabled: **81 passed, 2 skipped,
129 subtests passed**. Ruff, compilation, dependency consistency, the offline
demo, source/wheel builds and an import/demo smoke check of the built wheel
passed. The two skips are real-container tests because Docker is unavailable.
The offline suite covers ingestion schemas, sanitization, source isolation,
durable/semantic deduplication, DNS/redirect/response limits, hostile ASTs,
container command restrictions and cleanup, provider protocol shapes and privacy
gates, model output parsing, fixture semantics, receipt tampering/replay,
quarantine, probation/rollback, safe ZIP extraction, package signatures, CLI
behavior, and GitHub publication refusal conditions.

No paid API requests or model downloads were performed during development.
Provider tests inject synthetic credentials and fake HTTP responses. Generated
source is never executed on the host, including during offline tests.

Offline commands:

```powershell
python -m ruff check src tests tools
python -m compileall -q src tools
python -m pytest -q
python -m divalia demo
python -m build
```

Angerona interoperability tests run only when its source location is explicitly
provided:

```powershell
$env:DIVALIA_ANGERONA_SRC = 'D:/local-security-ai/AngeronaSuite/src'
python -m pytest -q tests/test_angerona_compatibility.py
```

These checks import Angerona's package contract, not the application or GUI.
They verify canonical Unicode digest parity, mixed telemetry field semantics,
exact-byte Ed25519 signature verification, malformed fixtures and tamper
rejection. A discovered `severity = null` normalization mismatch was corrected
in the exporter. No Angerona repository files were changed.

Docker was not available on the local development machine. Real isolated
execution tests are therefore explicitly skipped locally; sandbox unavailable
and fail-closed paths are exercised. To test a reviewed worker:

```powershell
$env:DIVALIA_TEST_SANDBOX_IMAGE = 'sha256:YOUR_IMMUTABLE_WORKER_ID'
python -m pytest -q tests/test_live_sandbox.py
```

GitHub CI defines a real Linux-container job that builds an immutable worker
and executes positive/negative fixtures plus a runtime exception. Separate
jobs validate Python 3.11, 3.12 and 3.13 on Linux and Windows. A workflow definition
alone is not evidence that remote CI passed; inspect the run for the published
commit before relying on those environments.

Publication uses a reviewed clean main commit, the exact canonical Divalia HTTPS
origin, an atomic non-forced push, ancestry checks against existing public main,
and post-push checks of public/default main, local HEAD/branch, clean worktree
and byte-identical public README. There are no relative README image assets;
the publisher fails closed if any are introduced without a decoder-backed
validity verifier. Divergence is reported without merge, rebase, reset or force.
