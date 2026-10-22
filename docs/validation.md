# Validation record

The initial 1.0.0 implementation was validated on Windows with CPython 3.12.10.
Initial local result with Angerona compatibility enabled: **81 passed, 2 skipped,
129 subtests passed**. Ruff, compilation, dependency consistency, the offline
demo, source/wheel builds and an import/demo smoke check of the built wheel
passed. The two skips are real-container tests because Docker is unavailable.

The module-tool positioning and screenshot update passed **99 tests and 129
subtests**, with 3 skips: the two real-container tests and a Windows symlink test
unavailable under the local host's permissions. The three screenshots were
visually reviewed, decoded successfully, and include real CLI/review output with
demo and unavailable states labeled. Publication tests cover corrupted,
untracked, redirected and uncommitted image assets as well as exact HEAD bytes.
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
and byte-identical public README. Every relative README screenshot must be
repository-confined, tracked in the reviewed HEAD, decoder-valid, and identical
both to its committed bytes and its public main asset. Divergence is reported
without merge, rebase, reset or force.

## October 22, 2026: performance and real module-workflow review

The final local full suite passed on Windows/CPython 3.12.10 with
`DIVALIA_ANGERONA_SRC` explicitly set: **141 passed, 211 subtests passed,
6 skipped in 170.96 seconds**. Four skipped tests require a real immutable Linux
Docker worker; the Docker CLI is absent locally. Two symlink checks require
privileges unavailable to this account. A skipped execution test is not a
passing container result.

Ruff across `src`, `tests`, `tools` and `examples`, compilation, `pip check`,
source/wheel builds and an import/resource/offline-demo check of the built wheel
passed. All three README screenshots were regenerated and visually inspected.
The practical [encoded PowerShell example](../examples/encoded-powershell/README.md)
contains a Python prototype, 14 labeled synthetic events and a matching Angerona
package. Coverage includes normalization requirements and benign/unsupported
cases; it does not prove the rule detects every encoded command or establishes
maliciousness.

The review adds direct `create`/`retest` workflows, a fair bounded synthesis
queue, cached positive relevance, lazy archive reads, bounded near-duplicate
indexing, per-role readiness, cancellable inference and lifecycle fixes. Tests
cover source/fixture/result bindings, declarative package agreement, review
snapshot preservation, activation preconditions, cancellation cleanup, rejected
status and malformed telemetry that must not quarantine a healthy module.
Performance observations, allocator peaks, interrupted baseline cases and
busy-host limitations are recorded in [the performance review](performance-review.md)
with sanitized machine-readable measurements.

A real CPU-only local Ollama trial with `llama3.2:3b` returned valid light-role
classification JSON in **85.93 seconds**. A first heavy response took **58.15
seconds**, but its `source` was an object rather than the required Python-source
string; the raw proposal was rejected. It omitted the optional declarative
package. After clarifying the prompt, a heavy rerun reached the configured
whole-request timeout at **180.005 seconds** and returned `ProviderError`.
Neither attempt demonstrated viable heavy synthesis, an accepted module or
deployment. No generated source ran on the host, and no model downloads or
remote API calls were performed. The temporary test runtime/process tree was
cleaned up; the existing shared service was untouched.

The optional runtime-installer binary download was not tested. That path still
requires explicit consent and a matching SHA-256, bounds the binary size and
uses a socket inactivity timeout. It does not have the inference adapter's
whole-request deadline. No successful engine installation or downloaded-binary
execution is claimed.

The [real-container job](https://github.com/Ag3nt47/Divalia/actions/runs/39844398460/job/120053721812)
passed for published commit `cb5b152098e04912648eb597d8a0145b64f1d27e`:
**4 tests passed in 8.32 seconds**. It exercised the practical 14-fixture module
through CLI creation, retesting, review, independent approval, isolated hit/miss
events and export, plus the API marker lifecycle's replacement, detector failure,
rollback and signed export. CLI create/retest/approval took 0.541/0.530/0.545
seconds; isolated events took 0.537/0.541 seconds and export 0.129 seconds,
including process startup and Docker where applicable.

The separate two-event API marker worker reported 16 fixture executions in
0.000243 seconds, peak RSS of 24,356 KiB and sampled peak growth of 0 KiB.
Worker-only time excludes container startup; small synthetic fixtures and a
zero sampled growth value do not prove memory invariance or absence of leaks.
The clean runner also completed 5,000-record workloads: CVE-indexed ingestion
1.174 seconds new / 0.713 repeated, CVE-free ingestion 4.321 / 0.697, AST checking
1.083, and an archive read of 0.839 seconds for all records versus 0.0263 for
the first ten. These Linux results are separate observations, not controlled
speedup comparisons with the busy Windows review host.

Full JUnit and performance/allocation JSON reports are uploaded from `artifacts/`
as `isolated-module-workflow`. A [selected machine-readable job record](performance/github-actions.json)
includes provenance, exact measurements and source links. **All seven jobs
passed** in [run 39844398460](https://github.com/Ag3nt47/Divalia/actions/runs/39844398460):
Python 3.11, 3.12 and 3.13 on Linux and Windows, plus isolated execution.
This verifies the complete configured matrix for the published code commit
identified above, including real container execution for the tested cases.
