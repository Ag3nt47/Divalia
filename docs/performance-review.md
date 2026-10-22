# Divalia 1.0 performance and module-workflow review

This review exercises Divalia as a module development and deployment preparation
tool for Angerona. It covers intelligence intake, model adapters, operator-authored
candidates, source/fixture validation, review, package export and the boundaries
around approval. The project version remains **1.0.0**.

## Changes from the review

- **Bounded near-duplicate lookup.** CVE-free claims previously reread and decoded
  up to 1,000 archived token/vector records for every new claim. A transaction-local
  index now decodes that window once and uses token postings before cosine scoring.
  It retains the same 1,000 most recent CVE-free claims, newest-first match order,
  0.80 lexical/Jaccard guard and 0.95 cosine threshold. A new cycle observes history
  committed by other collectors. Distinct CVE sets and older exact matches remain
  indexed separately.
- **Cheaper duplicates.** Indexed exact-content and CVE-set matches no longer
  recompute embeddings. Repeated observations avoid rewriting unchanged metadata;
  additional source hosts, evidence and credibility still update the record.
- **Bounded archive reads.** `ArtifactStore.iter_ids()` scans validated filenames
  without decoding their JSON. `iter_values(limit=...)` loads selected records
  lazily. The synthesis queue checks existing candidates/filter decisions first
  and stops when its batch is full. A persisted round-robin cursor prevents an
  interrupted or failing early briefing from monopolizing bounded batches;
  cached positive filter decisions avoid repeating light inference on synthesis
  retries. Invalid filter-cache records are audited and re-filtered. Filenames
  still require sorting; this does
  not make enumeration independent of archive size. Runtime atomic writes and
  `fsync` durability are retained.
- **Direct module authoring.** `create` accepts an operator's Python source,
  explanation and labeled fixtures. `retest` repeats stored validation without
  model generation. The shared candidate builder checks sandbox source/telemetry/
  test digests and hit/miss semantics, reports optional package validation, retains
  revision diffs and preserves quarantine. Attached declarative packages must
  agree with the prototype's labeled fixtures at preparation and export; shared
  cases are evidence of agreement rather than a proof of universal equivalence.
  Both entry paths require human approval.
- **Lifecycle and recovery.** Activation completes receipt, quarantine and prior
  probation checks before writing version records. Immutable review snapshots,
  distinguished by receipt when the same source is reviewed again, preserve the
  original consent and rollback evidence. Malformed telemetry is rejected before
  module execution without quarantining a healthy version; genuine detector
  failures still trigger rollback. Cancellation reaps the test subprocess and
  attempts bounded named-container cleanup. Human rejection now updates the
  visible candidate status while preserving authenticated version snapshots.
- **Model transport and readiness.** Inference uses cancellable async transport
  with a whole-request timeout, bounded HTTP/JSON reads and redirect refusal.
  This avoids abandoned blocking request threads after cancellation. Model roles
  receive different output budgets. Ollama requests JSON output, and `doctor`
  checks the actual model configured for each role rather than treating a running
  inference engine as proof that both models are installed.
- **Malformed input handling.** Invalid provider/feed kinds, numeric bounds,
  nonfinite/huge values and malformed model responses produce bounded validation
  failures. Failed synthesis remains visible and retryable. The original isolation,
  key privacy and Angerona promotion requirements remain in force.

See [operations](operations.md) for complete `create`, `retest`, role-aware
`doctor`, `list --limit`, review and export examples.

The [encoded PowerShell module](../examples/encoded-powershell/README.md) is a
practical source/fixture/package example with 14 synthetic telemetry cases.
It covers the narrow encoded-command string rule, benign administration, mixed
case and missing/null/numeric field values. It requires a process basename and
ordinary-space-normalized command line. Raw executable paths and tab-separated
switches are explicit negative cases; other encodings and parser behavior are
outside its coverage. It observes a signal rather than proving maliciousness.

## Diagnostic measurements

Environment: CPython 3.12.10 on Windows 11. Feed transport was an injected,
in-memory fixture fetcher. The benchmark never calls a model or executes detector
source. Records have deterministic distinct token features, optional unique
CVEs and synthetic public-looking URLs; each ingestion run is repeated to check
durable deduplication. Workloads of 5,000 records use multiple bounded feeds.

**The host was busy with concurrent background and test workloads.** Wall times
varied substantially, including on paths changed only to avoid redundant work.
These are observations for diagnosis, not controlled speedup measurements,
production latency promises or portable pass/fail thresholds.

Elapsed seconds without allocation tracing:

| CVE-free briefings | Before: new | After: new | Before: repeated | After: repeated |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 0.602 | 0.416 | 0.208 | 0.582 |
| 1,000 | 31.069 | 3.186 | 1.475 | 2.080 |
| 5,000 | Incomplete | 13.632 | Incomplete | 5.702 |

The old 5,000-item CVE-free workload did not finish before the benchmark process
was stopped at 399.55 seconds total (256.45 CPU seconds). That total includes
earlier completed cases; it is **not** a measured duration or lower bound for a
completed 5,000-item operation. No completed baseline is claimed at that size.

CVE-indexed ingestion showed the host's timing variance clearly: 5,000 records
took 4.371 seconds new / 4.980 repeated before and 9.827 new / 39.108 repeated
after. These results do not support an across-the-board throughput improvement.
All completed new cases retained the expected record count, and repeated runs
returned zero new records.

Other completed observations:

| Workload | Elapsed seconds | Result |
| --- | ---: | --- |
| AST validation, 100 / 1,000 / 5,000 detectors | 0.071 / 0.819 / 3.425 | All passed the policy; source was not executed |
| Archive of 100, read all records | 1.641 | 100 JSON records loaded |
| Same archive, request first 10 | 0.033 | 10 JSON records loaded |
| Sanitize 100 HTML inputs of 55,600 bytes each, tracing enabled | 7.246 | All produced sanitized text |

The archive comparison requests different amounts of work. Regression tests
also assert the exact requested JSON load count and ensure skipped old content
is not decoded. Larger archive cases were stopped during fixture seeding at
327.12 seconds total (27.48 CPU seconds); they have no completed read timings.
The reproducer now creates trusted fixture files without per-fixture durability
flushes outside the timed read. Application writes still use the durable store.

With `tracemalloc` enabled, Python allocation peaks were:

| CVE-free briefings | New ingestion | Repeated ingestion |
| ---: | ---: | ---: |
| 100 | 1.29 MB | 0.15 MB |
| 1,000 | 11.82 MB | 1.38 MB |
| 5,000 | 18.48 MB | 4.06 MB |

These are decimal MB, not process RSS, container memory or proof that leaks are
absent. The feature index trades some temporary memory for fewer archive reads
and is bounded to 1,000 recent claims. Parsed feed/results memory still scales
with the bounded batch. The traced sanitizer run peaked at 251,468 bytes and
100 AST checks at 63,636 bytes. Allocation tracing adds substantial execution
overhead, so its timings must not be compared with untraced runs.

Machine-readable observations:
[before](performance/before.json), [after](performance/after.json),
[before with tracing](performance/before-traced.json),
[after with tracing](performance/after-traced.json). Partial records explicitly
identify interrupted workloads. They contain synthetic workload metadata and
measurements, without credentials, private telemetry or operator paths.

## Verified Linux container run

The [isolated-execution job](https://github.com/Ag3nt47/Divalia/actions/runs/39844398460/job/120053721812)
passed on published commit `cb5b152098e04912648eb597d8a0145b64f1d27e`:
**4 real-container tests passed in 8.32 seconds**. The practical 14-fixture module
completed CLI creation, retesting, review, independent approval, isolated hit/miss
events and export. The separate API marker lifecycle exercised replacement,
runtime failure, rollback and exact-byte signed export.

CLI elapsed times on that GitHub Actions Ubuntu/CPython 3.12 runner include
process startup and Docker where applicable:

| Operation | Seconds |
| --- | ---: |
| Create / retest | 0.541 / 0.530 |
| Review / independent approval | 0.126 / 0.545 |
| Isolated miss / hit events | 0.537 / 0.541 |
| Export | 0.129 |

The separate two-event API marker case reported 16 fixture executions in
0.000243 seconds of worker wall time, peak RSS of 24,356 KiB (about 23.8 MiB)
and sampled peak growth of 0 KiB. Worker time excludes container startup. These
tiny fixtures and sampled memory observations do not establish leak freedom,
memory invariance or production sensor throughput.

Completed untraced offline workloads on the same runner:

| Workload | New/all, seconds | Repeated/first 10, seconds |
| --- | ---: | ---: |
| 5,000 CVE-indexed briefings | 1.174 | 0.713 |
| 5,000 CVE-free briefings | 4.321 | 0.697 |
| 5,000 AST validations | 1.083 | — |
| Archive of 5,000 records | 0.839 | 0.0263 |

New ingestion retained 5,000 records, repeated ingestion returned zero new
records, all AST checks passed, and archive reads returned the requested record
counts. This runner differs from the busy Windows host above; these values are
not a controlled cross-hardware speedup comparison. The allocation-traced run
also completed. See [selected machine-readable job output](performance/github-actions.json)
for measurements, provenance and the source job URL. Full JUnit/JSON reports
are available in the run's `isolated-module-workflow` artifact.

## Reproduce

Use the project's virtual environment and installed dependencies:

```powershell
python tools/benchmark_performance.py --sizes 100 1000 5000 --workloads ingestion non-cve ast --output .divalia/performance-review/local.json
python tools/benchmark_performance.py --sizes 100 1000 5000 --workloads ingestion non-cve --trace --output .divalia/performance-review/local-traced.json
python tools/benchmark_performance.py --sizes 100 --workloads sanitizer ast storage --trace --output .divalia/performance-review/local-other.json
```

Run one benchmark at a time on an otherwise idle host for comparisons. Fixture
construction is outside timed operations. The tool reports `perf_counter`
elapsed time, result counts and optional `tracemalloc` peak bytes, and checkpoints
each result to JSON. The tool enforces correctness/count checks and does not
enforce machine-dependent timing thresholds.

## Validation status

Final local validation on **October 22, 2026**, with
`DIVALIA_ANGERONA_SRC` explicitly set, completed with **141 passed, 211 subtests
passed and 6 skipped in 170.96 seconds**. Four skips require real Docker
execution, unavailable on this host; two require symlink creation privileges.
Ruff across source/tests/tools/examples, compilation, dependency consistency,
source and wheel builds, wheel import/resources and the offline CLI demo all
passed. All three screenshots were regenerated and visually checked.

The focused ingestion/storage run completed with **29 passed, 30 subtests passed
and 1 skipped**. The skip is the Windows account's inability to create a symlink;
the corresponding confinement behavior remains covered where symlinks can be
created. Scoped Ruff checks passed.

The first real CPU-only Ollama trial used `llama3.2:3b`. Its light-role request
returned valid classification JSON (`relevant: false`) in **85.93 seconds**.
The heavy request returned JSON in **58.15 seconds**, but `source` was an object
instead of a Python-source string, so the proposal was rejected. Valid JSON
transport does not establish a valid module. No model source ran on the host.
The prompt now explicitly requires a JSON string for `source`. The first heavy
response also omitted the optional declarative detection package; its invalid
source schema prevented acceptance regardless. A rerun with the clarified
prompt reached the configured whole-request limit at **180.005 seconds** and
returned `ProviderError`. It produced no accepted module.

This small-model, CPU-only trial on a busy host did not demonstrate viable heavy
generation, synthesis performance or deployment. Model availability and a valid
light response do not establish those capabilities. The timeout/cancellation
handling is bounded, but it does not solve the model/hardware limitation. No
model downloads or remote API calls were made. The temporary test runtime and
its child processes were cleaned up; the existing shared service was untouched.

The Docker CLI is absent on the local review host, so real container execution
was validated by the successful isolated GitHub job described above.
**All seven jobs passed** in
[run 39844398460](https://github.com/Ag3nt47/Divalia/actions/runs/39844398460):
Python 3.11, 3.12 and 3.13 on Linux and Windows, plus isolated execution.
These results apply to the published code commit identified above. See
[the validation record](validation.md) for the detailed local and remote results.
Local Docker availability, model reliability and detection quality must be
assessed separately; AST success and performance measurements cannot establish
them.

The optional runtime-installer binary download was not exercised. It retains
explicit consent, a size bound, an expected SHA-256 and a socket inactivity
timeout, but does not have inference transport's whole-request deadline. No
runtime installation or downloaded-binary execution is claimed by this review.
