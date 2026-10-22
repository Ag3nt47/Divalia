# Divalia 1.0 — Module Development & Deployment for Angerona

**A standalone, optional module development and deployment tool for
[Angerona Security Suite](https://github.com/Ag3nt47/AngeronaSuite).** Develop and
test detector modules, review generated code, and prepare detection packages for
human-approved deployment through Angerona's DetectionForge. Angerona runs without
Divalia; Divalia uses its own environment and separate state.

Divalia collects curated intelligence, filters it with a lightweight model,
asks a heavier model for an observe-only detector, audits its AST, tests it in
an isolated container, and presents the evidence for human review. Automation
never approves or deploys a candidate.

| Module development | Deployment to Angerona |
| --- | --- |
| Turn threat briefings into detector prototypes with configurable AI models. | Export digest-sealed detection packages, optionally signed with Ed25519. |
| Inspect source diffs, AST policy results and isolated telemetry tests. | Import, review and promote packages through Angerona DetectionForge. |
| Approve, test and roll back versions in Divalia's isolated runtime. | Keep Angerona's existing publisher trust and activation requirements. |

```mermaid
flowchart LR
  A[RSS / Atom / KEV / advisories / curated social] --> B[Sanitize, score, deduplicate]
  B --> C[Light model: relevance]
  C --> D[Heavy model: detector proposal]
  D --> E[AST policy and isolated fixture tests]
  E --> F[Human review: approve / modify / reject]
  F --> G[Divalia isolated plugin versions and rollback]
  F --> H[Angerona declarative package export]
  H --> I[Angerona DetectionForge review and promotion]
```

## Screenshots

### Develop and review an Angerona module

![Divalia module review showing source changes, AST policy results and human deployment approval](docs/images/module-review.png)

The actual read-only review report shows the detector's purpose, source diff and
validation status. This benign demo correctly reports container testing as
unavailable; it does not represent a tested or deployed module.

### Configure the module development toolchain

![Rendered Divalia CLI transcript showing Angerona module development commands and model provider options](docs/images/cli-workflow.png)

Rendered transcript of actual CLI help and provider output. Use local models or
explicitly configured remote providers throughout development and review.

### Prepare a deployment for Angerona

![Rendered Divalia CLI transcript showing a digest-sealed detection package export for Angerona DetectionForge](docs/images/deployment-package.png)

Actual export output and package JSON from the demo fixture. Deployment into
Angerona continues through DetectionForge import, review and promotion.
See [screenshot provenance and regeneration](docs/screenshots.md).

## Install and try it

Requires Python 3.11 or newer. Windows, Linux and macOS use the same CLI.

```powershell
git clone https://github.com/Ag3nt47/Divalia.git
cd Divalia
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\divalia.exe init
.venv\Scripts\divalia.exe demo
.venv\Scripts\divalia.exe --config divalia.toml doctor
```

On Linux/macOS use `.venv/bin/python` and `.venv/bin/divalia`. The offline demo
checks an AST and exports a declarative fixture package without a model, Docker,
API key or Angerona installation. It does not claim container testing occurred.

Edit `divalia.toml` to select feeds, models and the sandbox image. API keys are
never part of this file. [config.example.toml](config.example.toml) documents all
settings. See [operations](docs/operations.md) for a complete workflow.

You can also develop a module directly from your own Python source and labeled
telemetry fixtures, without an AI provider:

```powershell
divalia --config divalia.toml create marker_detector.py --id marker-observer --fixtures fixtures.json --explanation "Observe an explicit test marker"
divalia --config divalia.toml review marker-observer --html review.html
divalia --config divalia.toml retest marker-observer
divalia --config divalia.toml list candidates --limit 20
```

See the [complete source and fixture example](docs/operations.md#write-a-module-without-ai).
Creating or retesting a candidate still requires the reviewed container worker
for a passing result. Missing isolation saves a blocked candidate for inspection.
For a practical module and matching Angerona package, follow the
[encoded PowerShell example](examples/encoded-powershell/README.md). Its 14
synthetic fixtures document normalized telemetry, benign cases and narrow
string-matching coverage; it does not classify every encoded command as malicious.

## Models and API keys

Model names are configurable strings; choose models supported by your runtime
and hardware. The two model roles can use different providers and credentials.

| Provider | Configuration | Credential |
| --- | --- | --- |
| Ollama | `provider = "ollama"`; literal loopback endpoint | Usually none |
| LM Studio | `provider = "lmstudio"`; loopback `/v1` endpoint | Optional `key_env` |
| llama.cpp | `provider = "llamacpp"`; loopback `/v1` endpoint | Optional `key_env` |
| Custom compatible/FastAPI endpoint | `provider = "compatible"`; chat-completions protocol | Optional `key_env` |
| OpenAI | `provider = "openai"`; `allow_remote = true` | `OPENAI_API_KEY` |
| Anthropic | `provider = "anthropic"`; `allow_remote = true` | `ANTHROPIC_API_KEY` |
| Gemini | `provider = "gemini"`; `allow_remote = true` | `GEMINI_API_KEY` |

`key_env` names an environment variable populated by your shell, service manager
or secret manager. Divalia does not load `.env` files, print credentials or write
keys into configuration. Remote adapters use fixed official API hosts; custom
remote compatible endpoints require explicit HTTPS configuration and opt-in.
There is no automatic local-to-cloud fallback. Remote inference sends selected
threat briefing text to the chosen provider; do not include private telemetry in
briefings unless you intend that disclosure.

Example: keep filtering local and select a remote reasoning model yourself:

```toml
[ai]
provider = "ollama"
endpoint = "http://127.0.0.1:11434"
light_model = "YOUR_LOCAL_FILTER_MODEL"
heavy_model = "YOUR_LOCAL_CODE_MODEL"
allow_remote = false

[ai.heavy]
provider = "openai"
heavy_model = "YOUR_CHOSEN_REMOTE_MODEL"
key_env = "OPENAI_API_KEY"
allow_remote = true
```

`divalia providers` lists adapters. Additional provider protocols implement
[`BaseProvider`](src/divalia/ai/base_provider.py), which is also injectable into
the synthesis pipeline. Optional runtime setup checks Ollama readiness and can
pull explicitly requested models:

```powershell
divalia --config divalia.toml runtime
divalia --config divalia.toml runtime --pull YOUR_CHOSEN_MODEL --consent
```

`doctor` reports the configured light and heavy roles separately, including
each Ollama model's presence and each role's remote-inference policy. It does
not make paid inference requests or certify container execution readiness.

The runtime downloader accepts an official HTTPS installer URL, a separately
verified SHA-256 and explicit consent. It saves the installer for operator
review; it does not execute downloaded scripts or silently install engines.

## Isolated Python testing

Generated code is never executed on the host. A trusted Linux Docker worker is
required for Python candidate validation, approval and runtime events. Without
it, candidates remain blocked. An AST score of 100 means the current allowlist
found no violations; it is not a probability or security guarantee.

Build the worker from a reviewed CPython Linux base pinned by digest or local
immutable image ID. Set the resulting worker ID as `[sandbox].image`:

```powershell
docker pull python:3.12-slim
# Review the resolved image before proceeding; a mutable tag is not a trust decision.
$baseImage = docker image inspect python:3.12-slim --format '{{index .RepoDigests 0}}'
docker build --build-arg "BASE_IMAGE=$baseImage" -t divalia-worker src/divalia/harness
docker image inspect divalia-worker --format '{{.Id}}'
```

Copy the returned `sha256:...` worker ID to your configuration. Registry
`repository@sha256:...` references are also supported when installed locally.
Divalia never pulls an image automatically. Each test drops capabilities,
uses an unprivileged user, disables networking and host mounts, makes the root
filesystem read-only, and limits memory, CPU, processes, output and duration.
Docker Desktop must use Linux containers on Windows.

## Angerona integration

The supported exchange is a digest-sealed, optionally Ed25519-signed
`sigma-subset` JSON detection package. Import it into Angerona's DetectionForge
and use its existing review, trusted publisher enrollment, replay quality and
promotion workflow. Compatibility is tested against Angerona's actual package
loader. Divalia never edits its registry or manufactures promotion receipts.

Angerona's external Python module loader requires signed manifests and a restart;
it has no supported source-code hot-reload hook. Divalia's atomic replacement
and probation rollback apply to its own isolated plugin runtime. Angerona live
activation and rollback remain owned by its existing authorities.

A pinned-commit/SHA-256 [download hook](src/divalia/integration/downloader.py)
is available to an optional future Angerona settings integration. This release
does not add a settings button, expose an HTTP server, or change Angerona.

## Current boundaries

- Python detectors use a deliberately small, pure `detect(event)` subset.
  Native Go parsing/execution is unsupported and rejected.
- Source credibility and local token-vector deduplication reduce repetition;
  cross-reporting is not independent artifact verification. Reference URLs are
  evidence pointers, not authenticated proof or permission to execute content.
- Tests exercise synthetic hit/miss fixtures repeatedly and record resource
  observations. They cannot prove all leaks, deadlocks or detection mistakes
  are absent. Each live event uses a separate container: this is a research
  harness, not Angerona's high-throughput sensor path.
- Local operators and the state directory are trusted. See
  [SECURITY.md](SECURITY.md) for the full trust model and recovery constraints.

## Development

```powershell
python -m pip install -e ".[dev]"
python -m ruff check src tests tools
python -m compileall -q src tools
python -m pytest -q
python -m divalia demo
python -m build
```

Offline tests never call paid APIs or execute generated Python on the host.
The GitHub workflow includes Linux/Windows Python 3.11–3.13 checks and a separate
real Linux-container test job. Opt-in integration checks and local validation
results are documented in [validation](docs/validation.md).

The [performance and module-workflow review](docs/performance-review.md) records
the ingestion/archive fixes, reproducible 100/1,000/5,000-item measurements,
allocation peaks and the limits of measurements from a busy host.

Project structure and provider protocol references are in
[architecture](docs/architecture.md). License: [MIT](LICENSE).
