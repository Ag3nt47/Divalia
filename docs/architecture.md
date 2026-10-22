# Architecture

```text
src/divalia/
  config.py                  bounded TOML configuration
  storage.py                 confined atomic artifacts and local audit log
  pipeline.py                light filtering, heavy synthesis, fixture checks
  cli.py                     operator commands, watch loop and review actions
  core/
    models.py                serializable ThreatBriefing contract
    sanitizer.py             markup/noise cleanup and URL normalization
    ingestion.py             RSS/Atom, KEV, GitHub, NVD, Mastodon; SQLite dedup
  ai/
    base_provider.py         async provider contract and compatible HTTP adapter
    ollama_provider.py       local generation, status and opt-in model pulls
    remote_provider.py       optional OpenAI, Anthropic and Gemini adapters
    router.py                independent light/heavy provider selection
    installer.py             readiness and consent/digest-gated runtime downloads
  harness/
    ast_validator.py         deterministic allowlist, source digest and policy ID
    sandbox.py               bounded immutable Linux Docker worker orchestration
    container_worker.py      isolated fixture execution and resource observations
    Dockerfile               operator-built trusted worker
  integration/
    review.py                escaped text and standalone HTML side-by-side diff
    publisher.py             human receipts, atomic versions, probation rollback
    detection_export.py      Angerona JSON contract and optional detached signature
    downloader.py            bounded pinned GitHub source archive extraction
```

Ingestion schedules independent fetches asynchronously. Default transport pins
public DNS results while preserving TLS hostname verification, rejects redirects
and ambient proxies, bounds response sizes and socket lifetime, and isolates
source failures. Markup is removed before a briefing is serialized. Source
credibility is an operator-supplied weight, not an externally verified claim.

SQLite stores normalized content fingerprints and lightweight local token
vectors for near-duplicate detection. Distinct CVE sets are kept separate.
Multiple independent configured hosts can mark a claim `cross_reported`;
references are never automatically promoted to verified evidence.

The light model classifies relevance. The heavy model produces strict JSON
containing source, rationale, fixtures and optionally an Angerona rule package.
Malformed or ambiguous output fails closed. Prompt instructions label evidence
as untrusted; deterministic validation and isolation enforce execution safety
independently of model cooperation. Models do not receive tools.

The Python allowlist excludes imports, classes, reflection, privileged calls,
loops and dynamic execution. A detector returns an alert dictionary or `None`.
Container validation is bound to source, telemetry and test protocol digests.
The worker repeats fixtures eight times, checks deterministic outputs, and
reports bounded resource observations. Semantic hit/miss assertions are also
checked before a candidate can be approved.

Approval repeats container validation rather than trusting stored `passed`
fields. A locally authenticated receipt binds the exact reviewed candidate.
Activation consumes that receipt and atomically changes a pointer to an
authenticated immutable version. An exclusive filesystem lock serializes
writers. A version must complete probation before it can become the previous
stable version of a replacement. Runtime failures quarantine the failing source
and restore that stable version; first-version failure disables it.

For Angerona, declarative export is intentionally separate from Divalia plugin
activation. Package source bytes receive a deterministic digest and optional
exact-byte Ed25519 signature. Angerona independently validates and promotes them.

Protocol references reviewed for this implementation:

- [Ollama generation](https://docs.ollama.com/api/generate) and
  [model pull](https://docs.ollama.com/api/pull).
- [LM Studio chat completions](https://lmstudio.ai/docs/developer/openai-compat/chat-completions).
- [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
- [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create).
- [Gemini content generation](https://ai.google.dev/api/generate-content).
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
  and [engine security](https://docs.docker.com/engine/security/).
