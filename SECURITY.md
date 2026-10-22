# Security model

Report vulnerabilities privately through the repository owner's GitHub contact
or private vulnerability reporting when enabled. Do not include secrets or
personal telemetry in public issues.

Divalia develops modules and prepares reviewed detection deployments for Angerona.
Its generated detectors observe and report. It does not synthesize or deploy
process termination, firewall modification, persistence, credential access,
exploit payloads, or other automatic mitigations.

Trust boundaries:

1. Configured HTTPS feeds are untrusted claims. Sanitization is not verification;
   source weights and cross-reporting are recorded without declaring claims true.
2. Models receive explicitly labeled evidence, no tools, and no secrets. Remote
   inference is opt-in per configured role; there is no silent remote fallback.
3. Deterministic AST policy allows only a small pure `detect(event)` subset.
   Native Go and unsupported constructs fail closed. A score of 100 means zero
   current policy violations, not a security guarantee or useful detection.
4. Generated Python executes only inside a trusted immutable Linux Docker worker:
   no network, host mounts, writable root, capabilities, or elevated user;
   bounded input/output, memory, processes, CPU and wall-clock time. Containers
   share the host kernel and are not a VM security boundary. Keep Docker and
   the host patched; review the base image and worker before pinning its ID.
5. Approval reruns the sandbox, verifies declared hit/miss fixtures, and binds
   exact source, telemetry and metadata to a one-use authenticated receipt.
   Atomic pointers select reviewed immutable versions. Probation requires both
   60 seconds and 3 successful submitted events; runtime failures quarantine
   the failed source and restore a previous stable version or disable it.
6. Angerona exports are declarative JSON. Signing does not bypass Angerona's
   independent publisher enrollment, replay quality or promotion authorities.

The Divalia state directory, configuration, signing keys, Docker daemon and
local operator are trusted. Use a private local directory on a filesystem with
atomic rename. Junctions/symlinks are rejected. Same-user administrators can
change trusted code and keys; local receipts do not protect against an already
compromised account. The audit log is local operational history, not a remotely
anchored tamper-evident ledger. Multi-user authorization is outside this release.

Repeated fixtures and resource observations cannot prove absence of all leaks,
deadlocks, false positives or false negatives. Evaluate representative local
telemetry and review each candidate before deployment. An interrupted publisher
leaves a fail-closed lock; confirm no writer exists before recovering the lock.
