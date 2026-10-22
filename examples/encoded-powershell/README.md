# Encoded PowerShell module example

This observe-only example develops an Angerona detection through Divalia's manual
source, fixture, review and deployment-package workflow. No model or API key is
required. It observes PowerShell process creation with an encoded-command flag;
it does not decode a payload, launch a process, block execution or establish that
the process is malicious.

`detector.py` is the Python research prototype. `fixtures.json` labels 14 benign
synthetic events. `detection.json` is the corresponding digest-sealed Angerona
DetectionForge package, with the same 14 labeled events and matching logic.

## Telemetry and detection scope

Map your process sensor into these JSON fields:

- `event_type`: `process.creation`.
- `process_name`: the executable basename, such as `powershell.exe`, `powershell`,
  `pwsh.exe` or `pwsh`.
- `cmdline`: the full command line, including the executable and argument values,
  with arguments separated by ordinary ASCII spaces.

The prototype and declarative package compare these fields without regard to
case. They recognize ` -EncodedCommand `, ` -enc ` and ` -e `, including their
surrounding spaces. A lookalike such as `-EncodedCommandSuffix` does not match.
Missing, null and numeric field values are handled without an execution error.
The fixtures include a quoted executable path in `cmdline`, mixed case, normal
administrative scripts and other process names.

Normalize an image path to its basename and normalize argument whitespace in
your telemetry adapter before applying this rule. Raw paths in `process_name`
and tab-separated switches deliberately do not match; both cases appear in the
negative fixtures. Quoted switch tokens, switches without a following value,
other PowerShell abbreviations, renamed executables and encoded content passed
by other mechanisms are outside this example's coverage. This is a small string
rule rather than a complete PowerShell command-line parser.

Legitimate administrative deployment tools and scripts can use encoded commands.
A string mentioned inside a command's text can also match. Review the parent
process, user, host role and script provenance before deciding what the event
means. Tune exceptions only from reviewed local evidence. The fixture payloads
are harmless examples, and no payload is executed by this workflow.

## Create, test and review

Run these commands from the repository root in your installed virtual
environment. Follow the [worker setup](../../README.md#isolated-python-testing)
to build and review the Linux container worker, then set `[sandbox].image` in
`divalia.toml` to its immutable `sha256:...` image ID or installed
`repository@sha256:...` reference. Docker must use a running Linux engine.
Divalia does not pull images automatically.

```powershell
python -m divalia --config divalia.toml create examples/encoded-powershell/detector.py --id encoded-powershell --fixtures examples/encoded-powershell/fixtures.json --explanation "Observe PowerShell encoded-command flags; administrative automation may also match. Requires normalized process-creation telemetry." --detection examples/encoded-powershell/detection.json
python -m divalia --config divalia.toml retest encoded-powershell
python -m divalia --config divalia.toml review encoded-powershell --html encoded-powershell-review.html
```

Open the review report and inspect the source, fixtures, audit, sandbox evidence
and package. `retest` repeats validation without invoking an AI provider. Missing
isolation returns exit code 2 and saves a blocked candidate that you can still
review; approval and runtime execution remain blocked. Passing AST validation
alone does not establish detection quality or security.

After reviewing the current candidate, copy its displayed source SHA-256 into
this command:

```powershell
python -m divalia --config divalia.toml approve encoded-powershell --reviewer "Your reviewer name" --sha256 "PASTE_THE_REVIEWED_SOURCE_SHA256"
```

Approval independently repeats the container tests, records the human review
and activates the version in Divalia's isolated development runtime. It does not
activate a Python module in Angerona. Do not run `detector.py` directly or import
it to exercise its detection function on the host.

To send one of the labeled events through the isolated runtime in PowerShell:

```powershell
$fixture = (Get-Content examples/encoded-powershell/fixtures.json -Raw | ConvertFrom-Json)[0]
$fixture.event | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 encoded-powershell-event.json
python -m divalia --config divalia.toml run-event encoded-powershell encoded-powershell-event.json
python -m divalia --config divalia.toml list plugins
```

Fixture index `0` is a hit; index `4` is a benign administrative script and is a
miss. Test both against your expected telemetry. The default probation window
requires at least 60 elapsed seconds and three successful `run-event` calls
before a replacement is permitted. A successful miss counts as a successful
event. Each call uses a separate restricted container; this is development
validation, not a production sensor-throughput benchmark.

## Export for Angerona

Review the declarative package separately, then export it:

```powershell
python -m divalia --config divalia.toml export encoded-powershell --output encoded-powershell-package.json
```

If you already manage a reviewed Ed25519 PKCS8 signing key, add
`--private-key reviewer.pem --key-id your-publisher-id` to produce an exact-byte
detached signature. Keep the key outside the repository. The example package
expires on October 22, 2027; review and update its expiry and version before using
it beyond that date. Divalia recomputes the package digest when creating or
exporting it.

Import the exported package through Angerona DetectionForge and complete its
trusted-publisher enrollment, fixture replay, human review and promotion gates.
Signing or exporting alone does not grant trust or deployment authority.
Angerona owns live activation and rollback. Its trust stores, detection registry
and governance receipts are never changed by this example.
