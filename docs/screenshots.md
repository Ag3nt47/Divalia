# Screenshot provenance

These images show Divalia's existing module development and deployment workflow
for Angerona Security Suite. Chrome captured local HTML files in headless mode;
no image generation or external graphic assets were used.

| Image | What was captured |
| --- | --- |
| [Module review](images/module-review.png) | The actual HTML report produced by `divalia review --html`, using a benign candidate saved through `ArtifactStore`. Includes the source diff, real AST policy result and real sandbox availability result. |
| [CLI workflow](images/cli-workflow.png) | An explicitly labeled **rendered CLI transcript** containing actual `python -m divalia --help` and `python -m divalia providers` stdout. This is a documentation rendering, not a native terminal screenshot. |
| [Deployment package](images/deployment-package.png) | An explicitly labeled **rendered CLI transcript** containing a real `export-file` receipt and the complete exported package displayed with `python -m json.tool`. Prepared for Angerona DetectionForge review; no activation was performed. |

The example detects only `DIVALIA_TEST_MARKER` in synthetic process telemetry.
It is an observe-only demonstration, not a real threat detection. Its AST audit
passes, but `SandboxRunner(image="")` reports `unavailable` because the capture
deliberately configures no pinned container image. Approval remains blocked.
The capture neither invokes a model nor executes detector source on the host.

The deployment example is unsigned. Angerona independently owns package import,
trust, evaluation and promotion. The receipt's transient absolute workspace path
is replaced with `[demo-workspace]`, as labeled in the image. Other CLI output is
unchanged. The package expiry and digest come from that capture's actual export.

## Regenerate

From the repository root, install Divalia in your development environment and
use an existing Chrome, Chromium or Edge browser:

```powershell
python -m pip install -e .
python tools/capture_screenshots.py
```

To select a browser explicitly:

```powershell
python tools/capture_screenshots.py --browser "C:/Program Files/Google/Chrome/Application/chrome.exe"
```

On Linux, for example:

```sh
python tools/capture_screenshots.py --browser /usr/bin/chromium
```

The script creates a fresh private fixture directory under the ignored
`.divalia/screenshots/` directory, including the raw command outputs, generated
HTML, benign candidate, exported package and a capture manifest. Its dedicated
configuration isolates the example from operator settings. Each screenshot uses
a separate headless browser profile. The only tracked outputs are the PNG files
under `docs/images/`; no credentials or personal paths are included.

The actual operations performed in each private fixture directory are:

```text
python -m divalia --config capture.toml --state-dir state review candidate-marker-demo --html module-review.html
python -m divalia --help
python -m divalia --config capture.toml --state-dir state providers
python -m divalia --config capture.toml --state-dir state export-file marker-package.json --output exported/angerona-marker.json
python -m json.tool exported/angerona-marker.json
```

The rendered transcript command labels omit the capture-only configuration and
state arguments for readability; these options do not change the displayed
provider list or export semantics. The module review is captured at 1600×1100,
the CLI transcript at 1600×1100, and the deployment transcript at 1600×1240.
