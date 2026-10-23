"""Daily source-checkout update launcher; never executes downloaded code before consent."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from divalia.integration.app_updater import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
