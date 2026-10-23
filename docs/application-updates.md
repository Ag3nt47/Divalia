# Approved application updates

Use the updater launcher for the first Divalia start of the day:

```powershell
python tools/update_divalia.py --run watch
```

On Windows, `start-divalia-updated.bat` uses the project's existing `.venv` and
starts the same workflow. Complete the normal model, feed and sandbox setup in
`divalia.toml` first. To preserve explicit configuration or other CLI arguments:

```powershell
python tools/update_divalia.py --run --config divalia.toml watch --limit 3
```

The launcher checks the canonical public `Ag3nt47/Divalia` main branch at most
once per local calendar day. It records an attempt before networking, including
failed attempts. Later starts reuse that day's result. Checking downloads only
GitHub metadata. Ordinary Divalia commands remain free of update network calls.

When a different commit is available, the interactive launcher shows the local
and proposed full commit IDs and a comparison link. Approval requires typing
`update FULL_COMMIT_SHA`; declining preserves the installation. Approval applies
only to that observed commit. A later push requires another review.

The updater applies a fast-forward to a clean, canonical `main` source checkout.
It refuses local edits, untracked files, a different branch or origin, diverged
history, redirected paths and unsupported Git configuration. It never stashes,
resets, force-updates, discards local work or runs repository hooks.
Ignored local files are also protected from overwrite by Git's
[`--no-overwrite-ignore` merge option](https://git-scm.com/docs/git-merge).
Changes to dependencies, Python requirements, build settings, container build
inputs or entry points require manual setup instead of changing the environment
underneath the application.

Normal Divalia commands retain OS-backed runtime leases. An update is held while
another command is using the checkout. Close those commands and try again;
the updater does not find or terminate processes by name. Crashed commands do
not retain an OS lock. After an approved update, `--run` starts a fresh Divalia
process with the supplied arguments. No running instance is silently restarted.

Close every Divalia instance before adopting this updater for the first time.
Legacy processes started before the lease support was installed, and programs
that call Divalia libraries directly, do not hold these leases. Read-only source
copies and linked worktrees remain usable normally but cannot self-update.

This workflow supports editable source checkouts. Installed wheels and packaged
copies require their installation mechanism; the updater does not rewrite
site-packages or install dependencies. A GitHub commit identifies the selected
source, not an independent security certification. Review the proposed changes.
Plugin review receipts, quarantines, keys and Angerona settings are unaffected.

## Daily checks without starting Divalia

```powershell
python tools/update_divalia.py --check-only
python tools/update_divalia.py --check-only --force
```

The second command requests a manual refresh, retaining a 15-minute retry floor.
Noninteractive sessions never approve an update. A scheduler can run the first
command once daily and retain its output; no task or service is installed by
Divalia. The startup launcher checks when invoked, rather than polling while
the application is closed.

## Angerona uses verified releases

Angerona's existing **Settings → General → Check GitHub for updates once a day**
option checks on startup and while open, with a persisted 24-hour interval.
It is an explicit network opt-in. Source changes and stable releases are shown
separately. Ordinary source pushes can be discovered, but they do not authorize
an Angerona installation.

Angerona's approved release helper is `tools/update_angerona.py` in
`Ag3nt47/AngeronaSuite`. It downloads the selected stable Windows release and
hands installation to the protected installed verifier/installer. Signed-release
authorization and rollback protections remain required. See
[Angerona's update guide](https://github.com/Ag3nt47/AngeronaSuite/blob/main/docs/github-updates.md).
