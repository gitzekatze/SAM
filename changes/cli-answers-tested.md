### Checking an AppImage before adding it works again; the command line's answers are tested

- Fixed: `sam-jail verify FILE` for an AppImage without a sandbox (the
  window's check before adding, with `--permissions-stdin`) was always
  refused with "run `sam-jail review sam-check-preview`". The start gate
  for settings nobody confirmed also stopped this check, whose scratch
  record nobody can confirm. Only SAM's stand-in and its test program run
  there, never the app's own code, so the check runs again. Nothing else
  changes: an app with unconfirmed settings still does not start.
- New tests for answers a mutation run (2026-11-23) could change without
  any test noticing: `scan` and `discover` naming a sandboxed app and a
  moved copy on the terminal; `hints --apply` applying only the hint
  asked for; `menu list` naming unsandboxed menu entries; `list --search`,
  `--badge`, `--category` and `--sort`; `info` naming what compatibility
  mode turned on while it is on; `set` showing the warnings of the
  changed setting; the reminder of `add` to confirm the settings;
  `add --progress`; `uninstall` removing only with `--yes`; the arguments
  of `run` and `command`; `logs --file`; `verify` refusing given settings
  for a sandboxed app; `desktop`; `onboarding`; `dev sign-appimage` with
  the real GnuPG; the `function` of each command's errors.
- `selftest` is tested in a real sandbox with an app that keeps running:
  it ends the app when the time is up and passes it, its JSON answer
  stays the only thing on standard output, and the terminal marks passed
  and failed apps correctly. The verdict and the throttle of the progress
  lines are small functions now, tested with chosen times and records
  (same behaviour).
