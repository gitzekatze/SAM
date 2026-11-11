# Contributing to SAM

Thank you for helping. A few notes make it smoother.

## Before you start

- **Bugs:** open an issue with the *Bug report* form. For anything that
  weakens the sandbox, follow [SECURITY.md](SECURITY.md) instead.
- **Ideas:** open an issue first for larger changes, so we can agree on the
  approach before you spend time on it.

## Building and testing

```sh
make                 # release build of the command line and the window
make test            # the whole test suite, including real sandbox tests
cargo fmt --all      # the code format (rustfmt.toml); CI checks it
cargo clippy --workspace --all-targets -- -D warnings
```

Every security promise in `docs/security.md` has a test in
`crates/sam-runner/tests/breakout.rs`; a change to the sandbox needs one
too. More in [docs/testing.md](docs/testing.md) and
[docs/architecture.md](docs/architecture.md).

**Window tests** (`tests/gui/smoke.sh`) run in an invisible session of
their own (`tests/real-apps/run.sh` with `SESSION_SCRIPT`), never in your
desktop session: a private D-Bus started with your real runtime folder can
stop the desktop portals that Flatpak apps rely on.

## Ground rules

- SAM and Flatpak are separate apps: SAM never reads or writes Flatpak's
  files or folders.
- SAM never runs an app without a sandbox, and nothing an app prints may
  grant it more access.
- Text people see is plain and specific; explain what happens and what to
  do.
- The `--json` output is SAM's interface (`docs/json-interface.md`): raise
  `JSON_INTERFACE` in `sam-core` for any change an older reader would
  misread.
- Add a line to `CHANGELOG.md` under *Unreleased*.

## Licence

SAM is GPL-3.0-or-later. By contributing you agree that your contribution
is licensed the same way.
