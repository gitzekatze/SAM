# Contributing to SAM

Thank you for helping. A few notes make it smoother.

## What SAM stands for

Every change is weighed against five columns:

1. **Reliable opening:** SAM opens nearly any AppImage, measured on many
   real ones, not just test files.
2. **A simple flow:** from "found an AppImage" to "it runs safely" in a few
   clear steps, without hiding what matters.
3. **Real security:** protections that hold up, each promise proven by a
   test (docs/security.md).
4. **Privacy:** what SAM learns about you stays on your computer. No
   telemetry, network use only when asked, and bug reports that hide
   personal data.
5. **Clean code:** well structured, auditable and tested, so others can
   check it.

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

## Tests for every change

- Every change comes with a test that proves it. A fixed bug comes with a
  regression test that fails without the fix; say "Regression:" and what
  went wrong in the test's doc comment.
- Name a test after the promise it keeps (`undo_restores_every_app`), or
  give it a doc comment whose first sentence states that promise. Prefer
  regression tests that guard a real promise over tests that only raise
  line coverage.
- Logic that runs without a display gets unit or integration tests; the
  window is checked by `tests/gui/smoke.sh`, `tests/gui/permissions-atspi.sh`
  and `tests/gui/a11y-atspi.sh` (every control has a name for screen readers
  and takes keyboard focus).
- Every test belongs to one of SAM's functions: add its name under the
  function it proves in `docs/functions.toml`. A test may prove several
  functions; a new function needs a test, a scripted check, or a stated gap.
- A test must give the same result every time. CI runs the suite twice and
  fails on a test whose result differs (flaky), for example because two tests
  change the same environment variable at once.
- After adding, moving or renaming tests, run `make test-library` and commit
  `docs/test-library.md` and `docs/functions.md`; CI fails when they are out
  of date.

## The version report

`make report` (`scripts/version-report.py`) runs every test in a build that
records which code runs, then the benchmarks (`sam-jail dev bench`), and
writes `docs/reports/<version>-<commit>.md` and `.json`. The report shows for
each part of SAM the tests that pass and fail, its line coverage, how long
its steps take, and which parts it depends on, each compared with the
previous report: new and removed tests, coverage up or down, steps that got
more than 25 % slower, dependencies added or removed. Make a report at the
end of each phase of work and before every published version, and commit
it. Line coverage is a gap finder, not a score: it points at code no test
runs, where a regression test may be missing.

## Version numbers

The version changes only when a version is published. Small changes raise
the last number (0.1.0 → 0.1.1); big changes raise the middle number and
reset the last one (0.1.4 → 0.2.0).

## Ground rules

- SAM and Flatpak are separate apps: SAM never reads or writes Flatpak's
  files or folders.
- SAM never runs an app without a sandbox, and nothing an app prints may
  grant it more access.
- Text people see is plain and specific; explain what happens and what to
  do. Write whole sentences and wrap them in `tr`, `trf` or `trn` so they
  can be translated, then add the German, Spanish and French translations
  ([docs/translating.md](docs/translating.md)).
- The `--json` output is SAM's interface (`docs/json-interface.md`): raise
  `JSON_INTERFACE` in `sam-core` for any change an older reader would
  misread.
- Add a line to `CHANGELOG.md` under *Unreleased*.

## Licence

SAM is GPL-3.0-or-later. By contributing you agree that your contribution
is licensed the same way.
