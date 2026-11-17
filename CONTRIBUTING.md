# Contributing to SAM

Thank you for helping. A few notes make it smoother.

## What SAM stands for

Every change and every design decision is weighed against SAM's five
columns. They are for the people who build SAM; they guide the work and are
not a promise on the website.

1. **Reliability:** apps work in their sandbox and keep working, measured on
   many real AppImages, not just test files.
2. **Security:** the protection really holds and gives no false sense of
   safety. Each promise is proven by a test (docs/security.md).
3. **Simplicity:** "Simplicity is the highest form of sophistication", for
   the person using SAM and for every design decision behind it.
4. **Compatibility:** every kind of AppImage, through rules that fit whole
   groups of apps, never special cases for single apps.
5. **Privacy:** what SAM learns about you stays on your computer. No
   telemetry, network use only when asked, and bug reports that hide
   personal data.

Clean, auditable and tested code serves all five, above all Security and
Simplicity.

New to maintaining SAM, or back after a break? Start with the
[maintainer handbook](docs/handbook/index.md).

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
- Logic that runs without a display gets unit or integration tests. The
  window is checked in CI by `tests/gui/smoke.sh` (every page opens cleanly)
  and by the click-through tests `tests/gui/*-atspi.sh`: the main flow and
  the language, the app page, the Permission Manager, and names and keyboard
  focus for every control.
- **Test first where it pays:** for a bug, for a security boundary or limit,
  and for a new function, write the failing test before the code (a new
  function goes into `docs/functions.toml` first, with its promise and
  `gap = "…"` until its test exists). Layout and wording are checked by
  screenshots and the click-through tests instead.
- **Check that your tests would catch a mistake:** `make mutants-diff`
  changes only the code you touched, on purpose, and reports every change
  no test noticed. It takes minutes; run it before you push a change to
  security-relevant code.
- Every test belongs to one of SAM's functions: add its name under the
  function it proves in `docs/functions.toml`. A test may prove several
  functions; a new function needs a test, a scripted check, or a stated gap.
- A test must give the same result every time. CI runs the suite twice and
  fails on a test whose result differs (flaky), for example because two tests
  change the same environment variable at once.
- The tests that prove SAM's security promises are **protected**
  (`keeper.toml`): they may gain lines, never lose or change them. A change
  that weakens a promise, changes a protected test or adds a dependency
  needs the owner's label `owner-approved` ([AUTOMATION.md](AUTOMATION.md)).
- Code that starts using something outside SAM (a program, an option, a
  path, a variable, a D-Bus name, a syscall) needs a contract in
  `docs/contracts.toml`; `python3 scripts/contract-map.py` says which.
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
- Describe what changes for users in a new file in `changes/` (see
  [changes/README.md](changes/README.md)); never edit `CHANGELOG.md` directly, so
  two pull requests never collide there.

## Licence

SAM is GPL-3.0-or-later. By contributing you agree that your contribution
is licensed the same way.
