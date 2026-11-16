# Your tools

Every command SAM's maintenance uses: what it does, when to use it and why
it exists. Run them in `SAM/sam`.

## Everyday

| Command | What it does | When |
|---|---|---|
| `make test` | runs every test | before every commit |
| `cargo fmt --all` | puts the code into SAM's format | before every commit |
| `cargo clippy --workspace --all-targets -- -D warnings` | finds likely mistakes and unclear code | before every commit |
| `make test-library` | rewrites the test library and the function map | after adding, moving or renaming tests |
| `python3 scripts/i18n.py check` | translations complete, placeholders kept, informal address | after changing texts people read |
| `python3 scripts/i18n.py extract` | collects the texts to translate | after adding texts |
| `make mo` | compiles the translations | to try them in the window |
| `make mutants-diff` | changes the code you touched on purpose and lists every change no test noticed | before pushing security-relevant code |

## Releasing

| Command | What it does |
|---|---|
| `scripts/new-version.sh X.Y.Z --dry-run` | checks that a release is possible, changes nothing |
| `scripts/new-version.sh X.Y.Z` | the whole release up to the draft: checks, upgrade test, tag, push, GitHub's build, sealing with the release key |
| `scripts/sign-release.sh vX.Y.Z` | seals a draft's AppImages (part of the above; for repeating it alone) |
| `scripts/release.sh X.Y.Z` | version everywhere, all tests, signed tag (part of the above) |
| `make report` | the version report: tests, coverage, speed, compared with the last one |

The release key and its passphrase are explained in your private guide
(`SAM/personal/release-key-guide.md`).

## Deeper checks

| Command | What it does | When |
|---|---|---|
| `tests/upgrade/run.sh vX.Y.Z WORKDIR` | builds an older SAM, makes data with it, checks this SAM keeps it | before a release (done by `new-version.sh`) |
| `tests/real-apps/run.sh` with `WORK=…` | runs real AppImages through SAM's whole flow in a hidden session | before a release; see [testing](../testing.md) |
| `python3 -I tests/real-apps/table.py WORKDIR KINDS` | summarises a real-app run in a table | after a real-app run |
| `tests/gui/*-atspi.sh OUTDIR` | clicks through the window in a hidden session | after changing the window (CI runs them too) |
| `tests/gui/smoke.sh OUTDIR` | opens every page and fails on warnings | after changing the window |
| `cargo mutants …` | mutation testing of whole parts (hours) | once per version ([releasing](../releasing.md)) |
| `make test-shipped APPIMAGE=…` | the finished AppImage on fresh distributions | before publishing |

## Generated pages

These are written by scripts; never edit them by hand.

| Page | Made by |
|---|---|
| `docs/functions.md` | `scripts/function-map.py` (from `docs/functions.toml`) |
| `docs/test-library.md` | `scripts/test-library.py` |
| `DEVELOPMENT.md` (dashboard) | `scripts/dashboard.py` |
| `docs/reports/` | `scripts/version-report.py` (`make report`) |
| `THIRD-PARTY-LICENSES.md` | `scripts/third-party-licenses.py` |
| `data/man/` | `make man` |
| the website | `scripts/site.py` (on GitHub, by the Pages workflow; `make site` locally) |
| your copy with this handbook | `make handbook` (`scripts/site.py --private`, never published) |

## On GitHub

| Command | What it does |
|---|---|
| `gh pr create --fill` | opens a pull request for the current branch |
| `gh pr checks` | the state of a pull request's checks |
| `gh run list` | the newest CI runs |
| `gh run view RUN --log-failed` | the lines of a failed run that matter |
| `gh issue list` | open issues |
