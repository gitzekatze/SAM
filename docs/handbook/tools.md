# Your tools

Every command SAM's maintenance uses: what it does, when to use it and why
it exists. Run them in your clone of the repository.

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
| `sam-jail doctor --contracts` | checks every contract with the outside world on this computer, with the versions | after a system update, or when something stopped working |
| `python3 scripts/contract-map.py` | checks the contract map against the code and writes docs/contracts.md | after the code starts using something outside SAM (CI says so) |
| `python3 scripts/risk-class.py` | the risk class of your branch's changes (low to critical) | before a pull request; CI shows it too |
| `python3 scripts/contract-verifier.py` | what in your branch weakens a promise or a protected test and would need `owner-approved` | before a pull request; CI runs it as "Needs your approval" |
| `python3 scripts/workflow-check.py` | the GitHub workflows have no known injection hole | after changing `.github/workflows/` |
| `make mutants-diff` | changes the code you touched on purpose and lists every change no test noticed | before pushing security-relevant code |

## Releasing

| Command | What it does |
|---|---|
| `scripts/new-version.sh X.Y.Z --dry-run` | checks that a release is possible, changes nothing |
| `scripts/new-version.sh X.Y.Z` | the whole release up to the draft: checks, upgrade test handed to the program `SAM_RELEASE_UPGRADE_COMMAND` names (the script does not run it itself; that program should run it in a container or under a separate account), tag, push, GitHub's build, sealing with the release key |
| `scripts/sign-release.sh vX.Y.Z` | seals a draft's AppImages (part of the above; for repeating it alone) |
| `scripts/release.sh X.Y.Z` | version everywhere, all tests handed to the program `SAM_RELEASE_TEST_COMMAND` names (the script runs none itself; that program should run them in a container or under a separate account), signed tag (part of the above) |
| `make report` | the version report: tests, coverage, speed, compared with the last one |

The release key itself is described in [Keeping SAM healthy](care.md#the-release-key).

## Deeper checks

| Command | What it does | When |
|---|---|---|
| `tests/upgrade/run.sh vX.Y.Z WORKDIR` | builds an older SAM, makes data with it, checks this SAM keeps it | before a release (`new-version.sh` hands it to the program `SAM_RELEASE_UPGRADE_COMMAND` names) |
| `tests/real-apps/run.sh` with `WORK=…` | runs real AppImages through SAM's whole flow in a hidden session | before a release; see [testing](../testing.md) |
| `python3 -I tests/real-apps/table.py WORKDIR KINDS` | summarises a real-app run in a table | after a real-app run |
| `tests/gui/*-atspi.sh OUTDIR` | clicks through the window in a hidden session | after changing the window (CI runs them too) |
| `tests/gui/smoke.sh OUTDIR` | opens every page and fails on warnings | after changing the window |
| `cargo mutants …` | mutation testing of whole parts (hours) | once per version ([releasing](../releasing.md)) |
| `scripts/contract-diff.py OLD NEW` | what changed outside SAM between two runs (versions, contract states) | CI runs it on a failure |
| Actions → Early warning → Run workflow | the contracts on tomorrow's distributions, now instead of at night | after fixing an early-warning issue |
| `make test-shipped APPIMAGE=…` | the finished AppImage on fresh distributions | before publishing |

## Generated pages

These are written by scripts; never edit them by hand.

| Page | Made by |
|---|---|
| `docs/functions.md` | `scripts/function-map.py` (from `docs/functions.toml`) |
| `docs/contracts.md` | `scripts/contract-map.py` (from `docs/contracts.toml`) |
| (the automation's lists) | `keeper.toml`, read by the risk class, the contract verifier, the contract map and the early warning |
| `docs/test-library.md` | `scripts/test-library.py` |
| `DEVELOPMENT.md` (dashboard) | `scripts/dashboard.py` |
| `docs/reports/` | `scripts/version-report.py` (`make report`) |
| `THIRD-PARTY-LICENSES.md` | `scripts/third-party-licenses.py` |
| `data/man/` | `make man` |
| the website | `scripts/site.py` (on GitHub, by the Pages workflow; `make site` locally) |

## On GitHub

| Command | What it does |
|---|---|
| `gh pr create --fill` | opens a pull request for the current branch |
| `gh pr checks` | the state of a pull request's checks |
| `gh run list` | the newest CI runs |
| `gh run view RUN --log-failed` | the lines of a failed run that matter |
| `gh issue list` | open issues |
