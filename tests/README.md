# Tests

Most tests run with `cargo test --workspace`; this folder holds the ones that
need more than that. [docs/testing.md](../docs/testing.md) explains every
kind of test and the manual checks, and [docs/test-library.md](../docs/test-library.md)
lists every test with the promise it keeps.

| Folder | What it tests | How to run it |
|---|---|---|
| `gui/` | the window: every page opens cleanly (`smoke.sh`), and click-through tests through the accessibility interface (`*-atspi.sh`) | `tests/gui/smoke.sh OUTDIR`, `tests/gui/flow-atspi.sh OUTDIR`; CI runs them |
| `real-apps/` | real AppImages through SAM's whole flow, in an invisible KWin session with a private D-Bus and a fake home | `WORK=… tests/real-apps/run.sh App.AppImage …` |
| `upgrade/` | data made by an older SAM still works with this one | `tests/upgrade/run.sh vX.Y.Z WORKDIR` |
| `shipped/` | the finished AppImage on fresh distributions (used by `scripts/test-shipped.sh`) | `make test-shipped APPIMAGE=…` |
| `canary/` | the early warning: SAM's contracts and sandbox tests in a container of an upcoming distribution (used nightly by `.github/workflows/canary.yml`) | `docker run --privileged -v $PWD:/src:ro -v OUT:/out IMAGE sh /src/tests/canary/in-container.sh` |
| `appimages/` | a place for your own real AppImages (not committed) | |

Window and real-app tests start their own hidden sessions and never touch
your desktop.
