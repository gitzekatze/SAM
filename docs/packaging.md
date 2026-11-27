# Packaging

Native packages come first: SAM needs the host's sandbox tools.

## Packages

| Package | Contents | Requires |
|---|---|---|
| `sam-jail-cli` | `/usr/bin/sam-jail`, `/usr/bin/sam-jail-run`, docs | bubblewrap, libarchive (`bsdtar`), glibc |
| `sam-jail` | `/usr/bin/sam-jail-gui`, desktop entry, metainfo, icon | sam-jail-cli, gtk4, libadwaita |

Optional dependencies of `sam-jail-cli`:

- `xdg-dbus-proxy` (recommended): filtered session D-Bus.
- `squashfs-tools`: an additional SquashFS extractor.
- `strace`: diagnostic runs.
- `libnotify`: launch error notifications.

Packages build SAM with `cargo build --release` and no features: the
`dev-tools` feature (and `--all-features`) would put the test and release
tools into the packaged programs ([Testing](testing.md)). SAM's tests run
only in a developer build (`cargo test` without `--release`): a test build
in release mode stops with a message, because a release build ignores the
variables that keep the tests away from the real folders and tools. Unless
debug assertions are set explicitly, rustc turns them off at every
optimisation level above 0, so a level above 0 in `RUSTFLAGS` (for example
Fedora's `-Copt-level=3`) makes such a build too. The test steps of the
Arch and Fedora recipes therefore add `-C opt-level=0` after the
distribution's flags; on Arch this is a safety net, because the build step
already unsets makepkg's `RUSTFLAGS` before the test step runs. So package
test steps run SAM's tests unoptimised, and they take longer than an
optimised test build would. The build steps never set level 0: a release
build at level 0 has debug assertions and would follow SAM's developer
variables, and `release_builds_never_turn_on_debug_assertions` in
`crates/sam-jail-cli/tests/automation.rs` fails if a build step, the
Makefile, a release script or a recipe sets it outside these test steps.
Cargo also takes profile settings from the builder's environment and from
Cargo configuration files outside the source, which no test of the source
can see. So the test steps of both recipes first run
`scripts/check-release-build.sh target/release/sam-jail`: it starts the
built `sam-jail` with SAM's folder variables pointing at a temporary folder
and fails the package build if the program follows them. The Makefile's
`cli` target, `scripts/make-appimage.sh`, `scripts/release.sh` and
`scripts/sign-release.sh` run the same check on the programs they build or
use.

## Arch / CachyOS (AUR)

`packaging/arch/PKGBUILD` (with `.SRCINFO`) is the AUR package `sam-jail`,
split into `sam-jail-cli` and `sam-jail`. It downloads the two release files
from GitHub, checks them, and builds offline from the vendored crates.

Releases are made with one command, `scripts/new-version.sh X.Y.Z`. It
runs `scripts/release.sh` (version everywhere, dated changelog, man pages,
clippy and every test, signed tag and files in `dist/`) on a branch
`release-X.Y.Z`, because `main` is protected and takes changes only through
pull requests, and merges that pull request once its checks pass. The
*Release* workflow then builds a **draft** GitHub release from the tag;
publishing it is a person's click. [Releasing](releasing.md) has every step
and the checks before it. For the AUR afterwards:

- Copy `packaging/arch/PKGBUILD` and `.SRCINFO` into the AUR repository and
  push.

Test before publishing: copy both files next to the PKGBUILD (or point
`SRCDEST` at `dist/`) and run `makepkg -si`.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request (Ubuntu
24.04): build, format check, clippy with warnings as errors (every `unsafe`
block needs a `// SAFETY:` comment), and the whole test suite **twice**
(`scripts/flaky-check.py`): a test whose result differs between the two runs
is flaky and fails the job. The end-to-end sandbox tests run too (Ubuntu's
AppArmor restriction on user namespaces is lifted on the throwaway runner).
Then desktop file and metainfo validation; checks that `data/man` matches the
commands (`make man`), that the test library, the function map
(`docs/functions.md`) and `THIRD-PARTY-LICENSES.md` are up to date, and that
the translations compile; and a window smoke test (`tests/gui/smoke.sh` on
GTK's Broadway backend: every page opens without GTK warnings; screenshots
are kept as a CI artifact). The run page ends with a summary of which of
SAM's functions the change touches and how their tests did.

A second job runs the sandbox tests (breakout, hostile AppImages, the
permission matrix, fuzzing) on Fedora, in a privileged container, as an
ordinary user.

A third job runs `cargo deny check` (`deny.toml`): known security
advisories, licences that fit GPL-3.0-or-later, banned crates, and crates
only from crates.io. Dependabot (`.github/dependabot.yml`) proposes updates
for the Actions and the crates every week.

## Generic install

```sh
make && sudo make install PREFIX=/usr
# or into a staging dir
make install DESTDIR=/tmp/stage PREFIX=/usr
```

## AppImage

`make appimage RUNTIME=/path/to/runtime-ARCH` writes
`dist/SAM-X.Y.Z-ARCH.AppImage` (plus a `.sha256`) for this computer's
architecture, x86_64 or aarch64; the *Release* workflow builds both. The AppImage carries
SAM's update information (`gh-releases-zsync|gitzekatze|SAM|latest|…`) and
gets a `.zsync` file next to it, written by `sam-jail dev make-zsync` (a
build of its own with the `dev-tools` feature: the AppImage's programs do
not contain the release tools); upload
both with every release so `sam-jail self-update` can find them. It needs `mksquashfs`
(squashfs-tools) and the AppImage type 2 runtime from
<https://github.com/AppImage/type2-runtime/releases>; the script checks the
runtime against a pinned SHA-256 (`RUNTIME_SHA256` to override).

- Holds `sam-jail`, `sam-jail-run` and `sam-jail-gui` only. GTK 4 and
  libadwaita 1.5+ come from the system, like Bubblewrap. If they are
  missing, the AppImage says which packages to install.
- `SAM.AppImage` opens the window, `SAM.AppImage cli …` is `sam-jail …`,
  and `SAM.AppImage --app-id ID` starts a sandboxed app.
- Menu entries created from the AppImage call the AppImage file (its mount
  folder changes on every start). After moving the AppImage, open SAM once:
  it rewrites the menu entries (`sam-jail desktop all refresh`).
- SAM itself is not sandboxed when run from the AppImage: it has to start
  Bubblewrap on the host. Upload the AppImage with the release files.

## Other distributions

- **Fedora COPR, openSUSE OBS, Debian/Ubuntu:** see the notes in `packaging/`.
- **Flatpak of SAM itself:** not planned. SAM must start `bwrap` on the
  host, and Flatpak's sandbox prevents that.
