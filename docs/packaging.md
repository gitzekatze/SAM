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

## Arch / CachyOS (AUR)

`packaging/arch/PKGBUILD` (with `.SRCINFO`) is the AUR package `sam-jail`,
split into `sam-jail-cli` and `sam-jail`. It downloads the two release files
from GitHub, checks them, and builds offline from the vendored crates.

Release steps (one command does them all):

1. Write the changes under `## Unreleased` in `CHANGELOG.md`.
2. `RUNTIME=/path/to/runtime-x86_64 scripts/release.sh X.Y.Z`
   - sets the version everywhere (Cargo, metainfo, Fedora spec, PKGBUILD),
     dates the changelog section, regenerates the man pages;
   - runs clippy (warnings are errors) and the whole test suite;
   - commits `Release X.Y.Z` and tags `vX.Y.Z` with the release notes;
   - builds `dist/` (source, vendored crates, `SHA256SUMS`, the AppImage)
     and commits the PKGBUILD checksums and `.SRCINFO`.
   Releases are signed: `SIGN_KEY=<gpg id>` is required and signs the tag,
   the files and `SHA256SUMS` (`.asc` next to each). `UNSIGNED=1` makes an
   unsigned test release. Nothing is pushed.
3. `git push origin main vX.Y.Z`. The *Release* workflow builds the same
   files from the tag and attaches them to a **draft** GitHub release; check
   that its `SHA256SUMS` matches `dist/SHA256SUMS`, add the `.asc` files from
   `dist/`, then publish the draft (the repository must be public for the
   AUR).
4. Copy `packaging/arch/PKGBUILD` and `.SRCINFO` into the AUR repository and
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
gets a `.zsync` file next to it, written by `sam-jail dev make-zsync`; upload
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
