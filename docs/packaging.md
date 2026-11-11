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
   `SIGN_KEY=<gpg id>` also signs the tag and the files. Nothing is pushed.
3. `git push origin main vX.Y.Z`. The *Release* workflow builds the same
   files from the tag and attaches them to a **draft** GitHub release; check
   that its `SHA256SUMS` matches `dist/SHA256SUMS`, then publish the draft
   (the repository must be public for the AUR).
4. Copy `packaging/arch/PKGBUILD` and `.SRCINFO` into the AUR repository and
   push.

Test before publishing: copy both files next to the PKGBUILD (or point
`SRCDEST` at `dist/`) and run `makepkg -si`.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request (Ubuntu
24.04): build, clippy with warnings as errors, the whole test suite with the
end-to-end sandbox tests (Ubuntu's AppArmor restriction on user namespaces is
lifted on the throwaway runner), desktop file and metainfo validation, and a
check that `data/man` matches the commands (`make man`).

## Generic install

```sh
make && sudo make install PREFIX=/usr
# or into a staging dir
make install DESTDIR=/tmp/stage PREFIX=/usr
```

## AppImage

`make appimage RUNTIME=/path/to/runtime-x86_64` writes
`dist/SAM-X.Y.Z-x86_64.AppImage` (plus a `.sha256`). It needs `mksquashfs`
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
