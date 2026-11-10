# Packaging

Native packages come first (whitepaper §2.23): SAM needs the host's sandbox tools.

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

Release steps:

1. Bump the version in `Cargo.toml`, commit, tag `vX.Y.Z`.
2. `make dist`: `dist/sam-X.Y.Z.tar.gz`, `dist/sam-X.Y.Z-vendor.tar.xz` and
   `SHA256SUMS` (reproducible: the same tag gives the same files).
3. Upload both files to the GitHub release `vX.Y.Z` (the repository must be
   public for the AUR).
4. Put the checksums into the PKGBUILD, `makepkg --printsrcinfo > .SRCINFO`,
   push both to the AUR repository.

Test before publishing: copy both files next to the PKGBUILD (or point
`SRCDEST` at `dist/`) and run `makepkg -si`.

## Generic install

```sh
make && sudo make install PREFIX=/usr
# or into a staging dir
make install DESTDIR=/tmp/stage PREFIX=/usr
```

## Phase 2 and 3

- **Fedora COPR, openSUSE OBS, Debian/Ubuntu:** see the notes in `packaging/`.
- **Flatpak or AppImage of SAM itself:** not planned. SAM must start
  `bwrap` on the host, and Flatpak's sandbox prevents that.
