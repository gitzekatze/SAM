# Packaging

Native packages come first (whitepaper §2.23): SAM needs the host's sandbox tools.

## Packages

| Package | Contents | Requires |
|---|---|---|
| `sam-jail-cli` | `/usr/bin/sam-jail`, `/usr/bin/sam-jail-run`, docs | bubblewrap, libarchive (`bsdtar`), glibc |
| `sam` | `/usr/bin/sam-jail-gui`, desktop entry, metainfo, icon | sam-jail-cli, gtk4, libadwaita |

Optional dependencies of `sam-jail-cli`:

- `xdg-dbus-proxy` (recommended): filtered session D-Bus.
- `squashfs-tools`: an additional SquashFS extractor.
- `strace`: diagnostic runs.
- `libnotify`: launch error notifications.

## Arch / CachyOS

`packaging/arch/PKGBUILD` builds the tree it lives in. For the AUR, set
`source=` to a release tarball and replace `_srcroot` with `$srcdir/sam-$pkgver`.

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
