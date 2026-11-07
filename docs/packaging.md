# Packaging

Native packages come first (whitepaper §2.23): Appseal needs the host's sandbox tools.

## Packages

| Package | Contents | Requires |
|---|---|---|
| `appseal-cli` | `/usr/bin/appseal`, `/usr/bin/appseal-run`, docs | bubblewrap, libarchive (`bsdtar`), glibc |
| `appseal` | `/usr/bin/appseal-gui`, desktop entry, metainfo, icon | appseal-cli, qt6-base, qt6-declarative, kirigami, kirigami-addons, kcolorscheme, kconfig, qqc2-desktop-style |

Optional dependencies of `appseal-cli`:

- `xdg-dbus-proxy` (recommended): filtered session D-Bus.
- `bubblejail`, `firejail`: optional backends.
- `squashfs-tools`: an additional SquashFS extractor.
- `strace`: diagnostic runs.
- `libnotify`: launch error notifications.

## Arch / CachyOS

`packaging/arch/PKGBUILD` builds the tree it lives in. For the AUR, set
`source=` to a release tarball and replace `_srcroot` with `$srcdir/appseal-$pkgver`.

## Generic install

```sh
make && sudo make install PREFIX=/usr
# or into a staging dir
make install DESTDIR=/tmp/stage PREFIX=/usr
```

## Phase 2 and 3

- **Fedora COPR, openSUSE OBS, Debian/Ubuntu:** see the notes in `packaging/`.
- **Flatpak or AppImage of Appseal itself:** not planned. Appseal must start
  `bwrap` on the host, and Flatpak's sandbox prevents that.
