# Fedora

Planned: a COPR repository with an RPM spec, built from a release tarball
that includes all Rust crates (`cargo vendor`), because COPR/Koji builds
have no network access.

Packages, same split as on Arch:

- `sam-jail-cli`: `sam-jail`, `sam-jail-run`. Requires `bubblewrap`,
  `bsdtar`; recommends `xdg-dbus-proxy`, `passt`; suggests `strace`,
  `squashfs-tools`.
- `sam-jail`: `sam-jail-gui`, desktop entry, metainfo, icon. Requires
  `sam-jail-cli`, `gtk4`, `libadwaita`.

Build requirements: `cargo`, `rust` (1.80 or newer), `gtk4-devel`,
`libadwaita-devel`, `pkgconf`. Recent Fedora releases ship new enough
GTK and libadwaita. Unprivileged user namespaces are allowed by default,
so Bubblewrap works without extra setup.

`make && make install DESTDIR=… PREFIX=/usr` produces the same file layout
as the Arch package.
