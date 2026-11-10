# Fedora

`sam-jail.spec` builds offline from the two release files (source and
vendored Rust crates), as COPR and Koji require. Tested on Fedora 45
(Rust 1.99, GTK 4.24, libadwaita 1.10): builds, passes the test suite,
installs into a clean system with all dependencies, rpmlint clean apart
from missing man pages. A COPR repository is the planned way to publish.

Packages, same split as on Arch:

- `sam-jail-cli`: `sam-jail`, `sam-jail-run`. Requires `bubblewrap`,
  `bsdtar`; recommends `xdg-dbus-proxy`, `passt`; suggests `strace`,
  `squashfs-tools`.
- `sam-jail`: `sam-jail-gui`, desktop entry, metainfo, icon. Requires
  `sam-jail-cli`, `gtk4`, `libadwaita`.

Build requirements: `cargo`, `rust` (1.92 or newer: the GTK bindings
gtk-rs 0.11 need it, so only Fedora releases with Rust 1.92+ can build it),
`gtk4-devel`,
`libadwaita-devel`, `pkgconf`. Recent Fedora releases ship new enough
GTK and libadwaita. Unprivileged user namespaces are allowed by default,
so Bubblewrap works without extra setup.

`make && make install DESTDIR=… PREFIX=/usr` produces the same file layout
as the Arch package.

## Test build with podman

Without touching the host (storage in any folder you like):

```sh
P="podman --root $PWD/.containers/storage --runroot $PWD/.containers/run --storage-driver overlay"
$P run --name fedbuild -v "$PWD/packaging/fedora:/spec:ro,Z" registry.fedoraproject.org/fedora:latest \
    sh -c 'dnf -y install rpm-build rpmdevtools dnf-plugins-core && dnf -y builddep /spec/sam-jail.spec'
$P commit fedbuild sam-fedora-build && $P rm fedbuild
mkdir -p out
$P run --rm -v "$PWD/packaging/fedora:/spec:ro,Z" -v "$PWD/dist:/dist:ro,Z" -v "$PWD/out:/out:Z" sam-fedora-build \
    sh -c 'rpmdev-setuptree && cp /dist/sam-*.tar.* ~/rpmbuild/SOURCES/ && rpmbuild -ba /spec/sam-jail.spec && cp -r ~/rpmbuild/RPMS ~/rpmbuild/SRPMS /out/'
```

`dist/` comes from `make dist`. The end-to-end sandbox tests skip
themselves inside the container (no user namespaces there).
