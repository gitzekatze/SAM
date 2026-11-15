# Debian / Ubuntu

**Use the AppImage** (`SAM-X.Y.Z-x86_64.AppImage` from the GitHub release).
It uses the system's GTK 4 and libadwaita, so on Debian 13 (trixie) and
Ubuntu 24.04 or newer install these first:

```sh
sudo apt install bubblewrap libarchive-tools libgtk-4-1 libadwaita-1-0 xdg-dbus-proxy passt
```

`xdg-dbus-proxy` (filtered D-Bus) and `passt` (*This computer only*) are
optional but recommended; `strace` enables diagnostic runs.

*This computer only* needs a `pasta` with `--splice-only` (newer passt
releases). Ubuntu 24.04's passt is too old: SAM then starts such apps with no
network at all, never with internet access, and `SAM.AppImage cli doctor`
says so. On newer releases, `doctor`'s "This computer only" line shows whether
the installed passt is new enough.

## Why there are no .deb packages yet

SAM's GTK bindings (gtk-rs 0.11) need Rust 1.92 or newer. Debian 13 ships
Rust 1.85 and Ubuntu 24.04 offers versioned Rust packages of a similar age,
so the distributions' own build services (official Debian, Launchpad PPAs,
openSUSE Build Service) cannot build SAM. Revisit when those releases carry
Rust 1.92+ (Debian 14, Ubuntu 26.04), or build .debs with an upstream Rust
toolchain for the GitHub release.

If .debs are made later, use the same split as on Arch:

| Package | Contents | Depends |
|---|---|---|
| `sam-jail-cli` | `sam-jail`, `sam-jail-run` | `bubblewrap`, `libarchive-tools` (bsdtar); recommends `xdg-dbus-proxy`, `passt`; suggests `strace`, `squashfs-tools` |
| `sam-jail` | `sam-jail-gui`, desktop entry, metainfo, icon | `sam-jail-cli`, `libgtk-4-1`, `libadwaita-1-0` |

## Ubuntu: user namespaces

Since 23.10, Ubuntu restricts unprivileged user namespaces with AppArmor;
Bubblewrap needs an AppArmor allowance. `sam-jail doctor` (in the AppImage:
`SAM.AppImage cli doctor`) detects this and explains the fix. Electron apps
inside SAM then usually need `--no-sandbox` (SAM's repair offers it).
