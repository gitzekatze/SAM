# Debian / Ubuntu

Planned: `.deb` packages from one source (openSUSE Build Service or a
Launchpad PPA), built from a release tarball that includes all Rust crates
(`cargo vendor`), because these builders have no network access.

Packages, same split as on Arch:

| Package | Contents | Depends |
|---|---|---|
| `sam-jail-cli` | `sam-jail`, `sam-jail-run` | `bubblewrap`, `libarchive-tools` (bsdtar); recommends `xdg-dbus-proxy`, `passt`; suggests `strace`, `squashfs-tools` |
| `sam` | `sam-jail-gui`, desktop entry, metainfo, icon | `sam-jail-cli`, `libgtk-4-1`, `libadwaita-1-0` |

Build dependencies: `cargo`/`rustc` (1.80 or newer), `libgtk-4-dev`,
`libadwaita-1-dev`, `pkg-config`.

Release notes per distribution:

- **Debian 13 (trixie)** and newer: CLI and GUI.
- **Debian 12 (bookworm)**: libadwaita is too old for the GUI; CLI only.
- **Ubuntu 24.04 LTS** and newer: CLI and GUI (the GUI needs libadwaita
  1.5 or newer). Since 23.10, Ubuntu restricts unprivileged user
  namespaces with AppArmor; Bubblewrap needs an AppArmor allowance.
  `sam-jail doctor` detects this and explains the fix. Electron apps inside
  SAM then usually need `--no-sandbox` (SAM's repair offers it).
- Rust: Ubuntu 24.04's default `rustc` is too old; build with the
  versioned `rustc-1.80`/`cargo-1.80` packages or a newer toolchain.
