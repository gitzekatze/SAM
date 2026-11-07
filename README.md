# Appseal

Flatseal-style permission manager and sandbox launcher for AppImages.
Built in Rust and Qt6/Kirigami. Targets CachyOS first and works on other Linux distributions too.

Appseal unpacks an AppImage **without running it** and inspects its binaries
and libraries. It recommends a safe permission profile and then launches the
app inside a **Bubblewrap** sandbox. Every permission comes with a
plain-language explanation and a risk level, and risky choices show a warning.

> Appseal makes AppImages safer. It cannot make every AppImage perfectly
> secure or compatible without some involvement from you. See
> [docs/security.md](docs/security.md) for what it protects against and what it does not.

## Features

- **Intake:** Type 1 and Type 2 AppImages. Type 2 payloads (gzip, xz or zstd)
  are unpacked by a built-in SquashFS reader. Extraction strips setuid bits,
  removes symlinks that point outside the payload, and enforces size, file-count
  and time limits. Running the AppImage's own `--appimage-extract` is a fallback
  that needs your consent and runs inside a sandbox.
- **Dependency detection:** static ELF analysis (`DT_NEEDED`, glibc version
  requirements, CPU architecture, toolkit, Electron/Java markers). An optional
  diagnostic run under `strace` finds missing resources.
- **Recommended profiles** chosen by category (browser, media player, image
  editor, game, …) plus what detection found. Six built-in presets, and you can
  create, import and export your own.
- **Permissions:** filesystem (private home, XDG folders read-only or read/write,
  custom paths), network (full or none), GPU, audio, webcam, input devices, USB,
  Wayland and X11, session and system D-Bus (filtered through `xdg-dbus-proxy`),
  sockets, environment variables, and advanced options.
- **Backends:** Bubblewrap (default), Bubblejail (optional), Firejail (optional,
  disabled by default), and unsandboxed (needs explicit confirmation).
- **Kernel features:** Landlock write restrictions (defense in depth) and an
  optional strict seccomp filter.
- **Desktop integration:** menu launchers that always start the app through
  `appseal-run`, plus cached icons.
- **Usability:** onboarding, simple and advanced modes, status badges,
  drag-and-drop, a repair workflow, logs, a diagnostics screen, redacted bug
  reports, and four themes (Breeze Light, Breeze Dark, Breeze High Contrast,
  CachyOS Neon).

## Install (CachyOS / Arch)

```sh
cd packaging/arch
makepkg -si
```

The packages are `appseal-cli` (`appseal`, `appseal-run`) and `appseal` (the
GUI, `appseal-gui`). Recommended extras: `xdg-dbus-proxy`, and `strace` for
diagnostic runs.

## Build from source

Requirements: Rust (stable), CMake, Qt 6.5+, KF6 Kirigami, Kirigami Addons,
KColorScheme, KConfig and bubblewrap.

```sh
make            # release build of the CLI and the GUI
make test       # Rust test suite (includes an end-to-end sandbox test)
sudo make install PREFIX=/usr
```

For development: `cargo build`, then `cmake -S gui -B gui/build && cmake --build gui/build`.
Started from a source checkout, the GUI finds `target/debug/appseal` on its
own. You can also point it at a binary with `APPSEAL_CLI` / `APPSEAL_RUN`.

## Quick start

```sh
appseal add ~/Applications/Krita-5.2.6-x86_64.AppImage
appseal info krita                      # profile, warnings, dependencies
appseal set krita network.mode none     # change one permission
appseal preset apply "Image Editor" krita
appseal review krita                    # accept the profile
appseal run krita                       # or use the menu launcher
appseal doctor                          # check the system
```

Run `appseal --help` to see every command. Each command also accepts `--json`.

## Layout

```
crates/
  appseal-core                core types, permission model, risk, warnings, config, host probing, backend trait
  appseal-storage             app registry, presets, logs
  appseal-detect              AppImage type/payload detection, ELF dependency analysis
  appseal-intake              extraction, normalization, metadata, icons, launchers, staleness
  appseal-profile             categories, recommendations, presets, preset compatibility checks
  appseal-backend-bubblewrap  default backend
  appseal-backend-bubblejail  optional backend
  appseal-backend-firejail    optional compatibility backend
  appseal-runner              orchestration: add/update/launch, backend selection, D-Bus proxy, Landlock/seccomp, diagnostics
  appseal-cli                 appseal and appseal-run binaries
gui/                          Qt6/QML/Kirigami GUI (thin C++ shell; talks to the core via `appseal --json`)
data/                         desktop entry, AppStream metainfo, icon
packaging/                    Arch/CachyOS PKGBUILD, notes for other distributions
docs/                         whitepaper, security, profiles, packaging, architecture, testing
```

## Storage

```
~/.config/appseal/            config.toml, presets/, logs/
~/.local/share/appseal/       apps/, extracted/, icons/, desktop/, homes/ (private per-app homes)
~/.local/share/applications/  appseal-<app-id>.desktop
```

Set `APPSEAL_CONFIG_DIR`, `APPSEAL_DATA_DIR` and `APPSEAL_APPLICATIONS_DIR` to
use different locations, for example for testing.

## License

GPL-3.0-or-later.
