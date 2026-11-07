# SAM – Sandboxed AppImage Manager

Flatseal-style permission manager and sandbox launcher for AppImages.
Built in Rust and Qt6/Kirigami. Developed and tested on CachyOS (Arch); other
distributions should work but are not tested yet (see [docs/testing.md](docs/testing.md)).

SAM lists the AppImages on your computer, sandboxed or not. When you create a
sandbox for one, SAM unpacks it **without running it** and inspects its binaries
and libraries. It recommends a safe permission profile and then launches the
app inside a **Bubblewrap** sandbox. Every permission comes with a
plain-language explanation and a risk level, and risky choices show a warning.

> SAM makes AppImages safer. It cannot make every AppImage perfectly
> secure or compatible without some involvement from you. See
> [docs/security.md](docs/security.md) for what it protects against and what it does not.

## Features

- **Overview:** AppImages in `~/Applications`, `~/AppImages`, `~/.local/bin`,
  `~/bin` and your own folders (Downloads is opt-in), plus AppImages that
  existing menu entries start. Names and icons are read straight from the
  SquashFS image; nothing is unpacked or run until you create a sandbox.
- **Sandbox on demand:** only *Create sandbox* unpacks the app, builds its
  profile and adds a SAM menu entry. If AppImageLauncher, Gear Lever or similar
  already made an unsandboxed menu entry, SAM offers to hide it, and puts it
  back when the sandbox is removed.
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
  custom paths), network (none, *local network only*, or full), GPU, audio,
  webcam, input devices, USB, Wayland and X11, session and system D-Bus
  (filtered through `xdg-dbus-proxy`), desktop integrations (passwords &
  keyring, media controls, screen sharing, "show in folder"), sockets,
  environment variables, and advanced options (writable app folder, syscall
  filters, nested namespaces, …).
- **Backends, picked per app:** Bubblewrap (default), Bubblejail, Firejail
  (allowed in settings first; runs the original AppImage) and unsandboxed
  (explicit confirmation). On *Automatic*, SAM chooses for each app: features
  only Bubblewrap has force it; if the sandbox cannot be set up, the next
  backend is tried and the one that works is remembered for that app, with
  the reason shown. A backend you pick yourself is never changed. If the
  chosen backend does not enforce some of the app's settings (for example
  Firejail has no *Local network only*), the app page lists them.
- **Making apps work:** a first-run check after *Create sandbox* (no internet,
  files stay in the sandbox, window/GPU, logins, Electron on systems that
  restrict user namespaces); a log analyzer that turns common error messages
  into one-click fixes; a repair ladder ("Try the next fix and start", undo
  all), including starting Electron apps without Chromium's own sandbox when
  it cannot run inside SAM's; a "Didn't work last time" marker in the
  overview; `sam-jail selftest` to try apps briefly.
- **Compatibility helpers:** links open in your normal browser through the
  desktop portal; files picked in portal file dialogs are handed to the app
  through the document portal (portal identity); AppImages started from
  inside a sandbox extract instead of using FUSE; DNS works with any
  resolv.conf setup; symlinked system data (including `/etc/alternatives`) is
  followed; a writable app folder for portable apps.
- **Local network only:** no internet and no DNS, but the app's own web page
  opens in your browser and the app can reach the local services you list
  (e.g. port 11434 for Ollama). Uses `pasta`.
- **Security layers:**
  - Landlock write restrictions, plus blocking of abstract sockets outside
    the sandbox (e.g. XWayland's X11 socket; kernel 6.12+).
  - A baseline syscall filter on by default (like Flatpak's), with an
    optional strict filter.
  - A private `/dev/shm`.
  - A desktop-portal filter that only allows harmless functions; screenshot,
    autostart, menu-entry installation, trash, location and remote desktop
    are blocked.
  - Portal identity, so portals treat SAM apps as sandboxed.
- **Desktop integration:** menu launchers that always start the app through
  `sam-jail-run`, plus cached icons.
- **Usability:** onboarding, simple and advanced modes, status badges,
  drag-and-drop, a repair workflow, logs, a diagnostics screen, redacted bug
  reports, and four themes (Breeze Light, Breeze Dark, Breeze High Contrast,
  CachyOS Neon).

## Install (CachyOS / Arch)

```sh
cd packaging/arch
makepkg -si
```

The packages are `sam-jail-cli` (`sam-jail`, `sam-jail-run`) and `sam` (the
GUI, `sam-jail-gui`). Recommended extras:
- `xdg-dbus-proxy`: filtered D-Bus, portal filter and portal identity.
- `passt` (provides `pasta`): *Local network only*.
- `strace`: diagnostic runs.
- `bubblejail`, `firejail`: optional backends.

## Build from source

Requirements: Rust (stable), CMake, Qt 6.5+, KF6 Kirigami, Kirigami Addons,
KColorScheme, KConfig and bubblewrap.

```sh
make            # release build of the CLI and the GUI
make test       # Rust test suite (includes an end-to-end sandbox test)
sudo make install PREFIX=/usr
```

For development: `cargo build`, then `cmake -S gui -B gui/build && cmake --build gui/build`.
Started from a source checkout, the GUI finds `target/debug/sam-jail` on its
own. You can also point it at a binary with `SAM_CLI` / `SAM_RUN`.

## Quick start

```sh
sam-jail discover                        # AppImages found, sandboxed or not
sam-jail sandbox ~/Applications/Krita-5.2.6-x86_64.AppImage --hide-duplicates
sam-jail info krita                      # profile, warnings, dependencies
sam-jail set krita network.mode none     # change one permission
sam-jail preset apply "Image Editor" krita
sam-jail review krita                    # accept the profile
sam-jail run krita                       # or use the menu launcher
sam-jail doctor                          # check the system
sam-jail remove krita                    # remove the sandbox (the AppImage stays)
```

When an app does not work:

```sh
sam-jail hints krita                     # first-run check, with one-click fixes
sam-jail repair krita                    # what went wrong last time, and repair steps
sam-jail repair krita --next             # apply the next step (then start the app again)
sam-jail repair krita --undo             # undo all repair steps
sam-jail selftest                        # start every sandboxed app briefly
sam-jail backend krita auto              # let SAM pick the backend again
sam-jail menu list krita                 # unsandboxed menu entries for this AppImage
```

Run `sam-jail --help` to see every command. Each command also accepts `--json`.

## Layout

```
crates/
  sam-core                core types, permission model, risk, warnings, config, host probing, backend trait
  sam-storage             app registry, presets, logs
  sam-detect              AppImage type/payload detection, ELF dependency analysis
  sam-intake              extraction, normalization, metadata, icons, launchers, staleness
  sam-profile             categories, recommendations, presets, preset compatibility checks
  sam-backend-bubblewrap  default backend
  sam-backend-bubblejail  optional backend
  sam-backend-firejail    optional compatibility backend
  sam-runner              orchestration: discover/add/launch, per-app backend selection and fallback,
                          D-Bus proxy and portal filter, portal identity, Landlock/seccomp,
                          local network (pasta), repair (hints, log analyzer, ladder), diagnostics
  sam-jail-cli            sam-jail and sam-jail-run binaries
gui/                          Qt6/QML/Kirigami GUI (thin C++ shell; talks to the core via `sam-jail --json`)
data/                         desktop entry, AppStream metainfo, icon
packaging/                    Arch/CachyOS PKGBUILD, notes for other distributions
docs/                         whitepaper, security, profiles, packaging, architecture, testing
```

## Storage

```
~/.config/sam/            config.toml, presets/, logs/
~/.local/share/sam/       apps/, extracted/, icons/, desktop/, homes/ (private per-app homes),
                          previews/ (overview icons), overlays/ (writable app folders)
~/.local/share/applications/  sam-<app-id>.desktop
/run/user/<uid>/sam/      per-launch runtime files (D-Bus proxy socket, identity files)
/run/user/<uid>/.flatpak/ portal identity instance files while an app runs (removed afterwards)
```

Set `SAM_CONFIG_DIR`, `SAM_DATA_DIR` and `SAM_APPLICATIONS_DIR` to
use different locations, for example for testing.

## License

GPL-3.0-or-later.
