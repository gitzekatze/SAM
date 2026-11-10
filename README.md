# SAM – Sandboxed AppImage Manager

Flatseal-style permission manager and sandbox launcher for AppImages.
Built in Rust with a GTK 4 / libadwaita window (the toolkit Flatseal uses). Developed and tested on CachyOS (Arch); other
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
  `~/bin`, your own folders and single files you add (Downloads is opt-in),
  plus AppImages that existing menu entries start. Names and icons are read straight from the
  SquashFS image; nothing is unpacked or run until you create a sandbox.
- **Sandbox on demand:** only *Create sandbox* unpacks the app, builds its
  profile and adds a SAM menu entry. If AppImageLauncher, Gear Lever or similar
  already made an unsandboxed menu entry, SAM offers to hide it, and puts it
  back when the sandbox is removed.
- **Intake:** Type 1 and Type 2 AppImages. Type 2 payloads (gzip, xz or zstd)
  are unpacked by a built-in SquashFS reader. Extraction strips setuid bits,
  removes symlinks that point outside the payload, and enforces size, file-count
  and time limits. Extraction itself runs inside a minimal Bubblewrap sandbox.
  Running the AppImage's own `--appimage-extract` is a fallback that needs your
  consent and also runs inside a sandbox. Names, descriptions and file names
  from AppImages are shown as plain text, and launchers never register URL
  schemes or other broad file types.
- **Dependency detection:** static ELF analysis (`DT_NEEDED`, glibc version
  requirements, CPU architecture, toolkit, Electron/Java markers). An optional
  diagnostic run under `strace` finds missing resources.
- **Recommended profiles** chosen by category (browser, media player, image
  editor, game, …) plus what detection found. Settings you adjust before
  *Create sandbox* are kept; everything else follows what SAM finds after
  unpacking (e.g. GPU for apps that load their graphics stack at start). Six built-in presets, and you can
  create, import and export your own.
- **Permissions:** filesystem (private home, XDG folders read-only or read/write,
  custom paths), network (none, *local network only*, or full), GPU, audio,
  webcam, game controllers (only joysticks: keyboards and mice stay hidden),
  all input devices, USB, Wayland and X11, session and system D-Bus
  (filtered through `xdg-dbus-proxy`), desktop integrations (passwords &
  keyring, media controls, screen sharing, "show in folder", input methods
  such as Fcitx5 and IBus through their sandbox frontends), sockets,
  environment variables, and advanced options (writable app folder, syscall
  filters, nested namespaces, …).
- **One sandbox: Bubblewrap.** Every app runs under `bwrap` with SAM's own
  layout (private home, read-only system, no capabilities, private `/dev/shm`),
  plus SAM's Landlock and seccomp layers inside it. There is no backend to
  pick and no unsandboxed mode. If Bubblewrap cannot run on this system (for
  example user namespaces are disabled), SAM says so and starts nothing.
- **Making apps work:** a first-run check after *Create sandbox* (no internet,
  files stay in the sandbox, window/GPU, logins, Electron on systems that
  restrict user namespaces); a log analyzer that turns common error messages
  into one-click fixes; a repair ladder ("Try the next fix and start", undo
  all), including starting Electron apps without Chromium's own sandbox when
  it cannot run inside SAM's; a "Didn't work last time" marker in the
  overview; `sam-jail selftest` to try apps briefly.
- **Compatibility helpers:** links open in your normal browser through the
  desktop portal; files opened with the app are granted one by one;
  AppImages started from
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
  - Nothing the app prints can grant it access: repair suggestions based on
    app output always ask first and never offer services that could escape
    the sandbox.
  - Files you open with an app can be given read-only (the default for media
    players) or read/write.
- **Sandbox check:** starts an app's real sandbox with a test program
  instead of the app and confirms from inside that every setting applies
  (folders hidden, read-only or writable, network, devices, display, sound,
  reachable D-Bus names, Landlock, syscall filter, no privileges). Results
  are stored with the app; optionally SAM checks before every start when
  something changed and refuses to start on a failed check. Also works
  before the sandbox exists, for the settings shown (nothing is unpacked).
- **Desktop integration:** menu launchers that always start the app through
  `sam-jail-run`, plus cached icons.
- **User guide** built into the window (☰ → *User Guide*), from
  [docs/guide.md](docs/guide.md).
- **Two-column window, like Flatseal:**
  - **Left:** the AppImage locations (folders and single files you add,
    plus an optional Downloads switch) pinned at the top, and below them
    every AppImage SAM found, grouped into *Sandboxed* and *Not sandboxed*,
    with icon, name and path.
  - **Right:** the selected app with its main button (Launch, or Create
    sandbox) pinned at the top, then every setting: preset, then
    network, display, sound and devices, files, desktop integration, D-Bus,
    sockets and advanced options.
  - Nothing is hidden behind modes or popups. Settings that don't apply are
    greyed out, so you always see what is on and off. For an app without a
    sandbox, the right column shows SAM's recommendation, which you can
    adjust before creating the sandbox.
  - After the permissions: **Launching** (launch arguments, a
    compatibility-mode switch that restores your settings when turned off)
    and **Menu Entries** (SAM's menu entry, and a switch that hides or
    restores other tools' menu entries for the same AppImage). Then
    troubleshooting (repair steps, re-run detection), details, the
    generated command and every log (start, unpacking, detection,
    diagnostic run). Global settings, presets and diagnostics open in the
    right column from the menu at the top left.
  - A segmented filter (All / Sandboxed / Unsandboxed), search, status
    badges, settings grouped with a short explanation each, toasts for
    feedback.
  - Drag-and-drop: a dropped folder becomes a location, a dropped
    AppImage is added and selected, anything else is refused with a
    message.
  - *Remove Sandbox* can keep the app's settings and files, so a new
    sandbox for the same AppImage picks them up again; Diagnostics shows
    and deletes data left behind this way. Style: follow the system,
    light or dark.

## Install (CachyOS / Arch)

```sh
cd packaging/arch
makepkg -si
```

The packages are `sam-jail-cli` (`sam-jail`, `sam-jail-run`) and `sam-jail`
(the GUI, `sam-jail-gui`). Recommended extras:
- `xdg-dbus-proxy`: filtered D-Bus and the portal filter.
- `passt` (provides `pasta`): *Local network only*.
- `strace`: diagnostic runs.

## Build from source

Requirements: Rust (stable), GTK 4.12+, libadwaita 1.5+ and bubblewrap.

```sh
make            # release build of the CLI and the GUI
make test       # Rust test suite (includes an end-to-end sandbox test)
sudo make install PREFIX=/usr
```

For development: `cargo build`, then `target/debug/sam-jail-gui`. The GUI
uses the `sam-jail` built next to it (or the newer of `target/release` and
`target/debug`). You can also point it at a binary with `SAM_CLI` / `SAM_RUN`.

## Quick start

```sh
sam-jail discover                        # AppImages found, sandboxed or not
sam-jail sandbox ~/Applications/Krita-5.2.6-x86_64.AppImage --hide-duplicates
sam-jail info krita                      # profile, warnings, dependencies
sam-jail set krita network.mode none     # change one permission
sam-jail preset apply "Image Editor" krita
sam-jail review krita                    # accept the profile
sam-jail run krita                       # or use the menu launcher
sam-jail verify krita                    # sandbox check: do the settings really apply?
sam-jail verify ~/Applications/App.AppImage   # check the recommended settings before creating the sandbox
sam-jail doctor                          # check the system
sam-jail remove krita                    # remove the sandbox (the AppImage stays)
```

When an app does not work:

```sh
sam-jail hints krita                     # first-run check, with one-click fixes
sam-jail repair krita                    # what went wrong last time, and repair steps
sam-jail repair krita --next             # apply the next step (then start the app again)
sam-jail repair krita --undo             # undo all repair steps
sam-jail compat krita on                 # compatibility mode; `off` restores the previous settings
echo '["--no-sandbox"]' | sam-jail args krita --stdin   # launch arguments
sam-jail logs krita --list               # every log; show one with --file
sam-jail remove krita --keep-data        # remove the sandbox, keep the app's settings and files
sam-jail stop krita                      # close a running app (also one sitting in the tray)
sam-jail remove krita --stop             # close it first if it runs, then remove
sam-jail cleanup --data --list           # data left behind by removed sandboxes (drop --list to delete)
sam-jail selftest                        # start every sandboxed app briefly
sam-jail menu list krita                 # unsandboxed menu entries for this AppImage
```

Run `sam-jail --help` to see every command. Each command also accepts `--json`.

## Layout

```
crates/
  sam-core                core types, permission model, risk, warnings, config, host probing
  sam-storage             app registry, presets, logs
  sam-detect              AppImage type/payload detection, ELF dependency analysis
  sam-intake              extraction, normalization, metadata, icons, launchers, staleness
  sam-profile             categories, recommendations, presets, preset compatibility checks
  sam-backend-bubblewrap  the Bubblewrap command builder
  sam-runner              orchestration: discover/add/launch, Bubblewrap checks,
                          D-Bus proxy and portal filter, Landlock/seccomp,
                          local network (pasta), repair (hints, log analyzer, ladder), diagnostics
  sam-jail-cli            sam-jail and sam-jail-run binaries
  sam-gtk                 sam-jail-gui: the GTK 4 / libadwaita window (talks to the core via `sam-jail --json`)
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
/run/user/<uid>/sam/      per-launch runtime files (D-Bus proxy socket, passwd/group), removed afterwards
```

Apart from these, SAM only hides another tool's menu entry for an AppImage
when you ask it to (and puts it back on removal). It never touches Flatpak's
files or folders: SAM and Flatpak are separate apps; only SAM's window looks
like Flatseal so it is familiar.

Set `SAM_CONFIG_DIR`, `SAM_DATA_DIR` and `SAM_APPLICATIONS_DIR` to
use different locations, for example for testing.

## License

GPL-3.0-or-later.

The app icon (`data/io.github.gitzekatze.SAM.svg`) is based on the seal icon
from [Arcticons](https://github.com/Arcticons-Team/Arcticons), licensed under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
