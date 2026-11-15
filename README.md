# SAM - Sandboxed AppImage Manager

**Run AppImages in a sandbox, and see every permission they have as a simple switch.**

SAM does for AppImages what Flatseal does for Flatpak apps: a clear list of
apps, and for each one the access it has to your files, network, devices and
desktop. Unlike Flatseal, SAM also builds the sandbox itself, using
[Bubblewrap](https://github.com/containers/bubblewrap).

It is written in Rust, with a GTK 4 / libadwaita window and a full command
line (`sam-jail`). SAM is developed on CachyOS (Arch), where it is also tried
with 120 real AppImages. Every change runs the test suite on Ubuntu 24.04 and
the sandbox tests on Fedora, and before every release the finished AppImage is
tested on fresh Ubuntu, Debian, Fedora, Arch and openSUSE systems. Other
desktops and distributions have not been tried on real machines yet
([docs/testing.md](docs/testing.md)). [Functions and their proofs](docs/functions.md)
lists every promise SAM makes with the tests that prove it.

> [!NOTE]
> SAM makes AppImages much safer, but no sandbox makes every app perfectly
> secure. [docs/security.md](docs/security.md) explains what SAM protects
> against and where its limits are.

---

## How it works

1. **Find.** SAM lists the AppImages in your usual folders (`~/Applications`,
   `~/AppImages`, `~/.local/bin`, `~/bin`), in folders you add, and the ones
   existing menu entries start. Name and icon are read directly from the
   file. Nothing is unpacked or run.
2. **Inspect.** When you click *Create sandbox*, SAM unpacks the AppImage
   **without running it** and examines its programs and libraries: toolkit,
   graphics, sound, network, Electron, 32-bit and more.
3. **Recommend.** From the app's category (browser, media player, game, …)
   and what the inspection found, SAM proposes the smallest set of
   permissions the app needs. You can change anything before confirming.
4. **Sandbox.** The app gets its own private home folder and a menu entry
   that always starts it through the sandbox. If another tool such as
   AppImageLauncher or Gear Lever already made a menu entry for it, SAM
   offers to hide that one.
5. **Check.** A sandbox check starts the real sandbox with a test program
   instead of the app and confirms from the inside that every setting
   really applies.

---

## Features

### The sandbox

| Layer | What it does |
|---|---|
| Bubblewrap | Private home per app, read-only system, no capabilities, private `/dev/shm`. There is no unsandboxed mode: if Bubblewrap cannot run, SAM says why and starts nothing. |
| Landlock | Writes are allowed only where the profile allows them, even if a mount were wrong. Also blocks abstract sockets outside the sandbox (kernel 6.12+). |
| Syscall filter | A baseline filter, on by default (similar to Flatpak's), plus an optional strict filter. |
| D-Bus filter | Session and system bus go through `xdg-dbus-proxy`; the app sees only the names it is allowed to. |
| Portal filter | Opening links, file dialogs, notifications and printing work. Screenshots, autostart, menu-entry installation, location and remote desktop are blocked. |

### Permissions

Every permission has a plain-language explanation and a risk level
(*Low*, *Medium*, *High*, *Dangerous*). Risky choices show a warning.

- **Files:** private home, XDG folders (read-only or read/write), your own
  paths. Files you open with an app are granted one by one.
- **Network:** none, *This computer only* (no internet, but the app's own web
  page and the local services you list, such as Ollama), or full.
- **Display and devices:** Wayland, X11, GPU, sound (without access to
  cameras), webcam, game controllers
  (joysticks only, never keyboards or mice), USB, all input devices.
- **Desktop integration:** passwords and keyring, media controls, screen
  sharing, "show in folder", input methods (Fcitx5, IBus).
- **Advanced:** sockets, environment variables, a writable app folder for
  portable apps, syscall filters, nested namespaces.

### Making apps work

- **First-run check:** after *Create sandbox*, SAM points out what often goes
  wrong, such as logins that need a browser or files that stay inside the
  sandbox.
- **Log analysis:** common error messages turn into one-click fixes.
- **Repair steps:** *Try the next fix and start*, one step at a time, with
  *Undo all*.
- **Compatibility mode:** broader access for stubborn apps. Turning it off
  restores your previous settings.
- **Built in:** links open in your normal browser; DNS works with the usual
  setups (a plain `resolv.conf`, systemd-resolved, NetworkManager); AppImages
  started from inside a sandbox work without FUSE; AppImages for another
  processor are refused with a message that says which version to download.

### Safe intake

- Type 2 AppImages (gzip, xz, zstd and lz4), unpacked by SAM's own SquashFS
  reader inside a minimal sandbox. DwarFS-based AppImages are unpacked with
  `dwarfsextract` when it is installed. The old, rare Type 1 format is
  unpacked with `bsdtar`; no automated test covers it yet.
- Setuid bits, links that point outside the app and special files are
  removed. Size, file-count and time limits apply.
- Names, descriptions and file names from an AppImage are shown as plain
  text, never as markup.
- Menu entries never register URL schemes or broad file types.

### The window

- **Two columns, like Flatseal.** On the left: the AppImage locations and
  every AppImage found, grouped into *Sandboxed* and *Not sandboxed*. On the
  right: the selected app, its main button (*Launch* or *Create sandbox*) and
  every setting.
- **Nothing hidden.** There are no modes to switch. Settings that don't apply
  are greyed out, so you always see what is on and what is off. SAM asks only
  before something that cannot be undone, such as removing a sandbox, or that
  would take away access an app needs.
- **Before a sandbox exists,** the right column shows SAM's recommendation,
  ready to adjust.
- **All apps at a glance:** *Permission Manager* shows what every
  sandboxed app may access and changes a permission for several apps at
  once, with Undo.
- **Everything else:** your own presets, troubleshooting, logs, diagnostics and a
  built-in user guide (☰ → *User Guide*, also at
  [docs/guide.md](docs/guide.md)).
- **Handy:** drag and drop folders and AppImages onto the window, with
  search, filters and light or dark style.

---

## Installation

### Arch Linux and CachyOS

```sh
cd packaging/arch
makepkg -si
```

This installs two packages:

| Package | Contains |
|---|---|
| `sam-jail-cli` | `sam-jail` (command line) and `sam-jail-run` (sandbox runner) |
| `sam-jail` | `sam-jail-gui` (the window) |

Recommended extras:

| Package | Needed for |
|---|---|
| `xdg-dbus-proxy` | filtered D-Bus and the portal filter |
| `passt` (provides `pasta`) | *This computer only* |
| `strace` | diagnostic runs |

### Fedora

Build the RPMs from `packaging/fedora/sam-jail.spec`
([packaging/fedora/README.md](packaging/fedora/README.md)). A COPR
repository is planned.

### AppImage (any distribution)

`SAM-X.Y.Z-x86_64.AppImage` (or `-aarch64` for 64-bit ARM) from the GitHub
release runs on any recent distribution that has Bubblewrap, GTK 4 and libadwaita 1.5 or newer.
Before every release, the finished AppImage is tested on fresh installations of
Ubuntu 24.04, Debian 13, Fedora, Arch Linux and openSUSE Tumbleweed. Older
systems such as Debian 12 and Ubuntu 22.04 have a C library (glibc) that is too
old; there the AppImage says so and does not start.

```sh
chmod +x SAM-*-x86_64.AppImage
./SAM-*-x86_64.AppImage              # the window
./SAM-*-x86_64.AppImage cli doctor   # the command line (sam-jail)
```

Menu entries made by SAM point to the AppImage file. If you move it, open SAM
once so it can update them.

### From source

You need Rust 1.92 or newer, GTK 4.12+, libadwaita 1.5+ and Bubblewrap.

```sh
make                              # release build of the command line and the window
make test                         # test suite, including real sandbox tests
cargo fmt --all                   # the code format (rustfmt.toml); CI checks it
sudo make install PREFIX=/usr
```

During development, `cargo build` and then `target/debug/sam-jail-gui`. The
window uses the `sam-jail` built next to it; `SAM_CLI` and `SAM_RUN` point it
at other binaries. More in [docs/packaging.md](docs/packaging.md).

---

## Quick start

**In the window:** pick an AppImage on the left, look through the recommended
settings, click *Create sandbox*, then *Launch*.

**On the command line:**

```sh
sam-jail discover                               # AppImages found, sandboxed or not
sam-jail sandbox ~/Applications/Krita.AppImage  # create a sandbox
sam-jail info krita                             # permissions, warnings, dependencies
sam-jail set krita network.mode none            # change one permission
sam-jail group set network.mode none krita gimp # one change for several apps
sam-jail run krita                              # start it (or use the menu entry)
sam-jail verify krita                           # check that every setting applies
sam-jail remove krita                           # remove the sandbox; the AppImage stays
```

**When an app does not work:**

```sh
sam-jail hints krita            # first-run check, with fixes
sam-jail repair krita           # what went wrong last time
sam-jail repair krita --next    # apply the next repair step
sam-jail repair krita --undo    # undo all repair steps
sam-jail compat krita on        # compatibility mode (off restores your settings)
sam-jail logs krita --list      # every log of this app
sam-jail stop krita             # close a running app, also one in the tray
sam-jail doctor                 # check this computer
```

Every command accepts `--json`. `sam-jail --help` and `man sam-jail` list them
all.

---

## Where SAM keeps its files

| Folder | Contents |
|---|---|
| `~/.config/sam/` | `config.toml`, presets, logs |
| `~/.local/share/sam/` | app records, unpacked apps, private homes, icons, writable app folders |
| `~/.local/share/applications/` | menu entries `sam-<app>.desktop` |
| `/run/user/<uid>/sam/` | files for one start (D-Bus proxy socket, passwd), removed afterwards |

SAM writes nowhere else. The one exception is another tool's menu entry for
an AppImage: SAM hides it only when you ask and puts it back when the sandbox
is removed.

**SAM and Flatpak are separate.** SAM never touches Flatpak's files or
folders. Only its window looks like Flatseal, so it feels familiar.

For testing, `SAM_CONFIG_DIR`, `SAM_DATA_DIR` and `SAM_APPLICATIONS_DIR` move
these folders elsewhere.

### Updates

SAM's files carry a format number:

- A newer SAM migrates older files and keeps the original once
  (`….format0.bak`).
- An older SAM never changes files written by a newer one.
- Files SAM cannot read are moved aside as `….damaged-<time>`, never
  deleted. `sam-jail doctor` lists them.

### Removing SAM

```sh
sam-jail uninstall          # list what would be removed
sam-jail uninstall --yes    # remove it (--keep-data keeps settings and app data)
```

This closes running apps and removes every sandbox, SAM's menu entries, its
settings and the apps' private data. Menu entries SAM hid come back. Your
AppImage files stay untouched. Afterwards, remove the packages or the
AppImage.

---

## Documentation

| Document | For |
|---|---|
| [User guide](docs/guide.md) | everyone: the window, every setting, troubleshooting |
| [Security](docs/security.md) | what the sandbox protects against, and its limits |
| [Profiles and presets](docs/profiles.md) | the permission file format |
| [Packaging](docs/packaging.md) | building packages and the AppImage |
| [JSON interface](docs/json-interface.md) | scripts: the `--json` output of every command |
| [Development dashboard](DEVELOPMENT.md) | developers: the current state, every test, the version reports and the latest commits |
| [Functions and their proofs](docs/functions.md) | everyone who wants to check a promise: every function of SAM with the tests that prove it |
| [Threat model](docs/threat-model.md) | what SAM protects, against whom, how, and where that ends |
| [Architecture](docs/architecture.md) | developers: how the parts fit together |
| [Testing](docs/testing.md) | automated tests and the manual checklist |
| [Releasing](docs/releasing.md) | the checklist for a new version |
| [Translating](docs/translating.md) | adding a language |
| [Changelog](CHANGELOG.md) | what changed in each version |

### Source layout

| Crate | Purpose |
|---|---|
| `sam-core` | data model, permissions, risk, warnings, configuration, host checks |
| `sam-storage` | app records, presets, logs |
| `sam-detect` | AppImage format and ELF dependency analysis |
| `sam-intake` | unpacking, metadata, icons, menu entries |
| `sam-profile` | categories, recommendations, presets |
| `sam-sandbox` | the Bubblewrap command builder |
| `sam-runner` | everything that runs: launch, D-Bus proxy, Landlock and seccomp, "this computer only" network, sandbox check, repair, diagnostics |
| `sam-jail-cli` | the `sam-jail` and `sam-jail-run` programs |
| `sam-gtk` | `sam-jail-gui`, the window (talks to the core through `sam-jail --json`) |

Also: `data/` (menu entry, AppStream metainfo, icon, man pages),
`packaging/` (Arch, Fedora, notes for other distributions), `scripts/`
(release and AppImage builds) and `tests/` (real-app harness).

---

## How SAM is made

SAM is a one-person project. Most of its code and documentation was written
with [Claude](https://www.anthropic.com/claude), Anthropic's AI model, as a
coding assistant; the commits it helped with say so ("Co-Authored-By"). The
maintainer decides what SAM does and how far each permission may go, sets
the priorities and tries SAM on a real desktop; Claude writes most of the
code and the tests, and every change has to pass them before it goes in.

Because the code came about quickly and with AI help, SAM does not ask to be
trusted on its word. Every promise it makes is meant to be checked:

- each security promise in [docs/security.md](docs/security.md) names the
  test that proves it, and the [threat model](docs/threat-model.md) says
  what SAM does *not* protect against;
- each function SAM offers is mapped to its tests in
  [docs/functions.md](docs/functions.md), generated on every change;
- breakout tests run in a real sandbox in CI on Ubuntu and Fedora, untrusted
  input is fuzzed, and before each version mutation testing checks that the
  tests notice deliberate mistakes ([latest report](docs/reports/mutants-2026-11-15.md));
- the AppImage is tested on five distributions before each release, and
  releases are signed.

An outside security review is planned before the first public beta. Until
then, treat SAM as what it is: young, carefully tested software that has not
yet been reviewed by anyone but its makers. If you find a way out of the
sandbox, please report it privately ([SECURITY.md](SECURITY.md)).

---

## License

GPL-3.0-or-later. SAM's programs contain libraries by other people under their
own licenses (mostly MIT and Apache-2.0); [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)
lists them with their license texts and is installed with every package.

The app icon (`data/io.github.gitzekatze.SAM.svg`) is based on the seal icon
from [Arcticons](https://github.com/Arcticons-Team/Arcticons), licensed under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
