# SAM - Sandboxed AppImage Manager

**Run AppImages in a sandbox, and see every permission they have as a simple switch.**

**Website:** [gitzekatze.github.io/SAM](https://gitzekatze.github.io/SAM): the user guide, the evidence behind SAM's promises, and the maintainer handbook.

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
2. **Inspect.** When you click *Create Sandbox*, SAM unpacks the AppImage
   **without running it** and examines its programs and libraries: toolkit,
   graphics, sound, network, Electron, 32-bit and more.
3. **Recommend.** From the app's category (browser, media player, game, …)
   and what the inspection found, SAM proposes the smallest set of
   permissions the app needs. You can change anything before confirming.
4. **Sandbox.** The app gets its own private home folder and a menu entry
   that always starts it through the sandbox. If another tool such as
   AppImageLauncher or Gear Lever already made a menu entry for it, SAM
   offers to hide that one.
5. **Test.** The *Test* button starts the real sandbox with a probe program
   instead of the app, confirms from the inside that every setting really
   applies, and then starts the app for a few seconds to see that it runs.

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

Every permission has a plain-language explanation and a risk level (*low*,
*medium*, *high*, *dangerous*); tags show them in three colours: grey for
harmless, amber for think twice, red for dangerous. Risky choices show a
warning before they apply.

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

- **First-run check:** after *Create Sandbox*, SAM points out what often goes
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
  right: the selected app, its main button (*Launch* or *Create Sandbox*) and
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

> **Status:** the first release, 0.2.0 (a beta), is being prepared. Until it
> is out there is no ready-made download; testers can build SAM from the
> source code.

From the first release on, SAM comes as one **AppImage** that runs on Ubuntu
24.04 and newer, Debian 13, Fedora 40 and newer, Arch Linux, CachyOS and
openSUSE Tumbleweed: download it from the
[releases page](https://github.com/gitzekatze/SAM/releases), allow it to run,
and open it. Packages in the AUR (Arch, CachyOS) and a COPR repository
(Fedora) are planned.

**[Install SAM](docs/install.md)** has the details: what your computer needs,
the AppImage step by step, your first sandbox, and building SAM yourself.
Packagers find build and install options in [docs/packaging.md](docs/packaging.md).

---

## Quick start

**In the window:** pick an AppImage on the left, look through the recommended
settings, click *Create Sandbox*, then *Launch*.

**On the command line:**

```sh
sam-jail discover                               # AppImages found, sandboxed or not
sam-jail add ~/Applications/Krita.AppImage      # create a sandbox
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

The [website](https://gitzekatze.github.io/SAM) presents these documents for
reading; this table is the same set in the repository.

| Document | For |
|---|---|
| [Install SAM](docs/install.md) | everyone: what your computer needs, installing, your first sandbox |
| [User guide](docs/guide.md) | everyone: the window, every setting, troubleshooting |
| [Security](docs/security.md) | what the sandbox protects against, and its limits |
| [Permissions](docs/permissions.md) | permission keys, preset files, group changes |
| [Packaging](docs/packaging.md) | building packages and the AppImage |
| [JSON interface](docs/json-interface.md) | scripts: the `--json` output of every command |
| [Development dashboard](DEVELOPMENT.md) | developers: the current state, every test, the version reports and the latest commits |
| [Functions and their proofs](docs/functions.md) | everyone who wants to check a promise: every function of SAM with the tests that prove it |
| [Threat model](docs/threat-model.md) | what SAM protects, against whom, how, and where that ends |
| [Architecture](docs/architecture.md) | developers: how the parts fit together |
| [Testing](docs/testing.md) | automated tests and the manual checklist |
| [Maintainer handbook](docs/handbook/index.md) | whoever looks after SAM: GitHub, everyday work, tools, care |
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

One person, one AI assistant, and a lot of proof.

SAM is a one-person project, built with [Claude](https://www.anthropic.com/claude),
Anthropic's AI model, as a coding assistant; the commits it helped with say so.
The maintainer decides what SAM does and how far each permission may go, sets
the priorities and tries SAM on a real desktop. Claude writes most of the code
and the tests, and a change goes in only when every test passes.

SAM doesn't ask for your trust. It shows its work:

- **More than 240 tests** guard **40 functions**, and
  [docs/functions.md](docs/functions.md) shows, after every change, which
  tests prove which function. A fixed bug gets a test that fails without
  the fix.
- **Every security promise** in [docs/security.md](docs/security.md) is
  attacked by a breakout test from inside a real sandbox, and the
  [threat model](docs/threat-model.md) lists each threat with what stops it,
  the test that proves it, and just as clearly what SAM does *not* protect
  against.
- **Breakout tests** run inside a real sandbox on every push, on Ubuntu and
  on Fedora, and SAM's readers of untrusted files are fuzzed.
- **Mutation testing** changed the security-critical code 2,821 times on
  purpose; the tests caught 88.5 % of the changes that could be built, and
  each gap that mattered got a test
  ([report](docs/reports/mutants-2026-11-15.md)).
- **120 real AppImages**, from Electron and Qt apps to games, Wine and
  Flutter, run through SAM's whole flow before a release: 117 start in
  their sandbox, 2 fail for reasons inside the app, and one built for
  another processor is turned away at the door.
- **Every release** is tested on five Linux distributions before it is
  published, and signed with SAM's release key
  ([sam-release-key.asc](sam-release-key.asc)), the only key SAM accepts for
  updates of itself.

The next step is a pair of fresh eyes: an outside security review, planned
before the first public beta. Found a way out of the sandbox? Please report it privately
([SECURITY.md](SECURITY.md)).

---

## License

GPL-3.0-or-later. SAM's programs contain libraries by other people under their
own licenses (mostly MIT and Apache-2.0); [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)
lists them with their license texts and is installed with every package.

The app icon (`data/io.github.gitzekatze.SAM.svg`) is based on the seal icon
from [Arcticons](https://github.com/Arcticons-Team/Arcticons), licensed under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
