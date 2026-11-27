# SAM - Sandboxed AppImage Manager

**Every AppImage, in a *sandbox you control*.**

SAM runs each AppImage sealed off from your files, keys and accounts, and
shows everything it may reach as a plain switch.

**Website:** [gitzekatze.github.io/SAM](https://gitzekatze.github.io/SAM): the user guide, the evidence behind SAM's promises, and the maintainer handbook.

## Why AppImages need a sandbox

1. **Simple.** AppImages are the easiest way to get software on Linux: you
   download one file and run it.
2. **Unprotected.** That file can then reach everything you can: your
   documents, your keys and your browser profiles, and nothing shows you
   what it does.
3. **Sandboxed.** SAM gives each AppImage its own sandbox, with exactly
   the access you allow, in a window anyone can use.

Flatpak apps come with a sandbox, and Flatseal lets you adjust it. AppImages
have neither. Wrapping them by hand needs command-line tools and knowledge of
what each app needs. SAM does that work for you and explains every decision.
It builds the sandbox with [Bubblewrap](https://github.com/containers/bubblewrap),
the same tool Flatpak uses, and its window works like Flatseal's.

## What SAM does differently

- **Nothing runs before you decide.** SAM reads an AppImage's name, icon and
  needs without running it, and it unpacks the app without running it. The
  app starts only when you press *Launch*.
- **Each app gets the least access it needs.** Every app starts with a
  private home folder and its own window. SAM adds only what this app shows
  it needs: sound for a music player, the network for a browser.
- **Every switch says what it costs.** Each permission is explained in one
  sentence and marked as harmless, some access, think twice or dangerous.
- **SAM finds out why an app struggles.** After a failed start, SAM reads what
  went wrong and offers the one change that helps, from mild to strong. You
  can undo every change.
- **Sandboxed apps fit into your desktop.** They appear in your application
  menu, and SAM's menu entries always start them through the sandbox. Menu
  entries from other tools that would start an app without its sandbox are
  shown as a warning, and SAM offers to hide them, from the menu and from
  opening files (on by default in SAM's window, `--hide-duplicates` on the
  command line).
- **SAM is built on proven parts.** Bubblewrap, Landlock, a system-call
  filter and filtered desktop services do the work. SAM adds no new code that
  runs with special privileges.

## How it works

1. **Find.** SAM lists the AppImages in your usual folders (`~/Applications`,
   `~/AppImages`, `~/.local/bin`, `~/bin`), in folders you add, and the ones
   that existing menu entries start. It reads names and icons directly from
   the file, without unpacking or running anything.
2. **Inspect.** When you click *Create Sandbox*, SAM unpacks the AppImage
   inside a small sandbox, **without running it**, and examines its programs
   and libraries: toolkit, graphics, sound, network, Electron, 32-bit and more.
3. **Recommend.** From the app's kind (browser, media player, game and so on)
   and what the inspection found, SAM proposes the smallest set of permissions
   the app needs. You can change any of them before you confirm.
4. **Sandbox.** The app gets its own private home folder and a menu entry that
   always starts it through the sandbox. If another tool, such as
   AppImageLauncher or Gear Lever, already made a menu entry for the app, SAM
   offers to hide that entry.
5. **Test.** The *Test* button starts the real sandbox with a probe program
   instead of the app, confirms from the inside that every setting applies,
   and then starts the app for a few seconds to see that it runs.

> [!NOTE]
> SAM makes AppImages much safer, but no sandbox makes every app perfectly
> secure. [docs/security.md](docs/security.md) explains what SAM protects
> against and where its limits are.

## The evidence

SAM protects you from programs you download, so it does not ask for blind
trust. It shows its work, and every number below comes from a report in this
repository.

- **<!-- fact:apps_start -->229<!-- /fact --> of <!-- fact:apps_total -->240<!-- /fact --> real AppImages start in their sandbox.**
  The test sets cover Electron, Qt, GTK, Flutter, Tauri, Java, Wine, games
  and command-line tools. <!-- fact:apps_repaired -->3<!-- /fact --> of them
  need repair steps that SAM offers by itself, <!-- fact:apps_fail -->10<!-- /fact --> do not start (the report gives
  the reason for each), and <!-- fact:apps_refused -->1<!-- /fact --> built for another processor
  is turned away with a clear message
  ([report of <!-- fact:apps_date -->2026-11-20<!-- /fact -->](docs/reports/real-apps-2026-11-20.md)).
- **<!-- fact:tests -->1,143<!-- /fact --> automated tests guard <!-- fact:functions -->42<!-- /fact --> functions.**
  [Functions and their proofs](docs/functions.md) shows which tests prove
  which function. A fixed bug gets a test that fails without the fix.
- **Every security promise is attacked by a test, most from inside a real sandbox.**
  Breakout tests run on every change, on Ubuntu and on Fedora. The
  [threat model](docs/threat-model.md) lists each threat with what stops it,
  the test that proves it, and just as clearly what SAM does *not* protect
  against.
- **The tests themselves are tested.** Mutation testing changed every line
  of code touched since the security audit <!-- fact:mutants_tested -->1,364<!-- /fact --> times on purpose, and the tests caught <!-- fact:mutants_caught_percent -->86.6 %<!-- /fact --> of
  the changes that could be built. The report sorts what they missed, and
  each gap that matters gets a test
  ([report](docs/reports/mutants-2026-11-20.md)).
- **SAM's readers of untrusted files are fuzzed.** Hundreds of thousands of
  damaged AppImages, programs and menu files go through them without a crash
  ([report](docs/reports/fuzz-2026-11-20.md)).
- **Every release is tested and signed.** The finished AppImage is tested on
  fresh Ubuntu, Debian, Fedora, Arch and openSUSE systems and signed with
  SAM's release key ([sam-release-key.asc](sam-release-key.asc)), the only key
  SAM accepts for updates of itself.

SAM is developed on CachyOS (Arch). Other desktops and distributions have not
been tried on real machines yet ([docs/testing.md](docs/testing.md)).

### How SAM is made

SAM is a one-person project, built with [Claude](https://www.anthropic.com/claude),
Anthropic's AI model, as a coding assistant; the commits it helped with say
so. The maintainer decides what SAM does and how far each permission may go,
sets the priorities and tries SAM on a real desktop. Claude writes most of the
code and the tests, and a change goes in only when every test passes.

The next step is a pair of fresh eyes: an outside security review, planned
before the first public beta. If you find a way out of the sandbox, please
report it privately ([SECURITY.md](SECURITY.md)).

---

## Features

### The sandbox

| Layer | What it does |
|---|---|
| Bubblewrap | Private home per app, read-only system, no capabilities, private `/dev/shm`. There is no unsandboxed mode: if Bubblewrap cannot run, SAM says why and starts nothing. |
| Landlock | Writes are allowed only where the profile allows them, even if a mount were wrong. Also blocks abstract sockets outside the sandbox (kernel 6.12+; on older kernels Diagnostics warns). |
| Syscall filter | A baseline filter, on by default. Without nested sandboxes it blocks what Flatpak's default filter blocks except `ptrace`, some `personality` values and `modify_ldt` (crash reporters and Wine use them), and more (`io_uring`, BPF, `userfaultfd`, `kexec`, rare socket types); nested sandboxes (for apps with a sandbox of their own) open the namespace and mount calls. Plus an optional strict filter. |
| D-Bus filter | The session bus goes through `xdg-dbus-proxy`; the app sees only the names it is allowed to. The system bus cannot be filtered, so it is either hidden or fully open (dangerous, off by default). |
| Portal filter | Opening links, file dialogs, notifications and printing work. Screenshots, autostart, menu-entry installation, location and remote desktop are blocked. |

### Permissions

Every permission has a plain-language explanation and a risk level (*low*,
*medium*, *high*, *dangerous*), named *Harmless*, *Some access*, *Think twice*
and *Dangerous*; tags show them in three colours: grey for harmless and some
access, amber for think twice, red for dangerous. Risky choices show a
warning before they apply.

- **Files:** private home, XDG folders (read-only or read/write), your own
  paths. Files you open with an app are granted one by one.
- **Network:** none, *This computer only* (no internet, but the app's own web
  page and the local services you list, such as Ollama), or full.
- **Display and devices:** Wayland, X11, GPU, sound (without access to
  cameras), webcam, game controllers
  (joysticks only, never keyboards or mice, not even a controller that
  also reports itself as one), USB, all input devices.
- **Desktop integration:** passwords and keyring, media controls, screen
  sharing, "show in folder", input methods (Fcitx5, IBus).
- **Advanced:** sockets (a key agent, such as the SSH agent or GnuPG's,
  is rated dangerous: the app could sign, decrypt or log in as you),
  environment variables, a writable app folder for
  portable apps, syscall filters, nested namespaces.

### Making apps work

- **First-run check:** after *Create Sandbox*, SAM points out what often goes
  wrong, such as logins that need a browser or files that stay inside the
  sandbox.
- **Log analysis:** common error messages turn into one-click fixes.
- **Repair steps:** switches that appear after a failed start, one step at a
  time; each says what protection it costs. A step the next start shows did
  not help is undone by itself, and *Switch off all repair steps* undoes
  the rest.
- **Compatibility mode:** broader access for stubborn apps, including the
  whole session bus, which is a way out of the sandbox: only for apps you
  trust. Turning it off restores your previous settings.
- **Built in:** links open in your normal browser; DNS works with the usual
  setups (a plain `resolv.conf`, systemd-resolved, NetworkManager); AppImages
  started from inside a sandbox work without FUSE; AppImages for another
  processor are refused with a message that says which version to download.

### Safe intake

- Type 2 AppImages (gzip, xz, zstd and lz4), unpacked by SAM's own SquashFS
  reader inside a minimal sandbox; the rare lzo ones by `unsquashfs`, in the
  same sandbox. DwarFS-based AppImages are unpacked with `dwarfsextract`
  when it is installed. The old, rare Type 1 format is unpacked with
  `bsdtar`; its test uses a type 1 AppImage SAM's test makes, not one
  published by an app.
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
sam-jail hints krita            # first-run check, with fixes (a risky one needs --yes)
sam-jail repair krita           # what went wrong last time
sam-jail repair krita --next    # apply the next repair step
sam-jail repair krita --undo    # undo all repair steps
sam-jail compat krita on --yes  # compatibility mode, a way out (off restores your settings)
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

`XDG_CONFIG_HOME` and `XDG_DATA_HOME` move these folders in every build. For
testing, `SAM_CONFIG_DIR`, `SAM_DATA_DIR`, `SAM_APPLICATIONS_DIR` and
`SAM_RUNTIME_DIR` move them elsewhere too, but only in developer builds; an
installed SAM ignores them. It still hides the folders that `SAM_CONFIG_DIR`
and `SAM_DATA_DIR` name from every app while they are set, and no app can
rename the folders above them, so a folder it once kept there stays out of
the apps' reach (unless it is your home folder or a folder above it, or a
link to a folder of which the app is shown only some folders inside).

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
| [Real AppImages](docs/reports/real-apps-2026-11-20.md) | everyone: how each of the test AppImages did in its sandbox |
| [AUTOMATION.md](AUTOMATION.md) | what automation may do in this repository, its checks and the kill switch |
| [Contracts](docs/contracts.md) | every assumption SAM makes about the outside world, what happens when one breaks, and how each is checked |
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

## License

GPL-3.0-or-later. SAM's programs contain libraries by other people under their
own licenses (mostly MIT and Apache-2.0); [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)
lists them with their license texts and is installed with every package.

The app icon (`data/io.github.gitzekatze.SAM.svg`) is based on the seal from
[Fluent Emoji](https://github.com/microsoft/fluentui-emoji) (flat style) by
Microsoft, found through [Iconify](https://icon-sets.iconify.design/), licensed
under MIT; its notice is in [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
