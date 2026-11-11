# Changelog

All notable changes to SAM. Versions follow [Semantic Versioning](https://semver.org/):
before 1.0, a minor version (0.x) may change the command line or the JSON
output; patch versions (0.x.y) only fix bugs.

`scripts/release.sh` takes the *Unreleased* section as the notes of the next
version.

## Unreleased

### Security

- Nested namespaces are off by default; only apps whose engine builds its own
  sandbox (Electron, CEF, Qt WebEngine, WebKitGTK) get them.
- Full home read/write: more persistence paths stay read-only (`~/.local/bin`,
  D-Bus service files, `mimeapps.list`, KWin/Plasma scripts, service menus,
  git and editor configs), also when they do not exist yet.
- A granted folder that contains the home gets the same protection as full
  home access.
- SAM's own folders are hidden whenever a grant would show them.
- *Local network only* runs the app with the user's ids (it ran as root, so
  Electron apps did not start and the D-Bus proxy rejected every app).
- `systemd-run` inside the sandbox runs the command inside it;
  `flatpak-spawn` refuses.
- Blocked D-Bus names win over wildcard allow entries.
- The syscall filter also covers the x32 ABI, and blocks `io_uring`.
- Wayland security context: each app gets its own Wayland socket, and the
  desktop hides privileged functions (background clipboard access, screen
  capture, fake input) from it. *Privileged Wayland protocols* turns this
  off for tools that need them.
- *Audio* gives only the PulseAudio socket. The raw PipeWire socket, which
  also reaches cameras and other apps' screen-cast streams, is a separate
  advanced permission (*Direct PipeWire access*); the sandbox check confirms
  it is absent.
- `cargo deny` checks advisories, licences and sources in CI; Dependabot
  proposes updates; `scripts/release.sh` signs releases by default.
- New breakout test suite; security review report
  (`docs/security-review-2026-11-10.md`).

### Added

- `sam-jail uninstall` removes every trace of SAM (lists first; `--yes`).
- `sam-jail stop`, `sam-jail remove --stop`, and *Close and Remove* in the
  window for apps still running (also in the system tray).
- *Check the setup* and *Test start* per app; the sandbox check also works
  before a sandbox exists.
- The extraction folder can be chosen in Preferences.
- Terminal programs: no display or GPU, and *Launch* opens a terminal.
- `sam-jail preset check`; the window asks before a conflicting preset also
  when no sandbox exists yet.
- Single SAM window per data set.
- Man pages for `sam-jail`, `sam-jail-run` and `sam-jail-gui`.
- Translations (gettext): the window's own text can be translated; German
  is the first language (`docs/translating.md`).
- The list of AppImages updates by itself when files appear in or
  disappear from a location (a finished download, a deleted file).
- Screen readers announce every icon-only button by name; the blue label
  keeps enough contrast in light and dark style.
- 64-bit ARM (aarch64): an AppImage of SAM is built for it, and CI tests
  it once the repository is public; the breakout test uses each
  architecture's syscall numbers.
- Update check: SAM reads where an AppImage's updates are published (its
  update information: zsync or GitHub releases) and tells whether a newer
  version exists, with a link to download it. Only on request (*Check* on
  an app's page, `sam-jail updates`), or once a day at start when turned on
  in Preferences. Nothing is downloaded or replaced yet.
- Disk space per app (details, Diagnostics, `sam-jail space`) and *Free
  Space*: deletes the unpacked copy, which is unpacked again before the next
  start (`sam-jail free-space`).
- AppImage signatures are checked and shown; an update signed with another
  key, or no longer signed, gets a warning.
- AppImages with lz4-compressed SquashFS are unpacked by SAM's own reader.
- AppImages with a DwarFS image (uruntime) are recognised and unpacked with
  `dwarfsextract` when the dwarfs tools are installed.
- The JSON interface is documented (`docs/json-interface.md`).
- `sam-jail version` reports the JSON interface level; the window says so
  clearly when its command line tool is from another version.

### Changed

- SAM's files carry a format number: old ones are migrated (original kept),
  newer ones are never changed, damaged ones are moved aside and reported.
- Risk is shown with the permission that sets it (*High risk · Network +1*)
  instead of a score.
- *Compatibility mode* and *May not start* are separate labels; *May not
  start* clears after the first successful start.
- Log analysis reads stdout as well as stderr.
- `advanced.extra_backend_args` is now `advanced.extra_bwrap_args` (old
  profiles still load). Internally, the crate `sam-backend-bubblewrap` is
  now `sam-sandbox`.
- Detection skips bundled musl (Alpine) variants.
- The app is called *SAM - Sandboxed AppImage Manager* everywhere it
  introduces itself: window title, About, menu entry, metainfo, man pages,
  packages.
- The AppImage locations no longer scroll in a small box: the list grows
  with every location and the whole left column scrolls.
- README and security page rewritten.

### Fixed

- *Local network only* on systems whose `pasta` has no `--splice-only`
  (Ubuntu 24.04): every start failed with a misleading Bubblewrap error. Such
  a pasta is no longer used; the app starts with no network at all, and
  `doctor` says why.
- The writable app folder on Bubblewrap before 0.10 (Ubuntu 24.04, Debian 12):
  the app failed to start. The folder now stays read-only there, with a
  warning.
- The filter buttons above the AppImage list fit the narrowest window.
- On libadwaita 1.5 (Ubuntu 24.04) a narrow window now folds into one
  column instead of overflowing.
- The labels under an app's name are no longer cut off when they wrap onto
  a second line.

### Removed

- The never-enforced "filtered" network mode, `network.allowed_hosts`, the
  system-bus name lists and three unused config keys (old files still load).
- The placeholder for eBPF network filtering (Preferences, `doctor`), a
  feature that was never built.
- Outdated design and handover documents from before the GTK window.

## 0.1.0 - 2026-11-10

First release.

- Sandboxes AppImages with Bubblewrap, Landlock and a syscall filter; private
  home per app; filtered D-Bus and desktop portal; *Local network only*.
- Unpacks AppImages without running them; dependency analysis and
  recommended settings by category; presets.
- GTK 4 / libadwaita window in the style of Flatseal; `sam-jail` command line
  with JSON output.
- Sandbox check, repair steps, log analysis, diagnostics, user guide.
- Packages: Arch (AUR), Fedora (RPM spec), AppImage.
