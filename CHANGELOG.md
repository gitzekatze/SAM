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
- The syscall filter also covers the x32 ABI.
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

### Changed

- SAM's files carry a format number: old ones are migrated (original kept),
  newer ones are never changed, damaged ones are moved aside and reported.
- Risk is shown with the permission that sets it (*High risk · Network +1*)
  instead of a score.
- *Compatibility mode* and *May not start* are separate labels; *May not
  start* clears after the first successful start.
- Log analysis reads stdout as well as stderr.
- Detection skips bundled musl (Alpine) variants.

### Fixed

- *Local network only* on systems whose `pasta` has no `--splice-only`
  (Ubuntu 24.04): every start failed with a misleading Bubblewrap error. Such
  a pasta is no longer used; the app starts with no network at all, and
  `doctor` says why.
- The writable app folder on Bubblewrap before 0.10 (Ubuntu 24.04, Debian 12):
  the app failed to start. The folder now stays read-only there, with a
  warning.

### Removed

- The never-enforced "filtered" network mode, `network.allowed_hosts`, the
  system-bus name lists and three unused config keys (old files still load).

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
