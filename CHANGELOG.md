# Changelog

All notable changes to SAM. Versions follow [Semantic Versioning](https://semver.org/):
before 1.0, a minor version (0.x) may change the command line or the JSON
output; patch versions (0.x.y) only fix bugs.

`scripts/release.sh` takes the *Unreleased* section as the notes of the next
version.

## Unreleased

### Security

- Apps started from a terminal never get the user's terminal: SAM puts them
  on a pseudo-terminal of its own and passes the bytes on. As before, they
  cannot type commands into the shell (`TIOCSTI`); now escape codes for the
  clipboard, desktop notifications, tmux passthrough and window-title
  reports are removed from their output too, and terminal replies still
  queued when they end are discarded. (Before, Bubblewrap's new session
  stopped typed-in commands, but passed every escape code on and cut
  terminal programs off from resizing.) The app page and each start say
  what a terminal program can and cannot reach.
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
  in Preferences.
- *Update Now* (`sam-jail update APP`) downloads the newest version, checks
  it against the published checksum and the signing key, and puts it in
  place; settings stay. The replaced version is kept, and *Go back to the
  previous version* (`--undo`) restores it.
- Updates download only the changed parts when the AppImage publishes a
  zsync description (e.g. 5.5 of 11.5 MB for Neovim 0.12.5 → 0.12.6), and
  fall back to the whole file otherwise.
- SAM's own AppImage updates itself: *Check for SAM Updates* in the main
  menu, or `sam-jail self-update [--check]`. Release builds carry SAM's
  update information and a `.zsync` file.
- `SECURITY.md` (private vulnerability reports), `CONTRIBUTING.md` and issue
  forms.
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

- While Downloads is not searched, its switch says how many AppImages are
  there (browsers save new AppImages to Downloads).
- Asking to let an AppImage unpack itself is worded plainly, and for DwarFS
  AppImages names the dwarfs package that avoids the question; the command
  line says which command to use.
- When an app stops right after starting, the notification has a *Show the
  fix* button that opens SAM at that app; its page shows *What went wrong
  last time* first, with the fix one click away.
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

- Compatibility, from a test of 71 real AppImages (59 started before these
  fixes, 69 after; the other 2 are terminal tools):
  - Apps with an older bundled libxcb (many Qt and Java apps) could not
    connect to X11 even with X11 allowed: Landlock refused the abstract
    socket and old libxcb gives up instead of using the socket file. The
    sandbox now uses its own display number (:99) with a matching cookie.
  - Apps whose AppImage bundles only Qt's X11 plugin, and apps whose start
    script forces X11 (linuxdeploy's GTK hook, Tauri apps), get X11 in
    their recommendation.
  - X11 apps share the IPC namespace (as Flatpak's `--share=ipc`); GTK and
    Electron apps died with BadAccess from MIT-SHM.
  - With both Wayland and X11 allowed, Qt picks the platform itself; the
    list `wayland;xcb` stopped Qt before 5.12.
  - GTK's image loaders (glycin, gdk-pixbuf 2.44+) are visible; apps using
    the system's GTK aborted at the first icon.
  - Apps may own the D-Bus name of their own reverse-DNS ID (as with
    Flatpak); a refused name in the log is offered as a repair step.
  - Programs that load OpenGL or Vulkan only at run time (WezTerm, Rust
    apps) get the GPU; their EGL setup failed and no window appeared.
  - Qt apps that switch Qt to X11 in their own code (MuseScore and
    Audacity 4, which name their own `MU_`/`AU_QT_QPA_PLATFORM`) and Qt
    apps whose Wayland plugin lacks its bundled Qt Wayland library
    (OpenShot) get X11 from the start instead of after a repair step.
  - Terminal programs (Helix, Neovim, command-line tools) work in the
    terminal: they get a terminal of SAM's own, see the files and folders
    named when they start (`hx notes.txt`, `hx .`, relative to the folder
    they start in) and adapt to window resizing. A test start gives them a
    terminal too, and a tool that ends with an error code of its own (wrong
    arguments) no longer counts as a failed start, so repair steps no
    longer weaken their sandbox for nothing. From the menu, the window stays
    open after an error until Enter is pressed.
  - Second test set of 26 AppImages from groups the first lacked
    (Flutter, Tauri, Wails, sharun/anylinux, Wine, .NET/Avalonia, Java
    launcher, GTK4, Python): 20 started at once. Group-wide fixes:
    - Apps may own the D-Bus name of their window class (GTK and Flutter
      apps register their application ID there: Hiddify could not start)
      and KDE apps their org.kde.<app> name with its numbered variants
      (Kdenlive could not start). Names a service on this computer starts
      on demand are refused at every start.
    - The EGL driver configuration is shown without GPU access too, so
      apps that draw with OpenGL fall back to software instead of
      aborting (LocalSend); Flutter apps get the GPU recommended.
    - A library missing for what the main program loads at start, also
      through its bundled libraries (a Flutter plugin), counts as a start
      problem (AppFlowy was rated fine).
    - Without sound access, SDL gets its silent driver, so games and
      emulators start instead of quitting.
    - sharun's .env file counts when checking whether an app forces X11.
  - "May not start" only for real reasons. It showed for 44 of the 71
    test AppImages, of which 69 start: for using the system's GTK or
    OpenSSL (now an information note), for libraries only bundled
    libraries or Node add-ons need (now a notice naming the feature), and
    for add-ons built for another CPU (now ignored). A missing library
    counts as a start problem only when the app's main program needs it;
    for another program inside the app the label says so. On the test set,
    70 of 71 are now rated fine before their first start.
  - Bundled parts built for a CUDA or ROCm version this computer lacks
    get a short note naming the part (e.g. "foundry-local-sdk, bundled in
    this app, is built for CUDA 12. This computer has CUDA 13, which it
    cannot load ..."), saying that other ways the app uses the graphics
    card are not affected. Missing tray-menu or OpenCL libraries get their
    own short notes.
  - The sandbox shows the library folders the system's loader uses
    outside /usr (CUDA in /opt/cuda/lib64, /usr/local/lib), read-only:
    the analysis already counted libraries there as present.
  - Creating a sandbox shows its progress: step, a progress bar and what
    happens ("1.2 GB unpacked", "40 of 115 program files read"), and the
    settings are locked meanwhile (`sam-jail add --progress` for scripts).
    It is also much faster for large AppImages: AnythingLLM took over two
    minutes (in development builds), now 13 s.
  - First starts are faster: the sandbox includes the system's font cache
    (`/var/cache/fontconfig`, read-only), so an app no longer builds its
    own for every installed font (WezTerm's window took 35 s to appear,
    now under 5 s).
  - Apps whose start script launches the real program in the background
    and exits (Pulsar) stay alive: SAM's helper waits for the app's last
    process, not its first.
  - The AppImage's own extractor (after consent) works from files without
    the executable bit and with uruntime's AppDir layout (DwarFS
    "anylinux" AppImages).
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
- Unpacking tools installed outside `/usr` (e.g. `~/.local/bin`) now work
  inside the unpacking sandbox.
- Icons that some themes lack (a tick, a tool) replaced by ones every
  theme has.
- Keyboard: Tab no longer gets stuck at the "⋮" button of an app page (a
  label under the app's name could take the focus); greyed-out settings are
  skipped by Tab; the Downloads switch
  and the search field have names for screen readers.

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
