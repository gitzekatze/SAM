# SAM — session handover

Session date: 2026-11-07. This file sums up the first build session so work
can continue on another machine or platform. It is written for whoever picks
up next, human or agent.

- **Source plan:** `../SAM-Plan.md`, also copied to `docs/whitepaper.md`.
- **Project root:** `Claude/sam/`, the folder this file is in.

## 1. Status at a glance

| Area | State |
|---|---|
| Rust core and CLI (`sam-jail`, `sam-jail-run`) | Done. 64 tests pass. Clippy is clean apart from 2 cosmetic `sort_by_key` hints. |
| Bubblewrap backend | Done. The end-to-end security test passes (see §5). |
| Bubblejail and Firejail adapters | Written and unit-tested; **never run against real tools** |
| Extraction (Type 2: zstd, gzip, xz) | Done and tested |
| Extraction (Type 1, via `bsdtar`) | Written; **untested** (no Type 1 fixture) |
| Static dependency detection, recommendations, presets | Done and tested |
| Landlock (in-sandbox helper) | Done; verified manually |
| Strict seccomp | Done. An app launches with it on; the blocking itself was not exercised. |
| Filtered D-Bus via `xdg-dbus-proxy` | Written; **unverified** (see §6) |
| strace diagnostic fallback (`sam-jail diagnose`) | Written and unit-tested; **never run** (no strace was installed) |
| Qt6/QML/Kirigami GUI | Done. Every page checked through offscreen screenshots. |
| Packaging (PKGBUILD, Makefile, desktop file, metainfo, icon) | Done. `make all` and a staged install work. **`makepkg` was not run.** |
| Docs | `README.md`, plus `security.md`, `profiles.md`, `packaging.md`, `architecture.md` and `testing.md` in `docs/` |

## 2. Environment used in this session (important context)

- The session ran inside an **outer bubblejail sandbox** on the user's
  CachyOS machine:
  - seccomp blocks `sethostname`
  - the session D-Bus is already filtered, with only 2 names visible
  - there is no PipeWire socket
  - pacman's database is not readable
  - strace and Firejail are not installed
- The user is aware of this; system-level tests may have to be run by them
  or on a platform with more access.
- The Rust toolchain is installed **project-locally**:
  `Claude/.toolchain/` (rustup + cargo, stable 1.99). Load it with
  `source Claude/.toolchain/env.sh`. Nothing was installed system-wide or in
  `~/.cargo`.
- The host has Qt 6.12, KF6 (Kirigami, Kirigami Addons, KColorScheme,
  KConfig), bubblewrap 0.13.1, bubblejail 0.10.4, xdg-dbus-proxy and bsdtar.
  `unsquashfs` is not installed.
- Tests always used **isolated directories**, to stay out of the real home:
  `SAM_CONFIG_DIR`, `SAM_DATA_DIR` and `SAM_APPLICATIONS_DIR`,
  pointed into a scratch directory.
- One early run did write `~/.local/share/sam/` because of a bug. The bug
  is fixed (§7) and the directory was deleted.

## 3. Architecture (decisions made)

- **Rust workspace**, crate layout per plan §3.2:
  - `sam-core`: model, permission model, risk, warnings, config, paths,
    host probing, `Backend` trait
  - `sam-storage`: registry (`apps/<id>.json`), TOML presets, logs
  - `sam-detect`: AppImage magic/type/payload offset; ELF analysis with
    goblin (`DT_NEEDED`, glibc version needs, arch, toolkit, Electron/Java)
  - `sam-intake`: extraction, normalization, metadata/icons, launchers,
    fingerprints/staleness, ids, `testkit` (synthetic AppImage builder)
  - `sam-profile`: categories, recommendations, 6 built-in presets,
    preset compatibility check
  - `sam-backend-{bubblewrap,bubblejail,firejail}`
  - `sam-runner`: the `SAM` ops facade, backend selection, launch
    with logging and crash capture, xdg-dbus-proxy, Landlock and seccomp,
    doctor and bug report, strace diagnosis
  - `sam-jail-cli`: the `sam-jail` and `sam-jail-run` binaries
- **GUI:** a thin C++ Qt shell plus QML with Kirigami and Kirigami Addons
  FormCard. It talks to the core **only through `sam-jail --json …`**
  (asynchronous QProcess; payloads go in as JSON on stdin). This is the
  plan's "thin C++ shell" fallback, chosen deliberately to avoid Rust↔Qt
  bindings. Apps are launched detached through `sam-jail-run --app-id`.
- **Extraction is static by default.** backhand, a pure-Rust SquashFS
  reader, handles Type 2. `unsquashfs` is used if present. Type 1 uses
  `bsdtar`. The AppImage's own `--appimage-extract` runs only with explicit
  consent, inside bwrap with no network.
- **Sandbox layout (bwrap):**
  - **Payload:** the AppDir is mounted read-only at `/opt/app`.
  - **Host runtime:** in minimal mode, `/usr/lib`, `/usr/bin` and a
    whitelist of `/usr/share` and `/etc` entries; all of `/usr` in
    compatibility mode.
  - **Home:** a private per-app `$HOME` (`~/.local/share/sam/homes/<id>`)
    plus only the granted folders.
  - **Synthetic files:** a generated `passwd`/`group` containing only the user.
  - **Private mounts:** tmpfs for `/tmp`, `/var/tmp` and `$XDG_RUNTIME_DIR`.
  - **Root:** `--remount-ro /` after setup.
  - **Process:** `--cap-drop ALL`, `--new-session`, `--clearenv`.
- **Landlock** runs inside the sandbox: bwrap execs
  `/run/sam/sam-jail-run --sandbox-exec spec.json -- AppRun`. A Landlock
  domain can't create mounts, so it has to be applied after bwrap's setup.
- **Files passed as arguments** (e.g. "Open with") are bind-mounted one by
  one, like a document portal.
- **glibc and libstdc++/libgcc_s are classified "System"** (expected from the
  host by the AppImage convention), not "Dangerous". This deviates from plan
  §2.16.2 so that not every AppImage gets flagged. GTK, Qt, ssl/crypto,
  systemd and polkit are "Dangerous".

## 4. How to build and run

```sh
source Claude/.toolchain/env.sh          # or use system cargo
cd Claude/sam
make            # release build of CLI and GUI (gui/build-release)
make test       # cargo test --workspace
make install DESTDIR=/tmp/stage PREFIX=/usr
cd packaging/arch && makepkg -si         # NOT yet tried

# development
cargo build && cmake -S gui -B gui/build && cmake --build gui/build
gui/build/sam-jail-gui      # finds target/debug/sam-jail by itself

# headless GUI check (used for all UI verification in this session)
QT_QPA_PLATFORM=offscreen gui/build/sam-jail-gui --screenshot out.png \
    --page dashboard|app|presets|settings|diagnostics|onboarding [--app <id>] [--size WxH]
QT_FORCE_STDERR_LOGGING=1   # needed to see QML warnings and console.log output

# synthetic AppImages for manual tests
target/debug/sam-jail dev make-fixture /tmp/Hello.AppImage --name Hello \
    --categories "Graphics;" [--apprun script.sh]
```

## 5. What was verified

The end-to-end test, `crates/sam-runner/tests/sandbox.rs`, uses a fake
`$HOME` and a probe AppImage. Across its profiles it checks the following.

**Strict profile:**
- `~/.ssh` and Documents are hidden.
- The payload, `/usr` and `/` can't be written.
- Network is loopback only, the PID namespace is isolated, and `passwd` has 2 lines.
- setuid is stripped, and an escaping symlink was removed at extraction.
- The system bus is absent, there is no GPU and no X11.
- The private home persists, and the real home is untouched.

**Other profiles:**
- Documents read-only is visible but not writable; read/write is writable.
- Full home read-only still masks `~/.ssh` and denies writes.
- A file passed as an argument is granted.

**Lifecycle:** stale detection, then re-extract (the user-modified profile is
kept), then missing detection, then remove cleans up everything.

**Manual checks:**
- Landlock blocked a write to an rw mount the profile never granted.
- An app launched with strict seccomp enabled.

**GUI:** every page and all 4 themes (Breeze Light, Breeze Dark, Breeze High
Contrast, CachyOS Neon) were checked through screenshots.

## 6. Open issues and unverified items (next steps)

1. **Run `docs/testing.md`** on a normal desktop session. It is the full
   manual checklist: real AppImages, GPU, PipeWire, Electron, KDE menu
   launchers, notifications, Type 1, Bubblejail, Firejail, strace diagnose,
   and `makepkg`.
2. **Filtered D-Bus is unverified.** `xdg-dbus-proxy` failed even standalone
   here: the outer bubblejail proxy rejects its `AddMatch`/`GetNameOwner`
   calls, and clients got `Transport endpoint is not connected`. Verify with
   `busctl --user list` inside a sandboxed app on a normal session.
3. **PKGBUILD:** dependency names are assumed from Arch repos (`kirigami`,
   `kirigami-addons`, `kcolorscheme`, `kconfig`, `qqc2-desktop-style`,
   `extra-cmake-modules`). Check them with `makepkg` or `namcap`. `source=()`
   builds the local tree; switch it to a tarball for the AUR.
4. **Bubblejail adapter:** it writes
   `~/.local/share/bubblejail/instances/sam-<id>/services.toml` and runs
   `bubblejail run sam-<id> -- <AppDir>/AppRun`. Env vars go through
   `[debug] raw_bwrap_args`. Confirm against real bubblejail 0.10.x
   behaviour, especially that it accepts a command after `--`.
5. **Firejail adapter** is untested. Check the flags (`--noinput`,
   `--x11=none`, `--dbus-user=filter`) against the installed version.
6. **The "Overall risk" card** shows some empty space when there are no
   warnings (cosmetic).
7. **Not implemented:** eBPF network filtering, and the localhost/filtered
   network modes (both experimental per plan; they fall back to "none" with
   a warning). Bluetooth needs the system bus and is not wired up. There is
   no LD_LIBRARY_PATH handling; AppRun is trusted to set it.
8. **Plan items only partly covered:**
   - Strace diagnosis can't parse paths that strace writes in escaped form.
   - Dynamic tracing never runs with full home (by design).
   - Translations (i18n) are not set up; strings use `qsTr`.
9. **No git repo** exists yet. Consider `git init` before the next changes.

## 7. Bugs found and fixed during the session (for context)

- **`--hostname`:** bwrap failed where `sethostname` is seccomp-blocked.
  The hostname is no longer set; the UTS namespace is still unshared.
- **Unmountable binds:** optional `-try` binds of files with link count 0
  (unlinked but still open) made bwrap fail. Such sources are now skipped.
- **`/usr` writes:** in minimal mode `/usr` sat on the writable root tmpfs.
  Fixed with `--remount-ro /`, after making `$XDG_RUNTIME_DIR` its own tmpfs.
- **Extraction location:** the default `extraction.location` was a literal
  `~/.local/share/sam/extracted`, which ignored `SAM_DATA_DIR`. The
  default is now empty, meaning `<data dir>/extracted`.
- **QML window bindings:** `applicationWindow()` used in property bindings is
  evaluated before the page is attached and never updates. Pages now use
  `QQC2.ApplicationWindow.window`. SettingsPage loads its own config.
- **QML inline components** can't see the outer `id`. The SettingsPage
  `ConfigSwitch`/`ConfigChoice`/`ConfigNumber` now get `cfg` and `owner`
  passed in explicitly.
- **FormComboBoxDelegate** resets `currentIndex` when its model is set, so
  index bindings are installed in `Component.onCompleted`.
- **FormCard re-parents its children,** so `parent.x` doesn't reach the
  card. Use an `id` instead.
- **Makefile:** `$(wildcard)` broke on the spaces in the project path
  ("Agent Workspace Bubblejail"). It now uses a shell test.

## 8. Key files

- `crates/sam-backend-bubblewrap/src/lib.rs`: the sandbox layout
  (security-critical)
- `crates/sam-runner/src/launch.rs`: launch pipeline, logs, failure
  classification
- `crates/sam-runner/src/ops.rs`: add, re-extract, refresh, presets,
  scan
- `crates/sam-intake/src/extract.rs` and `normalize.rs`: extraction
  safety
- `crates/sam-core/src/permissions.rs`, `risk.rs` and `warnings.rs`:
  the policy
- `gui/src/backend.cpp`: the CLI bridge
- `gui/qml/PermissionsEditor.qml`: the Flatseal-style editor
- `docs/testing.md`: the manual test checklist

## 9. Session 2 (2026-11-07): tested on the real desktop, outside the sandbox

**Verified on the host** (KDE Wayland, NVIDIA, PipeWire). Isolated
`SAM_*` directories were used throughout.
- `sam-jail doctor` is all ok.
- Filtered D-Bus works: only portals, Notifications and the tray are visible,
  and notifications arrive. Session bus `none` leaves the address unset.
- Audio, GPU and network each work when granted.
- Landlock and strict seccomp are applied (`sam-jail logs`).
- Bubblejail backend: runs, and `sam-jail remove` deletes its instance.
- Firejail gating works.
- 8 real AppImages from `~/Downloads` extract. ZFontManager (GTK3) and Tuta
  (Electron) run.
- `makepkg` builds both packages, and every PKGBUILD dependency name resolves.
  Not installed (needs sudo).

**Fixed:**
- xkb data (`/usr/share/xkeyboard-config-2`) was missing in minimal mode.
  GTK and Electron aborted with "Failed to create XKB keymap".
- Backend `build()` no longer creates the private home. `launch.rs` does it.
  The tests failed on the hardcoded `/data`, and that broke `makepkg check()`.
- Tray: the filtered bus now lets the app own `org.{kde,freedesktop}.StatusNotifierItem-<2..12>-<1..2>`.
- Category mapping: bare `Network` maps to Communication, and
  `AudioVideo` + graphics maps to Image editor.
- ELF detection:
  - `$ORIGIN/...` DT_NEEDED paths are resolved.
  - A missing library needed only by bundled libraries is rated Risk, not
    LikelyBroken.
- `sam-jail logs` now picks the newest log when there are several in one
  second (the `-N` suffix).
- The Firejail error says "not installed" when it is enabled but not
  installed.
- Changing the profile or backend clears a "Broken" verdict from a failed
  launch. The GUI Run button is disabled only for Missing apps.
- `docs/security.md` documents `advanced.host_runtime full`.

**Still open:**
- strace diagnose (strace is not installed).
- Firejail runs (Firejail is not installed).
- Type 1 AppImages.
- KDE menu launchers.
- Package install.
- The filtered bus also exposes `org.freedesktop.portal.Flatpak` (through
  the `portal.*` wildcard). Consider listing portals explicitly.

## 10. Session 3 (2026-11-07): renamed to SAM, Flatseal-style overview

- **Renamed** Appseal to SAM (Sandboxed AppImage Manager).
  - App ID `io.github.gitzekatze.SAM`.
  - Commands `sam-jail`, `sam-jail-run` and `sam-jail-gui`; crates `sam-*`.
  - Data in `~/.config/sam` and `~/.local/share/sam`; env vars `SAM_*`.
  - Repo: github.com/gitzekatze/SAM (private).
- **Overview** (`sam-jail discover`, the GUI's Applications page):
  - Lists AppImages from the scan folders (Downloads is opt-in via
    `general.scan_downloads`) and from foreign menu entries.
  - Name, comment, category and icon are read straight from the SquashFS
    image (`sam-intake/src/peek.rs`). Results are cached in `<data>/previews`.
- **Create sandbox** = `sam-jail sandbox <file>` (alias of `add`). Only this
  creates a SAM menu entry.
  - `--hide-duplicates` hides AppImageLauncher/Gear Lever entries
    (`sam-intake/src/menu.rs`): user-level entries are edited in place
    (`NoDisplay=true` + `X-SAM-HiddenBy`), system-level ones get a user
    override.
  - `remove` restores them exactly. `sam-jail menu list|hide|restore <app>`
    does the same by hand.
- The GUI's ScanDialog was removed; the overview replaces it.

## 11. Session 4 (2026-11-07): Firejail tested for real, D-Bus tightened

- **Firejail backend** (firejail 0.9.82 now installed):
  - It now runs the original file with `firejail --appimage`. The extracted
    copy under `~/.local/share/sam` (or /tmp) is hidden by `--private` /
    `--private-tmp`, so the old command could never start an app.
  - Electron: the default `--seccomp` filter blocks `chroot`, which kills
    Chromium's zygote. When `advanced.allow_userns` is on, SAM uses
    `--seccomp=!chroot` (only that syscall is exempted).
  - Tray names are also granted via `--dbus-user.own`.
  - Verified with `firejail --join` on ZFontManager and Tuta: private home,
    `~/.ssh` hidden, network per profile, filtered bus, tray icon works.
  - Known limit: the synthetic testkit fixture's AppRun is reported "not
    executable" under firejail's AppImage mount. Real AppImages are fine.
  - Firejail starts programs through the login shell from /etc/passwd
    (here fish), not `$SHELL`.
- **D-Bus:** the default filtered list now names portals explicitly
  (Desktop, Documents, IBus, Fcitx) instead of `org.freedesktop.portal.*`,
  so `portal.Flatpak` and `portal.Tracker` are no longer reachable.

## 12. Session 5 (2026-11-07): compatibility work (plan phases 1–4)

- **Backends, per app:** `SandboxProfile.auto_backend` (kind + reason).
  The order on Automatic:
  1. Bubblewrap-only features (localhost, writable app folder).
  2. The backend learned for this app.
  3. Bubblejail when D-Bus filtering is needed and xdg-dbus-proxy is missing.
  4. The default backend.
  5. Bubblewrap → Bubblejail → Firejail (Firejail only if allowed).
  `launch::run_auto` retries the next backend after a sandbox *setup*
  failure (bwrap errors; bubblejail tracebacks; firejail `Error:`) and
  remembers the one that works. Setting a backend back to Automatic clears
  the learned choice.
- **Phase 1:**
  - Landlock allows writing to opened files and rw binds.
  - `/run/sam/bin/xdg-open` (and kde-open, …) call the portal's OpenURI.
  - `APPIMAGE_EXTRACT_AND_RUN=1`.
  - `ro_follow` also binds the targets of symlinks in whitelisted
    `/usr/share` and `/etc` entries (covers resolv.conf too).
- **Phase 2:**
  - `needs_network_by_purpose` (AI/web-UI/server/client/sync names) turns
    the network on.
  - `integrations.{keyring,media_controls,file_manager}`.
  - First-run hints (`sam-jail hints`, GUI dialog after Create sandbox).
  - "Files this app saved" opens the private home.
- **Phase 3:**
  - `repair.rs`: `analyze()` maps about 15 error patterns to fixes, stored
    as `LaunchRecord.findings`.
  - `ladder()` (`sam-jail repair --next/--apply/--undo`; GUI "Make it work").
  - `advanced.writable_appdir` (bwrap `--overlay`, upper dir in
    `<data>/overlays/<id>`).
  - Crash-at-start notification with the likely cause.
  - Overview chip "Didn't work last time".
- **Phase 4:**
  - `network.mode = localhost`: pasta `--splice-only -t auto -T auto,~53`
    wraps bwrap. Attaching pasta to bwrap's netns fails with EPERM.
    Strict seccomp is skipped in this mode, because pasta doesn't pass
    the fd on.
  - `sam-jail selftest`.
- **Verified on real apps:**
  - ArtCraft (wgpu) failed. The analyzer said "Graphics acceleration is
    off", and `repair --next` fixed it.
  - Localhost forwarding works both ways, with no internet and no DNS.
  - The overlay, saving opened files and the backend fallback chain all
    work.

## 13. Session 6 (2026-11-07): risk review fixes (priorities 1 + 2)

- **S1 portal filter:** `org.freedesktop.portal.Desktop` is translated to
  xdg-dbus-proxy `--call` rules for selected interfaces
  (`permissions::portal_interfaces`; Firejail `--dbus-user.call`).
  - Verified: Screenshot, Background, DynamicLauncher, Trash and Location
    are blocked; Settings, Properties and NetworkMonitor are allowed.
  - `portal.Documents` was removed from the defaults (it comes back only
    with a portal identity).
- **S2 localhost:** `network.host_ports` is the only ns→host forwarding
  (`-T` list, otherwise `none`); the app's own ports are still `-t auto`.
  Verified: a listed port is reachable, an unlisted one is blocked.
- **S3 seccomp:** baseline filter on by default (`security.baseline_seccomp`,
  per-app `advanced.seccomp_baseline`). Strict filter = baseline + more.
  Both are loaded by `sam-jail-run --sandbox-exec` (no more bwrap fd), so
  they also work under pasta.
- **S4:** private `/dev/shm` (tmpfs).
- **S5:** Landlock `Scope::AbstractUnixSocket`. Verified: XWayland's
  abstract socket gets EPERM even with full network.
- **Electron:** `FixAction::AddArg` and repair step `chromium-no-sandbox`.
  It's suggested by the analyzer after Chromium sandbox failures, and as a
  first-run hint when `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`
  is 1.
- **`/etc/alternatives`** is in the minimal `/etc` set.
- **Backend parity:** `select::limitations()`. The GUI shows a warning
  listing what the chosen backend does not enforce.
  `tests/parity.rs` checks network, X11, GPU, sound, home and portal
  across all three backends.
- **Portal identity** (`portal_identity.rs`, `security.portal_identity`):
  - `/.flatpak-info` + `/run/user/<uid>/.flatpak/<instance>/{info,
    bwrapinfo.json}` (bwrap `--info-fd`).
  - The proxy runs inside a minimal bwrap with the same info file (the
    portal identifies the D-Bus peer).
  - The doc view `/run/user/<uid>/doc/by-app/<id>` is bound at
    `/run/user/<uid>/doc`.
  - Verified: Documents.Add from the app, and the file is visible in the
    sandbox. Instance dirs are cleaned up.
  - Not used with localhost mode (pasta drops `--info-fd`).
  - Documents.Add of files whose sandbox path differs from the host path
    (private home) is rejected by the portal; portal file dialogs are not
    affected.
- Regression: ZFontManager and Tuta pass `selftest` with all of the above.

## 14. Session 7 (2026-11-07): audit and fixes

- Audit: `docs/review-2026-11-07.md` (3 high, 7 medium, 7 low findings).
  All fixed the same day; see its "Resolution" table.
- **Key mechanisms:**
  - bwrap `--json-status-fd` for verified setup failures.
  - A helper status fd (`SAM_STATUS_FD`, closed before exec) reports what
    was enforced.
  - `dangerous_bus_name`; `Suggestion.from_app_output`.
  - `display_safe` for untrusted text, `Util.plain`/`esc` in QML.
  - Launcher MIME filter; `OpenFile` with fd in the shim.
  - App-port exclusions for pasta.
  - Collision-safe Flatpak instance dirs.
  - Sandboxed extraction (`dev extract-squashfs`).
  - Per-launch runtime dirs; `filesystem.opened_files`.
- `tests/adversarial.rs` covers: the fake bwrap error, malicious repair
  output, markup in metadata, the MIME filter, and garbage input to the
  parsers.
- 93 tests, clippy clean. ZFontManager, Tuta and ArtCraft pass `selftest`.
