# Manual test checklist

These checks need a real desktop session: real AppImages, PipeWire, a GPU, an
unfiltered session bus, and packages that may not be installed. They
complement `cargo test --workspace` (unit tests plus the end-to-end sandbox
test).

To keep your real configuration untouched while testing, run:

```sh
export SAM_CONFIG_DIR=/tmp/sam-test/config \
       SAM_DATA_DIR=/tmp/sam-test/data \
       SAM_APPLICATIONS_DIR=/tmp/sam-test/applications
```

Leave `SAM_APPLICATIONS_DIR` unset if you want launchers to show up in your menu.

## 0. Automated permission matrix

`cargo test -p sam-runner --test matrix` starts a probe AppImage once per
permission and checks from inside the sandbox what it can see. Put
`target/debug` on `PATH` (after `cargo build -p sam-jail-cli`) so Landlock and
seccomp are applied too; `SAM_MATRIX_DEBUG=1` with `-- --nocapture` prints
every launch log.

`cargo test -p sam-runner --test verify` covers the sandbox check
(`sam-jail verify`): it passes for a correct sandbox, reports a folder leaked
through a raw Bubblewrap argument, and follows the settings (syscall filter
off is expected off). Same `PATH` requirement as above.

By hand: `sam-jail verify <app>` on a few real apps should report every check
as passed; `sam-jail config set security.check_before_launch true`, then a
raw `--ro-bind` of a hidden folder in `advanced.extra_bwrap_args`, must make
`sam-jail run` refuse to start with "sandbox check failed".

## 0a. Robustness and removal

`cargo test -p sam-jail-cli --test robustness` runs the real `sam-jail` on
old, newer, damaged and deliberately mangled files (truncated at many
lengths, single bytes changed): old ones are migrated with a backup, newer
ones are never changed, damaged ones are moved aside and reported, and
nothing panics. `cargo test -p sam-runner --test uninstall` checks that
`sam-jail uninstall` removes every trace, restores hidden menu entries,
keeps the AppImage and refuses folders that are not SAM's.

Scale (2026-11-10, release build): 200 AppImages among 3,200 files are
found in 0.8 s cold and 30 ms warm; with 40 sandboxes `list`, `doctor` and
`info` answer in under 40 ms, and the window shows all 240 entries.

## 0b. Real AppImages

`WORK=… tests/real-apps/run.sh App.AppImage …` runs the whole flow
(recommendation, Create Sandbox, sandbox check, test start, hints, repair
steps) on real AppImages in an invisible KWin session with a fake home;
`python3 tests/real-apps/analyze.py "$WORK"` summarises it. Results of the
first run: [real-apps-2026-11-10.md](real-apps-2026-11-10.md).

## 1. Environment

- [ ] `sam-jail doctor`: everything is `ok`. The sandbox test passes, and
      Wayland, PipeWire and D-Bus are detected.
- [ ] `sam-jail info <id>` prints `sandbox: Bubblewrap`.

## 2. Real AppImages

For each category (browser, media player, image editor, game, text editor,
Electron app, Qt app, GTK app):

- [ ] `sam-jail sandbox <file>` succeeds, and the category and recommendation make sense.
- [ ] `sam-jail run <id>` opens a window on Wayland.
- [ ] Rendering is GPU-accelerated when GPU is on (e.g. `chrome://gpu`,
      `glxinfo` inside a terminal app).
- [ ] Audio plays through PipeWire when sound is on, and is silent when off.
- [ ] Network works with `full` and fails with `none`.
- [ ] File dialogs only show granted folders. Opening a file from Dolphin
      ("Open with" via the launcher) works even when its folder isn't granted.
- [ ] Electron apps start (nested namespaces allowed).

## 3. D-Bus filtering

- [ ] With the session bus set to *filtered*, `busctl --user list` inside a
      sandboxed terminal app lists only the portals, notifications and tray.
- [ ] Notifications from the app appear.
- [ ] With the session bus set to *none*, `DBUS_SESSION_BUS_ADDRESS` is unset inside the sandbox.

## 4. Kernel features

- [ ] Logs show `landlock: true` (`sam-jail logs <id>`).
- [ ] With `sam-jail config set security.experimental_seccomp true` and
      `sam-jail set <id> advanced.seccomp_strict true`, a non-Electron app
      still starts.

## 5. Desktop integration

- [ ] A launcher appears in the KDE menu with the app's icon.
- [ ] Starting it from the menu runs the app sandboxed (`ps` shows `bwrap`).
- [ ] A failed launch from the menu shows a notification.
- [ ] Removing the app removes the launcher.

## 6. Updates and staleness

- [ ] Replace an AppImage with a newer version. `sam-jail refresh` reports it
      as stale and the GUI shows the *Stale* badge.
- [ ] Re-extract. A customized profile is kept, and new needs are listed under
      "Update needs new permissions".
- [ ] Move the AppImage. The overview shows it as a moved copy;
      *Reconnect* or *Locate…* fixes the path.

## 7. Diagnostics

- [ ] With user namespaces disabled, starting an app stops with a clear
      hint and nothing runs unsandboxed.
- [ ] **Diagnostic run** (needs `strace`): `sam-jail diagnose <id> --apply`
      lists findings, and low-risk fixes are applied.

## 8. Type 1 AppImages

- [ ] An old Type 1 AppImage (ISO 9660) is extracted via `bsdtar`.

## 9. GUI

- [ ] The overview lists AppImages from the scan folders under *Not sandboxed*,
      with names and icons, before anything is unpacked.
- [ ] Downloads is only listed after *Settings → Include the Downloads folder*.
- [ ] *Create sandbox* on an app with an AppImageLauncher/Gear Lever menu entry
      asks to hide it. *Hide it* removes it from the KDE menu; *Remove sandbox*
      brings it back unchanged.
- [ ] No SAM menu entry exists for apps that are not sandboxed.
- [ ] Adding a folder or a single file in "AppImage locations" lists its
      AppImages; removing it drops them from the list (sandboxed apps stay).
- [ ] Selecting an app without a sandbox shows the recommended settings;
      changes made there are used by *Create sandbox*.
- [ ] Drag an AppImage into the window: it is added to the list and selected.
- [ ] Every setting is visible at all times; settings that do not apply
      (e.g. ~/.ssh without full home) are greyed out, never hidden.
- [ ] Preferences → Style (Follow system, Light, Dark) applies instantly.
- [ ] Turning on full home, the system bus or raw devices asks for confirmation.
- [ ] Applying the "Untrusted Utility" preset to a browser warns that it removes network access.
- [ ] *Copy bug report* produces a report without your username or home path.

## 10. Compatibility helpers

- [ ] A link clicked in a sandboxed app opens in the normal browser.
- [ ] *Local network only*: the app reaches a host server on 127.0.0.1, the
      host browser reaches the app's own port, websites do not load.
- [ ] *Writable app folder*: a portable app keeps its settings; the extracted
      copy under `extracted/` is unchanged.
- [ ] An app that fails at start shows a notification with the likely cause,
      and *Details & Repair → Try the next fix and start* fixes it.
- [ ] `sam-jail selftest` lists every sandboxed app as ✓ or ✗.
- [ ] *Local network only*: the log shows `# enforced: landlock …`.
- [ ] After using SAM, nothing named `io.github.gitzekatze.SAM` exists under
      `/run/user/<uid>/.flatpak` or `~/.local/share/flatpak`.
- [ ] Removing or re-extracting an app while it runs is refused with
      "… is running. Close it first".
- [ ] Closing SAM leaves apps started with *Launch* running.
- [ ] *Launching*: adding and removing a launch argument shows in the
      sandbox command; compatibility mode on asks first, off restores the
      settings from before.
- [ ] *Menu Entries*: with an AppImageLauncher/Gear Lever entry, the hide
      switch hides and restores it; without one it is greyed out.
- [ ] *Environment variables*: `NAME=value` is set in the sandbox; an
      invalid name is refused with a message.
- [ ] *Logs*: the picker lists start, unpacking, detection and diagnostic
      logs; each one opens.
- [ ] A new app shows *Needs review*; *Mark as Reviewed* clears it.

## 11. Packaging

- [ ] `cd packaging/arch && makepkg -si` builds and installs both packages.
- [ ] SAM starts from the application menu.

## Keyboard

`sam-jail-gui --screenshot OUT.png --page app --focus-walk` (in the invisible
session of `tests/real-apps/run.sh`) moves the focus with Tab like a person,
1.5 s per step, and prints every stop with its name. On 2026-11-11 it found
two unnamed controls and a keyboard trap: Tab stopped for good at the app
page's "⋮" button, because one of the labels under the app's name could take
the focus (confirmed with a real keyboard; arrow keys still worked). Fixed:
the walk now passes all 130 controls of an app page and wraps around.

- [ ] On an app page, Tab from the AppImage list reaches *Check*, *Launch*
      and every setting, and Shift+Tab goes back.

