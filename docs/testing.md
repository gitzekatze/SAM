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

## 1. Environment

- [ ] `sam-jail doctor`: everything is `ok`. The sandbox test passes, and
      Wayland, PipeWire and D-Bus are detected.
- [ ] `sam-jail backends`: Bubblewrap is usable and Bubblejail is listed.

## 2. Real AppImages (whitepaper §3.3 corpus)

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

## 3. D-Bus filtering (could not be verified in the build sandbox)

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

## 7. Optional backends

- [ ] **Bubblejail:** `sam-jail backend <id> bubblejail`, then run. The
      instance `sam-<id>` appears in `bubblejail list`.
- [ ] **Firejail** (if installed): it is refused until
      `security.allow_firejail` is on *and* `--confirm` is given.
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
- [ ] All four themes apply instantly.
- [ ] Turning on full home, the system bus, raw devices or unsandboxed asks for confirmation.
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
- [ ] *Automatic* backend: if Bubblewrap cannot set up an app's sandbox, the
      app starts with Bubblejail and the header says "picked for this app".
- [ ] `sam-jail selftest` lists every sandboxed app as ✓ or ✗.

## 11. Packaging

- [ ] `cd packaging/arch && makepkg -si` builds and installs both packages.
- [ ] SAM starts from the application menu.
