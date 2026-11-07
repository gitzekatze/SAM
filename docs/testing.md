# Manual test checklist

These checks need a real desktop session: real AppImages, PipeWire, a GPU, an
unfiltered session bus, and packages that may not be installed. They
complement `cargo test --workspace` (unit tests plus the end-to-end sandbox
test).

To keep your real configuration untouched while testing, run:

```sh
export APPSEAL_CONFIG_DIR=/tmp/appseal-test/config \
       APPSEAL_DATA_DIR=/tmp/appseal-test/data \
       APPSEAL_APPLICATIONS_DIR=/tmp/appseal-test/applications
```

Leave `APPSEAL_APPLICATIONS_DIR` unset if you want launchers to show up in your menu.

## 1. Environment

- [ ] `appseal doctor`: everything is `ok`. The sandbox test passes, and
      Wayland, PipeWire and D-Bus are detected.
- [ ] `appseal backends`: Bubblewrap is usable and Bubblejail is listed.

## 2. Real AppImages (whitepaper §3.3 corpus)

For each category (browser, media player, image editor, game, text editor,
Electron app, Qt app, GTK app):

- [ ] `appseal add <file>` succeeds, and the category and recommendation make sense.
- [ ] `appseal run <id>` opens a window on Wayland.
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

- [ ] Logs show `landlock: true` (`appseal logs <id>`).
- [ ] With `appseal config set security.experimental_seccomp true` and
      `appseal set <id> advanced.seccomp_strict true`, a non-Electron app
      still starts.

## 5. Desktop integration

- [ ] A launcher appears in the KDE menu with the app's icon.
- [ ] Starting it from the menu runs the app sandboxed (`ps` shows `bwrap`).
- [ ] A failed launch from the menu shows a notification.
- [ ] Removing the app removes the launcher.

## 6. Updates and staleness

- [ ] Replace an AppImage with a newer version. `appseal refresh` reports it
      as stale and the GUI shows the *Stale* badge.
- [ ] Re-extract. A customized profile is kept, and new needs are listed under
      "Update needs new permissions".
- [ ] Move the AppImage. `appseal scan` reports it as a moved copy;
      `appseal scan --add` or *Locate…* fixes the path.

## 7. Optional backends

- [ ] **Bubblejail:** `appseal backend <id> bubblejail`, then run. The
      instance `appseal-<id>` appears in `bubblejail list`.
- [ ] **Firejail** (if installed): it is refused until
      `security.allow_firejail` is on *and* `--confirm` is given.
- [ ] **Diagnostic run** (needs `strace`): `appseal diagnose <id> --apply`
      lists findings, and low-risk fixes are applied.

## 8. Type 1 AppImages

- [ ] An old Type 1 AppImage (ISO 9660) is extracted via `bsdtar`.

## 9. GUI

- [ ] Drag an AppImage into the window to add it.
- [ ] The onboarding appears on first start and can be skipped.
- [ ] Switching between Simple and Advanced mode shows or hides the
      advanced permissions, backend selection and the generated command.
- [ ] All four themes apply instantly.
- [ ] Turning on full home, the system bus, raw devices or unsandboxed asks for confirmation.
- [ ] Applying the "Untrusted Utility" preset to a browser warns that it removes network access.
- [ ] *Copy bug report* produces a report without your username or home path.

## 10. Packaging

- [ ] `cd packaging/arch && makepkg -si` builds and installs both packages.
- [ ] Appseal starts from the application menu.
