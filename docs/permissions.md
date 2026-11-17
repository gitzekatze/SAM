# Permissions: keys, presets and group changes

A reference for people who use the command line or edit files by hand. The
window shows the same permissions with plain-language explanations.

## How SAM recommends permissions

SAM starts every app as strictly as it can: a private home, Wayland, a
filtered session bus (file dialogs, notifications, tray) and nothing else.
It then adds only what the app shows it needs: what kind of app it is (from
its desktop file, name and toolkit) and what it contains (graphics, sound or
network libraries, X11 without Wayland, its own browser sandbox). The app's
page says why each permission was recommended; the tests behind this are
listed under function 6 in [functions.md](functions.md).

## Permission keys

Use these keys with `sam-jail set <app> <key> <value>`, or edit the `[permissions]` table of a preset.

| Key | Values |
|---|---|
| `filesystem.home` | `true` / `false` |
| `filesystem.home_access` | `ro` / `rw` |
| `filesystem.documents` … `downloads`, `music`, `pictures`, `videos`, `desktop` | `none` / `ro` / `rw` |
| `filesystem.ssh`, `filesystem.gnupg`, `filesystem.hidden_files` | `true` / `false` (only apply with full home) |
| `filesystem.custom_read`, `filesystem.custom_write` | list, e.g. `"~/Projects, /mnt/data"` |
| `network.mode` | `none` / `localhost` (no internet; loopback ports forwarded by pasta, Bubblewrap only) / `full` (a `filtered` value from old profiles loads as `none`) |
| `devices.gpu`, `devices.webcam`, `devices.gamepads`, `devices.input`, `devices.usb`, `devices.bluetooth` | `true` / `false` |
| `audio.enabled`, `audio.pipewire`, `audio.alsa_raw` | `true` / `false` |
| `display.wayland`, `display.x11`, `display.wayland_privileged` | `true` / `false` |
| `dbus.session.mode` | `none` / `filtered` / `full` |
| `dbus.system.mode` | `none` / `full` (the system bus cannot be filtered; a `filtered` value from old profiles loads as `none`) |
| `dbus.session.allow` | bus names the app may talk to (wildcards allowed) |
| `dbus.session.own` | extra bus names the app may own (filtered bus) |
| `sockets.ssh_agent`, `sockets.cups` | `true` / `false` |
| `sockets.custom` | paths of extra service sockets; only real socket files are passed in |
| `environment.passthrough` | list of variable names |
| `dbus.session.deny` | bus names that stay blocked even if allowed elsewhere |
| `environment.set` | variables set inside the sandbox, e.g. `{"QT_SCALE_FACTOR": "1.5"}` (names: letters, digits, `_`) |
| `advanced.host_runtime` | `minimal` / `full` |
| `advanced.persistent_home`, `advanced.seccomp_strict`, `advanced.allow_userns`, `advanced.host_themes` | `true` / `false` |
| `advanced.landlock` | `true` / `false` (unset = follow the global setting) |
| `network.host_ports` | list of host ports reachable with `localhost`, e.g. `"11434"` |
| `integrations.screen_sharing` | `true` / `false`: screen sharing through the portal (asks each time) |
| `advanced.seccomp_baseline` | `true` / `false`: baseline syscall filter for this app |
| `advanced.writable_appdir` | `true` / `false`: overlay on the app folder, changes kept per app |
| `integrations.keyring` | `true` / `false`: Secret Service / KWallet (exposes every stored password) |
| `integrations.media_controls` | `true` / `false`: MPRIS media keys, screen-saver inhibit |
| `integrations.input_method` | `true` / `false` (default `true`): Fcitx5 and IBus through their sandbox frontends |
| `integrations.file_manager` | `true` / `false`: "Open the file manager" (shows a saved file in its folder) |
| `advanced.extra_bwrap_args` | list of raw backend arguments |

`sam-jail permissions` prints the same list with plain-language explanations and risk levels.

## Preset file format

```toml
[preset]
name = "My Browser"
description = "Browser profile with no home access except Downloads"
compatibility_notes = ""

[permissions.filesystem]
downloads = "rw"

[permissions.network]
mode = "full"

[permissions.display]
wayland = true
x11 = true
```

The older flat form (`network = "full"`, `gpu = true`,
`dbus_session = "filtered"`, …) is also accepted on import.

When you apply a preset, SAM compares it with what the app likely needs
and with your current profile. It asks for confirmation if the preset removes
something the app needs (e.g. the network for a browser) or adds high-risk
permissions.

## Your own presets only

SAM ships no ready-made presets. SAM's recommendation is made for each app
from what the app declares and contains, so a set made for a whole category
(such as "browser" or "game") would replace a fitting recommendation with a
guess. The category SAM recognizes stays visible as an explanation of the
recommendation. Save an app's settings with `sam-jail preset save APP NAME`
or on the app's page, and apply them with `sam-jail preset apply NAME APP`.

## Changing several apps at once

`sam-jail group set KEY VALUE APP…` sets one permission for several apps.
With `--dry-run` it only lists what each app would lose that it likely needs.
It prints the settings from before as `previous`; `sam-jail group restore`
reads that object on stdin and puts them back. `sam-jail group list` shows
every sandboxed app with its permission tags.
