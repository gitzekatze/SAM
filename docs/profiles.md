# Profiles and presets

## Recommended profiles

SAM infers a category from the desktop file's `Categories`, then the app
name, then the toolkit. It then adjusts the result with what dependency
detection found:

| Category | Default grants |
|---|---|
| Browser | network, Downloads read/write, audio, GPU |
| Communication | network, Downloads read/write, audio, GPU |
| Media player | Music and Videos read/write, Pictures read-only, audio, GPU, no network |
| Image editor | Pictures and Documents read/write, GPU |
| Video editor | Videos read/write, Music and Pictures read-only, audio, GPU |
| Audio editor | Music and Documents read/write, audio |
| Game | GPU, audio; network if it links networking libraries |
| Text editor / Office / Terminal | Documents read/write |
| Development | Documents and `~/Projects` read/write |
| Utility | Wayland window only |

Every profile starts with a private home, Wayland, a filtered session bus
(portals, notifications, tray) and no system bus. Detection then adds:

- **GPU** when the app links OpenGL or Vulkan.
- **Audio** when it links audio libraries.
- **X11** when no Wayland support is found (or for Electron and Java apps).
- **Nested namespaces** for Electron apps.

## Permission keys

Use these keys with `sam-jail set <app> <key> <value>`, or edit the `[permissions]` table of a preset.

| Key | Values |
|---|---|
| `filesystem.home` | `true` / `false` |
| `filesystem.home_access` | `ro` / `rw` |
| `filesystem.documents` … `downloads`, `music`, `pictures`, `videos`, `desktop` | `none` / `ro` / `rw` |
| `filesystem.ssh`, `filesystem.gnupg`, `filesystem.hidden_files` | `true` / `false` (only apply with full home) |
| `filesystem.custom_read`, `filesystem.custom_write` | list, e.g. `"~/Projects, /mnt/data"` |
| `network.mode` | `none` / `localhost` (no internet; loopback ports forwarded by pasta, Bubblewrap only) / `full` (`filtered` is experimental) |
| `devices.gpu`, `devices.webcam`, `devices.gamepads`, `devices.input`, `devices.usb`, `devices.bluetooth` | `true` / `false` |
| `audio.enabled`, `audio.pipewire`, `audio.alsa_raw` | `true` / `false` |
| `display.wayland`, `display.x11`, `display.wayland_privileged` | `true` / `false` |
| `dbus.session.mode`, `dbus.system.mode` | `none` / `filtered` / `full` |
| `dbus.session.allow`, `dbus.session.own` | list of bus names (wildcards allowed) |
| `sockets.ssh_agent`, `sockets.cups` | `true` / `false` |
| `sockets.custom` | list of socket paths |
| `environment.passthrough` | list of variable names |
| `sockets.custom` | paths of extra service sockets; only real socket files are passed in |
| `dbus.session.own` | extra bus names the app may own (filtered bus) |
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
