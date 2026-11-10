# SAM User Guide

**SAM, the Sandboxed AppImage Manager**, runs your AppImages in a sandbox and shows every permission an app has as a simple switch, much like Flatseal does for Flatpak apps.

> **The short version:** pick an AppImage on the left, look at the settings SAM recommends, click **Create Sandbox**, then **Launch**. Everything an app may reach is listed on its page, and nothing is ever hidden.

---

## At a glance

| You want to… | Do this |
|---|---|
| Sandbox an AppImage | Select it on the left, then **Create Sandbox** |
| Start a sandboxed app | **Launch** on its page, or from your application menu |
| Give an app access to a folder | Its page → **Files** |
| Confirm the sandbox really applies your settings | **Check** next to Launch, results under **Sandbox Check** |
| Fix an app that does not start | Its page → **Troubleshooting** |
| Reuse settings for other apps | Its page → **Presets** → *Save these settings as a preset* |
| Remove a sandbox | **Remove Sandbox** under the Launch button |

---

## Getting started

1. **Tell SAM where your AppImages are.** At the top left, under *AppImage locations*, add a folder with the folder button or a single file with **+**. You can also drop an AppImage or a folder onto the window.
2. **Pick an AppImage.** It appears under *AppImages found*. Selecting it shows the settings SAM recommends. Nothing is unpacked or run yet.
3. **Adjust if you like**, then click **Create Sandbox**. SAM unpacks the AppImage *without running it*, inspects its programs and creates a menu entry.
4. **Launch.** The app now runs inside its sandbox, with exactly the access shown on its page.

> **Tip:** SAM never runs an AppImage without a sandbox. If the sandbox cannot be set up on your system, SAM says why and does not start the app.

---

## The window

**Left column**

- **AppImage locations:** the folders and single files SAM searches. The ✕ removes a location (your files are not touched). *Also search the Downloads folder* adds your Downloads folder.
- **AppImages found:** every AppImage in those locations, grouped into *Sandboxed* and *Not sandboxed*. Use **All / Sandboxed / Unsandboxed** to filter and the search field to find one by name or path.
- Each row shows the app's icon, name, file name and a status: *Sandboxed*, *Not sandboxed*, *Needs review*, *Compatibility*, *Changed*, *Broken* or *Missing*. A ⚠ means something needs attention; hover over it to see what.

**Right column**

- **The header** shows the app, its file, its status, its risk and **Launch** (or **Create Sandbox**) with **Remove Sandbox** below it.
- **Below the header** come all settings and tools for the app, always visible. Settings that do not apply right now are greyed out, never hidden.
- **SAM's logo** at the top left opens the start page (no AppImage selected).
- The **☰ menu** at the top left opens this guide, **Presets**, **Diagnostics**, **Preferences** and *About SAM* in the right column.

---

## Settings, group by group

Every setting has a short explanation under its name. When a setting carries a real risk and is switched on, a red **High risk** or **Dangerous** pill appears next to it. If SAM would recommend a different value, the explanation says *SAM recommends: …*.

### Overview

The **risk** of the current settings (low, medium, high or dangerous, with a score) and anything worth watching out for, such as X11 access.

### Network

- **No network:** no connection at all, not even to this computer.
- **Local network only:** no internet, but the app can reach the services on this computer you list (for example port 11434 for Ollama), and its own web page opens in your browser.
- **Full network:** the app uses your internet connection like any other program.

### Display

**Wayland** shows windows through your compositor, which keeps apps apart. **X11 / XWayland** is for apps without Wayland support; X11 lets an app observe input and other windows, so only turn it on when needed.

### Sound and devices

Sound (PipeWire or PulseAudio), **GPU acceleration**, **Webcam**, **Game controllers** (only gamepads; keyboards and mice stay hidden), **All input devices** (only for tools that remap input), **Raw USB**, **Bluetooth** and **Raw ALSA devices**.

### Files

Each personal folder (Documents, Downloads, Pictures, Music, Videos, Desktop) can be *No access*, *Read-only* or *Read & write*. You can add **extra folders**, read-only or writable, and decide whether files you open with the app can be saved. **Full home access** is possible but dangerous; even then your SSH keys, GnuPG keys and sensitive dotfiles stay hidden unless you allow them one by one.

> **Where do an app's own files go?** Into its private folder. Open it from the app's ⋮ menu → *Files This App Saved*.

### Desktop integration

*Show in folder*, media keys and "now playing", screen sharing (your desktop always asks first), passwords and keyring (the keyring does not separate apps, so the app can read every stored password), and input methods such as Fcitx5 or IBus.

### D-Bus

How the app talks to other programs. **Filtered** (recommended) allows file dialogs, notifications, the tray and the services you list; **Names the app may own** and **Always blocked names** fine-tune it. **Full access** and the **system bus** let an app act far outside its sandbox.

### Sockets and environment

The SSH agent, printing, **extra sockets** (only real socket files are passed in), variables passed through from your desktop, and **environment variables** set as `NAME=value`.

### Advanced

How much of the system is visible (*Minimal* or *All of /usr*), whether the app keeps its private settings, a writable app folder for portable apps, theme settings, nested sandboxes for Chromium and Electron, Landlock, the syscall filters and raw Bubblewrap arguments. Change these only if an app does not work.

### Launching

**Launch arguments** passed every time the app starts (for example `--no-sandbox` for Electron apps), and **Compatibility mode**, which gives broad access when nothing else works. Turning compatibility mode off brings back your previous settings.

### Menu Entries

**Menu entry from SAM** adds or removes SAM's entry in your application menu. **Hide other menu entries for this AppImage** hides entries made by tools like AppImageLauncher or Gear Lever that would start the app *without* a sandbox, and shows them again when you turn it off or remove the sandbox.

---

## Presets

A preset is a named set of permissions you can apply to any app.

- **Start from a preset** applies one. Before the sandbox exists, it replaces the recommended settings shown.
- **Save these settings as a preset** stores the current settings under a name of your choice.
- **☰ → Presets** lists all presets. Built-in ones can be viewed and duplicated; your own can be edited, exported, imported and deleted.

---

## Sandbox Check

Does the sandbox really give the app exactly what its settings say? **Check**, next to **Launch** at the top, starts the app's real sandbox with a small test program instead of the app. From inside, it confirms every setting: which folders are visible and writable, the network, devices, display and sound, which desktop services are reachable, and that Landlock, the syscall filter and the other protections are active.

- It works before the sandbox exists too: then it checks the settings shown on the page, without unpacking or running the AppImage. That result is not stored.
- Nothing is changed and nothing leaves your computer. Write tests use invisible temporary files.
- A ✓ **Checked** pill appears in the header when everything applies. Failed checks are listed in red; checks that do not apply to your computer (for example no webcam) are shown as not applicable.
- **Preferences → Check the sandbox before each start** runs the check automatically, only when something changed since the last passing check. A failed check stops the start.

---

## When an app does not work

- **Worth checking** lists common reasons apps misbehave in a sandbox, with one-click fixes.
- **What went wrong last time** reads the app's own error messages and suggests a fix. Suggestions based on what the app printed always ask first, because an app could print misleading messages.
- **Troubleshooting** has *Try the next fix and start*, more repair steps, *Undo all repairs*, *Re-run detection*, a diagnostic run (needs `strace`) and a redacted bug report.
- **Logs** shows every log: starts, unpacking, detection and diagnostic runs.

> **Tip:** start with the sandbox check. If every setting applies but the app still fails, the app needs a permission it does not have yet. *What went wrong last time* usually names it.

---

## Removing a sandbox

**Remove Sandbox** deletes the unpacked app and SAM's menu entry, and shows again any menu entry SAM hid. Your AppImage file always stays. Tick **Keep the app's settings and files** to keep its private folder: a new sandbox for the same AppImage picks it up again. Data kept this way is listed under **☰ → Diagnostics → Data of removed sandboxes**.

---

## Preferences

Style (follow the system, light or dark), menu entries, repair options, warnings, the kernel security layers, the sandbox check, dependency detection, extraction limits and how many logs to keep.

## Diagnostics

A system check (Bubblewrap, user namespaces, Landlock, the D-Bus proxy, sockets), *Check all AppImages for changes*, *Remove unused extractions*, data of removed sandboxes, and a redacted bug report.

---

## Command line

Everything in the window is also available as `sam-jail`:

```
sam-jail add ~/Applications/App.AppImage    # create a sandbox
sam-jail run app                            # start it
sam-jail set app filesystem.documents ro    # change one setting
sam-jail verify app                         # sandbox check
sam-jail repair app --next                  # try the next repair step
sam-jail remove app --keep-data             # remove, keep its data
```

Run `sam-jail --help` for every command.

---

## What SAM protects you from

SAM uses **Bubblewrap**: each app gets its own view of the system with only the folders, devices and services you allow, read-only system files, no special privileges and its own process list. On top of that come **Landlock** write protection, a **syscall filter** and a **filtered D-Bus**.

Keep in mind:

- A sandbox limits what an app can reach; it does not make a malicious app harmless if you give it broad access such as full home, X11, the full session bus or the keyring.
- Prefer **Wayland** over X11, **Filtered** D-Bus over full access, and single folders over full home.
- Only allow risky settings for apps you trust. SAM asks before granting the dangerous ones.

---

## Where SAM keeps its files

| What | Where |
|---|---|
| Settings, presets, logs | `~/.config/sam/` |
| Unpacked apps, private homes, icons | `~/.local/share/sam/` |
| Menu entries | `~/.local/share/applications/sam-*.desktop` |
| Temporary files while an app runs | `/run/user/<id>/sam/` |

## Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl` + `R` or `F5` | Search the locations again |
| `Ctrl` + `W` | Close the window |
