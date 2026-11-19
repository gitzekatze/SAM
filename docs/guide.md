# SAM User Guide

**SAM - Sandboxed AppImage Manager** runs your AppImages in a sandbox and shows every permission an app has as a simple switch, much like Flatseal does for Flatpak apps.

> **The short version:** pick an AppImage on the left, look at the settings SAM recommends, click **Create Sandbox**, then **Launch**. Everything an app may reach is listed on its page, and nothing is ever hidden.

---

## At a glance

| You want to… | Do this |
|---|---|
| Sandbox an AppImage | Select it on the left, then **Create Sandbox** |
| Start a sandboxed app | **Launch** on its page, or from your application menu |
| Give an app access to a folder | Its page → **Files** |
| Confirm the sandbox really applies your settings and the app starts | **Test** next to Launch, results under **Test** |
| Fix an app that does not start | Its page → **Troubleshooting** |
| Change a permission for several apps | **Permission Manager** above the list, select the apps, change the switch |
| Reuse settings for other apps | Its page, at the end → **My Presets** → *Name for the new preset* |
| Find out what a label means | Hover over it |
| Remove a sandbox | The round trash button left of **Test** |
| Close an app that hides in the tray | The trash button offers *Close and Remove*, or `sam-jail stop app` |
| Use changed settings while the app runs | The bar "… is running" at the top of its page → **Restart** |
| Go back to the start page | Click SAM's logo at the top left |
| Change SAM's language | Main menu → **Language**, choose one, then **Restart Now** (apps keep your system's language) |

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

- **AppImage locations:** the folders and single files SAM searches. The ✕ removes a location (your files are not touched). When your Downloads folder holds AppImages but is not a location, a line says so and **Add Downloads** adds it like any other folder. The list grows with every location you add; the whole left column scrolls. New AppImages in these locations appear by themselves.
- **AppImages found:** every AppImage in those locations, grouped into *Sandboxed* and *Not sandboxed*. Use **All / Sandboxed / Not sandboxed** to filter and the search field to find one by name or path.
- Each row shows the app's icon, name, file name and a status. Hover over any status to see what it means.
  - *Sandboxed* / *Not sandboxed*: whether the app has a sandbox yet.
  - *Needs review*: look over the settings SAM chose, or new access the app asks for.
  - *Compatibility mode*: you turned on compatibility mode, so the app has broad access.
  - *May not start* / *Likely won't start*: SAM's analysis found the app relies on libraries it does not bring itself (or something worse). It is only a warning: launch the app, and the label disappears once it has started.
  - *Changed*, *Broken*, *Missing*: the AppImage file changed, the last start failed, or the file is gone.
  - *Changed outside SAM*: something other than SAM changed the app's settings, or replaced its AppImage file (not through a SAM update) and you unpacked it again; it does not start until you confirm on its page.
  - *Protection missing*: the last start lacked a protection layer its settings ask for (Landlock or the syscall filter, for example because SAM's helper is missing, or the Wayland security context, when the desktop offers it but it could not be made); the app's page says which.
- A ⚠ next to a row means something needs attention; hover over it to see what.

**Right column**

- **The header** shows the app, its file and labels for its state. Hover over a label to see what it means.
  - *Sandboxed* (green) or *Not sandboxed*.
  - *Sandbox unavailable* (red), only when Bubblewrap cannot run on this computer; *Diagnostics* says why.
  - The test state: *Not tested yet*, *Tested* with the date, *Test out of date* (the settings, SAM or the computer changed since) or *Test failed*.
  - Below them, the same permission tags as in the Permission Manager.
  - Anything that needs attention, such as *Needs review* or *May not start*. When the last start lacked a protection layer, a warning at the top of the page names it.
- The round trash button, **Test** and **Launch** (or **Create Sandbox**) sit on the right of the header; the trash button stays away from Launch so it is not hit by mistake. In a narrow window, the buttons stack. Every button explains itself when you hover over it.
- While the app runs, a bar at the top of its page says that changed settings apply the next time it starts, and **Restart** closes the app (it may save first) and starts it again with the new settings.
- **Below the header** come all settings and tools for the app, always visible. Settings that do not apply right now are greyed out, never hidden.
- **SAM's logo** at the top left opens the start page (no AppImage selected).
- The **☰ menu** at the top left opens this guide, **My Presets**, **Diagnostics**, **Preferences** and *About SAM* in the right column.

---

## Settings, group by group

Every setting has a short explanation under its name. When a setting carries a real risk and is switched on, a red **High risk** or **Dangerous** pill appears next to it. If SAM would recommend a different value, the explanation says *SAM recommends: …*.

### Overview

The **risk** of the current settings: *low*, *medium*, *high* or *dangerous*. It is the level of the riskiest permission, not a count, so one webcam permission makes an app *high risk* however little else it may do. The label names that permission, for example **High risk · Network +1** (network and one more high-risk permission). *What raises the risk* lists every permission above *low*, and hovering over the label shows the same. Settings that take a protection away count too (the syscall filter or Landlock switched off, a passed-through variable that holds a secret), and so do combinations: the network together with your home, keys or passwords is *dangerous*, because the app can send what it reads. Below that come things worth watching out for, such as X11 access.

### Network

- **No network:** no connection at all, not even to this computer.
- **This computer only:** no internet, but the app can reach the services on this computer you list (for example port 11434 for Ollama), and its own web page opens in your browser.
- **Full network:** the app uses your internet connection like any other program.

### Display

**Wayland** shows windows through your compositor, which keeps apps apart. **X11 / XWayland** is for apps without Wayland support; X11 lets an app observe input and other windows, so only turn it on when needed.

On desktops that support it, SAM tells the compositor that the app is sandboxed, and the desktop hides privileged functions from it: reading the clipboard in the background, capturing the screen, typing as a virtual keyboard. **Privileged Wayland protocols** (advanced) turns that off for the few tools that are exactly that, such as clipboard managers or screenshot tools. This is tested on KDE Plasma; other desktops that offer the protocol behave the same, and **Diagnostics** (or `sam-jail doctor`) tells whether yours does.

### Sound and devices

**Sound** (through SAM's sound relay, which plays and records but cannot load code into your sound server), **Sound without SAM's relay** (only where the relay cannot run: then the app could load code into the sound server, and SAM warns at every start), **GPU acceleration**, **Webcam**, **Game controllers** (only gamepads; keyboards and mice stay hidden), **All input devices** (only for tools that remap input), **Raw USB**, **Bluetooth**, **Direct PipeWire access** (only for apps that support nothing else: it also reaches cameras and other apps' screen streams) and **Raw ALSA devices**.

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

### Terminal programs

Programs that run in a terminal (Helix, Neovim, command-line tools) open in your terminal from the menu, or start with `sam-jail run <app> [files or folders]`. They get a terminal of SAM's own, so they cannot type into your shell or use the clipboard through the terminal. They see their private home, the folders allowed in their settings, and the files and folders you name: `sam-jail run helix notes.txt` opens that file, `sam-jail run helix .` the folder you are in. They also work in pipes: `cat data.json | sam-jail run jq .` passes the data in and the result out unchanged. See [Terminal programs](security.md#terminal-programs) for what this protects against and what it does not.

### Launching

**Launch arguments** passed every time the app starts (for example `--no-sandbox` for Electron apps), and **Compatibility mode**, which gives broad access when nothing else works. Turning compatibility mode off brings back your previous settings.

### Menu Entries

**Menu entry from SAM** adds or removes SAM's entry in your application menu. **Hide other menu entries for this AppImage** hides entries made by tools like AppImageLauncher or Gear Lever that would start the app *without* a sandbox, and shows them again when you turn it off or remove the sandbox.

---

## Permission Manager

The button **Permission Manager** above the list of AppImages opens a page that shows every sandboxed app with tags for what it may access. The tags use the same words as the switches and come in four groups: Network, Files, Devices and Desktop. Their color shows the risk, the same way everywhere in SAM: grey means harmless, amber means think twice, and red means dangerous. A filled tag means read and write access, an outlined tag means read-only or limited access. Hovering over a tag explains what the permission allows. The app's own page shows the same tags under its name.

- **Filter** by clicking a tag above the list: the first click shows only the apps that have this permission, the second click shows only the apps without it, and the third click turns the filter off. *Running*, *Needs review* and *May not start* filter by state.
- **Select** apps with the check boxes. Shift-click selects a range, and *Select all* selects every app the filter shows. Clicking an app selects only that app.
- **One app selected:** the right side shows the same permission settings as the app's own page.
- **Several apps selected:** the right side shows the permissions that make sense for a group (network, personal folders, sound, camera, game controllers, X11 and desktop services). Where the selected apps differ, a permission appears once per value, with the apps that have that value listed below it. Changing the big switch changes all apps of that row; changing the small switch next to an app moves only that app.
- Changes apply at once. A message at the bottom offers **Undo** for the whole change. Undo takes back only that change: anything you changed for these apps since stays. If you changed the same setting again in between, Undo changes nothing and says so. SAM asks first when its analysis says that an app would stop working, for example when a chat app would lose the internet or an X11-only app would lose X11, and when a change adds something rated *Think twice* or *Dangerous*.
- Apps that are running keep their old settings until they start the next time.

---

## My Presets

A preset is a named set of permissions you saved yourself. SAM ships no ready-made presets, because the settings SAM recommends for each app already fit that app better than a set made for a whole category.

- On an app's page, **My Presets** → *Name for the new preset* saves the app's current settings under that name.
- **☰ → My Presets** lists your presets. From the menu of a preset you can apply it to an app, edit, duplicate, export or delete it; the buttons in the header create a new preset or import one.
- Before a preset is applied, SAM compares it with what the app likely needs and asks if the preset would remove something important.

---

## Test

Does the sandbox really give the app exactly what its settings say, and does the app start in it? **Test**, next to **Launch** at the top, first starts the app's real sandbox with a small test program instead of the app, then starts the app itself for a few seconds. From inside, it confirms every setting: which folders are visible and writable, the network, devices, display and sound, which desktop services are reachable, and that Landlock, the syscall filter and the other protections are active.

- It works before the sandbox exists too: then it checks the settings shown on the page, without unpacking or running the AppImage. That result is not stored.
- Nothing is changed and nothing leaves your computer. Write tests use invisible temporary files.
- The header shows **Tested** with the date when everything applies, and the result of the short start appears under **Test**. Failed checks are listed in red; checks that do not apply to your computer (for example no webcam) are shown as not applicable.
- **Preferences → Check the sandbox before each start** runs the check automatically, only when something changed since the last passing check. A failed check stops the start.

---

## When an app does not work

- **Advice** is the one place for help: what went wrong last time (read from the app's own error messages, with *fix and start*), the repair steps, common reasons apps misbehave in a sandbox, and a warning when another menu entry still starts the AppImage without a sandbox (**Hide It** fixes that). Suggestions based on what the app printed always ask first, because an app could print misleading messages.
- **Repair steps** are switches and appear after a start failed. Each says what it turns on or off and what protection that costs. A step you turn on is tried at the next start: if the app still fails, SAM switches the step off again by itself and does not offer it again (*Switch off all repair steps* offers everything again). Switching a step off undoes exactly that step; *Switch off all repair steps* under Troubleshooting undoes them all. Either way, a setting you changed yourself after the step stays as you set it.
- **Compatibility mode** (under Launching) names exactly which switches it turns on. It includes the whole session bus, through which the app can ask desktop services to run programs outside its sandbox: a way out, only for apps you trust. *Never offer compatibility mode* in Preferences keeps it out of the repair steps.
- **Troubleshooting** has *Re-run detection*, a diagnostic run (needs `strace`), the setup check and a redacted bug report.
- **Extra Protection Layers** (the syscall filters and Landlock) are a group of their own at the end of the settings. Turn one off only when an app's log shows it fails because of it.
- **Logs** shows every log: starts, unpacking, detection and diagnostic runs.

> **Tip:** start with **Test**. If every setting applies but the app still fails, the app needs a permission it does not have yet. *What went wrong last time* usually names it.

---

## Removing a sandbox

The trash button asks what to remove; nothing is preselected, and the button names the action you chose:

- **Only the unpacked copy** (*Free Space*): frees disk space; the sandbox and the app's settings stay, and SAM unpacks the app again at its next start.
- **The sandbox, but keep the app's settings and files** (*Remove Sandbox*): removes the sandbox and SAM's menu entry and shows again any menu entry SAM hid; a new sandbox for the same AppImage picks up the kept private folder.
- **Everything** (*Delete Everything*): also deletes the app's private folder with its logins, settings and saved files.

Your AppImage file always stays. Data kept this way is listed under **☰ → Diagnostics → Data of removed sandboxes**.

If the app is still running, often only as an icon in the system tray, the dialog says so and the button starts with **Close and …**. SAM asks the app to quit so it can save its data, and only ends it if it is still running after ten seconds.

---

## Preferences

Style (follow the system, light or dark), menu entries, repair options, warnings, the kernel security layers, the sandbox check, dependency detection, where AppImages are unpacked and the extraction limits, and how many logs to keep.

## Diagnostics

A system check (Bubblewrap, user namespaces, Landlock, the D-Bus proxy, sockets), *Check all AppImages for changes*, *Remove unused unpacked copies* (only app folders SAM made and its own unfinished leftovers; when the unpack location is a folder that also holds other things, nothing else in it is touched, and uninstalling SAM leaves that folder), the disk space of sandboxed apps, data of removed sandboxes, and a redacted bug report.

**Updates:** under *Details*, **Check for Updates** asks the update source the AppImage names (GitHub or the app's own server) whether a newer version is published. If so, the page says which one and offers **Update Now**: SAM downloads it, checks it, puts it in place of the old file and unpacks it, keeping your settings. The old version is kept; **Go back to the previous version** under *Troubleshooting* restores it. (**Open Download Page** is there if you prefer to do it yourself.) *Preferences → Updates* can check every app once a day when SAM opens. When an update description is published (most do), only the changed parts are downloaded.

**SAM itself:** if you use SAM's AppImage, *Check for SAM Updates* in the main menu updates SAM the same way. Packages from your distribution update through its package manager.

**Disk space:** an app's page shows, under *Details*, how much space it takes. **Free Space** deletes its unpacked copy; its settings and files stay, and the next start unpacks the AppImage again (a few seconds).

---

## Command line

Everything in the window is also available as `sam-jail`:

```
sam-jail add ~/Applications/App.AppImage    # create a sandbox
sam-jail run app                            # start it
sam-jail set app filesystem.documents ro    # change one setting
sam-jail verify app                         # sandbox check
sam-jail repair app --next                  # try the next repair step
                                            # (one suggested by what the app printed needs --yes)
sam-jail remove app --keep-data             # remove, keep its data
sam-jail stop app                           # close a running app
```

Run `sam-jail --help` for every command. In the AppImage, the same commands are `SAM.AppImage cli …`, for example `./SAM-0.2.0-x86_64.AppImage cli doctor`.

---

## What SAM protects you from

SAM uses **Bubblewrap**: each app gets its own view of the system with only the folders, devices and services you allow, read-only system files, no special privileges and its own process list. On top of that come **Landlock** write protection, a **syscall filter** and a **filtered D-Bus**.

Keep in mind:

- A sandbox limits what an app can reach; it does not make a malicious app harmless if you give it broad access such as full home, X11, the full session bus or the keyring.
- Prefer **Wayland** over X11, **Filtered** D-Bus over full access, and single folders over full home.
- Only allow risky settings for apps you trust. SAM asks before any change rated *Think twice* or *Dangerous*.

---

## Installing SAM

SAM comes as an AppImage that runs on Ubuntu 24.04 and newer, Debian 13, Fedora 40 and newer, Arch Linux, CachyOS and openSUSE Tumbleweed. It uses the GTK 4 and libadwaita installed on your system, and Bubblewrap must be installed too; if something is missing, SAM says which packages to install. Packages for Arch (AUR) and Fedora (COPR) are planned. [Install SAM](install.md) has the steps.

> **Moved the AppImage?** Menu entries SAM made point at the AppImage file. Open SAM once from its new place and it updates them.

**Removing SAM:** run `sam-jail uninstall` to see what would be removed, then `sam-jail uninstall --yes`. It closes running apps, removes every sandbox (hidden menu entries come back), SAM's menu entries, its settings and the apps' private data; `--keep-data` keeps settings and app data. Your AppImage files stay. Then remove the package or the AppImage.

**Updating SAM** keeps your settings and sandboxes. If SAM ever finds a file it cannot read, it moves it aside (nothing is deleted) and **☰ → Diagnostics** lists it.

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
