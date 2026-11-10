# SAM security model

## Threat model (whitepaper §2.5)

SAM assumes that **you are trusted** and that **individual AppImages may not be**.

**What it mitigates:** accidental access to unrelated files, broad home access,
unneeded network access, unnecessary devices, excessive D-Bus access,
modification of other apps' configuration, and dangerous permissions granted
by mistake.

**What it cannot fully mitigate:**

- **X11:** any X11 client can log keystrokes and capture the screen. Prefer Wayland.
- **Kernel and firmware:** exploits there bypass any user-space sandbox.
- **Root-level malware.**
- **Social engineering.**
- **Apps that need privileged host access to work.**

## What the default sandbox looks like (Bubblewrap)

| Path | Contents |
|---|---|
| `/opt/app` | extracted payload, read-only |
| `/usr/lib`, `/usr/bin` | host runtime, read-only. All of `/usr` with `sam-jail set <id> advanced.host_runtime full`, or with compatibility mode (`sam-jail compat <id> on`) |
| `/usr/share/<x>` | whitelisted shared data (fonts, icons, locale, themes, …), read-only |
| `/etc/<x>` | whitelisted configuration; `passwd` and `group` are generated and contain only your user |
| `/tmp`, `/var/tmp`, `$XDG_RUNTIME_DIR` | private tmpfs |
| `$HOME` | **private per-app home** (`~/.local/share/sam/homes/<id>`) plus only the folders you granted |
| `/` | read-only after setup (`--remount-ro /`) |

Process isolation:

- **Namespaces:** user, PID, IPC, UTS and cgroup are always unshared. The
  network namespace is unshared when network access is "none".
- **Hardening:** `--cap-drop ALL`, `--new-session` (prevents TIOCSTI terminal
  injection) and `--die-with-parent`.
- **Environment:** cleared, then only safe variables are set.

## Defense in depth

- **Landlock** (on by default where the kernel supports it): `sam-jail-run`
  applies a Landlock ruleset *inside* the sandbox before it starts the app.
  Writes are then allowed only in the locations the profile grants read/write.
  If a mount is ever more permissive than intended, the kernel still blocks
  the write. On kernels with Landlock ABI 6 (6.12+) it also blocks
  connections to abstract UNIX sockets created outside the sandbox, such as
  XWayland's `@/tmp/.X11-unix/X0`, which would otherwise be reachable
  whenever the app shares the network namespace.
- **Baseline seccomp** (on by default, `security.baseline_seccomp`): blocks
  module loading, kexec, BPF, perf, keyrings, userfaultfd, handle-based
  opens, `syslog` and terminal injection (`TIOCSTI`, `TIOCLINUX`). Without
  nested sandboxes it also blocks namespaces and mounts. Loaded by
  `sam-jail-run` right before the app starts, so it also applies under
  *Local network only*.
- **Strict seccomp** (experimental, opt-in) adds ptrace, process memory
  access, `personality` and NUMA memory calls.
- **Private `/dev/shm`** per sandbox.
- **Portal filter:** the desktop portal is reachable only for opening links,
  notifications, appearance settings, file dialogs, printing, email,
  inhibit and system monitors. Camera needs the webcam permission and screen
  sharing its own permission. Screenshot, Background (autostart),
  DynamicLauncher, Trash, Wallpaper, RemoteDesktop, InputCapture,
  GlobalShortcuts, Location, Usb, Clipboard and Secret are blocked.
- **SAM and Flatpak are separate.** SAM never writes to Flatpak's files or
  folders and never presents its apps to the desktop as Flatpak apps.
  Portals therefore see a SAM app as an ordinary program; the method filter
  above is what limits it.
- **Local network only** forwards only the host ports listed in
  `network.host_ports`; DNS is never forwarded.
- **Full home access** stays guarded even when you grant it:
  - `~/.ssh`, `~/.gnupg` and other credential stores (keyrings, password
    stores, cloud credentials, browser profiles) stay hidden unless you
    explicitly allow them.
  - SAM's own configuration is hidden.
  - Shell startup files, `autostart`, `systemd --user` and
    `~/.local/share/applications` stay read-only. These are common ways for
    malware to persist.
- **Sandbox check** (`sam-jail verify`, *Check Now* in the window): the same
  launch path as a real start, but the helper runs a test program after
  Landlock and the syscall filter are in place instead of executing the app.
  It compares what it observes inside (folder identity by device and inode,
  write tests with invisible `O_TMPFILE` files, network routes, device nodes,
  D-Bus names via `GetNameOwner`, `NoNewPrivs`, capabilities, user
  namespaces, seccomp and Landlock state) with what the settings promise.
  `security.check_before_launch` repeats it before a start whenever SAM's
  version, the app's settings, the security configuration or the host
  changed, and refuses the start on any failure.

## What SAM never trusts

The sandboxed app controls its own output, and an AppImage controls its own
metadata and file name. SAM treats both as untrusted:

- **Sandbox failures** are reported only when Bubblewrap itself says the
  sandbox could not be built (`--json-status-fd`), never because of text the
  app printed. SAM never falls back to running an app without a sandbox.
- **Repair suggestions** derived from the app's output are labelled as such
  and always need confirmation. They never offer services that can act
  outside the sandbox (systemd, Flatpak, KWin/Plasma scripting, dconf, …)
  or protected locations (`~/.ssh`, keyrings, the whole home). Adding such a
  D-Bus service by hand is rated Dangerous and asks first.
- **Names, comments and file names** are cleaned (no markup, no control
  characters, capped length) and shown as plain text, so an AppImage cannot
  inject HTML (remote images, fake formatting) into SAM's windows or
  notifications.
- **MimeType** declarations are filtered: a sandboxed launcher never
  registers URL schemes (`https`, `mailto`, …), directories, executables or
  generic types.
- **What was enforced** (Landlock, seccomp) is reported by SAM's helper on a
  private channel that is closed before the app starts, and shown in the
  launch log and on the app page.

## Extraction safety (§2.11.4)

Extraction runs inside a minimal Bubblewrap sandbox (source read-only, only
the target writable, no network, no capabilities) whenever Bubblewrap is
usable; the extraction log says whether it was isolated. Extraction never
executes the AppImage by default. Additionally:

- **Archive paths:** entries containing `..` are refused. Parent directories
  are checked so that writes can't be redirected through symlinks.
- **Permissions:** setuid, setgid, sticky and world-writable bits are removed.
  Files become 0755 or 0644.
- **Symlinks and special files:** relative symlinks that resolve outside the
  payload are removed. Device nodes, FIFOs and sockets are removed.
- **Limits:** file-count, size and time limits abort the extraction and
  remove partial output.
- **Host-side reads:** SAM reads only icon and desktop files from the
  payload, and never follows a symlink out of it when doing so.

## Risk levels (§2.19.2)

| Permission | Risk |
|---|---|
| Fonts, icons, locale, timezone (read-only), Wayland, filtered D-Bus | Low |
| GPU, audio, folder access, full `/usr` | Medium |
| Network, X11, full home read-only, full session D-Bus, webcam, SSH agent | High |
| Full home read/write, system D-Bus, raw devices (input, USB, ALSA), exposed keys | Dangerous |

The score shown in the app is a weighted sum, capped at 100.

## Known limitations

- **D-Bus filtering** needs `xdg-dbus-proxy`.
  Without it, "filtered" falls back to *no* session bus.
- **Abstract sockets** are blocked only with Landlock ABI 6 (kernel 6.12+)
  On older kernels, XWayland's abstract socket is reachable with full
  network (X11 authorization still applies).
- **Domain-filtered network** is experimental and not enforced (falls back
  to no network).
- **Files picked in a file dialog** outside the folders an app may use are
  not visible to it: the portal hands over the host path, and the sandbox
  does not contain it. Grant the folder (or open the file with the app,
  which grants that one file) instead.
- **Local network only** forwards the app's ports to this computer
  automatically, except privileged ports and well-known local services;
  list `network.app_ports` to restrict it further.
- **Hostname:** the sandbox keeps the host's hostname. Changing it is blocked
  on some hardened hosts.
