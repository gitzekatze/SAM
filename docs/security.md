# Appseal security model

## Threat model (whitepaper §2.5)

Appseal assumes that **you are trusted** and that **individual AppImages may not be**.

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
| `/usr/lib`, `/usr/bin` | host runtime, read-only. All of `/usr` with `appseal set <id> advanced.host_runtime full`, or with compatibility mode (`appseal compat <id> on`) |
| `/usr/share/<x>` | whitelisted shared data (fonts, icons, locale, themes, …), read-only |
| `/etc/<x>` | whitelisted configuration; `passwd` and `group` are generated and contain only your user |
| `/tmp`, `/var/tmp`, `$XDG_RUNTIME_DIR` | private tmpfs |
| `$HOME` | **private per-app home** (`~/.local/share/appseal/homes/<id>`) plus only the folders you granted |
| `/` | read-only after setup (`--remount-ro /`) |

Process isolation:

- **Namespaces:** user, PID, IPC, UTS and cgroup are always unshared. The
  network namespace is unshared when network access is "none".
- **Hardening:** `--cap-drop ALL`, `--new-session` (prevents TIOCSTI terminal
  injection) and `--die-with-parent`.
- **Environment:** cleared, then only safe variables are set.

## Defense in depth

- **Landlock** (on by default where the kernel supports it): `appseal-run`
  applies a Landlock ruleset *inside* the sandbox before it starts the app.
  Writes are then allowed only in the locations the profile grants read/write.
  If a mount is ever more permissive than intended, the kernel still blocks
  the write.
- **Strict seccomp** (experimental, opt-in): blocks module loading, kexec,
  mount, ptrace, bpf, perf, keyring and similar system calls. Nested user
  namespaces can be blocked as well. Electron and Chromium need those for
  their own sandbox, which is why this is a separate toggle.
- **Full home access** stays guarded even when you grant it:
  - `~/.ssh`, `~/.gnupg` and other credential stores (keyrings, password
    stores, cloud credentials, browser profiles) stay hidden unless you
    explicitly allow them.
  - Appseal's own configuration is hidden.
  - Shell startup files, `autostart`, `systemd --user` and
    `~/.local/share/applications` stay read-only. These are common ways for
    malware to persist.

## Extraction safety (§2.11.4)

Extraction never executes the AppImage by default.

- **Archive paths:** entries containing `..` are refused. Parent directories
  are checked so that writes can't be redirected through symlinks.
- **Permissions:** setuid, setgid, sticky and world-writable bits are removed.
  Files become 0755 or 0644.
- **Symlinks and special files:** relative symlinks that resolve outside the
  payload are removed. Device nodes, FIFOs and sockets are removed.
- **Limits:** file-count, size and time limits abort the extraction and
  remove partial output.
- **Host-side reads:** Appseal reads only icon and desktop files from the
  payload, and never follows a symlink out of it when doing so.

## Risk levels (§2.19.2)

| Permission | Risk |
|---|---|
| Fonts, icons, locale, timezone (read-only), Wayland, filtered D-Bus | Low |
| GPU, audio, folder access, full `/usr` | Medium |
| Network, X11, full home read-only, full session D-Bus, webcam, SSH agent | High |
| Full home read/write, system D-Bus, raw devices (input, USB, ALSA), exposed keys, unsandboxed | Dangerous |

The score shown in the app is a weighted sum, capped at 100.

## Known limitations

- **D-Bus filtering** needs `xdg-dbus-proxy` (or the Bubblejail backend).
  Without it, "filtered" falls back to *no* session bus.
- **Abstract X11 sockets** (e.g. XWayland on `@/tmp/.X11-unix/X0`) can be
  reached through the shared network namespace when network access is
  "full", even with X11 off. Flatpak has the same limitation.
- **Localhost-only and domain-filtered network modes** are experimental and
  not enforced. Bubblewrap falls back to "none".
- **Firejail** is setuid-root. Use it only as a compatibility backend.
- **Hostname:** the sandbox keeps the host's hostname. Changing it is blocked
  on some hardened hosts.
