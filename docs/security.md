# Security

This page explains how SAM - Sandboxed AppImage Manager protects your
computer from the AppImages it runs, and where that protection ends.

**In short:** every app runs in a Bubblewrap sandbox with its own private
home, a read-only system, no privileges and only the access you allow. Inside
it, Landlock and a syscall filter add a second line of defence. SAM never
starts an app without a sandbox.

---

## Threat model

SAM assumes that **you are trusted** and that **an AppImage may not be**.
The full threat model, with each threat, what stops it and the test that
proves it, is in [threat-model.md](threat-model.md).

| SAM protects against | SAM cannot fully protect against |
|---|---|
| apps reading files they have no business with | **X11:** any X11 app can read keystrokes and capture the screen. Prefer Wayland. |
| apps changing other apps' settings | **Kernel and firmware bugs:** they bypass every user-space sandbox. |
| unneeded network, devices and D-Bus services | **Malware that is already root.** |
| dangerous permissions granted by mistake | **Social engineering:** an app that talks you into granting access. |
| an app starting programs outside its sandbox | **Apps that need privileged host access** to work at all. |

---

## Inside the sandbox

### Files

| Path in the sandbox | What it is |
|---|---|
| `$HOME` | the app's **private home** (`~/.local/share/sam/homes/<app>`), plus only the folders you granted |
| `/opt/app` | the unpacked app, read-only |
| `/usr/lib`, `/usr/bin` | the system's libraries and programs, read-only (all of `/usr` with `advanced.host_runtime full` or compatibility mode) |
| `/usr/share/…` | selected shared data (fonts, icons, locales, themes), read-only |
| `/etc/…` | selected configuration; `passwd` and `group` are generated and list only you |
| `/var/cache/fontconfig` | the system's font cache (names and paths of the fonts above), read-only |
| `/usr/local/lib`, `/opt/…` library folders | the library folders the system's loader searches outside `/usr` (from `/etc/ld.so.conf.d`, such as `/opt/cuda/lib64`), read-only; only below `/opt` and `/usr/local` |
| `/tmp`, `/var/tmp`, `$XDG_RUNTIME_DIR` | empty and private |
| `/` | read-only once the sandbox is set up |

### Processes

- **Namespaces:** user, PID, IPC, UTS and cgroup are always separate. The
  network is separate too, unless the app has full network access.
- **No privileges:** all capabilities dropped, and the sandbox ends when
  SAM's runner ends.
- **Never your terminal:** an app started without a terminal gets a new
  session, cut off from any terminal. An app started from a terminal gets a
  terminal of SAM's own instead (see [Terminal programs](#terminal-programs)).
  Either way it cannot type commands into your shell (`TIOCSTI`).
- **Clean environment:** cleared, then only safe variables are set.
- **Your ids:** the app runs with your user and group id, also with *Local
  network only*, where it would otherwise appear as root.

---

## Layers of protection

### Landlock

On by default where the kernel supports it. SAM's runner applies it inside
the sandbox, just before the app starts.

- Writes are allowed only in the app's home, its temporary folders and the
  folders granted read/write. Even if a mount were more permissive than
  intended, the kernel still blocks the write.
- Read-only folders inside the home (such as a read-only *Documents*) are
  protected by their read-only mount, which the app cannot change.
- With kernel 6.12+ (Landlock ABI 6), connections to abstract sockets outside
  the sandbox are blocked too, for example XWayland's
  `@/tmp/.X11-unix/X0`.

### Syscall filter

The **baseline filter** is on by default (`security.baseline_seccomp`). It
blocks:

- loading kernel modules, `kexec`, BPF and `perf`;
- keyrings, `userfaultfd`, handle-based opens and `syslog`;
- `io_uring`, a frequent source of kernel exploits (programs fall back to
  ordinary I/O);
- terminal injection (`TIOCSTI`, `TIOCLINUX`);
- namespaces and mounts, unless the app needs nested sandboxes.

It covers the x32 ABI as well. 32-bit system calls (`int 0x80`) end the
process, so 32-bit AppImages get the filter turned off in their
recommendation, and SAM says so.

The **strict filter** (experimental, opt-in) also blocks `ptrace`, access to
other processes' memory, `personality` and NUMA memory calls.

### Nested sandboxes are off by default

User namespaces inside the sandbox add kernel attack surface. Only apps whose
engine builds its own sandbox get them: Electron, CEF, Qt WebEngine and
WebKitGTK, as found by the dependency analysis.

### Wayland security context

Every app gets its own Wayland socket, created through the compositor's
security-context protocol (`wp_security_context_v1`) and marked with SAM as
the sandbox engine plus the app id. The compositor then hides privileged
functions from the app, as it does for Flatpak apps. On KDE Plasma these
include background clipboard access (`ext_data_control`) and fake input. The
launch log and `sam-jail doctor` say whether the desktop supports it.

*Privileged Wayland protocols* (advanced, High risk) gives the compositor's
own socket instead, for clipboard managers and screenshot tools. Desktops
without the protocol give every app all their functions; SAM says so.

### Sound without cameras

*Audio* gives the app only the PulseAudio socket (PipeWire's
`pipewire-pulse` on current systems). It can play and record sound, but it
cannot see cameras or screen-cast streams.

The raw PipeWire socket would reach those as well, because PipeWire limits
only Flatpak apps and treats every other program as trusted. So it is a
separate, advanced permission, *Direct PipeWire access* (High risk), for
the rare app that supports nothing else. Webcam and screen sharing don't
need it: their portals hand the app a PipeWire connection limited to what
you picked. The sandbox check confirms that the socket is absent.

### D-Bus and portals

- **D-Bus** goes through `xdg-dbus-proxy`. The app sees only the names it is
  allowed to talk to.
- **Its own name:** an app may own the D-Bus name of its ID (its menu
  entry's file name, or its window class, which GTK and Flutter apps use as
  their ID) when that is a reverse-DNS name, plus KDE's numbered variants
  (`org.kde.kdenlive-3`). Never: names of the D-Bus protocols
  (`org.freedesktop.*`, `org.gtk.*`, …), desktop services SAM treats as
  dangerous (KWin, Plasma, KRunner, GNOME Shell, …), and any service this
  computer starts on demand (its `dbus-1/services` files, e.g. KWallet).
  Taking such a name would let the app receive what is meant for the
  service. This is checked at every start, also for names you add.
- **Blocked names always win.** The proxy cannot make exceptions, so a
  wildcard allow entry that would also reach a blocked name is not used; the
  app page warns about it.
- **Portals** are reachable only for harmless functions: opening links,
  notifications, appearance settings, file dialogs, printing, email, inhibit
  and system monitors. Camera needs the webcam permission, screen sharing its
  own permission.
- **Blocked portals:** Screenshot, Background (autostart), DynamicLauncher,
  Trash, Wallpaper, RemoteDesktop, InputCapture, GlobalShortcuts, Location,
  Usb, Clipboard and Secret.
- **No Flatpak identity.** SAM never presents its apps as Flatpak apps, so
  portals see an ordinary program and the filter above is what limits it.

### This computer only

The app has no internet and no DNS. It can reach only the host ports listed
in `network.host_ports`. It needs `pasta` with `--splice-only`; an older
`pasta` is not used, and the app then gets no network at all, never more.

### Private `/dev/shm`

Each sandbox has its own shared memory folder.

---

## Full home access stays guarded

Granting the whole home, or a folder that contains it (such as `/home`),
still keeps these protections:

**Hidden unless you allow them explicitly:** `~/.ssh`, `~/.gnupg`, keyrings,
password stores, cloud credentials and browser profiles.

**Hidden whenever a grant would show them:** SAM's own folders
(configuration, data and unpacked apps, wherever they are). They are replaced
by an empty, throwaway folder, so an app cannot change its own permissions
or another app's files.

**Read-only, even with write access** (each of these can make your system
run a program the next time you log in or open a file):

| Kind | Examples |
|---|---|
| shell and session startup | `.bashrc`, `.profile`, `.pam_environment`, `environment.d` |
| autostart and services | `autostart`, `systemd --user`, D-Bus service files |
| programs on `$PATH` | `~/.local/bin`, `~/bin` |
| menu and default apps | menu entries, `mimeapps.list` |
| desktop scripting | KWin and Plasma scripts, file manager service menus |
| configs that run commands | git, vim, Neovim |

Missing folders from this list, and `.bashrc`, `.profile`, `.gitconfig` and
`mimeapps.list`, are created empty first so they can be protected. Files
whose mere presence changes behaviour (`.bash_profile`, `.zshrc`,
`.xinitrc`, `.xprofile`, `.vimrc`) are protected only if they exist.

---

## Terminal programs

Programs that run in a terminal (`Terminal=true` in their menu entry, such
as Helix, Neovim or appimagetool) share the terminal with the shell that
started them, unless something is in between. A program with your terminal
can type commands into your shell that run unsandboxed once it ends, keep
reading what you type after it seems to have ended, or send escape codes
that reach past the terminal. So SAM puts every app started from a terminal
(GUI apps too) on a pseudo-terminal of its own and passes the bytes on:

| What the app could try | What SAM does |
|---|---|
| Type into your shell (`TIOCSTI`, `TIOCLINUX`) | It only reaches its own terminal. The syscall filter blocks both as well, but this does not depend on it: a repair step can turn the filter off. |
| Change your terminal's settings, keep reading after it ends | It never gets your terminal. SAM restores your terminal's settings afterwards. |
| Read or change the clipboard (OSC 52, kitty's OSC 5522, iTerm2/WezTerm's OSC 1337) | Removed from its output. |
| Desktop notifications (OSC 9, 99, 777) | Removed. |
| Reach the terminal outside tmux (tmux passthrough) | Removed. |
| Set the window title, then ask for it back (`CSI 21 t`), so the terminal "types" text the app chose | The report request is removed; the title itself may be set. |
| Leave a query unanswered until it has ended, so the reply lands in your shell | Replies still queued when it ends are discarded. |

Inside, the app has no display, GPU or desktop services. It sees its private
home, the folders its settings allow (text editors get Documents by
default), and the files and folders you name when you start it
(`sam-jail run helix notes.txt`, `… helix .`), with the folder you started in
as its working folder. Named folders must be inside your home folder or on a
mounted drive; your home folder itself, the folders above it, sensitive
paths (keys, `~/.config`, `~/.local`) and files that make the desktop run
something (shell start files, menu entries, SAM's settings) are never shared
this way. Files it saves anywhere else stay in its private home. Each start
shows one line with what it can see, and the app's page shows the same
warning.

When the terminal window is closed (or SAM is asked to quit), SAM hangs up
the app's terminal, so the app ends, and finishes the launch normally.

**Not covered:** output that misleads you (a fake prompt, a link whose text
hides where it goes, a fake "sudo" password question: the app cannot run
`sudo`, but it can ask for your password), and security bugs in your
terminal program itself. 8-bit control codes are passed on unchanged, as
terminals in UTF-8 mode do not treat them as escape codes.

---

## No way out through system services

With full D-Bus access, `systemd-run` and `flatpak-spawn` could ask systemd
or Flatpak to start a program outside the sandbox. So inside every sandbox:

- `systemd-run` (and `run0`, a link to it) is replaced by a stand-in that
  runs the command directly, inside the sandbox. Apps whose start script
  uses `systemd-run` (such as KeePassXC) still start normally.
- `flatpak-spawn` refuses to run.

---

## The sandbox check

`sam-jail verify`, or *Check* in the window, proves that the settings apply.

1. It takes the same path as a real start, but SAM's runner starts a test
   program instead of the app, after Landlock and the syscall filter are in
   place.
2. The test program observes the sandbox from the inside: which folders it
   sees (by device and inode), where it can write (with invisible
   `O_TMPFILE` files), network routes, device nodes, reachable D-Bus names,
   `NoNewPrivs`, capabilities, user namespaces, and the seccomp and Landlock
   state.
3. SAM compares what it observed with what the settings promise.

With `security.check_before_launch`, SAM repeats the check before a start
whenever SAM, the app's settings, the security settings or the computer have
changed, and refuses to start on any failure.

---

## What SAM never trusts

An app controls what it prints, and an AppImage controls its own name and
metadata. SAM treats both as untrusted.

- **Sandbox errors** count only when Bubblewrap itself reports them (through
  `--json-status-fd`), never because of text the app printed. SAM never falls
  back to running an app without a sandbox.
- **Repair suggestions** based on app output are marked as such and always
  ask first. They never offer services that can act outside the sandbox
  (systemd, Flatpak, KWin/Plasma scripting, dconf, …) or protected places
  (`~/.ssh`, keyrings, the whole home). Adding such a D-Bus service by hand
  is rated *Dangerous* and asks first.
- **Names, descriptions and file names** are cleaned (no markup, no control
  characters, limited length) and shown as plain text, so an AppImage cannot
  inject formatting or remote images into SAM's window or notifications.
- **File types** a menu entry registers are filtered: never URL schemes
  (`https`, `mailto`, …), folders, programs or catch-all types.
- **What was enforced** (Landlock, seccomp) is reported by SAM's runner over
  a private channel that closes before the app starts. It appears in the
  launch log and on the app page.

---

## Network use by SAM itself

SAM goes online for one thing only: update checks. A check reads the update
source an AppImage names (GitHub, or the app's own server) and asks for the
first few kilobytes of the update description. It runs only when you click
*Check* or run `sam-jail updates`, or once a day when *Check for updates when
SAM opens* is on (off by default). It uses `curl`, HTTPS only (redirects
included), with a generic user agent; nothing about you or your apps is
sent, and nothing is downloaded or installed.

**Updating** (*Update Now*, `sam-jail update`) is the one time SAM
downloads a file, and only when you ask:
- The new AppImage comes from the address its update description names,
  over HTTPS. It is written next to the old file as a hidden
  `.….sam-download` file.
- It must match the published SHA-1 and be an AppImage.
- It must be signed like the installed version. A new or missing key stops
  the update unless you accept it.
- The old file moves into SAM's data folder, so you can go back.
- Downloading only the changed parts (zsync) reuses blocks of the old file
  and fetches the rest by HTTP range requests; the assembled file must still
  match the published SHA-1, or it is discarded and the whole file is
  downloaded instead.

SAM's own AppImage updates the same way (*Check for SAM Updates*), from
SAM's GitHub releases.

---

## Signatures

AppImages can carry a GPG signature and the signer's public key inside the
file. SAM checks the signature with `gpgv` in a throwaway keyring (your own
GnuPG folder is never used) and shows the result in the app's details:
*not signed*, *signed by …*, or a warning when the signature does not match
the file.

Because the key comes with the file, a valid signature shows that the file
is unchanged since signing, not who made it. What it adds is continuity:
SAM remembers the key, and when an updated AppImage is signed with another
key, or no longer signed, the app page shows a warning.

---

## Safe unpacking

SAM unpacks AppImages with its own reader and does not run them to do so.
Only when its reader fails and you agree does the AppImage unpack itself
(see the end of this section).
Unpacking happens inside a minimal Bubblewrap sandbox (the AppImage
read-only, only the target writable, no network, no privileges) whenever
Bubblewrap works; the unpacking log says whether it was isolated.

| Risk | What SAM does |
|---|---|
| paths with `..` | refused; parent folders are checked so writes cannot be redirected through links |
| setuid, setgid, sticky, world-writable | removed; files become `0755` or `0644` |
| links pointing outside the app | removed |
| device nodes, FIFOs, sockets | removed |
| huge or endless archives | file-count, size and time limits stop the unpacking and remove partial output |
| reading outside the sandbox | SAM itself reads only icon and desktop files, and never follows a link out of the app |

Running the AppImage's own `--appimage-extract` is a fallback that needs your
consent, and also runs in a sandbox.

---

## Risk levels

| Level | Permissions |
|---|---|
| **Low** | fonts, icons, locales, time zone (read-only), Wayland, filtered D-Bus |
| **Medium** | GPU, audio, folder access, all of `/usr` |
| **High** | network, X11, whole home read-only, full session D-Bus, webcam, SSH agent |
| **Dangerous** | whole home read/write, system D-Bus, raw devices (input, USB, ALSA), exposed keys |

An app's risk is the level of its riskiest permission. SAM shows the level
with the permission that sets it, for example *High risk · Network +1*. The
*Overview* group lists every permission above *Low*.

For scripts, the JSON output still has a weighted score (`risk.score`, at
most 100). The window does not show it, because a number next to the level
was easily misread.

---

## Known limitations

- **Icons are drawn outside the sandbox.** SAM copies an AppImage's icon
  (PNG, SVG or XPM, at most 10 MB) into its cache. The window and the menu
  draw it with the system's image libraries, as every AppImage integration
  tool does.
- **D-Bus filtering needs `xdg-dbus-proxy`.** Without it, an app with
  filtered D-Bus gets no session bus at all.
- **Abstract sockets** are blocked only on kernel 6.12+. On older kernels,
  XWayland's socket is reachable for apps with full network (X11
  authorization still applies).
- **No filtering by domain.** An app gets no network, only this computer
  (*This computer only*), or the full network.
- **File dialogs:** a file picked outside the folders an app may use is not
  visible to it, because the portal hands over the host path. Grant the
  folder, or open the file with the app (which grants that one file).
- **This computer only** forwards the app's own ports to this computer
  automatically, except privileged ports and well-known local services. List
  `network.app_ports` to restrict it further.
- **Hostname:** the sandbox keeps the computer's hostname, because changing
  it is blocked on some hardened systems.

---

## Reviews and tests

- [Security review 2026-11-10](reports/security-review-2026-11-10.md): every promise
  on this page checked by a breakout test, with the fixes it led to.
- The breakout tests run in CI on every push
  (`crates/sam-runner/tests/breakout.rs`).
