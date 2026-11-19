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

- **Namespaces:** user, PID, UTS and cgroup are always separate. IPC is
  separate too, except for apps with X11 access: X11's shared-memory
  extension needs the X server to see the app's shared memory (Flatpak
  does the same). X11 itself already exposes far more than that. The
  network is separate unless the app has full network access.
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
- With the whole home writable, Landlock allows writing all of it: the
  start files and other protected places inside are then guarded by their
  read-only mounts and by moving new ones aside (see *Full home access*),
  not by Landlock.
- If Landlock (or the syscall filter) cannot be applied at a start, for
  example because SAM's helper `sam-jail-run` is missing, the app still
  starts in its Bubblewrap sandbox, but never silently: the command line
  warns, the app's page says which layer was missing, and the overview marks
  the app *Protection missing* until a start has every layer again. The same
  holds for the Wayland security context: when the desktop offers it but
  making one fails, the app gets the normal Wayland socket, and the start is
  marked as missing that layer. A syscall filter that fails to load stops
  the start.
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
- namespaces and mounts, unless the app needs nested sandboxes;
- every socket type except local, internet and netlink (the kernel's status
  channel): no virtual-machine (`AF_VSOCK`, which no network setting
  stops), raw-packet or kernel-crypto sockets. Bluetooth sockets only with
  the *Bluetooth* switch. As in Flatpak, a refused type answers "not
  supported", so programs fall back;
- every call through the x32 ABI (a niche x86-64 mode with its own call
  numbers, which no AppImage uses).

32-bit system calls (`int 0x80`) end the process, so 32-bit AppImages get
the filter turned off in their recommendation, and SAM says so.

The same filter applies while SAM unpacks an AppImage, to its own reader
and to the AppImage's own extractor (`an_unpacking_tool_cannot_open_the_kernels_rarely_used_doors`).
`docs/syscalls-reviewed.txt` lists every kernel call with what the filter
does with it, and a test compares each line with the filter.

The **strict filter** (experimental, opt-in) also blocks `ptrace`, access to
other processes' memory, `personality` and NUMA memory calls.

### Nested sandboxes are off by default

User namespaces inside the sandbox add kernel attack surface. Only apps whose
engine builds its own sandbox get them: Electron, CEF, Qt WebEngine and
WebKitGTK, as found by the dependency analysis.

### Systems that switch user namespaces off

Some systems switch unprivileged user namespaces off on purpose (Debian's
`kernel.unprivileged_userns_clone = 0`, `linux-hardened`, or
`user.max_user_namespaces = 0`). Bubblewrap cannot build a sandbox there.
SAM never advises switching that setting back on: it would open user
namespaces to every program, and the computer would be less safe than
without SAM. It names the narrower way instead, a setuid Bubblewrap
(Arch: `bubblewrap-suid`; Debian: `dpkg-statoverride … 4755 /usr/bin/bwrap`),
which gives the right to Bubblewrap only, and says that this, too, changes
the system. SAM never changes it itself.

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

### Sound without cameras, and without loading code

*Audio* gives the app a PulseAudio connection to **SAM's sound relay**, not
to your sound server. It can play and record sound, but it cannot see
cameras or screen-cast streams, and it cannot load modules.

Your sound server's own PulseAudio connection lets every program load
modules into it, and the sound server runs outside the sandbox: an app with
only sound on made it load one (audit S-F1, proven 2026-11-18). PipeWire can
switch this off only for the whole server, which SAM does not change. So for
each start SAM runs a small second copy of PipeWire's PulseAudio server with
module loading off, connected to your PipeWire as one more client, and shows
the app only that one (`sound_never_loads_code_into_the_sound_server`).

The relay itself runs in a sandbox of its own: it sees the system's
programs, your PipeWire socket and its own folder, but not your home, SAM's
folders or the network. That matters on PipeWire before 1.2 (Ubuntu 24.04
LTS, Debian 12), which ignores the setting: there a module the app asks for
loads, but only inside the relay's sandbox, where it can reach none of your
files. `sam-jail doctor --contracts` checks both on your computer.

Where the relay cannot run (a sound server without PipeWire), the app has
no sound, and the start says why. An advanced switch, *Sound without SAM's
relay* (Dangerous), gives it the sound server's own connection anyway; SAM
then warns at every start.

The raw PipeWire socket would reach those as well, because PipeWire limits
only Flatpak apps and treats every other program as trusted. So it is a
separate, advanced permission, *Direct PipeWire access* (High risk), for
the rare app that supports nothing else. Webcam and screen sharing don't
need it: their portals hand the app a PipeWire connection limited to what
you picked. The sandbox check confirms that the socket is absent.

### D-Bus and portals

- **D-Bus** goes through `xdg-dbus-proxy`. The app sees only the names it is
  allowed to talk to.
- **Its own name:** an app may own the D-Bus name it really asks for. SAM
  learns it from the D-Bus filter's own record of what it refused (never
  from what the app prints) and allows it when nobody on this computer uses
  it: no program holds it right now, no installed app has that menu ID or
  one under it (a terminal's `org.gnome.Terminal`, say), it is no D-Bus
  protocol name (`org.freedesktop.*`, `org.gtk.*`, …), no desktop service
  SAM treats as dangerous (KWin, Plasma, KRunner, GNOME Shell, …), no
  service this computer starts on demand (its `dbus-1/services` files, e.g.
  KWallet, also through a wildcard) and no other SAM app's. If the app did
  not start without it, SAM starts it once more at once; the app's page
  shows the name, and names SAM did not allow with the reason
  (`an_app_gets_the_name_it_asks_for_only_when_nobody_uses_it`). A media
  player gets its own player's name (`org.mpris.MediaPlayer2.<player>`)
  the same way, with the media controls switch. SAM also allows the name
  of the app's ID from the start (its menu entry's file name, or its window
  class) and KDE's numbered variants (`org.kde.kdenlive-3`). Every name the
  app may own, also one you add, is checked again at every start; one an
  app installed since then or another SAM app has is left out, with a
  warning.
- **Blocked names always win.** The proxy cannot make exceptions, so a
  wildcard allow entry that would also reach a blocked name is not used; the
  app page warns about it.
- **Portals** are reachable only for functions that need you or show what
  happens: opening links, notifications, appearance settings, file dialogs,
  printing, email, inhibit and system monitors. Camera needs the webcam
  permission, screen sharing its own permission.
- **Links leave the sandbox, and can carry data.** A web link the app opens
  goes to your browser, which loads it with your network, even when the app
  itself has none: an app could put what it read into a link
  (`https://example.org/?data`). Mail links go to your mail program. Any
  other kind of link (`steam://`, `vscode://`, a program's own scheme)
  would start the program that handles it, so SAM's link helper has the
  portal ask first, with its app chooser
  (`links_to_other_programs_ask_first`; `sam-jail doctor --contracts`
  checks that the portal can). An app that calls the portal itself instead
  of the helper can still open such a link without the question: the D-Bus
  filter can allow or refuse the function, not look at its arguments.
- **Single functions and signals of services** (`dbus.session.calls`,
  `dbus.session.broadcasts`) count in the risk word: a function of a
  service that can act outside the sandbox (systemd, the desktop shell)
  makes it *Dangerous*, and a preset that adds one asks first.
- **Blocked portals:** Screenshot, Background (autostart), DynamicLauncher,
  Trash, Wallpaper, RemoteDesktop, InputCapture, GlobalShortcuts, Location,
  Usb, Clipboard and Secret.
- **No Flatpak identity.** SAM never presents its apps as Flatpak apps, so
  portals see an ordinary program and the filter above is what limits it.

### This computer only

The app has no internet and no DNS. It can reach only the host ports listed
in `network.host_ports`. It needs `pasta` with `--splice-only`; an older
`pasta` is not used, and the app then gets no network at all, never more.

The app's own ports (its web page, for example) are offered on this
computer's loopback addresses only, 127.0.0.1 and ::1: other computers on
the network cannot reach them, and a scan of your computer does not show
them. Ports of well-known local services are never taken over
automatically, so their clients cannot end up talking to the app: besides
databases, caches and local AI servers, also browser and Node.js debugging
(9222, 9229), X11 and PulseAudio over the network, VNC, Remote Desktop,
Docker and Kubernetes, Tor and other proxies, KDE Connect, Syncthing,
Steam and Discord (`NEVER_FORWARD_FROM_APP` in `netns.rs`;
`the_apps_ports_are_offered_on_this_computer_only`). An app that needs one
of them gets it only when you list it in `network.app_ports`.

### Private `/dev/shm`

Each sandbox has its own shared memory folder.

---

## Full home access: what stays guarded, and what does not

Granting the whole home, or a folder that contains it (such as `/home`),
still keeps these protections:

**Hidden unless you allow them explicitly:** `~/.ssh`, `~/.gnupg`, keyrings
and password stores (pass, KeePassXC, Bitwarden, 1Password, KWallet), cloud
and developer logins (AWS, Google Cloud, Azure, Kubernetes, Docker, GitHub
and GitLab command line tools, npm, PyPI, Cargo, rclone, `~/.netrc`, Git
credentials and others), mail and browser profiles (Thunderbird, Firefox,
LibreWolf, Chrome, Chromium, Brave, Vivaldi, Edge, Opera and others), and
the data of apps installed as Flatpak or Snap. The full list is in
`crates/sam-core/src/places.rs`.

**Hidden whenever anything would show them:** SAM's own folders
(configuration, data and unpacked apps, wherever they are), whether a
permission, a folder you open with the app or a path on its command line
would show them. They are replaced by an empty, throwaway folder, so an app
cannot change its own permissions or another app's files.

**Read-only, even with write access** (each of these can make your system
run a program the next time you log in or open a file):

| Kind | Examples |
|---|---|
| shell and session startup | `.bashrc`, `.profile`, `.bash_profile`, `.zshrc` and the other shell start and end files, `.pam_environment`, `environment.d`, `.xprofile`, `.xsession` |
| autostart and services | `autostart`, `systemd --user`, D-Bus service files |
| programs on `$PATH` | `~/.local/bin`, `~/bin` |
| menu and default apps | menu entries, `mimeapps.list` |
| desktop scripting | KWin and Plasma scripts, file manager service menus |
| configs that run commands | git, Mercurial, vim, Neovim, tmux, screen |

How these stay protected with the home writable:

- **Folders are created empty first** where an empty folder changes
  nothing: menu entries, autostart, `systemd --user`, `environment.d`,
  `~/.local/bin`, D-Bus services, the KWin, Plasma, fish, git, Neovim and
  tmux settings folders and file manager service menus; and the files
  `.bashrc`, `.profile`, `.gitconfig`, `mimeapps.list` and `user-dirs.dirs`.
- **The folders above them cannot be renamed** (`.config`, `.local`,
  `.local/share` and so on are mount points of their own), so an app cannot
  move `.config` away and fill a new one. The same holds for the folders
  above SAM's own folders, whatever grant shows them: with write access to
  `~/.local` alone, `~/.local/share` cannot be moved away to plant records
  where SAM keeps its own.
- **Parts of the home count too.** A writable folder that holds any of
  these places (`~/.config`, `~/.local`, a dotfiles folder that `~/.bashrc`
  links into, a user folder) gets the same protections as the whole home:
  the places are made first, locked, and watched while the app runs.
- **User folders are only what they are.** `user-dirs.dirs` says where
  Documents, Downloads and the others are. A folder set there to the home,
  a folder above it, a system folder, a key folder, a start place or a
  place inside SAM's folders is not shown, and the launch log says why (a
  user folder that holds one of SAM's folders is shown, with SAM's folder
  hidden inside it). A user folder
  that is a link is shown where it leads, with the link where the app looks
  for it.
- **Files named on the command line** are checked where they really lead:
  never a key or credential store, a start place (also through a link: a
  dotfiles folder holding the real `.bashrc` is not shared), or anything
  inside SAM's folders.
- **No grant undoes these protections.** They are added after every grant,
  so an extra folder (`/home`, `~/.local`, `~/.config`) cannot show a
  hidden key or make a start file writable again. Grants are checked where
  they really lead: a granted link (or a home folder that is itself a link)
  is followed, and the protections apply wherever the app sees these
  places.
- **Files whose mere presence changes behaviour** (`.bash_profile`, `.zshrc`,
  `.xprofile`, `.vimrc`, `.pam_environment` and the like) cannot be protected
  by a mount before they exist: making one would create the file. So SAM
  watches these places while the app runs: Linux reports every change in
  the folders that hold them (inotify), and SAM looks at once. Whatever the
  app created in one of these places, and whatever replaced a link to one of
  them, SAM moves into `~/.local/share/sam/moved-aside/APP/` (with the time
  of the start) within moments and puts links back; it looks once more when
  the app ends. If SAM's folder cannot take it (another drive, a full disk),
  it is renamed in place to a name nothing reads, or deleted; if even that
  fails, the command line and the launch log say so in capitals. When Linux
  refuses to watch a folder while the app runs, that is said too, and the
  folder is still checked when the app ends. The command line, the launch log and the app's page say so.
  The watch costs nothing while nothing changes: it waits for Linux to
  report, without a timer.
  The same holds for `~/.ssh` and `~/.gnupg` when the app was not given them.
- **Key folders that are links** (dotfiles managed with `stow`, for example)
  are hidden where they point; **start files that are links** are locked
  where they point, and a replaced link is put back.

**What full home access does not cover.** With read and write access to the
home, an app can still change other files that programs outside the sandbox
read: settings of programs not in the table above, scripts in project
folders. SAM protects the places that make a computer run something by
themselves; it cannot know every program's settings. And a file the app
creates in a watched place exists for a moment (usually well under a second)
before SAM moves it aside: a program outside that reads it in exactly that
moment would see it. So full home access is meant only for apps you trust,
and SAM warns when you grant it.

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
| Program a function key (DECUDK) that types the app's text when you press it later in the shell | Removed. |
| Make the terminal read a file of yours (kitty's graphics, its file transfer), change its font or the folder it opens new tabs in | Removed. |
| Hide a code from the filter: a doubled escape, an escape inside another code, extra parameters, huge numbers, 8-bit control codes, a code split across reads or across its two output streams | The filter works from an allow-list: it reads the output as a terminal does and passes on only whole, known, harmless pieces (text, colours, cursor movement, screen modes, the title, links). Everything else is removed, including what is malformed or unknown. A test checks this against a model of a terminal written apart from the filter, with many thousands of random inputs (`nothing_past_the_filter_reaches_past_the_terminal`), and another starts a real terminal app in its real sandbox from a terminal and reads what arrives (`a_sandboxed_terminal_app_cannot_reach_past_the_terminal`). |
| Leave a query unanswered until it has ended, so the reply lands in your shell | SAM discards what the terminal still sends until it has been quiet for a moment (at most a second). |
| Leave mouse reporting, bracketed paste or the alternate screen switched on | Switched off again when the app ends. |

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
the app's terminal, so the app ends, and finishes the launch normally. An
app started from the menu is asked to quit when you log out (SAM passes the
request on, as `sam-jail stop` does) and has 10 seconds to save before its
sandbox is ended; the start is recorded as closed and leaves nothing behind
(`logging_out_closes_a_menu_started_app_properly`).

An app started with its input from a pipe or a file (`cat data.json |
sam-jail run jq .`, `< file`, a script), or with its output going to a
file or a pipe (`sam-jail run jq . data.json > out.json`), gets no terminal
of its own: the input goes to the app, and its output comes back
unchanged, byte for byte and as it arrives, so a command-line tool works in
a pipe as it would without SAM. With only the output redirected, it gets no
input from the terminal (give it with `<` or a pipe). Without a terminal of
its own it has none to type into; its output still passes the same filter
whenever it is shown in a terminal, and there requests the terminal would
answer are removed too, since the answer would reach your shell.

**What SAM itself prints** carries an app's text too: the name of its
file, its menu name, the lines of its log, the error line a failed start is
explained with, preset and release names. Every line SAM prints passes one
filter that keeps only text, line breaks, tabs and SAM's own colours, and
removes direction overrides and invisible characters, so a file named to
look like another cannot fool you
(`what_sam_prints_about_an_app_cannot_reach_past_the_terminal`). The code
check refuses any other way of printing
(`every_printed_line_goes_through_the_screen_filter`). Logs keep only the
text of what an app wrote, so `cat` on a log file is safe as well. In
`--json` output, these characters are written as `\u` escapes: the same
data, nothing a terminal acts on.

**Not covered:** output that misleads you (a fake prompt, a link whose text
hides where it goes, a fake "sudo" password question: the app cannot run
`sudo`, but it can ask for your password), and security bugs in your
terminal program itself. Images in the terminal (sixel, kitty's graphics)
are not shown for apps in SAM's sandbox.

---

## No way out through system services

With full D-Bus access, `systemd-run` and `flatpak-spawn` could ask systemd
or Flatpak to start a program outside the sandbox. So inside every sandbox:

- `systemd-run` (and `run0`, a link to it) is replaced by a stand-in that
  runs the command directly, inside the sandbox. Apps whose start script
  uses `systemd-run` (such as KeePassXC) still start normally.
- `flatpak-spawn` refuses to run.

This closes the two commands apps commonly use; it is not a wall. With full
D-Bus access an app can still talk to systemd and other session services
directly, which is why SAM rates full session bus access *Dangerous* and
gives apps a filtered bus by default.

---

## The sandbox check

`sam-jail verify`, or **Test** in the window, proves that the settings apply.

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
included), with a generic user agent and without reading a `~/.curlrc`
(where a setting could switch off certificate checks or send requests
elsewhere); nothing about you or your apps is sent, and nothing is
downloaded or installed.

**Updating** (*Update Now*, `sam-jail update`) is the one time SAM
downloads a file, and only when you ask:
- The new AppImage comes from the address its update description names,
  over HTTPS. It is downloaded and checked in SAM's own data folder, which
  no app can reach, never in the AppImage's folder, where another app could
  plant a link under the download's name or swap the file between the check
  and the move.
- It must match the published SHA-1 and be an AppImage.
- It must be signed like the installed version. A new or missing key stops
  the update unless you accept it. A signed update that was signed earlier
  than the installed version is an older version and is refused: whoever
  controls the download cannot hand out an old release with holes fixed
  since. For unsigned apps SAM cannot tell versions apart this way.
- A server cannot keep SAM busy or crash it: every request has a time
  limit, a download at most the published length (8 GiB without one),
  update addresses are never expanded as patterns, and working out which
  parts of the old file can be reused stops after a minute (the rest is
  downloaded).
- The old file moves into SAM's data folder, so you can go back; going back
  keeps the newer version, also when both have the same file name.
- The new file is put in place by renaming, or, across drives, by copying
  into a new file; SAM never writes through a link it finds there.
- The app keeps its sandbox. When the new version asks for more (another
  category, the network, a folder), the app page shows it, and nothing
  changes until you switch it on yourself.
- Downloading only the changed parts (zsync) reuses blocks of the old file
  and fetches the rest by HTTP range requests; the assembled file must still
  match the published SHA-1, or it is discarded and the whole file is
  downloaded instead.

SAM's own AppImage updates the same way (*Check for SAM Updates*), from
SAM's GitHub releases.

---

## Privacy

SAM keeps what it learns about you on your computer.

- **No telemetry.** SAM has no usage statistics, crash reporting or
  "phone home" of any kind. The only network traffic SAM itself makes is
  described above: update checks and updates, when you ask for them, and
  the daily check only if you switch it on
  (`update_checks_stay_off_unless_switched_on`).
- **What stays on your disk:** SAM's settings, the app records and, per app,
  the last 20 launch logs (Preferences → Diagnostics). A launch log holds
  what the app printed, which can include personal data; it never leaves your
  computer unless you send it, and older logs are deleted automatically
  (`the_newest_log_survives_pruning_within_one_second`). Logs and app
  records (which can hold values you gave an app, such as an API key) are
  readable by you alone, not by other people on the same computer
  (`grants_of_parts_of_the_home_never_reach_start_places_or_secrets`).
- **Your folders:** SAM looks into the folders you add and reads nothing
  there but the AppImages it lists. It also looks at the file names in your
  Downloads folder, to offer adding it when AppImages are waiting there;
  that stays on your computer.
- **Bug reports** (Diagnostics → *Copy a redacted bug report*, or
  `sam-jail report`) are made to be shared, so SAM removes what identifies
  you or gives access before you see the text: your home folder and other
  users' folders, your user name and the computer's name, email addresses,
  logins, query strings and the part after `#` in links, parts of a link
  that look like a key, `Authorization` and cookie lines and other named
  secrets (`token=`, `password:`, `"api_key":`), IP addresses, and the
  values of environment variables you gave an app
  (`bug_reports_hide_names_addresses_and_secrets`,
  `bug_reports_hide_tokens_in_every_shape`). An app's log stays inside its
  code block: its own text cannot end the block and add to the report
  (`a_log_cannot_break_out_of_its_code_block`). Read it once before you
  paste it anywhere: an app can print personal data SAM cannot recognize.

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

The signer is the key that `gpgv` itself reports for the signature it
checked (its `VALIDSIG` status line), never simply a key found in the file.
A file that carries more than one key is refused: `gpgv` accepts a signature
by any key it is given, so a second key could otherwise borrow the name of a
trusted one, for example SAM's public release key. Every GnuPG step has a
time limit of 20 seconds, and `sam-jail doctor` checks that the installed
GnuPG still names the real signer.

---

## Safe unpacking

SAM unpacks AppImages with its own reader and does not run them to do so.
Only when its reader fails and you agree does the AppImage unpack itself
(see the end of this section).
Unpacking happens inside a minimal Bubblewrap sandbox (the AppImage
read-only, no network, no privileges) whenever Bubblewrap works; the
unpacking log says whether it was isolated. The only writable place in it
is a fresh, empty folder for the unpacked files, never the app's folder
where SAM keeps its notes, the menu entry and the icon: an unpacking tool
tricked by a crafted image cannot leave links there for SAM to write
through. SAM itself writes those files without following links.

| Risk | What SAM does |
|---|---|
| paths with `..` | refused; parent folders are checked so writes cannot be redirected through links |
| setuid, setgid, sticky, world-writable | removed; files become `0755` or `0644` |
| links pointing outside the app | removed |
| a start file that names a program outside the app (`Exec=/usr/bin/…`, `../`) | never used as the app's entry point |
| named pipes and other special files | removed while unpacking; SAM's own reads refuse them without waiting |
| device nodes, FIFOs, sockets | removed |
| huge or endless archives | file-count, size and time limits stop the unpacking and remove partial output; a limit reached inside the unpack sandbox stops it too, without trying other tools or the AppImage's own unpacker |
| reading outside the sandbox | SAM itself reads only icon and desktop files, and never follows a link out of the app |

Running the AppImage's own `--appimage-extract` is a fallback that needs your
consent, and also runs in a sandbox.

---

## Risk levels

| Level | Words | Permissions |
|---|---|---|
| **Low** | Harmless | fonts, icons, locales, time zone (read-only), Wayland, filtered D-Bus, "This computer only", the app's own ports |
| **Medium** | Harmless | GPU, sound, folder access, all of `/usr`, nested namespaces, names the app may own, passed-through variables |
| **High** | Think twice | network, X11, whole home read-only, webcam, SSH agent, keyring, direct PipeWire, raw sound devices (ALSA), local services the app may reach, a passed-through variable that holds a secret, the syscall filter or Landlock switched off, single functions of a service |
| **Dangerous** | Dangerous | whole home read/write, full session D-Bus, system D-Bus, raw input and USB devices, exposed keys, raw Bubblewrap arguments, compatibility mode, sound without SAM's relay, a function of a service that can act outside the sandbox, and the network together with your home, keys or passwords (it can send what it reads) |

An app's risk is the level of its riskiest permission. SAM shows the level
with the permission that sets it, for example *High risk · Network +1*. The
*Overview* group lists every permission above *Low*. The window shows each
switch with the same word the assessment uses (a test compares them,
`every_switch_has_one_risk_word`).

**One rule for asking.** A change that adds anything rated *Think twice* or
*Dangerous* asks first, wherever it is made: a switch in the window, the
Permission Manager for several apps at once, a preset, or the command line
(`sam-jail set`, `profile set`, `group set` refuse it without `--yes`). The
rule is worked out from the settings themselves, so it holds even when the
window's list of permissions fails to load.

**Settings nobody has confirmed** do not start. SAM's recommendation is
partly chosen from what the app says about itself (its name and
description decide its category, and with that for example the network),
so an app added on the command line without `--accept` starts only after
`sam-jail review APP` or confirming its settings in the window.

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
  (127.0.0.1 and ::1 only) automatically, except privileged ports and
  well-known local services. Another local service that is not on SAM's
  list and starts after the app can find its port taken. List
  `network.app_ports` to restrict it further.
- **Hostname:** the sandbox keeps the computer's hostname, because changing
  it is blocked on some hardened systems.

---

## Reviews and tests

- [Security review 2026-11-10](reports/security-review-2026-11-10.md): every promise
  on this page checked by a breakout test, with the fixes it led to.
- The breakout tests run in CI on every push
  (`crates/sam-runner/tests/breakout.rs`).
- The audit of 2026-11-16 (an outside, automated code audit): its points
  were checked against the code; what held was fixed with a test, including
  a sandbox that outlived a killed launcher with "This computer only". See
  the changelog.

## For reviewers: where to start

An outside review is planned before the wide announcement. The question to
ask of each part is not *does it work* but *how can it fail in a way that
helps the app inside*. The parts where that matters most:

| Part | What it does |
|---|---|
| `crates/sam-runner/src/launch.rs` | prepares and starts a sandbox, its status pipes and the launch record |
| `crates/sam-runner/src/pty.rs` | the terminal relay and its escape-code filter |
| `crates/sam-runner/src/dbus_proxy.rs` | the filtered session bus |
| `crates/sam-runner/src/netns.rs` | "This computer only" through pasta |
| `crates/sam-runner/src/kernel.rs` | Landlock and the syscall filter, applied inside the sandbox |
| `crates/sam-sandbox/src/lib.rs` | the Bubblewrap command built from the settings |
| `crates/sam-core/src/permissions.rs` | the settings, their risk and the D-Bus rules |
| `crates/sam-intake/src/extract.rs`, `normalize.rs` | unpacking untrusted AppImages |
| `crates/sam-runner/src/updates.rs`, `zsync.rs`, `release_key.rs` | updates and their checks |
| every `unsafe` block | each carries a `SAFETY:` comment (enforced by a lint) |

The [threat model](threat-model.md) names the test behind each promise, and
the [test library](test-library.md) lists every test with what it proves.

