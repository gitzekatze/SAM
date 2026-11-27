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
| `$HOME` | the app's **private home** (`~/.local/share/sam/homes/<app>`), plus the folders you granted. Also shown, read-only: your fonts (`~/.local/share/fonts`, `~/.fonts`, `~/.config/fontconfig`) and, with *Host theme settings* (on by default), your desktop's look: the GTK, Qt and KDE settings (`~/.config/gtk-3.0`, `~/.config/gtk-4.0`, `~/.config/kdeglobals` and similar), icons and themes. The file chooser's bookmarks and server list in the GTK folders stay out, unless you grant their folder |
| `/opt/app` | the unpacked app, read-only |
| `/usr/lib`, `/usr/bin` | the system's libraries and programs, read-only (all of `/usr` with `advanced.host_runtime full` or compatibility mode) |
| `/usr/share/…` | selected shared data (fonts, icons, locales, themes), read-only |
| `/etc/…` | selected configuration; `passwd` and `group` are generated and list only you |
| `/var/cache/fontconfig` | the system's font cache (names and paths of the fonts above), read-only |
| `/usr/local/lib`, `/opt/…` library folders | the library folders the system's loader searches outside `/usr` (from `/etc/ld.so.conf.d`, such as `/opt/cuda/lib64`), read-only; only below `/opt` and `/usr/local` |
| `/tmp`, `/var/tmp`, `$XDG_RUNTIME_DIR` | empty and private |
| `/` | read-only once the sandbox is set up |

### Processes

- **Namespaces:** user, PID and UTS are always separate, and the cgroup
  namespace wherever the kernel has one (every kernel since 4.6; Bubblewrap's
  `--unshare-cgroup-try` leaves it shared on an older or restricted one). IPC is
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
- **Clean environment:** cleared, then only safe variables are set. The
  app's own variables (its AppImage variables, those passed through and
  those set in its settings) are set by SAM's helper for the app alone,
  once Landlock and the syscall filter are in place: the helper's own start
  never sees them, so a setting such as `LD_PRELOAD` or `LD_LIBRARY_PATH`
  cannot run the app's code before those layers. `$OWD` names the folder
  the app started from only when the app can see it; otherwise it is the
  app's home, where the app starts.
- **No inherited descriptors:** SAM's programs mark every open descriptor
  they inherited (a terminal's or a launcher's) close-on-exec before they
  start anything, so an app gets only its standard input, output and error
  (Flatpak does the same).
- **Private folders:** an app's private home, its own layer of a writable
  app folder and what SAM moved aside are readable by your user only
  (0700), launch logs by you only (0600), also when an older SAM made them
  readable for everyone.
- **Your ids:** the app runs with your user and group id, also with *This
  computer only*, where it would otherwise appear as root.

---

## Layers of protection

### Landlock

On by default where the kernel supports it. SAM's runner applies it inside
the sandbox, just before the app starts. Turning it off for every app in
Preferences asks first, as turning it off on one app's page does; so does
turning off the syscall filter (`turning_a_protection_off_for_every_app_asks_first`,
`tests/gui/flow-atspi.sh`). On the command line, `sam-jail config set` and
`config put` turn either off only with `--yes`
(`turning_a_protection_off_for_every_app_needs_yes`,
`putting_a_configuration_that_turns_a_protection_off_needs_yes`).

- Writes are allowed only in the app's home, its temporary folders and the
  folders granted read/write. Even if a mount were more permissive than
  intended, the kernel still blocks the write.
- Read-only folders inside the home (such as a read-only *Documents*) are
  protected by their read-only mount, which the app cannot change.
- With the whole home writable, Landlock allows writing all of it: the
  start files and other protected places inside are then guarded by their
  read-only mounts and by moving new ones aside (see *Full home access*),
  not by Landlock.
- If SAM's helper `sam-jail-run` is missing, so that Landlock and the
  syscall filter the app's settings ask for cannot be applied, or the
  desktop offers the Wayland security context but making one fails, SAM
  does not start the app. It says which protection is missing and why; you
  can start the app anyway for that one start (*Start anyway* on the
  notification, `sam-jail run --start-anyway`). Such a start runs in its
  Bubblewrap sandbox without that layer (without the security context, with
  the compositor's own socket), never silently: a start from the menu shows
  a notification while the app runs (with a button to the app's page), the
  app's page says which layer was missing, and the overview marks the app
  *Protection missing* until a start has every layer again. If Landlock
  itself cannot be applied by the kernel at a start, the app starts and is
  marked the same way. A syscall filter that fails to load stops the start.
- With kernel 6.12+ (Landlock ABI 6), connections to abstract sockets outside
  the sandbox are blocked too, for example XWayland's
  `@/tmp/.X11-unix/X0`. These sockets have a name but no file, and they
  belong to the network: an app with full network shares the computer's
  and could reach them, even with X11 off. SAM's helper reports this fence
  on its own (`abstract sockets: scoped` or `NOT scoped`), not folded into
  "Landlock partially enforced"; a start with full network that should
  have had it but did not is marked *Protection missing*
  (`a_missing_socket_fence_is_reported_when_the_start_relies_on_it`).
  Diagnostics warn when the kernel is older than 6.12, and the sandbox
  check tries to connect to the X server's and an abstract session bus's
  socket (`the_check_tries_the_hosts_abstract_sockets_the_app_must_not_reach`).

### Syscall filter

The **baseline filter** is on by default (`security.baseline_seccomp`). It
blocks:

- loading kernel modules, `kexec`, BPF and `perf`;
- keyrings, `userfaultfd`, handle-based opens and `syslog`;
- `io_uring`, a frequent source of kernel exploits (programs fall back to
  ordinary I/O);
- the NUMA memory calls (`mbind`, `move_pages`, `migrate_pages`,
  `get_mempolicy`, `set_mempolicy`, `set_mempolicy_home_node`: which memory
  banks of a many-processor server a program uses), as in Flatpak
  (`the_baseline_blocks_what_no_desktop_app_needs`);
- terminal injection (`TIOCSTI`, `TIOCLINUX`);
- namespaces, mounts and `chroot`, unless the app needs nested sandboxes
  (Chromium's own sandbox uses `chroot`; `fchroot`, which newer kernels
  have and the C library has no number for yet, needs the same right,
  which an app without nested sandboxes lacks): also
  `clone` into a new user namespace, and `clone3`, whose flags no filter
  can read, answers "not implemented" so programs fall back to `clone`, as
  in Flatpak (`without_nested_sandboxes_clone_cannot_make_a_user_namespace`);
- every socket type except local, internet and netlink (the kernel's status
  channel): no virtual-machine (`AF_VSOCK`, which no network setting
  stops), raw-packet or kernel-crypto sockets. Bluetooth sockets only with
  the *Bluetooth* switch. As in Flatpak, a refused type answers "not
  supported", so programs fall back. The same limit holds for pairs of
  sockets (`socketpair`, which makes its sockets the same way;
  `a_socket_pair_opens_only_the_listed_families_too`);
- every call through the x32 ABI (a niche x86-64 mode with its own call
  numbers, which no AppImage uses).

32-bit system calls (`int 0x80`) end the process, except for an app whose
start program is a 32-bit program: its filter answers 32-bit calls like
their 64-bit twins, so the filter stays on for 32-bit AppImages
(`a_32_bit_app_gets_its_calls_filtered_not_switched_off`). It used to be
switched off for them, which let any app choose to run without it by
making its start program 32-bit. One gap remains, as in Flatpak: a 32-bit
socket or socket pair made through the old `socketcall` call is not
limited to the listed types, because its type sits where no filter can
read it. Other apps keep ending at a 32-bit call, so a 64-bit program
cannot use the 32-bit doors.

The same filter applies while SAM unpacks an AppImage, to its own reader
and to the AppImage's own extractor (`an_unpacking_tool_cannot_open_the_kernels_rarely_used_doors`).
`docs/syscalls-reviewed.txt` lists every kernel call with what the filter
does with it, and a test compares each line with the filter.

The **strict filter** (experimental, opt-in) also blocks `ptrace` and the
calls that reach as far into another process (its memory, its descriptors,
its kernel objects: `process_vm_readv`, `process_vm_writev`,
`process_madvise`, `pidfd_getfd`, `kcmp`) and `personality`
(`the_strict_filter_blocks_every_call_its_text_names`).

Compared with Flatpak's default filter, the baseline also blocks
`io_uring`, BPF, `userfaultfd`, `kexec`, keyrings and the rare socket types
above, and leaves `ptrace`, `personality` (Flatpak refuses only values
other than plain Linux) and `modify_ldt` (Flatpak refuses it only for apps
without 32-bit support) to the strict filter or allowed: crash reporters
use `ptrace` on their own app's processes (the app's own process namespace
keeps it there), and Wine uses `modify_ldt` and `personality`. With nested
sandboxes, which Flatpak never allows, the namespace, mount and `chroot`
calls are open.

What no system call filter can block: `/proc/<pid>/mem` (another
process's memory) and `/proc/<pid>/fd` (its open files) are ordinary file
opens, allowed wherever the kernel's own tracing rules allow them. Every
app runs in its own process namespace (`--unshare-pid`), so it sees and
reaches only its own processes there, never the desktop's or another
app's, with or without the strict filter.

Graphics drivers built on Mesa use `kcmp` to check whether two handles of
the graphics card are the same. Under the strict filter that check is
refused, and some drivers print a warning about it; the app works as
before.

### Nested sandboxes are off by default

User namespaces inside the sandbox add kernel attack surface. Only apps whose
engine builds its own sandbox get them: Electron, CEF, Qt WebEngine and
WebKitGTK, as found by the dependency analysis.

### Room service: sandboxes that programs ask for

Some programs protect themselves by starting risky parts in a sandbox of
their own. The common case is GTK's image loader *glycin*: it decodes every
picture in a separate program locked in with Bubblewrap. Inside SAM's
sandbox that cannot work (Landlock forbids building sandboxes there), so
without help glycin would decode pictures with no sandbox at all, or the
app would crash.

**Room service** builds such a sandbox (a *room*) from outside, under one
rule: **no more than the app, no less than asked.**

- **The stand-in.** `bwrap` on the app's `PATH` is SAM's helper in a
  stand-in mode (`/run/sam/bin/bwrap`, a link to the helper: no script and
  no shell in between, which could leave a file of its own open; the
  computer's Bubblewrap version it answers to `--version` lies read-only
  beside it). It reads Bubblewrap's arguments
  inside the app's sandbox and sends a small fixed form, with the program's
  open connections (up to 253, as Bubblewrap passes them all), to SAM's
  launcher. Programs need no change.
- **The service** runs in SAM's launcher, which stays for the whole start.
  It trusts nothing the stand-in checked: every rule is enforced there.
  - A room shows only places of the app's own view (SAM's *floor plan* of
    the app), each at the same place as in the app, rebuilt as it is
    stacked in the app: the last mount over a place counts, and SAM's
    hiding mounts (`~/.ssh`, `~/.gnupg`, SAM's own folders, grants inside
    them) come along, so a room never sees what the app does not.
  - Every source is opened once when the app starts and shown by that
    handle; nothing else is found by name later, whatever the app renames.
    A source that exists but cannot be opened then (most likely when SAM's
    launcher has no descriptors left) is never left out quietly: no room is
    built that start, SAM warns when the app starts, and every refusal
    names the place.
    A path the request names below a source is opened without following
    any link (a link the app made could lead to a place it sees protected
    or hidden); such a request is refused. SAM's room helper then checks,
    before anything else, that every place shown by handle is exactly the
    file or folder SAM opened (same device and inode), reached without
    following any link, and still the root of the mount Bubblewrap made
    there, and ends the room otherwise. Ubuntu 24.04's Bubblewrap mounts a
    handle's path by name, so an app swapping a folder for a link while
    its room is built would put the link's target in the room. The
    mount-root rule is defence in depth against a program outside the
    app's sandbox (another program of yours) that can write the folder
    holding a place: once Bubblewrap mounted the place, such a program can
    move the place's name away (the mount goes with the name) and put the
    very same file back at its name through a second name made before (a
    hard link), so the room reaches the file no longer through the mount
    Bubblewrap made. Today a room loses nothing by that: Room service
    shows nothing inside a place the app can write, so the folder that
    then shows the file is read-only for the room as well. The rule keeps
    a room's places exactly as SAM built them should that change. The
    check is made once, when SAM's helper starts in the room: a move made
    later, while the room's program runs, is not detected (see
    [Known limitations](#known-limitations)). A
    kernel that does not say whether a place is the root of a mount (older
    than Linux 5.8) ends every room this way, with a message naming the
    cause. Device places are the one thing
    shown by name (Bubblewrap cannot show a device by handle): only as a
    whole, as SAM or the person named them, never a path below one (which
    could lead through a link the app made in `/dev/shm`); one missing
    when the app starts is left out, so a device plugged in later never
    reaches a room. One present then is remembered by what it is (device
    and inode, through links) and shown in a room only while it is still
    that device; SAM's helper checks in the room that it is. A device
    unplugged since, or another one now at its name (a keyboard at a game
    controller's number), is left out and recorded. A source on a drive
    that may be unmounted (any file
    system other than the root's and the home's, and anything under
    `/media`, `/mnt`, `/run/media`) is not held open, so the drive stays
    free to unmount: it is remembered by what it is and where it really is
    (every link resolved at the start), and opened again there for a room
    without following any link (one the app planted since, at a folder
    above it that it can write, is never followed by the launcher), which
    is refused unless it is still the same. Device and inode
    alone repeat (another stick at the same port has the same device number,
    and its top folder the same inode), so the drive's own identity is
    compared too: the mount's unique ID on Linux 6.8 and later, before that
    the file system's ID from `/dev/disk/by-uuid` (written when it was
    formatted). A drive with neither is compared by device and inode alone
    (see Known limitations). On Linux 6.8 and later, a drive unmounted and
    mounted again, also by an automounter after its idle time, is a new
    mount: rooms are refused its places until the app starts again (before
    6.8 the same drive, with its same file-system ID, is shown again).
  - Writable only where the app's place is writable (the app's own
    `--remount-ro` arguments count); devices only the app's, and working
    only where the request asked for working devices (the app's `/dev`
    asked for without them is the room's own, with the same few nodes not
    working); the network only when
    the app has the full network (its own Bubblewrap arguments may take it
    away) and the program does not take it away (as in Bubblewrap, the last
    of `--share-net` and `--unshare-net` or `--unshare-all` counts).
  - The room's own new things (folders, links, file systems) are made only
    in its own space, never inside a place shown from the app: Bubblewrap
    makes them before any protection applies and would follow a link the
    app left there onto the computer. The room's own links come last, after
    every mount, and nothing is made or shown at or behind one; a link may
    not name Bubblewrap's build stage (`/oldroot`, `/newroot`, `..`).
  - A place the app can write, and any device place, is shown only as a
    whole: nothing of the room (another place, a device, a hiding mount, a
    thing of its own) may lie below it, in any order. Such a request is
    refused: the app could exchange anything below that place for a link
    while the room is built. A place below a folder the app can write is
    shown only when every protected or hidden place inside that folder is
    pinned in the app (each folder above it a mount point of its own, as
    SAM makes them): otherwise the app could rename a folder holding one,
    and the room would show it from the computer, unhidden.
  - Writable only where the app can write: its mount and its Landlock rules.
    The room's own new places are writable inside its own file systems
    (`--tmpfs`); the room's root is read-only, so a folder made there is
    not, and an own place with a place of the app inside or over it gets no
    write rule of its own (writable only where the app's own rules reach;
    both recorded). A place asked for read-only keeps the
    app's hiding places and `/dev` inside it read-only too. SAM's room
    helper never follows a link to a Landlock rule's place.
  - The room's own links are made last, after every mount, and never
    inside a place shown from the app, whatever the order they were named
    in: Bubblewrap would follow a link in that place onto the computer.
  - A place of the app that cannot be shown means no room, never one
    without it (only a path the request named itself with `-try` may be
    missing); at most 2000 places per room.
  - Every restriction the program asks for in its Bubblewrap arguments is
    kept, and its resource limits (where lower than the launcher's) and
    its umask too, as Bubblewrap's children keep them (glycin caps its
    loader's memory this way). A syscall filter or Landlock the program
    put on itself, outside those arguments, does not follow it into the
    room: the room is built from outside, and gets SAM's own layers
    instead, never more than the app. Options that could give
    a room more than its app are refused by name (joining other namespaces,
    other users, extra powers, places or files from connections, options
    from a connection); an unknown option is refused too, never guessed.
- **SAM's layers in every room.** The room's first program is SAM's room
  helper, a static program (no loader, no library) that SAM passes in as
  data together with the room's rules, at a place where no request may
  make, show, change or enter anything, or point a link (`/.sam-room`),
  before anything of the request is laid out, and no request may lay
  anything over it: nothing the request shapes runs
  before SAM's layers, and nothing of it is read except the one link the C
  library's start-up asks for (`/proc/self/exe`), whose answer the helper
  never uses. It applies Landlock
  (the app's read and write rules, the room's own new places writable;
  abstract sockets outside the room blocked from Landlock 6 on), then
  SAM's syscall filter (never allowing nested sandboxes), confirms both,
  then loads the program's own filter and starts the program with exactly
  the environment it asked for (with `PWD` naming the room's folder, as
  Bubblewrap sets it), found as Bubblewrap finds it (its PATH, never the
  room's folder otherwise; a script without `#!` through the shell). The
  program's own filters are read before the report and loaded only right
  before it starts; the record names them as asked for, not as confirmed. The start record says what the helper
  confirmed; a room whose helper confirmed nothing is ended at once. A
  layer that does not load means no room; on a kernel without Landlock the
  room has what the app has, and the record says so.
- **Exceptions are for the app, not its helpers.** If Landlock or the
  filter is off for an app, or nested sandboxes are allowed, its rooms still
  get SAM's default layers.
- **Lifetime and limits.** A room ends when its stand-in goes, and every
  room ends with the app's start, before SAM waits for the app's output.
  A room always keeps Bubblewrap's own first process (`--as-pid-1` is not
  passed on): its parent-death signal, which the program cannot clear,
  ends everything in the room with SAM. At
  most 16 rooms of one app run at once (more wait), at most 64 connections
  are open at once (requests being read and rooms running; more are closed
  and recorded), and at most 512 passed connections are held. Everything
  held for rooms (passed connections, the places a room opens) is counted
  before it is taken, within what the launcher's own descriptor limit
  leaves free; a request beyond that is refused, so an app cannot run
  SAM's launcher out of descriptors.
- **Records.** The start record names each room's program, the layers its
  helper confirmed, what was capped, and every refusal of the service,
  including options the stand-in passes on because no room gets them (a
  request with an argument, a variable or a folder that is not text is
  refused as a whole, never passed on changed); a stand-in that cannot reach the service at all says
  so to its program only. Never the room's environment. Rooms are recorded
  apart from refusals, so a flood of refusals cannot push them out: at most
  500 rooms and 200 refusals per start, the rest counted.
- **Turning it off.** `advanced.room_service` (on by default) turns Room
  service off for one app. Then programs that build a sandbox of their own
  fail inside SAM, or run without it.
- **Builds.** SAM's room helper is built as a static program (needs the
  static C library when SAM is built). A SAM built without it has Room
  service off, and every start says so. So does a start with a Bubblewrap
  that cannot show places by handle (`--ro-bind-fd`, Bubblewrap 0.10 or a
  backport): no room could be built, so programs keep the computer's own
  Bubblewrap, as before Room service.

Not covered: programs that call `/usr/bin/bwrap` by its full path, and
other sandbox tools (Firejail, `flatpak-spawn --sandbox`). Chromium's own
sandbox is not Bubblewrap and has its own setting (*Nested sandboxes*).
Programs in apps with nested sandboxes allowed now get rooms too, so a
request with options a room refuses (see above) fails there where plain
Bubblewrap ran before: a room never gets more than the app.

The tests attack every rule from a real sandbox, under every network
setting, in an app with its exceptions on and in a shared home, including
hand-written messages past the stand-in, a folder exchanged for a link
while rooms are built, links planted to the computer's root, a room
layout that points the system's library folders into the app's own
folder, and the limits
(`room_service_builds_working_rooms_that_never_get_more_than_their_app`).
A second test generates many requests and compares each room with its app:
abilities, writes on the computer, and every mount with its read-only or
writable state, so it checks the service itself, not only Landlock behind
it (`every_room_is_a_subset_of_its_app`).

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
functions from the app, as it does for Flatpak apps. On KDE Plasma (KWin
6.8) these are background clipboard access (`ext_data_control`), fake
input, screen casting, the list of other windows, the lock screen overlay,
start-up feedback and security contexts of its own; a test compares what
the app gets with what an unsandboxed client gets. What a compositor hides
is its own choice, not SAM's: KWin still offers sandboxed apps a few
functions of the desktop shell, such as drawing a panel or overlay above
other windows (`zwlr_layer_shell_v1`, `org_kde_plasma_shell`) and changing
the screen layout (`kde_output_management_v2`). The launch log and `sam-jail doctor` say whether the desktop supports
it.

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
folders or the network, and nothing in it can make a user namespace of its
own (`nothing_in_the_sound_relay_can_make_a_user_namespace`). That matters
on PipeWire before 1.2 (Ubuntu 24.04
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
- **Desktop services reach only their own objects.** The filter gives a
  program's unique name (`:1.10`) the rules of every name it holds, and one
  program often holds many: on KDE Plasma 6, plasmashell runs the
  notification service and also Klipper's clipboard history and the shell's
  script runner. So for the services SAM allows by default or through a
  switch (notifications, the tray watcher, the input methods' sandbox
  frontends, the screen saver, power management, the file manager) the app
  gets calls and signals on that service's own object paths only, which the
  filter checks for the unique name too. The keyring switch reaches its
  whole service, and any other name you allow yourself reaches the whole
  program behind it (see `dbus.session.deny` in the settings reference).
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
credentials in `~/.git-credentials` and `~/.config/git/credentials`, and
others), mail and browser profiles (Thunderbird, Firefox,
LibreWolf, Chrome, Chromium, Brave, Vivaldi, Edge, Opera and others), and
the data of apps installed as Flatpak or Snap. The full list is in
`crates/sam-core/src/places.rs`. A folder becomes an empty one, and
anything else (a file, but also a named pipe a password manager feeds, or a
socket) an empty file. Where one is a link, it is hidden where the link
leads too, also inside a place kept read-only (`~/.git-credentials` a link
to `~/.config/git/credentials`): these are hidden after every other mount,
so nothing bound later shows them again
(`no_later_bind_shows_a_hidden_credential_again`,
`credentials_behind_links_pipes_and_sockets_stay_hidden`). Git's second
credential file is hidden on its own too, inside `~/.config/git`, which
SAM keeps read-only as a start place, so a read-only lock alone would let
the app read it (`git_credentials_under_config_git_stay_hidden`). Where
`XDG_CONFIG_HOME` or `XDG_DATA_HOME` names another folder inside the home
(`~/cfg`), the stores kept under `~/.config` or `~/.local/share` are hidden
there as well (`~/cfg/git/credentials`, `~/cfg/keepassxc`), as the start
places are locked there, and none of them is shared as a file named on the
command line (`credential_stores_follow_other_config_and_data_folders`).
Such a folder outside the home is shown only when you grant it, and SAM
does not hide the stores in it then.

**Hidden whenever anything would show them:** SAM's own folders
(configuration, data and unpacked apps, wherever they are, and the folders
where SAM keeps them unless told otherwise: `~/.config/sam` and
`~/.local/share/sam`, also below `XDG_CONFIG_HOME` and `XDG_DATA_HOME`
where those point inside the home, even while SAM keeps its own
elsewhere), whether a
permission, a folder you open with the app or a path on its command line
would show them. They are replaced by an empty, throwaway folder, so an app
cannot change its own permissions or another app's files. Where SAM keeps
its own folders is hidden wherever it leads. A folder by one of the names
above is hidden wherever it leads too, also when it is a link (another SAM
may keep its settings in `~/Sync/sam`, with `~/.local/share/sam` a link
there: with the whole home or `~/Sync` granted, the app does not see
them). It is kept read-only like the start places below instead only where
hiding it would cover too much: where it really is the home or a folder
above it, or where it leads elsewhere through a link and the app is shown
only folders inside the place it leads to, never that place itself. So an
app that plants `~/.config/sam` as a link to the home, or to `~/work` while
`~/work/project` is granted, cannot make SAM cover the home or that grant
with an empty folder. Where the app is shown the place such a link leads to
itself (the whole home, or exactly that folder), SAM cannot tell a planted
link from another SAM's folder kept there, and the place stays hidden, as
it always was.

The folders that `SAM_CONFIG_DIR` and `SAM_DATA_DIR` name are hidden in the
same way, also by an installed SAM, which ignores these developer variables
and never keeps anything there. An installed SAM that once kept its data
through `SAM_DATA_DIR=~/Games/sam` left its app records and the other apps'
private homes there; with `~/Games` or the whole home granted, the app does
not see them. Such a folder counts by the rules for the names above,
whatever its own name: it is not hidden where it really is the home or a
folder above it (`/` too), nor where it leads elsewhere through a link and
the app is shown only folders inside the place it leads to, so a variable
naming the home never covers the home with an empty folder. As for SAM's
own folders, the folders above such a folder cannot be renamed, so the next
start still finds it where the variable names it. SAM reads these two
variables only to hide more, never to keep its files there or to show
anything (`a_folder_a_switch_names_is_hidden_but_never_used_in_a_release_build`,
`a_folder_a_switch_names_is_hidden_unless_that_would_cover_too_much`,
`an_old_switch_folder_stays_hidden_from_a_real_sandbox`).

A link to the home by one of those names is kept read-only where the app
reaches it, and that is the whole home. So with `~/.config/sam` leading to
the home and the whole home granted read and write, the app sees the whole
home read-only: it cannot change any file there, Documents and the other
user folders and extra folders inside the home included, while keys,
credential stores and SAM's own folders stay hidden as always. Without the
whole home, an extra folder you allow the app to write inside the home is
shown read-only. The same holds for a start place (`~/.config/fish`, say)
that leads to the home. The start, the app page and `sam-jail info` say
which link leads to the home, and the sandbox check expects the home
read-only (`a_link_named_like_sams_folder_never_hides_the_home`,
`the_check_never_takes_the_home_for_sams_folder_through_a_link`). If you
did not make such a link, remove it: an app that can write `~/.config` may
have planted it.

**Read-only whenever anything would show them writable:** SAM's own
programs, which every menu entry runs outside the sandbox: SAM's AppImage
file and the `sam-jail-run`, `sam-jail` and `sam-jail-gui` next to the
running program, wherever you keep them (`~/Downloads`, `~/Applications`,
`~/.cargo/bin`). An app with write access to that folder can neither
change, rename nor delete them, nor rename the folders above them to put
its own program in their place: the next click on a menu entry would have
run its program unsandboxed.

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
  While another app runs that saw such a place missing, SAM leaves it
  missing: both watches move aside whatever appears there, as for
  `.bash_profile`.
- **The folders above them cannot be renamed** (`.config`, `.local`,
  `.local/share` and so on are mount points of their own), so an app cannot
  move `.config` away and fill a new one. The same holds for the folders
  above SAM's own folders, whatever grant shows them: with write access to
  `~/.local` alone, `~/.local/share` cannot be moved away to plant records
  where SAM keeps its own. It holds as well for the folders above the
  folders that `SAM_CONFIG_DIR` and `SAM_DATA_DIR` name: with
  `SAM_DATA_DIR=~/Games/sam`, `~/Games` cannot be renamed, which would
  carry the empty folder away and leave the old folder unhidden at the
  next start.
- **Parts of the home count too.** A writable folder that holds any of
  these places (`~/.config`, `~/.local`, a dotfiles folder that `~/.bashrc`
  links into, a user folder) gets the same protections as the whole home:
  the places are made first, locked, and watched while the app runs.
- **Extra folders inside a start place stay read-only.** An extra folder
  granted read and write that is a start place, lies inside one
  (`~/.config/fish/conf.d`) or is where one really is (a dotfiles folder
  that `~/.config/fish` links to) is shown read-only, with or without the
  whole home. It is checked as written, through links and with `..`, also
  below `XDG_CONFIG_HOME` and `XDG_DATA_HOME` where they point inside the
  home (start places under an `XDG_CONFIG_HOME` or `XDG_DATA_HOME` outside
  the home are not covered, a known gap older than this rule). The start
  notes it, and the app page and `sam-jail info` warn before the start;
  the folder's rating stays as it is. Such a folder is shown read-only
  where it leads also when it lies inside another folder the app may
  write (`conf.d` kept as a link into a granted `~/work`), and the folders
  between them cannot be renamed. SAM decides this once per start, on the
  place it binds. Any other extra folder below a folder the app can
  already change (another writable extra folder, a folder opened writable
  on the command line, the writable home) is not bound a second time: the
  app could otherwise turn a part of its way into a link to a start place
  after SAM looked. This holds against the app itself, not against a
  second program: another sandbox, or a copy of the app started with other
  settings (with `~/work` writable, say), that can already write a folder
  above a grant can swap a part of its way for a link in the short time
  between SAM's look and Bubblewrap's mount, and Bubblewrap follows that
  link, so a start place could be bound writable. This is a known gap,
  older than this rule (SAM had the same race before); such a program can
  also write there when a start place holds a link into a folder it can
  write, which SAM does not lock yet. Every other folder SAM binds by its
  path at an access of its own inside a folder the app can change (a
  read-only extra folder, a user folder bound at its own access such as
  Documents read-only in `~/Sync` under a writable home, and an extra
  writable folder inside a read-only one) has the folders above it pinned
  as well: a second start of the same app with the same settings (starts
  of one app may run side by side) cannot rename `~/Sync` away and put a
  link in its place while SAM starts the app again
  (`the_folders_above_a_folder_bound_at_its_own_access_are_pinned`,
  `the_folders_above_a_read_only_user_folder_cannot_be_renamed`). The
  same race stays open for a second program with other settings, as
  above, and for a folder that did not exist yet when the running copy
  started (it holds no mount there): swapped for a link between SAM's look
  and the mount, such a folder is bound where that link leads, and nothing
  checks it before the app runs. Checking each bound place inside the
  finished sandbox before the app starts, and binding through an open
  handle, which close the race, are planned.
  An extra folder inside SAM's own folders is not shown at all, also inside
  the folders named like them (`~/.config/sam`, `~/.local/share/sam`) while
  SAM keeps its own elsewhere, wherever they lead; inside one that SAM only
  keeps read-only because hiding it would cover too much (see *Hidden
  whenever anything would show them*), it is shown read-only. The sandbox
  check, the app page and a terminal app's start line take the same answer
  as the sandbox.
- **User folders are only what they are.** `user-dirs.dirs` says where
  Documents, Downloads and the others are. A folder set there to the home,
  a folder above it, a system folder, a key folder, a start place, a
  place inside SAM's folders, or `/tmp` and the folders in it where
  programs outside the sandbox listen (`/tmp/tmux-1000`, `/tmp/ssh-…`,
  `/tmp/.X11-unix`: connecting to a socket needs no write access, so even
  a read-only Downloads there handed them over) is not shown, and the
  launch log says why (a
  user folder that holds one of SAM's folders is shown, with SAM's folder
  hidden inside it). With the whole home shared, the launch log names such
  a folder only when it is refused for listening programs or for a link
  (below); a folder refused for another reason gets no note, no place of
  its own, and the app sees that place only where the home shows it, with
  the home's protections (key folders, SAM's own folders) as they are for
  the home. The app page and `sam-jail info` name a granted
  user folder that is not shown for listening programs or for a link
  (below) before the start, with the way out: a Downloads set to `/tmp`
  so that downloads clear themselves is not shown, the app saves into its
  own empty `/tmp` and what it saved is gone when it quits; set it to a
  folder of its own such as `/tmp/downloads`
  (`a_user_folder_the_sandbox_does_not_show_is_named_before_the_start`).
  A user folder
  that is a link is shown where it leads, with the link where the app looks
  for it, unless a link on its way lies in a folder the app may change in
  this start (the writable whole home, a writable user or extra folder),
  also inside a read-only folder there (Documents read-only under the
  writable home): the app could have put it there itself (`mv ~/Downloads
  ~/D; ln -s /tmp ~/Downloads`), also before that folder was set read-only,
  and a read-only Documents that is itself such a link is not mounted at
  all, so the home shows it writable
  (`a_link_inside_a_read_only_folder_in_the_writable_home_is_not_followed`,
  `a_link_planted_inside_a_refused_read_only_folder_is_never_followed`).
  `user-dirs.dirs` stays locked, but the folder it names
  did not. Such a folder is not shown where the link leads, the start names
  the link, and the sandbox check expects it not shown; SAM cannot tell
  such a link from one the person made, so a Documents kept as a link out
  of a writable home is not shown either: set `XDG_DOCUMENTS_DIR` to the
  real place instead
  (`a_user_folder_behind_a_link_the_app_could_plant_is_not_shown`,
  `a_user_folder_link_the_app_planted_never_shows_where_it_leads`,
  `a_user_folder_where_outside_programs_listen_is_not_shown`). A user folder is shown at its own access also with the whole home
  granted, inside the home or outside it, unless SAM refuses it as above
  (set to the home, a folder above it, a system folder, a protected place
  such as `~/.local/share/Documents`, or inside SAM's own folders): such a
  folder gets no place of its own, so a read-only Documents at
  `~/.local/share/Documents` is writable through a writable home, and no
  note names it. Otherwise Documents set to read-only is
  read-only under a writable home, so a start file kept as a link into it
  (`~/.bashrc` to `~/Documents/dotfiles/bashrc`) cannot be changed either,
  and one outside the home (`XDG_DOCUMENTS_DIR=/data/Documents`) is shown
  read-only or writable as set, where before it was not shown at all. The
  protections inside still come after it, so a start file in a writable
  user folder inside a read-only Documents stays locked
  (`a_read_only_user_folder_under_a_writable_home_is_read_only`,
  `a_start_file_linked_into_a_read_only_user_folder_stays_locked_with_a_writable_home`,
  `a_read_only_user_folder_outside_the_home_is_shown_with_the_whole_home`).
  Two user folders set to one place at different access (Music read and
  write, Pictures read-only, both `~/Media`) are shown at one access, the
  stricter one, whatever their order: `~/Media` is read-only, as
  "read-only means read-only" (owner decision of 2026-11-27). The mounts,
  the views, Landlock, the sandbox check and the start take this one
  answer, and the start, the app page and `sam-jail info` name the
  folders and the rule, with the way out: set each to read and write, or
  give them places of their own
  (`user_folders_at_one_place_take_the_stricter_access`,
  `the_check_expects_user_folders_at_one_place_at_one_access`,
  `user_folders_at_one_place_with_different_access_are_named`).
  An extra folder granted read and write inside a read-only user folder
  (`~/Documents/proj` with Documents read-only) is bound writable after
  it, as inside a read-only extra folder: SAM judges whether the app can
  already change it on the folder right above it, the read-only folder
  around it is a mount of its own the app cannot rename, and the folders
  above that are pinned (`a_write_grant_inside_a_read_only_user_folder_stays_writable`,
  `a_writable_extra_folder_inside_a_read_only_user_folder_stays_writable`).
  Not covered: a home
  kept behind a link (`/home/ann` a link to `/data/home/ann`). There SAM
  binds a user folder with an access of its own at its real place, as it
  binds extra folders, while the app still reaches it through the home at
  the home's access, and the sandbox check reports this.
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
- **Extra folders are rated where they lead.** `.`, `..` and doubled `/`
  count for nothing, so `/.` is the whole computer and `~/..` the folder
  above the home, both *Dangerous*; a folder that holds the home counts as
  the home, and a relative path or one with `..` is *Dangerous* too
  (`a_path_with_dots_or_double_slashes_is_rated_where_it_leads`).
- **A folder hands over the programs listening in it.** Connecting to a
  socket file needs no write access, so even a read-only folder lets the
  app talk to the programs that listen there: `/tmp` holds the sockets of
  tmux, SSH connections and the X server (without systemd also the session
  bus and the sound server), and a tmux socket runs commands
  outside the sandbox. A grant of `/tmp`, or of those places in it, is
  rated *Dangerous* and warned about
  (`a_grant_of_tmp_or_its_listening_places_is_dangerous_even_read_only`).
- **Extra sockets** (`sockets.custom`) are passed in from where their links
  lead. One reached through a link in a folder the app may change is left
  out (the app could have made that link, to the session bus or another
  program's socket), and so is one whose link leads to a socket SAM rates
  *Dangerous* (Docker, the system or session bus, the sound server's own
  socket, a key agent) unless the name you listed is rated *Dangerous* for
  the same reason (Docker, Podman and containerd count as one, so
  podman-docker's `docker.sock` may lead to Podman)
  (`an_app_cannot_turn_its_extra_socket_into_a_link_to_another_one`,
  `an_extra_socket_is_passed_in_only_as_dangerous_as_its_name`,
  `a_docker_socket_may_lead_to_podman_but_not_to_the_bus`). One
  that lies below a folder the app may change is left out too: SAM checks
  the socket before the start and Bubblewrap takes it by name a moment
  later, so a running copy of the app could swap it in between
  (`an_extra_socket_in_a_folder_the_app_can_change_is_not_passed_in`).
  Not covered: another app with its own access to that folder.
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
- **What SAM watches is kept on disk** while the app runs, in
  `~/.local/share/sam/home-watch/` (one record per launch, which no app can
  see). A launch that starts while another watched app runs takes over
  what that launch saw at its start, not what is there now: a link an app
  planted meanwhile is never taken for yours and put back. If SAM's
  launcher is ended before its last look (killed, or a crash), the next
  time SAM looks at the running apps (the window, `sam-jail stop`, any
  start) it takes that look and writes what it moved into that launch's
  log. A record from before the computer was restarted is dropped without
  that look.
- **Key folders that are links** (dotfiles managed with `stow`, for example)
  are hidden where they point, also when only the folder they point into is
  granted (`~/.gnupg` a link to `~/Sync/gnupg`, and `~/Sync` granted);
  **start files that are links** are locked where they point, and a
  replaced link is put back.
- **Links are followed as the app follows them.** Each protection is
  mounted where the app reaches the place, never through a link: with
  `~/.config` a link (to `~/dotfiles/config` or to another drive), apps
  start as usual, and a folder granted read-only that the link leads into
  stays read-only. With the home itself kept behind a link (`/home/u` a
  link to `/data/u`), a link that names the home's real path
  (`/data/u/dots/config`) is covered where the app reaches that place:
  under the home's own name.

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

Asking an app to quit (Close, `sam-jail stop`, logging out) reaches only
the app's own processes inside its sandbox, chosen by where they run, not
by their names. SAM's helpers are never asked: pasta ("This computer
only") would quit at once and end the whole sandbox with it, with no time
to save (`closing_a_this_computer_only_app_gives_it_time_to_save`). An app
that does not quit within the 10 seconds is ended, and SAM still finishes
its launch: the last look at the start places, the record and the log
(`closing_an_app_that_ignores_it_still_finishes_its_launch`). Closing
waits for and signals only the launches running when it began, each
through a handle on that very process (a pidfd, on Linux 5.3 and later),
so a launch started meanwhile is left alone and a process that got an
ended launcher's process number is never hit
(`a_launch_started_while_closing_is_left_alone`). It never signals SAM's
own program or the program that started it, and a launch's lock reached
through a link never counts
(`sams_own_program_and_its_parent_are_never_signalled`,
`a_lock_reached_through_a_link_is_never_taken`).

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
  uses `systemd-run` (such as KeePassXC) still start normally. Where
  `systemd-run` is itself a link, the stand-in covers the file it leads to
  (`stand_ins_cover_the_real_tool_also_behind_a_link`).
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
  `--json-status-fd`), never because of text the app printed. One exception:
  when the program SAM started ends with code 126 or 127, the codes shells
  and the system's loader use for "cannot be run" and "not found", SAM reads
  the start as failed in the sandbox (a library or program the app needs is
  missing there), marks the app as not working and suggests repair steps.
  An app can use this only to make itself look broken: the message is SAM's
  own, and every repair step asks first. SAM never falls back to running an
  app without a sandbox.
- **Repair suggestions** based on app output are marked as such and always
  ask first. They never offer services that can act outside the sandbox
  (systemd, Flatpak, KWin/Plasma scripting, dconf, terminals that run any
  command they are sent such as GNOME Terminal and Konsole, …) or protected places
  (`~/.ssh`, keyrings, the whole home). Adding such a D-Bus service by hand
  is rated *Dangerous* and asks first.
- **Names, descriptions and file names** are cleaned (no markup, no control
  characters, limited length) and shown as plain text, so an AppImage cannot
  inject formatting or remote images into SAM's window or notifications.
- **File types** a menu entry registers are filtered: never URL schemes
  (`https`, `mailto`, …), folders, programs or catch-all types.
- **An app's name never picks the app a command means.** `sam-jail set vlc …`
  changes an app only when `vlc` names that one app alone, by any rule (an
  ID prefix, its name, part of its name): an AppImage named `vlc` next to
  "VLC media player" makes the command fail with both IDs, instead of
  taking the app whose name matches exactly
  (`an_apps_own_name_never_captures_a_reference_to_another_app`).
- **Links the window opens** are https pages only, for an app's update and
  for SAM's own (`only_an_https_release_page_is_opened`).
- **What a question was about** is what is applied: the window asks about a
  preset, then applies it with its fingerprint, and a preset changed while
  the question was open is refused
  (`a_preset_changed_after_the_question_is_not_applied`).
- **What was enforced** (Landlock, seccomp) is reported by SAM's runner over
  a private channel that closes before the app starts. It appears in the
  launch log and on the app page.
- **Programs in your home.** The programs SAM itself runs (Bubblewrap,
  pasta, the D-Bus proxy, the unpack tools, GnuPG, its own launcher) run
  outside the sandbox. SAM takes each from `$PATH`, but only a copy that
  you cannot change: neither the file nor any folder on its way may belong
  to you or be writable for you. A copy in `~/.cargo/bin`, `~/go/bin` or
  `~/.nix-profile/bin`, where an app with write access to your home could
  have put it, is skipped (`sam_never_runs_a_helper_the_user_can_change`).
  For the same reason the window runs only the `sam-jail` next to itself,
  and menu entries name SAM's launcher by its whole path, so the desktop
  never looks it up on `$PATH`. A newer helper you installed in your home
  yourself is not used; install it for the whole system instead.
- **Developer variables.** `SAM_CLI` and `SAM_RUN` (another `sam-jail` or
  `sam-jail-run` for the window), `SAM_LOCALE_DIR` (another folder of
  translations), `SAM_DBUS_LOG` (a log of every D-Bus call) and the test
  hook `SAM_TRUST_TOOLS_IN` (a folder of stand-in tools SAM may run although
  you own them) work only in developer builds. A release build ignores
  them (the window takes SAM's programs next to it or, without them, a
  copy on `$PATH` you cannot change), so a forgotten developer setting, or a variable something else put
  into your desktop's environment, never makes the window run another
  program outside any sandbox, makes SAM run a tool you (and so every app)
  can change, gives SAM's questions another wording, or writes every app's
  D-Bus calls into a file. Neither the release profile nor a packaging
  recipe turns on debug assertions, which would make a release build read
  them (`release_builds_never_turn_on_debug_assertions`,
  `a_release_build_ignores_developer_variables`,
  `an_installed_window_ignores_a_program_named_in_its_environment`,
  `a_release_build_trusts_no_folder_of_test_tools`,
  `a_release_build_ignores_a_translation_folder_from_the_environment`,
  `a_release_build_keeps_no_dbus_log`).

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
downloaded or installed. Only the AppImage SAM unpacked is checked: SAM
reads the file once, compares its checksum with what it unpacked last and
takes the update address from exactly the bytes it compared. A file
replaced outside SAM (for example by another app with access to that
folder) is not checked, and no server is asked, because its update address
could carry that app's data out to a server of its choice; the app page
says that the file changed outside SAM. Use *Unpack Again* and look at the
app first. Anything that is not a plain file of the unpacked size is not
read at all, and an app SAM has not unpacked yet is not checked.

**Updating** (*Update Now*, `sam-jail update`) is the one time SAM
downloads a file, and only when you ask:
- SAM updates only the AppImage it unpacked. It first copies the installed
  file into its own data folder and compares it with what it unpacked last;
  a file replaced outside SAM (for example by another app with access to
  that folder) is not updated, because its update information would decide
  what then runs with this app's permissions. Use *Unpack Again* and look
  at the app first. The update address is read from that checked copy.
- The new AppImage comes from the address its update description names,
  over HTTPS. It is downloaded and checked in SAM's own data folder, which
  no app can reach, never in the AppImage's folder, where another app could
  plant a link under the download's name or swap the file between the check
  and the move.
- It must match the published SHA-1, be an AppImage, and be built for this
  computer's processor: a build for another one would leave the app unable
  to start. Among the files of a GitHub release, those that name this
  computer's processor are tried first.
- It must be signed like the installed version. A new or missing key stops
  the update unless you accept it. The refused download waits in SAM's own
  folder, and accepting it (*Update Anyway*, `sam-jail update --accept-key-change`)
  installs exactly that file, as long as it is still the published one;
  SAM never downloads again for that answer, so a server cannot hand out a
  different file under your yes. A yes counts once. Saying no (*Cancel*,
  `sam-jail update --decline-key-change`) deletes the waiting download; one
  never answered is deleted after a week, when updates are checked or run. When the installed version's signature
  could not be checked when it was added (GnuPG missing), SAM checks the
  installed file again now; a signature that still cannot be checked lets
  no other key, missing or bad signature through without a question. A signed update that was signed earlier
  than the installed version is an older version and is refused: whoever
  controls the download cannot hand out an old release with holes fixed
  since. When the record of the installed version has no signing time
  (checked before SAM kept it), SAM checks the installed file again to
  learn it; when a signing time still cannot be read, SAM cannot tell
  whether the update is older and asks first (*Signing Time Unknown*,
  answered like the questions above), and SAM's own update is refused. For unsigned apps SAM
  cannot tell versions apart this way.
- A server cannot keep SAM busy, crash it or fill the disk: every request
  has a time limit, and one update download ends within an hour in all,
  the partial download and the whole file after it together, each request
  getting at most the time left; a server that ignores range requests and
  sends more than the part asked for ends the partial download at its
  first answer, and the file is downloaded whole, once; SAM itself counts what a download writes and stops at
  the published length (8 GiB without one), whatever the server sends and
  whichever curl is installed; a release description may be up to 16 MiB,
  and a longer one is an error, never read as if complete; update addresses
  are never expanded as patterns; a description whose blocks are smaller
  than 512 bytes or number more than about four million is not used for a
  partial download (the file is downloaded whole); the old version is
  mapped, not read into memory; and working out which parts of the old
  file can be reused stops after a minute (the rest is downloaded).
- The new file keeps its published name only when that is a plain
  AppImage name (letters, digits and `._+-`, ending in `.AppImage`) that no
  other file in the folder has; otherwise it takes the old name. The update
  server chooses that name, and in a folder on the command search path
  (`~/.local/bin`) a name like `sudo` would replace a command, outside any
  sandbox.
- The checked copy of the old file is kept in SAM's data folder, so you can
  go back; going back keeps the newer version, also when both have the same
  file name. The earlier version goes back into the app's folder under the
  name it had, never to a place an app record names: a record changed
  outside SAM cannot make it a command in `~/.local/bin`. Going back checks
  the current file like an update does: SAM
  keeps a copy of it in its own folder (never the file itself, which
  another app could still hold under a second name) and accepts it only
  when it is what SAM unpacked, or what the update put there when
  unpacking that failed. A version kept by an older SAM (without its
  recorded checksum) asks for a review once it is back.
- The new file is put in place as a copy in a new file; SAM never writes
  through a link it finds there. The copy is written whole under a hidden
  name in the AppImage's folder and then renamed into place, so the folder
  always holds the complete old version or the complete new one, also after
  a crash or a power loss. The earlier kept version is deleted only once
  the app's record names the new one, and a failure before that (a full
  disk, a read-only folder) leaves the old AppImage, its record and the
  earlier kept version as they were. Going back works in the same order:
  before its record is saved, nothing in the backup folder is renamed or
  overwritten. An earlier version that an older SAM left aside is
  repaired when SAM can tell the files apart; otherwise going back and
  updating stop and say where both files are. From the moment the record
  names the new state until the version is unpacked, the record also says
  what is being put in place, and SAM keeps its own checked copy of it: a
  SAM stopped in between finishes the work at the app's next update or go
  back from that copy, never from a file in the AppImage's folder. A
  half-written copy left by a stopped SAM is removed at the app's next
  update, go back, relocation or removal. The sandbox is unpacked from
  the checked download in SAM's own folder, not from the AppImage's folder, where
  another app could swap the file in that moment; a file swapped there
  afterwards is noticed like any changed AppImage.
- The app keeps its sandbox. When the new version asks for more (another
  category, the network, a folder), the app page shows it, and nothing
  changes until you switch it on yourself.
- Downloading only the changed parts (zsync) reuses blocks of the old file
  and fetches the rest by HTTP range requests; the assembled file must still
  match the published SHA-1, or it is discarded and the whole file is
  downloaded instead. It is written to a new file in SAM's own folder,
  never through a link, and is on the disk before SAM uses it.

SAM's own AppImage updates the same way (*Check for SAM Updates*), from
SAM's GitHub releases. Like an app's update, it works from one copy it
takes of SAM's AppImage at the start, in SAM's own folder: the update
source, the old version's parts and the running version's signature come
from that copy. The file in your folder is only moved to the backups at the
end, kept for going back by hand. Only one
update of SAM runs at a time; a second one, from the window and the command
line at once, is refused until the first is done
(`sam_updates_itself_from_its_own_copy_even_if_the_file_is_replaced`,
`a_second_update_of_sam_is_refused_while_one_runs`).

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
key, or no longer signed, the app page shows a warning. A signature that
could not be checked (GnuPG missing) is no remembered key: SAM checks the
installed file again when it updates.

The signer is the key that `gpgv` itself reports for the signature it
checked (its `VALIDSIG` status line), never simply a key found in the file.
A file that carries more than one key is refused: `gpgv` accepts a signature
by any key it is given, so a second key could otherwise borrow the name of a
trusted one, for example SAM's public release key. Every GnuPG step has a
time limit of 20 seconds, and `sam-jail doctor` checks that the installed
GnuPG still names the real signer.

The key and the signature are the file's own bytes, written by whoever
made it, so GnuPG reads them inside the unpack sandbox, like every other
program that reads an AppImage: no network, nothing of the home, the
throwaway GnuPG folder as the only writable place, the baseline syscall
filter, and anything GnuPG leaves running (a gpg-agent) ends with the
sandbox (`gnupg_reads_an_appimages_key_and_signature_only_in_a_sandbox`).
Where SAM can build no sandbox, an added AppImage's signature counts as not
checked (an update then asks first); only SAM's own update is still checked
directly there, as before.

---

## Safe unpacking

SAM unpacks AppImages with its own reader and does not run them to do so.
Only when its reader fails and you agree does the AppImage unpack itself
(see the end of this section).
Unpacking happens inside a minimal Bubblewrap sandbox (the AppImage
read-only, no network, no privileges); the unpacking log says whether it
was isolated. Where Bubblewrap cannot run, or SAM's `sam-jail` is not next
to the program, SAM refuses to unpack and says which of the two is
missing, whatever its program is called, so a package that renames SAM's
programs cannot make it unpack without a sandbox
(`a_release_build_of_any_name_never_unpacks_without_a_sandbox`). Only a
developer build of a program that is not SAM's, such as a test, unpacks
in its own process. The only writable place in it
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
| huge or endless archives | file-count, size and time limits stop the unpacking and remove partial output; a limit reached inside the unpack sandbox stops it too, without trying other tools or the AppImage's own unpacker. They hold for every unpacking program while it runs (SAM's reader, `unsquashfs`, `bsdtar`, `dwarfsextract`, the AppImage's own unpacker): SAM counts the files it wrote as it goes, also in folders the image makes unreadable, and stops it once it passes a limit, and the kernel lets no single file grow past the size limit (`every_unpacking_tool_meets_the_limits_while_it_runs`). The partial output is removed, folders nobody may enter included (`an_unpack_box_with_locked_folders_is_removed`). The AppImage's own unpacker is the AppImage's code: it can hide what it writes from the count (a file deleted while it keeps it open still takes space), so for it the time limit, the size limit per file and the stop at a full disk are what hold |
| an archive built to use up memory | every unpacking program may use at most `extraction.max_memory_mb` (4 GiB by default) of memory; SAM's reader reaching it stops the unpacking like a limit |
| a full disk | SAM stops at once, removes what was unpacked and says the disk is full; it does not try the next tool or offer the AppImage's own unpacker (`a_full_disk_in_the_unpack_sandbox_stops_unpacking`) |
| replacing the earlier unpacked app | the new one takes its place in one step, or the old one stays (`a_failed_swap_keeps_the_old_app`) |
| reading outside the sandbox | SAM itself reads only icon and desktop files, and never follows a link out of the app |

Running the AppImage's own `--appimage-extract` is a fallback that needs your
consent, and also runs in a sandbox.

Adding an AppImage and *Unpack Again* first copy the file into SAM's own
data folder, reading it once; its checksum, its signature and what is
unpacked all come from that copy. Another program with access to the
AppImage's folder can no longer swap the file between SAM's check and the
unpacking, so SAM never records one file and unpacks another
(`what_is_unpacked_is_what_sam_checked_even_if_the_file_is_swapped`). A
file swapped there afterwards is noticed like any changed AppImage. Moving such a
file elsewhere does not pass it off as the app's own: SAM follows a moved
AppImage only when its content is what SAM unpacked for the app; another
file is added as an app of its own
(`a_swapped_appimage_moved_elsewhere_is_not_taken_for_the_apps_own_file`).
Data kept when a sandbox is removed likewise goes back only to the
AppImage SAM unpacked
(`kept_data_goes_back_to_the_unpacked_file_after_a_swap_was_seen`).

Nothing in an unpack sandbox can make a user namespace of its own
(Bubblewrap's `--disable-userns` and the syscall filter): one would give
the program inside full rights over a fresh network namespace, the usual
way into kernel bugs
(`nothing_in_the_unpack_sandbox_can_make_a_user_namespace`).

**Before you agree to anything.** The overview shows the name and icon of
every AppImage in the folders SAM searches, so it reads them before anyone
chose to trust them. That reading happens in the same kind of sandbox,
with at most 15 seconds and 1 GiB of memory: an image crafted to make the
reader hang, run out of memory or crash ends only that sandbox
(`a_reader_gone_wrong_comes_to_nothing`,
`the_overview_reads_names_inside_a_sandbox`). Where no sandbox can be
built, SAM shows only the file name. Icons are taken only as PNG of at most
1024×1024 pixels (read from the header, before anything decodes them) or
small SVG, at most 1 MiB; XPM is not taken. The format is read from the
file's start only: a PNG starts with the PNG signature, and an SVG is text
whose first element is `<svg`, so an XPM, ICO or other image that merely
contains the text `<svg` is not installed as an SVG for the desktop to
decode with its own loader (`only_a_real_svg_counts_as_one`). The window
checks this again before it shows an icon
(`only_icons_that_are_safe_to_decode_are_taken`).
The preview and the unpacked app use the same desktop file
(`preview_and_unpack_take_the_same_desktop_file`).

---

## Risk levels

| Level | Words | Permissions |
|---|---|---|
| **Low** | Harmless | fonts, icons, locales, time zone (read-only), Wayland, filtered D-Bus, "This computer only", the app's own ports |
| **Medium** | Some access | GPU, sound, folder access, all of `/usr`, nested namespaces, names the app may own, passed-through variables |
| **High** | Think twice | network, X11, whole home read-only, webcam, keyring (also a password service allowed by name), direct PipeWire, raw sound devices (ALSA), local services the app may reach, a passed-through variable that holds a secret, the syscall filter or Landlock switched off, single functions of a service |
| **Dangerous** | Dangerous | whole home read/write, full session D-Bus, system D-Bus, raw input and USB devices, exposed keys, raw Bubblewrap arguments, compatibility mode, the SSH agent and, as an extra socket, a key agent at its usual places: GnuPG's agent (`S.gpg-agent`), OpenSSH's (`~/.ssh/agent/…` and `/tmp/ssh-…/agent.…`), `ssh-agent` in a name (systemd's, Bitwarden's), `openssh_agent`, GNOME Keyring's (`keyring/ssh`), gcr's (`gcr/ssh`) and 1Password's (`~/.1password/agent.sock`) (the app can decrypt, sign or log in to other computers as you), sound without SAM's relay (also the sound server's socket as an extra socket), a service that can act outside the sandbox allowed by name or one of its functions (a terminal that runs any command it is sent included), a wildcard over the portal, an extra folder that is a system folder, the home, a folder above it or `/tmp` (however it is written), and the network together with your home, keys (a key agent included) or passwords (it can send what it reads) |

An app's risk is the level of its riskiest permission. SAM shows the level
with the permission that sets it, for example *High risk · Network +1*. The
*Overview* group lists every permission above *Low*. The window shows each
switch with the same word the assessment uses (a test compares them,
`every_switch_has_one_risk_word`). Each level has words of its own, the same
in the window and on the command line (`each_risk_level_has_words_of_its_own`,
`the_window_names_each_risk_level_in_its_own_words`,
`a_medium_app_reads_some_access_in_list_and_info`): *Medium* reads *Some
access*, not *Harmless* like *Low*, and `sam-jail list --risk harmless`
selects Low apps only (`--risk some-access` selects Medium). The words do
not change when SAM asks first: that stays from *Think twice* on.

**One rule for asking.** A change that adds anything rated *Think twice* or
*Dangerous* asks first, wherever it is made: a switch in the window, the
Permission Manager for several apps at once, a preset, or the command line
(`sam-jail set`, `profile set`, `group set` refuse it without `--yes`). A
first-run hint rated *Think twice* or *Dangerous* asks in the same way
(`sam-jail hints APP --apply ID` and `repair APP --apply ID` refuse it
without `--yes`), and a hint or repair step is never rated below what
applying it adds. The rule is worked out from the
settings themselves, so it holds even when the window's list of
permissions fails to load. Raw Bubblewrap arguments count by what they
say: other arguments ask again, even when the app already had some.

**Settings nobody has confirmed** do not start. SAM's recommendation is
partly chosen from what the app says about itself (its name and
description decide its category, and with that for example the network),
so an app added on the command line without `--accept` starts only after
`sam-jail review APP` or confirming its settings in the window. Changing
one switch (`sam-jail set`, a group change, a repair step, a switch in the
window) confirms nothing about the others; applying a preset or setting the
whole profile (`profile set`) replaces them all and does. The check before
adding (`sam-jail verify FILE`) is not held back by this: it runs only
SAM's stand-in and test program with the settings shown, never the app's
own code (`verify_checks_an_appimage_without_a_sandbox`).

For scripts, the JSON output still has a weighted score (`risk.score`, at
most 100). The window does not show it, because a number next to the level
was easily misread.

---

## Known limitations

- **Icons are drawn outside the sandbox.** SAM copies an AppImage's icon
  (PNG or SVG, checked as above, at most 1 MiB) into its cache. The window and the menu
  draw it with the system's image libraries, as every AppImage integration
  tool does.
- **Some swapped drives before Linux 6.8.** Room service tells a drive
  put in after the app started from the one the app was shown by its
  unique mount ID (Linux 6.8+), before that by its file-system ID. A
  network or FUSE mount, or a file system on no single block device (such
  as btrfs), has no file-system ID SAM can match there; and copies of one
  stick, or sticks written from the same image, share theirs. Such a drive
  mounted at the same place with the same device and inode numbers could
  be shown in a room on an older kernel.
- **A room's place moved after the room started.** SAM's room helper
  checks once, when it starts in the room and before the room's program
  runs, that every place is still the root of the mount Bubblewrap made
  there. A program outside the app's sandbox that can write the folder
  holding a place can move the place away later, while the room's program
  runs, and put the same file back at its name; the room then reaches the
  file without that mount, and nothing detects it. Since a room shows
  nothing inside a place the app can write, the file is then still shown
  read-only. Such a program can usually change the file directly anyway.
- **Rooms need Linux 5.8 or later.** SAM's room helper checks every place
  of a room with `openat2`, which refuses links, and with `statx`, which
  says whether the place is the root of its mount (Linux 5.8). An older
  kernel, or a container whose syscall filter blocks `openat2` or `statx`,
  refuses every room, with a message naming the cause.
- **D-Bus filtering needs `xdg-dbus-proxy`.** Without it, an app with
  filtered D-Bus gets no session bus at all.
- **Abstract sockets** are blocked only on kernel 6.12+. On older kernels,
  XWayland's socket is reachable for apps with full network (X11
  authorization still applies; many desktops let every program of the
  same user in), and so is a session bus on an abstract socket. Diagnostics
  and the sandbox check say so; such a start is not marked *Protection
  missing*, because the kernel has nothing SAM could apply.
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

