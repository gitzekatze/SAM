//! Room service: a program inside an app's sandbox asks for a sandbox of its
//! own (a room) with Bubblewrap, and SAM builds it from outside under one
//! rule: no more than the app, no less than asked.
//!
//! Test apps go through SAM's normal path (added like any AppImage, started
//! with the settings SAM recommends). Each app first builds a plain room as
//! a control, and every attack result needs a built room or a clear
//! refusal: "no result" never passes. Writes, files and left-over processes
//! are judged on the computer afterwards, not by what the app reports.
//!
//! The other Room service tests: room_service_compare.rs (every room's
//! mounts and abilities within its app's, for many generated requests),
//! room_service_local.rs ("This computer only"), room_service_glycin.rs
//! (GTK's real image loader).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod rooms_common;

use std::collections::BTreeSet;
use std::fs;
use std::time::{Duration, Instant};

use rooms_common::{
    cases, check, host_bwrap_version, kill_all, landlock_abi, markers, open_fds, processes, World,
};
use sam_core::permissions::{Access, NetworkMode};

/// The most open connections a request may pass (room_rules::MAX_FDS): the
/// scripts below name the number itself.
const _MOST_FDS: () = assert!(sam_runner::room_rules::MAX_FDS == 253);

/// Rooms work: a room shows what it asks for and nothing of the app it did
/// not ask for, writes where asked and the app can, passes open
/// connections, the exit code and its environment, answers like the
/// computer's Bubblewrap, starts in its program's folder where it shows
/// it, gets no other open connection and nothing of the computer's
/// environment, and keeps what it asked to give up.
const WORKS: &str = r#"
say control "$(rv room -- /usr/bin/echo ok)"
say view "$(rv room -- /usr/bin/sh -c "test -e '$HOME' && echo sees-home || echo no-home")"
say own_tmpfs "$(rv room --tmpfs /scratch -- $P write /scratch x)"
say own_chmod "$(rv room --tmpfs /scratch --chmod 0700 /scratch -- /usr/bin/echo ok)"
say home_rw "$(rv room --bind "$HOME" "$HOME" -- $P write "$HOME" room-rw-marker)"
say home_ro "$(rv room --ro-bind "$HOME" "$HOME" -- $P write "$HOME" room-ro-marker)"
exec 5>"$HOME/fd5"
room -- /usr/bin/sh -c 'echo via-fd-5 >&5'
exec 5>&-
say fd "$(cat "$HOME/fd5")"
room -- /usr/bin/sh -c 'exit 7'
say exit "$?"
say stdin "$(echo piped | room -- /usr/bin/cat)"
say env "$(rv room --clearenv --setenv ROOM_VAR yes -- /usr/bin/sh -c 'echo "${ROOM_VAR:-unset}-${HOME:-nohome}"')"
say token "$(rv room --setenv ROOM_TOKEN "tok-$TEST_PID-secret" -- $P env ROOM_TOKEN)"
say version "$(bwrap --version)"
KEEP_FDS='import os, sys
want = int(sys.argv[1])
def kept():
    n = 0
    for f in os.listdir("/proc/self/fd"):
        try:
            n += os.get_inheritable(int(f))
        except OSError:
            pass  # the listing of the folder, closed again
    return n
while kept() < want:
    os.set_inheritable(os.open("/dev/null", os.O_RDONLY), True)
os.execvp(sys.argv[2], sys.argv[2:])'
# The room gets exactly its program's open connections, also for a
# program holding many (16 here): a shell between the program and SAM's
# helper would add its own (dash, /bin/sh on Debian and Ubuntu, leaves the
# script's file open in the program it starts once 10 or more are open).
# One line from the program itself, one from its room.
FDS_BOTH="$(python3 -c "$KEEP_FDS" 16 /usr/bin/sh -c "$P fds; bwrap --ro-bind /usr /usr $SYS --ro-bind $APPDIR $APPDIR --proc /proc -- $P fds" 2>/dev/null)"
say fds_app "$(echo "$FDS_BOTH" | sed -n 1p)"
say fds "$(echo "$FDS_BOTH" | sed -n 2p)"
# The stand-in is SAM's helper itself, with no script and no shell in
# between (nothing that could leave a file open in it).
say standin_is_helper "$(if [ "$(command -v bwrap)" -ef /run/sam/sam-jail-run ]; then echo helper; else echo other; fi)"
# It answers as Bubblewrap when started by its path under another name, or
# as SAM's helper under Bubblewrap's name.
say version_by_path "$(python3 -c 'import os; os.execv("/run/sam/bin/bwrap", ["loader", "--version"])' 2>/dev/null)"
say version_by_name "$(python3 -c 'import os; os.execv("/run/sam/sam-jail-run", ["bwrap", "--version"])' 2>/dev/null)"
say host_env_app "$($P env SAM_ROOMS_HOST_MARKER)"
say host_env_room "$(rv room -- $P env SAM_ROOMS_HOST_MARKER)"
say nested_userns "$(rv room -- $P userns)"
say own_pids "$(rv room --proc /proc -- $P pids)"
# A program holding many open connections (as glycin started from an
# Electron app does) still gets its room: real Bubblewrap passes them all.
say many_fds "$(python3 -c 'import os, sys
for _ in range(150):
    os.set_inheritable(os.open("/dev/null", os.O_RDONLY), True)
os.execvp("sh", ["sh", "-c", sys.argv[1]])' "bwrap --ro-bind /usr /usr $SYS -- /usr/bin/echo ok" 2>/dev/null)"
# The program's resource limits and umask stay in its room, as with
# Bubblewrap (glycin caps its loader's memory this way).
say limits "$(ulimit -v 4000000; ulimit -c 0; umask 077; rv room -- /usr/bin/sh -c 'echo "$(ulimit -v)/$(ulimit -c)/$(umask)"')"
# Found as Bubblewrap's execvp finds it: never from the room's folder when
# it is not on PATH; a script without a #! line runs with the shell.
printf 'echo ran-from-folder\n' > "$HOME/sam-room-not-on-path"
chmod 755 "$HOME/sam-room-not-on-path"
say not_on_path "$(rv room --bind "$HOME" "$HOME" --chdir "$HOME" --setenv PATH /usr/bin -- sam-room-not-on-path)"
cp "$HOME/sam-room-not-on-path" "$HOME/sam-room-no-shebang"
say no_shebang "$(rv room --bind "$HOME" "$HOME" -- "$HOME/sam-room-no-shebang")"
# With no shell in the room, a script without a #! line is passed over and
# the search goes on along PATH, as Bubblewrap's would.
mkdir -p "$HOME/first"
cp "$HOME/sam-room-not-on-path" "$HOME/first/echo"
LIBS=""
for d in /lib /lib32 /lib64; do
  if [ -L "$d" ]; then LIBS="$LIBS --symlink $(readlink "$d") $d"
  elif [ -d "$d" ]; then LIBS="$LIBS --ro-bind $d $d"; fi
done
# shellcheck disable=SC2086
say shell_missing "$(bwrap --ro-bind /usr /usr $LIBS --bind "$HOME" "$HOME" --setenv PATH "$HOME/first:/usr/bin" -- echo next 2>/dev/null || echo refused)"
# The app's /dev asked for without devices: its few nodes, not working,
# and the links every /dev has.
say dev_without_devices "$(rv room --ro-bind /dev /dev -- /usr/bin/sh -c '(echo x > /dev/null) 2>/dev/null && echo works || echo blocked')"
say dev_links "$(rv room --ro-bind /dev /dev -- /usr/bin/sh -c 'test -L /dev/stdout && test -L /dev/fd && echo links')"
# PWD names the room's folder, as with Bubblewrap (also after --clearenv).
# (Read by the probe: a shell would set PWD itself.)
say pwd "$(rv room --clearenv --chdir /usr -- $P env PWD)"
say pwd_stale "$(export PWD=/tmp; rv room --chdir /usr -- $P env PWD)"
# Without --chdir a room starts in its program's folder when it shows
# that folder as a place of the app (/usr/bin here), else in /.
say cwd "$(cd /usr/bin && rv room -- /usr/bin/sh -c 'pwd -P')"
say cwd_not_shown "$(cd "$HOME" && rv room -- /usr/bin/sh -c 'pwd -P')"
# Exactly as many open connections as a request may pass (253, room_rules::MAX_FDS):
# still a room; one more is refused.
# shellcheck disable=SC2086
say fds_most "$(rv python3 -c "$KEEP_FDS" 253 bwrap --ro-bind /usr /usr $SYS -- /usr/bin/echo ok)"
# shellcheck disable=SC2086
say fds_over "$(rv python3 -c "$KEEP_FDS" 254 bwrap --ro-bind /usr /usr $SYS -- /usr/bin/echo ok)"
# A name found on PATH (the default /bin:/usr/bin without one).
say on_path "$(rv room --setenv PATH /usr/bin -- echo ok)"
say default_path "$(rv room --clearenv -- echo ok)"
# A variable that is not text: the request is refused, never run without it.
SAM_ROOM_NOT_TEXT="$(printf 'x\377')"
export SAM_ROOM_NOT_TEXT
say env_not_text "$(rv room -- /usr/bin/echo ok)"
unset SAM_ROOM_NOT_TEXT
"#;

/// Attacks under one network setting: greedy requests; links out of the
/// app's view and to places the app sees with other rights; options a room
/// never gets; folders by handle; the same path from another source; the
/// computer's /proc; the network, sockets outside the sandbox, a system
/// call SAM's filter blocks, nested sandboxes, devices; an environment that
/// would run code before SAM's layers; the program's own filter.
const ATTACKS: &str = r#"
say control "$(rv room -- /usr/bin/echo ok)"
say greedy_secret "$(rv room --bind / / --dev-bind /dev /dev --share-net -- $P read "$SECRET_FILE")"
say greedy_other_app "$(rv room --bind / / -- $P read "$OTHER_APP")"
say greedy_settings "$(rv room --bind / / -- $P read "$SAM_SETTINGS")"
say greedy_key "$(rv room --bind / / -- $P read "$HOST_KEY")"
say greedy_own_app "$(rv room --bind / / -- $P write "$APPDIR/usr/bin" evil-greedy)"
ln -sfn "$SECRET_FILE" "$HOME/link-file"
say link_file "$(rv room --ro-bind "$HOME/link-file" "$HOME/link-file" -- $P read "$HOME/link-file")"
ln -sfn "$SECRET_DIR" "$HOME/link-dir"
say link_dir "$(rv room --ro-bind "$HOME/link-dir" "$HOME/link-dir" -- $P read "$HOME/link-dir/f")"
ln -sfn "../../../../../../../../../../../../..$SECRET_DIR" "$HOME/link-up"
say link_up "$(rv room --ro-bind "$HOME/link-up" "$HOME/link-up" -- $P read "$HOME/link-up/f")"
ln -sfn "$APPDIR/usr/bin" "$HOME/to-app"
say link_to_app "$(rv room --bind "$HOME/to-app" "$HOME/to-app" -- $P write "$HOME/to-app" evil-via-link)"
ln -sfn /run/sam "$HOME/to-sam"
say link_to_sam "$(rv room --bind "$HOME/to-sam" "$HOME/to-sam" -- $P write "$HOME/to-sam" evil-via-link)"
say unknown_option "$(rv room --cap-add ALL -- /usr/bin/echo ok)"
# While Bubblewrap builds a room, the computer's root is at /oldroot: a link
# the app plants in its own folder must not lead Bubblewrap to make files
# there.
ln -sfn "/oldroot$HOME/.config/autostart" "$HOME/planted"
printf '[Desktop Entry]\nExec=evil\n' > "$HOME/payload.desktop"
say planted_symlink "$(rv room --bind "$HOME" "$HOME" --symlink "$HOME/payload.desktop" "$HOME/planted/evil-link.desktop" -- /usr/bin/echo ok)"
say planted_dir "$(rv room --bind "$HOME" "$HOME" --dir "$HOME/planted/evil-dir" -- /usr/bin/echo ok)"
# The room's layout must not decide what runs before SAM's layers: with
# the system's library folders pointing into the app's own folder, SAM's
# room helper still starts and confirms its layers (the program itself,
# which does not exist, then fails).
mkdir -p "$HOME/fakelib"
bwrap --ro-bind /usr /usr --bind "$HOME" "$HOME" --symlink "$HOME/fakelib" /lib64 --symlink "$HOME/fakelib" /lib -- /usr/bin/loader-layout-check >/dev/null 2>&1
say loader_layout done
# A link of the room's own as a trap for a later place of the app: asking
# for everything after a link at /usr/lib pointing to SAM's own place would
# mount the app's /usr/lib over SAM's room helper.
say trap_link "$(rv bwrap --symlink ../.sam-room /usr/lib --ro-bind / / -- /usr/bin/echo ok)"
say trap_link_later "$(rv bwrap --symlink /tmp /usr --ro-bind / / -- /usr/bin/echo ok)"
say trap_link_name "$(rv bwrap --symlink .sam-room /usr --ro-bind / / -- /usr/bin/echo ok)"
say moved_folder "$(rv room --ro-bind /usr /elsewhere -- /usr/bin/echo ok)"
exec 7<"$HOME"
say folder_by_handle "$(rv room --bind-fd 7 "$HOME" -- /usr/bin/echo ok)"
exec 7<&-
accepted=""
for opt in "--userns 0" "--userns2 0" "--pidns 0" "--info-fd 1" "--json-status-fd 1" \
           "--overlay-src /usr" "--uid 0" "--gid 0" "--exec-label x" "--file-label x" \
           "--file 0 /x" "--bind-data 0 /x" "--ro-bind-data 0 /x" "--sync-fd 1" \
           "--block-fd 0" "--userns-block-fd 0" "--cap-add CAP_SYS_ADMIN" \
           "--lock-file /tmp/x" "--tmp-overlay /opt" "--ro-overlay /opt" \
           "--overlay /tmp /tmp /opt" "--argv0 x" "--args 0" "--not-a-security-boundary"; do
  # A file, not a pipe: a process the attempt leaves behind must not hold
  # this script up.
  # shellcheck disable=SC2086
  timeout -s KILL 10 bwrap --ro-bind /usr /usr $SYS $opt -- /usr/bin/echo ok </dev/null >"$HOME/exotic.out" 2>/dev/null
  rc=$?
  out=$(cat "$HOME/exotic.out")
  # The room ran (its "ok" on a line of its own), whatever else came out:
  # --info-fd 1 and --json-status-fd 1 would add Bubblewrap's own lines.
  if [ "$rc" = 137 ]; then accepted="$accepted [$opt: hung]"
  elif printf '%s\n' "$out" | grep -qx ok; then accepted="$accepted [$opt]"; fi
done
say exotic "${accepted:-all-refused}"
say chmod_app_folder "$(rv room --bind "$HOME" "$HOME" --chmod 0777 "$HOME" -- /usr/bin/echo ok)"
IDS="/etc/passwd /etc/group /etc/hosts /etc/resolv.conf /usr/bin/systemd-run /usr/bin/flatpak-spawn /run/sam/sam-jail-run /run/user/$(id -u)/bus /run/user/$(id -u)/pulse/native"
# shellcheck disable=SC2086
say ids_app "$($P ids $IDS)"
# shellcheck disable=SC2086
say ids_greedy "$(rv room --bind / / -- $P ids $IDS)"
# shellcheck disable=SC2086
say ids_named "$(rv room --ro-bind /etc /etc --ro-bind-try /run /run -- $P ids $IDS)"
say proc_by_name "$(rv room --ro-bind-try /proc /proc -- /usr/bin/sh -c "test -e /proc/$TEST_PID && echo sees-computer || echo own-or-none")"
say tcp_app "$($P tcp "$PORT")"
say tcp_room "$(rv room --share-net -- $P tcp "$PORT")"
say tcp_unshared "$(rv room --share-net --unshare-net -- $P tcp "$PORT")"
say abstract_app "$($P abstract "$ABSTRACT")"
say abstract_room "$(rv room --share-net -- $P abstract "$ABSTRACT")"
say keyctl_app "$($P keyctl)"
say keyctl_room "$(rv room -- $P keyctl)"
say userns_room "$(rv room -- $P userns)"
say dev_app "$($P devices)"
say dev_room "$(rv room --dev-bind /dev /dev -- $P devices)"
say preload "$(rv room --dev /dev --bind "$HOME" "$HOME" --setenv LD_DEBUG files --setenv LD_DEBUG_OUTPUT "$HOME/ld" -- /usr/bin/sh -c 'cat "$HOME"/ld.* 2>/dev/null | grep -c "needed by"')"
python3 - "$HOME/filter.bpf" <<'PY'
import os, struct, sys
aarch64 = os.path.exists("/lib/ld-linux-aarch64.so.1")
uname = 160 if aarch64 else 63
# Kills landlock_create_ruleset (as an older glycin's filter does for every
# call it does not know), refuses uname, allows everything else.
f = [(0x20, 0, 0, 0), (0x15, 0, 1, 444), (0x06, 0, 0, 0x80000000),
     (0x15, 0, 1, uname), (0x06, 0, 0, 0x00050001), (0x06, 0, 0, 0x7fff0000)]
open(sys.argv[1], "wb").write(b"".join(struct.pack("HBBI", *i) for i in f))
PY
exec 9<"$HOME/filter.bpf"
room --seccomp 9 -- /usr/bin/true
say filter_start "$?"
exec 9<&-
exec 9<"$HOME/filter.bpf"
say filter_holds "$(rv room --seccomp 9 -- $P uname)"
exec 9<&-
# A program filter that refuses every write: SAM's helper confirms its
# layers before loading it, so the room is still built and confirmed.
python3 - "$HOME/nowrite.bpf" <<'PY'
import os, struct, sys
write = 64 if os.path.exists("/lib/ld-linux-aarch64.so.1") else 1
f = [(0x20, 0, 0, 0), (0x15, 0, 1, write), (0x06, 0, 0, 0x00050001), (0x06, 0, 0, 0x7fff0000)]
open(sys.argv[1], "wb").write(b"".join(struct.pack("HBBI", *i) for i in f))
PY
exec 9<"$HOME/nowrite.bpf"
room --seccomp 9 -- /usr/bin/sync
say filter_quiet "$?"
exec 9<&-
# An argument that is not text: the whole request is refused, never run
# with the argument changed.
say not_text "$(rv room -- /usr/bin/echo "$(printf 'x\377')")"
"#;

/// A shared home (read/write): its protected places (autostart, shell
/// startup files, the folders above them) stay protected in rooms.
const FULL_HOME: &str = r#"
say control "$(rv room -- /usr/bin/echo ok)"
say autostart_app "$($P write "$HOME/.config/autostart" app-evil.desktop)"
say autostart_room "$(rv room --dev /dev --bind "$HOME" "$HOME" -- $P write "$HOME/.config/autostart" room-evil.desktop)"
say bashrc_app "$( (echo app-evil >> "$HOME/.bashrc") 2>/dev/null && echo allowed || echo blocked)"
say bashrc_room "$(rv room --dev /dev --bind "$HOME" "$HOME" -- /usr/bin/sh -c 'echo room-evil >> "$HOME/.bashrc" 2>/dev/null && echo allowed || echo blocked')"
say rename_app "$(mv "$HOME/.config" "$HOME/.config-app" 2>/dev/null && echo allowed || echo blocked)"
say rename_room "$(rv room --dev /dev --bind "$HOME" "$HOME" -- /usr/bin/sh -c 'mv "$HOME/.config" "$HOME/.config-room" 2>/dev/null && echo allowed || echo blocked')"
# SAM hides ~/.ssh from the app with an empty folder over it: a room asking
# for the home must not see it either.
say ssh_app "$($P read "$HOME/.ssh/id_ed25519")"
say ssh_room "$(rv room --ro-bind "$HOME" "$HOME" -- $P read "$HOME/.ssh/id_ed25519")"
# Links the app makes in its writable home to places it sees protected or
# hidden: a requested path never follows a link.
ln -sfn .config/autostart "$HOME/to-autostart"
say link_protected "$(rv room --dev /dev --bind "$HOME/to-autostart" "$HOME/to-autostart" -- $P write "$HOME/to-autostart" via-link.desktop)"
# A room link named before a place the app is shown (here read-only for
# the room), through a link in that place to Bubblewrap's view of the
# computer: refused, never made last through the link.
say link_first "$(rv room --symlink /nonexistent "$HOME/rodir/x$HOME/.config/autostart/link-first.desktop" --ro-bind "$HOME/rodir" "$HOME/rodir" -- /usr/bin/true)"
ln -sfn .ssh "$HOME/to-ssh"
say link_hidden "$(rv room --ro-bind "$HOME/to-ssh" "$HOME/to-ssh" -- $P read "$HOME/to-ssh/id_ed25519")"
"#;

/// A grant inside SAM's own folder, which SAM hides from the app with a
/// later mount over it: a room asking for it sees nothing either.
const SAM_FOLDER_GRANT: &str = r#"
say control "$(rv room -- /usr/bin/echo ok)"
say grant_app "$($P read "$OTHER_APP")"
say grant_room "$(rv room --ro-bind-try "$(dirname "$OTHER_APP")" "$(dirname "$OTHER_APP")" -- $P read "$OTHER_APP")"
"#;

/// A folder the app is shown is renamed away inside its writable home and
/// a link to a place it is not shown is put in its place: a room shows the
/// folder the app was shown (held since the start), never the link's target.
const HELD_SOURCES: &str = r#"
say control "$(rv room -- /usr/bin/echo ok)"
mv "$HOME/work" "$HOME/work-moved" && mkdir -p "$HOME/work" && ln -sfn "$SECRET_DIR" "$HOME/work/docs"
say renamed "$([ -L "$HOME/work/docs" ] && echo yes || echo no)"
say held "$(rv room --ro-bind "$HOME/work/docs" "$HOME/work/docs" -- /usr/bin/cat "$HOME/work/docs/f")"
"#;

/// The person's own Bubblewrap arguments that cut the app off the network
/// count for its rooms too.
const EXTRA_ARGS: &str = r#"
say control "$(rv room -- /usr/bin/echo ok)"
say tcp_app "$($P tcp "$PORT")"
say tcp_room "$(rv room --unshare-all --share-net -- $P tcp "$PORT")"
"#;

/// Messages written by hand to the room service, past the stand-in: every
/// rule holds in the service itself, and nothing an app sends stops it
/// from serving. Answers: exit=N, refused, closed (it hung up: counted as
/// refused), hung.
const HOSTILE_MESSAGES: &str = r#"
python3 - <<'PY'
import array, json, os, socket, struct, time
APPDIR = os.environ["APPDIR"]
HOME = os.environ["HOME"]
SECRET_FILE = os.environ["SECRET_FILE"]
SYS = []
for d in ("/bin", "/sbin", "/lib", "/lib32", "/lib64"):
    if os.path.islink(d):
        SYS.append(["--symlink", os.readlink(d), d])
    elif os.path.isdir(d):
        SYS.append(["--ro-bind", d, d])
BASE = [["--ro-bind", "/usr", "/usr"], ["--ro-bind", APPDIR, APPDIR]] + SYS

def say(k, v):
    print(f"CASE {k}={v}", flush=True)

def message(obj):
    d = json.dumps(obj).encode()
    return struct.pack("!I", len(d)) + d

def raw_message(data):
    return struct.pack("!I", len(data)) + data

def request(ops, command, flags=(), fds=(), env=None, **extra):
    m = {"v": 1, "ops": ops, "flags": list(flags), "command": command,
         "env": env or {}, "cwd": "/", "fds": list(fds)}
    m.update(extra)
    return message(m)

def ask(raw, fds=()):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(20)
    try:
        s.connect("/run/sam/rooms")
        anc = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
        s.sendmsg([raw], anc)
        head = b""
        while len(head) < 4:
            c = s.recv(4 - len(head))
            if not c:
                return "closed"
            head += c
        n = struct.unpack("!I", head)[0]
        body = b""
        while len(body) < n:
            c = s.recv(n - len(body))
            if not c:
                return "closed"
            body += c
        ans = json.loads(body)
        return f"exit={ans['exit']}" if "exit" in ans else "refused"
    except socket.timeout:
        return "hung"
    except OSError as e:
        return f"error-{e.errno}"
    finally:
        s.close()

def refusal(r):
    # Only an answer counts: a hang-up could be a crash of the service.
    return r

say("direct_control", ask(request(BASE, ["/usr/bin/true"])))
probe = f'echo "CASE direct_greedy=$(/usr/bin/python3 -I -S {APPDIR}/usr/bin/probe.py read {SECRET_FILE})"'
a = ask(request([["--bind", "/", "/"]] + BASE, ["/usr/bin/sh", "-c", probe], fds=[1]), fds=[1])
if a != "exit=0":
    say("direct_greedy", a)
home_fd = os.open(HOME, os.O_RDONLY | os.O_DIRECTORY)
say("direct_fd_place", refusal(ask(request(BASE + [["--bind-fd", str(home_fd), HOME]], ["/usr/bin/true"], fds=[home_fd]), fds=[home_fd])))
os.close(home_fd)
say("direct_env", ask(request(BASE + [["--dev", "/dev"], ["--bind", HOME, HOME]], ["/usr/bin/true"],
                              env={"LD_DEBUG": "files", "LD_DEBUG_OUTPUT": HOME + "/ldm", "HOME": HOME})))
# Far more places than a room may have (each /usr brings SAM's own places
# below it, at least 3): refused as a whole, never built in part. Well
# under the 256 options a request may have, whatever BASE holds here.
say("direct_many_places", refusal(ask(request(BASE + [["--ro-bind", "/usr", "/usr"]] * 210, ["/usr/bin/true"]))))
say("direct_moved", refusal(ask(request(BASE + [["--ro-bind", "/usr", "/elsewhere"]], ["/usr/bin/true"]))))
say("direct_dotdot", refusal(ask(request(BASE + [["--ro-bind", "/usr/../etc", "/usr/../etc"]], ["/usr/bin/true"]))))
say("direct_relative", refusal(ask(request(BASE + [["--ro-bind", "usr", "usr"]], ["/usr/bin/true"]))))
say("direct_flag", refusal(ask(request(BASE, ["/usr/bin/true"], flags=["--cap-add"]))))
say("direct_no_command", refusal(ask(request(BASE, []))))
say("direct_unknown_field", refusal(ask(request(BASE, ["/usr/bin/true"], extra_field=1))))
dup = b'{"v":1,"ops":[],"flags":[],"command":["/usr/bin/true"],"command":["/usr/bin/id"],"env":{},"cwd":"/","fds":[]}'
say("direct_duplicate_field", refusal(ask(raw_message(dup))))
say("direct_not_utf8", refusal(ask(raw_message(b'{"v":1,"ops":[["--ro-bind","/usr/\xff","/usr/\xff"]],"flags":[],"command":["/usr/bin/true"],"env":{},"cwd":"/","fds":[]}'))))
say("direct_garbage", refusal(ask(b"\x00\x00\x00\x05nope!")))
say("direct_wrong_version", refusal(ask(message({"v": 99, "ops": BASE, "flags": [], "command": ["/usr/bin/true"],
                                                  "env": {}, "cwd": "/", "fds": []}))))
say("direct_many_ops", refusal(ask(request(BASE + [["--dir", f"/d{i}"] for i in range(257)], ["/usr/bin/true"]))))
say("direct_many_fds", refusal(ask(request(BASE, ["/usr/bin/true"], fds=list(range(254))), fds=[0] * 253)))
t = time.monotonic()
r = refusal(ask(struct.pack("!I", 0x7FFFFFFF) + b"{"))
say("direct_huge", r if time.monotonic() - t < 10 else f"{r}-slow")
# Connections that send nothing, or half a header, must not stop the service.
idle = []
for i in range(40):
    s = socket.socket(socket.AF_UNIX)
    try:
        s.connect("/run/sam/rooms")
        if i % 2:
            s.send(b"\x00\x00")
        idle.append(s)
    except OSError:
        break
t = time.monotonic()
r = ask(request(BASE, ["/usr/bin/true"]))
say("served_beside_idle", "yes" if r == "exit=0" and time.monotonic() - t < 20 else f"no-{r}")
for s in idle:
    s.close()
time.sleep(1)
# More than 64 connections at once: the rest are closed at once.
idle = []
for i in range(70):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    try:
        s.connect("/run/sam/rooms")
        idle.append(s)
    except OSError:
        break
closed = 0
for s in idle:
    try:
        if s.recv(1) == b"":
            closed += 1
    except socket.timeout:
        pass
    except OSError:
        closed += 1
say("connections_limited", "yes" if closed >= 6 else f"no-{closed}-closed")
for s in idle:
    s.close()
time.sleep(1)
# Connections held while requests are still being sent count against the
# service's budget (512): two half-sent requests with 253 each are held,
# a third with 10 more is refused at once (long before the read limit).
null = os.open("/dev/null", os.O_RDONLY)
half = []
for count in (253, 253, 10):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(4)
    s.connect("/run/sam/rooms")
    s.sendmsg([struct.pack("!I", 1000)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [null] * count))])
    half.append(s)
    time.sleep(0.3)
try:
    head = half[2].recv(4)
    third = "refused" if len(head) == 4 else "closed"
except socket.timeout:
    third = "held"
say("held_limited", "yes" if third == "refused" else f"no-{third}")
for s in half:
    s.close()
time.sleep(1)
# Once a room has started, its connections leave the budget: two running
# rooms that were passed 253 connections each do not keep a third request
# out (counted, they would make 516 of 512).
longs = []
for i in range(2):
    l = socket.socket(socket.AF_UNIX)
    l.settimeout(20)
    l.connect("/run/sam/rooms")
    l.sendmsg([request(BASE + [["--bind", HOME, HOME]],
                       ["/usr/bin/sh", "-c", f"echo up > {HOME}/long-room-{i}; exec /usr/bin/sleep 8"],
                       fds=list(range(3, 256)))],
              [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [null] * 253))])
    longs.append(l)
    time.sleep(1.5)
# Both run now (else the third request proves nothing).
for _ in range(100):
    if all(os.path.exists(f"{HOME}/long-room-{i}") for i in range(2)):
        break
    time.sleep(0.1)
say("long_rooms_built", "yes" if all(os.path.exists(f"{HOME}/long-room-{i}") for i in range(2)) else "no")
r3 = ask(request(BASE, ["/usr/bin/true"], fds=list(range(3, 13))), fds=[null] * 10)
say("budget_released", "yes" if r3 == "exit=0" else f"no-{r3}")
for l in longs:
    l.close()
# Many small requests at the same moment, each passing a few connections:
# every one is built (requests read together never take each other's
# room for connections).
import threading
results = [None] * 30
gate = threading.Barrier(30)
def one(i):
    gate.wait()
    results[i] = ask(request(BASE, ["/usr/bin/true"], fds=[3, 4, 5]), fds=[null] * 3)
threads = [threading.Thread(target=one, args=(i,)) for i in range(30)]
for t in threads:
    t.start()
for t in threads:
    t.join()
say("together", str(sum(r == "exit=0" for r in results)) + "-" + ",".join(sorted(set(r for r in results if r != "exit=0"))))
# The start record keeps at most 200 room lines.
for i in range(230):
    ask(b"\x00\x00\x00\x02{}")
say("many_refused", "sent")
for s in half:
    s.close()
time.sleep(1)
PY
# A room after the flood of refusals: printf is used nowhere else here, so
# its line in the start record is this room's.
say final_control "$(rv room -- /usr/bin/printf ok)"
"#;

/// A folder the room asks for is exchanged, as fast as the kernel allows,
/// with a link out of the app's view (absolute and relative) while rooms
/// are built: no room may ever show what the link points to.
/// The exchanges come in bursts with short pauses between them: on a slow
/// computer nonstop swapping outpaced every room's build, so all 400 were
/// refused, which is safe but proves nothing about the build (CI,
/// 2026-11-23). Rooms are asked for until at least one was built (at least
/// 400, at most 3000), and the swapping runs until they are done.
const RACE: &str = r#"
mkdir -p "$HOME/race/d"
echo inside > "$HOME/race/d/f"
ln -sfn "$SECRET_DIR" "$HOME/race/abs"
ln -sfn "../../../../../../../../../../../../..$SECRET_DIR" "$HOME/race/rel"
python3 - <<'PY' &
import ctypes, os, random, time
libc = ctypes.CDLL(None, use_errno=True)
AT, EXCHANGE = -100, 2
h = os.environ["HOME"] + "/race/"
d, a, r = (h + "d").encode(), (h + "abs").encode(), (h + "rel").encode()
end = time.monotonic() + 900
while time.monotonic() < end:
    # Bursts of exchanges as fast as the kernel allows, then a short pause
    # with the real folder in place: rooms built in a burst meet the race,
    # and on any computer some fall into a pause and are built.
    burst = time.monotonic() + random.uniform(0.02, 0.08)
    while time.monotonic() < burst:
        for other in (a, a, r, r):
            libc.renameat2(AT, d, AT, other, EXCHANGE)
    time.sleep(random.uniform(0, 0.3))
PY
swapper=$!
inside=0; leaked=0; other=0; i=0
while [ $i -lt 400 ] || { [ $inside -eq 0 ] && [ $i -lt 3000 ]; }; do
  r=$(room --ro-bind-try "$HOME/race/d" "$HOME/race/d" -- /usr/bin/cat "$HOME/race/d/f" 2>/dev/null)
  case "$r" in
    inside) inside=$((inside+1)) ;;
    *ROOM-SERVICE-SECRET*) leaked=$((leaked+1)) ;;
    *) other=$((other+1)) ;;
  esac
  i=$((i+1))
done
kill "$swapper" 2>/dev/null
say race_inside "$inside"
say race_leaked "$leaked"
say race_other "$other"
"#;

/// The program of the --as-pid-1 room: it leaves a marker, clears its parent-death signal
/// and waits (the seconds follow).
const PDEATH_CODE: &str = "import ctypes, os, time; open(os.environ['HOME'] + '/pid1-up', 'w').close(); ctypes.CDLL(None).prctl(1, 0, 0, 0, 0); time.sleep(";

/// The program of each room in the count of rooms at once (its number
/// follows). It marks itself running in a folder it shares with the app
/// ($HOME/slots), counts the marks again and again and keeps the highest
/// count it saw. Once sixteen run (Room service's most, MAX_ROOMS), it
/// stays as long again as they took to gather, and two seconds more: a
/// seventeenth room built beside them would be counted by then, however
/// busy the computer. The first room to leave says so ("done"), and the
/// rooms built after it leave at once. If sixteen never gather, the rooms
/// give up once no new room has come for a minute (each room also leaves a
/// lasting "seen" mark): not after a fixed time from the start, which a
/// busy computer may need just to build sixteen rooms. A slot frees only
/// after its room has ended, so the count never runs ahead of the rooms
/// really running.
const SLOT_ROOM: &str = r#"me=$1
d=$HOME/slots
: > "$d/seen-$me"
: > "$d/run-$me"
read -r t0 < "$d/t0"
most=0; full=0; seen=0; came=$(/usr/bin/date +%s%N)
while :; do
  set -- "$d"/run-*
  n=$#
  [ -e "$1" ] || n=0
  [ "$n" -gt "$most" ] && most=$n
  [ -e "$d/done" ] && break
  now=$(/usr/bin/date +%s%N)
  set -- "$d"/seen-*
  [ "$#" != "$seen" ] && seen=$# && came=$now
  [ "$full" = 0 ] && [ "$n" -ge 16 ] && full=$now
  if [ "$full" != 0 ] && [ $((now - full)) -ge $((full - t0 + 2000000000)) ]; then : > "$d/done"; break; fi
  if [ "$full" = 0 ] && [ $((now - came)) -ge 60000000000 ]; then : > "$d/done"; break; fi
  /usr/bin/sleep 0.1
done
echo "$most" > "$d/most-$me"
/usr/bin/rm -f "$d/run-$me""#;

/// Closing the app (Close in SAM's window, `sam-jail stop`, logout) gives
/// a room's program its time to save, as the app gets: the program traps
/// SIGTERM, takes two seconds and only then writes `room-saved`. The app
/// itself quits on SIGTERM at once; its room keeps it going until the
/// room's program has quit. The room's program says when it is ready
/// (`room-up`), and the test then closes the app.
const CLOSE: &str = r#"
cat > "$HOME/saver" <<'EOF'
trap 'trap "" TERM; /usr/bin/sleep 2; echo saved > "$HOME/room-saved"; exit 0' TERM
echo up > "$HOME/room-up"
while :; do /usr/bin/sleep 0.1; done
EOF
room --bind "$HOME" "$HOME" -- /usr/bin/sh "$HOME/saver" </dev/null >/dev/null 2>&1 &
wait
"#;

/// Many rooms at once all finish, and no more than sixteen run at a time
/// (counted by the rooms themselves, not timed). A stand-in killed outright
/// ends its room; a room still running when its app's start ends does not
/// outlive it. The waits are generous (a minute) for a busy computer; they
/// only cost time when something is wrong. The script ends by writing
/// `lifetime-done`: its start is then ended from outside (see
/// [`end_start_after`]), since the rooms left running keep it going.
fn lifetime_script(left: &str) -> String {
    format!(
        r#"
pids=""
i=0
while [ $i -lt 40 ]; do room -- /usr/bin/sleep 1 & pids="$pids $!"; i=$((i+1)); done
ok=0
for p in $pids; do wait "$p" && ok=$((ok+1)); done
say flood "$ok"
# Twenty rooms at once: sixteen run together, the other four wait for a
# slot (SLOT_ROOM above counts them).
mkdir -p "$HOME/slots"
date +%s%N > "$HOME/slots/t0"
pids=""
i=0
while [ $i -lt 20 ]; do room --bind "$HOME" "$HOME" -- /usr/bin/sh -c '{SLOT_ROOM}' sh "$i" & pids="$pids $!"; i=$((i+1)); done
ok=0
for p in $pids; do wait "$p" && ok=$((ok+1)); done
say slots_ended_well "$ok"
ran=0; most=0
for f in "$HOME"/slots/most-*; do
  [ -e "$f" ] || continue
  ran=$((ran+1)); m=$(cat "$f")
  [ "$m" -gt "$most" ] && most=$m
done
say slots_ran "$ran"
say slots_most_at_once "$most"
# bwrap itself in the background (not the room function, whose $! would be
# a subshell): $! is then the stand-in.
# shellcheck disable=SC2086
bwrap --ro-bind /usr /usr $SYS --bind "$HOME" "$HOME" -- /usr/bin/sh -c 'while :; do date +%s%N > "$HOME/beat"; /usr/bin/sleep 0.2; done' &
standin=$!
i=0; while [ ! -s "$HOME/beat" ] && [ $i -lt 300 ]; do sleep 0.2; i=$((i+1)); done
kill -9 "$standin"
# The room ends soon after its stand-in: its beat stops (unchanged for two
# seconds), within a minute on a busy computer.
if [ ! -s "$HOME/beat" ]; then killed=no-room; else
  killed=room-still-running; i=0
  while [ $i -lt 30 ]; do
    a=$(cat "$HOME/beat"); sleep 2; b=$(cat "$HOME/beat")
    if [ "$a" = "$b" ]; then killed=room-ended; break; fi
    i=$((i+1))
  done
fi
say killed_standin "$killed"
room --bind "$HOME" "$HOME" -- /usr/bin/sh -c 'echo up > "$HOME/alive"; exec /usr/bin/sleep {left}' &
# A room asked to make its program the first process, whose program then
# drops its tie to the room's starter: it still ends with the app's start.
room --as-pid-1 --bind "$HOME" "$HOME" -- /usr/bin/python3 -c "{PDEATH_CODE}{left})" </dev/null >/dev/null 2>&1 &
i=0; while [ ! -e "$HOME/pid1-up" ] && [ $i -lt 300 ]; do sleep 0.2; i=$((i+1)); done
say pid1_running "$([ -e "$HOME/pid1-up" ] && echo started || echo not-started)"
i=0; while [ ! -s "$HOME/alive" ] && [ $i -lt 300 ]; do sleep 0.2; i=$((i+1)); done
say left_running "$([ -s "$HOME/alive" ] && echo started || echo not-started)"
: > "$HOME/lifetime-done"
"#
    )
}

/// Ends an app's start once the app has written `marker` (a file in its
/// home on the computer), the way SAM's own time limit ends it: its
/// sandbox is killed. An app whose rooms still run never ends by itself:
/// its sandbox lives while any of its processes does (Bubblewrap's first
/// process waits for them all), and a room's stand-in waits for its room.
/// Gives up when `ended` is set (the start ended by itself).
fn end_start_after(marker: &std::path::Path, ended: &std::sync::atomic::AtomicBool) {
    use std::sync::atomic::Ordering;
    while !marker.exists() {
        if ended.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // The app's sandbox: a child of this process (the start runs here)
    // that is shown Room service's socket. Rooms are children too, but
    // none of these asks for that socket.
    let me = std::process::id().to_string();
    for d in fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = d.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let stat = fs::read_to_string(d.path().join("stat")).unwrap_or_default();
        let parent = stat
            .rfind(')')
            .and_then(|i| stat[i + 1..].split_whitespace().nth(1));
        let cmdline = fs::read(d.path().join("cmdline")).unwrap_or_default();
        if parent == Some(me.as_str()) && cmdline.split(|b| *b == 0).any(|a| a == b"/run/sam/rooms")
        {
            // SAFETY: a plain signal to a child of this process.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// The room link named before a place shown from the app was refused by
/// Room service's rule, and nothing reached the person's autostart folder.
fn link_named_first_refused(name: &str, log: &str, w: &World) -> Vec<String> {
    let mut out = Vec::new();
    if cases(log).get("link_first").map(String::as_str) != Some("refused")
        || !log.lines().any(|l| {
            l.starts_with("sam-room: refused")
                && l.contains("rodir/x")
                && l.contains("inside a place shown from the app")
        })
    {
        out.push(format!(
            "{name}: link_first: a room link named before a shown place was not refused by the rule"
        ));
    }
    if w.home.join(".config/autostart/link-first.desktop").exists() {
        out.push(format!(
            "{name}: a room made a link in the person's autostart folder"
        ));
    }
    out
}

/// The start record's room lines and the script's last cases, shown with
/// a failure (CI keeps no start record).
fn record_dump(name: &str, log: &str) -> String {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for l in log.lines().filter(|l| l.starts_with("sam-room:")) {
        // Group equal lines without the asking process.
        let key = match (l.find(" (asked by "), l.find("): ")) {
            (Some(a), Some(b)) if b > a => format!("{}{}", &l[..a], &l[b + 1..]),
            _ => l.to_string(),
        };
        *counts.entry(key.chars().take(240).collect()).or_default() += 1;
    }
    let lines: Vec<String> = counts.iter().map(|(l, n)| format!("{n:>4}x {l}")).collect();
    let tail: Vec<&str> = log.lines().filter(|l| l.starts_with("CASE ")).collect();
    format!(
        "{name}: the start record's room lines:\n  {}\n{name}: the last cases: {:?}",
        lines.join("\n  "),
        &tail[tail.len().saturating_sub(6)..]
    )
}

fn control_built(name: &str, log: &str) -> Option<String> {
    let c = cases(log);
    (c.get("control").map(String::as_str) != Some("ok")).then(|| {
        format!(
            "{name}: the control room was not built ({}), so Room service is missing or broken; log:\n{log}",
            c.get("control").map_or("no result", String::as_str)
        )
    })
}

/// For each `X_app` / `X_room` pair: both gave a clear result (`allowed` or
/// `blocked`; `refused` or nothing means no room was built), and the room
/// has a thing only where its app has it.
fn room_within_app(name: &str, log: &str, pairs: &[&str]) -> Vec<String> {
    let c = cases(log);
    let mut out = Vec::new();
    for p in pairs {
        let app = c.get(&format!("{p}_app")).map(String::as_str);
        let room = c.get(&format!("{p}_room")).map(String::as_str);
        // A room refused gets nothing at all: never more than its app.
        if !matches!(app, Some("allowed" | "blocked"))
            || !matches!(room, Some("allowed" | "blocked" | "refused"))
        {
            out.push(format!(
                "{name}: {p}: no clear result (app {app:?}, room {room:?})"
            ));
        } else if room == Some("allowed") && app != Some("allowed") {
            out.push(format!("{name}: {p}: the room got it, its app has not"));
        }
    }
    out
}

fn devices_within_app(name: &str, log: &str) -> Vec<String> {
    let c = cases(log);
    let set = |k: &str| -> BTreeSet<String> {
        c.get(k)
            .map(|v| v.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    };
    let (app, room) = (set("dev_app"), set("dev_room"));
    if room.is_empty() || room.contains("refused") {
        return vec![format!("{name}: dev_room: no room was built")];
    }
    let extra: Vec<&String> = room.difference(&app).collect();
    if extra.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "{name}: the room has devices the app has not: {extra:?}"
        )]
    }
}

/// Every path a room sees comes from the same file on the computer as in
/// its app (the bus is SAM's proxy, /etc/passwd SAM's own, systemd-run
/// SAM's stand-in…).
fn same_sources(name: &str, log: &str) -> Vec<String> {
    let c = cases(log);
    let parse = |k: &str| -> Option<serde_json::Map<String, serde_json::Value>> {
        serde_json::from_str::<serde_json::Value>(c.get(k)?)
            .ok()?
            .as_object()
            .cloned()
    };
    let Some(app) = parse("ids_app") else {
        return vec![format!("{name}: ids_app: no result")];
    };
    let mut out = Vec::new();
    for k in ["ids_greedy", "ids_named"] {
        let Some(room) = parse(k) else {
            out.push(format!("{name}: {k}: no room was built"));
            continue;
        };
        for (path, id) in &room {
            if !id.is_null() && app.get(path) != Some(id) {
                out.push(format!(
                    "{name}: {k}: {path} in the room is another file than in the app"
                ));
            }
        }
    }
    out
}

/// The requested environment reached the room's program (the control, when
/// `case` names one), never SAM's helper before it, nor anything on the
/// computer's side (a debug file named `stem.*` in the person's own home).
/// SAM's helper is linked statically and has no loader, so it ignores the
/// loader's variables anyway: the helper check stays as a guard against a
/// helper that is ever linked dynamically again.
fn environment_only_in_the_program(
    name: &str,
    log: &str,
    w: &World,
    id: &str,
    stem: &str,
    case: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(case) = case {
        let n = cases(log).get(case).and_then(|v| v.parse::<u32>().ok());
        if !n.is_some_and(|n| n > 0) {
            out.push(format!(
                "{name}: {case}: the requested environment never reached the program ({n:?})"
            ));
        }
    }
    let on_computer = markers(&w.home, &format!("{stem}."));
    if !on_computer.is_empty() {
        out.push(format!(
            "{name}: the requested environment reached a program outside the sandbox: {on_computer:?}"
        ));
    }
    let home = w.app_home(id);
    let in_helper = markers(&home, &format!("{stem}."))
        .iter()
        .filter(|f| {
            fs::read_to_string(home.join(f))
                .is_ok_and(|t| t.contains("sam-room-exec") || t.contains("sam-jail-run"))
        })
        .count();
    if in_helper > 0 {
        out.push(format!(
            "{name}: the requested environment reached SAM's helper before its layers ({in_helper} files)"
        ));
    }
    out
}

/// How many threads of this process carry `name` (the name a thread
/// gives itself, as /proc shows it).
fn threads_named(name: &str) -> usize {
    fs::read_dir("/proc/self/task")
        .map(|tasks| {
            tasks
                .flatten()
                .filter(|t| {
                    fs::read_to_string(t.path().join("comm")).is_ok_and(|c| c.trim_end() == name)
                })
                .count()
        })
        .unwrap_or(0)
}

/// A room built for a connection that stays open ends when the service
/// stops (the end of the app's start).
fn rooms_end_with_the_service(w: &World) -> Vec<String> {
    use sam_runner::room_rules::{AppFacts, FloorPlan, Request, VERSION};
    use sam_runner::room_service::{RoomContext, RoomService};
    use std::io::{Read, Write};
    let dir = w.root.join("service");
    fs::create_dir_all(&dir).unwrap();
    let Ok(mut service) = RoomService::open(&dir) else {
        return vec!["stop: the service could not open its socket".into()];
    };
    let mut sys: Vec<String> = Vec::new();
    for d in ["/bin", "/sbin", "/lib", "/lib32", "/lib64"] {
        let p = std::path::Path::new(d);
        if let Ok(t) = fs::read_link(p) {
            sys.extend([
                "--symlink".into(),
                t.to_string_lossy().into_owned(),
                d.into(),
            ]);
        } else if p.is_dir() {
            sys.extend(["--ro-bind".into(), d.into(), d.into()]);
        }
    }
    let mut args: Vec<String> = vec!["--ro-bind".into(), "/usr".into(), "/usr".into()];
    args.extend(sys.iter().cloned());
    service.serve(RoomContext {
        plan: FloorPlan::from_bwrap_args(&args).unwrap(),
        facts: AppFacts::default(),
        bwrap: w.host.tools.bwrap.as_ref().unwrap().path.clone(),
        landlock: sam_runner::kernel::LandlockSpec {
            read: vec!["/".into()],
            write: vec![],
        },
        seccomp: sam_runner::kernel::SeccompSpec::default(),
    });
    let sleep = format!("{}.25", 4000 + std::process::id() % 1000);
    let mut ops = vec![vec!["--ro-bind".to_string(), "/usr".into(), "/usr".into()]];
    ops.extend(sys.chunks(3).map(<[String]>::to_vec));
    let req = Request {
        v: VERSION,
        ops,
        flags: vec![],
        command: vec!["/usr/bin/sleep".into(), sleep.clone()],
        env: Default::default(),
        cwd: "/".into(),
        fds: vec![],
        limits: vec![],
        umask: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    let mut conn = std::os::unix::net::UnixStream::connect(&service.socket).unwrap();
    conn.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    conn.write_all(&body).unwrap();
    let target = ["/usr/bin/sleep", sleep.as_str()];
    // (The waits here are generous for a busy computer; they only cost
    // time when something is wrong.)
    let end = Instant::now() + Duration::from_secs(60);
    while processes(&target).is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    if processes(&target).is_empty() {
        return vec!["stop: the room was never built".into()];
    }
    // A request still being read when the service stops: it is recorded,
    // never lost.
    // It is stopped only once the service has taken the request in (a
    // thread of its own, named "sam-room", reads it): a fixed short wait
    // may end before a busy computer has taken it, and a request never
    // taken in is not one being read.
    let serving = threads_named("sam-room");
    let idle = std::os::unix::net::UnixStream::connect(&service.socket).unwrap();
    let end = Instant::now() + Duration::from_secs(30);
    while threads_named("sam-room") <= serving && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    let lines = service.stop();
    drop(idle);
    let end = Instant::now() + Duration::from_secs(30);
    while !processes(&target).is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut out = Vec::new();
    if !processes(&target).is_empty() {
        kill_all(&target);
        out.push("stop: a room outlived the service's stop".into());
    }
    if !lines.iter().any(|l| l.starts_with("sam-room: built sleep")) {
        out.push(format!("stop: the record names no room ({lines:?})"));
    }
    if !lines
        .iter()
        .any(|l| l.contains("the app's start ended while the request was read"))
    {
        out.push(format!(
            "stop: a request still being read when the service stopped is not in the record ({lines:?})"
        ));
    }
    // A service that cannot read the app's floor plan keeps its socket and
    // refuses every request, saying why.
    let dir2 = w.root.join("service-refusing");
    fs::create_dir_all(&dir2).unwrap();
    if let Ok(mut refusing) = RoomService::open(&dir2) {
        refusing.serve_refusing(
            RoomContext {
                plan: FloorPlan::default(),
                facts: AppFacts::default(),
                bwrap: w.host.tools.bwrap.as_ref().unwrap().path.clone(),
                landlock: sam_runner::kernel::LandlockSpec {
                    read: vec!["/".into()],
                    write: vec![],
                },
                seccomp: sam_runner::kernel::SeccompSpec::default(),
            },
            "no floor plan".into(),
        );
        let mut c = std::os::unix::net::UnixStream::connect(&refusing.socket).unwrap();
        c.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        c.write_all(&body).unwrap();
        let _ = c.set_read_timeout(Some(Duration::from_secs(30)));
        let mut answer = Vec::new();
        let _ = c.read_to_end(&mut answer);
        let lines = refusing.stop();
        if !String::from_utf8_lossy(&answer).contains("no floor plan")
            || !lines
                .iter()
                .any(|l| l.contains("refused") && l.contains("no floor plan"))
        {
            out.push(format!(
                "refusing: a service without a floor plan did not refuse ({lines:?})"
            ));
        }
    } else {
        out.push("refusing: the second service could not open its socket".into());
    }
    // The connection learns the room ended.
    let mut rest = Vec::new();
    let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = conn.read_to_end(&mut rest);
    if rest.len() < 4 || !String::from_utf8_lossy(&rest[4..]).contains("exit") {
        out.push(format!(
            "stop: the waiting stand-in got no answer when its room ended ({:?})",
            String::from_utf8_lossy(&rest)
        ));
    }
    out
}

/// Room service builds rooms that work, and no room ever gets more than its
/// app: not under "No network" or the full network, not in an app whose
/// Landlock and syscall filter are off, not in a shared home, not through
/// messages written by hand past the stand-in, not by exchanging a folder
/// for a link while rooms are built; and no room outlives its app.
#[test]
fn room_service_builds_working_rooms_that_never_get_more_than_their_app() {
    if !rooms_common::require() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "bwrap-rooms", "kernel-seccomp"])
        .unwrap_or_else(|e| panic!("{e}"));
    let w = World::new();
    let abstract_scoped = landlock_abi() >= 6;
    let fds_before = open_fds();
    let mut failures: Vec<String> = Vec::new();

    // Rooms work.
    let id = w.add("RoomsWork", WORKS);
    // The app ends by itself in a few seconds; the limit is only for a
    // hang, and generous: under heavy load building rooms takes many times
    // as long, and the app alone may wait a minute for its stand-in's room.
    let log = w.start(&id, |_| {}, 180);
    let before = failures.len();
    failures.extend(control_built("works", &log));
    failures.extend(
        check(
            &log,
            &[
                ("view", "no-home"),
                ("own_tmpfs", "allowed"),
                ("own_chmod", "ok"),
                ("home_rw", "allowed"),
                ("home_ro", "blocked"),
                ("fd", "via-fd-5"),
                ("exit", "7"),
                ("stdin", "piped"),
                ("env", "yes-nohome"),
                ("host_env_app", "none"),
                ("host_env_room", "none"),
                ("nested_userns", "blocked"),
                ("many_fds", "ok"),
                ("limits", "4000000/0/0077"),
                ("not_on_path", "refused"),
                ("on_path", "ok"),
                ("default_path", "ok"),
                ("pwd", "/usr"),
                ("pwd_stale", "/usr"),
                ("cwd", "/usr/bin"),
                ("cwd_not_shown", "/"),
                ("fds_most", "ok"),
                ("fds_over", "refused"),
                ("no_shebang", "ran-from-folder"),
                ("shell_missing", "next"),
                ("dev_without_devices", "blocked"),
                ("dev_links", "links"),
                ("env_not_text", "refused"),
            ],
        )
        .into_iter()
        .map(|f| format!("works: {f}")),
    );
    // The program not on PATH was looked for in a built room, not refused
    // before.
    if !log
        .lines()
        .any(|l| l.starts_with("sam-room: built sam-room-not-on-path (layers:"))
    {
        failures.push("works: not_on_path: no room was built for it".into());
    }
    let c = cases(&log);
    // The room gets exactly the program's own open connections, as with
    // Bubblewrap: no other, none missing.
    if !c.contains_key("fds") || c.get("fds") != c.get("fds_app") {
        failures.push(format!(
            "works: the room's open connections {:?} are not its program's {:?}",
            c.get("fds"),
            c.get("fds_app")
        ));
    }
    // The program really held many open connections: with fewer than 10,
    // dash would close the script's file itself and hide a leak.
    let program_fds = c.get("fds_app").map_or(0, |v| v.split(',').count());
    if program_fds < 12 {
        failures.push(format!(
            "works: the program held {program_fds} open connections, not at least 12"
        ));
    }
    if c.get("standin_is_helper").map(String::as_str) != Some("helper") {
        failures.push(format!(
            "works: bwrap on the app's PATH is not SAM's helper itself ({:?})",
            c.get("standin_is_helper")
        ));
    }
    for case in ["version", "version_by_path", "version_by_name"] {
        if c.get(case) != Some(&host_bwrap_version(&w.host)) {
            failures.push(format!(
                "works: {case}: --version does not answer like the computer's Bubblewrap ({:?})",
                c.get(case)
            ));
        }
    }
    if failures.len() > before {
        failures.push(record_dump("works", &log));
    }
    if !c
        .get("own_pids")
        .and_then(|v| v.parse::<u32>().ok())
        .is_some_and(|n| (1..=3).contains(&n))
    {
        failures.push(format!(
            "works: a room with its own /proc sees other processes ({:?})",
            c.get("own_pids")
        ));
    }
    let token = format!("tok-{}-secret", std::process::id());
    if c.get("token") != Some(&token) {
        failures.push("works: the requested environment did not reach the program".into());
    }
    let record: Vec<&str> = log.lines().filter(|l| l.contains("sam-room:")).collect();
    if !record.iter().any(|l| l.contains("sam-room: built")) {
        failures.push("works: the start record names no room".into());
    }
    // Every room's line says what SAM's helper confirmed it applied.
    let want_layers = if landlock_abi() > 0 {
        "(layers: landlock "
    } else {
        "(layers: landlock not available"
    };
    for l in record.iter().filter(|l| l.contains("sam-room: built")) {
        if !l.contains(want_layers) || !l.contains("seccomp") {
            failures.push(format!("works: a room's layers are not confirmed: {l}"));
        }
    }
    if record.iter().any(|l| l.contains(&token)) {
        failures.push("works: the start record holds a value of a room's environment".into());
    }
    if !w.app_home(&id).join("room-rw-marker").exists() {
        failures.push("works: the room's write to the app's home is not on the computer".into());
    }
    if w.app_home(&id).join("room-ro-marker").exists() {
        failures.push("works: a read-only room wrote to the app's home".into());
    }

    // Attacks, under no network, the full network, and in an app with
    // exceptions (Landlock off, its syscall filter off, nested sandboxes
    // allowed): its rooms still get SAM's layers.
    let runs: [(&str, NetworkMode, bool); 3] = [
        ("attacks-none", NetworkMode::None, false),
        ("attacks-full", NetworkMode::Full, false),
        ("exceptions", NetworkMode::Full, true),
    ];
    for (name, mode, exceptions) in runs {
        let before = failures.len();
        let id = w.add(&format!("Room{}", name.replace('-', "")), ATTACKS);
        let log = w.start(
            &id,
            |p| {
                p.network.mode = mode;
                if exceptions {
                    p.advanced.landlock = Some(false);
                    p.advanced.seccomp_baseline = false;
                    p.advanced.allow_userns = true;
                }
            },
            120,
        );
        failures.extend(control_built(name, &log));
        let mut want = vec![
            ("greedy_secret", "blocked|refused"),
            ("greedy_other_app", "blocked|refused"),
            ("greedy_settings", "blocked|refused"),
            ("greedy_key", "blocked|refused"),
            ("greedy_own_app", "blocked|refused"),
            ("link_file", "refused"),
            ("link_dir", "refused"),
            ("link_up", "refused"),
            ("link_to_app", "refused|blocked"),
            ("link_to_sam", "refused|blocked"),
            ("unknown_option", "refused"),
            ("moved_folder", "refused"),
            ("folder_by_handle", "refused"),
            ("exotic", "all-refused"),
            ("chmod_app_folder", "refused"),
            ("proc_by_name", "own-or-none|refused"),
            ("tcp_unshared", "blocked"),
            ("keyctl_room", "blocked"),
            ("userns_room", "blocked"),
            ("filter_start", "0"),
            ("filter_holds", "blocked"),
            ("filter_quiet", "0"),
            ("not_text", "refused"),
            ("planted_symlink", "refused"),
            ("planted_dir", "refused"),
            ("loader_layout", "done"),
            ("trap_link", "refused"),
            ("trap_link_later", "refused"),
            ("trap_link_name", "refused"),
        ];
        if abstract_scoped {
            want.push(("abstract_room", "blocked"));
        }
        if exceptions {
            // The control: the exceptions really apply to the app.
            want.push(("keyctl_app", "allowed"));
            want.push(("abstract_app", "allowed"));
        }
        failures.extend(
            check(&log, &want)
                .into_iter()
                .map(|f| format!("{name}: {f}")),
        );
        if !exceptions {
            failures.extend(room_within_app(name, &log, &["tcp", "abstract", "keyctl"]));
        }
        failures.extend(devices_within_app(name, &log));
        failures.extend(same_sources(name, &log));
        failures.extend(environment_only_in_the_program(
            name,
            &log,
            &w,
            &id,
            "ld",
            Some("preload"),
        ));
        let c = cases(&log);
        let want_tcp = if mode == NetworkMode::Full {
            "allowed"
        } else {
            "blocked"
        };
        if c.get("tcp_app").map(String::as_str) != Some(want_tcp) {
            failures.push(format!(
                "{name}: the app's own network is not as set ({:?}), so the network results mean nothing",
                c.get("tcp_app")
            ));
        }
        if mode == NetworkMode::Full && c.get("tcp_room").map(String::as_str) != Some("allowed") {
            failures.push(format!(
                "{name}: a room that asked for the network did not get the app's full network ({:?})",
                c.get("tcp_room")
            ));
        }
        // Refused by Room service's own rule (newer Bubblewraps refuse such
        // a link on their own; older ones follow it onto the computer).
        for planted in ["planted/evil-link.desktop", "planted/evil-dir"] {
            if !log.lines().any(|l| {
                l.contains("sam-room: refused")
                    && l.contains(planted)
                    && l.contains("inside a place shown from the app")
            }) {
                failures.push(format!(
                    "{name}: {planted}: a new thing inside a shown place was not refused by Room service's rule"
                ));
            }
        }
        // Each trap refused by its own rule, in its words.
        for (trap, words) in [
            ("trap_link", "a link to ../.sam-room is not allowed"),
            ("trap_link_later", "lies at or behind a link of the room"),
            ("trap_link_name", "a link to .sam-room is not allowed"),
        ] {
            if !log
                .lines()
                .any(|l| l.contains("sam-room: refused") && l.contains(words))
            {
                failures.push(format!(
                    "{name}: {trap}: a link of the room's own as a trap was not refused by Room service's rule ({words:?})"
                ));
            }
        }
        // The room whose own filter refuses every write was built and
        // confirmed: SAM's helper reports before loading that filter.
        if !log.lines().any(|l| {
            l.starts_with("sam-room: built sync (layers:") && l.contains("the program's own filter")
        }) {
            failures.push(format!(
                "{name}: filter_quiet: a room with a filter that refuses writes was not confirmed in the start record"
            ));
        }
        for planted in ["evil-link.desktop", "evil-dir"] {
            if w.home.join(".config/autostart").join(planted).exists() {
                failures.push(format!(
                    "{name}: a room made {planted} in the computer's autostart folder"
                ));
            }
        }
        if !log
            .lines()
            .any(|l| l.contains("sam-room: built loader-layout-check (layers: landlock"))
        {
            let rooms: Vec<&str> = log.lines().filter(|l| l.contains("sam-room:")).collect();
            failures.push(format!(
                "{name}: with the room's library folders pointing into the app's own folder, SAM's room helper did not confirm its layers; the record:\n  {}",
                rooms.join("\n  ")
            ));
        }
        if !log
            .lines()
            .any(|l| l.contains("sam-room: refused") && l.contains("--cap-add"))
        {
            failures.push(format!("{name}: a refused room is not in the start record"));
        }
        let wrote_app: Vec<String> = w
            .app_dirs()
            .iter()
            .flat_map(|d| markers(&d.join("usr/bin"), "evil-"))
            .collect();
        if !wrote_app.is_empty() {
            failures.push(format!(
                "{name}: a room wrote into an app's own folder: {wrote_app:?}"
            ));
        }
        if failures.len() > before {
            failures.push(record_dump(name, &log));
        }
    }

    // A shared home: its protected places stay protected in rooms. The
    // person's folder holds a link to Bubblewrap's view of the computer.
    fs::create_dir_all(w.home.join("rodir")).unwrap();
    std::os::unix::fs::symlink("/oldroot", w.home.join("rodir/x")).unwrap();
    let id = w.add("RoomFullHome", FULL_HOME);
    let log = w.start(
        &id,
        |p| {
            p.filesystem.home = true;
            p.filesystem.home_access = Access::Rw;
        },
        60,
    );
    failures.extend(control_built("full-home", &log));
    failures.extend(room_within_app(
        "full-home",
        &log,
        &["autostart", "bashrc", "rename", "ssh"],
    ));
    failures.extend(
        check(
            &log,
            &[
                ("ssh_app", "blocked"),
                ("ssh_room", "blocked|refused"),
                ("link_protected", "refused"),
                ("link_hidden", "refused"),
            ],
        )
        .into_iter()
        .map(|f| format!("full-home: {f}")),
    );
    if w.home.join(".config/autostart/via-link.desktop").exists() {
        failures.push("full-home: a room wrote an autostart entry through a link".into());
    }
    // Refused for the right reason: a writable home is shown only as a
    // whole, and SAM's protections lie inside it (the four requests above).
    let whole = log
        .lines()
        .filter(|l| {
            l.starts_with("sam-room: refused")
                && l.contains(
                    "a place the app can write: a room shows such a place only as a whole",
                )
        })
        .count();
    if whole < 4 {
        failures.push(format!(
            "full-home: the requests for the writable home were not refused by the only-as-a-whole rule ({whole} of 4)"
        ));
    }
    failures.extend(link_named_first_refused("full-home", &log, &w));

    // A shared home read-only: here such rooms are built, with SAM's hiding
    // and protecting places inside the home rebuilt as in the app.
    let id = w.add("RoomFullHomeRo", FULL_HOME);
    let log = w.start(
        &id,
        |p| {
            p.filesystem.home = true;
            p.filesystem.home_access = Access::Ro;
        },
        60,
    );
    failures.extend(control_built("full-home-ro", &log));
    failures.extend(
        check(
            &log,
            &[
                ("autostart_room", "blocked"),
                ("bashrc_room", "blocked"),
                ("rename_room", "blocked"),
                ("ssh_app", "blocked"),
                ("ssh_room", "blocked"),
            ],
        )
        .into_iter()
        .map(|f| format!("full-home-ro: {f}")),
    );
    failures.extend(room_within_app(
        "full-home-ro",
        &log,
        &["autostart", "bashrc", "rename", "ssh"],
    ));
    failures.extend(link_named_first_refused("full-home-ro", &log, &w));

    // A grant inside SAM's own folder, hidden from the app.
    let id = w.add("RoomSamFolderGrant", SAM_FOLDER_GRANT);
    let other = w.other_app.display().to_string();
    let log = w.start(&id, |p| p.filesystem.custom_read = vec![other.clone()], 60);
    failures.extend(control_built("sam-folder", &log));
    failures.extend(
        check(
            &log,
            &[("grant_app", "blocked"), ("grant_room", "blocked|refused")],
        )
        .into_iter()
        .map(|f| format!("sam-folder: {f}")),
    );

    // Sources held since the start, whatever the app renames.
    std::fs::create_dir_all(w.home.join("work/docs")).unwrap();
    std::fs::write(w.home.join("work/docs/f"), "inside").unwrap();
    let id = w.add("RoomHeldSources", HELD_SOURCES);
    let docs = w.home.join("work/docs").display().to_string();
    let log = w.start(
        &id,
        |p| {
            p.filesystem.home = true;
            p.filesystem.home_access = Access::Rw;
            p.filesystem.custom_read = vec![docs.clone()];
        },
        60,
    );
    failures.extend(control_built("held", &log));
    failures.extend(
        check(&log, &[("renamed", "yes"), ("held", "inside")])
            .into_iter()
            .map(|f| format!("held: {f}")),
    );
    let _ = std::fs::rename(w.home.join("work-moved"), w.home.join("work-restored"));

    // The person's own Bubblewrap arguments that cut the network.
    let id = w.add("RoomExtraArgs", EXTRA_ARGS);
    let log = w.start(
        &id,
        |p| {
            p.network.mode = NetworkMode::Full;
            p.advanced.extra_bwrap_args = vec!["--unshare-net".into()];
        },
        60,
    );
    failures.extend(control_built("extra-args", &log));
    failures.extend(
        check(&log, &[("tcp_app", "blocked"), ("tcp_room", "blocked")])
            .into_iter()
            .map(|f| format!("extra-args: {f}")),
    );
    if w.home.join(".config/autostart/room-evil.desktop").exists() {
        failures.push("full-home: a room left an autostart entry".into());
    }
    if fs::read_to_string(w.home.join(".bashrc"))
        .unwrap()
        .contains("room-evil")
    {
        failures.push("full-home: a room changed .bashrc".into());
    }
    if w.home.join(".config-room").exists() {
        failures.push("full-home: a room renamed the folder above the autostart entries".into());
    }

    // Messages past the stand-in.
    let id = w.add("RoomHostileMessages", HOSTILE_MESSAGES);
    // Ends by itself (about 25 s); the limit is only for a hang, and
    // generous for a busy computer.
    let log = w.start(&id, |_| {}, 300);
    if cases(&log).get("direct_control").map(String::as_str) != Some("exit=0") {
        failures.push(format!(
            "messages: a well-formed message built no room ({:?}), so the other results mean nothing",
            cases(&log).get("direct_control")
        ));
    }
    failures.extend(
        check(
            &log,
            &[
                ("direct_greedy", "blocked|refused"),
                ("direct_fd_place", "refused"),
                ("direct_env", "exit=0"),
                ("direct_moved", "refused"),
                ("direct_dotdot", "refused"),
                ("direct_relative", "refused"),
                ("direct_flag", "refused"),
                ("direct_no_command", "refused"),
                ("direct_unknown_field", "refused"),
                ("direct_duplicate_field", "refused"),
                ("direct_not_utf8", "refused"),
                ("direct_garbage", "refused"),
                ("direct_wrong_version", "refused"),
                ("direct_many_ops", "refused"),
                ("direct_many_places", "refused"),
                ("direct_many_fds", "refused"),
                ("direct_huge", "refused"),
                ("served_beside_idle", "yes"),
                ("connections_limited", "yes"),
                ("held_limited", "yes"),
                ("together", "30-"),
                ("long_rooms_built", "yes"),
                ("budget_released", "yes"),
                ("many_refused", "sent"),
                ("final_control", "ok"),
            ],
        )
        .into_iter()
        .map(|f| format!("messages: {f}")),
    );
    failures.extend(environment_only_in_the_program(
        "messages", &log, &w, &id, "ldm", None,
    ));
    if !log.contains("requests and rooms at once") {
        failures
            .push("messages: connections closed at the limit are not in the start record".into());
    }
    if !log.contains("too many places") {
        failures.push("messages: a room with too many places was not refused for that".into());
    }
    let refusals = log
        .lines()
        .filter(|l| l.starts_with("sam-room: refused"))
        .count();
    if refusals > 200 || !log.contains("more refusals not recorded") {
        failures.push(format!(
            "messages: the start record's refusals are not capped ({refusals} lines)"
        ));
    }
    // Rooms built are kept apart: a flood of refusals never pushes out a
    // room built after it.
    if !log.lines().any(|l| l.starts_with("sam-room: built printf")) {
        failures.push(
            "messages: a room built after a flood of refusals is missing from the start record"
                .into(),
        );
    }

    // A folder exchanged for a link while rooms are built.
    let id = w.add("RoomRace", RACE);
    let log = w.start(&id, |_| {}, 900);
    let c = cases(&log);
    let n = |k: &str| c.get(k).and_then(|v| v.parse::<u32>().ok());
    eprintln!(
        "race: real folder {:?}, secret {:?}, no room {:?}",
        n("race_inside"),
        n("race_leaked"),
        n("race_other")
    );
    match (n("race_inside"), n("race_leaked")) {
        (Some(inside), Some(0)) if inside > 0 => {}
        (inside, leaked) => {
            failures.push(format!(
                "race: rooms showing the real folder {inside:?} (must be some), showing the secret {leaked:?} (must be 0)"
            ));
            failures.push(record_dump("race", &log));
        }
    }

    // Many rooms; a stand-in killed; a room left running when the app ends.
    let left = format!("{}.5", 3000 + std::process::id() % 1000);
    let id = w.add("RoomLifetime", &lifetime_script(&left));
    let started = Instant::now();
    // The script's end ends the start (its rooms left running would keep
    // it going); the limit is only for a hang, and generous: on a computer
    // under heavy load (a mutation run runs six whole test suites at once)
    // 40 rooms took over 40 s to start.
    let marker = w.app_home(&id).join("lifetime-done");
    let ended = std::sync::atomic::AtomicBool::new(false);
    let log = std::thread::scope(|s| {
        s.spawn(|| end_start_after(&marker, &ended));
        let log = w.start(&id, |_| {}, 300);
        ended.store(true, std::sync::atomic::Ordering::SeqCst);
        log
    });
    eprintln!(
        "lifetime: the start took {:.1} s",
        started.elapsed().as_secs_f64()
    );
    let before = failures.len();
    failures.extend(
        check(
            &log,
            &[
                ("flood", "40"),
                // All twenty rooms ran and ended well (none refused), and
                // exactly sixteen ran at once: never more, and side by side.
                ("slots_ended_well", "20"),
                ("slots_ran", "20"),
                ("slots_most_at_once", "16"),
                ("killed_standin", "room-ended"),
                ("left_running", "started"),
                ("pid1_running", "started"),
            ],
        )
        .into_iter()
        .map(|f| format!("lifetime: {f}")),
    );
    if failures.len() > before {
        failures.push(record_dump("lifetime", &log));
    }
    let leftover = ["/usr/bin/sleep", left.as_str()];
    let end = Instant::now() + Duration::from_secs(30);
    while !processes(&leftover).is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(200));
    }
    if !processes(&leftover).is_empty() {
        kill_all(&leftover);
        failures.push("lifetime: a room outlived its app's start".into());
    }
    let code = format!("{PDEATH_CODE}{left})");
    let pid1 = ["/usr/bin/python3", "-c", code.as_str()];
    let end = Instant::now() + Duration::from_secs(30);
    while !processes(&pid1).is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(200));
    }
    if !processes(&pid1).is_empty() {
        kill_all(&pid1);
        failures.push(
            "lifetime: a room's program that dropped its tie to the room outlived its app's start"
                .into(),
        );
    }

    // Closing the app gives a room's program its time to save, as the app
    // gets (review of PR 95: the stand-in died of SAM's SIGTERM and its
    // room was killed at once, and the room's program was never asked).
    let id = w.add("RoomClose", CLOSE);
    let up = w.app_home(&id).join("room-up");
    let saved = w.app_home(&id).join("room-saved");
    let ended = std::sync::atomic::AtomicBool::new(false);
    let sam = &w.sam;
    let (log, closed) = std::thread::scope(|s| {
        let closer = s.spawn(|| {
            while !up.exists() {
                if ended.load(std::sync::atomic::Ordering::SeqCst) {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            // As SAM's window closes an app.
            Some(sam.stop(&id).map_err(|e| format!("{e:#}")))
        });
        let log = w.start(&id, |_| {}, 120);
        ended.store(true, std::sync::atomic::Ordering::SeqCst);
        (log, closer.join().unwrap())
    });
    let before = failures.len();
    if !matches!(closed, Some(Ok(1))) {
        failures.push(format!(
            "close: the app was not closed as one running start ({closed:?})"
        ));
    }
    if !log
        .lines()
        .any(|l| l.starts_with("sam-room: built sh (layers:"))
    {
        failures.push("close: the room was not built".into());
    }
    if fs::read_to_string(&saved).ok().as_deref() != Some("saved\n") {
        failures
            .push("close: the room's program got no time to save when its app was closed".into());
    }
    if failures.len() > before {
        failures.push(record_dump("close", &log));
    }

    // A room whose stand-in stays connected still ends when the start ends
    // (the service's own stop, besides the stand-in dying with its app).
    failures.extend(rooms_end_with_the_service(&w));

    // The room service keeps nothing open after the starts (it runs in this
    // process: a handle it forgot would also reach later rooms).
    // (Waited for a while: on a busy computer a room's thread may still be
    // closing its handles.)
    let end = Instant::now() + Duration::from_secs(10);
    while open_fds() != fds_before && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(200));
    }
    let fds_after = open_fds();
    if fds_after != fds_before {
        failures.push(format!(
            "the room service left handles open: {fds_before} before the starts, {fds_after} after"
        ));
    }

    assert!(
        failures.is_empty(),
        "Room service:\n{}",
        failures.join("\n")
    );
}
