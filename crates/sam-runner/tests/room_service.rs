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

/// Rooms work: a room shows what it asks for and nothing of the app it did
/// not ask for, writes where asked and the app can, passes open
/// connections, the exit code and its environment, answers like the
/// computer's Bubblewrap, gets no other open connection and nothing of the
/// computer's environment, and keeps what it asked to give up.
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
say fds "$(rv room --proc /proc -- $P fds)"
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
say moved_folder "$(rv room --ro-bind /usr /elsewhere -- /usr/bin/echo ok)"
exec 7<"$HOME"
say folder_by_handle "$(rv room --bind-fd 7 "$HOME" -- /usr/bin/echo ok)"
exec 7<&-
accepted=""
for opt in "--userns 0" "--userns2 0" "--pidns 0" "--info-fd 1" "--json-status-fd 1" \
           "--overlay-src /usr" "--uid 0" "--gid 0" "--exec-label x" "--file-label x" \
           "--file 0 /x" "--bind-data 0 /x" "--ro-bind-data 0 /x" "--sync-fd 1" \
           "--block-fd 0" "--userns-block-fd 0" "--cap-add CAP_SYS_ADMIN"; do
  # A file, not a pipe: a process the attempt leaves behind must not hold
  # this script up.
  # shellcheck disable=SC2086
  timeout -s KILL 10 bwrap --ro-bind /usr /usr $SYS $opt -- /usr/bin/echo ok </dev/null >"$HOME/exotic.out" 2>/dev/null
  rc=$?
  out=$(cat "$HOME/exotic.out")
  case "$rc:$out" in
    137:*) accepted="$accepted [$opt: hung]" ;;
    *:ok) accepted="$accepted [$opt]" ;;
  esac
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
exec 11<"$HOME/filter.bpf"
room --seccomp 11 -- /usr/bin/true
say filter_start "$?"
exec 11<&-
exec 11<"$HOME/filter.bpf"
say filter_holds "$(rv room --seccomp 11 -- $P uname)"
exec 11<&-
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
    return "refused" if r in ("refused", "closed") else r

say("direct_control", ask(request(BASE, ["/usr/bin/true"])))
probe = f'echo "CASE direct_greedy=$(/usr/bin/python3 -I -S {APPDIR}/usr/bin/probe.py read {SECRET_FILE})"'
if ask(request([["--bind", "/", "/"]] + BASE, ["/usr/bin/sh", "-c", probe], fds=[1]), fds=[1]) != "exit=0":
    say("direct_greedy", "refused")
home_fd = os.open(HOME, os.O_RDONLY | os.O_DIRECTORY)
say("direct_fd_place", refusal(ask(request(BASE + [["--bind-fd", str(home_fd), HOME]], ["/usr/bin/true"], fds=[home_fd]), fds=[home_fd])))
os.close(home_fd)
say("direct_env", ask(request(BASE + [["--dev", "/dev"], ["--bind", HOME, HOME]], ["/usr/bin/true"],
                              env={"LD_DEBUG": "files", "LD_DEBUG_OUTPUT": HOME + "/ldm", "HOME": HOME})))
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
say("direct_many_places", refusal(ask(request(BASE + [["--dir", f"/d{i}"] for i in range(257)], ["/usr/bin/true"]))))
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
PY
say final_control "$(rv room -- /usr/bin/echo ok)"
"#;

/// A folder the room asks for is exchanged, as fast as the kernel allows,
/// with a link out of the app's view (absolute and relative) while rooms
/// are built: no room may ever show what the link points to.
const RACE: &str = r#"
mkdir -p "$HOME/race/d"
echo inside > "$HOME/race/d/f"
ln -sfn "$SECRET_DIR" "$HOME/race/abs"
ln -sfn "../../../../../../../../../../../../..$SECRET_DIR" "$HOME/race/rel"
python3 - <<'PY' &
import ctypes, os, time
libc = ctypes.CDLL(None, use_errno=True)
AT, EXCHANGE = -100, 2
h = os.environ["HOME"] + "/race/"
d, a, r = (h + "d").encode(), (h + "abs").encode(), (h + "rel").encode()
end = time.monotonic() + 90
while time.monotonic() < end:
    for other in (a, a, r, r):
        libc.renameat2(AT, d, AT, other, EXCHANGE)
PY
swapper=$!
inside=0; leaked=0; other=0; i=0
while [ $i -lt 400 ]; do
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

/// Many rooms at once all finish. A stand-in killed outright ends its room;
/// a room still running when its app ends does not outlive the app's start.
fn lifetime_script(left: &str) -> String {
    format!(
        r#"
pids=""
i=0
while [ $i -lt 40 ]; do room -- /usr/bin/sleep 1 & pids="$pids $!"; i=$((i+1)); done
ok=0
for p in $pids; do wait "$p" && ok=$((ok+1)); done
say flood "$ok"
# bwrap itself in the background (not the room function, whose $! would be
# a subshell): $! is then the stand-in.
# shellcheck disable=SC2086
bwrap --ro-bind /usr /usr $SYS --bind "$HOME" "$HOME" -- /usr/bin/sh -c 'while :; do date +%s%N > "$HOME/beat"; /usr/bin/sleep 0.2; done' &
standin=$!
i=0; while [ ! -s "$HOME/beat" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
kill -9 "$standin"
sleep 2; a=$(cat "$HOME/beat" 2>/dev/null); sleep 2; b=$(cat "$HOME/beat" 2>/dev/null)
if [ -z "$a" ]; then say killed_standin no-room
elif [ "$a" = "$b" ]; then say killed_standin room-ended
else say killed_standin room-still-running; fi
room --bind "$HOME" "$HOME" -- /usr/bin/sh -c 'echo up > "$HOME/alive"; exec /usr/bin/sleep {left}' &
i=0; while [ ! -s "$HOME/alive" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
say left_running "$([ -s "$HOME/alive" ] && echo started || echo not-started)"
"#
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
        if !matches!(app, Some("allowed" | "blocked"))
            || !matches!(room, Some("allowed" | "blocked"))
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
        .filter(|f| fs::read_to_string(home.join(f)).is_ok_and(|t| t.contains("sam-jail-run")))
        .count();
    if in_helper > 0 {
        out.push(format!(
            "{name}: the requested environment reached SAM's helper before its layers ({in_helper} files)"
        ));
    }
    out
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
        helper: sam_runner::find_helper().unwrap(),
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
    };
    let body = serde_json::to_vec(&req).unwrap();
    let mut conn = std::os::unix::net::UnixStream::connect(&service.socket).unwrap();
    conn.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    conn.write_all(&body).unwrap();
    let target = ["/usr/bin/sleep", sleep.as_str()];
    let end = Instant::now() + Duration::from_secs(10);
    while processes(&target).is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    if processes(&target).is_empty() {
        return vec!["stop: the room was never built".into()];
    }
    let lines = service.stop();
    let end = Instant::now() + Duration::from_secs(5);
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
    // The connection learns the room ended.
    let mut rest = Vec::new();
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = conn.read_to_end(&mut rest);
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
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "kernel-seccomp"])
        .unwrap_or_else(|e| panic!("{e}"));
    let w = World::new();
    let abstract_scoped = landlock_abi() >= 6;
    let fds_before = open_fds();
    let mut failures: Vec<String> = Vec::new();

    // Rooms work.
    let id = w.add("RoomsWork", WORKS);
    let log = w.start(&id, |_| {}, 60);
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
                ("fds", "0,1,2"),
                ("host_env_app", "none"),
                ("host_env_room", "none"),
                ("nested_userns", "blocked"),
                ("many_fds", "ok"),
            ],
        )
        .into_iter()
        .map(|f| format!("works: {f}")),
    );
    let c = cases(&log);
    if c.get("version") != Some(&host_bwrap_version(&w.host)) {
        failures.push(format!(
            "works: --version does not answer like the computer's Bubblewrap ({:?})",
            c.get("version")
        ));
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
            ("greedy_secret", "blocked"),
            ("greedy_other_app", "blocked"),
            ("greedy_settings", "blocked"),
            ("greedy_key", "blocked"),
            ("greedy_own_app", "blocked"),
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
    }

    // A shared home: its protected places stay protected in rooms.
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
        &["autostart", "bashrc", "rename"],
    ));
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
    let log = w.start(&id, |_| {}, 150);
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
                ("direct_many_places", "refused"),
                ("direct_many_fds", "refused"),
                ("direct_huge", "refused"),
                ("served_beside_idle", "yes"),
                ("final_control", "ok"),
            ],
        )
        .into_iter()
        .map(|f| format!("messages: {f}")),
    );
    failures.extend(environment_only_in_the_program(
        "messages", &log, &w, &id, "ldm", None,
    ));

    // A folder exchanged for a link while rooms are built.
    let id = w.add("RoomRace", RACE);
    let log = w.start(&id, |_| {}, 240);
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
        (inside, leaked) => failures.push(format!(
            "race: rooms showing the real folder {inside:?} (must be some), showing the secret {leaked:?} (must be 0)"
        )),
    }

    // Many rooms; a stand-in killed; a room left running when the app ends.
    let left = format!("{}.5", 3000 + std::process::id() % 1000);
    let id = w.add("RoomLifetime", &lifetime_script(&left));
    let started = Instant::now();
    let log = w.start(&id, |_| {}, 40);
    eprintln!(
        "lifetime: the start took {:.1} s",
        started.elapsed().as_secs_f64()
    );
    failures.extend(
        check(
            &log,
            &[
                ("flood", "40"),
                ("killed_standin", "room-ended"),
                ("left_running", "started"),
            ],
        )
        .into_iter()
        .map(|f| format!("lifetime: {f}")),
    );
    let leftover = ["/usr/bin/sleep", left.as_str()];
    let end = Instant::now() + Duration::from_secs(10);
    while !processes(&leftover).is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(200));
    }
    if !processes(&leftover).is_empty() {
        kill_all(&leftover);
        failures.push("lifetime: a room outlived its app's start".into());
    }

    // A room whose stand-in stays connected still ends when the start ends
    // (the service's own stop, besides the stand-in dying with its app).
    failures.extend(rooms_end_with_the_service(&w));

    // The room service keeps nothing open after the starts (it runs in this
    // process: a handle it forgot would also reach later rooms).
    std::thread::sleep(Duration::from_millis(500));
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
