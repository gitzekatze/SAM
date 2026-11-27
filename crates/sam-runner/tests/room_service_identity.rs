//! A room shows exactly the files and folders SAM opened for it, whatever
//! Bubblewrap does: Ubuntu 24.04's Bubblewrap mounts a handle's path by
//! name (`--ro-bind-fd`), so a folder swapped for a link while the room is
//! built put the link's target in the room. SAM's room helper checks every
//! place against what SAM opened and ends the room otherwise. Here a
//! stand-in Bubblewrap shows another folder in place of the handle, and
//! another one lets a program outside the app's sandbox move a place's
//! mount away while the room is built.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod rooms_common;

use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rooms_common::World;
use sam_runner::room_rules::{AppFacts, FloorPlan, Request, VERSION};
use sam_runner::room_service::{RoomContext, RoomService};

/// `World::new` changes the whole process's environment: the tests of
/// this file take turns.
static ONE_WORLD: Mutex<()> = Mutex::new(());

/// The system folders a room needs to run a program, as links or places.
fn system_places() -> Vec<String> {
    let mut sys = vec!["--ro-bind".to_string(), "/usr".into(), "/usr".into()];
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
    sys
}

/// What a room did: the exit code in the service's reply, the service's
/// record and what the room wrote to its standard error.
struct Outcome {
    code: Option<i64>,
    record: Vec<String>,
    stderr: String,
}

/// A room's program that greps for `real` in `file`: exit code 0 when the
/// real file was shown, 1 for another one.
fn grep_for_real(file: &str) -> Vec<String> {
    vec![
        "/usr/bin/grep".into(),
        "-q".into(),
        "real".into(),
        file.into(),
    ]
}

/// Sends `data` over `conn` with the connection `fd` riding along, as a
/// program in the app passes its connections to its room.
fn send_with_fd(conn: &UnixStream, data: &[u8], fd: RawFd) {
    let fds = [fd];
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(&fds) as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: an all-zero msghdr is valid; it is pointed at live buffers below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: the control buffer has room for one header with one
    // connection number (CMSG_SPACE above).
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(&fds) as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd);
    }
    // SAFETY: msg points at the live buffers above, of the sizes given.
    let n = unsafe { libc::sendmsg(conn.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    assert_eq!(n, data.len() as isize, "the request was not sent whole");
}

/// Asks `service` for a room with `ops` that runs `command`, with a pipe of
/// this test as the room's standard error.
fn ask(service: RoomService, ops: Vec<Vec<String>>, command: Vec<String>) -> Outcome {
    let req = Request {
        v: VERSION,
        ops,
        flags: vec![],
        command,
        env: Default::default(),
        cwd: "/".into(),
        fds: vec![2],
        limits: vec![],
        umask: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    let mut msg = (body.len() as u32).to_be_bytes().to_vec();
    msg.extend(&body);
    let (mut err_read, err_write) = std::io::pipe().unwrap();
    let conn = UnixStream::connect(&service.socket).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    send_with_fd(&conn, &msg, err_write.as_raw_fd());
    drop(err_write);
    // Read until the room's last copy of the pipe is closed.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err_read.read_to_string(&mut s);
        let _ = tx.send(s);
    });
    let mut conn = conn;
    let mut head = [0u8; 4];
    let code = conn.read_exact(&mut head).ok().and_then(|()| {
        let mut b = vec![0u8; u32::from_be_bytes(head) as usize];
        conn.read_exact(&mut b).ok()?;
        serde_json::from_slice::<serde_json::Value>(&b).ok()?["exit"].as_i64()
    });
    let record = service.stop();
    let stderr = rx
        .recv_timeout(Duration::from_secs(30))
        .unwrap_or_else(|_| "(the room's standard error was still open)".into());
    Outcome {
        code,
        record,
        stderr,
    }
}

/// Serves one room request with the floor plan of `plan_args`, through
/// the Bubblewrap at `bwrap`, in a runtime folder `name` of its own: a
/// room that greps for `real` in `file`.
fn serve_room(
    w: &World,
    bwrap: &Path,
    name: &str,
    plan_args: &[String],
    ops: &[Vec<String>],
    file: &str,
) -> Outcome {
    let dir = w.root.join(name);
    fs::create_dir_all(&dir).unwrap();
    let mut service = RoomService::open(&dir).unwrap();
    service.serve(RoomContext {
        plan: FloorPlan::from_bwrap_args(plan_args).unwrap(),
        facts: AppFacts::default(),
        bwrap: bwrap.to_path_buf(),
        landlock: sam_runner::kernel::LandlockSpec {
            read: vec!["/".into()],
            write: vec![],
        },
        seccomp: sam_runner::kernel::SeccompSpec::default(),
    });
    ask(service, ops.to_vec(), grep_for_real(file))
}

/// The same room: its exit code (0: the real file was shown, 1: another
/// one) and the record.
fn room(
    w: &World,
    bwrap: &Path,
    name: &str,
    plan_args: &[String],
    ops: &[Vec<String>],
    file: &str,
) -> (Option<i64>, Vec<String>) {
    let out = serve_room(w, bwrap, name, plan_args, ops, file);
    (out.code, out.record)
}

/// Writes the stand-in Bubblewrap `script` (Python) as a program.
fn stand_in(at: &Path, script: &str) {
    fs::write(at, script).unwrap();
    fs::set_permissions(at, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A stand-in Bubblewrap at `at` that is the real one at `bwrap`, with the
/// folder `sync` for two signals and a short wait in the room right before
/// SAM's helper. A program of its own, outside the room, waits for the
/// room to be ready, then makes `the_move` (each step `(how, from, to)`,
/// `how` being `link` or `rename`; none for a control) and lets the room
/// go on.
fn pausing_bwrap(at: &Path, bwrap: &Path, sync: &Path, the_move: &[(&str, &Path, &Path)]) {
    fs::create_dir_all(sync).unwrap();
    let steps: String = the_move
        .iter()
        .map(|(how, from, to)| format!("        os.{how}({from:?}, {to:?})\n"))
        .collect();
    stand_in(
        at,
        &format!(
            r#"#!/usr/bin/python3
import os, sys, time
a = sys.argv[1:]
end = a.index('--')
wait = (': > /sync/ready; n=0; '
        'while [ ! -e /sync/go ] && [ $n -lt 3000 ]; do /usr/bin/sleep 0.01; n=$((n+1)); done; '
        'exec "$@"')
out = ['--bind', {sync:?}, '/sync'] + a[:end] + ['--', '/bin/sh', '-c', wait, 'sh'] + a[end + 1:]
if os.fork() == 0:
    if os.fork() == 0:
        os.closerange(3, 1 << 16)
        until = time.time() + 30
        while not os.path.exists({ready:?}):
            if time.time() > until:
                os._exit(1)
            time.sleep(0.01)
{steps}        open({go:?}, 'w').close()
    os._exit(0)
os.wait()
os.execv({bwrap:?}, [{bwrap:?}] + out)
"#,
            sync = sync.to_string_lossy(),
            ready = sync.join("ready").to_string_lossy(),
            go = sync.join("go").to_string_lossy(),
            bwrap = bwrap.to_string_lossy(),
        ),
    );
}

#[test]
fn a_room_shows_only_what_sam_opened_whatever_bubblewrap_does() {
    let _turn = ONE_WORLD.lock().unwrap_or_else(|e| e.into_inner());
    if !rooms_common::require() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "bwrap-rooms"])
        .unwrap_or_else(|e| panic!("{e}"));
    let w = World::new();
    let base = w.root.join("identity");
    let (real, decoy) = (base.join("real"), base.join("decoy"));
    fs::create_dir_all(&real).unwrap();
    fs::create_dir_all(&decoy).unwrap();
    fs::write(real.join("f"), "real\n").unwrap();
    fs::write(decoy.join("f"), "decoy\n").unwrap();
    let real_s = real.to_string_lossy().into_owned();
    let bwrap = w.host.tools.bwrap.as_ref().unwrap().path.clone();
    // A Bubblewrap that shows the decoy where SAM passed the real folder's
    // handle (what a by-name mount does when the name was swapped).
    let fake = base.join("bwrap");
    stand_in(
        &fake,
        &format!(
            "#!/usr/bin/python3\nimport os, sys\na = sys.argv[1:]\nout = []\ni = 0\n\
             while i < len(a):\n    if a[i] in ('--ro-bind-fd', '--bind-fd') and a[i + 2] == {real:?}:\n\
             \x20       out += ['--ro-bind', {decoy:?}, a[i + 2]]\n        i += 3\n\
             \x20   else:\n        out.append(a[i])\n        i += 1\n\
             os.execv({bwrap:?}, [{bwrap:?}] + out)\n",
            real = real_s,
            decoy = decoy.to_string_lossy(),
            bwrap = bwrap.to_string_lossy(),
        ),
    );
    let mut plan_args = system_places();
    plan_args.extend(["--ro-bind".into(), real_s.clone(), real_s.clone()]);
    let mut ops: Vec<Vec<String>> = system_places().chunks(3).map(<[String]>::to_vec).collect();
    ops.push(vec!["--ro-bind".into(), real_s.clone(), real_s.clone()]);
    let file = format!("{real_s}/f");
    let mut failures = Vec::new();
    // The control: with the computer's Bubblewrap the room shows the real
    // folder.
    let (code, record) = room(&w, &bwrap, "control", &plan_args, &ops, &file);
    if code != Some(0) {
        failures.push(format!(
            "control: the room did not show the real folder ({code:?}): {record:?}"
        ));
    }
    // With a Bubblewrap that shows another folder, the room never runs.
    let (code, record) = room(&w, &fake, "swapped", &plan_args, &ops, &file);
    if code == Some(1) {
        failures.push("a room showed another folder than the one SAM opened".into());
    }
    if code == Some(0)
        || !record
            .iter()
            .any(|l| l.starts_with("sam-room: failed grep"))
    {
        failures.push(format!(
            "the room with another folder was not ended by SAM's helper ({code:?}): {record:?}"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// After Bubblewrap mounted a room's place, a program outside the app's
/// sandbox that can write the folder holding it (another program of the
/// person's) moves the place away (the room's mount goes with its name)
/// and puts the very same file back at the name (a second name made
/// beforehand, a hard link). The room then reaches the file SAM opened, by
/// the same device and inode, but no longer through the mount Bubblewrap
/// made. SAM's helper requires every place to be the root of a mount and
/// ends such a room before its program runs. Today that costs a room
/// nothing it had: Room service shows nothing inside a place the app can
/// write (`nothing_is_placed_inside_a_place_the_app_can_write`), so the
/// folder that then shows the file is read-only, as here; the rule is
/// defence in depth. The stand-in Bubblewrap is the real one; it only lets
/// the room wait, just before SAM's helper, until the program outside has
/// made its move, so the move lands in exactly that moment every time.
/// The control goes through the same stand-in and wait without a move.
/// The check runs once, at that moment: a move made later, while the
/// room's program runs, is not caught (docs/security.md, Known
/// limitations).
#[test]
fn a_room_place_whose_mount_was_moved_away_and_the_original_put_back_is_refused() {
    let _turn = ONE_WORLD.lock().unwrap_or_else(|e| e.into_inner());
    if !rooms_common::require() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "bwrap-rooms"])
        .unwrap_or_else(|e| panic!("{e}"));
    let w = World::new();
    let base = w.root.join("moved");
    let work = base.join("work");
    fs::create_dir_all(&work).unwrap();
    let f = work.join("f");
    fs::write(&f, "real\n").unwrap();
    let ino = fs::metadata(&f).unwrap().ino();
    let (away, spare) = (work.join("away"), work.join("spare"));
    let bwrap = w.host.tools.bwrap.as_ref().unwrap().path.clone();
    // The app sees the folder read-only and the file as a place of its
    // own (as SAM shows a locked file); the room asks for the folder.
    let (work_s, f_s) = (
        work.to_string_lossy().into_owned(),
        f.to_string_lossy().into_owned(),
    );
    let mut plan_args = system_places();
    plan_args.extend(["--ro-bind".into(), work_s.clone(), work_s.clone()]);
    plan_args.extend(["--ro-bind".into(), f_s.clone(), f_s.clone()]);
    let mut ops: Vec<Vec<String>> = system_places().chunks(3).map(<[String]>::to_vec).collect();
    ops.push(vec!["--ro-bind".into(), work_s.clone(), work_s.clone()]);
    let same = |p: &Path| fs::metadata(p).is_ok_and(|m| m.ino() == ino);
    let mut failures = Vec::new();

    // The control: the same stand-in and its wait, no move. SAM's helper
    // lets the room run, and the room shows the file.
    let still = base.join("bwrap-still");
    pausing_bwrap(&still, &bwrap, &base.join("sync-still"), &[]);
    let out = serve_room(&w, &still, "still", &plan_args, &ops, &f_s);
    if out.code != Some(0)
        || !out
            .record
            .iter()
            .any(|l| l.starts_with("sam-room: built grep"))
    {
        failures.push(format!(
            "control: without a move the room did not run and show the file ({:?}): {:?}; {}",
            out.code, out.record, out.stderr
        ));
    }

    // The move, made by a program outside while the room is built.
    let moving = base.join("bwrap-moved");
    let sync = base.join("sync-moved");
    pausing_bwrap(
        &moving,
        &bwrap,
        &sync,
        &[
            ("link", &f, &spare),
            ("rename", &f, &away),
            ("rename", &spare, &f),
        ],
    );
    let out = serve_room(&w, &moving, "moved", &plan_args, &ops, &f_s);
    // The move really happened: the file's first name now holds the
    // room's mount, and the very same file is back at its name.
    if !(sync.join("go").exists() && same(&away) && same(&f)) {
        failures.push(format!(
            "the move did not take place (signal {}, moved {}, put back {}): {:?}",
            sync.join("go").exists(),
            same(&away),
            same(&f),
            out.record
        ));
    }
    if out.code == Some(0) {
        failures.push(
            "a room ran with a place that was no longer the mount Bubblewrap made (the file SAM opened, put back at its name)"
                .into(),
        );
    }
    // Ended by SAM's helper, for exactly this reason.
    let why = format!(
        "{f_s} is not the place SAM checked for this room (it is no longer shown through the mount made there (moved away))"
    );
    if !out
        .record
        .iter()
        .any(|l| l.starts_with("sam-room: failed grep"))
        || !out.stderr.contains(&why)
    {
        failures.push(format!(
            "the room whose place was moved away was not ended by SAM's helper for that reason ({:?}): {:?}; {}",
            out.code, out.record, out.stderr
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
