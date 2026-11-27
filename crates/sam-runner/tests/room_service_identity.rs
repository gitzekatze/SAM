//! A room shows exactly the files and folders SAM opened for it, whatever
//! Bubblewrap does: Ubuntu 24.04's Bubblewrap mounts a handle's path by
//! name (`--ro-bind-fd`), so a folder swapped for a link while the room is
//! built put the link's target in the room. SAM's room helper checks every
//! place against what SAM opened and ends the room otherwise. Here a
//! stand-in Bubblewrap shows another folder in place of the handle, and
//! another one lets a program outside the room move a place's mount away
//! while the room is built.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod rooms_common;

use std::fs;
use std::io::{Read, Write};
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

/// Asks `service` for a room that greps for `real` in `file`; the room's
/// exit code (0: the real file was shown, 1: another one) and the record.
fn ask(service: RoomService, ops: Vec<Vec<String>>, file: &str) -> (Option<i64>, Vec<String>) {
    let req = Request {
        v: VERSION,
        ops,
        flags: vec![],
        command: vec![
            "/usr/bin/grep".into(),
            "-q".into(),
            "real".into(),
            file.into(),
        ],
        env: Default::default(),
        cwd: "/".into(),
        fds: vec![],
        limits: vec![],
        umask: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    let mut conn = UnixStream::connect(&service.socket).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    conn.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    conn.write_all(&body).unwrap();
    let mut head = [0u8; 4];
    let code = conn.read_exact(&mut head).ok().and_then(|()| {
        let mut b = vec![0u8; u32::from_be_bytes(head) as usize];
        conn.read_exact(&mut b).ok()?;
        serde_json::from_slice::<serde_json::Value>(&b).ok()?["exit"].as_i64()
    });
    (code, service.stop())
}

/// Serves one room request with the floor plan of `plan_args`, through
/// the Bubblewrap at `bwrap`, in a runtime folder `name` of its own.
fn room(
    w: &World,
    bwrap: &Path,
    name: &str,
    plan_args: &[String],
    ops: &[Vec<String>],
    file: &str,
) -> (Option<i64>, Vec<String>) {
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
    ask(service, ops.to_vec(), file)
}

/// Writes the stand-in Bubblewrap `script` (Python) as a program.
fn stand_in(at: &Path, script: &str) {
    fs::write(at, script).unwrap();
    fs::set_permissions(at, fs::Permissions::from_mode(0o755)).unwrap();
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

/// After Bubblewrap mounted a room's place, a program outside the room
/// that can write the folder holding it moves the place away (the room's
/// mount goes with its name) and puts the very same file back at the name
/// (a second name made beforehand, a hard link). The room then shows the
/// file SAM opened, by the same device and inode, but no longer through
/// the mount Bubblewrap made, so whatever that mount gave (read-only, or a
/// handle in place of a name) no longer holds. SAM's helper requires every
/// place to be the root of a mount and ends such a room. The stand-in
/// Bubblewrap is the real one; it only lets the room wait, just before
/// SAM's helper, until the program outside has made its move, so the move
/// lands in exactly that moment every time.
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
    let sync = base.join("sync");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&sync).unwrap();
    let f = work.join("f");
    fs::write(&f, "real\n").unwrap();
    let ino = fs::metadata(&f).unwrap().ino();
    let (away, spare) = (work.join("away"), work.join("spare"));
    let (ready, go) = (sync.join("ready"), sync.join("go"));
    let bwrap = w.host.tools.bwrap.as_ref().unwrap().path.clone();
    // The real Bubblewrap, with a folder for the two signals and a short
    // wait in the room right before SAM's helper; a program of its own,
    // outside the room, makes the move during that wait.
    let fake = base.join("bwrap");
    stand_in(
        &fake,
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
        os.link({f:?}, {spare:?})
        os.rename({f:?}, {away:?})
        os.rename({spare:?}, {f:?})
        open({go:?}, 'w').close()
    os._exit(0)
os.wait()
os.execv({bwrap:?}, [{bwrap:?}] + out)
"#,
            sync = sync.to_string_lossy(),
            ready = ready.to_string_lossy(),
            go = go.to_string_lossy(),
            f = f.to_string_lossy(),
            spare = spare.to_string_lossy(),
            away = away.to_string_lossy(),
            bwrap = bwrap.to_string_lossy(),
        ),
    );
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
    let mut failures = Vec::new();
    // The control: with the computer's Bubblewrap and no move, the room
    // shows the file.
    let (code, record) = room(&w, &bwrap, "control", &plan_args, &ops, &f_s);
    if code != Some(0) {
        failures.push(format!(
            "control: the room did not show the file ({code:?}): {record:?}"
        ));
    }
    let (code, record) = room(&w, &fake, "moved", &plan_args, &ops, &f_s);
    // The move really happened while the room was built: the file's first
    // name now holds the room's mount, and the very same file is back at
    // its name.
    let same = |p: &Path| fs::metadata(p).is_ok_and(|m| m.ino() == ino);
    if !(go.exists() && same(&away) && same(&f)) {
        failures.push(format!(
            "the move did not take place (signal {}, moved {}, put back {}): {record:?}",
            go.exists(),
            same(&away),
            same(&f)
        ));
    }
    if code == Some(0) {
        failures.push(
            "a room ran with a place that was no longer the mount Bubblewrap made (the file SAM opened, put back at its name)"
                .into(),
        );
    }
    if !record
        .iter()
        .any(|l| l.starts_with("sam-room: failed grep"))
    {
        failures.push(format!(
            "the room whose place was moved away was not ended by SAM's helper ({code:?}): {record:?}"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
