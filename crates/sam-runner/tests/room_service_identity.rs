//! A room shows exactly the files and folders SAM opened for it, whatever
//! Bubblewrap does: Ubuntu 24.04's Bubblewrap mounts a handle's path by
//! name (`--ro-bind-fd`), so a folder swapped for a link while the room is
//! built put the link's target in the room. SAM's room helper checks every
//! place against what SAM opened and ends the room otherwise. Here a
//! stand-in Bubblewrap shows another folder in place of the handle.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

mod rooms_common;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use rooms_common::World;
use sam_runner::room_rules::{AppFacts, FloorPlan, Request, VERSION};
use sam_runner::room_service::{RoomContext, RoomService};

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
/// exit code (0: the real folder, 1: another one) and the record.
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

#[test]
fn a_room_shows_only_what_sam_opened_whatever_bubblewrap_does() {
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
    fs::write(
        &fake,
        format!(
            "#!/usr/bin/python3\nimport os, sys\na = sys.argv[1:]\nout = []\ni = 0\n\
             while i < len(a):\n    if a[i] in ('--ro-bind-fd', '--bind-fd') and a[i + 2] == {real:?}:\n\
             \x20       out += ['--ro-bind', {decoy:?}, a[i + 2]]\n        i += 3\n\
             \x20   else:\n        out.append(a[i])\n        i += 1\n\
             os.execv({bwrap:?}, [{bwrap:?}] + out)\n",
            real = real_s,
            decoy = decoy.to_string_lossy(),
            bwrap = bwrap.to_string_lossy(),
        ),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let mut plan_args = system_places();
    plan_args.extend(["--ro-bind".into(), real_s.clone(), real_s.clone()]);
    let mut ops: Vec<Vec<String>> = system_places().chunks(3).map(<[String]>::to_vec).collect();
    ops.push(vec!["--ro-bind".into(), real_s.clone(), real_s.clone()]);
    let file = format!("{real_s}/f");
    let run = |bwrap: &std::path::Path, name: &str| {
        let dir = w.root.join(name);
        fs::create_dir_all(&dir).unwrap();
        let mut service = RoomService::open(&dir).unwrap();
        service.serve(RoomContext {
            plan: FloorPlan::from_bwrap_args(&plan_args).unwrap(),
            facts: AppFacts::default(),
            bwrap: bwrap.to_path_buf(),
            landlock: sam_runner::kernel::LandlockSpec {
                read: vec!["/".into()],
                write: vec![],
            },
            seccomp: sam_runner::kernel::SeccompSpec::default(),
        });
        ask(service, ops.clone(), &file)
    };
    let mut failures = Vec::new();
    // The control: with the computer's Bubblewrap the room shows the real
    // folder.
    let (code, record) = run(&bwrap, "control");
    if code != Some(0) {
        failures.push(format!(
            "control: the room did not show the real folder ({code:?}): {record:?}"
        ));
    }
    // With a Bubblewrap that shows another folder, the room never runs.
    let (code, record) = run(&fake, "swapped");
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
