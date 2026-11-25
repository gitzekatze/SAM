//! A whole start through SAM's launcher with "Game controllers": the
//! controller SAM shows is the one it watches, and once it is unplugged its
//! node is gone from the running app, which runs on to its end (review R56).
//! The controller is a stand-in (`/dev/null` behind a link, with a udev
//! record); the sandbox and the removal are real. One test per file: it
//! changes the process's environment (`testenv::isolate_this_process`).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sam_core::permissions::PermissionSet;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

fn bwrap_here() -> bool {
    let ok = Command::new("bwrap")
        .args(["--unshare-user", "--ro-bind", "/", "/", "true"])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        sam_runner::contracts::skip("Bubblewrap cannot make a sandbox here").unwrap();
    }
    ok
}

/// Through SAM's launcher: an app with "Game controllers" gets the
/// controller, and once it is unplugged the node is gone from the running
/// app, which runs on to its end (review R56).
#[test]
fn the_launcher_takes_an_unplugged_controller_out_of_the_running_app() {
    if !bwrap_here() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    // The stand-in controller and udev's record of it (/dev/null is c1:3).
    let (input, udev) = (root.join("input"), root.join("udev"));
    std::fs::create_dir_all(&input).unwrap();
    std::fs::create_dir_all(&udev).unwrap();
    let node = input.join("event99");
    std::os::unix::fs::symlink("/dev/null", &node).unwrap();
    std::fs::write(udev.join("c1:3"), "E:ID_INPUT=1\nE:ID_INPUT_JOYSTICK=1\n").unwrap();
    // The app writes what it sees into its home every 0.1 s, for 8 s.
    let img = root.join("Pad-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Pad");
    spec.apprun = format!(
        "#!/bin/sh\ni=0\nwhile [ $i -lt 80 ]; do\n  if [ -c '{n}' ]; then s=device; else s=gone; fi\n  echo $s > \"$HOME/state.new\" && mv \"$HOME/state.new\" \"$HOME/state\"\n  sleep 0.1; i=$((i+1))\ndone\necho END=1\n",
        n = node.display()
    );
    build(&img, &spec).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&root.join("samroot"))).unwrap();
    let id = sam
        .add(
            &img,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let mut p = PermissionSet::strict_gui();
    p.devices.gamepads = true;
    let mut e = sam.set_permissions(&id, p).unwrap();
    let mut host = sam_runner::testenv::test_host(HostInfo::probe());
    host.input_devices.nodes = input.clone();
    host.input_devices.udev_data = udev.clone();
    let state = sam.paths.app_home(&id).join("state");
    let (config, paths) = (sam.config.clone(), sam.paths.clone());
    let started = std::thread::spawn(move || {
        run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                owd: Some(home),
                ..Default::default()
            },
            &config,
            &paths,
            &host,
        )
        .unwrap()
    });
    let seen = |what: &str, secs: u64| {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(secs) {
            if std::fs::read_to_string(&state).is_ok_and(|s| s.trim() == what) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    };
    assert!(seen("device", 30), "the app never saw its controller");
    std::fs::remove_file(&node).unwrap();
    assert!(
        seen("gone", 5),
        "the unplugged controller is still in the sandbox"
    );
    let rec = started.join().unwrap();
    let log = std::fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap();
    assert!(rec.success, "{}: {log}", rec.summary);
    assert!(log.contains("END=1"), "the app was ended: {log}");
    assert!(
        log.contains(&format!(
            "game controller unplugged: {} taken out of the sandbox",
            node.display()
        )),
        "{log}"
    );
}
