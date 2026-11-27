//! A whole start through SAM's launcher with "Game controllers" and
//! "Nested namespaces": the app may make namespaces of its own, and a copy
//! of its controller in one of them would stay out of SAM's reach. So an
//! unplugged controller ends the app instead of being taken out (review
//! R56, independent review of PR 139). The controller is a stand-in
//! (`/dev/null` behind a link, with a udev record); the sandbox and its
//! ending are real. One test per file: it changes the process's environment
//! (`testenv::isolate_this_process`).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

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

/// With "Nested namespaces" on, SAM ends the app when its controller is
/// unplugged, and says why; the app does not run on to its end.
#[test]
fn with_nested_namespaces_an_unplugged_controller_ends_the_app() {
    // SAM ends the sandbox here: only on an isolated computer (incident
    // 2026-11-25).
    if !sam_runner::contracts::isolated_only("a start that ends its sandbox") {
        return;
    }
    if !bwrap_here() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    let (input, udev) = (root.join("input"), root.join("udev"));
    std::fs::create_dir_all(&input).unwrap();
    std::fs::create_dir_all(&udev).unwrap();
    let node = input.join("event99");
    std::os::unix::fs::symlink("/dev/null", &node).unwrap();
    std::fs::write(udev.join("c1:3"), "E:ID_INPUT=1\nE:ID_INPUT_JOYSTICK=1\n").unwrap();
    // The app writes whether it sees its controller every 0.1 s, for 8 s.
    let img = root.join("Pad-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Pad");
    spec.apprun = format!(
        r#"#!/bin/sh
i=0
while [ $i -lt 80 ]; do
  if [ -c '{n}' ]; then s=device; else s=gone; fi
  echo "$s" > "$HOME/state.new" && mv "$HOME/state.new" "$HOME/state"
  sleep 0.1; i=$((i+1))
done
echo END=1
"#,
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
    p.advanced.allow_userns = true;
    let mut e = sam.set_permissions(&id, p).unwrap();
    let mut host = sam_runner::testenv::test_host(HostInfo::probe());
    // Without Landlock SAM ends the app for that reason first.
    let landlock = host.landlock_abi.is_some();
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
    let start = Instant::now();
    while !std::fs::read_to_string(&state).is_ok_and(|s| s.trim() == "device") {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the app never saw its controller"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::remove_file(&node).unwrap();
    let rec = started.join().unwrap();
    let log = std::fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap();
    assert!(!rec.success, "{}: {log}", rec.summary);
    assert!(!log.contains("END=1"), "the app ran on to its end: {log}");
    assert!(log.contains("SAM ended the app"), "{log}");
    if !landlock {
        sam_runner::contracts::not_here("no Landlock: SAM ends the app for that reason first");
        return;
    }
    assert!(
        log.contains("the app may make namespaces of its own"),
        "the reason is named: {log}"
    );
}
