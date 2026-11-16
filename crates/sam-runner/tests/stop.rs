//! Closing a running app (`sam-jail stop`, `remove --stop`): an app that
//! handles SIGTERM quits cleanly, one that ignores it is ended by stopping its
//! runner, and removal works afterwards. Apps are started through the real
//! `sam-jail-run`, like menu entries and the window do. Uses a fake `$HOME`.
//! Skipped when Bubblewrap cannot run here or sam-jail-run is not on PATH.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::time::{Duration, Instant};

use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};
use std::process::{Child, Command, Stdio};

fn usable() -> bool {
    let host = HostInfo::probe();
    host.tools.bwrap.is_some()
        && sam_runner::doctor::bwrap_functional(&host).is_ok()
        && sam_runner::find_helper().is_some()
}

/// Adds an app with this entry point, starts it with sam-jail-run and
/// waits until SAM sees it running.
fn start(app: &Sam, root: &std::path::Path, name: &str, apprun: &str) -> (String, Child) {
    let img = root.join(format!("{name}-1.0-x86_64.AppImage"));
    let mut spec = FixtureSpec::hello(name);
    spec.apprun = apprun.into();
    spec.host_binary = None;
    build(&img, &spec).unwrap();
    let id = app
        .add(
            &img,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let child = Command::new(sam_runner::find_helper().unwrap())
        .args(["--app-id", &id])
        .env("SAM_CONFIG_DIR", &app.paths.config_dir)
        .env("SAM_DATA_DIR", &app.paths.data_dir)
        .env("SAM_APPLICATIONS_DIR", &app.paths.applications_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(20);
    while app.running(&id).is_empty() {
        assert!(Instant::now() < end, "{name} did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(500)); // let the trap be set up
    (id, child)
}

/// Closing an app ends all of its running starts.
#[test]
fn stop_closes_running_apps() {
    if !usable() {
        eprintln!("skipping: bubblewrap or sam-jail-run not available");
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    let app = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();

    // 1. An app that quits on SIGTERM gets the chance to do so.
    let (id, mut child) = start(&app, root, "Polite", "#!/bin/sh\ntrap 'touch \"$HOME/quit-cleanly\"; exit 0' TERM\nwhile :; do sleep 0.2; done\n");
    assert!(
        app.remove(&id, false).is_err(),
        "removal refuses while the app runs"
    );
    let t = Instant::now();
    assert_eq!(app.stop(&id).unwrap(), 1);
    assert!(app.running(&id).is_empty());
    assert!(
        t.elapsed() < Duration::from_secs(8),
        "a polite app is not forced"
    );
    assert!(
        app.paths.app_home(&id).join("quit-cleanly").exists(),
        "the app quit by itself"
    );
    child.wait().unwrap();
    let last = app.resolve(&id).unwrap().last_launch.unwrap();
    assert!(
        last.success && !last.sandbox_failure,
        "recorded as closed, not failed: {}",
        last.summary
    );
    assert_eq!(last.summary, "closed by SAM");
    app.remove(&id, false).unwrap();
    assert_eq!(app.stop(&id).ok(), None, "the app is gone");

    // 2. An app that ignores SIGTERM is ended anyway.
    let (id, mut child) = start(
        &app,
        root,
        "Stubborn",
        "#!/bin/sh\ntrap '' TERM\nwhile :; do sleep 0.2; done\n",
    );
    assert_eq!(app.stop(&id).unwrap(), 1);
    assert!(app.running(&id).is_empty());
    child.wait().unwrap();
    app.remove(&id, false).unwrap();

    // 3. Nothing running: nothing to do.
    let (id, mut child) = start(
        &app,
        root,
        "Short",
        "#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 0.2; done\n",
    );
    app.stop(&id).unwrap();
    child.wait().unwrap();
    assert_eq!(app.stop(&id).unwrap(), 0);
}
