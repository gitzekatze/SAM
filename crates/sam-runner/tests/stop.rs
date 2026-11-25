//! Closing a running app (`sam-jail stop`, `remove --stop`): an app that
//! handles SIGTERM quits cleanly, one that ignores it is ended by stopping its
//! runner, and removal works afterwards. Apps are started through the real
//! `sam-jail-run`, like menu entries and the window do. Uses a fake `$HOME`.
//! Skipped when Bubblewrap cannot run here or SAM's helper is not found.
//! Runs the same on every computer (testenv::isolate_command).
//! A launch started while closing runs uses stand-ins for the runners
//! (shells that hold their launch's lock as sam-jail-run does) and runs
//! everywhere, without Bubblewrap.
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
    // Settings nobody has confirmed do not start (audit U-M11).
    app.mark_reviewed(&id).unwrap();
    let mut cmd = Command::new(sam_runner::find_helper().unwrap());
    cmd.args(["--app-id", &id])
        .env("SAM_CONFIG_DIR", &app.paths.config_dir)
        .env("SAM_DATA_DIR", &app.paths.data_dir)
        .env("SAM_APPLICATIONS_DIR", &app.paths.applications_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Its runtime folder is the one of `app`; the same run on every computer.
    sam_runner::testenv::isolate_command(&mut cmd, &root.join("sam"));
    let child = cmd.spawn().unwrap();
    // The app says when its signal handler is set: a fixed pause was a guess
    // that a slow computer could miss.
    let ready = app.paths.app_home(&id).join("ready");
    let end = Instant::now() + Duration::from_secs(20);
    while app.running(&id).is_empty() || !ready.exists() {
        assert!(Instant::now() < end, "{name} did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    (id, child)
}

/// Closing an app ends all of its running starts.
#[test]
fn stop_closes_running_apps() {
    if !usable() {
        sam_runner::contracts::skip("bubblewrap or sam-jail-run not available")
            .unwrap_or_else(|e| panic!("{e}"));
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
    let (id, mut child) = start(&app, root, "Polite", "#!/bin/sh\ntrap 'touch \"$HOME/quit-cleanly\"; exit 0' TERM\ntouch \"$HOME/ready\"\nwhile :; do sleep 0.2; done\n");
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
        "#!/bin/sh\ntrap '' TERM\ntouch \"$HOME/ready\"\nwhile :; do sleep 0.2; done\n",
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
        "#!/bin/sh\ntrap 'exit 0' TERM\ntouch \"$HOME/ready\"\nwhile :; do sleep 0.2; done\n",
    );
    app.stop(&id).unwrap();
    child.wait().unwrap();
    assert_eq!(app.stop(&id).unwrap(), 0);
}

/// A stand-in for a launch's runner (sam-jail-run): a shell that holds its
/// launch's `running.lock` open and locked, in the launch folder named
/// after its process number, as a real launch does. `script` runs in it,
/// with `marks` as `$0`.
fn stand_in_runner(
    base: &std::path::Path,
    marks: &std::path::Path,
    script: &str,
) -> (Child, std::path::PathBuf) {
    use std::os::fd::AsRawFd;
    // Made under another name first: the folder's name needs the
    // process number, known once it runs.
    let pending = base.join("pending");
    fs::create_dir_all(&pending).unwrap();
    let lock = fs::File::create(pending.join("running.lock")).unwrap();
    // SAFETY: `lock` is an open file; flock only takes its descriptor.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    // The shell keeps the locked file open as its input.
    let child = Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(marks)
        .stdin(Stdio::from(lock))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let dir = base.join(format!("l{}-0", child.id()));
    fs::rename(&pending, &dir).unwrap();
    (child, dir)
}

/// Closing an app closes the launches running when it began and waits
/// only for those: a launch started meanwhile is neither asked to quit nor
/// waited for, so closing ends once the earlier launch has (review B2 S6,
/// R85: closing waited for every launch of the app, so a quick start again
/// kept it waiting until it failed after 28 seconds, and its signals went
/// to the earlier runner's process number long after the check).
#[test]
fn a_launch_started_while_closing_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let img = root.join("Again-1.0-x86_64.AppImage");
    build(&img, &FixtureSpec::hello("Again")).unwrap();
    let app = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
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
    let base = app.paths.runtime_dir(&id);
    let marks = root.join("marks");
    fs::create_dir_all(&marks).unwrap();
    // The earlier launch takes two seconds to finish once asked.
    let (mut first, first_dir) = stand_in_runner(
        &base,
        &marks,
        "trap 'sleep 2; exit 0' TERM; while :; do sleep 0.1; done",
    );
    assert_eq!(app.running(&id), [first.id()]);
    let (paths, query) = (app.paths.clone(), id.clone());
    let closing = std::thread::spawn(move || {
        let t = Instant::now();
        let closed = Sam::with_paths(paths)
            .unwrap()
            .stop(&query)
            .map_err(|e| e.to_string());
        (closed, t.elapsed())
    });
    // The next launch starts once the closing has chosen its launches.
    let end = Instant::now() + Duration::from_secs(10);
    while !first_dir.join(sam_runner::launch::STOP_MARKER).exists() {
        assert!(Instant::now() < end, "the closing never chose the launch");
        std::thread::sleep(Duration::from_millis(20));
    }
    let (mut second, second_dir) = stand_in_runner(
        &base,
        &marks,
        "trap 'touch \"$0/second-asked\"' TERM; while :; do sleep 0.1; done",
    );
    let (closed, took) = closing.join().unwrap();
    // A signal reaches the shell's trap after its current pause.
    std::thread::sleep(Duration::from_millis(300));
    let second_runs = second.try_wait().unwrap().is_none();
    let second_asked = marks.join("second-asked").exists();
    let second_marked = second_dir.join(sam_runner::launch::STOP_MARKER).exists();
    let _ = second.kill();
    let _ = second.wait();
    let _ = first.kill();
    let first_ended = first.wait().unwrap();
    assert_eq!(closed, Ok(1), "the earlier launch was closed");
    assert!(
        took < Duration::from_secs(8),
        "closing waited for the later launch: {took:?}"
    );
    assert!(first_ended.success(), "the earlier launch quit by itself");
    assert!(second_runs, "the later launch was ended");
    assert!(!second_asked, "the later launch was asked to quit");
    assert!(!second_marked, "the later launch was marked as closed");
}
