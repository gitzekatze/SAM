//! When the launcher dies, the sandbox dies with it. `sam-jail run` is
//! killed hard (SIGKILL: no clean-up code of SAM runs), and no process of
//! the sandbox may survive: nothing keeps running unsupervised, outside
//! SAM's view. Checked with no network and with "This computer only", where
//! pasta sits between SAM and Bubblewrap. Skipped when Bubblewrap cannot
//! run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bwrap_works() -> bool {
    Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-user",
            "--unshare-pid",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn pasta_with_splice_only() -> bool {
    Command::new("pasta")
        .arg("--help")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("--splice-only"))
}

/// Processes whose command line contains `marker`.
fn with_marker(marker: &str) -> Vec<u32> {
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            fs::read(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|c| String::from_utf8_lossy(&c).contains(marker))
        })
        .collect()
}

fn wait_for(what: impl Fn() -> bool, secs: u64) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if what() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn sam(root: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE");
    // The same run on every computer: its own runtime folder, no desktop session.
    sam_runner::testenv::isolate_command(&mut c, root);
    c
}

fn killing_the_launcher_ends_the_sandbox(network: &str) {
    // The outside world this test relies on (docs/contracts.md).
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let marker = format!("sam-teardown-{}-{network}", std::process::id());
    // The app keeps a shell with the marker in its command line alive.
    let apprun = root.join("AppRun");
    fs::write(
        &apprun,
        format!("#!/bin/sh\nexec sh -c 'sleep 300; true' {marker}\n"),
    )
    .unwrap();
    let img = root.join("Sleeper-1.0-x86_64.AppImage");
    let ok = |c: &mut Command| {
        let o = c.output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    ok(sam(root)
        .args(["dev", "make-fixture", "--name", "Sleeper", "--apprun"])
        .arg(&apprun)
        .arg(&img));
    ok(sam(root).arg("add").arg(&img).arg("--no-launcher"));
    let list = ok(sam(root).args(["--json", "list"]));
    let id = list
        .lines()
        .last()
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v["data"][0]["id"].as_str().map(String::from))
        .unwrap();
    ok(sam(root).args(["set", &id, "network.mode", network]));

    let mut launcher = sam(root)
        .args(["run", &id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for(|| !with_marker(&marker).is_empty(), 30),
        "the app did not start ({network})"
    );
    launcher.kill().unwrap(); // SIGKILL
    launcher.wait().unwrap();
    assert!(
        wait_for(|| with_marker(&marker).is_empty(), 10),
        "the sandbox outlived its launcher ({network}): {:?}",
        with_marker(&marker)
    );
    // No clean-up code of SAM ran, so the launch's runtime folder is still
    // there. SAM must not take it for a running app, and removing the app
    // leaves nothing behind in the runtime folder (before, every test run
    // left two folders there; in a plain `cargo test`, the real one).
    let info = ok(sam(root).args(["--json", "info", &id]));
    let running = info
        .lines()
        .last()
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v["data"]["running"].as_u64());
    assert_eq!(
        running,
        Some(0),
        "a killed launch still counts as running ({network})"
    );
    ok(sam(root).args(["remove", &id]));
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(|v| Path::new(&v).join("sam"))
        .unwrap_or_else(|| root.join("data/runtime"))
        .join(&id);
    assert!(
        !runtime.exists(),
        "removing the app left {} behind ({network})",
        runtime.display()
    );
    // Nothing reached the real runtime folder above, and the test's own is
    // empty again too.
    let own = sam_core::Paths::rooted(root).runtime_dir(&id);
    assert!(
        !own.exists(),
        "removing the app left {} behind ({network})",
        own.display()
    );
}

#[test]
fn without_network_the_sandbox_dies_with_its_launcher() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    killing_the_launcher_ends_the_sandbox("none");
}

#[test]
fn with_this_computer_only_the_sandbox_dies_with_its_launcher() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    if !pasta_with_splice_only() {
        // A fair skip anywhere: without --splice-only SAM never starts
        // "This computer only" (contract pasta-splice-only), so there is no
        // pasta to outlive the launcher.
        sam_runner::contracts::not_here(
            "no pasta with --splice-only, so SAM never starts \"This computer only\" here",
        );
        eprintln!("skipped: no pasta with --splice-only here");
        return;
    }
    killing_the_launcher_ends_the_sandbox("localhost");
}

/// Logging out sends SIGTERM to the launcher of an app started from the
/// menu (audit L-F9). The launcher no longer dies on the spot (which left
/// the app to be killed hard, saved no record and left its runtime folder
/// behind): it passes the request on, the app closes itself, and the
/// launch ends as "closed by SAM" with everything cleaned up.
#[test]
fn logging_out_closes_a_menu_started_app_properly() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let marker = format!("sam-logout-{}", std::process::id());
    // The app saves and quits on SIGTERM, like a real one at logout.
    let apprun = root.join("AppRun");
    fs::write(
        &apprun,
        format!(
            "#!/bin/sh\nexec sh -c 'trap \"echo saved > \\\"$HOME/quit-seen\\\"; exit 0\" TERM; \
             while :; do sleep 0.1; done' {marker}\n"
        ),
    )
    .unwrap();
    let img = root.join("Saver-1.0-x86_64.AppImage");
    let ok = |c: &mut Command| {
        let o = c.output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    ok(sam(root)
        .args(["dev", "make-fixture", "--name", "Saver", "--apprun"])
        .arg(&apprun)
        .arg(&img));
    ok(sam(root)
        .arg("add")
        .arg(&img)
        .args(["--no-launcher", "--accept"]));
    let list = ok(sam(root).args(["--json", "list"]));
    let id = list
        .lines()
        .last()
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v["data"][0]["id"].as_str().map(String::from))
        .unwrap();

    // Started the way the menu starts it: no terminal anywhere.
    let mut launcher = sam(root)
        .args(["run", &id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for(|| !with_marker(&marker).is_empty(), 30),
        "the app did not start"
    );
    // SAFETY: kill takes plain integers; the launcher is our own child.
    unsafe { libc::kill(launcher.id() as libc::pid_t, libc::SIGTERM) };
    let end = Instant::now() + Duration::from_secs(20);
    while launcher.try_wait().unwrap().is_none() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    let ended = launcher.try_wait().unwrap().is_some();
    if !ended {
        launcher.kill().unwrap();
    }
    launcher.wait().unwrap();
    assert!(ended, "the launcher did not end after SIGTERM");
    assert!(
        wait_for(|| with_marker(&marker).is_empty(), 10),
        "the app outlived its launcher"
    );
    let home = root.join("data/homes").join(&id);
    assert!(
        home.join("quit-seen").exists(),
        "the app was killed instead of asked to quit"
    );
    let info = ok(sam(root).args(["--json", "info", &id]));
    let v: serde_json::Value = serde_json::from_str(info.lines().last().unwrap()).unwrap();
    let last = &v["data"]["entry"]["last_launch"];
    assert_eq!(last["summary"], "closed by SAM", "{v}");
    assert_eq!(v["data"]["running"].as_u64(), Some(0), "{v}");
    let runtime = sam_core::Paths::rooted(root).runtime_dir(&id);
    let left: Vec<_> = fs::read_dir(&runtime)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert!(
        left.is_empty(),
        "the launch left {left:?} in its runtime folder"
    );
}

/// An app that ignores the request to quit at logout does not keep the
/// launcher waiting: after the grace time (10 s) its sandbox is ended, and
/// the start is still recorded as closed.
#[test]
fn an_app_that_ignores_logout_is_ended_after_the_grace_time() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let marker = format!("sam-stubborn-{}", std::process::id());
    let apprun = root.join("AppRun");
    fs::write(
        &apprun,
        format!("#!/bin/sh\nexec sh -c 'trap \"\" TERM; while :; do sleep 0.1; done' {marker}\n"),
    )
    .unwrap();
    let img = root.join("Stubborn-1.0-x86_64.AppImage");
    let ok = |c: &mut Command| {
        let o = c.output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    ok(sam(root)
        .args(["dev", "make-fixture", "--name", "Stubborn", "--apprun"])
        .arg(&apprun)
        .arg(&img));
    ok(sam(root)
        .arg("add")
        .arg(&img)
        .args(["--no-launcher", "--accept"]));
    let list = ok(sam(root).args(["--json", "list"]));
    let id = list
        .lines()
        .last()
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v["data"][0]["id"].as_str().map(String::from))
        .unwrap();
    let mut launcher = sam(root)
        .args(["run", &id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for(|| !with_marker(&marker).is_empty(), 30),
        "the app did not start"
    );
    let asked = Instant::now();
    // SAFETY: kill takes plain integers; the launcher is our own child.
    unsafe { libc::kill(launcher.id() as libc::pid_t, libc::SIGTERM) };
    let end = Instant::now() + Duration::from_secs(30);
    while launcher.try_wait().unwrap().is_none() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    let ended = launcher.try_wait().unwrap().is_some();
    if !ended {
        launcher.kill().unwrap();
    }
    launcher.wait().unwrap();
    let took = asked.elapsed();
    assert!(
        ended,
        "the launcher waited forever for an app that ignores logout"
    );
    assert!(
        took >= Duration::from_secs(9),
        "the app got no time to save: ended after {took:?}"
    );
    assert!(
        wait_for(|| with_marker(&marker).is_empty(), 10),
        "the app outlived its launcher"
    );
    let info = ok(sam(root).args(["--json", "info", &id]));
    let v: serde_json::Value = serde_json::from_str(info.lines().last().unwrap()).unwrap();
    assert_eq!(
        v["data"]["entry"]["last_launch"]["summary"], "closed by SAM",
        "{v}"
    );
}

/// An app made from `apprun`, added, and set with `sets`; its id. With
/// `home`, SAM runs with that folder as the home.
fn add_app(
    root: &Path,
    home: Option<&Path>,
    name: &str,
    apprun: &str,
    sets: &[(&str, &str)],
) -> String {
    let run = |args: &[&str]| {
        let mut c = sam(root);
        if let Some(h) = home {
            c.env("HOME", h);
        }
        let o = c.args(args).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let script = root.join(format!("{name}.AppRun"));
    fs::write(&script, apprun).unwrap();
    let img = root.join(format!("{name}-1.0-x86_64.AppImage"));
    let (script, img) = (script.to_str().unwrap(), img.to_str().unwrap());
    run(&[
        "dev",
        "make-fixture",
        "--name",
        name,
        "--apprun",
        script,
        img,
    ]);
    run(&["add", img, "--no-launcher", "--accept"]);
    let list = run(&["--json", "list"]);
    let v: serde_json::Value = serde_json::from_str(list.lines().last().unwrap()).unwrap();
    let id = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == name)
        .and_then(|a| a["id"].as_str())
        .unwrap()
        .to_string();
    for (key, value) in sets {
        run(&["set", &id, key, value, "--yes"]);
    }
    id
}

/// Review 2026-11-23 F3: closing an app whose network is "This computer
/// only" gives it its time to save, like any other. Before, pasta (which
/// sits between SAM and Bubblewrap) was asked to quit too; it did at once,
/// and Bubblewrap took the whole sandbox down with it.
#[test]
fn closing_a_this_computer_only_app_gives_it_time_to_save() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    if !pasta_with_splice_only() {
        sam_runner::contracts::not_here(
            "no pasta with --splice-only, so SAM never starts \"This computer only\" here",
        );
        eprintln!("skipped: no pasta with --splice-only here");
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "pasta-splice-only"])
        .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let marker = format!("sam-local-saver-{}", std::process::id());
    // Saving takes a moment, as it does for a real app.
    let id = add_app(
        root,
        None,
        "LocalSaver",
        &format!(
            "#!/bin/sh\nexec sh -c 'trap \"sleep 1; echo saved > \\\"$HOME/quit-seen\\\"; exit 0\" TERM; \
             while :; do sleep 0.1; done' {marker}\n"
        ),
        &[("network.mode", "localhost")],
    );
    let mut launcher = sam(root)
        .args(["run", &id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for(|| !with_marker(&marker).is_empty(), 30),
        "the app did not start"
    );
    let stop = sam(root).args(["stop", &id]).output().unwrap();
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    launcher.wait().unwrap();
    let home = root.join("data/homes").join(&id);
    assert!(
        home.join("quit-seen").exists(),
        "the app was ended before it could save"
    );
}

/// Review 2026-11-23 F2: closing an app that ignores the request to quit
/// still finishes its launch. Before, SAM's runner began its own grace
/// time when `stop` signalled it after 10 seconds, and `stop` killed it 3
/// seconds later: no last look at the start places, no record, no end of
/// the log. Here the app keeps writing a start file the whole time.
#[test]
fn closing_an_app_that_ignores_it_still_finishes_its_launch() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    let marker = format!("sam-stubborn-writer-{}", std::process::id());
    let id = add_app(
        root,
        Some(&home),
        "StubbornWriter",
        &format!(
            "#!/bin/sh\nexec sh -c 'trap \"\" TERM; \
             while :; do echo pwned > \"$HOME/.bash_profile\"; sleep 0.05; done' {marker}\n"
        ),
        &[
            ("filesystem.home", "true"),
            ("filesystem.home_access", "rw"),
        ],
    );
    let mut launcher = sam(root)
        .env("HOME", &home)
        .args(["run", &id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for(|| !with_marker(&marker).is_empty(), 30),
        "the app did not start"
    );
    let asked = Instant::now();
    let stop = sam(root)
        .env("HOME", &home)
        .args(["stop", &id])
        .output()
        .unwrap();
    let took = asked.elapsed();
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    launcher.wait().unwrap();
    assert!(
        wait_for(|| with_marker(&marker).is_empty(), 10),
        "the app outlived its launcher"
    );
    assert!(
        took >= Duration::from_secs(9),
        "the app got no time to save: closed after {took:?}"
    );
    assert!(
        fs::symlink_metadata(home.join(".bash_profile")).is_err(),
        "the start file stayed"
    );
    let info = sam(root)
        .env("HOME", &home)
        .args(["--json", "info", &id])
        .output()
        .unwrap();
    let info = String::from_utf8_lossy(&info.stdout);
    let v: serde_json::Value = serde_json::from_str(info.lines().last().unwrap()).unwrap();
    let last = &v["data"]["entry"]["last_launch"];
    assert_eq!(
        last["summary"], "closed by SAM",
        "the launch was not finished: {last}"
    );
    assert!(
        last["moved_aside"].as_array().is_some_and(|m| m
            .iter()
            .any(|x| x.as_str().is_some_and(|s| s.contains(".bash_profile")))),
        "the start file is not named: {last}"
    );
}
