//! When the launcher dies, the sandbox dies with it. `sam-jail run` is
//! killed hard (SIGKILL: no clean-up code of SAM runs), and no process of
//! the sandbox may survive: nothing keeps running unsupervised, outside
//! SAM's view. Checked with no network and with "This computer only", where
//! pasta sits between SAM and Bubblewrap. Skipped when Bubblewrap cannot
//! run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

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

fn wait_for(mut what: impl FnMut() -> bool, secs: u64) -> bool {
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
        sam_core::errln!("skipped: no pasta with --splice-only here");
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
    let ended = wait_for(|| launcher.try_wait().unwrap().is_some(), 20);
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
