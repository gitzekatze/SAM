//! When the launcher dies, the sandbox dies with it. `sam-jail run` is
//! killed hard (SIGKILL: no clean-up code of SAM runs), and no process of
//! the sandbox may survive: nothing keeps running unsupervised, outside
//! SAM's view. Checked with no network and with "This computer only", where
//! pasta sits between SAM and Bubblewrap. Skipped when Bubblewrap cannot
//! run here.
#![allow(clippy::unwrap_used)] // a test: a panic is a failed test

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
    c
}

fn killing_the_launcher_ends_the_sandbox(network: &str) {
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
}

#[test]
fn without_network_the_sandbox_dies_with_its_launcher() {
    if !bwrap_works() {
        eprintln!("skipped: bubblewrap cannot run here");
        return;
    }
    killing_the_launcher_ends_the_sandbox("none");
}

#[test]
fn with_this_computer_only_the_sandbox_dies_with_its_launcher() {
    if !bwrap_works() || !pasta_with_splice_only() {
        eprintln!("skipped: bubblewrap or a pasta with --splice-only is missing");
        return;
    }
    killing_the_launcher_ends_the_sandbox("localhost");
}
