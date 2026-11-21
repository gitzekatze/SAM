//! Room service's rooms die with SAM's launcher: `sam-jail run` is killed
//! hard (SIGKILL: no clean-up code of SAM runs) while a room of its app
//! runs, and the room may not survive it. Skipped when Bubblewrap cannot
//! run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Processes running exactly these arguments.
fn running(args: &[&str]) -> Vec<u32> {
    let want: Vec<u8> = args
        .iter()
        .flat_map(|a| [a.as_bytes(), b"\0"].concat())
        .collect();
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| c == want))
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

/// A room of an app (built by Room service, outside the app's sandbox)
/// ends when SAM's launcher is killed outright.
#[test]
fn a_room_dies_with_sams_launcher() {
    let host = sam_core::HostInfo::probe();
    if sam_runner::bwrap::check(&host).is_err() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "bwrap-rooms"])
        .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let left = format!("{}.75", 5000 + std::process::id() % 1000);
    // The app asks for a room running a sleep with a number of its own, and
    // waits for it.
    let apprun = root.join("AppRun");
    fs::write(
        &apprun,
        format!(
            r#"#!/bin/sh
SYS=""
for d in /bin /sbin /lib /lib32 /lib64; do
  if [ -L "$d" ]; then SYS="$SYS --symlink $(readlink "$d") $d"
  elif [ -d "$d" ]; then SYS="$SYS --ro-bind $d $d"; fi
done
# shellcheck disable=SC2086
bwrap --ro-bind /usr /usr $SYS -- /usr/bin/sleep {left}
"#
        ),
    )
    .unwrap();
    let img = root.join("Roomer-1.0-x86_64.AppImage");
    let ok = |c: &mut Command| {
        let o = c.output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    ok(sam(root)
        .args(["dev", "make-fixture", "--name", "Roomer", "--apprun"])
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
    let mut launcher = sam(root)
        .args(["run", &id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let room = ["/usr/bin/sleep", left.as_str()];
    if !wait_for(|| !running(&room).is_empty(), 30) {
        let _ = launcher.kill();
        panic!("the app's room did not start (Room service missing or broken)");
    }
    launcher.kill().unwrap(); // SIGKILL
    launcher.wait().unwrap();
    let gone = wait_for(|| running(&room).is_empty(), 10);
    for pid in running(&room) {
        // SAFETY: a plain signal to a process of this test's user.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    assert!(gone, "a room outlived SAM's launcher");
}
