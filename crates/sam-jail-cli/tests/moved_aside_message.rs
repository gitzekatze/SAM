//! A start file an app left in a writable home is moved aside, and the
//! command line says so (mutation run of 2026-11-21: the message could
//! have been printed only for quiet starts, unnoticed).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;
use std::process::{Command, Stdio};

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

#[test]
fn a_start_file_left_in_the_home_is_moved_aside_and_named() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // The same run on every computer (the only test here, so its process).
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    let sam = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sam-jail"))
            .args(args)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("SAM_CONFIG_DIR", root.join("config"))
            .env("SAM_DATA_DIR", root.join("data"))
            .env("SAM_APPLICATIONS_DIR", root.join("applications"))
            .env("LC_ALL", "C")
            .env_remove("LANGUAGE")
            .output()
            .unwrap()
    };
    // An app that leaves a new ~/.bash_profile, which the next login runs.
    let apprun = root.join("AppRun");
    fs::write(
        &apprun,
        "#!/bin/sh\necho 'echo from the app' > \"$HOME/.bash_profile\"\n",
    )
    .unwrap();
    let img = root.join("Profile-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    let made = sam(&[
        "dev",
        "make-fixture",
        "--name",
        "Profile",
        "--apprun",
        apprun.to_str().unwrap(),
        img_s,
    ]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    assert!(sam(&["add", img_s, "--no-launcher", "--accept"])
        .status
        .success());
    let list = sam(&["--json", "list"]);
    let list: serde_json::Value = serde_json::from_str(
        String::from_utf8_lossy(&list.stdout)
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    let id = list["data"][0]["id"].as_str().unwrap().to_string();
    for (key, value) in [
        ("filesystem.home", "true"),
        ("filesystem.home_access", "rw"),
    ] {
        let set = sam(&["set", &id, key, value, "--yes"]);
        assert!(
            set.status.success(),
            "{}",
            String::from_utf8_lossy(&set.stderr)
        );
    }

    let run = sam(&["run", &id]);
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(
        !home.join(".bash_profile").exists(),
        "the new start file stayed: {err}"
    );
    assert!(err.contains("SAM moved it aside"), "not named: {err}");
}
