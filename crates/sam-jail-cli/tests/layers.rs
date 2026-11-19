//! A start that lacks a protection layer its settings ask for is never
//! silent. SAM's helper (`sam-jail-run`), which applies seccomp and Landlock
//! inside the sandbox, is left out on purpose: the app still starts in its
//! Bubblewrap sandbox, and its record and its overview status say which
//! layers were missing. Skipped when Bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

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

fn json(out: &std::process::Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.lines().last().unwrap_or("null")).unwrap()
}

#[test]
fn a_start_without_the_helper_reports_its_missing_layers() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // With SAM installed in /usr, sam-jail finds that helper on the PATH
    // below, so a start without the helper cannot be shown on this computer.
    if ["/usr/bin/sam-jail-run", "/bin/sam-jail-run"]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        sam_runner::contracts::skip(
            "an installed SAM's helper is in /usr/bin, so a start without it cannot be shown here",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // The same run on every computer (the only test here, so its process).
    sam_runner::testenv::isolate_this_process(root);
    // sam-jail alone, without sam-jail-run next to it.
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), bin.join("sam-jail")).unwrap();
    let sam = |args: &[&str]| {
        Command::new(bin.join("sam-jail"))
            .args(args)
            .env("SAM_CONFIG_DIR", root.join("config"))
            .env("SAM_DATA_DIR", root.join("data"))
            .env("SAM_APPLICATIONS_DIR", root.join("applications"))
            .env("LC_ALL", "C")
            .env_remove("LANGUAGE")
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap()
    };
    let img = root.join("Quick-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    assert!(sam(&["dev", "make-fixture", "--name", "Quick", img_s])
        .status
        .success());
    assert!(sam(&["add", img_s, "--no-launcher"]).status.success());
    let id = json(&sam(&["--json", "list"]))["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    // Settings nobody has confirmed do not start (audit U-M11).
    assert!(sam(&["review", &id]).status.success());
    let run = sam(&["run", &id]);
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(
        err.contains("this start ran without"),
        "the command line warns: {err}"
    );
    let info = json(&sam(&["--json", "info", &id]));
    let entry = &info["data"]["entry"];
    let missing: Vec<&str> = entry["last_launch"]["missing_layers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(missing.contains(&"seccomp"), "recorded: {missing:?}");
    let list = json(&sam(&["--json", "list"]));
    assert_eq!(list["data"][0]["badge"], "protection-missing", "{list}");
}
