//! SAM unpacks an AppImage only inside a sandbox, also when a menu start
//! (`sam-jail-run`) unpacks it again after *Free Space* (threat model:
//! "SAM's own unpacker … run in a sandbox"). Without SAM's command line next
//! to `sam-jail-run`, the start refuses instead of unpacking unprotected.
//! Skipped when Bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

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

fn json(out: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.lines().last().unwrap_or("null")).unwrap()
}

/// Runs one of SAM's programs from `bin` with its own folders under `root`.
fn sam(root: &Path, program: &str, args: &[&str]) -> Output {
    Command::new(root.join("bin").join(program))
        .args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap()
}

/// A sandboxed fixture app whose unpacked copy was freed; returns its id.
fn freed_app(root: &Path) -> String {
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("run")).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), root.join("bin/sam-jail")).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_sam-jail-run"),
        root.join("bin/sam-jail-run"),
    )
    .unwrap();
    let img = root.join("Quick-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    assert!(sam(
        root,
        "sam-jail",
        &["dev", "make-fixture", "--name", "Quick", img_s]
    )
    .status
    .success());
    assert!(sam(root, "sam-jail", &["add", img_s, "--no-launcher"])
        .status
        .success());
    let id = json(&sam(root, "sam-jail", &["--json", "list"]))["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let freed = sam(root, "sam-jail", &["free-space", &id]);
    assert!(
        freed.status.success(),
        "{}",
        String::from_utf8_lossy(&freed.stderr)
    );
    id
}

fn unpacked_log(root: &Path, id: &str) -> Option<String> {
    fs::read_to_string(root.join("data/extracted").join(id).join("extraction.log")).ok()
}

#[test]
fn a_menu_start_after_free_space_unpacks_inside_a_sandbox() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = freed_app(root);
    assert!(
        unpacked_log(root, &id).is_none(),
        "Free Space removed the unpacked copy"
    );
    sam(root, "sam-jail-run", &["--app-id", &id]);
    let log = unpacked_log(root, &id).expect("the menu start unpacked the app again");
    assert!(
        log.contains("[extract] isolated"),
        "unpacking again ran inside the sandbox:\n{log}"
    );
}

#[test]
fn without_the_command_line_a_menu_start_refuses_to_unpack() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = freed_app(root);
    fs::remove_file(root.join("bin/sam-jail")).unwrap();
    let run = sam(root, "sam-jail-run", &["--app-id", &id]);
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "the start stops");
    assert!(err.contains("only inside a sandbox"), "and says why: {err}");
    assert!(
        unpacked_log(root, &id).is_none(),
        "nothing was unpacked: {err}"
    );
}

/// Every file below `dir`.
fn files_in(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files_in(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

/// Unpacking limits hold inside the unpack sandbox too. Regression (audit
/// I-F3): when SAM's own reader hit the file or size limit inside the
/// sandbox, SAM saw only "failed", tried unsquashfs (which has only a time
/// limit) and then offered to let the AppImage unpack itself, so a crafted
/// image escaped the limits. The tests of the limits used to run without the
/// sandbox; this one goes through `sam-jail add`, which unpacks in it.
#[test]
fn an_unpacking_limit_inside_the_sandbox_stops_unpacking() {
    if !bwrap_works() {
        assert!(
            std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
            "SAM_REQUIRE_SANDBOX=1, but Bubblewrap does not work here"
        );
        eprintln!("skipped: Bubblewrap does not work here");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("run")).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), root.join("bin/sam-jail")).unwrap();
    let img = root.join("Tool-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    assert!(sam(
        root,
        "sam-jail",
        &["dev", "make-fixture", "--name", "Tool", img_s]
    )
    .status
    .success());
    assert!(sam(
        root,
        "sam-jail",
        &["config", "set", "extraction.max_files", "2"]
    )
    .status
    .success());
    let added = sam(
        root,
        "sam-jail",
        &["--json", "add", img_s, "--accept", "--no-launcher"],
    );
    let v = json(&added);
    assert_ne!(
        v["data"]["needs_fallback_consent"].as_bool(),
        Some(true),
        "no offer to let the AppImage unpack itself: {v}"
    );
    let logs: String = files_in(root)
        .iter()
        .filter_map(|f| fs::read_to_string(f).ok())
        .filter(|t| t.contains("[extract]"))
        .collect();
    assert!(
        logs.contains("[extract] isolated"),
        "unpacked in the sandbox:\n{logs}"
    );
    assert!(
        logs.contains("more than 2 files"),
        "the limit was hit:\n{logs}"
    );
    assert!(
        !logs.contains("trying unsquashfs"),
        "nothing else was tried:\n{logs}"
    );
    let app = &json(&sam(root, "sam-jail", &["--json", "list"]))["data"][0];
    assert_ne!(app["state"].as_str(), Some("ready"), "{app}");
    // The reason given is the limit's own message from inside the sandbox.
    let id = app["id"].as_str().unwrap();
    let info = json(&sam(root, "sam-jail", &["--json", "info", id]));
    assert!(
        info.to_string().contains("more than 2 files"),
        "the reason is shown: {info}"
    );
}
