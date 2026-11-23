//! *Check the sandbox before each start* holds for every way of starting an
//! app: `sam-jail run` refuses a sandbox whose settings do not apply, as a
//! menu start does. Skipped when Bubblewrap cannot run here.
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

/// Runs SAM's command line from `root/bin` with its own folders and home.
fn sam(root: &Path, args: &[&str]) -> Output {
    Command::new(root.join("bin/sam-jail"))
        .args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("XDG_DATA_HOME", root.join("home/.local/share"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap()
}

#[test]
fn sam_jail_run_refuses_a_sandbox_whose_settings_do_not_apply() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["bin", "run", "config", "home/Documents"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), root.join("bin/sam-jail")).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_sam-jail-run"),
        root.join("bin/sam-jail-run"),
    )
    .unwrap();
    fs::write(
        root.join("config/config.toml"),
        "[security]\ncheck_before_launch = true\n",
    )
    .unwrap();
    let img = root.join("Quick-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    assert!(
        sam(root, &["dev", "make-fixture", "--name", "Quick", img_s])
            .status
            .success()
    );
    assert!(sam(root, &["add", img_s, "--no-launcher", "--accept"])
        .status
        .success());
    let id = json(&sam(root, &["--json", "list"]))["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    // Documents is "No access", but a raw Bubblewrap argument mounts it.
    let docs = root.join("home/Documents").display().to_string();
    let leak = serde_json::json!(["--ro-bind", docs, docs]).to_string();
    // Raw arguments are Dangerous: refused without --yes, saying what it
    // adds (audit D-M9: applied silently).
    let refused = sam(root, &["set", &id, "advanced.extra_bwrap_args", &leak]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--yes"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let set = sam(
        root,
        &["set", &id, "advanced.extra_bwrap_args", &leak, "--yes"],
    );
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    let run = sam(root, &["run", &id]);
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "the start stops: {err}");
    assert!(err.contains("sandbox check failed"), "and says why: {err}");
    assert!(err.contains("Documents"), "naming the setting: {err}");
}

/// An app added on the command line without `--accept` has settings nobody
/// has confirmed: SAM chose them partly from what the app says about itself
/// (its name and description pick its category, and with it the network).
/// `sam-jail run` refuses it until `review` (audit U-M11). The refusal
/// comes before any sandbox is built, so it needs no Bubblewrap.
#[test]
fn an_app_nobody_has_confirmed_does_not_start() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["bin", "run", "config", "home"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), root.join("bin/sam-jail")).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_sam-jail-run"),
        root.join("bin/sam-jail-run"),
    )
    .unwrap();
    let img = root.join("Quick-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    assert!(
        sam(root, &["dev", "make-fixture", "--name", "Quick", img_s])
            .status
            .success()
    );
    assert!(sam(root, &["add", img_s, "--no-launcher"]).status.success());
    let id = json(&sam(root, &["--json", "list"]))["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    // One switch changed, alone or for a group of apps, confirms nothing
    // about the others (review F5: any change marked the app reviewed).
    let changes: [&[&str]; 2] = [
        &["set", &id, "devices.gpu", "true"],
        &["group", "set", "audio.enabled", "false", &id],
    ];
    for change in changes {
        let o = sam(root, change);
        assert!(
            o.status.success(),
            "{change:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        let run = sam(root, &["run", &id]);
        let err = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{change:?}: the start stops: {err}");
        assert!(
            err.contains("have not been confirmed"),
            "{change:?}: and says why: {err}"
        );
        assert!(err.contains("sam-jail review"), "and what to do: {err}");
    }
    assert!(sam(root, &["review", &id]).status.success());
    let again = sam(root, &["run", &id]);
    let err = String::from_utf8_lossy(&again.stderr);
    assert!(
        !err.contains("have not been confirmed"),
        "confirmed once, it is no longer refused for this: {err}"
    );
}
