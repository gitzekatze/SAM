//! A script can rely on SAM's exit code: 0 when the command did what was
//! asked and every check passed, 3 when it ran but a check did not pass or
//! it did not do what was asked, 1 on an error, 2 on a wrong command line.
//! The output comes first, so a script still reads what failed (audit
//! G-F9: `verify` with a failed check, `preset apply` not applied,
//! `selftest`, `doctor --contracts` with a broken contract and `run --json`
//! on a failure all ended with 0, and `compat APP ON` meant off).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const NOT_PASSED: Option<i32> = Some(3);

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

/// SAM's command line as built (its helper is next to it; a copy would
/// race with the other tests here starting programs: "Text file busy"),
/// with its own folders and home.
fn sam_with_path(root: &Path, path: &str, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    cmd.args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("XDG_DATA_HOME", root.join("home/.local/share"))
        .env("PATH", path)
        // Stand-in tools of a test belong to the user: SAM runs them only
        // from the folder named here.
        .env("SAM_TRUST_TOOLS_IN", path)
        .stdin(Stdio::null());
    // The same run on every computer: no desktop session of the person
    // (its Wayland socket would look broken from the test's runtime folder).
    sam_runner::testenv::isolate_command(&mut cmd, &root.join("sam"));
    // Without the socket, the session type alone would make the Wayland
    // contract look broken.
    cmd.env_remove("XDG_SESSION_TYPE");
    cmd.output().unwrap()
}

fn sam(root: &Path, args: &[&str]) -> Output {
    sam_with_path(root, "/usr/bin:/bin", args)
}

/// The JSON reply (the last line on stdout).
fn reply(o: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&o.stdout);
    serde_json::from_str(text.lines().last().unwrap_or("null"))
        .unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// SAM's folders with an app added and confirmed. With `apprun`, the app
/// runs that script.
fn setup(root: &Path, name: &str, apprun: Option<&str>) -> String {
    for d in ["run", "config", "home"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let img = root.join(format!("{name}-1.0-x86_64.AppImage"));
    let img_s = img.to_str().unwrap();
    let mut make = vec!["dev", "make-fixture", "--name", name];
    let script = root.join("apprun");
    if let Some(body) = apprun {
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        make.extend(["--apprun", script.to_str().unwrap()]);
    }
    make.push(img_s);
    assert!(sam(root, &make).status.success());
    let add = sam(root, &["--json", "add", img_s, "--no-launcher", "--accept"]);
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    reply(&sam(root, &["--json", "list"]))["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// `compat` takes on and off in any case and refuses anything else.
#[test]
fn compat_takes_on_and_off_in_any_case_and_nothing_else() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Quick", None);
    let on = sam(root, &["--json", "compat", &id, "ON", "--yes"]);
    assert!(
        on.status.success(),
        "{}",
        String::from_utf8_lossy(&on.stdout)
    );
    let info = reply(&sam(root, &["--json", "info", &id]));
    assert_eq!(
        info["data"]["entry"]["profile"]["compatibility_mode"], true,
        "ON means on"
    );
    let unclear = sam(root, &["--json", "compat", &id, "maybe"]);
    assert_eq!(unclear.status.code(), Some(1));
    assert_eq!(reply(&unclear)["ok"], false);
    let info = reply(&sam(root, &["--json", "info", &id]));
    assert_eq!(
        info["data"]["entry"]["profile"]["compatibility_mode"], true,
        "an unclear word changes nothing"
    );
    assert!(sam(root, &["compat", &id, "Off"]).status.success());
    let info = reply(&sam(root, &["--json", "info", &id]));
    assert_eq!(
        info["data"]["entry"]["profile"]["compatibility_mode"], false,
        "Off means off"
    );
}

/// `doctor` and `doctor --contracts` end with 3 exactly when they report a
/// failed check or a broken contract, and with 0 otherwise.
#[test]
fn doctor_ends_with_what_it_reports() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["run", "config", "home"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let o = sam(root, &["--json", "doctor", "--contracts"]);
    let broken = reply(&o)["data"]["contracts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["state"] == "broken");
    assert_eq!(
        o.status.code(),
        Some(if broken { 3 } else { 0 }),
        "broken: {broken}"
    );
    let o = sam(root, &["--json", "doctor"]);
    let failed = reply(&o)["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["status"] == "fail");
    assert_eq!(
        o.status.code(),
        Some(if failed { 3 } else { 0 }),
        "failed: {failed}"
    );
}

/// `sam-jail info` shows every permission with its value, each group of
/// permissions under one heading (audit G-F14).
#[test]
fn info_on_the_terminal_shows_every_permission_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Quick", None);
    assert!(sam(
        root,
        &[
            "set",
            &id,
            "environment.set",
            r#"{"QT_SCALE_FACTOR": "1.5"}"#
        ]
    )
    .status
    .success());
    let o = sam(root, &["info", &id]);
    let text = String::from_utf8_lossy(&o.stdout);
    for (title, value) in [
        ("Bluetooth", "off"),
        ("SSH agent", "off"),
        ("Environment variables", "QT_SCALE_FACTOR=1.5"),
        ("Passed-through variables", "–"),
        ("Baseline syscall filter", "on"),
    ] {
        assert!(
            text.lines()
                .any(|l| l.trim_start().starts_with(title) && l.trim_end().ends_with(value)),
            "{title}: {value} in\n{text}"
        );
    }
    let headings = ["Filesystem", "Network", "Devices", "D-Bus", "Advanced"];
    for h in headings {
        assert_eq!(
            text.lines().filter(|l| l.trim() == h).count(),
            1,
            "{h} once in\n{text}"
        );
    }
}

/// A preset that is not applied (it needs a confirmation) ends with 3 and
/// still says what it would change; applied, it ends with 0.
#[test]
fn a_preset_not_applied_ends_with_not_passed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Quick", None);
    assert!(sam(root, &["set", &id, "devices.webcam", "true", "--yes"])
        .status
        .success());
    assert!(sam(root, &["preset", "save", &id, "With camera"])
        .status
        .success());
    assert!(sam(root, &["set", &id, "devices.webcam", "false"])
        .status
        .success());
    let asked = sam(root, &["--json", "preset", "apply", "With camera", &id]);
    assert_eq!(asked.status.code(), NOT_PASSED);
    let r = reply(&asked);
    assert_eq!(r["ok"], true, "the answer is still there: {r}");
    assert_eq!(r["data"]["applied"], false);
    let applied = sam(
        root,
        &["--json", "preset", "apply", "With camera", &id, "--yes"],
    );
    assert_eq!(applied.status.code(), Some(0));
    assert_eq!(reply(&applied)["data"]["applied"], true);
}

/// A broken contract (here a Bubblewrap that cannot build a sandbox) ends
/// `doctor --contracts` with 3.
#[test]
fn a_broken_contract_ends_with_not_passed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let fakes = root.join("fakes");
    fs::create_dir_all(&fakes).unwrap();
    let bwrap = fakes.join("bwrap");
    fs::write(
        &bwrap,
        "#!/bin/sh\ncase \"$1\" in\n  --version) echo \"bubblewrap 0.4.0\" ;;\n  *) echo \"bwrap: setting up uid map: Permission denied\" >&2; exit 1 ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o755)).unwrap();
    let o = sam_with_path(
        root,
        fakes.to_str().unwrap(),
        &["--json", "doctor", "--contracts"],
    );
    assert_eq!(o.status.code(), NOT_PASSED);
    let r = reply(&o);
    assert!(r["data"]["contracts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["id"] == "bwrap-core" && c["state"] == "broken"));
}

/// In a real sandbox: `run --json` passes on the app's exit code, a
/// `selftest` with a failing app ends with 3, and `verify` with a failed
/// check ends with 3, so `sam-jail verify APP && sam-jail run APP` gates.
#[test]
fn checks_that_do_not_pass_end_with_not_passed() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Failing", Some("#!/bin/sh\nexit 7\n"));
    // A command-line tool that ends with an error code has run fine in its
    // sandbox (the start counts as successful), and scripts still get its
    // code.
    let script = root.join("tool-apprun");
    fs::write(&script, "#!/bin/sh\nexit 5\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let img = root.join("Tool-1.0-x86_64.AppImage");
    let (img_s, script_s) = (img.to_str().unwrap(), script.to_str().unwrap());
    assert!(sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            "Tool",
            "--terminal",
            "--apprun",
            script_s,
            img_s
        ]
    )
    .status
    .success());
    let add = reply(&sam(
        root,
        &["--json", "add", img_s, "--no-launcher", "--accept"],
    ));
    let tool = add["data"]["app"]["id"].as_str().unwrap().to_string();
    let run = sam(root, &["--json", "run", &tool]);
    assert_eq!(
        reply(&run)["data"]["success"],
        true,
        "{}",
        String::from_utf8_lossy(&run.stdout)
    );
    assert_eq!(run.status.code(), Some(5), "the tool's own exit code");
    let run = sam(root, &["--json", "run", &id]);
    assert_eq!(run.status.code(), Some(7), "the app's own exit code");
    assert_eq!(reply(&run)["ok"], true, "with the launch record");
    let test = sam(root, &["--json", "selftest", &id, "--seconds", "5"]);
    assert_eq!(test.status.code(), NOT_PASSED);
    assert_eq!(reply(&test)["data"]["results"][0]["status"], "fail");

    // Documents is "No access", but a raw Bubblewrap argument mounts it:
    // the sandbox check finds it.
    let docs = root.join("home/Documents");
    fs::create_dir_all(&docs).unwrap();
    let d = docs.display().to_string();
    let leak = serde_json::json!(["--ro-bind", d, d]).to_string();
    assert!(sam(
        root,
        &["set", &id, "advanced.extra_bwrap_args", &leak, "--yes"]
    )
    .status
    .success());
    let verify = sam(root, &["--json", "verify", &id]);
    assert_eq!(verify.status.code(), NOT_PASSED);
    let r = reply(&verify);
    assert!(
        !r["data"]["record"]["failed"].as_array().unwrap().is_empty(),
        "{r}"
    );
}
