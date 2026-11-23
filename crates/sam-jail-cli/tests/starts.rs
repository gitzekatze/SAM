//! What `selftest`, `run` and `verify` report after a real start in a real
//! sandbox: a selftest ends an app that keeps running after the time given
//! and calls that a pass, keeps the app's output out of its own answer and
//! marks each app passed or not on the terminal; `run` hands the app the
//! arguments given; `verify` checks an AppImage that has no sandbox yet.
//! Each was missing (mutation run 2026-11-23).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
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

/// Skips (fails where a run must prove everything) without a working
/// Bubblewrap; checks the contracts the starts rely on.
fn sandbox_here() -> Option<sam_runner::contracts::Guard> {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return None;
    }
    Some(sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}")))
}

/// SAM's command line with its own folders and home and no desktop
/// session, ended after `limit` if it hangs (then the test fails).
fn sam_within(root: &Path, args: &[&str], limit: Duration) -> Output {
    sam_with_input(root, args, None, limit)
}

/// [`sam_within`] with `input` on standard input.
fn sam_with_input(root: &Path, args: &[&str], input: Option<&str>, limit: Duration) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    cmd.args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("XDG_DATA_HOME", root.join("home/.local/share"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAM_TRUST_TOOLS_IN", "/usr/bin:/bin")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sam_runner::testenv::isolate_command(&mut cmd, &root.join("sam"));
    cmd.env_remove("XDG_SESSION_TYPE");
    let mut child = cmd.spawn().unwrap();
    if let Some(text) = input {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(text.as_bytes()).unwrap();
    }
    // Read the output while waiting, so a full pipe never stops SAM.
    let reader = |mut r: Box<dyn std::io::Read + Send>| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            r.read_to_end(&mut v).ok();
            v
        })
    };
    let o = reader(Box::new(child.stdout.take().unwrap()));
    let e = reader(Box::new(child.stderr.take().unwrap()));
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > limit {
            child.kill().ok();
            child.wait().ok();
            panic!("{args:?} still runs after {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: o.join().unwrap(),
        stderr: e.join().unwrap(),
    }
}

fn sam(root: &Path, args: &[&str]) -> Output {
    sam_within(root, args, Duration::from_secs(120))
}

/// The JSON reply: the whole of standard output, one JSON value.
fn reply(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "standard output is not one JSON value ({e}):\n{}",
            String::from_utf8_lossy(&o.stdout)
        )
    })
}

/// A test AppImage that runs `apprun`.
fn fixture(root: &Path, name: &str, apprun: &str) -> PathBuf {
    for d in ["config", "home"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let script = root.join(format!("{name}-apprun"));
    fs::write(&script, apprun).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let img = root.join(format!("{name}-1.0-x86_64.AppImage"));
    let o = sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            name,
            "--apprun",
            script.to_str().unwrap(),
            img.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    img
}

/// The fixture added and confirmed; its id.
fn added(root: &Path, name: &str, apprun: &str) -> String {
    let img = fixture(root, name, apprun);
    let o = sam(
        root,
        &[
            "--json",
            "add",
            img.to_str().unwrap(),
            "--no-launcher",
            "--accept",
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    reply(&o)["data"]["entry"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A selftest ends an app that keeps running once the time is up and
/// passes it (instead of waiting for it forever); what the app prints goes
/// to its log, not into SAM's answer; on the terminal a passed app gets ✓
/// and a failed one ✗.
#[test]
fn a_selftest_ends_a_lasting_app_in_time_and_keeps_its_output_out() {
    let Some(_contracts) = sandbox_here() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let lasting = added(
        root,
        "Lasting",
        "#!/bin/sh\necho APP-SAYS-HI\necho APP-ERR >&2\nexec sleep 300\n",
    );
    let failing = added(root, "Failing", "#!/bin/sh\nexit 7\n");

    let o = sam_within(
        root,
        &["--json", "selftest", &lasting, "--seconds", "2"],
        Duration::from_secs(90),
    );
    let r = reply(&o);
    assert_eq!(o.status.code(), Some(0), "{r}");
    assert_eq!(r["data"]["results"][0]["status"], "ok", "{r}");
    assert!(
        r["data"]["results"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("kept running"),
        "{r}"
    );
    for stream in [&o.stdout, &o.stderr] {
        let text = String::from_utf8_lossy(stream);
        assert!(
            !text.contains("APP-SAYS-HI") && !text.contains("APP-ERR"),
            "the app's output stays in its log:\n{text}"
        );
    }

    let passed = sam_within(
        root,
        &["selftest", &lasting, "--seconds", "2"],
        Duration::from_secs(90),
    );
    let text = String::from_utf8_lossy(&passed.stdout);
    assert!(text.contains('✓') && !text.contains('✗'), "{text}");
    let failed = sam(root, &["selftest", &failing, "--seconds", "5"]);
    assert_eq!(failed.status.code(), Some(3));
    let text = String::from_utf8_lossy(&failed.stdout);
    assert!(text.contains('✗') && !text.contains('✓'), "{text}");
}

/// `run APP -- ARGS` starts the app with those arguments.
#[test]
fn run_hands_the_app_the_arguments_given() {
    let Some(_contracts) = sandbox_here() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = added(root, "Echo", "#!/bin/sh\necho \"ARGS:$*\"\n");
    let o = sam(root, &["--json", "run", &id, "--", "--hello", "world"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(reply(&o)["data"]["success"], true);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("ARGS:--hello world"), "{err}");
}

/// `verify FILE` checks an AppImage that has no sandbox yet, with the
/// settings SAM would give it or, as the window asks before adding, with
/// the settings given; no sandbox is created. Regression: the check was
/// refused because nobody had confirmed the settings of its scratch
/// record (which nobody can).
#[test]
fn verify_checks_an_appimage_without_a_sandbox() {
    let Some(_contracts) = sandbox_here() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let img = fixture(root, "Unadded", "#!/bin/sh\nexit 0\n");
    let img = img.to_str().unwrap();
    let mut settings =
        reply(&sam(root, &["--json", "preview", img]))["data"]["permissions"].clone();
    settings["network"]["mode"] = "localhost".into();
    let settings = settings.to_string();
    for (args, input) in [
        (&["--json", "verify", img][..], None),
        (
            &["--json", "verify", img, "--permissions-stdin"][..],
            Some(settings.as_str()),
        ),
    ] {
        let o = sam_with_input(root, args, input, Duration::from_secs(120));
        let r = reply(&o);
        assert_eq!(r["ok"], true, "{args:?}: {r}");
        assert!(
            !r["data"]["report"]["results"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{r}"
        );
    }
    let list = reply(&sam(root, &["--json", "list"]));
    assert_eq!(
        list["data"],
        serde_json::json!([]),
        "no sandbox was created"
    );
}
