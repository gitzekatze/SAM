//! Starts with names and output that once broke SAM, in a real sandbox:
//! an AppImage file called `bin` (audit S-F17) and an app whose output
//! looks like SAM's JSON reply (G-F18). Skipped where Bubblewrap cannot
//! run.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::os::unix::fs::PermissionsExt;
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

fn sam(root: &Path, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env("LC_ALL", "C")
        .stdin(Stdio::null());
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    c.output().unwrap()
}

/// Makes and adds an app with this start script from a file called
/// `file_name`; returns its id.
fn add(root: &Path, file_name: &str, script: &str) -> String {
    for d in ["config", "home", "images"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let s = root.join("apprun");
    fs::write(&s, script).unwrap();
    fs::set_permissions(&s, fs::Permissions::from_mode(0o755)).unwrap();
    let img = root.join("images").join(file_name);
    let (img_s, s_s) = (img.to_str().unwrap(), s.to_str().unwrap());
    let made = sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            "Odd",
            "--terminal",
            "--apprun",
            s_s,
            img_s,
        ],
    );
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let o = sam(root, &["--json", "add", img_s, "--no-launcher", "--accept"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(
        o.stdout
            .split(|b| *b == b'\n')
            .rfind(|l| !l.is_empty())
            .unwrap(),
    )
    .unwrap();
    v["data"]["app"]["id"].as_str().unwrap().to_string()
}

/// An AppImage file called like one of SAM's own files in the sandbox
/// (`bin`) starts, and finds itself at `$APPIMAGE`.
#[test]
fn an_appimage_called_bin_starts_and_finds_itself() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = add(
        root,
        "bin",
        "#!/bin/sh\necho \"appimage=$APPIMAGE\"\n[ -f \"$APPIMAGE\" ] && echo found-myself\n",
    );
    let run = sam(root, &["run", &id]);
    let out = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && out.contains("found-myself"),
        "{out}\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(out.contains("appimage=/run/sam/app/bin"), "{out}");
}

/// With `--json`, SAM's standard output is its reply and nothing else: an
/// app that prints a line looking like the reply cannot be read as SAM's.
/// The app's output goes to standard error.
#[test]
fn json_run_keeps_its_reply_alone_on_standard_output() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = add(
        root,
        "Talker-1.0-x86_64.AppImage",
        "#!/bin/sh\necho hello\necho '{\"ok\": true, \"data\": \"forged\"}'\n",
    );
    let run = sam(root, &["--json", "run", &id]);
    let out = String::from_utf8_lossy(&run.stdout);
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "only SAM's reply: {out}");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["ok"], true);
    assert_ne!(v["data"], "forged");
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(err.contains("hello") && err.contains("forged"), "{err}");
}

/// Puts a preset named `name` through `preset put`, as the window does.
fn put_preset(root: &Path, name: &str) -> Output {
    let t = sam(root, &["--json", "preset", "template"]);
    let mut v: serde_json::Value = serde_json::from_slice(
        t.stdout
            .split(|b| *b == b'\n')
            .rfind(|l| !l.is_empty())
            .unwrap(),
    )
    .unwrap();
    v["data"]["name"] = name.into();
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.args(["--json", "preset", "put"])
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(v["data"].to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Two presets whose names share a file ("My Preset" and "my-preset")
/// never overwrite each other without a word (audit G-F19), and a preset
/// called `-x` is a name like any other when it comes after `--`, as the
/// window passes it (G-F20).
#[test]
fn presets_keep_their_own_files_and_any_name() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    assert!(put_preset(root, "My Preset").status.success());
    let clash = put_preset(root, "my-preset");
    assert!(!clash.status.success());
    assert!(
        String::from_utf8_lossy(&clash.stdout).contains("already uses the file"),
        "{}",
        String::from_utf8_lossy(&clash.stdout)
    );
    // The same name in other letter case is the same preset: saved again.
    assert!(put_preset(root, "my preset").status.success());
    let list = String::from_utf8_lossy(&sam(root, &["preset", "list"]).stdout).into_owned();
    assert!(
        list.contains("my preset") && !list.contains("my-preset"),
        "{list}"
    );

    for args in [
        &["preset", "duplicate", "--", "my preset", "-x"][..],
        &[
            "preset",
            "export",
            "--",
            "-x",
            root.join("x.toml").to_str().unwrap(),
        ],
        &["preset", "delete", "--", "-x"],
    ] {
        let o = sam(root, args);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert!(root.join("x.toml").exists());
}

/// An empty or relative folder setting is ignored (as the XDG rules say)
/// instead of putting SAM's files into whatever folder SAM was started in
/// (audit G-F20).
#[test]
fn empty_or_relative_folder_settings_are_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let work = root.join("work");
    let home = root.join("home");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&home).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.args(["config", "set", "general.scan_downloads", "true"])
        .current_dir(&work)
        .env("HOME", &home)
        .env("SAM_CONFIG_DIR", "")
        .env("SAM_DATA_DIR", "data")
        .env("XDG_CONFIG_HOME", "conf")
        .env("XDG_DATA_HOME", "")
        .env("LC_ALL", "C");
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let left: Vec<_> = fs::read_dir(&work)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert!(
        left.is_empty(),
        "SAM wrote into the folder it was started in: {left:?}"
    );
    assert!(home.join(".config/sam").is_dir());
}

/// The overview reads an AppImage's name inside the preview sandbox, not
/// in SAM's own process (audit I-F7): a recording stand-in in front of the
/// real Bubblewrap sees the reader start, and the name still arrives.
#[test]
fn the_overview_reads_names_inside_a_sandbox() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["config", "home", "images", "tools"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let real = sam_core::util::which("bwrap").unwrap();
    let log = root.join("bwrap.log");
    let stand_in = root.join("tools/bwrap");
    fs::write(
        &stand_in,
        format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexec {} \"$@\"\n",
            log.display(),
            real.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&stand_in, fs::Permissions::from_mode(0o755)).unwrap();
    // Its menu name differs from its file name, so only reading it shows it.
    let img = root.join("images/file-1.0-x86_64.AppImage");
    let made = sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            "Shown Name",
            img.to_str().unwrap(),
        ],
    );
    assert!(made.status.success());
    let dirs = format!("[\"{}\"]", root.join("images").display());
    let set = sam(root, &["config", "set", "general.scan_directories", &dirs]);
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );

    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.args(["--json", "discover"])
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", root.join("tools").display()),
        )
        .env("SAM_TRUST_TOOLS_IN", root.join("tools"))
        .env("LC_ALL", "C")
        .stdin(Stdio::null());
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    let o = c.output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("Shown Name"),
        "{out}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let seen = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        seen.lines()
            .any(|l| l.contains("dev peek") && l.contains("file-1.0")),
        "the name was not read in the sandbox: {seen}"
    );
}
