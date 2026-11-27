//! A start from the menu (`sam-jail-run`) has no terminal: when SAM refuses
//! or fails to start the app, or the app stops right after starting, the
//! person hears it through a notification, with a "Show the fix" button
//! that opens SAM at the app's repair page; and the files from the menu
//! reach the app. A stand-in `notify-send` writes down every notice (and
//! answers that the button was clicked), a stand-in SAM window writes down
//! how it was opened. Standard error is a pipe, as from the menu. The
//! starts that need a sandbox are skipped where Bubblewrap cannot run.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
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

fn script(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// SAM's folders under `root`, and the stand-ins in `root/tools`: a
/// `notify-send` that appends its arguments to `root/notices` and answers
/// "open" (the button was clicked), and a SAM window that appends its
/// arguments to `root/window`.
fn setup(root: &Path) {
    for d in ["config", "home", "images", "tools"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    script(
        &root.join("tools/notify-send"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\necho open\n",
            root.join("notices").display()
        ),
    );
    script(
        &root.join("tools/sam-window"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n",
            root.join("window").display()
        ),
    );
}

fn isolated(program: &str, root: &Path) -> Command {
    let mut c = Command::new(program);
    c.env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("XDG_DATA_HOME", root.join("home/.local/share"))
        .env_remove("APPIMAGE")
        .stdin(Stdio::null());
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    c
}

fn sam(root: &Path, args: &[&str]) -> Output {
    let o = isolated(env!("CARGO_BIN_EXE_sam-jail"), root)
        .args(args)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "sam-jail {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

/// `sam-jail-run` as the menu starts it, finding the stand-ins first (and
/// trusting them: SAM runs a tool the user can change only from the folder
/// a test names). With `window`, SAM runs from that AppImage file.
fn menu_start(root: &Path, args: &[&OsStr], window: Option<&Path>) -> Output {
    let tools = root.join("tools");
    let mut c = isolated(env!("CARGO_BIN_EXE_sam-jail-run"), root);
    c.args(args)
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .env("SAM_TRUST_TOOLS_IN", &tools);
    if let Some(w) = window {
        c.env("APPIMAGE", w);
    }
    c.output().unwrap()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// What `path` holds once it contains `needle`. The button is waited for
/// in a process of its own that outlives the start, so its notice and the
/// window come a moment later; fails after a minute without it.
fn wait_for(path: &Path, needle: &str) -> String {
    let start = std::time::Instant::now();
    loop {
        let text = read(path);
        if text.contains(needle) {
            return text;
        }
        if start.elapsed() > std::time::Duration::from_secs(60) {
            panic!("{} never held {needle:?}: {text:?}", path.display());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Makes and adds a confirmed app with this start script; returns its id.
fn add(root: &Path, name: &str, apprun: &str) -> String {
    let s = root.join("apprun");
    script(&s, apprun);
    let img = root
        .join("images")
        .join(format!("{name}-1.0-x86_64.AppImage"));
    let (img_s, s_s) = (img.to_str().unwrap(), s.to_str().unwrap());
    sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            name,
            "--apprun",
            s_s,
            img_s,
        ],
    );
    let o = sam(root, &["--json", "add", img_s, "--no-launcher", "--accept"]);
    let v: serde_json::Value = serde_json::from_slice(
        o.stdout
            .split(|b| *b == b'\n')
            .rfind(|l| !l.is_empty())
            .unwrap(),
    )
    .unwrap();
    v["data"]["app"]["id"].as_str().unwrap().to_string()
}

/// A start SAM refuses before any sandbox is built (an app it does not
/// know, a file name that is not text) is told in a notice, naming what
/// went wrong; the start still ends with an error.
#[test]
fn a_refused_menu_start_is_told_in_a_notice() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    setup(root);
    let run = menu_start(
        root,
        &[OsStr::new("--app-id"), OsStr::new("no-such-app")],
        None,
    );
    assert_eq!(run.status.code(), Some(1));
    let seen = read(&root.join("notices"));
    assert!(
        seen.contains("SAM could not start the app") && seen.contains("no-such-app"),
        "the notice names the app: {seen:?}\n{}",
        String::from_utf8_lossy(&run.stderr)
    );

    fs::remove_file(root.join("notices")).unwrap();
    let odd = OsStr::from_bytes(b"/home/j\xffo.txt");
    let run = menu_start(root, &[OsStr::new("--app-id"), OsStr::new("x"), odd], None);
    assert_eq!(run.status.code(), Some(1));
    let seen = read(&root.join("notices"));
    assert!(
        seen.contains("SAM could not start the app") && seen.contains("not valid text"),
        "the notice says why: {seen:?}\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// An app that fails right after it started gets a notice saying so, and
/// its button opens SAM's window at that app's repair page.
#[test]
fn a_quick_failure_gets_a_notice_with_the_fix_button() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    setup(root);
    let id = add(root, "Crash", "#!/bin/sh\nexit 1\n");
    let window = root.join("tools/sam-window");
    let run = menu_start(
        root,
        &[OsStr::new("--app-id"), OsStr::new(&id)],
        Some(&window),
    );
    let err = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(1), "{err}");
    let seen = wait_for(&root.join("notices"), "stopped right after starting");
    assert!(seen.contains("Crash"), "{seen:?}");
    let opened = wait_for(&root.join("window"), "--page app-repair");
    assert_eq!(
        opened.trim(),
        format!("--page app-repair --app {id}"),
        "the button opens this app's repair page"
    );
}

/// A start the sandbox check refuses (a setting that does not apply) gets
/// the notice that says where to look: the app's Test.
#[test]
fn a_menu_start_the_sandbox_check_refuses_points_to_test() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    setup(root);
    fs::create_dir_all(root.join("home/Documents")).unwrap();
    fs::write(
        root.join("config/config.toml"),
        "[security]\ncheck_before_launch = true\n",
    )
    .unwrap();
    let id = add(root, "Quick", "#!/bin/sh\nexit 0\n");
    // Documents is "No access", but a raw Bubblewrap argument mounts it.
    let docs = root.join("home/Documents").display().to_string();
    let leak = serde_json::json!(["--ro-bind", docs, docs]).to_string();
    sam(
        root,
        &["set", &id, "advanced.extra_bwrap_args", &leak, "--yes"],
    );
    let run = menu_start(root, &[OsStr::new("--app-id"), OsStr::new(&id)], None);
    let err = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(1), "the start stops: {err}");
    let seen = read(&root.join("notices"));
    assert!(
        seen.contains("Quick was not started") && seen.contains("→ Test"),
        "the notice points to Test: {seen:?}\n{err}"
    );
}

/// The files from the menu reach the app, without the `--` that may
/// separate them from the id.
#[test]
fn the_files_from_the_menu_reach_the_app() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    setup(root);
    let id = add(root, "Echo", "#!/bin/sh\necho \"ARGS:$*\"\n");
    for given in [
        vec!["--app-id", &id, "hello", "two words"],
        vec![&id, "--", "hello", "two words"],
    ] {
        let given: Vec<&OsStr> = given.iter().map(OsStr::new).collect();
        let run = menu_start(root, &given, None);
        let out = String::from_utf8_lossy(&run.stdout);
        assert!(
            run.status.success() && out.lines().any(|l| l == "ARGS:hello two words"),
            "{given:?}: {out}\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
}
