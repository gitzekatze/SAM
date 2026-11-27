//! The views `sam-jail` prints for people say what its JSON says: the risk
//! and every warning of `evaluate` and `info`, the dependency report of
//! `redetect`, the exact command of `command`, and an app's risk and state
//! in their columns of `list` and `group list`, whatever name the app gives
//! itself. Only the JSON was checked before, so these views could drop a
//! warning, the risk or the sandbox's options unnoticed.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// SAM's command line as built, with its own folders and home, in English.
fn sam(root: &Path, args: &[&str], stdin: Option<&str>) -> Output {
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sam_runner::testenv::isolate_command(&mut cmd, &root.join("sam"));
    cmd.env_remove("XDG_SESSION_TYPE");
    let mut child = cmd.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    if let Some(s) = stdin {
        input.write_all(s.as_bytes()).unwrap();
    }
    drop(input);
    let o = child.wait_with_output().unwrap();
    assert!(
        o.status.success(),
        "{args:?}: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

/// The human view of a command.
fn human(root: &Path, args: &[&str], stdin: Option<&str>) -> String {
    String::from_utf8(sam(root, args, stdin).stdout).unwrap()
}

/// The `data` of the JSON reply of a command.
fn json(root: &Path, args: &[&str], stdin: Option<&str>) -> Value {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    let o = sam(root, &a, stdin);
    let text = String::from_utf8_lossy(&o.stdout);
    let v: Value = serde_json::from_str(text.lines().last().unwrap_or("null"))
        .unwrap_or_else(|e| panic!("{e}: {text}"));
    v["data"].clone()
}

/// SAM's folders with the test app `name` added and confirmed; its id.
fn setup(root: &Path, name: &str) -> String {
    for d in ["config", "home"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let img = root.join("app.AppImage");
    let img = img.to_str().unwrap();
    sam(root, &["dev", "make-fixture", "--name", name, img], None);
    let add = json(root, &["add", img, "--no-launcher", "--accept"], None);
    add["entry"]["id"]
        .as_str()
        .or(add["id"].as_str())
        .unwrap()
        .to_string()
}

/// The risk level's words in English (the program runs with `LC_ALL=C`).
fn level_words(level: &Value) -> &'static str {
    match level.as_str().unwrap() {
        "low" => "Harmless",
        "medium" => "Some access",
        "high" => "Think twice",
        "dangerous" => "Dangerous",
        other => panic!("unknown level {other}"),
    }
}

/// Every warning of the JSON reply, title and message, is in `text`.
fn shows_every_warning(text: &str, warnings: &Value) {
    let warnings = warnings.as_array().unwrap();
    assert!(!warnings.is_empty(), "the test needs a warning");
    for w in warnings {
        for part in ["title", "message"] {
            let s = w[part].as_str().unwrap();
            assert!(text.contains(s), "{part} {s:?} missing in:\n{text}");
        }
    }
}

/// `evaluate` and `info` show the risk with what sets it and every
/// warning, as their JSON has them.
#[test]
fn evaluate_and_info_show_the_risk_and_every_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Calc");

    let mut p = sam_core::permissions::PermissionSet::strict_gui();
    p.network.mode = sam_core::permissions::NetworkMode::Full;
    p.filesystem.home = true;
    p.filesystem.home_access = sam_core::permissions::Access::Rw;
    let perms = serde_json::to_string(&p).unwrap();
    let ev = json(root, &["evaluate"], Some(&perms));
    let text = human(root, &["evaluate"], Some(&perms));
    let risk = text.lines().next().unwrap();
    assert!(
        risk.starts_with(&format!("risk: {}", level_words(&ev["risk"]["level"]))),
        "{text}"
    );
    let deciding: Vec<&str> = ev["risk"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["level"] == ev["risk"]["level"])
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert!(!deciding.is_empty());
    for t in deciding {
        assert!(risk.contains(t), "{t} missing in {risk}");
    }
    shows_every_warning(&text, &ev["warnings"]);

    // The same permissions on the app: `info` shows its warnings too.
    for (key, value) in [
        ("network.mode", "full"),
        ("filesystem.home", "true"),
        ("filesystem.home_access", "rw"),
    ] {
        sam(root, &["set", &id, key, value, "--yes"], None);
    }
    let info = json(root, &["info", &id], None);
    let text = human(root, &["info", &id], None);
    assert!(text.contains("\nWarnings\n"), "{text}");
    shows_every_warning(&text, &info["warnings"]);
}

/// An app rated Medium reads "Some access" in `list` and `info`, no longer
/// "Harmless" like a Low one, and `--risk` selects it by these words only:
/// `harmless` now selects Low apps alone (owner decision 17 of
/// 2026-11-23).
#[test]
fn a_medium_app_reads_some_access_in_list_and_info() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Calc");
    // Sound is rated Medium and does not ask first.
    sam(root, &["set", &id, "audio.enabled", "true"], None);
    let info = json(root, &["info", &id], None);
    assert_eq!(
        info["app"]["risk"]["level"], "medium",
        "the test needs a Medium app: {info}"
    );

    let text = human(root, &["info", &id], None);
    let risk = text
        .lines()
        .find(|l| l.trim_start().starts_with("risk:"))
        .unwrap_or_else(|| panic!("no risk line in:\n{text}"));
    let shown = risk.trim_start().trim_start_matches("risk:").trim_start();
    assert!(shown.starts_with("Some access"), "{risk}");

    let text = human(root, &["list"], None);
    let mut lines = text.lines();
    let header = lines.next().unwrap();
    let row = lines.next().unwrap();
    assert!(
        from(row, column(header, "RISK")).starts_with("Some access"),
        "{header}\n{row}"
    );

    let picked = |risk: &str| {
        json(root, &["list", "--risk", risk], None)
            .as_array()
            .unwrap()
            .len()
    };
    assert_eq!(picked("some-access"), 1);
    assert_eq!(picked("some access"), 1);
    assert_eq!(picked("medium"), 1);
    assert_eq!(picked("harmless"), 0);
}

/// Saving and applying a preset name the risk in its words too: a preset
/// that turns sound on reads "Some access" when it is saved, listed and
/// applied, never the internal name "Medium" (owner decision 17 of
/// 2026-11-23).
#[test]
fn presets_name_the_risk_in_its_words() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Calc");
    // The strictest window settings (Harmless), then sound (Some access).
    let strict =
        serde_json::to_string(&sam_core::permissions::PermissionSet::strict_gui()).unwrap();
    sam(root, &["profile", "set", &id, "--yes"], Some(&strict));
    sam(root, &["set", &id, "audio.enabled", "true"], None);
    assert_eq!(
        json(root, &["info", &id], None)["app"]["risk"]["level"],
        "medium"
    );

    let saved = human(root, &["preset", "save", &id, "With sound"], None);
    assert!(saved.contains("(Some access)"), "{saved}");
    let listed = human(root, &["preset", "list"], None);
    assert!(listed.contains("Some access"), "{listed}");

    sam(root, &["profile", "set", &id, "--yes"], Some(&strict));
    assert_eq!(
        json(root, &["info", &id], None)["app"]["risk"]["level"],
        "low"
    );
    let applied = human(root, &["preset", "apply", "With sound", &id, "--yes"], None);
    assert!(
        applied.contains("(risk Harmless → Some access)"),
        "{applied}"
    );
    for text in [&saved, &listed, &applied] {
        assert!(!text.to_lowercase().contains("medium"), "{text}");
    }
}

/// `redetect` shows the dependency report it made.
#[test]
fn redetect_shows_the_dependency_report() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Calc");
    let report = json(root, &["redetect", &id], None)["detection"].clone();
    let text = human(root, &["redetect", &id], None);
    let compat = format!(
        "  compatibility: {}",
        report["compatibility"].as_str().unwrap()
    );
    // The JSON name is in kebab case, the view shows the Rust name.
    let shown = compat.replace("likely-broken", "LikelyBroken");
    let shown = shown
        .replace(": good", ": Good")
        .replace(": risk", ": Risk");
    assert!(
        text.lines().any(|l| l.starts_with(&shown)),
        "{shown:?} missing in:\n{text}"
    );
    assert!(text.lines().any(|l| l.starts_with("  toolkit: ")), "{text}");
}

/// `command` shows exactly the command that runs: joined again, its lines
/// are the argument list of `--json command`, the program's own arguments
/// included.
#[test]
fn command_shows_exactly_the_command_that_runs() {
    if sam_core::util::which("bwrap").is_none() {
        sam_runner::contracts::skip("bubblewrap is not installed")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = setup(root, "Calc");
    let args = ["command", &id, "two words", "--ro-bind"];
    let argv: Vec<String> =
        serde_json::from_value(json(root, &args, None)["argv"].clone()).unwrap();
    assert!(
        argv.iter()
            .any(|a| a == "--unshare-user" || a == "--unshare-all"),
        "{argv:?}"
    );
    let text = human(root, &args, None);
    let command: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
    assert!(command.len() > 10, "one option per line: {text}");
    assert_eq!(
        without_launch_folder(&command.join("\n").replace(" \\\n  ", " ")),
        without_launch_folder(&sam_core::util::shell_join(&argv))
    );
}

/// `s` with the folder of each launch (`/l<process>-<n>/`, different for
/// the two runs) left out.
fn without_launch_folder(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("/l") {
        out += &rest[..i + 2];
        rest = &rest[i + 2..];
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 && rest[digits..].starts_with('-') {
            let tail = &rest[digits + 1..];
            let n = tail.chars().take_while(char::is_ascii_digit).count();
            if n > 0 && tail[n..].starts_with('/') {
                out += "-";
                rest = &tail[n..];
            }
        }
    }
    out + rest
}

/// The column where `header`'s word `title` starts, in characters.
fn column(header: &str, title: &str) -> usize {
    header[..header.find(title).unwrap()].chars().count()
}

/// The text of `row` from character `at` on.
fn from(row: &str, at: usize) -> String {
    row.chars().skip(at).collect()
}

/// A long name with columns of its own cannot push SAM's real risk and
/// state out of their columns in `list`, nor the permission tags in
/// `group list`: the name is cut to its column.
#[test]
fn a_long_app_name_cannot_push_risk_and_state_out_of_their_columns() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let fake = format!(
        "Calc{}Office      Harmless    Ready       never{}.",
        " ".repeat(20),
        " ".repeat(60)
    );
    setup(root, &fake);
    let apps = json(root, &["list"], None);
    let app = &apps[0];
    assert!(
        app["name"].as_str().unwrap().contains("Harmless    Ready"),
        "the test needs the long name kept: {app}"
    );
    let text = human(root, &["list"], None);
    let mut lines = text.lines();
    let header = lines.next().unwrap();
    let row = lines.next().unwrap();
    let risk = from(row, column(header, "RISK"));
    assert!(
        risk.starts_with(level_words(&app["risk"]["level"])),
        "{header}\n{row}"
    );
    let status = from(row, column(header, "STATUS"));
    assert!(
        status.starts_with(app["badge_label"].as_str().unwrap()),
        "{header}\n{row}"
    );

    let overview = json(root, &["group", "list"], None);
    let tags: Vec<&str> = overview[0]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["label"].as_str().unwrap())
        .collect();
    let tags = if tags.is_empty() {
        "-".to_string()
    } else {
        tags.join(", ")
    };
    let text = human(root, &["group", "list"], None);
    let row = text.lines().next().unwrap();
    assert_eq!(from(row, 29), tags, "{row}");
}
