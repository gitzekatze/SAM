//! The JSON interface the window uses for the Permissions page and the
//! user's presets, through the real `sam-jail` binary.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

struct Env {
    tmp: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        Env {
            tmp: tempfile::tempdir().unwrap(),
        }
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let r = self.tmp.path();
        let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"))
            .args(args)
            .env("SAM_CONFIG_DIR", r.join("config"))
            .env("SAM_DATA_DIR", r.join("data"))
            .env("SAM_APPLICATIONS_DIR", r.join("applications"))
            // English, whatever language the computer running the tests uses.
            .env("LC_ALL", "C")
            .env_remove("LANGUAGE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(s) = stdin {
            use std::io::Write;
            c.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
        }
        c.wait_with_output().unwrap()
    }

    /// `--json` output: the `data` of the envelope.
    fn json(&self, args: &[&str], stdin: Option<&str>) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        let o = self.run(&a, stdin);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        v.get("data").cloned().unwrap_or(v)
    }

    fn add(&self, name: &str) -> String {
        let img = self.tmp.path().join(format!("{name}.AppImage"));
        assert!(self
            .run(
                &["dev", "make-fixture", "--name", name, img.to_str().unwrap()],
                None
            )
            .status
            .success());
        let v = self.json(
            &["add", img.to_str().unwrap(), "--no-launcher", "--accept"],
            None,
        );
        v["entry"]["id"]
            .as_str()
            .or(v["id"].as_str())
            .expect("id")
            .to_string()
    }
}

/// The JSON interface lists apps with their tags, changes a permission for several apps, and restores them with the returned "previous" object.
#[test]
fn group_list_set_and_restore_round_trip() {
    let e = Env::new();
    let a = e.add("One");
    let b = e.add("Two");
    let list = e.json(&["group", "list"], None);
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 2);
    for app in list {
        for field in [
            "id",
            "name",
            "permissions",
            "tags",
            "running",
            "needs_review",
            "may_not_start",
        ] {
            assert!(app.get(field).is_some(), "group list lacks {field}");
        }
    }
    let dry = e.json(
        &[
            "group",
            "set",
            "devices.webcam",
            "true",
            &a,
            &b,
            "--dry-run",
        ],
        None,
    );
    assert_eq!(dry["applied"], false);
    // The webcam is rated Think twice: refused without --yes (audit G-F2).
    assert!(!e
        .run(&["group", "set", "devices.webcam", "true", &a, &b], None)
        .status
        .success());
    let set = e.json(
        &["group", "set", "devices.webcam", "true", &a, &b, "--yes"],
        None,
    );
    assert_eq!(set["applied"], true);
    let previous = set["previous"].clone();
    assert_eq!(previous.as_object().unwrap().len(), 2);
    let tagged = e.json(&["group", "list"], None);
    assert!(tagged.as_array().unwrap().iter().all(|x| x["tags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["key"] == "devices.webcam")));
    let r = e.json(&["group", "restore"], Some(&previous.to_string()));
    assert_eq!(r["restored"], 2);
    let back = e.json(&["group", "list"], None);
    assert!(back
        .as_array()
        .unwrap()
        .iter()
        .all(|x| x["permissions"]["devices"]["webcam"] == false));
    // The refusal names what the change adds, each item once even when
    // several apps get it, and with the combination it makes.
    let refused = e.run(&["group", "set", "devices.webcam", "true", &a, &b], None);
    let err = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(err.matches("Webcam").count(), 1, "{err}");
    assert!(err.contains("--yes"), "{err}");
    e.json(&["set", &a, "filesystem.ssh", "true", "--yes"], None);
    let refused = e.run(&["group", "set", "network.mode", "full", &a, &b], None);
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success());
    assert!(err.contains("Full network"), "{err}");
    assert!(err.contains("Can send what it reads"), "{err}");
}

/// A group change with an invalid value, an unknown key or no app is refused, and no app changes.
#[test]
fn group_set_refuses_bad_input_without_changing_anything() {
    let e = Env::new();
    let a = e.add("One");
    let before = e.json(&["group", "list"], None);
    assert!(!e
        .run(&["group", "set", "network.mode", "sideways", &a], None)
        .status
        .success());
    assert!(!e
        .run(&["group", "set", "no.such.key", "true", &a], None)
        .status
        .success());
    assert!(
        !e.run(&["group", "set", "devices.webcam", "true"], None)
            .status
            .success(),
        "at least one app is required"
    );
    assert_eq!(e.json(&["group", "list"], None), before);
}

/// The command line lists only the user's own presets; the template is strict, and saved presets carry no built-in flag.
#[test]
fn presets_are_the_users_own_only() {
    let e = Env::new();
    assert_eq!(
        e.json(&["preset", "list"], None),
        Value::Array(vec![]),
        "no built-in presets"
    );
    assert!(
        !e.run(&["preset", "check", "x", "y"], None).status.success(),
        "`preset check` was removed"
    );
    let t = e.json(&["preset", "template"], None);
    assert_eq!(t["permissions"]["network"]["mode"], "none");
    let mut p = t.clone();
    p["name"] = "Mine".into();
    e.json(&["preset", "put"], Some(&p.to_string()));
    let list = e.json(&["preset", "list"], None);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(
        list[0].get("builtin").is_none(),
        "presets no longer carry a built-in flag"
    );
    fs::metadata(e.tmp.path().join("config/presets"))
        .expect("stored as a file in the presets folder");
}

/// Regression (found by the fuzzer): one damaged AppImage in a searched
/// folder made `sam-jail discover` crash, so the window's list stayed empty.
/// The list still loads, and the other AppImages are in it.
#[test]
fn one_damaged_appimage_does_not_stop_the_list() {
    let e = Env::new();
    let dir = e.tmp.path().join("apps");
    fs::create_dir_all(&dir).unwrap();
    let damaged = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../sam-intake/tests/data/squashfs-reader-panic.AppImage");
    fs::copy(&damaged, dir.join("Damaged.AppImage")).unwrap();
    assert!(e
        .run(
            &[
                "dev",
                "make-fixture",
                "--name",
                "Good",
                dir.join("Good.AppImage").to_str().unwrap()
            ],
            None
        )
        .status
        .success());
    fs::create_dir_all(e.tmp.path().join("config")).unwrap();
    fs::write(
        e.tmp.path().join("config/config.toml"),
        format!("[general]\nscan_directories = [\"{}\"]\n", dir.display()),
    )
    .unwrap();
    let list = e.json(&["discover"], None);
    let names: Vec<String> = list["apps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["path"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with("Good.AppImage")),
        "{names:?}"
    );
}
