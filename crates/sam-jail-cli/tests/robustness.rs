//! SAM's files from older, newer and broken SAMs: the real `sam-jail` binary
//! must migrate old ones (keeping the original), leave newer ones untouched,
//! move damaged ones aside and carry on, and never panic on mangled data.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

struct Env {
    _tmp: tempfile::TempDir,
    config: std::path::PathBuf,
    data: std::path::PathBuf,
    apps: std::path::PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let r = tmp.path().to_path_buf();
    let e = Env {
        config: r.join("config"),
        data: r.join("data"),
        apps: r.join("applications"),
        _tmp: tmp,
    };
    fs::create_dir_all(e.data.join("apps")).unwrap();
    fs::create_dir_all(e.config.join("presets")).unwrap();
    fs::create_dir_all(&e.data).unwrap();
    e
}

fn sam(e: &Env, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sam-jail"))
        .args(args)
        .env("SAM_CONFIG_DIR", &e.config)
        .env("SAM_DATA_DIR", &e.data)
        .env("SAM_APPLICATIONS_DIR", &e.apps)
        // English, whatever language the computer running the tests uses.
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .output()
        .unwrap()
}

fn no_panic(o: &Output, what: &str) {
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        o.status.code() != Some(101) && !err.contains("panicked"),
        "{what}: panic\n{err}"
    );
}

fn damaged_in(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".damaged-"))
        .count()
}

const RECORD: &str =
    r#"{"id": "appimage-demo-1234", "name": "Demo", "source_path": "/nonexistent/Demo.AppImage"}"#;

/// Files from older SAM versions are migrated to the current format, and the originals are kept.
#[test]
fn old_formats_are_migrated_and_kept() {
    let e = env();
    // Format 0: no `format`, an older theme name.
    fs::write(
        e.config.join("config.toml"),
        "[general]\ntheme = \"breeze-dark\"\n",
    )
    .unwrap();
    fs::write(e.data.join("apps/appimage-demo-1234.json"), RECORD).unwrap();
    let o = sam(&e, &["--json", "list"]);
    no_panic(&o, "list");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("appimage-demo-1234"));
    // A change saves both in the current format; the originals stay.
    assert!(
        sam(&e, &["config", "set", "general.scan_downloads", "true"])
            .status
            .success()
    );
    assert!(sam(
        &e,
        &["set", "appimage-demo-1234", "network.mode", "full", "--yes"]
    )
    .status
    .success());
    let cfg = fs::read_to_string(e.config.join("config.toml")).unwrap();
    assert!(
        cfg.contains("format = 1") && cfg.contains("theme = \"dark\""),
        "{cfg}"
    );
    assert!(e.config.join("config.toml.format0.bak").exists());
    let rec = fs::read_to_string(e.data.join("apps/appimage-demo-1234.json")).unwrap();
    assert!(rec.contains("\"format\": 1"), "{rec}");
    assert_eq!(
        fs::read_to_string(e.data.join("apps/appimage-demo-1234.json.format0.bak")).unwrap(),
        RECORD
    );
}

/// Files from a newer SAM are never changed by an older one.
#[test]
fn newer_formats_are_left_untouched() {
    let e = env();
    let newer_cfg = "format = 99\n[general]\ntheme = \"dark\"\nsomething_new = true\n";
    fs::write(e.config.join("config.toml"), newer_cfg).unwrap();
    let o = sam(&e, &["config", "set", "general.scan_downloads", "true"]);
    no_panic(&o, "config set");
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("newer SAM"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        fs::read_to_string(e.config.join("config.toml")).unwrap(),
        newer_cfg,
        "not overwritten"
    );

    let e = env();
    let newer_rec =
        r#"{"format": 99, "id": "appimage-new-1234", "name": "New", "future_field": [1, 2]}"#;
    fs::write(e.data.join("apps/appimage-new-1234.json"), newer_rec).unwrap();
    let o = sam(&e, &["--json", "list"]);
    no_panic(&o, "list");
    assert!(o.status.success());
    assert!(
        !String::from_utf8_lossy(&o.stdout).contains("appimage-new-1234"),
        "not shown"
    );
    let o = sam(&e, &["set", "appimage-new-1234", "network.mode", "full"]);
    assert!(!o.status.success());
    assert_eq!(
        fs::read_to_string(e.data.join("apps/appimage-new-1234.json")).unwrap(),
        newer_rec,
        "not overwritten"
    );
    assert_eq!(
        damaged_in(&e.data.join("apps")),
        0,
        "a newer record is not damaged"
    );
}

/// Damaged files are moved aside and reported, and SAM carries on.
#[test]
fn damaged_files_are_moved_aside_and_reported() {
    let e = env();
    fs::write(e.config.join("config.toml"), "[general\ntheme = = \x01").unwrap();
    fs::write(e.data.join("apps/appimage-demo-1234.json"), &RECORD[..30]).unwrap();
    fs::write(e.config.join("presets/broken.toml"), "[preset\nname=").unwrap();
    let o = sam(&e, &["--json", "list"]);
    no_panic(&o, "list");
    assert!(
        o.status.success(),
        "SAM carries on: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let o = sam(&e, &["--json", "preset", "list"]);
    no_panic(&o, "preset list");
    assert_eq!(damaged_in(&e.config), 1, "config moved aside");
    assert_eq!(damaged_in(&e.data.join("apps")), 1, "record moved aside");
    assert_eq!(
        damaged_in(&e.config.join("presets")),
        1,
        "preset moved aside"
    );
    let o = sam(&e, &["doctor"]);
    no_panic(&o, "doctor");
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("Damaged files") && out.contains(".damaged-"),
        "{out}"
    );
    // A single invalid value is reset, not the whole file.
    let e = env();
    fs::write(
        e.config.join("config.toml"),
        "[general]\nscan_downloads = true\n[extraction]\nlocation = \"relative/dir\"\n",
    )
    .unwrap();
    let o = sam(&e, &["--json", "config", "show"]);
    assert!(o.status.success());
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(
        v["data"]["general"]["scan_downloads"], true,
        "other settings kept"
    );
    assert_eq!(
        v["data"]["extraction"]["location"], "",
        "invalid value reset"
    );
    assert_eq!(damaged_in(&e.config), 0);
}

/// Mangled files never make SAM crash.
#[test]
fn mangled_files_never_crash() {
    let cfg = "format = 1\n[general]\ntheme = \"dark\"\nscan_directories = [\"~/Applications\"]\n[security]\nwarn_x11 = true\n[extraction]\nmax_files = 1000\n";
    let rec = r#"{"format": 1, "id": "appimage-demo-1234", "name": "Demo", "source_path": "/x/Demo.AppImage", "profile": {"permissions": {"network": {"mode": "full", "host_ports": ["11434"]}, "filesystem": {"documents": "rw"}}, "args": ["--a"]}, "last_launch": {"started_at": 1, "finished_at": 2, "success": true}}"#;
    let mut cases: Vec<(String, String)> = Vec::new();
    // Truncated at many lengths, and with single bytes changed.
    for n in (0..rec.len()).step_by(17) {
        cases.push((cfg.to_string(), rec[..n].to_string()));
    }
    for n in (0..cfg.len()).step_by(13) {
        cases.push((cfg[..n].to_string(), rec.to_string()));
    }
    for (i, b) in [b'{', b'"', b'1', b']', b'\0', b'\n', 0xff]
        .iter()
        .enumerate()
    {
        let mut r = rec.as_bytes().to_vec();
        let at = (i * 37 + 11) % r.len();
        r[at] = *b;
        cases.push((cfg.to_string(), String::from_utf8_lossy(&r).into_owned()));
    }
    for (c, r) in cases {
        let e = env();
        fs::write(e.config.join("config.toml"), &c).unwrap();
        fs::write(e.data.join("apps/appimage-demo-1234.json"), &r).unwrap();
        for args in [
            &["--json", "list"][..],
            &["doctor"][..],
            &["--json", "info", "appimage-demo-1234"][..],
        ] {
            no_panic(
                &sam(&e, args),
                &format!("{args:?} with config {c:?} and record {r:?}"),
            );
        }
    }
}

/// `sam-jail version` answers with the JSON interface version even when the configuration cannot be read.
#[test]
fn version_reports_the_json_interface() {
    let e = env();
    // Answers even when SAM's configuration cannot be read.
    fs::write(e.config.join("config.toml"), "format = 99\n").unwrap();
    let o = sam(&e, &["--json", "version"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains(&format!("\"interface\":{}", sam_core::JSON_INTERFACE)),
        "{out}"
    );
    assert!(out.contains(env!("CARGO_PKG_VERSION")), "{out}");
}

/// Signing a file that has no AppImage signature sections is refused with
/// a clear message, before GnuPG is asked anything, and the file stays as
/// it was.
#[test]
fn signing_a_file_without_signature_sections_is_refused() {
    let e = env();
    let f = e.config.join("NotSignable.AppImage");
    fs::write(&f, b"\x7fELF not really a runtime").unwrap();
    let before = fs::read(&f).unwrap();
    let o = sam(
        &e,
        &[
            "--json",
            "dev",
            "sign-appimage",
            f.to_str().unwrap(),
            "--key",
            "AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6",
        ],
    );
    assert!(!o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("no signature sections"), "{out}");
    assert_eq!(fs::read(&f).unwrap(), before, "the file is unchanged");
}
