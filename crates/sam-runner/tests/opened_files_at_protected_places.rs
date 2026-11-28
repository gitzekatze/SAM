//! SAM does not share a file named on the command line at a start place
//! that `XDG_CONFIG_HOME` moves, attacked from inside a real sandbox
//! (docs/security.md, *Files named on the command line*), with files
//! opened with the app set to read and write:
//! - with `XDG_CONFIG_HOME=/data/cfg` (outside the home), an autostart
//!   entry in `/data/cfg/autostart` can be neither read nor written (the
//!   control, `/data/notes.txt`, is written);
//! - with `XDG_CONFIG_HOME` the home itself, an autostart entry in
//!   `~/autostart` cannot be written (the control, `~/work/notes.txt`, is
//!   written).
//!
//! Before, both entries were shared writable, so the app could add a
//! command that the desktop runs outside the sandbox at the next login.
//!
//! Each variant has its own folder (home and data in it) beside the build,
//! outside `/tmp` and outside every system folder. In its own file, with
//! one test, because it sets `HOME` and `XDG_CONFIG_HOME` for the test
//! process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// The attack; `@ROOT@` becomes the folder that holds every variant.
const ATTACK: &str = r#"#!/bin/sh
R="@ROOT@"
cat "$R/out/data/cfg/autostart/x.desktop" 2>/dev/null | grep -q mine && echo OUT_AUTO=read || echo OUT_AUTO=hidden
echo pwned >> "$R/out/data/cfg/autostart/x.desktop" 2>/dev/null
echo pwned >> "$R/out/data/notes.txt" 2>/dev/null
echo pwned >> "$R/home/home/tester/autostart/x.desktop" 2>/dev/null
echo pwned >> "$R/home/home/tester/work/notes.txt" 2>/dev/null
echo END=1
"#;

fn parse(log: &Path) -> HashMap<String, String> {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// One variant's folders: `<root>/<name>/home/tester` and
/// `<root>/<name>/data`.
struct Variant {
    home: PathBuf,
    data: PathBuf,
}

fn variant(root: &Path, name: &str) -> Variant {
    let home = root.join(name).join("home/tester");
    let data = root.join(name).join("data");
    for d in [home.join("work"), home.join(".config"), data.clone()] {
        fs::create_dir_all(d).unwrap();
    }
    Variant { home, data }
}

#[test]
fn opened_files_at_moved_start_places_in_a_real_sandbox() {
    let host = HostInfo::probe();
    if host.tools.bwrap.is_none() || sam_runner::doctor::bwrap_functional(&host).is_err() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = fs::canonicalize(scratch.path()).unwrap();
    for outside in [
        "/tmp", "/var", "/etc", "/usr", "/boot", "/root", "/proc", "/sys", "/dev", "/run",
    ] {
        assert!(
            !root.starts_with(outside),
            "the build's scratch folder lies in {outside}: {}",
            root.display()
        );
    }
    sam_runner::testenv::isolate_this_process(&root);
    let out = variant(&root, "out");
    let at_home = variant(&root, "home");
    std::env::set_var("HOME", &out.home);

    let img = root.join("Attack-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Attack");
    spec.apprun = ATTACK.replace("@ROOT@", &root.to_string_lossy());
    build(&img, &spec).unwrap();
    let app = Sam::with_paths(Paths::rooted(&root.join("samroot"))).unwrap();
    let id = app
        .add(
            &img,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let mut p = PermissionSet::strict_gui();
    p.filesystem.opened_files = Access::Rw;
    // A start in the variant `v` with `XDG_CONFIG_HOME` at `config` and the
    // files `args` named on the command line.
    let start = |v: &Variant, config: &Path, args: &[PathBuf], what: &str| {
        std::env::set_var("HOME", &v.home);
        std::env::set_var("XDG_CONFIG_HOME", config);
        std::env::set_var("XDG_DATA_HOME", v.home.join(".local/share"));
        let mut e = app.set_permissions(&id, p.clone()).unwrap();
        let mut h = sam_runner::testenv::test_host(HostInfo::probe());
        h.xdg_dirs.clear();
        let rec = run(
            &mut e,
            &LaunchOptions {
                args: args
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect(),
                quiet: true,
                owd: Some(v.home.clone()),
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &h,
        )
        .unwrap_or_else(|e| panic!("the app did not start with {what}: {e:#}"));
        let log = rec.log_file.unwrap();
        let r = parse(&log);
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "the attack ran with {what}: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        r
    };

    // An autostart entry under a settings folder outside the home.
    let cfg = out.data.join("cfg");
    fs::create_dir_all(cfg.join("autostart")).unwrap();
    let entry = cfg.join("autostart/x.desktop");
    let notes = out.data.join("notes.txt");
    fs::write(&entry, "mine\n").unwrap();
    fs::write(&notes, "mine\n").unwrap();
    let r = start(
        &out,
        &cfg,
        &[entry.clone(), notes.clone()],
        "the settings folder outside the home",
    );
    assert_eq!(r["OUT_AUTO"], "hidden", "outside the home: {r:?}");
    assert_eq!(
        fs::read_to_string(&entry).unwrap(),
        "mine\n",
        "outside the home: the autostart entry was written"
    );
    assert!(
        fs::read_to_string(&notes).unwrap().contains("pwned"),
        "control, outside the home: the opened file was not written"
    );

    // An autostart entry at the top of the home, the settings folder being
    // the home itself.
    fs::create_dir_all(at_home.home.join("autostart")).unwrap();
    let entry = at_home.home.join("autostart/x.desktop");
    let notes = at_home.home.join("work/notes.txt");
    fs::write(&entry, "mine\n").unwrap();
    fs::write(&notes, "mine\n").unwrap();
    start(
        &at_home,
        &at_home.home,
        &[entry.clone(), notes.clone()],
        "the settings folder at the home",
    );
    assert_eq!(
        fs::read_to_string(&entry).unwrap(),
        "mine\n",
        "at the home: the autostart entry was written"
    );
    assert!(
        fs::read_to_string(&notes).unwrap().contains("pwned"),
        "control, at the home: the opened file was not written"
    );
}
