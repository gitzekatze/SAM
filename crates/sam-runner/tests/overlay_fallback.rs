//! The writable app folder's fallback: where no overlay can work, the app
//! starts with a read-only app folder and a warning. In its own file
//! because it sets `HOME` for the whole test process, which would race
//! with the other sandbox tests.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

const PROBE: &str = "#!/bin/sh\ntouch /opt/app/x 2>/dev/null && echo \"APPDIR_WRITE=yes\" || echo \"APPDIR_WRITE=no\"\n";

fn bwrap_works() -> bool {
    let host = HostInfo::probe();
    host.tools.bwrap.is_some() && sam_runner::doctor::bwrap_functional(&host).is_ok()
}

fn parse(log: &Path) -> HashMap<String, String> {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// When the folder for the writable app folder's changes cannot hold an
/// overlay, the app still starts, with a read-only app folder and a warning
/// that says why (regression: on Fedora in a container, SAM's data folder
/// was on an overlay, and the app failed with a raw Bubblewrap error).
#[test]
fn an_app_starts_read_only_when_its_writable_app_folder_cannot_work() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    let img = root.join("Probe-2.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Probe");
    spec.apprun = PROBE.into();
    build(&img, &spec).unwrap();
    let paths = Paths::rooted(&root.join("sam"));
    let app = Sam::with_paths(paths.clone()).unwrap();
    let id = app
        .add(
            &img,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    // A file where the overlay folder belongs: no overlay can work there.
    fs::create_dir_all(&paths.data_dir).unwrap();
    fs::write(paths.data_dir.join("overlays"), "not a folder").unwrap();

    let mut p = PermissionSet::strict_gui();
    p.advanced.writable_appdir = true;
    let mut e = app.set_permissions(&id, p).unwrap();
    let opts = LaunchOptions {
        quiet: true,
        owd: Some(home.clone()),
        ..Default::default()
    };
    let rec = run(
        &mut e,
        &opts,
        &app.config,
        &app.paths,
        &sam_runner::testenv::test_host(HostInfo::probe()),
    )
    .unwrap();
    assert!(rec.success, "the app starts: {}", rec.summary);
    let log = fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap();
    assert_eq!(
        parse(rec.log_file.as_ref().unwrap())["APPDIR_WRITE"],
        "no",
        "the app folder is read-only"
    );
    assert!(
        log.contains("# warning [writable-appdir-unavailable]"),
        "the warning says why:\n{log}"
    );
}
