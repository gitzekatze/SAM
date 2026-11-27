//! A repair step is tried at the next start: kept when the app then runs,
//! undone by SAM when it still fails (owner decision of 2026-11-18; night
//! run N3: in all eight apps that did not start, the steps that did not
//! help stayed applied). From a real sandbox:
//! - an app that needs all of /usr: "Show all of /usr" helps and stays;
//! - an app that fails anyway: the step tried is undone exactly, kept out
//!   of the ladder, and the start says so.
//!
//! In its own file because it sets `HOME`.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;

use sam_core::permissions::{HostRuntime, PermissionSet};
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// "needs-usr": runs only when it sees /usr/share/doc (all of /usr);
/// "fail": never runs.
const APP: &str = r#"#!/bin/sh
case "$1" in
  needs-usr) [ -d /usr/share/doc ] || exit 1 ;;
  *) echo "cannot open display" >&2; exit 1 ;;
esac
echo END=1
"#;

#[test]
fn a_repair_step_is_kept_when_it_helps_and_undone_when_it_does_not() {
    let host = HostInfo::probe();
    if host.tools.bwrap.is_none() || sam_runner::doctor::bwrap_functional(&host).is_err() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    if !std::path::Path::new("/usr/share/doc").is_dir() {
        sam_runner::contracts::skip("this system has no /usr/share/doc")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    let img = root.join("Trial-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Trial");
    spec.apprun = APP.into();
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
    let host = sam_runner::testenv::test_host(HostInfo::probe());
    let start = |mode: &str| {
        let mut e = app.registry().get(&id).unwrap().unwrap();
        run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                args: vec![mode.into()],
                owd: Some(home.clone()),
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &host,
        )
        .unwrap()
    };
    let apply = |step: &str| {
        let e = app.registry().get(&id).unwrap().unwrap();
        let sug = app
            .find_suggestion(&e, step)
            .unwrap_or_else(|| panic!("{step} offered"));
        app.apply_suggestion(&id, &sug, true, true).unwrap();
    };
    let entry = || app.registry().get(&id).unwrap().unwrap();
    app.set_permissions(&id, PermissionSet::strict_gui())
        .unwrap();

    // It helps: kept, no longer on trial.
    assert!(!start("needs-usr").success, "fails with the minimal /usr");
    apply("full-usr");
    assert!(entry().applied_repairs.iter().any(|r| r.on_trial));
    let rec = start("needs-usr");
    assert!(rec.success, "{rec:?}");
    assert!(rec.undone_repairs.is_empty());
    let e = entry();
    assert_eq!(
        e.profile.permissions.advanced.host_runtime,
        HostRuntime::Full
    );
    assert!(
        e.applied_repairs.iter().all(|r| !r.on_trial),
        "judged and kept"
    );

    // It does not help: undone exactly, not offered again.
    let gpu_before = e.profile.permissions.devices.gpu;
    apply("gpu");
    assert_ne!(entry().profile.permissions.devices.gpu, gpu_before);
    let rec = start("fail");
    assert!(!rec.success);
    assert_eq!(rec.undone_repairs.len(), 1, "{rec:?}");
    let e = entry();
    assert_eq!(e.profile.permissions.devices.gpu, gpu_before, "undone");
    assert_eq!(
        e.profile.permissions.advanced.host_runtime,
        HostRuntime::Full,
        "the step that helped stays"
    );
    assert!(e.tried_repairs.contains(&"gpu".to_string()));
    assert!(
        app.find_suggestion(&e, "gpu").is_none(),
        "not offered again"
    );
    assert_eq!(
        e.last_launch.as_ref().unwrap().undone_repairs,
        rec.undone_repairs,
        "the record says so"
    );
}
