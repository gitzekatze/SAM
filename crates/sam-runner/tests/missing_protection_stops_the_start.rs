//! A start that lacks a protection its settings ask for stops before the
//! app runs, unless the person chose "Start anyway" for that start (review
//! of PR 95, B2 R75 and R77; owner, 2026-11-25). Here the compositor offers
//! the Wayland security context but refuses it (a stand-in that hangs up):
//! before, the app started with the compositor's own socket and every
//! privileged Wayland function, with a warning only. In its own file
//! because it sets `HOME` for the whole test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions, PROTECTION_MISSING};
use sam_runner::ops::{AddOptions, Sam};

#[test]
fn a_start_whose_wayland_security_context_fails_does_not_run_the_app() {
    let host = HostInfo::probe();
    if !(host.tools.bwrap.is_some() && sam_runner::doctor::bwrap_functional(&host).is_ok()) {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    // The app leaves a sign when it runs.
    let sign = root.join("sign");
    fs::create_dir_all(&sign).unwrap();
    let img = root.join("Signs-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Signs");
    spec.apprun = format!("#!/bin/sh\necho ran > {}/ran\n", sign.display());
    build(&img, &spec).unwrap();
    let app = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
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
    let mut p = PermissionSet::strict_gui();
    p.display.wayland = true;
    p.display.wayland_privileged = false;
    let mut e = app.set_permissions(&id, p).unwrap();

    // A compositor that hangs up at once: no security context.
    let display = root.join("wayland-0");
    let listener = std::os::unix::net::UnixListener::bind(&display).unwrap();
    std::thread::spawn(move || {
        for c in listener.incoming() {
            drop(c);
        }
    });
    let mut host = sam_runner::testenv::test_host(HostInfo::probe());
    host.sockets.wayland = Some(display);

    let opts = |start_anyway| LaunchOptions {
        quiet: true,
        owd: Some(home.clone()),
        extra_binds: vec![(sign.clone(), sign.clone(), true)],
        start_anyway,
        ..Default::default()
    };
    let err = run(&mut e, &opts(false), &app.config, &app.paths, &host)
        .expect_err("a start without its Wayland security context stops");
    assert_eq!(
        sam_core::error::code_of(&err),
        Some(PROTECTION_MISSING),
        "{err:#}"
    );
    assert!(
        format!("{err:#}").contains("Wayland security context"),
        "{err:#}"
    );
    assert!(!sign.join("ran").exists(), "the app did not run");

    // "Start anyway": this one start runs, and says what it lacked.
    let rec = run(&mut e, &opts(true), &app.config, &app.paths, &host).unwrap();
    assert!(sign.join("ran").exists(), "the app ran");
    assert!(
        rec.missing_layers
            .contains(&"Wayland security context".to_string()),
        "{:?}",
        rec.missing_layers
    );
}
