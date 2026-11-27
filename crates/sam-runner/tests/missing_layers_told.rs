//! Review K-4: a start that lacks a protection layer its settings ask for
//! says so while the app runs, not only in its record afterwards: a start
//! from the menu has no terminal, and the app may run for hours. Here the
//! compositor refuses the Wayland security context (a stand-in that hangs
//! up), the layer goes missing, and the start's hook is called while the
//! app still waits for it. In its own file because it sets `HOME` for the
//! whole test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// Where the hook leaves its sign for the app, and what it was told.
static SIGN: OnceLock<PathBuf> = OnceLock::new();
static TOLD: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn tell(_id: &str, _name: &str, missing: &[String]) {
    TOLD.lock().unwrap().extend(missing.iter().cloned());
    fs::write(SIGN.get().unwrap().join("told"), "yes").unwrap();
}

fn bwrap_works() -> bool {
    let host = HostInfo::probe();
    host.tools.bwrap.is_some() && sam_runner::doctor::bwrap_functional(&host).is_ok()
}

#[test]
fn a_missing_layer_is_told_while_the_app_runs() {
    if !bwrap_works() {
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
    let sign = root.join("sign");
    fs::create_dir_all(&sign).unwrap();
    SIGN.set(sign.clone()).unwrap();

    // The app waits up to a minute for the sign that it was told.
    let img = root.join("Waits-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Waits");
    spec.apprun = format!(
        "#!/bin/sh\ni=0\nwhile [ $i -lt 600 ]; do\n  [ -e {s}/told ] && {{ echo told-while-running; exit 0; }}\n  sleep 0.1; i=$((i+1))\ndone\necho not-told\n",
        s = sign.display()
    );
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

    let rec = run(
        &mut e,
        &LaunchOptions {
            quiet: true,
            owd: Some(home.clone()),
            extra_binds: vec![(sign.clone(), sign.clone(), false)],
            on_missing_layers: Some(tell),
            // Chosen for this start: the layer goes missing (B2 R77).
            start_anyway: true,
            ..Default::default()
        },
        &app.config,
        &app.paths,
        &host,
    )
    .unwrap();
    let log = fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap();
    assert!(
        rec.missing_layers
            .contains(&"Wayland security context".to_string()),
        "{:?}\n{log}",
        rec.missing_layers
    );
    assert!(log.contains("told-while-running"), "{log}");
    assert_eq!(
        *TOLD.lock().unwrap(),
        rec.missing_layers,
        "told exactly what the record says"
    );
}
