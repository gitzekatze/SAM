//! A start that lacks a protection layer says so once, also when SAM
//! starts the app a second time by itself because it needed its own bus
//! name: before, the restart called the start's hook again, and a start
//! from the menu showed its notification twice. Here the compositor
//! refuses the Wayland security context (a stand-in that hangs up) and the
//! app ends at once without its bus name, on a private session bus. In its
//! own file because it sets `HOME` and the session bus for the whole test
//! process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;
use std::sync::Mutex;

use sam_core::permissions::{DbusMode, PermissionSet};
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// Each time the hook was called: what it was told.
static TOLD: Mutex<Vec<Vec<String>>> = Mutex::new(Vec::new());

fn tell(_id: &str, _name: &str, missing: &[String]) {
    TOLD.lock().unwrap().push(missing.to_vec());
}

/// Asks for the bus name it is given and ends with an error without it
/// (as GApplication does).
const APP: &str = r#"#!/bin/sh
if gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
     --method org.freedesktop.DBus.RequestName "$1" 4 2>/dev/null | grep -q '(uint32 1,)'; then
  echo "OWN $1=yes"
else
  echo "OWN $1=no"
  exit 1
fi
"#;

/// A start that lacks the Wayland security context and is started again
/// by SAM for its bus name calls the start's hook once, not once per try.
#[test]
fn a_missing_layer_is_told_once_when_sam_starts_the_app_again() {
    let host = HostInfo::probe();
    let ready = host.tools.bwrap.is_some()
        && sam_runner::doctor::bwrap_functional(&host).is_ok()
        && host.tools.xdg_dbus_proxy.is_some()
        && sam_core::util::which("gdbus").is_some();
    if !ready {
        sam_runner::contracts::skip("bubblewrap, xdg-dbus-proxy or gdbus is not available")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let services = sam_runner::testenv::PrivateServices::start(root);
    if services.bus_address().is_none() {
        sam_runner::contracts::skip("dbus-daemon is not installed")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Named-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Named");
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
    let mut p = PermissionSet::strict_gui();
    p.display.wayland = true;
    p.display.wayland_privileged = false;
    p.dbus.session.mode = DbusMode::Filtered;
    p.dbus.session.own.clear();
    let mut e = app.set_permissions(&id, p).unwrap();

    // A compositor that hangs up at once: no security context.
    let display = root.join("wayland-0");
    let listener = std::os::unix::net::UnixListener::bind(&display).unwrap();
    std::thread::spawn(move || {
        for c in listener.incoming() {
            drop(c);
        }
    });
    let mut host =
        services.apply_to_this_process(sam_runner::testenv::test_host(HostInfo::probe()));
    host.sockets.wayland = Some(display);

    let logs = || {
        fs::read_dir(app.paths.app_logs_dir(&id))
            .map(|d| d.count())
            .unwrap_or(0)
    };
    let before = logs();
    let rec = run(
        &mut e,
        &LaunchOptions {
            quiet: true,
            args: vec!["org.example.Wanted".into()],
            owd: Some(home.clone()),
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
    assert!(rec.success, "{log}");
    assert!(log.contains("OWN org.example.Wanted=yes"), "{log}");
    assert_eq!(logs(), before + 2, "one first try and one restart");
    assert!(
        rec.missing_layers
            .contains(&"Wayland security context".to_string()),
        "{:?}\n{log}",
        rec.missing_layers
    );
    assert_eq!(
        *TOLD.lock().unwrap(),
        vec![rec.missing_layers.clone()],
        "told once, for the first try"
    );
    drop(services);
}
