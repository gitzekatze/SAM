//! A bus name the person put on the always-blocked list stays blocked from
//! inside a real sandbox, also when another setting allows it: here the
//! app's own list of names it may own, and a wildcard that covers it. The
//! app asks for each name on a private session bus; it gets only the names
//! nobody blocked, and SAM never learns a blocked name it asked for
//! (review of PR 95, 2026-11-24: the blocked list held only for talking,
//! and only for exact names).
//!
//! In its own file because it sets `HOME` and the session bus.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;

use sam_core::permissions::{DbusMode, PermissionSet};
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// Asks for each name it is given and says whether it got it.
const APP: &str = r#"#!/bin/sh
for n in "$@"; do
  if gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
       --method org.freedesktop.DBus.RequestName "$n" 4 2>/dev/null | grep -q '(uint32 1,)'; then
    echo "OWN $n=yes"
  else
    echo "OWN $n=no"
  fi
done
echo END=1
"#;

#[test]
fn an_always_blocked_name_cannot_be_owned_from_inside_the_sandbox() {
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
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Blocked-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Blocked");
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
    p.dbus.session.mode = DbusMode::Filtered;
    p.dbus.session.own = vec![
        "org.example.Blocked".into(),
        "org.example.Covered".into(),
        "org.example.Open".into(),
    ];
    p.dbus.session.deny = vec!["org.example.Blocked".into(), "org.example.Covered*".into()];
    app.set_permissions(&id, p).unwrap();
    let host = services.apply_to_this_process(sam_runner::testenv::test_host(HostInfo::probe()));

    let mut e = app.registry().get(&id).unwrap().unwrap();
    let names = [
        "org.example.Open",
        "org.example.Blocked",
        "org.example.Covered",
        "org.example.CoveredToo",
    ];
    let rec = run(
        &mut e,
        &LaunchOptions {
            quiet: true,
            args: names.iter().map(|a| a.to_string()).collect(),
            owd: Some(home.clone()),
            ..Default::default()
        },
        &app.config,
        &app.paths,
        &host,
    )
    .unwrap();
    let log = fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap();
    assert!(log.contains("END=1"), "the app ran: {log}");
    assert!(
        log.contains("OWN org.example.Open=yes"),
        "a name nobody blocked: {log}"
    );
    for blocked in &names[1..] {
        assert!(
            log.contains(&format!("OWN {blocked}=no"))
                && !log.contains(&format!("OWN {blocked}=yes")),
            "{blocked} is blocked: {log}"
        );
    }
    // Asked for, but never learned: it stays out of the app's list.
    let own = app
        .registry()
        .get(&id)
        .unwrap()
        .unwrap()
        .profile
        .permissions
        .dbus
        .session
        .own;
    assert!(
        !own.iter().any(|n| n == "org.example.CoveredToo"),
        "{own:?}"
    );
    assert!(rec.learned_names.is_empty(), "{:?}", rec.learned_names);
    assert!(
        rec.refused_names
            .iter()
            .any(|r| r.starts_with("org.example.CoveredToo:") && r.contains("always blocked")),
        "told why: {:?}",
        rec.refused_names
    );
}
