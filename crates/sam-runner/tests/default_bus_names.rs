//! The desktop services every app may use by default reach only their own
//! objects from inside a real sandbox, also through the unique name of the
//! program behind them (review of PR 95, B2 R76, 2026-11-25).
//!
//! xdg-dbus-proxy gives a program's unique name (`:1.10`) the rules of
//! every name it owns, and a plain `--talk` lets every call through. On KDE
//! Plasma 6 the program behind the notification service, plasmashell, also
//! holds Klipper (the clipboard history) and the shell's script runner. Here
//! a stand-in holds the notification service and the tray watcher on a
//! private session bus; the app calls the service's own object and an
//! object of another service of the same program, by name and by unique
//! name. The proxy refuses at once what it does not pass (`AccessDenied`);
//! what it passes reaches the stand-in, which never answers (`NoReply`).
//! Any other answer (a name the filter hides: `NameHasNoOwner`) is neither
//! and fails the test.
//!
//! In its own file because it sets `HOME` and the session bus.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;
use std::time::Duration;

use sam_core::permissions::{DbusMode, PermissionSet};
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// For each service (`name path`): finds the program's unique name, then
/// calls the service's own object and another object of the program, by
/// name and by unique name, and says whether the filter refused the call.
const APP: &str = r#"#!/bin/sh
try() { # label dest path method
  out=$(dbus-send --session --print-reply --reply-timeout=2000 --dest="$2" "$3" "$4" 2>&1)
  case "$out" in
    *org.freedesktop.DBus.Error.AccessDenied*) echo "CALL $1=refused" ;;
    *org.freedesktop.DBus.Error.NoReply*) echo "CALL $1=passed" ;;
    *) echo "CALL $1=other: $out" | tr '\n' ' '; echo ;;
  esac
}
while [ $# -ge 3 ]; do
  name=$1 own=$2 other=$3
  shift 3
  owner=$(dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.GetNameOwner string:"$name" 2>&1 | sed -n 's/^ *string "\(:[0-9.]*\)"$/\1/p')
  echo "OWNER $name=${owner:-none}"
  try "$name own" "$name" "$own" org.example.Own.Ping
  try "$name other" "$name" "$other" org.kde.klipper.klipper.getClipboardContents
  if [ -n "$owner" ]; then
    try "$name own by unique name" "$owner" "$own" org.example.Own.Ping
    try "$name other by unique name" "$owner" "$other" org.kde.klipper.klipper.getClipboardContents
  fi
done
echo END=1
"#;

#[test]
fn default_desktop_services_reach_only_their_own_objects() {
    let host = HostInfo::probe();
    let ready = host.tools.bwrap.is_some()
        && sam_runner::doctor::bwrap_functional(&host).is_ok()
        && host.tools.xdg_dbus_proxy.is_some()
        && sam_core::util::which("dbus-send").is_some();
    if !ready {
        sam_runner::contracts::skip("bubblewrap, xdg-dbus-proxy or dbus-send is not available")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let services = sam_runner::testenv::PrivateServices::start(root);
    let Some(bus) = services.bus_address().map(str::to_string) else {
        sam_runner::contracts::skip("dbus-daemon is not installed")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    };
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    // The stand-ins: each holds one service SAM allows by default and
    // never answers, so a call the filter passes ends without a reply.
    let services_checked = [
        (
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
        ),
        ("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher"),
    ];
    let _standins: Vec<_> = services_checked
        .iter()
        .map(|(name, _)| {
            sam_runner::dbus_check::own_name(&bus, name, Duration::from_secs(5)).unwrap()
        })
        .collect();

    let img = root.join("Services-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Services");
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
    // The default bus settings: only the mode is spelled out.
    let mut p = PermissionSet::strict_gui();
    p.dbus.session.mode = DbusMode::Filtered;
    assert!(
        services_checked
            .iter()
            .all(|(n, _)| p.dbus.session.allow.iter().any(|a| a == n)),
        "both are allowed by default: {:?}",
        p.dbus.session.allow
    );
    app.set_permissions(&id, p).unwrap();
    let host = services.apply_to_this_process(sam_runner::testenv::test_host(HostInfo::probe()));

    let mut e = app.registry().get(&id).unwrap().unwrap();
    let args: Vec<String> = services_checked
        .iter()
        .flat_map(|(name, own)| [name.to_string(), own.to_string(), "/klipper".to_string()])
        .collect();
    let rec = run(
        &mut e,
        &LaunchOptions {
            quiet: true,
            args,
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
        !log.contains("=other: "),
        "every call passed or was refused: {log}"
    );
    for (name, _) in services_checked {
        assert!(
            !log.contains(&format!("OWNER {name}=none")),
            "the app sees who holds {name}: {log}"
        );
        // The service itself still works, also through the unique name.
        for how in ["own", "own by unique name"] {
            assert!(
                log.contains(&format!("CALL {name} {how}=passed")),
                "{name} {how}: {log}"
            );
        }
        // Another object of the same program does not, by either name.
        for how in ["other", "other by unique name"] {
            assert!(
                log.contains(&format!("CALL {name} {how}=refused")),
                "{name} {how}: {log}"
            );
        }
    }
}
