//! An app gets the bus name it really asks for, learned from the D-Bus
//! filter's record, when nobody on this computer uses it; never one that
//! belongs to an installed app or that another program holds now (owner
//! decision of 2026-11-18, option D; night run N1: four apps did not start
//! without their name; audit D-M6: a terminal's name runs host commands).
//! From inside a real sandbox, on a private session bus:
//! - a new name: refused at the first try, learned, and the app started
//!   once more by SAM, which then runs; the next start has it at once;
//! - an installed app's name and a name in use: refused, not learned, no
//!   restart;
//! - an app that runs on without its name gets it for the next start and
//!   is not started again;
//! - an app that fails with its name too is restarted only once.
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

/// Asks for each name it is given; without the first one it ends with an
/// error (as GApplication does), unless "soft" follows (it runs on without
/// its name, as many apps do); with "fail" as the last word it fails
/// anyway.
const APP: &str = r#"#!/bin/sh
for n in "$@"; do
  [ "$n" = fail ] || [ "$n" = soft ] && continue
  if gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
       --method org.freedesktop.DBus.RequestName "$n" 4 2>/dev/null | grep -q '(uint32 1,)'; then
    echo "OWN $n=yes"
  else
    echo "OWN $n=no"
    [ "$n" = "$1" ] && [ "$2" != soft ] && exit 1
  fi
done
for n in "$@"; do [ "$n" = fail ] && exit 1; done
echo END=1
"#;

#[test]
fn an_app_gets_the_name_it_asks_for_only_when_nobody_uses_it() {
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
    let Some(bus) = services.bus_address().map(String::from) else {
        sam_runner::contracts::skip("dbus-daemon is not installed")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    };
    let home = root.join("home/tester");
    // An installed app whose name an app must never take.
    let apps = home.join(".local/share/applications");
    fs::create_dir_all(&apps).unwrap();
    fs::write(
        apps.join("org.example.Installed.desktop"),
        "[Desktop Entry]\n",
    )
    .unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    // A name another program holds right now.
    let _busy =
        sam_runner::dbus_check::own_name(&bus, "org.example.Busy", Duration::from_secs(5)).unwrap();

    let img = root.join("Names-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Names");
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
    p.dbus.session.own.clear();
    app.set_permissions(&id, p).unwrap();
    let host = services.apply_to_this_process(sam_runner::testenv::test_host(HostInfo::probe()));
    let logs = || {
        fs::read_dir(app.paths.app_logs_dir(&id))
            .map(|d| d.count())
            .unwrap_or(0)
    };
    let start = |args: &[&str]| {
        let mut e = app.registry().get(&id).unwrap().unwrap();
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                args: args.iter().map(|a| a.to_string()).collect(),
                owd: Some(home.clone()),
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &host,
        )
        .unwrap();
        let log = fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap();
        (rec, log)
    };
    let own = || {
        app.registry()
            .get(&id)
            .unwrap()
            .unwrap()
            .profile
            .permissions
            .dbus
            .session
            .own
    };

    // A new name: refused, learned, one restart that runs.
    let before = logs();
    let (rec, log) = start(&["org.example.Wanted"]);
    assert!(rec.success, "{log}");
    assert!(log.contains("OWN org.example.Wanted=yes"), "{log}");
    assert_eq!(logs(), before + 2, "one first try and one restart");
    assert!(own().contains(&"org.example.Wanted".to_string()));
    // The next start has it at once.
    let before = logs();
    let (rec, log) = start(&["org.example.Wanted"]);
    assert!(
        rec.success && log.contains("OWN org.example.Wanted=yes"),
        "{log}"
    );
    assert_eq!(logs(), before + 1);

    // An installed app's name and a name in use: refused, no restart.
    for name in ["org.example.Installed", "org.example.Busy"] {
        let before = logs();
        let (rec, log) = start(&[name]);
        assert!(!rec.success, "{log}");
        assert!(log.contains(&format!("OWN {name}=no")), "{log}");
        assert!(
            rec.refused_names.iter().any(|r| r.starts_with(name)),
            "{rec:?}"
        );
        assert!(!own().contains(&name.to_string()));
        assert_eq!(logs(), before + 1, "no restart");
    }

    // A desktop protocol name and a name that would intercept the desktop
    // (the shell): refused even though nobody holds them on this private
    // bus, never learned, no restart (verification audit 2026-11-19: only
    // unit tests showed these refusals).
    for name in ["org.freedesktop.Notifications", "org.gnome.Shell"] {
        let before = logs();
        let (rec, log) = start(&[name]);
        assert!(!rec.success, "{log}");
        assert!(log.contains(&format!("OWN {name}=no")), "{log}");
        assert!(!own().contains(&name.to_string()), "{name} was learned");
        assert_eq!(logs(), before + 1, "no restart for {name}");
    }
    // Written into the settings by hand, they are still not handed to the
    // app: the D-Bus filter leaves them out.
    let mut p = app
        .registry()
        .get(&id)
        .unwrap()
        .unwrap()
        .profile
        .permissions;
    p.dbus.session.own = vec![
        "org.freedesktop.Notifications".into(),
        "org.gnome.Shell".into(),
    ];
    app.set_permissions(&id, p).unwrap();
    for name in ["org.freedesktop.Notifications", "org.gnome.Shell"] {
        let (_, log) = start(&[name]);
        assert!(log.contains(&format!("OWN {name}=no")), "{log}");
    }
    let mut p = app
        .registry()
        .get(&id)
        .unwrap()
        .unwrap()
        .profile
        .permissions;
    p.dbus.session.own.clear();
    app.set_permissions(&id, p).unwrap();

    // An app that runs on without its name gets it for the next start and
    // is not started again (night run: 21 apps ran without theirs).
    let before = logs();
    let (rec, log) = start(&["org.example.Soft", "soft"]);
    assert!(rec.success, "{log}");
    assert_eq!(rec.learned_names, ["org.example.Soft"]);
    assert_eq!(logs(), before + 1, "no restart after a start that ran");
    assert!(own().contains(&"org.example.Soft".to_string()));

    // An app that fails with its name too is restarted once only.
    let before = logs();
    let (rec, _) = start(&["org.example.Twice", "fail"]);
    assert!(!rec.success);
    assert_eq!(logs(), before + 2);
    drop(services);
}
