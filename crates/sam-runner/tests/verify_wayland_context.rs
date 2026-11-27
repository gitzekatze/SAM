//! The sandbox check fails when the Wayland security context is missing
//! although the desktop offers it (review of PR 95, B2 R78). SAM makes the
//! context outside the sandbox, so the probe inside sees only that a
//! Wayland socket is there; before, a check whose context the compositor
//! refused passed, while the app got the compositor's own socket with every
//! privileged function. Here the compositor is a stand-in that hangs up. In
//! its own file because it sets `HOME` for the whole test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

#[test]
fn the_sandbox_check_fails_without_the_wayland_security_context() {
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
    let img = root.join("Checked-1.0-x86_64.AppImage");
    build(&img, &FixtureSpec::hello("Checked")).unwrap();
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
    let e = app.set_permissions(&id, p).unwrap();

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

    let out = sam_runner::verify::verify(&e, &app.config, &app.paths, &host).unwrap();
    let item = out
        .report
        .results
        .iter()
        .find(|r| r.id == "wayland-context")
        .unwrap_or_else(|| panic!("the check names the context: {:?}", out.report.results));
    assert_eq!(item.ok, Some(false), "{item:?}");
    assert!(
        out.record.failed.contains(&item.title),
        "a failed check: {:?}",
        out.record.failed
    );
}
