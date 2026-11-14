//! The sandbox check: it passes for a correct sandbox, and it catches a
//! sandbox that gives the app more than its settings say. Uses a fake
//! `$HOME`. Skipped when Bubblewrap cannot run here or SAM's helper
//! (sam-jail-run) is not on PATH.

use std::fs;

use sam_core::permissions::*;
use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

fn usable() -> bool {
    let host = sam_core::HostInfo::probe();
    host.tools.bwrap.is_some() && sam_runner::doctor::bwrap_functional(&host).is_ok() && sam_runner::find_helper().is_some()
}

/// The sandbox check passes when the settings apply, and catches a setting that does not apply.
#[test]
fn the_sandbox_check_passes_and_catches_mismatches() {
    if !usable() {
        eprintln!("skipping: bubblewrap or sam-jail-run not available");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    fs::create_dir_all(home.join("Documents")).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Check-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Check");
    spec.categories = "Utility;".into();
    build(&img, &spec).unwrap();
    let app = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
    let id = app.add(&img, &AddOptions { launcher: Some(false), ..Default::default() }).unwrap().entry.id;

    // 1. A correct sandbox: nothing fails.
    app.set_permissions(&id, PermissionSet::strict_gui()).unwrap();
    let out = app.verify(&id).unwrap();
    let failed: Vec<_> = out.report.failed().iter().map(|r| format!("{}: {}", r.title, r.observed)).collect();
    assert!(failed.is_empty(), "unexpected failures: {failed:?}");
    assert!(out.report.results.iter().any(|r| r.title == "Documents" && r.ok == Some(true)));
    assert!(out.report.results.iter().any(|r| r.title.contains("home folder") && r.ok == Some(true)));
    assert_eq!(app.resolve(&id).unwrap().last_check.unwrap().failed.len(), 0, "result stored with the app");

    // 2. Documents is "No access", but a raw Bubblewrap argument mounts it
    //    anyway: the check must notice.
    let mut p = PermissionSet::strict_gui();
    let docs = home.join("Documents").display().to_string();
    p.advanced.extra_bwrap_args = vec!["--ro-bind".into(), docs.clone(), docs];
    app.set_permissions(&id, p).unwrap();
    let out = app.verify(&id).unwrap();
    let failed: Vec<String> = out.report.failed().iter().map(|r| r.title.clone()).collect();
    assert!(failed.iter().any(|t| t == "Documents"), "the leaked folder is reported: {failed:?}");
    assert_eq!(app.resolve(&id).unwrap().last_check.unwrap().failed, failed);

    // 2b. This computer only (pasta): the app runs as the user, not root,
    //     so the D-Bus proxy accepts it and every check passes.
    if sam_runner::netns::pasta_usable().is_ok() {
        let mut p = PermissionSet::strict_gui();
        p.network.mode = NetworkMode::Localhost;
        app.set_permissions(&id, p).unwrap();
        let out = app.verify(&id).unwrap();
        let failed: Vec<_> = out.report.failed().iter().map(|r| format!("{}: {}", r.title, r.observed)).collect();
        assert!(failed.is_empty(), "this computer only: {failed:?}");
    }

    // 3. Expectations follow the settings: without the syscall filter the
    //    check expects it off (and finds it off).
    let mut p = PermissionSet::strict_gui();
    p.advanced.seccomp_baseline = false;
    app.set_permissions(&id, p).unwrap();
    let out = app.verify(&id).unwrap();
    let filter = out.report.results.iter().find(|r| r.title == "Syscall filter").unwrap();
    assert_eq!(filter.ok, Some(true), "{}", filter.observed);
    assert_eq!(filter.observed, "not active");
}
