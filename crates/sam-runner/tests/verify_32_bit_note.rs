//! The sandbox check of a 32-bit app says that its socket limit is
//! incomplete. Its filter has a 32-bit part with one gap, as
//! in Flatpak: the old socketcall call. The test program inside the
//! sandbox makes only 64-bit calls, so it cannot try the gap; SAM adds the
//! note outside the sandbox, neither passed nor failed, under the probe's
//! last heading (Security). Here a real sandbox runs with the filter and
//! its 32-bit part loaded. In its own file because it sets `HOME` for the
//! whole test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

/// A real sandbox check of a 32-bit app adds the socket note under
/// Security and counts it as a note, not as not applicable; a 64-bit app
/// gets no note. The filter's 32-bit part exists only on x86-64.
#[cfg(target_arch = "x86_64")]
#[test]
fn the_sandbox_check_of_a_32_bit_app_says_its_socket_limit_is_incomplete() {
    use std::fs;

    use sam_core::permissions::PermissionSet;
    use sam_core::{HostInfo, Paths};
    use sam_intake::testkit::{build, FixtureSpec};
    use sam_runner::ops::{AddOptions, Sam};

    let probe = HostInfo::probe();
    if !(probe.tools.bwrap.is_some()
        && sam_runner::doctor::bwrap_functional(&probe).is_ok()
        && sam_runner::find_helper().is_some())
    {
        sam_runner::contracts::skip("bubblewrap or sam-jail-run not available")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "kernel-seccomp"])
        .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    let img = root.join("Old-1.0-x86_64.AppImage");
    build(&img, &FixtureSpec::hello("Old")).unwrap();
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
    let mut e = app
        .set_permissions(&id, PermissionSet::strict_gui())
        .unwrap();
    let host = sam_runner::testenv::test_host(HostInfo::probe());

    // The start program as the detection report of a 32-bit AppImage
    // names it: the filter gets its 32-bit part.
    let mut report = e.detection.clone().unwrap_or_default();
    report.arch = "i686".into();
    report.entry_is_script = false;
    report.entry_binary = report.entry_binary.or_else(|| Some("usr/bin/old".into()));
    e.detection = Some(report);
    let out = sam_runner::verify::verify(&e, &app.config, &app.paths, &host).unwrap();
    let results = &out.report.results;
    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    let at = ids
        .iter()
        .position(|id| *id == "seccomp-32-bit-sockets")
        .unwrap_or_else(|| panic!("the check names the socket limit: {ids:?}"));
    let note = &results[at];
    assert_eq!(note.ok, None, "neither passed nor failed: {note:?}");
    assert!(
        at > 0 && ids[at - 1] == "userns",
        "the note follows the last Security check: {ids:?}"
    );
    let groups: Vec<&str> = results.iter().map(|r| r.group.as_str()).collect();
    let mut runs = groups.clone();
    runs.dedup();
    let mut once = runs.clone();
    once.sort_unstable();
    once.dedup();
    assert_eq!(
        runs.len(),
        once.len(),
        "a heading appears twice: {groups:?}"
    );
    let filter = results
        .iter()
        .find(|r| r.id == "seccomp")
        .unwrap_or_else(|| panic!("the check has the filter: {ids:?}"));
    assert_eq!(
        filter.ok,
        Some(true),
        "the filter with its 32-bit part runs: {filter:?}"
    );
    assert!(
        out.record.failed.is_empty(),
        "nothing failed: {:?}",
        out.record.failed
    );
    // The record counts the note as a note, not as a check that could not
    // run ("not applicable" in `sam-jail verify`).
    let count = |f: &dyn Fn(&sam_runner::probe::ProbeResult) -> bool| {
        results.iter().filter(|r| f(r)).count()
    };
    assert_eq!(
        (
            out.record.passed,
            out.record.failed.len(),
            out.record.skipped,
            out.record.notes
        ),
        (
            count(&|r| r.ok == Some(true)),
            0,
            count(&|r| r.ok.is_none()) - 1,
            1
        ),
        "passed, failed, not applicable, notes: {:?}",
        out.record
    );

    // A 64-bit start program: no note.
    if let Some(d) = e.detection.as_mut() {
        d.arch = "x86_64".into();
    }
    let out = sam_runner::verify::verify(&e, &app.config, &app.paths, &host).unwrap();
    assert!(
        !out.report
            .results
            .iter()
            .any(|r| r.id == "seccomp-32-bit-sockets"),
        "a 64-bit app: {:?}",
        out.report.results
    );
    assert_eq!(out.record.notes, 0, "a 64-bit app: {:?}", out.record);
}
