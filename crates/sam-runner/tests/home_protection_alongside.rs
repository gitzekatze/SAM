//! Two real launches at once (review B2 R52). App A may write `~/.config`
//! only and sees `~/.local/bin` missing at its start, so its watch keeps
//! that place empty. App B may write the whole home and starts while A
//! runs. SAM must not make `~/.local/bin` for B: A's watch, and B's, which
//! takes A's over, would move that empty folder aside at once, and B's
//! record would tell the person of something moved aside that no app had
//! made. In its own file because it sets `HOME` for the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// A: says it runs, then waits (at most 60 s) until B has run.
const WAITS: &str = r#"#!/bin/sh
touch "$HOME/.config/a-runs"
n=0
while [ ! -e "$HOME/.config/b-ran" ] && [ $n -lt 600 ]; do sleep 0.1; n=$((n+1)); done
echo END=1
"#;

/// B: says what it sees, then lets A end.
const LOOKS: &str = r#"#!/bin/sh
[ -e "$HOME/.local/bin" ] && echo BIN=there || echo BIN=missing
touch "$HOME/.config/b-ran"
echo END=1
"#;

#[test]
fn a_launch_alongside_another_reports_nothing_it_did_not_find() {
    let host = HostInfo::probe();
    if host.tools.bwrap.is_none() || sam_runner::doctor::bwrap_functional(&host).is_err() {
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
    fs::create_dir_all(home.join(".config")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let paths = Paths::rooted(&root.join("sam"));
    let sam = Sam::with_paths(paths.clone()).unwrap();
    let add = |name: &str, script: &str, p: PermissionSet| {
        let img = root.join(format!("{name}-1.0-x86_64.AppImage"));
        let mut spec = FixtureSpec::hello(name);
        spec.apprun = script.into();
        build(&img, &spec).unwrap();
        let id = sam
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
        sam.set_permissions(&id, p).unwrap()
    };
    let mut narrow = PermissionSet::strict_gui();
    narrow.filesystem.custom_write = vec![home.join(".config").to_string_lossy().into()];
    let mut whole = PermissionSet::strict_gui();
    whole.filesystem.home = true;
    whole.filesystem.home_access = Access::Rw;
    let mut a = add("Waits", WAITS, narrow);
    let mut b = add("Looks", LOOKS, whole);
    let opts = LaunchOptions {
        quiet: true,
        owd: Some(home.clone()),
        ..Default::default()
    };
    let test_host = sam_runner::testenv::test_host(HostInfo::probe());

    let (rec_a, rec_b) = std::thread::scope(|s| {
        let first = s.spawn(|| run(&mut a, &opts, &sam.config, &sam.paths, &test_host));
        let start = Instant::now();
        while !home.join(".config/a-runs").exists() {
            assert!(start.elapsed() < Duration::from_secs(60), "A never started");
            std::thread::sleep(Duration::from_millis(50));
        }
        let rec_b = run(&mut b, &opts, &sam.config, &sam.paths, &test_host).unwrap();
        (first.join().unwrap().unwrap(), rec_b)
    });
    let ended = |log: &Path| fs::read_to_string(log).unwrap().contains("END=1");
    assert!(ended(rec_a.log_file.as_ref().unwrap()), "A ran to its end");
    let log_b = fs::read_to_string(rec_b.log_file.as_ref().unwrap()).unwrap();
    assert!(log_b.contains("END=1"), "B ran to its end: {log_b}");
    eprintln!(
        "B: {log_b}\nMOVED A: {:?} B: {:?}",
        rec_a.moved_aside, rec_b.moved_aside
    );

    // Nothing was made where A watches an empty place, so nothing moved.
    assert!(log_b.contains("BIN=missing"), "{log_b}");
    assert!(rec_b.moved_aside.is_empty(), "B: {:?}", rec_b.moved_aside);
    assert!(rec_a.moved_aside.is_empty(), "A: {:?}", rec_a.moved_aside);
    assert!(fs::symlink_metadata(home.join(".local/bin")).is_err());
}
