//! Two real launches at once that may both write the whole home, so both
//! watch the same start places. App A plants `~/.bash_profile` again and
//! again while B runs; each planted file must be moved aside and reported
//! exactly once, with the folder it went to, and never as "deleted" or
//! "COULD NOT BE REMOVED" by the other launch's watch. This is the check
//! of the whole way through SAM's launches (the live watches, the start
//! and the last looks); the unit tests of `home_shared`, `home_live` and
//! `put_aside` are the ones that fail without the rule: here the two
//! watches met at the same moment often, but not in every run. Here no
//! launcher is stopped and every look ends well within the wait for a turn
//! (at most about a second, after which a look looks anyway and two looks
//! can overlap), so each file is reported once. In its own file because it
//! sets `HOME` for the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::path::Path;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// How many times A plants the file.
const PLANTS: usize = 20;

/// A: waits (at most 60 s) until B runs, then plants `~/.bash_profile`
/// with a text of its own each time, and waits (at most 5 s) until a watch
/// has taken it away before the next.
const PLANTS_SCRIPT: &str = r#"#!/bin/sh
n=0
while [ ! -e "$HOME/b-runs" ] && [ $n -lt 600 ]; do sleep 0.1; n=$((n+1)); done
i=1
while [ $i -le 20 ]; do
  echo "plant $i" > "$HOME/.bash_profile"
  n=0
  while [ -e "$HOME/.bash_profile" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n+1)); done
  i=$((i+1))
done
touch "$HOME/a-done"
echo END=1
"#;

/// B: says it runs (its live watch is up by then), then waits (at most
/// 120 s) until A is done.
const WAITS_SCRIPT: &str = r#"#!/bin/sh
touch "$HOME/b-runs"
n=0
while [ ! -e "$HOME/a-done" ] && [ $n -lt 1200 ]; do sleep 0.1; n=$((n+1)); done
echo END=1
"#;

/// Every file below `dir`, read as text.
fn texts_below(dir: &Path, out: &mut Vec<String>) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        let m = fs::symlink_metadata(&p).unwrap();
        if m.is_dir() {
            texts_below(&p, out);
        } else {
            out.push(fs::read_to_string(&p).unwrap().trim().to_string());
        }
    }
}

#[test]
fn two_real_launches_report_each_planted_file_once() {
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
    let add = |name: &str, script: &str| {
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
        let mut whole = PermissionSet::strict_gui();
        whole.filesystem.home = true;
        whole.filesystem.home_access = Access::Rw;
        sam.set_permissions(&id, whole).unwrap()
    };
    let mut a = add("Plants", PLANTS_SCRIPT);
    let mut b = add("Waits", WAITS_SCRIPT);
    let opts = LaunchOptions {
        quiet: true,
        owd: Some(home.clone()),
        ..Default::default()
    };
    let test_host = sam_runner::testenv::test_host(HostInfo::probe());

    let (rec_a, rec_b) = std::thread::scope(|s| {
        let first = s.spawn(|| run(&mut a, &opts, &sam.config, &sam.paths, &test_host));
        let second = s.spawn(|| run(&mut b, &opts, &sam.config, &sam.paths, &test_host));
        (
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        )
    });
    let log = |rec: &sam_core::model::LaunchRecord| {
        fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap()
    };
    let (log_a, log_b) = (log(&rec_a), log(&rec_b));
    eprintln!(
        "A: {log_a}\nB: {log_b}\nMOVED A: {:?} B: {:?}",
        rec_a.moved_aside, rec_b.moved_aside
    );
    assert!(log_a.contains("END=1"), "A ran to its end: {log_a}");
    assert!(log_b.contains("END=1"), "B ran to its end: {log_b}");
    assert!(home.join("a-done").exists(), "A planted every file");

    // Exactly one report per planted file, each a move into SAM's folder.
    let all: Vec<&String> = rec_a
        .moved_aside
        .iter()
        .chain(rec_b.moved_aside.iter())
        .collect();
    for m in &all {
        assert!(
            !m.contains("deleted") && !m.contains("COULD NOT BE REMOVED"),
            "a false report: {m}"
        );
        assert!(m.starts_with("~/.bash_profile → "), "{m}");
    }
    assert_eq!(all.len(), PLANTS, "{all:?}");
    // Every planted file is in SAM's folder, none lost or written over.
    let mut texts = Vec::new();
    texts_below(&paths.data_dir.join("moved-aside"), &mut texts);
    texts.sort_by_key(|t| {
        t.strip_prefix("plant ")
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(usize::MAX)
    });
    let want: Vec<String> = (1..=PLANTS).map(|i| format!("plant {i}")).collect();
    assert_eq!(texts, want);
    assert!(fs::symlink_metadata(home.join(".bash_profile")).is_err());
}
