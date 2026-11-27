//! Full home read/write with start files kept through links, attacked from
//! inside a real sandbox. `~/.profile` leads through a second link
//! (`~/cfg`) to the real file, and `~/.zshrc` leads to a place that does
//! not exist yet. The app replaces the second link with a folder of its
//! own and creates the missing place, so that the protected links, which
//! stay as they were, would lead to the app's files at the next shell
//! outside the sandbox. In its own file because it sets `HOME` for the
//! test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

const ATTACK: &str = r#"#!/bin/sh
H="$HOME"
if rm "$H/cfg" 2>/dev/null && mkdir "$H/cfg" && echo 'echo pwned' > "$H/cfg/profile"; then
    echo LINK=replaced
else
    echo LINK=refused
fi
if mkdir "$H/.dotfiles" 2>/dev/null && echo 'echo pwned' > "$H/.dotfiles/zshrc"; then
    echo TARGET=created
else
    echo TARGET=refused
fi
# While the app still runs, both are taken away again.
sleep 1
grep -q pwned "$H/.profile" 2>/dev/null && echo PROFILE_LIVE=app || echo PROFILE_LIVE=own
[ -e "$H/.zshrc" ] && echo ZSHRC_LIVE=app || echo ZSHRC_LIVE=gone
echo END=1
"#;

fn parse(log: &Path) -> HashMap<String, String> {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn a_start_file_reached_through_more_links_or_a_missing_place_cannot_be_planted() {
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
    // `~/.profile` leads through `~/cfg` to the real file; `~/.zshrc`
    // leads to a place that does not exist.
    fs::create_dir_all(home.join("store/cfg")).unwrap();
    fs::write(home.join("store/cfg/profile"), "echo mine\n").unwrap();
    std::os::unix::fs::symlink("cfg/profile", home.join(".profile")).unwrap();
    std::os::unix::fs::symlink("store/cfg", home.join("cfg")).unwrap();
    std::os::unix::fs::symlink(".dotfiles/zshrc", home.join(".zshrc")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Plant-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Plant");
    spec.apprun = ATTACK.into();
    build(&img, &spec).unwrap();
    let paths = Paths::rooted(&root.join("sam"));
    let app = Sam::with_paths(paths.clone()).unwrap();
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
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    let mut e = app.set_permissions(&id, p).unwrap();
    let opts = LaunchOptions {
        quiet: true,
        owd: Some(home.clone()),
        ..Default::default()
    };
    let rec = run(
        &mut e,
        &opts,
        &app.config,
        &app.paths,
        &sam_runner::testenv::test_host(HostInfo::probe()),
    )
    .unwrap();
    let r = parse(rec.log_file.as_ref().unwrap());
    eprintln!("ATTACK RESULTS: {r:?} MOVED: {:?}", rec.moved_aside);
    assert_eq!(
        r.get("END").map(String::as_str),
        Some("1"),
        "the attack ran: {r:?}"
    );

    // Whatever the app could do, the protected names lead where they led
    // before, both after the start and already while the app runs.
    assert_eq!(
        fs::read_to_string(home.join(".profile")).unwrap(),
        "echo mine\n",
        "{r:?}"
    );
    assert_eq!(
        fs::read_link(home.join("cfg")).unwrap(),
        Path::new("store/cfg")
    );
    assert!(!home.join(".zshrc").exists(), "{r:?}");
    assert_eq!(r["PROFILE_LIVE"], "own", "{r:?}");
    assert_eq!(r["ZSHRC_LIVE"], "gone", "{r:?}");
    let moved = rec.moved_aside.join("\n");
    if r["LINK"] == "replaced" {
        assert!(moved.contains("~/cfg"), "{moved}");
    }
    if r["TARGET"] == "created" {
        assert!(moved.contains("~/.dotfiles"), "{moved}");
    }
}
