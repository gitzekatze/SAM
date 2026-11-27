//! Full home read/write with start files kept through links, as dotfiles
//! managers such as `stow` set them up (`~/.bashrc` a link into
//! `~/dotfiles`), attacked from inside a real sandbox. SAM guards such a
//! file where its link leads. The app tries to rename the folder above
//! that place and to put a start file of its own there, so that the link,
//! which stays as it was, would lead to the app's file at the next shell
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
if mv "$H/dotfiles" "$H/dotfiles-old" 2>/dev/null; then
    echo RENAME=done
    mkdir -p "$H/dotfiles/bash" && echo 'echo pwned' > "$H/dotfiles/bash/bashrc"
else
    echo RENAME=refused
fi
if mv "$H/dotfiles/bash" "$H/dotfiles/bash-old" 2>/dev/null; then
    echo RENAME_INNER=done
    mkdir -p "$H/dotfiles/bash" && echo 'echo pwned' > "$H/dotfiles/bash/bashrc"
else
    echo RENAME_INNER=refused
fi
echo 'echo pwned' > "$H/.bashrc" 2>/dev/null && echo WRITE=done || echo WRITE=refused
cat "$H/.netrc" 2>/dev/null | grep -q SECRET && echo NETRC=read || echo NETRC=hidden
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
fn a_start_file_kept_through_a_link_cannot_be_swapped_by_renaming_its_folder() {
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
    // `~/.bashrc` and `~/.netrc` are links into a dotfiles folder.
    fs::create_dir_all(home.join("dotfiles/bash")).unwrap();
    fs::write(home.join("dotfiles/bash/bashrc"), "echo mine\n").unwrap();
    fs::write(home.join("dotfiles/netrc"), "SECRET token").unwrap();
    std::os::unix::fs::symlink("dotfiles/bash/bashrc", home.join(".bashrc")).unwrap();
    std::os::unix::fs::symlink("dotfiles/netrc", home.join(".netrc")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Swap-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Swap");
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

    // The folders above where the guard lands cannot be renamed away.
    assert_eq!(r["RENAME"], "refused", "{r:?}");
    assert_eq!(r["RENAME_INNER"], "refused", "{r:?}");
    assert_eq!(r["WRITE"], "refused", "{r:?}");
    // The link still leads to the person's own start file, nothing else.
    assert_eq!(
        fs::read_link(home.join(".bashrc")).unwrap(),
        Path::new("dotfiles/bash/bashrc")
    );
    assert_eq!(
        fs::read_to_string(home.join(".bashrc")).unwrap(),
        "echo mine\n",
        "the start file the link leads to is the person's own"
    );
    // The credential file behind its link stays hidden.
    assert_eq!(r["NETRC"], "hidden", "{r:?}");
}
