//! SAM's own programs stay out of an app's reach, attacked from inside a
//! real sandbox (security review 2026-11-23, SB-1). Every menu entry SAM
//! writes runs SAM's own AppImage (or its `sam-jail-run`) outside the
//! sandbox, wherever the person keeps it. An app that could replace that
//! file would run its own code unsandboxed at the next click on any menu
//! entry:
//! - SAM's AppImage in a writable Downloads folder can be neither
//!   overwritten, nor renamed or deleted to put another file in its place;
//! - with the whole home writable, the folder holding SAM's AppImage
//!   (`~/Applications`) cannot be renamed away and replaced;
//! - with the home kept behind a link (`/home/u` a link to `/data/u`), the
//!   file is protected where the app sees it.
//!
//! Each case has a control: an ordinary file next to SAM's is written.
//!
//! In its own file because it sets `HOME`, `APPIMAGE` and `APPDIR` for the
//! test process (SAM finds its own AppImage through them).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

const ATTACK: &str = r#"#!/bin/sh
H="$HOME"
D="$H/Downloads"
echo EVIL > "$D/SAM.AppImage" 2>/dev/null
mv "$D/SAM.AppImage" "$D/SAM.old" 2>/dev/null && echo EVIL > "$D/SAM.AppImage" 2>/dev/null
rm -f "$D/SAM.AppImage" 2>/dev/null && echo EVIL > "$D/SAM.AppImage" 2>/dev/null
echo written > "$D/other.txt" 2>/dev/null
A="$H/Applications"
echo EVIL > "$A/SAM.AppImage" 2>/dev/null
mv "$A" "$H/Apps2" 2>/dev/null && mkdir -p "$A" && echo EVIL > "$A/SAM.AppImage" 2>/dev/null
echo written > "$A/other.txt" 2>/dev/null
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
fn an_app_can_never_replace_the_programs_that_menu_entries_run() {
    let host = HostInfo::probe();
    if host.tools.bwrap.is_none() || sam_runner::doctor::bwrap_functional(&host).is_err() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    sam_runner::testenv::isolate_this_process(&root);
    let home = root.join("home/tester");
    for d in ["Downloads", "Applications"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    // This program stands in for SAM started from its AppImage: the
    // AppImage runtime sets these two, with the program inside `APPDIR`.
    let exe = std::env::current_exe().unwrap();
    std::env::set_var("APPDIR", exe.parent().unwrap());
    let sam_file = |at: &Path| {
        fs::write(at, "ORIGINAL SAM").unwrap();
        std::env::set_var("APPIMAGE", at);
        assert_eq!(sam_core::util::own_appimage().as_deref(), Some(at));
    };

    let img = root.join("Attack-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Attack");
    spec.apprun = ATTACK.into();
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
    let start = |p: PermissionSet, home_seen: &Path| {
        let mut e = app.set_permissions(&id, p).unwrap();
        let mut h = sam_runner::testenv::test_host(HostInfo::probe());
        h.home = home_seen.to_path_buf();
        h.xdg_dirs.clear();
        h.xdg_dirs
            .insert("downloads".into(), home_seen.join("Downloads"));
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                owd: Some(home_seen.to_path_buf()),
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &h,
        )
        .unwrap();
        let r = parse(rec.log_file.as_ref().unwrap());
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "the attack ran: {r:?}"
        );
    };
    let read = |p: PathBuf| fs::read_to_string(p).unwrap_or_default();

    // SAM's AppImage in Downloads, and the app may write Downloads.
    let downloads = home.join("Downloads");
    sam_file(&downloads.join("SAM.AppImage"));
    let mut p = PermissionSet::strict_gui();
    p.filesystem.downloads = Access::Rw;
    start(p, &home);
    assert_eq!(
        read(downloads.join("other.txt")),
        "written\n",
        "control: the app could write Downloads"
    );
    assert_eq!(
        read(downloads.join("SAM.AppImage")),
        "ORIGINAL SAM",
        "SAM's AppImage was changed or replaced"
    );
    assert!(
        !downloads.join("SAM.old").exists(),
        "SAM's AppImage was moved"
    );

    // SAM's AppImage in ~/Applications, and the whole home writable.
    let apps = home.join("Applications");
    sam_file(&apps.join("SAM.AppImage"));
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    start(p.clone(), &home);
    assert_eq!(
        read(apps.join("other.txt")),
        "written\n",
        "control: the app could write the home"
    );
    assert_eq!(read(apps.join("SAM.AppImage")), "ORIGINAL SAM");
    assert!(
        !home.join("Apps2").exists(),
        "the folder holding SAM's AppImage was renamed away"
    );

    // The same home reached through a link: the app sees `/…/linked`,
    // SAM's AppImage is named by its real place.
    fs::remove_file(apps.join("other.txt")).unwrap();
    let linked = root.join("home/linked");
    std::os::unix::fs::symlink(&home, &linked).unwrap();
    start(p, &linked);
    assert_eq!(
        read(apps.join("other.txt")),
        "written\n",
        "control: the app could write the home behind the link"
    );
    assert_eq!(
        read(apps.join("SAM.AppImage")),
        "ORIGINAL SAM",
        "SAM's AppImage was changed through the linked home"
    );
    assert!(!home.join("Apps2").exists());
}
