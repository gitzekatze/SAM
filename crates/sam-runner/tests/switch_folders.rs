//! The folders an installed SAM once kept through `SAM_DATA_DIR` or
//! `SAM_CONFIG_DIR` stay hidden, attacked from inside a real sandbox (batch
//! review of the change that made release builds ignore these switches):
//! - SAM keeps its own elsewhere, as a release build does with the
//!   switches set, and `SAM_DATA_DIR=~/Games/sam`: an app granted `~/Games`
//!   read and write, or the whole home, cannot read the other apps'
//!   private homes and the app records there, nor plant a record there,
//!   and `SAM_CONFIG_DIR=~/Configs/sam` hides the settings there from a
//!   grant of `~/Configs`;
//! - a switch naming the home or `/` would cover too much: nothing covers
//!   the home, which the app still reads and writes as granted, while the
//!   home's protections and SAM's folders by name (`~/.local/share/sam`)
//!   hold as before.
//!
//! Controls show the attack would have been seen: the rest of `~/Games`
//! is read and written.
//!
//! In its own file because it sets `HOME` and the switches for the test
//! process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

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
grep -q SECRET "$H/Games/sam/homes/x/secret" 2>/dev/null && echo OLD_HOME=read || echo OLD_HOME=hidden
grep -q RECORD "$H/Games/sam/apps/x.json" 2>/dev/null && echo OLD_RECORD=read || echo OLD_RECORD=hidden
mkdir -p "$H/Games/sam/apps" 2>/dev/null && echo planted > "$H/Games/sam/apps/planted.json" 2>/dev/null
grep -q OLDCFG "$H/Configs/sam/config.toml" 2>/dev/null && echo OLD_CONFIG=read || echo OLD_CONFIG=hidden
grep -q NOTE "$H/Games/note.txt" 2>/dev/null && echo GAMES_NOTE=read || echo GAMES_NOTE=hidden
echo x > "$H/Games/ok.txt" 2>/dev/null && echo GAMES_WRITE=written || echo GAMES_WRITE=refused
grep -q HOMENOTE "$H/note.txt" 2>/dev/null && echo HOME_NOTE=read || echo HOME_NOTE=hidden
echo x > "$H/ok.txt" 2>/dev/null && echo HOME_WRITE=written || echo HOME_WRITE=refused
cat "$H/.ssh/id_ed25519" 2>/dev/null | grep -q SECRET && echo KEY=read || echo KEY=hidden
echo x > "$H/.config/autostart/evil.desktop" 2>/dev/null && echo AUTOSTART=written || echo AUTOSTART=refused
grep -q BYNAME "$H/.local/share/sam/apps.toml" 2>/dev/null && echo BY_NAME=read || echo BY_NAME=hidden
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
fn an_old_switch_folder_stays_hidden_from_a_real_sandbox() {
    let host = HostInfo::probe();
    if host.tools.bwrap.is_none() || sam_runner::doctor::bwrap_functional(&host).is_err() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    for d in [
        "Games/sam/homes/x",
        "Games/sam/apps",
        "Configs/sam",
        ".ssh",
        ".config/autostart",
        ".local/share/sam",
    ] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    fs::write(home.join("Games/sam/homes/x/secret"), "SECRET").unwrap();
    fs::write(home.join("Games/sam/apps/x.json"), "RECORD").unwrap();
    fs::write(home.join("Configs/sam/config.toml"), "OLDCFG").unwrap();
    fs::write(home.join("Games/note.txt"), "NOTE").unwrap();
    fs::write(home.join("note.txt"), "HOMENOTE").unwrap();
    fs::write(home.join(".ssh/id_ed25519"), "SECRET KEY").unwrap();
    fs::write(home.join(".local/share/sam/apps.toml"), "BYNAME").unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Switch-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Switch");
    spec.apprun = ATTACK.into();
    build(&img, &spec).unwrap();
    // SAM keeps its own elsewhere, as a release build does while the
    // switches name other folders: they are never where it keeps its own.
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
    let start = |p: PermissionSet| {
        let mut e = app.set_permissions(&id, p).unwrap();
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                owd: Some(home.clone()),
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &sam_runner::testenv::test_host(HostInfo::probe()),
        )
        .unwrap();
        let r = parse(rec.log_file.as_ref().unwrap());
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "the attack ran: {r:?}"
        );
        for f in ["Games/ok.txt", "ok.txt"] {
            let _ = fs::remove_file(home.join(f));
        }
        r
    };
    let games_rw = || {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec!["~/Games".into()];
        p.filesystem.custom_read = vec!["~/Configs".into()];
        p
    };
    let whole_home_rw = || {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        p
    };

    // The old folders, with `~/Games` and `~/Configs` granted and with the
    // whole home: hidden, while the rest of `~/Games` is shown as granted.
    std::env::set_var("SAM_DATA_DIR", home.join("Games/sam"));
    std::env::set_var("SAM_CONFIG_DIR", home.join("Configs/sam"));
    for (what, p) in [("~/Games", games_rw()), ("whole home", whole_home_rw())] {
        let r = start(p);
        assert_eq!(r["OLD_HOME"], "hidden", "{what}: {r:?}");
        assert_eq!(r["OLD_RECORD"], "hidden", "{what}: {r:?}");
        assert_eq!(r["OLD_CONFIG"], "hidden", "{what}: {r:?}");
        assert!(
            !home.join("Games/sam/apps/planted.json").exists(),
            "{what}: a record was planted in the old folder"
        );
        assert_eq!(r["GAMES_NOTE"], "read", "control, {what}: {r:?}");
        assert_eq!(r["GAMES_WRITE"], "written", "control, {what}: {r:?}");
        assert!(home.join("Games/sam/homes/x/secret").is_file(), "{what}");
    }

    // A switch naming the home or `/` would cover too much: nothing covers
    // the home, which the app reads and writes as granted; the home's
    // protections and SAM's folders by name hold as before.
    for dir in [home.clone(), "/".into()] {
        std::env::set_var("SAM_DATA_DIR", &dir);
        std::env::set_var("SAM_CONFIG_DIR", &dir);
        let r = start(whole_home_rw());
        let at = dir.display();
        assert_eq!(r["HOME_NOTE"], "read", "{at}: {r:?}");
        assert_eq!(r["HOME_WRITE"], "written", "{at}: {r:?}");
        assert_eq!(r["GAMES_NOTE"], "read", "{at}: {r:?}");
        assert_eq!(r["KEY"], "hidden", "{at}: {r:?}");
        assert_eq!(r["AUTOSTART"], "refused", "{at}: {r:?}");
        assert!(
            !home.join(".config/autostart/evil.desktop").exists(),
            "{at}"
        );
        assert_eq!(r["BY_NAME"], "hidden", "{at}: {r:?}");
    }
    std::env::remove_var("SAM_DATA_DIR");
    std::env::remove_var("SAM_CONFIG_DIR");
}
