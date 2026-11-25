//! The home protections hold whatever else is granted, attacked from inside
//! a real sandbox (audit S-F2, S-F3, S-F4; night run 2026-11-18):
//! - full home plus a grant of the folder above it (`/home`): keys stay
//!   hidden and autostart read-only (the grant used to cover them);
//! - write access to `~/.local`: `~/.local/share` cannot be renamed away to
//!   plant records where SAM keeps its own;
//! - a granted link to `~/.local`: SAM's folders stay hidden through it;
//! - a private home has the folders every home has;
//! - with the whole home writable, the file that says where Documents and
//!   the other user folders are (`~/.config/user-dirs.dirs`) stays
//!   read-only: rewritten, it could point the person's file dialogs at a
//!   folder the app chose (threat model row 44).
//! - a writable extra folder inside a start place (`~/.config/fish/conf.d`)
//!   stays read-only, without, with a read-only and with a writable whole
//!   home, while an ordinary writable extra folder takes the app's file
//!   (owner decision 9 of 2026-11-23);
//! - a start place kept as a link into a writable extra folder (stow:
//!   `~/.config/tmux` a link to `~/work/dots/tmux`, `~/work` granted) and
//!   granted itself stays read-only where it leads, and the folder between
//!   cannot be renamed away (independent review of decision 9).
//!
//! In its own file because it sets `HOME` for the test process.
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
S="$H/.local/share/samroot"
cat "$H/.ssh/id_ed25519" 2>/dev/null | grep -q SECRET && echo KEY=read || echo KEY=hidden
echo x > "$H/.config/autostart/evil.desktop" 2>/dev/null && echo AUTOSTART=written || echo AUTOSTART=refused
echo 'XDG_DOCUMENTS_DIR="$HOME/.local/share/evil"' >> "$H/.config/user-dirs.dirs" 2>/dev/null && echo USERDIRS=written || echo USERDIRS=refused
mv "$H/.config/user-dirs.dirs" "$H/.config/user-dirs.old" 2>/dev/null && echo USERDIRS_MOVE=done || echo USERDIRS_MOVE=refused
if mv "$H/.local/share" "$H/.local/s2" 2>/dev/null; then echo RENAME=done; else echo RENAME=refused; fi
for base in "$H/.local/share/samroot" "$H/link/share/samroot"; do
  mkdir -p "$base/data/apps" 2>/dev/null && echo planted > "$base/data/apps/PLANTED" 2>/dev/null
done
[ -d "$H/.local/share" ] && [ -d "$H/.config" ] && [ -d "$H/.cache" ] && echo STD=yes || echo STD=no
echo x > "$H/.config/fish/conf.d/evil.fish" 2>/dev/null && echo FISH=written || echo FISH=refused
echo x > "$H/work/ok.txt" 2>/dev/null && echo WORK=written || echo WORK=refused
if [ -e "$H/work/STOW" ]; then
  echo x > "$H/work/dots/tmux/evil.conf" 2>/dev/null && echo STOW=written || echo STOW=refused
  mv "$H/work/dots" "$H/work/dots2" 2>/dev/null && echo STOW_MOVE=done || echo STOW_MOVE=refused
fi
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
fn the_home_protections_hold_whatever_else_is_granted() {
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
    fs::create_dir_all(home.join(".config/autostart")).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::create_dir_all(home.join(".config/fish/conf.d")).unwrap();
    fs::create_dir_all(home.join("work/dots/tmux")).unwrap();
    std::os::unix::fs::symlink(home.join("work/dots/tmux"), home.join(".config/tmux")).unwrap();
    fs::write(home.join(".ssh/id_ed25519"), "SECRET KEY").unwrap();
    let user_dirs = "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n";
    fs::write(home.join(".config/user-dirs.dirs"), user_dirs).unwrap();
    // A link to ~/.local under another name (S-F3).
    fs::create_dir_all(home.join(".local/share")).unwrap();
    std::os::unix::fs::symlink(home.join(".local"), home.join("link")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Attack-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Attack");
    spec.apprun = ATTACK.into();
    build(&img, &spec).unwrap();
    // SAM keeps its records inside the home, as by default.
    let sam_root = home.join(".local/share/samroot");
    let app = Sam::with_paths(Paths::rooted(&sam_root)).unwrap();
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
    let planted = |base: &Path| base.join("data/apps/PLANTED").exists();
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
        r
    };

    // S-F2: full home, plus the folder above it read/write.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.custom_write = vec![root.join("home").to_string_lossy().into_owned()];
    let r = start(p);
    assert_eq!(r["KEY"], "hidden", "{r:?}");
    assert_eq!(r["AUTOSTART"], "refused", "{r:?}");
    assert!(!home.join(".config/autostart/evil.desktop").exists());
    // Row 44: the user folders' locations stay as they were (verification
    // audit 2026-11-19: only the argument list showed this).
    assert_eq!(r["USERDIRS"], "refused", "{r:?}");
    assert_eq!(r["USERDIRS_MOVE"], "refused", "{r:?}");
    assert_eq!(
        fs::read_to_string(home.join(".config/user-dirs.dirs")).unwrap(),
        user_dirs
    );
    assert!(!planted(&sam_root), "SAM's records stayed out of reach");

    // S-F4: ~/.local read/write in a private home.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_write = vec!["~/.local".into()];
    let r = start(p);
    assert_eq!(r["RENAME"], "refused", "{r:?}");
    assert!(
        home.join(".local/share/samroot").is_dir(),
        "SAM's folder is where it was"
    );
    assert!(!home.join(".local/s2").exists());
    assert!(
        !planted(&sam_root),
        "no records planted where SAM keeps its own"
    );

    // S-F3: the same folder granted through a link.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_write = vec!["~/link".into()];
    let r = start(p);
    assert!(
        !planted(&sam_root),
        "SAM's folder stays hidden through a link: {r:?}"
    );
    assert!(home.join(".local/share/samroot").is_dir());

    // Night run: a private home has the folders every home has.
    let r = start(PermissionSet::strict_gui());
    assert_eq!(r["STD"], "yes", "{r:?}");

    // Owner decision 9 of 2026-11-23: a writable folder inside a start
    // place is shown read-only, with or without the whole home; without
    // it, `conf.d/evil.fish` ran at the next shell outside the sandbox.
    // (The start with the whole home writable above wrote `~/work` too.)
    let _ = fs::remove_file(home.join("work/ok.txt"));
    for whole_home in [None, Some(Access::Ro), Some(Access::Rw)] {
        let mut p = PermissionSet::strict_gui();
        if let Some(access) = whole_home {
            p.filesystem.home = true;
            p.filesystem.home_access = access;
        }
        p.filesystem.custom_write = vec!["~/.config/fish/conf.d".into(), "~/work".into()];
        let r = start(p);
        assert_eq!(r["FISH"], "refused", "{whole_home:?}: {r:?}");
        assert!(
            !home.join(".config/fish/conf.d/evil.fish").exists(),
            "{whole_home:?}"
        );
        assert_eq!(r["WORK"], "written", "control, {whole_home:?}: {r:?}");
        assert!(home.join("work/ok.txt").is_file(), "{whole_home:?}");
        fs::remove_file(home.join("work/ok.txt")).unwrap();
    }

    // A start place kept through a link into a writable folder (stow),
    // granted itself: read-only where it leads, also below the writable
    // folder or the writable home, and the folder between pinned.
    fs::write(home.join("work/STOW"), "").unwrap();
    for whole_home in [false, true] {
        let mut p = PermissionSet::strict_gui();
        if whole_home {
            p.filesystem.home = true;
            p.filesystem.home_access = Access::Rw;
        }
        p.filesystem.custom_write = vec!["~/work".into(), "~/.config/tmux".into()];
        let r = start(p);
        assert_eq!(r["STOW"], "refused", "{whole_home}: {r:?}");
        assert!(
            !home.join("work/dots/tmux/evil.conf").exists(),
            "{whole_home}"
        );
        assert_eq!(r["STOW_MOVE"], "refused", "{whole_home}: {r:?}");
        assert!(home.join("work/dots/tmux").is_dir(), "{whole_home}");
        assert_eq!(r["WORK"], "written", "control, {whole_home}: {r:?}");
        fs::remove_file(home.join("work/ok.txt")).unwrap();
    }
    fs::remove_file(home.join("work/STOW")).unwrap();
}
