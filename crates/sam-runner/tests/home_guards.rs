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
//! - a folder inside a start place kept as a link into a writable extra
//!   folder (stow: `~/.config/tmux/plugins` a link to `~/work/dots/tmux`,
//!   `~/work` granted) and granted itself stays read-only where it leads,
//!   and the folder between cannot be renamed away (independent review of
//!   decision 9).
//! - another SAM's folders kept through a link (`~/.local/share/sam` a link
//!   to `~/Sync/sam`) stay hidden with the whole home and with a grant of
//!   `~/Sync` (independent review of decision 9).
//! - SAM's folders by name below another config or data folder
//!   (`XDG_CONFIG_HOME=~/cfg`: `~/cfg/sam`, `~/dat/sam`) stay hidden, not
//!   only read-only: the app cannot read them with the whole home or with
//!   a grant of `~/cfg` and `~/dat` (independent review of decision 9).
//!
//! - a start file kept as a link into a read-only user folder
//!   (`~/.bashrc` to `~/Documents/dotfiles/bashrc`) stays read-only with
//!   the whole home writable, also when a writable user folder inside it
//!   holds the file (finding R63).
//!
//! Its tests take turns, because each sets `HOME` for the test process.
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
grep -q OTHER "$H/Sync/sam/config.toml" 2>/dev/null && echo OTHER_SAM=read || echo OTHER_SAM=hidden
grep -q OTHER "$H/.local/share/sam/config.toml" 2>/dev/null && echo OTHER_LINK=read || echo OTHER_LINK=hidden
grep -q NOTE "$H/Sync/note.txt" 2>/dev/null && echo SYNC_NOTE=read || echo SYNC_NOTE=hidden
grep -q CFGSAM "$H/cfg/sam/config.toml" 2>/dev/null && echo CFG_SAM=read || echo CFG_SAM=hidden
grep -q DATSAM "$H/dat/sam/apps.toml" 2>/dev/null && echo DAT_SAM=read || echo DAT_SAM=hidden
grep -q CFGNOTE "$H/cfg/note.txt" 2>/dev/null && echo CFG_NOTE=read || echo CFG_NOTE=hidden
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

/// The tests here set `HOME` and the rest of the environment for the whole
/// test process: one at a time.
static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn the_home_protections_hold_whatever_else_is_granted() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    fs::create_dir_all(home.join(".config/tmux")).unwrap();
    std::os::unix::fs::symlink(
        home.join("work/dots/tmux"),
        home.join(".config/tmux/plugins"),
    )
    .unwrap();
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

    // A folder inside a start place kept through a link into a writable
    // folder (stow), granted itself: read-only where it leads, also below
    // the writable folder or the writable home, where the start place's
    // own lock does not reach it, and the folder between pinned.
    fs::write(home.join("work/STOW"), "").unwrap();
    for whole_home in [false, true] {
        let mut p = PermissionSet::strict_gui();
        if whole_home {
            p.filesystem.home = true;
            p.filesystem.home_access = Access::Rw;
        }
        p.filesystem.custom_write = vec!["~/work".into(), "~/.config/tmux/plugins".into()];
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

    // Another SAM's folders kept through a link (`~/.local/share/sam` a
    // link to `~/Sync/sam`) while this SAM keeps its own elsewhere stay
    // hidden, through the link and where it leads, with the whole home and
    // with a grant of `~/Sync`, which still shows the rest of `~/Sync`.
    // Taken for an ordinary start place because it was a link, it was only
    // kept read-only, and the app read the other SAM's settings
    // (independent review of decision 9).
    fs::create_dir_all(home.join("Sync/sam")).unwrap();
    fs::write(home.join("Sync/sam/config.toml"), "OTHER SAM").unwrap();
    fs::write(home.join("Sync/note.txt"), "NOTE").unwrap();
    std::os::unix::fs::symlink(home.join("Sync/sam"), home.join(".local/share/sam")).unwrap();
    for whole_home in [true, false] {
        let mut p = PermissionSet::strict_gui();
        if whole_home {
            p.filesystem.home = true;
            p.filesystem.home_access = Access::Rw;
        } else {
            p.filesystem.custom_read = vec!["~/Sync".into()];
        }
        let r = start(p);
        assert_eq!(r["OTHER_SAM"], "hidden", "{whole_home}: {r:?}");
        assert_eq!(r["OTHER_LINK"], "hidden", "{whole_home}: {r:?}");
        assert_eq!(r["SYNC_NOTE"], "read", "control, {whole_home}: {r:?}");
        assert!(home.join("Sync/sam/config.toml").is_file(), "{whole_home}");
    }

    // SAM's folders by name below another config or data folder
    // (`XDG_CONFIG_HOME=~/cfg`, `XDG_DATA_HOME=~/dat`: `~/cfg/sam`,
    // `~/dat/sam`) while this SAM keeps its own elsewhere are hidden, not
    // only locked read-only: the app cannot read them with the whole home
    // or with a grant of `~/cfg` and `~/dat`, which still show the rest.
    // Only locked read-only, `~/cfg/sam` let the app read the settings
    // there; before, only the Bubblewrap arguments showed this
    // (independent review of decision 9).
    fs::create_dir_all(home.join("cfg/sam")).unwrap();
    fs::create_dir_all(home.join("dat/sam")).unwrap();
    fs::write(home.join("cfg/sam/config.toml"), "CFGSAM").unwrap();
    fs::write(home.join("dat/sam/apps.toml"), "DATSAM").unwrap();
    fs::write(home.join("cfg/note.txt"), "CFGNOTE").unwrap();
    std::env::set_var("XDG_CONFIG_HOME", home.join("cfg"));
    std::env::set_var("XDG_DATA_HOME", home.join("dat"));
    for whole_home in [true, false] {
        let mut p = PermissionSet::strict_gui();
        if whole_home {
            p.filesystem.home = true;
            p.filesystem.home_access = Access::Rw;
        } else {
            p.filesystem.custom_read = vec!["~/cfg".into(), "~/dat".into()];
        }
        let r = start(p);
        let _ = fs::remove_file(home.join("work/ok.txt"));
        assert_eq!(r["CFG_SAM"], "hidden", "cfg, {whole_home}: {r:?}");
        assert_eq!(r["DAT_SAM"], "hidden", "dat, {whole_home}: {r:?}");
        assert_eq!(r["CFG_NOTE"], "read", "control, {whole_home}: {r:?}");
        assert!(home.join("cfg/sam/config.toml").is_file(), "{whole_home}");
    }
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
}

const RC_ATTACK: &str = r#"#!/bin/sh
H="$HOME"
( echo evil >> "$H/.bashrc" ) 2>/dev/null && echo RC=written || echo RC=refused
( echo evil > "$H/Documents/dotfiles/bashrc" ) 2>/dev/null && echo RC_TARGET=written || echo RC_TARGET=refused
( echo x > "$H/Documents/dotfiles/notes.txt" ) 2>/dev/null && echo DOTS_WRITE=yes || echo DOTS_WRITE=no
mv "$H/Documents/dotfiles" "$H/Documents/d2" 2>/dev/null && echo RC_MOVE=done || echo RC_MOVE=refused
( echo x > "$H/ok.txt" ) 2>/dev/null && echo HOME_WRITE=yes || echo HOME_WRITE=no
echo END=1
"#;

/// Finding R63, attacked from inside a real sandbox: with the whole home
/// writable and Documents set to read-only, a start file kept as a link
/// into Documents (`~/.bashrc` to `Documents/dotfiles/bashrc`, as stow
/// makes it) cannot be changed, through the link or where it leads, and
/// its folder cannot be renamed away. Before, Documents was shown writable
/// through the home, and no lock reached the file, because SAM took it for
/// read-only; the change ran at the next shell outside the sandbox. With
/// the dotfiles folder a writable user folder of its own inside the
/// read-only Documents (Desktop set to it), the start file is still locked
/// (the protections come after every mount), while the rest of that folder
/// takes the app's file.
#[test]
fn a_start_file_linked_into_a_read_only_user_folder_stays_locked_with_a_writable_home() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let dots = home.join("Documents/dotfiles");
    fs::create_dir_all(&dots).unwrap();
    fs::create_dir_all(home.join(".config")).unwrap();
    let rc = "# the person's own\n";
    fs::write(dots.join("bashrc"), rc).unwrap();
    std::os::unix::fs::symlink("Documents/dotfiles/bashrc", home.join(".bashrc")).unwrap();
    fs::write(
        home.join(".config/user-dirs.dirs"),
        "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\nXDG_DESKTOP_DIR=\"$HOME/Documents/dotfiles\"\n",
    )
    .unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Rc-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Rc");
    spec.apprun = RC_ATTACK.into();
    build(&img, &spec).unwrap();
    let app = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
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
    let host = sam_runner::testenv::test_host(HostInfo::probe());
    assert_eq!(
        host.xdg_dir("documents"),
        Some(home.join("Documents").as_path()),
        "the test's own"
    );
    let start = |desktop: Access| {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        p.filesystem.documents = Access::Ro;
        p.filesystem.desktop = desktop;
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
            &host,
        )
        .unwrap();
        let r = parse(rec.log_file.as_ref().unwrap());
        assert_eq!(r.get("END").map(String::as_str), Some("1"), "{r:?}");
        r
    };

    let r = start(Access::None);
    assert_eq!(r["RC"], "refused", "{r:?}");
    assert_eq!(r["RC_TARGET"], "refused", "{r:?}");
    assert_eq!(r["DOTS_WRITE"], "no", "{r:?}");
    assert_eq!(r["RC_MOVE"], "refused", "{r:?}");
    assert_eq!(
        r["HOME_WRITE"], "yes",
        "control: the home is writable: {r:?}"
    );
    assert_eq!(fs::read_to_string(dots.join("bashrc")).unwrap(), rc);
    assert!(dots.is_dir(), "the folder is where it was");

    // The dotfiles folder a writable user folder inside the read-only
    // Documents: the start file stays locked, the rest takes the file.
    let r = start(Access::Rw);
    assert_eq!(r["RC"], "refused", "{r:?}");
    assert_eq!(r["RC_TARGET"], "refused", "{r:?}");
    assert_eq!(r["DOTS_WRITE"], "yes", "control: {r:?}");
    assert_eq!(r["RC_MOVE"], "refused", "{r:?}");
    assert_eq!(fs::read_to_string(dots.join("bashrc")).unwrap(), rc);
    assert!(fs::symlink_metadata(home.join(".bashrc"))
        .unwrap()
        .file_type()
        .is_symlink());
}
