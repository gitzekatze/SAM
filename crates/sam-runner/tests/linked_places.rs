//! Places kept behind a link stay protected, attacked from inside a real
//! sandbox (security review 2026-11-23, SB-2 and SB-6):
//! - a key folder that is a link (`~/.gnupg` to `~/Sync/gnupg`) stays
//!   hidden, also unwritten, when only the folder it points into is granted;
//! - so are the key folders and the credential stores whose switches are
//!   stored "on" without the whole home (an old profile, a hand-edited
//!   file): the switches count only with the whole home;
//! - with the whole home writable and `~/.config` a link with a whole path
//!   (dotfiles kept elsewhere), the app starts, and autostart stays
//!   read-only;
//! - with `~/.config` a link to another place nobody granted, the app
//!   starts (also with fonts settings there, which SAM shows read-only),
//!   and a `~/.config` the app puts in the link's place is moved aside
//!   afterwards; SAM's own settings are in `~/.config/sam`, behind the
//!   link, as on a real system (the empty folder SAM puts on them went
//!   through the link and stopped the start);
//! - with `~/.config` a link into a folder granted read-only, that folder
//!   stays read-only (the folder above autostart, made a mount point of
//!   its own, made it writable again);
//! - with the home kept behind a link, a link in it that names the home's
//!   real path is covered where the app reaches its target: under the
//!   home's name.
//!
//! Controls show the attack would have been seen: an ordinary file the
//! app may write is written.
//!
//! In its own file because it sets `HOME` for the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

const ATTACK: &str = r#"#!/bin/sh
H="$HOME"
cat "$H/Sync/gnupg/private.key" 2>/dev/null | grep -q SECRET && echo GPGKEY=read || echo GPGKEY=hidden
cat "$H/Sync/ssh/id_ed25519" 2>/dev/null | grep -q SECRET && echo SSHKEY=read || echo SSHKEY=hidden
cat "$H/Sync/netrc" 2>/dev/null | grep -q SECRET && echo NETRC=read || echo NETRC=hidden
echo 'pinentry-program /evil' >> "$H/Sync/gnupg/gpg-agent.conf" 2>/dev/null
echo written >> "$H/Sync/notes.txt" 2>/dev/null
mkdir -p "$H/.config/autostart" 2>/dev/null
echo x > "$H/.config/autostart/evil.desktop" 2>/dev/null && echo AUTOSTART=written || echo AUTOSTART=refused
echo written > "$H/dotfiles/config/app.conf" 2>/dev/null && echo DOTFILES=written || echo DOTFILES=refused
echo written > "$H/work.txt" 2>/dev/null
if [ "$1" = direct ]; then
  echo x > "$H/dotfiles/config/autostart/evil.desktop" 2>/dev/null && echo DIRECT=written || echo DIRECT=refused
fi
if [ "$1" = replace ]; then
  rm -f "$H/.config" && mkdir -p "$H/.config/autostart" && echo x > "$H/.config/autostart/evil.desktop"
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
fn places_behind_links_stay_protected_and_the_app_still_starts() {
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
    // Fonts settings too: SAM shows them read-only, also through the link.
    for d in [
        "Sync/gnupg",
        "dotfiles/config/autostart",
        "dotfiles/config/fontconfig",
    ] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    fs::create_dir_all(root.join("elsewhere/config/autostart")).unwrap();
    fs::write(home.join("Sync/gnupg/private.key"), "SECRET KEY").unwrap();
    fs::write(home.join("Sync/gnupg/gpg-agent.conf"), "# mine\n").unwrap();
    symlink(home.join("Sync/gnupg"), home.join(".gnupg")).unwrap();
    fs::create_dir_all(home.join("Sync/ssh")).unwrap();
    fs::write(home.join("Sync/ssh/id_ed25519"), "SECRET KEY").unwrap();
    symlink(home.join("Sync/ssh"), home.join(".ssh")).unwrap();
    fs::write(home.join("Sync/netrc"), "machine x password SECRET\n").unwrap();
    symlink(home.join("Sync/netrc"), home.join(".netrc")).unwrap();
    // `~/.config` a link with a whole path into the home (dotfiles kept
    // elsewhere); SAM keeps its settings in it, as on a real system.
    symlink(home.join("dotfiles/config"), home.join(".config")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

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
    // `seen`: the home as the app sees it (the start's home).
    let start_in = |p: PermissionSet, args: &[&str], seen: &Path| {
        let mut e = app.set_permissions(&id, p).unwrap();
        let mut h = sam_runner::testenv::test_host(HostInfo::probe());
        h.home = seen.to_path_buf();
        h.xdg_dirs.clear();
        // SAM's settings where SAM keeps them: in `~/.config`, behind the
        // link (the empty folder SAM puts on them went through the link
        // and stopped the start when it led to a place nobody granted).
        let mut paths = app.paths.clone();
        paths.config_dir = seen.join(".config/sam");
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                owd: Some(seen.to_path_buf()),
                args: args.iter().map(|a| a.to_string()).collect(),
                ..Default::default()
            },
            &app.config,
            &paths,
            &h,
        )
        .unwrap_or_else(|e| panic!("the app did not start: {e:#}"));
        let r = parse(rec.log_file.as_ref().unwrap());
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "the attack ran: {r:?}"
        );
        r
    };
    let start = |p: PermissionSet, args: &[&str]| start_in(p, args, &home);
    let read = |p: &Path| fs::read_to_string(p).unwrap_or_default();

    // SB-2: only ~/Sync granted, writable; ~/.gnupg is a link into it.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_write = vec!["~/Sync".into()];
    let r = start(p, &[]);
    assert_eq!(read(&home.join("Sync/notes.txt")), "written\n", "control");
    assert_eq!(r["GPGKEY"], "hidden", "{r:?}");
    assert_eq!(
        read(&home.join("Sync/gnupg/gpg-agent.conf")),
        "# mine\n",
        "the key folder's settings were changed"
    );

    // The same with the key and credential switches stored "on" but not the
    // whole home (an old profile, a hand-edited file): they count only
    // with the whole home, so everything stays hidden.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_write = vec!["~/Sync".into()];
    p.filesystem.ssh = true;
    p.filesystem.gnupg = true;
    p.filesystem.hidden_files = true;
    let r = start(p, &[]);
    assert_eq!(r["GPGKEY"], "hidden", "GnuPG keys: {r:?}");
    assert_eq!(r["SSHKEY"], "hidden", "SSH keys: {r:?}");
    assert_eq!(r["NETRC"], "hidden", "the credential store ~/.netrc: {r:?}");
    assert_eq!(
        read(&home.join("Sync/gnupg/gpg-agent.conf")),
        "# mine\n",
        "the key folder's settings were changed with the switch stored on"
    );
    // Control: with the whole home (read-only, so nothing is changed for
    // the stages below), the same switches show them.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Ro;
    p.filesystem.ssh = true;
    p.filesystem.gnupg = true;
    p.filesystem.hidden_files = true;
    let r = start(p, &[]);
    assert_eq!(r["GPGKEY"], "read", "control, GnuPG keys: {r:?}");
    assert_eq!(r["SSHKEY"], "read", "control, SSH keys: {r:?}");
    assert_eq!(r["NETRC"], "read", "control, ~/.netrc: {r:?}");

    // SB-6, a link with a whole path into the home: the start used to fail
    // (Bubblewrap followed the link from its own root).
    let full = || {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        p
    };
    let r = start(full(), &[]);
    assert_eq!(read(&home.join("work.txt")), "written\n", "control");
    assert_eq!(r["AUTOSTART"], "refused", "{r:?}");
    assert!(!home.join("dotfiles/config/autostart/evil.desktop").exists());

    // SB-6, a link with a whole path to a place nobody granted: the app
    // starts (the link leads nowhere inside), and a ~/.config it puts in
    // the link's place is moved aside, the link put back.
    fs::remove_file(home.join(".config")).unwrap();
    symlink(root.join("elsewhere/config"), home.join(".config")).unwrap();
    start(full(), &["replace"]);
    assert!(!root
        .join("elsewhere/config/autostart/evil.desktop")
        .exists());
    assert_eq!(
        fs::read_link(home.join(".config")).unwrap(),
        root.join("elsewhere/config"),
        "the link is back"
    );
    assert!(!home.join(".config/autostart/evil.desktop").exists());
    // With fonts settings there too, shown read-only where they lie.
    fs::create_dir_all(root.join("elsewhere/config/fontconfig")).unwrap();
    start(full(), &[]);
    assert!(!root
        .join("elsewhere/config/autostart/evil.desktop")
        .exists());

    // SB-6, a relative link into a folder granted read-only (the app could
    // write there with the whole home, above).
    fs::remove_file(home.join("dotfiles/config/app.conf")).unwrap();
    fs::remove_file(home.join(".config")).unwrap();
    symlink("dotfiles/config", home.join(".config")).unwrap();
    let mut p = full();
    p.filesystem.custom_read = vec!["~/dotfiles".into()];
    let r = start(p, &[]);
    assert_eq!(r["DOTFILES"], "refused", "{r:?}");
    assert!(!home.join("dotfiles/config/app.conf").exists());
    assert_eq!(r["AUTOSTART"], "refused", "{r:?}");

    // The home kept behind a link (the app sees `/…/linked`), and links in
    // it that name the home's real path, as tools that resolve the folder
    // they run in write them: inside, `~/.config` and `~/.gnupg` lead
    // nowhere, yet the app reaches the same folders under the home's name.
    // Autostart stays read-only there and the key folder hidden (the start
    // used to fail here; with links followed, both were open).
    fs::remove_file(home.join(".config")).unwrap();
    symlink(home.join("dotfiles/config"), home.join(".config")).unwrap();
    let linked = root.join("home/linked");
    symlink(&home, &linked).unwrap();
    let r = start_in(full(), &["direct"], &linked);
    assert_eq!(r["DIRECT"], "refused", "{r:?}");
    assert!(!home.join("dotfiles/config/autostart/evil.desktop").exists());
    assert_eq!(r["GPGKEY"], "hidden", "{r:?}");
    assert_eq!(
        read(&home.join("Sync/gnupg/gpg-agent.conf")),
        "# mine\n",
        "the key folder's settings were changed through the linked home"
    );
}
