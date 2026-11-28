//! Git's second credential file, `~/.config/git/credentials`, stays hidden,
//! attacked from inside a real sandbox. git-credential-store keeps your
//! passwords there in plain text when `~/.git-credentials` does not exist.
//! SAM hid only `~/.git-credentials`: `~/.config/git` is a start place kept
//! read-only, so the app could not change the file but could read it
//! wherever it reached the folder:
//! - with the whole home, read and write or read-only;
//! - with `~/.config/git` an extra read-only folder, or `~/.config` an
//!   extra writable one;
//! - with the file a link into a dotfiles folder (`stow`), where the link
//!   leads too;
//! - with `XDG_CONFIG_HOME=~/cfg`, where Git keeps the file in
//!   `~/cfg/git/credentials` (only `~/.config/git/credentials` was hidden;
//!   `~/cfg/git` is a start place kept read-only too), in the same ways;
//!   and a credential store under `~/cfg` named on the command line ("Open
//!   with") is not shared with the app.
//! - with `XDG_CONFIG_HOME=~/cfg` and a private home, `~/.fonts` a link to
//!   `~/cfg/gh` (an app with the whole home writable can make it in an
//!   earlier start: a link needs no access to where it leads): SAM's own
//!   read-only bind of the fonts does not show the GitHub tool's token
//!   there (only `~/.config/gh` was guarded); nor with `XDG_CONFIG_HOME`
//!   outside the home (only the stores in the home were guarded). SAM now
//!   follows no link at a font place at all, so a fonts folder that is a
//!   link to an ordinary folder shows nothing either.
//!
//! The controls show the attack would have been seen: Git's settings file
//! in the same folder stays readable, an ordinary file named on the
//! command line is shared, and a real fonts folder is shown.
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
cat "$H/.config/git/credentials" 2>/dev/null | grep -q SECRET && echo STORE=read || echo STORE=hidden
cat "$H/dotfiles/git-credentials" 2>/dev/null | grep -q SECRET && echo DOTFILES=read || echo DOTFILES=hidden
cat "$H/.config/git/config" 2>/dev/null | grep -q mine && echo CONFIG=read || echo CONFIG=hidden
cat "$H/cfg/git/credentials" 2>/dev/null | grep -q SECRET && echo MOVED=read || echo MOVED=hidden
cat "$H/cfg/git/config" 2>/dev/null | grep -q mine && echo MOVED_CONFIG=read || echo MOVED_CONFIG=hidden
cat "$H/cfg/gh/hosts.yml" 2>/dev/null | grep -q SECRET && echo GH=read || echo GH=hidden
cat "$H/notes.txt" 2>/dev/null | grep -q mine && echo NOTES=read || echo NOTES=hidden
cat "$H/.fonts/hosts.yml" 2>/dev/null | grep -q SECRET && echo FONTS_GH=read || echo FONTS_GH=hidden
cat "$H/.fonts/mine.txt" 2>/dev/null | grep -q mine && echo FONTS_MINE=read || echo FONTS_MINE=hidden
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
fn git_credentials_under_config_git_stay_hidden() {
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
    let store = home.join(".config/git/credentials");
    fs::create_dir_all(home.join(".config/git")).unwrap();
    fs::create_dir_all(home.join("dotfiles")).unwrap();
    fs::write(home.join(".config/git/config"), "# mine\n").unwrap();
    // No `~/.git-credentials`: git-credential-store then uses this one.
    fs::write(&store, "https://u:SECRET@example.org\n").unwrap();
    fs::write(
        home.join("dotfiles/git-credentials"),
        "https://u:SECRET@example.org\n",
    )
    .unwrap();
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
    let start_with = |p: PermissionSet, what: &str, args: Vec<String>| {
        let mut e = app.set_permissions(&id, p).unwrap();
        let rec = run(
            &mut e,
            &LaunchOptions {
                args,
                quiet: true,
                owd: Some(home.clone()),
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &sam_runner::testenv::test_host(HostInfo::probe()),
        )
        .unwrap_or_else(|e| panic!("the app did not start with {what}: {e:#}"));
        let r = parse(rec.log_file.as_ref().unwrap());
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "the attack ran with {what}: {r:?}"
        );
        r
    };
    let start = |p: PermissionSet, what: &str| start_with(p, what, Vec::new());
    let ways = || {
        let mut out = Vec::new();
        for access in [Access::Rw, Access::Ro] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            p.filesystem.home_access = access;
            out.push((p, format!("the whole home {access:?}")));
        }
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_read = vec!["~/.config/git".into()];
        out.push((p, "~/.config/git read-only".to_string()));
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec!["~/.config".into()];
        out.push((p, "~/.config writable".to_string()));
        out
    };

    // The file itself, as git-credential-store writes it.
    for (p, what) in ways() {
        let r = start(p, &what);
        assert_eq!(r["CONFIG"], "read", "control, {what}: {r:?}");
        assert_eq!(r["STORE"], "hidden", "{what}: {r:?}");
    }
    assert_eq!(
        fs::read_to_string(&store).unwrap(),
        "https://u:SECRET@example.org\n",
        "the host's file is unchanged"
    );

    // The file a link into a dotfiles folder: hidden where it leads too.
    fs::remove_file(&store).unwrap();
    std::os::unix::fs::symlink("../../dotfiles/git-credentials", &store).unwrap();
    for (p, what) in ways() {
        let r = start(p, &what);
        let what = format!("{what}, the file a link");
        assert_eq!(r["CONFIG"], "read", "control, {what}: {r:?}");
        assert_eq!(r["STORE"], "hidden", "{what}: {r:?}");
        assert_eq!(r["DOTFILES"], "hidden", "{what}: {r:?}");
    }

    // `XDG_CONFIG_HOME` moved into the home: git-credential-store keeps the
    // passwords in `~/cfg/git/credentials`, which SAM only locked
    // read-only, so the app read them in each of these ways.
    let cfg = home.join("cfg");
    fs::create_dir_all(cfg.join("git")).unwrap();
    fs::create_dir_all(cfg.join("gh")).unwrap();
    fs::write(cfg.join("git/config"), "# mine\n").unwrap();
    fs::write(
        cfg.join("git/credentials"),
        "https://u:SECRET@example.org\n",
    )
    .unwrap();
    fs::write(cfg.join("gh/hosts.yml"), "oauth_token: SECRET\n").unwrap();
    fs::write(home.join("notes.txt"), "mine\n").unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &cfg);
    let mut moved = Vec::new();
    for access in [Access::Rw, Access::Ro] {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = access;
        moved.push((p, format!("the whole home {access:?}")));
    }
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_read = vec!["~/cfg/git".into()];
    moved.push((p, "~/cfg/git read-only".to_string()));
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_write = vec!["~/cfg".into()];
    moved.push((p, "~/cfg writable".to_string()));
    for (p, what) in moved {
        let r = start(p, &what);
        let what = format!("{what}, XDG_CONFIG_HOME=~/cfg");
        assert_eq!(r["MOVED_CONFIG"], "read", "control, {what}: {r:?}");
        assert_eq!(r["MOVED"], "hidden", "{what}: {r:?}");
        assert_eq!(r["STORE"], "hidden", "{what}: {r:?}");
    }
    assert_eq!(
        fs::read_to_string(cfg.join("git/credentials")).unwrap(),
        "https://u:SECRET@example.org\n",
        "the host's file is unchanged"
    );

    // Named on the command line: a credential store under the moved folder
    // is never shared, an ordinary file is.
    let args = vec![
        cfg.join("gh/hosts.yml").to_string_lossy().into_owned(),
        home.join("notes.txt").to_string_lossy().into_owned(),
    ];
    let r = start_with(PermissionSet::strict_gui(), "files named to open", args);
    assert_eq!(r["NOTES"], "read", "control, files named to open: {r:?}");
    assert_eq!(r["GH"], "hidden", "files named to open: {r:?}");

    // A fonts folder made a link to a credential store under the moved
    // folder: SAM's own read-only bind of the fonts does not show it in a
    // private home. Nor does a fonts folder that is a link to an ordinary
    // folder there: SAM follows no link at a font place. A real fonts
    // folder is shown, so a read would have been seen.
    let fonts = home.join(".fonts");
    std::os::unix::fs::symlink(cfg.join("gh"), &fonts).unwrap();
    let r = start(
        PermissionSet::strict_gui(),
        "a private home, ~/.fonts a link to ~/cfg/gh",
    );
    assert_eq!(
        r["FONTS_GH"], "hidden",
        "~/.fonts a link to ~/cfg/gh: {r:?}"
    );
    fs::remove_file(&fonts).unwrap();
    fs::create_dir_all(cfg.join("myfonts")).unwrap();
    fs::write(cfg.join("myfonts/mine.txt"), "mine\n").unwrap();
    std::os::unix::fs::symlink(cfg.join("myfonts"), &fonts).unwrap();
    let r = start(
        PermissionSet::strict_gui(),
        "a private home, ~/.fonts a link to ~/cfg/myfonts",
    );
    assert_eq!(
        r["FONTS_MINE"], "hidden",
        "~/.fonts a link to ~/cfg/myfonts: {r:?}"
    );
    fs::remove_file(&fonts).unwrap();
    fs::create_dir_all(&fonts).unwrap();
    fs::write(fonts.join("mine.txt"), "mine\n").unwrap();
    let r = start(
        PermissionSet::strict_gui(),
        "a private home, a real ~/.fonts",
    );
    assert_eq!(r["FONTS_MINE"], "read", "control, a real ~/.fonts: {r:?}");
    fs::remove_dir_all(&fonts).unwrap();
    std::os::unix::fs::symlink(cfg.join("myfonts"), &fonts).unwrap();

    // The same with `XDG_CONFIG_HOME` outside the home (and outside `/tmp`,
    // where any link counts as one to programs listening outside the
    // sandbox anyway): only the stores in the home were guarded, so
    // `~/.fonts` a link to `/data/cfg/gh` showed the token.
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let data = fs::canonicalize(scratch.path()).unwrap();
    assert!(
        !data.starts_with("/tmp") && !data.starts_with("/var/tmp"),
        "the build's scratch folder lies in a temp folder: {}",
        data.display()
    );
    let far = data.join("cfg");
    fs::create_dir_all(far.join("gh")).unwrap();
    fs::create_dir_all(far.join("myfonts")).unwrap();
    fs::write(far.join("gh/hosts.yml"), "oauth_token: SECRET\n").unwrap();
    fs::write(far.join("myfonts/mine.txt"), "mine\n").unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &far);
    fs::remove_file(&fonts).unwrap();
    std::os::unix::fs::symlink(far.join("gh"), &fonts).unwrap();
    let r = start(
        PermissionSet::strict_gui(),
        "a private home, ~/.fonts a link to the GitHub folder outside the home",
    );
    assert_eq!(
        r["FONTS_GH"],
        "hidden",
        "~/.fonts a link to {}/gh: {r:?}",
        far.display()
    );
    fs::remove_file(&fonts).unwrap();
    std::os::unix::fs::symlink(far.join("myfonts"), &fonts).unwrap();
    let r = start(
        PermissionSet::strict_gui(),
        "a private home, ~/.fonts a link to a fonts folder outside the home",
    );
    assert_eq!(
        r["FONTS_MINE"],
        "hidden",
        "~/.fonts a link to {}/myfonts: {r:?}",
        far.display()
    );
}
