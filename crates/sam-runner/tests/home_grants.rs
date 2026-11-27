//! Grants of parts of the home never reach a start place, a credential
//! store or SAM's own records, attacked from inside a real sandbox (audit
//! 2026-11-18: D-M2, D-M3, S-F11, S-F13, the credential-store list; A2 and
//! U-L6 for who can read the logs and records):
//! - a folder named on the command line that holds the real `~/.bashrc`
//!   (kept in `~/dotfiles`, linked) is not shared;
//! - a writable `~/.config` cannot leave a new autostart entry, and a
//!   writable `~/.bash_profile` stays read-only;
//! - a Documents folder that `user-dirs.dirs` points above the home is not
//!   shown;
//! - a writable Documents folder that holds the real `~/.bashrc` is shown,
//!   the start file in it stays read-only;
//! - a file inside SAM's folder (kept outside the home) or `~/.netrc` named
//!   on the command line is not shared;
//! - with the whole home, Vivaldi's profile and `~/.npmrc` stay hidden;
//! - the start's log and the app's record are for the user only.
//!
//! Each case has a control that shows the attack would have been seen:
//! an ordinary folder opened or granted the same way is written.
//!
//! In its own file because it sets `HOME` for the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

const ATTACK: &str = r#"#!/bin/sh
H="$HOME"
for f in "$@"; do echo pwned >> "$f" 2>/dev/null; done
echo pwned >> "$H/dotfiles/bashrc" 2>/dev/null
echo pwned >> "$H/work/notes.txt" 2>/dev/null
echo pwned >> "$H/dotfiles/notes.txt" 2>/dev/null
mkdir -p "$H/.config/autostart" 2>/dev/null && echo x > "$H/.config/autostart/evil.desktop" 2>/dev/null
mkdir -p "$H/.config/myapp" 2>/dev/null && echo x > "$H/.config/myapp/settings" 2>/dev/null
echo pwned >> "$H/.bash_profile" 2>/dev/null
cat "$H/docs/tester/.ssh/id_ed25519" 2>/dev/null | grep -q SECRET && echo DOCSKEY=read || echo DOCSKEY=hidden
mkdir -p "$H/docs/tester/.config/autostart" 2>/dev/null && echo x > "$H/docs/tester/.config/autostart/evil2.desktop" 2>/dev/null
cat "$H/.config/vivaldi/Default/Login Data" 2>/dev/null | grep -q SECRET && echo VIVALDI=read || echo VIVALDI=hidden
cat "$H/.npmrc" 2>/dev/null | grep -q SECRET && echo NPMRC=read || echo NPMRC=hidden
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

fn mode(p: &Path) -> u32 {
    fs::metadata(p).map_or(0, |m| m.permissions().mode() & 0o777)
}

#[test]
fn grants_of_parts_of_the_home_never_reach_start_places_or_secrets() {
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
    for d in [".ssh", "dotfiles", "work", ".config/vivaldi/Default"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    fs::write(home.join(".ssh/id_ed25519"), "SECRET KEY").unwrap();
    // Dotfiles kept in a folder of their own and linked (`stow`).
    fs::write(home.join("dotfiles/bashrc"), "# mine\n").unwrap();
    std::os::unix::fs::symlink(home.join("dotfiles/bashrc"), home.join(".bashrc")).unwrap();
    fs::write(home.join("work/notes.txt"), "notes\n").unwrap();
    fs::write(home.join("dotfiles/notes.txt"), "notes\n").unwrap();
    fs::write(home.join(".bash_profile"), "# mine\n").unwrap();
    fs::write(home.join(".netrc"), "machine x password SECRET\n").unwrap();
    fs::write(home.join(".config/vivaldi/Default/Login Data"), "SECRET").unwrap();
    fs::write(home.join(".npmrc"), "//registry/:_authToken=SECRET\n").unwrap();
    // A Documents folder set to a link to the folder above the home.
    std::os::unix::fs::symlink(root.join("home"), home.join("docs")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Attack-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Attack");
    spec.apprun = ATTACK.into();
    build(&img, &spec).unwrap();
    // SAM's folders outside the home, as a person may choose.
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
    let record = app.paths.app_file(&id);
    // Every case is checked, and every failure reported together.
    let failed = RefCell::new(Vec::<String>::new());
    let check = |ok: bool, what: String| {
        if !ok {
            failed.borrow_mut().push(what);
        }
    };
    let read = |p: &Path| fs::read_to_string(p).unwrap_or_default();
    let start = |p: PermissionSet, args: Vec<PathBuf>, docs: Option<PathBuf>| {
        let Ok(mut e) = app.set_permissions(&id, p) else {
            check(false, "SAM's record is broken (written by the app?)".into());
            return (HashMap::new(), PathBuf::new());
        };
        let mut h = sam_runner::testenv::test_host(HostInfo::probe());
        h.xdg_dirs.clear();
        if let Some(d) = docs {
            h.xdg_dirs.insert("documents".into(), d);
        }
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                owd: Some(home.clone()),
                args: args
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect(),
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &h,
        )
        .unwrap();
        let log = rec.log_file.clone().unwrap();
        let r = parse(&log);
        check(
            r.get("END").map(String::as_str) == Some("1"),
            format!(
                "the attack ran: {}",
                fs::read_to_string(&log).unwrap_or_default()
            ),
        );
        (r, log)
    };
    let opening = || {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.opened_files = Access::Rw;
        p
    };

    // D-M2: the folder that holds the real ~/.bashrc, named on the command
    // line, is not shared; an ordinary folder is (the control).
    start(opening(), vec![home.join("dotfiles")], None);
    check(
        read(&home.join(".bashrc")) == "# mine\n",
        "D-M2: the start file behind a link was written".into(),
    );
    start(opening(), vec![home.join("work")], None);
    check(
        read(&home.join("work/notes.txt")).contains("pwned"),
        "control: an opened folder was not written".into(),
    );

    // D-M3: a writable ~/.config leaves no autostart entry behind (the
    // app's own settings stay); a writable ~/.bash_profile stays as it was.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_write = vec!["~/.config".into(), "~/.bash_profile".into()];
    start(p, vec![], None);
    check(
        !home.join(".config/autostart/evil.desktop").exists(),
        "D-M3: an autostart entry was left in a granted ~/.config".into(),
    );
    check(
        home.join(".config/myapp/settings").is_file(),
        "control: the granted folder was not written".into(),
    );
    check(
        read(&home.join(".bash_profile")) == "# mine\n",
        "D-M3: a granted ~/.bash_profile was written".into(),
    );

    // S-F11: Documents set to a link to the folder above the home.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.documents = Access::Rw;
    let (r, _) = start(p, vec![], Some(home.join("docs")));
    check(
        r.get("DOCSKEY").map(String::as_str) == Some("hidden"),
        format!("S-F11: a key was read through Documents: {r:?}"),
    );
    check(
        !home.join(".config/autostart/evil2.desktop").exists(),
        "S-F11: an autostart entry was left through Documents".into(),
    );

    // Documents set to the folder that holds the real ~/.bashrc (dotfiles
    // linked into the home), granted writable: the folder is shown, the
    // start file in it stays read-only (mutation run P14: whether a granted
    // user folder counts as writable was untested).
    // (The first case's attack left a file of that name in the app's own
    // home, where the folder is shown.)
    let _ = fs::remove_file(app.paths.app_home(&id).join("dotfiles"));
    let mut p = PermissionSet::strict_gui();
    p.filesystem.documents = Access::Rw;
    start(p, vec![], Some(home.join("dotfiles")));
    check(
        read(&home.join(".bashrc")) == "# mine\n",
        "the start file in a writable Documents folder was written".into(),
    );
    check(
        read(&home.join("dotfiles/notes.txt")).contains("pwned"),
        "control: the writable Documents folder was not written".into(),
    );

    // S-F13: a file inside SAM's folder, and ~/.netrc, named on the command
    // line, are not shared.
    start(opening(), vec![record.clone(), home.join(".netrc")], None);
    check(
        !read(&record).contains("pwned"),
        "S-F13: the app wrote SAM's record".into(),
    );
    check(
        read(&home.join(".netrc")) == "machine x password SECRET\n",
        "S-F13: the app wrote ~/.netrc".into(),
    );

    // Credential stores the list missed: hidden with the whole home (whose
    // ~/.bashrc is a link: such a home used to stop every start).
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.hidden_files = false;
    let (r, log) = start(p, vec![], None);
    for k in ["VIVALDI", "NPMRC"] {
        check(
            r.get(k).map(String::as_str) == Some("hidden"),
            format!("credential list: {k} was read: {r:?}"),
        );
    }

    // A2, U-L6: the log, its folders and the record are the user's alone.
    for (p, want, what) in [
        (log.clone(), 0o600, "the log"),
        (
            log.parent().unwrap_or(Path::new("")).to_path_buf(),
            0o700,
            "the app's log folder",
        ),
        (app.paths.logs_dir(), 0o700, "the log folder"),
        (record.clone(), 0o600, "the record"),
    ] {
        check(
            mode(&p) == want,
            format!("A2/U-L6: {what} has mode {:o}", mode(&p)),
        );
    }
    let failed = failed.into_inner();
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}
