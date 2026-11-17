//! Full home read/write, attacked from inside a real sandbox. The app tries
//! each known way to make the computer run something later, or to reach a
//! key, and none may work:
//! - renaming `~/.config` away and filling a new one (`autostart`);
//! - creating a startup file that did not exist (`~/.bash_profile`);
//! - reading a key through a key folder that is a link (dotfiles, `stow`);
//! - replacing that link with a folder of its own (`authorized_keys`).
//!
//! What the app leaves behind is moved aside after the start, and links are
//! put back. In its own file because it sets `HOME` for the test process.
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
if mv "$H/.config" "$H/.c-old" 2>/dev/null; then
    echo RENAME=done
    mkdir -p "$H/.config/autostart" && echo x > "$H/.config/autostart/evil.desktop"
else
    echo RENAME=refused
fi
echo 'echo pwned' > "$H/.bash_profile" 2>/dev/null && echo PROFILE=written || echo PROFILE=refused
cat "$H/.ssh/id_ed25519" 2>/dev/null | grep -q SECRET && echo KEY=read || echo KEY=hidden
if rm "$H/.ssh" 2>/dev/null && mkdir "$H/.ssh" && echo planted > "$H/.ssh/authorized_keys"; then
    echo LINK=replaced
else
    echo LINK=refused
fi
# While the app still runs: the new startup file is already gone.
sleep 1
[ -e "$H/.bash_profile" ] && echo PROFILE_LIVE=stayed || echo PROFILE_LIVE=gone
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
fn full_home_access_cannot_leave_anything_that_runs_later() {
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
    // The key folder is a link into a dotfiles folder.
    let dotfiles = home.join("dotfiles/ssh");
    fs::create_dir_all(&dotfiles).unwrap();
    fs::write(dotfiles.join("id_ed25519"), "SECRET KEY").unwrap();
    std::os::unix::fs::symlink(&dotfiles, home.join(".ssh")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Attack-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Attack");
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

    // 1. ~/.config cannot be renamed away (it is a mount point of its own).
    assert_eq!(r["RENAME"], "refused");
    assert!(!home.join(".config/autostart/evil.desktop").exists());
    // 2. A new startup file does not stay.
    assert!(
        !home.join(".bash_profile").exists(),
        "the new .bash_profile was moved aside"
    );
    // ... and it is moved aside while the app runs, not only at its end.
    assert_eq!(r["PROFILE_LIVE"], "gone");
    // 3. The key behind the link stays hidden.
    assert_eq!(r["KEY"], "hidden");
    // 4. The link is back, the folder the app put there is gone.
    assert_eq!(fs::read_link(home.join(".ssh")).unwrap(), dotfiles);
    assert_eq!(
        fs::read_to_string(dotfiles.join("id_ed25519")).unwrap(),
        "SECRET KEY"
    );
    assert!(!dotfiles.join("authorized_keys").exists());

    // What was moved, and where: in the record, the log and SAM's folder.
    let moved = rec.moved_aside.join("\n");
    assert!(moved.contains("~/.bash_profile"), "{moved}");
    if r["LINK"] == "replaced" {
        assert!(moved.contains("~/.ssh"), "{moved}");
    }
    let aside = paths.data_dir.join("moved-aside").join(&id);
    let kept: Vec<_> = walk(&aside);
    assert!(
        kept.iter()
            .any(|p| p.ends_with(".bash_profile")
                && fs::read_to_string(p).unwrap().contains("pwned")),
        "kept for a look: {kept:?}"
    );
    let log = fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap();
    assert!(log.contains("# moved aside"), "{log}");
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        }
        out.push(p);
    }
    out
}
