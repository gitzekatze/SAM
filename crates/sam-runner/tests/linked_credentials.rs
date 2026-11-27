//! Credential places SAM hides stay hidden, attacked from inside a real
//! sandbox (mutation run 2026-11-23):
//! - a credential file kept behind a link into a protected place
//!   (`~/.git-credentials` to `~/.config/git/credentials`): the protected
//!   place, bound read-only after the hiding, showed the real file again,
//!   with the whole home writable and, had the read-only home bound it as
//!   well, read-only;
//! - a credential place that is a named pipe (`~/.netrc` fed by a password
//!   manager, so the secret never lies on disk) or a socket: only files and
//!   folders were hidden, so the app could read the pipe.
//! - a key agent's socket in the home (1Password's, Bitwarden's, OpenSSH's
//!   in `~/.ssh/agent`): a read-only home still lets the app connect and
//!   use your unlocked keys (owner decision 11 of 2026-11-23).
//!
//! Controls show the attack would have been seen: the protected place's
//! other files are readable, and an ordinary socket in the home is seen.
//!
//! In its own file because it sets `HOME` for the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

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
cat "$H/.git-credentials" 2>/dev/null | grep -q SECRET && echo LINKED=read || echo LINKED=hidden
cat "$H/.config/git/credentials" 2>/dev/null | grep -q SECRET && echo TARGET=read || echo TARGET=hidden
cat "$H/.config/git/config" 2>/dev/null | grep -q mine && echo CONFIG=read || echo CONFIG=hidden
[ -p "$H/.netrc" ] && echo NETRC=pipe || echo NETRC=hidden
[ -S "$H/.authinfo" ] && echo AUTHINFO=socket || echo AUTHINFO=hidden
[ -S "$H/.1password/agent.sock" ] && echo ONEPASSWORD=socket || echo ONEPASSWORD=hidden
[ -S "$H/.bitwarden-ssh-agent.sock" ] && echo BITWARDEN=socket || echo BITWARDEN=hidden
[ -S "$H/.ssh/agent/s.test" ] && echo OPENSSH=socket || echo OPENSSH=hidden
[ -S "$H/plain.sock" ] && echo PLAIN=socket || echo PLAIN=hidden
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
fn credentials_behind_links_pipes_and_sockets_stay_hidden() {
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
    fs::create_dir_all(home.join(".config/git")).unwrap();
    fs::write(home.join(".config/git/config"), "# mine\n").unwrap();
    fs::write(
        home.join(".config/git/credentials"),
        "https://u:SECRET@example.org\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        home.join(".config/git/credentials"),
        home.join(".git-credentials"),
    )
    .unwrap();
    let fifo = std::ffi::CString::new(home.join(".netrc").to_str().unwrap()).unwrap();
    // SAFETY: a valid, NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0, "mkfifo");
    let _socket = std::os::unix::net::UnixListener::bind(home.join(".authinfo")).unwrap();
    fs::create_dir_all(home.join(".1password")).unwrap();
    fs::create_dir_all(home.join(".ssh/agent")).unwrap();
    let _agents: Vec<_> = [
        ".1password/agent.sock",
        ".bitwarden-ssh-agent.sock",
        ".ssh/agent/s.test",
        "plain.sock",
    ]
    .iter()
    .map(|s| std::os::unix::net::UnixListener::bind(home.join(s)).unwrap())
    .collect();
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
    for access in [Access::Rw, Access::Ro] {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = access;
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
        .unwrap_or_else(|e| panic!("the app did not start with the home {access:?}: {e:#}"));
        let r = parse(rec.log_file.as_ref().unwrap());
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "the attack ran: {r:?}"
        );
        assert_eq!(r["CONFIG"], "read", "control, home {access:?}: {r:?}");
        assert_eq!(r["PLAIN"], "socket", "control, home {access:?}: {r:?}");
        for (k, hidden) in [
            ("LINKED", "hidden"),
            ("TARGET", "hidden"),
            ("NETRC", "hidden"),
            ("AUTHINFO", "hidden"),
            ("ONEPASSWORD", "hidden"),
            ("BITWARDEN", "hidden"),
            ("OPENSSH", "hidden"),
        ] {
            assert_eq!(r[k], hidden, "{k}, home {access:?}: {r:?}");
        }
    }
}
