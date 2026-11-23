//! An extra socket in a folder the app may write cannot be turned into a
//! way to another socket, attacked from inside a real sandbox (review
//! 2026-11-23, SB-4): while the listed program is not running (no socket,
//! so nothing is bound there), the app puts a link in its place to a
//! socket in the real home (here a stand-in for a password manager's
//! agent), and at the next start SAM bound whatever the link named.
//!
//! The control: before the swap, the app reaches the listed socket, so a
//! connection through the link would have been seen.
//!
//! In its own file because it sets `HOME` for the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::Path;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// `connect`: connect to the listed socket and say whether it worked.
/// `swap`: put a link where the listed socket was, to the agent's socket in
/// the real home (relative, so it leads there on the host).
const PROBE_PY: &str = r#"
import os, socket
listed = os.environ["SAM_TEST_LISTED"]
if os.environ.get("SAM_TEST_STEP") == "swap":
    os.symlink(os.environ["SAM_TEST_LINK"], listed)
    print("SWAPPED=" + os.readlink(listed))
else:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(listed); s.sendall(b"pwned"); print("CONNECT=ok")
    except OSError as e:
        print("CONNECT=" + str(e.errno))
print("END=1")
"#;

const APPRUN: &str = "#!/bin/sh\nexec python3 \"$APPDIR/usr/bin/probe.py\"\n";

fn parse(log: &Path) -> HashMap<String, String> {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Whether anyone connected to `l` (it does not wait).
fn was_reached(l: &UnixListener) -> bool {
    l.set_nonblocking(true).unwrap();
    l.accept().is_ok()
}

#[test]
fn an_app_cannot_turn_its_extra_socket_into_a_link_to_another_one() {
    let host = HostInfo::probe();
    if host.tools.bwrap.is_none()
        || sam_runner::doctor::bwrap_functional(&host).is_err()
        || sam_core::util::which("python3").is_none()
    {
        sam_runner::contracts::skip("bubblewrap is not functional here, or python3 is missing")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    sam_runner::testenv::isolate_this_process(&root);
    let home = root.join("home/tester");
    let shared = home.join("Shared");
    fs::create_dir_all(&shared).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    // The listed socket, in a folder the app may write, and a socket in
    // the real home that the app must never reach. Inside the sandbox the
    // home is the app's private one, so a link to `../agent.sock` leads
    // there (where Bubblewrap can make a place for a bind).
    let listed = shared.join("app.sock");
    let listed_l = UnixListener::bind(&listed).unwrap();
    let agent = home.join("agent.sock");
    let agent_l = UnixListener::bind(&agent).unwrap();

    let img = root.join("Links-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Links");
    spec.apprun = APPRUN.into();
    spec.host_binary = None;
    spec.files.push(FixtureFile {
        path: "usr/bin/probe.py".into(),
        data: PROBE_PY.as_bytes().to_vec(),
        mode: 0o644,
    });
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
    let test_host = sam_runner::testenv::test_host(HostInfo::probe());
    let start = |step: &str| {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![shared.display().to_string()];
        p.sockets.custom = vec![listed.display().to_string()];
        for (k, v) in [
            ("SAM_TEST_STEP", step.to_string()),
            ("SAM_TEST_LISTED", listed.display().to_string()),
            ("SAM_TEST_LINK", "../agent.sock".to_string()),
        ] {
            p.environment.set.insert(k.into(), v);
        }
        let mut e = app.set_permissions(&id, p).unwrap();
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &test_host,
        )
        .unwrap();
        let log = rec.log_file.clone().unwrap();
        let r = parse(&log);
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "{step}: the probe did not finish: {}\n{}",
            rec.summary,
            fs::read_to_string(&log).unwrap_or_default()
        );
        r
    };

    // Control: the listed socket is reached while it is one.
    let r = start("connect");
    assert_eq!(r["CONNECT"], "ok", "the listed socket is passed in");
    assert!(
        was_reached(&listed_l),
        "the listed socket's program was reached"
    );
    assert!(!was_reached(&agent_l));

    // The listed program stops (its socket goes), the app puts a link in
    // its place, and starts again.
    drop(listed_l);
    fs::remove_file(&listed).unwrap();
    let r = start("swap");
    assert_eq!(r["SWAPPED"], "../agent.sock");
    assert!(fs::symlink_metadata(&listed)
        .unwrap()
        .file_type()
        .is_symlink());
    let r = start("connect");
    assert_ne!(
        r["CONNECT"], "ok",
        "the app reached a socket through its link"
    );
    assert!(
        !was_reached(&agent_l),
        "the socket in the real home was reached through the app's link"
    );
}
