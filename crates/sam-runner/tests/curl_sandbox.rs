//! SAM runs curl only in its sandbox (`updates::curl_command`): when the
//! sandbox cannot be built, an update request stops with an error that
//! says so, and curl never runs.
//!
//! In its own file because it changes the process's PATH and
//! `SAM_TRUST_TOOLS_IN` (stand-ins for Bubblewrap and curl).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::os::unix::fs::PermissionsExt;

fn script(path: &std::path::Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// An update request (here asking an app's update source what it
/// publishes) stops with the sandbox's error, and the stand-in curl never
/// runs: first with a Bubblewrap that cannot build the sandbox, then with
/// no Bubblewrap at all.
#[test]
fn an_update_request_without_curls_sandbox_sends_nothing() {
    if sam_core::util::which("objcopy").is_none() {
        sam_runner::contracts::skip("objcopy writes the test AppImage's update source")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let img = root.join("Tool-1.0-x86_64.AppImage");
    let mut spec = sam_intake::testkit::FixtureSpec::hello("Tool");
    spec.update_info = Some("zsync|https://127.0.0.1:9/Tool-x86_64.AppImage.zsync".into());
    sam_intake::testkit::build(&img, &spec).unwrap();

    let tools = root.join("tools");
    fs::create_dir_all(&tools).unwrap();
    let ran = root.join("curl-ran");
    script(
        &tools.join("curl"),
        &format!("/usr/bin/touch '{}'", ran.display()),
    );
    script(
        &tools.join("bwrap"),
        "echo 'bwrap: No permissions to create a new namespace' >&2\nexit 1",
    );
    std::env::set_var("SAM_TRUST_TOOLS_IN", &tools);
    std::env::set_var("PATH", &tools);

    let err = format!("{:#}", sam_runner::updates::newest(&img).unwrap_err());
    assert!(
        err.contains("could not start curl's sandbox, so it sent nothing")
            && err.contains("No permissions to create a new namespace"),
        "{err}"
    );
    assert!(
        !ran.exists(),
        "curl ran although its sandbox could not start"
    );

    fs::remove_file(tools.join("bwrap")).unwrap();
    let err = format!("{:#}", sam_runner::updates::newest(&img).unwrap_err());
    assert!(
        err.contains("Bubblewrap is not installed, so SAM sent nothing"),
        "{err}"
    );
    assert!(!ran.exists(), "curl ran without its sandbox");
}
