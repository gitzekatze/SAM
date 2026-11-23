//! The guard the GnuPG tests use (`gpg_agent::Stop`) stops the test's
//! gpg-agent also when the test fails partway: before, the older GnuPG
//! tests stopped it only on their last line, so a failed assertion left an
//! agent running and its socket folder behind.
//!
//! Runs only with SAM_TEST_GPG=1 (CI sets it; then a missing gpgconf fails
//! the test instead of skipping it).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

mod gpg_agent;

use std::path::PathBuf;
use std::process::Command;

/// Whether an agent answers for the GnuPG folder `home`.
fn agent_answers(home: &std::path::Path) -> bool {
    gpg_agent::pid(home).is_some()
}

/// A test that panics while it holds the guard leaves no gpg-agent
/// running and no socket folder behind.
#[test]
fn a_test_that_fails_partway_leaves_no_gpg_agent_running() {
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") {
        sam_runner::contracts::skip("set SAM_TEST_GPG=1 (with gpg installed)")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    assert!(
        ["gpgconf", "gpg-connect-agent", "gpg-agent"]
            .iter()
            .all(|t| sam_core::util::which(t).is_some()),
        "SAM_TEST_GPG=1, but gpgconf, gpg-connect-agent or gpg-agent is not installed"
    );
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("gnupg");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let launched = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&home)
        .args(["--launch", "gpg-agent"])
        .status()
        .unwrap();
    let socket_dir = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&home)
        .args(["--list-dirs", "socketdir"])
        .output()
        .unwrap();
    let socket_dir = PathBuf::from(String::from_utf8(socket_dir.stdout).unwrap().trim());
    let running_before = launched.success() && agent_answers(&home);

    // A test that holds the guard and fails partway.
    let failed = std::panic::catch_unwind(|| {
        let _agent = gpg_agent::Stop::new(&home);
        panic!("a test that fails partway");
    });

    // The folder first: asking GnuPG anything may make it again.
    let socket_dir_left = !socket_dir.starts_with(&home) && socket_dir.exists();
    let running_after = agent_answers(&home);
    // Whatever the outcome, nothing of this test stays running.
    gpg_agent::stop(&home);
    assert!(running_before, "the agent did not start for {home:?}");
    assert!(failed.is_err(), "the stand-in test did not fail");
    assert!(!running_after, "the agent outlived the failed test");
    assert!(!socket_dir_left, "{socket_dir:?} stays behind");
}
