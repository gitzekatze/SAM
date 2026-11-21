//! A test that cannot run says so, and never silently in CI: `skip()` is an
//! error where the run must prove everything (`SAM_REQUIRE_SANDBOX=1`) and
//! otherwise writes a line to the skip log, and `not_here()` always writes
//! one (CI compares those lines with tests/expected-not-here.toml).
//! Mutation run P14 (2026-11-20): a `skip()` that always allowed, or a
//! `not_here()` that wrote nothing, went unnoticed; either would let a test
//! pass without checking anything.
//!
//! Both read the environment, so they are run in a child process with its
//! own: changing it in this process would change it for every other test.
#![allow(clippy::unwrap_used)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // the child's answer to its parent

use std::process::Command;

use sam_runner::contracts::{not_here, skip};

const ME: &str = "skips_are_refused_in_ci_and_always_written_down";
const CHILD: &str = "SAM_TEST_SKIP_CHILD";

/// In the child: what the two helpers do with this environment.
fn as_the_child() {
    let verdict = skip("a requirement is missing");
    not_here("another processor");
    println!(
        "verdict: {}",
        if verdict.is_ok() {
            "allowed"
        } else {
            "refused"
        }
    );
}

#[test]
fn skips_are_refused_in_ci_and_always_written_down() {
    if std::env::var_os(CHILD).is_some() {
        as_the_child();
        return;
    }
    let d = tempfile::tempdir().unwrap();
    // (SAM_REQUIRE_SANDBOX, skip's verdict, lines in the skip log)
    for (required, want, lines) in [("1", "refused", 1), ("0", "allowed", 2)] {
        let log = d.path().join(format!("skips-{required}.log"));
        let out = Command::new(std::env::current_exe().unwrap())
            .args([ME, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("SAM_REQUIRE_SANDBOX", required)
            .env("SAM_SKIP_LOG", &log)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && text.contains(&format!("verdict: {want}")),
            "SAM_REQUIRE_SANDBOX={required}: skip() is {want}\n{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let written = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(
            written.lines().count(),
            lines,
            "SAM_REQUIRE_SANDBOX={required}: lines in the skip log\n{written}"
        );
        assert!(
            written.contains(": not here: another processor"),
            "not_here() is written down\n{written}"
        );
        if required == "0" {
            assert!(
                written.contains(": a requirement is missing"),
                "an allowed skip is written down\n{written}"
            );
        }
    }
}
