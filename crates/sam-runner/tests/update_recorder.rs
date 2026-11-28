//! The recording server of the update tests (`update_common`) writes down
//! every request, whatever its method, so the privacy test
//! (update_privacy.rs) cannot miss a request that is not a GET.
//!
//! In its own file because the server sets process-wide variables
//! (`update_common::start_server`).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

mod update_common;

use std::fs;
use std::process::Command;

use update_common::server_or_skip;

/// HEAD, POST and PUT requests, sent here with curl to the recording
/// server, are all in its request log, with their request lines.
#[test]
fn the_recording_server_records_every_method() {
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let Some((server, _)) = server_or_skip(&root) else {
        return;
    };
    let url = format!("https://127.0.0.1:{}/anything", server.port);
    for args in [
        &["--head"][..],
        &["-X", "POST", "--data", "x"],
        &["-X", "PUT", "--data", "x"],
    ] {
        // --disable: the server's test ~/.curlrc names a dead proxy.
        let st = Command::new("curl")
            .args([
                "--disable",
                "--silent",
                "--output",
                "/dev/null",
                "--max-time",
                "20",
            ])
            .args(args)
            .arg(&url)
            .status()
            .unwrap();
        assert!(st.code().is_some(), "curl {args:?} did not end");
    }
    let log = fs::read_to_string(format!("{}.headers", server.log.display())).unwrap_or_default();
    let lines: Vec<String> = log
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["line"].as_str().unwrap().to_string()
        })
        .collect();
    for m in ["HEAD", "POST", "PUT"] {
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with(&format!("{m} /anything "))),
            "the recording server did not record a {m} request: {lines:?}"
        );
    }
}
