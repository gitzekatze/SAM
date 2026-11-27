//! A terminal program in a pipe: `cat f | sam-jail run tool`. Through the
//! real `sam-jail` binary and a real sandbox, the tool gets the piped input
//! and its output comes back byte for byte (no line end added, a very long
//! line not split), and it has no terminal of its own. Skipped when
//! Bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn sam(root: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE");
    // The same run on every computer: its own runtime folder, no desktop session.
    sam_runner::testenv::isolate_command(&mut c, root);
    c
}

/// A pipe into a terminal program passes through unchanged: the tool reads
/// the piped input, its output arrives byte for byte, and it has no
/// terminal of its own.
#[test]
fn a_pipe_into_a_terminal_program_passes_through_unchanged() {
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // A terminal tool that turns text into capitals and says whether it
    // was given a terminal.
    let apprun = root.join("AppRun");
    fs::write(
        &apprun,
        "#!/bin/sh\nif [ -t 0 ] || [ -t 1 ]; then echo HAS-A-TERMINAL >&2; fi\ntr a-z A-Z\n",
    )
    .unwrap();
    let img = root.join("Upper-1.0-x86_64.AppImage");
    let made = sam(root)
        .args([
            "dev",
            "make-fixture",
            "--name",
            "Upper",
            "--terminal",
            "--apprun",
        ])
        .arg(&apprun)
        .arg(&img)
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let added = sam(root)
        .args(["--json", "add", "--no-launcher", "--accept"])
        .arg(&img)
        .output()
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&added.stdout).unwrap();
    let v = v.get("data").unwrap_or(&v);
    let id = v["entry"]["id"]
        .as_str()
        .or(v["id"].as_str())
        .expect("id")
        .to_string();
    let saved = fs::read_to_string(root.join("data/apps").join(format!("{id}.json"))).unwrap();
    assert!(
        saved.contains("\"terminal\": true"),
        "the fixture is a terminal program: {saved}"
    );

    // A short line, a line of 100,000 characters, and a last line without
    // a line end.
    let input = format!("hello\n{}\nlast line", "a".repeat(100_000));
    let mut child = sam(root)
        .args(["run", &id])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let to_write = input.clone();
    let writer = std::thread::spawn(move || {
        // Fails only if the tool stopped reading; the checks below say why.
        let _ = stdin.write_all(to_write.as_bytes());
    });
    // A tool waiting for typing that never comes would hang: a time limit.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = done_tx.send(child.wait_with_output());
    });
    let out = match done_rx.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(out) => out.unwrap(),
        Err(_) => {
            let _ = Command::new("kill").arg(pid.to_string()).status();
            panic!("the tool never got the piped input: it still waited after 60 s");
        }
    };
    writer.join().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        out.stdout == input.to_uppercase().as_bytes(),
        "the output arrives byte for byte: {} bytes instead of {}; starts {:?}; stderr: {stderr}",
        out.stdout.len(),
        input.len(),
        String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(80)])
    );
    assert!(!stderr.contains("HAS-A-TERMINAL"), "{stderr}");
}
