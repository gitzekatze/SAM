//! `sam-jail man DIR` writes the man pages the release ships: one for
//! `sam-jail` and one per visible command, none for the hidden developer
//! commands (`man`, `dev`). Needs no sandbox.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::process::{Command, Stdio};

#[test]
fn man_writes_a_page_per_visible_command_and_none_for_hidden_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("man");
    let o = Command::new(env!("CARGO_BIN_EXE_sam-jail"))
        .arg("man")
        .arg(&dir)
        .env("SAM_CONFIG_DIR", tmp.path().join("config"))
        .env("SAM_DATA_DIR", tmp.path().join("data"))
        .env("HOME", tmp.path().join("home"))
        .env("SAM_MAN_DATE", "2026-01-02")
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let page = |name: &str| std::fs::read_to_string(dir.join(name)).ok();
    let main = page("sam-jail.1").expect("the page of sam-jail");
    assert!(
        main.lines()
            .any(|l| l.starts_with(".TH sam-jail 1 2026-01-02")),
        "{main}"
    );
    for visible in ["add", "run", "set", "list"] {
        let p = page(&format!("sam-jail-{visible}.1"))
            .unwrap_or_else(|| panic!("no page for sam-jail {visible}"));
        assert!(
            p.lines()
                .any(|l| l.starts_with(&format!(".TH sam-jail-{visible} 1 2026-01-02"))),
            "{visible}: {p}"
        );
    }
    for hidden in ["man", "dev"] {
        assert!(
            page(&format!("sam-jail-{hidden}.1")).is_none(),
            "a page for the hidden command {hidden}"
        );
    }
}
