//! The overview reads the name and icon of every AppImage in the scanned
//! folders before anyone agreed to anything, so it reads them in a sandbox
//! with limits (audit I-F7). Here stand-ins play a reader that a crafted
//! image has gone wrong in: one wants more memory than allowed, one hangs,
//! one hands back an icon that is a decode bomb. Each comes to nothing,
//! and SAM itself carries on. Fails instead of skipping where CI must test
//! the sandbox (SAM_REQUIRE_SANDBOX=1).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use sam_intake::extract::Isolation;
use sam_intake::peek::peek_isolated;

fn bwrap_works() -> Option<PathBuf> {
    let bwrap = sam_core::util::which("bwrap")?;
    Command::new(&bwrap)
        .args(["--ro-bind", "/", "/", "true"])
        .status()
        .ok()?
        .success()
        .then_some(bwrap)
}

/// The preview sandbox with `reader` in place of SAM's own reader.
fn sandbox(bwrap: PathBuf, reader: &Path) -> Isolation {
    Isolation {
        bwrap,
        self_exe: reader.to_path_buf(),
        system: sam_sandbox::helper_system_args(&sam_core::HostInfo::probe()),
        filter: None,
    }
}

/// A stand-in reader: a shell script; `$4` is the folder for its answer.
fn reader(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, format!("#!/bin/sh\nout=\"$4\"\n{body}\n")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p
}

const ANSWER: &str = r#"printf '{"metadata":{"name":"Answered"},"icon":"png"}' > "$out/peek.json""#;

#[test]
fn a_reader_gone_wrong_comes_to_nothing() {
    let Some(bwrap) = bwrap_works() else {
        assert!(
            std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
            "SAM_REQUIRE_SANDBOX=1, but Bubblewrap does not work here"
        );
        eprintln!("skipped: Bubblewrap does not work here");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let image = d.join("Some.AppImage");
    fs::write(&image, b"not really").unwrap();

    // A well-behaved stand-in: its answer comes back.
    let fine = reader(d, "fine", ANSWER);
    let p = peek_isolated(&sandbox(bwrap.clone(), &fine), &image).unwrap();
    assert_eq!(p.metadata.name, "Answered");

    // It needs 1.5 GiB before it answers: more than the sandbox may use.
    let greedy = reader(
        d,
        "greedy",
        &format!("python3 -c 'x = b\"x\" * (1536 * 1024 * 1024)' || exit 1\n{ANSWER}"),
    );
    assert!(
        peek_isolated(&sandbox(bwrap.clone(), &greedy), &image).is_err(),
        "a reader that used 1.5 GiB was let through"
    );

    // It never ends: it is stopped at the time limit.
    let slow = reader(d, "slow", "sleep 300");
    let started = Instant::now();
    assert!(peek_isolated(&sandbox(bwrap.clone(), &slow), &image).is_err());
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );

    // It answers with an icon whose header asks for 65535×65535 pixels:
    // the name comes back, the icon does not.
    let bomb = reader(
        d,
        "bomb",
        &format!(
            "{ANSWER}\nprintf '\\211PNG\\r\\n\\032\\n\\000\\000\\000\\rIHDR\\000\\000\\377\\377\\000\\000\\377\\377\\010\\006\\000\\000\\000' > \"$out/icon\""
        ),
    );
    let p = peek_isolated(&sandbox(bwrap, &bomb), &image).unwrap();
    assert_eq!(p.metadata.name, "Answered");
    assert!(p.icon.is_none(), "the decode bomb came back as an icon");
}
