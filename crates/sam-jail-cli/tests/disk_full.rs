//! Regression (review 2026-11-23, F2): a full disk was never recognized
//! when unpacking ran in its sandbox. The reader's "No space left on
//! device" went only to the log and SAM saw "exited with 1", so it filled
//! the disk again with the next tool and then offered to let the AppImage
//! unpack itself, the weaker way, for a problem that is just a full disk.
//! Here `sam-jail add` unpacks, in its real sandbox, onto a file system of
//! 80 MiB (a tmpfs in namespaces of the test's own) an app that needs
//! 120 MiB: SAM says the disk became full and offers nothing else.
//!
//! Needs Bubblewrap and util-linux's `unshare` with user namespaces; with
//! SAM_REQUIRE_SANDBOX=1 (CI) a missing one fails the test.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Runs `args` with a fresh 80 MiB file system at `small`, as the user
/// (a namespace that maps the user to root mounts it, a second one inside
/// maps the user back, so Bubblewrap and SAM's checks see an ordinary
/// user). `env` is set for the program.
fn on_small_disk(small: &Path, args: &[&str], env: &[(&str, &Path)]) -> std::io::Result<Output> {
    // SAFETY: getuid and getgid have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let mut c = Command::new("unshare");
    c.args(["--user", "--map-root-user", "--mount", "sh", "-c"])
        .arg(
            "mount -t tmpfs -o size=80m tmpfs \"$1\" && shift && \
             exec unshare --user --map-user=\"$SAM_T_UID\" --map-group=\"$SAM_T_GID\" \"$@\"",
        )
        .arg("sh")
        .arg(small)
        .args(args)
        .env("SAM_T_UID", uid.to_string())
        .env("SAM_T_GID", gid.to_string())
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null());
    for (k, v) in env {
        c.env(k, v);
    }
    c.output()
}

#[test]
fn a_full_disk_in_the_unpack_sandbox_stops_unpacking() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["bin", "run", "data", "probe"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let probe = on_small_disk(&root.join("probe"), &["bwrap", "--ro-bind", "/", "/", "true"], &[]);
    if !probe.as_ref().is_ok_and(|o| o.status.success()) {
        sam_runner::contracts::skip(&format!(
            "no small file system of the test's own here (unshare and Bubblewrap in user namespaces): {probe:?}"
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let sam = root.join("bin/sam-jail");
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), &sam).unwrap();
    // 120 MiB of text: a small AppImage that unpacks to more than the disk.
    let apprun = root.join("apprun");
    fs::write(
        &apprun,
        format!("#!/bin/sh\n{}", format!("{}\n", "x".repeat(1023)).repeat(120 * 1024)),
    )
    .unwrap();
    let img = root.join("Big-1.0-x86_64.AppImage");
    let made = Command::new(&sam)
        .args(["dev", "make-fixture", "--name", "Big", "--apprun"])
        .arg(&apprun)
        .arg(&img)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    assert!(fs::metadata(&img).unwrap().len() < 4 * 1024 * 1024);

    let out = on_small_disk(
        &root.join("data"),
        &[sam.to_str().unwrap(), "add", img.to_str().unwrap(), "--no-launcher"],
        &[
            ("SAM_CONFIG_DIR", &root.join("config")),
            ("SAM_DATA_DIR", &root.join("data")),
            ("SAM_APPLICATIONS_DIR", &root.join("applications")),
            ("XDG_RUNTIME_DIR", &root.join("run")),
        ],
    )
    .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("The disk became full"), "{text}");
    assert!(
        !text.contains("unpack itself"),
        "a full disk is no reason to let the AppImage unpack itself: {text}"
    );
}
