//! A start that lacks a protection layer its settings ask for is never
//! silent. SAM's helper (`sam-jail-run`), which applies seccomp and Landlock
//! inside the sandbox, is left out on purpose: the app still starts in its
//! Bubblewrap sandbox, and its record and its overview status say which
//! layers were missing. Skipped when Bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::process::{Command, Stdio};

fn bwrap_works() -> bool {
    Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-user",
            "--unshare-pid",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn json(out: &std::process::Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.lines().last().unwrap_or("null")).unwrap()
}

#[test]
fn a_start_without_the_helper_reports_its_missing_layers() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // With SAM installed in /usr, sam-jail finds that helper on the PATH
    // below, so a start without the helper cannot be shown on this computer.
    if ["/usr/bin/sam-jail-run", "/bin/sam-jail-run"]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        sam_runner::contracts::skip(
            "an installed SAM's helper is in /usr/bin, so a start without it cannot be shown here",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // The same run on every computer (the only test here, so its process).
    sam_runner::testenv::isolate_this_process(root);
    // sam-jail alone, without sam-jail-run next to it.
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), bin.join("sam-jail")).unwrap();
    let sam = |args: &[&str]| {
        Command::new(bin.join("sam-jail"))
            .args(args)
            .env("SAM_CONFIG_DIR", root.join("config"))
            .env("SAM_DATA_DIR", root.join("data"))
            .env("SAM_APPLICATIONS_DIR", root.join("applications"))
            .env("LC_ALL", "C")
            .env_remove("LANGUAGE")
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap()
    };
    let img = root.join("Quick-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    assert!(sam(&["dev", "make-fixture", "--name", "Quick", img_s])
        .status
        .success());
    assert!(sam(&["add", img_s, "--no-launcher"]).status.success());
    let id = json(&sam(&["--json", "list"]))["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    // Settings nobody has confirmed do not start (audit U-M11).
    assert!(sam(&["review", &id]).status.success());
    let run = sam(&["run", &id]);
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(
        err.contains("this start ran without"),
        "the command line warns: {err}"
    );
    let info = json(&sam(&["--json", "info", &id]));
    let entry = &info["data"]["entry"];
    let missing: Vec<&str> = entry["last_launch"]["missing_layers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(missing.contains(&"seccomp"), "recorded: {missing:?}");
    let list = json(&sam(&["--json", "list"]));
    assert_eq!(list["data"][0]["badge"], "protection-missing", "{list}");
}

/// A tiny syscall filter of the test's own: loading another filter
/// (`seccomp()`, or `prctl(PR_SET_SECCOMP)`) fails with EPERM, everything
/// else is allowed. Under it, SAM's helper cannot load its filter.
fn no_more_filters() -> Vec<libc::sock_filter> {
    let op = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    const LD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RET: u16 = 0x06; // BPF_RET | BPF_K
    vec![
        op(LD, 0, 0, 0),                            // the call's number
        op(JEQ, 4, 0, libc::SYS_seccomp as u32),    // seccomp() → refuse
        op(JEQ, 0, 2, libc::SYS_prctl as u32),      // prctl() → look closer
        op(LD, 0, 0, 16),                           // its first argument
        op(JEQ, 1, 0, libc::PR_SET_SECCOMP as u32), // PR_SET_SECCOMP → refuse
        op(RET, 0, 0, libc::SECCOMP_RET_ALLOW),     // anything else
        op(RET, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ]
}

/// Threat model row 52: "a syscall filter that fails to load stops the
/// start". SAM's real helper is started as in a sandbox, asked for its
/// filter, while the kernel refuses every new filter: the app must not run
/// (verification audit 2026-11-19: no test showed it). The same start
/// without the refusal runs the app, so the refusal is what stops it.
#[test]
fn a_syscall_filter_that_fails_to_load_stops_the_start() {
    use std::os::unix::process::CommandExt;
    let tmp = tempfile::tempdir().unwrap();
    let spec = tmp.path().join("spec.json");
    fs::write(
        &spec,
        r#"{"landlock": null, "seccomp": {"strict": false, "allow_userns": false}}"#,
    )
    .unwrap();
    let marker = tmp.path().join("the-app-ran");
    let start = |refuse_filters: bool| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail-run"));
        c.arg("--sandbox-exec")
            .arg(&spec)
            .args(["--", "/bin/sh", "-c", "echo yes > \"$0\""])
            .arg(&marker)
            .stdin(Stdio::null());
        if refuse_filters {
            let prog = no_more_filters();
            // SAFETY: between fork and exec the closure only calls prctl,
            // which is async-signal-safe, on a program that lives as long
            // as the closure (moved into it).
            unsafe {
                c.pre_exec(move || {
                    let f = libc::sock_fprog {
                        len: prog.len() as u16,
                        filter: prog.as_ptr().cast_mut(),
                    };
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        || libc::prctl(
                            libc::PR_SET_SECCOMP,
                            libc::SECCOMP_MODE_FILTER,
                            &raw const f,
                        ) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        c.output().unwrap()
    };

    let out = start(false);
    assert!(
        out.status.success() && marker.exists(),
        "with the filter loaded, the app runs: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::remove_file(&marker).unwrap();

    let out = start(true);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the start fails: {err}");
    assert!(!marker.exists(), "the app never ran without its filter");
    assert!(err.contains("seccomp"), "the error names the filter: {err}");
}
