//! Threat-model row 46 with the real thing: `sam-jail run` starts a
//! terminal program in its real sandbox from a terminal, and the app tries
//! every known way to reach past it (audit D-M10: the tests named as proof
//! ran without a sandbox or without a terminal, so they passed without the
//! protection; L-F1: escape codes got past the filter). A pseudo-terminal
//! plays the person's terminal; the test reads exactly what it would get.
//! Skipped when Bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

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

fn cmd(root: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env("PATH", "/usr/bin:/bin");
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    c
}

fn sam(root: &Path, args: &[&str]) -> Output {
    cmd(root, args).stdin(Stdio::null()).output().unwrap()
}

/// A terminal pair: (leader, follower). The follower is the person's
/// terminal as SAM sees it; the test reads what it shows at the leader.
fn terminal() -> (OwnedFd, OwnedFd) {
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let (mut l, mut f) = (-1, -1);
    // SAFETY: `l` and `f` are valid ints to fill, `size` a valid winsize.
    let r = unsafe {
        libc::openpty(
            &mut l,
            &mut f,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    assert_eq!(r, 0, "openpty");
    for fd in [l, f] {
        // SAFETY: one of the two descriptors openpty just created.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    // SAFETY: openpty returned two new descriptors that nothing else owns.
    unsafe { (OwnedFd::from_raw_fd(l), OwnedFd::from_raw_fd(f)) }
}

fn name_of(fd: RawFd) -> String {
    let mut buf = [0u8; 128];
    // SAFETY: `buf` is writable for its length and `fd` is an open terminal.
    let r = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(r, 0, "ttyname");
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn has(out: &[u8], needle: &[u8]) -> bool {
    out.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_sandboxed_terminal_app_cannot_reach_past_the_terminal() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["config", "home"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    // The app: every known way past the old filter, then the name of its
    // terminal.
    let script = root.join("apprun");
    fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf 'hello|'\n",
            // A doubled ESC in front of a clipboard code.
            "printf '\\033\\033]52;c;eA==\\007]52;c;ZGF0YQ==\\007|'\n",
            // An ESC inside a control sequence.
            "printf '\\033[\\033]52;c;eA==\\007|'\n",
            // A title report with an extra parameter.
            "printf '\\033]2;rm -rf ~\\007\\033[21;0t|'\n",
            // The UTF-8 form of an 8-bit CSI.
            "printf '\\302\\23321t|'\n",
            // tmux passthrough, a notification, programmable keys.
            "printf '\\033Ptmux;\\033\\033]52;c;eA==\\007\\033\\\\|'\n",
            "printf '\\033]9;hi\\007|\\033P0;1|17/726d\\033\\\\|'\n",
            "printf '\\033[?1000h\\033[?2004h'\n",
            "printf '\\nits terminal: '; tty\n",
            "printf 'END-MARK\\n'\n",
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let img = root.join("Term-1.0-x86_64.AppImage");
    let (img_s, script_s) = (img.to_str().unwrap(), script.to_str().unwrap());
    assert!(sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            "Term",
            "--terminal",
            "--apprun",
            script_s,
            img_s
        ]
    )
    .status
    .success());
    let add = sam(root, &["--json", "add", img_s, "--no-launcher", "--accept"]);
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(
        add.stdout
            .split(|b| *b == b'\n')
            .rfind(|l| !l.is_empty())
            .unwrap(),
    )
    .unwrap();
    let id = v["data"]["app"]["id"].as_str().unwrap().to_string();

    // Started from "the person's terminal".
    let (leader, follower) = terminal();
    let outer_name = name_of(follower.as_raw_fd());
    let mut c = cmd(root, &["run", &id]);
    let fd = follower.as_raw_fd();
    // SAFETY: dup returns new descriptors for the open follower.
    let (i, o, e) = unsafe { (libc::dup(fd), libc::dup(fd), libc::dup(fd)) };
    // SAFETY: each is a fresh descriptor nothing else owns.
    unsafe {
        c.stdin(Stdio::from(OwnedFd::from_raw_fd(i)))
            .stdout(Stdio::from(OwnedFd::from_raw_fd(o)))
            .stderr(Stdio::from(OwnedFd::from_raw_fd(e)));
        // The person's terminal is SAM's controlling terminal.
        c.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = c.spawn().unwrap();
    drop(c);
    drop(follower);
    let mut seen = Vec::new();
    let end = Instant::now() + Duration::from_secs(60);
    let mut buf = [0u8; 4096];
    loop {
        let mut p = libc::pollfd {
            fd: leader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&mut p, 1, 200) } > 0;
        if ready {
            // SAFETY: `buf` is writable for its length.
            let n = unsafe { libc::read(leader.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                seen.extend_from_slice(&buf[..n as usize]);
                continue;
            }
            // EIO: SAM and the app have closed the terminal.
            break;
        }
        if child.try_wait().unwrap().is_some() || Instant::now() > end {
            break;
        }
    }
    let status = child.wait().unwrap();
    let text = String::from_utf8_lossy(&seen).into_owned();
    assert!(
        has(&seen, b"END-MARK"),
        "the app ran to its end ({status}): {text:?}"
    );
    assert!(has(&seen, b"hello|"), "{text:?}");
    for (bad, what) in [
        (&b"\x1b]52"[..], "a clipboard code"),
        (b"\x1b[21", "a title report"),
        (&[0xc2, 0x9b], "an 8-bit CSI"),
        (
            b"\x1bP",
            "a device control string (tmux, programmable keys)",
        ),
        (b"\x1b]9;", "a notification"),
    ] {
        assert!(!has(&seen, bad), "{what} reached the terminal: {text:?}");
    }
    // The title may be set; asking for it back is what was removed.
    assert!(has(&seen, b"\x1b]2;rm -rf ~\x07"), "{text:?}");
    // Modes the app left on are switched off when it ends.
    assert!(
        has(&seen, b"\x1b[?1000l") && has(&seen, b"\x1b[?2004l"),
        "{text:?}"
    );
    // It has a terminal of its own, not the person's: what it printed
    // arrived filtered, which only SAM's relay does (inside the sandbox
    // its terminal is called /dev/console).
    let line = text
        .lines()
        .find(|l| l.contains("its terminal: "))
        .unwrap_or_else(|| panic!("{text:?}"));
    let its = line.split("its terminal: ").nth(1).unwrap().trim();
    assert_ne!(its, outer_name, "the app had the person's terminal");
}

/// Runs `sam-jail` with its output on a terminal (no input) and returns
/// everything that terminal received.
fn on_terminal(root: &Path, args: &[&str]) -> (std::process::ExitStatus, Vec<u8>) {
    let (leader, follower) = terminal();
    let mut c = cmd(root, args);
    let fd = follower.as_raw_fd();
    // SAFETY: dup returns new descriptors for the open follower.
    let (o, e) = unsafe { (libc::dup(fd), libc::dup(fd)) };
    // SAFETY: each is a fresh descriptor nothing else owns.
    unsafe {
        c.stdin(Stdio::null())
            .stdout(Stdio::from(OwnedFd::from_raw_fd(o)))
            .stderr(Stdio::from(OwnedFd::from_raw_fd(e)));
    }
    let mut child = c.spawn().unwrap();
    drop(c);
    drop(follower);
    let mut seen = Vec::new();
    let end = Instant::now() + Duration::from_secs(60);
    let mut buf = [0u8; 4096];
    loop {
        let mut p = libc::pollfd {
            fd: leader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        if unsafe { libc::poll(&mut p, 1, 200) } > 0 {
            // SAFETY: `buf` is writable for its length.
            let n = unsafe { libc::read(leader.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                seen.extend_from_slice(&buf[..n as usize]);
                continue;
            }
            break;
        }
        if child.try_wait().unwrap().is_some() || Instant::now() > end {
            break;
        }
    }
    (child.wait().unwrap(), seen)
}

/// What SAM itself prints about an app (G-F5, L-F3, I-F11, I-F12): the
/// name of its file, the failure summary taken from its error output, its
/// log. All of it is the app's text, and none of it may bring a clipboard
/// code, a title or a direction override to the person's terminal. The
/// app's own output is filtered too; it sends nothing the filter lets
/// through, so whatever arrives came from SAM's lines.
#[test]
fn what_sam_prints_about_an_app_cannot_reach_past_the_terminal() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["config", "home", "downloads"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let evil = "\x1b]52;c;ZGF0YQ==\x07\x1b]2;owned\x07\u{202E}";
    // The app fails with an error line that looks like Bubblewrap's.
    let script = root.join("apprun");
    fs::write(
        &script,
        "#!/bin/sh\nprintf 'bwrap: \\033]52;c;ZGF0YQ==\\007 no\\n' >&2\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let img = root.join(format!("downloads/Evil{evil}-1.0-x86_64.AppImage"));
    let (img_s, script_s) = (img.to_str().unwrap(), script.to_str().unwrap());
    assert!(sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            "Evil",
            "--apprun",
            script_s,
            img_s
        ]
    )
    .status
    .success());
    let downloads = root.join("downloads");
    let mut seen = Vec::new();
    let mut step = |args: &[&str]| {
        let (status, out) = on_terminal(root, args);
        seen.extend_from_slice(&out);
        (status, String::from_utf8_lossy(&out).into_owned())
    };
    let (_, scan) = step(&["scan", downloads.to_str().unwrap()]);
    assert!(scan.contains("Evil"), "the scan names the file: {scan:?}");
    let (st, add) = step(&["add", img_s, "--no-launcher", "--accept"]);
    assert!(st.success(), "{add:?}");
    let list = sam(root, &["--json", "list"]);
    let v: serde_json::Value = serde_json::from_slice(
        list.stdout
            .split(|b| *b == b'\n')
            .rfind(|l| !l.is_empty())
            .unwrap(),
    )
    .unwrap();
    let id = v["data"][0]["id"].as_str().unwrap().to_string();
    let (_, info) = step(&["info", &id]);
    assert!(info.contains("Evil"), "info names the file: {info:?}");
    let (st, run) = step(&["run", &id]);
    assert!(!st.success(), "the app fails: {run:?}");
    let (_, logs) = step(&["logs", &id, "--kind", "launch"]);
    assert!(
        logs.contains("bwrap: "),
        "the log holds the app's line: {logs:?}"
    );

    let text = String::from_utf8_lossy(&seen).into_owned();
    for (bad, what) in [
        (&b"\x1b]52"[..], "a clipboard code"),
        (b"\x1b]2;", "a window title"),
        (b"\x07", "a bell (the end of a string sequence)"),
        ("\u{202E}".as_bytes(), "a direction override"),
    ] {
        assert!(!has(&seen, bad), "{what} reached the terminal: {text:?}");
    }

    // The log on disk and its JSON hold only the text.
    let logs = sam(root, &["--json", "logs", &id]);
    assert!(
        !has(&logs.stdout, b"\x1b"),
        "{:?}",
        String::from_utf8_lossy(&logs.stdout)
    );
    let dir = root.join("data/logs");
    for f in walk(&dir) {
        let data = fs::read(&f).unwrap();
        assert!(!has(&data, b"\x1b"), "{} keeps an escape code", f.display());
    }
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
