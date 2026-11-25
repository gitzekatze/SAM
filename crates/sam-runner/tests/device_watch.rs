//! A game controller unplugged while the app runs is taken out of the real
//! sandbox, and the app keeps running (review R56, owner decision C of
//! 2026-11-25). Before, the bound node stayed: opening it reached the next
//! device that got its number, possibly a keyboard.
//!
//! Stand-ins: the "controller" is `/dev/null`, shown inside a real
//! Bubblewrap sandbox (with SAM's namespace options) at a name whose link
//! on the computer is then removed (unplugged) or pointed at `/dev/zero`
//! (another device at the name). The removal itself is real: SAM enters
//! the sandbox's namespaces and removes the bind. With "This computer
//! only" the sandbox runs inside pasta, which gives it its own process
//! numbers, so that case runs too. Where taking the node out is not enough,
//! SAM ends the whole sandbox instead, also inside pasta. A whole start
//! through SAM's launcher (with Landlock, which taking out relies on) is in
//! device_watch_launch.rs. Tests that end a sandbox run only on an
//! isolated computer (`SAM_ISOLATED=1`: CI, the test container), never on a
//! desktop (incident 2026-11-25).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::io::{BufRead, BufReader, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use sam_core::sandbox::WatchedDevice;
use sam_runner::device_watch::{end_launched, DeviceWatch, Unplugged};

/// Inside the sandbox: says every 0.1 s whether the node is still a
/// device, for at most 20 s (then the sandbox ends by itself).
const LOOP: &str = r#"i=0; while [ $i -lt 200 ]; do if [ -c "$1" ]; then echo device; else echo gone; fi; sleep 0.1; i=$((i+1)); done"#;

struct Running {
    child: Child,
    out: BufReader<ChildStdout>,
    status: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    /// The next line the app printed.
    fn line(&mut self) -> String {
        let mut l = String::new();
        self.out.read_line(&mut l).unwrap();
        l.trim().to_string()
    }
}

/// Bubblewrap (inside pasta when `pasta`) with `/dev/null` shown at `node`,
/// its status line read through a FIFO as SAM does for pasta.
fn start(dir: &Path, node: &Path, pasta: bool) -> Running {
    let fifo = dir.join("status");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a valid C string and a mode.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let n = node.to_str().unwrap();
    let mut args: Vec<&str> = Vec::new();
    if pasta {
        args.extend([
            "pasta",
            "--quiet",
            "--splice-only",
            "-T",
            "none",
            "-u",
            "none",
            "-U",
            "none",
            "-t",
            "none",
            "--",
        ]);
    }
    let f = fifo.to_str().unwrap();
    args.extend([
        "/bin/sh",
        "-c",
        r#"exec 3>"$1"; shift; exec "$@""#,
        "sh",
        f,
        "bwrap",
        "--json-status-fd",
        "3",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--die-with-parent",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--dev-bind",
        "/dev/null",
        n,
        "--remount-ro",
        "/",
        "--",
        "/bin/sh",
        "-c",
        LOOP,
        "sh",
        n,
    ]);
    let mut child = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    // Never waits for a status line that cannot come: opened without
    // waiting for a writer, read once Bubblewrap wrote, and given up when
    // the sandbox has ended or after 30 s.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let started = Instant::now();
    loop {
        let mut pfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        if unsafe { libc::poll(&mut pfd, 1, 100) } > 0 && pfd.revents & libc::POLLIN != 0 {
            break;
        }
        if let Some(st) = child.try_wait().unwrap() {
            panic!("the sandbox ended before it reported itself: {st}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "no status line from Bubblewrap"
        );
    }
    // Bubblewrap may write its line in pieces: read the rest waiting.
    // SAFETY: clears the flags of a descriptor this test owns.
    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, 0) };
    let mut status = String::new();
    BufReader::new(file).read_line(&mut status).unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    let mut r = Running { child, out, status };
    assert!(r.status.contains("child-pid"), "no sandbox: {:?}", r.status);
    assert_eq!(r.line(), "device", "the stand-in controller is shown");
    r
}

fn watched(path: &Path) -> WatchedDevice {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).unwrap();
    WatchedDevice {
        path: path.to_path_buf(),
        dev: m.dev(),
        ino: m.ino(),
        rdev: m.rdev(),
    }
}

/// Taking out, as SAM does it where its helper reported Landlock in place
/// (here a stand-in report: this sandbox is Bubblewrap's alone).
fn take_out() -> Unplugged {
    Unplugged::TakeOut {
        helper_report: Arc::new(Mutex::new(Some("landlock: fully enforced".into()))),
    }
}

/// `change` unplugs the stand-in; the node must be gone inside within a
/// few seconds, while the app keeps running.
fn taken_out_after(change: fn(&Path), pasta: bool) {
    let dir = tempfile::tempdir().unwrap();
    // A name the sandbox's own /tmp holds too (its parents are made there).
    let node: PathBuf = dir.path().join("input").join("event99");
    std::fs::create_dir(dir.path().join("input")).unwrap();
    std::os::unix::fs::symlink("/dev/null", &node).unwrap();
    let mut app = start(dir.path(), &node, pasta);
    let (tx, rx) = mpsc::channel();
    let ended = Arc::new(AtomicBool::new(false));
    let e = ended.clone();
    let watch = DeviceWatch::start(
        vec![watched(&node)],
        rx,
        take_out(),
        Box::new(move || e.store(true, Ordering::SeqCst)),
    )
    .unwrap();
    tx.send(app.status.trim().to_string()).unwrap();
    // Still shown while it is plugged in and watched.
    std::thread::sleep(Duration::from_millis(300));
    for _ in 0..3 {
        assert_eq!(app.line(), "device", "taken out while still plugged in");
    }
    change(&node);
    let start = Instant::now();
    loop {
        let l = app.line();
        if l == "gone" {
            break;
        }
        assert_eq!(l, "device", "the app ended early");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the unplugged controller is still in the sandbox"
        );
    }
    // The app keeps running.
    assert_eq!(app.line(), "gone");
    assert!(app.child.try_wait().unwrap().is_none(), "the app was ended");
    let report = watch.finish();
    assert!(!report.ended_app && !ended.load(Ordering::SeqCst));
    assert_eq!(report.lines.len(), 1, "{:?}", report.lines);
    assert!(
        report.lines[0].contains("taken out of the sandbox"),
        "{:?}",
        report.lines
    );
    let mut rest = String::new();
    let _ = app.child.kill();
    let _ = app.out.read_to_string(&mut rest);
}

/// Where taking the node out is not enough, an unplugged controller ends
/// the whole sandbox at once: no process of it is left.
fn ended_after_unplug(pasta: bool) {
    let dir = tempfile::tempdir().unwrap();
    let node: PathBuf = dir.path().join("input").join("event99");
    std::fs::create_dir(dir.path().join("input")).unwrap();
    std::os::unix::fs::symlink("/dev/null", &node).unwrap();
    let mut app = start(dir.path(), &node, pasta);
    let mnt: u64 = {
        let v: serde_json::Value = serde_json::from_str(app.status.trim()).unwrap();
        v["mnt-namespace"].as_u64().unwrap()
    };
    let in_sandbox = || {
        std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter(|e| {
                std::fs::metadata(e.path().join("ns/mnt"))
                    .is_ok_and(|m| std::os::unix::fs::MetadataExt::ino(&m) == mnt)
            })
            .count()
    };
    assert!(in_sandbox() > 0, "the sandbox is not found");
    let (tx, rx) = mpsc::channel();
    let watch = DeviceWatch::start(
        vec![watched(&node)],
        rx,
        Unplugged::EndApp("not enough here".into()),
        end_launched(app.child.id()),
    )
    .unwrap();
    tx.send(app.status.trim().to_string()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    unplug(&node);
    let start = Instant::now();
    while in_sandbox() > 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the sandbox still runs after its controller was unplugged"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let report = watch.finish();
    assert!(report.ended_app, "{:?}", report.lines);
    assert!(
        report.lines[0].contains("SAM ended the app (not enough here)"),
        "{:?}",
        report.lines
    );
    // The app saw its controller to the end: never another device.
    let mut rest = String::new();
    let _ = app.out.read_to_string(&mut rest);
    assert!(rest.lines().all(|l| l == "device"), "{rest}");
}

fn unplug(node: &Path) {
    std::fs::remove_file(node).unwrap();
}

fn another_device_at_its_name(node: &Path) {
    let next = node.with_extension("next");
    std::os::unix::fs::symlink("/dev/zero", &next).unwrap();
    std::fs::rename(&next, node).unwrap();
}

fn bwrap_here() -> bool {
    let ok = Command::new("bwrap")
        .args(["--unshare-user", "--ro-bind", "/", "/", "true"])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        sam_runner::contracts::skip("Bubblewrap cannot make a sandbox here").unwrap();
    }
    ok
}

/// An unplugged controller is taken out of the running sandbox; the app
/// keeps running (review R56).
#[test]
fn an_unplugged_controller_leaves_the_running_sandbox() {
    if bwrap_here() {
        taken_out_after(unplug, false);
    }
}

/// Another device at an unplugged controller's name (a keyboard that got
/// its number) is never reachable: the node is taken out (review R56).
#[test]
fn another_device_at_a_controllers_name_is_never_shown() {
    if bwrap_here() {
        taken_out_after(another_device_at_its_name, false);
    }
}

/// With "This computer only" (pasta, which gives the sandbox its own
/// process numbers) an unplugged controller is taken out too (review R56).
#[test]
fn an_unplugged_controller_leaves_a_sandbox_inside_pasta() {
    if !bwrap_here() {
        return;
    }
    // SAM uses only a pasta with --splice-only; with an older one (or
    // none) "This computer only" does not run pasta at all.
    if let Err(e) = sam_runner::netns::pasta_usable() {
        sam_runner::contracts::not_here(&format!("no pasta SAM would use: {e}"));
        return;
    }
    taken_out_after(unplug, true);
}

/// Where taking an unplugged controller out is not enough (no Landlock, or
/// the app may make namespaces of its own), SAM ends the whole sandbox at
/// once (review R56).
#[test]
fn where_taking_out_is_not_enough_the_whole_sandbox_ends() {
    if !sam_runner::contracts::isolated_only("ending a sandbox") {
        return;
    }
    if bwrap_here() {
        ended_after_unplug(false);
    }
}

/// … also inside pasta, which gives the sandbox its own process numbers
/// (review R56).
#[test]
fn where_taking_out_is_not_enough_a_sandbox_inside_pasta_ends() {
    if !sam_runner::contracts::isolated_only("ending a sandbox") {
        return;
    }
    if !bwrap_here() {
        return;
    }
    if let Err(e) = sam_runner::netns::pasta_usable() {
        sam_runner::contracts::not_here(&format!("no pasta SAM would use: {e}"));
        return;
    }
    ended_after_unplug(true);
}
