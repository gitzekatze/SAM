//! The connection between the user's terminal and the app's own terminal
//! (`pty::Pty::start`), tested end to end without a sandbox. A second
//! pseudo-terminal plays the user's terminal: the test types into it and
//! reads what the user would see. Checked: typing reaches the app, the
//! output arrives filtered, the window size is copied and follows a resize,
//! keys reach the app unchanged (Ctrl+C included), the user's terminal gets
//! its settings back, a closed terminal hangs up the app, and the log stays
//! within its limit. In its own file: it handles SIGWINCH for the process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sam_runner::pty::{Outer, OutputSink, Pty};

/// A terminal pair: (leader, follower). The follower is "the user's
/// terminal" as SAM sees it; the test acts as the person at the leader.
fn terminal(rows: u16, cols: u16) -> (OwnedFd, OwnedFd) {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
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
    // Not inherited by any app started meanwhile: closing the user's side
    // must really close it.
    for fd in [l, f] {
        // SAFETY: one of the two descriptors openpty just created.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    // SAFETY: openpty returned two new descriptors that nothing else owns.
    unsafe { (OwnedFd::from_raw_fd(l), OwnedFd::from_raw_fd(f)) }
}

/// One at a time: a resize reaches whichever connection runs (one flag for
/// the process, as in SAM, which runs one app per process).
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Reads what the user sees until `needle` appears or 10 s pass.
fn read_until(fd: RawFd, seen: &mut String, needle: &str) {
    let end = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 4096];
    while !seen.contains(needle) && Instant::now() < end {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        if unsafe { libc::poll(&mut p, 1, 100) } > 0 {
            // SAFETY: `buf` is writable for its length.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                seen.push_str(&String::from_utf8_lossy(&buf[..n as usize]));
            } else {
                break;
            }
        }
    }
    assert!(seen.contains(needle), "{needle:?} never arrived: {seen:?}");
}

fn type_in(fd: RawFd, text: &[u8]) {
    // SAFETY: `text` is a valid buffer of its length.
    let n = unsafe { libc::write(fd, text.as_ptr().cast(), text.len()) };
    assert_eq!(n, text.len() as isize);
}

fn canonical(fd: RawFd) -> bool {
    // SAFETY: termios is a plain C struct; all zeros is a valid value.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `t` is writable, `fd` an open terminal.
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut t) }, 0);
    t.c_lflag & libc::ICANON != 0
}

struct Started {
    child: std::process::Child,
    relay: sam_runner::pty::Relay,
    head: Arc<Mutex<String>>,
    log: std::path::PathBuf,
}

/// Starts `script` in a terminal of its own, connected to `user`.
fn start(dir: &std::path::Path, user: RawFd, script: &str, log_limit: usize) -> Started {
    start_with(
        dir,
        Outer {
            input: user,
            output: user,
        },
        script,
        log_limit,
    )
}

fn start_with(dir: &std::path::Path, outer: Outer, script: &str, log_limit: usize) -> Started {
    let pty = Pty::open(Some(outer)).unwrap();
    let mut cmd = Command::new("sh");
    cmd.args(["-c", script]);
    sam_runner::testenv::isolate_command(&mut cmd, dir);
    cmd.stdin(pty.stdio().unwrap())
        .stdout(pty.stdio().unwrap())
        .stderr(pty.stdio().unwrap());
    // SAFETY: only async-signal-safe calls (setsid, ioctl).
    unsafe { cmd.pre_exec(Pty::become_controlling_terminal) };
    let child = cmd.spawn().unwrap();
    drop(cmd);
    let log = dir.join("launch.log");
    let head = Arc::new(Mutex::new(String::new()));
    let relay = pty.start(OutputSink {
        head: head.clone(),
        head_limit: 4096,
        log: Arc::new(Mutex::new(fs::File::create(&log).unwrap())),
        log_limit,
    });
    Started {
        child,
        relay,
        head,
        log,
    }
}

fn wait_child(child: &mut std::process::Child) -> std::process::ExitStatus {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s;
        }
        if Instant::now() > end {
            let _ = child.kill();
            panic!("the app did not end");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Typing reaches the app; its output reaches the user filtered (colours
/// pass, a clipboard write does not); the window size is copied at the
/// start and follows a resize; the log and the error head get the text
/// without control codes; the user's terminal is raw while the app runs
/// and gets its settings back afterwards.
#[test]
fn the_terminal_connection_passes_typing_and_filtered_output() {
    let _one = one_at_a_time();
    let t = tempfile::tempdir().unwrap();
    let (user_side, user) = terminal(50, 132);
    let (me, user) = (user_side.as_raw_fd(), user.as_raw_fd());
    assert!(canonical(user), "a fresh terminal is line-based");
    let script = r#"
stty size
read -r line
printf 'got:%s\n' "$line"
printf '\033]52;c;ZXZpbA==\007'
printf '\033[31mred\033[0m\n'
read -r again
stty size
echo done
"#;
    let mut s = start(t.path(), user, script, 1 << 20);
    let mut seen = String::new();
    read_until(me, &mut seen, "50 132");
    assert!(
        !canonical(user),
        "raw while the app runs: keys go to it unchanged"
    );
    type_in(me, b"hello\r");
    read_until(me, &mut seen, "red");
    assert!(
        seen.contains("got:hello"),
        "typing reached the app: {seen:?}"
    );
    assert!(seen.contains("\x1b[31mred"), "colours pass: {seen:?}");
    assert!(!seen.contains("]52;"), "no clipboard write: {seen:?}");

    // The user's window becomes smaller.
    let small = libc::winsize {
        ws_row: 30,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `small` is a valid winsize; `me` an open terminal leader.
    unsafe {
        libc::ioctl(me, libc::TIOCSWINSZ, &small);
        libc::raise(libc::SIGWINCH);
    }
    std::thread::sleep(Duration::from_millis(500));
    type_in(me, b"x\r");
    read_until(me, &mut seen, "done");
    assert!(
        seen.contains("30 100"),
        "the new size reached the app: {seen:?}"
    );

    assert!(wait_child(&mut s.child).success());
    let end = s.relay.finish();
    assert!(!end.hung_up);
    assert!(!end.blocked.is_empty(), "the clipboard write is reported");
    assert!(canonical(user), "the user's terminal got its settings back");
    let log = fs::read_to_string(&s.log).unwrap();
    assert!(log.contains("got:hello") && log.contains("red"), "{log:?}");
    assert!(
        !log.contains('\x1b'),
        "no control codes in the log: {log:?}"
    );
    assert!(s.head.lock().unwrap().contains("got:hello"));
}

/// Keys reach the app unchanged: Ctrl+C interrupts the app, not SAM.
#[test]
fn ctrl_c_reaches_the_app() {
    let _one = one_at_a_time();
    let t = tempfile::tempdir().unwrap();
    let (user_side, user) = terminal(24, 80);
    let (me, user) = (user_side.as_raw_fd(), user.as_raw_fd());
    let script = "trap 'echo caught-int; exit 0' INT; echo ready; while :; do sleep 0.1; done";
    let mut s = start(t.path(), user, script, 1 << 20);
    let mut seen = String::new();
    read_until(me, &mut seen, "ready");
    type_in(me, b"\x03");
    read_until(me, &mut seen, "caught-int");
    wait_child(&mut s.child);
    assert!(!s.relay.finish().hung_up);
}

/// When the user's terminal closes, SAM hangs up the app's terminal: the
/// app ends, and the end says so.
#[test]
fn closing_the_users_terminal_hangs_up_the_app() {
    let _one = one_at_a_time();
    let t = tempfile::tempdir().unwrap();
    let (user_side, user_end) = terminal(24, 80);
    let user = user_end.as_raw_fd();
    let mut s = start(t.path(), user, "echo ready; exec sleep 30", 1 << 20);
    let mut seen = String::new();
    read_until(user_side.as_raw_fd(), &mut seen, "ready");
    drop(user_side); // the terminal window is closed
    let status = wait_child(&mut s.child);
    assert!(!status.success(), "the app was hung up: {status:?}");
    assert!(s.relay.finish().hung_up);
    drop(user_end);
}

/// The log keeps at most its limit of terminal output and says so.
#[test]
fn the_log_stays_within_its_limit() {
    let _one = one_at_a_time();
    let t = tempfile::tempdir().unwrap();
    let (user_side, user) = terminal(24, 80);
    let (me, user) = (user_side.as_raw_fd(), user.as_raw_fd());
    let script = "i=0; while [ $i -lt 200 ]; do echo 0123456789; i=$((i+1)); done; echo finished";
    let mut s = start(t.path(), user, script, 64);
    let mut seen = String::new();
    read_until(me, &mut seen, "finished");
    wait_child(&mut s.child);
    s.relay.finish();
    let log = fs::read_to_string(&s.log).unwrap();
    // The limit is checked per piece of output read: nothing after the note.
    assert!(
        log.trim_end()
            .ends_with("(more terminal output not logged)"),
        "{log:?}"
    );
    assert_eq!(log.matches("not logged").count(), 1, "{log:?}");
}

/// An app that leaves something running on its terminal (a helper in the
/// background) does not keep SAM waiting once the app itself has ended.
#[test]
fn something_left_on_the_apps_terminal_does_not_keep_sam_waiting() {
    let _one = one_at_a_time();
    let t = tempfile::tempdir().unwrap();
    let (user_side, user) = terminal(24, 80);
    let (me, user) = (user_side.as_raw_fd(), user.as_raw_fd());
    // The helper ignores the hang-up and keeps the terminal open for 5 s.
    let script = "(trap '' HUP; exec sleep 5) & echo ready";
    let mut s = start(t.path(), user, script, 1 << 20);
    let mut seen = String::new();
    read_until(me, &mut seen, "ready");
    wait_child(&mut s.child);
    let begin = Instant::now();
    s.relay.finish();
    assert!(
        begin.elapsed() < Duration::from_secs(2),
        "SAM waited {:?} for what the app left behind",
        begin.elapsed()
    );
}

/// When the user's terminal can no longer show anything (its output is
/// gone), SAM stops writing there but keeps the log, and the app runs to
/// its end.
#[test]
fn the_output_is_still_logged_when_the_terminal_cannot_show_it() {
    let _one = one_at_a_time();
    let t = tempfile::tempdir().unwrap();
    let (_user_side, user) = terminal(24, 80);
    let user = user.as_raw_fd();
    let mut fds = [0; 2];
    // SAFETY: `fds` holds room for the two descriptors pipe2 returns.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: two new descriptors that nothing else owns.
    let (gone, output) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(gone); // writing there fails from now on
    let mut s = start_with(
        t.path(),
        Outer {
            input: user,
            output: output.as_raw_fd(),
        },
        "echo first; sleep 0.3; echo second",
        1 << 20,
    );
    assert!(wait_child(&mut s.child).success());
    let end = s.relay.finish();
    assert!(!end.hung_up);
    let log = fs::read_to_string(&s.log).unwrap();
    assert!(log.contains("first") && log.contains("second"), "{log:?}");
}
