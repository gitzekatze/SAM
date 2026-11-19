//! A terminal of its own for apps that run in a terminal.
//!
//! An app started from a terminal would otherwise share the user's
//! terminal device with the shell that started it. With that device it can:
//!
//! - type commands into the shell (`TIOCSTI`, `TIOCLINUX`), which run
//!   unsandboxed once the app ends;
//! - change the terminal's settings, or keep reading the user's typing from
//!   a process left behind;
//! - send escape codes that reach past the terminal: the clipboard
//!   (OSC 52), desktop notifications, tmux's passthrough to the outer
//!   terminal, or a window-title report that the terminal answers by
//!   "typing" text the app chose.
//!
//! So SAM puts the app on a pseudo-terminal of its own and passes the bytes
//! on: the user's typing to the app, the app's output through
//! [`OutputFilter`] (an allow-list, `sam_core::terminal`) to the user's
//! terminal. Whatever the app does to its
//! terminal stays on that pseudo-terminal. When the app ends, replies the
//! terminal still had queued are discarded, so they cannot reach the shell.
//! The syscall filter blocks `TIOCSTI` and `TIOCLINUX` as well; this does
//! not depend on it (a repair step can turn the filter off).
//!
//! Not covered: output that misleads the user (a fake prompt, a link whose
//! text hides its target), and security bugs in the user's terminal program
//! itself.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};

/// How an app's terminal is handled for one launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalMode {
    /// No terminal: output goes through pipes into the log (desktop starts).
    None,
    /// Started from a terminal: the app gets its own pseudo-terminal, which
    /// SAM connects to the user's.
    Relay,
    /// A terminal program started without one (test start): it gets a
    /// pseudo-terminal of 80×24 with no input, so it can start as usual.
    Headless,
}

impl TerminalMode {
    /// `stdin_tty`, `stdout_tty`: SAM's own input and output are a
    /// terminal. `interactive`: the user uses the app (not a test start or
    /// a check).
    ///
    /// The user's start with input from a pipe or a file (`cat f | sam-jail
    /// run jq .`, a script) gets no terminal: input and output pass through
    /// unchanged, so the tool works as in any pipe. Output shown in a
    /// terminal is still filtered (`launch::pump_output`), and without a
    /// terminal of its own the app has none to type into.
    ///
    /// The same with the output going to a file or a pipe (`sam-jail run
    /// jq . f > out.json`): a terminal of its own would turn its line ends
    /// into CR LF and mix its errors into the output (audit L-F6). It then
    /// gets no input from the terminal.
    pub fn choose(
        terminal_program: bool,
        stdin_tty: bool,
        stdout_tty: bool,
        interactive: bool,
    ) -> TerminalMode {
        if stdin_tty && stdout_tty && interactive {
            TerminalMode::Relay
        } else if terminal_program && !interactive {
            TerminalMode::Headless
        } else {
            TerminalMode::None
        }
    }
}

/// Whether `fd` is a terminal.
pub fn is_tty(fd: RawFd) -> bool {
    // SAFETY: isatty takes a descriptor and has no other preconditions.
    unsafe { libc::isatty(fd) == 1 }
}

/// A pseudo-terminal pair: the app gets the follower side as its
/// standard input, output and error; SAM keeps the leader side.
pub struct Pty {
    leader: OwnedFd,
    follower: OwnedFd,
    outer: Option<Outer>,
}

/// The user's terminal: where the typing comes from and the output goes
/// (SAM's standard input and output).
#[derive(Debug, Clone, Copy)]
pub struct Outer {
    pub input: RawFd,
    pub output: RawFd,
}

impl Outer {
    pub const STDIO: Outer = Outer {
        input: 0,
        output: 1,
    };
}

impl Pty {
    /// With an outer terminal, its size and settings are copied.
    pub fn open(outer: Option<Outer>) -> Result<Pty> {
        let mut size = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: termios is a plain C struct; all zeros is a valid value.
        let mut settings: libc::termios = unsafe { std::mem::zeroed() };
        let mut have_settings = false;
        if let Some(o) = outer {
            // SAFETY: `size` and `settings` are valid, writable structs; `o.input` is the outer terminal's open descriptor.
            unsafe {
                libc::ioctl(o.input, libc::TIOCGWINSZ, &mut size);
                have_settings = libc::tcgetattr(o.input, &mut settings) == 0;
            }
        }
        let (mut leader, mut follower) = (-1, -1);
        let tp = if have_settings {
            &settings as *const libc::termios
        } else {
            std::ptr::null()
        };
        // SAFETY: `leader` and `follower` are valid ints to fill; `tp` is null or points to `settings`, and `size` is valid.
        if unsafe { libc::openpty(&mut leader, &mut follower, std::ptr::null_mut(), tp, &size) }
            != 0
        {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "could not create a terminal for the app: {error}",
                    &[("error", &std::io::Error::last_os_error())]
                )
            );
        }
        // SAFETY: openpty returned two new descriptors that nothing else owns.
        let (leader, follower) =
            unsafe { (OwnedFd::from_raw_fd(leader), OwnedFd::from_raw_fd(follower)) };
        // openpty does not set close-on-exec: neither end may leak into the
        // sandbox beyond the app's standard streams.
        for fd in [&leader, &follower] {
            // SAFETY: `fd` is one of the two descriptors openpty just created; F_SETFD only changes its flags.
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        Ok(Pty {
            leader,
            follower,
            outer,
        })
    }

    /// One of the app's standard streams.
    pub fn stdio(&self) -> std::io::Result<Stdio> {
        Ok(Stdio::from(self.follower.try_clone()?))
    }

    /// For `Command::pre_exec`: makes the terminal the controlling terminal
    /// of a new session, so Ctrl+C, resizing and hang-up reach the app.
    /// Only async-signal-safe calls.
    pub fn become_controlling_terminal() -> std::io::Result<()> {
        // SAFETY: runs between fork and exec (pre_exec) and calls only setsid and ioctl, which are async-signal-safe.
        unsafe {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Starts passing bytes on, in a thread. Call after the app was started
    /// (and SAM's `Command`, which holds copies of the follower, dropped).
    pub fn start(self, out: OutputSink) -> Relay {
        let done = Arc::new(AtomicBool::new(false));
        let Pty {
            leader,
            follower,
            outer,
        } = self;
        drop(follower);
        let d = done.clone();
        let thread = std::thread::spawn(move || relay(leader, outer, out, d));
        Relay {
            done,
            thread: Some(thread),
        }
    }
}

/// Where the app's output goes besides the user's terminal.
pub struct OutputSink {
    /// The first part, for diagnosing a failed start (control codes removed).
    pub head: Arc<Mutex<String>>,
    pub head_limit: usize,
    /// The launch log (control codes removed, up to `log_limit` bytes).
    pub log: Arc<Mutex<fs::File>>,
    pub log_limit: usize,
}

/// The running relay; [`Relay::finish`] once the app has ended.
pub struct Relay {
    done: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<RelayEnd>>,
}

/// How the relay ended.
#[derive(Debug, Default)]
pub struct RelayEnd {
    /// What the output filter removed.
    pub blocked: BTreeSet<&'static str>,
    /// The user's terminal closed (or SAM was asked to quit) while the app
    /// ran: SAM hung up the app's terminal.
    pub hung_up: bool,
}

impl Relay {
    /// Waits for the remaining output and gives the user's terminal its
    /// settings back.
    pub fn finish(mut self) -> RelayEnd {
        self.done.store(true, Ordering::SeqCst);
        self.thread
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

static ENDING: AtomicBool = AtomicBool::new(false);

extern "C" fn on_end(_: libc::c_int) {
    ENDING.store(true, Ordering::SeqCst);
}

/// When the user's terminal closes (SIGHUP) or SAM is asked to quit
/// (SIGTERM, also at logout), SAM ends the app and then finishes the launch
/// properly (record, log, runtime folder, D-Bus filter) instead of dying
/// first and leaving the app to be killed hard: on a terminal the relay
/// hangs up the app's terminal; otherwise the launch asks the app to quit
/// ([`end_requested`]). A handler, not "ignore": handlers are reset when a
/// program starts, so the app gets the signal as usual.
pub fn end_cleanly_on_signal() {
    // SAFETY: `sa` is a zeroed sigaction whose handler is a valid extern C function; sigaction only reads it.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_end as *const () as usize;
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

/// Whether SIGHUP or SIGTERM arrived since [`end_cleanly_on_signal`].
pub fn end_requested() -> bool {
    ENDING.load(Ordering::SeqCst)
}

static WINCH: AtomicBool = AtomicBool::new(false);

extern "C" fn on_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::SeqCst);
}

/// The user's terminal in raw mode (keys go to the app unchanged, Ctrl+C
/// included) until dropped.
struct RawMode(RawFd, libc::termios);

impl RawMode {
    fn enter(fd: RawFd) -> Option<RawMode> {
        // SAFETY: termios is a plain C struct; all zeros is a valid value.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `saved` is a valid, writable termios and `fd` an open descriptor.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return None;
        }
        let mut raw = saved;
        // SAFETY: `raw` is a valid termios copied from the terminal's own settings.
        unsafe {
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
        }
        Some(RawMode(fd, saved))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restores the settings saved when raw mode was entered, on the same descriptor.
        unsafe { libc::tcsetattr(self.0, libc::TCSANOW, &self.1) };
    }
}

fn relay(
    leader: OwnedFd,
    outer: Option<Outer>,
    out: OutputSink,
    done: Arc<AtomicBool>,
) -> RelayEnd {
    let lfd = leader.as_raw_fd();
    // SAFETY: `lfd` is the terminal leader this relay owns; F_GETFL/F_SETFL only change its flags.
    unsafe {
        let fl = libc::fcntl(lfd, libc::F_GETFL);
        libc::fcntl(lfd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    let raw = outer.and_then(|o| {
        // SAFETY: `sa` is a zeroed sigaction whose handler is a valid extern C function; sigaction only reads it.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_winch as *const () as usize;
            libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
        }
        RawMode::enter(o.input)
    });
    // On the relay, the terminal's answers to the app's requests go to
    // the app.
    let mut filter = OutputFilter::for_relay();
    let mut plain = sam_core::terminal::PlainText::default();
    let mut to_app: Vec<u8> = Vec::new();
    let mut stdout_ok = outer.is_some();
    let mut logged = 0usize;
    let mut buf = vec![0u8; 16 * 1024];
    let mut hung_up = false;
    loop {
        if let Some(o) = outer.filter(|_| WINCH.swap(false, Ordering::SeqCst)) {
            // SAFETY: winsize is a plain C struct; all zeros is a valid value.
            let mut size: libc::winsize = unsafe { std::mem::zeroed() };
            // SAFETY: `size` is a valid, writable winsize and `o.input` the outer terminal's open descriptor.
            if unsafe { libc::ioctl(o.input, libc::TIOCGWINSZ, &mut size) } == 0 {
                // SAFETY: `size` holds the size just read; `lfd` is the leader this relay owns.
                unsafe { libc::ioctl(lfd, libc::TIOCSWINSZ, &size) };
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: lfd,
                events: libc::POLLIN | if to_app.is_empty() { 0 } else { libc::POLLOUT },
                revents: 0,
            },
            libc::pollfd {
                fd: outer
                    .filter(|_| to_app.len() < 64 * 1024)
                    .map_or(-1, |o| o.input),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let finished = done.load(Ordering::SeqCst);
        // SAFETY: `fds` is a valid array of two pollfds.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, if finished { 50 } else { 200 }) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if n == 0 && finished {
            break;
        }
        if ENDING.load(Ordering::SeqCst) {
            hung_up = true;
            break;
        }
        // The user's typing → the app.
        if let Some(o) = outer.filter(|_| fds[1].revents != 0) {
            // SAFETY: `buf` is a valid, writable buffer of buf.len() bytes and `o.input` is open.
            let r = unsafe { libc::read(o.input, buf.as_mut_ptr().cast(), buf.len()) };
            if r > 0 {
                to_app.extend_from_slice(&buf[..r as usize]);
            } else if r == 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                // The user's terminal is gone: hang up the app's.
                hung_up = true;
                break;
            }
        }
        if !to_app.is_empty() && fds[0].revents & libc::POLLOUT != 0 {
            // SAFETY: `to_app` is a valid buffer of to_app.len() bytes and `lfd` is open.
            let w = unsafe { libc::write(lfd, to_app.as_ptr().cast(), to_app.len()) };
            if w > 0 {
                to_app.drain(..w as usize);
            }
        }
        // The app's output → the user's terminal, filtered.
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            // SAFETY: `buf` is a valid, writable buffer of buf.len() bytes and `lfd` is open.
            let r = unsafe { libc::read(lfd, buf.as_mut_ptr().cast(), buf.len()) };
            if r > 0 {
                let chunk = &buf[..r as usize];
                let shown = filter.filter(chunk);
                if stdout_ok && outer.is_some_and(|o| write_all(o.output, &shown).is_err()) {
                    stdout_ok = false;
                }
                let text = plain.feed(chunk);
                if let Ok(mut h) = out.head.lock() {
                    if h.len() < out.head_limit {
                        h.push_str(&text);
                    }
                }
                if logged < out.log_limit {
                    if let Ok(mut l) = out.log.lock() {
                        let _ = l.write_all(text.as_bytes());
                        logged += text.len();
                        if logged >= out.log_limit {
                            let _ = writeln!(l, "\n# (more terminal output not logged)");
                        }
                    }
                }
            } else if r == 0 {
                break;
            } else {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::Interrupted
                {
                    // EIO: every copy of the app's side is closed.
                    break;
                }
            }
        }
    }
    // An unfinished last sequence is dropped; modes the app left on that
    // would change the shell's terminal are switched off (audit L-F11).
    let tail = filter.finish();
    if stdout_ok {
        if let Some(o) = outer {
            let _ = write_all(o.output, &tail);
        }
    }
    // Still in raw mode: a reply without a line end can be read and
    // discarded only there.
    if let Some(o) = outer {
        discard_replies(o.input);
    }
    drop(raw);
    drop(leader);
    RelayEnd {
        blocked: filter.blocked,
        hung_up,
    }
}

/// Replies the terminal still sends to requests the app made just before it
/// ended would land in the shell: they are read and discarded until the
/// terminal has been quiet for 150 ms (at most one second), then whatever
/// is still queued is dropped (audit L-F10: one fixed wait of 60 ms let a
/// slow reply through).
fn discard_replies(input: RawFd) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(1);
    let mut buf = [0u8; 4096];
    while std::time::Instant::now() < end {
        let mut fds = [libc::pollfd {
            fd: input,
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: `fds` is a valid array of one pollfd.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 1, 150) };
        if n <= 0 {
            break;
        }
        // SAFETY: `buf` is a valid, writable buffer and `input` is open.
        let r = unsafe { libc::read(input, buf.as_mut_ptr().cast(), buf.len()) };
        if r <= 0 {
            break;
        }
    }
    // SAFETY: tcflush takes the outer terminal's open descriptor and a plain flag.
    unsafe { libc::tcflush(input, libc::TCIFLUSH) };
}

fn write_all(fd: RawFd, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        // SAFETY: `data` is a valid buffer of data.len() bytes and `fd` is open.
        let w = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if w < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        data = &data[w as usize..];
    }
    Ok(())
}

/// The one filter for terminal output (see `sam_core::terminal`): only
/// known, harmless pieces pass.
pub type OutputFilter = sam_core::terminal::Filter;
pub use sam_core::terminal::plain_text;

#[cfg(test)]
mod tests {
    use super::*;

    /// The filter as on SAM's terminal relay.
    fn run(chunks: &[&[u8]]) -> (Vec<u8>, OutputFilter) {
        let mut f = OutputFilter::for_relay();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(f.filter(c));
        }
        (out, f)
    }

    /// Ordinary terminal output, colors and links pass through the relay unchanged.
    #[test]
    fn ordinary_output_passes_unchanged() {
        let s: &[u8] =
            "plain ✓ text\r\n\x1b[1;31mred\x1b[0m \x1b[2J\x1b[?1049h\x1b]0;title\x07\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\\x1bP$qm\x1b\\".as_bytes();
        let (out, f) = run(&[s]);
        assert_eq!(out, s);
        assert!(f.blocked.is_empty());
    }

    /// A doubled ESC in front of a clipboard code does not smuggle it past
    /// the filter: the terminal reads the second ESC as the start of the
    /// code, so the filter must too. Also after cancelled sequences.
    #[test]
    fn a_doubled_escape_does_not_smuggle_a_clipboard_code() {
        let (out, f) = run(&[b"a\x1b\x1b]52;c;aGVsbG8=\x07b"]);
        assert!(
            !out.windows(3).any(|w| w == b"]52"),
            "the clipboard code was removed: {:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(f.blocked.contains("clipboard"));
        // A CSI sequence cancelled by CAN or SUB ends there; what follows is
        // filtered again.
        for cancel in [0x18u8, 0x1a] {
            let mut s = b"\x1b[12".to_vec();
            s.push(cancel);
            s.extend_from_slice(b"\x1b]52;c;aGk=\x07z");
            let (out, f) = run(&[&s]);
            assert!(
                out.ends_with(b"z") && !out.windows(3).any(|w| w == b"]52"),
                "{:?}",
                String::from_utf8_lossy(&out)
            );
            assert!(f.blocked.contains("clipboard"));
        }
    }

    /// Escape codes that read or write the clipboard are removed from an app's terminal output.
    #[test]
    fn clipboard_codes_are_removed() {
        // Write (BEL- and ST-terminated) and the read request.
        let (out, f) = run(&[b"a\x1b]52;c;aGVsbG8=\x07b\x1b]52;c;?\x1b\\c"]);
        assert_eq!(out, b"abc");
        assert!(f.blocked.contains("clipboard"));
        // Split across reads at every point.
        let s = b"x\x1b]52;c;cm0gLXJmIH4=\x07y";
        for cut in 1..s.len() {
            let (out, _) = run(&[&s[..cut], &s[cut..]]);
            assert_eq!(out, b"xy", "cut at {cut}");
        }
        // Kitty's clipboard protocol, iTerm2's extensions, notifications.
        let (out, f) = run(&[b"1\x1b]5522;type=write\x07 2\x1b]1337;CopyToClipboard=\x07 3\x1b]9;hi\x07 4\x1b]777;notify;a;b\x07 5\x1b]99;;x\x1b\\"]);
        assert_eq!(out, b"1 2 3 4 5");
        assert_eq!(f.blocked.len(), 3);
    }

    /// Leading zeros do not smuggle a code past the filter: terminals read
    /// "0052" as 52 and "021" as 21, and so does SAM; a number too long for
    /// any real code is removed whole (regression: an 11-digit OSC 52 was cut
    /// to 5 and passed on).
    #[test]
    fn leading_zeros_do_not_smuggle_a_code() {
        let (out, f) = run(&[b"a\x1b]0052;c;aGk=\x07b"]);
        assert_eq!(out, b"ab");
        assert!(f.blocked.contains("clipboard"));
        let (out, f) = run(&[b"a\x1b]00000000052;c;aGk=\x07b"]);
        assert_eq!(out, b"ab");
        assert!(f.blocked.contains("clipboard"));
        let (out, f) = run(&[b"a\x1b]00000000520000;c;aGk=\x07b"]);
        assert_eq!(out, b"ab");
        assert!(
            f.blocked.contains("malformed control codes"),
            "{:?}",
            f.blocked
        );
        let (out, f) = run(&[b"a\x1b[021tb"]);
        assert_eq!(out, b"ab");
        assert!(f.blocked.contains("title reports"));
        // An ordinary code with a leading zero still passes.
        let (out, _) = run(&[b"a\x1b]02;title\x07b"]);
        assert_eq!(out, b"a\x1b]02;title\x07b");
    }

    /// Escape codes that report the window title or pass through tmux are removed; setting the title stays allowed.
    #[test]
    fn title_reports_and_tmux_passthrough_are_removed() {
        let (out, f) = run(&[b"\x1b]2;rm -rf ~\x07\x1b[21t\x1b[20tok\x1b[8;24;80t"]);
        assert_eq!(
            out, b"\x1b]2;rm -rf ~\x07ok\x1b[8;24;80t",
            "the title may be set, not reported; other window ops pass"
        );
        assert!(f.blocked.contains("title reports"));
        let (out, f) = run(&[b"a\x1bPtmux;\x1b\x1b]52;c;eA==\x07\x1b\\b"]);
        assert_eq!(out, b"ab");
        assert!(f.blocked.contains("tmux passthrough"));
        // Images (sixel) are not on the allow-list: removed.
        let (out, _) = run(&[b"\x1bPq#0;2;0;0;0\x1b\\"]);
        assert_eq!(out, b"");
    }

    /// An escape code hidden inside a removed code cannot slip through.
    #[test]
    fn an_escape_inside_a_removed_code_starts_a_new_sequence() {
        let (out, _) = run(&[b"\x1b]52;c;abc\x1b[31mred"]);
        assert_eq!(out, b"\x1b[31mred");
        let (out, _) = run(&[b"\x1b]52;c;abc\x18after"]);
        assert_eq!(out, b"after");
    }

    /// Logs get plain text without escape codes.
    #[test]
    fn plain_text_for_the_log() {
        assert_eq!(
            plain_text(b"\x1b[1mbold\x1b[0m\r\n\x1b]0;t\x07x\ty\x1b(B"),
            "bold\nx\ty"
        );
    }

    /// The log's plain text survives every unfinished or odd code: one cut
    /// off at the end of the data (no read past it), a title ended by
    /// ESC \\ with text after it, a backslash inside a title, and an ESC
    /// with intermediate bytes at the very end (found by mutation testing:
    /// no test reached these edges).
    #[test]
    fn plain_text_survives_unfinished_and_odd_codes() {
        assert_eq!(plain_text(b"a\x1b[12"), "a", "CSI cut off at the end");
        assert_eq!(plain_text(b"a\x1b]0;title"), "a", "OSC cut off at the end");
        assert_eq!(plain_text(b"x\x1b("), "x", "ESC ( cut off at the end");
        assert_eq!(
            plain_text(b"\x1b]0;t\x1b\\after"),
            "after",
            "OSC ended by ESC \\"
        );
        assert_eq!(
            plain_text(b"\x1b]0;a\\b\x07after"),
            "after",
            "a backslash inside a title"
        );
        assert_eq!(
            plain_text(b"\x1b]0;a\x1bb\x07after"),
            "after",
            "an ESC inside a title ends nothing"
        );
    }

    /// Only "tmux;" itself is tmux passthrough: a device control string
    /// that merely starts with "t" is not named as one (it is removed as
    /// unknown; found by mutation testing).
    #[test]
    fn only_tmux_itself_counts_as_tmux_passthrough() {
        for s in [&b"a\x1bPtq\x1b\\b"[..], b"a\x1bPtmu\x1b\\b"] {
            let (out, f) = run(&[s]);
            assert_eq!(out, b"ab");
            assert!(!f.blocked.contains("tmux passthrough"), "{s:?}");
        }
        let (_, f) = run(&[b"\x1bPtmux;x\x1b\\"]);
        assert!(f.blocked.contains("tmux passthrough"));
    }

    /// Of the device control strings only the two that ask for the
    /// terminal's capabilities and settings pass; tmux passthrough,
    /// programmable keys and anything unknown are removed, the text around
    /// them stays.
    #[test]
    fn only_known_device_strings_pass() {
        let s = b"a\x1bP+q544e\x1b\\\x1bP$qm\x1b\\b";
        let (out, f) = run(&[s]);
        assert_eq!(out, s.to_vec());
        assert!(f.blocked.is_empty());
        let (out, f) = run(&[b"a\x1bPtq\x1b\\b"]);
        assert_eq!(out, b"ab");
        assert!(
            !f.blocked.contains("tmux passthrough"),
            "only tmux itself is tmux"
        );
        let (out, f) = run(&[b"a\x1bPtmux;\x1b\x1b]52;c;x\x07\x1b\\b"]);
        assert_eq!(out, b"ab");
        assert!(f.blocked.contains("tmux passthrough"));
        // Programmable function keys (DECUDK): a key the person presses
        // later in the shell would type what the app chose.
        let (out, f) = run(&[b"a\x1bP0;1|17/726d202d7266\x1b\\b"]);
        assert_eq!(out, b"ab");
        assert!(!f.blocked.is_empty());
    }

    /// Apps started from a terminal get SAM's terminal relay; with input from a pipe or a file they get none (input and output pass through), and a terminal program's test start gets a terminal of its own.
    #[test]
    fn terminal_apps_get_sams_terminal_relay() {
        assert_eq!(
            TerminalMode::choose(true, true, true, true),
            TerminalMode::Relay
        );
        assert_eq!(
            TerminalMode::choose(false, true, true, true),
            TerminalMode::Relay,
            "GUI apps started from a terminal too"
        );
        assert_eq!(
            TerminalMode::choose(true, false, true, true),
            TerminalMode::None,
            "input from a pipe passes through to a terminal program"
        );
        assert_eq!(
            TerminalMode::choose(true, false, true, false),
            TerminalMode::Headless,
            "a terminal program's test start gets a terminal of its own"
        );
        assert_eq!(
            TerminalMode::choose(true, true, true, false),
            TerminalMode::Headless,
            "a test start does not take over the user's terminal"
        );
        assert_eq!(
            TerminalMode::choose(false, false, true, true),
            TerminalMode::None
        );
        assert_eq!(
            TerminalMode::choose(true, true, false, true),
            TerminalMode::None,
            "output to a file stays exact (audit L-F6)"
        );
    }

    /// A second pseudo-terminal stands in for the user's terminal: SAM's
    /// side of it is `Outer`, the test plays the terminal program.
    #[test]
    fn typing_and_output_pass_and_leftover_replies_are_discarded() {
        let (mut user, mut outer_fd) = (-1, -1);
        // SAFETY: `user` and `outer_fd` are valid ints to fill; the optional arguments are null.
        let opened = unsafe {
            libc::openpty(
                &mut user,
                &mut outer_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0);
        // SAFETY: openpty returned two new descriptors that nothing else owns.
        let (user, outer_fd) =
            unsafe { (OwnedFd::from_raw_fd(user), OwnedFd::from_raw_fd(outer_fd)) };
        let outer = Outer {
            input: outer_fd.as_raw_fd(),
            output: outer_fd.as_raw_fd(),
        };
        let pty = Pty::open(Some(outer)).unwrap();
        let mut cmd = std::process::Command::new("/bin/sh");
        // Reads one line, prints it back, asks for the window title and
        // ends at once: the reply must not stay queued for the shell.
        cmd.args(["-c", r#"read line; printf 'got:%s\n' "$line"; printf '\033]2;evil\007\033[21t\033]52;c;?\007'"#]);
        cmd.stdin(pty.stdio().unwrap())
            .stdout(pty.stdio().unwrap())
            .stderr(pty.stdio().unwrap());
        // SAFETY: become_controlling_terminal uses only async-signal-safe calls, as pre_exec requires.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(Pty::become_controlling_terminal);
        }
        let mut child = cmd.spawn().unwrap();
        drop(cmd);
        let d = tempfile::tempdir().unwrap();
        let head = Arc::new(Mutex::new(String::new()));
        let log = Arc::new(Mutex::new(fs::File::create(d.path().join("log")).unwrap()));
        let relay = pty.start(OutputSink {
            head,
            head_limit: 4096,
            log,
            log_limit: 4096,
        });
        // The user types a line (raw mode: Enter is a carriage return).
        std::thread::sleep(std::time::Duration::from_millis(200));
        write_all(user.as_raw_fd(), b"hello\r").unwrap();
        assert!(child.wait().unwrap().success());
        // The terminal program answers a query late, as a real one might.
        write_all(user.as_raw_fd(), b"\x1b]l late reply \x1b\\").unwrap();
        let end = relay.finish();
        assert!(!end.hung_up);
        let blocked = end.blocked;
        // What reached the user's terminal.
        let mut shown = Vec::new();
        let mut buf = [0u8; 4096];
        // SAFETY: `user` is an open descriptor; F_SETFL only changes its flags.
        unsafe { libc::fcntl(user.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        loop {
            // SAFETY: `buf` is a valid, writable buffer of buf.len() bytes and `user` is open.
            let r = unsafe { libc::read(user.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if r <= 0 {
                break;
            }
            shown.extend_from_slice(&buf[..r as usize]);
        }
        let shown = String::from_utf8_lossy(&shown);
        assert!(shown.contains("got:hello"), "{shown:?}");
        assert!(
            shown.contains("\x1b]2;evil\x07") && !shown.contains("[21t") && !shown.contains("]52"),
            "{shown:?}"
        );
        assert!(blocked.contains("title reports") && blocked.contains("clipboard"));
        // Nothing is left for the shell to read.
        let mut queued: libc::c_int = 0;
        // SAFETY: `queued` is a valid, writable int and `outer_fd` is open.
        unsafe { libc::ioctl(outer_fd.as_raw_fd(), libc::FIONREAD, &mut queued) };
        assert_eq!(queued, 0, "leftover terminal replies were discarded");
    }

    /// An app on SAM's terminal relay cannot type into the user's real terminal.
    #[test]
    fn the_app_cannot_reach_the_outer_terminal() {
        // A program on SAM's pseudo-terminal: its output arrives filtered,
        // and keystrokes it injects (where the kernel still allows that)
        // only reach its own terminal.
        let pty = Pty::open(None).unwrap();
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", r#"printf 'hello\033]52;c;eA==\007 world'; tty"#]);
        cmd.stdin(pty.stdio().unwrap())
            .stdout(pty.stdio().unwrap())
            .stderr(pty.stdio().unwrap());
        // SAFETY: become_controlling_terminal uses only async-signal-safe calls, as pre_exec requires.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(Pty::become_controlling_terminal);
        }
        let mut child = cmd.spawn().unwrap();
        drop(cmd);
        let d = tempfile::tempdir().unwrap();
        let head = Arc::new(Mutex::new(String::new()));
        let log = Arc::new(Mutex::new(fs::File::create(d.path().join("log")).unwrap()));
        let relay = pty.start(OutputSink {
            head: head.clone(),
            head_limit: 4096,
            log,
            log_limit: 4096,
        });
        assert!(child.wait().unwrap().success());
        let blocked = relay.finish().blocked;
        let text = head.lock().unwrap().clone();
        assert!(text.starts_with("hello world"), "{text:?}");
        assert!(
            text.contains("/dev/pts/"),
            "the app's terminal is a pseudo-terminal: {text:?}"
        );
        assert!(blocked.contains("clipboard"));
    }

    /// A slow terminal that answers requests in a trickle after the app has
    /// ended: nothing of it reaches the shell (audit L-F10: one fixed wait
    /// of 60 ms let later replies through). And a terminal that never stops
    /// sending does not keep SAM waiting: at most about a second.
    #[test]
    fn a_slow_terminals_late_replies_do_not_reach_the_shell() {
        use std::sync::atomic::AtomicBool;
        for (gap_ms, count, must_be_clean) in [(30u64, 10u32, true), (30, 200, false)] {
            let (mut user, mut outer_fd) = (-1, -1);
            // SAFETY: valid ints to fill; the optional arguments are null.
            let opened = unsafe {
                libc::openpty(
                    &mut user,
                    &mut outer_fd,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            assert_eq!(opened, 0);
            // SAFETY: openpty returned two new descriptors that nothing else owns.
            let (user, outer_fd) =
                unsafe { (OwnedFd::from_raw_fd(user), OwnedFd::from_raw_fd(outer_fd)) };
            let outer = Outer {
                input: outer_fd.as_raw_fd(),
                output: outer_fd.as_raw_fd(),
            };
            let pty = Pty::open(Some(outer)).unwrap();
            let mut cmd = std::process::Command::new("/bin/sh");
            cmd.args(["-c", "printf 'x\\033[6n'"]);
            cmd.stdin(pty.stdio().unwrap())
                .stdout(pty.stdio().unwrap())
                .stderr(pty.stdio().unwrap());
            // SAFETY: become_controlling_terminal uses only async-signal-safe calls.
            unsafe {
                use std::os::unix::process::CommandExt;
                cmd.pre_exec(Pty::become_controlling_terminal);
            }
            let mut child = cmd.spawn().unwrap();
            drop(cmd);
            let d = tempfile::tempdir().unwrap();
            let relay = pty.start(OutputSink {
                head: Arc::new(Mutex::new(String::new())),
                head_limit: 4096,
                log: Arc::new(Mutex::new(fs::File::create(d.path().join("log")).unwrap())),
                log_limit: 4096,
            });
            assert!(child.wait().unwrap().success());
            // The terminal answers late, a little at a time.
            let stop = Arc::new(AtomicBool::new(false));
            let (fd, stop2) = (user.as_raw_fd(), stop.clone());
            let writer = std::thread::spawn(move || {
                for _ in 0..count {
                    if stop2.load(Ordering::SeqCst) {
                        break;
                    }
                    let _ = write_all(fd, b"\x1b[12;1R");
                    std::thread::sleep(std::time::Duration::from_millis(gap_ms));
                }
            });
            let started = std::time::Instant::now();
            relay.finish();
            let took = started.elapsed();
            // The trickle runs to its end; the endless one is stopped.
            if !must_be_clean {
                stop.store(true, Ordering::SeqCst);
            }
            writer.join().unwrap();
            assert!(
                took < std::time::Duration::from_secs(2),
                "SAM waited {took:?}"
            );
            if must_be_clean {
                // As the shell reads it at its prompt: in raw mode, where a
                // reply without a line end is there to read.
                // SAFETY: `t` is a valid termios to fill and `outer_fd` an open terminal.
                unsafe {
                    let mut t: libc::termios = std::mem::zeroed();
                    libc::tcgetattr(outer_fd.as_raw_fd(), &mut t);
                    libc::cfmakeraw(&mut t);
                    libc::tcsetattr(outer_fd.as_raw_fd(), libc::TCSANOW, &t);
                }
                let mut queued: libc::c_int = 0;
                // SAFETY: `queued` is a valid, writable int and `outer_fd` is open.
                unsafe { libc::ioctl(outer_fd.as_raw_fd(), libc::FIONREAD, &mut queued) };
                assert_eq!(queued, 0, "late replies stayed queued for the shell");
            }
        }
    }
}
