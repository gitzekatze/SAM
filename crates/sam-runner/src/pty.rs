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
//! [`OutputFilter`] to the user's terminal. Whatever the app does to its
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
    /// `stdin_tty`: SAM's own input is a terminal. `interactive`: the user
    /// uses the app (not a test start or a check).
    pub fn choose(terminal_program: bool, stdin_tty: bool, interactive: bool) -> TerminalMode {
        if stdin_tty && interactive {
            TerminalMode::Relay
        } else if terminal_program {
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
    pub const STDIO: Outer = Outer { input: 0, output: 1 };
}

impl Pty {
    /// With an outer terminal, its size and settings are copied.
    pub fn open(outer: Option<Outer>) -> Result<Pty> {
        let mut size = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
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
        let tp = if have_settings { &settings as *const libc::termios } else { std::ptr::null() };
        // SAFETY: `leader` and `follower` are valid ints to fill; `tp` is null or points to `settings`, and `size` is valid.
        if unsafe { libc::openpty(&mut leader, &mut follower, std::ptr::null_mut(), tp, &size) } != 0 {
            bail!("{}", sam_core::i18n::trf("could not create a terminal for the app: {error}", &[("error", &std::io::Error::last_os_error())]));
        }
        // SAFETY: openpty returned two new descriptors that nothing else owns.
        let (leader, follower) = unsafe { (OwnedFd::from_raw_fd(leader), OwnedFd::from_raw_fd(follower)) };
        // openpty does not set close-on-exec: neither end may leak into the
        // sandbox beyond the app's standard streams.
        for fd in [&leader, &follower] {
            // SAFETY: `fd` is one of the two descriptors openpty just created; F_SETFD only changes its flags.
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        Ok(Pty { leader, follower, outer })
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
        let Pty { leader, follower, outer } = self;
        drop(follower);
        let d = done.clone();
        let thread = std::thread::spawn(move || relay(leader, outer, out, d));
        Relay { done, thread: Some(thread) }
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
        self.thread.take().and_then(|t| t.join().ok()).unwrap_or_default()
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
/// (SIGTERM), the relay hangs up the app's terminal, so the app ends, and
/// SAM finishes the launch properly (log, runtime folder, D-Bus filter)
/// instead of dying first. A handler, not "ignore": handlers are reset when
/// a program starts, so the app gets the hang-up as usual.
pub fn end_with_the_terminal() {
    // SAFETY: `sa` is a zeroed sigaction whose handler is a valid extern C function; sigaction only reads it.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_end as *const () as usize;
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
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

fn relay(leader: OwnedFd, outer: Option<Outer>, out: OutputSink, done: Arc<AtomicBool>) -> RelayEnd {
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
    let mut filter = OutputFilter::default();
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
            libc::pollfd { fd: lfd, events: libc::POLLIN | if to_app.is_empty() { 0 } else { libc::POLLOUT }, revents: 0 },
            libc::pollfd { fd: outer.filter(|_| to_app.len() < 64 * 1024).map_or(-1, |o| o.input), events: libc::POLLIN, revents: 0 },
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
            } else if r == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
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
                let text = plain_text(chunk);
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
                if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::Interrupted {
                    // EIO: every copy of the app's side is closed.
                    break;
                }
            }
        }
    }
    drop(raw);
    if let Some(o) = outer {
        // Replies the terminal still sends to queries the app made just
        // before it ended would land in the shell: let them arrive, then
        // discard everything queued on the user's terminal.
        std::thread::sleep(std::time::Duration::from_millis(60));
        // SAFETY: tcflush takes the outer terminal's open descriptor and a plain flag.
        unsafe { libc::tcflush(o.input, libc::TCIFLUSH) };
    }
    drop(leader);
    RelayEnd { blocked: filter.blocked, hung_up }
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

/// Terminal output as plain text for the log: escape sequences and control
/// characters removed (line breaks and tabs kept).
pub fn plain_text(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == 0x1b {
            i += 1;
            match data.get(i) {
                Some(b'[') => {
                    i += 1;
                    while i < data.len() && !(0x40..=0x7e).contains(&data[i]) {
                        i += 1;
                    }
                }
                Some(b']') | Some(b'P') | Some(b'_') | Some(b'^') => {
                    while i < data.len() && data[i] != 0x07 && !(data[i] == 0x1b && data.get(i + 1) == Some(&b'\\')) {
                        i += 1;
                    }
                    if data.get(i) == Some(&0x1b) {
                        i += 1;
                    }
                }
                _ => {
                    // ESC, intermediate bytes, final byte (e.g. ESC ( B).
                    while i < data.len() && (0x20..=0x2f).contains(&data[i]) {
                        i += 1;
                    }
                }
            }
            i += 1;
            continue;
        }
        if b == b'\n' || b == b'\t' || b >= 0x20 && b != 0x7f {
            out.push(b);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Escape codes that reach past the terminal, by what they do.
fn blocked_osc(num: u32) -> Option<&'static str> {
    match num {
        52 | 5522 => Some("clipboard"),
        1337 => Some("terminal extensions (iTerm2/WezTerm: clipboard, files)"),
        9 | 99 | 777 => Some("desktop notifications"),
        _ => None,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum St {
    #[default]
    Ground,
    Esc,
    /// After ESC [ (kept in `seq` until the final byte).
    Csi,
    /// After ESC ] while the number is read (kept in `seq`).
    OscNum,
    Osc {
        pass: bool,
        esc: bool,
    },
    /// After ESC P while the start is read (kept in `seq`).
    DcsHead,
    Dcs {
        pass: bool,
        esc: bool,
    },
}

/// Removes the escape codes listed in the module documentation from a
/// stream of terminal output; everything else passes unchanged. Sequences
/// may be split across calls.
///
/// 8-bit control codes (C1) pass: in UTF-8 they are parts of characters,
/// and terminals in UTF-8 mode do not treat them as escape codes.
#[derive(Debug, Default)]
pub struct OutputFilter {
    st: St,
    seq: Vec<u8>,
    /// What was blocked, for the launch log.
    pub blocked: BTreeSet<&'static str>,
}

impl OutputFilter {
    pub fn filter(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            self.byte(b, &mut out);
        }
        out
    }

    fn byte(&mut self, b: u8, out: &mut Vec<u8>) {
        const ESC: u8 = 0x1b;
        const BEL: u8 = 0x07;
        const CAN: u8 = 0x18;
        const SUB: u8 = 0x1a;
        match self.st {
            St::Ground => {
                if b == ESC {
                    self.st = St::Esc;
                } else {
                    out.push(b);
                }
            }
            St::Esc => match b {
                b'[' => {
                    self.seq.clear();
                    self.seq.extend_from_slice(b"\x1b[");
                    self.st = St::Csi;
                }
                b']' => {
                    self.seq.clear();
                    self.seq.extend_from_slice(b"\x1b]");
                    self.st = St::OscNum;
                }
                b'P' => {
                    self.seq.clear();
                    self.seq.extend_from_slice(b"\x1bP");
                    self.st = St::DcsHead;
                }
                ESC => out.push(ESC),
                _ => {
                    out.extend_from_slice(&[ESC, b]);
                    self.st = St::Ground;
                }
            },
            St::Csi => {
                self.seq.push(b);
                if (0x40..=0x7e).contains(&b) {
                    let params = &self.seq[2..self.seq.len() - 1];
                    // Window-title and icon-label reports: the terminal
                    // answers with text the app set before.
                    if b == b't' && matches!(params, b"20" | b"21") {
                        self.blocked.insert("title reports");
                    } else {
                        out.extend_from_slice(&self.seq);
                    }
                    self.st = St::Ground;
                } else if b == CAN || b == SUB || self.seq.len() > 256 {
                    out.extend_from_slice(&self.seq);
                    self.st = St::Ground;
                }
            }
            St::OscNum => {
                if b.is_ascii_digit() && self.seq.len() < 12 {
                    self.seq.push(b);
                    return;
                }
                let num = std::str::from_utf8(&self.seq[2..]).ok().and_then(|s| s.parse::<u32>().ok());
                match num.and_then(blocked_osc) {
                    Some(what) => {
                        self.blocked.insert(what);
                        self.st = St::Osc { pass: false, esc: false };
                    }
                    None => {
                        out.extend_from_slice(&self.seq);
                        self.st = St::Osc { pass: true, esc: false };
                    }
                }
                self.byte(b, out);
            }
            St::Osc { pass, esc } | St::Dcs { pass, esc } => {
                let osc = matches!(self.st, St::Osc { .. });
                let back = |esc| if osc { St::Osc { pass, esc } } else { St::Dcs { pass, esc } };
                if esc {
                    if b == b'\\' {
                        if pass {
                            out.extend_from_slice(&[ESC, b'\\']);
                        }
                        self.st = St::Ground;
                    } else if b == ESC {
                        // A doubled ESC is content (how tmux passthrough
                        // carries escape codes).
                        if pass {
                            out.extend_from_slice(&[ESC, ESC]);
                        }
                        self.st = back(false);
                    } else {
                        // ESC ended the sequence and starts a new one.
                        if pass {
                            out.push(ESC);
                        }
                        self.st = St::Esc;
                        self.byte(b, out);
                    }
                } else if b == ESC {
                    self.st = back(true);
                } else if (osc && b == BEL) || b == CAN || b == SUB {
                    if pass {
                        out.push(b);
                    }
                    self.st = St::Ground;
                } else if pass {
                    out.push(b);
                }
            }
            St::DcsHead => {
                const TMUX: &[u8] = b"tmux;";
                let got = self.seq.len() - 2;
                if b == TMUX[got] {
                    self.seq.push(b);
                    if self.seq.len() - 2 == TMUX.len() {
                        // tmux passes this on to the terminal outside tmux.
                        self.blocked.insert("tmux passthrough");
                        self.st = St::Dcs { pass: false, esc: false };
                    }
                } else {
                    out.extend_from_slice(&self.seq);
                    self.st = St::Dcs { pass: true, esc: false };
                    self.byte(b, out);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&[u8]]) -> (Vec<u8>, OutputFilter) {
        let mut f = OutputFilter::default();
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

    /// Escape codes that report the window title or pass through tmux are removed; setting the title stays allowed.
    #[test]
    fn title_reports_and_tmux_passthrough_are_removed() {
        let (out, f) = run(&[b"\x1b]2;rm -rf ~\x07\x1b[21t\x1b[20tok\x1b[8;24;80t"]);
        assert_eq!(out, b"\x1b]2;rm -rf ~\x07ok\x1b[8;24;80t", "the title may be set, not reported; other window ops pass");
        assert!(f.blocked.contains("title reports"));
        let (out, f) = run(&[b"a\x1bPtmux;\x1b\x1b]52;c;eA==\x07\x1b\\b"]);
        assert_eq!(out, b"ab");
        assert!(f.blocked.contains("tmux passthrough"));
        // Other DCS sequences pass (e.g. sixel images, DECRQSS).
        let (out, _) = run(&[b"\x1bPq#0;2;0;0;0\x1b\\"]);
        assert_eq!(out, b"\x1bPq#0;2;0;0;0\x1b\\");
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
        assert_eq!(plain_text(b"\x1b[1mbold\x1b[0m\r\n\x1b]0;t\x07x\ty\x1b(B"), "bold\nx\ty");
    }

    /// Apps started from a terminal get SAM's terminal relay; apps without a terminal get none.
    #[test]
    fn terminal_apps_get_sams_terminal_relay() {
        assert_eq!(TerminalMode::choose(true, true, true), TerminalMode::Relay);
        assert_eq!(TerminalMode::choose(false, true, true), TerminalMode::Relay, "GUI apps started from a terminal too");
        assert_eq!(TerminalMode::choose(true, false, true), TerminalMode::Headless);
        assert_eq!(TerminalMode::choose(true, true, false), TerminalMode::Headless, "a test start does not take over the user's terminal");
        assert_eq!(TerminalMode::choose(false, false, true), TerminalMode::None);
    }

    /// A second pseudo-terminal stands in for the user's terminal: SAM's
    /// side of it is `Outer`, the test plays the terminal program.
    #[test]
    fn typing_and_output_pass_and_leftover_replies_are_discarded() {
        let (mut user, mut outer_fd) = (-1, -1);
        // SAFETY: `user` and `outer_fd` are valid ints to fill; the optional arguments are null.
        assert_eq!(unsafe { libc::openpty(&mut user, &mut outer_fd, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) }, 0);
        // SAFETY: openpty returned two new descriptors that nothing else owns.
        let (user, outer_fd) = unsafe { (OwnedFd::from_raw_fd(user), OwnedFd::from_raw_fd(outer_fd)) };
        let outer = Outer { input: outer_fd.as_raw_fd(), output: outer_fd.as_raw_fd() };
        let pty = Pty::open(Some(outer)).unwrap();
        let mut cmd = std::process::Command::new("/bin/sh");
        // Reads one line, prints it back, asks for the window title and
        // ends at once: the reply must not stay queued for the shell.
        cmd.args(["-c", r#"read line; printf 'got:%s\n' "$line"; printf '\033]2;evil\007\033[21t\033]52;c;?\007'"#]);
        cmd.stdin(pty.stdio().unwrap()).stdout(pty.stdio().unwrap()).stderr(pty.stdio().unwrap());
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
        let relay = pty.start(OutputSink { head, head_limit: 4096, log, log_limit: 4096 });
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
        assert!(shown.contains("\x1b]2;evil\x07") && !shown.contains("[21t") && !shown.contains("]52"), "{shown:?}");
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
        cmd.stdin(pty.stdio().unwrap()).stdout(pty.stdio().unwrap()).stderr(pty.stdio().unwrap());
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
        let relay = pty.start(OutputSink { head: head.clone(), head_limit: 4096, log, log_limit: 4096 });
        assert!(child.wait().unwrap().success());
        let blocked = relay.finish().blocked;
        let text = head.lock().unwrap().clone();
        assert!(text.starts_with("hello world"), "{text:?}");
        assert!(text.contains("/dev/pts/"), "the app's terminal is a pseudo-terminal: {text:?}");
        assert!(blocked.contains("clipboard"));
    }
}
