//! Game controllers leave the running sandbox when they are unplugged
//! (review R56, owner decision C of 2026-11-25).
//!
//! Bubblewrap shows a controller by name (`/dev/input/event7`). The node it
//! binds stays a node for its device number: once the controller is
//! unplugged, opening it reaches the next device that gets the number,
//! possibly a keyboard, and the old node's access rights still apply. So
//! while the app runs, SAM watches the names of the nodes it gave the app
//! (Linux reports each change in their folder, and SAM looks at least once
//! a second). When a name is gone or shows another device, SAM takes the
//! node out of the sandbox: a child process of the launcher enters the
//! sandbox's namespaces and removes Bubblewrap's bind, leaving Bubblewrap's
//! empty placeholder file. The app keeps running.
//!
//! A handle the app opened before stays a way to the node: through
//! `/proc/self/fd` it can be opened again, and that open, too, goes by the
//! number. Landlock closes it: SAM's Landlock layer lets the app read only
//! below the sandbox's root, and a node taken out is no longer below it,
//! so every new open of it is refused (checked by the tests). So SAM takes
//! a node out only where Landlock is in place and the app cannot make
//! namespaces of its own (they would hold copies of the node that SAM's
//! removal does not reach). Elsewhere, and whenever taking a node out
//! fails, SAM ends the app: a way to another device is never left behind.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use sam_core::sandbox::WatchedDevice;

/// `ioctl(NS_GET_USERNS)`: the user namespace that owns a namespace.
const NS_GET_USERNS: libc::c_ulong = 0xb701;

/// How long SAM waits for Bubblewrap's status line once a watched node has
/// changed before the sandbox is known.
const STATUS_WAIT: Duration = Duration::from_secs(5);

/// A running sandbox's mount namespace, and the user namespace that owns
/// it, held open while the app runs.
pub struct Sandbox {
    user: OwnedFd,
    mnt: OwnedFd,
    /// The mount namespace's inode: what makes a process one of the sandbox.
    ino: u64,
}

impl Sandbox {
    /// The sandbox Bubblewrap announced in its status line
    /// (`--json-status-fd`: `child-pid`, `mnt-namespace`). The mount
    /// namespace's inode is the proof: with "This computer only" the pid is
    /// one of pasta's own process namespace, so every process is looked at
    /// for that namespace, never one taken on the pid's word.
    pub fn from_status(line: &str) -> Result<Sandbox, String> {
        let v: serde_json::Value = serde_json::from_str(line.trim())
            .map_err(|e| format!("Bubblewrap's status line is not readable: {e}"))?;
        let want = v["mnt-namespace"]
            .as_u64()
            .ok_or("Bubblewrap did not report the sandbox's mount namespace")?;
        // Never SAM's own namespace (that of the person's whole session):
        // ending "the sandbox" there would end everything (incident
        // 2026-11-25).
        if want == own_ns("mnt")? {
            return Err("the status line names SAM's own mount namespace, not a sandbox".into());
        }
        let first = v["child-pid"].as_u64().map(|p| p.to_string());
        let others = std::fs::read_dir("/proc")
            .map_err(|e| format!("/proc: {e}"))?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()));
        for pid in first.into_iter().chain(others) {
            let Ok(f) = std::fs::File::open(format!("/proc/{pid}/ns/mnt")) else {
                continue;
            };
            if f.metadata().map(|m| m.ino()).ok() != Some(want) {
                continue;
            }
            let mnt = OwnedFd::from(f);
            // SAFETY: `mnt` is an open namespace descriptor; the call
            // returns a new descriptor or -1.
            let user = unsafe { libc::ioctl(mnt.as_raw_fd(), NS_GET_USERNS) };
            if user < 0 {
                return Err(format!(
                    "the sandbox's user namespace: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: `user` was just returned by the kernel and is owned here alone.
            let user = unsafe { OwnedFd::from_raw_fd(user) };
            // A sandbox of SAM always has its own user namespace: a mount
            // namespace owned by SAM's own is never taken for a sandbox.
            let user_ino = std::fs::File::from(user.try_clone().map_err(|e| e.to_string())?)
                .metadata()
                .map(|m| m.ino())
                .map_err(|e| format!("the sandbox's user namespace: {e}"))?;
            if user_ino == own_ns("user")? {
                return Err("the namespace belongs to SAM's own user namespace, not a sandbox".into());
            }
            return Ok(Sandbox {
                user,
                mnt,
                ino: want,
            });
        }
        Err("no process of the sandbox was found".into())
    }

    /// Ends every process of the sandbox at once (each found by its mount
    /// namespace, signalled through a pidfd taken before the check, so a
    /// process number used again is never hit).
    pub fn end_all(&self) {
        // Checked again right here: never SAM's own namespace.
        if own_ns("mnt").map_or(true, |own| own == self.ino) {
            return;
        }
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return;
        };
        let me = std::process::id() as libc::pid_t;
        for e in rd.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<libc::pid_t>() else {
                continue;
            };
            if pid == me {
                continue;
            }
            let Some(fd) = pidfd(pid) else {
                continue;
            };
            let ours = std::fs::metadata(format!("/proc/{pid}/ns/mnt"))
                .is_ok_and(|m| m.ino() == self.ino);
            if ours {
                signal_kill(&fd);
            }
        }
    }

    /// Takes the node at `path` out of the sandbox: removes Bubblewrap's
    /// bind (and any bind below it), then checks that what is left at the
    /// name is a plain file (Bubblewrap's placeholder), never a device.
    pub fn take_out(&self, path: &Path) -> Result<(), String> {
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let (user, mnt) = (self.user.as_raw_fd(), self.mnt.as_raw_fd());
        // SAFETY: the child runs only raw system calls (setns, umount2,
        // lstat, _exit), which are async-signal-safe, so forking from this
        // threaded process is sound; it never returns into Rust code.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork: {}", std::io::Error::last_os_error()));
        }
        if pid == 0 {
            // SAFETY: see above; every pointer is valid in the child.
            unsafe { libc::_exit(take_out_here(user, mnt, &c)) };
        }
        let mut status = 0;
        // SAFETY: `pid` is this process's own child, waited for once.
        while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("waitpid: {}", std::io::Error::last_os_error()));
            }
        }
        match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
            Some(0) => Ok(()),
            Some(1) => Err("entering the sandbox's user namespace failed".into()),
            Some(2) => Err("entering the sandbox's mount namespace failed".into()),
            Some(3) => Err("the node is still a device after removing its bind".into()),
            Some(4) => Err("the node's name no longer leads to Bubblewrap's placeholder".into()),
            _ => Err(format!("the helper process ended with status {status}")),
        }
    }
}

/// In the forked child: enter the sandbox, remove the binds at `path`,
/// check what is left. Returns the exit code.
///
/// # Safety
/// Only for a freshly forked, single-threaded child.
unsafe fn take_out_here(user: i32, mnt: i32, path: &CString) -> i32 {
    // SAFETY: plain system calls on valid descriptors and a valid C string.
    unsafe {
        if libc::setns(user, libc::CLONE_NEWUSER) != 0 {
            return 1;
        }
        if libc::setns(mnt, libc::CLONE_NEWNS) != 0 {
            return 2;
        }
        let mut st: libc::stat = std::mem::zeroed();
        // A few binds at most (Bubblewrap makes one); each removal shows
        // what was below it.
        for _ in 0..8 {
            if libc::lstat(path.as_ptr(), &mut st) != 0 {
                return 4;
            }
            if st.st_mode & libc::S_IFMT != libc::S_IFCHR {
                break;
            }
            if libc::umount2(path.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) != 0 {
                return 3;
            }
        }
        match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => 0,
            libc::S_IFCHR => 3,
            _ => 4,
        }
    }
}

/// Whether the name still shows the device SAM chose: the same node
/// (devtmpfs makes a new one for every device) for the same number.
fn unchanged(d: &WatchedDevice) -> bool {
    std::fs::metadata(&d.path)
        .is_ok_and(|m| m.dev() == d.dev && m.ino() == d.ino && m.rdev() == d.rdev)
}

/// The inode of SAM's own namespace of this kind (`mnt`, `user`).
fn own_ns(kind: &str) -> Result<u64, String> {
    std::fs::metadata(format!("/proc/self/ns/{kind}"))
        .map(|m| m.ino())
        .map_err(|e| format!("SAM's own {kind} namespace: {e}"))
}

fn pidfd(pid: libc::pid_t) -> Option<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    // SAFETY: a descriptor just returned by the kernel, owned here alone.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn signal_kill(pidfd: &OwnedFd) {
    // SAFETY: a valid pidfd, a signal number, no info, no flags.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
}

/// Ends the sandbox the launcher started (`pid`: Bubblewrap, or pasta
/// around it) at once; Bubblewrap's `--die-with-parent` takes everything
/// inside with it. Through a pidfd taken now, so a process number used
/// again after the sandbox ended is never hit; without pidfds (Linux
/// before 5.3) only while `pid` is still the launcher's unreaped child.
pub fn end_launched(pid: u32) -> Box<dyn FnOnce() + Send> {
    let pid = pid as libc::pid_t;
    let fd = pidfd(pid);
    Box::new(move || match fd {
        Some(fd) => signal_kill(&fd),
        None => {
            // SAFETY: waitid with WNOWAIT only looks; `info` is valid.
            let still_ours = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                ) == 0
            };
            if still_ours {
                // SAFETY: a signal to the launcher's own, not yet reaped child.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    })
}

/// What SAM does when a controller the app was given is unplugged.
pub enum Unplugged {
    /// Takes its node out. Enough only with Landlock in place, which
    /// refuses every new open of a node taken out, also through a handle
    /// the app holds: `helper_report` is what SAM's helper reported it
    /// enforced (none yet: the app has not started, so it holds nothing).
    TakeOut {
        helper_report: Arc<Mutex<Option<String>>>,
    },
    /// Ends the app, for this reason.
    EndApp(String),
}

/// The running watch; [`DeviceWatch::finish`] ends it.
pub struct DeviceWatch {
    /// Written to end the thread at once (an eventfd; -1 without one).
    wake: i32,
    /// Set to end the thread; it looks at least once a second.
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Report>>,
}

/// What the watch did, for the launch log and the start's outcome.
#[derive(Debug, Default)]
pub struct Report {
    /// One line per node taken out, or per failure.
    pub lines: Vec<String>,
    /// SAM ended the app, as a node could not be taken out.
    pub ended_app: bool,
}

impl DeviceWatch {
    /// Watches `nodes` while the app runs. `status` brings Bubblewrap's
    /// first status line (none, when the sender is dropped without one);
    /// `unplugged` says what to do; `end_app` ends the sandbox at once.
    /// `None` when there is nothing to watch.
    pub fn start(
        nodes: Vec<WatchedDevice>,
        status: Receiver<String>,
        unplugged: Unplugged,
        end_app: Box<dyn FnOnce() + Send>,
    ) -> Option<DeviceWatch> {
        if nodes.is_empty() {
            return None;
        }
        // SAFETY: eventfd takes an initial value and flags and returns a new descriptor or -1.
        let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        let stop = Arc::new(AtomicBool::new(false));
        let w = Watch {
            status,
            unplugged,
            end_app: Some(end_app),
            wake,
            stop: stop.clone(),
        };
        let thread = std::thread::spawn(move || w.run(nodes));
        Some(DeviceWatch {
            wake,
            stop,
            thread: Some(thread),
        })
    }

    /// Ends the watch (the app has ended) and returns what it did.
    pub fn finish(mut self) -> Report {
        self.signal();
        self.thread
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default()
    }

    fn signal(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if self.wake >= 0 {
            let one: u64 = 1;
            // SAFETY: writes 8 bytes from a valid u64 to the eventfd.
            unsafe { libc::write(self.wake, (&one as *const u64).cast(), 8) };
        }
    }
}

impl Drop for DeviceWatch {
    fn drop(&mut self) {
        self.signal();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if self.wake >= 0 {
            // SAFETY: the eventfd is closed exactly once, after the thread ended.
            unsafe { libc::close(self.wake) };
        }
    }
}

struct Watch {
    status: Receiver<String>,
    unplugged: Unplugged,
    end_app: Option<Box<dyn FnOnce() + Send>>,
    wake: i32,
    stop: Arc<AtomicBool>,
}

impl Watch {
    fn run(mut self, mut nodes: Vec<WatchedDevice>) -> Report {
        let mut report = Report::default();
        let inotify = Inotify::new(&nodes);
        let mut sandbox: Option<Result<Sandbox, String>> = None;
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return report;
            }
            if sandbox.is_none() {
                match self.status.try_recv() {
                    Ok(line) => sandbox = Some(Sandbox::from_status(&line)),
                    Err(TryRecvError::Disconnected) => {
                        sandbox = Some(Err("Bubblewrap reported no sandbox".into()))
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
            let changed: Vec<usize> = (0..nodes.len())
                .filter(|&i| !unchanged(&nodes[i]))
                .collect();
            if !changed.is_empty() && sandbox.is_none() {
                // Bubblewrap writes the line as soon as the sandbox exists.
                sandbox = Some(match self.status.recv_timeout(STATUS_WAIT) {
                    Ok(line) => Sandbox::from_status(&line),
                    Err(RecvTimeoutError::Timeout) => {
                        Err("Bubblewrap's status line did not come".into())
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        Err("Bubblewrap reported no sandbox".into())
                    }
                });
            }
            for i in changed.into_iter().rev() {
                let d = nodes.remove(i);
                match self.take_out(sandbox.as_ref(), &d.path) {
                    Ok(()) => report.lines.push(format!(
                        "# game controller unplugged: {} taken out of the sandbox",
                        d.path.display()
                    )),
                    Err(why) => {
                        report.lines.push(format!(
                            "# game controller unplugged: {}; SAM ended the app ({why})",
                            d.path.display()
                        ));
                        report.ended_app = true;
                        if let Some(f) = self.end_app.take() {
                            f();
                        }
                        if let Some(Ok(s)) = &sandbox {
                            s.end_all();
                        }
                        return report;
                    }
                }
            }
            if nodes.is_empty() {
                return report;
            }
            // Quickly while the sandbox is still being built, else on a
            // change in the folder, on the end of the app, or after a second.
            let timeout = if sandbox.is_none() { 50 } else { 1000 };
            let mut fds = vec![];
            if self.wake >= 0 {
                fds.push(libc::pollfd {
                    fd: self.wake,
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            if let Some(i) = &inotify {
                fds.push(libc::pollfd {
                    fd: i.0.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            // SAFETY: `fds` is a valid array of pollfd of the given length.
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
            if let Some(i) = &inotify {
                i.drain();
            }
        }
    }

    /// Takes an unplugged controller's node out, where that is enough.
    fn take_out(&self, sandbox: Option<&Result<Sandbox, String>>, path: &Path) -> Result<(), String> {
        let helper_report = match &self.unplugged {
            Unplugged::EndApp(why) => return Err(why.clone()),
            Unplugged::TakeOut { helper_report } => helper_report,
        };
        // The helper reports before it starts the app, so the report is
        // there, or comes within moments; without it, SAM does not know.
        let waited = std::time::Instant::now();
        let report = loop {
            if let Some(r) = helper_report.lock().ok().and_then(|r| r.clone()) {
                break r;
            }
            if waited.elapsed() >= STATUS_WAIT {
                return Err("SAM's helper did not report whether Landlock is in place".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if !(report.contains("landlock: fully enforced")
            || report.contains("landlock: partially enforced"))
        {
            return Err(
                "Landlock is not in place, so a handle the app holds could still reach the next device"
                    .into(),
            );
        }
        match sandbox {
            Some(Ok(s)) => s.take_out(path),
            Some(Err(e)) => Err(e.clone()),
            None => Err("the sandbox is not known".into()),
        }
    }
}

/// Linux's reports of changes in the nodes' folders (nodes made, removed,
/// moved, or their details changed). Without them, SAM looks once a second.
struct Inotify(OwnedFd);

impl Inotify {
    fn new(nodes: &[WatchedDevice]) -> Option<Inotify> {
        // SAFETY: inotify_init1 takes flags only and returns a new descriptor or -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` was just returned by the kernel and is owned here alone.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut dirs: Vec<PathBuf> = nodes
            .iter()
            .filter_map(|d| d.path.parent().map(Path::to_path_buf))
            .collect();
        dirs.sort();
        dirs.dedup();
        let mask = libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_ATTRIB;
        for d in dirs {
            let Ok(c) = CString::new(d.as_os_str().as_bytes()) else {
                continue;
            };
            // SAFETY: valid descriptor and C string.
            unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c.as_ptr(), mask) };
        }
        Some(Inotify(fd))
    }

    fn drain(&self) {
        let mut buf = [0u8; 4096];
        // SAFETY: reads into a valid buffer of its length; non-blocking.
        while unsafe { libc::read(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn landlock(report: &str) -> Unplugged {
        Unplugged::TakeOut {
            helper_report: Arc::new(Mutex::new(Some(report.to_string()))),
        }
    }

    /// A stand-in controller (a link to /dev/null), unplugged after the
    /// watch has started with `status`; whether SAM ended the app.
    fn unplugged_with(status: Option<&str>, unplugged: Unplugged) -> (Report, bool) {
        let t = tempfile::tempdir().unwrap();
        let node = t.path().join("event7");
        std::os::unix::fs::symlink("/dev/null", &node).unwrap();
        let m = std::fs::metadata(&node).unwrap();
        let (tx, rx) = mpsc::channel();
        if let Some(s) = status {
            tx.send(s.to_string()).unwrap();
        } else {
            drop(tx);
        }
        let ended = Arc::new(AtomicBool::new(false));
        let e = ended.clone();
        let w = DeviceWatch::start(
            vec![WatchedDevice {
                path: node.clone(),
                dev: m.dev(),
                ino: m.ino(),
                rdev: m.rdev(),
            }],
            rx,
            unplugged,
            Box::new(move || e.store(true, Ordering::SeqCst)),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(!ended.load(Ordering::SeqCst), "ended while plugged in");
        std::fs::remove_file(&node).unwrap();
        let start = std::time::Instant::now();
        while !ended.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        (w.finish(), ended.load(Ordering::SeqCst))
    }

    /// When SAM cannot reach the sandbox to take an unplugged controller
    /// out, it ends the app: Bubblewrap gave no status line, or one without
    /// the sandbox's mount namespace, or one no process has (review R56).
    #[test]
    fn an_unplugged_controller_that_cannot_be_taken_out_ends_the_app() {
        for status in [
            None,
            Some(r#"{"child-pid": 7}"#),
            Some(r#"{"child-pid": 7, "mnt-namespace": 1}"#),
            Some("not a status line"),
        ] {
            let (report, ended) = unplugged_with(status, landlock("landlock: fully enforced"));
            assert!(ended && report.ended_app, "{status:?}");
            assert!(
                report.lines.iter().any(|l| l.contains("SAM ended the app")),
                "{status:?}: {:?}",
                report.lines
            );
        }
    }

    /// Where taking the node out is not enough (no Landlock, or the app
    /// may make namespaces of its own), an unplugged controller ends the
    /// app (review R56). A stand-in status line that names no namespace
    /// any process has: nothing is ended but the stand-in (the whole
    /// sandbox ending is in tests/device_watch.rs, on isolated computers).
    #[test]
    fn without_landlock_an_unplugged_controller_ends_the_app() {
        let status = r#"{"child-pid": 1, "mnt-namespace": 1}"#.to_string();
        for (unplugged, why) in [
            (landlock("landlock: not enforced"), "Landlock is not in place"),
            (
                Unplugged::TakeOut {
                    helper_report: Arc::new(Mutex::new(None)),
                },
                "did not report",
            ),
            (
                Unplugged::EndApp("the app may make namespaces of its own".into()),
                "namespaces of its own",
            ),
        ] {
            let (report, ended) = unplugged_with(Some(&status), unplugged);
            assert!(ended && report.ended_app, "{why}");
            assert!(
                report.lines.iter().any(|l| l.contains(why)),
                "{why}: {:?}",
                report.lines
            );
        }
    }

    /// When SAM ends a sandbox it cannot keep its promise in, the program
    /// it started ends at once, whatever it does; once that program has
    /// ended, its number is never signalled again (review R56). It sends a
    /// signal: only on an isolated computer.
    #[test]
    fn ending_the_sandbox_ends_it_at_once() {
        use std::os::unix::process::ExitStatusExt;
        if !crate::contracts::isolated_only("ending a started program") {
            return;
        }
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let end = end_launched(child.id());
        end();
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    /// SAM's own namespace (that of the person's whole session) is never
    /// taken for a sandbox, whatever the status line says: ending "the
    /// sandbox" there would end everything (incident 2026-11-25). Only
    /// looks: nothing is ended.
    #[test]
    fn sams_own_namespace_is_never_taken_for_a_sandbox() {
        let own = std::fs::metadata("/proc/self/ns/mnt").unwrap().ino();
        let status = format!(
            r#"{{"child-pid": {}, "mnt-namespace": {own}}}"#,
            std::process::id()
        );
        let e = Sandbox::from_status(&status).err().unwrap();
        assert!(e.contains("SAM's own mount namespace"), "{e}");
    }

    /// Nothing to watch: no watch at all.
    #[test]
    fn no_controller_no_watch() {
        let (_tx, rx) = mpsc::channel();
        let none = Unplugged::EndApp(String::new());
        assert!(DeviceWatch::start(vec![], rx, none, Box::new(|| {})).is_none());
    }
}
