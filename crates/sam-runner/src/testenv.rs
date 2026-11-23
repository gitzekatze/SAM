//! The environment of SAM's tests: the computer without the person's
//! desktop session, a runtime folder of the test's own, and private
//! services (a session bus without services, an SSH agent) instead of the
//! person's. Only tests use this module (keeper.toml, contracts.test_only),
//! so the programs it starts are not SAM's outside assumptions.

/// The computer as a test that starts sandboxes should see it: without the
/// person's desktop session (display, session bus, sound, SSH agent), so the
/// run is the same on a desktop as on CI and never reaches the real
/// compositor or bus. Inside SAM's own test session (tests/gui/session.sh
/// sets SAM_TEST_SESSION=1) that session's display and bus are kept: they
/// are the test's own.
pub fn test_host(host: sam_core::HostInfo) -> sam_core::HostInfo {
    if std::env::var("SAM_TEST_SESSION").as_deref() == Ok("1") {
        host
    } else {
        host.without_desktop()
    }
}

/// The person's desktop session in the environment: dropped by
/// [`isolate_command`] and [`isolate_this_process`].
const DESKTOP_VARS: &[&str] = &[
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "SSH_AUTH_SOCK",
    "PULSE_SERVER",
    "PIPEWIRE_REMOTE",
];

/// The runtime folder for a test rooted at `root` (see `Paths::rooted`),
/// created private, as a runtime folder must be.
fn test_runtime(root: &std::path::Path) -> std::path::PathBuf {
    let run = sam_core::Paths::rooted(root)
        .runtime_root
        .unwrap_or_else(|| root.join("run"));
    let _ = std::fs::create_dir_all(&run);
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700));
    }
    run
}

/// A SAM program started by a test runs the same on every computer: the
/// runtime folder of `Paths::rooted(root)` (SAM_RUNTIME_DIR), no desktop
/// session of the person (kept inside SAM's own test session, see
/// [`test_host`]), English messages.
pub fn isolate_command(cmd: &mut std::process::Command, root: &std::path::Path) {
    if std::env::var("SAM_TEST_SESSION").as_deref() != Ok("1") {
        for v in DESKTOP_VARS {
            cmd.env_remove(v);
        }
        cmd.env("XDG_RUNTIME_DIR", test_runtime(root));
    }
    // The program finds its launches where `Paths::rooted(root)` does.
    cmd.env("SAM_RUNTIME_DIR", test_runtime(root));
    cmd.env("LC_ALL", "C").env_remove("LANGUAGE");
}

/// [`isolate_command`] for the test process itself, for tests that call
/// SAM's functions directly. Changes the environment: only for a test file
/// with a single test, before anything else runs.
pub fn isolate_this_process(root: &std::path::Path) {
    if std::env::var("SAM_TEST_SESSION").as_deref() != Ok("1") {
        for v in DESKTOP_VARS {
            std::env::remove_var(v);
        }
        std::env::set_var("XDG_RUNTIME_DIR", test_runtime(root));
    }
    std::env::set_var("SAM_RUNTIME_DIR", test_runtime(root));
    std::env::set_var("LC_ALL", "C");
    std::env::remove_var("LANGUAGE");
}

/// A session bus without any services and an SSH agent, started for one
/// test and ended with it. Tests use them instead of the person's own, so
/// their bus and agent sections run on every computer, CI included.
pub struct PrivateServices {
    bus: Option<(String, std::path::PathBuf)>,
    agent: Option<std::path::PathBuf>,
    children: Vec<std::process::Child>,
}

impl PrivateServices {
    /// Starts what is installed here (dbus-daemon, ssh-agent), below the
    /// runtime folder of `Paths::rooted(root)` (short socket paths).
    pub fn start(root: &std::path::Path) -> Self {
        use std::process::Stdio;
        let dir = test_runtime(root).join("services");
        let _ = std::fs::create_dir_all(&dir);
        let mut me = PrivateServices {
            bus: None,
            agent: None,
            children: Vec::new(),
        };
        if sam_core::util::which("dbus-daemon").is_some() {
            let socket = dir.join("bus");
            let conf = dir.join("bus.conf");
            let _ = std::fs::write(
                &conf,
                format!(
                    "<busconfig><type>session</type><listen>unix:path={}</listen>\
                     <policy context=\"default\"><allow send_destination=\"*\" eavesdrop=\"true\"/>\
                     <allow eavesdrop=\"true\"/><allow own=\"*\"/></policy></busconfig>",
                    socket.display()
                ),
            );
            if let Ok(mut child) = service("dbus-daemon")
                .arg(format!("--config-file={}", conf.display()))
                .args(["--nofork", "--print-address=1"])
                .stdout(Stdio::piped())
                .spawn()
            {
                let mut address = String::new();
                if let Some(out) = child.stdout.take() {
                    let _ = std::io::BufRead::read_line(
                        &mut std::io::BufReader::new(out),
                        &mut address,
                    );
                }
                if !address.trim().is_empty() {
                    me.bus = Some((address.trim().to_string(), socket));
                }
                me.children.push(child);
            }
        }
        if sam_core::util::which("ssh-agent").is_some() {
            let socket = dir.join("agent");
            if let Ok(child) = service("ssh-agent")
                .arg("-D")
                .arg("-a")
                .arg(&socket)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                me.children.push(child);
                let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !socket.exists() && std::time::Instant::now() < end {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                if socket.exists() {
                    me.agent = Some(socket);
                }
            }
        }
        me
    }

    /// The private session bus's address, if dbus-daemon is installed.
    pub fn bus_address(&self) -> Option<&str> {
        self.bus.as_ref().map(|(a, _)| a.as_str())
    }

    /// `host` with these as its session bus and SSH agent; the process's
    /// SSH_AUTH_SOCK points at this agent (or is removed). Changes the
    /// environment: only for a test file with a single test.
    pub fn apply_to_this_process(&self, mut host: sam_core::HostInfo) -> sam_core::HostInfo {
        if let Some((address, socket)) = &self.bus {
            host.sockets.dbus_session_address = Some(address.clone());
            host.sockets.dbus_session = Some(socket.clone());
        }
        host.sockets.ssh_agent = self.agent.clone();
        match &self.agent {
            Some(a) => std::env::set_var("SSH_AUTH_SOCK", a),
            None => std::env::remove_var("SSH_AUTH_SOCK"),
        }
        host
    }
}

/// A private service's command: the service ends with the test process
/// however that ends (killed, a closed output pipe, an abort), when no
/// `Drop` runs, and it inherits no descriptor above the standard three.
/// On 2026-11-23 a dbus-daemon and an ssh-agent that outlived their test
/// held a build slot's lock for 5.5 hours.
fn service(program: &str) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let mut c = std::process::Command::new(program);
    // SAFETY: getpid has no preconditions.
    let parent = unsafe { libc::getpid() };
    // SAFETY: runs between fork and exec and calls only prctl, getppid,
    // syscall(close_range), fcntl and _exit, which are async-signal-safe.
    unsafe {
        c.pre_exec(move || {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            // The test process may have ended before prctl took effect.
            if libc::getppid() != parent {
                libc::_exit(1);
            }
            let marked = libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            if marked != 0 {
                // Before Linux 5.11: one by one.
                for fd in 3..65536 {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags >= 0 {
                        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                    }
                }
            }
            Ok(())
        });
    }
    c
}

impl Drop for PrivateServices {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PrivateServices;
    use std::fs;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    const NAME: &str =
        "testenv::tests::private_services_end_with_the_test_process_that_started_them";
    const CHILD: &str = "SAM_TEST_SERVICES_HOLDER";

    /// Gone, or only a zombie waiting for its parent to collect it.
    fn ended(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(s) => s
                .rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
        }
    }

    /// TEST-LEAK (2026-11-23): a test process killed while it holds private
    /// services takes them along, and they never held one of its
    /// descriptors: a pipe the test process inherited reaches its end
    /// once the test process is gone, and both services have ended. (A
    /// service that outlived its test held a build lock for hours.)
    #[test]
    fn private_services_end_with_the_test_process_that_started_them() {
        if let Some(dir) = std::env::var_os(CHILD) {
            let services = PrivateServices::start(std::path::Path::new(&dir));
            let pids: Vec<String> = services
                .children
                .iter()
                .map(|c| c.id().to_string())
                .collect();
            sam_core::outln!("pids: {}", pids.join(" "));
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        if sam_core::util::which("dbus-daemon").is_none()
            || sam_core::util::which("ssh-agent").is_none()
        {
            crate::contracts::skip("dbus-daemon and ssh-agent are needed")
                .unwrap_or_else(|e| panic!("{e}"));
            return;
        }
        let root = tempfile::tempdir().unwrap();
        // A pipe whose write end the test process inherits, as it inherits
        // a build lock (only it: other tests here start programs too).
        let mut ends = [0; 2];
        // SAFETY: pipe2 writes two descriptors into the array.
        let made = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(made, 0);
        // SAFETY: both descriptors were just made and belong to this test.
        let (read, write) =
            unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        let inherited = write.as_raw_fd();
        let mut holder = std::process::Command::new(std::env::current_exe().unwrap());
        holder
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, root.path())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        // SAFETY: between fork and exec only dup2, which is
        // async-signal-safe; the copy has no close-on-exec mark.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut holder, move || {
                if libc::dup2(inherited, 10) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut holder = holder.spawn().unwrap();
        // From now on only the holder holds the write end.
        drop(write);
        let out = holder.stdout.take().unwrap();
        // The holder's line with the services' numbers, within a minute.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in std::io::BufRead::lines(std::io::BufReader::new(out)).map_while(Result::ok) {
                // After the test harness's "test NAME ... " on the same line.
                if let Some((_, rest)) = l.split_once("pids: ") {
                    let _ = tx.send(rest.to_string());
                    return;
                }
            }
        });
        let line = rx
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|_| {
                let _ = holder.kill();
                panic!("the holder never said which services it started")
            });
        let pids: Vec<u32> = line
            .split_whitespace()
            .map(|p| p.parse().unwrap())
            .collect();
        assert_eq!(pids.len(), 2, "both services started: {line:?}");
        // While they run, neither holds the pipe the holder inherited.
        let pipe = {
            use std::os::unix::fs::MetadataExt;
            let ino = fs::metadata(format!("/proc/self/fd/{}", read.as_raw_fd()))
                .unwrap()
                .ino();
            format!("pipe:[{ino}]")
        };
        // (ssh-agent hides its descriptors from everyone: it makes itself
        // non-dumpable. dbus-daemon shows them.)
        let mut looked = 0;
        for p in &pids {
            let Ok(fds) = fs::read_dir(format!("/proc/{p}/fd")) else {
                continue;
            };
            let held: Vec<String> = fds
                .flatten()
                .filter_map(|e| fs::read_link(e.path()).ok())
                .map(|t| t.display().to_string())
                .collect();
            assert!(!held.contains(&pipe), "service {p} holds {pipe}: {held:?}");
            looked += 1;
        }
        assert!(looked > 0, "at least one service shows its descriptors");
        holder.kill().unwrap();
        holder.wait().unwrap();
        // The pipe ends when nobody holds its write end any more.
        let fd = read.as_raw_fd();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut buf = [0u8; 1];
        let at_end = loop {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            if unsafe { libc::poll(&mut pfd, 1, 200) } > 0 {
                // SAFETY: reads at most one byte into `buf`.
                break unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 1) } == 0;
            }
            if Instant::now() > deadline {
                break false;
            }
        };
        assert!(at_end, "no service kept the test process's descriptor");
        while !pids.iter().all(|p| ended(*p)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        for p in &pids {
            assert!(ended(*p), "service {p} ended with the test process");
        }
    }
}
