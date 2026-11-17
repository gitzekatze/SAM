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
        use std::process::{Command, Stdio};
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
            if let Ok(mut child) = Command::new("dbus-daemon")
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
            if let Ok(child) = Command::new("ssh-agent")
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

impl Drop for PrivateServices {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
