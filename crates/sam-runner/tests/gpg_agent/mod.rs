//! Shared by the tests that run the real GnuPG: signing starts a
//! gpg-agent for the test's GnuPG folder, and it must not outlive the test,
//! also when the test fails partway. [`Stop`] stops it when it is dropped,
//! which Rust does on every way out of the test, a panic included.
//! sam-detect's signature test includes this file too.
#![allow(dead_code)] // a test helper: not every test uses all of it

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn gpgconf(home: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("gpgconf")
        .arg("--homedir")
        .arg(home)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// The process id of the agent that runs for `home`, without starting one.
pub fn pid(home: &Path) -> Option<u32> {
    let o = Command::new("gpg-connect-agent")
        .arg("--homedir")
        .arg(home)
        .args(["--no-autostart", "GETINFO pid", "/bye"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("D ")?.trim().parse().ok())
}

/// Stops the gpg-agent of the GnuPG folder `home` and removes its socket
/// folder, which GnuPG keeps outside the test's folder (in the computer's
/// runtime folder, /run/user/<uid>/gnupg/d.*) and would leave behind.
/// `gpgconf --kill` does not wait until the agent has removed its sockets,
/// and the folder goes only once it is empty: it is tried again until it
/// is gone, for at most 30 seconds.
pub fn stop(home: &Path) {
    let socket_dir = gpgconf(home, &["--list-dirs", "socketdir"]).map(PathBuf::from);
    let _ = gpgconf(home, &["--kill", "all"]);
    let Some(dir) = socket_dir.filter(|d| d.is_absolute() && d != home) else {
        return;
    };
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        let _ = gpgconf(home, &["--remove-socketdir"]);
        if !dir.exists() || Instant::now() >= end {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Stops the agent of its GnuPG folder when dropped: make it right after
/// the folder, so it is dropped before the folder is deleted.
pub struct Stop(PathBuf);

impl Stop {
    pub fn new(home: &Path) -> Stop {
        Stop(home.to_path_buf())
    }
}

impl Drop for Stop {
    fn drop(&mut self) {
        stop(&self.0);
    }
}
