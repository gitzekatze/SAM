// SPDX-License-Identifier: GPL-3.0-or-later
//! The sandbox check's probe. SAM starts an app's exact sandbox (same
//! Bubblewrap command, Landlock, syscall filter, D-Bus filter, network), but
//! the helper runs these checks instead of the app, after every layer is in
//! place, and prints the results. Every check is harmless: nothing is
//! written (write tests use invisible O_TMPFILE files), no network traffic
//! leaves the computer.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What the check should find, computed outside the sandbox from the
/// settings and from what this computer has.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProbePlan {
    pub checks: Vec<ProbeCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeCheck {
    pub id: String,
    /// Settings group, as in the GUI ("Files", "Network", …).
    pub group: String,
    pub title: String,
    pub test: ProbeTest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Access {
    /// The real folder is not visible (absent, or only an empty private one).
    Hidden,
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeTest {
    /// A host folder: `host_id` is its (device, inode) on the host, which a
    /// bind mount keeps, so the probe can tell the real folder from an
    /// empty private one with the same name.
    Folder {
        path: PathBuf,
        host_id: Option<(u64, u64)>,
        expect: Access,
    },
    /// A file or socket is present / absent.
    Present {
        path: PathBuf,
        expect: bool,
    },
    /// A file exists but cannot be read.
    Unreadable {
        path: PathBuf,
    },
    /// Nothing can be created in this folder.
    NotWritable {
        path: PathBuf,
    },
    /// An environment variable: `None` = must be unset.
    Env {
        name: String,
        expect: Option<String>,
    },
    /// The Wayland socket named by $WAYLAND_DISPLAY.
    Wayland {
        expect: bool,
    },
    /// An X11 socket and $DISPLAY.
    X11 {
        expect: bool,
    },
    /// The PulseAudio socket in $XDG_RUNTIME_DIR.
    Audio {
        expect: bool,
    },
    /// The raw PipeWire socket in $XDG_RUNTIME_DIR.
    PipeWire {
        expect: bool,
    },
    /// Only the loopback interface and no default route.
    NoNetwork,
    /// A default route exists (full network).
    Network,
    /// TCP connection to 127.0.0.1:port succeeds / fails.
    LocalPort {
        port: u16,
        expect: bool,
    },
    /// The session bus: `None` = no session bus at all.
    SessionBus {
        expect: bool,
    },
    /// A name on the session bus is reachable / hidden.
    BusName {
        name: String,
        expect: bool,
    },
    NoNewPrivileges,
    NoCapabilities,
    /// Own process list (PID namespace).
    OwnProcesses,
    /// Creating a user namespace is blocked (or allowed).
    UserNamespaces {
        blocked: bool,
    },
    /// The baseline syscall filter blocks keyring syscalls.
    SyscallFilter {
        active: bool,
    },
    /// Typing into the terminal (TIOCSTI) is refused by the syscall filter.
    NoTerminalInjection {
        active: bool,
    },
    /// The kernel-level write protection reported by the helper.
    Landlock {
        expect: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub id: String,
    pub group: String,
    pub title: String,
    /// `Some(true)` passed, `Some(false)` failed, `None` could not be checked.
    pub ok: Option<bool>,
    /// What the probe found, in plain words.
    pub observed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProbeReport {
    pub results: Vec<ProbeResult>,
    /// The helper's enforcement line ("landlock: fully enforced; …").
    pub enforcement: String,
}

impl ProbeReport {
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.ok == Some(true)).count()
    }
    pub fn failed(&self) -> Vec<&ProbeResult> {
        self.results.iter().filter(|r| r.ok == Some(false)).collect()
    }
}

/// Marker the helper prints before the JSON report.
pub const REPORT_MARKER: &str = "SAM-PROBE-REPORT:";

/// Runs the plan inside the sandbox. Checks that change the process itself
/// (user namespaces) run last.
pub fn run(plan: &ProbePlan, enforcement: &str) -> ProbeReport {
    let mut checks: Vec<&ProbeCheck> = plan.checks.iter().collect();
    checks.sort_by_key(|c| matches!(c.test, ProbeTest::UserNamespaces { .. }));
    let results = checks
        .into_iter()
        .map(|c| {
            let (ok, observed) = check(&c.test, enforcement);
            ProbeResult { id: c.id.clone(), group: c.group.clone(), title: c.title.clone(), ok, observed }
        })
        .collect();
    ProbeReport { results, enforcement: enforcement.to_string() }
}

fn pass(s: impl Into<String>) -> (Option<bool>, String) {
    (Some(true), s.into())
}
fn fail(s: impl Into<String>) -> (Option<bool>, String) {
    (Some(false), s.into())
}
fn skip(s: impl Into<String>) -> (Option<bool>, String) {
    (None, s.into())
}

/// (device, inode) of a path, following symlinks.
pub fn identity(p: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
}

/// Can a new file be created in `dir`? Uses an unnamed O_TMPFILE file that
/// disappears when closed, so nothing ever shows up in the folder.
fn can_create_in(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else { return false };
    // SAFETY: `c` is a NUL-terminated path; the returned descriptor is checked and closed below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_TMPFILE | libc::O_WRONLY | libc::O_CLOEXEC, 0o600) };
    if fd >= 0 {
        // SAFETY: the descriptor opened above is closed exactly once here.
        unsafe { libc::close(fd) };
        return true;
    }
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if e == libc::EOPNOTSUPP || e == libc::EISDIR {
        // File systems without O_TMPFILE: a hidden file, removed at once.
        let probe = dir.join(format!(".sam-check-{}", std::process::id()));
        if std::fs::OpenOptions::new().write(true).create_new(true).open(&probe).is_ok() {
            let _ = std::fs::remove_file(&probe);
            return true;
        }
    }
    false
}

fn check(t: &ProbeTest, enforcement: &str) -> (Option<bool>, String) {
    match t {
        ProbeTest::Folder { path, host_id, expect } => {
            let here = identity(path);
            let real = match (here, host_id) {
                (Some(a), Some(b)) => a == *b,
                (Some(_), None) => true,
                (None, _) => false,
            };
            let readable = real && std::fs::read_dir(path).is_ok();
            let writable = real && can_create_in(path);
            let seen = match (real, readable, writable) {
                (false, _, _) if here.is_some() => "only an empty private folder",
                (false, _, _) => "not visible",
                (true, _, true) => "can read and write",
                (true, true, false) => "can read, cannot write",
                (true, false, false) => "visible, cannot read",
            };
            let ok = match expect {
                Access::Hidden => !real,
                Access::ReadOnly => readable && !writable,
                Access::ReadWrite => writable,
            };
            (Some(ok), seen.to_string())
        }
        ProbeTest::Present { path, expect } => {
            let there = std::fs::symlink_metadata(path).is_ok();
            let seen = if there { "present" } else { "absent" };
            (Some(there == *expect), seen.into())
        }
        ProbeTest::NotWritable { path } => {
            if can_create_in(path) {
                fail("can be written")
            } else {
                pass("cannot be written")
            }
        }
        ProbeTest::Unreadable { path } => match std::fs::File::open(path) {
            Ok(_) => fail("can be read"),
            Err(_) => pass("cannot be read"),
        },
        ProbeTest::Env { name, expect } => {
            let v = std::env::var(name).ok();
            match (expect, &v) {
                (None, None) => pass("not set"),
                (None, Some(_)) => fail("set"),
                (Some(e), Some(v)) if e == v => pass("set as expected"),
                (Some(_), Some(_)) => fail("set to a different value"),
                (Some(_), None) => fail("not set"),
            }
        }
        ProbeTest::Wayland { expect } => {
            let sock = std::env::var("WAYLAND_DISPLAY").ok().and_then(|d| std::env::var("XDG_RUNTIME_DIR").ok().map(|r| Path::new(&r).join(d)));
            let there = sock.is_some_and(|s| s.exists());
            (Some(there == *expect), if there { "connected".into() } else { "no Wayland socket".to_string() })
        }
        ProbeTest::X11 { expect } => {
            let there = std::env::var("DISPLAY").is_ok() && std::fs::read_dir("/tmp/.X11-unix").is_ok_and(|mut d| d.next().is_some());
            (Some(there == *expect), if there { "X11 socket present".into() } else { "no X11 socket".to_string() })
        }
        ProbeTest::Audio { expect } => {
            let rt = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
            let there = Path::new(&rt).join("pulse/native").exists();
            (Some(there == *expect), if there { "sound socket present".into() } else { "no sound socket".to_string() })
        }
        ProbeTest::PipeWire { expect } => {
            let rt = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
            let there = Path::new(&rt).join("pipewire-0").exists();
            (Some(there == *expect), if there { "PipeWire socket present".into() } else { "no PipeWire socket".to_string() })
        }
        ProbeTest::NoNetwork | ProbeTest::Network => {
            let ifaces = interfaces();
            let route = has_default_route();
            let seen = format!("interfaces: {}; {}", ifaces.join(", "), if route { "default route" } else { "no default route" });
            let ok = match t {
                ProbeTest::NoNetwork => !route && ifaces.iter().all(|i| i == "lo"),
                _ => route,
            };
            (Some(ok), seen)
        }
        ProbeTest::LocalPort { port, expect } => {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], *port));
            let open = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok();
            (Some(open == *expect), if open { "reachable".into() } else { "not reachable".to_string() })
        }
        ProbeTest::SessionBus { expect } => {
            let addr = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
            let works = addr.as_deref().is_some_and(|a| crate::dbus_check::name_reachable(a, "org.freedesktop.DBus", Duration::from_secs(2)).is_ok());
            (Some(works == *expect), if works { "connected".into() } else { "no session bus".to_string() })
        }
        ProbeTest::BusName { name, expect } => {
            let Ok(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") else { return skip("no session bus") };
            match crate::dbus_check::name_reachable(&addr, name, Duration::from_secs(2)) {
                Ok(r) => (Some(r == *expect), if r { "reachable".into() } else { "hidden".to_string() }),
                Err(e) => skip(format!("could not ask the bus: {e}")),
            }
        }
        ProbeTest::NoNewPrivileges => match status_field("NoNewPrivs") {
            Some(v) if v == "1" => pass("cannot gain privileges"),
            Some(_) => fail("could gain privileges (setuid)"),
            None => skip("unknown"),
        },
        ProbeTest::NoCapabilities => match status_field("CapEff") {
            Some(v) if v.trim_start_matches('0').is_empty() => pass("none"),
            Some(v) => fail(format!("has capabilities ({v})")),
            None => skip("unknown"),
        },
        ProbeTest::OwnProcesses => {
            let n = std::fs::read_dir("/proc")
                .map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit())).count())
                .unwrap_or(0);
            (Some(n > 0 && n < 20), format!("sees {n} process(es)"))
        }
        ProbeTest::UserNamespaces { blocked } => {
            // SAFETY: unshare takes a flag and changes only this probe process, which exits after the check.
            let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            let is_blocked = r != 0;
            (Some(is_blocked == *blocked), if is_blocked { "blocked".into() } else { "allowed".to_string() })
        }
        ProbeTest::SyscallFilter { active } => {
            // keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0):
            // the baseline filter answers EPERM.
            // SAFETY: keyctl is called with plain integers only (the probe expects it to be refused).
            let r = unsafe { libc::syscall(libc::SYS_keyctl, 0, -3, 0) };
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            let filtered = r < 0 && e == libc::EPERM;
            (Some(filtered == *active), if filtered { "active".into() } else { "not active".to_string() })
        }
        ProbeTest::NoTerminalInjection { active } => {
            // ioctl(0, TIOCSTI): the baseline filter answers EPERM before the
            // kernel looks at the descriptor.
            let c: u8 = 0;
            // SAFETY: `c` is a valid byte for TIOCSTI to read (the probe expects the call to be refused).
            let r = unsafe { libc::ioctl(0, libc::TIOCSTI, &c) };
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            let blocked = r < 0 && e == libc::EPERM;
            (Some(blocked == *active), if blocked { "blocked".into() } else { "not blocked by the filter".to_string() })
        }
        ProbeTest::Landlock { expect } => {
            let on = enforcement.contains("landlock: fully enforced") || enforcement.contains("landlock: partially enforced");
            (Some(on == *expect), if on { "active".into() } else { "not active".to_string() })
        }
    }
}

fn interfaces() -> Vec<String> {
    std::fs::read_to_string("/proc/net/dev").unwrap_or_default().lines().skip(2).filter_map(|l| l.split(':').next().map(|s| s.trim().to_string())).collect()
}

/// A default route in /proc/net/route (IPv4) or /proc/net/ipv6_route.
pub fn has_default_route() -> bool {
    let v4 = std::fs::read_to_string("/proc/net/route").unwrap_or_default().lines().skip(1).any(|l| l.split_whitespace().nth(1) == Some("00000000"));
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default().lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() > 9 && f[0] == "00000000000000000000000000000000" && f[1] == "00" && f[9] != "lo"
    });
    v4 || v6
}

fn status_field(name: &str) -> Option<String> {
    std::fs::read_to_string("/proc/self/status").ok()?.lines().find_map(|l| l.strip_prefix(&format!("{name}:")).map(|v| v.trim().to_string()))
}

/// TCP ports something listens on, on the host (/proc/net/tcp{,6}).
pub fn listening_ports() -> Vec<u16> {
    let mut out = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for l in std::fs::read_to_string(f).unwrap_or_default().lines().skip(1) {
            let cols: Vec<&str> = l.split_whitespace().collect();
            if cols.len() > 3 && cols[3] == "0A" {
                if let Some(port) = cols[1].rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok()) {
                    out.push(port);
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sandbox check tells a real folder of the user from a private stand-in.
    #[test]
    fn folder_check_tells_real_from_private() {
        let t = tempfile::tempdir().unwrap();
        let id = identity(t.path());
        let rw = check(&ProbeTest::Folder { path: t.path().into(), host_id: id, expect: Access::ReadWrite }, "");
        assert_eq!(rw.0, Some(true), "{}", rw.1);
        // Same name, different folder: counts as hidden.
        let other = check(&ProbeTest::Folder { path: t.path().into(), host_id: Some((0, 1)), expect: Access::Hidden }, "");
        assert_eq!(other.0, Some(true), "{}", other.1);
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 0, "write test leaves nothing behind");
    }
}
