//! Host environment probing: sockets, namespaces, kernel features, tools.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::util::{home_dir, which};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sockets {
    pub wayland: Option<PathBuf>,
    pub wayland_display: String,
    pub x11: Option<PathBuf>,
    pub x11_display: Option<String>,
    pub xauthority: Option<PathBuf>,
    pub pipewire: Option<PathBuf>,
    pub pulse: Option<PathBuf>,
    pub dbus_session_address: Option<String>,
    pub dbus_session: Option<PathBuf>,
    pub dbus_system: Option<PathBuf>,
    pub ssh_agent: Option<PathBuf>,
    pub cups: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsernsStatus {
    pub max_user_namespaces: Option<u64>,
    /// `kernel.unprivileged_userns_clone` (Debian/Arch-hardened knob).
    pub unprivileged_clone: Option<bool>,
    /// Ubuntu 24.04+ AppArmor restriction.
    pub apparmor_restricted: Option<bool>,
    /// bwrap is installed setuid (works even without unprivileged userns).
    pub bwrap_setuid: bool,
}

impl UsernsStatus {
    pub fn usable(&self) -> bool {
        if self.bwrap_setuid {
            return true;
        }
        if self.max_user_namespaces == Some(0) || self.unprivileged_clone == Some(false) {
            return false;
        }
        true
    }

    pub fn explain(&self) -> String {
        if self.max_user_namespaces == Some(0) {
            "User namespaces are disabled on this system (user.max_user_namespaces = 0). Bubblewrap cannot create a sandbox.".into()
        } else if self.unprivileged_clone == Some(false) {
            "Unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone = 0). Enable them with: sudo sysctl kernel.unprivileged_userns_clone=1".into()
        } else if self.apparmor_restricted == Some(true) {
            "AppArmor restricts unprivileged user namespaces. Bubblewrap may need an AppArmor profile (Ubuntu 24.04+).".into()
        } else {
            "User namespaces are available.".into()
        }
    }
}

/// Whether the installed Bubblewrap supports overlays (`--overlay-src`,
/// Bubblewrap 0.10+), which the writable app folder needs. Ubuntu 24.04 and
/// Debian 12 ship older ones. Asked once per process.
pub fn bwrap_supports_overlay() -> bool {
    static CHECKED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CHECKED.get_or_init(|| {
        let Some(path) = crate::util::which("bwrap") else { return false };
        let out = std::process::Command::new(path).arg("--version").output();
        let text = out.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        version_at_least(&text, (0, 10))
    })
}

/// "bubblewrap 0.13.1" -> true for (0, 10).
fn version_at_least(text: &str, want: (u32, u32)) -> bool {
    let v = text.split_whitespace().find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit())).unwrap_or("");
    let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0)) >= want
}

#[cfg(test)]
mod version_tests {
    #[test]
    fn bubblewrap_versions() {
        assert!(super::version_at_least("bubblewrap 0.13.1", (0, 10)));
        assert!(super::version_at_least("bubblewrap 0.10.0\n", (0, 10)));
        assert!(!super::version_at_least("bubblewrap 0.9.0", (0, 10)));
        assert!(!super::version_at_least("", (0, 10)));
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tool {
    pub path: PathBuf,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tools {
    pub bwrap: Option<Tool>,
    pub xdg_dbus_proxy: Option<Tool>,
    pub unsquashfs: Option<Tool>,
    pub bsdtar: Option<Tool>,
    pub strace: Option<Tool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInfo {
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    pub home: PathBuf,
    pub runtime_dir: Option<PathBuf>,
    pub session_type: String,
    pub desktop: String,
    pub arch: String,
    pub kernel: String,
    pub distro: String,
    pub sockets: Sockets,
    pub userns: UsernsStatus,
    pub landlock_abi: Option<u32>,
    pub seccomp: bool,
    pub tools: Tools,
    pub gpu_devices: Vec<PathBuf>,
    pub xdg_dirs: BTreeMap<String, PathBuf>,
}

impl HostInfo {
    /// Fast probe, without running tools to get their versions.
    pub fn probe() -> HostInfo {
        Self::probe_inner(false)
    }

    /// Full probe including tool versions (diagnostics).
    pub fn probe_full() -> HostInfo {
        Self::probe_inner(true)
    }

    fn probe_inner(versions: bool) -> HostInfo {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let home = home_dir();
        let user = std::env::var("USER")
            .ok()
            .filter(|u| !u.is_empty())
            .or_else(|| home.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "user".into());
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_dir());

        let tool = |name: &str, args: &[&str]| -> Option<Tool> {
            which(name).map(|path| Tool {
                version: if versions { tool_version(&path, args) } else { None },
                path,
            })
        };
        let tools = Tools {
            bwrap: tool("bwrap", &["--version"]),
            xdg_dbus_proxy: tool("xdg-dbus-proxy", &["--version"]),
            unsquashfs: tool("unsquashfs", &["-version"]),
            bsdtar: tool("bsdtar", &["--version"]),
            strace: tool("strace", &["-V"]),
        };

        let bwrap_setuid = tools
            .bwrap
            .as_ref()
            .and_then(|t| fs::metadata(&t.path).ok())
            .map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o4000 != 0
            })
            .unwrap_or(false);

        HostInfo {
            uid,
            gid,
            user,
            sockets: probe_sockets(runtime_dir.as_deref(), &home),
            runtime_dir,
            session_type: std::env::var("XDG_SESSION_TYPE").unwrap_or_default(),
            desktop: std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default(),
            arch: std::env::consts::ARCH.into(),
            kernel: read_trim("/proc/sys/kernel/osrelease").unwrap_or_default(),
            distro: os_release_name(),
            userns: UsernsStatus {
                max_user_namespaces: read_trim("/proc/sys/user/max_user_namespaces").and_then(|s| s.parse().ok()),
                unprivileged_clone: read_trim("/proc/sys/kernel/unprivileged_userns_clone").map(|s| s == "1"),
                apparmor_restricted: read_trim("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").map(|s| s == "1"),
                bwrap_setuid,
            },
            landlock_abi: landlock_abi(),
            seccomp: read_trim("/proc/self/status")
                .map(|s| s.lines().any(|l| l.starts_with("Seccomp:")))
                .unwrap_or(false),
            tools,
            gpu_devices: gpu_devices(),
            xdg_dirs: xdg_user_dirs(&home),
            home,
        }
    }

    pub fn xdg_dir(&self, key: &str) -> Option<&Path> {
        self.xdg_dirs.get(key).map(PathBuf::as_path)
    }
}

fn read_trim(p: &str) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn tool_version(path: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new(path).args(args).output().ok()?;
    let text = if out.stdout.is_empty() { out.stderr } else { out.stdout };
    String::from_utf8_lossy(&text).lines().next().map(|l| l.trim().to_string())
}

fn os_release_name() -> String {
    let s = fs::read_to_string("/etc/os-release").unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default()
}

fn probe_sockets(runtime: Option<&Path>, home: &Path) -> Sockets {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let mut s = Sockets::default();

    // Wayland
    let wd = env("WAYLAND_DISPLAY").unwrap_or_else(|| "wayland-0".into());
    s.wayland_display = wd.clone();
    let wpath = if wd.starts_with('/') {
        Some(PathBuf::from(&wd))
    } else {
        runtime.map(|r| r.join(&wd))
    };
    s.wayland = wpath.filter(|p| p.exists());

    // X11
    if let Some(display) = env("DISPLAY") {
        s.x11_display = Some(display.clone());
        if let Some(n) = x11_display_number(&display) {
            let sock = PathBuf::from(format!("/tmp/.X11-unix/X{n}"));
            if sock.exists() {
                s.x11 = Some(sock);
            }
        }
        s.xauthority = env("XAUTHORITY")
            .map(PathBuf::from)
            .or_else(|| Some(home.join(".Xauthority")))
            .filter(|p| p.is_file());
    }

    if let Some(r) = runtime {
        s.pipewire = Some(r.join("pipewire-0")).filter(|p| p.exists());
        s.pulse = Some(r.join("pulse/native")).filter(|p| p.exists());
    }
    if let Some(ps) = env("PULSE_SERVER").and_then(|v| v.strip_prefix("unix:").map(PathBuf::from)) {
        if ps.exists() {
            s.pulse = Some(ps);
        }
    }

    s.dbus_session_address = env("DBUS_SESSION_BUS_ADDRESS");
    s.dbus_session = s
        .dbus_session_address
        .as_deref()
        .and_then(dbus_unix_path)
        .or_else(|| runtime.map(|r| r.join("bus")))
        .filter(|p| p.exists());
    s.dbus_system = Some(PathBuf::from("/run/dbus/system_bus_socket")).filter(|p| p.exists());
    s.ssh_agent = env("SSH_AUTH_SOCK").map(PathBuf::from).filter(|p| p.exists());
    s.cups = Some(PathBuf::from("/run/cups/cups.sock")).filter(|p| p.exists());
    s
}

/// `:0`, `:1.0`, `unix:0` -> `0`. Remote displays return `None`.
pub fn x11_display_number(display: &str) -> Option<String> {
    let (host, rest) = display.rsplit_once(':')?;
    if !(host.is_empty() || host == "unix") {
        return None;
    }
    let num = rest.split('.').next()?;
    (!num.is_empty() && num.chars().all(|c| c.is_ascii_digit())).then(|| num.to_string())
}

/// Extract `path=` from a D-Bus address such as `unix:path=/run/user/1000/bus,guid=...`.
pub fn dbus_unix_path(addr: &str) -> Option<PathBuf> {
    addr.split(';').find_map(|a| {
        let a = a.strip_prefix("unix:")?;
        a.split(',').find_map(|kv| kv.strip_prefix("path=").map(PathBuf::from))
    })
}

fn gpu_devices() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = fs::read_dir("/dev/dri") {
        for e in rd.flatten() {
            v.push(e.path());
        }
    }
    if let Ok(rd) = fs::read_dir("/dev") {
        for e in rd.flatten() {
            let n = e.file_name();
            let n = n.to_string_lossy();
            if n.starts_with("nvidia") {
                v.push(e.path());
            }
        }
    }
    v.sort();
    v
}

/// Parse `~/.config/user-dirs.dirs` with sensible fallbacks.
pub fn xdg_user_dirs(home: &Path) -> BTreeMap<String, PathBuf> {
    let mut m = BTreeMap::new();
    let defaults = [
        ("desktop", "DESKTOP", "Desktop"),
        ("documents", "DOCUMENTS", "Documents"),
        ("downloads", "DOWNLOAD", "Downloads"),
        ("music", "MUSIC", "Music"),
        ("pictures", "PICTURES", "Pictures"),
        ("videos", "VIDEOS", "Videos"),
    ];
    let cfg_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let text = fs::read_to_string(cfg_home.join("user-dirs.dirs")).unwrap_or_default();
    for (key, var, fallback) in defaults {
        let from_file = text.lines().find_map(|l| {
            let l = l.trim();
            let v = l.strip_prefix(&format!("XDG_{var}_DIR="))?;
            let v = v.trim().trim_matches('"');
            let p = if let Some(r) = v.strip_prefix("$HOME/") {
                home.join(r)
            } else if v == "$HOME" {
                home.to_path_buf()
            } else {
                PathBuf::from(v)
            };
            Some(p)
        });
        let p = from_file.unwrap_or_else(|| home.join(fallback));
        // A user dir equal to $HOME means "disabled" in xdg-user-dirs.
        if p != home {
            m.insert(key.to_string(), p);
        }
    }
    m
}

/// Query the Landlock ABI version via `landlock_create_ruleset(NULL, 0, VERSION)`.
pub fn landlock_abi() -> Option<u32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
    {
        const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
        const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
        let r = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<u8>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if r > 0 {
            return Some(r as u32);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_numbers() {
        assert_eq!(x11_display_number(":0").as_deref(), Some("0"));
        assert_eq!(x11_display_number(":1.0").as_deref(), Some("1"));
        assert_eq!(x11_display_number("unix:2").as_deref(), Some("2"));
        assert_eq!(x11_display_number("remote:0"), None);
    }

    #[test]
    fn dbus_paths() {
        assert_eq!(
            dbus_unix_path("unix:path=/run/user/1000/bus,guid=abc"),
            Some(PathBuf::from("/run/user/1000/bus"))
        );
        assert_eq!(dbus_unix_path("unix:abstract=/tmp/dbus-x"), None);
    }
}
