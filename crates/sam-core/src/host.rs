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
            crate::i18n::tr("User namespaces are disabled on this system (user.max_user_namespaces = 0). Bubblewrap cannot create a sandbox.")
        } else if self.unprivileged_clone == Some(false) {
            crate::i18n::tr("Unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone = 0). Enable them with: sudo sysctl kernel.unprivileged_userns_clone=1")
        } else if self.apparmor_restricted == Some(true) {
            crate::i18n::tr("AppArmor restricts unprivileged user namespaces. Bubblewrap may need an AppArmor profile (Ubuntu 24.04+).")
        } else {
            crate::i18n::tr("User namespaces are available.")
        }
    }
}

/// Whether the installed Bubblewrap supports overlays (`--overlay-src`,
/// Bubblewrap 0.10+), which the writable app folder needs. Ubuntu 24.04 and
/// Debian 12 ship older ones. Asked once per process.
pub fn bwrap_supports_overlay() -> bool {
    static CHECKED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CHECKED.get_or_init(|| {
        let Some(path) = crate::util::which("bwrap") else {
            return false;
        };
        let out = std::process::Command::new(path).arg("--version").output();
        let text = out
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        version_at_least(&text, (0, 10))
    })
}

/// Whether an overlay with its changes kept in `dir` really works: the
/// Bubblewrap version is not enough, because some filesystems cannot hold
/// an overlay's changes (NFS, eCryptfs, some FUSE filesystems, another
/// overlay such as a container's). Tried once per folder with a real
/// overlay in a throwaway sandbox; `dir` is created if needed.
pub fn overlay_works_in(dir: &std::path::Path) -> bool {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CHECKED: Mutex<Option<HashMap<std::path::PathBuf, bool>>> = Mutex::new(None);
    if !bwrap_supports_overlay() {
        return false;
    }
    let mut cache = CHECKED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(&known) = cache.get_or_insert_with(HashMap::new).get(dir) {
        return known;
    }
    let works = try_overlay_in(dir);
    cache
        .get_or_insert_with(HashMap::new)
        .insert(dir.to_path_buf(), works);
    works
}

fn try_overlay_in(dir: &std::path::Path) -> bool {
    let Some(bwrap) = crate::util::which("bwrap") else {
        return false;
    };
    let probe = dir.join(format!(".overlay-check-{}", std::process::id()));
    remove_stale_probes(dir);
    let made = std::fs::create_dir_all(dir).is_ok()
        && ["lower", "upper", "work"]
            .iter()
            .all(|d| std::fs::create_dir_all(probe.join(d)).is_ok());
    let works = made
        && std::process::Command::new(bwrap)
            .args([
                "--unshare-user",
                "--ro-bind",
                "/",
                "/",
                "--tmpfs",
                "/tmp",
                "--overlay-src",
            ])
            .arg(probe.join("lower"))
            .arg("--overlay")
            .arg(probe.join("upper"))
            .arg(probe.join("work"))
            .args(["/tmp/o", "true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
    remove_probe(&probe);
    works
}

/// Removes what checks of SAM's that no longer run left behind (older
/// versions could not remove the overlay's locked work folder).
fn remove_stale_probes(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(".overlay-check-"))
        else {
            continue;
        };
        if pid.parse::<u32>().is_ok() && !std::path::Path::new("/proc").join(pid).exists() {
            remove_probe(&e.path());
        }
    }
}

/// Removes the overlay check's folder. The overlay leaves `work/work`
/// without any permissions; it belongs to the user, so it is opened first.
fn remove_probe(probe: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        probe.join("work/work"),
        std::fs::Permissions::from_mode(0o700),
    );
    let _ = std::fs::remove_dir_all(probe);
}

/// "bubblewrap 0.13.1" -> true for (0, 10).
fn version_at_least(text: &str, want: (u32, u32)) -> bool {
    let v = text
        .split_whitespace()
        .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or("");
    let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0)) >= want
}

#[cfg(test)]
mod probe_tests {
    /// The overlay check leaves nothing behind, even the work folder the
    /// overlay locks (a leftover folder per check piled up in SAM's data).
    #[test]
    fn the_overlay_check_leaves_no_folder_behind() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let probe = tmp.path().join(".overlay-check-1");
        std::fs::create_dir_all(probe.join("work/work")).unwrap();
        std::fs::create_dir_all(probe.join("upper")).unwrap();
        std::fs::set_permissions(
            probe.join("work/work"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        super::remove_probe(&probe);
        assert!(!probe.exists());
    }

    /// Folders left by earlier checks whose process is gone are removed;
    /// one of a check still running stays.
    #[test]
    fn leftovers_of_earlier_overlay_checks_are_removed() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        // Process ids above the kernel's limit (4194304) never exist.
        let old = tmp.path().join(".overlay-check-4194399");
        std::fs::create_dir_all(old.join("work/work")).unwrap();
        std::fs::set_permissions(
            old.join("work/work"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let running = tmp
            .path()
            .join(format!(".overlay-check-{}", std::process::id()));
        std::fs::create_dir_all(&running).unwrap();
        let other = tmp.path().join("appimage-krita-1234");
        std::fs::create_dir_all(&other).unwrap();
        super::remove_stale_probes(tmp.path());
        assert!(!old.exists());
        assert!(running.exists());
        assert!(other.exists(), "only the checks' own folders are touched");
    }
}

#[cfg(test)]
mod version_tests {
    /// Bubblewrap versions are compared correctly, including missing or malformed version text.
    #[test]
    fn bubblewrap_versions_are_compared_correctly() {
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
    /// Library folders outside `/usr` and `/lib` that the system's loader
    /// searches (see [`extra_lib_dirs`]), e.g. `/opt/cuda/lib64`.
    #[serde(default)]
    pub extra_lib_dirs: Vec<PathBuf>,
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
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        // SAFETY: getgid has no preconditions and cannot fail.
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
                version: if versions {
                    tool_version(&path, args)
                } else {
                    None
                },
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
                max_user_namespaces: read_trim("/proc/sys/user/max_user_namespaces")
                    .and_then(|s| s.parse().ok()),
                unprivileged_clone: read_trim("/proc/sys/kernel/unprivileged_userns_clone")
                    .map(|s| s == "1"),
                apparmor_restricted: read_trim(
                    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                )
                .map(|s| s == "1"),
                bwrap_setuid,
            },
            landlock_abi: landlock_abi(),
            seccomp: read_trim("/proc/self/status")
                .map(|s| s.lines().any(|l| l.starts_with("Seccomp:")))
                .unwrap_or(false),
            tools,
            gpu_devices: gpu_devices(),
            extra_lib_dirs: extra_lib_dirs(&home),
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
    let text = if out.stdout.is_empty() {
        out.stderr
    } else {
        out.stdout
    };
    String::from_utf8_lossy(&text)
        .lines()
        .next()
        .map(|l| l.trim().to_string())
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
    s.ssh_agent = env("SSH_AUTH_SOCK")
        .map(PathBuf::from)
        .filter(|p| p.exists());
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
        a.split(',')
            .find_map(|kv| kv.strip_prefix("path=").map(PathBuf::from))
    })
}

/// D-Bus names that services on this computer start on demand (their
/// `.service` files, e.g. `org.kde.kwalletd6`). Such a name is free until
/// something asks for the service, so an app must never take one: it would
/// receive what is meant for the service (a password manager's requests).
pub fn activatable_bus_names(home: &Path) -> std::collections::BTreeSet<String> {
    let mut dirs: Vec<PathBuf> = vec![
        home.join(".local/share/dbus-1/services"),
        PathBuf::from("/usr/local/share/dbus-1/services"),
        PathBuf::from("/usr/share/dbus-1/services"),
    ];
    if let Ok(x) = std::env::var("XDG_DATA_DIRS") {
        dirs.extend(
            x.split(':')
                .filter(|d| d.starts_with('/'))
                .map(|d| Path::new(d).join("dbus-1/services")),
        );
    }
    let mut names = std::collections::BTreeSet::new();
    for d in dirs {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let Ok(text) = fs::read_to_string(e.path()) else {
                continue;
            };
            names.extend(
                text.lines()
                    .filter_map(|l| l.trim().strip_prefix("Name="))
                    .map(|n| n.trim().to_string()),
            );
        }
    }
    names
}

/// Library folders listed in `/etc/ld.so.conf.d` (the loader's search
/// path, set up by packages such as CUDA or ROCm), plus `/usr/local/lib`.
pub fn loader_lib_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/usr/local/lib")];
    if let Ok(rd) = fs::read_dir("/etc/ld.so.conf.d") {
        let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files {
            if let Ok(s) = fs::read_to_string(&f) {
                dirs.extend(
                    s.lines()
                        .map(str::trim)
                        .filter(|l| l.starts_with('/'))
                        .map(PathBuf::from),
                );
            }
        }
    }
    dirs.retain(|d| d.is_dir());
    dirs.dedup();
    dirs
}

/// [`loader_lib_dirs`] that a sandbox does not show otherwise (outside
/// `/usr/lib*` and `/lib*`) and that may be shown read-only: never below the
/// home folder or a system area like `/etc`, `/var` or `/run`.
pub fn extra_lib_dirs(home: &Path) -> Vec<PathBuf> {
    loader_lib_dirs()
        .into_iter()
        .filter(|d| {
            let shown = [
                "/usr/lib",
                "/usr/lib32",
                "/usr/lib64",
                "/lib",
                "/lib32",
                "/lib64",
            ]
            .iter()
            .any(|s| d.starts_with(s));
            let allowed = ["/opt", "/usr/local"].iter().any(|r| d.starts_with(r));
            !shown && allowed && !d.starts_with(home)
        })
        .collect()
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
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    {
        const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
        const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
        // SAFETY: asks the kernel for its Landlock version: a null attribute pointer with size 0 is what the version query expects.
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

    /// The X11 display number is read from every common DISPLAY form, and remote displays are refused.
    #[test]
    fn the_x11_display_number_is_read_from_every_display_form() {
        assert_eq!(x11_display_number(":0").as_deref(), Some("0"));
        assert_eq!(x11_display_number(":1.0").as_deref(), Some("1"));
        assert_eq!(x11_display_number("unix:2").as_deref(), Some("2"));
        assert_eq!(x11_display_number("remote:0"), None);
    }

    /// Only real socket paths are taken from a D-Bus address; abstract sockets are not.
    #[test]
    fn only_real_socket_paths_are_taken_from_a_dbus_address() {
        assert_eq!(
            dbus_unix_path("unix:path=/run/user/1000/bus,guid=abc"),
            Some(PathBuf::from("/run/user/1000/bus"))
        );
        assert_eq!(dbus_unix_path("unix:abstract=/tmp/dbus-x"), None);
    }
}
