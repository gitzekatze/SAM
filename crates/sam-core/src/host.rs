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
            crate::i18n::tr("User namespaces are disabled on this system (user.max_user_namespaces = 0). Bubblewrap cannot create a sandbox. If you want sandboxes here, install Bubblewrap setuid (Arch: the bubblewrap-suid package; Debian: sudo dpkg-statoverride --update --add root root 4755 /usr/bin/bwrap): only Bubblewrap gets this right, not every program. This, too, changes the system; SAM never does it itself.")
        } else if self.unprivileged_clone == Some(false) {
            // Not "switch the setting on": that would open user namespaces to
            // every program and make the computer less safe than without SAM.
            crate::i18n::tr("Unprivileged user namespaces are disabled on this system (kernel.unprivileged_userns_clone = 0), a deliberate hardening. Keep it. If you want sandboxes here, install Bubblewrap setuid instead (Arch: the bubblewrap-suid package; Debian: sudo dpkg-statoverride --update --add root root 4755 /usr/bin/bwrap): only Bubblewrap gets this right, not every program. This, too, changes the system; SAM never does it itself.")
        } else if self.apparmor_restricted == Some(true) {
            crate::i18n::tr("AppArmor restricts unprivileged user namespaces (Ubuntu 24.04 and later), a deliberate hardening. Keep it. Give Bubblewrap alone the right with the restricted profile that comes with AppArmor: sudo cp /usr/share/apparmor/extra-profiles/bwrap-userns-restrict /etc/apparmor.d/ and sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict. Its cost: apps in the sandbox cannot start sandboxes of their own, which SAM does not allow by default anyway. Never use an unconfined profile for bwrap or switch the restriction off: that lifts it for every program.")
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
    try_overlay_with(&bwrap, dir)
}

/// [`try_overlay_in`] with the Bubblewrap at `bwrap`: true only when its
/// folders could be made and `bwrap` ran the overlay successfully.
fn try_overlay_with(bwrap: &std::path::Path, dir: &std::path::Path) -> bool {
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

    /// The overlay check believes Bubblewrap's answer: a Bubblewrap that
    /// fails means no overlay, even though the check's folders could be
    /// made (NFS, eCryptfs, another overlay), and one that succeeds means
    /// a working overlay. Stand-ins for Bubblewrap; the real one is
    /// compared in sam-runner's host_probe tests. Either way the check's
    /// folder is gone afterwards.
    #[test]
    fn the_overlay_check_believes_bubblewraps_answer() {
        let tmp = tempfile::tempdir().unwrap();
        let probe = tmp
            .path()
            .join(format!(".overlay-check-{}", std::process::id()));
        let fails = crate::util::which("false").expect("false is installed");
        let works = crate::util::which("true").expect("true is installed");
        assert!(!super::try_overlay_with(&fails, tmp.path()));
        assert!(!probe.exists(), "the check's folder is removed");
        assert!(super::try_overlay_with(&works, tmp.path()));
        assert!(!probe.exists(), "the check's folder is removed");
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
    /// PipeWire's program, which also runs SAM's sound relay.
    pub pipewire: Option<Tool>,
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

    /// This computer without the person's desktop session: no display, no
    /// session bus, no sound, no SSH agent. Tests that start sandboxes use
    /// it, so they run the same code on a desktop as on a bare CI machine
    /// and never reach the real compositor or session bus; the desktop
    /// parts are tested in a session of their own (tests/gui/).
    pub fn without_desktop(mut self) -> HostInfo {
        let s = &mut self.sockets;
        s.wayland = None;
        s.wayland_display = String::new();
        s.x11 = None;
        s.x11_display = None;
        s.xauthority = None;
        s.pipewire = None;
        s.pulse = None;
        s.dbus_session_address = None;
        s.dbus_session = None;
        s.ssh_agent = None;
        self.session_type = String::new();
        self.desktop = String::new();
        self
    }

    fn probe_inner(versions: bool) -> HostInfo {
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        // SAFETY: getgid has no preconditions and cannot fail.
        let gid = unsafe { libc::getgid() };
        let home = home_dir();
        let user = user_name(std::env::var("USER").ok(), &home);
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
            pipewire: tool("pipewire", &["--version"]),
        };

        let bwrap_setuid = tools.bwrap.as_ref().is_some_and(|t| is_setuid(&t.path));

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
            userns: userns_status(read_trim, bwrap_setuid),
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

/// The user's name: `$USER` when it is set and not empty, else the home
/// folder's name, else "user". It becomes the sandbox's `USER`, `LOGNAME`
/// and the name in its passwd and group files.
fn user_name(env_user: Option<String>, home: &Path) -> String {
    env_user
        .filter(|u| !u.is_empty())
        .or_else(|| home.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "user".into())
}

/// Whether the file at `path` carries the setuid bit (a missing file does
/// not).
fn is_setuid(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o4000 != 0)
}

/// The kernel's user namespace settings, each read by `read` (a file's
/// trimmed text, `None` where the file is missing).
fn userns_status(read: impl Fn(&str) -> Option<String>, bwrap_setuid: bool) -> UsernsStatus {
    UsernsStatus {
        max_user_namespaces: read("/proc/sys/user/max_user_namespaces")
            .and_then(|s| s.parse().ok()),
        unprivileged_clone: read("/proc/sys/kernel/unprivileged_userns_clone").map(|s| s == "1"),
        apparmor_restricted: read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .map(|s| s == "1"),
        bwrap_setuid,
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

/// How to install `package` here: the command of this distribution's
/// package manager, found by the `ID` and `ID_LIKE` lines of
/// `/etc/os-release` (audit T2: every system was told `sudo pacman -S`).
pub fn install_hint(package: &str) -> String {
    let os = fs::read_to_string("/etc/os-release").unwrap_or_default();
    match install_command(&os, package) {
        Some(cmd) => crate::i18n::trf("Install it: {command}", &[("command", &cmd)]),
        None => crate::i18n::trf(
            "Install the package \"{package}\" with your distribution's package manager.",
            &[("package", &package)],
        ),
    }
}

/// The install command for `package` on the system `os_release` describes.
fn install_command(os_release: &str, package: &str) -> Option<String> {
    let field = |key: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_ascii_lowercase())
            .unwrap_or_default()
    };
    let (id, like) = (field("ID"), field("ID_LIKE"));
    let ids: Vec<&str> = std::iter::once(id.as_str())
        .chain(like.split_whitespace())
        .collect();
    // By the start of the name too: "opensuse-leap", "rhel-like" builds.
    let is = |names: &[&str]| ids.iter().any(|i| names.iter().any(|n| i.starts_with(n)));
    let manager = if is(&["arch"]) {
        "sudo pacman -S"
    } else if is(&["debian", "ubuntu"]) {
        "sudo apt install"
    } else if is(&["fedora", "rhel", "centos"]) {
        "sudo dnf install"
    } else if is(&["opensuse", "suse", "sles"]) {
        "sudo zypper install"
    } else if is(&["alpine"]) {
        "sudo apk add"
    } else if is(&["void"]) {
        "sudo xbps-install"
    } else {
        return None;
    };
    Some(format!("{manager} {package}"))
}

fn os_release_name() -> String {
    let s = fs::read_to_string("/etc/os-release").unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default()
}

/// `p` when it is a socket. The paths come from variables of the user's
/// session; a wrong value (a file instead of a socket, for example a key)
/// must never be shared with a sandbox as if it were a desktop service.
fn socket(p: PathBuf) -> Option<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(&p)
        .is_ok_and(|m| m.file_type().is_socket())
        .then_some(p)
}

fn probe_sockets(runtime: Option<&Path>, home: &Path) -> Sockets {
    probe_sockets_with(&|k| std::env::var(k).ok(), runtime, home)
}

/// [`probe_sockets`] with the session's variables read by `var`; an empty
/// variable counts as unset.
fn probe_sockets_with(
    var: &dyn Fn(&str) -> Option<String>,
    runtime: Option<&Path>,
    home: &Path,
) -> Sockets {
    let env = |k: &str| var(k).filter(|v| !v.is_empty());
    let mut s = Sockets::default();

    // Wayland
    let wd = env("WAYLAND_DISPLAY").unwrap_or_else(|| "wayland-0".into());
    s.wayland_display = wd.clone();
    let wpath = if wd.starts_with('/') {
        Some(PathBuf::from(&wd))
    } else {
        runtime.map(|r| r.join(&wd))
    };
    s.wayland = wpath.and_then(socket);

    // X11
    if let Some(display) = env("DISPLAY") {
        s.x11_display = Some(display.clone());
        if let Some(n) = x11_display_number(&display) {
            s.x11 = socket(PathBuf::from(format!("/tmp/.X11-unix/X{n}")));
        }
        s.xauthority = env("XAUTHORITY")
            .map(PathBuf::from)
            .or_else(|| Some(home.join(".Xauthority")))
            .filter(|p| p.is_file());
    }

    if let Some(r) = runtime {
        s.pipewire = socket(r.join("pipewire-0"));
        s.pulse = socket(r.join("pulse/native"));
    }
    if let Some(ps) = env("PULSE_SERVER")
        .and_then(|v| v.strip_prefix("unix:").map(PathBuf::from))
        .and_then(socket)
    {
        s.pulse = Some(ps);
    }

    s.dbus_session_address = env("DBUS_SESSION_BUS_ADDRESS");
    s.dbus_session = s
        .dbus_session_address
        .as_deref()
        .and_then(dbus_unix_path)
        .or_else(|| runtime.map(|r| r.join("bus")))
        .and_then(socket);
    s.dbus_system = socket(PathBuf::from("/run/dbus/system_bus_socket"));
    s.ssh_agent = env("SSH_AUTH_SOCK").map(PathBuf::from).and_then(socket);
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
    // The user's data folder where it is set elsewhere, and the runtime
    // folder's services (audit L-F13).
    for (var, sub) in [
        ("XDG_DATA_HOME", "dbus-1/services"),
        ("XDG_RUNTIME_DIR", "dbus-1/services"),
    ] {
        if let Some(d) = std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|d| d.is_absolute())
        {
            dirs.push(d.join(sub));
        }
    }
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
    loader_lib_dirs_from(
        Path::new("/etc/ld.so.conf.d"),
        PathBuf::from("/usr/local/lib"),
    )
}

/// [`loader_lib_dirs`] from the files in `conf_d`, in the order of their
/// names, after `local`; only folders that exist.
fn loader_lib_dirs_from(conf_d: &Path, local: PathBuf) -> Vec<PathBuf> {
    let mut dirs = vec![local];
    if let Ok(rd) = fs::read_dir(conf_d) {
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
    keep_extra_lib_dirs(loader_lib_dirs(), home)
}

/// The folders below which the loader's extra library folders may be shown.
const LIB_ROOTS: [&str; 2] = ["/opt", "/usr/local"];

/// The folders of `dirs` that [`extra_lib_dirs`] keeps.
fn keep_extra_lib_dirs(dirs: Vec<PathBuf>, home: &Path) -> Vec<PathBuf> {
    let roots: Vec<PathBuf> = LIB_ROOTS.iter().map(PathBuf::from).collect();
    keep_extra_lib_dirs_with(dirs, home, &roots, &real_place)
}

/// Where a path really leads, every link followed; `None` when that cannot
/// be found.
fn real_place(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

/// [`keep_extra_lib_dirs`] with the allowed `roots` and `real` telling where
/// a path leads. The read-only bind follows links and `..` as the real
/// place does, so a folder is kept only when its real place is known and
/// both its name and its real place pass (review B2 R60: `/opt/../run` or a
/// link below `/opt` to `/run` passed as text). A root's own real place counts as
/// allowed too, as on Fedora Atomic, where `/opt` leads to `/var/opt`,
/// unless it is `/`, a system area or the home.
fn keep_extra_lib_dirs_with(
    dirs: Vec<PathBuf>,
    home: &Path,
    roots: &[PathBuf],
    real: &dyn Fn(&Path) -> Option<PathBuf>,
) -> Vec<PathBuf> {
    let shown = |d: &Path| {
        [
            "/usr/lib",
            "/usr/lib32",
            "/usr/lib64",
            "/lib",
            "/lib32",
            "/lib64",
        ]
        .iter()
        .any(|s| d.starts_with(s))
    };
    let homes: Vec<PathBuf> = [Some(home.to_path_buf()), real(home)]
        .into_iter()
        .flatten()
        .collect();
    let in_home = |d: &Path| homes.iter().any(|h| d.starts_with(h));
    let system = |d: &Path| {
        d.parent().is_none()
            || [Path::new("/usr"), Path::new("/var")].contains(&d)
            || ["/etc", "/run", "/proc", "/sys", "/dev", "/boot", "/root"]
                .iter()
                .any(|s| d.starts_with(s))
    };
    let real_roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|r| real(r))
        .filter(|r| !system(r) && !shown(r) && !in_home(r))
        .collect();
    let below = |d: &Path, roots: &[PathBuf]| roots.iter().any(|r| d.starts_with(r));
    dirs.into_iter()
        .filter(|d| {
            let Some(to) = real(d) else {
                return false;
            };
            below(d, roots)
                && !shown(d)
                && !in_home(d)
                && (below(&to, roots) || below(&to, &real_roots))
                && !shown(&to)
                && !in_home(&to)
        })
        .collect()
}

fn gpu_devices() -> Vec<PathBuf> {
    gpu_devices_in(Path::new("/dev"))
}

/// The graphics devices in the device folder `dev`: everything in `dri/`
/// and the `nvidia*` entries, sorted.
fn gpu_devices_in(dev: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = fs::read_dir(dev.join("dri")) {
        for e in rd.flatten() {
            v.push(e.path());
        }
    }
    if let Ok(rd) = fs::read_dir(dev) {
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
    let cfg_home = config_home(std::env::var_os("XDG_CONFIG_HOME"), home);
    let text = fs::read_to_string(cfg_home.join("user-dirs.dirs")).unwrap_or_default();
    parse_user_dirs(&text, home)
}

/// The user's config folder: `$XDG_CONFIG_HOME` when it is set and not
/// empty, else `~/.config`.
fn config_home(var: Option<std::ffi::OsString>, home: &Path) -> PathBuf {
    var.filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
}

/// The user folders from the text of `user-dirs.dirs`, with the usual
/// names as fallbacks; a folder set to $HOME means "disabled".
fn parse_user_dirs(text: &str, home: &Path) -> BTreeMap<String, PathBuf> {
    let mut m = BTreeMap::new();
    let defaults = [
        ("desktop", "DESKTOP", "Desktop"),
        ("documents", "DOCUMENTS", "Documents"),
        ("downloads", "DOWNLOAD", "Downloads"),
        ("music", "MUSIC", "Music"),
        ("pictures", "PICTURES", "Pictures"),
        ("videos", "VIDEOS", "Videos"),
    ];
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
mod socket_tests {
    use super::{activatable_bus_names, parse_user_dirs, probe_sockets_with, socket};
    use std::path::Path;

    /// The sockets given to a sandbox follow the user's session: a set
    /// variable names the socket (WAYLAND_DISPLAY=wayland-7 is not
    /// wayland-0, which may be another compositor's), and an empty one
    /// counts as unset, so the usual places are used.
    #[test]
    fn the_sockets_follow_the_sessions_variables() {
        use std::os::unix::net::UnixListener;
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let run = t.join("run");
        let home = t.join("home");
        std::fs::create_dir_all(run.join("pulse")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let _listeners = [
            run.join("wayland-0"),
            run.join("wayland-7"),
            run.join("pulse/native"),
            run.join("bus"),
            t.join("pulse-other"),
            t.join("bus-other"),
            t.join("agent"),
        ]
        .map(|p| UnixListener::bind(p).unwrap());
        let xauth = t.join("xauth");
        std::fs::write(&xauth, "").unwrap();
        std::fs::write(home.join(".Xauthority"), "").unwrap();
        let bus_address = format!("unix:path={}", t.join("bus-other").display());
        let set = |k: &str| -> Option<String> {
            Some(match k {
                "WAYLAND_DISPLAY" => "wayland-7".into(),
                "DISPLAY" => ":5".into(),
                "XAUTHORITY" => xauth.display().to_string(),
                "PULSE_SERVER" => format!("unix:{}", t.join("pulse-other").display()),
                "DBUS_SESSION_BUS_ADDRESS" => bus_address.clone(),
                "SSH_AUTH_SOCK" => t.join("agent").display().to_string(),
                _ => return None,
            })
        };
        let s = probe_sockets_with(&set, Some(&run), &home);
        assert_eq!(s.wayland_display, "wayland-7");
        assert_eq!(s.wayland, Some(run.join("wayland-7")));
        assert_eq!(s.x11_display.as_deref(), Some(":5"));
        assert_eq!(s.xauthority, Some(xauth.clone()));
        assert_eq!(s.pulse, Some(t.join("pulse-other")));
        assert_eq!(s.dbus_session_address, Some(bus_address.clone()));
        assert_eq!(s.dbus_session, Some(t.join("bus-other")));
        assert_eq!(s.ssh_agent, Some(t.join("agent")));

        let empty = |_: &str| Some(String::new());
        let s = probe_sockets_with(&empty, Some(&run), &home);
        assert_eq!(s.wayland_display, "wayland-0");
        assert_eq!(s.wayland, Some(run.join("wayland-0")));
        assert_eq!(s.x11_display, None);
        assert_eq!(s.xauthority, None, "no display, no X11 key");
        assert_eq!(s.pulse, Some(run.join("pulse/native")));
        assert_eq!(s.dbus_session_address, None);
        assert_eq!(s.dbus_session, Some(run.join("bus")));
        assert_eq!(s.ssh_agent, None);
    }

    /// `$XDG_CONFIG_HOME` decides where user-dirs.dirs is read, so which
    /// real folder a Documents or Downloads permission shows; an empty one
    /// counts as unset, never as the current folder.
    #[test]
    fn the_user_folders_are_read_from_the_users_config_folder() {
        let home = Path::new("/home/u");
        let c = |v: Option<&str>| super::config_home(v.map(Into::into), home);
        assert_eq!(c(Some("/x/cfg")), Path::new("/x/cfg"));
        assert_eq!(c(Some("")), home.join(".config"));
        assert_eq!(c(None), home.join(".config"));
    }

    /// Services that start on demand are recognized from their folders,
    /// including the user's own (contract dbus-activatable).
    #[test]
    fn services_that_start_on_demand_are_recognized() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".local/share/dbus-1/services");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("org.example.OnDemand.service"),
            "[D-BUS Service]\nName=org.example.OnDemand\nExec=/usr/bin/false\n",
        )
        .unwrap();
        assert!(activatable_bus_names(home.path()).contains("org.example.OnDemand"));
    }

    /// The user folders come from user-dirs.dirs, with the usual names as
    /// fallbacks; a folder set to $HOME is disabled (contract xdg-folders).
    #[test]
    fn user_folders_come_from_user_dirs_dirs() {
        let home = Path::new("/home/u");
        let m = parse_user_dirs(
            "XDG_DOCUMENTS_DIR=\"$HOME/Dokumente\"\nXDG_DOWNLOAD_DIR=\"/data/dl\"\nXDG_MUSIC_DIR=\"$HOME\"\n",
            home,
        );
        assert_eq!(m["documents"], home.join("Dokumente"));
        assert_eq!(m["downloads"], Path::new("/data/dl"));
        assert_eq!(m["pictures"], home.join("Pictures"), "fallback");
        assert!(!m.contains_key("music"), "$HOME means disabled");
    }

    #[test]
    fn only_a_real_socket_counts_as_a_desktop_service() {
        let dir = std::env::temp_dir().join(format!("sam-socket-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("id_ed25519");
        std::fs::write(&file, "secret").unwrap();
        let sock = dir.join("wayland-test");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert_eq!(socket(file.clone()), None, "a file is not a socket");
        assert_eq!(socket(dir.clone()), None, "a folder is not a socket");
        assert_eq!(socket(dir.join("missing")), None);
        assert_eq!(socket(sock.clone()), Some(sock));
        std::fs::remove_dir_all(&dir).unwrap();
    }
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
        // Only digits make a display number: it names a socket in the
        // world-writable /tmp/.X11-unix.
        assert_eq!(x11_display_number(":"), None);
        assert_eq!(x11_display_number(":abc"), None);
        assert_eq!(x11_display_number(":0x"), None);
        assert_eq!(x11_display_number(":1/../X0"), None);
    }

    /// Only library folders a sandbox does not show anyway and that may be
    /// shown are kept: below /opt or /usr/local, never below the home
    /// folder (also where the home is itself below /opt) or in /etc, /var
    /// or /run.
    #[test]
    fn only_library_folders_outside_the_home_and_system_areas_are_shown() {
        let dirs = [
            "/opt/cuda/lib64",
            "/usr/local/lib",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib32",
            "/lib64",
            "/etc/foo",
            "/var/lib/x",
            "/run/x",
            "/home/u/lib",
            "/opt/home/u/lib",
        ];
        let keep = |home: &str| -> Vec<String> {
            keep_extra_lib_dirs_with(
                dirs.iter().map(PathBuf::from).collect(),
                Path::new(home),
                &LIB_ROOTS.map(PathBuf::from),
                &|d| Some(d.to_path_buf()),
            )
            .iter()
            .map(|d| d.display().to_string())
            .collect()
        };
        assert_eq!(keep("/opt/home/u"), ["/opt/cuda/lib64", "/usr/local/lib"]);
        assert_eq!(
            keep("/home/u"),
            ["/opt/cuda/lib64", "/usr/local/lib", "/opt/home/u/lib"]
        );
    }

    /// A library folder is judged by its name and by where it leads: a name
    /// with `..` or a link below /opt that leads into a system area or the
    /// home, or a folder whose real place is unknown, is not shown (review
    /// B2 R60).
    #[test]
    fn library_folders_are_judged_by_where_they_lead() {
        let real = |d: &Path| -> Option<PathBuf> {
            match d.to_str()? {
                "/opt/link" => Some("/run/x".into()),
                "/opt/tolib" => Some("/usr/lib/x".into()),
                "/opt/tohome" => Some("/opt/home/u/lib".into()),
                "/opt/fine" => Some("/opt/real/lib".into()),
                "/opt/../run/x" => Some("/run/x".into()),
                _ => None,
            }
        };
        let dirs = [
            "/opt/../run/x",
            "/opt/link",
            "/opt/tolib",
            "/opt/tohome",
            "/opt/fine",
            "/opt/unknown",
        ];
        let kept = keep_extra_lib_dirs_with(
            dirs.iter().map(PathBuf::from).collect(),
            Path::new("/opt/home/u"),
            &LIB_ROOTS.map(PathBuf::from),
            &real,
        );
        assert_eq!(kept, [PathBuf::from("/opt/fine")]);
    }

    /// The same on a real file system, with the real lookup: a root that
    /// leads elsewhere (Fedora Atomic's `/opt` to `/var/opt`) still shows
    /// its folders; a link out of a root, into the home (a home below
    /// /opt, known by its linked name) or through a root that leads to `/`
    /// does not.
    #[test]
    fn library_folders_follow_real_links() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let t = fs::canonicalize(tmp.path()).unwrap();
        for d in ["opt/fine", "elsewhere", "var/local/lib", "opt/home/lib"] {
            fs::create_dir_all(t.join(d)).unwrap();
        }
        symlink(t.join("elsewhere"), t.join("opt/link")).unwrap();
        symlink(t.join("opt/home/lib"), t.join("opt/tohome")).unwrap();
        symlink("/run", t.join("opt/sys")).unwrap();
        symlink(t.join("var/local"), t.join("local")).unwrap();
        symlink("/", t.join("rootlink")).unwrap();
        symlink(t.join("opt/home"), t.join("homelink")).unwrap();
        let dirs = [
            "opt/fine",
            "opt/link",
            "opt/tohome",
            "opt/sys",
            "opt/gone",
            "local/lib",
            "rootlink/run",
        ];
        let roots = ["opt", "local", "rootlink"].map(|r| t.join(r));
        let kept = keep_extra_lib_dirs_with(
            dirs.iter().map(|d| t.join(d)).collect(),
            &t.join("homelink"),
            &roots,
            &real_place,
        );
        assert_eq!(kept, [t.join("opt/fine"), t.join("local/lib")]);
    }

    /// The loader's folders come from the files in ld.so.conf.d in the
    /// order of their names, after /usr/local/lib: only lines that name a
    /// folder, and only folders that exist.
    #[test]
    fn the_loaders_folders_come_from_its_config_files() {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let conf = t.join("ld.so.conf.d");
        for d in ["local", "x/lib", "y", "z", "ld.so.conf.d"] {
            std::fs::create_dir_all(t.join(d)).unwrap();
        }
        let p = |d: &str| t.join(d).display().to_string();
        std::fs::write(
            conf.join("b.conf"),
            format!(
                "{}\n  {}  \n# {}\ninclude other.conf\n{}\n",
                p("x/lib"),
                p("y"),
                p("z"),
                p("missing")
            ),
        )
        .unwrap();
        std::fs::write(conf.join("c.conf"), format!("{}\n", p("z"))).unwrap();
        std::fs::write(conf.join("a.conf"), "relative/lib\n").unwrap();
        assert_eq!(
            loader_lib_dirs_from(&conf, t.join("local")),
            [t.join("local"), t.join("x/lib"), t.join("y"), t.join("z")]
        );
        assert_eq!(
            loader_lib_dirs_from(&t.join("none"), t.join("missing")),
            Vec::<PathBuf>::new()
        );
    }

    /// The graphics devices are everything in dri/ and the nvidia* entries,
    /// sorted, and nothing else of the device folder.
    #[test]
    fn the_graphics_devices_are_found_in_the_device_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let dev = tmp.path();
        std::fs::create_dir_all(dev.join("dri")).unwrap();
        for f in [
            "dri/renderD128",
            "dri/card0",
            "nvidiactl",
            "nvidia0",
            "null",
            "video0",
        ] {
            std::fs::write(dev.join(f), "").unwrap();
        }
        assert_eq!(
            gpu_devices_in(dev),
            [
                dev.join("dri/card0"),
                dev.join("dri/renderD128"),
                dev.join("nvidia0"),
                dev.join("nvidiactl")
            ]
        );
        assert_eq!(gpu_devices_in(&dev.join("none")), Vec::<PathBuf>::new());
    }

    /// The sandbox's user name is `$USER`; where that is empty or unset,
    /// the home folder's name, and "user" where there is none.
    #[test]
    fn the_user_name_is_users_or_the_home_folders() {
        let bob = Path::new("/home/bob");
        assert_eq!(user_name(Some("alice".into()), bob), "alice");
        assert_eq!(user_name(Some(String::new()), bob), "bob");
        assert_eq!(user_name(None, bob), "bob");
        assert_eq!(user_name(None, Path::new("/")), "user");
    }

    /// A setuid Bubblewrap is told from a normal one by its file's setuid
    /// bit: only a setuid one works where user namespaces are switched off.
    #[test]
    fn a_setuid_bubblewrap_is_told_from_a_normal_one() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("bwrap");
        std::fs::write(&f, "").unwrap();
        let mode = |m: u32| std::fs::set_permissions(&f, std::fs::Permissions::from_mode(m));
        mode(0o755).unwrap();
        assert!(!is_setuid(&f));
        mode(0o4755).unwrap();
        assert!(is_setuid(&f));
        assert!(!is_setuid(&tmp.path().join("missing")));
    }

    /// The kernel's user namespace knobs are read as they are meant: "1"
    /// is on, "0" off, a missing file unknown (the AppArmor restriction
    /// of Ubuntu 24.04 and later included).
    #[test]
    fn the_user_namespace_knobs_are_read_as_meant() {
        let read = |values: &'static [(&'static str, &'static str)]| {
            move |p: &str| {
                values
                    .iter()
                    .find(|(k, _)| p.ends_with(k))
                    .map(|(_, v)| v.to_string())
            }
        };
        let on = userns_status(
            read(&[
                ("max_user_namespaces", "0"),
                ("unprivileged_userns_clone", "1"),
                ("apparmor_restrict_unprivileged_userns", "1"),
            ]),
            false,
        );
        assert_eq!(on.max_user_namespaces, Some(0));
        assert_eq!(on.unprivileged_clone, Some(true));
        assert_eq!(on.apparmor_restricted, Some(true));
        let off = userns_status(
            read(&[
                ("max_user_namespaces", "63000"),
                ("unprivileged_userns_clone", "0"),
                ("apparmor_restrict_unprivileged_userns", "0"),
            ]),
            true,
        );
        assert_eq!(off.max_user_namespaces, Some(63000));
        assert_eq!(off.unprivileged_clone, Some(false));
        assert_eq!(off.apparmor_restricted, Some(false));
        assert!(off.bwrap_setuid);
        let none = userns_status(read(&[]), false);
        assert_eq!(none.max_user_namespaces, None);
        assert_eq!(none.unprivileged_clone, None);
        assert_eq!(none.apparmor_restricted, None);
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

#[cfg(test)]
mod install_hint_tests {
    use super::install_command;

    /// Where AppArmor restricts user namespaces, the advice names the
    /// restricted profile for Bubblewrap alone and what it costs, and warns
    /// against the ways that lift the restriction for every program (audit
    /// A3).
    #[test]
    fn the_apparmor_advice_keeps_the_restriction_for_other_programs() {
        let s = super::UsernsStatus {
            apparmor_restricted: Some(true),
            ..Default::default()
        };
        let text = s.explain();
        assert!(text.contains("bwrap-userns-restrict"), "{text}");
        assert!(text.contains("Its cost"), "{text}");
        assert!(text.contains("Never use an unconfined profile"), "{text}");
    }

    /// The install hint names this distribution's package manager, also on
    /// derivatives (by `ID_LIKE`), and none where SAM does not know it
    /// (audit T2).
    #[test]
    fn the_install_hint_fits_the_distribution() {
        let c = |os: &str| install_command(os, "bubblewrap");
        assert_eq!(c("ID=arch\n").as_deref(), Some("sudo pacman -S bubblewrap"));
        assert_eq!(
            c("ID=cachyos\nID_LIKE=arch\n").as_deref(),
            Some("sudo pacman -S bubblewrap")
        );
        assert_eq!(
            c("ID=ubuntu\nID_LIKE=debian\n").as_deref(),
            Some("sudo apt install bubblewrap")
        );
        assert_eq!(
            c("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n").as_deref(),
            Some("sudo apt install bubblewrap")
        );
        assert_eq!(
            c("ID=fedora\n").as_deref(),
            Some("sudo dnf install bubblewrap")
        );
        assert_eq!(
            c("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n").as_deref(),
            Some("sudo dnf install bubblewrap")
        );
        assert_eq!(
            c("ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n").as_deref(),
            Some("sudo zypper install bubblewrap")
        );
        assert_eq!(c("ID=alpine\n").as_deref(), Some("sudo apk add bubblewrap"));
        assert_eq!(
            c("ID=void\n").as_deref(),
            Some("sudo xbps-install bubblewrap")
        );
        assert_eq!(
            c("ID=\"opensuse-leap\"\n").as_deref(),
            Some("sudo zypper install bubblewrap")
        );
        assert_eq!(c("ID=nixos\n"), None);
        // On this computer: a whole sentence that names the package.
        let here = super::install_hint("bubblewrap");
        assert!(
            here.contains("bubblewrap") && here.len() > "bubblewrap".len() + 10,
            "{here}"
        );
        assert_eq!(c(""), None);
        // A key that only starts like ID is not ID.
        assert_eq!(c("IDX=arch\nVERSION_ID=1\n"), None);
    }
}
