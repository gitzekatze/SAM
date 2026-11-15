//! Dynamic dependency fallback.
//!
//! The app is launched once in diagnostic mode under `strace`, inside the
//! *same* sandbox (never with full home access). Failed file and socket
//! accesses are collected and classified:
//!
//! * low risk (read-only shared data under /usr/share, /etc): applied
//!   automatically when `dependencies.automatic_low_risk_fixes` is on
//! * medium/high risk (devices, sockets, home folders): only suggested

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use sam_core::risk::{is_sensitive_path, RiskLevel};
use sam_core::util::tildify;
use sam_core::{AppEntry, HostInfo, PermissionSet};
use serde::Serialize;

use crate::launch::{run, LaunchOptions};
use crate::ops::Sam;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: String,
    pub error: String,
    pub risk: RiskLevel,
    pub suggestion: String,
    /// `(permission key, value)` that would fix it.
    pub fix: Option<(String, String)>,
    pub applied: bool,
    /// The fix is already in effect, so the access failed for another
    /// reason; `trace_line` shows the call as the app made it.
    pub already_granted: bool,
    /// The failed call, exactly as strace recorded it.
    pub trace_line: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnoseResult {
    pub findings: Vec<Finding>,
    pub applied: usize,
    pub log_file: Option<PathBuf>,
    /// The full trace of the diagnostic run, kept in the app's log folder.
    pub trace_file: Option<PathBuf>,
    pub launch_summary: String,
}

const ETC_SENSITIVE: &[&str] =
    &["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh", "/etc/NetworkManager", "/etc/polkit-1", "/etc/pam.d", "/etc/security"];

/// System calls that change a file rather than read or reach it.
const CHANGE_CALLS: &[&str] = &[
    "chmod",
    "fchmodat",
    "fchmodat2",
    "chown",
    "lchown",
    "fchownat",
    "utime",
    "utimes",
    "utimensat",
    "futimesat",
    "mkdir",
    "mkdirat",
    "unlink",
    "unlinkat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "mknod",
    "mknodat",
    "truncate",
    "setxattr",
    "lsetxattr",
    "removexattr",
    "lremovexattr",
];

/// Parse strace lines: `123 openat(AT_FDCWD, "/path", O_RDONLY) = -1 ENOENT (No such file or directory)`.
/// Returns each path once, with its error and the first line that failed.
pub fn parse_trace(text: &str) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some(eq) = line.rfind(" = -1 ") else { continue };
        let err = line[eq + 6..].split_whitespace().next().unwrap_or("").to_string();
        if !matches!(err.as_str(), "ENOENT" | "EACCES" | "EPERM" | "EROFS" | "ECONNREFUSED") {
            continue;
        }
        // Failed attempts to change a file (its mode, owner, name) are not
        // missing access: they fail for any ordinary user, sandbox or not.
        // NVIDIA's driver, for one, tries to chmod its device nodes.
        let call = line.split_whitespace().nth(1).and_then(|c| c.split('(').next()).unwrap_or("");
        if CHANGE_CALLS.contains(&call) {
            continue;
        }
        let Some(q1) = line.find('"') else { continue };
        // Asking to write under /usr or /etc (access with W_OK, or an open
        // for writing) fails for every ordinary user; apps often just check.
        let writes = line.contains("W_OK") || line.contains("O_WRONLY") || line.contains("O_RDWR") || line.contains("O_CREAT");
        let system = line[q1 + 1..].starts_with("/usr/") || line[q1 + 1..].starts_with("/etc/");
        if writes && system {
            continue;
        }
        let Some(q2) = line[q1 + 1..].find('"') else { continue };
        let path = &line[q1 + 1..q1 + 1 + q2];
        if !path.starts_with('/') || path.starts_with("/proc/") || path.starts_with("/opt/app") || path.starts_with("/run/sam") {
            continue;
        }
        out.entry(path.to_string()).or_insert((err, line.trim().to_string()));
    }
    out
}

pub fn classify(path: &str, err: &str, host: &HostInfo) -> Option<Finding> {
    let p = Path::new(path);
    let mk = |risk, suggestion: String, fix: Option<(&str, String)>| Finding {
        path: path.to_string(),
        error: err.to_string(),
        risk,
        suggestion,
        fix: fix.map(|(k, v)| (k.to_string(), v)),
        applied: false,
        already_granted: false,
        trace_line: String::new(),
    };
    let run = format!("/run/user/{}", host.uid);
    if path.starts_with("/dev/dri") || path.starts_with("/dev/nvidia") {
        return Some(mk(RiskLevel::Medium, sam_core::i18n::tr("The app tried to use the GPU. Enable GPU acceleration."), Some(("devices.gpu", "true".into()))));
    }
    if path.starts_with("/dev/snd") {
        return Some(mk(
            RiskLevel::High,
            sam_core::i18n::tr("The app tried to open sound devices directly. Enable audio (or raw ALSA)."),
            Some(("audio.enabled", "true".into())),
        ));
    }
    if path.starts_with("/dev/video") {
        return Some(mk(RiskLevel::High, sam_core::i18n::tr("The app tried to open a camera."), Some(("devices.webcam", "true".into()))));
    }
    if path.starts_with("/dev/input") {
        return Some(mk(
            RiskLevel::Medium,
            sam_core::i18n::tr("The app looked for input devices, probably game controllers. Allow game controllers."),
            Some(("devices.gamepads", "true".into())),
        ));
    }
    if path.starts_with("/tmp/.X11-unix") {
        return Some(mk(RiskLevel::High, sam_core::i18n::tr("The app tried to connect to X11. Enable X11 / XWayland."), Some(("display.x11", "true".into()))));
    }
    if path.starts_with(&format!("{run}/wayland")) {
        return Some(mk(RiskLevel::Low, sam_core::i18n::tr("The app tried to connect to Wayland."), Some(("display.wayland", "true".into()))));
    }
    if path.starts_with(&format!("{run}/pulse")) || path.starts_with(&format!("{run}/pipewire")) {
        return Some(mk(RiskLevel::Medium, sam_core::i18n::tr("The app tried to use the sound server."), Some(("audio.enabled", "true".into()))));
    }
    if path == format!("{run}/bus") {
        return Some(mk(RiskLevel::High, sam_core::i18n::tr("The app tried to use the session D-Bus."), Some(("dbus.session.mode", "filtered".into()))));
    }
    if path.starts_with("/run/dbus/system_bus_socket") {
        return Some(mk(RiskLevel::Dangerous, sam_core::i18n::tr("The app tried to use the system D-Bus (left denied)."), None));
    }
    // Only report filesystem paths that actually exist on the host;
    // missing-everywhere paths are normal library probing.
    if !p.exists() {
        return None;
    }
    if path.starts_with("/usr/share/") || path.starts_with("/usr/lib/") || path.starts_with("/etc/") {
        if ETC_SENSITIVE.iter().any(|s| path.starts_with(s)) {
            return Some(mk(
                RiskLevel::Dangerous,
                sam_core::i18n::trf("The app tried to read {path}, which holds sensitive system data (left denied).", &[("path", &path)]),
                None,
            ));
        }
        // Files in /etc describe this computer (its disks, its system, its
        // package sources). Apps ran without them, so they are suggested
        // and never added by themselves.
        if path.starts_with("/etc/") {
            return Some(mk(
                RiskLevel::Medium,
                sam_core::i18n::trf(
                    "The app looked for {path}, which the sandbox hides because it describes this computer. Allow it only if the app misses something.",
                    &[("path", &path)],
                ),
                Some(("filesystem.custom_read", path.to_string())),
            ));
        }
        let top: PathBuf = p.components().take(4).collect();
        let dir = if p.is_dir() { p.to_path_buf() } else { top.clone() };
        let dir = if dir.as_os_str().len() > top.as_os_str().len() { top } else { dir };
        return Some(mk(
            RiskLevel::Low,
            sam_core::i18n::trf("Read-only system data {folder} is needed.", &[("folder", &dir.display())]),
            Some(("filesystem.custom_read", dir.display().to_string())),
        ));
    }
    if let Ok(rel) = p.strip_prefix(&host.home) {
        // The app's own cache, settings and data live in its private home,
        // where they do not exist yet on the first start; the app creates
        // them itself. Granting the real folder would only share yours.
        let own = [".cache", ".config", ".local"];
        if err == "ENOENT" && rel.components().next().is_some_and(|c| own.iter().any(|o| c.as_os_str() == *o)) {
            return None;
        }
        if is_sensitive_path(path) {
            return Some(mk(
                RiskLevel::Dangerous,
                sam_core::i18n::trf("The app tried to access {path} (sensitive; left denied).", &[("path", &tildify(p))]),
                None,
            ));
        }
        // Suggest the closest top-level folder in home.
        let first: PathBuf = host.home.join(rel.components().next().map(|c| c.as_os_str()).unwrap_or_default());
        let key = if err == "EROFS" { "filesystem.custom_write" } else { "filesystem.custom_read" };
        return Some(mk(
            RiskLevel::High,
            sam_core::i18n::trf("The app tried to access {path}. Grant the folder if this is expected.", &[("path", &tildify(p))]),
            Some((key, tildify(&first))),
        ));
    }
    None
}

pub fn diagnose(sam: &Sam, entry: &mut AppEntry, timeout: u64, apply_low_risk: bool) -> Result<DiagnoseResult> {
    let host = HostInfo::probe();
    let strace = host.tools.strace.clone();
    let Some(strace) = strace else { bail!("{}", sam_core::i18n::tr("strace is not installed; install it to use dynamic diagnosis (sudo pacman -S strace)")) };
    if entry.profile.permissions.filesystem.home {
        bail!("{}", sam_core::i18n::tr("diagnostic runs are refused while full home access is granted"));
    }
    let diag_dir = sam.paths.runtime_dir(&entry.id).join("diag");
    let _ = fs::remove_dir_all(&diag_dir);
    fs::create_dir_all(&diag_dir)?;
    let opts = LaunchOptions {
        tracer: Some(vec![
            strace.path.display().to_string(),
            "-f".into(),
            "-qq".into(),
            "-e".into(),
            "trace=%file,connect".into(),
            "-o".into(),
            "/run/sam-diag/trace.log".into(),
        ]),
        extra_binds: vec![(diag_dir.clone(), PathBuf::from("/run/sam-diag"), true)],
        timeout_secs: Some(timeout),
        quiet: true,
        ..Default::default()
    };
    let rec = run(entry, &opts, &sam.config, &sam.paths, &host)?;
    let trace = fs::read_to_string(diag_dir.join("trace.log")).unwrap_or_default();
    let mut findings: Vec<Finding> =
        parse_trace(&trace).into_iter().filter_map(|(p, (e, line))| classify(&p, &e, &host).map(|f| Finding { trace_line: line, ..f })).collect();
    findings.dedup_by(|a, b| a.fix == b.fix && a.fix.is_some());
    if entry.profile.permissions.network.mode != sam_core::permissions::NetworkMode::Full {
        findings.retain(|f| !is_network_file(&f.path));
    }
    mark_already_granted(&mut findings, &entry.profile.permissions);
    // The whole trace stays in the app's log folder, so a finding can be
    // checked against what really happened.
    let logs = sam.paths.app_logs_dir(&entry.id);
    let trace_file = fs::create_dir_all(&logs).and_then(|_| fs::write(logs.join("diagnose-trace.log"), &trace)).ok().map(|_| logs.join("diagnose-trace.log"));

    let mut applied = 0;
    if apply_low_risk && sam.config.dependencies.automatic_low_risk_fixes {
        let mut perms: PermissionSet = entry.profile.permissions.clone();
        for f in findings.iter_mut().filter(|f| f.risk == RiskLevel::Low && !f.already_granted) {
            if let Some((k, v)) = &f.fix {
                let ok = if k == "filesystem.custom_read" {
                    if !perms.filesystem.custom_read.contains(v) {
                        perms.filesystem.custom_read.push(v.clone());
                    }
                    true
                } else {
                    perms.set_key(k, v).is_ok()
                };
                if ok {
                    f.applied = true;
                    applied += 1;
                }
            }
        }
        if applied > 0 {
            *entry = sam.set_permissions(&entry.id, perms)?;
        }
    }
    let _ = fs::remove_dir_all(&diag_dir);
    Ok(DiagnoseResult { findings, applied, log_file: rec.log_file, trace_file, launch_summary: rec.summary })
}

/// The network's configuration files, which the sandbox hides on purpose
/// when the app has no full network access.
pub fn is_network_file(path: &str) -> bool {
    ["/etc/resolv.conf", "/etc/hosts", "/etc/host.conf", "/etc/gai.conf", "/etc/services", "/etc/protocols", "/etc/nsswitch.conf"].contains(&path)
}

/// Marks findings whose fix the app already has: the access failed for
/// another reason, and suggesting the same switch again would mislead.
pub fn mark_already_granted(findings: &mut [Finding], perms: &PermissionSet) {
    for f in findings.iter_mut() {
        let Some((k, v)) = &f.fix else { continue };
        let has = match k.as_str() {
            "filesystem.custom_read" => perms.filesystem.custom_read.contains(v) || perms.filesystem.custom_write.contains(v),
            "filesystem.custom_write" => perms.filesystem.custom_write.contains(v),
            _ => perms.get_key(k).ok().is_some_and(|cur| match cur {
                serde_json::Value::String(s) => s == *v,
                other => serde_json::from_str::<serde_json::Value>(v).is_ok_and(|want| want == other),
            }),
        };
        if has {
            f.already_granted = true;
            f.suggestion = sam_core::i18n::trf(
                "{path} could not be opened ({error}), although the app already has this access. The cause is elsewhere; the trace line shows the call.",
                &[("path", &f.path), ("error", &f.error)],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::sandbox::sample_context;

    /// Failed file and socket accesses are read from a diagnostic trace.
    #[test]
    fn failed_accesses_are_read_from_a_trace() {
        let t = r#"12 openat(AT_FDCWD, "/usr/share/X11/xkb/rules/evdev", O_RDONLY) = -1 ENOENT (No such file or directory)
12 openat(AT_FDCWD, "/opt/app/usr/lib/libfoo.so", O_RDONLY) = -1 ENOENT (No such file or directory)
12 connect(5, {sa_family=AF_UNIX, sun_path="/tmp/.X11-unix/X0"}, 20) = -1 ENOENT (No such file or directory)
12 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3
"#;
        let m = parse_trace(t);
        assert!(m["/usr/share/X11/xkb/rules/evdev"].1.starts_with("12 openat(AT_FDCWD, \"/usr/share/X11/xkb/rules/evdev\""), "the raw line is kept");
        assert!(m.contains_key("/tmp/.X11-unix/X0"));
        assert!(!m.contains_key("/opt/app/usr/lib/libfoo.so"));
        assert!(!m.contains_key("/etc/hosts"));
    }

    /// Failed accesses are mapped to the permission that would fix them (X11 socket, GPU device), and unknown paths to none.
    #[test]
    fn failed_accesses_map_to_the_permission_that_fixes_them() {
        let host = sample_context().host;
        let f = classify("/tmp/.X11-unix/X0", "ENOENT", &host).unwrap();
        assert_eq!(f.fix.unwrap().0, "display.x11");
        let f = classify("/dev/dri/renderD128", "ENOENT", &host).unwrap();
        assert_eq!(f.risk, RiskLevel::Medium);
        assert!(classify("/definitely/not/here", "ENOENT", &host).is_none());
        if Path::new("/usr/share/zoneinfo").exists() {
            let f = classify("/usr/share/zoneinfo", "ENOENT", &host).unwrap();
            assert_eq!(f.risk, RiskLevel::Low);
        }
    }

    /// A GPU device that fails to open while the GPU is already allowed is
    /// reported as "already granted", not as a suggestion to allow the GPU
    /// (regression: neovide on NVIDIA got "Enable GPU acceleration" twice).
    #[test]
    fn a_failure_despite_the_permission_is_not_suggested_again() {
        let host = sample_context().host;
        let mut perms = PermissionSet::default();
        perms.devices.gpu = true;
        let mut f = vec![classify("/dev/nvidia-modeset", "EACCES", &host).unwrap()];
        mark_already_granted(&mut f, &perms);
        assert!(f[0].already_granted);
        assert!(f[0].suggestion.contains("already has this access"), "{}", f[0].suggestion);
        perms.devices.gpu = false;
        let mut f = vec![classify("/dev/nvidia-modeset", "EACCES", &host).unwrap()];
        mark_already_granted(&mut f, &perms);
        assert!(!f[0].already_granted);
    }

    /// A missing cache, settings or data folder in the app's private home is
    /// the app's own and is not reported, while a missing document folder
    /// is (regression: ~/.cache/nvidia was suggested as a folder to grant).
    #[test]
    fn the_apps_own_folders_in_its_private_home_are_not_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let mut host = sample_context().host;
        host.home = tmp.path().to_path_buf();
        for d in [".cache/nvidia", "Documents"] {
            fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        let cache = tmp.path().join(".cache/nvidia");
        assert!(classify(cache.to_str().unwrap(), "ENOENT", &host).is_none());
        let docs = tmp.path().join("Documents");
        assert!(classify(docs.to_str().unwrap(), "ENOENT", &host).is_some());
    }

    /// A failed attempt to change a file's mode is not missing access
    /// (regression: NVIDIA's driver chmods /dev/nvidia-modeset, which fails
    /// for every ordinary user, and diagnose reported it as a GPU problem).
    #[test]
    fn failed_changes_to_a_file_are_not_missing_access() {
        let t = "5     chmod(\"/dev/nvidia-modeset\", 0666) = -1 EPERM (Operation not permitted)\n5     mkdir(\"/usr/share/foo\", 0755) = -1 EROFS (Read-only file system)\n5     openat(AT_FDCWD, \"/dev/nvidia0\", O_RDWR) = -1 EACCES (Permission denied)\n";
        let m = parse_trace(t);
        assert!(!m.contains_key("/dev/nvidia-modeset"));
        assert!(!m.contains_key("/usr/share/foo"));
        assert!(m.contains_key("/dev/nvidia0"), "a failed open still counts");
    }

    /// Checking whether a system file is writable is not missing access
    /// (regression: Zrythm and mpv ask access(W_OK) for files in /usr, which
    /// fails for every user, and diagnose suggested granting /usr/lib/lv2).
    #[test]
    fn write_checks_on_system_folders_are_not_missing_access() {
        let t = "35 access(\"/usr/lib/lv2/x.lv2/.\", W_OK) = -1 EACCES (Permission denied)\n35 openat(AT_FDCWD, \"/etc/foo.conf\", O_WRONLY|O_CREAT, 0644) = -1 EROFS (Read-only file system)\n35 access(\"/usr/share/icons/x/index.theme\", R_OK) = -1 EACCES (Permission denied)\n";
        let m = parse_trace(t);
        assert!(!m.contains_key("/usr/lib/lv2/x.lv2/."));
        assert!(!m.contains_key("/etc/foo.conf"));
        assert!(m.contains_key("/usr/share/icons/x/index.theme"), "a failed read still counts");
    }

    /// A file in /etc is suggested, never added by itself, because it
    /// describes this computer (regression: /etc/fstab and /etc/pacman.conf
    /// were "low risk" and added automatically, although the apps ran
    /// without them).
    #[test]
    fn files_in_etc_are_suggested_and_not_added_automatically() {
        let host = sample_context().host;
        if Path::new("/etc/fstab").exists() {
            let f = classify("/etc/fstab", "ENOENT", &host).unwrap();
            assert_eq!(f.risk, RiskLevel::Medium);
        }
        assert!(is_network_file("/etc/resolv.conf"));
        assert!(!is_network_file("/etc/fstab"));
    }

    /// The app's own settings folder in its private home is not reported as
    /// a sensitive folder (regression: ~/.config was "dangerous").
    #[test]
    fn the_apps_own_settings_folder_is_not_reported_as_sensitive() {
        let tmp = tempfile::tempdir().unwrap();
        let mut host = sample_context().host;
        host.home = tmp.path().to_path_buf();
        fs::create_dir_all(tmp.path().join(".config/kwinrc")).unwrap();
        for p in [".config", ".config/kwinrc", ".local"] {
            fs::create_dir_all(tmp.path().join(p)).unwrap();
            assert!(classify(tmp.path().join(p).to_str().unwrap(), "ENOENT", &host).is_none(), "{p}");
        }
    }
}
