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
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnoseResult {
    pub findings: Vec<Finding>,
    pub applied: usize,
    pub log_file: Option<PathBuf>,
    pub launch_summary: String,
}

const ETC_SENSITIVE: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh", "/etc/NetworkManager", "/etc/polkit-1", "/etc/pam.d", "/etc/security"];

/// Parse strace lines: `123 openat(AT_FDCWD, "/path", O_RDONLY) = -1 ENOENT (No such file or directory)`.
pub fn parse_trace(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some(eq) = line.rfind(" = -1 ") else { continue };
        let err = line[eq + 6..].split_whitespace().next().unwrap_or("").to_string();
        if !matches!(err.as_str(), "ENOENT" | "EACCES" | "EPERM" | "EROFS" | "ECONNREFUSED") {
            continue;
        }
        let Some(q1) = line.find('"') else { continue };
        let Some(q2) = line[q1 + 1..].find('"') else { continue };
        let path = &line[q1 + 1..q1 + 1 + q2];
        if !path.starts_with('/') || path.starts_with("/proc/") || path.starts_with("/opt/app") || path.starts_with("/run/sam") {
            continue;
        }
        out.entry(path.to_string()).or_insert(err);
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
    };
    let run = format!("/run/user/{}", host.uid);
    if path.starts_with("/dev/dri") || path.starts_with("/dev/nvidia") {
        return Some(mk(RiskLevel::Medium, "The app tried to use the GPU. Enable GPU acceleration.".into(), Some(("devices.gpu", "true".into()))));
    }
    if path.starts_with("/dev/snd") {
        return Some(mk(RiskLevel::High, "The app tried to open sound devices directly. Enable audio (or raw ALSA).".into(), Some(("audio.enabled", "true".into()))));
    }
    if path.starts_with("/dev/video") {
        return Some(mk(RiskLevel::High, "The app tried to open a camera.".into(), Some(("devices.webcam", "true".into()))));
    }
    if path.starts_with("/dev/input") {
        return Some(mk(RiskLevel::Medium, "The app looked for input devices, probably game controllers. Allow game controllers.".into(), Some(("devices.gamepads", "true".into()))));
    }
    if path.starts_with("/tmp/.X11-unix") {
        return Some(mk(RiskLevel::High, "The app tried to connect to X11. Enable X11 / XWayland.".into(), Some(("display.x11", "true".into()))));
    }
    if path.starts_with(&format!("{run}/wayland")) {
        return Some(mk(RiskLevel::Low, "The app tried to connect to Wayland.".into(), Some(("display.wayland", "true".into()))));
    }
    if path.starts_with(&format!("{run}/pulse")) || path.starts_with(&format!("{run}/pipewire")) {
        return Some(mk(RiskLevel::Medium, "The app tried to use the sound server.".into(), Some(("audio.enabled", "true".into()))));
    }
    if path == format!("{run}/bus") {
        return Some(mk(RiskLevel::High, "The app tried to use the session D-Bus.".into(), Some(("dbus.session.mode", "filtered".into()))));
    }
    if path.starts_with("/run/dbus/system_bus_socket") {
        return Some(mk(RiskLevel::Dangerous, "The app tried to use the system D-Bus (left denied).".into(), None));
    }
    // Only report filesystem paths that actually exist on the host;
    // missing-everywhere paths are normal library probing.
    if !p.exists() {
        return None;
    }
    if path.starts_with("/usr/share/") || path.starts_with("/usr/lib/") || path.starts_with("/etc/") {
        if ETC_SENSITIVE.iter().any(|s| path.starts_with(s)) {
            return Some(mk(RiskLevel::Dangerous, format!("The app tried to read {path}, which holds sensitive system data (left denied)."), None));
        }
        let top: PathBuf = p.components().take(4).collect();
        let dir = if p.is_dir() { p.to_path_buf() } else { top.clone() };
        let dir = if dir.as_os_str().len() > top.as_os_str().len() { top } else { dir };
        return Some(mk(RiskLevel::Low, format!("Read-only system data {} is needed.", dir.display()), Some(("filesystem.custom_read", dir.display().to_string()))));
    }
    if p.starts_with(&host.home) {
        if is_sensitive_path(path) {
            return Some(mk(RiskLevel::Dangerous, format!("The app tried to access {} (sensitive; left denied).", tildify(p)), None));
        }
        // Suggest the closest top-level folder in home.
        let rel = p.strip_prefix(&host.home).unwrap();
        let first: PathBuf = host.home.join(rel.components().next().map(|c| c.as_os_str()).unwrap_or_default());
        let key = if err == "EROFS" { "filesystem.custom_write" } else { "filesystem.custom_read" };
        return Some(mk(RiskLevel::High, format!("The app tried to access {}. Grant the folder if this is expected.", tildify(p)), Some((key, tildify(&first)))));
    }
    None
}

pub fn diagnose(sam: &Sam, entry: &mut AppEntry, timeout: u64, apply_low_risk: bool) -> Result<DiagnoseResult> {
    let host = HostInfo::probe();
    let strace = host.tools.strace.clone();
    let Some(strace) = strace else { bail!("strace is not installed; install it to use dynamic diagnosis (sudo pacman -S strace)") };
    if entry.profile.permissions.filesystem.home {
        bail!("diagnostic runs are refused while full home access is granted");
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
    let mut findings: Vec<Finding> = parse_trace(&trace).iter().filter_map(|(p, e)| classify(p, e, &host)).collect();
    findings.dedup_by(|a, b| a.fix == b.fix && a.fix.is_some());

    let mut applied = 0;
    if apply_low_risk && sam.config.dependencies.automatic_low_risk_fixes {
        let mut perms: PermissionSet = entry.profile.permissions.clone();
        for f in findings.iter_mut().filter(|f| f.risk == RiskLevel::Low) {
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
    Ok(DiagnoseResult { findings, applied, log_file: rec.log_file, launch_summary: rec.summary })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::backend::sample_context;

    #[test]
    fn parses_strace_output() {
        let t = r#"12 openat(AT_FDCWD, "/usr/share/X11/xkb/rules/evdev", O_RDONLY) = -1 ENOENT (No such file or directory)
12 openat(AT_FDCWD, "/opt/app/usr/lib/libfoo.so", O_RDONLY) = -1 ENOENT (No such file or directory)
12 connect(5, {sa_family=AF_UNIX, sun_path="/tmp/.X11-unix/X0"}, 20) = -1 ENOENT (No such file or directory)
12 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3
"#;
        let m = parse_trace(t);
        assert!(m.contains_key("/usr/share/X11/xkb/rules/evdev"));
        assert!(m.contains_key("/tmp/.X11-unix/X0"));
        assert!(!m.contains_key("/opt/app/usr/lib/libfoo.so"));
        assert!(!m.contains_key("/etc/hosts"));
    }

    #[test]
    fn classifies() {
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
}
