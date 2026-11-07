//! Risk scoring (whitepaper §2.19.2).

use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
use crate::permissions::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Dangerous,
}

impl RiskLevel {
    pub fn weight(self) -> u32 {
        match self {
            RiskLevel::Low => 1,
            RiskLevel::Medium => 5,
            RiskLevel::High => 15,
            RiskLevel::Dangerous => 35,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Dangerous => "Dangerous",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskItem {
    pub key: String,
    pub title: String,
    pub level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RiskAssessment {
    /// Highest individual risk.
    pub level: RiskLevel,
    /// 0..=100 aggregate score.
    pub score: u32,
    pub items: Vec<RiskItem>,
}

fn item(items: &mut Vec<RiskItem>, key: &str, title: &str, level: RiskLevel) {
    items.push(RiskItem {
        key: key.into(),
        title: title.into(),
        level,
    });
}

/// Score a permission set, optionally taking the backend into account.
pub fn assess(p: &PermissionSet, backend: Option<BackendKind>) -> RiskAssessment {
    let mut items = Vec::new();

    // Baseline resources every sandbox gets.
    item(&mut items, "baseline.fonts", "Fonts (read-only)", RiskLevel::Low);
    item(&mut items, "baseline.locale", "Locale and timezone (read-only)", RiskLevel::Low);
    item(&mut items, "baseline.icons", "Icons and themes (read-only)", RiskLevel::Low);

    let fs = &p.filesystem;
    if fs.home {
        let lvl = if fs.home_access == Access::Rw { RiskLevel::Dangerous } else { RiskLevel::High };
        let t = if fs.home_access == Access::Rw { "Full home read/write" } else { "Full home read-only" };
        item(&mut items, "filesystem.home", t, lvl);
        if fs.ssh {
            item(&mut items, "filesystem.ssh", "SSH keys exposed", RiskLevel::Dangerous);
        }
        if fs.gnupg {
            item(&mut items, "filesystem.gnupg", "GnuPG keys exposed", RiskLevel::Dangerous);
        }
        if fs.hidden_files {
            item(&mut items, "filesystem.hidden_files", "Sensitive dotfiles exposed", RiskLevel::Dangerous);
        }
    }
    for key in XDG_DIR_KEYS {
        match fs.xdg_access(key) {
            Access::None => {}
            Access::Ro => item(&mut items, &format!("filesystem.{key}"), &format!("{} (read-only)", cap(key)), RiskLevel::Low),
            Access::Rw => item(&mut items, &format!("filesystem.{key}"), &format!("{} (read/write)", cap(key)), RiskLevel::Medium),
        }
    }
    for path in &fs.custom_read {
        item(&mut items, "filesystem.custom_read", &format!("Read {path}"), path_risk(path, false));
    }
    for path in &fs.custom_write {
        item(&mut items, "filesystem.custom_write", &format!("Write {path}"), path_risk(path, true));
    }

    match p.network.mode {
        NetworkMode::Full => item(&mut items, "network.mode", "Network", RiskLevel::High),
        NetworkMode::Localhost | NetworkMode::Filtered => {
            item(&mut items, "network.mode", "Restricted network (experimental)", RiskLevel::Medium)
        }
        NetworkMode::None => {}
    }

    if p.devices.gpu {
        item(&mut items, "devices.gpu", "GPU", RiskLevel::Medium);
    }
    if p.devices.webcam {
        item(&mut items, "devices.webcam", "Webcam", RiskLevel::High);
    }
    if p.devices.input {
        item(&mut items, "devices.input", "Raw input devices", RiskLevel::Dangerous);
    }
    if p.devices.usb {
        item(&mut items, "devices.usb", "Raw USB devices", RiskLevel::Dangerous);
    }
    if p.devices.bluetooth {
        item(&mut items, "devices.bluetooth", "Bluetooth", RiskLevel::Dangerous);
    }
    if p.audio.enabled {
        item(&mut items, "audio.enabled", "Audio", RiskLevel::Medium);
    }
    if p.audio.alsa_raw {
        item(&mut items, "audio.alsa_raw", "Raw ALSA devices", RiskLevel::Dangerous);
    }
    if p.display.wayland {
        item(&mut items, "display.wayland", "Wayland", RiskLevel::Low);
    }
    if p.display.x11 {
        item(&mut items, "display.x11", "X11", RiskLevel::High);
    }
    match p.dbus.session.mode {
        DbusMode::None => {}
        DbusMode::Filtered => item(&mut items, "dbus.session.mode", "Filtered session D-Bus (portals)", RiskLevel::Low),
        DbusMode::Full => item(&mut items, "dbus.session.mode", "Full session D-Bus", RiskLevel::High),
    }
    match p.dbus.system.mode {
        DbusMode::None => {}
        DbusMode::Filtered => item(&mut items, "dbus.system.mode", "Filtered system D-Bus", RiskLevel::High),
        DbusMode::Full => item(&mut items, "dbus.system.mode", "System D-Bus", RiskLevel::Dangerous),
    }
    if p.sockets.ssh_agent {
        item(&mut items, "sockets.ssh_agent", "SSH agent", RiskLevel::High);
    }
    if p.sockets.cups {
        item(&mut items, "sockets.cups", "Printing", RiskLevel::Low);
    }
    for s in &p.sockets.custom {
        item(&mut items, "sockets.custom", &format!("Socket {s}"), RiskLevel::High);
    }
    if p.advanced.host_runtime == HostRuntime::Full {
        item(&mut items, "advanced.host_runtime", "Full /usr exposure", RiskLevel::Medium);
    }
    if !p.advanced.extra_backend_args.is_empty() {
        item(&mut items, "advanced.extra_backend_args", "Raw backend arguments", RiskLevel::High);
    }

    match backend {
        Some(BackendKind::Firejail) => item(&mut items, "backend", "Firejail backend (setuid)", RiskLevel::Medium),
        Some(BackendKind::Unsandboxed) => item(&mut items, "backend", "No sandbox", RiskLevel::Dangerous),
        _ => {}
    }

    let level = items.iter().map(|i| i.level).max().unwrap_or_default();
    let score = items
        .iter()
        .filter(|i| !i.key.starts_with("baseline."))
        .map(|i| i.level.weight())
        .sum::<u32>()
        .min(100);
    RiskAssessment { level, score, items }
}

fn cap(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Paths that must never be granted casually.
pub const SENSITIVE_PATHS: &[&str] = &[
    "/", "/etc", "/usr", "/boot", "/root", "/var", "/proc", "/sys", "/dev", "/run",
    "~", "~/.ssh", "~/.gnupg", "~/.config", "~/.local", "~/.local/share", "~/.bashrc",
    "~/.zshrc", "~/.profile", "~/.config/autostart", "~/.config/systemd",
    "~/.password-store", "~/.local/share/keyrings", "~/.mozilla", "~/.aws", "~/.kube",
    "~/.docker", "~/.config/sam", "~/.local/share/sam", "~/.local/share/applications",
];

pub fn is_sensitive_path(path: &str) -> bool {
    let norm = normalize_display_path(path);
    SENSITIVE_PATHS.iter().any(|s| {
        let s = normalize_display_path(s);
        norm == s || (s != "/" && s != "~" && norm.starts_with(&format!("{s}/")))
    })
}

fn normalize_display_path(p: &str) -> String {
    let home = crate::util::home_dir();
    let home_s = home.to_string_lossy();
    let mut p = p.trim().trim_end_matches('/').to_string();
    if p.is_empty() {
        p = "/".into();
    }
    if p == home_s {
        return "~".into();
    }
    if let Some(rest) = p.strip_prefix(&format!("{home_s}/")) {
        return format!("~/{rest}");
    }
    if let Some(rest) = p.strip_prefix("$HOME") {
        return format!("~{rest}");
    }
    p
}

fn path_risk(path: &str, write: bool) -> RiskLevel {
    if is_sensitive_path(path) {
        RiskLevel::Dangerous
    } else if write {
        RiskLevel::High
    } else {
        RiskLevel::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_is_low() {
        let a = assess(&PermissionSet::strict_gui(), Some(BackendKind::Bubblewrap));
        assert_eq!(a.level, RiskLevel::Low);
        assert_eq!(a.score, 2);
    }

    #[test]
    fn full_home_is_dangerous() {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        assert_eq!(assess(&p, None).level, RiskLevel::Dangerous);
        p.filesystem.home_access = Access::Ro;
        assert_eq!(assess(&p, None).level, RiskLevel::High);
    }

    #[test]
    fn network_and_x11_high() {
        let mut p = PermissionSet::strict_gui();
        p.network.mode = NetworkMode::Full;
        p.display.x11 = true;
        let a = assess(&p, None);
        assert_eq!(a.level, RiskLevel::High);
        assert!(a.score >= 30);
    }

    #[test]
    fn sensitive_paths() {
        assert!(is_sensitive_path("~/.ssh"));
        assert!(is_sensitive_path("~/.ssh/id_rsa"));
        assert!(is_sensitive_path("/etc"));
        assert!(is_sensitive_path("/"));
        assert!(!is_sensitive_path("~/Projects"));
        assert!(!is_sensitive_path("/mnt/data"));
    }
}
