//! Risk scoring.

use serde::{Deserialize, Serialize};

use crate::permissions::*;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, Hash,
)]
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
    /// The words people see, in the window and on the command line alike:
    /// three levels (low and medium are both harmless), translated.
    pub fn words(self) -> String {
        match self {
            RiskLevel::Low | RiskLevel::Medium => crate::i18n::tr("Harmless"),
            RiskLevel::High => crate::i18n::tr("Think twice"),
            RiskLevel::Dangerous => crate::i18n::tr("Dangerous"),
        }
    }
    /// Whether `name` names this level: the internal name (`low`, `high`, …)
    /// or the words people see (`harmless`, `think-twice`, `dangerous`).
    pub fn is_named(self, name: &str) -> bool {
        let n = name.trim().to_lowercase().replace([' ', '_'], "-");
        n == self.label().to_lowercase()
            || match self {
                RiskLevel::Low | RiskLevel::Medium => n == "harmless",
                RiskLevel::High => n == "think-twice",
                RiskLevel::Dangerous => false,
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
    /// Sum of item weights, capped at 100. Kept for scripts; not shown,
    /// because a number next to the level is easily misread.
    pub score: u32,
    pub items: Vec<RiskItem>,
}

impl RiskAssessment {
    /// The permissions that set `level` (the riskiest ones). Empty for low
    /// risk, where only harmless basics are granted.
    pub fn deciding(&self) -> Vec<&RiskItem> {
        if self.level == RiskLevel::Low {
            return Vec::new();
        }
        self.items
            .iter()
            .filter(|i| i.level == self.level && !i.key.starts_with("baseline."))
            .collect()
    }

    /// Why the level is what it is: "Network", "Network +2", or "" for low.
    pub fn reason(&self) -> String {
        let d = self.deciding();
        match d.len() {
            0 => String::new(),
            1 => d[0].title.clone(),
            n => format!("{} +{}", d[0].title, n - 1),
        }
    }
}

fn item(items: &mut Vec<RiskItem>, key: &str, title: &str, level: RiskLevel) {
    items.push(RiskItem {
        key: key.into(),
        title: crate::i18n::tr(title),
        level,
    });
}

/// Score a permission set.
pub fn assess(p: &PermissionSet) -> RiskAssessment {
    let mut items = Vec::new();

    // Baseline resources every sandbox gets.
    item(
        &mut items,
        "baseline.fonts",
        "Fonts (read-only)",
        RiskLevel::Low,
    );
    item(
        &mut items,
        "baseline.locale",
        "Locale and timezone (read-only)",
        RiskLevel::Low,
    );
    item(
        &mut items,
        "baseline.icons",
        "Icons and themes (read-only)",
        RiskLevel::Low,
    );

    let fs = &p.filesystem;
    if fs.home {
        let lvl = if fs.home_access == Access::Rw {
            RiskLevel::Dangerous
        } else {
            RiskLevel::High
        };
        let t = if fs.home_access == Access::Rw {
            crate::i18n::n_("Full home access")
        } else {
            crate::i18n::n_("Full home access (read-only)")
        };
        item(&mut items, "filesystem.home", t, lvl);
        if fs.ssh {
            item(
                &mut items,
                "filesystem.ssh",
                "SSH keys",
                RiskLevel::Dangerous,
            );
        }
        if fs.gnupg {
            item(
                &mut items,
                "filesystem.gnupg",
                "GnuPG keys",
                RiskLevel::Dangerous,
            );
        }
        if fs.hidden_files {
            item(
                &mut items,
                "filesystem.hidden_files",
                "Sensitive dotfiles",
                RiskLevel::Dangerous,
            );
        }
    }
    for key in XDG_DIR_KEYS {
        match fs.xdg_access(key) {
            Access::None => {}
            // The switch's title and option words ("Desktop folder (read & write)").
            Access::Ro => item(
                &mut items,
                &format!("filesystem.{key}"),
                &format!("{} (read-only)", switch_title(key)),
                RiskLevel::Low,
            ),
            Access::Rw => item(
                &mut items,
                &format!("filesystem.{key}"),
                &format!("{} (read & write)", switch_title(key)),
                RiskLevel::Medium,
            ),
        }
    }
    for path in &fs.custom_read {
        item(
            &mut items,
            "filesystem.custom_read",
            &format!("Read {path}"),
            path_risk(path, false),
        );
    }
    for path in &fs.custom_write {
        item(
            &mut items,
            "filesystem.custom_write",
            &format!("Write {path}"),
            path_risk(path, true),
        );
    }

    match p.network.mode {
        NetworkMode::Full => item(&mut items, "network.mode", "Full network", RiskLevel::High),
        NetworkMode::Localhost => item(
            &mut items,
            "network.mode",
            "This computer only",
            RiskLevel::Low,
        ),
        NetworkMode::None => {}
    }

    if p.devices.gpu {
        item(
            &mut items,
            "devices.gpu",
            "GPU acceleration",
            RiskLevel::Medium,
        );
    }
    if p.devices.webcam {
        item(&mut items, "devices.webcam", "Webcam", RiskLevel::High);
    }
    if p.devices.gamepads && !p.devices.input {
        item(
            &mut items,
            "devices.gamepads",
            "Game controllers",
            RiskLevel::Medium,
        );
    }
    if p.devices.input {
        item(
            &mut items,
            "devices.input",
            "All input devices",
            RiskLevel::Dangerous,
        );
    }
    if p.devices.usb {
        item(&mut items, "devices.usb", "Raw USB", RiskLevel::Dangerous);
    }
    if p.devices.bluetooth {
        item(
            &mut items,
            "devices.bluetooth",
            "Bluetooth",
            RiskLevel::Dangerous,
        );
    }
    if p.audio.enabled {
        item(&mut items, "audio.enabled", "Sound", RiskLevel::Medium);
    }
    if p.display.wayland && p.display.wayland_privileged {
        item(
            &mut items,
            "display.wayland_privileged",
            "Privileged Wayland protocols",
            RiskLevel::High,
        );
    }
    if p.audio.pipewire {
        item(
            &mut items,
            "audio.pipewire",
            "Direct PipeWire access",
            RiskLevel::High,
        );
    }
    if p.audio.direct {
        item(
            &mut items,
            "audio.direct",
            "Sound without SAM's relay",
            RiskLevel::Dangerous,
        );
    }
    if p.audio.alsa_raw {
        item(
            &mut items,
            "audio.alsa_raw",
            "Raw ALSA devices",
            RiskLevel::Dangerous,
        );
    }
    if p.display.wayland {
        item(&mut items, "display.wayland", "Wayland", RiskLevel::Low);
    }
    if p.integrations.keyring {
        item(
            &mut items,
            "integrations.keyring",
            "Passwords & keyring",
            RiskLevel::High,
        );
    }
    if p.integrations.media_controls {
        item(
            &mut items,
            "integrations.media_controls",
            "Media controls",
            RiskLevel::Low,
        );
    }
    if p.integrations.screen_sharing {
        item(
            &mut items,
            "integrations.screen_sharing",
            "Screen sharing",
            RiskLevel::Medium,
        );
    }
    if p.integrations.input_method {
        item(
            &mut items,
            "integrations.input_method",
            "Input method",
            RiskLevel::Low,
        );
    }
    if p.integrations.file_manager {
        item(
            &mut items,
            "integrations.file_manager",
            "Open the file manager",
            RiskLevel::Low,
        );
    }
    if p.advanced.writable_appdir {
        item(
            &mut items,
            "advanced.writable_appdir",
            "Writable app folder",
            RiskLevel::Low,
        );
    }
    if p.display.x11 {
        item(&mut items, "display.x11", "X11 / XWayland", RiskLevel::High);
    }
    match p.dbus.session.mode {
        DbusMode::None => {}
        DbusMode::Filtered => item(
            &mut items,
            "dbus.session.mode",
            "Session bus: filtered",
            RiskLevel::Low,
        ),
        // The full bus includes org.freedesktop.systemd1, which can start
        // programs outside the sandbox: as dangerous as allowing that name.
        DbusMode::Full => item(
            &mut items,
            "dbus.session.mode",
            "Session bus: full access",
            RiskLevel::Dangerous,
        ),
    }
    for name in &p.dbus.session.allow {
        if crate::permissions::dangerous_bus_name(name).is_some() {
            item(
                &mut items,
                "dbus.session.allow",
                &format!("Session service {name}"),
                RiskLevel::Dangerous,
            );
        }
    }
    if p.dbus.session.mode == DbusMode::Filtered {
        for name in &p.dbus.session.own {
            let level = if crate::permissions::dangerous_bus_name(name).is_some() {
                RiskLevel::Dangerous
            } else {
                RiskLevel::Low
            };
            item(
                &mut items,
                "dbus.session.own",
                &format!("Owns {name}"),
                level,
            );
        }
    }
    match p.dbus.system.mode {
        DbusMode::None => {}
        DbusMode::Filtered => {} // not possible for the system bus (loads as none)
        DbusMode::Full => item(
            &mut items,
            "dbus.system.mode",
            "System bus: full access",
            RiskLevel::Dangerous,
        ),
    }
    if p.sockets.ssh_agent {
        item(
            &mut items,
            "sockets.ssh_agent",
            "SSH agent",
            RiskLevel::High,
        );
    }
    if p.sockets.cups {
        item(&mut items, "sockets.cups", "Printing", RiskLevel::Low);
    }
    for s in &p.sockets.custom {
        let level = if crate::permissions::dangerous_socket(s).is_some() {
            RiskLevel::Dangerous
        } else {
            RiskLevel::High
        };
        item(&mut items, "sockets.custom", &format!("Socket {s}"), level);
    }
    if p.advanced.host_runtime == HostRuntime::Full {
        item(
            &mut items,
            "advanced.host_runtime",
            "All of /usr",
            RiskLevel::Medium,
        );
    }
    if !p.advanced.extra_bwrap_args.is_empty() {
        item(
            &mut items,
            "advanced.extra_bwrap_args",
            "Raw Bubblewrap arguments",
            RiskLevel::High,
        );
    }

    let level = items.iter().map(|i| i.level).max().unwrap_or_default();
    let score = items
        .iter()
        .filter(|i| !i.key.starts_with("baseline."))
        .map(|i| i.level.weight())
        .sum::<u32>()
        .min(100);
    RiskAssessment {
        level,
        score,
        items,
    }
}

/// The title of a personal folder's switch (`desktop` → "Desktop folder").
fn switch_title(folder: &str) -> String {
    let key = format!("filesystem.{folder}");
    crate::permissions::permission_catalog()
        .into_iter()
        .find(|i| i.key == key)
        .map(|i| i.title.to_string())
        .unwrap_or_else(|| folder.to_string())
}

/// Paths that must never be granted casually.
pub const SENSITIVE_PATHS: &[&str] = &[
    "/",
    "/etc",
    "/usr",
    "/boot",
    "/root",
    "/var",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "~",
    "~/.ssh",
    "~/.gnupg",
    "~/.config",
    "~/.local",
    "~/.local/share",
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
    "~/.config/autostart",
    "~/.config/systemd",
    "~/.password-store",
    "~/.local/share/keyrings",
    "~/.mozilla",
    "~/.aws",
    "~/.kube",
    "~/.docker",
    "~/.config/sam",
    "~/.local/share/sam",
    "~/.local/share/applications",
];

pub fn is_sensitive_path(path: &str) -> bool {
    is_sensitive_path_in(path, &crate::util::home_dir())
}

/// [`is_sensitive_path`] for the home folder `home`: the system folders,
/// the home itself, its key folders and credential stores, and the places
/// that make the computer run something (start files, menu entries, SAM's
/// own settings; the same lists the sandbox locks, so a grant of
/// `~/.bash_profile` is as dangerous as one of `~/.bashrc`; audit D-M3).
/// Drives under `/run/media` are user files, not system ones.
pub fn is_sensitive_path_in(path: &str, home: &std::path::Path) -> bool {
    let norm = normalize_display_path(path, home);
    if norm == "/run/media" || norm.starts_with("/run/media/") {
        return false;
    }
    let home_places = crate::places::PROTECTED_RO
        .iter()
        .chain(crate::places::SENSITIVE_DOTFILES)
        .map(|p| format!("~/{p}"));
    SENSITIVE_PATHS
        .iter()
        .map(|s| s.to_string())
        .chain(home_places)
        .any(|s| {
            let s = normalize_display_path(&s, home);
            norm == s || (s != "/" && s != "~" && norm.starts_with(&format!("{s}/")))
        })
}

fn normalize_display_path(p: &str, home: &std::path::Path) -> String {
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

    /// SAM's strictest window profile counts as low risk.
    /// The command line and the window name risk with the same three words,
    /// and the command line's filter understands both names.
    #[test]
    fn risk_has_the_same_three_words_everywhere() {
        assert_eq!(RiskLevel::Low.words(), "Harmless");
        assert_eq!(RiskLevel::Medium.words(), "Harmless");
        assert_eq!(RiskLevel::High.words(), "Think twice");
        assert_eq!(RiskLevel::Dangerous.words(), "Dangerous");
        assert!(RiskLevel::High.is_named("think twice") && RiskLevel::High.is_named("high"));
        assert!(RiskLevel::Medium.is_named("harmless") && !RiskLevel::High.is_named("harmless"));
    }

    /// The full session bus reaches systemd, which can start programs
    /// outside the sandbox, so it is rated like allowing systemd by name.
    #[test]
    fn the_full_session_bus_is_rated_dangerous() {
        let mut p = PermissionSet::default();
        p.dbus.session.mode = DbusMode::Full;
        let full = assess(&p);
        assert_eq!(full.level, RiskLevel::Dangerous);
        p.dbus.session.mode = DbusMode::Filtered;
        p.dbus.session.allow = vec!["org.freedesktop.systemd1".into()];
        assert_eq!(assess(&p).level, full.level, "the same as systemd by name");
    }

    #[test]
    fn the_strictest_window_profile_is_low_risk() {
        let a = assess(&PermissionSet::strict_gui());
        assert_eq!(a.level, RiskLevel::Low);
    }

    /// Full home access counts as dangerous, and as think twice when it is read-only.
    #[test]
    fn full_home_is_dangerous() {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        assert_eq!(assess(&p).level, RiskLevel::Dangerous);
        p.filesystem.home_access = Access::Ro;
        assert_eq!(assess(&p).level, RiskLevel::High);
    }

    /// Full network together with X11 makes the settings think twice (high risk).
    #[test]
    fn network_and_x11_high() {
        let mut p = PermissionSet::strict_gui();
        p.network.mode = NetworkMode::Full;
        p.display.x11 = true;
        let a = assess(&p);
        assert_eq!(a.level, RiskLevel::High);
        assert!(a.score >= 30);
    }

    /// Paths that hold keys or the whole system (~/.ssh, /etc, /) are recognized as sensitive; ordinary folders are not.
    #[test]
    fn key_and_system_folders_count_as_sensitive() {
        assert!(is_sensitive_path("~/.ssh"));
        assert!(is_sensitive_path("~/.ssh/id_rsa"));
        assert!(is_sensitive_path("/etc"));
        assert!(is_sensitive_path("/"));
        assert!(!is_sensitive_path("~/Projects"));
        assert!(!is_sensitive_path("/mnt/data"));
    }

    /// Every start place and credential store the sandbox locks or hides
    /// counts as sensitive, under any home; a drive under /run/media does
    /// not, though /run does (audit D-M2, D-M3).
    #[test]
    fn start_places_and_credential_stores_count_as_sensitive() {
        let home = std::path::Path::new("/mnt/disk/home/ann");
        let s = |p: &str| is_sensitive_path_in(p, home);
        for p in [
            "/mnt/disk/home/ann/.bash_profile",
            "/mnt/disk/home/ann/.ssh/id_ed25519",
            "/mnt/disk/home/ann/.config/vivaldi/Default",
            "/mnt/disk/home/ann/.local/bin/ls",
            "/mnt/disk/home/ann",
            "~/.zshenv",
            "/run/user/1000",
        ] {
            assert!(s(p), "{p}");
        }
        for p in ["/run/media/ann/stick/a.txt", "/mnt/disk/home/ann/Documents"] {
            assert!(!s(p), "{p}");
        }
    }
}
