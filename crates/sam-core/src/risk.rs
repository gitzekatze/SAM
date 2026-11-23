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

/// What `after` adds that is rated Think twice or Dangerous and `before`
/// did not have (at that level): the one rule for when a change asks first,
/// in the window, the Permission Manager, the command line and presets
/// (audit G-F2, G-F11, D-M9: each decided differently, and the window did
/// not ask at all when its permission list failed to load).
pub fn new_risks(before: &PermissionSet, after: &PermissionSet) -> Vec<RiskItem> {
    let had = assess(before).items;
    assess(after)
        .items
        .into_iter()
        .filter(|i| {
            i.level >= RiskLevel::High
                && !had
                    .iter()
                    .any(|b| b.key == i.key && b.title == i.title && b.level >= i.level)
        })
        .collect()
}

/// Whether a passed-through variable usually holds a secret or a way in
/// (a token, a key, a password, an agent or bus address).
fn secret_variable(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    [
        "TOKEN",
        "KEY",
        "SECRET",
        "PASS",
        "AUTH",
        "CREDENTIAL",
        "COOKIE",
        "SESSION",
        "SSH_",
        "GPG",
        "DBUS",
        "XAUTHORITY",
    ]
    .iter()
    .any(|w| n.contains(w))
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
            RiskLevel::High,
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
    // A service that hands out stored passwords counts as the keyring
    // switch does, whichever way it is reached (review F2: in the list of
    // allowed names it counted for nothing, so nothing asked first).
    for name in &p.dbus.session.allow {
        let level = if crate::permissions::dangerous_bus_name(name).is_some() {
            RiskLevel::Dangerous
        } else if crate::permissions::secret_bus_name(name) {
            RiskLevel::High
        } else {
            continue;
        };
        item(
            &mut items,
            "dbus.session.allow",
            &format!("Session service {name}"),
            level,
        );
    }
    if p.dbus.session.mode == DbusMode::Filtered {
        // Method and signal rules (`NAME=[METHOD][@PATH]`) reach a service
        // the app may not talk to otherwise: a call to systemd's is a way
        // out (audit D-H2: they counted for nothing).
        let service = |rule: &str| rule.split(['=', '@']).next().unwrap_or("").to_string();
        for rule in &p.dbus.session.calls {
            let level = if crate::permissions::dangerous_bus_name(&service(rule)).is_some() {
                RiskLevel::Dangerous
            } else {
                RiskLevel::High
            };
            item(
                &mut items,
                "dbus.session.calls",
                &format!("Calls {rule}"),
                level,
            );
        }
        for rule in &p.dbus.session.broadcasts {
            let level = if crate::permissions::dangerous_bus_name(&service(rule)).is_some() {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            };
            item(
                &mut items,
                "dbus.session.broadcasts",
                &format!("Hears {rule}"),
                level,
            );
        }
        for name in &p.dbus.session.own {
            let level = if crate::permissions::dangerous_bus_name(name).is_some() {
                RiskLevel::Dangerous
            } else {
                RiskLevel::Medium
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
    // Raw arguments can undo any part of the sandbox (`--bind / /`,
    // `--share-net`): audit D-M9.
    if !p.advanced.extra_bwrap_args.is_empty() {
        item(
            &mut items,
            "advanced.extra_bwrap_args",
            "Raw Bubblewrap arguments",
            RiskLevel::Dangerous,
        );
    }
    // Settings that take a protection away count too (audit D-H4, U-M10:
    // an app with the syscall filter off still read "Harmless").
    if !p.advanced.seccomp_baseline {
        item(
            &mut items,
            "advanced.seccomp_baseline",
            "Syscall filter off",
            RiskLevel::High,
        );
    }
    if p.advanced.landlock == Some(false) {
        item(
            &mut items,
            "advanced.landlock",
            "Landlock off",
            RiskLevel::High,
        );
    }
    if p.advanced.allow_userns {
        item(
            &mut items,
            "advanced.allow_userns",
            "Nested namespaces (more of the kernel within reach)",
            RiskLevel::Medium,
        );
    }
    for v in &p.environment.passthrough {
        let level = if secret_variable(v) {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
        item(
            &mut items,
            "environment.passthrough",
            &format!("Passes on {v}"),
            level,
        );
    }
    for port in &p.network.host_ports {
        item(
            &mut items,
            "network.host_ports",
            &format!("Reaches port {port} on this computer"),
            RiskLevel::High,
        );
    }
    for port in &p.network.app_ports {
        item(
            &mut items,
            "network.app_ports",
            &format!("Its port {port}, open to this computer"),
            RiskLevel::Low,
        );
    }
    // Together worse than apart: what the app can read, it can send with
    // the network (audit U-M10: full home and full network read the same as
    // the network alone).
    let reads_secrets = fs.home
        || fs.ssh
        || fs.gnupg
        || p.sockets.ssh_agent
        || p.integrations.keyring
        || p.dbus
            .session
            .allow
            .iter()
            .any(|n| crate::permissions::secret_bus_name(n))
        // A function rule reaches the password store as well
        // (`org.freedesktop.secrets=*`).
        || (p.dbus.session.mode == DbusMode::Filtered
            && p.dbus.session.calls.iter().any(|r| {
                crate::permissions::secret_bus_name(r.split(['=', '@']).next().unwrap_or(""))
            }));
    if p.network.mode == NetworkMode::Full && reads_secrets {
        item(
            &mut items,
            "combination.read_and_send",
            "Can send what it reads: your home, keys or passwords, with the network",
            RiskLevel::Dangerous,
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
/// the home itself and every folder that holds it, its key folders and
/// credential stores, and the places that make the computer run something
/// (start files, menu entries, SAM's own settings; the same lists the
/// sandbox locks, so a grant of `~/.bash_profile` is as dangerous as one of
/// `~/.bashrc`; audit D-M3). Compared as the path is reached: `.`, `..` and
/// repeated `/` count for nothing, so `/.` is `/` and `~/..` the folder
/// above the home (review F1: they were rated as harmless text). A
/// relative path is sensitive: what it names depends on where SAM was
/// started. Drives under `/run/media` are user files, not system ones.
pub fn is_sensitive_path_in(path: &str, home: &std::path::Path) -> bool {
    let home_abs = lexical_path(&home.to_string_lossy());
    let abs = lexical_path(&expand_home_text(path, &home_abs));
    if !abs.starts_with('/') {
        return true;
    }
    if home_abs == abs || home_abs.starts_with(&format!("{}/", abs.trim_end_matches('/'))) {
        return true;
    }
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

/// Folders in `/tmp` where programs outside the sandbox listen: terminal
/// multiplexers, SSH connections and agents, the X server, editors, and
/// the session bus and sound server where they keep their socket in
/// `/tmp` (`dbus-launch` without systemd, PulseAudio without a runtime
/// folder).
const SOCKET_FOLDERS_IN_TMP: &[&str] = &[
    "tmux-",
    "ssh-",
    ".X11-unix",
    ".ICE-unix",
    ".XIM-unix",
    "emacs",
    "dbus-",
    "pulse-",
];

/// Whether a folder grant of `path` shows the places in `/tmp` where
/// programs outside the sandbox listen. Connecting to them needs no write
/// access, so even a read-only grant hands them over: `tmux -S
/// /tmp/tmux-1000/default new-window …` runs a command outside the
/// sandbox (review SB-3). Only folder grants count: a file in `/tmp`
/// opened with the app shows no socket.
pub fn shows_host_sockets(path: &str) -> bool {
    let home = crate::util::home_dir();
    let abs = lexical_path(&expand_home_text(
        path,
        &lexical_path(&home.to_string_lossy()),
    ));
    match abs.strip_prefix("/tmp") {
        Some("") => true,
        Some(rest) => rest.strip_prefix('/').is_some_and(|first| {
            let first = first.split('/').next().unwrap_or("");
            SOCKET_FOLDERS_IN_TMP.iter().any(|s| first.starts_with(s))
        }),
        None => false,
    }
}

/// Whether a folder grant of `path` is dangerous by its name: a sensitive
/// path, a folder where outside programs listen, or a path with `..`. The
/// sandbox mounts a grant where its links lead, and `..` after a link goes
/// back from where the link leads, not from where it is written, so the
/// text alone cannot tell where such a grant ends up (review F1).
pub fn is_dangerous_grant(path: &str) -> bool {
    is_sensitive_path(path) || shows_host_sockets(path) || path.trim().split('/').any(|c| c == "..")
}

/// `p` with a leading `~` or `$HOME` written out as `home`.
fn expand_home_text(p: &str, home: &str) -> String {
    let t = p.trim();
    if t == "~" || t == "$HOME" {
        return home.to_string();
    }
    match t.strip_prefix("~/").or_else(|| t.strip_prefix("$HOME/")) {
        Some(rest) => format!("{}/{rest}", home.trim_end_matches('/')),
        None => t.to_string(),
    }
}

/// An absolute path as the kernel reaches it when no link is on the way:
/// without `.`, repeated `/` and trailing `/`, with `..` taking back the
/// folder before it (never above `/`). A relative path comes back
/// unchanged, without a trailing `/`.
fn lexical_path(p: &str) -> String {
    let p = p.trim();
    if !p.starts_with('/') {
        return p.trim_end_matches('/').to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

fn normalize_display_path(p: &str, home: &std::path::Path) -> String {
    let home_s = lexical_path(&home.to_string_lossy());
    let t = p.trim();
    if t.is_empty() {
        return "/".into();
    }
    let p = lexical_path(&expand_home_text(t, &home_s));
    if home_s == "/" {
        return p;
    }
    if p == home_s {
        return "~".into();
    }
    if let Some(rest) = p.strip_prefix(&format!("{home_s}/")) {
        return format!("~/{rest}");
    }
    p
}

fn path_risk(path: &str, write: bool) -> RiskLevel {
    if is_dangerous_grant(path) {
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

    /// Every switch says the same risk word in the window (its catalogue
    /// entry) as in the risk assessment that decides the badges and which
    /// changes ask first (audit D-M12: raw ALSA was "Think twice" in one and
    /// "Dangerous" in the other, so the window did not ask).
    #[test]
    fn every_switch_has_one_risk_word() {
        use crate::permissions::{permission_catalog, PermissionSet};
        let mut differ = Vec::new();
        for i in permission_catalog() {
            let mut p = PermissionSet::strict_gui();
            p.dbus.session.mode = DbusMode::Filtered;
            let had: Vec<String> = assess(&p)
                .items
                .iter()
                .filter(|x| x.key == i.key)
                .map(|x| x.title.clone())
                .collect();
            // A folder list gets a folder: "true" would be a relative
            // path, which is rated Dangerous (where it leads depends on
            // where SAM was started).
            let value = match i.key {
                "filesystem.custom_read" | "filesystem.custom_write" => "/srv/data",
                _ => "true",
            };
            if p.set_key(i.key, value).is_err() {
                continue;
            }
            let got = assess(&p)
                .items
                .into_iter()
                .filter(|x| x.key == i.key && !had.contains(&x.title))
                .map(|x| x.level)
                .max();
            if let Some(level) = got {
                if level != i.risk {
                    differ.push(format!(
                        "{}: window {:?}, assessment {level:?}",
                        i.key, i.risk
                    ));
                }
            }
        }
        assert!(differ.is_empty(), "{differ:#?}");
    }

    /// Single functions and signals of a service count in the risk word: a
    /// function of a service that can act outside the sandbox is
    /// Dangerous, any other function Think twice, a signal Harmless
    /// (audit D-H2: they counted for nothing).
    #[test]
    fn function_and_signal_rules_count_in_the_risk_word() {
        let mut p = PermissionSet::strict_gui();
        p.dbus.session.mode = DbusMode::Filtered;
        let base = assess(&p).level;
        p.dbus.session.calls = vec![
            "org.freedesktop.systemd1=org.freedesktop.systemd1.Manager.StartTransientUnit".into(),
        ];
        assert_eq!(assess(&p).level, RiskLevel::Dangerous);
        p.dbus.session.calls = vec!["org.example.Service=org.example.Iface.Method".into()];
        assert_eq!(assess(&p).level.max(base), RiskLevel::High.max(base));
        assert!(assess(&p)
            .items
            .iter()
            .any(|i| i.key == "dbus.session.calls"));
        p.dbus.session.calls.clear();
        p.dbus.session.broadcasts = vec!["org.example.Service=org.example.Iface.Changed".into()];
        assert!(assess(&p)
            .items
            .iter()
            .any(|i| i.key == "dbus.session.broadcasts"));
        assert!(assess(&p).level <= RiskLevel::Medium.max(base));
    }

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

    /// The one ask rule: a change asks when it adds something rated Think
    /// twice or Dangerous that was not there, or raises it; taking a risk
    /// away, keeping it, or adding something harmless does not ask
    /// (audit G-F2).
    #[test]
    fn only_new_or_higher_serious_risks_ask() {
        let mut before = PermissionSet::strict_gui();
        before.dbus.session.mode = DbusMode::Filtered;
        assert!(
            new_risks(&before, &before).is_empty(),
            "no change asks nothing"
        );
        let mut after = before.clone();
        after.devices.webcam = true;
        let added = new_risks(&before, &after);
        assert_eq!(added.len(), 1, "{added:#?}");
        assert_eq!(added[0].level, RiskLevel::High);
        assert!(
            new_risks(&after, &before).is_empty(),
            "taking it away does not ask"
        );
        assert!(
            new_risks(&after, &after).is_empty(),
            "keeping it does not ask"
        );
        let mut gpu = before.clone();
        gpu.devices.gpu = true;
        assert!(
            new_risks(&before, &gpu).is_empty(),
            "a harmless change does not ask"
        );
        // Raising the same switch asks again: read-only home to writable.
        let mut ro = before.clone();
        ro.filesystem.home = true;
        ro.filesystem.home_access = Access::Ro;
        let mut rw = ro.clone();
        rw.filesystem.home_access = Access::Rw;
        assert!(new_risks(&ro, &rw)
            .iter()
            .any(|i| i.level == RiskLevel::Dangerous));
        // A new item of a switch that already had one asks too: a second
        // secret passed through is a new secret.
        let mut one = before.clone();
        one.environment.passthrough = vec!["GITHUB_TOKEN".into()];
        let mut two = one.clone();
        two.environment
            .passthrough
            .push("AWS_SECRET_ACCESS_KEY".into());
        let added = new_risks(&one, &two);
        assert_eq!(added.len(), 1, "{added:#?}");
        assert!(added[0].title.contains("AWS_SECRET_ACCESS_KEY"));
    }

    /// Settings that take a protection away count in the risk word, and a
    /// secret passed through counts more than an ordinary variable (audit
    /// D-H4).
    #[test]
    fn switching_a_protection_off_counts() {
        let mut base = PermissionSet::strict_gui();
        base.dbus.session.mode = DbusMode::Filtered;
        let level_of = |p: &PermissionSet, key: &str| {
            assess(p)
                .items
                .into_iter()
                .filter(|i| i.key == key)
                .map(|i| i.level)
                .max()
        };
        let mut p = base.clone();
        p.advanced.seccomp_baseline = false;
        assert_eq!(
            level_of(&p, "advanced.seccomp_baseline"),
            Some(RiskLevel::High)
        );
        let mut p = base.clone();
        p.advanced.landlock = Some(false);
        assert_eq!(level_of(&p, "advanced.landlock"), Some(RiskLevel::High));
        let mut p = base.clone();
        p.advanced.extra_bwrap_args = vec!["--bind".into(), "/".into(), "/".into()];
        assert_eq!(
            level_of(&p, "advanced.extra_bwrap_args"),
            Some(RiskLevel::Dangerous)
        );
        let mut p = base.clone();
        p.environment.passthrough = vec!["LANG".into()];
        assert_eq!(
            level_of(&p, "environment.passthrough"),
            Some(RiskLevel::Medium)
        );
        p.environment.passthrough = vec!["GITHUB_TOKEN".into()];
        assert_eq!(
            level_of(&p, "environment.passthrough"),
            Some(RiskLevel::High)
        );
        let mut p = base.clone();
        p.network.host_ports = vec!["5432".into()];
        assert_eq!(level_of(&p, "network.host_ports"), Some(RiskLevel::High));
    }

    /// The network together with your home, keys or passwords is Dangerous:
    /// each alone is Think twice, but together the app can send what it
    /// reads (audit U-M10).
    #[test]
    fn reading_and_sending_together_is_dangerous() {
        let mut p = PermissionSet::strict_gui();
        p.dbus.session.mode = DbusMode::Filtered;
        p.network.mode = NetworkMode::Full;
        let combo = |p: &PermissionSet| {
            assess(p)
                .items
                .iter()
                .any(|i| i.key == "combination.read_and_send" && i.level == RiskLevel::Dangerous)
        };
        assert!(!combo(&p), "the network alone");
        let mut home = p.clone();
        home.filesystem.home = true;
        home.filesystem.home_access = Access::Ro;
        assert!(combo(&home), "network and the home, even read-only");
        let mut keys = p.clone();
        keys.filesystem.ssh = true;
        assert!(combo(&keys), "network and SSH keys");
        let mut gpg = p.clone();
        gpg.filesystem.gnupg = true;
        assert!(combo(&gpg), "network and GnuPG keys");
        let mut agent = p.clone();
        agent.sockets.ssh_agent = true;
        assert!(combo(&agent), "network and the SSH agent");
        let mut keyring = p.clone();
        keyring.integrations.keyring = true;
        assert!(combo(&keyring), "network and the keyring");
        let mut offline = home.clone();
        offline.network.mode = NetworkMode::None;
        assert!(!combo(&offline), "the home without the network");
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

    /// SAM's strictest window profile counts as low risk.
    #[test]
    fn the_strictest_window_profile_is_low_risk() {
        let a = assess(&PermissionSet::strict_gui());
        assert_eq!(a.level, RiskLevel::Low);
    }

    /// Full home access counts as dangerous, and as think twice when it is
    /// read-only; its name says which, so a writable home never reads as a
    /// read-only one.
    #[test]
    fn full_home_is_dangerous() {
        let home = |p: &PermissionSet| {
            let a = assess(p);
            let i = a.items.iter().find(|i| i.key == "filesystem.home").unwrap();
            (i.title.clone(), i.level, a.level)
        };
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        assert_eq!(
            home(&p),
            (
                "Full home access".into(),
                RiskLevel::Dangerous,
                RiskLevel::Dangerous
            )
        );
        p.filesystem.home_access = Access::Ro;
        assert_eq!(
            home(&p),
            (
                "Full home access (read-only)".into(),
                RiskLevel::High,
                RiskLevel::High
            )
        );
    }

    /// The reason given for a risk word names exactly the permissions at
    /// that level: the riskiest ones, never the milder ones next to them and
    /// never the basics every sandbox gets; low risk names none.
    #[test]
    fn the_reason_names_exactly_the_riskiest_permissions() {
        let deciding = |p: &PermissionSet| -> Vec<String> {
            assess(p).deciding().iter().map(|i| i.key.clone()).collect()
        };
        let mut p = PermissionSet::strict_gui();
        assert!(deciding(&p).is_empty(), "Wayland alone");
        assert_eq!(assess(&p).reason(), "");
        p.devices.gpu = true;
        assert_eq!(deciding(&p), ["devices.gpu"], "the one at Medium");
        p.network.mode = NetworkMode::Full;
        assert_eq!(deciding(&p), ["network.mode"]);
        assert_eq!(assess(&p).reason(), "Full network");
        p.devices.webcam = true;
        assert_eq!(deciding(&p), ["network.mode", "devices.webcam"]);
        assert_eq!(assess(&p).reason(), "Full network +1");
        let mut p = PermissionSet::strict_gui();
        p.devices.gpu = true;
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        p.filesystem.ssh = true;
        assert_eq!(deciding(&p), ["filesystem.home", "filesystem.ssh"]);
    }

    /// Game controllers count on their own; with all input devices granted
    /// they are part of that one, which counts as dangerous.
    #[test]
    fn game_controllers_count_unless_all_input_is_granted() {
        let mut p = PermissionSet::strict_gui();
        p.devices.gamepads = true;
        let a = assess(&p);
        assert!(a
            .items
            .iter()
            .any(|i| i.key == "devices.gamepads" && i.level == RiskLevel::Medium));
        assert_eq!(a.level, RiskLevel::Medium);
        p.devices.input = true;
        let a = assess(&p);
        assert!(!a.items.iter().any(|i| i.key == "devices.gamepads"));
        assert!(a
            .items
            .iter()
            .any(|i| i.key == "devices.input" && i.level == RiskLevel::Dangerous));
    }

    /// A level shows as its name where it is put into a text (the message
    /// after saving a preset).
    #[test]
    fn a_risk_level_shows_as_its_name() {
        for l in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Dangerous,
        ] {
            assert_eq!(l.to_string(), l.label());
        }
        assert_eq!(format!("({})", RiskLevel::High), "(High)");
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

    /// A path is rated where it leads, not as it is written: `.`, `..`
    /// and repeated `/` count for nothing, so `/.` is the whole computer
    /// and `~/..` the folder above the home, and a folder that holds the
    /// home counts as the home. A relative path is sensitive (what it
    /// names depends on where SAM was started); `..` inside the home that
    /// stays inside it is not (review F1).
    #[test]
    fn a_path_with_dots_or_double_slashes_is_rated_where_it_leads() {
        let home = std::path::Path::new("/home/ann");
        let s = |p: &str| is_sensitive_path_in(p, home);
        for p in [
            "/.",
            "/tmp/..",
            "//run",
            "/run/./user",
            "~/..",
            "~/.",
            "~/./.ssh",
            "/home/ann/Music/../../..",
            "/home",
            "$HOME/../ann",
            ".",
            "Documents",
        ] {
            assert!(s(p), "{p}");
        }
        for p in [
            "~/Projects/./notes",
            "/home/ann/Projects/../Music",
            "/mnt//data/",
            "/run/media/ann/../ann/stick",
        ] {
            assert!(!s(p), "{p}");
        }
    }

    /// An extra folder written so that it mounts the whole computer, the
    /// whole home or a place found through `..` is Dangerous, warned about
    /// and asks first (review F1: `/.` read Harmless and a preset applied
    /// it without a question).
    #[test]
    fn an_extra_folder_that_leads_to_the_whole_computer_asks_first() {
        let before = PermissionSet::strict_gui();
        for (read, write) in [
            (vec!["/."], vec![]),
            (vec!["//run"], vec![]),
            (vec!["/tmp/.."], vec![]),
            (vec![], vec!["~/."]),
            (vec!["/mnt/data/link/.."], vec![]),
        ] {
            let mut after = before.clone();
            after.filesystem.custom_read = read.iter().map(|s| s.to_string()).collect();
            after.filesystem.custom_write = write.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                assess(&after).level,
                RiskLevel::Dangerous,
                "{read:?} {write:?}"
            );
            assert!(!new_risks(&before, &after).is_empty(), "{read:?} {write:?}");
            let w = crate::warnings::evaluate(&after, &crate::warnings::WarningContext::default());
            assert!(
                w.iter().any(|w| w.code == "sensitive-path"),
                "{read:?} {write:?}: {w:?}"
            );
        }
    }

    /// A folder grant of /tmp, or of a place in it where outside programs
    /// listen, is Dangerous and warned about even read-only: connecting to
    /// a terminal session or an SSH connection there needs no write access
    /// (review SB-3). An ordinary folder in /tmp is not.
    #[test]
    fn a_grant_of_tmp_or_its_listening_places_is_dangerous_even_read_only() {
        let before = PermissionSet::strict_gui();
        for path in [
            "/tmp",
            "/tmp/",
            "/tmp/tmux-1000",
            "/tmp/ssh-XXXXabcd",
            "/tmp/.X11-unix",
            "/tmp/dbus-AbCdEf1234",
            "/tmp/pulse-AbCdEf1234",
        ] {
            let mut after = before.clone();
            after.filesystem.custom_read = vec![path.to_string()];
            assert_eq!(assess(&after).level, RiskLevel::Dangerous, "{path}");
            assert!(!new_risks(&before, &after).is_empty(), "{path}");
            let w = crate::warnings::evaluate(&after, &crate::warnings::WarningContext::default());
            assert!(w.iter().any(|w| w.code == "socket-folder"), "{path}: {w:?}");
        }
        let mut after = before.clone();
        after.filesystem.custom_read = vec!["/tmp/exchange".into()];
        assert!(!shows_host_sockets("/tmp/exchange"));
        assert_eq!(
            assess(&after)
                .items
                .iter()
                .find(|i| i.key == "filesystem.custom_read")
                .map(|i| i.level),
            Some(RiskLevel::Medium)
        );
    }

    /// A password service allowed by name counts as the keyring switch:
    /// Think twice, asks first, and with full network the app "can send
    /// what it reads". The default allowed names add nothing (review F2).
    #[test]
    fn a_password_service_allowed_by_name_counts_as_the_keyring_switch() {
        let mut before = PermissionSet::strict_gui();
        before.dbus.session.mode = DbusMode::Filtered;
        assert!(!assess(&before)
            .items
            .iter()
            .any(|i| i.key == "dbus.session.allow"));
        let (keyring, _) = IntegrationPerms {
            keyring: true,
            media_controls: false,
            file_manager: false,
            screen_sharing: false,
            input_method: false,
        }
        .bus_names();
        assert!(!keyring.is_empty());
        for name in keyring
            .into_iter()
            .chain(["org.freedesktop.secret*", "org.gnome.OnlineAccounts"])
        {
            let mut after = before.clone();
            after.dbus.session.allow.push(name.to_string());
            let added = new_risks(&before, &after);
            assert!(
                added
                    .iter()
                    .any(|i| i.key == "dbus.session.allow" && i.level == RiskLevel::High),
                "{name}: {added:?}"
            );
            after.network.mode = NetworkMode::Full;
            assert!(
                assess(&after)
                    .items
                    .iter()
                    .any(|i| i.key == "combination.read_and_send"),
                "{name}"
            );
        }
    }

    /// A function rule of a password service reaches the stored passwords
    /// as the allowed name does: with full network the app "can send what
    /// it reads" (review 2026-11-23).
    #[test]
    fn a_function_of_a_password_service_counts_with_the_network() {
        let mut p = PermissionSet::strict_gui();
        p.dbus.session.mode = DbusMode::Filtered;
        p.network.mode = NetworkMode::Full;
        let combined = |p: &PermissionSet| {
            assess(p)
                .items
                .iter()
                .any(|i| i.key == "combination.read_and_send")
        };
        assert!(!combined(&p));
        p.dbus.session.calls = vec!["org.freedesktop.secrets=*".into()];
        assert!(combined(&p));
        assert_eq!(assess(&p).level, RiskLevel::Dangerous);
    }

    /// A wildcard that covers the portal's own name lets every portal call
    /// through, past SAM's choice of interfaces: Dangerous. The portal's
    /// plain name stays allowed by default (review F2).
    #[test]
    fn a_wildcard_over_the_portal_is_dangerous() {
        for w in [
            "org.freedesktop.portal.Desktop.*",
            "org.freedesktop.portal.Desktop*",
            "org.freedesktop.portal.De*",
        ] {
            assert!(dangerous_bus_name(w).is_some(), "{w}");
            let mut p = PermissionSet::strict_gui();
            p.dbus.session.allow.push(w.into());
            assert_eq!(assess(&p).level, RiskLevel::Dangerous, "{w}");
        }
        assert!(dangerous_bus_name(PORTAL_NAME).is_none());
    }

    /// The sound server's own socket listed as an extra socket is as
    /// dangerous as "Sound without SAM's relay" (review SB-4); PipeWire's
    /// stays at the level of "Direct PipeWire access".
    #[test]
    fn the_sound_servers_own_socket_is_dangerous_as_an_extra_socket() {
        let mut p = PermissionSet::strict_gui();
        p.sockets.custom = vec!["/run/user/1000/pulse/native".into()];
        assert_eq!(assess(&p).level, RiskLevel::Dangerous);
        p.sockets.custom = vec!["/run/user/1000/pipewire-0".into()];
        assert_eq!(assess(&p).level, RiskLevel::High);
    }

    /// A dangerous socket is known however its path is written: `.` and
    /// doubled `/` count for nothing, as for the kernel (review
    /// 2026-11-23: `/run/dbus//system_bus_socket` read as an ordinary
    /// extra socket).
    #[test]
    fn a_dangerous_socket_is_known_however_it_is_written() {
        for s in [
            "/run/dbus//system_bus_socket",
            "/run/user/1000/pulse/./native",
            "/run/user/1000/systemd//private",
        ] {
            assert!(dangerous_socket(s).is_some(), "{s}");
            let mut p = PermissionSet::strict_gui();
            p.sockets.custom = vec![s.into()];
            assert_eq!(assess(&p).level, RiskLevel::Dangerous, "{s}");
        }
        assert!(dangerous_socket("/run/user/1000/kpxc_server").is_none());
    }
}
