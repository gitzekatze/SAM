//! The permission model (whitepaper §2.15).
//!
//! A [`PermissionSet`] is backend-neutral. Backends translate it into their own
//! command line or configuration. Every struct uses `#[serde(default)]` so
//! partial profiles and presets deserialize cleanly; the `Default` impls are
//! the strict, "nothing granted" posture.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize};

use crate::risk::RiskLevel;

/// Access level for a filesystem location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    #[default]
    None,
    Ro,
    Rw,
}

impl Access {
    pub fn is_granted(self) -> bool {
        self != Access::None
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Access::None => "none",
            Access::Ro => "ro",
            Access::Rw => "rw",
        }
    }
}

impl<'de> Deserialize<'de> for Access {
    /// Accepts `"none" | "ro" | "rw"` as well as booleans (`false` = none,
    /// `true` = rw) so the flat preset format from the whitepaper also loads.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            B(bool),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::B(false) => Ok(Access::None),
            Raw::B(true) => Ok(Access::Rw),
            Raw::S(s) => match s.to_ascii_lowercase().as_str() {
                "none" | "false" | "no" | "off" | "" => Ok(Access::None),
                "ro" | "read" | "read-only" | "readonly" => Ok(Access::Ro),
                "rw" | "true" | "yes" | "on" | "read-write" | "readwrite" => Ok(Access::Rw),
                other => Err(serde::de::Error::custom(format!(
                    "invalid access level '{other}' (expected none, ro or rw)"
                ))),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesystemPerms {
    /// Full home directory access. High risk.
    pub home: bool,
    /// Access level used when `home` is true.
    pub home_access: Access,
    pub documents: Access,
    pub downloads: Access,
    pub music: Access,
    pub pictures: Access,
    pub videos: Access,
    pub desktop: Access,
    /// Only meaningful with full home access: expose `~/.ssh`.
    pub ssh: bool,
    /// Only meaningful with full home access: expose `~/.gnupg`.
    pub gnupg: bool,
    /// Only meaningful with full home access: expose other sensitive dotfiles
    /// (keyrings, password stores, cloud credentials, ...).
    pub hidden_files: bool,
    pub custom_read: Vec<String>,
    pub custom_write: Vec<String>,
}

impl Default for FilesystemPerms {
    fn default() -> Self {
        FilesystemPerms {
            home: false,
            home_access: Access::Rw,
            documents: Access::None,
            downloads: Access::None,
            music: Access::None,
            pictures: Access::None,
            videos: Access::None,
            desktop: Access::None,
            ssh: false,
            gnupg: false,
            hidden_files: false,
            custom_read: vec![],
            custom_write: vec![],
        }
    }
}

/// The XDG user directories that have their own toggle.
pub const XDG_DIR_KEYS: [&str; 6] = ["documents", "downloads", "music", "pictures", "videos", "desktop"];

impl FilesystemPerms {
    pub fn xdg_access(&self, key: &str) -> Access {
        match key {
            "documents" => self.documents,
            "downloads" => self.downloads,
            "music" => self.music,
            "pictures" => self.pictures,
            "videos" => self.videos,
            "desktop" => self.desktop,
            _ => Access::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Full,
    #[default]
    None,
    /// Experimental: loopback only. Not part of the MVP.
    Localhost,
    /// Experimental: domain filtered. Not part of the MVP.
    Filtered,
}

impl NetworkMode {
    pub fn is_experimental(self) -> bool {
        matches!(self, NetworkMode::Localhost | NetworkMode::Filtered)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::Full => "full",
            NetworkMode::None => "none",
            NetworkMode::Localhost => "localhost",
            NetworkMode::Filtered => "filtered",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkPerms {
    pub mode: NetworkMode,
    /// Hosts for the experimental `filtered` mode.
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DevicePerms {
    pub gpu: bool,
    pub webcam: bool,
    pub input: bool,
    pub usb: bool,
    pub bluetooth: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AudioPerms {
    /// PipeWire / PulseAudio socket access.
    pub enabled: bool,
    /// Raw ALSA devices (`/dev/snd`). Off unless required.
    pub alsa_raw: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DisplayPerms {
    pub wayland: bool,
    pub x11: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbusMode {
    #[default]
    None,
    Filtered,
    Full,
}

impl DbusMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DbusMode::None => "none",
            DbusMode::Filtered => "filtered",
            DbusMode::Full => "full",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DbusBusPerms {
    pub mode: DbusMode,
    /// Bus names the app may talk to (filtered mode). Wildcards like
    /// `org.freedesktop.portal.*` are allowed.
    pub allow: Vec<String>,
    /// Bus names that are explicitly hidden even if matched by `allow`.
    pub deny: Vec<String>,
    /// Bus names the app may own (filtered mode).
    pub own: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DbusPerms {
    pub session: DbusBusPerms,
    pub system: DbusBusPerms,
}

/// Names a filtered session bus allows by default: desktop portals,
/// notifications and the system tray. Mirrors common Flatpak defaults.
pub fn default_session_allow() -> Vec<String> {
    vec![
        "org.freedesktop.portal.*".into(),
        "org.freedesktop.Notifications".into(),
        "org.kde.StatusNotifierWatcher".into(),
    ]
}

impl Default for DbusPerms {
    fn default() -> Self {
        DbusPerms {
            session: DbusBusPerms {
                mode: DbusMode::Filtered,
                allow: default_session_allow(),
                deny: vec![],
                own: vec![],
            },
            system: DbusBusPerms::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SocketPerms {
    /// Forward `$SSH_AUTH_SOCK`.
    pub ssh_agent: bool,
    /// CUPS printing socket.
    pub cups: bool,
    /// Additional socket paths (bound read-write).
    pub custom: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EnvPerms {
    /// Host environment variables passed through unchanged.
    pub passthrough: Vec<String>,
    /// Variables set explicitly inside the sandbox.
    pub set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostRuntime {
    /// `/usr/lib*`, `/usr/bin` and the whitelisted `/usr/share` resources.
    #[default]
    Minimal,
    /// All of `/usr` read-only (compatibility mode).
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdvancedPerms {
    pub host_runtime: HostRuntime,
    /// Keep the private sandbox home between runs. If false, a fresh tmpfs is used.
    pub persistent_home: bool,
    /// Landlock defense-in-depth. `None` follows the global setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub landlock: Option<bool>,
    /// Experimental strict seccomp filter.
    pub seccomp_strict: bool,
    /// Allow nested user namespaces (required by Chromium/Electron's own sandbox).
    pub allow_userns: bool,
    /// Expose host theme configuration (GTK/Qt/KDE settings, read-only).
    pub host_themes: bool,
    /// Extra raw backend arguments (power users only).
    pub extra_backend_args: Vec<String>,
}

impl Default for AdvancedPerms {
    fn default() -> Self {
        AdvancedPerms {
            host_runtime: HostRuntime::Minimal,
            persistent_home: true,
            landlock: None,
            seccomp_strict: false,
            allow_userns: true,
            host_themes: true,
            extra_backend_args: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PermissionSet {
    pub filesystem: FilesystemPerms,
    pub network: NetworkPerms,
    pub devices: DevicePerms,
    pub audio: AudioPerms,
    pub display: DisplayPerms,
    pub dbus: DbusPerms,
    pub sockets: SocketPerms,
    pub environment: EnvPerms,
    pub advanced: AdvancedPerms,
}

impl PermissionSet {
    /// The strictest set that still lets a Wayland GUI app open a window.
    pub fn strict_gui() -> Self {
        let mut p = PermissionSet::default();
        p.display.wayland = true;
        p
    }

    /// Read a value by dotted key, e.g. `network.mode`.
    pub fn get_key(&self, key: &str) -> Result<serde_json::Value> {
        let v = serde_json::to_value(self)?;
        let mut cur = &v;
        for part in key.split('.') {
            cur = cur
                .get(part)
                .ok_or_else(|| anyhow!("unknown permission key '{key}'"))?;
        }
        Ok(cur.clone())
    }

    /// Set a value by dotted key. `raw` is parsed as JSON when possible
    /// (`true`, `["a","b"]`, `3`), otherwise taken as a string.
    pub fn set_key(&mut self, key: &str, raw: &str) -> Result<()> {
        let mut v = serde_json::to_value(&*self)?;
        let parts: Vec<&str> = key.split('.').collect();
        let (last, parents) = parts.split_last().context("empty key")?;
        let mut cur = &mut v;
        for part in parents {
            cur = cur
                .get_mut(*part)
                .ok_or_else(|| anyhow!("unknown permission key '{key}'"))?;
        }
        let obj = cur
            .as_object_mut()
            .ok_or_else(|| anyhow!("'{key}' is not a settable key"))?;
        let existing = obj.get(*last);
        if existing.is_none() && !(*last == "landlock" && parents == ["advanced"]) {
            bail!("unknown permission key '{key}'");
        }
        let new_val = parse_value(raw, existing);
        obj.insert((*last).to_string(), new_val);
        *self = serde_json::from_value(v).with_context(|| format!("invalid value for '{key}': {raw}"))?;
        Ok(())
    }
}

fn parse_value(raw: &str, existing: Option<&serde_json::Value>) -> serde_json::Value {
    use serde_json::Value;
    // Comma separated input into an array field, for CLI convenience.
    if let Some(Value::Array(_)) = existing {
        if !raw.trim_start().starts_with('[') {
            let items: Vec<Value> = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_string()))
                .collect();
            return Value::Array(items);
        }
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(_) => Value::String(raw.to_string()),
    }
}

/// Plain-language description of a permission, for the GUI and `sam-jail permissions`.
#[derive(Debug, Clone, Serialize)]
pub struct PermissionInfo {
    pub key: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub risk: RiskLevel,
    /// Only shown in advanced mode.
    pub advanced: bool,
}

macro_rules! perm {
    ($key:expr, $cat:expr, $title:expr, $desc:expr, $risk:ident) => {
        PermissionInfo { key: $key, category: $cat, title: $title, description: $desc, risk: RiskLevel::$risk, advanced: false }
    };
    ($key:expr, $cat:expr, $title:expr, $desc:expr, $risk:ident, advanced) => {
        PermissionInfo { key: $key, category: $cat, title: $title, description: $desc, risk: RiskLevel::$risk, advanced: true }
    };
}

pub fn permission_catalog() -> Vec<PermissionInfo> {
    vec![
        perm!("filesystem.home", "Filesystem", "Full Home Access",
            "Allows the app to read and write all files in your home directory. This is high risk and usually not required.", Dangerous),
        perm!("filesystem.home_access", "Filesystem", "Home access level",
            "Whether full home access is read-only or read/write.", High, advanced),
        perm!("filesystem.documents", "Filesystem", "Documents",
            "Lets the app open and save files in your Documents folder.", Medium),
        perm!("filesystem.downloads", "Filesystem", "Downloads",
            "Lets the app open and save files in your Downloads folder.", Medium),
        perm!("filesystem.music", "Filesystem", "Music",
            "Lets the app access your Music folder.", Medium),
        perm!("filesystem.pictures", "Filesystem", "Pictures",
            "Lets the app access your Pictures folder.", Medium),
        perm!("filesystem.videos", "Filesystem", "Videos",
            "Lets the app access your Videos folder.", Medium),
        perm!("filesystem.desktop", "Filesystem", "Desktop folder",
            "Lets the app access files on your Desktop.", Medium),
        perm!("filesystem.ssh", "Filesystem", "SSH keys",
            "With full home access, also exposes ~/.ssh. Your SSH private keys could be stolen.", Dangerous, advanced),
        perm!("filesystem.gnupg", "Filesystem", "GnuPG keys",
            "With full home access, also exposes ~/.gnupg. Your PGP private keys could be stolen.", Dangerous, advanced),
        perm!("filesystem.hidden_files", "Filesystem", "Sensitive dotfiles",
            "With full home access, also exposes keyrings, password stores and cloud credentials.", Dangerous, advanced),
        perm!("filesystem.custom_read", "Filesystem", "Extra read-only folders",
            "Additional folders the app can read but not change.", Medium, advanced),
        perm!("filesystem.custom_write", "Filesystem", "Extra read/write folders",
            "Additional folders the app can read and change.", High, advanced),
        perm!("network.mode", "Network", "Network access",
            "'full' shares your internet connection with the app. 'none' places it in an isolated network with no connectivity.", High),
        perm!("devices.gpu", "Devices", "GPU acceleration",
            "Hardware-accelerated graphics through /dev/dri and host graphics drivers. Needed by most games, browsers and editors.", Medium),
        perm!("devices.webcam", "Devices", "Webcam",
            "Access to video capture devices. The app could record you.", High),
        perm!("devices.input", "Devices", "Input devices / gamepads",
            "Raw access to /dev/input, e.g. for game controllers. Can be used to read keystrokes.", Dangerous, advanced),
        perm!("devices.usb", "Devices", "Raw USB",
            "Raw access to USB devices. Needed by flashing tools and some hardware utilities.", Dangerous, advanced),
        perm!("devices.bluetooth", "Devices", "Bluetooth",
            "Bluetooth needs the system D-Bus and cannot be isolated well.", Dangerous, advanced),
        perm!("audio.enabled", "Audio", "Sound",
            "Play and record audio through PipeWire or PulseAudio. Recording is possible once this is on.", Medium),
        perm!("audio.alsa_raw", "Audio", "Raw ALSA devices",
            "Direct sound card access. Only needed by apps that do not support PipeWire/PulseAudio.", High, advanced),
        perm!("display.wayland", "Display", "Wayland",
            "Show windows through the Wayland compositor. Wayland isolates apps from each other.", Low),
        perm!("display.x11", "Display", "X11 / XWayland",
            "X11 access allows the app to observe input and other windows. Wayland is safer, but some apps may require XWayland.", High),
        perm!("dbus.session.mode", "D-Bus", "Session bus",
            "'filtered' only allows portals, notifications and the tray. 'full' lets the app talk to every desktop service, which is high risk.", High),
        perm!("dbus.session.allow", "D-Bus", "Allowed session names",
            "Bus names reachable in filtered mode.", Medium, advanced),
        perm!("dbus.system.mode", "D-Bus", "System bus",
            "The system bus controls hardware, networking and power. Denied by default.", Dangerous, advanced),
        perm!("sockets.ssh_agent", "Sockets", "SSH agent",
            "Lets the app use keys loaded in your SSH agent.", High, advanced),
        perm!("sockets.cups", "Sockets", "Printing",
            "Access to the CUPS printing service.", Low, advanced),
        perm!("environment.passthrough", "Environment", "Passed-through variables",
            "Host environment variables made visible to the app.", Medium, advanced),
        perm!("advanced.host_runtime", "Advanced", "Host runtime exposure",
            "'minimal' exposes system libraries and a whitelist of shared data. 'full' exposes all of /usr read-only (compatibility).", Medium, advanced),
        perm!("advanced.persistent_home", "Advanced", "Persistent private home",
            "Keep the app's own private settings folder between runs.", Low, advanced),
        perm!("advanced.landlock", "Advanced", "Landlock enforcement",
            "Kernel-enforced write restrictions as an extra layer. Unset follows the global setting.", Low, advanced),
        perm!("advanced.seccomp_strict", "Advanced", "Strict syscall filter",
            "Experimental: blocks rarely needed, dangerous system calls. Can break apps.", Low, advanced),
        perm!("advanced.allow_userns", "Advanced", "Nested namespaces",
            "Lets Chromium/Electron apps start their own internal sandbox.", Low, advanced),
        perm!("advanced.host_themes", "Advanced", "Host theme settings",
            "Read-only access to GTK/Qt/KDE theme configuration so apps match your desktop.", Low, advanced),
        perm!("advanced.extra_backend_args", "Advanced", "Raw backend arguments",
            "Arguments passed verbatim to the sandbox backend. Can weaken the sandbox.", High, advanced),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_from_bool_and_str() {
        #[derive(Deserialize)]
        struct T {
            a: Access,
            b: Access,
            c: Access,
        }
        let t: T = toml::from_str("a = false\nb = \"ro\"\nc = true").unwrap();
        assert_eq!((t.a, t.b, t.c), (Access::None, Access::Ro, Access::Rw));
    }

    #[test]
    fn set_and_get_keys() {
        let mut p = PermissionSet::default();
        p.set_key("network.mode", "full").unwrap();
        assert_eq!(p.network.mode, NetworkMode::Full);
        p.set_key("filesystem.documents", "ro").unwrap();
        assert_eq!(p.filesystem.documents, Access::Ro);
        p.set_key("devices.gpu", "true").unwrap();
        assert!(p.devices.gpu);
        p.set_key("filesystem.custom_read", "/a, /b").unwrap();
        assert_eq!(p.filesystem.custom_read, vec!["/a", "/b"]);
        p.set_key("advanced.landlock", "false").unwrap();
        assert_eq!(p.advanced.landlock, Some(false));
        assert!(p.set_key("network.bogus", "1").is_err());
        assert!(p.set_key("network.mode", "sideways").is_err());
        assert_eq!(p.get_key("network.mode").unwrap(), "full");
    }

    #[test]
    fn toml_roundtrip() {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.downloads = Access::Rw;
        let s = toml::to_string(&p).unwrap();
        let back: PermissionSet = toml::from_str(&s).unwrap();
        assert_eq!(p, back);
    }
}
