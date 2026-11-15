//! The permission model.
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
    /// `true` = rw) so the older flat preset format also loads.
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
                other => Err(serde::de::Error::custom(crate::i18n::trf("invalid access level '{other}' (expected none, ro or rw)", &[("other", &other)]))),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesystemPerms {
    /// Files passed to the app ("Open with"): `rw` lets it save them, `ro`
    /// only view them.
    pub opened_files: Access,
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
            opened_files: Access::Rw,
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
    /// "filtered" was an experimental mode that was never enforced and
    /// always meant no network; old profiles with it load as `None`.
    #[default]
    #[serde(alias = "filtered")]
    None,
    /// Loopback only: no internet, but local servers on both sides stay
    /// reachable (forwarded by `pasta`). For local AI/web-UI apps.
    Localhost,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::Full => "full",
            NetworkMode::None => "none",
            NetworkMode::Localhost => "localhost",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkPerms {
    pub mode: NetworkMode,
    /// `localhost` mode: TCP ports on the host's loopback the app may reach,
    /// e.g. "11434" for Ollama. Nothing else on the host is reachable.
    pub host_ports: Vec<String>,
    /// `localhost` mode: the app's own ports to make reachable from this
    /// computer (e.g. its web page). Empty = detected automatically, except
    /// privileged ports and well-known local services.
    pub app_ports: Vec<String>,
}

impl NetworkPerms {
    /// Valid ports from `host_ports` (DNS, port 53, is never forwarded).
    pub fn valid_app_ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.app_ports.iter().filter_map(|p| p.trim().parse().ok()).filter(|p| *p != 0).collect();
        v.sort();
        v.dedup();
        v
    }

    pub fn valid_host_ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.host_ports.iter().filter_map(|p| p.trim().parse().ok()).filter(|p| *p != 0 && *p != 53).collect();
        v.sort();
        v.dedup();
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DevicePerms {
    pub gpu: bool,
    pub webcam: bool,
    /// Game controllers only: joystick device nodes, not keyboards or mice.
    pub gamepads: bool,
    /// All of /dev/input (keyboards, mice, everything) and /dev/uinput.
    pub input: bool,
    pub usb: bool,
    pub bluetooth: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AudioPerms {
    /// Sound through the PulseAudio socket (PipeWire's `pipewire-pulse`
    /// on current systems): playing and recording, but no cameras or
    /// screen-cast streams.
    pub enabled: bool,
    /// The raw PipeWire socket (`pipewire-0`). It reaches every PipeWire
    /// node, including cameras and other apps' screen-cast streams, because
    /// PipeWire does not restrict programs outside Flatpak. Only for apps
    /// that speak PipeWire natively and have no PulseAudio support.
    pub pipewire: bool,
    /// Raw ALSA devices (`/dev/snd`). Off unless required.
    pub alsa_raw: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DisplayPerms {
    pub wayland: bool,
    pub x11: bool,
    /// The compositor's own socket instead of one with a security context,
    /// so privileged protocols (clipboard history, screen capture, virtual
    /// keyboards) stay visible. Only for tools that are exactly that.
    pub wayland_privileged: bool,
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
    /// Method-level rules `NAME=[METHOD][@PATH]` (xdg-dbus-proxy `--call`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<String>,
    /// Signal rules `NAME=[METHOD][@PATH]` (xdg-dbus-proxy `--broadcast`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broadcasts: Vec<String>,
}

pub const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";

/// Session-bus services that can act outside the sandbox (start programs,
/// run scripts in the desktop shell, change any setting, bypass the portal
/// filter), with the reason. Exact names and prefixes ending in `.`.
const DANGEROUS_BUS_NAMES: &[(&str, &str)] = &[
    ("org.freedesktop.systemd1", crate::i18n::n_("can start any program outside the sandbox")),
    ("org.freedesktop.Flatpak", crate::i18n::n_("can start programs outside the sandbox")),
    ("org.freedesktop.portal.Flatpak", crate::i18n::n_("can start new sandboxes and programs")),
    ("org.freedesktop.impl.portal.", crate::i18n::n_("bypasses the portal and its prompts")),
    ("org.kde.KWin", crate::i18n::n_("can run scripts in the window manager")),
    ("org.kde.plasmashell", crate::i18n::n_("can run scripts in the desktop shell")),
    ("org.kde.klauncher", crate::i18n::n_("can start programs outside the sandbox")),
    ("org.kde.kded", crate::i18n::n_("controls desktop background services")),
    ("org.kde.krunner", crate::i18n::n_("can run commands")),
    ("org.kde.ksmserver", crate::i18n::n_("controls the session (log out, restore programs)")),
    ("org.kde.kglobalaccel", crate::i18n::n_("can register global shortcuts and observe key presses")),
    ("org.gnome.Shell", crate::i18n::n_("can run scripts in the desktop shell")),
    ("org.gnome.SessionManager", crate::i18n::n_("controls the session")),
    ("ca.desrt.dconf", crate::i18n::n_("can change any desktop setting, including autostart")),
];

/// Why a bus name (or wildcard) in an allow list is dangerous, if it is.
/// Wildcards (`org.kde.*`, `*`) count when they cover a dangerous name, and
/// any wildcard over the portal namespace would bypass SAM's portal filter.
/// Sockets that give whoever can connect control over the computer or
/// a way around the sandbox's D-Bus filter.
pub fn dangerous_socket(path: &str) -> Option<String> {
    let p = path.trim();
    let bad: &[(&str, &str)] = &[
        ("docker.sock", crate::i18n::n_("controls Docker, which equals full control of the computer")),
        ("podman.sock", crate::i18n::n_("controls Podman containers on this computer")),
        ("containerd.sock", crate::i18n::n_("controls containers on this computer")),
        ("/run/dbus/system_bus_socket", crate::i18n::n_("is the system bus, unfiltered")),
        ("systemd/private", crate::i18n::n_("controls systemd")),
        ("/bus", crate::i18n::n_("is a D-Bus socket, which bypasses SAM's D-Bus filter")),
        ("libvirt", crate::i18n::n_("controls virtual machines")),
    ];
    bad.iter().find(|(needle, _)| p.contains(needle)).map(|(_, why)| format!("{p} {}", crate::i18n::tr(why)))
}

/// True when a bus-name pattern (`org.kde.*`, `org.kde*`, exact) covers `name`.
pub fn bus_pattern_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix(".*") {
        Some(prefix) => name == prefix || name.starts_with(&format!("{prefix}.")),
        None => match pattern.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => pattern == name,
        },
    }
}

/// Wildcard allow entries that cover a name in `deny`: they cannot be
/// enforced together, so the wildcard is not used.
pub fn blocked_wildcards(b: &DbusBusPerms) -> Vec<String> {
    b.allow.iter().filter(|a| a.ends_with('*') && b.deny.iter().any(|d| bus_pattern_matches(a, d))).cloned().collect()
}

/// Why an app may not own `name` on the session bus, if it may not:
/// a name of the D-Bus protocols themselves, a service SAM treats as
/// dangerous, or one a service on this computer starts on demand
/// (`activatable`, see `host::activatable_bus_names`). Checked at every
/// start, also for names the user added.
pub fn refuse_own_name(name: &str, activatable: &std::collections::BTreeSet<String>) -> Option<String> {
    const PROTOCOL: [&str; 6] = ["org.freedesktop.", "org.gtk.", "org.mpris.", "ca.desrt.", "org.a11y.", "io.github.gitzekatze.SAM"];
    if PROTOCOL.iter().any(|p| name.starts_with(p)) {
        return Some(crate::i18n::trf("{name} belongs to the desktop's own protocols", &[("name", &name)]));
    }
    if let Some(why) = dangerous_bus_name(name) {
        return Some(why);
    }
    activatable
        .contains(name)
        .then(|| crate::i18n::trf("{name} is a service on this computer that starts on demand; owning it would intercept its requests", &[("name", &name)]))
}

pub fn dangerous_bus_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name == "*" || name == "org.*" || name == "org.freedesktop.*" || name.starts_with("org.freedesktop.portal.*") {
        return Some(crate::i18n::trf("{name} covers services that can act outside the sandbox", &[("name", &name)]));
    }
    let wildcard = name.strip_suffix(".*").or_else(|| name.strip_suffix('*'));
    for (d, why) in DANGEROUS_BUS_NAMES {
        let hit = match wildcard {
            Some(prefix) => d.starts_with(prefix) || prefix.starts_with(d.trim_end_matches('.')),
            None => {
                if d.ends_with('.') {
                    name.starts_with(d)
                } else {
                    name == *d || name.starts_with(&format!("{d}.")) || name.starts_with(&format!("{d}5")) || name.starts_with(&format!("{d}6"))
                }
            }
        };
        if hit {
            return Some(format!("{name} {}", crate::i18n::tr(why)));
        }
    }
    None
}

/// Portal interfaces a sandboxed app may use. Portals see SAM apps as
/// ordinary (unsandboxed) programs, so interfaces that would act on the
/// host without asking are left out: Screenshot, Background (autostart),
/// DynamicLauncher (menu entries), Trash, Wallpaper, RemoteDesktop,
/// InputCapture, GlobalShortcuts, Location, Usb, Clipboard, Secret, Account.
pub fn portal_interfaces(p: &PermissionSet) -> Vec<&'static str> {
    let mut v = vec![
        "OpenURI",
        "Notification",
        "Settings",
        "FileChooser",
        "Print",
        "Email",
        "Inhibit",
        "NetworkMonitor",
        "ProxyResolver",
        "MemoryMonitor",
        "PowerProfileMonitor",
    ];
    if p.devices.webcam {
        v.push("Camera");
    }
    if p.integrations.screen_sharing {
        v.push("ScreenCast");
    }
    v
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DbusPerms {
    pub session: DbusBusPerms,
    /// The system bus is all or nothing (no filter), so it has a mode only.
    pub system: DbusSystemPerms,
}

/// System bus access: `none` or `full`. A "filtered" value from older
/// profiles (never supported) loads as `none`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DbusSystemPerms {
    #[serde(deserialize_with = "system_bus_mode")]
    pub mode: DbusMode,
}

fn system_bus_mode<'de, D: serde::Deserializer<'de>>(d: D) -> Result<DbusMode, D::Error> {
    Ok(match DbusMode::deserialize(d)? {
        DbusMode::Full => DbusMode::Full,
        _ => DbusMode::None,
    })
}

impl DbusBusPerms {
    /// Bus names a tray icon registers under (`org.kde.StatusNotifierItem-<pid>-<n>`,
    /// used by libappindicator, Qt and Electron). D-Bus filters cannot
    /// wildcard the suffix, so, like Flatpak, grant the concrete names. The app
    /// runs in its own PID namespace, so its PID is small (2 when AppRun execs
    /// the binary). Empty unless the tray watcher is allowed.
    pub fn tray_own_names(&self) -> Vec<String> {
        if !self.allow.iter().any(|n| n == "org.kde.StatusNotifierWatcher") {
            return vec![];
        }
        let mut names = Vec::new();
        for prefix in ["org.kde.StatusNotifierItem", "org.freedesktop.StatusNotifierItem"] {
            for pid in 2..=12 {
                for n in 1..=2 {
                    names.push(format!("{prefix}-{pid}-{n}"));
                }
            }
        }
        names
    }
}

/// Names a filtered session bus allows by default: desktop portals,
/// notifications and the system tray. Mirrors common Flatpak defaults.
///
/// Portals are listed one by one instead of `org.freedesktop.portal.*`: the
/// wildcard also exposed `portal.Flatpak` (sandbox spawning API) and
/// `portal.Tracker` (file index search), which AppImages do not need.
pub fn default_session_allow() -> Vec<String> {
    vec![
        // Desktop portal, restricted to selected interfaces (see portal_interfaces).
        "org.freedesktop.portal.Desktop".into(),
        "org.freedesktop.Notifications".into(),
        "org.kde.StatusNotifierWatcher".into(),
    ]
}

impl Default for DbusPerms {
    fn default() -> Self {
        DbusPerms {
            session: DbusBusPerms { mode: DbusMode::Filtered, allow: default_session_allow(), deny: vec![], own: vec![], calls: vec![], broadcasts: vec![] },
            system: DbusSystemPerms::default(),
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
    /// Baseline syscall filter (follows the global setting when on; a
    /// repair step can turn it off for one app).
    pub seccomp_baseline: bool,
    /// Allow nested user namespaces (required by Chromium/Electron's own sandbox).
    pub allow_userns: bool,
    /// Expose host theme configuration (GTK/Qt/KDE settings, read-only).
    pub host_themes: bool,
    /// Writable app folder: changes the app makes to its own files go to a
    /// separate per-app layer (Bubblewrap overlay); the extracted copy stays
    /// untouched. For portable apps that save next to themselves.
    pub writable_appdir: bool,
    /// Extra raw Bubblewrap arguments (power users only). Profiles from
    /// before 0.2 call it `extra_backend_args`.
    #[serde(alias = "extra_backend_args")]
    pub extra_bwrap_args: Vec<String>,
    /// Bundled libraries replaced by the system's copy (file names such as
    /// `libsystemd.so.0`), read-only. For AppImages that bundle a library
    /// older than a system library that needs it.
    pub system_libraries: Vec<String>,
}

/// Whether `name` is a plain shared-library file name (`libfoo.so`,
/// `libfoo.so.1.2`), which is all `advanced.system_libraries` accepts: no
/// folders, no `..`, so the list cannot bind arbitrary files.
pub fn is_library_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("lib") else { return false };
    let Some(pos) = rest.find(".so") else { return false };
    let (stem, tail) = rest.split_at(pos);
    !stem.is_empty()
        && name.len() <= 100
        && stem.chars().all(|c| c.is_ascii_alphanumeric() || "_+-".contains(c))
        && tail[3..].split('.').skip(1).all(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        && (tail.len() == 3 || tail[3..].starts_with('.'))
}

/// Desktop services an app may use through the filtered session bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IntegrationPerms {
    /// Password storage (Secret Service / KWallet). The keyring does not
    /// separate apps: the app can read every stored password.
    pub keyring: bool,
    /// Media keys and "now playing" (MPRIS), and keeping the screen awake.
    pub media_controls: bool,
    /// "Show in folder" through the file manager.
    pub file_manager: bool,
    /// Screen sharing through the portal (the desktop always asks which
    /// screen or window). For video calls and streaming.
    pub screen_sharing: bool,
    /// Typing through an input method (Fcitx5 or IBus), e.g. for Chinese,
    /// Japanese or Korean.
    pub input_method: bool,
}

impl Default for IntegrationPerms {
    fn default() -> Self {
        // Input methods are on by default, like Flatpak: their portal
        // frontends only accept typed text from the app.
        IntegrationPerms { keyring: false, media_controls: false, file_manager: false, screen_sharing: false, input_method: true }
    }
}

impl IntegrationPerms {
    /// Bus names to talk to and to own for the enabled integrations.
    pub fn bus_names(&self) -> (Vec<&'static str>, Vec<&'static str>) {
        let (mut talk, mut own) = (Vec::new(), Vec::new());
        if self.keyring {
            talk.extend(["org.freedesktop.secrets", "org.kde.kwalletd6", "org.kde.kwalletd5"]);
        }
        if self.media_controls {
            talk.extend(["org.freedesktop.ScreenSaver", "org.freedesktop.PowerManagement"]);
            own.push("org.mpris.MediaPlayer2.*");
        }
        if self.file_manager {
            talk.push("org.freedesktop.FileManager1");
        }
        if self.input_method {
            // The sandbox frontends of Fcitx5 and IBus, the names Flatpak
            // apps use. Not `org.fcitx.Fcitx5`: its controller interface
            // can change Fcitx's configuration.
            talk.extend(["org.freedesktop.portal.Fcitx", "org.freedesktop.portal.IBus"]);
        }
        (talk, own)
    }
}

impl Default for AdvancedPerms {
    fn default() -> Self {
        AdvancedPerms {
            host_runtime: HostRuntime::Minimal,
            persistent_home: true,
            landlock: None,
            seccomp_strict: false,
            seccomp_baseline: true,
            // Off: namespaces add kernel attack surface. Turned on by the
            // recommendation only for apps that start their own sandbox.
            allow_userns: false,
            host_themes: true,
            writable_appdir: false,
            extra_bwrap_args: vec![],
            system_libraries: vec![],
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
    pub integrations: IntegrationPerms,
}

impl PermissionSet {
    /// The strictest set that still lets a Wayland GUI app open a window.
    pub fn strict_gui() -> Self {
        let mut p = PermissionSet::default();
        p.display.wayland = true;
        p
    }

    /// The filtered session bus as it is enforced: the explicit lists plus
    /// the enabled integrations and tray item names.
    pub fn effective_session_bus(&self) -> DbusBusPerms {
        let mut b = self.dbus.session.clone();
        // xdg-dbus-proxy has no deny rules: a wildcard allow entry would let
        // a blocked name through. Fail closed: drop such wildcards.
        let blocked = blocked_wildcards(&b);
        b.allow.retain(|a| !blocked.contains(a));
        let (talk, own) = self.integrations.bus_names();
        for n in talk {
            if !b.allow.iter().any(|x| x == n) {
                b.allow.push(n.into());
            }
        }
        b.own.extend(own.into_iter().map(String::from));
        b.own.extend(b.tray_own_names());
        // The portal: only selected interfaces, method by method.
        if let Some(i) = b.allow.iter().position(|n| n == PORTAL_NAME) {
            b.allow.remove(i);
            let obj = "/org/freedesktop/portal/desktop";
            for iface in portal_interfaces(self) {
                b.calls.push(format!("{PORTAL_NAME}=org.freedesktop.portal.{iface}.*@{obj}"));
            }
            b.calls.push(format!("{PORTAL_NAME}=org.freedesktop.portal.Request.*@{obj}/request/*"));
            if self.integrations.screen_sharing {
                b.calls.push(format!("{PORTAL_NAME}=org.freedesktop.portal.Session.*@{obj}/session/*"));
            }
            // Version checks and introspection (read-only).
            b.calls.push(format!("{PORTAL_NAME}=org.freedesktop.DBus.Properties.Get@{obj}"));
            b.calls.push(format!("{PORTAL_NAME}=org.freedesktop.DBus.Properties.GetAll@{obj}"));
            b.calls.push(format!("{PORTAL_NAME}=org.freedesktop.DBus.Introspectable.*@{obj}"));
            b.broadcasts.push(format!("{PORTAL_NAME}=@/org/freedesktop/portal/*"));
        }
        b
    }

    /// Read a value by dotted key, e.g. `network.mode`.
    pub fn get_key(&self, key: &str) -> Result<serde_json::Value> {
        let v = serde_json::to_value(self)?;
        let mut cur = &v;
        for part in key.split('.') {
            cur = cur.get(part).ok_or_else(|| anyhow!("{}", crate::i18n::trf("unknown permission key '{key}'", &[("key", &key)])))?;
        }
        Ok(cur.clone())
    }

    /// Set a value by dotted key. `raw` is parsed as JSON when possible
    /// (`true`, `["a","b"]`, `3`), otherwise taken as a string.
    pub fn set_key(&mut self, key: &str, raw: &str) -> Result<()> {
        let mut v = serde_json::to_value(&*self)?;
        let parts: Vec<&str> = key.split('.').collect();
        let (last, parents) = parts.split_last().context(crate::i18n::tr("empty key"))?;
        let mut cur = &mut v;
        for part in parents {
            cur = cur.get_mut(*part).ok_or_else(|| anyhow!("{}", crate::i18n::trf("unknown permission key '{key}'", &[("key", &key)])))?;
        }
        let obj = cur.as_object_mut().ok_or_else(|| anyhow!("{}", crate::i18n::trf("'{key}' is not a settable key", &[("key", &key)])))?;
        let existing = obj.get(*last);
        if existing.is_none() && !(*last == "landlock" && parents == ["advanced"]) {
            bail!("{}", crate::i18n::trf("unknown permission key '{key}'", &[("key", &key)]));
        }
        let new_val = parse_value(raw, existing);
        obj.insert((*last).to_string(), new_val);
        *self = serde_json::from_value(v).with_context(|| crate::i18n::trf("invalid value for '{key}': {raw}", &[("key", &key), ("raw", &raw)]))?;
        Ok(())
    }
}

fn parse_value(raw: &str, existing: Option<&serde_json::Value>) -> serde_json::Value {
    use serde_json::Value;
    // Comma separated input into an array field, for CLI convenience.
    if let Some(Value::Array(_)) = existing {
        if !raw.trim_start().starts_with('[') {
            let items: Vec<Value> = raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(|s| Value::String(s.to_string())).collect();
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
    /// Title and explanation, in the user's language.
    pub title: String,
    pub description: String,
    pub risk: RiskLevel,
    /// Only shown in advanced mode.
    pub advanced: bool,
}

macro_rules! perm {
    ($key:expr, $cat:expr, $title:expr, $desc:expr, $risk:ident) => {
        PermissionInfo {
            key: $key,
            category: $cat,
            title: crate::i18n::tr($title),
            description: crate::i18n::tr($desc),
            risk: RiskLevel::$risk,
            advanced: false,
        }
    };
    ($key:expr, $cat:expr, $title:expr, $desc:expr, $risk:ident, advanced) => {
        PermissionInfo {
            key: $key,
            category: $cat,
            title: crate::i18n::tr($title),
            description: crate::i18n::tr($desc),
            risk: RiskLevel::$risk,
            advanced: true,
        }
    };
}

pub fn permission_catalog() -> Vec<PermissionInfo> {
    vec![
        perm!("filesystem.home", "Filesystem", "Full home access",
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
        perm!("filesystem.opened_files", "Filesystem", "Files you open with the app",
            "Files you open with this app (e.g. 'Open with' in the file manager). Read & write lets it save them; read-only lets it only view them.", Low),
        perm!("filesystem.custom_read", "Filesystem", "Extra read-only folders",
            "Additional folders the app can read but not change.", Medium, advanced),
        perm!("filesystem.custom_write", "Filesystem", "Extra read/write folders",
            "Additional folders the app can read and change.", High, advanced),
        perm!("network.mode", "Network", "Network access",
            "'Full network' shares your internet connection with the app. 'This computer only' blocks the internet and the local network, but keeps the services on this computer that you list reachable (e.g. a local AI model), and the app's own web page opens in your browser. 'No network' gives the app no connection at all.", High),
        perm!("network.host_ports", "Network", "Local services the app may reach",
            "With 'This computer only': ports on this computer the app may connect to, e.g. 11434 for Ollama or 1234 for LM Studio. Nothing else on your computer is reachable.", Medium),
        perm!("network.app_ports", "Network", "The app's own ports",
            "With 'This computer only': ports of the app (e.g. its web page) reachable from this computer. Empty = detected automatically, except privileged ports and well-known local services.", Low, advanced),
        perm!("devices.gpu", "Devices", "GPU acceleration",
            "Hardware-accelerated graphics through /dev/dri and host graphics drivers. Needed by most games, browsers and editors.", Medium),
        perm!("devices.webcam", "Devices", "Webcam",
            "Access to video capture devices. The app could record you.", High),
        perm!("devices.gamepads", "Devices", "Game controllers",
            "Gamepads and joysticks that are plugged in when the app starts. Keyboards and mice stay hidden.", Medium),
        perm!("devices.input", "Devices", "All input devices",
            "Raw access to every keyboard, mouse and controller in /dev/input. Can be used to read keystrokes. Only for tools that remap or configure input devices.", Dangerous, advanced),
        perm!("devices.usb", "Devices", "Raw USB",
            "Raw access to USB devices. Needed by flashing tools and some hardware utilities.", Dangerous, advanced),
        perm!("devices.bluetooth", "Devices", "Bluetooth",
            "Bluetooth needs the system D-Bus and cannot be isolated well.", Dangerous, advanced),
        perm!("audio.enabled", "Audio", "Sound",
            "Play and record audio (through PipeWire's PulseAudio service). Recording is possible once this is on.", Medium),
        perm!("audio.pipewire", "Audio", "Direct PipeWire access",
            "The full PipeWire connection. Besides sound it reaches cameras and screen-cast streams of other apps, bypassing the webcam and screen sharing settings. Only for apps that support nothing else.", High, advanced),
        perm!("audio.alsa_raw", "Audio", "Raw ALSA devices",
            "Direct sound card access. Only needed by apps that do not support PipeWire/PulseAudio.", High, advanced),
        perm!("display.wayland", "Display", "Wayland",
            "Show windows through the Wayland compositor. Wayland isolates apps from each other.", Low),
        perm!("display.wayland_privileged", "Display", "Privileged Wayland protocols",
            "Lets the app use Wayland functions the desktop normally hides from sandboxed apps: reading the clipboard in the background, capturing the screen, typing as a virtual keyboard. Only for clipboard managers, screenshot and remote-control tools.", High, advanced),
        perm!("display.x11", "Display", "X11 / XWayland",
            "X11 access allows the app to observe input and other windows. Wayland is safer, but some apps may require XWayland.", High),
        perm!("dbus.session.mode", "D-Bus", "Session bus",
            "'filtered' only allows portals, notifications and the tray. 'full' lets the app talk to every desktop service, which is high risk.", High),
        perm!("dbus.session.allow", "D-Bus", "Allowed session names",
            "Bus names reachable in filtered mode.", Medium, advanced),
        perm!("dbus.system.mode", "D-Bus", "System bus",
            "The system bus controls hardware, networking and power. Denied by default.", Dangerous, advanced),
        perm!("integrations.keyring", "Desktop integration", "Passwords & keyring",
            "Lets the app store logins in your keyring or KWallet. The keyring does not separate apps: the app can read every password stored there.", High),
        perm!("integrations.media_controls", "Desktop integration", "Media controls",
            "Media keys and 'now playing' in the panel, and keeping the screen awake during playback.", Low),
        perm!("integrations.screen_sharing", "Desktop integration", "Screen sharing",
            "Lets the app ask to share your screen or a window (video calls, streaming). Your desktop always asks which screen or window first.", Medium),
        perm!("integrations.file_manager", "Desktop integration", "Open the file manager",
            "Lets the app open your file manager and show a file it saved there (\"Show in folder\").", Low),
        perm!("integrations.input_method", "Desktop integration", "Input method",
            "Typing through Fcitx5 or IBus (their sandbox frontends), e.g. for Chinese, Japanese or Korean, and emoji pickers.", Low),
        perm!("sockets.ssh_agent", "Sockets", "SSH agent",
            "Lets the app use keys loaded in your SSH agent.", High, advanced),
        perm!("sockets.cups", "Sockets", "Printing",
            "Access to the CUPS printing service.", Low, advanced),
        perm!("sockets.custom", "Sockets", "Extra sockets",
            "Paths of other service sockets the app may connect to, e.g. a password manager's browser connection. The app can do whatever that service allows. Only real socket files are passed into the sandbox.", High, advanced),
        perm!("dbus.session.own", "D-Bus", "Names the app may own",
            "Extra bus names the app may register with the filtered session bus, for apps that do not start without their own name. Owning a well-known name lets the app pose as that service.", Medium, advanced),
        perm!("dbus.session.deny", "D-Bus", "Always blocked names",
            "Bus names that stay blocked even when a preset or another setting allows them.", Low, advanced),
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
        perm!("advanced.seccomp_baseline", "Advanced", "Baseline syscall filter",
            "Blocks kernel interfaces no desktop app needs (modules, BPF, perf, keyrings, io_uring, terminal injection). Turn off only if an app fails because of it.", Low, advanced),
        perm!("advanced.allow_userns", "Advanced", "Nested namespaces",
            "Lets Chromium/Electron apps start their own internal sandbox.", Low, advanced),
        perm!("advanced.host_themes", "Advanced", "Host theme settings",
            "Read-only access to GTK/Qt/KDE theme configuration so apps match your desktop.", Low, advanced),
        perm!("advanced.writable_appdir", "Advanced", "Writable app folder",
            "For portable apps that save settings next to themselves. Changes go to a separate layer; the extracted app stays untouched.", Low, advanced),
        perm!("advanced.system_libraries", "Advanced", "System copies of libraries",
            "Replaces these bundled libraries with your system's copies, read-only. For apps that bundle a library too old for your system.", Low, advanced),
        perm!("advanced.extra_bwrap_args", "Advanced", "Raw Bubblewrap arguments",
            "Arguments passed verbatim to Bubblewrap. Can weaken the sandbox.", High, advanced),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An app may not own a bus name of a desktop service or of a service that starts on demand; its own application names stay allowed.
    #[test]
    fn own_names_that_are_refused() {
        let activatable: std::collections::BTreeSet<String> = ["org.kde.kwalletd6".to_string()].into();
        assert!(refuse_own_name("org.kde.kdenlive", &activatable).is_none());
        assert!(refuse_own_name("app.hiddify.com", &activatable).is_none());
        assert!(refuse_own_name("org.kde.kwalletd6", &activatable).unwrap().contains("starts on demand"));
        assert!(refuse_own_name("org.freedesktop.Notifications", &activatable).is_some());
        assert!(refuse_own_name("org.kde.KWin", &activatable).is_some());
        assert!(refuse_own_name("org.gnome.Shell", &activatable).is_some());
    }

    /// Folder access is read from both the old form (true/false) and the current form ("ro", "rw").
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

    /// Permissions can be read and set by key, and unknown keys or values are refused.
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

    /// A bus name the user blocks stays blocked even when a wildcard in the allowed list would match it.
    #[test]
    fn blocked_names_win_over_wildcards() {
        let mut p = PermissionSet::strict_gui();
        p.dbus.session.allow = vec!["org.kde.*".into(), "org.example.App".into()];
        p.dbus.session.deny = vec!["org.kde.KWin".into()];
        let b = p.effective_session_bus();
        assert!(!b.allow.iter().any(|a| a == "org.kde.*"), "wildcard dropped");
        assert!(b.allow.iter().any(|a| a == "org.example.App"));
        assert!(bus_pattern_matches("org.kde.*", "org.kde.KWin") && !bus_pattern_matches("org.kde.*", "org.kdex"));
    }

    /// Settings saved with options SAM no longer has still load, with the removed options mapped to their safe meaning.
    #[test]
    fn old_profiles_with_removed_options_still_load() {
        // "filtered" network (never enforced, meant no network) with its
        // host list, and a "filtered" system bus with name lists.
        let old = r#"{"network": {"mode": "filtered", "allowed_hosts": ["example.org"]},
            "dbus": {"system": {"mode": "filtered", "allow": ["org.freedesktop.NetworkManager"], "own": [], "deny": []}}}"#;
        let p: PermissionSet = serde_json::from_str(old).unwrap();
        assert_eq!(p.network.mode, NetworkMode::None);
        assert_eq!(p.dbus.system.mode, DbusMode::None);
        let full: PermissionSet = serde_json::from_str(r#"{"dbus": {"system": {"mode": "full"}}}"#).unwrap();
        assert_eq!(full.dbus.system.mode, DbusMode::Full);
    }

    /// Permissions saved as TOML load back unchanged.
    #[test]
    fn permissions_saved_as_toml_load_back_unchanged() {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.downloads = Access::Rw;
        let s = toml::to_string(&p).unwrap();
        let back: PermissionSet = toml::from_str(&s).unwrap();
        assert_eq!(p, back);
    }
}

#[cfg(test)]
mod rename_tests {
    /// Raw sandbox arguments saved under their old name still load.
    #[test]
    fn old_extra_backend_args_still_load() {
        let a: super::AdvancedPerms = serde_json::from_str(r#"{"extra_backend_args": ["--setenv", "A", "1"]}"#).unwrap();
        assert_eq!(a.extra_bwrap_args, vec!["--setenv", "A", "1"]);
    }

    /// Only plain shared-library file names are accepted as system
    /// libraries: no folders, no `..`, nothing that is not a library.
    #[test]
    fn only_plain_library_names_are_accepted() {
        for ok in ["libsystemd.so.0", "libstdc++.so.6", "libfoo.so", "libgtk-4.so.1.1600.1", "libz_x.so.1"] {
            assert!(super::is_library_name(ok), "{ok}");
        }
        for bad in ["../libc.so.6", "/usr/lib/libc.so.6", "libc.so.6/..", "libc", "foo.so.1", "lib.so.1", "libc.so.x", "libc.so.6.", "libc.sox"] {
            assert!(!super::is_library_name(bad), "{bad}");
        }
    }
}
