//! Warning generation.

use serde::{Deserialize, Serialize};

use crate::host::HostInfo;
use crate::permissions::*;
use crate::risk::is_dangerous_grant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Danger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    /// Stable machine-readable code, e.g. `x11-enabled`.
    pub code: String,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    /// Permission key this warning refers to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl Warning {
    /// Title and message are shown in the user's language: a literal is
    /// looked up here; a message built from parts comes translated already
    /// (`trf`), and looking it up again leaves it as it is.
    pub fn new(code: &str, severity: Severity, title: &str, message: impl Into<String>) -> Self {
        Warning {
            code: code.into(),
            severity,
            title: crate::i18n::tr(title),
            message: crate::i18n::tr(&message.into()),
            key: None,
        }
    }
    pub fn with_key(mut self, key: &str) -> Self {
        self.key = Some(key.into());
        self
    }
    pub fn info(code: &str, title: &str, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Info, title, message)
    }
    pub fn warn(code: &str, title: &str, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Warning, title, message)
    }
    pub fn danger(code: &str, title: &str, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Danger, title, message)
    }
}

/// Inputs that refine warnings beyond the permission set itself.
#[derive(Debug, Clone, Default)]
pub struct WarningContext<'a> {
    /// Whether the app appears to need network (from its category/libraries).
    pub app_needs_network: Option<bool>,
    pub host: Option<&'a HostInfo>,
    pub warn_x11: bool,
    pub warn_full_home: bool,
    /// The app runs in a terminal (`Terminal=true`).
    pub terminal_program: bool,
    /// Where this SAM keeps its own folders (`Paths::sam_dirs`), so the
    /// app page decides about an extra folder in SAM's folders as the
    /// sandbox does.
    pub sam_dirs: &'a [std::path::PathBuf],
}

impl WarningContext<'_> {
    pub fn all_enabled() -> Self {
        WarningContext {
            warn_x11: true,
            warn_full_home: true,
            ..Default::default()
        }
    }
}

/// What a terminal program can and cannot do in SAM's sandbox.
pub const TERMINAL_PROGRAM: &str = "It runs in a terminal window and sees everything you type there while it runs. \
SAM gives it a terminal of its own: it cannot type commands into your shell, read or change the clipboard through the terminal, or send desktop notifications. \
Besides the folders allowed below, it sees its private home and the files and folders you name when you start it (for example: hx notes.txt). \
Not covered: output that misleads you (a fake prompt, a link whose text hides where it goes) and security bugs in your terminal program.";

/// Extra writable folders that SAM shows read-only because they are a
/// start place or lie inside one (`~/.config/fish/conf.d`), or does not
/// show at all because they lie inside SAM's own folders: the window and
/// `sam-jail info` say so before the start, with the words of the launch
/// note (owner decision 9 of 2026-11-23). The rating stays as it is: the
/// grant still names a sensitive place. Also the whole home, granted
/// read and write, where a protected place leads to it and the sandbox
/// shows it read-only (independent review of decision 9).
fn read_only_grants(p: &PermissionSet, ctx: &WarningContext) -> Vec<Warning> {
    let fallback;
    let host = match ctx.host {
        Some(h) => h,
        None => {
            fallback = HostInfo {
                home: crate::util::home_dir(),
                ..Default::default()
            };
            &fallback
        }
    };
    let home = host.home.clone();
    // SAM's own folders as the sandbox counts them in this start: where
    // this SAM keeps its own and the folders named like them that count
    // for what the start shows. Decided by name alone, the page said
    // "Shown read-only" for a grant in this SAM's own `~/.local/share/sam`
    // kept as a link, which the sandbox leaves out (independent review of
    // decision 9). A start from the window or the menu has no extra binds
    // of SAM's (only a diagnostic run adds one), so this is the list the
    // sandbox takes.
    let sams =
        crate::places::sams_folders(&home, ctx.sam_dirs, &crate::places::shown_folders(p, host));
    let mut out = Vec::new();
    // The whole home read and write, while a protected place the sandbox
    // does not hide really is the home (`~/.config/sam` planted as a link
    // to it): the sandbox locks that place where the app reaches it, which
    // is the whole home. The answer the sandbox's note and its check take.
    if p.filesystem.home && p.filesystem.home_access == Access::Rw {
        if let Some(place) = crate::places::protected_place_at_home(&home, &sams) {
            out.push(
                Warning::warn(
                    "home-read-only",
                    "Shown read-only",
                    crate::places::home_read_only_note(&place),
                )
                .with_key("filesystem.home"),
            );
        }
    }
    out.extend(p.filesystem.custom_write.iter().filter_map(|c| {
        let grant = match c.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None if c == "~" => home.clone(),
            None => crate::util::expand_home(c),
        };
        let bound = crate::places::resolve(&grant);
        let found = crate::places::start_place_of_bound_write_grant(&grant, &bound, &home);
        // In SAM's own folders also outside any start place
        // (`~/Games/sam/saves`, where SAM keeps its data): not shown, as
        // the sandbox leaves it out. Asked only for a folder in a start
        // place, the page said nothing about it (independent review of
        // decision 9).
        let w = if crate::places::write_grant_in_sams_folders(&bound, found.as_ref(), &sams, &home)
        {
            Warning::warn(
                "start-place-read-only",
                "Not shown",
                crate::places::inside_sams_folders_note(c),
            )
        } else {
            Warning::warn(
                "start-place-read-only",
                "Shown read-only",
                crate::places::start_place_note(c, &found?),
            )
        };
        Some(w.with_key("filesystem.custom_write"))
    }));
    out
}

/// Granted user folders (Documents, Downloads, …) that the sandbox does
/// not show although the person set them: one set to `/tmp` or a folder in
/// it where programs outside the sandbox listen, and one reached through a
/// link in a folder the app can change. The window and `sam-jail info` say
/// so before the start, with the words of the launch note, in the order
/// the sandbox decides them. Told only in the launch log, a Downloads set
/// to `/tmp` (so downloads clear themselves) looked as before, while what
/// the app saved there was gone when it quit (review of finding R63).
fn refused_user_folders(p: &PermissionSet, ctx: &WarningContext) -> Vec<Warning> {
    let Some(host) = ctx.host else {
        return Vec::new();
    };
    XDG_DIR_KEYS
        .iter()
        .filter(|key| p.filesystem.xdg_access(key).is_granted())
        .filter_map(|key| {
            let dir = host.xdg_dir(key)?;
            let note = if let Some(link) =
                crate::places::user_folder_link_the_app_can_change(p, host, dir)
            {
                crate::places::user_folder_link_note(key, dir, &link)
            } else if crate::risk::shows_host_sockets(
                &crate::places::resolve(dir).to_string_lossy(),
            ) {
                crate::places::user_folder_sockets_note(key, dir)
            } else {
                return None;
            };
            Some(
                Warning::warn("user-folder-not-shown", "Not shown", note)
                    .with_key(&format!("filesystem.{key}")),
            )
        })
        .collect()
}

/// Granted user folders set to one place at different access (Music read
/// and write, Pictures read-only, both `~/Media`): the stricter setting
/// wins, so the app sees the place read-only
/// ([`crate::places::user_folder_access`], owner decision of 2026-11-27).
/// The window and `sam-jail info` name the folders and the rule before
/// the start, with the words of the launch note, at the first of them set
/// to read and write, the one that does not get what its switch says.
fn user_folders_at_one_place(p: &PermissionSet, ctx: &WarningContext) -> Vec<Warning> {
    let Some(host) = ctx.host else {
        return Vec::new();
    };
    crate::places::user_folders_at_one_place(p, host)
        .into_iter()
        .map(|(place, keys)| {
            let note = crate::places::user_folders_at_one_place_note(&keys, &place);
            let w = Warning::warn("user-folders-one-place", "Shown read-only", note);
            match keys
                .iter()
                .find(|k| p.filesystem.xdg_access(k) == Access::Rw)
            {
                Some(k) => w.with_key(&format!("filesystem.{k}")),
                None => w,
            }
        })
        .collect()
}

pub fn evaluate(p: &PermissionSet, ctx: &WarningContext) -> Vec<Warning> {
    let mut w = Vec::new();
    let ignored = crate::permissions::blocked_wildcards(&p.dbus.session);
    if !ignored.is_empty() && p.dbus.session.mode == DbusMode::Filtered {
        w.push(
            Warning::warn(
                "dbus-wildcard-ignored",
                "D-Bus wildcard not used",
                crate::i18n::trf(
                    "{names} would also reach a name you blocked, and the D-Bus filter cannot make exceptions, so SAM does not allow it. List the services you need one by one.",
                    &[("names", &ignored.join(", "))],
                ),
            )
            .with_key("dbus.session.allow"),
        );
    }

    if p.display.x11 && ctx.warn_x11 {
        w.push(
            Warning::warn(
                "x11-enabled",
                "X11 access",
                "X11 access allows the app to observe input and other windows. Wayland is safer, but some apps may require XWayland.",
            )
            .with_key("display.x11"),
        );
    }
    if ctx.terminal_program {
        w.push(Warning::warn(
            "terminal-program",
            "Terminal program",
            TERMINAL_PROGRAM,
        ));
    } else if !p.display.x11 && !p.display.wayland {
        w.push(Warning::info(
            "no-display",
            "No display access",
            "The app cannot open windows. This is only correct for command-line tools.",
        ));
    }
    if p.filesystem.home && ctx.warn_full_home {
        w.push(
            Warning::danger(
                "full-home",
                "Full home access",
                "The app can read and write every file in your home folder, including other apps' settings and files that programs outside the sandbox read, so it could make them run its code later. SAM protects the usual places (shell startup, autostart, menu entries), not every one. Only for apps you trust.",
            )
            .with_key("filesystem.home"),
        );
    }
    // Its own warning: switching off the full-home warning silenced this
    // one too (audit U-M10).
    if p.filesystem.home && (p.filesystem.ssh || p.filesystem.gnupg || p.filesystem.hidden_files) {
        w.push(Warning::danger(
            "secrets-exposed",
            "Private keys exposed",
            "SSH keys, GnuPG keys or other credential stores are visible to the app.",
        ));
    }
    w.extend(read_only_grants(p, ctx));
    w.extend(refused_user_folders(p, ctx));
    w.extend(user_folders_at_one_place(p, ctx));
    for path in p
        .filesystem
        .custom_write
        .iter()
        .chain(p.filesystem.custom_read.iter())
    {
        if crate::risk::shows_host_sockets(path) {
            w.push(
                Warning::danger(
                    "socket-folder",
                    "Connections to other programs exposed",
                    crate::i18n::trf("'{path}' holds connections to programs outside the sandbox (terminal sessions, SSH connections, the X server). The app can use them to run commands outside the sandbox, even with read-only access.", &[("path", &path)]),
                )
                .with_key("filesystem.custom_write"),
            );
        } else if is_dangerous_grant(path) {
            w.push(
                Warning::danger(
                    "sensitive-path",
                    "Sensitive path exposed",
                    crate::i18n::trf("'{path}' contains system or credential data. Exposing it weakens the sandbox significantly.", &[("path", &path)]),
                )
                .with_key("filesystem.custom_write"),
            );
        }
    }
    if p.network.mode == NetworkMode::Full && ctx.app_needs_network == Some(false) {
        w.push(
            Warning::warn(
                "network-unneeded",
                "Network may not be needed",
                "This app does not appear to need the network. Consider setting network access to 'none'.",
            )
            .with_key("network.mode"),
        );
    }
    if p.network.mode == NetworkMode::None && ctx.app_needs_network == Some(true) {
        w.push(
            Warning::info(
                "network-needed",
                "Network is off",
                "This app looks like it uses the network. Some features may not work until network access is enabled.",
            )
            .with_key("network.mode"),
        );
    }
    match p.dbus.system.mode {
        DbusMode::None => {}
        _ => w.push(
            Warning::danger(
                "system-dbus",
                "System D-Bus requested",
                "The system bus controls hardware, networking, power and package management. Grant only to apps you trust.",
            )
            .with_key("dbus.system.mode"),
        ),
    }
    // Dangerous, as the risk words rate it (audit U-M10: a plain warning here).
    if p.dbus.session.mode == DbusMode::Full {
        w.push(
            Warning::danger(
                "session-dbus-full",
                "Full session D-Bus",
                "Unfiltered session bus access lets the app control other desktop applications and services, and can be used to escape the sandbox.",
            )
            .with_key("dbus.session.mode"),
        );
    }
    if p.dbus.session.mode == DbusMode::Filtered {
        for name in &p.dbus.session.allow {
            if let Some(why) = crate::permissions::dangerous_bus_name(name) {
                w.push(
                    Warning::danger(
                        "dbus-dangerous-name",
                        "Dangerous D-Bus access",
                        crate::i18n::trf("Allowed session service: {why}. This can let the app escape the sandbox.", &[("why", &why)]),
                    )
                    .with_key("dbus.session.allow"),
                );
            }
        }
        if let Some(host) = ctx.host {
            if host.tools.xdg_dbus_proxy.is_none() {
                w.push(Warning::info(
                    "dbus-proxy-missing",
                    "D-Bus filtering unavailable",
                    "xdg-dbus-proxy is not installed, so the filtered session bus is disabled. Install xdg-dbus-proxy.",
                ));
            }
        }
    }
    if p.devices.input || p.devices.usb || p.audio.alsa_raw {
        w.push(Warning::danger(
            "raw-devices",
            "Raw device access",
            "Raw input, USB or sound devices are exposed. Input devices can be used to log keystrokes.",
        ));
    }
    // Grants the risk words rate "Think twice" or higher had no warning at
    // all (audit U-M10).
    if p.integrations.keyring {
        w.push(
            Warning::warn(
                "keyring",
                "Passwords & keyring",
                "The app can read every password and secret stored in your keyring, also those of other apps.",
            )
            .with_key("integrations.keyring"),
        );
    }
    if p.devices.webcam {
        w.push(
            Warning::warn(
                "webcam",
                "Webcam",
                "The app can switch on your camera and record what it sees.",
            )
            .with_key("devices.webcam"),
        );
    }
    // Dangerous, as the risk words rate it (owner decision 11 of
    // 2026-11-23).
    if p.sockets.ssh_agent {
        w.push(
            Warning::danger(
                "ssh-agent",
                "SSH agent",
                "While it runs, the app can use your SSH keys through the agent to log in to other computers as you.",
            )
            .with_key("sockets.ssh_agent"),
        );
    }
    if p.display.wayland && p.display.wayland_privileged {
        w.push(
            Warning::warn(
                "wayland-privileged",
                "Privileged Wayland protocols",
                "The app can use desktop functions meant for trusted tools, such as capturing the screen, reading the clipboard history or typing into other windows.",
            )
            .with_key("display.wayland_privileged"),
        );
    }
    if !p.advanced.seccomp_baseline {
        w.push(
            Warning::warn(
                "seccomp-off",
                "Syscall filter off",
                "The kernel functions SAM normally blocks are within the app's reach, so a flaw in the kernel is easier to use from inside the sandbox.",
            )
            .with_key("advanced.seccomp_baseline"),
        );
    }
    if p.advanced.landlock == Some(false) {
        w.push(
            Warning::warn(
                "landlock-off",
                "Landlock off",
                "The second barrier around your files (Landlock) is off; only the sandbox's own view of the files protects them.",
            )
            .with_key("advanced.landlock"),
        );
    }
    if p.advanced.allow_userns {
        w.push(
            Warning::info(
                "nested-namespaces",
                "Nested namespaces",
                "The app may build sandboxes of its own, which brings more of the kernel within its reach. Browsers built on Chromium need this for their own sandbox.",
            )
            .with_key("advanced.allow_userns"),
        );
    }
    if p.devices.bluetooth {
        w.push(
            Warning::warn(
                "bluetooth",
                "Bluetooth",
                "Bluetooth requires system D-Bus access (BlueZ), which SAM cannot filter. The toggle is ignored unless the system bus is granted.",
            )
            .with_key("devices.bluetooth"),
        );
    }
    if !p.advanced.extra_bwrap_args.is_empty() {
        w.push(Warning::warn(
            "raw-backend-args",
            "Raw backend arguments",
            "Custom backend arguments are passed through unchecked and may weaken the sandbox.",
        ));
    }
    if p.advanced.seccomp_strict {
        w.push(Warning::info(
            "seccomp-experimental",
            "Experimental seccomp filter",
            "Strict syscall filtering is experimental and can break apps (for example, Electron apps that need nested namespaces).",
        ));
    }

    if let Some(host) = ctx.host {
        if !host.userns.usable() {
            w.push(Warning::danger(
                "userns-unavailable",
                "User namespaces unavailable",
                host.userns.explain(),
            ));
        }
        if p.display.wayland && host.sockets.wayland.is_none() && !p.display.x11 {
            w.push(Warning::warn(
                "wayland-missing",
                "Wayland socket not available",
                "The Wayland socket is not available. Enable X11 or log in to a Wayland session.",
            ));
        }
        if p.display.x11 && host.sockets.x11.is_none() && host.sockets.wayland.is_none() {
            w.push(Warning::warn(
                "x11-missing",
                "X11 display not available",
                "No X11 display was found ($DISPLAY is unset or its socket is missing).",
            ));
        }
        if p.audio.enabled && host.sockets.pulse.is_none() {
            w.push(Warning::warn(
                "audio-missing",
                "Sound server not found",
                if host.sockets.pipewire.is_some() {
                    crate::i18n::n_(
                        "PipeWire runs without its PulseAudio service (pipewire-pulse), which sandboxed apps use for sound. Install or start pipewire-pulse.",
                    )
                } else {
                    crate::i18n::n_("No PulseAudio or PipeWire sound server was found. Audio may not work.")
                },
            ));
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(w: &[Warning]) -> Vec<&str> {
        w.iter().map(|w| w.code.as_str()).collect()
    }

    /// Dangerous settings (X11, full home, system bus, network an app does not need) each produce a warning.
    #[test]
    fn each_dangerous_setting_produces_its_warning() {
        let mut p = PermissionSet::strict_gui();
        p.display.x11 = true;
        p.filesystem.home = true;
        p.network.mode = NetworkMode::Full;
        p.dbus.system.mode = DbusMode::Full;
        let mut ctx = WarningContext::all_enabled();
        ctx.app_needs_network = Some(false);
        let w = evaluate(&p, &ctx);
        let c = codes(&w);
        for code in [
            "x11-enabled",
            "full-home",
            "network-unneeded",
            "system-dbus",
        ] {
            assert!(c.contains(&code), "missing {code} in {c:?}");
        }
    }

    /// Regression (audit U-M10): grants the risk words rate "Think twice"
    /// had no warning at all, the private-keys warning was silenced by
    /// switching off the full-home warning, and the full session bus was a
    /// plain warning while the risk words call it Dangerous.
    #[test]
    fn every_grant_the_risk_words_question_is_warned_about() {
        let mut p = PermissionSet::strict_gui();
        p.integrations.keyring = true;
        p.devices.webcam = true;
        p.sockets.ssh_agent = true;
        p.display.wayland = true;
        p.display.wayland_privileged = true;
        p.advanced.seccomp_baseline = false;
        p.advanced.landlock = Some(false);
        p.advanced.allow_userns = true;
        let w = evaluate(&p, &WarningContext::default());
        let c = codes(&w);
        for code in [
            "keyring",
            "webcam",
            "ssh-agent",
            "wayland-privileged",
            "seccomp-off",
            "landlock-off",
            "nested-namespaces",
        ] {
            assert!(c.contains(&code), "missing {code} in {c:?}");
        }

        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.ssh = true;
        let quiet = WarningContext::default();
        assert!(!quiet.warn_full_home);
        let w = evaluate(&p, &quiet);
        let c = codes(&w);
        assert!(c.contains(&"secrets-exposed"), "{c:?}");
        assert!(!c.contains(&"full-home"), "that warning is switched off");

        let mut p = PermissionSet::strict_gui();
        p.dbus.session.mode = DbusMode::Full;
        let w = evaluate(&p, &quiet);
        let bus = w.iter().find(|w| w.code == "session-dbus-full").unwrap();
        assert_eq!(bus.severity, Severity::Danger);
        assert_eq!(
            crate::risk::assess(&p)
                .items
                .iter()
                .find(|i| i.key == "dbus.session.mode")
                .map(|i| i.level),
            Some(crate::risk::RiskLevel::Dangerous),
            "the same as the risk words"
        );

        // The SSH agent is Dangerous in both (owner decision 11 of
        // 2026-11-23).
        let mut p = PermissionSet::strict_gui();
        p.sockets.ssh_agent = true;
        let w = evaluate(&p, &quiet);
        let agent = w.iter().find(|w| w.code == "ssh-agent").unwrap();
        assert_eq!(agent.severity, Severity::Danger);
        assert_eq!(
            crate::risk::assess(&p).level,
            crate::risk::RiskLevel::Dangerous,
            "the same as the risk words"
        );
    }

    /// SAM's strictest window profile produces no danger warning.
    #[test]
    fn strict_has_no_danger() {
        let w = evaluate(&PermissionSet::strict_gui(), &WarningContext::all_enabled());
        assert!(w.iter().all(|w| w.severity != Severity::Danger));
    }

    /// A filtered session bus on a computer without xdg-dbus-proxy (where
    /// SAM then gives the app no session bus) says so; with the proxy
    /// installed, or without a filtered bus, it does not.
    #[test]
    fn a_missing_dbus_proxy_is_named_only_where_the_filter_needs_it() {
        let mut host = crate::sandbox::sample_context().host;
        let mut p = PermissionSet::strict_gui();
        p.dbus.session.mode = DbusMode::Filtered;
        let named = |p: &PermissionSet, h: &crate::host::HostInfo| {
            let ctx = WarningContext {
                host: Some(h),
                ..WarningContext::all_enabled()
            };
            codes(&evaluate(p, &ctx)).contains(&"dbus-proxy-missing")
        };
        assert!(!named(&p, &host), "installed");
        host.tools.xdg_dbus_proxy = None;
        assert!(named(&p, &host), "missing");
        p.dbus.session.mode = DbusMode::None;
        assert!(!named(&p, &host), "no filtered bus asked for");
    }

    fn find<'a>(w: &'a [Warning], code: &str) -> Option<&'a Warning> {
        w.iter().find(|w| w.code == code)
    }

    /// A host where everything works: sockets for Wayland, X11 and sound,
    /// usable user namespaces and xdg-dbus-proxy installed.
    fn working_host() -> HostInfo {
        let mut h = HostInfo::default();
        h.sockets.wayland = Some("/run/user/1000/wayland-0".into());
        h.sockets.x11 = Some("/tmp/.X11-unix/X0".into());
        h.sockets.pulse = Some("/run/user/1000/pulse/native".into());
        h.tools.xdg_dbus_proxy = Some(crate::host::Tool::default());
        h
    }

    /// With the whole home granted, each credential store on its own (SSH
    /// keys, GnuPG keys, the other hidden files) gives the danger warning
    /// that private keys are visible; with all three off there is none.
    #[test]
    fn each_credential_store_in_a_full_home_is_named_as_exposed_keys() {
        type Flag = fn(&mut PermissionSet);
        let cases: [(&str, Flag); 3] = [
            ("ssh", |p| p.filesystem.ssh = true),
            ("gnupg", |p| p.filesystem.gnupg = true),
            ("hidden_files", |p| p.filesystem.hidden_files = true),
        ];
        for (name, set) in cases {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            set(&mut p);
            let w = evaluate(&p, &WarningContext::all_enabled());
            let hit = find(&w, "secrets-exposed")
                .unwrap_or_else(|| panic!("{name} alone: no secrets-exposed in {:?}", codes(&w)));
            assert_eq!(hit.severity, Severity::Danger, "{name}");
        }
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        let w = evaluate(&p, &WarningContext::all_enabled());
        assert!(find(&w, "secrets-exposed").is_none(), "{:?}", codes(&w));
    }

    /// Only an unfiltered session bus is named as a way out of the sandbox;
    /// a filtered bus or none is not.
    #[test]
    fn only_the_full_session_bus_is_named_as_an_escape() {
        for (mode, expected) in [
            (DbusMode::Full, true),
            (DbusMode::Filtered, false),
            (DbusMode::None, false),
        ] {
            let mut p = PermissionSet::strict_gui();
            p.dbus.session.mode = mode;
            let w = evaluate(&p, &WarningContext::all_enabled());
            let hit = find(&w, "session-dbus-full");
            assert_eq!(hit.is_some(), expected, "{mode:?}: {:?}", codes(&w));
            if let Some(hit) = hit {
                assert_eq!(hit.key.as_deref(), Some("dbus.session.mode"));
            }
        }
    }

    /// On a filtered session bus, an allowed name that reaches outside the
    /// sandbox gives a danger warning, and a missing xdg-dbus-proxy is
    /// named. With the bus off, the same list says nothing: it is not used.
    #[test]
    fn dangerous_bus_names_and_a_missing_proxy_are_named_for_the_filtered_bus_only() {
        let no_proxy = HostInfo::default();
        for (mode, expected) in [(DbusMode::Filtered, true), (DbusMode::None, false)] {
            let mut p = PermissionSet::strict_gui();
            p.dbus.session.mode = mode;
            p.dbus.session.allow = vec!["org.freedesktop.portal.*".into()];
            let ctx = WarningContext {
                host: Some(&no_proxy),
                ..WarningContext::all_enabled()
            };
            let w = evaluate(&p, &ctx);
            let hit = find(&w, "dbus-dangerous-name");
            assert_eq!(hit.is_some(), expected, "{mode:?}: {:?}", codes(&w));
            if let Some(hit) = hit {
                assert_eq!(hit.severity, Severity::Danger);
            }
            assert_eq!(
                find(&w, "dbus-proxy-missing").is_some(),
                expected,
                "{mode:?}: {:?}",
                codes(&w)
            );
        }
    }

    /// A wildcard that also covers a blocked name is named only when the
    /// filtered bus would use it: not for a filter without such a wildcard,
    /// and not for a full or no session bus, where the lists do not apply.
    #[test]
    fn a_wildcard_over_a_blocked_name_is_named_for_the_filtered_bus_only() {
        let mut p = PermissionSet::strict_gui();
        p.dbus.session.mode = DbusMode::Filtered;
        p.dbus.session.allow = vec![];
        p.dbus.session.deny = vec![];
        let w = evaluate(&p, &WarningContext::all_enabled());
        assert!(
            find(&w, "dbus-wildcard-ignored").is_none(),
            "{:?}",
            codes(&w)
        );

        p.dbus.session.allow = vec!["org.example.*".into()];
        p.dbus.session.deny = vec!["org.example.Foo".into()];
        for (mode, expected) in [
            (DbusMode::Filtered, true),
            (DbusMode::Full, false),
            (DbusMode::None, false),
        ] {
            p.dbus.session.mode = mode;
            let w = evaluate(&p, &WarningContext::all_enabled());
            let hit = find(&w, "dbus-wildcard-ignored");
            assert_eq!(hit.is_some(), expected, "{mode:?}: {:?}", codes(&w));
            if let Some(hit) = hit {
                assert!(hit.message.contains("org.example.*"), "{}", hit.message);
            }
        }
    }

    /// Raw input devices (keystrokes), raw USB and raw sound devices each
    /// give the danger warning on their own; the strict profile none.
    #[test]
    fn each_raw_device_gives_the_raw_device_danger() {
        type Flag = fn(&mut PermissionSet);
        let cases: [(&str, Flag); 3] = [
            ("input", |p| p.devices.input = true),
            ("usb", |p| p.devices.usb = true),
            ("alsa_raw", |p| p.audio.alsa_raw = true),
        ];
        for (name, set) in cases {
            let mut p = PermissionSet::strict_gui();
            set(&mut p);
            let w = evaluate(&p, &WarningContext::all_enabled());
            let hit = find(&w, "raw-devices")
                .unwrap_or_else(|| panic!("{name} alone: no raw-devices in {:?}", codes(&w)));
            assert_eq!(hit.severity, Severity::Danger, "{name}");
        }
        let w = evaluate(&PermissionSet::strict_gui(), &WarningContext::all_enabled());
        assert!(find(&w, "raw-devices").is_none(), "{:?}", codes(&w));
    }

    /// Unchecked Bubblewrap arguments are named when there are some, and
    /// only then.
    #[test]
    fn raw_backend_arguments_are_named_when_there_are_some() {
        let mut p = PermissionSet::strict_gui();
        let w = evaluate(&p, &WarningContext::all_enabled());
        assert!(find(&w, "raw-backend-args").is_none(), "{:?}", codes(&w));
        p.advanced.extra_bwrap_args = vec!["--share-net".into()];
        let w = evaluate(&p, &WarningContext::all_enabled());
        assert!(find(&w, "raw-backend-args").is_some(), "{:?}", codes(&w));
    }

    /// "Cannot open windows" is said only with neither Wayland nor X11; a
    /// terminal program gets its own notice instead.
    #[test]
    fn no_display_is_named_only_without_any_display() {
        for (wayland, x11, expected) in [
            (true, false, false),
            (false, true, false),
            (true, true, false),
            (false, false, true),
        ] {
            let mut p = PermissionSet::strict_gui();
            p.display.wayland = wayland;
            p.display.x11 = x11;
            let w = evaluate(&p, &WarningContext::default());
            assert_eq!(
                find(&w, "no-display").is_some(),
                expected,
                "wayland={wayland} x11={x11}: {:?}",
                codes(&w)
            );
        }
        let mut p = PermissionSet::strict_gui();
        p.display.wayland = false;
        let ctx = WarningContext {
            terminal_program: true,
            ..Default::default()
        };
        let c = evaluate(&p, &ctx);
        assert!(find(&c, "terminal-program").is_some(), "{:?}", codes(&c));
        assert!(find(&c, "no-display").is_none(), "{:?}", codes(&c));
    }

    /// The network advice fits both the setting and what the app seems to
    /// need: "may not be needed" only for network on and not needed,
    /// "network is off" only for network off and needed.
    #[test]
    fn network_advice_fits_the_setting_and_the_apps_need() {
        for (mode, needs, unneeded, needed) in [
            (NetworkMode::Full, Some(false), true, false),
            (NetworkMode::Full, Some(true), false, false),
            (NetworkMode::Full, None, false, false),
            (NetworkMode::None, Some(true), false, true),
            (NetworkMode::None, Some(false), false, false),
            (NetworkMode::None, None, false, false),
        ] {
            let mut p = PermissionSet::strict_gui();
            p.network.mode = mode;
            let ctx = WarningContext {
                app_needs_network: needs,
                ..WarningContext::all_enabled()
            };
            let w = evaluate(&p, &ctx);
            assert_eq!(
                find(&w, "network-unneeded").is_some(),
                unneeded,
                "{mode:?} {needs:?}: {:?}",
                codes(&w)
            );
            assert_eq!(
                find(&w, "network-needed").is_some(),
                needed,
                "{mode:?} {needs:?}: {:?}",
                codes(&w)
            );
        }
    }

    /// Unusable user namespaces are a danger notice on such a computer
    /// only; setuid Bubblewrap makes them usable again.
    #[test]
    fn unusable_user_namespaces_are_named_only_where_they_are() {
        let mut host = working_host();
        let p = PermissionSet::strict_gui();
        let on = |h: &HostInfo| {
            let ctx = WarningContext {
                host: Some(h),
                ..WarningContext::all_enabled()
            };
            evaluate(&p, &ctx)
        };
        let w = on(&host);
        assert!(find(&w, "userns-unavailable").is_none(), "{:?}", codes(&w));

        host.userns.max_user_namespaces = Some(0);
        let w = on(&host);
        let hit = find(&w, "userns-unavailable").expect("max_user_namespaces = 0");
        assert_eq!(hit.severity, Severity::Danger);

        host.userns.max_user_namespaces = None;
        host.userns.unprivileged_clone = Some(false);
        host.userns.bwrap_setuid = true;
        let w = on(&host);
        assert!(find(&w, "userns-unavailable").is_none(), "{:?}", codes(&w));
    }

    /// A missing Wayland socket, X11 display or sound server is named only
    /// when the app uses it, the host lacks it and no fallback is there.
    #[test]
    fn missing_display_and_sound_are_named_only_when_the_app_would_miss_them() {
        struct Case {
            name: &'static str,
            wayland: bool,
            x11: bool,
            audio: bool,
            host_wayland: bool,
            host_x11: bool,
            host_pulse: bool,
            missing: &'static [&'static str],
        }
        let cases = [
            Case {
                name: "all there",
                wayland: true,
                x11: true,
                audio: true,
                host_wayland: true,
                host_x11: true,
                host_pulse: true,
                missing: &[],
            },
            Case {
                name: "wayland app, no wayland",
                wayland: true,
                x11: false,
                audio: false,
                host_wayland: false,
                host_x11: true,
                host_pulse: true,
                missing: &["wayland-missing"],
            },
            Case {
                name: "wayland app with x11 fallback, no wayland",
                wayland: true,
                x11: true,
                audio: false,
                host_wayland: false,
                host_x11: true,
                host_pulse: true,
                missing: &[],
            },
            Case {
                name: "x11 app, no display at all",
                wayland: false,
                x11: true,
                audio: false,
                host_wayland: false,
                host_x11: false,
                host_pulse: true,
                missing: &["x11-missing"],
            },
            Case {
                name: "x11 app, x11 there, no wayland",
                wayland: false,
                x11: true,
                audio: false,
                host_wayland: false,
                host_x11: true,
                host_pulse: true,
                missing: &[],
            },
            Case {
                name: "x11 app, xwayland through wayland",
                wayland: false,
                x11: true,
                audio: false,
                host_wayland: true,
                host_x11: false,
                host_pulse: true,
                missing: &[],
            },
            Case {
                name: "no display app, nothing on the host",
                wayland: false,
                x11: false,
                audio: false,
                host_wayland: false,
                host_x11: false,
                host_pulse: false,
                missing: &[],
            },
            Case {
                name: "sound app, no sound server",
                wayland: true,
                x11: false,
                audio: true,
                host_wayland: true,
                host_x11: false,
                host_pulse: false,
                missing: &["audio-missing"],
            },
        ];
        let all = ["wayland-missing", "x11-missing", "audio-missing"];
        for c in cases {
            let mut host = working_host();
            if !c.host_wayland {
                host.sockets.wayland = None;
            }
            if !c.host_x11 {
                host.sockets.x11 = None;
            }
            if !c.host_pulse {
                host.sockets.pulse = None;
            }
            let mut p = PermissionSet::strict_gui();
            p.display.wayland = c.wayland;
            p.display.x11 = c.x11;
            p.audio.enabled = c.audio;
            let ctx = WarningContext {
                host: Some(&host),
                ..WarningContext::all_enabled()
            };
            let w = evaluate(&p, &ctx);
            for code in all {
                assert_eq!(
                    find(&w, code).is_some(),
                    c.missing.contains(&code),
                    "{}: {code} in {:?}",
                    c.name,
                    codes(&w)
                );
            }
        }
    }

    /// Without pipewire-pulse the sound notice names it when PipeWire runs.
    #[test]
    fn missing_sound_names_pipewire_pulse_when_pipewire_runs() {
        let mut host = working_host();
        host.sockets.pulse = None;
        host.sockets.pipewire = Some("/run/user/1000/pipewire-0".into());
        let mut p = PermissionSet::strict_gui();
        p.audio.enabled = true;
        let ctx = WarningContext {
            host: Some(&host),
            ..WarningContext::all_enabled()
        };
        let w = evaluate(&p, &ctx);
        let hit = find(&w, "audio-missing").expect("audio-missing");
        assert!(hit.message.contains("pipewire-pulse"), "{}", hit.message);
    }

    /// An extra writable folder inside a start place gets a warning that
    /// SAM shows it read-only, named in the window and in `info` before the
    /// start; an ordinary extra folder does not (owner decision 9 of
    /// 2026-11-23).
    #[test]
    fn a_write_grant_inside_a_start_place_is_said_to_be_read_only() {
        let t = tempfile::tempdir().unwrap();
        let mut host = working_host();
        host.home = std::fs::canonicalize(t.path()).unwrap().join("u");
        for d in [".config/fish/conf.d", "work"] {
            std::fs::create_dir_all(host.home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(host.home.join(".config/fish"), host.home.join("fishlink"))
            .unwrap();
        let ctx = WarningContext {
            host: Some(&host),
            ..WarningContext::all_enabled()
        };
        for grant in ["~/.config/fish/conf.d", "~/fishlink/conf.d"] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.custom_write = vec![grant.into(), "~/work".into()];
            let w = evaluate(&p, &ctx);
            let hits: Vec<&Warning> = w
                .iter()
                .filter(|w| w.code == "start-place-read-only")
                .collect();
            assert_eq!(hits.len(), 1, "{grant}: {:?}", codes(&w));
            let hit = hits[0];
            assert_eq!(hit.key.as_deref(), Some("filesystem.custom_write"));
            assert_eq!(hit.severity, Severity::Warning);
            assert!(
                hit.message.contains(grant) && hit.message.contains("~/.config/fish"),
                "{}",
                hit.message
            );
            assert!(hit.message.contains("read-only"), "{}", hit.message);
        }
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec!["~/work".into()];
        assert!(!codes(&evaluate(&p, &ctx)).contains(&"start-place-read-only"));
        // In SAM's own folders: said to be not shown, not read-only.
        p.filesystem.custom_write = vec!["~/.config/sam/apps".into()];
        let w = evaluate(&p, &ctx);
        let hit = find(&w, "start-place-read-only").expect("named");
        assert!(hit.message.contains("SAM's own folders"), "{}", hit.message);
        assert!(!hit.message.contains("read-only"), "{}", hit.message);
    }

    /// The app page decides about an extra writable folder in a place named
    /// like SAM's folders as the sandbox does, with where this SAM keeps
    /// its own (independent review of decision 9): this SAM's own
    /// `~/.local/share/sam` kept as a link to `~/Sync/sam` is not shown,
    /// through the link or by its real place, where the page said "Shown
    /// read-only" while the sandbox left the folder out; a folder by that
    /// name that SAM only keeps read-only (`~/.config/sam` planted as a link
    /// to the home) is shown read-only, and so is the same link's folder
    /// for a SAM that keeps its own elsewhere and a start that shows only a
    /// folder inside it.
    #[test]
    fn the_app_page_says_what_the_sandbox_does_with_a_grant_in_sams_folders() {
        let t = tempfile::tempdir().unwrap();
        let mut host = working_host();
        host.home = std::fs::canonicalize(t.path()).unwrap().join("u");
        let home = host.home.clone();
        for d in ["Sync/sam/apps", ".local/share", ".config", "work"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(home.join("Sync/sam"), home.join(".local/share/sam")).unwrap();
        std::os::unix::fs::symlink(&home, home.join(".config/sam")).unwrap();
        let at = |rel: &str| home.join(rel).to_string_lossy().into_owned();
        let said = |own: &[std::path::PathBuf], grant: &str| {
            let ctx = WarningContext {
                host: Some(&host),
                sam_dirs: own,
                ..WarningContext::all_enabled()
            };
            let mut p = PermissionSet::strict_gui();
            p.filesystem.custom_write = vec![grant.to_string()];
            let w = evaluate(&p, &ctx);
            let hit = find(&w, "start-place-read-only")
                .unwrap_or_else(|| panic!("{grant}: {:?}", codes(&w)));
            hit.message.clone()
        };
        let own = [t.path().join("elsewhere"), home.join(".local/share/sam")];
        for grant in [at(".local/share/sam/apps"), at("Sync/sam/apps")] {
            let m = said(&own, &grant);
            assert!(m.contains("SAM's own folders"), "{grant}: {m}");
            assert!(!m.contains("read-only"), "{grant}: {m}");
        }
        let m = said(&own, &at("work"));
        assert!(
            m.contains("read-only") && m.contains("~/.config/sam"),
            "{m}"
        );
        // The words say where that place leads, not that `~/work` lies
        // "inside ~/.config/sam" (independent review of decision 9).
        assert!(
            m.contains("~/.config/sam, a folder SAM protects, is not a real folder but a shortcut to your home folder or a folder above it"),
            "{m}"
        );
        assert!(!m.contains("is inside"), "{m}");
        let elsewhere = [t.path().join("elsewhere")];
        let m = said(&elsewhere, &at(".local/share/sam/apps"));
        assert!(m.contains("read-only"), "{m}");
        // The whole home read and write: the sandbox locks the link where
        // the app reaches it, the whole home, and the page says so; not
        // with the home read-only, which needs no word.
        let home_warning = |access: Access| {
            let ctx = WarningContext {
                host: Some(&host),
                sam_dirs: &elsewhere,
                ..WarningContext::all_enabled()
            };
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            p.filesystem.home_access = access;
            find(&evaluate(&p, &ctx), "home-read-only").cloned()
        };
        let hit = home_warning(Access::Rw).expect("the home is said to be read-only");
        assert_eq!(hit.key.as_deref(), Some("filesystem.home"));
        assert!(
            hit.message
                .contains("~/.config/sam, a folder SAM protects, is not a real folder but a shortcut to your whole home folder")
                && hit.message.contains("delete the shortcut ~/.config/sam")
                && hit.message.contains("read-only"),
            "{}",
            hit.message
        );
        assert!(home_warning(Access::Ro).is_none());
        std::fs::remove_file(home.join(".config/sam")).unwrap();
        assert!(home_warning(Access::Rw).is_none(), "no link, no word");
    }

    /// An extra writable folder inside SAM's own folders outside any start
    /// place (`~/Games/sam/saves`, where SAM keeps its data, also reached
    /// through a link, or SAM's folders outside the home) is said to be
    /// not shown, as the sandbox leaves it out; a folder next to SAM's gets
    /// no word. Before, the page asked only about a folder in a start
    /// place and said nothing about it (independent review of
    /// decision 9).
    #[test]
    fn a_write_grant_in_sams_folders_outside_start_places_is_said_not_shown() {
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let mut host = working_host();
        host.home = base.join("u");
        let home = host.home.clone();
        for d in ["Games/sam/saves", "Games/other"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::create_dir_all(base.join("data/sam/shared")).unwrap();
        std::os::unix::fs::symlink(home.join("Games"), home.join("g")).unwrap();
        let own = [home.join("Games/sam"), base.join("data/sam")];
        let ctx = WarningContext {
            host: Some(&host),
            sam_dirs: &own,
            ..WarningContext::all_enabled()
        };
        let at = |p: std::path::PathBuf| p.to_string_lossy().into_owned();
        for grant in [
            "~/Games/sam/saves".to_string(),
            at(home.join("g/sam/saves")),
            at(base.join("data/sam/shared")),
        ] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.custom_write = vec![grant.clone()];
            let w = evaluate(&p, &ctx);
            let hit = find(&w, "start-place-read-only")
                .unwrap_or_else(|| panic!("{grant}: {:?}", codes(&w)));
            assert_eq!(hit.title, "Not shown", "{grant}");
            assert_eq!(hit.key.as_deref(), Some("filesystem.custom_write"));
            assert!(
                hit.message.contains(&grant) && hit.message.contains("SAM's own folders"),
                "{grant}: {}",
                hit.message
            );
            assert!(!hit.message.contains("read-only"), "{}", hit.message);
        }
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec!["~/Games/other".into()];
        assert!(!codes(&evaluate(&p, &ctx)).contains(&"start-place-read-only"));
    }

    /// A granted user folder the sandbox does not show is named on the app
    /// page and in `sam-jail info` before the start, with the launch note's
    /// words and the way out: Downloads set to `/tmp` (so downloads clear
    /// themselves), where programs outside the sandbox listen, and one
    /// reached through a link in the writable home. Said only in the launch
    /// log, what the app saved to such a Downloads was gone when it quit.
    /// An ordinary folder, or one not granted, gives no such warning.
    #[test]
    fn a_user_folder_the_sandbox_does_not_show_is_named_before_the_start() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("home");
        let elsewhere = home.parent().unwrap().join("elsewhere");
        std::fs::create_dir_all(home.join("Music")).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join("Downloads")).unwrap();
        let warned = |p: &PermissionSet, downloads: &std::path::Path| {
            let mut host = HostInfo {
                home: home.clone(),
                ..Default::default()
            };
            host.xdg_dirs
                .insert("downloads".into(), downloads.to_path_buf());
            let ctx = WarningContext {
                host: Some(&host),
                ..Default::default()
            };
            evaluate(p, &ctx)
                .into_iter()
                .find(|w| w.code == "user-folder-not-shown")
        };
        let mut p = PermissionSet::strict_gui();
        p.filesystem.downloads = Access::Rw;
        let hit = warned(&p, std::path::Path::new("/tmp")).expect("Downloads at /tmp is named");
        assert_eq!(hit.key.as_deref(), Some("filesystem.downloads"));
        assert!(
            hit.message.contains("programs outside the sandbox listen")
                && hit.message.contains("/tmp/downloads"),
            "{}",
            hit.message
        );
        assert!(warned(&p, &home.join("Music")).is_none());
        let mut none = p.clone();
        none.filesystem.downloads = Access::None;
        assert!(warned(&none, std::path::Path::new("/tmp")).is_none());
        // A link in the writable whole home.
        let mut full = p.clone();
        full.filesystem.home = true;
        full.filesystem.home_access = Access::Rw;
        let hit = warned(&full, &home.join("Downloads")).expect("a planted link is named");
        assert!(
            hit.message.contains("the app may have put it there"),
            "{}",
            hit.message
        );
        assert!(
            warned(&p, &home.join("Downloads")).is_none(),
            "without the home"
        );
    }

    /// Two granted user folders set to one place at different access
    /// (Music read and write, Pictures read-only, both `~/Media`) are named
    /// on the app page and in `sam-jail info` before the start, with the
    /// place, the rule (the stricter setting wins, so the app sees it
    /// read-only) and the way out, at the switch of the writable one,
    /// whatever their order. Folders at one place at one access, at
    /// places of their own, or not granted give no such warning.
    #[test]
    fn user_folders_at_one_place_with_different_access_are_named() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("home");
        let media = home.join("Media");
        std::fs::create_dir_all(&media).unwrap();
        std::fs::create_dir_all(home.join("Pictures")).unwrap();
        let mut host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        host.xdg_dirs.insert("music".into(), media.clone());
        host.xdg_dirs.insert("videos".into(), media.clone());
        host.xdg_dirs
            .insert("pictures".into(), home.join("Pictures"));
        let warned = |p: &PermissionSet, host: &HostInfo| {
            let ctx = WarningContext {
                host: Some(host),
                ..Default::default()
            };
            evaluate(p, &ctx)
                .into_iter()
                .filter(|w| w.code == "user-folders-one-place")
                .collect::<Vec<_>>()
        };
        for (music, videos, key) in [
            (Access::Rw, Access::Ro, "filesystem.music"),
            (Access::Ro, Access::Rw, "filesystem.videos"),
        ] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.music = music;
            p.filesystem.videos = videos;
            let hits = warned(&p, &host);
            assert_eq!(hits.len(), 1, "{music:?} {videos:?}: {hits:?}");
            let hit = &hits[0];
            assert_eq!(hit.key.as_deref(), Some(key));
            assert!(
                hit.message.contains("music, videos")
                    && hit.message.contains("/Media")
                    && hit.message.contains("The stricter setting wins")
                    && hit.message.contains("read-only")
                    && hit.message.contains("places of their own"),
                "{}",
                hit.message
            );
        }
        let mut p = PermissionSet::strict_gui();
        p.filesystem.music = Access::Rw;
        p.filesystem.videos = Access::Rw;
        p.filesystem.pictures = Access::Ro;
        assert!(warned(&p, &host).is_empty(), "one access at one place");
        let mut apart = host.clone();
        apart
            .xdg_dirs
            .insert("videos".into(), home.join("Pictures"));
        p.filesystem.pictures = Access::None;
        p.filesystem.videos = Access::Ro;
        assert!(warned(&p, &apart).is_empty(), "places of their own");
        p.filesystem.music = Access::None;
        assert!(warned(&p, &host).is_empty(), "one not granted");
    }

    /// The X11 warning disappears when the user turns it off in the preferences.
    #[test]
    fn x11_warning_can_be_disabled() {
        let mut p = PermissionSet::strict_gui();
        p.display.x11 = true;
        let w = evaluate(&p, &WarningContext::default());
        assert!(!codes(&w).contains(&"x11-enabled"));
    }
}
