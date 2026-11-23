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
    if p.sockets.ssh_agent {
        w.push(
            Warning::warn(
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
    }

    /// SAM's strictest window profile produces no danger warning.
    #[test]
    fn strict_has_no_danger() {
        let w = evaluate(&PermissionSet::strict_gui(), &WarningContext::all_enabled());
        assert!(w.iter().all(|w| w.severity != Severity::Danger));
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
