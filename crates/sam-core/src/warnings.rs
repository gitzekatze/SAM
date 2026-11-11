//! Warning generation.

use serde::{Deserialize, Serialize};

use crate::host::HostInfo;
use crate::permissions::*;
use crate::risk::is_sensitive_path;

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
    pub fn new(code: &str, severity: Severity, title: &str, message: impl Into<String>) -> Self {
        Warning {
            code: code.into(),
            severity,
            title: title.into(),
            message: message.into(),
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

pub fn evaluate(p: &PermissionSet, ctx: &WarningContext) -> Vec<Warning> {
    let mut w = Vec::new();
    let ignored = crate::permissions::blocked_wildcards(&p.dbus.session);
    if !ignored.is_empty() && p.dbus.session.mode == DbusMode::Filtered {
        w.push(
            Warning::warn(
                "dbus-wildcard-ignored",
                "D-Bus wildcard not used",
                format!(
                    "{} would also reach a name you blocked, and the D-Bus filter cannot make exceptions, so SAM does not allow it. List the services you need one by one.",
                    ignored.join(", ")
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
    if !p.display.x11 && !p.display.wayland {
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
                "The app can read and write every file in your home directory, including other apps' settings. This is high risk and usually not required.",
            )
            .with_key("filesystem.home"),
        );
        if p.filesystem.ssh || p.filesystem.gnupg || p.filesystem.hidden_files {
            w.push(Warning::danger(
                "secrets-exposed",
                "Private keys exposed",
                "SSH keys, GnuPG keys or other credential stores are visible to the app.",
            ));
        }
    }
    for path in p.filesystem.custom_write.iter().chain(p.filesystem.custom_read.iter()) {
        if is_sensitive_path(path) {
            w.push(
                Warning::danger(
                    "sensitive-path",
                    "Sensitive path exposed",
                    format!("'{path}' contains system or credential data. Exposing it weakens the sandbox significantly."),
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
    if p.dbus.session.mode == DbusMode::Full {
        w.push(
            Warning::warn(
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
                w.push(Warning::danger("dbus-dangerous-name", "Dangerous D-Bus access", format!("Allowed session service: {why}. This can let the app escape the sandbox.")).with_key("dbus.session.allow"));
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
                    "PipeWire runs without its PulseAudio service (pipewire-pulse), which sandboxed apps use for sound. Install or start pipewire-pulse."
                } else {
                    "No PulseAudio or PipeWire sound server was found. Audio may not work."
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

    #[test]
    fn required_warnings() {
        let mut p = PermissionSet::strict_gui();
        p.display.x11 = true;
        p.filesystem.home = true;
        p.network.mode = NetworkMode::Full;
        p.dbus.system.mode = DbusMode::Full;
        let mut ctx = WarningContext::all_enabled();
        ctx.app_needs_network = Some(false);
        let w = evaluate(&p, &ctx);
        let c = codes(&w);
        for code in ["x11-enabled", "full-home", "network-unneeded", "system-dbus"] {
            assert!(c.contains(&code), "missing {code} in {c:?}");
        }
    }

    #[test]
    fn strict_has_no_danger() {
        let w = evaluate(&PermissionSet::strict_gui(), &WarningContext::all_enabled());
        assert!(w.iter().all(|w| w.severity != Severity::Danger));
    }

    #[test]
    fn x11_warning_can_be_disabled() {
        let mut p = PermissionSet::strict_gui();
        p.display.x11 = true;
        let w = evaluate(&p, &WarningContext::default());
        assert!(!codes(&w).contains(&"x11-enabled"));
    }
}
