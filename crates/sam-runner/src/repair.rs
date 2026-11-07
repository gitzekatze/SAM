//! Making apps work: first-run hints, a log analyzer that turns common error
//! messages into fixes (no strace needed), and the repair ladder that tries
//! one fix at a time.

use sam_core::permissions::*;
use sam_core::risk::RiskLevel;
use sam_core::{AppEntry, BackendKind, Config, FixAction, Suggestion};

fn s(id: &str, title: &str, explanation: impl Into<String>, action: FixAction, risk: RiskLevel) -> Suggestion {
    Suggestion { id: id.into(), title: title.into(), explanation: explanation.into(), action, risk }
}
fn set(key: &str, value: &str) -> FixAction {
    FixAction::Set { key: key.into(), value: value.into() }
}

/// Does applying `action` change anything for this profile?
pub fn changes_something(p: &PermissionSet, compat: bool, auto: Option<BackendKind>, action: &FixAction) -> bool {
    match action {
        FixAction::Set { key, value } => p.get_key(key).ok().map(|v| v.to_string().trim_matches('"').to_string()) != Some(value.clone()),
        FixAction::Add { key, value } => !p.get_key(key).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default().iter().any(|x| x.as_str() == Some(value)),
        FixAction::Compat => !compat,
        FixAction::Backend { backend } => auto != Some(*backend),
        FixAction::None => true,
    }
}

// ------------------------------------------------------------------ hints

/// Things likely to surprise the user right after creating a sandbox,
/// each with a one-click change. Shown once as the "first-run check".
pub fn first_run_hints(e: &AppEntry) -> Vec<Suggestion> {
    let p = &e.profile.permissions;
    let req = e.detection.as_ref().map(|d| d.requirements.clone()).unwrap_or_default();
    let toolkit = req.toolkit.as_str();
    let mut out = Vec::new();
    if p.network.mode == NetworkMode::None && (req.network || req.electron) {
        out.push(s("network", "No internet", "The app has no network access. If it loads web content, syncs, signs in or talks to an AI model, it will seem broken. 'Local network only' is a middle ground for apps that use local servers.", set("network.mode", "full"), RiskLevel::High));
    }
    let any_folder = p.filesystem.home || XDG_DIR_KEYS.iter().any(|k| p.filesystem.xdg_access(k).is_granted());
    if !any_folder {
        out.push(s("files", "Files stay inside the sandbox", "The app cannot see your folders. Files it saves land in its private folder (open it with 'Files this app saved'). Grant Downloads to save there instead.", set("filesystem.downloads", "rw"), RiskLevel::Medium));
    }
    if !p.display.x11 && !req.wayland && matches!(toolkit, "Unknown" | "") && e.detection.as_ref().is_some_and(|d| d.elf_count > 0) {
        out.push(s("x11", "The window may not appear", "SAM found no Wayland support in this app. If no window opens, turn on X11 (XWayland).", set("display.x11", "true"), RiskLevel::High));
    }
    if !p.devices.gpu && !req.wayland && !req.x11 && matches!(toolkit, "Unknown" | "") && e.detection.as_ref().is_some_and(|d| d.elf_count > 0) {
        out.push(s("gpu", "Graphics may not work", "SAM found no graphics libraries in this app, which usually means it loads them at start (common for Rust and game engines). If it fails to start or draw, turn on GPU acceleration.", set("devices.gpu", "true"), RiskLevel::Medium));
    }
        let signs_in = matches!(e.category.as_str(), "communication" | "browser") || req.electron;
    if signs_in && !p.integrations.keyring && p.dbus.session.mode != DbusMode::None {
        out.push(s("keyring", "Logins may not be remembered", "Apps that sign in usually store the login in your keyring or KWallet, which is blocked. Allowing it lets the app read every password stored there.", set("integrations.keyring", "true"), RiskLevel::High));
    }
    out
}

// ------------------------------------------------------------- analyzer

/// Turn an app's error output into likely causes with fixes.
pub fn analyze(output: &str, p: &PermissionSet, signal: Option<i32>) -> Vec<Suggestion> {
    let low = output.to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| low.contains(&n.to_lowercase()));
    let mut out: Vec<Suggestion> = Vec::new();
    let mut push = |x: Suggestion| {
        if !out.iter().any(|o| o.id == x.id) {
            out.push(x);
        }
    };

    if let Some(lib) = after(output, "error while loading shared libraries: ").map(|r| r.split(':').next().unwrap_or("").trim().to_string()) {
        if p.advanced.host_runtime == HostRuntime::Minimal {
            push(s("libs-missing", "A library is not visible", format!("The app needs {lib}, which SAM's minimal system view may hide. Show all of /usr."), set("advanced.host_runtime", "full"), RiskLevel::Medium));
        } else {
            push(s("libs-missing", "A library is missing on this system", format!("The app needs {lib}, which is not installed. Install the package that provides it."), FixAction::None, RiskLevel::Low));
        }
    }
    if has(&["failed to create xkb keymap", "xkbcommon: error", "couldn't find file \"rules/evdev\"", "could not find a usable locale", "locale: cannot set"]) && p.advanced.host_runtime == HostRuntime::Minimal {
        push(s("system-data", "System data is missing", "Keyboard layouts or locale data were not found in SAM's minimal system view. Show all of /usr.", set("advanced.host_runtime", "full"), RiskLevel::Medium));
    }
    if !p.display.x11
        && has(&["cannot open display", "unable to open x display", "missing x server or $display", "can't connect to x11 window server", "java.awt.headlessexception", "could not connect to display", "could not load the qt platform plugin \"xcb\"", "no platform plugin", "qt.qpa.plugin: could not find the qt platform plugin \"wayland\""])
    {
        push(s("x11", "The app needs X11", "The app tried to open a window through X11 (or has no Wayland support). Turn on X11 (XWayland).", set("display.x11", "true"), RiskLevel::High));
    }
    if has(&["zygote process exited", "no usable sandbox", "suid sandbox helper binary", "failed to move to new namespace", "operation not permitted: clone", "credentials.cc"]) {
        if !p.advanced.allow_userns {
            push(s("userns", "Chromium's own sandbox cannot start", "Electron/Chromium apps start their own internal sandbox. Allow nested namespaces.", set("advanced.allow_userns", "true"), RiskLevel::Low));
        } else if p.advanced.seccomp_strict {
            push(s("seccomp", "The strict syscall filter blocks the app", "Turn off the strict syscall filter for this app.", set("advanced.seccomp_strict", "false"), RiskLevel::Low));
        } else {
            push(s("backend-bubblejail", "Try another sandbox backend", "Chromium's sandbox fails in this backend. Bubblejail sets up namespaces differently.", FixAction::Backend { backend: BackendKind::Bubblejail }, RiskLevel::Low));
        }
    }
    if p.network.mode != NetworkMode::Full
        && has(&["enotfound", "temporary failure in name resolution", "name or service not known", "network is unreachable", "err_name_not_resolved", "err_internet_disconnected", "could not resolve host", "getaddrinfo", "no address associated with hostname", "err_network_changed"])
    {
        push(s("network", "The app tried to go online", "Network requests failed because the app has no internet access.", set("network.mode", "full"), RiskLevel::High));
    }
    if has(&["read-only file system"]) && low.contains("/opt/app") && !p.advanced.writable_appdir {
        push(s("writable-appdir", "The app writes into its own folder", "Portable apps save settings next to themselves. Give it a writable app folder (changes go to a separate layer).", set("advanced.writable_appdir", "true"), RiskLevel::Low));
    }
    for line in output.lines() {
        if let Some(path) = denied_home_path(line) {
            let dir = std::path::Path::new(&path).parent().map(|d| d.display().to_string()).unwrap_or(path.clone());
            push(s("grant-folder", "Access to a folder was denied", format!("The app could not open {path}. Grant read/write access to {dir}."), FixAction::Add { key: "filesystem.custom_write".into(), value: dir }, RiskLevel::High));
            break;
        }
    }
    if let Some(v) = after(output, "version `GLIBC_").map(|r| r.split('\'').next().unwrap_or("").to_string()) {
        push(s("glibc", "The app needs a newer system", format!("The app needs glibc {v}, newer than this system's. Update the system or use an older version of the app."), FixAction::None, RiskLevel::Low));
    }
    if has(&[
        "libgl error: failed to load driver", "mesa-loader: failed to open", "failed to initialize glx", "gpu process isn't usable",
        "egl_not_initialized", "failed to get gbm", "wgpu error", "failed to create surface", "no suitable adapter",
        "failed to find a suitable gpu", "vk_error", "vulkan: no devices", "failed to create opengl context", "glutin",
    ]) {
        if !p.devices.gpu {
            push(s("gpu", "Graphics acceleration is off", "The app could not use the GPU. Turn on GPU acceleration.", set("devices.gpu", "true"), RiskLevel::Medium));
        } else if p.advanced.host_runtime == HostRuntime::Minimal {
            push(s("gpu-data", "Graphics driver files are hidden", "The GPU driver could not load in SAM's minimal system view. Show all of /usr.", set("advanced.host_runtime", "full"), RiskLevel::Medium));
        }
    }
    if let Some(name) = after(output, "The name ").and_then(|r| r.split_whitespace().next()).filter(|_| low.contains("was not provided") || low.contains("serviceunknown")) {
        let name = name.trim_matches(|c| c == '\'' || c == '"' || c == ',').to_string();
        if name.contains("secrets") || name.contains("kwallet") {
            push(s("keyring", "The app wants your keyring", "The app tried to store or read a login. Allowing the keyring lets it read every password stored there.", set("integrations.keyring", "true"), RiskLevel::High));
        } else if name.contains("ScreenSaver") || name.contains("PowerManagement") || name.contains("mpris") {
            push(s("media", "The app wants media controls", "Allow media keys and keeping the screen awake.", set("integrations.media_controls", "true"), RiskLevel::Low));
        } else if name.contains('.') && !name.starts_with(':') {
            push(s("dbus-name", "A desktop service is blocked", format!("The app tried to use {name}, which the D-Bus filter blocks. Allow just this service."), FixAction::Add { key: "dbus.session.allow".into(), value: name }, RiskLevel::Medium));
        }
    }
    if !p.audio.enabled && has(&["pa_context_connect", "connection to pulseaudio", "alsa lib", "cannot find card", "pipewire: can't connect"]) {
        push(s("audio", "Sound is off", "The app tried to use audio. Turn on sound.", set("audio.enabled", "true"), RiskLevel::Medium));
    }
    if has(&["fusermount", "libfuse.so.2", "appimages require fuse"]) {
        push(s("fuse", "The app starts another AppImage", "It tried to mount an AppImage with FUSE, which is not available in a sandbox. SAM already asks AppImages to extract instead; if this still fails, the inner app needs its own sandbox.", FixAction::None, RiskLevel::Low));
    }
    drop(push);
    if signal == Some(11) && out.is_empty() {
        out.push(s("crash", "The app crashed", "A crash right at start is often a missing system file. Showing all of /usr is the safest first step.", set("advanced.host_runtime", "full"), RiskLevel::Medium));
    }
    out
}

fn after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    text.find(marker).map(|i| &text[i + marker.len()..])
}

/// `EACCES ... '/home/u/x'` or `/home/u/x: Permission denied`.
fn denied_home_path(line: &str) -> Option<String> {
    let l = line.to_lowercase();
    if !(l.contains("permission denied") || l.contains("eacces")) {
        return None;
    }
    let start = line.find("/home/")?;
    let rest = &line[start..];
    let end = rest.find(|c: char| c == '\'' || c == '"' || c == ':' || c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string()).filter(|p| p.len() > 6)
}

// --------------------------------------------------------------- ladder

/// Repair steps to try, best first: what the last launch's output suggests,
/// then generic steps. Steps already applied, or that change nothing, are
/// left out.
pub fn ladder(e: &AppEntry, cfg: &Config) -> Vec<Suggestion> {
    let p = &e.profile.permissions;
    let mut steps: Vec<Suggestion> = e.last_launch.as_ref().map(|l| l.findings.clone()).unwrap_or_default();
    steps.extend([
        s("full-usr", "Show all of /usr", "Most crashes at start are a system file hidden by SAM's minimal view.", set("advanced.host_runtime", "full"), RiskLevel::Medium),
        s("x11", "Turn on X11", "For apps without Wayland support, or whose window does not appear.", set("display.x11", "true"), RiskLevel::High),
        s("gpu", "Turn on GPU acceleration", "Some apps refuse to start without hardware graphics.", set("devices.gpu", "true"), RiskLevel::Medium),
        s("userns", "Allow nested namespaces", "Needed by apps that start their own sandbox (Chromium, Electron, WebKit).", set("advanced.allow_userns", "true"), RiskLevel::Low),
        s("writable-appdir", "Writable app folder", "For apps that save next to themselves.", set("advanced.writable_appdir", "true"), RiskLevel::Low),
        s("compat", "Compatibility mode", "Grants broad access (network, full session bus, all of /usr, X11, GPU, sound). Use when nothing else helps.", FixAction::Compat, RiskLevel::High),
        s("backend-bubblejail", "Try Bubblejail", "A different way of building the sandbox.", FixAction::Backend { backend: BackendKind::Bubblejail }, RiskLevel::Low),
    ]);
    if cfg.security.allow_firejail {
        steps.push(s("backend-firejail", "Try Firejail", "Runs the original AppImage with Firejail (setuid). Last resort.", FixAction::Backend { backend: BackendKind::Firejail }, RiskLevel::High));
    }
    let auto = e.profile.auto_backend.as_ref().map(|l| l.kind);
    let mut seen = Vec::new();
    steps.retain(|st| {
        let keep = !seen.contains(&st.id)
            && !e.repairs_applied.contains(&st.id)
            && !matches!(st.action, FixAction::None)
            && (e.profile.backend == sam_core::BackendChoice::Auto || !matches!(st.action, FixAction::Backend { .. }))
            && changes_something(p, e.profile.compatibility_mode, auto, &st.action);
        seen.push(st.id.clone());
        keep
    });
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzer_maps_errors_to_fixes() {
        let p = PermissionSet::strict_gui();
        let ids = |out: &str| analyze(out, &p, None).into_iter().map(|s| s.id).collect::<Vec<_>>();
        assert_eq!(ids("./app: error while loading shared libraries: libfoo.so.1: cannot open shared object file"), vec!["libs-missing"]);
        assert_eq!(ids("(app:2): Gdk-ERROR **: Failed to create XKB keymap"), vec!["system-data"]);
        assert_eq!(ids("Error: Missing X server or $DISPLAY"), vec!["x11"]);
        assert_eq!(ids("Error: getaddrinfo ENOTFOUND api.example.com"), vec!["network"]);
        assert_eq!(ids("EACCES: permission denied, open '/home/u/Projects/x.txt'"), vec!["grant-folder"]);
        assert_eq!(ids("org.freedesktop.DBus.Error.ServiceUnknown: The name org.freedesktop.secrets was not provided"), vec!["keyring"]);
        assert_eq!(ids("touch: cannot touch '/opt/app/settings.ini': Read-only file system"), vec!["writable-appdir"]);
        assert_eq!(ids("/lib/libc.so.6: version `GLIBC_2.99' not found"), vec!["glibc"]);
        assert_eq!(ids("ERROR eframe::native::run] Exiting because of error: WGPU error: Failed to create surface for any enabled backend"), vec!["gpu"]);
        assert!(ids("all good").is_empty());
        assert_eq!(analyze("", &p, Some(11))[0].id, "crash");
    }

    #[test]
    fn ladder_skips_applied_and_noop_steps() {
        let mut e = AppEntry::default();
        e.profile.permissions = PermissionSet::strict_gui();
        let cfg = Config::default();
        let ids: Vec<String> = ladder(&e, &cfg).into_iter().map(|s| s.id).collect();
        assert_eq!(ids.first().map(String::as_str), Some("full-usr"));
        assert!(!ids.contains(&"userns".to_string()), "already allowed by default");
        assert!(!ids.contains(&"backend-firejail".to_string()), "firejail not allowed");
        e.repairs_applied.push("full-usr".into());
        assert_ne!(ladder(&e, &cfg)[0].id, "full-usr");
    }
}
