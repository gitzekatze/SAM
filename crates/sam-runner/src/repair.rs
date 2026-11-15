//! Making apps work: first-run hints, a log analyzer that turns common error
//! messages into fixes (no strace needed), and the repair ladder that tries
//! one fix at a time.

use sam_core::permissions::dangerous_bus_name;
use sam_core::permissions::*;
use sam_core::risk::RiskLevel;
use sam_core::util::display_safe;
use sam_core::{AppEntry, Config, FixAction, Suggestion};

fn s(id: &str, title: &str, explanation: impl Into<String>, action: FixAction, risk: RiskLevel) -> Suggestion {
    Suggestion { id: id.into(), title: title.into(), explanation: explanation.into(), action, risk, from_app_output: false }
}
fn set(key: &str, value: &str) -> FixAction {
    FixAction::Set { key: key.into(), value: value.into() }
}

/// Does applying `action` change anything for this profile?
pub fn changes_something(p: &PermissionSet, compat: bool, args: &[String], action: &FixAction) -> bool {
    match action {
        FixAction::Set { key, value } => p.get_key(key).ok().map(|v| v.to_string().trim_matches('"').to_string()) != Some(value.clone()),
        FixAction::Add { key, value } => !p.get_key(key).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default().iter().any(|x| x.as_str() == Some(value)),
        FixAction::Compat => !compat,
        FixAction::AddArg { value } => !args.contains(value),
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
    if p.network.mode == NetworkMode::None && e.category == "game" && !(req.network || req.electron) {
        out.push(s("network", "No online play", "The game has no network access, so multiplayer, online accounts and downloads of extra content will not work. Single-player games run fine without it.", set("network.mode", "full"), RiskLevel::High));
    }
    if p.network.mode == NetworkMode::None && (req.network || req.electron) {
        out.push(s("network", "No internet", "The app has no network access. If it loads web content, syncs, signs in or talks to an AI model, it will seem broken. 'This computer only' is a middle ground for apps that use local servers.", set("network.mode", "full"), RiskLevel::High));
    }
    let any_folder = p.filesystem.home || XDG_DIR_KEYS.iter().any(|k| p.filesystem.xdg_access(k).is_granted());
    if !any_folder {
        out.push(s("files", "Files stay inside the sandbox", "The app cannot see your folders. Files it saves land in its private folder (open it with \"Files This App Saved\" under Launching). Grant Downloads to save there instead.", set("filesystem.downloads", "rw"), RiskLevel::Medium));
    }
    let windowed = !e.metadata.terminal;
    if windowed && !p.display.x11 && !req.wayland && matches!(toolkit, "Unknown" | "") && e.detection.as_ref().is_some_and(|d| d.elf_count > 0) {
        out.push(s(
            "x11",
            "The window may not appear",
            "SAM found no Wayland support in this app. If no window opens, turn on X11 (XWayland).",
            set("display.x11", "true"),
            RiskLevel::High,
        ));
    }
    if windowed && !p.devices.gpu && !req.wayland && !req.x11 && matches!(toolkit, "Unknown" | "") && e.detection.as_ref().is_some_and(|d| d.elf_count > 0) {
        out.push(s("gpu", "Graphics may not work", "SAM found no graphics libraries in this app, which usually means it loads them at start (common for Rust and game engines). If it fails to start or draw, turn on GPU acceleration.", set("devices.gpu", "true"), RiskLevel::Medium));
    }
    if req.electron && apparmor_restricts_userns() && !e.profile.args.iter().any(|a| a == "--no-sandbox") {
        out.push(no_sandbox("This system (AppArmor) does not let apps inside a sandbox create their own sandbox, so Electron apps usually fail to start. Starting it without Chromium's internal sandbox fixes that; SAM's sandbox still protects your system."));
    }
    let signs_in = matches!(e.category.as_str(), "communication" | "browser") || req.electron;
    if signs_in && !p.integrations.keyring && p.dbus.session.mode != DbusMode::None {
        out.push(s("keyring", "Logins may not be remembered", "Apps that sign in usually store the login in your keyring or KWallet, which is blocked. Allowing it lets the app read every password stored there.", set("integrations.keyring", "true"), RiskLevel::High));
    }
    out
}

/// Ubuntu 23.10+ style restriction of unprivileged user namespaces.
fn apparmor_restricts_userns() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").is_ok_and(|s| s.trim() == "1")
}

fn no_sandbox(why: &str) -> Suggestion {
    s("chromium-no-sandbox", "Start without Chromium's own sandbox", why, FixAction::AddArg { value: "--no-sandbox".into() }, RiskLevel::Medium)
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

    if let Some(lib) = after(output, "error while loading shared libraries: ").map(|r| display_safe(r.split(':').next().unwrap_or("").trim(), 120)) {
        if p.advanced.host_runtime == HostRuntime::Minimal {
            push(s(
                "libs-missing",
                "A library is not visible",
                format!("The app needs {lib}, which SAM's minimal system view may hide. Show all of /usr."),
                set("advanced.host_runtime", "full"),
                RiskLevel::Medium,
            ));
        } else {
            push(s(
                "libs-missing",
                "A library is missing on this system",
                format!("The app needs {lib}, which is not installed. Install the package that provides it."),
                FixAction::None,
                RiskLevel::Low,
            ));
        }
    }
    if has(&["failed to create xkb keymap", "xkbcommon: error", "couldn't find file \"rules/evdev\"", "could not find a usable locale", "locale: cannot set"])
        && p.advanced.host_runtime == HostRuntime::Minimal
    {
        push(s(
            "system-data",
            "System data is missing",
            "Keyboard layouts or locale data were not found in SAM's minimal system view. Show all of /usr.",
            set("advanced.host_runtime", "full"),
            RiskLevel::Medium,
        ));
    }
    if !p.display.x11
        && has(&[
            "cannot open display",
            "unable to open x display",
            "missing x server or $display",
            "can't connect to x11 window server",
            "java.awt.headlessexception",
            "could not connect to display",
            "could not load the qt platform plugin \"xcb\"",
            "no platform plugin",
            "qt.qpa.plugin: could not find the qt platform plugin \"wayland\"",
        ])
    {
        push(s(
            "x11",
            "The app needs X11",
            "The app tried to open a window through X11 (or has no Wayland support). Turn on X11 (XWayland).",
            set("display.x11", "true"),
            RiskLevel::High,
        ));
    }
    if has(&[
        "zygote process exited",
        "no usable sandbox",
        "suid sandbox helper binary",
        "failed to move to new namespace",
        "operation not permitted: clone",
        "credentials.cc",
    ]) {
        if !p.advanced.allow_userns {
            push(s(
                "userns",
                "Chromium's own sandbox cannot start",
                "Electron/Chromium apps start their own internal sandbox. Allow nested namespaces.",
                set("advanced.allow_userns", "true"),
                RiskLevel::Low,
            ));
        } else if p.advanced.seccomp_strict {
            push(s(
                "seccomp",
                "The strict syscall filter blocks the app",
                "Turn off the strict syscall filter for this app.",
                set("advanced.seccomp_strict", "false"),
                RiskLevel::Low,
            ));
        } else {
            push(no_sandbox("Chromium's internal sandbox could not start inside SAM's sandbox (common on systems that restrict user namespaces). Starting without it fixes that; SAM's sandbox still protects your system."));
        }
    }
    if p.network.mode != NetworkMode::Full
        && has(&[
            "enotfound",
            "temporary failure in name resolution",
            "name or service not known",
            "network is unreachable",
            "err_name_not_resolved",
            "err_internet_disconnected",
            "could not resolve host",
            "getaddrinfo",
            "no address associated with hostname",
            "err_network_changed",
        ])
    {
        push(s(
            "network",
            "The app tried to go online",
            "Network requests failed because the app has no internet access.",
            set("network.mode", "full"),
            RiskLevel::High,
        ));
    }
    if has(&["read-only file system"]) && low.contains("/opt/app") && !p.advanced.writable_appdir && sam_core::host::bwrap_supports_overlay() {
        push(s(
            "writable-appdir",
            "The app writes into its own folder",
            "Portable apps save settings next to themselves. Give it a writable app folder (changes go to a separate layer).",
            set("advanced.writable_appdir", "true"),
            RiskLevel::Low,
        ));
    }
    for line in output.lines() {
        if let Some(path) = denied_home_path(line) {
            let dir = std::path::Path::new(&path).parent().map(|d| d.display().to_string()).unwrap_or(path.clone());
            let (shown_path, shown_dir) = (display_safe(&path, 200), display_safe(&dir, 200));
            let home = sam_core::util::home_dir();
            let too_broad = std::path::Path::new(&dir) == home || !std::path::Path::new(&dir).starts_with(&home);
            if sam_core::risk::is_sensitive_path(&dir) || sam_core::risk::is_sensitive_path(&path) || too_broad {
                push(s("grant-folder-refused", "The app asked for a protected location", format!("The app reported that it could not open {shown_path}. SAM does not offer access to {shown_dir}: it holds keys, passwords or your whole home."), FixAction::None, RiskLevel::Dangerous));
            } else {
                push(s(
                    "grant-folder",
                    "Access to a folder was denied",
                    format!("The app reported that it could not open {shown_path}. Grant read/write access to {shown_dir}."),
                    FixAction::Add { key: "filesystem.custom_write".into(), value: dir },
                    RiskLevel::High,
                ));
            }
            break;
        }
    }
    // "/opt/app/usr/lib/libsystemd.so.0: version `LIBSYSTEMD_251' not found
    // (required by /usr/lib/libmount.so.1)": a bundled library is older than
    // a system library that needs it. The system's copy fits.
    if let Some((lib, needed_by)) = bundled_library_too_old(output) {
        push(s(
            "system-library",
            "A bundled library is too old for this system",
            format!("The app brings its own {lib}, which is older than your system's {needed_by} needs. Use your system's copy of {lib} instead (read-only)."),
            FixAction::Add { key: "advanced.system_libraries".into(), value: lib },
            RiskLevel::Low,
        ));
    }
    if let Some(v) = after(output, "version `GLIBC_").map(|r| display_safe(r.split('\'').next().unwrap_or(""), 16)) {
        push(s(
            "glibc",
            "The app needs a newer system",
            format!("The app needs glibc {v}, newer than this system's. Update the system or use an older version of the app."),
            FixAction::None,
            RiskLevel::Low,
        ));
    }
    if has(&[
        "libgl error: failed to load driver",
        "mesa-loader: failed to open",
        "failed to initialize glx",
        "gpu process isn't usable",
        "egl_not_initialized",
        "failed to get gbm",
        "wgpu error",
        "failed to create surface",
        "no suitable adapter",
        "failed to find a suitable gpu",
        "vk_error",
        "vulkan: no devices",
        "failed to create opengl context",
        "glutin",
    ]) {
        if !p.devices.gpu {
            push(s(
                "gpu",
                "Graphics acceleration is off",
                "The app could not use the GPU. Turn on GPU acceleration.",
                set("devices.gpu", "true"),
                RiskLevel::Medium,
            ));
        } else if p.advanced.host_runtime == HostRuntime::Minimal {
            push(s(
                "gpu-data",
                "Graphics driver files are hidden",
                "The GPU driver could not load in SAM's minimal system view. Show all of /usr.",
                set("advanced.host_runtime", "full"),
                RiskLevel::Medium,
            ));
        }
    }
    if let Some(name) =
        after(output, "The name ").and_then(|r| r.split_whitespace().next()).filter(|_| low.contains("was not provided") || low.contains("serviceunknown"))
    {
        let name = name.trim_matches(|c| c == '\'' || c == '"' || c == ',').to_string();
        let name = if name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) { name } else { display_safe(&name, 80) };
        if name.contains("secrets") || name.contains("kwallet") {
            push(s(
                "keyring",
                "The app wants your keyring",
                "The app tried to store or read a login. Allowing the keyring lets it read every password stored there.",
                set("integrations.keyring", "true"),
                RiskLevel::High,
            ));
        } else if name.contains("ScreenSaver") || name.contains("PowerManagement") || name.contains("mpris") {
            push(s(
                "media",
                "The app wants media controls",
                "Allow media keys and keeping the screen awake.",
                set("integrations.media_controls", "true"),
                RiskLevel::Low,
            ));
        } else if let Some(why) = dangerous_bus_name(&name) {
            push(s(
                "dbus-name-refused",
                "The app asked for a dangerous service",
                format!("The app tried to use {why}. SAM does not offer this: it would let the app escape the sandbox."),
                FixAction::None,
                RiskLevel::Dangerous,
            ));
        } else if name.contains('.') && !name.starts_with(':') {
            push(s(
                "dbus-name",
                "A desktop service is blocked",
                format!("The app tried to use {name}, which the D-Bus filter blocks. Allow just this service."),
                FixAction::Add { key: "dbus.session.allow".into(), value: name },
                RiskLevel::Medium,
            ));
        }
    }
    // The app could not register a D-Bus name of its own (single-instance
    // handling, its own service). Owning a name of an app's own namespace is
    // harmless; desktop services and dangerous names are never offered.
    for marker in ["Failed to register name '", "failed to acquire bus name '", "Could not register D-Bus service '", "Unable to register service '"] {
        let Some(rest) = after(output, marker) else { continue };
        let name = display_safe(rest.split('\'').next().unwrap_or(""), 200);
        // KDE's per-instance name "org.kde.kdenlive-3": the base name covers
        // it (SAM allows the numbered variants with it).
        let name = match name.rsplit_once('-') {
            Some((base, n)) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => base.to_string(),
            _ => name,
        };
        let valid = name.split('.').count() >= 2 && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
        if valid && sam_core::permissions::refuse_own_name(&name, &Default::default()).is_none() && !p.dbus.session.own.contains(&name) {
            push(s(
                "dbus-own",
                "The app wants its own D-Bus name",
                format!("The app tried to register {name} (usually so that a second start hands over to the first). Allow it to own just this name."),
                FixAction::Add { key: "dbus.session.own".into(), value: name },
                RiskLevel::Low,
            ));
        }
        break;
    }
    if !p.audio.enabled && has(&["pa_context_connect", "connection to pulseaudio", "alsa lib", "cannot find card", "pipewire: can't connect"]) {
        push(s("audio", "Sound is off", "The app tried to use audio. Turn on sound.", set("audio.enabled", "true"), RiskLevel::Medium));
    } else if p.audio.enabled && !p.audio.pipewire && has(&["pipewire: can't connect", "pw_context_connect", "failed to connect to pipewire"]) {
        push(s("pipewire", "The app wants PipeWire directly", "It has sound through PulseAudio, but tried to connect to PipeWire itself. Direct access also reaches cameras and other apps' screen streams; allow it only if sound does not work otherwise.", set("audio.pipewire", "true"), RiskLevel::High));
    }
    if has(&["fusermount", "libfuse.so.2", "appimages require fuse"]) {
        push(s("fuse", "The app starts another AppImage", "It tried to mount an AppImage with FUSE, which is not available in a sandbox. SAM already asks AppImages to extract instead; if this still fails, the inner app needs its own sandbox.", FixAction::None, RiskLevel::Low));
    }
    drop(push);
    for x in &mut out {
        x.from_app_output = true;
    }
    if signal == Some(11) && out.is_empty() {
        out.push(s(
            "crash",
            "The app crashed",
            "A crash right at start is often a missing system file. Showing all of /usr is the safest first step.",
            set("advanced.host_runtime", "full"),
            RiskLevel::Medium,
        ));
    }
    out
}

/// `(bundled library, system library that needs a newer one)` from a
/// loader error like "/opt/app/usr/lib/libX.so.0: version `V' not found
/// (required by /usr/lib/libY.so.1)".
fn bundled_library_too_old(output: &str) -> Option<(String, String)> {
    for line in output.lines() {
        let Some((head, tail)) = line.split_once(": version `") else { continue };
        let Some(by) = tail.split("(required by ").nth(1).and_then(|r| r.split(')').next()) else { continue };
        if !(by.starts_with("/usr/") || by.starts_with("/lib")) {
            continue;
        }
        // The library that is too old: the last path on the line before the
        // version, inside the app folder.
        let path = head.rsplit(": ").next().unwrap_or(head).trim();
        if !path.starts_with("/opt/app/") {
            continue;
        }
        let lib = path.rsplit('/').next().unwrap_or("");
        if sam_core::permissions::is_library_name(lib) {
            let by_name = by.rsplit('/').next().unwrap_or(by);
            return Some((lib.to_string(), display_safe(by_name, 60)));
        }
    }
    None
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
    // The user's real home folder (e.g. /var/home/… on Fedora Silverblue),
    // which is where the sandbox shows the app its private home.
    let home = format!("{}/", sam_core::util::home_dir().display());
    let start = line.find(&home).or_else(|| line.find("/home/"))?;
    let rest = &line[start..];
    let end = rest.find(|c: char| c == '\'' || c == '"' || c == ':' || c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string()).filter(|p| p.len() > 6)
}

// --------------------------------------------------------------- ladder

/// Repair steps to try, best first: what the last launch's output suggests,
/// then generic steps. Steps already applied, or that change nothing, are
/// left out.
/// The words of a permission as the switches and tags use them.
fn words(key: &str) -> (String, String) {
    let info = sam_core::permissions::permission_catalog().into_iter().find(|i| i.key == key);
    let title = match key {
        "network.mode" => "Full network".to_string(),
        "dbus.session.mode" => "Session bus: full access".to_string(),
        "advanced.host_runtime" => "All of /usr".to_string(),
        _ => info.as_ref().map(|i| i.title.to_string()).unwrap_or_else(|| key.to_string()),
    };
    (title, info.map(|i| i.description.to_string()).unwrap_or_default())
}

/// What compatibility mode turns on for these settings, in the switches'
/// words (only what it actually changes).
pub fn compat_changes(p: &PermissionSet) -> Vec<String> {
    let wide = sam_profile::compatibility_profile(p);
    sam_core::permissions::permission_catalog().into_iter().filter(|i| p.get_key(i.key).ok() != wide.get_key(i.key).ok()).map(|i| words(i.key).0).collect()
}

/// What applying a repair step changes, in one or two complete sentences,
/// including the protection it costs.
pub fn effect(s: &Suggestion, p: &PermissionSet) -> String {
    match &s.action {
        FixAction::Set { key, value } => {
            let (title, desc) = words(key);
            let off = matches!(value.as_str(), "false" | "none" | "minimal");
            format!("{} “{}”. {}", if off { "Turns off" } else { "Turns on" }, if off { words_plain(key) } else { title }, desc)
        }
        FixAction::Add { key, value } => {
            let (title, desc) = words(key);
            format!("Adds {value} to “{title}”. {desc}")
        }
        FixAction::Compat => {
            let c = compat_changes(p);
            if c.is_empty() {
                "Compatibility mode changes nothing more for these settings.".into()
            } else {
                format!("Turns on: {}. Each of these weakens the sandbox; once the app works, try turning them off one by one.", c.join(", "))
            }
        }
        FixAction::AddArg { value } if value == "--no-sandbox" => {
            "Starts the app with --no-sandbox, which turns off the app's own internal sandbox; SAM's sandbox stays.".into()
        }
        FixAction::AddArg { value } => format!("Starts the app with {value} every time."),
        FixAction::None => String::new(),
    }
}

/// The catalog title of a key (for a switch being turned off).
fn words_plain(key: &str) -> String {
    sam_core::permissions::permission_catalog().into_iter().find(|i| i.key == key).map(|i| i.title.to_string()).unwrap_or_else(|| key.to_string())
}

pub fn ladder(e: &AppEntry, _cfg: &Config, paths: &sam_core::Paths) -> Vec<Suggestion> {
    let p = &e.profile.permissions;
    let mut steps: Vec<Suggestion> = e.last_launch.as_ref().map(|l| l.findings.clone()).unwrap_or_default();
    steps.extend([
        s(
            "full-usr",
            "Show all of /usr",
            "Most crashes at start are a system file hidden by SAM's minimal view.",
            set("advanced.host_runtime", "full"),
            RiskLevel::Medium,
        ),
        s("x11", "Turn on X11", "For apps without Wayland support, or whose window does not appear.", set("display.x11", "true"), RiskLevel::High),
        s("gpu", "Turn on GPU acceleration", "Some apps refuse to start without hardware graphics.", set("devices.gpu", "true"), RiskLevel::Medium),
        s(
            "userns",
            "Allow nested namespaces",
            "Needed by apps that start their own sandbox (Chromium, Electron, WebKit).",
            set("advanced.allow_userns", "true"),
            RiskLevel::Low,
        ),
        s(
            "seccomp-baseline",
            "Turn off the baseline syscall filter",
            "Rarely needed: some apps use kernel interfaces the filter blocks.",
            set("advanced.seccomp_baseline", "false"),
            RiskLevel::Medium,
        ),
        s("writable-appdir", "Writable app folder", "For apps that save next to themselves.", set("advanced.writable_appdir", "true"), RiskLevel::Low),
        s(
            "compat",
            "Compatibility mode",
            "Grants broad access (network, full session bus, all of /usr, X11, GPU, sound). Use when nothing else helps.",
            FixAction::Compat,
            RiskLevel::High,
        ),
    ]);
    if e.detection.as_ref().is_some_and(|d| d.requirements.electron) {
        steps.insert(
            steps.len().saturating_sub(1),
            no_sandbox("For Electron apps whose internal Chromium sandbox fails inside SAM's sandbox. SAM's sandbox still protects your system."),
        );
    }
    let mut seen = Vec::new();
    steps.retain(|st| {
        let keep = !seen.contains(&st.id)
            && !e.repairs_applied.contains(&st.id)
            && !matches!(st.action, FixAction::None)
            // A terminal program has no window: display steps cannot help.
            && !(e.metadata.terminal && matches!(st.id.as_str(), "x11" | "gpu"))
            // Needs overlays: Bubblewrap 0.10+ and a filesystem that can
            // hold the app's changes.
            && !(st.id == "writable-appdir" && !sam_core::host::overlay_works_in(&paths.overlays_dir()))
            && changes_something(p, e.profile.compatibility_mode, &e.profile.args, &st.action);
        seen.push(st.id.clone());
        keep
    });
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::Paths;

    /// Compatibility mode lists only what it actually changes, in the words
    /// of the switches.
    #[test]
    fn compatibility_mode_names_only_what_it_changes() {
        let mut p = PermissionSet::strict_gui();
        let all = compat_changes(&p);
        assert!(all.contains(&"Full network".to_string()) && all.contains(&"X11 / XWayland".to_string()), "{all:?}");
        p.display.x11 = true;
        assert!(!compat_changes(&p).contains(&"X11 / XWayland".to_string()), "already on, so not listed");
    }

    /// A repair step says in a sentence what it turns on or off, with the
    /// switch's own explanation of what that allows.
    #[test]
    fn a_repair_step_says_what_it_changes_and_costs() {
        let p = PermissionSet::strict_gui();
        let x11 = Suggestion {
            id: "x11".into(),
            title: "X11".into(),
            explanation: String::new(),
            action: FixAction::Set { key: "display.x11".into(), value: "true".into() },
            risk: RiskLevel::High,
            from_app_output: false,
        };
        let t = effect(&x11, &p);
        assert!(t.starts_with("Turns on “X11 / XWayland”.") && t.contains("observe input"), "{t}");
        let off = Suggestion { action: FixAction::Set { key: "advanced.seccomp_baseline".into(), value: "false".into() }, ..x11.clone() };
        assert!(effect(&off, &p).starts_with("Turns off “Baseline syscall filter”."), "{}", effect(&off, &p));
        let compat = Suggestion { action: FixAction::Compat, ..x11 };
        assert!(effect(&compat, &p).contains("Full network"));
    }

    /// An app that fails to register its bus name gets a repair step that allows exactly that name.
    #[test]
    fn own_name_requests_become_a_repair() {
        let p = PermissionSet::default();
        let log = "kf.dbusaddons: Failed to register name 'com.nextcloud.desktopclient.nextcloud' with DBUS - does this process have permission";
        let sug = analyze(log, &p, None);
        let own = sug.iter().find(|x| x.id == "dbus-own").expect("suggested");
        assert!(matches!(&own.action, FixAction::Add { key, value } if key == "dbus.session.own" && value == "com.nextcloud.desktopclient.nextcloud"));
        let bad = analyze("Failed to register name 'org.freedesktop.Notifications' with DBUS", &p, None);
        assert!(!bad.iter().any(|x| x.id == "dbus-own"), "desktop services are never offered");
        let kde = analyze("kf.dbusaddons: Failed to register name 'org.kde.kdenlive-3' with DBUS", &p, None);
        assert!(
            kde.iter().any(|x| matches!(&x.action, FixAction::Add { value, .. } if value == "org.kde.kdenlive")),
            "the base name, not this instance's number"
        );
    }

    /// Error messages in an app's output are mapped to the repair step that fixes them.
    #[test]
    fn analyzer_maps_errors_to_fixes() {
        let p = PermissionSet::strict_gui();
        let ids = |out: &str| analyze(out, &p, None).into_iter().map(|s| s.id).collect::<Vec<_>>();
        assert_eq!(ids("./app: error while loading shared libraries: libfoo.so.1: cannot open shared object file"), vec!["libs-missing"]);
        assert_eq!(ids("(app:2): Gdk-ERROR **: Failed to create XKB keymap"), vec!["system-data"]);
        assert_eq!(ids("Error: Missing X server or $DISPLAY"), vec!["x11"]);
        // Audacity 4: Qt forced to xcb, with colour codes from its logger.
        let audacity = "\x1b[1;33m20:59:06.972 | WARN  | main_thread     | Qt              | could not connect to display \x1b[0m\n\x1b[1;32m20:59:06.973 | INFO  | main_thread     | Qt              | Could not load the Qt platform plugin \"xcb\" in \"\" even though it was found.\x1b[0m\n/opt/app/AppRun: line 34:     6 Aborted                    (core dumped)";
        assert!(ids(audacity).contains(&"x11".to_string()), "{:?}", ids(audacity));
        assert_eq!(ids("Error: getaddrinfo ENOTFOUND api.example.com"), vec!["network"]);
        let home = sam_core::util::home_dir().display().to_string();
        assert_eq!(ids(&format!("EACCES: permission denied, open '{home}/Projects/x.txt'")), vec!["grant-folder"]);
        // Homes outside /home (Fedora Silverblue, root) are recognised too.
        if !home.starts_with("/home/") {
            assert_eq!(ids(&format!("permission denied: '{home}/Music/a.mp3'")), vec!["grant-folder"]);
        }
        assert_eq!(ids(&format!("EACCES: permission denied, open '{home}/.ssh/id_ed25519'")), vec!["grant-folder-refused"]);
        assert_eq!(ids("ServiceUnknown: The name org.freedesktop.systemd1 was not provided"), vec!["dbus-name-refused"]);
        assert!(analyze("Error: getaddrinfo ENOTFOUND x", &p, None).iter().all(|s| s.from_app_output));
        assert!(analyze("error while loading shared libraries: <img src=x>: cannot open", &p, None)[0].explanation.contains("‹img"));
        assert_eq!(ids("org.freedesktop.DBus.Error.ServiceUnknown: The name org.freedesktop.secrets was not provided"), vec!["keyring"]);
        // Offered only where Bubblewrap can do it (0.10+, overlays).
        let expected: Vec<&str> = if sam_core::host::bwrap_supports_overlay() { vec!["writable-appdir"] } else { vec![] };
        assert_eq!(ids("touch: cannot touch '/opt/app/settings.ini': Read-only file system"), expected);
        assert_eq!(ids("/lib/libc.so.6: version `GLIBC_2.99' not found"), vec!["glibc"]);
        // A bundled library too old for a system library that needs it
        // (regression: ImHex bundles libsystemd 249, the system's libmount
        // needs 251, and SAM had no step for it).
        let imhex = "/opt/app/usr/bin/imhex: /opt/app/usr/bin/../lib/libsystemd.so.0: version `LIBSYSTEMD_251' not found (required by /usr/lib/libmount.so.1)";
        let found = analyze(imhex, &p, None);
        assert_eq!(found.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), vec!["system-library"]);
        assert!(matches!(&found[0].action, FixAction::Add { key, value } if key == "advanced.system_libraries" && value == "libsystemd.so.0"));
        assert!(found[0].explanation.contains("libmount.so.1"));
        assert_eq!(ids("ERROR eframe::native::run] Exiting because of error: WGPU error: Failed to create surface for any enabled backend"), vec!["gpu"]);
        assert!(ids("all good").is_empty());
        assert_eq!(analyze("", &p, Some(11))[0].id, "crash");
        // Nested namespaces are off by default: allowing them comes first;
        // when they are on already, starting without Chromium's sandbox.
        let zygote = |p: &PermissionSet| analyze("Zygote process exited prematurely", p, None).into_iter().map(|s| s.id).collect::<Vec<_>>();
        assert_eq!(zygote(&p), vec!["userns"]);
        let mut nested = p.clone();
        nested.advanced.allow_userns = true;
        assert_eq!(zygote(&nested), vec!["chromium-no-sandbox"]);
    }

    /// The repair ladder leaves out steps already applied and steps that would change nothing.
    #[test]
    fn ladder_skips_applied_and_noop_steps() {
        let mut e = AppEntry::default();
        e.profile.permissions = PermissionSet::strict_gui();
        let cfg = Config::default();
        let tmp = tempfile::tempdir().unwrap();
        let ids: Vec<String> = ladder(&e, &cfg, &Paths::rooted(tmp.path())).into_iter().map(|s| s.id).collect();
        assert_eq!(ids.first().map(String::as_str), Some("full-usr"));
        assert!(ids.contains(&"userns".to_string()), "offered: nested namespaces are off by default");
        e.profile.permissions.advanced.allow_userns = true;
        assert!(!ladder(&e, &cfg, &Paths::rooted(tmp.path())).iter().any(|s| s.id == "userns"), "not offered once allowed");
        e.profile.permissions.advanced.allow_userns = false;
        e.repairs_applied.push("full-usr".into());
        assert_ne!(ladder(&e, &cfg, &Paths::rooted(tmp.path()))[0].id, "full-usr");
    }

    /// The repair steps offer a writable app folder only where an overlay
    /// can work: not where SAM's overlay folder cannot hold one
    /// (regression: the step was offered by Bubblewrap's version alone, and
    /// on such disks the app then started read-only anyway).
    #[test]
    fn a_writable_app_folder_is_offered_only_where_it_can_work() {
        let mut e = AppEntry::default();
        e.profile.permissions = PermissionSet::strict_gui();
        let cfg = Config::default();
        let tmp = tempfile::tempdir().unwrap();
        let good = Paths::rooted(&tmp.path().join("good"));
        let offered = ladder(&e, &cfg, &good).iter().any(|s| s.id == "writable-appdir");
        assert_eq!(offered, sam_core::host::overlay_works_in(&good.overlays_dir()));
        // A file where the overlay folder belongs: no overlay can work there.
        let bad = Paths::rooted(&tmp.path().join("bad"));
        std::fs::create_dir_all(&bad.data_dir).unwrap();
        std::fs::write(bad.overlays_dir(), "not a folder").unwrap();
        assert!(!ladder(&e, &cfg, &bad).iter().any(|s| s.id == "writable-appdir"));
    }
}
