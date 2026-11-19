//! Making apps work: first-run hints, a log analyzer that turns common error
//! messages into fixes (no strace needed), and the repair ladder that tries
//! one fix at a time.

use sam_core::i18n::tr;
use sam_core::permissions::dangerous_bus_name;
use sam_core::permissions::*;
use sam_core::risk::RiskLevel;
use sam_core::util::display_safe;
use sam_core::{AppEntry, Config, FixAction, Suggestion};

fn s(
    id: &str,
    title: &str,
    explanation: impl Into<String>,
    action: FixAction,
    risk: RiskLevel,
) -> Suggestion {
    // In the user's language; an explanation built from parts comes
    // translated already (`trf`).
    Suggestion {
        id: id.into(),
        title: tr(title),
        explanation: tr(&explanation.into()),
        action,
        risk,
        from_app_output: false,
    }
}
fn set(key: &str, value: &str) -> FixAction {
    FixAction::Set {
        key: key.into(),
        value: value.into(),
    }
}

/// Does applying `action` change anything for this profile?
pub fn changes_something(
    p: &PermissionSet,
    compat: bool,
    args: &[String],
    action: &FixAction,
) -> bool {
    match action {
        FixAction::Set { key, value } => {
            p.get_key(key)
                .ok()
                .map(|v| v.to_string().trim_matches('"').to_string())
                != Some(value.clone())
        }
        FixAction::Add { key, value } => !p
            .get_key(key)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .any(|x| x.as_str() == Some(value)),
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
    let req = e
        .detection
        .as_ref()
        .map(|d| d.requirements.clone())
        .unwrap_or_default();
    let toolkit = req.toolkit.as_str();
    let mut out = Vec::new();
    if p.network.mode == NetworkMode::None && e.category == "game" && !(req.network || req.electron)
    {
        out.push(s("network", "No online play", "The game has no network access, so multiplayer, online accounts and downloads of extra content will not work. Single-player games run fine without it.", set("network.mode", "full"), RiskLevel::High));
    }
    if p.network.mode == NetworkMode::None && (req.network || req.electron) {
        out.push(s("network", "No internet", "The app has no network access. If it loads web content, syncs, signs in or talks to an AI model, it will seem broken. 'This computer only' is a middle ground for apps that use local servers.", set("network.mode", "full"), RiskLevel::High));
    }
    let any_folder = p.filesystem.home
        || XDG_DIR_KEYS
            .iter()
            .any(|k| p.filesystem.xdg_access(k).is_granted());
    if !any_folder {
        out.push(s("files", "Files stay inside the sandbox", "The app cannot see your folders. Files it saves land in its private folder (open it with \"Files This App Saved\" under Launching). Grant Downloads to save there instead.", set("filesystem.downloads", "rw"), RiskLevel::Medium));
    }
    let windowed = !e.metadata.terminal;
    if windowed
        && !p.display.x11
        && !req.wayland
        && matches!(toolkit, "Unknown" | "")
        && e.detection.as_ref().is_some_and(|d| d.elf_count > 0)
    {
        out.push(s(
            "x11",
            "The window may not appear",
            "SAM found no Wayland support in this app. If no window opens, turn on X11 (XWayland).",
            set("display.x11", "true"),
            RiskLevel::High,
        ));
    }
    if windowed
        && !p.devices.gpu
        && !req.wayland
        && !req.x11
        && matches!(toolkit, "Unknown" | "")
        && e.detection.as_ref().is_some_and(|d| d.elf_count > 0)
    {
        out.push(s("gpu", "Graphics may not work", "SAM found no graphics libraries in this app, which usually means it loads them at start (common for Rust and game engines). If it fails to start or draw, turn on GPU acceleration.", set("devices.gpu", "true"), RiskLevel::Medium));
    }
    if req.electron
        && chromium_sandbox_blocked()
        && !e.profile.args.iter().any(|a| a == "--no-sandbox")
    {
        out.push(no_sandbox());
    }
    let signs_in = matches!(e.category.as_str(), "communication" | "browser") || req.electron;
    if signs_in && !p.integrations.keyring && p.dbus.session.mode != DbusMode::None {
        out.push(s("keyring", "Logins may not be remembered", "Apps that sign in usually store the login in your keyring or KWallet, which is blocked. Allowing it lets the app read every password stored there.", set("integrations.keyring", "true"), RiskLevel::High));
    }
    // A step tried at a start that did not help is not offered again,
    // here either (only the ladder knew, so it came back as a hint).
    out.retain(|st| !e.tried_repairs.contains(&st.id));
    out
}

/// Whether this computer keeps a program inside a sandbox from creating
/// its own, so Chromium's sandbox cannot start in SAM's: user namespaces
/// switched off, unprivileged ones forbidden, or Ubuntu's AppArmor
/// restriction. Read from the kernel's settings, nothing else.
pub fn chromium_sandbox_blocked() -> bool {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    blocked_by(
        read("/proc/sys/user/max_user_namespaces").as_deref(),
        read("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
        read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref(),
    )
}

/// [`chromium_sandbox_blocked`] from the three settings' values.
fn blocked_by(max: Option<&str>, clone: Option<&str>, apparmor: Option<&str>) -> bool {
    max == Some("0") || clone == Some("0") || apparmor == Some("1")
}

/// Starting without Chromium's own sandbox: only offered where this
/// computer blocks it (audit A1: offered to every Electron app, it took a
/// working layer away), saying what is lost.
fn no_sandbox() -> Suggestion {
    s(
        "chromium-no-sandbox",
        "Start without Chromium's own sandbox",
        "This computer does not let a program inside a sandbox make its own (AppArmor, or user namespaces switched off), so Chromium's sandbox cannot start in SAM's. Without it, the web pages the app shows are no longer kept apart from the rest of the app (your logins in it, its other windows); SAM's sandbox still keeps the app away from your files and your computer.",
        FixAction::AddArg {
            value: "--no-sandbox".into(),
        },
        RiskLevel::High,
    )
}

// ------------------------------------------------------------- analyzer

/// Turn an app's error output into likely causes with fixes.
pub fn analyze(output: &str, p: &PermissionSet, signal: Option<i32>) -> Vec<Suggestion> {
    analyze_with(output, p, signal, chromium_sandbox_blocked())
}

/// [`analyze`] with whether this computer blocks Chromium's own sandbox.
fn analyze_with(
    output: &str,
    p: &PermissionSet,
    signal: Option<i32>,
    chromium_blocked: bool,
) -> Vec<Suggestion> {
    let low = output.to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| low.contains(&n.to_lowercase()));
    let mut out: Vec<Suggestion> = Vec::new();
    let mut push = |x: Suggestion| {
        if !out.iter().any(|o| o.id == x.id) {
            out.push(x);
        }
    };

    if let Some(lib) = after(output, "error while loading shared libraries: ")
        .map(|r| display_safe(r.split(':').next().unwrap_or("").trim(), 120))
    {
        if p.advanced.host_runtime == HostRuntime::Minimal {
            push(s(
                "libs-missing",
                "A library is not visible",
                sam_core::i18n::trf("The app needs {lib}, which SAM's minimal system view may hide. Show all of /usr.", &[("lib", &lib)]),
                set("advanced.host_runtime", "full"),
                RiskLevel::Medium,
            ));
        } else {
            push(s(
                "libs-missing",
                "A library is missing on this system",
                sam_core::i18n::trf("The app needs {lib}, which is not installed. Install the package that provides it.", &[("lib", &lib)]),
                FixAction::None,
                RiskLevel::Low,
            ));
        }
    }
    if has(&[
        "failed to create xkb keymap",
        "xkbcommon: error",
        "couldn't find file \"rules/evdev\"",
        "could not find a usable locale",
        "locale: cannot set",
    ]) && p.advanced.host_runtime == HostRuntime::Minimal
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
        } else if chromium_blocked {
            push(no_sandbox());
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
    if has(&["read-only file system"])
        && low.contains("/opt/app")
        && !p.advanced.writable_appdir
        && sam_core::host::bwrap_supports_overlay()
    {
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
            let dir = std::path::Path::new(&path)
                .parent()
                .map(|d| d.display().to_string())
                .unwrap_or(path.clone());
            let (shown_path, shown_dir) = (display_safe(&path, 200), display_safe(&dir, 200));
            let home = sam_core::util::home_dir();
            let too_broad = std::path::Path::new(&dir) == home
                || !std::path::Path::new(&dir).starts_with(&home);
            if sam_core::risk::is_sensitive_path(&dir)
                || sam_core::risk::is_sensitive_path(&path)
                || too_broad
            {
                push(s("grant-folder-refused", "The app asked for a protected location", sam_core::i18n::trf("The app reported that it could not open {shown_path}. SAM does not offer access to {shown_dir}: it holds keys, passwords or your whole home.", &[("shown_path", &shown_path), ("shown_dir", &shown_dir)]), FixAction::None, RiskLevel::Dangerous));
            } else {
                push(s(
                    "grant-folder",
                    "Access to a folder was denied",
                    sam_core::i18n::trf(
                        "The app reported that it could not open {shown_path}. Grant read/write access to {shown_dir}.",
                        &[("shown_path", &shown_path), ("shown_dir", &shown_dir)],
                    ),
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
            sam_core::i18n::trf(
                "The app brings its own {lib}, which is older than your system's {needed_by} needs. Use your system's copy of {lib} instead (read-only).",
                &[("lib", &lib), ("needed_by", &needed_by)],
            ),
            FixAction::Add { key: "advanced.system_libraries".into(), value: lib },
            RiskLevel::Low,
        ));
    }
    if let Some(v) = after(output, "version `GLIBC_")
        .map(|r| display_safe(r.split('\'').next().unwrap_or(""), 16))
    {
        push(s(
            "glibc",
            "The app needs a newer system",
            sam_core::i18n::trf(
                "The app needs glibc {version}, newer than this system's. Update the system or use an older version of the app.",
                &[("version", &v)],
            ),
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
    if let Some(name) = after(output, "The name ")
        .and_then(|r| r.split_whitespace().next())
        .filter(|_| low.contains("was not provided") || low.contains("serviceunknown"))
    {
        let name = name
            .trim_matches(|c| c == '\'' || c == '"' || c == ',')
            .to_string();
        let name = if name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            name
        } else {
            display_safe(&name, 80)
        };
        if name.contains("secrets") || name.contains("kwallet") {
            push(s(
                "keyring",
                "The app wants your keyring",
                "The app tried to store or read a login. Allowing the keyring lets it read every password stored there.",
                set("integrations.keyring", "true"),
                RiskLevel::High,
            ));
        } else if name.contains("ScreenSaver")
            || name.contains("PowerManagement")
            || name.contains("mpris")
        {
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
                sam_core::i18n::trf("The app tried to use {why}. SAM does not offer this: it would let the app escape the sandbox.", &[("why", &why)]),
                FixAction::None,
                RiskLevel::Dangerous,
            ));
        } else if name.contains('.') && !name.starts_with(':') {
            push(s(
                "dbus-name",
                "A desktop service is blocked",
                sam_core::i18n::trf("The app tried to use {name}, which the D-Bus filter blocks. Allow just this service.", &[("name", &name)]),
                FixAction::Add { key: "dbus.session.allow".into(), value: name },
                RiskLevel::Medium,
            ));
        }
    }
    // A bus name of its own is never suggested from what the app printed:
    // SAM learns the name the app really asked for from the D-Bus filter's
    // record and allows it when nobody on this computer uses it
    // (`own_names`, option D of 2026-11-18). The app's own words named
    // anything it liked, a terminal's name too (audit D-M6).
    if !p.audio.enabled
        && has(&[
            "pa_context_connect",
            "connection to pulseaudio",
            "alsa lib",
            "cannot find card",
            "pipewire: can't connect",
        ])
    {
        push(s(
            "audio",
            "Sound is off",
            "The app tried to use audio. Turn on sound.",
            set("audio.enabled", "true"),
            RiskLevel::Medium,
        ));
    } else if p.audio.enabled
        && !p.audio.pipewire
        && has(&[
            "pipewire: can't connect",
            "pw_context_connect",
            "failed to connect to pipewire",
        ])
    {
        push(s("pipewire", "The app wants PipeWire directly", "It has sound through PulseAudio, but tried to connect to PipeWire itself. Direct access also reaches cameras and other apps' screen streams; allow it only if sound does not work otherwise.", set("audio.pipewire", "true"), RiskLevel::High));
    }
    if has(&["fusermount", "libfuse.so.2", "appimages require fuse"]) {
        push(s("fuse", "The app starts another AppImage", "It tried to mount an AppImage with FUSE, which is not available in a sandbox. SAM already asks AppImages to unpack themselves instead; if this still fails, the inner app needs its own sandbox.", FixAction::None, RiskLevel::Low));
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
        let Some((head, tail)) = line.split_once(": version `") else {
            continue;
        };
        let Some(by) = tail
            .split("(required by ")
            .nth(1)
            .and_then(|r| r.split(')').next())
        else {
            continue;
        };
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
    let end = rest
        .find(|c: char| c == '\'' || c == '"' || c == ':' || c.is_whitespace())
        .unwrap_or(rest.len());
    Some(rest[..end].to_string()).filter(|p| p.len() > 6)
}

// --------------------------------------------------------------- ladder

/// Repair steps to try, best first: what the last launch's output suggests,
/// then generic steps. Steps already applied, or that change nothing, are
/// left out.
/// The words of a permission as the switches and tags use them.
fn words(key: &str) -> (String, String) {
    let info = sam_core::permissions::permission_catalog()
        .into_iter()
        .find(|i| i.key == key);
    let title = match key {
        "network.mode" => tr("Full network"),
        "dbus.session.mode" => tr("Session bus: full access"),
        "advanced.host_runtime" => tr("All of /usr"),
        _ => info
            .as_ref()
            .map(|i| i.title.to_string())
            .unwrap_or_else(|| key.to_string()),
    };
    (
        title,
        info.map(|i| i.description.to_string()).unwrap_or_default(),
    )
}

/// What compatibility mode turns on for these settings, in the switches'
/// words (only what it actually changes).
pub fn compat_changes(p: &PermissionSet) -> Vec<String> {
    let wide = sam_profile::compatibility_profile(p);
    sam_core::permissions::permission_catalog()
        .into_iter()
        .filter(|i| p.get_key(i.key).ok() != wide.get_key(i.key).ok())
        .map(|i| words(i.key).0)
        .collect()
}

/// What applying a repair step changes, in one or two complete sentences,
/// including the protection it costs.
pub fn effect(s: &Suggestion, p: &PermissionSet) -> String {
    match &s.action {
        FixAction::Set { key, value } => {
            let (title, desc) = words(key);
            let off = matches!(value.as_str(), "false" | "none" | "minimal");
            // Whole sentences, so a translation can place the setting freely.
            if off {
                sam_core::i18n::trf("Turns off “{setting}”. {explanation}", &[("setting", &words_plain(key)), ("explanation", &desc)])
            } else {
                sam_core::i18n::trf("Turns on “{setting}”. {explanation}", &[("setting", &title), ("explanation", &desc)])
            }
        }
        FixAction::Add { key, value } => {
            let (title, desc) = words(key);
            sam_core::i18n::trf("Adds {value} to “{setting}”. {explanation}", &[("value", &value), ("setting", &title), ("explanation", &desc)])
        }
        FixAction::Compat => {
            let c = compat_changes(p);
            if c.is_empty() {
                tr("Compatibility mode changes nothing more for these settings.")
            } else {
                sam_core::i18n::trf(
                    "Turns on: {settings}. Each of these weakens the sandbox; once the app works, try turning them off one by one.",
                    &[("settings", &c.join(", "))],
                )
            }
        }
        FixAction::AddArg { value } if value == "--no-sandbox" => {
            tr("Starts the app with --no-sandbox, which turns off the app's own internal sandbox; SAM's sandbox stays.")
        }
        FixAction::AddArg { value } => sam_core::i18n::trf("Starts the app with {value} every time.", &[("value", &value)]),
        FixAction::None => String::new(),
    }
}

/// The catalog title of a key (for a switch being turned off).
fn words_plain(key: &str) -> String {
    sam_core::permissions::permission_catalog()
        .into_iter()
        .find(|i| i.key == key)
        .map(|i| i.title.to_string())
        .unwrap_or_else(|| key.to_string())
}

/// Compatibility mode: the full session bus in it is a way out of the
/// sandbox, so it is Dangerous and says so (audit D-H5: "broad access").
pub fn compat_step() -> Suggestion {
    s(
        "compat",
        "Compatibility mode",
        "Grants broad access: the network, all of /usr, X11, GPU, sound and the full session bus. Through the full session bus the app can ask desktop services to run programs outside its sandbox, so this is a way out. Only when nothing else helps, and only for apps you trust.",
        FixAction::Compat,
        RiskLevel::Dangerous,
    )
}

/// Puts back exactly what the applied repair step `r` changed (already
/// taken out of `e.applied_repairs`), keeping the other steps.
pub fn revert_step(e: &mut AppEntry, r: &sam_core::model::AppliedRepair) -> anyhow::Result<()> {
    use anyhow::Context;
    let step = r
        .step
        .clone()
        .context(sam_core::i18n::tr("damaged repair record"))?;
    match &step.action {
        FixAction::Set { .. } => {
            for (key, old) in &r.before {
                e.profile
                    .permissions
                    .set_key(key, &serde_json::to_string(old)?)?;
            }
        }
        FixAction::Add { key, .. } => {
            if let Some(v) = &r.added {
                let mut list: Vec<String> =
                    serde_json::from_value(e.profile.permissions.get_key(key)?)?;
                list.retain(|x| x != v);
                e.profile
                    .permissions
                    .set_key(key, &serde_json::to_string(&list)?)?;
            }
        }
        FixAction::Compat => {
            e.profile.permissions = e
                .profile
                .before_compat
                .take()
                .unwrap_or_else(|| e.recommended.clone());
            e.profile.compatibility_mode = false;
        }
        FixAction::AddArg { .. } => {
            if let Some(v) = &r.added {
                e.profile.args.retain(|x| x != v);
            }
        }
        FixAction::None => {}
    }
    e.repairs_applied.retain(|id| *id != step.id);
    if e.applied_repairs.is_empty() {
        e.repair_backup = None;
    }
    Ok(())
}

/// After a start: repair steps on trial that the start proved are kept
/// (`worked`), or undone and remembered as tried when it failed (owner
/// decision of 2026-11-18; night run N3). Newest first, so each step finds
/// the settings it changed. Returns the titles of the undone steps.
pub fn judge_trials(e: &mut AppEntry, worked: bool) -> Vec<String> {
    let mut undone = Vec::new();
    let mut i = e.applied_repairs.len();
    while i > 0 {
        i -= 1;
        if !e.applied_repairs[i].on_trial {
            continue;
        }
        if worked {
            e.applied_repairs[i].on_trial = false;
            continue;
        }
        let r = e.applied_repairs.remove(i);
        let (id, title) = r
            .step
            .as_ref()
            .map(|s| (s.id.clone(), s.title.clone()))
            .unwrap_or_default();
        if revert_step(e, &r).is_ok() {
            if !e.tried_repairs.contains(&id) {
                e.tried_repairs.push(id);
            }
            undone.push(title);
        } else {
            // Could not be undone (damaged record): keep it, judged.
            let mut r = r;
            r.on_trial = false;
            e.applied_repairs.insert(i, r);
        }
    }
    undone
}

pub fn ladder(e: &AppEntry, cfg: &Config, paths: &sam_core::Paths) -> Vec<Suggestion> {
    ladder_for(e, cfg, paths, chromium_sandbox_blocked())
}

/// [`ladder`] with whether this computer blocks Chromium's own sandbox.
fn ladder_for(
    e: &AppEntry,
    cfg: &Config,
    paths: &sam_core::Paths,
    chromium_blocked: bool,
) -> Vec<Suggestion> {
    let p = &e.profile.permissions;
    let mut steps: Vec<Suggestion> = e
        .last_launch
        .as_ref()
        .map(|l| l.findings.clone())
        .unwrap_or_default();
    steps.extend([
        s(
            "full-usr",
            "Show all of /usr",
            "Most crashes at start are a system file hidden by SAM's minimal view.",
            set("advanced.host_runtime", "full"),
            RiskLevel::Medium,
        ),
        s(
            "x11",
            "Turn on X11",
            "For apps without Wayland support, or whose window does not appear.",
            set("display.x11", "true"),
            RiskLevel::High,
        ),
        s(
            "gpu",
            "Turn on GPU acceleration",
            "Some apps refuse to start without hardware graphics.",
            set("devices.gpu", "true"),
            RiskLevel::Medium,
        ),
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
        s(
            "writable-appdir",
            "Writable app folder",
            "For apps that save next to themselves.",
            set("advanced.writable_appdir", "true"),
            RiskLevel::Low,
        ),
        compat_step(),
    ]);
    if chromium_blocked
        && e.detection
            .as_ref()
            .is_some_and(|d| d.requirements.electron)
    {
        steps.insert(steps.len().saturating_sub(1), no_sandbox());
    }
    // "Never offer compatibility mode" (Preferences): never (audit U-M9).
    if cfg.compatibility.behavior == sam_core::config::CompatBehavior::Never {
        steps.retain(|st| !matches!(st.action, FixAction::Compat));
    }
    let mut seen = Vec::new();
    steps.retain(|st| {
        let keep = !seen.contains(&st.id)
            && !e.repairs_applied.contains(&st.id)
            // Tried, did not help, undone: not again.
            && !e.tried_repairs.contains(&st.id)
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
        assert!(
            all.contains(&"Full network".to_string())
                && all.contains(&"X11 / XWayland".to_string()),
            "{all:?}"
        );
        p.display.x11 = true;
        assert!(
            !compat_changes(&p).contains(&"X11 / XWayland".to_string()),
            "already on, so not listed"
        );
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
            action: FixAction::Set {
                key: "display.x11".into(),
                value: "true".into(),
            },
            risk: RiskLevel::High,
            from_app_output: false,
        };
        let t = effect(&x11, &p);
        assert!(
            t.starts_with("Turns on “X11 / XWayland”.") && t.contains("observe input"),
            "{t}"
        );
        let off = Suggestion {
            action: FixAction::Set {
                key: "advanced.seccomp_baseline".into(),
                value: "false".into(),
            },
            ..x11.clone()
        };
        assert!(
            effect(&off, &p).starts_with("Turns off “Baseline syscall filter”."),
            "{}",
            effect(&off, &p)
        );
        let compat = Suggestion {
            action: FixAction::Compat,
            ..x11
        };
        assert!(effect(&compat, &p).contains("Full network"));
    }

    /// What the app prints never gets it a bus name, whatever name it
    /// claims it needs (a terminal's name runs host commands; audit D-M6):
    /// names come only from the D-Bus filter's record (`own_names`).
    #[test]
    fn the_apps_own_words_never_give_it_a_bus_name() {
        let p = PermissionSet::default();
        for log in [
            "kf.dbusaddons: Failed to register name 'com.nextcloud.desktopclient.nextcloud' with DBUS",
            "Failed to register name 'org.gnome.Terminal' with DBUS",
            "failed to acquire bus name 'org.kde.konsole'",
            "Could not register D-Bus service 'org.example.App'",
            "Unable to register service 'org.example.App'",
        ] {
            assert!(
                !analyze(log, &p, None)
                    .iter()
                    .any(|s| matches!(&s.action, FixAction::Add { key, .. } if key == "dbus.session.own")),
                "{log}"
            );
        }
    }

    #[test]
    fn analyzer_maps_errors_to_fixes() {
        let p = PermissionSet::strict_gui();
        let ids = |out: &str| {
            analyze(out, &p, None)
                .into_iter()
                .map(|s| s.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids("./app: error while loading shared libraries: libfoo.so.1: cannot open shared object file"), vec!["libs-missing"]);
        assert_eq!(
            ids("(app:2): Gdk-ERROR **: Failed to create XKB keymap"),
            vec!["system-data"]
        );
        assert_eq!(ids("Error: Missing X server or $DISPLAY"), vec!["x11"]);
        // Audacity 4: Qt forced to xcb, with colour codes from its logger.
        let audacity = "\x1b[1;33m20:59:06.972 | WARN  | main_thread     | Qt              | could not connect to display \x1b[0m\n\x1b[1;32m20:59:06.973 | INFO  | main_thread     | Qt              | Could not load the Qt platform plugin \"xcb\" in \"\" even though it was found.\x1b[0m\n/opt/app/AppRun: line 34:     6 Aborted                    (core dumped)";
        assert!(
            ids(audacity).contains(&"x11".to_string()),
            "{:?}",
            ids(audacity)
        );
        assert_eq!(
            ids("Error: getaddrinfo ENOTFOUND api.example.com"),
            vec!["network"]
        );
        let home = sam_core::util::home_dir().display().to_string();
        assert_eq!(
            ids(&format!(
                "EACCES: permission denied, open '{home}/Projects/x.txt'"
            )),
            vec!["grant-folder"]
        );
        // Homes outside /home (Fedora Silverblue, root) are recognised too.
        if !home.starts_with("/home/") {
            assert_eq!(
                ids(&format!("permission denied: '{home}/Music/a.mp3'")),
                vec!["grant-folder"]
            );
        }
        assert_eq!(
            ids(&format!(
                "EACCES: permission denied, open '{home}/.ssh/id_ed25519'"
            )),
            vec!["grant-folder-refused"]
        );
        assert_eq!(
            ids("ServiceUnknown: The name org.freedesktop.systemd1 was not provided"),
            vec!["dbus-name-refused"]
        );
        assert!(analyze("Error: getaddrinfo ENOTFOUND x", &p, None)
            .iter()
            .all(|s| s.from_app_output));
        assert!(analyze(
            "error while loading shared libraries: <img src=x>: cannot open",
            &p,
            None
        )[0]
        .explanation
        .contains("‹img"));
        assert_eq!(ids("org.freedesktop.DBus.Error.ServiceUnknown: The name org.freedesktop.secrets was not provided"), vec!["keyring"]);
        // Offered only where Bubblewrap can do it (0.10+, overlays).
        let expected: Vec<&str> = if sam_core::host::bwrap_supports_overlay() {
            vec!["writable-appdir"]
        } else {
            vec![]
        };
        assert_eq!(
            ids("touch: cannot touch '/opt/app/settings.ini': Read-only file system"),
            expected
        );
        assert_eq!(
            ids("/lib/libc.so.6: version `GLIBC_2.99' not found"),
            vec!["glibc"]
        );
        // A bundled library too old for a system library that needs it
        // (regression: ImHex bundles libsystemd 249, the system's libmount
        // needs 251, and SAM had no step for it).
        let imhex = "/opt/app/usr/bin/imhex: /opt/app/usr/bin/../lib/libsystemd.so.0: version `LIBSYSTEMD_251' not found (required by /usr/lib/libmount.so.1)";
        let found = analyze(imhex, &p, None);
        assert_eq!(
            found.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            vec!["system-library"]
        );
        assert!(
            matches!(&found[0].action, FixAction::Add { key, value } if key == "advanced.system_libraries" && value == "libsystemd.so.0")
        );
        assert!(found[0].explanation.contains("libmount.so.1"));
        assert_eq!(ids("ERROR eframe::native::run] Exiting because of error: WGPU error: Failed to create surface for any enabled backend"), vec!["gpu"]);
        assert!(ids("all good").is_empty());
        assert_eq!(analyze("", &p, Some(11))[0].id, "crash");
        // Nested namespaces are off by default: allowing them comes first;
        // when they are on already, starting without Chromium's sandbox, but
        // only where this computer blocks it (audit A1).
        let zygote = |p: &PermissionSet, blocked: bool| {
            analyze_with("Zygote process exited prematurely", p, None, blocked)
                .into_iter()
                .map(|s| s.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(zygote(&p, true), vec!["userns"]);
        let mut nested = p.clone();
        nested.advanced.allow_userns = true;
        assert_eq!(zygote(&nested, true), vec!["chromium-no-sandbox"]);
        assert!(zygote(&nested, false).is_empty(), "not where it works");
    }

    /// The repair ladder leaves out steps already applied and steps that would change nothing.
    #[test]
    fn ladder_skips_applied_and_noop_steps() {
        let mut e = AppEntry::default();
        e.profile.permissions = PermissionSet::strict_gui();
        let cfg = Config::default();
        let tmp = tempfile::tempdir().unwrap();
        let ids: Vec<String> = ladder(&e, &cfg, &Paths::rooted(tmp.path()))
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(ids.first().map(String::as_str), Some("full-usr"));
        assert!(
            ids.contains(&"userns".to_string()),
            "offered: nested namespaces are off by default"
        );
        e.profile.permissions.advanced.allow_userns = true;
        assert!(
            !ladder(&e, &cfg, &Paths::rooted(tmp.path()))
                .iter()
                .any(|s| s.id == "userns"),
            "not offered once allowed"
        );
        e.profile.permissions.advanced.allow_userns = false;
        e.repairs_applied.push("full-usr".into());
        assert_ne!(
            ladder(&e, &cfg, &Paths::rooted(tmp.path()))[0].id,
            "full-usr"
        );
    }

    /// A step on trial is kept when the next start works and undone when it
    /// fails: exactly what it changed is put back, it is remembered as
    /// tried and not offered again; a step from before (not on trial) is
    /// never touched (owner decision of 2026-11-18; night run N3).
    #[test]
    fn a_repair_step_that_did_not_help_is_undone() {
        let mut e = AppEntry::default();
        e.profile.permissions = PermissionSet::strict_gui();
        let step = |id: &str, key: &str, value: &str, on_trial: bool, e: &AppEntry| {
            sam_core::model::AppliedRepair {
                step: Some(s(id, id, "", set(key, value), RiskLevel::Medium)),
                before: vec![(key.to_string(), e.profile.permissions.get_key(key).unwrap())],
                added: None,
                on_trial,
            }
        };
        // An older step that worked before, and two new ones on trial.
        let old = step("gpu", "devices.gpu", "true", false, &e);
        e.profile.permissions.devices.gpu = true;
        let x11 = step("x11", "display.x11", "true", true, &e);
        e.profile.permissions.display.x11 = true;
        let usr = step("full-usr", "advanced.host_runtime", "full", true, &e);
        e.profile.permissions.advanced.host_runtime = HostRuntime::Full;
        e.applied_repairs = vec![old, x11, usr];
        e.repairs_applied = vec!["gpu".into(), "x11".into(), "full-usr".into()];
        e.repair_backup = Some(Default::default());

        let mut worked = e.clone();
        assert!(judge_trials(&mut worked, true).is_empty());
        assert!(
            worked.applied_repairs.iter().all(|r| !r.on_trial),
            "kept, judged"
        );
        assert!(worked.profile.permissions.display.x11);

        let undone = judge_trials(&mut e, false);
        assert_eq!(undone, ["full-usr", "x11"]);
        let p = &e.profile.permissions;
        assert!(!p.display.x11 && p.advanced.host_runtime == HostRuntime::Minimal);
        assert!(p.devices.gpu, "the older step stays");
        assert_eq!(e.repairs_applied, ["gpu"]);
        assert_eq!(e.tried_repairs, ["full-usr", "x11"]);
        let tmp = tempfile::tempdir().unwrap();
        let ids: Vec<String> =
            ladder_for(&e, &Config::default(), &Paths::rooted(tmp.path()), false)
                .into_iter()
                .map(|s| s.id)
                .collect();
        assert!(
            !ids.contains(&"x11".to_string()) && !ids.contains(&"full-usr".to_string()),
            "{ids:?}"
        );
        assert!(
            judge_trials(&mut e, false).is_empty(),
            "nothing left on trial"
        );
    }

    /// Steps that add a list entry or an argument are undone by removing
    /// exactly that, and a tried step is not offered again as a first-run
    /// hint either.
    #[test]
    fn steps_that_add_are_undone_and_tried_steps_are_no_hints() {
        let mut e = AppEntry::default();
        e.profile.permissions = PermissionSet::strict_gui();
        e.profile.permissions.filesystem.custom_read = vec!["/data/keep".into()];
        e.profile
            .permissions
            .filesystem
            .custom_read
            .push("/data/added".into());
        e.profile.args = vec!["--keep".into(), "--no-sandbox".into()];
        e.applied_repairs = vec![
            sam_core::model::AppliedRepair {
                step: Some(s(
                    "dir",
                    "dir",
                    "",
                    FixAction::Add {
                        key: "filesystem.custom_read".into(),
                        value: "/data/added".into(),
                    },
                    RiskLevel::Medium,
                )),
                added: Some("/data/added".into()),
                on_trial: true,
                ..Default::default()
            },
            sam_core::model::AppliedRepair {
                step: Some(no_sandbox()),
                added: Some("--no-sandbox".into()),
                on_trial: true,
                ..Default::default()
            },
        ];
        assert_eq!(judge_trials(&mut e, false).len(), 2);
        assert_eq!(e.profile.permissions.filesystem.custom_read, ["/data/keep"]);
        assert_eq!(e.profile.args, ["--keep"]);

        // The gpu hint: offered for an app with programs but no graphics
        // libraries, not once tried.
        let mut h = AppEntry::default();
        h.profile.permissions = PermissionSet::strict_gui();
        h.detection = Some(sam_core::DependencyReport {
            elf_count: 1,
            ..Default::default()
        });
        let hint = |h: &AppEntry| first_run_hints(h).iter().any(|s| s.id == "gpu");
        assert!(hint(&h), "{:?}", first_run_hints(&h));
        h.tried_repairs.push("gpu".into());
        assert!(!hint(&h));
    }

    /// Starting without Chromium's own sandbox is offered only where this
    /// computer blocks it (audit A1), compatibility mode is Dangerous and
    /// says it is a way out (D-H5), and "never offer compatibility mode"
    /// keeps it out (U-M9).
    #[test]
    fn the_ladder_offers_only_what_can_help_and_says_what_it_costs() {
        let mut e = AppEntry::default();
        e.profile.permissions = PermissionSet::strict_gui();
        e.detection = Some(sam_core::DependencyReport {
            requirements: sam_core::model::Requirements {
                electron: true,
                ..Default::default()
            },
            ..Default::default()
        });
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let ids = |cfg: &Config, blocked: bool| -> Vec<String> {
            ladder_for(&e, cfg, &paths, blocked)
                .into_iter()
                .map(|s| s.id)
                .collect()
        };
        let cfg = Config::default();
        assert!(!ids(&cfg, false).contains(&"chromium-no-sandbox".to_string()));
        assert!(ids(&cfg, true).contains(&"chromium-no-sandbox".to_string()));
        let compat = ladder_for(&e, &cfg, &paths, false)
            .into_iter()
            .find(|s| s.id == "compat")
            .expect("offered");
        assert_eq!(compat.risk, RiskLevel::Dangerous);
        assert!(
            compat.explanation.contains("way out"),
            "{}",
            compat.explanation
        );
        let mut never = Config::default();
        never.compatibility.behavior = sam_core::config::CompatBehavior::Never;
        assert!(!ids(&never, false).contains(&"compat".to_string()));
        assert!(no_sandbox().explanation.contains("kept apart"));
        // The three settings that block Chromium's own sandbox.
        assert!(blocked_by(Some("0"), None, None));
        assert!(blocked_by(None, Some("0"), None));
        assert!(blocked_by(None, None, Some("1")));
        assert!(!blocked_by(Some("63000"), Some("1"), Some("0")));
        assert!(!blocked_by(None, None, None));
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
        let offered = ladder(&e, &cfg, &good)
            .iter()
            .any(|s| s.id == "writable-appdir");
        assert_eq!(
            offered,
            sam_core::host::overlay_works_in(&good.overlays_dir())
        );
        // A file where the overlay folder belongs: no overlay can work there.
        let bad = Paths::rooted(&tmp.path().join("bad"));
        std::fs::create_dir_all(&bad.data_dir).unwrap();
        std::fs::write(bad.overlays_dir(), "not a folder").unwrap();
        assert!(!ladder(&e, &cfg, &bad)
            .iter()
            .any(|s| s.id == "writable-appdir"));
    }
}
