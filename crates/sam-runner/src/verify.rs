// SPDX-License-Identifier: GPL-3.0-or-later
//! The sandbox check: does the sandbox SAM builds for an app really give it
//! exactly what its settings say? SAM starts the app's sandbox with a probe
//! instead of the app (same command, same kernel layers, same D-Bus filter,
//! same network) and compares what the probe sees with what the settings
//! and this computer lead us to expect.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use sam_core::config::Config;
use sam_core::permissions::{Access as Perm, DbusMode, NetworkMode, PermissionSet};
use sam_core::{AppEntry, CheckRecord, HostInfo, Paths};

use crate::launch::{prepare, LaunchOptions};
use crate::probe::{self, Access, ProbeCheck, ProbePlan, ProbeReport, ProbeTest};

/// Report plus the record stored with the app.
pub struct Outcome {
    pub report: ProbeReport,
    pub record: CheckRecord,
}

fn c(id: &str, group: &str, title: impl Into<String>, test: ProbeTest) -> ProbeCheck {
    ProbeCheck { id: id.into(), group: group.into(), title: title.into(), test }
}

fn level(a: Perm) -> Access {
    match a {
        Perm::None => Access::Hidden,
        Perm::Ro => Access::ReadOnly,
        Perm::Rw => Access::ReadWrite,
    }
}

fn rank(a: Access) -> u8 {
    match a {
        Access::Hidden => 0,
        Access::ReadOnly => 1,
        Access::ReadWrite => 2,
    }
}

/// The checks for an app, with what each should find.
pub fn plan(p: &PermissionSet, cfg: &Config, host: &HostInfo) -> ProbePlan {
    let mut v: Vec<ProbeCheck> = Vec::new();
    let fs = &p.filesystem;
    let home_level = if fs.home { level(fs.home_access) } else { Access::Hidden };

    // Files.
    if fs.home {
        v.push(c("home", "Files", "Your home folder", ProbeTest::Folder { path: host.home.clone(), host_id: probe::identity(&host.home), expect: home_level }));
    } else {
        v.push(c("home", "Files", "Your home folder stays private", ProbeTest::Folder { path: host.home.clone(), host_id: probe::identity(&host.home), expect: Access::Hidden }));
    }
    for (key, title, a) in [
        ("documents", "Documents", fs.documents),
        ("downloads", "Downloads", fs.downloads),
        ("pictures", "Pictures", fs.pictures),
        ("music", "Music", fs.music),
        ("videos", "Videos", fs.videos),
        ("desktop", "Desktop folder", fs.desktop),
    ] {
        let Some(path) = host.xdg_dir(key) else { continue };
        if !path.is_dir() || path == host.home {
            continue;
        }
        let want = if rank(home_level) > rank(level(a)) { home_level } else { level(a) };
        v.push(c(key, "Files", title, ProbeTest::Folder { path: path.to_path_buf(), host_id: probe::identity(path), expect: want }));
    }
    for (list, want) in [(&fs.custom_read, Access::ReadOnly), (&fs.custom_write, Access::ReadWrite)] {
        for raw in list {
            let path = sam_core::util::expand_home(raw);
            if path.is_dir() {
                let want = if rank(home_level) > rank(want) && path.starts_with(&host.home) { home_level } else { want };
                v.push(c("custom", "Files", format!("Extra folder {}", sam_core::util::tildify(&path)), ProbeTest::Folder { host_id: probe::identity(&path), path, expect: want }));
            }
        }
    }
    for (name, title, granted) in [(".ssh", "SSH keys", fs.ssh), (".gnupg", "GnuPG keys", fs.gnupg)] {
        let path = host.home.join(name);
        if path.is_dir() {
            let want = if fs.home && granted { home_level } else { Access::Hidden };
            v.push(c("keys", "Files", title, ProbeTest::Folder { host_id: probe::identity(&path), path, expect: want }));
        }
    }
    v.push(c("usr", "System", "System files are read-only", ProbeTest::NotWritable { path: "/usr".into() }));
    v.push(c("etc", "System", "System settings are read-only", ProbeTest::NotWritable { path: "/etc".into() }));
    v.push(c("shadow", "System", "Password hashes are unreadable", ProbeTest::Unreadable { path: "/etc/shadow".into() }));
    v.push(c("tmp", "System", "Private /tmp", ProbeTest::Folder { path: "/tmp".into(), host_id: probe::identity(Path::new("/tmp")), expect: Access::Hidden }));
    v.push(c("shm", "System", "Private shared memory", ProbeTest::Folder { path: "/dev/shm".into(), host_id: probe::identity(Path::new("/dev/shm")), expect: Access::Hidden }));

    // Network.
    match p.network.mode {
        NetworkMode::Full => {
            if probe::has_default_route() {
                v.push(c("net", "Network", "Internet connection", ProbeTest::Network));
            }
        }
        NetworkMode::Localhost => {
            v.push(c("net", "Network", "No internet", ProbeTest::NoNetwork));
            let listening = probe::listening_ports();
            let granted = p.network.valid_host_ports();
            for port in granted.iter().filter(|p| listening.contains(p)) {
                v.push(c("port", "Network", format!("Local service on port {port} reachable"), ProbeTest::LocalPort { port: *port, expect: true }));
            }
            if let Some(other) = listening.iter().find(|p| !granted.contains(p)) {
                v.push(c("port", "Network", format!("Other local services hidden (port {other})"), ProbeTest::LocalPort { port: *other, expect: false }));
            }
        }
        _ => v.push(c("net", "Network", "No network", ProbeTest::NoNetwork)),
    }

    // Display and sound.
    let s = &host.sockets;
    v.push(c("wayland", "Display", "Wayland", ProbeTest::Wayland { expect: p.display.wayland && s.wayland.is_some() }));
    v.push(c("x11", "Display", "X11 / XWayland", ProbeTest::X11 { expect: p.display.x11 && s.x11.is_some() }));
    v.push(c("audio", "Sound and devices", "Sound", ProbeTest::Audio { expect: p.audio.enabled && s.pulse.is_some() }));
    if s.pipewire.is_some() {
        let label = if p.audio.pipewire { "Direct PipeWire access" } else { "Cameras and screen streams through PipeWire stay hidden" };
        v.push(c("pipewire", "Sound and devices", label, ProbeTest::PipeWire { expect: p.audio.pipewire }));
    }

    // Devices.
    let dev = |path: &str| Path::new(path).exists();
    v.push(c("gpu", "Sound and devices", "GPU", ProbeTest::Present { path: "/dev/dri".into(), expect: p.devices.gpu && dev("/dev/dri") }));
    if let Some(cam) = list_dev("/dev", "video").into_iter().next() {
        v.push(c("webcam", "Sound and devices", "Webcam", ProbeTest::Present { path: cam, expect: p.devices.webcam }));
    }
    let events = list_dev("/dev/input", "event");
    let pads = sam_sandbox::gamepad_nodes(Path::new("/dev/input"), Path::new("/run/udev/data"));
    if p.devices.input {
        if let Some(e) = events.first() {
            v.push(c("input", "Sound and devices", "All input devices", ProbeTest::Present { path: e.clone(), expect: true }));
        }
    } else {
        if p.devices.gamepads {
            for pad in &pads {
                v.push(c("gamepad", "Sound and devices", format!("Game controller {}", pad.display()), ProbeTest::Present { path: pad.clone(), expect: true }));
            }
        }
        if let Some(e) = events.iter().find(|e| !pads.contains(e)) {
            v.push(c("input", "Sound and devices", "Keyboards and mice stay hidden", ProbeTest::Present { path: e.clone(), expect: false }));
        }
    }
    if dev("/dev/bus/usb") {
        v.push(c("usb", "Sound and devices", "Raw USB", ProbeTest::Present { path: "/dev/bus/usb".into(), expect: p.devices.usb }));
    }
    if dev("/dev/snd") {
        v.push(c("alsa", "Sound and devices", "Raw ALSA devices", ProbeTest::Present { path: "/dev/snd".into(), expect: p.audio.alsa_raw }));
    }

    // D-Bus.
    let host_bus = s.dbus_session_address.clone().filter(|a| a.contains("unix:path="));
    let on_host = |name: &str| host_bus.as_deref().is_some_and(|a| crate::dbus_check::name_reachable(a, name, Duration::from_secs(2)).unwrap_or(false));
    let proxy = host.tools.xdg_dbus_proxy.is_some();
    let bus_mode = p.dbus.session.mode;
    let bus_on = host_bus.is_some() && (bus_mode == DbusMode::Full || (bus_mode == DbusMode::Filtered && proxy));
    v.push(c("bus", "D-Bus", "Session bus", ProbeTest::SessionBus { expect: bus_on }));
    if bus_on {
        // The desktop portal always passes the filter (limited to safe
        // functions, see permissions::portal_interfaces).
        let allowed = |n: &str| {
            bus_mode == DbusMode::Full
                || n == "org.freedesktop.portal.Desktop"
                || p.effective_session_bus().allow.iter().any(|a| a == n || a.strip_suffix(".*").is_some_and(|pre| n.starts_with(pre)))
        };
        for (name, title) in [
            ("org.freedesktop.portal.Desktop", "Desktop portal"),
            ("org.freedesktop.systemd1", "Service manager (systemd)"),
            ("org.freedesktop.secrets", "Passwords and keyring"),
            ("org.kde.KWin", "Window manager (KWin)"),
        ] {
            if on_host(name) {
                let want = allowed(name) && !p.dbus.session.deny.iter().any(|d| d == name);
                v.push(c("busname", "D-Bus", if want { format!("{title} reachable") } else { format!("{title} hidden") }, ProbeTest::BusName { name: name.into(), expect: want }));
            }
        }
    }
    if s.dbus_system.is_some() {
        v.push(c("sysbus", "D-Bus", "System bus", ProbeTest::Present { path: "/run/dbus/system_bus_socket".into(), expect: p.dbus.system.mode != DbusMode::None }));
    }

    // Sockets and environment.
    let agent = p.sockets.ssh_agent && s.ssh_agent.is_some();
    v.push(c("ssh-agent", "Sockets and environment", "SSH agent", ProbeTest::Env { name: "SSH_AUTH_SOCK".into(), expect: agent.then(|| format!("/run/user/{}/ssh-agent.sock", host.uid)) }));
    if s.cups.is_some() {
        v.push(c("cups", "Sockets and environment", "Printing", ProbeTest::Present { path: "/run/cups/cups.sock".into(), expect: p.sockets.cups }));
    }
    for raw in &p.sockets.custom {
        let path = sam_core::util::expand_home(raw);
        if sam_sandbox::is_socket(&path) {
            v.push(c("socket", "Sockets and environment", format!("Socket {}", sam_core::util::tildify(&path)), ProbeTest::Present { path, expect: true }));
        }
    }
    for name in &p.environment.passthrough {
        if let Ok(val) = std::env::var(name) {
            v.push(c("env", "Sockets and environment", format!("Variable {name} passed through"), ProbeTest::Env { name: name.clone(), expect: Some(val) }));
        }
    }
    for (name, val) in &p.environment.set {
        let valid = name.chars().next().is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_') && name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if valid {
            v.push(c("env", "Sockets and environment", format!("Variable {name}"), ProbeTest::Env { name: name.clone(), expect: Some(val.clone()) }));
        }
    }

    // Security layers.
    let landlock = p.advanced.landlock.unwrap_or(cfg.security.experimental_landlock) && host.landlock_abi.is_some();
    let strict = p.advanced.seccomp_strict && cfg.security.experimental_seccomp;
    let filter = (cfg.security.baseline_seccomp && p.advanced.seccomp_baseline) || strict;
    v.push(c("landlock", "Security", "Landlock write protection", ProbeTest::Landlock { expect: landlock }));
    v.push(c("seccomp", "Security", "Syscall filter", ProbeTest::SyscallFilter { active: filter }));
    v.push(c("nnp", "Security", "Cannot gain privileges", ProbeTest::NoNewPrivileges));
    v.push(c("caps", "Security", "No special capabilities", ProbeTest::NoCapabilities));
    v.push(c("pidns", "Security", "Own process list", ProbeTest::OwnProcesses));
    v.push(c("userns", "Security", if p.advanced.allow_userns { "Nested sandboxes allowed" } else { "Nested sandboxes blocked" }, ProbeTest::UserNamespaces { blocked: !p.advanced.allow_userns }));
    ProbePlan { checks: v }
}

fn list_dev(dir: &str, prefix: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(prefix)).map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// What a check result applies to: the settings, SAM's version, the
/// relevant preferences and what this computer offers. A passing check with
/// the same key needs no repeat.
pub fn check_key(app: &AppEntry, cfg: &Config, host: &HostInfo) -> String {
    let host_state = serde_json::json!({
        "sockets": &host.sockets,
        "landlock": host.landlock_abi,
        "proxy": host.tools.xdg_dbus_proxy.is_some(),
        "gpu": host.gpu_devices,
    });
    let data = serde_json::json!({
        "sam": env!("CARGO_PKG_VERSION"),
        "profile": &app.profile,
        "security": &cfg.security,
        "host": host_state,
    });
    sam_intake::fingerprint::short_hash(data.to_string().as_bytes())
}

/// Runs the sandbox check for an app.
pub fn verify(app: &AppEntry, cfg: &Config, paths: &Paths, host: &HostInfo) -> Result<Outcome> {
    let plan = plan(&app.profile.permissions, cfg, host);
    let prepared = prepare(app, &LaunchOptions { probe: Some(plan), quiet: true, ..Default::default() }, cfg, paths, host)?;
    if prepared.context.helper.is_none() {
        bail!("SAM's sandbox helper (sam-jail-run) was not found, so the sandbox cannot be checked");
    }
    let cmd = &prepared.command;
    let mut command = Command::new(&cmd.program);
    command.args(&cmd.args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).current_dir(&host.home);
    if cmd.clear_env {
        command.env_clear();
    }
    for (k, v) in &cmd.env {
        command.env(k, v);
    }
    let mut child = command.spawn().with_context(|| format!("starting {}", cmd.program.display()))?;
    let (mut out, mut err) = (child.stdout.take().context("no stdout")?, child.stderr.take().context("no stderr")?);
    let out_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("the sandbox check did not finish within 30 seconds");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let stdout = out_t.join().unwrap_or_default();
    let stderr = err_t.join().unwrap_or_default();
    drop(prepared);
    let json = stdout
        .lines()
        .find_map(|l| l.strip_prefix(probe::REPORT_MARKER))
        .with_context(|| format!("the sandbox did not start: {}", stderr.lines().take(3).collect::<Vec<_>>().join(" ")))?;
    let report: ProbeReport = serde_json::from_str(json).context("reading the check report")?;
    let record = CheckRecord {
        at: sam_core::util::now(),
        key: check_key(app, cfg, host),
        passed: report.passed(),
        failed: report.failed().iter().map(|r| r.title.clone()).collect(),
        skipped: report.results.iter().filter(|r| r.ok.is_none()).count(),
    };
    Ok(Outcome { report, record })
}
