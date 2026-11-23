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

/// One check, with its group and title in the user's language (a title
/// that arrives through a variable is marked with n_ where it is written).
fn c(id: &str, group: &str, title: impl Into<String>, test: ProbeTest) -> ProbeCheck {
    ProbeCheck {
        id: id.into(),
        group: sam_core::i18n::tr(group),
        title: sam_core::i18n::tr(&title.into()),
        test,
    }
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
    let home_level = if fs.home {
        level(fs.home_access)
    } else {
        Access::Hidden
    };

    // Files.
    if fs.home {
        v.push(c(
            "home",
            "Files",
            "Your home folder",
            ProbeTest::Folder {
                path: host.home.clone(),
                host_id: probe::identity(&host.home),
                expect: home_level,
            },
        ));
    } else {
        v.push(c(
            "home",
            "Files",
            "Your home folder stays private",
            ProbeTest::Folder {
                path: host.home.clone(),
                host_id: probe::identity(&host.home),
                expect: Access::Hidden,
            },
        ));
    }
    for (key, title, a) in [
        ("documents", "Documents", fs.documents),
        ("downloads", "Downloads", fs.downloads),
        ("pictures", "Pictures", fs.pictures),
        ("music", "Music", fs.music),
        ("videos", "Videos", fs.videos),
        ("desktop", "Desktop folder", fs.desktop),
    ] {
        let Some(path) = host.xdg_dir(key) else {
            continue;
        };
        if !path.is_dir() || path == host.home {
            continue;
        }
        let want = if rank(home_level) > rank(level(a)) {
            home_level
        } else {
            level(a)
        };
        v.push(c(
            key,
            "Files",
            title,
            ProbeTest::Folder {
                path: path.to_path_buf(),
                host_id: probe::identity(path),
                expect: want,
            },
        ));
    }
    for (list, want) in [
        (&fs.custom_read, Access::ReadOnly),
        (&fs.custom_write, Access::ReadWrite),
    ] {
        for raw in list {
            let path = sam_core::util::expand_home(raw);
            if path.is_dir() {
                let want = if rank(home_level) > rank(want) && path.starts_with(&host.home) {
                    home_level
                } else {
                    want
                };
                v.push(c(
                    "custom",
                    "Files",
                    format!("Extra folder {}", sam_core::util::tildify(&path)),
                    ProbeTest::Folder {
                        host_id: probe::identity(&path),
                        path,
                        expect: want,
                    },
                ));
            }
        }
    }
    for (name, title, granted) in [
        (".ssh", "SSH keys", fs.ssh),
        (".gnupg", "GnuPG keys", fs.gnupg),
    ] {
        let path = host.home.join(name);
        if path.is_dir() {
            let want = if fs.home && granted {
                home_level
            } else {
                Access::Hidden
            };
            v.push(c(
                "keys",
                "Files",
                title,
                ProbeTest::Folder {
                    host_id: probe::identity(&path),
                    path,
                    expect: want,
                },
            ));
        }
    }
    // With full home access, the places that would start code later stay
    // closed (SAM mounts them read-only).
    if fs.home {
        for (rel, title) in [
            (
                ".config/autostart",
                sam_core::i18n::n_("Autostart entries cannot be created"),
            ),
            (
                ".local/share/applications",
                sam_core::i18n::n_("Menu entries cannot be created"),
            ),
        ] {
            let path = host.home.join(rel);
            if path.is_dir() {
                v.push(c(
                    "persist",
                    "Files",
                    title,
                    ProbeTest::NotWritable { path },
                ));
            }
        }
    }
    v.push(c(
        "usr",
        "System",
        "System files are read-only",
        ProbeTest::NotWritable {
            path: "/usr".into(),
        },
    ));
    v.push(c(
        "etc",
        "System",
        "System settings are read-only",
        ProbeTest::NotWritable {
            path: "/etc".into(),
        },
    ));
    v.push(c(
        "shadow",
        "System",
        "Password hashes are unreadable",
        ProbeTest::Unreadable {
            path: "/etc/shadow".into(),
        },
    ));
    v.push(c(
        "tmp",
        "System",
        "Private /tmp",
        ProbeTest::Folder {
            path: "/tmp".into(),
            host_id: probe::identity(Path::new("/tmp")),
            expect: Access::Hidden,
        },
    ));
    v.push(c(
        "shm",
        "System",
        "Private shared memory",
        ProbeTest::Folder {
            path: "/dev/shm".into(),
            host_id: probe::identity(Path::new("/dev/shm")),
            expect: Access::Hidden,
        },
    ));

    // Network.
    match p.network.mode {
        NetworkMode::Full => {
            if probe::has_default_route() {
                v.push(c(
                    "net",
                    "Network",
                    "Internet connection",
                    ProbeTest::Network,
                ));
            }
        }
        NetworkMode::Localhost => {
            v.push(c("net", "Network", "No internet", ProbeTest::NoNetwork));
            let listening = probe::listening_ports();
            let granted = p.network.valid_host_ports();
            for port in granted.iter().filter(|p| listening.contains(p)) {
                v.push(c(
                    "port",
                    "Network",
                    sam_core::i18n::trf(
                        "Local service on port {port} reachable",
                        &[("port", &port)],
                    ),
                    ProbeTest::LocalPort {
                        port: *port,
                        expect: true,
                    },
                ));
            }
            if let Some(other) = listening.iter().find(|p| !granted.contains(p)) {
                v.push(c(
                    "port",
                    "Network",
                    sam_core::i18n::trf(
                        "Other local services hidden (port {other})",
                        &[("other", &other)],
                    ),
                    ProbeTest::LocalPort {
                        port: *other,
                        expect: false,
                    },
                ));
            }
        }
        _ => v.push(c("net", "Network", "No network", ProbeTest::NoNetwork)),
    }

    // Display and sound.
    let s = &host.sockets;
    v.push(c(
        "wayland",
        "Display",
        "Wayland",
        ProbeTest::Wayland {
            expect: p.display.wayland && s.wayland.is_some(),
        },
    ));
    v.push(c(
        "x11",
        "Display",
        "X11 / XWayland",
        ProbeTest::X11 {
            expect: p.display.x11 && s.x11.is_some(),
        },
    ));
    // The X server also listens on an abstract socket of the same name,
    // which needs no file: an app that shares the host's network can
    // reach it with X11 off unless Landlock fences abstract sockets (Linux
    // 6.12; review K-1). The check tries to connect.
    if let Some(x) = s.x11.as_ref().filter(|_| !p.display.x11) {
        v.push(c(
            "x11-abstract",
            "Display",
            "X server outside the sandbox unreachable",
            ProbeTest::AbstractSocket {
                name: x.display().to_string(),
                expect: false,
            },
        ));
    }
    v.push(c(
        "audio",
        "Sound and devices",
        "Sound",
        ProbeTest::Audio {
            expect: crate::sound_relay::sound_reaches_app(&p.audio, host),
        },
    ));
    if s.pipewire.is_some() {
        let label = if p.audio.pipewire {
            sam_core::i18n::n_("Direct PipeWire access")
        } else {
            sam_core::i18n::n_("Cameras and screen streams through PipeWire stay hidden")
        };
        v.push(c(
            "pipewire",
            "Sound and devices",
            label,
            ProbeTest::PipeWire {
                expect: p.audio.pipewire,
            },
        ));
    }

    // Devices.
    let dev = |path: &str| Path::new(path).exists();
    v.push(c(
        "gpu",
        "Sound and devices",
        "GPU",
        ProbeTest::Present {
            path: "/dev/dri".into(),
            expect: p.devices.gpu && dev("/dev/dri"),
        },
    ));
    if let Some(cam) = list_dev("/dev", "video").into_iter().next() {
        v.push(c(
            "webcam",
            "Sound and devices",
            "Webcam",
            ProbeTest::Present {
                path: cam,
                expect: p.devices.webcam,
            },
        ));
    }
    let events = list_dev("/dev/input", "event");
    let pads = sam_sandbox::gamepad_nodes(Path::new("/dev/input"), Path::new("/run/udev/data"));
    if p.devices.input {
        if let Some(e) = events.first() {
            v.push(c(
                "input",
                "Sound and devices",
                "All input devices",
                ProbeTest::Present {
                    path: e.clone(),
                    expect: true,
                },
            ));
        }
    } else {
        if p.devices.gamepads {
            for pad in &pads {
                v.push(c(
                    "gamepad",
                    "Sound and devices",
                    format!("Game controller {}", pad.display()),
                    ProbeTest::Present {
                        path: pad.clone(),
                        expect: true,
                    },
                ));
            }
        }
        if let Some(e) = events.iter().find(|e| !pads.contains(e)) {
            v.push(c(
                "input",
                "Sound and devices",
                "Keyboards and mice stay hidden",
                ProbeTest::Present {
                    path: e.clone(),
                    expect: false,
                },
            ));
        }
    }
    if dev("/dev/bus/usb") {
        v.push(c(
            "usb",
            "Sound and devices",
            "Raw USB",
            ProbeTest::Present {
                path: "/dev/bus/usb".into(),
                expect: p.devices.usb,
            },
        ));
    }
    if dev("/dev/snd") {
        v.push(c(
            "alsa",
            "Sound and devices",
            "Raw ALSA devices",
            ProbeTest::Present {
                path: "/dev/snd".into(),
                expect: p.audio.alsa_raw,
            },
        ));
    }

    // D-Bus.
    let host_bus = s
        .dbus_session_address
        .clone()
        .filter(|a| a.contains("unix:path="));
    let on_host = |name: &str| {
        host_bus.as_deref().is_some_and(|a| {
            crate::dbus_check::name_reachable(a, name, Duration::from_secs(2)).unwrap_or(false)
        })
    };
    let proxy = host.tools.xdg_dbus_proxy.is_some();
    let bus_mode = p.dbus.session.mode;
    let bus_on = host_bus.is_some()
        && (bus_mode == DbusMode::Full || (bus_mode == DbusMode::Filtered && proxy));
    v.push(c(
        "bus",
        "D-Bus",
        "Session bus",
        ProbeTest::SessionBus { expect: bus_on },
    ));
    if bus_on {
        // The desktop portal always passes the filter (limited to safe
        // functions, see permissions::portal_interfaces).
        let allowed = |n: &str| {
            bus_mode == DbusMode::Full
                || n == "org.freedesktop.portal.Desktop"
                || p.effective_session_bus()
                    .allow
                    .iter()
                    .any(|a| a == n || a.strip_suffix(".*").is_some_and(|pre| n.starts_with(pre)))
        };
        for (name, title) in [
            (
                "org.freedesktop.portal.Desktop",
                sam_core::i18n::n_("Desktop portal"),
            ),
            (
                "org.freedesktop.systemd1",
                sam_core::i18n::n_("Service manager (systemd)"),
            ),
            (
                "org.freedesktop.secrets",
                sam_core::i18n::n_("Passwords and keyring"),
            ),
            ("org.kde.KWin", sam_core::i18n::n_("Window manager (KWin)")),
        ] {
            if on_host(name) {
                let want = allowed(name) && !p.dbus.session.deny.iter().any(|d| d == name);
                v.push(c(
                    "busname",
                    "D-Bus",
                    if want {
                        format!("{title} reachable")
                    } else {
                        format!("{title} hidden")
                    },
                    ProbeTest::BusName {
                        name: name.into(),
                        expect: want,
                    },
                ));
            }
        }
    }
    // A session bus on an abstract socket (unix:abstract=…) is reachable
    // without its file the same way, past the D-Bus filter (review K-1).
    if bus_mode != DbusMode::Full {
        for name in abstract_bus_names(s.dbus_session_address.as_deref()) {
            v.push(c(
                "bus-abstract",
                "D-Bus",
                "Unfiltered session bus unreachable",
                ProbeTest::AbstractSocket {
                    name,
                    expect: false,
                },
            ));
        }
    }
    if s.dbus_system.is_some() {
        v.push(c(
            "sysbus",
            "D-Bus",
            "System bus",
            ProbeTest::Present {
                path: "/run/dbus/system_bus_socket".into(),
                expect: p.dbus.system.mode != DbusMode::None,
            },
        ));
    }

    // Sockets and environment.
    let agent = p.sockets.ssh_agent && s.ssh_agent.is_some();
    v.push(c(
        "ssh-agent",
        "Sockets and environment",
        "SSH agent",
        ProbeTest::Env {
            name: "SSH_AUTH_SOCK".into(),
            expect: agent.then(|| format!("/run/user/{}/ssh-agent.sock", host.uid)),
        },
    ));
    if s.cups.is_some() {
        v.push(c(
            "cups",
            "Sockets and environment",
            "Printing",
            ProbeTest::Present {
                path: "/run/cups/cups.sock".into(),
                expect: p.sockets.cups,
            },
        ));
    }
    for raw in &p.sockets.custom {
        let path = sam_core::util::expand_home(raw);
        if sam_sandbox::is_socket(&path) {
            v.push(c(
                "socket",
                "Sockets and environment",
                format!("Socket {}", sam_core::util::tildify(&path)),
                ProbeTest::Present { path, expect: true },
            ));
        }
    }
    for name in &p.environment.passthrough {
        if let Ok(val) = std::env::var(name) {
            v.push(c(
                "env",
                "Sockets and environment",
                format!("Variable {name} passed through"),
                ProbeTest::Env {
                    name: name.clone(),
                    expect: Some(val),
                },
            ));
        }
    }
    for (name, val) in &p.environment.set {
        let valid = name
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if valid {
            v.push(c(
                "env",
                "Sockets and environment",
                format!("Variable {name}"),
                ProbeTest::Env {
                    name: name.clone(),
                    expect: Some(val.clone()),
                },
            ));
        }
    }

    // Security layers.
    let landlock = p
        .advanced
        .landlock
        .unwrap_or(cfg.security.experimental_landlock)
        && host.landlock_abi.is_some();
    let strict = p.advanced.seccomp_strict;
    let filter = (cfg.security.baseline_seccomp && p.advanced.seccomp_baseline) || strict;
    v.push(c(
        "landlock",
        "Security",
        "Landlock write protection",
        ProbeTest::Landlock { expect: landlock },
    ));
    v.push(c(
        "seccomp",
        "Security",
        "Syscall filter",
        ProbeTest::SyscallFilter { active: filter },
    ));
    v.push(c(
        "tiocsti",
        "Security",
        "Typing into the terminal is blocked",
        ProbeTest::NoTerminalInjection { active: filter },
    ));
    v.push(c(
        "nnp",
        "Security",
        "Cannot gain privileges",
        ProbeTest::NoNewPrivileges,
    ));
    v.push(c(
        "caps",
        "Security",
        "No special capabilities",
        ProbeTest::NoCapabilities,
    ));
    v.push(c(
        "pidns",
        "Security",
        "Own process list",
        ProbeTest::OwnProcesses,
    ));
    v.push(c(
        "userns",
        "Security",
        if p.advanced.allow_userns {
            sam_core::i18n::n_("Nested sandboxes allowed")
        } else {
            sam_core::i18n::n_("Nested sandboxes blocked")
        },
        ProbeTest::UserNamespaces {
            blocked: !p.advanced.allow_userns,
        },
    ));
    ProbePlan { checks: v }
}

/// The abstract socket names in a D-Bus address (`unix:abstract=NAME`,
/// several addresses separated by `;`), with D-Bus's %XX escapes undone.
fn abstract_bus_names(address: Option<&str>) -> Vec<String> {
    let unescape = |v: &str| -> String {
        let b = v.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            let hex = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            match (b[i], hex) {
                (b'%', Some(x)) => {
                    out.push(x);
                    i += 3;
                }
                (c, _) => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    address
        .unwrap_or_default()
        .split(';')
        .filter_map(|a| a.strip_prefix("unix:"))
        .flat_map(|a| a.split(','))
        .filter_map(|kv| kv.strip_prefix("abstract="))
        .map(unescape)
        .collect()
}

fn list_dev(dir: &str, prefix: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
                .map(|e| e.path())
                .collect()
        })
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
    let prepared = prepare(
        app,
        &LaunchOptions {
            probe: Some(plan),
            quiet: true,
            ..Default::default()
        },
        cfg,
        paths,
        host,
    )?;
    if prepared.context.helper.is_none() {
        bail!("{}", sam_core::i18n::tr("SAM's sandbox helper (sam-jail-run) was not found, so the sandbox cannot be checked"));
    }
    let cmd = &prepared.command;
    let mut command = Command::new(&cmd.program);
    command
        .args(&cmd.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(&host.home);
    if cmd.clear_env {
        command.env_clear();
    }
    for (k, v) in &cmd.env {
        command.env(k, v);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("starting {}", cmd.program.display()))?;
    let (mut out, mut err) = (
        child
            .stdout
            .take()
            .context(sam_core::i18n::tr("no stdout"))?,
        child
            .stderr
            .take()
            .context(sam_core::i18n::tr("no stderr"))?,
    );
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
            bail!(
                "{}",
                sam_core::i18n::tr("the sandbox check did not finish within 30 seconds")
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let stdout = out_t.join().unwrap_or_default();
    let stderr = err_t.join().unwrap_or_default();
    drop(prepared);
    let json = stdout
        .lines()
        .find_map(|l| l.strip_prefix(probe::REPORT_MARKER))
        .with_context(|| {
            sam_core::i18n::trf(
                "the sandbox did not start: {reason}",
                &[(
                    "reason",
                    &stderr.lines().take(3).collect::<Vec<_>>().join(" "),
                )],
            )
        })?;
    let mut report: ProbeReport =
        serde_json::from_str(json).context(sam_core::i18n::tr("reading the check report"))?;
    // The probe inside the sandbox reports fixed English phrases (marked
    // with n_ there); they are translated here, outside, where SAM's
    // language files are.
    for r in &mut report.results {
        r.observed = sam_core::i18n::tr(&r.observed);
    }
    let record = CheckRecord {
        at: sam_core::util::now(),
        key: check_key(app, cfg, host),
        passed: report.passed(),
        failed: report.failed().iter().map(|r| r.title.clone()).collect(),
        skipped: report.results.iter().filter(|r| r.ok.is_none()).count(),
    };
    Ok(Outcome { report, record })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A fixed computer: a real home with Documents, Pictures and ~/.ssh in
    /// a temporary folder, no sockets, no tools (cases add what they need).
    fn host_in(t: &Path) -> HostInfo {
        let mut h = sam_core::sandbox::sample_context().host;
        h.home = t.join("home");
        for d in ["Documents", "Pictures", ".ssh"] {
            fs::create_dir_all(h.home.join(d)).unwrap();
        }
        h.xdg_dirs = [("documents", "Documents"), ("pictures", "Pictures")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), h.home.join(v)))
            .collect();
        h.sockets = Default::default();
        h.tools = Default::default();
        h.landlock_abi = None;
        h
    }

    fn folder(plan: &ProbePlan, title: &str) -> Access {
        match plan
            .checks
            .iter()
            .find(|c| c.title == title)
            .map(|c| &c.test)
        {
            Some(ProbeTest::Folder { expect, .. }) => *expect,
            other => panic!("no folder check {title}: {other:?}"),
        }
    }

    fn test_of<'a>(plan: &'a ProbePlan, id: &str) -> &'a ProbeTest {
        &plan
            .checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check {id}"))
            .test
    }

    /// What the check expects of each folder: the folder's own setting, but
    /// never less than the home shows it (a read-only home shows Documents
    /// read-only even when Documents has no setting; a writable folder in a
    /// read-only home stays writable); keys only with full home and their
    /// own switch; extra folders like the home inside it.
    #[test]
    fn the_check_expects_each_folder_as_its_settings_show_it() {
        let t = tempfile::tempdir().unwrap();
        let h = host_in(t.path());
        let cfg = Config::default();
        let plan_of = |f: &dyn Fn(&mut PermissionSet)| {
            let mut p = PermissionSet::strict_gui();
            f(&mut p);
            plan(&p, &cfg, &h)
        };
        // Private home, Documents read-only.
        let pl = plan_of(&|p| p.filesystem.documents = Perm::Ro);
        assert_eq!(
            folder(&pl, "Your home folder stays private"),
            Access::Hidden
        );
        assert_eq!(folder(&pl, "Documents"), Access::ReadOnly);
        assert_eq!(folder(&pl, "Pictures"), Access::Hidden);
        // Read-only home, Documents read & write, Pictures nothing.
        let pl = plan_of(&|p| {
            p.filesystem.home = true;
            p.filesystem.home_access = Perm::Ro;
            p.filesystem.documents = Perm::Rw;
        });
        assert_eq!(folder(&pl, "Your home folder"), Access::ReadOnly);
        assert_eq!(folder(&pl, "Documents"), Access::ReadWrite);
        assert_eq!(folder(&pl, "Pictures"), Access::ReadOnly);
        // Writable home: every folder writable; keys only with their switch.
        let pl = plan_of(&|p| {
            p.filesystem.home = true;
            p.filesystem.home_access = Perm::Rw;
        });
        assert_eq!(folder(&pl, "Pictures"), Access::ReadWrite);
        assert_eq!(folder(&pl, "SSH keys"), Access::Hidden);
        let pl = plan_of(&|p| {
            p.filesystem.home = true;
            p.filesystem.home_access = Perm::Rw;
            p.filesystem.ssh = true;
        });
        assert_eq!(folder(&pl, "SSH keys"), Access::ReadWrite);
        let pl = plan_of(&|p| p.filesystem.ssh = true);
        assert_eq!(
            folder(&pl, "SSH keys"),
            Access::Hidden,
            "keys need the home too"
        );
        // Extra folders: inside a writable home they are writable, outside it
        // as listed.
        let inside = h.home.join("Documents").to_string_lossy().into_owned();
        let outside = t.path().to_string_lossy().into_owned();
        let pl = plan_of(&|p| {
            p.filesystem.home = true;
            p.filesystem.home_access = Perm::Rw;
            p.filesystem.custom_read = vec![inside.clone(), outside.clone()];
        });
        let extra = |path: &str| {
            folder(
                &pl,
                &format!("Extra folder {}", sam_core::util::tildify(Path::new(path))),
            )
        };
        assert_eq!(extra(&inside), Access::ReadWrite);
        assert_eq!(extra(&outside), Access::ReadOnly);
        // A user folder that is the home itself (unset in user-dirs.dirs) is
        // the home's check, not a folder check of its own.
        let mut h2 = h.clone();
        h2.xdg_dirs.insert("desktop".into(), h2.home.clone());
        let pl = plan(&PermissionSet::strict_gui(), &cfg, &h2);
        assert!(!pl.checks.iter().any(|c| c.title == "Desktop folder"));
        let pl = plan_of(&|p| p.filesystem.custom_write = vec![inside.clone()]);
        assert_eq!(
            folder(
                &pl,
                &format!(
                    "Extra folder {}",
                    sam_core::util::tildify(Path::new(&inside))
                )
            ),
            Access::ReadWrite
        );
    }

    /// Network, display, sound, the session bus, the SSH agent, variables
    /// and the security layers: the check expects each only where both the
    /// setting and this computer provide it.
    #[test]
    fn the_check_expects_the_rest_where_setting_and_computer_allow_it() {
        let t = tempfile::tempdir().unwrap();
        let mut h = host_in(t.path());
        let cfg = Config::default();
        let p = PermissionSet::strict_gui();

        // Network: "This computer only" plans "No internet"; full never "No network".
        let mut q = p.clone();
        q.network.mode = NetworkMode::Localhost;
        assert!(plan(&q, &cfg, &h)
            .checks
            .iter()
            .any(|c| c.id == "net" && c.title == "No internet"));
        q.network.mode = NetworkMode::Full;
        assert!(!matches!(
            plan(&q, &cfg, &h)
                .checks
                .iter()
                .find(|c| c.id == "net")
                .map(|c| &c.test),
            Some(ProbeTest::NoNetwork)
        ));
        q.network.mode = NetworkMode::None;
        assert!(matches!(
            test_of(&plan(&q, &cfg, &h), "net"),
            ProbeTest::NoNetwork
        ));

        // Display and sound: only setting and socket together.
        let mut q = p.clone();
        q.display.wayland = true;
        q.display.x11 = true;
        q.audio.enabled = true;
        let expects = |q: &PermissionSet, h: &HostInfo| {
            let pl = plan(q, &cfg, h);
            let w = matches!(test_of(&pl, "wayland"), ProbeTest::Wayland { expect: true });
            let x = matches!(test_of(&pl, "x11"), ProbeTest::X11 { expect: true });
            let a = matches!(test_of(&pl, "audio"), ProbeTest::Audio { expect: true });
            (w, x, a)
        };
        assert_eq!(
            expects(&q, &h),
            (false, false, false),
            "no sockets on this computer"
        );
        h.sockets.wayland = Some("/run/user/1000/wayland-0".into());
        h.sockets.x11 = Some("/tmp/.X11-unix/X0".into());
        h.sockets.pulse = Some("/run/user/1000/pulse/native".into());
        assert_eq!(
            expects(&q, &h),
            (true, true, false),
            "PulseAudio without PipeWire: no relay, so no sound (audit S-F1)"
        );
        q.audio.direct = true;
        assert_eq!(expects(&q, &h), (true, true, true), "allowed without relay");
        q.audio.direct = false;
        h.sockets.pipewire = Some("/run/user/1000/pipewire-0".into());
        h.tools.pipewire = Some(sam_core::host::Tool {
            path: "/usr/bin/pipewire".into(),
            version: None,
        });
        h.tools.bwrap = Some(sam_core::host::Tool {
            path: "/usr/bin/bwrap".into(),
            version: None,
        });
        assert_eq!(expects(&q, &h), (true, true, true), "through the relay");
        let mut none = p.clone();
        none.display.wayland = false; // a GUI profile has Wayland on
        none.display.x11 = false;
        none.audio.enabled = false;
        assert_eq!(
            expects(&none, &h),
            (false, false, false),
            "sockets but no setting"
        );

        // Session bus: a real socket address, and full access or the filter
        // with its proxy installed.
        let bus = |q: &PermissionSet, h: &HostInfo| {
            matches!(
                test_of(&plan(q, &cfg, h), "bus"),
                ProbeTest::SessionBus { expect: true }
            )
        };
        let mut q = p.clone();
        q.dbus.session.mode = DbusMode::Full;
        assert!(!bus(&q, &h), "no bus address");
        h.sockets.dbus_session_address = Some("unix:abstract=/tmp/dbus-x".into());
        assert!(!bus(&q, &h), "an abstract socket is not passed on");
        h.sockets.dbus_session_address =
            Some(format!("unix:path={}", t.path().join("no-bus").display()));
        assert!(bus(&q, &h), "full access");
        q.dbus.session.mode = DbusMode::Filtered;
        assert!(!bus(&q, &h), "filter without its proxy");
        h.tools.xdg_dbus_proxy = Some(sam_core::host::Tool {
            path: "/usr/bin/xdg-dbus-proxy".into(),
            version: None,
        });
        assert!(bus(&q, &h), "filter with its proxy");
        q.dbus.session.mode = DbusMode::None;
        assert!(!bus(&q, &h), "no bus");

        // SSH agent: setting and agent together.
        let agent = |q: &PermissionSet, h: &HostInfo| {
            matches!(
                test_of(&plan(q, &cfg, h), "ssh-agent"),
                ProbeTest::Env {
                    expect: Some(_),
                    ..
                }
            )
        };
        let mut q = p.clone();
        q.sockets.ssh_agent = true;
        assert!(!agent(&q, &h), "no agent on this computer");
        h.sockets.ssh_agent = Some("/run/user/1000/ssh-agent".into());
        assert!(agent(&q, &h));
        assert!(!agent(&p, &h));

        // Variables: only valid names are checked.
        let mut q = p.clone();
        for n in ["_OK", "Ok1", "1BAD", "BAD-NAME", ""] {
            q.environment.set.insert(n.to_string(), "v".into());
        }
        let pl = plan(&q, &cfg, &h);
        let named: Vec<_> = pl
            .checks
            .iter()
            .filter(|c| c.id == "env")
            .map(|c| c.title.clone())
            .collect();
        assert_eq!(named, ["Variable Ok1", "Variable _OK"]);

        // The GPU: setting and device together (whatever this computer has).
        let gpu = |q: &PermissionSet| match test_of(&plan(q, &cfg, &h), "gpu") {
            ProbeTest::Present { expect, .. } => *expect,
            t => panic!("{t:?}"),
        };
        let mut q = p.clone();
        q.devices.gpu = false;
        assert!(!gpu(&q));
        q.devices.gpu = true;
        assert_eq!(gpu(&q), Path::new("/dev/dri").exists());
        // The system bus, where this computer has one.
        h.sockets.dbus_system = Some("/run/dbus/system_bus_socket".into());
        let sysbus = |q: &PermissionSet| {
            matches!(
                test_of(&plan(q, &cfg, &h), "sysbus"),
                ProbeTest::Present { expect: true, .. }
            )
        };
        let mut q = p.clone();
        q.dbus.system.mode = DbusMode::None;
        assert!(!sysbus(&q));
        q.dbus.system.mode = DbusMode::Full;
        assert!(sysbus(&q));
        // Nested sandboxes: blocked unless allowed.
        let blocked = |q: &PermissionSet| {
            matches!(
                test_of(&plan(q, &cfg, &h), "userns"),
                ProbeTest::UserNamespaces { blocked: true }
            )
        };
        let mut q = p.clone();
        q.advanced.allow_userns = false;
        assert!(blocked(&q));
        q.advanced.allow_userns = true;
        assert!(!blocked(&q));

        // Security layers: settings, configuration and the kernel together.
        let layers = |q: &PermissionSet, c: &Config, h: &HostInfo| {
            let pl = plan(q, c, h);
            (
                matches!(
                    test_of(&pl, "landlock"),
                    ProbeTest::Landlock { expect: true }
                ),
                matches!(
                    test_of(&pl, "seccomp"),
                    ProbeTest::SyscallFilter { active: true }
                ),
            )
        };
        let mut c = cfg.clone();
        let mut q = p.clone();
        q.advanced.landlock = Some(true);
        assert!(!layers(&q, &c, &h).0, "no Landlock in this kernel");
        h.landlock_abi = Some(4);
        assert!(layers(&q, &c, &h).0);
        q.advanced.landlock = Some(false);
        assert!(!layers(&q, &c, &h).0, "switched off for the app");
        c.security.baseline_seccomp = true;
        q.advanced.seccomp_baseline = true;
        assert!(layers(&q, &c, &h).1, "baseline filter");
        q.advanced.seccomp_baseline = false;
        q.advanced.seccomp_strict = true;
        c.security.experimental_seccomp = false;
        assert!(
            layers(&q, &c, &h).1,
            "the app's strict filter switch works on its own (audit D-M13)"
        );
    }

    /// What the check expects of each desktop service that exists on the
    /// computer: full access reaches all of them; the filter reaches the
    /// desktop portal and exactly the names its list allows (a whole name,
    /// or a family with `.*`); a denied name stays hidden even with full
    /// access; a service the computer does not have is not checked at all.
    /// A private test bus owns the names, so this runs on every computer.
    #[test]
    fn the_check_expects_each_desktop_service_as_the_filter_shows_it() {
        if sam_core::util::which("dbus-daemon").is_none() {
            crate::contracts::skip("dbus-daemon is not installed")
                .unwrap_or_else(|e| panic!("{e}"));
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let services = crate::testenv::PrivateServices::start(t.path());
        let address = services.bus_address().expect("a private bus").to_string();
        let mut h = host_in(t.path());
        h.sockets.dbus_session_address = Some(address.clone());
        h.tools.xdg_dbus_proxy = Some(sam_core::host::Tool {
            path: "/usr/bin/xdg-dbus-proxy".into(),
            version: None,
        });
        let cfg = Config::default();
        const PORTAL: &str = "org.freedesktop.portal.Desktop";
        const SYSTEMD: &str = "org.freedesktop.systemd1";
        const SECRETS: &str = "org.freedesktop.secrets";
        const KWIN: &str = "org.kde.KWin";
        // Name → expected reachable, for every name the plan checks.
        let names = |q: &PermissionSet| -> Vec<(String, bool)> {
            plan(q, &cfg, &h)
                .checks
                .into_iter()
                .filter_map(|c| match c.test {
                    ProbeTest::BusName { name, expect } => Some((name, expect)),
                    _ => None,
                })
                .collect()
        };
        let reach = |q: &PermissionSet, n: &str| -> Option<bool> {
            names(q).into_iter().find(|(m, _)| m == n).map(|(_, e)| e)
        };

        // No desktop service on this bus yet: none is checked.
        let mut full = PermissionSet::strict_gui();
        full.dbus.session.mode = DbusMode::Full;
        assert!(names(&full).is_empty(), "{:?}", names(&full));

        let _owned: Vec<_> = [PORTAL, SYSTEMD, SECRETS, KWIN]
            .iter()
            .map(|n| crate::dbus_check::own_name(&address, n, Duration::from_secs(2)).unwrap())
            .collect();

        // Full access: every one reachable, each checked once.
        assert_eq!(
            names(&full),
            [PORTAL, SYSTEMD, SECRETS, KWIN]
                .iter()
                .map(|n| (n.to_string(), true))
                .collect::<Vec<_>>()
        );
        // ... except what is denied.
        let mut q = full.clone();
        q.dbus.session.deny = vec![SECRETS.into()];
        assert_eq!(reach(&q, SECRETS), Some(false));
        assert_eq!(reach(&q, SYSTEMD), Some(true));

        // The filter: the portal always; the rest only from the list.
        let mut f = PermissionSet::strict_gui();
        f.dbus.session.mode = DbusMode::Filtered;
        f.dbus.session.allow = vec!["org.example.Other".into()];
        assert_eq!(reach(&f, PORTAL), Some(true));
        assert_eq!(reach(&f, SYSTEMD), Some(false));
        assert_eq!(
            reach(&f, SECRETS),
            Some(false),
            "another name allows nothing"
        );
        assert_eq!(reach(&f, KWIN), Some(false));
        f.dbus.session.allow = vec![SECRETS.into()];
        assert_eq!(reach(&f, SECRETS), Some(true), "a whole name");
        assert_eq!(reach(&f, SYSTEMD), Some(false));
        f.dbus.session.allow = vec!["org.freedesktop.secret".into()];
        assert_eq!(
            reach(&f, SECRETS),
            Some(false),
            "part of a name is not a family"
        );
        f.dbus.session.allow = vec!["org.kde.*".into()];
        assert_eq!(reach(&f, KWIN), Some(true), "a family");
        assert_eq!(reach(&f, SECRETS), Some(false));
        f.dbus.session.deny = vec![KWIN.into()];
        assert_eq!(reach(&f, KWIN), Some(false), "denied wins over a family");

        // No bus for the app: nothing to check.
        let mut none = full.clone();
        none.dbus.session.mode = DbusMode::None;
        assert!(names(&none).is_empty());
        // The filter without its proxy is no bus either.
        let mut no_proxy = h.clone();
        no_proxy.tools.xdg_dbus_proxy = None;
        let mut f = PermissionSet::strict_gui();
        f.dbus.session.mode = DbusMode::Filtered;
        assert!(!plan(&f, &cfg, &no_proxy)
            .checks
            .iter()
            .any(|c| matches!(c.test, ProbeTest::BusName { .. })));
        drop(services);
    }

    /// A passed check is reused only on the same computer as it was then:
    /// other GPU devices, the D-Bus proxy installed or removed, other
    /// sockets or another Landlock each make the check run again.
    #[test]
    fn a_passed_check_is_repeated_when_the_computer_changes() {
        let app = AppEntry::default();
        let cfg = Config::default();
        let host = sam_core::sandbox::sample_context().host;
        let key = |h: &HostInfo| check_key(&app, &cfg, h);
        let same = key(&host);
        assert_eq!(key(&host.clone()), same, "the same computer");
        let changes: [(&str, fn(&mut HostInfo)); 5] = [
            ("no GPU", |h| h.gpu_devices.clear()),
            ("another GPU", |h| h.gpu_devices.truncate(2)),
            ("no D-Bus proxy", |h| h.tools.xdg_dbus_proxy = None),
            ("no Wayland socket", |h| h.sockets.wayland = None),
            ("another Landlock", |h| h.landlock_abi = Some(99)),
        ];
        for (what, change) in changes {
            let mut h = host.clone();
            change(&mut h);
            assert_ne!(key(&h), same, "{what}");
        }
    }

    /// Review K-1: with X11 off, the check tries the X server's abstract
    /// socket, which needs no file; with a session bus on an abstract
    /// socket, it tries that too unless the app may use the whole bus.
    #[test]
    fn the_check_tries_the_hosts_abstract_sockets_the_app_must_not_reach() {
        let t = tempfile::tempdir().unwrap();
        let mut h = host_in(t.path());
        let cfg = Config::default();
        let mut p = PermissionSet::strict_gui();
        let abstract_names = |p: &PermissionSet, h: &HostInfo| -> Vec<(String, String)> {
            plan(p, &cfg, h)
                .checks
                .into_iter()
                .filter_map(|c| match c.test {
                    ProbeTest::AbstractSocket {
                        name,
                        expect: false,
                    } => Some((c.id, name)),
                    _ => None,
                })
                .collect()
        };
        assert!(abstract_names(&p, &h).is_empty(), "no X server, no bus");
        h.sockets.x11 = Some("/tmp/.X11-unix/X1".into());
        h.sockets.dbus_session_address =
            Some("unix:abstract=/tmp/dbus-AbC%2d1,guid=0123;unix:path=/run/user/1000/bus".into());
        p.display.x11 = false;
        p.dbus.session.mode = DbusMode::Filtered;
        assert_eq!(
            abstract_names(&p, &h),
            [
                ("x11-abstract".to_string(), "/tmp/.X11-unix/X1".to_string()),
                ("bus-abstract".to_string(), "/tmp/dbus-AbC-1".to_string()),
            ]
        );
        // X11 granted, the whole bus granted: nothing to keep out.
        p.display.x11 = true;
        p.dbus.session.mode = DbusMode::Full;
        assert!(abstract_names(&p, &h).is_empty());
    }
}
