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
use crate::probe::{self, Access, ProbeCheck, ProbePlan, ProbeReport, ProbeResult, ProbeTest};

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

/// What the sandbox check expects at `path`, a user or extra folder the
/// sandbox leaves out because the way there leads through a link the app
/// could have planted or to where programs outside the sandbox listen
/// ([`sam_core::places::linked_place_left_out`]). Inside the sandbox the
/// link itself may still be there (the home or a user folder shows it),
/// and the probe follows it, so it finds what the other grants show where
/// the link leads: their expectation (`shown`, the deepest decides, as
/// the mounts do), nothing in SAM's own folders (`sam_dirs`), and nothing
/// where none of them shows it. A person who kept such a link and listed
/// its place as well was told the check failed. `None` (no check) where
/// the sandbox may show the place on its own: the system folders it binds
/// read-only (also `extra_lib_dirs`), `/run`, `/proc`, `/dev`, `/sys`,
/// and the fonts and theme files a private home binds on its own (`own`:
/// only those with no link on their way in the home; one skipped for a
/// link shows nothing there).
fn expect_at_target(
    path: &Path,
    shown: &[(PathBuf, Access)],
    sam_dirs: &[PathBuf],
    own: &[PathBuf],
    extra_lib_dirs: &[PathBuf],
) -> Option<Access> {
    let leads = sam_core::places::follow(path).leads;
    if sam_core::places::inside_sams_folders(&leads, sam_dirs) {
        return Some(Access::Hidden);
    }
    if let Some((_, want)) = shown
        .iter()
        .filter(|(g, _)| leads.starts_with(g))
        .max_by_key(|(g, _)| g.components().count())
    {
        return Some(*want);
    }
    let on_its_own = [
        "/usr",
        "/etc",
        "/bin",
        "/sbin",
        "/lib",
        "/lib32",
        "/lib64",
        "/var/cache/fontconfig",
        "/run",
        "/proc",
        "/dev",
        "/sys",
    ]
    .iter()
    .map(PathBuf::from)
    .chain(extra_lib_dirs.iter().cloned())
    .chain(
        own.iter()
            .flat_map(|o| [o.clone(), sam_core::places::resolve(o)]),
    )
    .any(|d| leads.starts_with(&d));
    (!on_its_own).then_some(Access::Hidden)
}

/// The checks for an app, with what each should find.
pub fn plan(p: &PermissionSet, cfg: &Config, paths: &Paths, host: &HostInfo) -> ProbePlan {
    let mut v: Vec<ProbeCheck> = Vec::new();
    let fs = &p.filesystem;
    // SAM's own folders, the list the sandbox hides: also the folders
    // named like them (`~/.local/share/sam`) while SAM keeps its own
    // elsewhere, which the sandbox hides by name unless that would cover
    // too much, decided for what this start shows as the sandbox decides
    // it (independent reviews of decision 9). The check's start has no
    // extra binds of SAM's (`verify` passes none), so this is the list
    // the sandbox takes for it.
    let sam_dirs = sam_core::places::sams_folders(
        &host.home,
        &paths.sam_dirs(&cfg.extraction.location),
        &sam_core::places::shown_folders(p, host),
    );
    // With the whole home writable, a protected place the sandbox does not
    // hide that really is the home (`~/.config/sam` planted as a link to
    // it) is locked read-only where the app reaches it, which is the whole
    // home: the home and everything shown through it are read-only. The
    // answer the sandbox's note takes (independent review of decision 9:
    // the check expected the home writable and failed a sandbox that did
    // what it should).
    // What the check's start adds to its permissions for the binds made
    // where their links lead: nothing writable (it opens no folder and
    // has no binds of SAM's) and SAM's runtime folders, the folder that
    // holds every app's start folders, as the sandbox takes them.
    let this = sam_core::places::ThisStart {
        writable: Vec::new(),
        sam_runtime: crate::launch::sam_runtime_folders(paths),
    };
    let home_locked = fs.home
        && fs.home_access == Perm::Rw
        && sam_core::places::protected_place_at_home(&host.home, &sam_dirs).is_some();
    let home_level = if !fs.home {
        Access::Hidden
    } else if home_locked {
        Access::ReadOnly
    } else {
        level(fs.home_access)
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
    // What the sandbox itself shows of the home, the user folders and the
    // extra folders, each where it really is, with what the check expects
    // there. A user or extra folder the sandbox leaves out through a link
    // is expected as these show the place the link leads to
    // ([`expect_at_target`]).
    let mut shown: Vec<(PathBuf, Access)> = Vec::new();
    if fs.home {
        shown.push((host.home.clone(), home_level));
        shown.push((sam_core::places::resolve(&host.home), home_level));
    }
    // The folder checks, in order: id, title, path and what it should
    // find; `None` for one the sandbox leaves out through a link.
    let mut folders: Vec<(&str, String, PathBuf, Option<Access>)> = Vec::new();
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
        // A user folder set inside SAM's own folders is not shown: the
        // sandbox refuses it and hides SAM's folders with the home
        // (independent re-review of decision 9). A granted one the sandbox
        // shows is shown at its own access, also with the whole home,
        // inside the home or outside it: read-only in a writable home
        // (finding R63). One not granted, or one the sandbox refuses (for
        // showing more than a user folder, for listening programs in
        // `/tmp`, or for a link on its way the app could have put there),
        // is seen only through the home, at the home's access, and only
        // where it lies in the home as named and as reached; elsewhere it
        // is not shown at all.
        let real = sam_core::places::resolve(path);
        let through_home =
            path.starts_with(&host.home) && real.starts_with(sam_core::places::resolve(&host.home));
        // Granted and not refused for showing more than a user folder, for
        // listening programs in `/tmp` or for a link the app could have put
        // on its way: the sandbox shows it at its own access.
        let shown_own =
            a.is_granted() && sam_core::places::user_folder_shown(p, host, path).is_some();
        let want = if sam_core::places::inside_sams_folders(&real, &sam_dirs) {
            Access::Hidden
        } else if shown_own {
            // Two user folders at one place at different access (Music
            // read and write, Pictures read-only, both `~/Media`): the
            // stricter one decides for both, as in the sandbox.
            level(sam_core::places::user_folder_access(p, host, key))
        } else if through_home {
            home_level
        } else {
            Access::Hidden
        };
        // With the whole home writable, a user folder the home already
        // shows at its own access gets no mount of its own: one in the home
        // is then shown through it, so read-only at most where the home is
        // locked read-only (independent review of decision 9). One mounted
        // of its own inside the home is covered by that lock as well.
        let want =
            if home_locked && path.starts_with(&host.home) && rank(want) > rank(Access::ReadOnly) {
                Access::ReadOnly
            } else {
                want
            };
        // A granted one is left out where its way leads through a link the
        // app could have planted, or to where programs outside the sandbox
        // listen: by the sandbox's rule. With the whole home it is then
        // seen only as the home shows the place its link leads to. Only a
        // user folder the sandbox shows (granted, not left out, not
        // refused as above) gets a bind of its own, in a private home and
        // with the whole home, so only such a one is counted where it
        // really is. One not granted, or one the sandbox refuses, gets no
        // bind: counted hidden there, it hid a wider grant around that
        // place (the read-only home, `/usr`) from a left-out link that
        // leads into it. One inside SAM's own folders is hidden there
        // whatever is counted ([`expect_at_target`]).
        let left_out =
            a.is_granted() && sam_core::places::user_folder_left_out(p, host, key, &this).is_some();
        if shown_own && !left_out {
            shown.push((sam_core::places::resolve(path), want));
        }
        folders.push((
            key,
            title.to_string(),
            path.to_path_buf(),
            (!left_out).then_some(want),
        ));
    }
    for (list, want) in [
        (&fs.custom_read, Access::ReadOnly),
        (&fs.custom_write, Access::ReadWrite),
    ] {
        for raw in list {
            let path = sam_core::util::expand_home(raw);
            let bound = sam_core::places::resolve(&path);
            // A writable folder in a start place is shown read-only, also
            // inside a writable home (owner decision 9 of 2026-11-23).
            let in_start_place =
                sam_core::places::start_place_of_bound_write_grant(&path, &bound, &host.home);
            // In SAM's own folders, wherever they are kept, nothing is
            // shown: asked as the sandbox asks it, so the check never
            // expects a folder the sandbox leaves out (independent review
            // of decision 9: SAM's data kept in `~/Games/sam`).
            let in_sams = if want == Access::ReadWrite {
                sam_core::places::write_grant_in_sams_folders(
                    &bound,
                    in_start_place.as_ref(),
                    &sam_dirs,
                    &host.home,
                )
            } else {
                sam_core::places::inside_sams_folders(&bound, &sam_dirs)
            };
            // Reached through a link the app could have planted, out of
            // what it is shown, or through a link to where programs outside
            // the sandbox listen: the sandbox leaves it out, by the same
            // rule.
            let left_out = sam_core::places::linked_place_left_out(
                p,
                host,
                &path,
                want == Access::ReadWrite,
                &this,
            )
            .is_some();
            let want = if in_sams {
                Access::Hidden
            } else if in_start_place.is_some() {
                Access::ReadOnly
            } else if rank(home_level) > rank(want) && path.starts_with(&host.home) {
                home_level
            } else {
                want
            };
            if !left_out {
                shown.push((bound, want));
            }
            if path.is_dir() {
                folders.push((
                    "custom",
                    format!("Extra folder {}", sam_core::util::tildify(&path)),
                    path,
                    (!left_out).then_some(want),
                ));
            }
        }
    }
    // The fonts and theme files a private home binds on its own: only
    // those with no link on their way in the home, judged as the sandbox
    // judges them ([`sam_core::places::own_places_from_settings`]). One
    // skipped for a link is not shown on its own, so a left-out folder
    // whose link leads to its target is expected hidden there.
    let own: Vec<PathBuf> = if fs.home {
        Vec::new()
    } else {
        sam_core::places::own_places_from_settings(p, host, &sam_dirs, &this)
            .into_iter()
            .filter(|(_, d)| *d == sam_core::places::OwnBind::Bind)
            .map(|(rel, _)| host.home.join(rel))
            .collect()
    };
    for (id, title, path, want) in folders {
        let want = match want {
            Some(want) => Some(want),
            None => expect_at_target(&path, &shown, &sam_dirs, &own, &host.extra_lib_dirs),
        };
        if let Some(want) = want {
            v.push(c(
                id,
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
    for (name, title, granted) in [
        (".ssh", "SSH keys", fs.ssh_given()),
        (".gnupg", "GnuPG keys", fs.gnupg_given()),
    ] {
        let path = host.home.join(name);
        if path.is_dir() {
            let want = if granted { home_level } else { Access::Hidden };
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
    // The bus the start gives the app: only where SAM found its socket (the
    // start passes that socket, never the address alone), asked through the
    // address or that socket (B2 R79).
    let host_bus = s.dbus_session.as_ref().map(|sock| {
        s.dbus_session_address
            .clone()
            .filter(|a| a.contains("unix:path="))
            .unwrap_or_else(|| format!("unix:path={}", sock.display()))
    });
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
        // A name the filter lets the app see: one it may talk to, call
        // functions of or hear signals from (the portal through its
        // function rules, while it is allowed), matched as the filter
        // matches (B2 R79). Not the names it may own: the start refuses
        // every own rule that covers one of the names checked here (the
        // desktop's protocols, dangerous services).
        let bus = p.effective_session_bus();
        let allowed = |n: &str| {
            let rule_name =
                |r: &String| r.split_once('=').map_or(r.clone(), |(n, _)| n.to_string());
            bus_mode == DbusMode::Full
                || bus
                    .allow
                    .iter()
                    .cloned()
                    .chain(bus.calls.iter().chain(&bus.broadcasts).map(rule_name))
                    .any(|a| proxy_covers(&a, n))
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
                let want = allowed(name)
                    && !sam_core::permissions::bus_name_denied(&p.dbus.session.deny, name);
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

/// Whether a name rule of the filter covers `name` as xdg-dbus-proxy reads
/// it: `org.kde.*` is `org.kde` and every name below it; anything else is
/// that exact name (the filter knows no other wildcard).
fn proxy_covers(rule: &str, name: &str) -> bool {
    match rule.strip_suffix(".*") {
        Some(prefix) => name == prefix || name.starts_with(&format!("{prefix}.")),
        None => rule == name,
    }
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
/// relevant preferences and what this computer offers, with the kernel and
/// the programs that build the sandbox (Bubblewrap, SAM's helper, pasta). A
/// passing check with the same key needs no repeat. An updated kernel or
/// Bubblewrap, or a rebuilt SAM (all development builds carry the same
/// version number), is checked again (audit: the key left them out).
pub fn check_key(app: &AppEntry, cfg: &Config, paths: &Paths, host: &HostInfo) -> String {
    let planned = plan(&app.profile.permissions, cfg, paths, host);
    check_key_of(app, cfg, host, &planned)
}

/// [`check_key`] for the plan a check ran (B2 R82: computed afterwards,
/// a service that started during the check would enter the key untested).
fn check_key_of(app: &AppEntry, cfg: &Config, host: &HostInfo, planned: &ProbePlan) -> String {
    check_key_with(
        app,
        cfg,
        host,
        crate::find_helper(),
        sam_core::util::which("pasta"),
        planned,
    )
}

/// What of a plan goes into the key: each check's id and test, without the
/// titles (they follow the language, not the computer), without the values
/// of passed-through variables (a per-start token would make every start
/// check again, and a secret would go into the record), and with only
/// "another port listens" for the hidden local services (which port is the
/// lowest changes by itself).
fn plan_fingerprint(planned: &ProbePlan) -> Vec<serde_json::Value> {
    planned
        .checks
        .iter()
        .map(|c| {
            let test = match &c.test {
                ProbeTest::Env { name, expect } => {
                    serde_json::json!({"kind": "env", "name": name, "set": expect.is_some()})
                }
                ProbeTest::LocalPort { expect: false, .. } => {
                    serde_json::json!({"kind": "local_port", "other": true})
                }
                t => serde_json::to_value(t).unwrap_or_default(),
            };
            serde_json::json!([c.id, test])
        })
        .collect()
}

/// [`check_key`] with SAM's helper, pasta and the plan given.
fn check_key_with(
    app: &AppEntry,
    cfg: &Config,
    host: &HostInfo,
    helper: Option<PathBuf>,
    pasta: Option<PathBuf>,
    planned: &ProbePlan,
) -> String {
    // Which build of a program: its size and time, which an update or a
    // new build changes (not its path: SAM's AppImage shows it at a new
    // place every time it runs).
    let build = |p: Option<&Path>| {
        p.and_then(|p| std::fs::metadata(p).ok()).map(|m| {
            use std::os::unix::fs::MetadataExt;
            (m.size(), m.mtime(), m.mtime_nsec())
        })
    };
    let host_state = serde_json::json!({
        "sockets": &host.sockets,
        "landlock": host.landlock_abi,
        "proxy": host.tools.xdg_dbus_proxy.is_some(),
        "gpu": host.gpu_devices,
        "kernel": host.kernel,
        "bwrap": build(host.tools.bwrap.as_ref().map(|t| t.path.as_path())),
        "helper": build(helper.as_deref()),
        "pasta": build(pasta.as_deref()),
    });
    // What the check checks on this computer: which folders, devices,
    // ports and desktop services it finds, and what it expects of each (B2
    // R82: a pass recorded while the keyring was not running was reused
    // once it ran).
    let planned = plan_fingerprint(planned);
    let data = serde_json::json!({
        "sam": env!("CARGO_PKG_VERSION"),
        "profile": &app.profile,
        "security": &cfg.security,
        "host": host_state,
        "plan": planned,
    });
    sam_intake::fingerprint::short_hash(data.to_string().as_bytes())
}

/// The sandbox check's item for the Wayland security context, which SAM
/// sets up outside the sandbox, so the probe inside cannot see it: passed
/// when this start has one, failed when the desktop offers security
/// contexts but refused one (the app would get every Wayland function,
/// such as reading the clipboard in the background), none when the start
/// asks for none or the desktop has none (B2 R78).
fn wayland_context_result(made: bool, failed: bool) -> Option<ProbeResult> {
    let (ok, observed) = match (made, failed) {
        (true, _) => (true, sam_core::i18n::tr("in place")),
        (false, true) => (
            false,
            sam_core::i18n::tr(
                "the desktop did not set it up, so the app would get every Wayland function",
            ),
        ),
        (false, false) => return None,
    };
    Some(ProbeResult {
        id: "wayland-context".into(),
        group: sam_core::i18n::tr("Display"),
        title: sam_core::i18n::tr("Privileged Wayland functions hidden"),
        ok: Some(ok),
        observed,
    })
}

/// The sandbox check's note for a 32-bit app whose filter has the
/// socketcall gap: the test program makes only 64-bit calls, so it cannot
/// try the gap, and the check says the limit is incomplete instead of
/// passing in silence. Neither passed nor failed, so it never stops a
/// start ("Check the sandbox before each start" stops only on a failure).
fn socket_limit_result(app: &AppEntry, cfg: &Config, host: &HostInfo) -> Option<ProbeResult> {
    crate::launch::socket_limit_incomplete(app, &app.profile.permissions, cfg, host).then(|| {
        ProbeResult {
            id: "seccomp-32-bit-sockets".into(),
            group: sam_core::i18n::tr("Security"),
            title: sam_core::i18n::tr("Socket limit for 32-bit calls"),
            ok: None,
            observed: sam_core::i18n::tr(
                "incomplete: a 32-bit socket made through the old socketcall call can be of any type, Bluetooth included when the app has full network access, and the test program cannot try 32-bit calls",
            ),
        }
    })
}

/// The results SAM adds outside the sandbox, after the probe's own: the
/// socket note first, so it stays under the probe's last heading
/// (Security; `sam-jail verify` prints a heading each time the group
/// changes), then the Wayland context (Display).
fn add_outside_results(
    report: &mut ProbeReport,
    socket: Option<ProbeResult>,
    wayland: Option<ProbeResult>,
) {
    report.results.extend(socket);
    report.results.extend(wayland);
}

/// Runs the sandbox check for an app.
pub fn verify(app: &AppEntry, cfg: &Config, paths: &Paths, host: &HostInfo) -> Result<Outcome> {
    let plan = plan(&app.profile.permissions, cfg, paths, host);
    // The key of the plan that runs, not of one made afterwards.
    let key = check_key_of(app, cfg, host, &plan);
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
    let wayland = wayland_context_result(prepared.wayland_context, prepared.wayland_context_failed);
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
    add_outside_results(&mut report, socket_limit_result(app, cfg, host), wayland);
    let record = CheckRecord {
        at: sam_core::util::now(),
        key,
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

    /// A scratch folder outside `/tmp` and `/var/tmp`, beside the test
    /// program: there a link's target is an ordinary folder, while
    /// anything in `/tmp` counts as a place where programs outside the
    /// sandbox listen ([`sam_core::places::leads_to_host_services`]).
    fn scratch() -> tempfile::TempDir {
        let exe = std::env::current_exe().unwrap();
        let t = tempfile::Builder::new()
            .prefix("verify-")
            .tempdir_in(exe.parent().unwrap())
            .unwrap();
        let real = fs::canonicalize(t.path()).unwrap();
        assert!(
            !real.starts_with("/tmp") && !real.starts_with("/var/tmp"),
            "the test program lies in a temp folder: {}",
            real.display()
        );
        t
    }

    /// SAM's own folders where no test grants anything; a case that needs
    /// them somewhere sets its own.
    fn sam_paths() -> Paths {
        Paths {
            config_dir: PathBuf::from("/nonexistent/sam-test/config"),
            data_dir: PathBuf::from("/nonexistent/sam-test/data"),
            applications_dir: PathBuf::from("/nonexistent/sam-test/applications"),
            runtime_root: None,
        }
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

    /// What the check expects of each folder: a granted user folder at its
    /// own setting, one without a setting as the home shows it (a
    /// read-only home shows Documents read-only even when Documents has no
    /// setting; a writable folder in a read-only home stays writable); keys
    /// only with full home and their own switch; extra folders like the
    /// home inside it.
    #[test]
    fn the_check_expects_each_folder_as_its_settings_show_it() {
        let t = tempfile::tempdir().unwrap();
        let h = host_in(t.path());
        let cfg = Config::default();
        let plan_of = |f: &dyn Fn(&mut PermissionSet)| {
            let mut p = PermissionSet::strict_gui();
            f(&mut p);
            plan(&p, &cfg, &sam_paths(), &h)
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
        let pl = plan(&PermissionSet::strict_gui(), &cfg, &sam_paths(), &h2);
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
        // A writable folder inside a start place is shown read-only, with
        // or without the whole home (owner decision 9 of 2026-11-23).
        let conf_d = h.home.join(".config/fish/conf.d");
        fs::create_dir_all(&conf_d).unwrap();
        let conf_d = conf_d.to_string_lossy().into_owned();
        for home in [false, true] {
            let pl = plan_of(&|p| {
                p.filesystem.home = home;
                p.filesystem.home_access = Perm::Rw;
                p.filesystem.custom_write = vec![conf_d.clone()];
            });
            let title = format!(
                "Extra folder {}",
                sam_core::util::tildify(Path::new(&conf_d))
            );
            assert_eq!(folder(&pl, &title), Access::ReadOnly, "home {home}");
        }
    }

    /// With the whole home granted, the check expects a granted user folder
    /// at its own access, as the sandbox mounts it, not at the higher of
    /// the home's and its own: read-only in a writable home (finding R63),
    /// and outside the home read-only or writable as set
    /// (`XDG_DOCUMENTS_DIR=/data/Documents`). A user folder not granted is
    /// seen through the home.
    #[test]
    fn the_check_expects_a_user_folder_at_its_own_access_with_the_whole_home() {
        let t = tempfile::tempdir().unwrap();
        let h = host_in(t.path());
        let cfg = Config::default();
        let plan_with = |h: &HostInfo, home: Perm, docs: Perm| {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            p.filesystem.home_access = home;
            p.filesystem.documents = docs;
            plan(&p, &cfg, &sam_paths(), h)
        };
        let pl = plan_with(&h, Perm::Rw, Perm::Ro);
        assert_eq!(folder(&pl, "Your home folder"), Access::ReadWrite);
        assert_eq!(folder(&pl, "Documents"), Access::ReadOnly);
        assert_eq!(
            folder(&pl, "Pictures"),
            Access::ReadWrite,
            "not granted: through the home"
        );
        assert_eq!(
            folder(&plan_with(&h, Perm::Ro, Perm::Rw), "Documents"),
            Access::ReadWrite
        );
        // Outside the home.
        let mut out = h.clone();
        let docs = t.path().join("data/Documents");
        fs::create_dir_all(&docs).unwrap();
        out.xdg_dirs.insert("documents".into(), docs);
        for home in [Perm::Rw, Perm::Ro] {
            for (docs, want) in [(Perm::Ro, Access::ReadOnly), (Perm::Rw, Access::ReadWrite)] {
                assert_eq!(
                    folder(&plan_with(&out, home, docs), "Documents"),
                    want,
                    "{home:?} home, {docs:?} Documents"
                );
            }
        }
    }

    /// The check expects user folders set to one place at one access, the
    /// one the sandbox takes: the stricter one, whatever their order
    /// (Music, Pictures and Videos all `~/Media`; owner decision of
    /// 2026-11-27), with the whole home writable, read-only or not
    /// granted. Each at its own access, the check expected one folder
    /// writable and read-only at once and failed whatever the sandbox did;
    /// with the folder listed last deciding, it expected Pictures
    /// read-only and Videos writable at one place writable.
    #[test]
    fn the_check_expects_user_folders_at_one_place_at_one_access() {
        let t = tempfile::tempdir().unwrap();
        let mut h = host_in(t.path());
        let media = h.home.join("Media");
        fs::create_dir_all(&media).unwrap();
        for key in ["music", "pictures", "videos"] {
            h.xdg_dirs.insert(key.into(), media.clone());
        }
        let cfg = Config::default();
        for home in [Some(Perm::Rw), Some(Perm::Ro), None] {
            for (music, pictures, videos, want) in [
                (Perm::Rw, Perm::Ro, Perm::Rw, Access::ReadOnly),
                (Perm::Rw, Perm::Ro, Perm::None, Access::ReadOnly),
                (Perm::Ro, Perm::Rw, Perm::None, Access::ReadOnly),
                (Perm::None, Perm::Ro, Perm::Rw, Access::ReadOnly),
                (Perm::Rw, Perm::None, Perm::Rw, Access::ReadWrite),
                (Perm::Ro, Perm::None, Perm::Ro, Access::ReadOnly),
            ] {
                let mut p = PermissionSet::strict_gui();
                if let Some(acc) = home {
                    p.filesystem.home = true;
                    p.filesystem.home_access = acc;
                }
                p.filesystem.music = music;
                p.filesystem.pictures = pictures;
                p.filesystem.videos = videos;
                let pl = plan(&p, &cfg, &sam_paths(), &h);
                for (title, acc) in [("Music", music), ("Pictures", pictures), ("Videos", videos)] {
                    if acc.is_granted() {
                        assert_eq!(
                            folder(&pl, title),
                            want,
                            "{home:?} home, {music:?} {pictures:?} {videos:?}: {title}"
                        );
                    }
                }
            }
        }
    }

    /// The check expects a user folder the sandbox refuses as the sandbox
    /// shows it: one reached through a link the app could have put in the
    /// writable home (`~/Downloads` a link to `/data/elsewhere`), or one
    /// set to `/tmp`, where programs outside the sandbox listen, is
    /// expected not shown, not writable through the home. The same link
    /// in a read-only home is followed and expected at its own access.
    /// Built outside `/tmp`: a link there to a folder in `/tmp` leads to
    /// where programs outside the sandbox listen, so the sandbox leaves
    /// it out also in a read-only home, and the check expects it so.
    #[test]
    fn the_check_expects_a_refused_user_folder_as_not_shown() {
        let t = scratch();
        let mut h = host_in(t.path());
        let elsewhere = t.path().join("data/elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, h.home.join("Downloads")).unwrap();
        h.xdg_dirs
            .insert("downloads".into(), h.home.join("Downloads"));
        let cfg = Config::default();
        let plan_with = |h: &HostInfo, home: Perm| {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            p.filesystem.home_access = home;
            p.filesystem.downloads = Perm::Rw;
            plan(&p, &cfg, &sam_paths(), h)
        };
        assert_eq!(
            folder(&plan_with(&h, Perm::Rw), "Downloads"),
            Access::Hidden
        );
        assert_eq!(
            folder(&plan_with(&h, Perm::Ro), "Downloads"),
            Access::ReadWrite,
            "a link the app cannot change is followed"
        );
        let in_tmp = tempfile::tempdir().unwrap();
        let tmp_target = fs::canonicalize(in_tmp.path()).unwrap();
        let tmp_link = h.home.join("TmpDownloads");
        std::os::unix::fs::symlink(&tmp_target, &tmp_link).unwrap();
        h.xdg_dirs.insert("downloads".into(), tmp_link);
        for home in [Perm::Rw, Perm::Ro] {
            assert_eq!(
                folder(&plan_with(&h, home), "Downloads"),
                Access::Hidden,
                "{home:?} home: a link to a folder in /tmp is not followed"
            );
        }
        h.xdg_dirs.insert("downloads".into(), PathBuf::from("/tmp"));
        assert_eq!(
            folder(&plan_with(&h, Perm::Rw), "Downloads"),
            Access::Hidden
        );
    }

    /// SAM's runtime folder holds the sockets of SAM's helpers for every
    /// running app (the D-Bus proxy, the sound relay), also where it lies
    /// outside the host's runtime folder (`XDG_RUNTIME_DIR` unset, or
    /// `SAM_RUNTIME_DIR`): a user folder that is a link there is left out
    /// by the sandbox, so the check expects it not shown, read-only or
    /// writable, in a private home where no link counts as planted. Taken
    /// as shown, the check failed a sandbox that did the right thing. The
    /// same link to an ordinary folder is expected at its own access.
    /// Built outside `/tmp`, where the temp rule would leave it out anyway.
    #[test]
    fn the_check_expects_a_user_folder_linked_to_sams_runtime_folder_as_not_shown() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let mut h = host_in(&base);
        let samrun = base.join("sam-run");
        let elsewhere = base.join("data/elsewhere");
        for d in [samrun.join("app"), elsewhere.clone()] {
            fs::create_dir_all(d).unwrap();
        }
        let paths = Paths {
            runtime_root: Some(samrun.clone()),
            ..sam_paths()
        };
        assert!(
            !h.runtime_dir
                .as_ref()
                .is_some_and(|r| samrun.starts_with(r)),
            "SAM's runtime folder lies outside the host's"
        );
        let downloads = h.home.join("Downloads");
        h.xdg_dirs.insert("downloads".into(), downloads.clone());
        let to = |target: &Path| {
            let _ = fs::remove_file(&downloads);
            std::os::unix::fs::symlink(target, &downloads).unwrap();
        };
        let cfg = Config::default();
        for (access, shown) in [(Perm::Rw, Access::ReadWrite), (Perm::Ro, Access::ReadOnly)] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.downloads = access;
            to(&samrun.join("app"));
            assert_eq!(
                folder(&plan(&p, &cfg, &paths, &h), "Downloads"),
                Access::Hidden,
                "{access:?}: a link to SAM's runtime folder"
            );
            to(&elsewhere);
            assert_eq!(
                folder(&plan(&p, &cfg, &paths, &h), "Downloads"),
                shown,
                "{access:?}: a link to an ordinary folder"
            );
        }
    }

    /// An extra folder inside SAM's own folders kept in a place of the
    /// person's choosing (SAM's data in `~/Games/sam`) is expected hidden,
    /// read-only or writable, with or without the whole home: the sandbox
    /// does not show it, and the check asks SAM's folders as the sandbox
    /// does. Before, only `~/.config/sam` and `~/.local/share/sam` were
    /// known, so the check expected the folder shown and failed a sandbox
    /// that was right (independent review of decision 9). A folder next to
    /// SAM's stays as granted. The folders named like SAM's
    /// (`~/.local/share/sam`) count too while SAM keeps its own elsewhere
    /// (independent re-review of decision 9).
    #[test]
    fn the_check_expects_no_folder_inside_sams_folders_wherever_they_are_kept() {
        let t = tempfile::tempdir().unwrap();
        let h = host_in(t.path());
        let cfg = Config::default();
        let paths = Paths {
            data_dir: h.home.join("Games/sam"),
            ..sam_paths()
        };
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        let saves = h.home.join("Games/sam/saves");
        let shared = h.home.join("Games/sam/shared");
        let next_to = h.home.join("Games/other");
        for d in [&saves, &shared, &next_to] {
            fs::create_dir_all(d).unwrap();
        }
        for home in [false, true] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = home;
            p.filesystem.home_access = Perm::Rw;
            p.filesystem.custom_write = vec![
                saves.to_string_lossy().into_owned(),
                next_to.to_string_lossy().into_owned(),
            ];
            p.filesystem.custom_read = vec![shared.to_string_lossy().into_owned()];
            let pl = plan(&p, &cfg, &paths, &h);
            assert_eq!(folder(&pl, &title(&saves)), Access::Hidden, "home {home}");
            assert_eq!(folder(&pl, &title(&shared)), Access::Hidden, "home {home}");
            assert_eq!(
                folder(&pl, &title(&next_to)),
                Access::ReadWrite,
                "home {home}"
            );
        }
        // The folders where SAM keeps its own unless told otherwise
        // (`~/.config/sam`, `~/.local/share/sam`) count as SAM's folders
        // also while this SAM keeps its own elsewhere: the sandbox hides
        // them by name, with the whole home and without it, so the check
        // expects a folder inside them hidden, read-only or writable.
        // Before, a read-only one was expected shown, and the check failed
        // a sandbox that hid it (independent re-review of decision 9).
        let by_name = [
            h.home.join(".local/share/sam/x"),
            h.home.join(".config/sam/y"),
        ];
        let written = h.home.join(".local/share/sam/w");
        for d in by_name.iter().chain([&written]) {
            fs::create_dir_all(d).unwrap();
        }
        for home in [false, true] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = home;
            p.filesystem.home_access = Perm::Rw;
            p.filesystem.custom_read = by_name
                .iter()
                .map(|d| d.to_string_lossy().into_owned())
                .collect();
            p.filesystem.custom_write = vec![written.to_string_lossy().into_owned()];
            let pl = plan(&p, &cfg, &paths, &h);
            for d in by_name.iter().chain([&written]) {
                assert_eq!(
                    folder(&pl, &title(d)),
                    Access::Hidden,
                    "{} home {home}",
                    d.display()
                );
            }
        }
        // A user folder set inside SAM's folders (where it keeps its own,
        // or named like them) is refused by the sandbox and hidden with
        // SAM's folders, so it is expected hidden too.
        let mut h2 = h.clone();
        for (key, rel) in [
            ("documents", ".local/share/sam/docs"),
            ("pictures", "Games/sam/pics"),
        ] {
            fs::create_dir_all(h2.home.join(rel)).unwrap();
            h2.xdg_dirs.insert(key.into(), h2.home.join(rel));
        }
        for home in [false, true] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = home;
            p.filesystem.home_access = Perm::Rw;
            p.filesystem.documents = Perm::Rw;
            p.filesystem.pictures = Perm::Ro;
            let pl = plan(&p, &cfg, &paths, &h2);
            for t in ["Documents", "Pictures"] {
                assert_eq!(folder(&pl, t), Access::Hidden, "{t} home {home}");
            }
        }
    }

    /// A folder named like SAM's that is a link (`~/.config/sam` planted
    /// as a link to the home while SAM keeps its own elsewhere) never
    /// makes the check count the home as SAM's folder: a read-only and a
    /// writable extra folder in the home are expected shown read-only, as
    /// below any start place reached through a link, which is what the
    /// sandbox does. Before, both were expected hidden, with the sandbox
    /// hiding every grant in the home (independent re-review of
    /// decision 9). With the whole home writable, the sandbox locks the
    /// link read-only where the app reaches it, which is the whole home:
    /// the check expects the home and the user folders in it read-only,
    /// also Documents set to read and write; without the planted link, or
    /// without the whole home, they stay as their settings say
    /// (independent review of decision 9: the check expected the home
    /// writable).
    #[test]
    fn the_check_never_takes_the_home_for_sams_folder_through_a_link() {
        let t = tempfile::tempdir().unwrap();
        let h = host_in(t.path());
        let cfg = Config::default();
        let paths = Paths {
            data_dir: t.path().join("elsewhere/data"),
            ..sam_paths()
        };
        for d in [".config", "notes", "work"] {
            fs::create_dir_all(h.home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(&h.home, h.home.join(".config/sam")).unwrap();
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        let (notes, work) = (h.home.join("notes"), h.home.join("work"));
        for home in [false, true] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = home;
            p.filesystem.home_access = Perm::Rw;
            p.filesystem.custom_read = vec![notes.to_string_lossy().into_owned()];
            p.filesystem.custom_write = vec![work.to_string_lossy().into_owned()];
            let pl = plan(&p, &cfg, &paths, &h);
            assert_eq!(folder(&pl, &title(&notes)), Access::ReadOnly, "home {home}");
            assert_eq!(folder(&pl, &title(&work)), Access::ReadOnly, "home {home}");
        }
        // The whole home writable: read-only where the link leads to it.
        let whole = |documents: Perm| {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            p.filesystem.home_access = Perm::Rw;
            p.filesystem.documents = documents;
            plan(&p, &cfg, &paths, &h)
        };
        for documents in [Perm::None, Perm::Rw] {
            let pl = whole(documents);
            assert_eq!(
                folder(&pl, "Your home folder"),
                Access::ReadOnly,
                "{documents:?}"
            );
            assert_eq!(folder(&pl, "Documents"), Access::ReadOnly, "{documents:?}");
            assert_eq!(folder(&pl, "Pictures"), Access::ReadOnly, "{documents:?}");
        }
        // Without the whole home, Documents is as its setting says.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Perm::Rw;
        let pl = plan(&p, &cfg, &paths, &h);
        assert_eq!(folder(&pl, "Documents"), Access::ReadWrite);
        // Without the planted link, the writable home is writable.
        fs::remove_file(h.home.join(".config/sam")).unwrap();
        let pl = whole(Perm::Rw);
        assert_eq!(folder(&pl, "Your home folder"), Access::ReadWrite);
        assert_eq!(folder(&pl, "Documents"), Access::ReadWrite);
    }

    /// The check counts another SAM's folders kept through a link
    /// (`~/.local/share/sam` a link to `~/Sync/sam`) as SAM's, as the
    /// sandbox does: a folder in them is expected hidden, read-only or
    /// writable, with the whole home and with a grant of `~/Sync`. While
    /// every link counted as an ordinary start place, both were expected
    /// shown, read-only. A start that shows only a folder inside the place
    /// a link named like SAM's folders leads to (`~/.config/sam` planted as
    /// a link to `~/work`, `~/work/proj` granted) expects that folder
    /// read-only, as the sandbox shows it (independent review of
    /// decision 9).
    #[test]
    fn the_check_follows_the_sandbox_for_folders_named_like_sams_behind_links() {
        let t = tempfile::tempdir().unwrap();
        let h = host_in(t.path());
        let cfg = Config::default();
        let paths = Paths {
            data_dir: h.home.join("Games/sam"),
            ..sam_paths()
        };
        for d in [
            ".local/share",
            ".config",
            "Sync/sam/apps",
            "Sync/sam/shared",
            "work/proj",
        ] {
            fs::create_dir_all(h.home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(h.home.join("Sync/sam"), h.home.join(".local/share/sam"))
            .unwrap();
        std::os::unix::fs::symlink(h.home.join("work"), h.home.join(".config/sam")).unwrap();
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let apps = h.home.join("Sync/sam/apps");
        let shared = h.home.join("Sync/sam/shared");
        for home in [true, false] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = home;
            p.filesystem.home_access = Perm::Rw;
            p.filesystem.custom_write = vec![s(&apps)];
            p.filesystem.custom_read = vec![s(&shared)];
            if !home {
                p.filesystem.custom_read.push(s(&h.home.join("Sync")));
            }
            let pl = plan(&p, &cfg, &paths, &h);
            assert_eq!(folder(&pl, &title(&apps)), Access::Hidden, "home {home}");
            assert_eq!(folder(&pl, &title(&shared)), Access::Hidden, "home {home}");
        }
        let proj = h.home.join("work/proj");
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![s(&proj)];
        let pl = plan(&p, &cfg, &paths, &h);
        assert_eq!(folder(&pl, &title(&proj)), Access::ReadOnly);
    }

    /// An extra folder that the sandbox leaves out because the app could
    /// have planted the link on its way (the whole home writable, the link
    /// leading out of it) is expected not to be shown, read-only or
    /// writable; so is one whose link leads to a socket folder in `/tmp`.
    /// The same link in a read-only home is expected as listed.
    #[test]
    fn the_check_expects_an_extra_folder_behind_a_planted_link_as_not_shown() {
        let t = scratch();
        let h = host_in(t.path());
        let cfg = Config::default();
        let outside = t.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&h.home).unwrap();
        let sockets = tempfile::Builder::new()
            .prefix("tmux-")
            .tempdir_in("/tmp")
            .unwrap();
        let ro = h.home.join("ro");
        let rw = h.home.join("rw");
        let tmux = h.home.join("tmux");
        std::os::unix::fs::symlink(&outside, &ro).unwrap();
        std::os::unix::fs::symlink(&outside, &rw).unwrap();
        std::os::unix::fs::symlink(sockets.path(), &tmux).unwrap();
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Perm::Rw;
        p.filesystem.custom_read = vec![s(&ro), s(&tmux)];
        p.filesystem.custom_write = vec![s(&rw)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        for f in [&ro, &rw, &tmux] {
            assert_eq!(folder(&pl, &title(f)), Access::Hidden, "{}", f.display());
        }
        p.filesystem.home_access = Perm::Ro;
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, &title(&ro)), Access::ReadOnly);
        assert_eq!(folder(&pl, &title(&rw)), Access::ReadWrite);
        assert_eq!(folder(&pl, &title(&tmux)), Access::Hidden);
    }

    /// The check judges a writable extra folder reached through a link as
    /// the sandbox does, by what is shown writable, and a read-only one by
    /// what is shown at all. With the whole home writable and Documents
    /// read-only, `~/w` a link to `~/Documents/sub` and listed writable is
    /// left out (the home shows `sub` only read-only, through Documents),
    /// so the check expects it read-only, as Documents shows it; expected
    /// writable, the check passed a sandbox that bound it writable inside
    /// the read-only Documents. The same link listed read-only is shown,
    /// at the home's access.
    #[test]
    fn the_check_judges_a_writable_extra_folder_by_what_is_shown_writable() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let h = host_in(&base);
        let cfg = Config::default();
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        fs::create_dir_all(h.home.join("Documents/sub")).unwrap();
        let (w, r) = (h.home.join("w"), h.home.join("r"));
        for link in [&w, &r] {
            std::os::unix::fs::symlink(h.home.join("Documents/sub"), link).unwrap();
        }
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Perm::Rw;
        p.filesystem.documents = Perm::Ro;
        p.filesystem.custom_write = vec![s(&w)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, "Documents"), Access::ReadOnly);
        assert_eq!(
            folder(&pl, &title(&w)),
            Access::ReadOnly,
            "a writable extra folder linked into the read-only Documents"
        );
        p.filesystem.custom_write = Vec::new();
        p.filesystem.custom_read = vec![s(&r)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(
            folder(&pl, &title(&r)),
            Access::ReadWrite,
            "a read-only extra folder the writable home shows"
        );
    }

    /// An extra folder the sandbox leaves out because of a link the app
    /// could have planted is expected as the other grants show the place
    /// the link leads to: the link itself stays visible through the home
    /// or a user folder, and the probe follows it. Listed by its real place
    /// as well (as the launch note advises), it is expected as that entry
    /// shows it, read-only or writable; in a private home with Documents
    /// writable, read-only as its real place is listed. Shown by nothing
    /// else, it is expected not to be shown.
    #[test]
    fn the_check_expects_a_left_out_extra_folder_as_its_target_is_shown() {
        let t = tempfile::tempdir().unwrap();
        let h = host_in(t.path());
        let cfg = Config::default();
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        let (data, data2, data3) = (
            t.path().join("data"),
            t.path().join("data2"),
            t.path().join("data3"),
        );
        for d in [&data, &data2, &data3] {
            fs::create_dir_all(d).unwrap();
        }
        let (rw, ro, docs) = (
            h.home.join("Data"),
            h.home.join("Data2"),
            h.home.join("Documents/Data3"),
        );
        std::os::unix::fs::symlink(&data, &rw).unwrap();
        std::os::unix::fs::symlink(&data2, &ro).unwrap();
        std::os::unix::fs::symlink(&data3, &docs).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Perm::Rw;
        p.filesystem.custom_write = vec![s(&rw), s(&data)];
        p.filesystem.custom_read = vec![s(&ro), s(&data2)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, &title(&rw)), Access::ReadWrite);
        assert_eq!(folder(&pl, &title(&ro)), Access::ReadOnly);
        // Only the link: nothing else shows its place.
        p.filesystem.custom_write = vec![s(&rw)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, &title(&rw)), Access::Hidden);
        // A private home, the link in writable Documents.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Perm::Rw;
        p.filesystem.custom_read = vec![s(&docs), s(&data3)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, &title(&docs)), Access::ReadOnly);
    }

    /// In a private home SAM binds the fonts on its own only where they are
    /// no link: an extra folder left out for a planted link that leads to
    /// the target of a linked `~/.fonts` is expected as not shown there,
    /// since nothing binds that target. While the fonts were bound where
    /// their link led, the check made no probe there. One that leads into
    /// a real `~/.fonts`, which SAM binds, still gets none.
    #[test]
    fn the_check_expects_nothing_at_the_target_of_a_skipped_font_link() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let h = host_in(&base);
        let cfg = Config::default();
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        let myfonts = base.join("myfonts");
        let w = h.home.join("w");
        for d in [&myfonts, &w] {
            fs::create_dir_all(d).unwrap();
        }
        std::os::unix::fs::symlink(&myfonts, h.home.join(".fonts")).unwrap();
        let planted = w.join("l");
        std::os::unix::fs::symlink(&myfonts, &planted).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_read = vec![s(&planted)];
        p.filesystem.custom_write = vec![s(&w)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, &title(&planted)), Access::Hidden);
        // A real `~/.fonts`, bound on its own: no probe at a place that
        // leads into it.
        fs::remove_file(h.home.join(".fonts")).unwrap();
        fs::create_dir_all(h.home.join(".fonts/sub")).unwrap();
        fs::remove_file(&planted).unwrap();
        std::os::unix::fs::symlink(h.home.join(".fonts/sub"), &planted).unwrap();
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert!(
            !pl.checks.iter().any(|c| c.title == title(&planted)),
            "{:?}",
            pl.checks.iter().map(|c| &c.title).collect::<Vec<_>>()
        );
    }

    /// With the whole home and in a private home, a user folder without a
    /// setting gets no bind of its own, so the check counts nothing for it
    /// where the folder really is: an extra folder left out for a planted
    /// link that leads into such a user folder outside the home (Documents
    /// set to `/data/Docs`, or to `~/Docs`, a link there, not granted) is
    /// expected as the extra read-only folder `/data` around it shows it,
    /// read-only. Counted as hidden there, the check expected the place
    /// hidden and failed a sandbox that showed it as it should.
    #[test]
    fn the_check_expects_a_left_out_extra_folder_inside_an_ungranted_user_folder_as_the_grant_around_it_shows_it(
    ) {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let mut h = host_in(&base);
        let cfg = Config::default();
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        let (data, docs) = (base.join("data"), base.join("data/Docs"));
        fs::create_dir_all(&docs).unwrap();
        h.xdg_dirs.insert("documents".into(), docs.clone());
        let link = h.home.join("docs-link");
        std::os::unix::fs::symlink(&docs, &link).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Perm::Rw;
        p.filesystem.documents = Perm::None;
        p.filesystem.custom_read = vec![s(&data), s(&link)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, &title(&data)), Access::ReadOnly);
        assert_eq!(
            folder(&pl, &title(&link)),
            Access::ReadOnly,
            "left out, and shown read-only by the extra folder around its place"
        );
        // A private home: Documents set to `~/Docs`, a link to `/data/Docs`
        // the private home does not show, not granted; the app planted
        // `~/w/l`, a link to `/data/Docs`, in the writable extra folder
        // `~/w`. The sandbox leaves `~/w/l` out and the app reaches the
        // place read-only through `~/w`, the link and `/data`.
        let home_docs = h.home.join("Docs");
        std::os::unix::fs::symlink(&docs, &home_docs).unwrap();
        h.xdg_dirs.insert("documents".into(), home_docs);
        let w = h.home.join("w");
        fs::create_dir_all(&w).unwrap();
        let planted = w.join("l");
        std::os::unix::fs::symlink(&docs, &planted).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Perm::None;
        p.filesystem.custom_read = vec![s(&data), s(&planted)];
        p.filesystem.custom_write = vec![s(&w)];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, "Documents"), Access::Hidden);
        assert_eq!(folder(&pl, &title(&data)), Access::ReadOnly);
        assert_eq!(
            folder(&pl, &title(&planted)),
            Access::ReadOnly,
            "left out in a private home, and shown read-only by the extra folder around its place"
        );
    }

    /// A granted user folder the sandbox refuses gets no bind of its own,
    /// so the check counts nothing for it where it really is: an extra
    /// folder left out for a planted link that leads into such a place is
    /// expected as the rest shows that place. Counted as hidden there, the
    /// check expected the place hidden and failed a sandbox that showed it
    /// as it should.
    #[test]
    fn the_check_expects_a_left_out_extra_folder_inside_a_refused_user_folder_as_the_rest_shows_it()
    {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let mut h = host_in(&base);
        let cfg = Config::default();
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let title = |p: &Path| format!("Extra folder {}", sam_core::util::tildify(p));
        // The whole home read-only, `/data/w` an extra writable folder.
        // Documents, read-only, is set to `/data/w/Docs`, a link the person
        // made to `~/Papers`: refused, since the link lies in a folder the
        // app can change. The app planted `/data/w/inbox`, a link to
        // `~/Papers/inbox`, listed as an extra writable folder. The sandbox
        // leaves it out, since the read-only home does not show the place
        // writable, and the app reaches it read-only through `/data/w`,
        // the link and the home.
        let w = base.join("data/w");
        let papers = h.home.join("Papers");
        fs::create_dir_all(&w).unwrap();
        fs::create_dir_all(papers.join("inbox")).unwrap();
        let docs = w.join("Docs");
        std::os::unix::fs::symlink(&papers, &docs).unwrap();
        h.xdg_dirs.insert("documents".into(), docs.clone());
        let inbox = w.join("inbox");
        std::os::unix::fs::symlink(papers.join("inbox"), &inbox).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Perm::Ro;
        p.filesystem.documents = Perm::Ro;
        p.filesystem.custom_write = vec![s(&w), s(&inbox)];
        assert!(matches!(
            sam_core::places::user_folder_refused(
                &p,
                &h,
                "documents",
                &sam_core::places::ThisStart::default()
            ),
            Some(sam_core::places::UserFolderRefused::Link(_))
        ));
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(
            folder(&pl, &title(&inbox)),
            Access::ReadOnly,
            "left out, and shown read-only by the home around its place"
        );
        // Documents set to `/`, read-only: refused as a folder above the
        // home, with no link on the way. The app planted `/data/w/sys`, a
        // link to `/usr`, listed as an extra read-only folder. The sandbox
        // leaves it out, and `/usr` is shown read-only on its own, so the
        // check has nothing to expect there.
        h.xdg_dirs.insert("documents".into(), PathBuf::from("/"));
        let sys = w.join("sys");
        std::os::unix::fs::symlink("/usr", &sys).unwrap();
        p.filesystem.custom_write = vec![s(&w)];
        p.filesystem.custom_read = vec![s(&sys)];
        assert!(sam_core::places::user_folder_place(Path::new("/"), &h.home).is_none());
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert!(
            !pl.checks.iter().any(|c| c.title == title(&sys)),
            "left out, and `/usr` is shown on its own: {:?}",
            pl.checks.iter().find(|c| c.title == title(&sys))
        );
    }

    /// A user folder the sandbox leaves out because the way there leads
    /// through a link the app could have planted (Documents set to
    /// `~/Sync/Documents`, `~/Sync` writable) is expected as the rest shows
    /// the place it leads to, here not at all; reached through a link you
    /// made in the home, it is expected as its switch says.
    #[test]
    fn the_check_expects_a_user_folder_behind_a_planted_link_as_its_target_is_shown() {
        let t = scratch();
        let mut h = host_in(t.path());
        let cfg = Config::default();
        let outside = t.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(h.home.join("Sync")).unwrap();
        let docs = h.home.join("Sync/Documents");
        std::os::unix::fs::symlink(&outside, &docs).unwrap();
        h.xdg_dirs.insert("documents".into(), docs);
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Perm::Ro;
        p.filesystem.custom_write = vec![h.home.join("Sync").to_string_lossy().into_owned()];
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, "Documents"), Access::Hidden);
        let mine = h.home.join("MyDocs");
        std::os::unix::fs::symlink(&outside, &mine).unwrap();
        h.xdg_dirs.insert("documents".into(), mine);
        let pl = plan(&p, &cfg, &sam_paths(), &h);
        assert_eq!(folder(&pl, "Documents"), Access::ReadOnly);
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
        assert!(plan(&q, &cfg, &sam_paths(), &h)
            .checks
            .iter()
            .any(|c| c.id == "net" && c.title == "No internet"));
        q.network.mode = NetworkMode::Full;
        assert!(!matches!(
            plan(&q, &cfg, &sam_paths(), &h)
                .checks
                .iter()
                .find(|c| c.id == "net")
                .map(|c| &c.test),
            Some(ProbeTest::NoNetwork)
        ));
        q.network.mode = NetworkMode::None;
        assert!(matches!(
            test_of(&plan(&q, &cfg, &sam_paths(), &h), "net"),
            ProbeTest::NoNetwork
        ));

        // Display and sound: only setting and socket together.
        let mut q = p.clone();
        q.display.wayland = true;
        q.display.x11 = true;
        q.audio.enabled = true;
        let expects = |q: &PermissionSet, h: &HostInfo| {
            let pl = plan(q, &cfg, &sam_paths(), h);
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
                test_of(&plan(q, &cfg, &sam_paths(), h), "bus"),
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
        // The socket as SAM finds it next to the address (the start passes
        // that socket; B2 R79).
        h.sockets.dbus_session = Some(t.path().join("no-bus"));
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
                test_of(&plan(q, &cfg, &sam_paths(), h), "ssh-agent"),
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
        let pl = plan(&q, &cfg, &sam_paths(), &h);
        let named: Vec<_> = pl
            .checks
            .iter()
            .filter(|c| c.id == "env")
            .map(|c| c.title.clone())
            .collect();
        assert_eq!(named, ["Variable Ok1", "Variable _OK"]);

        // The GPU: setting and device together (whatever this computer has).
        let gpu = |q: &PermissionSet| match test_of(&plan(q, &cfg, &sam_paths(), &h), "gpu") {
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
                test_of(&plan(q, &cfg, &sam_paths(), &h), "sysbus"),
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
                test_of(&plan(q, &cfg, &sam_paths(), &h), "userns"),
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
            let pl = plan(q, c, &sam_paths(), h);
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
        h.sockets.dbus_session = sam_core::host::dbus_unix_path(&address);
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
            plan(q, &cfg, &sam_paths(), &h)
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

        // The filter: the portal while it is allowed (by default), through
        // its function rules; the rest only from the lists (B2 R79: the
        // portal counted as always allowed).
        let mut f = PermissionSet::strict_gui();
        f.dbus.session.mode = DbusMode::Filtered;
        assert_eq!(reach(&f, PORTAL), Some(true), "allowed by default");
        f.dbus.session.allow = vec!["org.example.Other".into()];
        assert_eq!(reach(&f, PORTAL), Some(false), "not allowed");
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
        // As the filter matches: no wildcard without its dot; a name it may
        // own or call functions of is one it reaches (B2 R79).
        f.dbus.session.deny = vec![];
        f.dbus.session.allow = vec!["org.kde*".into()];
        assert_eq!(
            reach(&f, KWIN),
            Some(false),
            "the filter has no such wildcard"
        );
        f.dbus.session.allow = vec![];
        f.dbus.session.own = vec!["org.kde.*".into()];
        assert_eq!(
            reach(&f, KWIN),
            Some(false),
            "the start refuses to let an app own KWin's family"
        );
        f.dbus.session.own = vec![];
        f.dbus.session.calls = vec![format!(
            "{SECRETS}=org.freedesktop.Secret.Service.*@/org/freedesktop/secrets"
        )];
        assert_eq!(reach(&f, SECRETS), Some(true), "one of its functions");
        f.dbus.session.calls = vec![];

        // No bus for the app: nothing to check.
        let mut none = full.clone();
        none.dbus.session.mode = DbusMode::None;
        assert!(names(&none).is_empty());
        // The filter without its proxy is no bus either.
        let mut no_proxy = h.clone();
        no_proxy.tools.xdg_dbus_proxy = None;
        let mut f = PermissionSet::strict_gui();
        f.dbus.session.mode = DbusMode::Filtered;
        assert!(!plan(&f, &cfg, &sam_paths(), &no_proxy)
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
        let key = |h: &HostInfo| check_key(&app, &cfg, &sam_paths(), h);
        let same = key(&host);
        assert_eq!(key(&host.clone()), same, "the same computer");
        type Change = fn(&mut HostInfo);
        let changes: [(&str, Change); 5] = [
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

    /// Audit: a passing check is repeated when the kernel changed or a
    /// program that builds the sandbox is another build (an updated
    /// Bubblewrap, a rebuilt SAM helper, a new pasta), not only when SAM's
    /// version number or the settings did. A check of the same computer
    /// keeps its key.
    #[test]
    fn the_check_is_repeated_after_the_kernel_or_a_sandbox_program_changed() {
        let t = tempfile::tempdir().unwrap();
        let mut h = host_in(t.path());
        let (cfg, app) = (Config::default(), AppEntry::default());
        let file = |name: &str, body: &str| {
            let p = t.path().join(name);
            fs::write(&p, body).unwrap();
            p
        };
        let (bwrap, helper, pasta) = (
            file("bwrap", "1"),
            file("sam-jail-run", "1"),
            file("pasta", "1"),
        );
        h.tools.bwrap = Some(sam_core::host::Tool {
            path: bwrap.clone(),
            version: None,
        });
        let key = |h: &HostInfo| {
            let planned = plan(&app.profile.permissions, &cfg, &sam_paths(), h);
            check_key_with(
                &app,
                &cfg,
                h,
                Some(helper.clone()),
                Some(pasta.clone()),
                &planned,
            )
        };
        let before = key(&h);
        assert_eq!(key(&h), before, "the same computer, the same key");
        let mut newer = h.clone();
        newer.kernel = format!("{}-updated", h.kernel);
        assert_ne!(key(&newer), before, "another kernel");
        for p in [&bwrap, &helper, &pasta] {
            let base = key(&h);
            // A build of another size (its time may not change in a test).
            fs::write(p, "a new build").unwrap();
            assert_ne!(key(&h), base, "another build of {}", p.display());
        }
    }

    /// B2 R82: a passing check is repeated when what it would check on this
    /// computer changed, not only its settings and programs: a folder or
    /// key folder that appeared or went, a desktop service that started.
    /// The same computer keeps its key.
    #[test]
    fn the_check_is_repeated_when_what_it_would_check_changed() {
        let t = tempfile::tempdir().unwrap();
        let h = host_in(t.path());
        let (cfg, app) = (Config::default(), AppEntry::default());
        let key = |h: &HostInfo| {
            let planned = plan(&app.profile.permissions, &cfg, &sam_paths(), h);
            check_key_with(&app, &cfg, h, None, None, &planned)
        };
        let before = key(&h);
        assert_eq!(key(&h), before, "the same computer, the same key");
        // GnuPG's folder appears: the check now looks that it stays hidden.
        fs::create_dir_all(h.home.join(".gnupg")).unwrap();
        let with_gnupg = key(&h);
        assert_ne!(with_gnupg, before, "a key folder appeared");
        // The Documents folder goes.
        fs::remove_dir_all(h.home.join("Documents")).unwrap();
        assert_ne!(key(&h), with_gnupg, "a folder went");
    }

    /// B2 R82: what changes by itself does not enter the key: the value of
    /// a passed-through variable (a per-start token; a secret would go into
    /// the record) and which other port happens to listen. Whether the
    /// variable is set, and whether another port listens, do.
    #[test]
    fn the_key_leaves_out_what_changes_by_itself() {
        let check = |test| ProbePlan {
            checks: vec![c("x", "Network", "X", test)],
        };
        let env = |v: Option<&str>| {
            check(ProbeTest::Env {
                name: "TOKEN".into(),
                expect: v.map(String::from),
            })
        };
        assert_eq!(
            plan_fingerprint(&env(Some("a"))),
            plan_fingerprint(&env(Some("b")))
        );
        assert_ne!(
            plan_fingerprint(&env(Some("a"))),
            plan_fingerprint(&env(None))
        );
        let port = |port, expect| check(ProbeTest::LocalPort { port, expect });
        assert_eq!(
            plan_fingerprint(&port(631, false)),
            plan_fingerprint(&port(8080, false))
        );
        assert_ne!(
            plan_fingerprint(&port(631, true)),
            plan_fingerprint(&port(8080, true)),
            "a granted port is a setting"
        );
    }

    /// B2 R79: the check expects the session bus wherever the start gives
    /// one, also when SAM found the bus's socket without an address (the
    /// start uses that socket; the check expected no bus and failed).
    #[test]
    fn the_check_expects_the_bus_the_start_gives() {
        let t = tempfile::tempdir().unwrap();
        let mut h = host_in(t.path());
        h.sockets.dbus_session_address = None;
        h.sockets.dbus_session = Some(t.path().join("bus"));
        h.tools.xdg_dbus_proxy = Some(sam_core::host::Tool {
            path: "/usr/bin/xdg-dbus-proxy".into(),
            version: None,
        });
        let expect = |h: &HostInfo| {
            plan(
                &PermissionSet::strict_gui(),
                &Config::default(),
                &sam_paths(),
                h,
            )
            .checks
            .into_iter()
            .find_map(|c| match c.test {
                ProbeTest::SessionBus { expect } => Some(expect),
                _ => None,
            })
        };
        assert_eq!(expect(&h), Some(true), "the socket without an address");
        h.sockets.dbus_session = None;
        assert_eq!(expect(&h), Some(false), "no bus at all");
        // An address whose socket SAM did not find: the start gives no bus.
        h.sockets.dbus_session_address = Some("unix:path=/nonexistent/bus".into());
        assert_eq!(expect(&h), Some(false), "an address without its socket");
    }

    /// B2 R78: the check names the Wayland security context, which SAM
    /// sets up outside the sandbox: failed when the desktop refused it,
    /// passed when it is in place, not named when there is none to make.
    #[test]
    fn the_check_names_the_wayland_security_context() {
        let failed = wayland_context_result(false, true).unwrap();
        assert_eq!(failed.ok, Some(false), "{failed:?}");
        assert_eq!(failed.id, "wayland-context");
        assert_eq!(wayland_context_result(true, false).unwrap().ok, Some(true));
        assert!(wayland_context_result(false, false).is_none());
    }

    /// Review R72: for a 32-bit app whose filter has the socketcall gap, the
    /// check notes that the socket limit is incomplete, neither passed nor
    /// failed, so a check before each start never refuses the app over it.
    /// No note for a 64-bit program, a script or with the filter off, nor
    /// on a processor without the filter's 32-bit part. The note stays
    /// under the probe's last heading (Security), before the Wayland
    /// context (Display), so every heading appears once.
    #[test]
    fn the_check_notes_the_incomplete_socket_limit_without_failing() {
        let host = sam_core::sandbox::sample_context().host;
        let cfg = Config::default();
        let x86 = cfg!(target_arch = "x86_64");
        let app = |arch: &str, script: bool, filter: bool| {
            let mut e = AppEntry {
                detection: Some(sam_core::DependencyReport {
                    arch: arch.into(),
                    entry_is_script: script,
                    entry_binary: Some("usr/bin/game".into()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            e.profile.permissions = PermissionSet::strict_gui();
            e.profile.permissions.advanced.seccomp_baseline = filter;
            e.profile.permissions.advanced.seccomp_strict = false;
            e
        };
        let note = socket_limit_result(&app("i686", false, true), &cfg, &host);
        assert_eq!(note.is_some(), x86, "a 32-bit start program: {note:?}");
        assert!(
            socket_limit_result(&app("x86_64", false, true), &cfg, &host).is_none(),
            "a 64-bit program"
        );
        assert!(
            socket_limit_result(&app("i686", true, true), &cfg, &host).is_none(),
            "a script among 32-bit files"
        );
        assert!(
            socket_limit_result(&app("i686", false, false), &cfg, &host).is_none(),
            "the filter off for this app"
        );
        // The note itself, built on every processor from the x86-64 case's
        // fields, so its shape is checked where it cannot appear too.
        let note = note.unwrap_or_else(|| ProbeResult {
            id: "seccomp-32-bit-sockets".into(),
            group: sam_core::i18n::tr("Security"),
            title: String::new(),
            ok: None,
            observed: String::new(),
        });
        assert_eq!(note.id, "seccomp-32-bit-sockets");
        assert_eq!(note.ok, None, "neither passed nor failed: {note:?}");
        let passed = ProbeResult {
            id: "userns".into(),
            group: sam_core::i18n::tr("Security"),
            title: "Nested sandboxes blocked".into(),
            ok: Some(true),
            observed: String::new(),
        };
        let mut report = ProbeReport {
            results: vec![passed],
            enforcement: String::new(),
        };
        add_outside_results(&mut report, Some(note), wayland_context_result(true, true));
        assert_eq!(report.passed(), 2, "the probe's result and the context");
        assert!(
            report.failed().is_empty(),
            "the note never fails the check: {:?}",
            report.failed()
        );
        let ids: Vec<&str> = report.results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["userns", "seccomp-32-bit-sockets", "wayland-context"]);
        let groups: Vec<&str> = report.results.iter().map(|r| r.group.as_str()).collect();
        let mut runs = groups.clone();
        runs.dedup();
        let mut once = runs.clone();
        once.sort_unstable();
        once.dedup();
        assert_eq!(
            runs.len(),
            once.len(),
            "a heading appears twice: {groups:?}"
        );
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
            plan(p, &cfg, &sam_paths(), h)
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
