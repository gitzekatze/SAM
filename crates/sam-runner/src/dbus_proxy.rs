//! Filtered session bus through `xdg-dbus-proxy` (for the Bubblewrap sandbox).

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use sam_core::permissions::DbusBusPerms;
use sam_core::HostInfo;

pub struct DbusProxy {
    child: Child,
    pub socket: PathBuf,
    pub args: Vec<String>,
    /// Names the settings allow but SAM refused (name, why).
    pub refused: Vec<(String, String)>,
    /// Names the app asked to own and the proxy refused, as the proxy's
    /// own record says (not what the app printed).
    wanted: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

/// At most this many names are learned per start: an app asking for
/// hundreds is not looking for its own name.
pub const MAX_WANTED_NAMES: usize = 8;

/// Keeps `name` among the wanted names: once, and at most
/// [`MAX_WANTED_NAMES`].
fn remember(wanted: &mut Vec<String>, name: String) {
    if !wanted.contains(&name) && wanted.len() < MAX_WANTED_NAMES {
        wanted.push(name);
    }
}

/// The name the app asked to own, from one line of the proxy's record:
/// `Filtering message due to arg0 NAME, policy: P (required 3)` (3 is
/// "own"). Only well-formed bus names count.
pub fn wanted_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix("Filtering message due to arg0 ")?;
    let (name, tail) = rest.split_once(", policy: ")?;
    if !tail.trim_end().ends_with("(required 3)") {
        return None;
    }
    sam_core::permissions::is_bus_name(name).then(|| name.to_string())
}

/// The desktop services SAM allows by default or through an integration
/// switch, with the object paths of their own protocol (`/x/*`: that path
/// and everything below it).
///
/// The filter (xdg-dbus-proxy) gives a program's unique name (`:1.10`) the
/// rules of every name it owns, and a plain `--talk` lets every call
/// through. One program often holds many names: on KDE Plasma 6,
/// plasmashell owns the notification service and also Klipper (the
/// clipboard history) and the shell's script runner; kded6 owns the tray
/// watcher and the desktop's background services; KWin owns the screen
/// saver name and its own scripting; Dolphin owns the file manager name and
/// its menu actions. So for these names the app gets calls and signals on
/// the service's own objects only, which the filter checks for the unique
/// name too (B2 R76, 2026-11-25). The keyring keeps `--talk`: that switch
/// hands out stored passwords anyway.
const SERVICE_PATHS: &[(&str, &[&str])] = &[
    (
        "org.freedesktop.Notifications",
        &["/org/freedesktop/Notifications"],
    ),
    ("org.kde.StatusNotifierWatcher", &["/StatusNotifierWatcher"]),
    (
        "org.freedesktop.ScreenSaver",
        &["/ScreenSaver", "/org/freedesktop/ScreenSaver"],
    ),
    (
        "org.freedesktop.PowerManagement",
        &["/org/freedesktop/PowerManagement/*"],
    ),
    (
        "org.freedesktop.FileManager1",
        &["/org/freedesktop/FileManager1"],
    ),
    // The input methods' sandbox frontends (Fcitx 5 runs its controller,
    // which can change its configuration, on the same connection).
    (
        "org.freedesktop.portal.Fcitx",
        &["/org/freedesktop/portal/*", "/inputmethod"],
    ),
    ("org.freedesktop.portal.IBus", &["/org/freedesktop/IBus/*"]),
];

/// The object paths the app may reach on `name`, when it is one of
/// [`SERVICE_PATHS`] (exact names only).
fn service_paths(name: &str) -> Option<&'static [&'static str]> {
    SERVICE_PATHS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, paths)| *paths)
}

/// The proxy's filter for `perms`: what the app may talk to and own, and
/// the names the settings allow that SAM refused (name, why).
/// `may_own` is the start's full check of a name ([`crate::own_names::NameCheck`]).
///
/// The tray's item names are exempt from the check only as the exact names
/// SAM chose ([`DbusBusPerms::tray_own_names`]), never as anything that
/// starts like one. The numbered instance names SAM adds for KDE apps
/// (`org.kde.kdenlive-3`) pass the same checks as the name itself; one that
/// fails is left out without a word, as nobody asked for it (audit L-F13).
fn filter_args(
    perms: &DbusBusPerms,
    activatable: &std::collections::BTreeSet<String>,
    app_id: &str,
    may_own: &dyn Fn(&str) -> bool,
) -> (Vec<String>, Vec<(String, String)>) {
    let mut args = vec!["--filter".to_string()];
    // The always-blocked names, checked again here for every list (the
    // start's rules come from `effective_session_bus`, which leaves them
    // out already).
    let denied = |n: &str| sam_core::permissions::bus_name_denied(&perms.deny, n);
    for name in perms.allow.iter().filter(|n| !denied(n)) {
        match service_paths(name) {
            // A desktop service SAM knows: only its own objects (B2 R76).
            Some(paths) => {
                for path in paths {
                    args.push(format!("--call={name}=*@{path}"));
                    args.push(format!("--broadcast={name}=*@{path}"));
                }
            }
            None => args.push(format!("--talk={name}")),
        }
    }
    let tray_names = perms.tray_own_names();
    let mut refused = Vec::new();
    for name in perms.own.iter().filter(|n| !denied(n)) {
        // The tray's item names are SAM's own choice, never refused.
        let tray = tray_names.contains(name);
        if let Some(why) = (!tray)
            .then(|| sam_core::permissions::refuse_own_name(name, activatable))
            .flatten()
        {
            refused.push((name.clone(), why));
            continue;
        }
        args.push(format!("--own={name}"));
        if !tray && !name.ends_with('*') {
            // KDE apps that allow several instances register their name
            // with the process number ("org.kde.kdenlive-3"); in the
            // sandbox's own process list it is small.
            args.extend(
                (2..=16)
                    .map(|pid| format!("{name}-{pid}"))
                    .filter(|n| {
                        sam_core::permissions::refuse_own_name(n, activatable).is_none()
                            && may_own(n)
                            && !denied(n)
                    })
                    .map(|n| format!("--own={n}")),
            );
        }
    }
    for rule in perms.calls.iter().filter(|r| !denied(r)) {
        args.push(format!("--call={rule}"));
    }
    for rule in perms.broadcasts.iter().filter(|r| !denied(r)) {
        args.push(format!("--broadcast={rule}"));
    }
    // Let the app own names under its own id.
    args.push(format!(
        "--own=io.github.gitzekatze.SAM.{}.*",
        app_id.replace('-', "_")
    ));
    (args, refused)
}

impl DbusProxy {
    /// `may_own`: see [`filter_args`].
    pub fn start(
        host: &HostInfo,
        perms: &DbusBusPerms,
        runtime_dir: &Path,
        app_id: &str,
        may_own: &dyn Fn(&str) -> bool,
    ) -> Result<DbusProxy> {
        let tool = host.tools.xdg_dbus_proxy.as_ref().context(sam_core::i18n::tr("xdg-dbus-proxy is not installed, so SAM cannot give the app filtered access to desktop services (file dialogs, notifications, the tray). Install the package xdg-dbus-proxy, or turn the app's session bus to No access."))?;
        let address = host
            .sockets
            .dbus_session_address
            .clone()
            .or_else(|| {
                host.sockets
                    .dbus_session
                    .as_ref()
                    .map(|p| format!("unix:path={}", p.display()))
            })
            .context(sam_core::i18n::tr("no session bus address"))?;
        let socket = runtime_dir.join("bus");
        let _ = std::fs::remove_file(&socket);
        let activatable = sam_core::host::activatable_bus_names(&host.home);
        let (filter, refused) = filter_args(perms, &activatable, app_id, may_own);
        let mut args = vec![address, socket.to_string_lossy().into_owned()];
        args.extend(filter);
        // Diagnostics: with SAM_DBUS_LOG set to a file, the proxy logs every
        // call it passes, filters or answers itself (for finding calls an
        // app waits on, such as a blocked service it expects to exist).
        let log = std::env::var_os("SAM_DBUS_LOG").and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
        });
        // The proxy's record tells which names the app asked to own and
        // was refused (option D of 2026-11-18: SAM learns the name from the
        // proxy, never from the app's own output).
        args.push("--log".into());
        let (program, argv) = (tool.path.clone(), args.clone());
        let mut cmd = Command::new(&program);
        cmd.args(&argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // SAFETY: the pre_exec closure runs between fork and exec and calls only prctl, which is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                // Die together with sam-jail-run.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let mut child = cmd
            .spawn()
            .context(sam_core::i18n::tr("starting xdg-dbus-proxy"))?;
        // Read the record as it comes (a full pipe would stall the proxy),
        // keep only refused own-name requests, and copy everything to
        // SAM_DBUS_LOG when that is set.
        let wanted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        if let Some(out) = child.stdout.take() {
            let wanted = wanted.clone();
            let mut log = log;
            std::thread::spawn(move || {
                use std::io::{BufRead, Write};
                for line in std::io::BufReader::new(out).lines().map_while(|l| l.ok()) {
                    if let Some(f) = log.as_mut() {
                        let _ = writeln!(f, "{line}");
                    }
                    if let Some(name) = wanted_name(&line) {
                        if let Ok(mut w) = wanted.lock() {
                            remember(&mut w, name);
                        }
                    }
                }
            });
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        // The socket file appears before the proxy listens on it; an app
        // that connected in between was refused (seen in CI). Wait until a
        // connection really succeeds.
        while !accepting(&socket) {
            if let Some(st) = child.try_wait()? {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "xdg-dbus-proxy exited early ({status})",
                        &[("status", &st)]
                    )
                );
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                bail!(
                    "{}",
                    sam_core::i18n::tr("xdg-dbus-proxy did not create its socket in time")
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(DbusProxy {
            child,
            socket,
            args,
            refused,
            wanted,
        })
    }

    /// The names the app asked to own and was refused, so far.
    pub fn wanted_names(&self) -> Vec<String> {
        self.wanted.lock().map(|w| w.clone()).unwrap_or_default()
    }
}

impl Drop for DbusProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

#[cfg(test)]
mod tests {
    use sam_core::permissions::DbusPerms;

    /// The proxy's filter never names an always-blocked name, in any of
    /// its rules, also when the rules it is given still hold one: the
    /// second line behind `effective_session_bus`.
    #[test]
    fn the_filter_never_names_an_always_blocked_name() {
        let mut p = DbusPerms::default().session;
        p.deny = vec!["org.x.*".into(), "org.ok.Mine-3".into()];
        p.allow = vec!["org.x.A".into(), "org.ok.A".into()];
        p.own = vec!["org.x.Mine".into(), "org.ok.Mine".into()];
        p.calls = vec!["org.x.A=a.b@/c".into()];
        p.broadcasts = vec!["org.x.A=@/d".into()];
        let (args, _) = super::filter_args(&p, &Default::default(), "appimage-x", &|_| true);
        assert!(!args.iter().any(|a| a.contains("org.x.")), "{args:?}");
        assert!(args.contains(&"--talk=org.ok.A".to_string()), "{args:?}");
        // Its numbered instance names too (`org.ok.Mine-2` to `-16`).
        assert!(
            !args.contains(&"--own=org.ok.Mine-3".to_string()),
            "{args:?}"
        );
        assert!(
            args.contains(&"--own=org.ok.Mine-4".to_string()),
            "{args:?}"
        );
    }

    /// B2 R76: a desktop service SAM allows by default or through a switch
    /// gets calls and signals on its own objects only, never a plain
    /// `--talk`, which would open every object of the program behind it
    /// (on Plasma 6, plasmashell's clipboard history and script runner
    /// behind the notification service). A name SAM does not know keeps
    /// `--talk`; an always-blocked one gets no rule at all.
    #[test]
    fn known_desktop_services_reach_only_their_own_objects() {
        let mut p = DbusPerms::default().session;
        for name in super::SERVICE_PATHS
            .iter()
            .map(|(n, _)| *n)
            .chain(["org.example.Other"])
        {
            // The defaults are there already.
            if !p.allow.iter().any(|a| a == name) {
                p.allow.push(name.into());
            }
        }
        p.deny = vec!["org.freedesktop.FileManager1".into()];
        let (args, _) = super::filter_args(&p, &Default::default(), "appimage-x", &|_| true);
        for (name, paths) in super::SERVICE_PATHS {
            assert!(
                !args.contains(&format!("--talk={name}")),
                "{name}: {args:?}"
            );
            if *name == "org.freedesktop.FileManager1" {
                assert!(!args.iter().any(|a| a.contains(name)), "blocked: {args:?}");
                continue;
            }
            let rules: Vec<&String> = args
                .iter()
                .filter(|a| a.contains(&format!("={name}=")))
                .collect();
            assert_eq!(rules.len(), 2 * paths.len(), "{name}: {rules:?}");
            for path in *paths {
                assert!(path.starts_with('/'), "{name}: {path}");
                for kind in ["--call", "--broadcast"] {
                    assert!(
                        args.contains(&format!("{kind}={name}=*@{path}")),
                        "{kind} {name} {path}: {args:?}"
                    );
                }
            }
        }
        // Every name SAM allows by default or through a switch is among
        // them, except the portal (its own rules, `effective_session_bus`)
        // and the keyring (which hands out passwords anyway).
        let all = sam_core::permissions::IntegrationPerms {
            keyring: false,
            media_controls: true,
            file_manager: true,
            input_method: true,
            ..Default::default()
        };
        let defaults = sam_core::permissions::default_session_allow();
        for name in defaults
            .iter()
            .map(String::as_str)
            .filter(|n| *n != sam_core::permissions::PORTAL_NAME)
            .chain(all.bus_names().0)
        {
            assert!(super::service_paths(name).is_some(), "{name}");
        }
        assert!(
            args.contains(&"--talk=org.example.Other".to_string()),
            "{args:?}"
        );
        // The paths are the ones these services use (checked 2026-11-25 on
        // KDE Plasma 6 and in the Fcitx 5 and IBus sources).
        assert_eq!(
            super::service_paths("org.freedesktop.Notifications"),
            Some(&["/org/freedesktop/Notifications"][..])
        );
        assert_eq!(
            super::service_paths("org.kde.StatusNotifierWatcher"),
            Some(&["/StatusNotifierWatcher"][..])
        );
    }

    /// Only the proxy's "wants to own" lines name a name to learn, and
    /// only a well-formed one (what the app printed never reaches this).
    #[test]
    fn the_proxy_record_names_what_the_app_wanted_to_own() {
        use super::wanted_name;
        let own = "Filtering message due to arg0 org.example.Wanted, policy: 0 (required 3)";
        assert_eq!(wanted_name(own).as_deref(), Some("org.example.Wanted"));
        for no in [
            "Filtering message due to arg0 org.example.Talk, policy: 0 (required 2)",
            "Filtering message due to arg0 :1.42, policy: 0 (required 3)",
            "Filtering message due to arg0 x, policy: 0 (required 3)",
            "C2: -> org.freedesktop.DBus call org.freedesktop.DBus.RequestName",
            "app said: Filtering message due to arg0 org.gnome.Terminal, policy: 0 (required 3)",
        ] {
            assert_eq!(wanted_name(no), None, "{no}");
        }
    }

    /// A name is kept once, and no more than eight in all.
    #[test]
    fn wanted_names_are_kept_once_and_at_most_eight() {
        let mut w = Vec::new();
        super::remember(&mut w, "org.example.A".into());
        super::remember(&mut w, "org.example.A".into());
        assert_eq!(w, ["org.example.A"]);
        for i in 0..20 {
            super::remember(&mut w, format!("org.example.N{i}"));
        }
        assert_eq!(w.len(), super::MAX_WANTED_NAMES);
        assert!(w.contains(&"org.example.N6".to_string()));
        assert!(!w.contains(&"org.example.N7".to_string()));
    }

    /// An app may register a tray icon only while the tray service is allowed.
    #[test]
    fn tray_names_follow_watcher_permission() {
        let mut p = DbusPerms::default().session;
        let names = p.tray_own_names();
        assert!(names.contains(&"org.kde.StatusNotifierItem-2-1".to_string()));
        assert!(names.contains(&"org.freedesktop.StatusNotifierItem-2-1".to_string()));
        p.allow.retain(|n| n != "org.kde.StatusNotifierWatcher");
        assert!(p.tray_own_names().is_empty());
    }

    /// Audit L-F13: the numbered instance names SAM adds to an allowed name
    /// (`org.example.App-3`) pass the same checks as the name itself, so an
    /// on-demand service or another app's name among them is never granted
    /// unchecked; and only the exact tray names SAM chose skip the check,
    /// not every name that starts like one.
    #[test]
    fn added_instance_names_and_tray_look_alikes_are_checked() {
        let mut p = DbusPerms::default().session;
        let tray = p.tray_own_names();
        p.own = vec!["org.example.App".into()];
        p.own.extend(tray.iter().cloned());
        // Not SAM's: a look-alike of a tray name in the desktop's protocol.
        p.own.push("org.freedesktop.StatusNotifierItem-evil".into());
        let activatable: std::collections::BTreeSet<String> =
            ["org.example.App-3".to_string()].into();
        // The start's check refuses another SAM app's name.
        let may_own = |n: &str| n != "org.example.App-5";
        let (args, refused) = super::filter_args(&p, &activatable, "appimage-x", &may_own);
        let owns = |n: &str| args.contains(&format!("--own={n}"));
        assert!(owns("org.example.App") && owns("org.example.App-2") && owns("org.example.App-16"));
        assert!(!owns("org.example.App-3"), "an on-demand service: {args:?}");
        assert!(!owns("org.example.App-5"), "another app's name: {args:?}");
        assert!(tray.iter().all(|t| owns(t)), "SAM's tray names: {args:?}");
        assert!(!owns("org.freedesktop.StatusNotifierItem-evil"), "{args:?}");
        assert_eq!(
            refused.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["org.freedesktop.StatusNotifierItem-evil"],
            "only names someone asked for are reported"
        );
        // Instance names are added only to the app's own names, never to
        // SAM's tray names (mutation run 2026-11-24).
        assert!(
            tray.iter().all(|t| !owns(&format!("{t}-2"))),
            "no instances of tray names: {args:?}"
        );
    }

    /// A name on the always-blocked list is not talked to although it is
    /// allowed, and blocking one name leaves the other allowed names alone
    /// (mutation run 2026-11-24: the comparison could be turned around
    /// unnoticed).
    #[test]
    fn an_always_blocked_name_is_not_talked_to_and_others_stay_allowed() {
        let mut p = DbusPerms::default().session;
        p.allow = vec!["org.a.B".into(), "org.c.D".into()];
        p.deny = vec!["org.x.Y".into(), "org.a.B".into()];
        let (args, _) = super::filter_args(&p, &Default::default(), "appimage-x", &|_| true);
        assert!(!args.contains(&"--talk=org.a.B".to_string()), "{args:?}");
        assert!(args.contains(&"--talk=org.c.D".to_string()), "{args:?}");
    }
}

/// Whether something listens on the Unix socket at `path` (an existing
/// file alone is not enough).
fn accepting(path: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(test)]
mod accepting_tests {
    /// The proxy counts as ready only when its socket accepts connections,
    /// not when the file merely exists (regression: the sandbox check
    /// sometimes found the session bus refused right after the start).
    #[test]
    fn a_socket_counts_as_ready_only_when_it_accepts() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("bus");
        assert!(!super::accepting(&path), "nothing there yet");
        std::fs::write(&path, b"").unwrap();
        assert!(
            !super::accepting(&path),
            "a file that exists is not a listening socket"
        );
        std::fs::remove_file(&path).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(super::accepting(&path));
    }
}
