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

impl DbusProxy {
    pub fn start(
        host: &HostInfo,
        perms: &DbusBusPerms,
        runtime_dir: &Path,
        app_id: &str,
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
        let mut args = vec![
            address,
            socket.to_string_lossy().into_owned(),
            "--filter".into(),
        ];
        for name in &perms.allow {
            if perms.deny.iter().any(|d| d == name) {
                continue;
            }
            args.push(format!("--talk={name}"));
        }
        let activatable = sam_core::host::activatable_bus_names(&host.home);
        let mut refused = Vec::new();
        for name in &perms.own {
            // The tray's item names are SAM's own choice, never refused.
            let tray = name.starts_with("org.kde.StatusNotifierItem-")
                || name.starts_with("org.freedesktop.StatusNotifierItem-");
            if let Some(why) = (!tray)
                .then(|| sam_core::permissions::refuse_own_name(name, &activatable))
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
                args.extend((2..=16).map(|pid| format!("--own={name}-{pid}")));
            }
        }
        for rule in &perms.calls {
            args.push(format!("--call={rule}"));
        }
        for rule in &perms.broadcasts {
            args.push(format!("--broadcast={rule}"));
        }
        // Let the app own names under its own id.
        args.push(format!(
            "--own=io.github.gitzekatze.SAM.{}.*",
            app_id.replace('-', "_")
        ));
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
