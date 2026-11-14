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
}

impl DbusProxy {
    pub fn start(host: &HostInfo, perms: &DbusBusPerms, runtime_dir: &Path, app_id: &str) -> Result<DbusProxy> {
        let tool = host.tools.xdg_dbus_proxy.as_ref().context("xdg-dbus-proxy is not installed")?;
        let address = host
            .sockets
            .dbus_session_address
            .clone()
            .or_else(|| host.sockets.dbus_session.as_ref().map(|p| format!("unix:path={}", p.display())))
            .context("no session bus address")?;
        let socket = runtime_dir.join("bus");
        let _ = std::fs::remove_file(&socket);
        let mut args = vec![address, socket.to_string_lossy().into_owned(), "--filter".into()];
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
            let tray = name.starts_with("org.kde.StatusNotifierItem-") || name.starts_with("org.freedesktop.StatusNotifierItem-");
            if let Some(why) = (!tray).then(|| sam_core::permissions::refuse_own_name(name, &activatable)).flatten() {
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
        args.push(format!("--own=io.github.gitzekatze.SAM.{}.*", app_id.replace('-', "_")));
        // Diagnostics: with SAM_DBUS_LOG set to a file, the proxy logs every
        // call it passes, filters or answers itself (for finding calls an
        // app waits on, such as a blocked service it expects to exist).
        let log = std::env::var_os("SAM_DBUS_LOG").and_then(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok());
        if log.is_some() {
            args.push("--log".into());
        }
        let (program, argv) = (tool.path.clone(), args.clone());
        let mut cmd = Command::new(&program);
        cmd.args(&argv).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        if let Some(f) = log {
            if let Ok(f2) = f.try_clone() {
                cmd.stdout(f).stderr(f2);
            }
        }
        unsafe {
            cmd.pre_exec(|| {
                // Die together with sam-jail-run.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let mut child = cmd.spawn().context("starting xdg-dbus-proxy")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while !socket.exists() {
            if let Some(st) = child.try_wait()? {
                bail!("xdg-dbus-proxy exited early ({st})");
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                bail!("xdg-dbus-proxy did not create its socket in time");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(DbusProxy { child, socket, args, refused })
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
