//! Filtered session bus through `xdg-dbus-proxy` (Bubblewrap backend).

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use appseal_core::permissions::DbusBusPerms;
use appseal_core::HostInfo;

pub struct DbusProxy {
    child: Child,
    pub socket: PathBuf,
    pub args: Vec<String>,
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
        for name in &perms.own {
            args.push(format!("--own={name}"));
        }
        args.extend(tray_own_names(perms).into_iter().map(|n| format!("--own={n}")));
        // Let the app own names under its own id, like Flatpak does.
        args.push(format!("--own=org.appseal.{}.*", app_id.replace('-', "_")));
        let mut cmd = Command::new(&tool.path);
        cmd.args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                // Die together with appseal-run.
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
        Ok(DbusProxy { child, socket, args })
    }
}

impl Drop for DbusProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Bus names a tray icon registers under (`org.kde.StatusNotifierItem-<pid>-<n>`,
/// used by libappindicator, Qt and Electron). xdg-dbus-proxy cannot wildcard
/// the suffix, so, like Flatpak, grant the concrete names. The app runs in its
/// own PID namespace, so its PID is small (2 when AppRun execs the binary).
pub fn tray_own_names(perms: &DbusBusPerms) -> Vec<String> {
    if !perms.allow.iter().any(|n| n == "org.kde.StatusNotifierWatcher") {
        return vec![];
    }
    let mut names = Vec::new();
    for prefix in ["org.kde.StatusNotifierItem", "org.freedesktop.StatusNotifierItem"] {
        for pid in 2..=12 {
            for n in 1..=2 {
                names.push(format!("{prefix}-{pid}-{n}"));
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use appseal_core::permissions::DbusPerms;

    #[test]
    fn tray_names_follow_watcher_permission() {
        let mut p = DbusPerms::default().session;
        let names = tray_own_names(&p);
        assert!(names.contains(&"org.kde.StatusNotifierItem-2-1".to_string()));
        assert!(names.contains(&"org.freedesktop.StatusNotifierItem-2-1".to_string()));
        p.allow.retain(|n| n != "org.kde.StatusNotifierWatcher");
        assert!(tray_own_names(&p).is_empty());
    }
}
