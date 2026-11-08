//! Portal identity: make xdg-desktop-portal treat a SAM app as a sandboxed
//! app (the way Flatpak apps are identified), so that
//! - files picked in a portal file dialog are handed to the app through the
//!   document portal (`/run/user/<uid>/doc/<id>/<file>`) instead of as host
//!   paths the sandbox cannot see, and
//! - portals apply their per-app rules and prompts instead of trusting the
//!   app like an ordinary program.
//!
//! How the portal identifies apps: it looks at the process on the other end
//! of the D-Bus connection (SAM's xdg-dbus-proxy), reads `/.flatpak-info`
//! from that process's root, and the instance's `bwrapinfo.json` under
//! `/run/user/<uid>/.flatpak/<instance>/`. So SAM writes that file, runs the
//! proxy inside a minimal Bubblewrap sandbox that carries it, binds it into
//! the app's sandbox (GTK and Qt then use portal dialogs on their own), and
//! lets the app's bwrap write `bwrapinfo.json` via `--info-fd`.

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sam_core::backend::PortalIdentity;

pub const APP_ID_PREFIX: &str = "io.github.gitzekatze.SAM";

/// Portal app id for a SAM app id (`appimage-tuta-8dda` ->
/// `io.github.gitzekatze.SAM.appimage_tuta_8dda`).
pub fn portal_app_id(sam_id: &str) -> String {
    let last: String = sam_id.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let last = if last.starts_with(|c: char| c.is_ascii_digit()) { format!("app_{last}") } else { last };
    format!("{APP_ID_PREFIX}.{last}")
}

/// A registered instance; removes its runtime directory when dropped.
pub struct Instance {
    pub identity: PortalIdentity,
    dir: PathBuf,
    /// `bwrapinfo.json`, open for bwrap's `--info-fd` until the app starts.
    info_out: Option<File>,
}

impl Instance {
    pub fn create(runtime_dir: &Path, uid: u32, sam_id: &str) -> Result<Instance> {
        let app_id = portal_app_id(sam_id);
        let instance_id = instance_number();
        let info_for = |instance_id: u64| format!(
            "[Application]\nname={app_id}\nruntime=runtime/{APP_ID_PREFIX}.Host/{arch}/host\n\n[Instance]\ninstance-id={instance_id}\nsession-bus-proxy=true\n",
            arch = std::env::consts::ARCH
        );
        // Never reuse a directory: a real Flatpak instance may own it. Only a
        // directory created here is ever written to or deleted.
        let base = PathBuf::from(format!("/run/user/{uid}/.flatpak"));
        fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
        remove_stale(&base);
        let mut instance_id = instance_id;
        let mut dir = base.join(instance_id.to_string());
        let mut tries = 0;
        loop {
            match fs::create_dir(&dir) {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 16 => {
                    tries += 1;
                    instance_id = instance_number().wrapping_add(tries * 7919);
                    dir = base.join(instance_id.to_string());
                }
                Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
            }
        }
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        let info = info_for(instance_id);
        let info_file = runtime_dir.join("flatpak-info");
        fs::write(&info_file, &info)?;
        fs::write(dir.join("info"), &info)?;
        let out = File::create(dir.join("bwrapinfo.json"))?;
        // bwrap must inherit it.
        unsafe { libc::fcntl(out.as_raw_fd(), libc::F_SETFD, 0) };
        // Make the document portal create this app's view.
        let doc_view = PathBuf::from(format!("/run/user/{uid}/doc/by-app/{app_id}"));
        let _ = fs::metadata(&doc_view);
        Ok(Instance {
            identity: PortalIdentity { app_id, info_file, info_fd: Some(out.as_raw_fd()), doc_view: doc_view.exists().then_some(doc_view) },
            dir,
            info_out: Some(out),
        })
    }

    /// Close SAM's copy of the info fd once bwrap has started.
    pub fn started(&mut self) {
        self.info_out.take();
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Removes SAM instances whose app is gone (SAM was killed before it could
/// clean up). Only directories whose `info` names a SAM app are touched;
/// real Flatpak instances are never removed.
fn remove_stale(base: &Path) {
    let Ok(rd) = fs::read_dir(base) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let dir = e.path();
        let Ok(info) = fs::read_to_string(dir.join("info")) else { continue };
        if !is_sam_instance(&info) {
            continue;
        }
        let pid = fs::read_to_string(dir.join("bwrapinfo.json")).ok().and_then(|j| child_pid(&j));
        let gone = match pid {
            Some(pid) => !Path::new(&format!("/proc/{pid}")).exists(),
            // Never started: stale once it is older than a minute.
            None => e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age.as_secs() > 60),
        };
        if gone {
            let _ = fs::remove_dir_all(&dir);
        }
    }
}

fn is_sam_instance(info: &str) -> bool {
    info.lines().any(|l| l.strip_prefix("name=").is_some_and(|n| n.starts_with(&format!("{APP_ID_PREFIX}."))))
        && info.contains(&format!("runtime=runtime/{APP_ID_PREFIX}.Host/"))
}

fn child_pid(bwrapinfo: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(bwrapinfo).ok()?;
    v.get("child-pid")?.as_u64().map(|p| p as u32)
}

fn instance_number() -> u64 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos() as u64).unwrap_or(0);
    1_000_000_000 + (nanos ^ (std::process::id() as u64) << 7) % 3_000_000_000
}

/// Wrap the xdg-dbus-proxy command line in a minimal Bubblewrap sandbox
/// that carries the identity file at `/.flatpak-info`.
pub fn wrap_proxy(bwrap: &Path, info_file: &Path, runtime_dir: &Path, bus_socket: Option<&Path>, proxy: &Path, proxy_args: &[String]) -> (PathBuf, Vec<String>) {
    let mut a: Vec<String> = ["--die-with-parent", "--unshare-user", "--unshare-pid", "--tmpfs", "/", "--ro-bind", "/usr", "/usr"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for d in ["/lib", "/lib64", "/bin", "/sbin"] {
        a.extend(["--ro-bind-try".into(), d.into(), d.into()]);
    }
    a.extend(["--ro-bind".into(), "/etc".into(), "/etc".into(), "--dev".into(), "/dev".into(), "--proc".into(), "/proc".into()]);
    let rd = runtime_dir.to_string_lossy().into_owned();
    a.extend(["--bind".into(), rd.clone(), rd]);
    if let Some(sock) = bus_socket {
        let s = sock.to_string_lossy().into_owned();
        a.extend(["--ro-bind".into(), s.clone(), s]);
    }
    a.extend(["--ro-bind".into(), info_file.to_string_lossy().into_owned(), "/.flatpak-info".into()]);
    a.push("--".into());
    a.push(proxy.to_string_lossy().into_owned());
    a.extend(proxy_args.iter().cloned());
    (bwrap.to_path_buf(), a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids_are_valid_dbus_names() {
        assert_eq!(portal_app_id("appimage-tuta-8dda"), "io.github.gitzekatze.SAM.appimage_tuta_8dda");
        assert_eq!(portal_app_id("9lives"), "io.github.gitzekatze.SAM.app_9lives");
    }

    #[test]
    fn only_dead_sam_instances_are_removed() {
        let t = tempfile::tempdir().unwrap();
        let sam_info = "[Application]\nname=io.github.gitzekatze.SAM.appimage_x\nruntime=runtime/io.github.gitzekatze.SAM.Host/x86_64/host\n";
        let mk = |n: &str, info: &str, pid: u32| {
            let d = t.path().join(n);
            fs::create_dir(&d).unwrap();
            fs::write(d.join("info"), info).unwrap();
            fs::write(d.join("bwrapinfo.json"), format!("{{\"child-pid\": {pid}}}")).unwrap();
        };
        mk("100", sam_info, 4_000_000_000);
        mk("101", sam_info, std::process::id());
        mk("102", "[Application]\nname=com.tutanota.Tutanota\nruntime=runtime/org.freedesktop.Platform/x86_64/24.08\n", 4_000_000_000);
        remove_stale(t.path());
        assert!(!t.path().join("100").exists(), "dead SAM instance removed");
        assert!(t.path().join("101").exists(), "running SAM instance kept");
        assert!(t.path().join("102").exists(), "Flatpak instance never touched");
    }

}
