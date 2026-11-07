//! sam-runner: the orchestration layer shared by the CLI and the GUI.
//!
//! * [`ops`]: the [`ops::SAM`] facade: add, re-extract, stale handling,
//!   permissions, presets, scanning
//! * [`select`]: backend selection logic (§2.13.3)
//! * [`launch`]: building and running sandboxes, logs and crash capture
//! * [`dbus_proxy`]: filtered session bus through xdg-dbus-proxy
//! * [`kernel`]: Landlock and seccomp (§2.22.2)
//! * [`doctor`]: environment checks, diagnostics and bug reports
//! * [`diagnose`]: dynamic dependency fallback via strace (§2.16.3)

pub mod dbus_proxy;
pub mod diagnose;
pub mod doctor;
pub mod kernel;
pub mod launch;
pub mod netns;
pub mod ops;
pub mod repair;
pub mod select;

use sam_core::{Backend, BackendKind};

pub fn backend_for(kind: BackendKind) -> Option<&'static dyn Backend> {
    match kind {
        BackendKind::Bubblewrap => Some(&sam_backend_bubblewrap::Bubblewrap),
        BackendKind::Bubblejail => Some(&sam_backend_bubblejail::Bubblejail),
        BackendKind::Firejail => Some(&sam_backend_firejail::Firejail),
        BackendKind::Unsandboxed => None,
    }
}

/// Locate the `sam-jail-run` helper (used for desktop launchers and as the
/// in-sandbox Landlock helper).
pub fn find_helper() -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if exe.file_name().is_some_and(|n| n == "sam-jail-run") {
            return Some(exe);
        }
        if let Some(dir) = exe.parent() {
            let c = dir.join("sam-jail-run");
            if c.exists() {
                return Some(c);
            }
        }
    }
    sam_core::util::which("sam-jail-run")
}
