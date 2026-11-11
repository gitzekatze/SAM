//! sam-runner: the orchestration layer shared by the CLI and the GUI.
//!
//! * [`ops`]: the [`ops::SAM`] facade: add, re-extract, stale handling,
//!   permissions, presets, scanning
//! * [`bwrap`]: checks that Bubblewrap can run here
//! * [`launch`]: building and running sandboxes, logs and crash capture
//! * [`dbus_proxy`]: filtered session bus through xdg-dbus-proxy
//! * [`kernel`]: Landlock and seccomp
//! * [`doctor`]: environment checks, diagnostics and bug reports
//! * [`diagnose`]: dynamic dependency fallback via strace

pub mod bwrap;
pub mod dbus_check;
pub mod dbus_proxy;
pub mod diagnose;
pub mod doctor;
pub mod kernel;
pub mod launch;
pub mod netns;
pub mod ops;
pub mod probe;
pub mod repair;
pub mod verify;
pub mod wayland_ctx;

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
