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
pub mod contracts;
pub mod dbus_check;
pub mod dbus_proxy;
pub mod diagnose;
pub mod doctor;
pub mod kernel;
pub mod launch;
pub mod netns;
pub mod ops;
pub mod probe;
pub mod progress;
pub mod pty;
pub mod release_key;
pub mod repair;
pub mod updates;
pub mod verify;
pub mod wayland_ctx;
pub mod zsync;

/// Locate the `sam-jail-run` helper (used for desktop launchers and as the
/// in-sandbox Landlock helper): this program, the one next to it, the one
/// of the same Cargo build, or the first on `PATH`. Tests run from inside
/// Cargo's build folder (`target/<profile>/…`, marked by `.cargo-lock`),
/// with the helper at its top; without that step, a test (or a mutation
/// run) that needs the helper skipped itself unless `PATH` was set by hand.
pub fn find_helper() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| helper_for(&exe))
        .or_else(|| sam_core::util::which("sam-jail-run"))
}

/// The helper for the program `exe`, without looking at `PATH`.
fn helper_for(exe: &std::path::Path) -> Option<std::path::PathBuf> {
    if exe.file_name().is_some_and(|n| n == "sam-jail-run") {
        return Some(exe.to_path_buf());
    }
    let dir = exe.parent()?;
    let next_to = dir.join("sam-jail-run");
    if next_to.exists() {
        return Some(next_to);
    }
    dir.ancestors()
        .take(6)
        .find(|d| d.join(".cargo-lock").is_file())
        .map(|d| d.join("sam-jail-run"))
        .filter(|c| c.exists())
}

#[cfg(test)]
mod helper_tests {
    use super::helper_for;
    use std::fs;

    /// A test program inside Cargo's build folder finds the helper of its
    /// own build, so tests that need it run instead of skipping; an
    /// installed program never looks above its own folder.
    #[test]
    fn tests_find_the_helper_of_their_own_build() {
        let t = tempfile::tempdir().unwrap();
        let profile = t.path().join("target/debug");
        let out = profile.join("build/sam-runner/0123abcd/out");
        fs::create_dir_all(&out).unwrap();
        fs::write(profile.join("sam-jail-run"), b"").unwrap();
        let test_program = out.join("verify-0123abcd");
        assert_eq!(
            helper_for(&test_program),
            None,
            "no build marker: not a Cargo build"
        );
        fs::write(profile.join(".cargo-lock"), b"").unwrap();
        assert_eq!(
            helper_for(&test_program),
            Some(profile.join("sam-jail-run"))
        );
        // Next to the program comes first, as in an installation.
        let bin = t.path().join("usr/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("sam-jail-run"), b"").unwrap();
        assert_eq!(
            helper_for(&bin.join("sam-jail")),
            Some(bin.join("sam-jail-run"))
        );
        assert_eq!(
            helper_for(&t.path().join("usr/sam-jail")),
            None,
            "never above"
        );
    }
}
