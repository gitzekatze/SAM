//! Storage layout.
//!
//! ```text
//! ~/.config/sam/            config.toml, presets/, logs/
//! ~/.local/share/sam/       apps/, extracted/, icons/, desktop/, homes/
//! ~/.local/share/applications/  sam-<app-id>.desktop
//! ```
//!
//! `SAM_CONFIG_DIR` and `SAM_DATA_DIR` override the roots (used by
//! tests and for portable setups).

use std::path::{Path, PathBuf};

use crate::util::{expand_home, home_dir};

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    /// Directory where launchers are installed (`~/.local/share/applications`).
    pub applications_dir: PathBuf,
    /// Where SAM's per-launch runtime folders go when not below
    /// `$XDG_RUNTIME_DIR/sam` (set for rooted paths: tests).
    pub runtime_root: Option<PathBuf>,
}

/// A folder named in the environment variable `var`, if it is set to an
/// absolute path. Empty or relative, it is ignored, as the XDG rules say:
/// "" or "data" would put SAM's files into whatever folder SAM was started
/// in (audit G-F20).
fn folder_from(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

impl Paths {
    pub fn from_env() -> Self {
        let home = home_dir();
        let xdg_config = folder_from("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
        let xdg_data = folder_from("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
        let config_dir = folder_from("SAM_CONFIG_DIR").unwrap_or_else(|| xdg_config.join("sam"));
        let data_dir = folder_from("SAM_DATA_DIR").unwrap_or_else(|| xdg_data.join("sam"));
        let applications_dir =
            folder_from("SAM_APPLICATIONS_DIR").unwrap_or_else(|| xdg_data.join("applications"));
        Paths {
            config_dir,
            data_dir,
            applications_dir,
            // SAM_RUNTIME_DIR moves the per-launch runtime folders, like the
            // three above (tests that start SAM's programs use it).
            runtime_root: folder_from("SAM_RUNTIME_DIR"),
        }
    }

    /// Root all paths under one directory (tests), the runtime folder too:
    /// a test never uses SAM's folder in the real runtime folder, and two
    /// runs at once (app IDs are the same in both) never share one.
    pub fn rooted(root: &Path) -> Self {
        Paths {
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            applications_dir: root.join("applications"),
            runtime_root: Some(rooted_runtime(root)),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn presets_dir(&self) -> PathBuf {
        self.config_dir.join("presets")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.config_dir.join("logs")
    }
    pub fn app_logs_dir(&self, id: &str) -> PathBuf {
        self.logs_dir().join(id)
    }
    pub fn apps_dir(&self) -> PathBuf {
        self.data_dir.join("apps")
    }
    pub fn app_file(&self, id: &str) -> PathBuf {
        self.apps_dir().join(format!("{id}.json"))
    }
    /// Default extraction root; may be overridden by config `extraction.location`.
    pub fn default_extracted_dir(&self) -> PathBuf {
        self.data_dir.join("extracted")
    }
    pub fn icons_dir(&self) -> PathBuf {
        self.data_dir.join("icons")
    }
    pub fn desktop_dir(&self) -> PathBuf {
        self.data_dir.join("desktop")
    }
    /// Where the writable app folders keep each app's changes.
    pub fn overlays_dir(&self) -> PathBuf {
        self.data_dir.join("overlays")
    }
    /// Private per-app home directories mounted as `$HOME` inside the sandbox.
    pub fn homes_dir(&self) -> PathBuf {
        self.data_dir.join("homes")
    }
    pub fn app_home(&self, id: &str) -> PathBuf {
        self.homes_dir().join(id)
    }
    /// Per-launch runtime scratch (generated passwd, D-Bus proxy socket, ...).
    pub fn runtime_dir(&self, id: &str) -> PathBuf {
        if let Some(r) = &self.runtime_root {
            return r.join(id);
        }
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .map(|v| PathBuf::from(v).join("sam"))
            .unwrap_or_else(|| self.data_dir.join("runtime"));
        base.join(id)
    }
    /// The desktop file ID of SAM's menu entry for an app ("sam-<id>"). The
    /// sandboxed app's windows carry the same ID, so the taskbar finds the
    /// menu entry and shows the app's icon and name.
    pub fn launcher_id(id: &str) -> String {
        format!("sam-{id}")
    }
    pub fn launcher_file(&self, id: &str) -> PathBuf {
        self.applications_dir
            .join(format!("{}.desktop", Self::launcher_id(id)))
    }
    pub fn onboarding_marker(&self) -> PathBuf {
        self.config_dir.join(".onboarding-done")
    }

    pub fn extracted_root(&self, cfg_location: &str) -> PathBuf {
        if cfg_location.trim().is_empty() {
            self.default_extracted_dir()
        } else {
            expand_home(cfg_location)
        }
    }
}

/// The runtime folder of rooted paths: `ROOT/run`, unless that is too long
/// for SAM's sockets (at most 108 characters, and they sit up to about 70
/// below it): then a folder of its own below `$XDG_RUNTIME_DIR` (or /tmp
/// when that path is long too), named after the root, so it is still never
/// shared.
fn rooted_runtime(root: &Path) -> PathBuf {
    rooted_runtime_below(root, std::env::var_os("XDG_RUNTIME_DIR").as_deref())
}

/// [`rooted_runtime`] for the runtime folder `xdg`. A test's runtime
/// folder is itself such a folder (`samt-…`); a root inside that test gets
/// one next to it, not in /tmp, where nothing ever removed them.
fn rooted_runtime_below(root: &Path, xdg: Option<&std::ffi::OsStr>) -> PathBuf {
    let own = root.join("run");
    if own.as_os_str().len() <= 36 {
        return own;
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    root.hash(&mut h);
    let base = xdg
        .filter(|v| !v.is_empty())
        .map(Path::new)
        .map(|d| match d.file_name() {
            Some(n) if n.to_string_lossy().starts_with("samt-") => d.parent().unwrap_or(d),
            _ => d,
        });
    // Short in any case: the runtime folder when its own path is short
    // (/run/user/UID), else /tmp.
    base.filter(|d| d.as_os_str().len() <= 24)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(format!("samt-{:08x}", h.finish() as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rooted paths (tests) keep their runtime folders apart from SAM's real
    /// one and from every other root, and short enough for SAM's sockets.
    #[test]
    fn rooted_paths_have_a_runtime_folder_of_their_own() {
        let short = Path::new("/tmp/.tmpAbC123");
        assert_eq!(
            Paths::rooted(short).runtime_dir("app"),
            short.join("run/app")
        );
        let long_a = Path::new("/home/someone/Projects/a/rather/long/checkout/path/tmp/.tmpAbC123");
        let long_b = Path::new("/home/someone/Projects/a/rather/long/checkout/path/tmp/.tmpXyZ789");
        let (a, b) = (
            Paths::rooted(long_a).runtime_dir("app"),
            Paths::rooted(long_b).runtime_dir("app"),
        );
        assert_ne!(a, b, "two runs never share a runtime folder");
        for d in [&a, &b] {
            assert!(
                !d.starts_with(long_a),
                "a long root is not used: {}",
                d.display()
            );
            assert!(
                !d.to_string_lossy().contains("/sam/"),
                "never SAM's real folder: {}",
                d.display()
            );
            assert!(
                d.as_os_str().len() <= 40,
                "short enough for sockets: {}",
                d.display()
            );
        }
    }

    /// A root inside a test whose runtime folder is already one of these
    /// gets its folder next to it, never in /tmp (16,304 were left there by
    /// one mutation run, 2026-11-20); a long runtime folder still falls
    /// back to /tmp.
    #[test]
    fn a_test_inside_a_test_keeps_its_runtime_folder_out_of_tmp() {
        let long = Path::new("/home/someone/Projects/a/rather/long/checkout/path/tmp/.tmpAbC123");
        let xdg = |s: &str| rooted_runtime_below(long, Some(std::ffi::OsStr::new(s)));
        let outer = xdg("/run/user/1000/st1");
        assert!(
            outer
                .to_string_lossy()
                .starts_with("/run/user/1000/st1/samt-"),
            "{}",
            outer.display()
        );
        let inner = xdg(&outer.to_string_lossy());
        assert_eq!(inner.parent(), outer.parent(), "{}", inner.display());
        assert!(xdg("/run/user/1000/a/runtime/folder/too/long")
            .to_string_lossy()
            .starts_with("/tmp/samt-"));
        assert!(rooted_runtime_below(long, None)
            .to_string_lossy()
            .starts_with("/tmp/samt-"));
    }

    /// Regression: sandboxed windows carried the app's id as their app ID
    /// while SAM's menu entry is "sam-<id>.desktop", so the taskbar found no
    /// entry and showed a generic icon. The ID given to the compositor is
    /// exactly the menu entry's file name without ".desktop".
    #[test]
    fn the_window_id_matches_the_name_of_sams_menu_entry() {
        let p = Paths::rooted(Path::new("/x"));
        let file = p.launcher_file("appimage-krita-9f3c");
        assert_eq!(
            file.file_stem().unwrap(),
            Paths::launcher_id("appimage-krita-9f3c").as_str()
        );
    }
}
