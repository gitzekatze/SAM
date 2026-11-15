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
}

impl Paths {
    pub fn from_env() -> Self {
        let home = home_dir();
        let xdg_config = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let xdg_data = std::env::var_os("XDG_DATA_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"));
        let config_dir = std::env::var_os("SAM_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| xdg_config.join("sam"));
        let data_dir = std::env::var_os("SAM_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| xdg_data.join("sam"));
        let applications_dir = std::env::var_os("SAM_APPLICATIONS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| xdg_data.join("applications"));
        Paths {
            config_dir,
            data_dir,
            applications_dir,
        }
    }

    /// Root all paths under one directory (tests).
    pub fn rooted(root: &Path) -> Self {
        Paths {
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            applications_dir: root.join("applications"),
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

#[cfg(test)]
mod tests {
    use super::*;

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
