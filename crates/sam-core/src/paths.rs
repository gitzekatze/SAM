//! Storage layout.
//!
//! ```text
//! ~/.config/sam/            config.toml, presets/, logs/
//! ~/.local/share/sam/       apps/, extracted/, icons/, desktop/, homes/
//! ~/.local/share/applications/  sam-<app-id>.desktop
//! ```
//!
//! `XDG_CONFIG_HOME` and `XDG_DATA_HOME` move these folders in every
//! build. `SAM_CONFIG_DIR`, `SAM_DATA_DIR`, `SAM_APPLICATIONS_DIR` and
//! `SAM_RUNTIME_DIR` move them only in a developer build (tests and work
//! on SAM itself, [`DeveloperVars`]); a release build ignores them.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::util::{environment, expand_home, home_dir, DeveloperVars};

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

/// A folder from the value of a variable, if it is an absolute path.
/// Empty or relative, it is ignored, as the XDG rules say: "" or "data"
/// would put SAM's files into whatever folder SAM was started in (audit
/// G-F20).
fn folder_from(value: Option<OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|p| p.is_absolute())
}

/// The folder that the developer variable `name` names: only in a
/// developer build, and only an absolute path ([`folder_from`]).
fn switched_folder(dev: &DeveloperVars, name: &str) -> Option<PathBuf> {
    folder_from(dev.get(name))
}

/// Whether a developer switch (`SAM_CONFIG_DIR` or `SAM_DATA_DIR`) moves
/// SAM's settings or data away from the folders where SAM keeps them
/// otherwise. SAM's window then runs as a window of its own and leaves
/// the desktop's entry for SAM alone (tests). A release build ignores
/// these switches, so for it the answer is always no: a stray switch in
/// the desktop's environment never makes an installed window run beside
/// another one on the same settings.
pub fn folders_moved_by_a_developer_switch() -> bool {
    folders_moved_in(&DeveloperVars::of_this_build())
}

/// [`folders_moved_by_a_developer_switch`] with the developer variables
/// `dev`.
fn folders_moved_in(dev: &DeveloperVars) -> bool {
    ["SAM_CONFIG_DIR", "SAM_DATA_DIR"]
        .iter()
        .any(|name| switched_folder(dev, name).is_some())
}

impl Paths {
    /// SAM's folders for this program: the standard XDG folders in every
    /// build, moved by SAM's own folder switches only in a developer build.
    pub fn from_env() -> Self {
        Self::from_vars(&home_dir(), &DeveloperVars::of_this_build(), &environment)
    }

    /// [`from_env`](Self::from_env) for the home folder `home`, the
    /// developer variables `dev` and the environment `env`, which gives
    /// the standard variables `XDG_CONFIG_HOME` and `XDG_DATA_HOME`
    /// (a test's stand-ins).
    fn from_vars(home: &Path, dev: &DeveloperVars, env: &dyn Fn(&str) -> Option<OsString>) -> Self {
        let xdg_config =
            folder_from(env("XDG_CONFIG_HOME")).unwrap_or_else(|| home.join(".config"));
        let xdg_data =
            folder_from(env("XDG_DATA_HOME")).unwrap_or_else(|| home.join(".local/share"));
        let config_dir =
            switched_folder(dev, "SAM_CONFIG_DIR").unwrap_or_else(|| xdg_config.join("sam"));
        let data_dir = switched_folder(dev, "SAM_DATA_DIR").unwrap_or_else(|| xdg_data.join("sam"));
        let applications_dir = switched_folder(dev, "SAM_APPLICATIONS_DIR")
            .unwrap_or_else(|| xdg_data.join("applications"));
        Paths {
            config_dir,
            data_dir,
            applications_dir,
            // SAM_RUNTIME_DIR moves the per-launch runtime folders, like the
            // three above (tests that start SAM's programs use it).
            runtime_root: switched_folder(dev, "SAM_RUNTIME_DIR"),
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
        self.runtime_base(std::env::var_os("XDG_RUNTIME_DIR").as_deref())
            .join(id)
    }
    /// The folder of [`runtime_dir`](Self::runtime_dir)s for the runtime
    /// folder `xdg` (`$XDG_RUNTIME_DIR`): `sam` in it, or SAM's data folder
    /// when there is none.
    fn runtime_base(&self, xdg: Option<&std::ffi::OsStr>) -> PathBuf {
        xdg.filter(|v| !v.is_empty())
            .map(|v| PathBuf::from(v).join("sam"))
            .unwrap_or_else(|| self.data_dir.join("runtime"))
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
    /// Where this SAM keeps its own folders, which no app ever sees,
    /// wherever they lead: its settings, its data and its unpack folder
    /// (`cfg_location`, config `extraction.location`). Each start adds the
    /// folders named like them (`~/.config/sam`, `~/.local/share/sam`, also
    /// under `XDG_CONFIG_HOME` and `XDG_DATA_HOME`) that count as SAM's for
    /// what it shows ([`crate::places::sams_folders`]): the sandbox hides
    /// that list, its check expects it hidden and a terminal app's start
    /// line leaves it out (independent reviews of decision 9).
    pub fn sam_dirs(&self, cfg_location: &str) -> Vec<PathBuf> {
        vec![
            self.config_dir.clone(),
            self.data_dir.clone(),
            self.extracted_root(cfg_location),
        ]
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

    /// A stand-in environment with SAM's four folder switches set to
    /// absolute folders, and the standard XDG folders set as `xdg` says.
    fn switches_set(xdg: bool) -> impl Fn(&str) -> Option<OsString> {
        move |name: &str| {
            let v = match name {
                "SAM_CONFIG_DIR" => "/home/ann/planted/config",
                "SAM_DATA_DIR" => "/home/ann/planted/data",
                "SAM_APPLICATIONS_DIR" => "/home/ann/planted/applications",
                "SAM_RUNTIME_DIR" => "/home/ann/planted/run",
                "XDG_CONFIG_HOME" if xdg => "/home/ann/cfg",
                "XDG_DATA_HOME" if xdg => "/home/ann/dat",
                _ => return None,
            };
            Some(OsString::from(v))
        }
    }

    /// A release build ignores SAM's folder switches (`SAM_CONFIG_DIR`,
    /// `SAM_DATA_DIR`, `SAM_APPLICATIONS_DIR`, `SAM_RUNTIME_DIR`): it keeps
    /// its settings, data and menu entries where it keeps them otherwise
    /// and its runtime folders in the session's runtime folder, so a
    /// variable in the desktop's environment never moves an installed SAM
    /// to other settings and app records (owner decision of 2026-11-27).
    /// The variables are a stand-in's.
    #[test]
    fn a_release_build_ignores_sams_folder_switches() {
        let env = switches_set(false);
        let home = Path::new("/home/ann");
        let p = Paths::from_vars(home, &DeveloperVars::new(false, &env), &env);
        assert_eq!(p.config_dir, home.join(".config/sam"));
        assert_eq!(p.data_dir, home.join(".local/share/sam"));
        assert_eq!(p.applications_dir, home.join(".local/share/applications"));
        assert_eq!(p.runtime_root, None, "a release build read SAM_RUNTIME_DIR");
    }

    /// A developer build (tests, work on SAM itself) follows SAM's four
    /// folder switches. The variables are a stand-in's.
    #[test]
    fn a_developer_build_follows_sams_folder_switches() {
        let env = switches_set(true);
        let p = Paths::from_vars(
            Path::new("/home/ann"),
            &DeveloperVars::new(true, &env),
            &env,
        );
        assert_eq!(p.config_dir, Path::new("/home/ann/planted/config"));
        assert_eq!(p.data_dir, Path::new("/home/ann/planted/data"));
        assert_eq!(
            p.applications_dir,
            Path::new("/home/ann/planted/applications")
        );
        assert_eq!(
            p.runtime_root.as_deref(),
            Some(Path::new("/home/ann/planted/run"))
        );
    }

    /// The standard `XDG_CONFIG_HOME` and `XDG_DATA_HOME` move SAM's
    /// folders in every build, a release build too, also while SAM's own
    /// folder switches are set and ignored. The variables are a stand-in's.
    #[test]
    fn every_build_follows_the_standard_config_and_data_folders() {
        let env = switches_set(true);
        let p = Paths::from_vars(
            Path::new("/home/ann"),
            &DeveloperVars::new(false, &env),
            &env,
        );
        assert_eq!(p.config_dir, Path::new("/home/ann/cfg/sam"));
        assert_eq!(p.data_dir, Path::new("/home/ann/dat/sam"));
        assert_eq!(p.applications_dir, Path::new("/home/ann/dat/applications"));
        assert_eq!(p.runtime_root, None);
    }

    /// An empty or relative folder is ignored in every build, for SAM's
    /// switches and the XDG folders alike: "" or "data" would put SAM's
    /// files into whatever folder SAM was started in (audit G-F20). The
    /// variables are a stand-in's.
    #[test]
    fn empty_or_relative_folders_are_ignored_in_every_build() {
        let env = |name: &str| match name {
            "SAM_CONFIG_DIR" | "XDG_DATA_HOME" => Some(OsString::new()),
            "SAM_DATA_DIR" | "SAM_APPLICATIONS_DIR" | "SAM_RUNTIME_DIR" | "XDG_CONFIG_HOME" => {
                Some(OsString::from("data"))
            }
            _ => None,
        };
        let home = Path::new("/home/ann");
        for developer in [false, true] {
            let p = Paths::from_vars(home, &DeveloperVars::new(developer, &env), &env);
            assert_eq!(p.config_dir, home.join(".config/sam"), "{developer}");
            assert_eq!(p.data_dir, home.join(".local/share/sam"), "{developer}");
            assert_eq!(
                p.applications_dir,
                home.join(".local/share/applications"),
                "{developer}"
            );
            assert_eq!(p.runtime_root, None, "{developer}");
            assert!(!folders_moved_in(&DeveloperVars::new(developer, &env)));
        }
    }

    /// SAM's window runs as a window of its own and leaves the desktop's
    /// entry for SAM alone only when a developer switch really moves its
    /// settings or data: in a developer build. In a release build with the
    /// switches set, it behaves as without them, so it never runs beside
    /// another window on the same settings. The variables are a stand-in's.
    #[test]
    fn only_a_developer_build_counts_its_folders_as_moved_by_a_switch() {
        let env = switches_set(false);
        assert!(!folders_moved_in(&DeveloperVars::new(false, &env)));
        assert!(folders_moved_in(&DeveloperVars::new(true, &env)));
        for only in ["SAM_CONFIG_DIR", "SAM_DATA_DIR"] {
            let one = |name: &str| (name == only).then(|| OsString::from("/home/ann/planted"));
            assert!(folders_moved_in(&DeveloperVars::new(true, &one)), "{only}");
            assert!(
                !folders_moved_in(&DeveloperVars::new(false, &one)),
                "{only}"
            );
        }
        let none = |_: &str| None;
        assert!(!folders_moved_in(&DeveloperVars::new(true, &none)));
    }

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

    /// Runtime folders (sockets, the passwd file of each start) go into
    /// the session's runtime folder when there is one, never onto the disk
    /// or into the folder SAM was started in; only without one into SAM's
    /// data folder.
    #[test]
    fn runtime_folders_go_into_the_sessions_runtime_folder() {
        let p = Paths {
            config_dir: "/c".into(),
            data_dir: "/d".into(),
            applications_dir: "/a".into(),
            runtime_root: None,
        };
        let base = |x: Option<&str>| p.runtime_base(x.map(std::ffi::OsStr::new));
        assert_eq!(
            base(Some("/run/user/1000")),
            Path::new("/run/user/1000/sam")
        );
        assert_eq!(base(Some("")), Path::new("/d/runtime"));
        assert_eq!(base(None), Path::new("/d/runtime"));
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

    /// SAM's own folders are its settings, data and unpack folders where
    /// they are kept, and the folders it keeps them in unless told
    /// otherwise (`~/.config/sam`, `~/.local/share/sam`), also while it
    /// keeps its own elsewhere (`SAM_DATA_DIR=~/Games/sam`), which the
    /// sandbox hides by name; each once (independent re-review of
    /// decision 9). Where it keeps its own comes first; each start adds
    /// the folders by name.
    #[test]
    fn sams_folders_hold_its_own_and_the_folders_named_like_them() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("u");
        let p = Paths {
            config_dir: home.join(".config/sam"),
            data_dir: home.join("Games/sam"),
            applications_dir: home.join(".local/share/applications"),
            runtime_root: None,
        };
        let own = p.sam_dirs("");
        assert_eq!(
            own,
            vec![
                home.join(".config/sam"),
                home.join("Games/sam"),
                home.join("Games/sam/extracted")
            ]
        );
        let places = crate::places::protected_places_with(&home, None, None);
        let dirs = crate::places::sams_folders_in(&home, &own, &[], &places);
        for d in [
            ".config/sam",
            "Games/sam",
            "Games/sam/extracted",
            ".local/share/sam",
        ] {
            let n = dirs.iter().filter(|x| **x == home.join(d)).count();
            assert_eq!(n, 1, "{d}: {dirs:?}");
        }
        assert_eq!(dirs.len(), 4, "{dirs:?}");
    }
}
