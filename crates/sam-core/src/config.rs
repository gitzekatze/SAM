//! User configuration, stored as TOML.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::util::{atomic_write, expand_home};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CompatBehavior {
    /// Offer compatibility mode in the repair flow, never apply automatically.
    #[default]
    Ask,
    /// Never offer compatibility mode.
    Never,
}

/// GUI colour scheme: follow the desktop, or force light or dark.
pub const THEMES: [&str; 3] = ["system", "light", "dark"];

/// Migrates a configuration (as a JSON value) from format `from` to the
/// current one, one step at a time.
fn migrate(mut v: serde_json::Value, from: u32) -> serde_json::Value {
    if from < 1 {
        // 0 -> 1: older theme names.
        if let Some(t) = v.pointer_mut("/general/theme") {
            let new = migrate_theme(t.as_str().unwrap_or("system"));
            *t = serde_json::Value::String(new.into());
        }
    }
    v
}

/// The configuration `v` with every setting that cannot be read in its
/// default, and the names of those settings (`extraction.max_files`).
/// Each value is tried on its own against the defaults, so one unreadable
/// value never costs the others.
fn readable_settings(v: &serde_json::Value) -> (Config, Vec<String>) {
    let mut good = serde_json::to_value(Config::default()).unwrap_or_default();
    let mut reset = Vec::new();
    keep_readable(&mut good, &[], v, &mut reset);
    let c = serde_json::from_value(good).unwrap_or_default();
    (c, reset)
}

fn keep_readable(
    good: &mut serde_json::Value,
    at: &[&str],
    user: &serde_json::Value,
    reset: &mut Vec<String>,
) {
    let Some(fields) = user.as_object() else {
        return;
    };
    for (k, value) in fields {
        let here: Vec<&str> = at.iter().copied().chain([k.as_str()]).collect();
        let section_is_object = |root: &serde_json::Value| {
            here.iter()
                .try_fold(root, |cur, p| cur.get(*p))
                .is_some_and(serde_json::Value::is_object)
        };
        if value.is_object() && section_is_object(good) {
            keep_readable(good, &here, value, reset);
            continue;
        }
        let mut trial = good.clone();
        let parent = here[..here.len() - 1]
            .iter()
            .try_fold(&mut trial, |cur, p| cur.get_mut(*p))
            .and_then(serde_json::Value::as_object_mut);
        let Some(parent) = parent else {
            reset.push(here.join("."));
            continue;
        };
        parent.insert(k.clone(), value.clone());
        if serde_json::from_value::<Config>(trial.clone()).is_ok() {
            *good = trial;
        } else {
            reset.push(here.join("."));
        }
    }
}

/// Theme names of format 0, mapped to the current ones.
fn migrate_theme(t: &str) -> &'static str {
    match t {
        "light" | "breeze-light" => "light",
        "dark" | "breeze-dark" | "cachyos-neon" => "dark",
        _ => "system",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    pub theme: String,
    /// Folders the overview searches for AppImages (two levels deep).
    pub scan_directories: Vec<String>,
    /// The old "Also search the Downloads folder" switch. The window turns
    /// it into an ordinary location once; the command line still honours it.
    pub scan_downloads: bool,
    /// Single AppImage files added by hand to the overview.
    pub scan_files: Vec<String>,
    pub desktop_integration: bool,
    /// The window's language: a code from `i18n::LANGUAGES`, or empty to
    /// follow the system.
    pub language: String,
}

/// Empty (follow the system) or one of the languages SAM speaks.
fn language_known(l: &str) -> bool {
    l.is_empty() || crate::i18n::LANGUAGES.iter().any(|(c, _)| *c == l)
}

impl Default for General {
    fn default() -> Self {
        General {
            theme: "system".into(),
            scan_directories: vec![
                "~/Applications".into(),
                "~/AppImages".into(),
                "~/.local/bin".into(),
                "~/bin".into(),
            ],
            scan_downloads: false,
            scan_files: vec![],
            desktop_integration: true,
            language: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    pub warn_x11: bool,
    pub warn_full_home: bool,
    pub experimental_landlock: bool,
    /// No longer used: each app's own "Strict syscall filter" switch
    /// decides (audit D-M13). Read from older files and ignored.
    pub experimental_seccomp: bool,
    /// Baseline syscall filter for every Bubblewrap sandbox (like Flatpak's).
    pub baseline_seccomp: bool,
    /// Run the sandbox check before an app starts (only when its settings,
    /// SAM or this computer changed since the last passing check); a failed
    /// check stops the start.
    pub check_before_launch: bool,
}

impl Default for Security {
    fn default() -> Self {
        Security {
            warn_x11: true,
            warn_full_home: true,
            experimental_landlock: true,
            experimental_seccomp: false,
            baseline_seccomp: true,
            check_before_launch: false,
        }
    }
}

/// The global switches that take a protection away from every sandboxed
/// app when turned off. Turning one off is made only after a yes: the
/// window asks first, `config set` and `config put` need `--yes` (audit
/// G-F11). Turning one on, and every other setting, needs no yes.
pub const PROTECTIONS: [&str; 2] = [
    "security.experimental_landlock",
    "security.baseline_seccomp",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dependencies {
    pub static_analysis: bool,
    pub dynamic_fallback: bool,
    pub automatic_low_risk_fixes: bool,
}

impl Default for Dependencies {
    fn default() -> Self {
        Dependencies {
            static_analysis: true,
            dynamic_fallback: true,
            automatic_low_risk_fixes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Extraction {
    /// Extraction root. Empty = `<data dir>/extracted`
    /// (`~/.local/share/sam/extracted` by default).
    pub location: String,
    pub max_files: u64,
    pub max_size_mb: u64,
    pub max_seconds: u64,
    /// How much memory each unpacking program may use (MiB; 0: no limit).
    pub max_memory_mb: u64,
    /// Allow `--appimage-extract` fallback (always asks for consent per app).
    pub allow_fallback: bool,
}

impl Default for Extraction {
    fn default() -> Self {
        Extraction {
            location: String::new(),
            max_files: 200_000,
            max_size_mb: 8192,
            max_seconds: 600,
            max_memory_mb: 4096,
            allow_fallback: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Diagnostics {
    /// How many launch logs to keep per app.
    pub keep_logs: usize,
}

impl Default for Diagnostics {
    fn default() -> Self {
        Diagnostics { keep_logs: 20 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Compatibility {
    pub behavior: CompatBehavior,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// File format (see `format`); written as the current one.
    pub format: u32,
    pub general: General,
    pub security: Security,
    pub dependencies: Dependencies,
    pub extraction: Extraction,
    pub diagnostics: Diagnostics,
    pub compatibility: Compatibility,
    pub updates: Updates,
}

/// Update checks. SAM contacts the internet only for these, and by default
/// only when asked (a check button, `sam-jail updates`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Updates {
    /// Check every sandboxed app's update source when the window opens
    /// (at most once a day).
    pub check_on_start: bool,
}

impl Config {
    /// Reads the configuration. Older formats are migrated (the original
    /// is kept once); one from a newer SAM is an error and stays untouched;
    /// a damaged one is moved aside and the defaults are used.
    pub fn load(paths: &Paths) -> Result<Config> {
        let file = paths.config_file();
        let s = match fs::read_to_string(&file) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
        };
        let parsed = toml::from_str::<toml::Value>(&s)
            .ok()
            .and_then(|v| serde_json::to_value(v).ok());
        let Some(v) = parsed else {
            return Ok(Self::damaged(&file));
        };
        let found = crate::format::of_json(&v);
        crate::format::check_not_newer(&file, found)?;
        let v = migrate(v, found);
        let mut c = match serde_json::from_value::<Config>(v.clone()) {
            Ok(c) => c,
            // A value of the wrong kind (`max_files = "x"`) or an unknown
            // word: only that setting is reset. Resetting the whole file
            // lost stricter choices such as compatibility.behavior = never
            // (audit U-L4).
            Err(_) => {
                let (c, reset) = readable_settings(&v);
                crate::errln!(
                    "sam-jail: {}",
                    crate::i18n::trf(
                        "{file}: {settings} could not be read and went back to the default; the other settings stay",
                        &[("file", &file.display()), ("settings", &reset.join(", "))]
                    )
                );
                c
            }
        };
        // A single invalid value is reset, not the whole file.
        if let Err(e) = c.validate() {
            crate::errln!(
                "sam-jail: {}",
                crate::i18n::trf(
                    "{file}: {error}; that setting was reset",
                    &[("file", &file.display()), ("error", &format!("{e:#}"))]
                )
            );
            if !THEMES.contains(&c.general.theme.as_str()) {
                c.general.theme = "system".into();
            }
            if !language_known(&c.general.language) {
                c.general.language.clear();
            }
            if (Config {
                extraction: c.extraction.clone(),
                ..Config::default()
            })
            .validate()
            .is_err()
            {
                c.extraction.location.clear();
            }
            if c.validate().is_err() {
                return Ok(Self::damaged(&file));
            }
        }
        crate::format::backup_before_migration(&file, found);
        c.format = crate::format::CURRENT;
        Ok(c)
    }

    fn damaged(file: &std::path::Path) -> Config {
        match crate::format::quarantine(file) {
            Some(to) => crate::errln!(
                "sam-jail: {}",
                crate::i18n::trf(
                    "{file} could not be read; it was moved to {moved} and the default settings are used",
                    &[("file", &file.display()), ("moved", &to.display())]
                )
            ),
            None => crate::errln!("sam-jail: {}", crate::i18n::trf("{file} could not be read; the default settings are used", &[("file", &file.display())])),
        }
        Config::default()
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        self.validate()?;
        let mut c = self.clone();
        c.format = crate::format::CURRENT;
        let s = toml::to_string_pretty(&c)?;
        atomic_write(&paths.config_file(), s.as_bytes())
    }

    pub fn validate(&self) -> Result<()> {
        if !language_known(&self.general.language) {
            let choices: Vec<&str> = crate::i18n::LANGUAGES.iter().map(|(c, _)| *c).collect();
            bail!(
                "{}",
                crate::i18n::trf(
                    "unknown language '{language}'; choose one of: {choices}, or leave it empty to follow the system",
                    &[("language", &self.general.language), ("choices", &choices.join(", "))]
                )
            );
        }
        if !THEMES.contains(&self.general.theme.as_str()) {
            bail!(
                "{}",
                crate::i18n::trf(
                    "unknown theme '{theme}'; choose one of: {choices}",
                    &[
                        ("theme", &self.general.theme),
                        ("choices", &THEMES.join(", "))
                    ]
                )
            );
        }
        // Extraction folder: empty (default) or an absolute folder below /.
        let loc = self.extraction.location.trim();
        if !loc.is_empty() {
            let p = expand_home(loc);
            let home = expand_home("~");
            if !p.is_absolute()
                || p.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                bail!("{}", crate::i18n::tr("extraction.location must be an absolute path (or start with ~/), without '..'"));
            }
            if p == std::path::Path::new("/") || p == home {
                bail!("{}", crate::i18n::tr("extraction.location cannot be / or the home folder itself; choose a folder of its own"));
            }
        }
        Ok(())
    }

    /// Folders to search. `downloads` is the user's XDG download folder,
    /// added only when `general.scan_downloads` is on.
    pub fn scan_dirs(&self, downloads: Option<&std::path::Path>) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self
            .general
            .scan_directories
            .iter()
            .map(|d| expand_home(d))
            .collect();
        if self.general.scan_downloads {
            dirs.push(
                downloads
                    .map(PathBuf::from)
                    .unwrap_or_else(|| expand_home("~/Downloads")),
            );
        }
        dirs.dedup();
        dirs
    }

    /// The [`PROTECTIONS`] that are on here and off in `new`: what changing
    /// this configuration into `new` turns off for every app.
    pub fn protections_turned_off(&self, new: &Config) -> Vec<&'static str> {
        let on = |c: &Config, key: &str| {
            c.get_key(key)
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };
        PROTECTIONS
            .into_iter()
            .filter(|key| on(self, key) && !on(new, key))
            .collect()
    }

    pub fn get_key(&self, key: &str) -> Result<serde_json::Value> {
        let v = serde_json::to_value(self)?;
        let mut cur = &v;
        for part in key.split('.') {
            cur = cur.get(part).ok_or_else(|| {
                anyhow!(
                    "{}",
                    crate::i18n::trf("unknown config key '{key}'", &[("key", &key)])
                )
            })?;
        }
        Ok(cur.clone())
    }

    pub fn set_key(&mut self, key: &str, raw: &str) -> Result<()> {
        use serde_json::Value;
        let mut v = serde_json::to_value(&*self)?;
        let parts: Vec<&str> = key.split('.').collect();
        let (last, parents) = parts.split_last().context(crate::i18n::tr("empty key"))?;
        let mut cur = &mut v;
        for p in parents {
            cur = cur.get_mut(*p).ok_or_else(|| {
                anyhow!(
                    "{}",
                    crate::i18n::trf("unknown config key '{key}'", &[("key", &key)])
                )
            })?;
        }
        let obj = cur.as_object_mut().ok_or_else(|| {
            anyhow!(
                "{}",
                crate::i18n::trf("'{key}' is not settable", &[("key", &key)])
            )
        })?;
        let existing = obj.get(*last).ok_or_else(|| {
            anyhow!(
                "{}",
                crate::i18n::trf("unknown config key '{key}'", &[("key", &key)])
            )
        })?;
        let new_val = match existing {
            Value::Array(_) if !raw.trim_start().starts_with('[') => Value::Array(
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.into()))
                    .collect(),
            ),
            Value::String(_) => Value::String(raw.to_string()),
            _ => serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.into())),
        };
        obj.insert((*last).to_string(), new_val);
        let cfg: Config = serde_json::from_value(v).with_context(|| {
            crate::i18n::trf(
                "invalid value for '{key}': {raw}",
                &[("key", &key), ("raw", &raw)],
            )
        })?;
        cfg.validate()?;
        *self = cfg;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete configuration file with every section loads without loss.
    #[test]
    fn a_complete_configuration_file_loads_every_setting() {
        let s = r#"
[general]
theme = "dark"
scan_directories = [
    "~/Applications",
    "~/.local/bin",
]

[security]
warn_x11 = true
warn_full_home = true
experimental_landlock = true
experimental_ebpf = false

[dependencies]
static_analysis = true
dynamic_fallback = true
automatic_low_risk_fixes = true

[extraction]
location = "~/.local/share/sam/extracted"
cleanup_stale = true
"#;
        let c: Config = toml::from_str(s).unwrap();
        assert_eq!(
            c.general.scan_directories,
            vec!["~/Applications", "~/.local/bin"]
        );
        assert!(
            c.security.warn_x11 && c.security.warn_full_home && c.security.experimental_landlock
        );
        assert!(c.dependencies.dynamic_fallback);
        assert_eq!(c.extraction.location, "~/.local/share/sam/extracted");
        c.validate().unwrap();
    }

    /// SAM contacts no update source on its own: the daily check when the
    /// window opens is off until the user switches it on.
    #[test]
    fn update_checks_stay_off_unless_switched_on() {
        assert!(!Config::default().updates.check_on_start);
        let c: Config = toml::from_str("format = 1\n").unwrap();
        assert!(
            !c.updates.check_on_start,
            "a settings file without the switch keeps it off"
        );
    }

    /// The window's language is empty (follow the system) or one of the
    /// languages SAM speaks; anything else is refused, and a wrong value in
    /// the file is reset to the system's language.
    #[test]
    fn the_language_is_the_system_or_one_sam_speaks() {
        let mut c = Config::default();
        assert_eq!(c.general.language, "", "the system's language by default");
        c.set_key("general.language", "de").unwrap();
        assert_eq!(c.general.language, "de");
        assert!(c.set_key("general.language", "xx").is_err());
        assert_eq!(c.general.language, "de", "a refused value changes nothing");
        c.set_key("general.language", "").unwrap();
        let t = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::rooted(t.path());
        std::fs::create_dir_all(paths.config_file().parent().unwrap()).unwrap();
        std::fs::write(
            paths.config_file(),
            "format = 1\n[general]\nlanguage = \"klingon\"\ntheme = \"dark\"\n",
        )
        .unwrap();
        let loaded = Config::load(&paths).unwrap();
        assert_eq!(
            loaded.general.language, "",
            "an unknown language in the file is reset"
        );
        assert_eq!(loaded.general.theme, "dark", "the other settings stay");
    }

    /// Regression (audit U-L4): one value of the wrong kind
    /// (`max_files = "x"`) or an unknown word made the whole file
    /// unreadable, and SAM used the defaults for everything, losing
    /// stricter choices such as "never offer compatibility mode". Now only
    /// the unreadable settings go back to their defaults; the file stays.
    #[test]
    fn one_unreadable_setting_does_not_cost_the_others() {
        let t = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::rooted(t.path());
        std::fs::create_dir_all(paths.config_file().parent().unwrap()).unwrap();
        let file = "format = 1\n[extraction]\nmax_files = \"x\"\nmax_size_mb = 123\n[security]\ncheck_before_launch = true\n[compatibility]\nbehavior = \"never\"\n[dependencies]\nautomatic_low_risk_fixes = false\n[updates]\ncheck_on_start = \"sometimes\"\n";
        std::fs::write(paths.config_file(), file).unwrap();
        let c = Config::load(&paths).unwrap();
        assert_eq!(
            c.compatibility.behavior,
            CompatBehavior::Never,
            "a stricter choice stays"
        );
        assert!(
            !c.dependencies.automatic_low_risk_fixes,
            "a stricter choice stays"
        );
        assert_eq!(
            c.extraction.max_size_mb, 123,
            "the same section keeps its other values"
        );
        assert!(c.security.check_before_launch, "a stricter choice stays");
        assert_eq!(
            c.extraction.max_files,
            Config::default().extraction.max_files
        );
        assert!(!c.updates.check_on_start);
        assert_eq!(
            std::fs::read_to_string(paths.config_file()).unwrap(),
            file,
            "the file is not moved aside"
        );
        // An unknown word for a choice: only that choice is reset.
        std::fs::write(
            paths.config_file(),
            "format = 1\n[compatibility]\nbehavior = \"sometimes\"\n[dependencies]\nautomatic_low_risk_fixes = false\n",
        )
        .unwrap();
        let c = Config::load(&paths).unwrap();
        assert_eq!(c.compatibility.behavior, CompatBehavior::Ask);
        assert!(!c.dependencies.automatic_low_risk_fixes);
        assert_eq!(
            readable_settings(
                &serde_json::json!({"extraction": {"max_files": "x"}, "general": "y"})
            )
            .1,
            vec!["extraction.max_files", "general"]
        );
    }

    /// Settings can be changed by key, and old theme names are migrated to Light, Dark or System.
    #[test]
    fn settings_change_by_key_and_old_theme_names_are_migrated() {
        let mut c = Config::default();
        c.set_key("general.theme", "dark").unwrap();
        assert_eq!(migrate_theme("breeze-light"), "light");
        assert_eq!(migrate_theme("cachyos-neon"), "dark");
        assert_eq!(migrate_theme("breeze-high-contrast"), "system");
        c.set_key("general.scan_directories", "~/A, ~/B").unwrap();
        assert_eq!(c.general.scan_directories, vec!["~/A", "~/B"]);
        assert!(
            !Config::default()
                .scan_dirs(None)
                .iter()
                .any(|d| d.ends_with("Downloads")),
            "Downloads is opt-in"
        );
        c.set_key("general.scan_downloads", "true").unwrap();
        assert!(c
            .scan_dirs(Some(std::path::Path::new("/x/Downloads")))
            .contains(&PathBuf::from("/x/Downloads")));
        assert!(c.set_key("general.theme", "pink").is_err());
        assert!(c.set_key("nope.key", "1").is_err());
    }

    /// `sam-jail config get` reads back what is set; an unknown key is an
    /// error. Text settings take the typed text literally: quotes are part
    /// of the value, not JSON.
    #[test]
    fn settings_read_back_by_key_and_text_is_taken_literally() {
        let mut c = Config::default();
        assert_eq!(
            c.get_key("general.theme").unwrap(),
            serde_json::json!("system")
        );
        c.set_key("security.warn_x11", "false").unwrap();
        assert_eq!(
            c.get_key("security.warn_x11").unwrap(),
            serde_json::json!(false)
        );
        assert_eq!(
            c.get_key("extraction.max_files").unwrap(),
            serde_json::json!(200_000)
        );
        assert!(c.get_key("no.such").is_err());
        assert!(c.get_key("general.nope").is_err());
        assert!(
            c.set_key("general.theme", "\"dark\"").is_err(),
            "the quotes belong to the value, which is no theme"
        );
        assert_eq!(c.general.theme, "system", "a refused value changes nothing");
        c.set_key("compatibility.behavior", "never").unwrap();
        assert_eq!(c.compatibility.behavior, CompatBehavior::Never);
    }

    /// A settings file that exists but cannot be read (not text, or a
    /// folder) is an error that names it, and it stays as it is: the
    /// stricter settings in it are never silently replaced by the
    /// defaults, which a later save would write over it.
    #[test]
    fn a_settings_file_that_cannot_be_read_is_an_error_and_stays() {
        let t = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::rooted(t.path());
        let file = paths.config_file();
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let bytes = b"format = 1\n[security]\ncheck_before_launch = true\n# \xff\n";
        std::fs::write(&file, bytes).unwrap();
        assert!(Config::load(&paths).is_err(), "not text");
        assert_eq!(std::fs::read(&file).unwrap(), bytes, "left unchanged");
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(Config::load(&paths).is_err(), "a folder");
        assert!(file.is_dir(), "left in place");
        std::fs::remove_dir(&file).unwrap();
        assert_eq!(
            Config::load(&paths).unwrap(),
            Config::default(),
            "only a missing file means the defaults"
        );
    }

    /// A file already in the current format is not migrated again: an old
    /// theme name in it is an invalid value and is reset to System. A theme
    /// that is no text resets only the theme and the file stays (audit
    /// U-L4: one unreadable value costs nothing else); a file that is no
    /// TOML at all is damaged (moved aside, the defaults apply).
    #[test]
    fn a_current_settings_file_is_not_migrated_again() {
        let t = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::rooted(t.path());
        let file = paths.config_file();
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "format = 1\n[general]\ntheme = \"breeze-dark\"\n").unwrap();
        assert_eq!(Config::load(&paths).unwrap().general.theme, "system");
        std::fs::write(&file, "format = 0\n[general]\ntheme = \"breeze-dark\"\n").unwrap();
        assert_eq!(
            Config::load(&paths).unwrap().general.theme,
            "dark",
            "format 0 is migrated"
        );
        std::fs::write(
            &file,
            "format = 1\n[general]\ntheme = 5\n[compatibility]\nbehavior = \"never\"\n",
        )
        .unwrap();
        let c = Config::load(&paths).unwrap();
        assert_eq!(c.general.theme, "system", "only the theme is reset");
        assert_ne!(
            c.compatibility,
            Config::default().compatibility,
            "the other settings stay"
        );
        assert!(
            file.exists(),
            "one unreadable value does not move the file aside"
        );
        std::fs::write(&file, "format = 1\n[general\ntheme = ").unwrap();
        assert_eq!(Config::load(&paths).unwrap(), Config::default());
        assert!(!file.exists(), "the damaged file was moved aside");
    }

    /// The extraction folder is a folder of its own: never the root, never
    /// the home folder itself (however it is written), never relative and
    /// never with `..`. SAM unpacks into it and later removes what it put
    /// there.
    #[test]
    fn the_extraction_folder_is_never_the_root_or_the_home_folder() {
        let home = expand_home("~");
        let home_s = home.to_string_lossy().into_owned();
        for bad in [
            "/".to_string(),
            "~".to_string(),
            "~/".to_string(),
            home_s.clone(),
            format!("{home_s}/"),
            format!("{home_s}/x/.."),
            "/tmp/a/..".to_string(),
            "relative/dir".to_string(),
        ] {
            let mut c = Config::default();
            c.extraction.location = bad.clone();
            assert!(c.validate().is_err(), "{bad}");
            let mut c = Config::default();
            assert!(c.set_key("extraction.location", &bad).is_err(), "{bad}");
            assert_eq!(c.extraction.location, "", "{bad} changed nothing");
        }
        for ok in ["/tmp/sam-x", "~/x", ""] {
            let mut c = Config::default();
            c.set_key("extraction.location", ok).unwrap();
            assert_eq!(c.extraction.location, ok);
        }
    }
}
