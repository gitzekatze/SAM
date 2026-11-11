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
    /// Also search the Downloads folder (opt-in: it often holds old copies).
    pub scan_downloads: bool,
    /// Single AppImage files added by hand to the overview.
    pub scan_files: Vec<String>,
    pub desktop_integration: bool,
}

impl Default for General {
    fn default() -> Self {
        General {
            theme: "system".into(),
            scan_directories: vec!["~/Applications".into(), "~/AppImages".into(), "~/.local/bin".into(), "~/bin".into()],
            scan_downloads: false,
            scan_files: vec![],
            desktop_integration: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    pub warn_x11: bool,
    pub warn_full_home: bool,
    pub experimental_landlock: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dependencies {
    pub static_analysis: bool,
    pub dynamic_fallback: bool,
    pub automatic_low_risk_fixes: bool,
}

impl Default for Dependencies {
    fn default() -> Self {
        Dependencies { static_analysis: true, dynamic_fallback: true, automatic_low_risk_fixes: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Extraction {
    /// Extraction root. Empty = `<data dir>/extracted`
    /// (`~/.local/share/sam/extracted` by default).
    pub location: String,
    pub cleanup_stale: bool,
    pub max_files: u64,
    pub max_size_mb: u64,
    pub max_seconds: u64,
    /// Allow `--appimage-extract` fallback (always asks for consent per app).
    pub allow_fallback: bool,
}

impl Default for Extraction {
    fn default() -> Self {
        Extraction { location: String::new(), cleanup_stale: true, max_files: 200_000, max_size_mb: 8192, max_seconds: 600, allow_fallback: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Diagnostics {
    pub verbose_logging: bool,
    /// How many launch logs to keep per app.
    pub keep_logs: usize,
}

impl Default for Diagnostics {
    fn default() -> Self {
        Diagnostics { verbose_logging: false, keep_logs: 20 }
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
        let parsed = toml::from_str::<toml::Value>(&s).ok().and_then(|v| serde_json::to_value(v).ok());
        let Some(v) = parsed else {
            return Ok(Self::damaged(&file));
        };
        let found = crate::format::of_json(&v);
        crate::format::check_not_newer(&file, found)?;
        let v = migrate(v, found);
        let Ok(mut c) = serde_json::from_value::<Config>(v) else {
            return Ok(Self::damaged(&file));
        };
        // A single invalid value is reset, not the whole file.
        if let Err(e) = c.validate() {
            eprintln!("sam-jail: {}: {e:#}; that setting was reset", file.display());
            if !THEMES.contains(&c.general.theme.as_str()) {
                c.general.theme = "system".into();
            }
            if (Config { extraction: c.extraction.clone(), ..Config::default() }).validate().is_err() {
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
            Some(to) => eprintln!("sam-jail: {} could not be read; moved it to {} and using the default settings", file.display(), to.display()),
            None => eprintln!("sam-jail: {} could not be read; using the default settings", file.display()),
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
        if !THEMES.contains(&self.general.theme.as_str()) {
            bail!("unknown theme '{}'; choose one of: {}", self.general.theme, THEMES.join(", "));
        }
        // Extraction folder: empty (default) or an absolute folder below /.
        let loc = self.extraction.location.trim();
        if !loc.is_empty() {
            let p = expand_home(loc);
            let home = expand_home("~");
            if !p.is_absolute() || p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                bail!("extraction.location must be an absolute path (or start with ~/), without '..'");
            }
            if p == std::path::Path::new("/") || p == home {
                bail!("extraction.location cannot be / or the home folder itself; choose a folder of its own");
            }
        }
        Ok(())
    }

    /// Folders to search. `downloads` is the user's XDG download folder,
    /// added only when `general.scan_downloads` is on.
    pub fn scan_dirs(&self, downloads: Option<&std::path::Path>) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self.general.scan_directories.iter().map(|d| expand_home(d)).collect();
        if self.general.scan_downloads {
            dirs.push(downloads.map(PathBuf::from).unwrap_or_else(|| expand_home("~/Downloads")));
        }
        dirs.dedup();
        dirs
    }

    pub fn get_key(&self, key: &str) -> Result<serde_json::Value> {
        let v = serde_json::to_value(self)?;
        let mut cur = &v;
        for part in key.split('.') {
            cur = cur.get(part).ok_or_else(|| anyhow!("unknown config key '{key}'"))?;
        }
        Ok(cur.clone())
    }

    pub fn set_key(&mut self, key: &str, raw: &str) -> Result<()> {
        use serde_json::Value;
        let mut v = serde_json::to_value(&*self)?;
        let parts: Vec<&str> = key.split('.').collect();
        let (last, parents) = parts.split_last().context("empty key")?;
        let mut cur = &mut v;
        for p in parents {
            cur = cur.get_mut(*p).ok_or_else(|| anyhow!("unknown config key '{key}'"))?;
        }
        let obj = cur.as_object_mut().ok_or_else(|| anyhow!("'{key}' is not settable"))?;
        let existing = obj.get(*last).ok_or_else(|| anyhow!("unknown config key '{key}'"))?;
        let new_val = match existing {
            Value::Array(_) if !raw.trim_start().starts_with('[') => {
                Value::Array(raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(|s| Value::String(s.into())).collect())
            }
            Value::String(_) => Value::String(raw.to_string()),
            _ => serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.into())),
        };
        obj.insert((*last).to_string(), new_val);
        let cfg: Config = serde_json::from_value(v).with_context(|| format!("invalid value for '{key}': {raw}"))?;
        cfg.validate()?;
        *self = cfg;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_example() {
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
        assert_eq!(c.general.scan_directories.len(), 2);
        c.validate().unwrap();
    }

    #[test]
    fn set_keys() {
        let mut c = Config::default();
        c.set_key("general.theme", "dark").unwrap();
        assert_eq!(migrate_theme("breeze-light"), "light");
        assert_eq!(migrate_theme("cachyos-neon"), "dark");
        assert_eq!(migrate_theme("breeze-high-contrast"), "system");
        c.set_key("general.scan_directories", "~/A, ~/B").unwrap();
        assert_eq!(c.general.scan_directories, vec!["~/A", "~/B"]);
        assert!(!Config::default().scan_dirs(None).iter().any(|d| d.ends_with("Downloads")), "Downloads is opt-in");
        c.set_key("general.scan_downloads", "true").unwrap();
        assert!(c.scan_dirs(Some(std::path::Path::new("/x/Downloads"))).contains(&PathBuf::from("/x/Downloads")));
        assert!(c.set_key("general.theme", "pink").is_err());
        assert!(c.set_key("nope.key", "1").is_err());
    }
}
