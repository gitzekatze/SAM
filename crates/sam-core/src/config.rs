//! User configuration (whitepaper §2.25), stored as TOML.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::BackendChoice;
use crate::paths::Paths;
use crate::util::{atomic_write, expand_home};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UiMode {
    #[default]
    Simple,
    Advanced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CompatBehavior {
    /// Offer compatibility mode in the repair flow, never apply automatically.
    #[default]
    Ask,
    /// Never offer compatibility mode.
    Never,
}

pub const THEMES: [&str; 4] = ["breeze-light", "breeze-dark", "breeze-high-contrast", "cachyos-neon"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    pub theme: String,
    pub default_backend: BackendChoice,
    /// Folders the overview searches for AppImages (two levels deep).
    pub scan_directories: Vec<String>,
    /// Also search the Downloads folder (opt-in: it often holds old copies).
    pub scan_downloads: bool,
    pub automatic_scanning: bool,
    pub desktop_integration: bool,
    pub ui_mode: UiMode,
}

impl Default for General {
    fn default() -> Self {
        General {
            theme: "breeze-dark".into(),
            default_backend: BackendChoice::Bubblewrap,
            scan_directories: vec!["~/Applications".into(), "~/AppImages".into(), "~/.local/bin".into(), "~/bin".into()],
            scan_downloads: false,
            automatic_scanning: true,
            desktop_integration: true,
            ui_mode: UiMode::Simple,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    pub warn_x11: bool,
    pub warn_full_home: bool,
    pub warn_firejail: bool,
    pub allow_firejail: bool,
    pub experimental_landlock: bool,
    pub experimental_seccomp: bool,
    pub experimental_ebpf: bool,
}

impl Default for Security {
    fn default() -> Self {
        Security {
            warn_x11: true,
            warn_full_home: true,
            warn_firejail: true,
            allow_firejail: false,
            experimental_landlock: true,
            experimental_seccomp: false,
            experimental_ebpf: false,
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
    pub cleanup_stale: bool,
    pub max_files: u64,
    pub max_size_mb: u64,
    pub max_seconds: u64,
    /// Allow `--appimage-extract` fallback (always asks for consent per app).
    pub allow_fallback: bool,
}

impl Default for Extraction {
    fn default() -> Self {
        Extraction {
            location: String::new(),
            cleanup_stale: true,
            max_files: 200_000,
            max_size_mb: 8192,
            max_seconds: 600,
            allow_fallback: true,
        }
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
        Diagnostics {
            verbose_logging: false,
            keep_logs: 20,
        }
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
    pub general: General,
    pub security: Security,
    pub dependencies: Dependencies,
    pub extraction: Extraction,
    pub diagnostics: Diagnostics,
    pub compatibility: Compatibility,
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Config> {
        let file = paths.config_file();
        match fs::read_to_string(&file) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", file.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", file.display())),
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        self.validate()?;
        let s = toml::to_string_pretty(self)?;
        atomic_write(&paths.config_file(), s.as_bytes())
    }

    pub fn validate(&self) -> Result<()> {
        if !THEMES.contains(&self.general.theme.as_str()) {
            bail!("unknown theme '{}'; choose one of: {}", self.general.theme, THEMES.join(", "));
        }
        if self.general.default_backend == BackendChoice::Unsandboxed {
            bail!("'unsandboxed' cannot be the default backend");
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
    fn parses_whitepaper_example() {
        let s = r#"
[general]
theme = "breeze-dark"
default_backend = "bubblewrap"
scan_directories = [
    "~/Applications",
    "~/.local/bin",
]

[security]
warn_x11 = true
warn_full_home = true
warn_firejail = true
allow_firejail = false
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
        assert!(!c.security.allow_firejail);
        c.validate().unwrap();
    }

    #[test]
    fn set_keys() {
        let mut c = Config::default();
        c.set_key("general.theme", "cachyos-neon").unwrap();
        c.set_key("security.allow_firejail", "true").unwrap();
        c.set_key("general.scan_directories", "~/A, ~/B").unwrap();
        assert_eq!(c.general.scan_directories, vec!["~/A", "~/B"]);
        assert!(!Config::default().scan_dirs(None).iter().any(|d| d.ends_with("Downloads")), "Downloads is opt-in");
        c.set_key("general.scan_downloads", "true").unwrap();
        assert!(c.scan_dirs(Some(std::path::Path::new("/x/Downloads"))).contains(&PathBuf::from("/x/Downloads")));
        assert!(c.set_key("general.theme", "pink").is_err());
        assert!(c.set_key("general.default_backend", "unsandboxed").is_err());
        assert!(c.set_key("nope.key", "1").is_err());
    }
}
