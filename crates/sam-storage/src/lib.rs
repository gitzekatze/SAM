//! sam-storage: the app registry (`apps/<id>.json`), user presets
//! (`presets/<slug>.toml`) and per-app logs.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sam_core::util::{atomic_write, now, slugify};
use sam_core::{AppEntry, Paths, PermissionSet, Preset};
use serde::{Deserialize, Serialize};

/// The app registry.
pub struct Registry {
    paths: Paths,
}

/// Migrates an app record (JSON) from format `from` to the current one.
fn migrate_app(v: serde_json::Value, _from: u32) -> serde_json::Value {
    // 0 -> 1: same layout; removed options load through serde aliases.
    v
}

/// A record that cannot be read: moved aside, reported once.
fn damaged_record(p: &Path, err: &anyhow::Error) {
    match sam_core::format::quarantine(p) {
        Some(to) => eprintln!(
            "sam-jail: {}",
            sam_core::i18n::trf(
                "the app record {file} could not be read ({error}); it was moved to {moved}",
                &[("file", &p.display()), ("error", &format!("{err:#}")), ("moved", &to.display())]
            )
        ),
        None => eprintln!(
            "sam-jail: {}",
            sam_core::i18n::trf("the app record {file} could not be read: {error}", &[("file", &p.display()), ("error", &format!("{err:#}"))])
        ),
    }
}

impl Registry {
    pub fn new(paths: &Paths) -> Self {
        Registry { paths: paths.clone() }
    }

    pub fn list(&self) -> Result<Vec<AppEntry>> {
        let dir = self.paths.apps_dir();
        let mut out = Vec::new();
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            match self.load_file(&p) {
                Ok(a) => out.push(a),
                // From a newer SAM: left alone, just not shown.
                Err(err) if err.downcast_ref::<serde_json::Error>().is_some() => damaged_record(&p, &err),
                // From a newer SAM, or not readable right now: left alone.
                Err(err) => eprintln!("sam-jail: {err:#}"),
            }
        }
        out.sort_by_key(|a| a.display_name().to_lowercase());
        Ok(out)
    }

    /// Reads one app record: migrated from older formats (original kept),
    /// an error for a newer one (left untouched).
    fn load_file(&self, p: &Path) -> Result<AppEntry> {
        let s = fs::read_to_string(p)?;
        let v: serde_json::Value = serde_json::from_str(&s)?;
        let found = sam_core::format::of_json(&v);
        sam_core::format::check_not_newer(p, found)?;
        let v = migrate_app(v, found);
        let mut e: AppEntry = serde_json::from_value(v)?;
        // The id names folders SAM creates and deletes (private home, logs,
        // runtime files). A record changed outside SAM must not point them
        // elsewhere ("../../.ssh"), so only safe ids that match the file
        // name are loaded.
        if !valid_id(&e.id) || p.file_stem().and_then(|s| s.to_str()) != Some(e.id.as_str()) {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file}: the app id {id} is not a safe name or does not match the file name; the record is ignored",
                    &[("file", &p.display()), ("id", &format!("{:?}", e.id))]
                )
            );
        }
        sam_core::format::backup_before_migration(p, found);
        // Changed by something other than SAM? Only records that carry a
        // checksum can tell; older ones get one at their next save.
        if let Some(stored) = e.integrity.clone() {
            e.changed_outside = found == sam_core::format::CURRENT && integrity_of(&e)? != stored;
        }
        e.format = sam_core::format::CURRENT;
        Ok(e)
    }

    pub fn get(&self, id: &str) -> Result<Option<AppEntry>> {
        if !valid_id(id) {
            return Ok(None);
        }
        let p = self.paths.app_file(id);
        if !p.exists() {
            return Ok(None);
        }
        match self.load_file(&p) {
            Ok(e) => Ok(Some(e)),
            Err(err) if err.downcast_ref::<serde_json::Error>().is_some() => {
                damaged_record(&p, &err);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    pub fn exists(&self, id: &str) -> bool {
        valid_id(id) && self.paths.app_file(id).exists()
    }

    /// Resolve a user-supplied reference: exact id, unique id prefix,
    /// slug match or case-insensitive name match.
    pub fn resolve(&self, query: &str) -> Result<AppEntry> {
        if let Some(a) = self.get(query)? {
            return Ok(a);
        }
        let all = self.list()?;
        let q = query.to_lowercase();
        let qslug = slugify(query);
        let tiers: [&dyn Fn(&AppEntry) -> bool; 4] =
            [&|a| a.name.to_lowercase() == q, &|a| a.id.starts_with(&q), &|a| !qslug.is_empty() && a.id.starts_with(&format!("appimage-{qslug}")), &|a| {
                a.name.to_lowercase().contains(&q)
            }];
        for tier in tiers {
            let m: Vec<&AppEntry> = all.iter().filter(|a| tier(a)).collect();
            match m.len() {
                0 => continue,
                1 => return Ok(m[0].clone()),
                _ => bail!("'{query}' is ambiguous: {}", m.iter().map(|a| a.id.as_str()).collect::<Vec<_>>().join(", ")),
            }
        }
        bail!("{}", sam_core::i18n::trf("no registered app matches '{query}' (see `sam-jail list`)", &[("query", &query)]))
    }

    pub fn save(&self, entry: &mut AppEntry) -> Result<()> {
        if !valid_id(&entry.id) {
            bail!("{}", sam_core::i18n::trf("invalid app id '{id}'", &[("id", &entry.id)]));
        }
        entry.updated_at = now();
        entry.format = sam_core::format::CURRENT;
        entry.integrity = Some(integrity_of(entry)?);
        entry.changed_outside = false;
        let s = serde_json::to_string_pretty(entry)?;
        atomic_write(&self.paths.app_file(&entry.id), s.as_bytes())
    }

    pub fn remove(&self, id: &str) -> Result<bool> {
        if !valid_id(id) {
            return Ok(false);
        }
        let p = self.paths.app_file(id);
        match fs::remove_file(&p) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// The checksum SAM writes into every app record it saves: SHA-256 over
/// the record without the checksum, with the keys in a fixed order. A record
/// whose checksum does not match was changed by something other than SAM
/// (a script, another tool, a damaged file). It is no protection against a
/// program that targets SAM on purpose: such a program can compute the
/// checksum too (see docs/threat-model.md).
pub fn integrity_of(e: &AppEntry) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut v = serde_json::to_value(e)?;
    if let Some(o) = v.as_object_mut() {
        o.remove("integrity");
    }
    let digest = Sha256::digest(serde_json::to_vec(&v)?);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// App ids are used as file names; keep them to a safe alphabet.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') && !id.starts_with('-')
}

/// On-disk preset format: `[preset]` metadata plus `[permissions]`.
#[derive(Debug, Serialize, Deserialize)]
struct PresetFile {
    preset: PresetMeta,
    #[serde(default = "empty_table")]
    permissions: toml::Value,
}

fn empty_table() -> toml::Value {
    toml::Value::Table(Default::default())
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(default)]
struct PresetMeta {
    /// File format (see `sam_core::format`).
    format: u32,
    name: String,
    description: String,
    risk: sam_core::RiskLevel,
    created_at: i64,
    modified_at: i64,
    compatibility_notes: String,
}

/// User presets stored as TOML in `~/.config/sam/presets/`.
pub struct PresetStore {
    dir: PathBuf,
}

impl PresetStore {
    pub fn new(paths: &Paths) -> Self {
        PresetStore { dir: paths.presets_dir() }
    }

    pub fn file_for(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{}.toml", preset_slug(name)))
    }

    pub fn list(&self) -> Result<Vec<Preset>> {
        let mut out = Vec::new();
        let rd = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            match read_preset_file(&p) {
                Ok(pr) => out.push(pr),
                // Not readable as a preset: moved aside, so it is reported
                // once (sam-jail doctor lists it) instead of on every start.
                Err(err) if err.chain().any(|c| c.downcast_ref::<toml::de::Error>().is_some()) => match sam_core::format::quarantine(&p) {
                    Some(to) => eprintln!(
                        "sam-jail: {}",
                        sam_core::i18n::trf(
                            "the preset {file} could not be read ({error}); it was moved to {moved}",
                            &[("file", &p.display()), ("error", &format!("{err:#}")), ("moved", &to.display())]
                        )
                    ),
                    None => eprintln!(
                        "sam-jail: {}",
                        sam_core::i18n::trf("skipping the damaged preset {file}: {error}", &[("file", &p.display()), ("error", &format!("{err:#}"))])
                    ),
                },
                Err(err) => eprintln!("sam-jail: skipping preset {}: {err:#}", p.display()),
            }
        }
        out.sort_by_key(|a| a.name.to_lowercase());
        Ok(out)
    }

    pub fn get(&self, name: &str) -> Result<Option<Preset>> {
        Ok(self.list()?.into_iter().find(|p| p.name.eq_ignore_ascii_case(name) || preset_slug(&p.name) == preset_slug(name)))
    }

    pub fn save(&self, preset: &mut Preset) -> Result<PathBuf> {
        if preset.name.trim().is_empty() {
            bail!("{}", sam_core::i18n::tr("preset name must not be empty"));
        }
        let t = now();
        if preset.created_at == 0 {
            preset.created_at = t;
        }
        preset.modified_at = t;
        preset.risk = sam_core::risk::assess(&preset.permissions).level;
        let path = self.file_for(&preset.name);
        atomic_write(&path, preset_to_toml(preset)?.as_bytes())?;
        Ok(path)
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        let p = self.file_for(name);
        match fs::remove_file(&p) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

pub fn preset_slug(name: &str) -> String {
    let s = slugify(name);
    if s.is_empty() {
        "preset".into()
    } else {
        s
    }
}

pub fn preset_to_toml(p: &Preset) -> Result<String> {
    let file = PresetFile {
        preset: PresetMeta {
            format: sam_core::format::CURRENT,
            name: p.name.clone(),
            description: p.description.clone(),
            risk: p.risk,
            created_at: p.created_at,
            modified_at: p.modified_at,
            compatibility_notes: p.compatibility_notes.clone(),
        },
        permissions: toml::Value::try_from(&p.permissions)?,
    };
    Ok(toml::to_string_pretty(&file)?)
}

pub fn read_preset_file(path: &Path) -> Result<Preset> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_preset_toml(&s).with_context(|| format!("parsing {}", path.display()))
}

/// Parse a preset, accepting both the structured format and the flat
/// format (`network = "full"`, `gpu = true`, ...).
pub fn parse_preset_toml(s: &str) -> Result<Preset> {
    let file: PresetFile = toml::from_str(s)?;
    if file.preset.format > sam_core::format::CURRENT {
        bail!("{}", sam_core::i18n::trf("this preset was made by a newer SAM (format {format}); update SAM to use it", &[("format", &file.preset.format)]));
    }
    let permissions = permissions_from_toml(file.permissions)?;
    Ok(Preset {
        name: file.preset.name,
        description: file.preset.description,
        permissions,
        risk: file.preset.risk,
        created_at: file.preset.created_at,
        modified_at: file.preset.modified_at,
        compatibility_notes: file.preset.compatibility_notes,
    })
}

fn permissions_from_toml(v: toml::Value) -> Result<PermissionSet> {
    let table = match v {
        toml::Value::Table(t) => t,
        _ => return Ok(PermissionSet::default()),
    };
    let is_flat = table.values().all(|v| !v.is_table());
    if !is_flat || table.is_empty() {
        return Ok(toml::Value::Table(table).try_into()?);
    }
    // Older flat format.
    let mut p = PermissionSet::default();
    for (k, v) in table {
        let raw = match &v {
            toml::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let key = match k.as_str() {
            "network" => "network.mode".to_string(),
            "home" | "documents" | "downloads" | "music" | "pictures" | "videos" | "desktop" | "ssh" | "gnupg" | "hidden_files" | "custom_read"
            | "custom_write" => format!("filesystem.{k}"),
            "audio" => "audio.enabled".into(),
            "alsa" | "alsa_raw" => "audio.alsa_raw".into(),
            "gpu" | "webcam" | "input" | "usb" | "bluetooth" => format!("devices.{k}"),
            "x11" | "wayland" => format!("display.{k}"),
            "dbus_session" => "dbus.session.mode".into(),
            "dbus_system" => "dbus.system.mode".into(),
            other => bail!("{}", sam_core::i18n::trf("unknown flat preset key '{other}'", &[("other", &other)])),
        };
        p.set_key(&key, &raw)?;
    }
    Ok(p)
}

/// Per-app log files under `~/.config/sam/logs/<id>/`.
pub struct Logs {
    paths: Paths,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogKind {
    Launch,
    Extract,
    Detect,
    Diagnose,
}

impl LogKind {
    pub fn prefix(self) -> &'static str {
        match self {
            LogKind::Launch => "launch",
            LogKind::Extract => "extract",
            LogKind::Detect => "detect",
            LogKind::Diagnose => "diagnose",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "launch" => LogKind::Launch,
            "extract" | "extraction" => LogKind::Extract,
            "detect" | "detection" => LogKind::Detect,
            "diagnose" | "diagnostic" => LogKind::Diagnose,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LogFile {
    pub path: PathBuf,
    pub kind: LogKind,
    pub modified: i64,
    pub size: u64,
}

impl Logs {
    pub fn new(paths: &Paths) -> Self {
        Logs { paths: paths.clone() }
    }

    /// A new timestamped log path for this app.
    pub fn new_log_path(&self, id: &str, kind: LogKind) -> Result<PathBuf> {
        let dir = self.paths.app_logs_dir(id);
        fs::create_dir_all(&dir)?;
        let ts = chrono_stamp();
        // Logs from the same second get a number above every existing one.
        // Reusing a free lower name (after older logs of that second were
        // pruned) would make the new log the oldest, and the next pruning
        // would delete it.
        let prefix = format!("{}-{ts}", kind.prefix());
        let highest = fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let rest = name.strip_prefix(&prefix)?.strip_suffix(".log")?.to_string();
                if rest.is_empty() {
                    Some(0)
                } else {
                    rest.strip_prefix('-')?.parse::<u32>().ok()
                }
            })
            .max();
        Ok(match highest {
            None => dir.join(format!("{prefix}.log")),
            Some(n) => dir.join(format!("{prefix}-{}.log", n + 1)),
        })
    }

    pub fn list(&self, id: &str, kind: Option<LogKind>) -> Result<Vec<LogFile>> {
        let dir = self.paths.app_logs_dir(id);
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(&dir) else { return Ok(out) };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(k) = name.split('-').next().and_then(LogKind::parse) else { continue };
            if kind.is_some_and(|want| want != k) {
                continue;
            }
            let meta = e.metadata()?;
            let modified = meta.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
            out.push(LogFile { path: e.path(), kind: k, modified, size: meta.len() });
        }
        // Newest first. Logs from the same second are `<kind>-<date>-<time>.log`,
        // then `...-1.log`, `...-2.log`: order by that sequence number, not by
        // name (where `.log` would sort after `-1.log`).
        out.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| log_stamp(&b.path).cmp(&log_stamp(&a.path))));
        Ok(out)
    }

    pub fn latest(&self, id: &str, kind: Option<LogKind>) -> Result<Option<LogFile>> {
        Ok(self.list(id, kind)?.into_iter().next())
    }

    /// Keep only the newest `keep` logs of a kind.
    pub fn prune(&self, id: &str, kind: LogKind, keep: usize) -> Result<()> {
        for old in self.list(id, Some(kind))?.into_iter().skip(keep.max(1)) {
            fs::remove_file(old.path).ok();
        }
        Ok(())
    }

    pub fn remove_all(&self, id: &str) -> Result<()> {
        let dir = self.paths.app_logs_dir(id);
        if dir.exists() {
            fs::remove_dir_all(dir)?;
        }
        Ok(())
    }
}

fn chrono_stamp() -> String {
    // YYYYmmdd-HHMMSS derived from the formatted local timestamp.
    sam_core::util::format_ts(now()).replace(['-', ':'], "").replace(' ', "-")
}

/// `(date, time, sequence)` from a log file name like `launch-20261107-013613-1.log`.
fn log_stamp(path: &Path) -> (String, String, u32) {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let mut parts = stem.split('-').skip(1);
    let date = parts.next().unwrap_or_default().to_string();
    let time = parts.next().unwrap_or_default().to_string();
    let seq = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
    (date, time, seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With more launches in one second than logs are kept, the newest log
    /// survives the pruning after its launch (regression: on a fast machine
    /// a pruned name was reused, sorted as the oldest and deleted at once).
    #[test]
    fn the_newest_log_survives_pruning_within_one_second() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = Logs::new(&Paths::rooted(tmp.path()));
        for round in 0..12 {
            let p = logs.new_log_path("app", LogKind::Launch).unwrap();
            fs::write(&p, format!("round {round}")).unwrap();
            logs.prune("app", LogKind::Launch, 3).unwrap();
            assert!(p.exists(), "round {round}: the log just written was pruned ({})", p.display());
        }
    }

    /// A record SAM saved loads as unchanged; a record changed afterwards
    /// by something else is recognized as changed outside SAM; a record
    /// from before the checksum existed still loads as unchanged; and
    /// saving it again through SAM makes it unchanged again.
    #[test]
    fn records_changed_outside_sam_are_recognized() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let mut e = AppEntry { id: "appimage-x-1".into(), name: "X".into(), ..Default::default() };
        reg.save(&mut e).unwrap();
        assert!(!reg.get("appimage-x-1").unwrap().unwrap().changed_outside);
        let file = paths.app_file("appimage-x-1");
        let mut v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        v["profile"]["permissions"]["network"]["mode"] = "full".into();
        fs::write(&file, v.to_string()).unwrap();
        let mut changed = reg.get("appimage-x-1").unwrap().unwrap();
        assert!(changed.changed_outside, "a change made outside SAM is noticed");
        assert_eq!(changed.badge(), sam_core::Badge::ChangedOutside);
        reg.save(&mut changed).unwrap();
        assert!(!reg.get("appimage-x-1").unwrap().unwrap().changed_outside, "saving through SAM confirms it");
        v.as_object_mut().unwrap().remove("integrity");
        fs::write(&file, v.to_string()).unwrap();
        assert!(!reg.get("appimage-x-1").unwrap().unwrap().changed_outside, "records from before the check still work");
    }

    /// A preset is always stored inside the presets folder, whatever its name:
    /// names like "../../evil" or "/etc/x" (typed, or from an imported file)
    /// cannot place a file elsewhere.
    #[test]
    fn preset_names_cannot_place_files_outside_the_presets_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let store = PresetStore::new(&paths);
        for name in ["../../evil", "/etc/evil", "..", "a/../../b"] {
            let mut p = Preset { name: name.into(), ..Default::default() };
            let file = store.save(&mut p).unwrap();
            assert_eq!(file.parent(), Some(paths.presets_dir().as_path()), "{name} → {}", file.display());
        }
        assert!(!tmp.path().join("evil.toml").exists() && !tmp.path().parent().unwrap().join("evil.toml").exists());
    }

    /// Regression (found in the test audit): a record changed outside SAM
    /// with an id like "../../.ssh" would have pointed the folders SAM
    /// deletes on removal (private home, logs) outside SAM's own folders.
    /// Such records, and records whose id differs from the file name, are
    /// not loaded.
    #[test]
    fn records_with_unsafe_or_mismatched_ids_are_not_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        fs::create_dir_all(paths.apps_dir()).unwrap();
        fs::write(paths.apps_dir().join("evil.json"), r#"{"id": "../../.ssh", "name": "Evil"}"#).unwrap();
        fs::write(paths.apps_dir().join("other.json"), r#"{"id": "appimage-real-1", "name": "Other"}"#).unwrap();
        fs::write(paths.apps_dir().join("appimage-ok-1.json"), r#"{"id": "appimage-ok-1", "name": "Ok"}"#).unwrap();
        let ids: Vec<String> = Registry::new(&paths).list().unwrap().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["appimage-ok-1"]);
    }

    /// The newest log is found even when two logs start within the same second.
    #[test]
    fn the_newest_log_is_found_even_within_one_second() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = Logs::new(&Paths::rooted(tmp.path()));
        let first = logs.new_log_path("appimage-x-1", LogKind::Launch).unwrap();
        fs::write(&first, "first").unwrap();
        let second = logs.new_log_path("appimage-x-1", LogKind::Launch).unwrap();
        fs::write(&second, "second").unwrap();
        // Same mtime second for both files, so the sequence number decides.
        let mtime = fs::metadata(&first).unwrap().modified().unwrap();
        fs::File::options().write(true).open(&second).unwrap().set_modified(mtime).unwrap();
        assert_eq!(logs.latest("appimage-x-1", None).unwrap().unwrap().path, second);
    }

    /// Apps are found by name or ID, and an ambiguous name is refused.
    #[test]
    fn apps_are_found_by_name_or_id_and_ambiguous_names_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let mut a = AppEntry { id: "appimage-krita-9f3c".into(), name: "Krita".into(), ..Default::default() };
        reg.save(&mut a).unwrap();
        let mut b = AppEntry { id: "appimage-kate-1234".into(), name: "Kate".into(), ..Default::default() };
        reg.save(&mut b).unwrap();
        assert_eq!(reg.list().unwrap().len(), 2);
        assert_eq!(reg.resolve("krita").unwrap().id, a.id);
        assert_eq!(reg.resolve("appimage-kate").unwrap().id, b.id);
        assert!(reg.resolve("k").is_err(), "ambiguous");
        assert!(reg.resolve("gimp").is_err());
        assert!(reg.remove(&a.id).unwrap());
        assert!(reg.get(&a.id).unwrap().is_none());
        assert!(reg.get("../etc/passwd").unwrap().is_none());
    }

    /// Presets in the older flat format still load.
    #[test]
    fn presets_in_the_older_flat_format_still_load() {
        let s = r#"
[preset]
name = "My Browser"
description = "Browser profile with no home access except Downloads"

[permissions]
network = "full"
home = false
downloads = "rw"
documents = false
audio = true
gpu = true
x11 = true
wayland = true
dbus_session = "filtered"
dbus_system = "none"
"#;
        let p = parse_preset_toml(s).unwrap();
        assert_eq!(p.name, "My Browser");
        assert_eq!(p.permissions.network.mode, sam_core::NetworkMode::Full);
        assert_eq!(p.permissions.filesystem.downloads, sam_core::Access::Rw);
        assert!(p.permissions.devices.gpu && p.permissions.audio.enabled && p.permissions.display.x11);
    }

    /// A saved preset loads back unchanged, found by its name in any letter case.
    #[test]
    fn a_saved_preset_loads_back_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PresetStore::new(&Paths::rooted(tmp.path()));
        let mut p = Preset { name: "My Preset".into(), permissions: PermissionSet::strict_gui(), ..Default::default() };
        store.save(&mut p).unwrap();
        let got = store.get("my preset").unwrap().unwrap();
        assert_eq!(got.permissions, p.permissions);
        assert!(got.created_at > 0);
        assert!(store.delete("My Preset").unwrap());
        assert!(store.get("My Preset").unwrap().is_none());
    }
}
