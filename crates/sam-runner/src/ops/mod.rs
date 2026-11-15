//! The [`SAM`] facade: every user-level operation, shared by CLI and GUI.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::progress::{self, ProgressSink, ADD_STEPS};
use anyhow::{bail, Context, Result};
use sam_core::model::{UpdateBackup, UpdateStatus};
use sam_core::permissions::*;
use sam_core::risk::{assess, RiskAssessment};
use sam_core::util::{now, tildify};
use sam_core::warnings::{evaluate, WarningContext};
use sam_core::*;
use sam_detect::{analyze_appdir_with, inspect, looks_like_appimage, AnalyzeOptions};
use sam_intake::extract::{extract, ExtractRequest, NeedsFallbackConsent};
use sam_intake::fingerprint::{self, SourceStatus};
use sam_intake::normalize::Limits;
use sam_intake::{desktop, id, menu, metadata, peek};
use sam_profile::{check_change, compatibility_profile, find_preset, recommend, ChangeCheck};
use sam_storage::{LogKind, Logs, PresetStore, Registry};
use serde::Serialize;

mod add;
mod maintain;
mod overview;
mod profiles;

pub struct Sam {
    pub paths: Paths,
    pub config: Config,
}

#[derive(Debug, Clone, Default)]
pub struct AddOptions {
    /// User consented to the `--appimage-extract` fallback.
    pub consent_fallback: bool,
    /// Override config `general.desktop_integration`.
    pub launcher: Option<bool>,
    pub preset: Option<String>,
    /// Mark the recommended profile as reviewed.
    pub accept: bool,
    /// Hide other (unsandboxed) menu entries that start this AppImage.
    pub hide_duplicates: bool,
    /// Use these permissions instead of the recommendation (the settings
    /// the user saw and adjusted before creating the sandbox).
    pub permissions: Option<PermissionSet>,
    /// Where the steps report how far they are (`progress::ADD_STEPS`).
    pub progress: crate::progress::ProgressSink,
}

/// An AppImage found on disk, sandboxed or not (the overview).
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredApp {
    pub path: PathBuf,
    pub size: u64,
    pub name: String,
    pub comment: String,
    pub version: String,
    pub categories: Vec<String>,
    pub category: String,
    pub category_label: String,
    /// Icon extracted for the preview (`<data>/previews/`).
    pub icon: Option<PathBuf>,
    /// Registered app id when this file already has a sandbox.
    pub sandboxed: Option<String>,
    /// A sandboxed app whose file went missing and has this file's checksum.
    pub moved_from: Option<String>,
    /// Unsandboxed menu entries that start this file directly (still visible).
    pub menu_entries: Vec<MenuEntryInfo>,
    /// Found through a menu entry rather than a scanned folder.
    pub from_menu: bool,
    /// Added by hand (`general.scan_files`).
    pub manual: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MenuEntryInfo {
    pub file: PathBuf,
    pub name: String,
    /// System-wide entry: SAM hides it with a user-level override.
    pub system: bool,
}

/// Cached preview of one AppImage, keyed by path, size and mtime.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
#[serde(default)]
struct Preview {
    key: String,
    name: String,
    comment: String,
    version: String,
    categories: Vec<String>,
    icon: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddOutcome {
    pub entry: AppEntry,
    pub created: bool,
    pub relocated: bool,
    pub needs_fallback_consent: bool,
    /// A tool that would let SAM unpack the AppImage itself (`dwarfs` for
    /// DwarFS images), when the fallback needs consent only for want of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_tool: Option<&'static str>,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanItem {
    pub path: PathBuf,
    pub registered: Option<String>,
    /// A missing registered app whose checksum matches this file.
    pub moved_from: Option<String>,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshItem {
    pub id: String,
    pub name: String,
    pub status: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evaluation {
    pub risk: RiskAssessment,
    /// The permission tags, as on the Permissions page.
    pub tags: Vec<sam_profile::tags::Tag>,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PresetApply {
    pub preset: String,
    pub check: ChangeCheck,
    pub applied: bool,
}

/// A sandboxed app as the Permissions page shows it.
#[derive(Debug, Clone, Serialize)]
pub struct OverviewApp {
    #[serde(flatten)]
    pub summary: AppSummary,
    pub permissions: PermissionSet,
    pub tags: Vec<sam_profile::tags::Tag>,
    pub running: bool,
    pub needs_review: bool,
    /// The last start failed, or the AppImage file is missing or damaged.
    pub may_not_start: bool,
}

/// One permission changed for several apps (see `Sam::group_change`).
#[derive(Debug, Clone, Serialize)]
pub struct GroupChange {
    pub key: String,
    pub value: String,
    pub applied: bool,
    pub apps: Vec<GroupApp>,
    /// The settings of the changed apps from before the change, for Undo.
    pub previous: BTreeMap<String, PermissionSet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupApp {
    pub id: String,
    pub name: String,
    pub check: ChangeCheck,
    pub running: bool,
    /// The app had another value before.
    pub changed: bool,
}

impl Sam {
    pub fn open() -> Result<Self> {
        let paths = Paths::from_env();
        let config = Config::load(&paths)?;
        Ok(Sam { paths, config })
    }

    pub fn with_paths(paths: Paths) -> Result<Self> {
        let config = Config::load(&paths)?;
        Ok(Sam { paths, config })
    }

    pub fn registry(&self) -> Registry {
        Registry::new(&self.paths)
    }

    pub fn host(&self) -> HostInfo {
        HostInfo::probe()
    }

    fn limits(&self) -> Limits {
        let e = &self.config.extraction;
        Limits { max_files: e.max_files, max_bytes: e.max_size_mb.saturating_mul(1024 * 1024), max_seconds: e.max_seconds }
    }

    pub fn extracted_root(&self) -> PathBuf {
        self.paths.extracted_root(&self.config.extraction.location)
    }

    pub fn resolve(&self, query: &str) -> Result<AppEntry> {
        self.registry().resolve(query)
    }
}

/// Browsers and chat apps need the network; games do when they link networking libraries.
pub fn app_needs_network(a: &AppEntry) -> bool {
    let by_category = sam_profile::Category::parse(&a.category).is_some_and(|c| c.needs_network());
    let game_online = a.category == "game" && a.detection.as_ref().is_some_and(|d| d.requirements.network);
    let file_name = a.source_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    by_category || game_online || sam_profile::needs_network_by_purpose(&a.metadata, &file_name)
}

/// Permissions the new recommendation wants that the user's profile lacks.
pub fn new_requirements(old_rec: &PermissionSet, new_rec: &PermissionSet, cur: &PermissionSet) -> Vec<String> {
    let mut v = Vec::new();
    let mut chk = |newly: bool, have: bool, what: &str| {
        if newly && !have {
            v.push(what.to_string());
        }
    };
    chk(new_rec.devices.gpu && !old_rec.devices.gpu, cur.devices.gpu, "GPU");
    chk(new_rec.audio.enabled && !old_rec.audio.enabled, cur.audio.enabled, "audio");
    chk(new_rec.network.mode == NetworkMode::Full && old_rec.network.mode != NetworkMode::Full, cur.network.mode == NetworkMode::Full, "network");
    chk(new_rec.display.x11 && !old_rec.display.x11, cur.display.x11, "X11");
    for key in XDG_DIR_KEYS {
        let n = new_rec.filesystem.xdg_access(key);
        chk(n > old_rec.filesystem.xdg_access(key), cur.filesystem.xdg_access(key) >= n, &format!("{key} folder"));
    }
    v
}

/// Result of `Sam::self_update`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelfUpdate {
    /// `current`, `available` or `updated`.
    pub state: String,
    pub latest: Option<String>,
    /// SAM's AppImage after the update (the new file when updated).
    pub path: PathBuf,
    pub detail: String,
    pub page: Option<String>,
}

/// Disk space of one app (bytes).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiskUsage {
    pub id: String,
    pub name: String,
    pub unpacked: u64,
    pub home: u64,
    pub overlay: u64,
    pub logs: u64,
    /// The version an update replaced (kept for going back).
    pub previous: u64,
    pub total: u64,
    /// The unpacked copy can be deleted (the AppImage is still there).
    pub can_free: bool,
}

/// Data left behind by a removed sandbox.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LeftoverData {
    pub id: String,
    pub paths: Vec<PathBuf>,
    pub size: u64,
}

/// Size of a folder tree in bytes (symlinks are not followed).
fn tree_size(p: &Path) -> u64 {
    let Ok(md) = fs::symlink_metadata(p) else { return 0 };
    if md.is_dir() {
        fs::read_dir(p).map(|rd| rd.flatten().map(|e| tree_size(&e.path())).sum()).unwrap_or(0)
    } else {
        md.len()
    }
}

/// What `Sam::uninstall` removes (or would remove).
#[derive(Debug, Default, Serialize)]
pub struct Uninstall {
    pub apps: Vec<String>,
    pub files: Vec<PathBuf>,
    pub dirs: Vec<PathBuf>,
    pub problems: Vec<String>,
}

/// Refuses folders that cannot be SAM's alone: `/`, the home folder or an
/// ancestor of it, top-level folders. Guards against odd SAM_*_DIR values.
fn safe_to_delete(d: &Path) -> Result<()> {
    let home = sam_core::util::home_dir();
    if d.components().count() < 3 || home.starts_with(d) {
        bail!("refusing to delete {}: not a folder of SAM's own", d.display());
    }
    Ok(())
}

/// The process has this file open.
fn holds_open(pid: u32, file: &Path) -> bool {
    let Ok(want) = fs::canonicalize(file) else { return false };
    fs::read_dir(format!("/proc/{pid}/fd")).into_iter().flatten().flatten().any(|fd| fs::read_link(fd.path()).is_ok_and(|t| t == want))
}

/// All processes below `root`, children before grandchildren.
fn descendants(root: u32) -> Vec<u32> {
    let mut parent_of = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
            let Ok(stat) = fs::read_to_string(e.path().join("stat")) else { continue };
            // "pid (comm) state ppid ...": comm may contain spaces or ')'.
            let Some(rest) = stat.rfind(')').map(|i| &stat[i + 1..]) else { continue };
            if let Some(ppid) = rest.split_whitespace().nth(1).and_then(|p| p.parse::<u32>().ok()) {
                parent_of.push((pid, ppid));
            }
        }
    }
    let mut out = Vec::new();
    let mut frontier = vec![root];
    while let Some(p) = frontier.pop() {
        for &(child, parent) in &parent_of {
            if parent == p && !out.contains(&child) {
                out.push(child);
                frontier.push(child);
            }
        }
    }
    out
}

/// `remove_dir_all` that also handles folders without permissions, such as
/// the `work/work` folder the kernel's overlay file system leaves behind.
pub fn remove_tree(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn unlock(p: &Path) {
        let Ok(md) = fs::symlink_metadata(p) else { return };
        if md.is_dir() {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
            if let Ok(rd) = fs::read_dir(p) {
                for e in rd.flatten() {
                    unlock(&e.path());
                }
            }
        }
    }
    if fs::remove_dir_all(path).is_ok() {
        return Ok(());
    }
    unlock(path);
    fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))
}

/// Three-way merge of permission sets: every setting the user changed from
/// `base` (what they were shown) is kept; every other setting comes from
/// `newer` (a recommendation that knows more).
pub fn merge_adjustments(base: &PermissionSet, user: &PermissionSet, newer: &PermissionSet) -> PermissionSet {
    fn merge(b: &serde_json::Value, u: &serde_json::Value, n: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match (b, u, n) {
            (Value::Object(bo), Value::Object(uo), Value::Object(no)) => {
                let mut out = no.clone();
                for (k, uv) in uo {
                    let merged = match (bo.get(k), no.get(k)) {
                        (Some(bv), Some(nv)) => merge(bv, uv, nv),
                        _ => uv.clone(),
                    };
                    out.insert(k.clone(), merged);
                }
                Value::Object(out)
            }
            _ if u == b => n.clone(),
            _ => u.clone(),
        }
    }
    let (b, u, n) = (serde_json::to_value(base), serde_json::to_value(user), serde_json::to_value(newer));
    match (b, u, n) {
        (Ok(b), Ok(u), Ok(n)) => serde_json::from_value(merge(&b, &u, &n)).unwrap_or_else(|_| user.clone()),
        _ => user.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When SAM's recommendation improves, the user's own changes are kept.
    #[test]
    fn user_changes_survive_better_recommendation() {
        let base = PermissionSet::strict_gui();
        let mut user = base.clone();
        user.network.mode = NetworkMode::Full;
        user.filesystem.music = Access::Ro;
        let mut newer = base.clone();
        newer.devices.gpu = true;
        newer.audio.enabled = true;
        let m = merge_adjustments(&base, &user, &newer);
        assert!(m.devices.gpu && m.audio.enabled, "detected needs are added");
        assert_eq!(m.network.mode, NetworkMode::Full, "user change kept");
        assert_eq!(m.filesystem.music, Access::Ro, "user change kept");
    }
}

/// Short description of a signature for messages.
pub(crate) fn sig_words(s: &sam_core::model::SignatureInfo) -> String {
    use sam_core::model::SignatureState as S;
    let key = s.fingerprint.as_deref().map(|f| format!(" (key {})", &f[f.len().saturating_sub(16)..])).unwrap_or_default();
    match s.state {
        S::Unsigned => "not signed".into(),
        S::Valid => format!("signed{key}"),
        S::Invalid => format!("signed{key}, but the signature does not match"),
        S::Unchecked => "signed (not checked)".into(),
    }
}

/// What the earlier signature was, when the new file is signed with another
/// key or no longer signed. An unsigned app that stays unsigned, or a first
/// signature, is no change worth a warning.
pub(crate) fn signing_key_change(old: Option<&sam_core::model::SignatureInfo>, new: &sam_core::model::SignatureInfo) -> Option<String> {
    use sam_core::model::SignatureState as S;
    let old = old?;
    let old_fp = old.fingerprint.as_deref().filter(|_| old.state == S::Valid)?;
    match (new.state, new.fingerprint.as_deref()) {
        (S::Valid, Some(fp)) if fp == old_fp => None,
        (S::Unchecked, _) => None,
        _ => Some(sig_words(old)),
    }
}

#[cfg(test)]
mod signature_tests {
    use super::signing_key_change;
    use sam_core::model::{SignatureInfo, SignatureState as S};

    fn sig(state: S, fp: Option<&str>) -> SignatureInfo {
        SignatureInfo { state, fingerprint: fp.map(str::to_string), detail: String::new() }
    }

    /// An update signed with another key, or not signed at all, is noticed.
    #[test]
    fn key_changes_are_noticed() {
        let a = sig(S::Valid, Some("AAAA"));
        assert_eq!(signing_key_change(Some(&a), &sig(S::Valid, Some("AAAA"))), None, "same key");
        assert!(signing_key_change(Some(&a), &sig(S::Valid, Some("BBBB"))).is_some(), "other key");
        assert!(signing_key_change(Some(&a), &sig(S::Unsigned, None)).is_some(), "no longer signed");
        assert_eq!(signing_key_change(Some(&sig(S::Unsigned, None)), &sig(S::Valid, Some("AAAA"))), None, "first signature");
        assert_eq!(signing_key_change(None, &sig(S::Unsigned, None)), None);
    }
}
