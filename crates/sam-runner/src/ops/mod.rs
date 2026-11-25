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
    /// The fingerprint of the preset's permissions as checked; passed back
    /// with `--expect`, only these are applied.
    pub fingerprint: String,
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
    /// The settings of the changed apps from before the change.
    pub previous: BTreeMap<String, PermissionSet>,
    /// For Undo (`group restore`): per app, the change back from the new
    /// settings to the old ones. Undo takes back only this change, so a
    /// change made to the apps since stays (audit G-F4).
    pub undo: BTreeMap<String, PermissionChange>,
}

/// A change of an app's permissions from `from` to `to`, applied to what
/// the app has when it is applied (see `sam_profile::apply_change`).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PermissionChange {
    pub from: PermissionSet,
    pub to: PermissionSet,
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
        Limits {
            max_files: e.max_files,
            max_bytes: e.max_size_mb.saturating_mul(1024 * 1024),
            max_seconds: e.max_seconds,
            max_memory: e.max_memory_mb.saturating_mul(1024 * 1024),
        }
    }

    /// The unpack folder, created if missing. A folder SAM creates itself
    /// (or finds empty) gets a marker, so it can later be removed as a whole;
    /// a folder that already held other things never does (see
    /// `unpack_root_is_sams`).
    pub(super) fn unpack_root(&self) -> Result<PathBuf> {
        let root = self.extracted_root();
        let new = fs::read_dir(&root).map_or(true, |mut rd| rd.next().is_none());
        fs::create_dir_all(&root)?;
        if new {
            sam_core::util::write_new(&root.join(UNPACK_MARKER), b"SAM unpacks AppImages here.\n")?;
        }
        Ok(root)
    }

    /// Whether the whole unpack folder is SAM's to delete: the default one, or
    /// one SAM created. The location can be set to any folder, for example
    /// `~/Documents`; cleaning up then deleted every folder in it, and
    /// uninstalling deleted it entirely (regression, audit U-L1).
    pub(super) fn unpack_root_is_sams(&self) -> bool {
        let root = self.extracted_root();
        root == self.paths.default_extracted_dir() || root.join(UNPACK_MARKER).is_file()
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
    let game_online =
        a.category == "game" && a.detection.as_ref().is_some_and(|d| d.requirements.network);
    let file_name = a
        .source_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    by_category || game_online || sam_profile::needs_network_by_purpose(&a.metadata, &file_name)
}

/// Permissions the new recommendation wants that the user's profile lacks.
pub fn new_requirements(
    old_rec: &PermissionSet,
    new_rec: &PermissionSet,
    cur: &PermissionSet,
) -> Vec<String> {
    let mut v = Vec::new();
    let mut chk = |newly: bool, have: bool, what: &str| {
        if newly && !have {
            v.push(what.to_string());
        }
    };
    chk(
        new_rec.devices.gpu && !old_rec.devices.gpu,
        cur.devices.gpu,
        "GPU",
    );
    chk(
        new_rec.audio.enabled && !old_rec.audio.enabled,
        cur.audio.enabled,
        "audio",
    );
    chk(
        new_rec.network.mode == NetworkMode::Full && old_rec.network.mode != NetworkMode::Full,
        cur.network.mode == NetworkMode::Full,
        "network",
    );
    chk(
        new_rec.display.x11 && !old_rec.display.x11,
        cur.display.x11,
        "X11",
    );
    for key in XDG_DIR_KEYS {
        let n = new_rec.filesystem.xdg_access(key);
        chk(
            n > old_rec.filesystem.xdg_access(key),
            cur.filesystem.xdg_access(key) >= n,
            &format!("{key} folder"),
        );
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
    let Ok(md) = fs::symlink_metadata(p) else {
        return 0;
    };
    if md.is_dir() {
        fs::read_dir(p)
            .map(|rd| rd.flatten().map(|e| tree_size(&e.path())).sum())
            .unwrap_or(0)
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
/// The marker file in an unpack folder SAM created itself.
const UNPACK_MARKER: &str = ".sam-unpack-folder";

/// Whether `name`, in the unpack folder, is something SAM put there: an
/// app's folder (`appimage-…`) or a leftover of an unpacking that did not
/// finish. Nothing else is ever deleted by cleaning up.
fn sams_own_unpack_entry(name: &str) -> bool {
    (name.starts_with("appimage-") && sam_storage::valid_id(name))
        || [".incoming-", ".unpack-", ".old-", ".staging-"]
            .iter()
            .any(|p| name.starts_with(p))
}

fn safe_to_delete(d: &Path) -> Result<()> {
    let home = sam_core::util::home_dir();
    if d.components().count() < 3 || home.starts_with(d) {
        bail!(
            "{}",
            sam_core::i18n::trf(
                "refusing to delete {folder}: it is not one of SAM's own folders",
                &[("folder", &d.display())]
            )
        );
    }
    Ok(())
}

/// The process has this file open.
fn holds_open(pid: u32, file: &Path) -> bool {
    let Ok(want) = fs::canonicalize(file) else {
        return false;
    };
    fs::read_dir(format!("/proc/{pid}/fd"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|fd| fs::read_link(fd.path()).is_ok_and(|t| t == want))
}

/// Asks an app to quit the way logging out does: SIGTERM to the app's own
/// processes, so it can save and close. `sandbox` is the program its
/// launcher `runner` started (Bubblewrap, or pasta with "This computer
/// only"); only processes below it that live in a process namespace of
/// their own (inside the sandbox) are asked, never the first process of
/// such a namespace (Bubblewrap's own). So SAM's helpers are never asked:
/// pasta quits on SIGTERM and Bubblewrap then takes the whole sandbox down
/// at once, with no time to save; the sound relay and the D-Bus proxy are
/// not below `sandbox` at all (review 2026-11-23 F3). Programs in Room
/// service's rooms are not below it either: each room's stand-in, one of
/// the app's processes, is asked and passes it on, so they get the same
/// time ([`ask_room_to_quit`]). Chosen by where a
/// process sits, not by its name, which any process can change. Each
/// process is signalled through a pidfd, after checking it is still the
/// one listed: a process id reused meanwhile is never hit.
pub(crate) fn ask_to_quit(runner: u32, sandbox: u32) {
    let procs = processes();
    // `sandbox` must be the runner's own child.
    if !procs.iter().any(|p| p.pid == sandbox && p.ppid == runner) {
        return;
    }
    let Some((base, _)) = ns_pid(runner) else {
        return;
    };
    ask_inside_to_quit(&procs, sandbox, base);
}

/// Asks the program in a room of Room service to quit, as its app was
/// asked: the room's stand-in, one of the app's own processes, got SIGTERM
/// and passed it on to the service (`room_service::standin`). `room` is
/// the room's Bubblewrap, a child of this process (the service runs in the
/// app's launcher); the same rule as for the app: only processes below it
/// in the room's own process namespace, never its first process
/// (Bubblewrap's own, which every room keeps).
pub(crate) fn ask_room_to_quit(room: u32) {
    let procs = processes();
    let me = std::process::id();
    if !procs.iter().any(|p| p.pid == room && p.ppid == me) {
        return;
    }
    let Some((base, _)) = ns_pid(me) else {
        return;
    };
    ask_inside_to_quit(&procs, room, base);
}

/// SIGTERM to the processes below `top` that live in a deeper process
/// namespace than `base`, except the first process of such a namespace.
fn ask_inside_to_quit(procs: &[Proc], top: u32, base: usize) {
    for p in below(procs, top) {
        match ns_pid(p.pid) {
            Some((depth, inner)) if depth > base && inner != 1 => {
                signal_same(p, libc::SIGTERM);
            }
            _ => {}
        }
    }
}

/// One process as `/proc` lists it.
#[derive(Debug, Clone, Copy)]
struct Proc {
    pid: u32,
    ppid: u32,
    /// When it started (clock ticks since boot): with `pid`, it names one
    /// process for good.
    start: u64,
}

/// The parent and start time from `/proc/<pid>/stat`.
fn stat_of(pid: u32) -> Option<(u32, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // "pid (comm) state ppid ...": comm may contain spaces or ')'.
    let rest: Vec<&str> = stat
        .get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    // After comm: state is field 3, ppid 4, starttime 22.
    Some((rest.get(1)?.parse().ok()?, rest.get(19)?.parse().ok()?))
}

/// Every process on the computer.
fn processes() -> Vec<Proc> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if let Some((ppid, start)) = stat_of(pid) {
                out.push(Proc { pid, ppid, start });
            }
        }
    }
    out
}

/// All processes below `root` (its children, theirs and so on).
fn below(procs: &[Proc], root: u32) -> Vec<Proc> {
    let mut out: Vec<Proc> = Vec::new();
    let mut frontier = vec![root];
    while let Some(p) = frontier.pop() {
        for c in procs.iter().filter(|c| c.ppid == p) {
            if !out.iter().any(|o| o.pid == c.pid) {
                out.push(*c);
                frontier.push(c.pid);
            }
        }
    }
    out
}

/// How many process namespaces deep `pid` lives (as seen from here), and
/// its number in the innermost one (`NSpid` in `/proc/<pid>/status`).
fn ns_pid(pid: u32) -> Option<(usize, u32)> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let ids: Vec<u32> = status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    Some((ids.len(), *ids.last()?))
}

/// Sends `sig` to `p` if it is still the same process.
fn signal_same(p: Proc, sig: i32) {
    let Ok(pid) = libc::pid_t::try_from(p.pid) else {
        return;
    };
    // SAFETY: pidfd_open takes a process id and flags; it returns a new
    // descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let same = || stat_of(p.pid).is_some_and(|(_, start)| start == p.start);
    if fd >= 0 {
        let Ok(fd) = i32::try_from(fd) else {
            return;
        };
        // Checked after the pidfd is open: it holds that very process.
        if same() {
            // SAFETY: `fd` is the pidfd opened above; no siginfo, no flags.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd,
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
        }
        // SAFETY: closing the descriptor opened above, once.
        unsafe { libc::close(fd) };
    } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) && same() {
        // No pidfd: a kernel older than 5.3 (ENOSYS), or a seccomp filter
        // around SAM that refuses the call (EPERM in some containers). The
        // app must still be asked; the start time was checked just now.
        // SAFETY: kill takes plain integers; a process that is gone only makes it fail.
        unsafe { libc::kill(pid, sig) };
    }
}

/// `remove_dir_all` that also handles folders without permissions, such as
/// the `work/work` folder the kernel's overlay file system leaves behind.
pub fn remove_tree(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn unlock(p: &Path) {
        let Ok(md) = fs::symlink_metadata(p) else {
            return;
        };
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
pub fn merge_adjustments(
    base: &PermissionSet,
    user: &PermissionSet,
    newer: &PermissionSet,
) -> PermissionSet {
    fn merge(
        b: &serde_json::Value,
        u: &serde_json::Value,
        n: &serde_json::Value,
    ) -> serde_json::Value {
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
    let (b, u, n) = (
        serde_json::to_value(base),
        serde_json::to_value(user),
        serde_json::to_value(newer),
    );
    match (b, u, n) {
        (Ok(b), Ok(u), Ok(n)) => {
            serde_json::from_value(merge(&b, &u, &n)).unwrap_or_else(|_| user.clone())
        }
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
    let key = s
        .fingerprint
        .as_deref()
        .map(|f| format!(" (key {})", &f[f.len().saturating_sub(16)..]))
        .unwrap_or_default();
    match s.state {
        S::Unsigned => "not signed".into(),
        S::Valid => format!("signed{key}"),
        S::Invalid => format!("signed{key}, but the signature does not match"),
        S::Unchecked => "signed (not checked)".into(),
    }
}

/// What the earlier signature was, when the new file is signed with another
/// key or no longer signed. An unsigned app that stays unsigned, or a first
/// signature, is no change worth a warning. An earlier signature that was
/// never checked (GnuPG missing) is no trusted key either: once the new
/// file's signature can be read, SAM cannot tell whether it is the same
/// key, so it counts as a change (review 2026-11-23, U-3).
pub(crate) fn signing_key_change(
    old: Option<&sam_core::model::SignatureInfo>,
    new: &sam_core::model::SignatureInfo,
) -> Option<String> {
    use sam_core::model::SignatureState as S;
    let old = old?;
    if old.state == S::Unchecked {
        return (new.state != S::Unchecked).then(|| sig_words(old));
    }
    let old_fp = old
        .fingerprint
        .as_deref()
        .filter(|_| old.state == S::Valid)?;
    match (new.state, new.fingerprint.as_deref()) {
        (S::Valid, Some(fp)) if fp == old_fp => None,
        (S::Unchecked, _) => None,
        _ => Some(sig_words(old)),
    }
}

/// What the earlier signature was, when it was checked and valid but the new
/// file's signature cannot be checked (GnuPG missing): then nobody can tell
/// whether the key changed, so it needs the same consent as a changed key.
pub(crate) fn signature_unconfirmed(
    old: Option<&sam_core::model::SignatureInfo>,
    new: &sam_core::model::SignatureInfo,
) -> Option<String> {
    use sam_core::model::SignatureState as S;
    let old = old.filter(|o| o.state == S::Valid && o.fingerprint.is_some())?;
    (new.state == S::Unchecked).then(|| sig_words(old))
}

/// When the new file is signed with the same key as the installed one but
/// earlier, it is an older version: an attacker who controls the download
/// could otherwise hand out an old, validly signed release with known holes
/// (audit U-M6). Returns both signing times. Unsigned or unchecked files, a
/// changed key (asked about separately) and records from before SAM kept
/// the time cannot be compared; [`signing_time_unknown`] tells when the key
/// is the same but a time is missing.
pub(crate) fn older_signed_version(
    old: Option<&sam_core::model::SignatureInfo>,
    new: &sam_core::model::SignatureInfo,
) -> Option<(i64, i64)> {
    use sam_core::model::SignatureState as S;
    let old = old.filter(|o| o.state == S::Valid)?;
    if new.state != S::Valid || new.fingerprint.is_none() || new.fingerprint != old.fingerprint {
        return None;
    }
    let (was, now) = (old.signed_at?, new.signed_at?);
    (now < was).then_some((was, now))
}

/// Whether the new file is signed with the same key as the installed one
/// while at least one of the two signing times is unknown (a record from
/// before SAM kept the time, or a time gpgv did not report): then SAM
/// cannot tell whether the update is an older version, and
/// [`older_signed_version`] cannot refuse it (review B2 S6, R94).
pub(crate) fn signing_time_unknown(
    old: Option<&sam_core::model::SignatureInfo>,
    new: &sam_core::model::SignatureInfo,
) -> bool {
    use sam_core::model::SignatureState as S;
    let Some(old) = old.filter(|o| o.state == S::Valid && o.fingerprint.is_some()) else {
        return false;
    };
    new.state == S::Valid
        && new.fingerprint == old.fingerprint
        && (old.signed_at.is_none() || new.signed_at.is_none())
}

#[cfg(test)]
mod signature_tests {
    use super::signing_key_change;
    use sam_core::model::{SignatureInfo, SignatureState as S};

    fn sig(state: S, fp: Option<&str>) -> SignatureInfo {
        SignatureInfo {
            state,
            fingerprint: fp.map(str::to_string),
            detail: String::new(),
            signed_at: None,
        }
    }

    /// An update signed with the same key but earlier than the installed
    /// version is an older version; later, equal, another key, unsigned or
    /// without a time is not judged here.
    #[test]
    fn an_older_signed_version_is_recognized() {
        use super::older_signed_version;
        let at = |state: S, fp: Option<&str>, t: Option<i64>| SignatureInfo {
            signed_at: t,
            ..sig(state, fp)
        };
        let installed = at(S::Valid, Some("A"), Some(2_000));
        assert_eq!(
            older_signed_version(Some(&installed), &at(S::Valid, Some("A"), Some(1_000))),
            Some((2_000, 1_000))
        );
        for new in [
            at(S::Valid, Some("A"), Some(3_000)),
            at(S::Valid, Some("A"), Some(2_000)),
            at(S::Valid, Some("B"), Some(1_000)),
            at(S::Valid, Some("A"), None),
            at(S::Invalid, Some("A"), Some(1_000)),
            at(S::Unsigned, None, None),
        ] {
            assert_eq!(
                older_signed_version(Some(&installed), &new),
                None,
                "{new:?}"
            );
        }
        assert_eq!(
            older_signed_version(
                Some(&at(S::Valid, Some("A"), None)),
                &at(S::Valid, Some("A"), Some(1))
            ),
            None,
            "a record from before SAM kept the time"
        );
        assert_eq!(
            older_signed_version(None, &at(S::Valid, Some("A"), Some(1))),
            None
        );
    }

    /// An update signed with another key, or not signed at all, is noticed.
    #[test]
    fn key_changes_are_noticed() {
        let a = sig(S::Valid, Some("AAAA"));
        assert_eq!(
            signing_key_change(Some(&a), &sig(S::Valid, Some("AAAA"))),
            None,
            "same key"
        );
        assert!(
            signing_key_change(Some(&a), &sig(S::Valid, Some("BBBB"))).is_some(),
            "other key"
        );
        assert!(
            signing_key_change(Some(&a), &sig(S::Unsigned, None)).is_some(),
            "no longer signed"
        );
        assert_eq!(
            signing_key_change(Some(&sig(S::Unsigned, None)), &sig(S::Valid, Some("AAAA"))),
            None,
            "first signature"
        );
        assert_eq!(signing_key_change(None, &sig(S::Unsigned, None)), None);
    }

    /// A signature recorded as "not checked" (GnuPG was missing) lets no key
    /// through: once the new file's signature can be read, whatever it is
    /// (another key, none, a bad one) counts as a change; both unchecked is
    /// no news (review 2026-11-23, U-3).
    #[test]
    fn a_signature_that_was_never_checked_lets_no_key_through() {
        let unchecked = sig(S::Unchecked, None);
        for new in [
            sig(S::Valid, Some("BBBB")),
            sig(S::Unsigned, None),
            sig(S::Invalid, None),
        ] {
            assert_eq!(
                signing_key_change(Some(&unchecked), &new).as_deref(),
                Some("signed (not checked)"),
                "{new:?}"
            );
        }
        assert_eq!(
            signing_key_change(Some(&unchecked), &sig(S::Unchecked, None)),
            None
        );
    }

    /// A signed app whose update cannot be checked (GnuPG missing) is not
    /// waved through: SAM cannot tell whether the key changed.
    #[test]
    fn an_update_that_cannot_be_checked_needs_consent_after_a_valid_signature() {
        use super::signature_unconfirmed;
        let valid = sig(S::Valid, Some("AAAA"));
        assert!(
            signature_unconfirmed(Some(&valid), &sig(S::Unchecked, None)).is_some(),
            "valid before, unchecked now"
        );
        assert_eq!(
            signature_unconfirmed(Some(&valid), &sig(S::Valid, Some("AAAA"))),
            None,
            "checked and the same"
        );
        assert_eq!(
            signature_unconfirmed(Some(&sig(S::Unsigned, None)), &sig(S::Unchecked, None)),
            None,
            "never signed before: nothing to confirm"
        );
        assert_eq!(
            signature_unconfirmed(Some(&sig(S::Unchecked, None)), &sig(S::Unchecked, None)),
            None,
            "never checked before"
        );
        assert_eq!(signature_unconfirmed(None, &sig(S::Unchecked, None)), None);
    }

    /// The same key on both versions, but one signing time unknown (a record
    /// from before SAM kept the time, or a time gpgv did not report): SAM
    /// cannot tell whether the update is older. Both times known, another
    /// key, an unsigned, unchecked or bad file, or no earlier signature is
    /// not this case (review B2 S6, R94).
    #[test]
    fn a_signing_time_that_cannot_be_read_is_noticed() {
        use super::signing_time_unknown;
        let at = |state: S, fp: Option<&str>, t: Option<i64>| SignatureInfo {
            signed_at: t,
            ..sig(state, fp)
        };
        let timed = at(S::Valid, Some("A"), Some(2_000));
        let untimed = at(S::Valid, Some("A"), None);
        assert!(
            signing_time_unknown(Some(&untimed), &at(S::Valid, Some("A"), Some(1_000))),
            "a record without a time"
        );
        assert!(
            signing_time_unknown(Some(&timed), &untimed),
            "a new file without a time"
        );
        assert!(signing_time_unknown(Some(&untimed), &untimed), "neither");
        for (old, new) in [
            (&timed, at(S::Valid, Some("A"), Some(1_000))),
            (&untimed, at(S::Valid, Some("B"), None)),
            (&untimed, at(S::Valid, None, None)),
            (&untimed, at(S::Unchecked, None, None)),
            (&untimed, at(S::Invalid, Some("A"), None)),
            (&untimed, at(S::Unsigned, None, None)),
            (&at(S::Valid, None, None), at(S::Valid, None, None)),
            (&at(S::Invalid, Some("A"), None), untimed.clone()),
            (&at(S::Unchecked, None, None), untimed.clone()),
        ] {
            assert!(!signing_time_unknown(Some(old), &new), "{old:?} {new:?}");
        }
        assert!(
            !signing_time_unknown(None, &untimed),
            "no earlier signature"
        );
    }
}

#[cfg(test)]
mod below_tests {
    use super::{below, Proc};

    /// The processes below an app's sandbox are its children and their
    /// children, and nothing else: quitting asks only those (mutation run
    /// 2026-11-24: the walk could take every other process instead, so
    /// stopping one app would have asked other sandboxes to quit).
    #[test]
    fn only_the_processes_below_a_sandbox_are_its_own() {
        let p = |pid, ppid| Proc {
            pid,
            ppid,
            start: 0,
        };
        // 10 is the sandbox: 11 and 12 its children, 13 a grandchild;
        // 20 and 21 another sandbox, 1 the system.
        let procs = [
            p(1, 0),
            p(10, 1),
            p(11, 10),
            p(12, 10),
            p(13, 11),
            p(20, 1),
            p(21, 20),
        ];
        let mut got: Vec<u32> = below(&procs, 10).iter().map(|c| c.pid).collect();
        got.sort_unstable();
        assert_eq!(got, [11, 12, 13]);
        assert!(below(&procs, 13).is_empty(), "no children, nothing below");
        // Reused process numbers can make a loop: the walk still ends.
        let looped = [p(40, 41), p(41, 40)];
        assert_eq!(below(&looped, 40).len(), 2);
    }
}

#[cfg(test)]
mod quit_tests {
    #![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
    use super::ask_to_quit;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Review 2026-11-23 F3: asking an app to quit reaches the app's own
    /// processes, also one whose program is called `bwrap`, and nothing of
    /// SAM's: not the program the launcher started (here a stand-in for
    /// pasta that quits on SIGTERM, which would take the sandbox down at
    /// once), not a helper beside the sandbox (as the sound relay).
    #[test]
    fn only_the_apps_own_processes_are_asked_to_quit() {
        let host = sam_core::HostInfo::probe();
        if host.tools.bwrap.is_none() || crate::doctor::bwrap_functional(&host).is_err() {
            crate::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = t.path().display().to_string();
        // The app's program file is named bwrap, so its process is too.
        std::fs::copy("/bin/sh", t.path().join("bwrap")).unwrap();
        let mut helper = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'touch {d}/helper-asked; exit' TERM; while :; do sleep 0.1; done"
            ))
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let app = format!(
            "trap 'echo saved > {d}/saved; exit 0' TERM; touch {d}/ready; while :; do sleep 0.1; done"
        );
        let mut root = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'touch {d}/root-asked; exit' TERM; \
                 bwrap --unshare-user --unshare-pid --die-with-parent --ro-bind / / \
                 --dev /dev --proc /proc --bind {d} {d} -- {d}/bwrap -c \"$0\" & wait",
            ))
            .arg(&app)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let wait_for = |name: &str| {
            let end = Instant::now() + Duration::from_secs(10);
            while Instant::now() < end {
                if t.path().join(name).exists() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        };
        assert!(wait_for("ready"), "the app did not start");
        ask_to_quit(std::process::id(), root.id());
        let saved = wait_for("saved");
        std::thread::sleep(Duration::from_millis(300));
        let root_asked = t.path().join("root-asked").exists();
        let helper_asked = t.path().join("helper-asked").exists();
        for c in [&mut helper, &mut root] {
            let _ = c.kill();
            let _ = c.wait();
        }
        assert!(saved, "the app was not asked to quit");
        assert!(!root_asked, "the program the launcher started was asked");
        assert!(!helper_asked, "a helper beside the sandbox was asked");
    }
}
