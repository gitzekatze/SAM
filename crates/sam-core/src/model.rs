//! Core data types: AppEntry, AppImageMetadata,
//! SandboxProfile, Preset, Warning, DiagnosticReport, ...

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::permissions::PermissionSet;
use crate::risk::{RiskAssessment, RiskLevel};
use crate::warnings::Warning;

/// Lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AppState {
    Detected,
    #[default]
    Registered,
    Extracted,
    Profiled,
    Ready,
    Stale,
    Broken,
    Unsafe,
    Missing,
}

/// User-facing badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Badge {
    Ready,
    NeedsReview,
    /// Compatibility mode is on: the app has broad access so that it works.
    CompatibilityMode,
    /// The dependency analysis found the app may not start in its sandbox
    /// (e.g. it relies on system libraries), and it has not started yet.
    CompatibilityRisk,
    Stale,
    Broken,
    Unsafe,
    Missing,
}

impl Badge {
    pub fn label(self) -> &'static str {
        match self {
            Badge::Ready => "Ready",
            Badge::NeedsReview => "Needs Review",
            Badge::CompatibilityMode => "Compatibility Mode",
            Badge::CompatibilityRisk => "May Not Start",
            Badge::Stale => "Stale",
            Badge::Broken => "Broken",
            Badge::Unsafe => "Unsafe",
            Badge::Missing => "Missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AppImageType {
    #[serde(rename = "type1")]
    Type1,
    #[serde(rename = "type2")]
    Type2,
    #[default]
    #[serde(rename = "unknown")]
    Unknown,
}

impl AppImageType {
    pub fn label(self) -> &'static str {
        match self {
            AppImageType::Type1 => "Type 1 (ISO 9660)",
            AppImageType::Type2 => "Type 2 (SquashFS)",
            AppImageType::Unknown => "Unknown",
        }
    }
}

/// Identity of the source file, used for staleness detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Fingerprint {
    pub size: u64,
    pub mtime: i64,
    pub inode: u64,
    pub device: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppImageMetadata {
    pub name: String,
    pub comment: String,
    pub icon_name: String,
    /// Cached icon path in SAM's icon cache.
    pub icon_path: Option<PathBuf>,
    pub categories: Vec<String>,
    pub mime_types: Vec<String>,
    /// Relative path of the .desktop file inside the AppDir.
    pub desktop_file: Option<String>,
    pub exec: String,
    pub version: String,
    pub terminal: bool,
    pub startup_wm_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ExtractionInfo {
    /// Directory containing `AppDir/`, `metadata.json`, `extraction.log`, ...
    pub root: PathBuf,
    /// The extracted payload root.
    pub appdir: PathBuf,
    /// Entry point relative to the AppDir (usually `AppRun`).
    pub entry: String,
    pub method: String,
    pub compression: String,
    pub file_count: u64,
    pub total_size: u64,
    pub extracted_at: i64,
    /// Fingerprint of the source at extraction time.
    pub source: Fingerprint,
    pub suspicious: Vec<String>,
    pub warnings: Vec<Warning>,
}

/// How a library or host resource is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ResourceClass {
    /// Read-only shared data, granted automatically.
    Safe,
    /// Granted only if the matching permission is enabled.
    Controlled,
    /// GPU stack resources. Medium risk, often required.
    Graphics,
    /// Expected from the host by AppImage convention (glibc & friends).
    System,
    /// ABI-sensitive host libraries that are never silently exposed.
    Dangerous,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingLibrary {
    pub name: String,
    pub class: ResourceClass,
    pub host_available: bool,
    /// Which binaries need it (capped).
    pub needed_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Requirements {
    pub gpu: bool,
    pub audio: bool,
    pub network: bool,
    pub x11: bool,
    pub wayland: bool,
    pub fonts: bool,
    pub certificates: bool,
    pub dbus: bool,
    pub electron: bool,
    pub java: bool,
    /// Starts its own sandbox with namespaces: Chromium engines (CEF, Qt
    /// WebEngine) and WebKitGTK (which runs Bubblewrap itself).
    #[serde(default)]
    pub nested_sandbox: bool,
    pub toolkit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostResource {
    pub resource: String,
    pub class: ResourceClass,
    pub reason: String,
    /// True when this was granted automatically as a low-risk fix.
    pub auto: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Compatibility {
    #[default]
    Good,
    Risk,
    LikelyBroken,
}

/// Unsafe-handling outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationVerdict {
    /// "This app can run, but meaningful isolation is limited."
    WeaklyIsolated,
    /// "This app probably cannot run correctly inside a sandbox."
    LikelyBroken,
    /// "This app requires access that cannot be safely sandboxed."
    UnsafeToSandbox,
}

impl IsolationVerdict {
    pub fn message(self) -> &'static str {
        match self {
            IsolationVerdict::WeaklyIsolated => "This app can run, but meaningful isolation is limited.",
            IsolationVerdict::LikelyBroken => "This app probably cannot run correctly inside a sandbox.",
            IsolationVerdict::UnsafeToSandbox => "This app requires access that cannot be safely sandboxed (it asks for administrator rights).",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DependencyReport {
    pub analyzed_at: i64,
    pub entry_binary: Option<String>,
    pub entry_is_script: bool,
    pub elf_count: u64,
    pub bundled_libraries: u64,
    pub arch: String,
    pub missing: Vec<MissingLibrary>,
    pub requirements: Requirements,
    pub resources: Vec<HostResource>,
    pub compatibility: Compatibility,
    pub verdict: Option<IsolationVerdict>,
    pub warnings: Vec<Warning>,
    pub notes: Vec<String>,
}

/// Outcome of a sandbox check: the sandbox was started with a probe
/// instead of the app, and every setting was checked from inside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CheckRecord {
    pub at: i64,
    /// Settings, SAM version and relevant host state the check applied to;
    /// a different key means the check is out of date.
    pub key: String,
    pub passed: usize,
    /// Titles of the checks that failed.
    pub failed: Vec<String>,
    /// Checks that could not run on this computer.
    pub skipped: usize,
}

/// Per-app sandbox settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SandboxProfile {
    pub permissions: PermissionSet,
    /// Name of the preset last applied, if any.
    pub preset: Option<String>,
    pub compatibility_mode: bool,
    /// Extra arguments always passed to the app.
    pub args: Vec<String>,
    /// The profile differs from the recommendation because the user changed it.
    pub user_modified: bool,
    /// Permissions from before compatibility mode was turned on; restored
    /// when it is turned off again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_compat: Option<PermissionSet>,
}

/// A suggested change that may make an app work (first-run hint, log
/// finding or repair step), with what applying it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suggestion {
    /// Stable id, e.g. `x11`, `network`, `libs-missing`.
    pub id: String,
    pub title: String,
    pub explanation: String,
    pub action: FixAction,
    pub risk: crate::risk::RiskLevel,
    /// Derived from the app's own output (which the app controls): always
    /// needs confirmation and is labelled as the app's request.
    #[serde(default)]
    pub from_app_output: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FixAction {
    /// Set one permission key.
    Set { key: String, value: String },
    /// Add a value to a list permission (folder, bus name).
    Add { key: String, value: String },
    /// Turn on compatibility mode.
    Compat,
    /// Always pass this argument to the app (e.g. `--no-sandbox`).
    AddArg { value: String },
    /// Nothing SAM can change (explanation only).
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LaunchRecord {
    pub started_at: i64,
    pub finished_at: i64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub success: bool,
    /// Failure looked like a sandbox setup problem rather than the app exiting.
    pub sandbox_failure: bool,
    /// Bubblewrap reported that the sandbox could not be built (its status
    /// channel never announced the app's process). App output never sets this.
    pub setup_failed: bool,
    /// What SAM's helper actually enforced inside the sandbox, e.g.
    /// "landlock: fully enforced; seccomp: baseline loaded".
    pub enforcement: Option<String>,
    pub log_file: Option<PathBuf>,
    pub summary: String,
    /// What the app's output suggests went wrong, with fixes.
    pub findings: Vec<Suggestion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppEntry {
    /// File format (see `format`); written as the current one.
    pub format: u32,
    pub id: String,
    pub name: String,
    pub source_path: PathBuf,
    pub appimage_type: AppImageType,
    pub source: Fingerprint,
    pub added_at: i64,
    pub updated_at: i64,
    pub last_launched: Option<i64>,
    pub state: AppState,
    pub category: String,
    pub metadata: AppImageMetadata,
    pub extraction: Option<ExtractionInfo>,
    pub detection: Option<DependencyReport>,
    pub recommended: PermissionSet,
    pub recommendation_notes: Vec<String>,
    pub profile: SandboxProfile,
    /// The user has looked at (or accepted) the current profile.
    pub reviewed: bool,
    /// Permissions newly requested after an update that need confirmation.
    pub pending_changes: Vec<String>,
    /// Result of the last sandbox check (`sam-jail verify`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_check: Option<CheckRecord>,
    pub last_launch: Option<LaunchRecord>,
    pub desktop_entry: Option<PathBuf>,
    pub last_error: Option<String>,
    /// Profile before the first repair step, for "Undo repairs".
    pub repair_backup: Option<SandboxProfile>,
    /// Repair step ids already applied (the ladder skips them).
    pub repairs_applied: Vec<String>,
    /// Unsandboxed menu entries for this AppImage (made by AppImageLauncher,
    /// Gear Lever, ...) that SAM hid when the sandbox was created.
    pub hidden_entries: Vec<HiddenEntry>,
    /// The AppImage's embedded signature, checked when it was unpacked.
    pub signature: Option<SignatureInfo>,
    /// Set when the current file is signed with another key than the one
    /// before (or no longer signed): what the earlier signature was.
    pub signing_key_changed: Option<String>,
    /// Result of the last update check (`sam-jail updates`).
    pub update: Option<UpdateStatus>,
    /// The version an update replaced, kept in SAM's data folder so the
    /// update can be undone (`sam-jail update APP --undo`).
    pub update_backup: Option<UpdateBackup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct UpdateBackup {
    /// The kept file (in `<data>/update-backups/<id>/`).
    pub file: PathBuf,
    /// Where it was before the update.
    pub original_path: PathBuf,
    /// When the update ran (Unix seconds).
    pub replaced_at: i64,
}

/// Whether a newer version of an AppImage is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateState {
    /// The AppImage names no update source SAM knows.
    #[default]
    Unsupported,
    /// The published file is the one on this computer.
    Current,
    /// A different file is published.
    Available,
    /// The check did not get an answer (offline, server error, …).
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct UpdateStatus {
    pub state: UpdateState,
    /// Release or file name of the newest version, when known.
    pub latest: Option<String>,
    /// Where people can download it (https only).
    pub download_page: Option<String>,
    /// One sentence for people.
    pub detail: String,
    /// When the check ran (Unix seconds).
    pub checked_at: i64,
}

/// State of an AppImage's embedded signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SignatureState {
    #[default]
    Unsigned,
    /// Matches the file (with the key that came in the file).
    Valid,
    /// Does not match: the file was changed after signing, or the key is unreadable.
    Invalid,
    /// Signed, but could not be checked (GnuPG missing, unreadable file).
    Unchecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SignatureInfo {
    pub state: SignatureState,
    /// Fingerprint of the signer's key, when it could be read.
    pub fingerprint: Option<String>,
    /// One sentence for people.
    pub detail: String,
}

/// A foreign menu entry SAM hid, with what is needed to restore it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HiddenEntry {
    /// The original desktop file.
    pub original: PathBuf,
    /// The file SAM wrote: the original itself (user-level entries) or an
    /// override with the same name in the user's applications folder.
    pub modified: PathBuf,
    pub created_override: bool,
    /// `NoDisplay=` value before SAM changed it, if there was one.
    pub previous_nodisplay: Option<String>,
}

impl AppEntry {
    /// Forget that the last launch failed in the sandbox setup. Called when the
    /// profile changes, since the next launch will be different.
    /// The record and its log stay; only the "Broken" verdict is dropped.
    pub fn clear_launch_failure(&mut self) {
        if let Some(l) = self.last_launch.as_mut().filter(|l| l.sandbox_failure) {
            l.sandbox_failure = false;
            self.last_error = None;
        }
    }

    /// Compute the badge shown in the UI.
    pub fn badge(&self) -> Badge {
        match self.state {
            AppState::Missing => return Badge::Missing,
            AppState::Broken => return Badge::Broken,
            AppState::Unsafe => return Badge::Unsafe,
            AppState::Stale => return Badge::Stale,
            _ => {}
        }
        if self.extraction.is_none() {
            return Badge::Broken;
        }
        if matches!(&self.last_launch, Some(l) if l.sandbox_failure) {
            return Badge::Broken;
        }
        if let Some(d) = &self.detection {
            if d.verdict == Some(IsolationVerdict::UnsafeToSandbox) {
                return Badge::Unsafe;
            }
        }
        if !self.reviewed || !self.pending_changes.is_empty() {
            return Badge::NeedsReview;
        }
        if self.profile.compatibility_mode {
            return Badge::CompatibilityMode;
        }
        // A warning from the analysis, until the app has shown it starts.
        if matches!(&self.detection, Some(d) if d.compatibility != Compatibility::Good) && !self.started_fine() {
            return Badge::CompatibilityRisk;
        }
        Badge::Ready
    }

    /// The last start got the app running: it exited normally, was closed by
    /// SAM, or ran for more than ten seconds.
    pub fn started_fine(&self) -> bool {
        self.last_launch.as_ref().is_some_and(|l| !l.sandbox_failure && (l.success || l.finished_at - l.started_at > 10))
    }

    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.id
        } else {
            &self.name
        }
    }
}

/// A reusable permission template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Preset {
    pub name: String,
    pub description: String,
    pub permissions: PermissionSet,
    pub risk: RiskLevel,
    pub created_at: i64,
    pub modified_at: i64,
    pub compatibility_notes: String,
}

/// Summary of a backend's availability on this machine.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiagnosticReport {
    pub generated_at: i64,
    pub sam_version: String,
    pub checks: Vec<DiagnosticCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub id: String,
    pub label: String,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl DiagnosticCheck {
    pub fn new(id: &str, label: &str, status: CheckStatus, detail: impl Into<String>) -> Self {
        DiagnosticCheck { id: id.into(), label: label.into(), status, detail: detail.into(), hint: None }
    }
    pub fn hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }
}

/// Per-app view used by the GUI/CLI: entry plus derived fields.
#[derive(Debug, Clone, Serialize)]
pub struct AppSummary {
    pub id: String,
    pub name: String,
    pub comment: String,
    pub icon_path: Option<PathBuf>,
    pub source_path: PathBuf,
    pub state: AppState,
    pub badge: Badge,
    pub badge_label: &'static str,
    pub category: String,
    pub risk: RiskAssessment,
    pub last_launched: Option<i64>,
    pub added_at: i64,
    /// The last start failed: the likely cause, or the exit summary.
    pub last_problem: Option<String>,
    /// A terminal program (`Terminal=true`): started in a terminal window.
    pub terminal: bool,
}

impl AppSummary {
    pub fn from_entry(e: &AppEntry) -> Self {
        let badge = e.badge();
        AppSummary {
            id: e.id.clone(),
            name: e.display_name().to_string(),
            comment: e.metadata.comment.clone(),
            icon_path: e.metadata.icon_path.clone(),
            source_path: e.source_path.clone(),
            state: e.state,
            badge,
            badge_label: badge.label(),
            category: e.category.clone(),
            risk: crate::risk::assess(&e.profile.permissions),
            last_launched: e.last_launched,
            added_at: e.added_at,
            last_problem: e
                .last_launch
                .as_ref()
                .filter(|l| !l.success && !matches!(l.signal, Some(9) | Some(15)))
                .map(|l| l.findings.first().map(|f| f.title.clone()).unwrap_or_else(|| l.summary.clone())),
            terminal: e.metadata.terminal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_change_clears_broken_launch() {
        let mut a = AppEntry {
            last_launch: Some(LaunchRecord { sandbox_failure: true, ..Default::default() }),
            last_error: Some("backend not available".into()),
            ..Default::default()
        };
        a.clear_launch_failure();
        assert!(!a.last_launch.as_ref().unwrap().sandbox_failure);
        assert!(a.last_error.is_none());
    }
}

#[cfg(test)]
mod badge_tests {
    use super::*;

    #[test]
    fn compatibility_labels() {
        let mut e = AppEntry { extraction: Some(ExtractionInfo::default()), reviewed: true, ..Default::default() };
        e.detection = Some(DependencyReport { compatibility: Compatibility::Risk, ..Default::default() });
        assert_eq!(e.badge(), Badge::CompatibilityRisk, "warning until it has started");
        e.last_launch = Some(LaunchRecord { started_at: 0, finished_at: 3, success: false, ..Default::default() });
        assert_eq!(e.badge(), Badge::CompatibilityRisk, "a crash right away keeps it");
        e.last_launch = Some(LaunchRecord { started_at: 0, finished_at: 60, success: false, ..Default::default() });
        assert_eq!(e.badge(), Badge::Ready, "ran for a minute: it starts");
        e.profile.compatibility_mode = true;
        assert_eq!(e.badge(), Badge::CompatibilityMode);
    }
}
