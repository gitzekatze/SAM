//! Core data types (build plan §3.4): AppEntry, AppImageMetadata,
//! SandboxProfile, Preset, Warning, BackendChoice, DiagnosticReport, ...

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::backend::BackendKind;
use crate::permissions::PermissionSet;
use crate::risk::{RiskAssessment, RiskLevel};
use crate::warnings::Warning;

/// Lifecycle state (whitepaper §2.10).
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

/// User-facing badge (whitepaper §2.20.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Badge {
    Ready,
    NeedsReview,
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
            Badge::CompatibilityRisk => "Compatibility Risk",
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

/// Identity of the source file, used for staleness detection (§2.11.7).
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

/// How a library or host resource is classified (§2.16.2).
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

/// Unsafe-handling outcomes (§2.19.4).
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
            IsolationVerdict::UnsafeToSandbox => "This app requires access that cannot be safely sandboxed. Run unsandboxed only if you trust this application.",
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

/// Backend selection stored per app (§2.13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendChoice {
    #[default]
    Auto,
    Bubblewrap,
    Bubblejail,
    Firejail,
    Unsandboxed,
}

impl BackendChoice {
    pub fn fixed(self) -> Option<BackendKind> {
        match self {
            BackendChoice::Auto => None,
            BackendChoice::Bubblewrap => Some(BackendKind::Bubblewrap),
            BackendChoice::Bubblejail => Some(BackendKind::Bubblejail),
            BackendChoice::Firejail => Some(BackendKind::Firejail),
            BackendChoice::Unsandboxed => Some(BackendKind::Unsandboxed),
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "auto" => BackendChoice::Auto,
            "bubblewrap" | "bwrap" => BackendChoice::Bubblewrap,
            "bubblejail" => BackendChoice::Bubblejail,
            "firejail" => BackendChoice::Firejail,
            "unsandboxed" | "none" => BackendChoice::Unsandboxed,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            BackendChoice::Auto => "auto",
            BackendChoice::Bubblewrap => "bubblewrap",
            BackendChoice::Bubblejail => "bubblejail",
            BackendChoice::Firejail => "firejail",
            BackendChoice::Unsandboxed => "unsandboxed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SandboxProfile {
    pub backend: BackendChoice,
    pub permissions: PermissionSet,
    /// Name of the preset last applied, if any.
    pub preset: Option<String>,
    pub compatibility_mode: bool,
    /// The user explicitly confirmed running without a sandbox.
    pub unsandboxed_confirmed: bool,
    /// The user explicitly confirmed Firejail use for this app.
    pub firejail_confirmed: bool,
    /// Extra arguments always passed to the app.
    pub args: Vec<String>,
    /// The profile differs from the recommendation because the user changed it.
    pub user_modified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LaunchRecord {
    pub started_at: i64,
    pub finished_at: i64,
    pub backend: Option<BackendKind>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub success: bool,
    /// Failure looked like a sandbox setup problem rather than the app exiting.
    pub sandbox_failure: bool,
    pub log_file: Option<PathBuf>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppEntry {
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
    pub last_launch: Option<LaunchRecord>,
    pub desktop_entry: Option<PathBuf>,
    pub last_error: Option<String>,
    /// Unsandboxed menu entries for this AppImage (made by AppImageLauncher,
    /// Gear Lever, ...) that SAM hid when the sandbox was created.
    pub hidden_entries: Vec<HiddenEntry>,
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
    /// profile or backend changes, since the next launch will be different.
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
            if d.verdict == Some(IsolationVerdict::UnsafeToSandbox) && self.profile.backend != BackendChoice::Unsandboxed {
                return Badge::Unsafe;
            }
        }
        if !self.reviewed || !self.pending_changes.is_empty() {
            return Badge::NeedsReview;
        }
        if self.profile.compatibility_mode
            || matches!(&self.detection, Some(d) if d.compatibility != Compatibility::Good)
        {
            return Badge::CompatibilityRisk;
        }
        Badge::Ready
    }

    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.id
        } else {
            &self.name
        }
    }
}

/// A reusable permission template (§2.18).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Preset {
    pub name: String,
    pub description: String,
    pub permissions: PermissionSet,
    /// Backend the preset prefers, if any (e.g. compatibility presets needing Firejail).
    pub backend: Option<BackendChoice>,
    pub risk: RiskLevel,
    pub created_at: i64,
    pub modified_at: i64,
    pub compatibility_notes: String,
    /// Shipped with SAM (read-only; duplicating creates a user copy).
    #[serde(skip_deserializing)]
    pub builtin: bool,
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
        DiagnosticCheck {
            id: id.into(),
            label: label.into(),
            status,
            detail: detail.into(),
            hint: None,
        }
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
    pub backend: BackendChoice,
    pub risk: RiskAssessment,
    pub last_launched: Option<i64>,
    pub added_at: i64,
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
            backend: e.profile.backend,
            risk: crate::risk::assess(&e.profile.permissions, e.profile.backend.fixed()),
            last_launched: e.last_launched,
            added_at: e.added_at,
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
