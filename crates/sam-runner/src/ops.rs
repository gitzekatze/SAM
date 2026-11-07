//! The [`SAM`] facade: every user-level operation, shared by CLI and GUI.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sam_core::permissions::*;
use sam_core::risk::{assess, RiskAssessment};
use sam_core::util::{now, tildify};
use sam_core::warnings::{evaluate, WarningContext};
use sam_core::*;
use sam_detect::{analyze_appdir, inspect, looks_like_appimage, AnalyzeOptions};
use sam_intake::extract::{extract, ExtractRequest, NeedsFallbackConsent};
use sam_intake::fingerprint::{self, SourceStatus};
use sam_intake::normalize::Limits;
use sam_intake::{desktop, id, metadata};
use sam_profile::{check_preset, compatibility_profile, find_preset, recommend, PresetCheck};
use sam_storage::{LogKind, Logs, PresetStore, Registry};
use serde::Serialize;

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
}

#[derive(Debug, Clone, Serialize)]
pub struct AddOutcome {
    pub entry: AppEntry,
    pub created: bool,
    pub relocated: bool,
    pub needs_fallback_consent: bool,
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
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PresetApply {
    pub preset: String,
    pub check: PresetCheck,
    pub applied: bool,
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
        }
    }

    pub fn extracted_root(&self) -> PathBuf {
        self.paths.extracted_root(&self.config.extraction.location)
    }

    pub fn resolve(&self, query: &str) -> Result<AppEntry> {
        self.registry().resolve(query)
    }

    // ------------------------------------------------------------------ add

    pub fn add(&self, path: &Path, opts: &AddOptions) -> Result<AddOutcome> {
        let source = fs::canonicalize(path).with_context(|| format!("{} does not exist", path.display()))?;
        if !source.is_file() {
            bail!("{} is not a file", source.display());
        }
        let reg = self.registry();
        let all = reg.list()?;
        if let Some(existing) = all.iter().find(|a| a.source_path == source) {
            bail!("{} is already registered as '{}' ({})", tildify(&source), existing.display_name(), existing.id);
        }
        let info = inspect(&source)?;
        if !info.is_appimage() {
            bail!("{} is not an AppImage ({})", tildify(&source), info.notes.join("; "));
        }
        let fp = fingerprint::compute(&source)?;

        // Same content as a registered app whose file went missing: relocate.
        if let Some(mut moved) = all.into_iter().find(|a| a.source.sha256 == fp.sha256 && !a.source_path.exists()) {
            moved.source_path = source.clone();
            moved.source = fp;
            if let Some(x) = moved.extraction.as_mut() {
                x.source = moved.source.clone();
            }
            if moved.state == AppState::Missing {
                moved.state = AppState::Ready;
            }
            reg.save(&mut moved)?;
            return Ok(AddOutcome { entry: moved, created: false, relocated: true, needs_fallback_consent: false, warnings: vec![] });
        }

        let t = now();
        let mut entry = AppEntry {
            source_path: source.clone(),
            appimage_type: info.kind,
            source: fp.clone(),
            added_at: t,
            state: AppState::Registered,
            ..Default::default()
        };
        // Extract into a temporary root; the final id depends on metadata.
        let root_base = self.extracted_root();
        let incoming = root_base.join(format!(".incoming-{}", &fp.sha256[..12]));
        if incoming.exists() {
            fs::remove_dir_all(&incoming)?;
        }
        let mut log = Vec::new();
        let req = ExtractRequest { source: &source, info: &info, root: &incoming, limits: self.limits(), allow_fallback: opts.consent_fallback && self.config.extraction.allow_fallback };
        let extracted = extract(&req, &mut log);
        let md = match &extracted {
            Ok(out) => metadata::read_metadata(&out.appdir).unwrap_or_default(),
            Err(_) => AppImageMetadata::default(),
        };
        entry.id = id::generate_id(&md.name, &source, &fp.sha256, |cand| reg.exists(cand));
        entry.name = if md.name.is_empty() { id::slug_from_filename(&source) } else { md.name.clone() };
        entry.metadata = md;

        let mut needs_consent = false;
        match extracted {
            Ok(out) => {
                let root = root_base.join(&entry.id);
                if root.exists() {
                    fs::remove_dir_all(&root)?;
                }
                fs::rename(&incoming, &root)?;
                let appdir = root.join("AppDir");
                entry.extraction = Some(self.extraction_info(&root, &appdir, &out, &info, &fp));
                entry.state = AppState::Extracted;
                self.finish_intake(&mut entry, &log)?;
            }
            Err(e) => {
                let _ = fs::remove_dir_all(&incoming);
                needs_consent = e.downcast_ref::<NeedsFallbackConsent>().is_some();
                entry.state = AppState::Broken;
                entry.last_error = Some(format!("{e:#}"));
                log.extend(format!("[extract] FAILED: {e:#}\n").bytes());
                self.write_log(&entry.id, LogKind::Extract, &log);
            }
        }

        if let Some(preset) = &opts.preset {
            if let Some(p) = find_preset(&self.paths, preset)? {
                entry.profile.permissions = p.permissions.clone();
                entry.profile.preset = Some(p.name.clone());
                if let Some(b) = p.backend {
                    entry.profile.backend = b;
                }
            } else {
                bail!("unknown preset '{preset}'");
            }
        }
        entry.reviewed = opts.accept;
        if entry.extraction.is_some() && opts.launcher.unwrap_or(self.config.general.desktop_integration) {
            match desktop::install_launcher(&self.paths, &entry) {
                Ok(p) => entry.desktop_entry = Some(p),
                Err(e) => entry.last_error = Some(format!("launcher: {e:#}")),
            }
        }
        reg.save(&mut entry)?;
        let warnings = self.app_warnings(&entry, &self.host());
        Ok(AddOutcome { entry, created: true, relocated: false, needs_fallback_consent: needs_consent, warnings })
    }

    fn extraction_info(&self, root: &Path, appdir: &Path, out: &sam_intake::extract::ExtractOutcome, info: &sam_detect::AppImageInfo, fp: &Fingerprint) -> ExtractionInfo {
        let mut warnings = Vec::new();
        let suspicious = out.report.all_suspicious();
        if !suspicious.is_empty() {
            warnings.push(Warning::warn(
                "suspicious-payload",
                "Unusual files in the AppImage",
                format!("{} item(s) were sanitized during extraction: {}", suspicious.len(), suspicious.iter().take(5).cloned().collect::<Vec<_>>().join("; ")),
            ));
        }
        if out.method.contains("appimage-extract") {
            warnings.push(Warning::info("fallback-extraction", "Fallback extraction used", "The AppImage's own extractor was used inside a restricted sandbox."));
        }
        ExtractionInfo {
            root: root.to_path_buf(),
            appdir: appdir.to_path_buf(),
            entry: "AppRun".into(),
            method: out.method.clone(),
            compression: info.compression.clone().unwrap_or_else(|| if info.kind == AppImageType::Type1 { "iso9660".into() } else { "unknown".into() }),
            file_count: out.report.file_count,
            total_size: out.report.total_size,
            extracted_at: now(),
            source: fp.clone(),
            suspicious,
            warnings,
        }
    }

    /// Metadata, icon, dependency detection and recommendation for an
    /// extracted entry. Keeps user-modified profiles intact.
    fn finish_intake(&self, entry: &mut AppEntry, extract_log: &[u8]) -> Result<()> {
        let x = entry.extraction.clone().context("not extracted")?;
        if !x.appdir.join("AppRun").exists() {
            // Some AppImages ship without AppRun; fall back to the desktop Exec.
            let exec = entry.metadata.exec.split_whitespace().next().unwrap_or("").to_string();
            let cand = ["usr/bin", "", "bin"].iter().map(|d| Path::new(d).join(&exec)).find(|p| !exec.is_empty() && x.appdir.join(p).is_file());
            if let Some(c) = cand {
                entry.extraction.as_mut().unwrap().entry = c.display().to_string();
            }
        }
        let x = entry.extraction.clone().unwrap();
        entry.metadata.icon_path = metadata::cache_icon(&x.appdir, &entry.metadata.icon_name, &entry.id, &self.paths.icons_dir(), &x.root).ok().flatten();
        if (entry.name.is_empty() || entry.name == id::slug_from_filename(&entry.source_path))
            && !entry.metadata.name.is_empty() {
                entry.name = entry.metadata.name.clone();
            }
        let _ = fs::write(x.root.join("metadata.json"), serde_json::to_vec_pretty(&entry.metadata)?);
        let _ = fs::write(x.root.join("extraction.log"), extract_log);
        self.write_log(&entry.id, LogKind::Extract, extract_log);
        if let Some(df) = &entry.metadata.desktop_file {
            if let Some(src) = sam_intake::normalize::safe_resolve(&x.appdir, Path::new(df)) {
                let _ = fs::create_dir_all(x.root.join("desktop"));
                let _ = fs::copy(src, x.root.join("desktop").join(Path::new(df).file_name().unwrap_or_default()));
            }
        }
        self.detect(entry)?;
        Ok(())
    }

    fn detect(&self, entry: &mut AppEntry) -> Result<()> {
        let x = entry.extraction.clone().context("not extracted")?;
        let report = if self.config.dependencies.static_analysis {
            let opts = AnalyzeOptions {
                entry: x.entry.clone(),
                exec_hint: (!entry.metadata.exec.is_empty()).then(|| entry.metadata.exec.clone()),
                ..Default::default()
            };
            match analyze_appdir(&x.appdir, &opts) {
                Ok(r) => Some(r),
                Err(e) => {
                    entry.last_error = Some(format!("dependency detection failed: {e:#}"));
                    None
                }
            }
        } else {
            None
        };
        if let Some(r) = &report {
            let mut log = String::new();
            log += &format!("entry binary: {:?} (script: {})\nELF files: {}  bundled libraries: {}  arch: {}\n", r.entry_binary, r.entry_is_script, r.elf_count, r.bundled_libraries, r.arch);
            log += &format!("requirements: {:?}\ncompatibility: {:?}  verdict: {:?}\n", r.requirements, r.compatibility, r.verdict);
            for m in &r.missing {
                log += &format!("needs {} [{:?}] host={} (by {})\n", m.name, m.class, m.host_available, m.needed_by.join(", "));
            }
            for w in &r.warnings {
                log += &format!("warning: {}\n", w.message);
            }
            for n in &r.notes {
                log += &format!("note: {n}\n");
            }
            self.write_log(&entry.id, LogKind::Detect, log.as_bytes());
        }
        let file_name = entry.source_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let rec = recommend(&entry.metadata, &file_name, report.as_ref());
        let old_rec = entry.recommended.clone();
        entry.category = rec.category.as_str().into();
        entry.recommendation_notes = rec.notes.clone();
        entry.recommended = rec.permissions.clone();
        if entry.profile.user_modified {
            entry.pending_changes = new_requirements(&old_rec, &rec.permissions, &entry.profile.permissions);
        } else {
            let keep_backend = entry.profile.backend;
            entry.profile.permissions = rec.permissions.clone();
            entry.profile.backend = keep_backend;
            entry.pending_changes.clear();
        }
        entry.state = match report.as_ref().and_then(|r| r.verdict) {
            Some(IsolationVerdict::UnsafeToSandbox) => AppState::Unsafe,
            _ => AppState::Ready,
        };
        entry.detection = report;
        Ok(())
    }

    fn write_log(&self, id: &str, kind: LogKind, data: &[u8]) {
        let logs = Logs::new(&self.paths);
        if let Ok(p) = logs.new_log_path(id, kind) {
            let _ = fs::write(p, data);
            let _ = logs.prune(id, kind, 5);
        }
    }

    // ------------------------------------------------------------ maintain

    /// Re-extract after an update or failure (§2.11.7 / repair workflow).
    pub fn reextract(&self, query: &str, consent_fallback: bool) -> Result<AppEntry> {
        let mut entry = self.resolve(query)?;
        if !entry.source_path.exists() {
            bail!("the source AppImage {} no longer exists; use `sam-jail relocate` to point SAM at its new location", tildify(&entry.source_path));
        }
        let info = inspect(&entry.source_path)?;
        if !info.is_appimage() {
            bail!("{} is no longer a valid AppImage", tildify(&entry.source_path));
        }
        let fp = fingerprint::compute(&entry.source_path)?;
        let root = self.extracted_root().join(&entry.id);
        let mut log = Vec::new();
        let req = ExtractRequest { source: &entry.source_path, info: &info, root: &root, limits: self.limits(), allow_fallback: consent_fallback && self.config.extraction.allow_fallback };
        match extract(&req, &mut log) {
            Ok(out) => {
                entry.appimage_type = info.kind;
                entry.source = fp.clone();
                let appdir = root.join("AppDir");
                entry.extraction = Some(self.extraction_info(&root, &appdir, &out, &info, &fp));
                let icon_name = entry.metadata.icon_name.clone();
                let new_md = metadata::read_metadata(&appdir).unwrap_or_default();
                entry.metadata = AppImageMetadata { icon_path: None, ..new_md };
                if entry.metadata.icon_name.is_empty() {
                    entry.metadata.icon_name = icon_name;
                }
                entry.last_error = None;
                self.finish_intake(&mut entry, &log)?;
                if entry.desktop_entry.is_some() || self.config.general.desktop_integration {
                    entry.desktop_entry = desktop::install_launcher(&self.paths, &entry).ok();
                }
            }
            Err(e) => {
                entry.state = AppState::Broken;
                entry.last_error = Some(format!("{e:#}"));
                log.extend(format!("[extract] FAILED: {e:#}\n").bytes());
                self.write_log(&entry.id, LogKind::Extract, &log);
                self.registry().save(&mut entry)?;
                return Err(e);
            }
        }
        self.registry().save(&mut entry)?;
        Ok(entry)
    }

    pub fn redetect(&self, query: &str) -> Result<AppEntry> {
        let mut entry = self.resolve(query)?;
        self.detect(&mut entry)?;
        self.registry().save(&mut entry)?;
        Ok(entry)
    }

    /// Stale/missing detection for one or all apps.
    pub fn refresh(&self, query: Option<&str>, deep: bool) -> Result<Vec<RefreshItem>> {
        let reg = self.registry();
        let apps = match query {
            Some(q) => vec![self.resolve(q)?],
            None => reg.list()?,
        };
        let mut out = Vec::new();
        for mut a in apps {
            let known = a.extraction.as_ref().map(|x| x.source.clone()).unwrap_or_else(|| a.source.clone());
            let (status, reasons) = match fingerprint::check(&a.source_path, &known, deep)? {
                SourceStatus::Unchanged => {
                    if matches!(a.state, AppState::Missing | AppState::Stale) && a.extraction.is_some() {
                        a.state = AppState::Ready;
                    }
                    ("unchanged", vec![])
                }
                SourceStatus::Touched(fp) => {
                    a.source = fp.clone();
                    if let Some(x) = a.extraction.as_mut() {
                        x.source = fp;
                    }
                    if a.state == AppState::Missing {
                        a.state = AppState::Ready;
                    }
                    ("touched", vec!["file metadata changed, content identical".into()])
                }
                SourceStatus::Changed { new, reasons } => {
                    a.source = new;
                    a.state = AppState::Stale;
                    a.last_error = Some(format!("AppImage changed: {}", reasons.join(", ")));
                    ("stale", reasons)
                }
                SourceStatus::Missing => {
                    a.state = AppState::Missing;
                    ("missing", vec![format!("{} not found", tildify(&a.source_path))])
                }
            };
            reg.save(&mut a)?;
            out.push(RefreshItem { id: a.id.clone(), name: a.display_name().into(), status: status.into(), reasons });
        }
        Ok(out)
    }

    pub fn relocate(&self, query: &str, new_path: &Path) -> Result<AppEntry> {
        let mut entry = self.resolve(query)?;
        let p = fs::canonicalize(new_path)?;
        let fp = fingerprint::compute(&p)?;
        let same = entry.extraction.as_ref().is_some_and(|x| x.source.sha256 == fp.sha256);
        entry.source_path = p;
        entry.source = fp;
        entry.state = if same { AppState::Ready } else { AppState::Stale };
        if same {
            if let Some(x) = entry.extraction.as_mut() {
                x.source = entry.source.clone();
            }
        }
        self.registry().save(&mut entry)?;
        Ok(entry)
    }

    pub fn remove(&self, query: &str, keep_data: bool) -> Result<AppEntry> {
        let entry = self.resolve(query)?;
        desktop::remove_launcher(&self.paths, &entry.id)?;
        if let Some(x) = &entry.extraction {
            if x.root.starts_with(self.extracted_root()) && x.root.exists() {
                fs::remove_dir_all(&x.root)?;
            }
        }
        for ext in ["png", "svg", "xpm"] {
            let _ = fs::remove_file(self.paths.icons_dir().join(format!("sam-{}.{ext}", entry.id)));
        }
        let _ = fs::remove_dir_all(self.paths.runtime_dir(&entry.id));
        let _ = sam_backend_bubblejail::remove_instance(&entry.id);
        if !keep_data {
            let home = self.paths.app_home(&entry.id);
            if home.exists() {
                fs::remove_dir_all(&home)?;
            }
            Logs::new(&self.paths).remove_all(&entry.id)?;
        }
        self.registry().remove(&entry.id)?;
        Ok(entry)
    }

    /// Remove extraction leftovers that no registered app references.
    pub fn cleanup(&self) -> Result<Vec<PathBuf>> {
        let root = self.extracted_root();
        let ids: Vec<String> = self.registry().list()?.into_iter().map(|a| a.id).collect();
        let mut removed = Vec::new();
        if let Ok(rd) = fs::read_dir(&root) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if !ids.contains(&name) {
                    fs::remove_dir_all(e.path())?;
                    removed.push(e.path());
                }
            }
        }
        Ok(removed)
    }

    // ---------------------------------------------------------- profiles

    fn save_profile(&self, entry: &mut AppEntry) -> Result<()> {
        entry.profile.user_modified = entry.profile.permissions != entry.recommended;
        entry.reviewed = true;
        entry.pending_changes.clear();
        entry.clear_launch_failure();
        self.registry().save(entry)
    }

    pub fn set_permission(&self, query: &str, key: &str, value: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        e.profile.permissions.set_key(key, value)?;
        e.profile.preset = None;
        self.save_profile(&mut e)?;
        Ok(e)
    }

    pub fn set_permissions(&self, query: &str, perms: PermissionSet) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        e.profile.permissions = perms;
        e.profile.preset = None;
        self.save_profile(&mut e)?;
        Ok(e)
    }

    pub fn reset_profile(&self, query: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        e.profile.permissions = e.recommended.clone();
        e.profile.compatibility_mode = false;
        e.profile.preset = None;
        self.save_profile(&mut e)?;
        Ok(e)
    }

    pub fn set_compat(&self, query: &str, on: bool) -> Result<AppEntry> {
        if on && self.config.compatibility.behavior == sam_core::config::CompatBehavior::Never {
            bail!("compatibility mode is disabled in settings (compatibility.behavior = never)");
        }
        let mut e = self.resolve(query)?;
        e.profile.compatibility_mode = on;
        e.profile.permissions = if on { compatibility_profile(&e.profile.permissions) } else { e.recommended.clone() };
        self.save_profile(&mut e)?;
        Ok(e)
    }

    pub fn mark_reviewed(&self, query: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        e.reviewed = true;
        e.pending_changes.clear();
        self.registry().save(&mut e)?;
        Ok(e)
    }

    pub fn set_backend(&self, query: &str, choice: BackendChoice, confirm: bool) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        match choice {
            BackendChoice::Unsandboxed if !confirm => bail!(
                "running unsandboxed gives the app all of your permissions. Repeat with --confirm if you trust this application."
            ),
            BackendChoice::Firejail if !self.config.security.allow_firejail => {
                bail!("Firejail is disabled. Enable it first: sam-jail config set security.allow_firejail true")
            }
            BackendChoice::Firejail if !confirm => bail!("{} Repeat with --confirm to use it for this app.", sam_backend_firejail::FIREJAIL_RISK),
            _ => {}
        }
        e.profile.unsandboxed_confirmed = choice == BackendChoice::Unsandboxed;
        e.profile.firejail_confirmed = choice == BackendChoice::Firejail;
        e.profile.backend = choice;
        e.clear_launch_failure();
        self.registry().save(&mut e)?;
        Ok(e)
    }

    pub fn apply_preset(&self, query: &str, preset_name: &str, confirm: bool) -> Result<PresetApply> {
        let mut e = self.resolve(query)?;
        let preset = find_preset(&self.paths, preset_name)?.with_context(|| format!("unknown preset '{preset_name}'"))?;
        let check = check_preset(&e, &preset);
        if check.needs_confirmation() && !confirm {
            return Ok(PresetApply { preset: preset.name, check, applied: false });
        }
        e.profile.permissions = preset.permissions.clone();
        e.profile.preset = Some(preset.name.clone());
        if let Some(b) = preset.backend {
            e.profile.backend = b;
        }
        self.save_profile(&mut e)?;
        Ok(PresetApply { preset: preset.name, check, applied: true })
    }

    pub fn save_preset_from_app(&self, query: &str, name: &str, description: &str) -> Result<Preset> {
        let e = self.resolve(query)?;
        if sam_profile::builtin_presets().iter().any(|b| b.name.eq_ignore_ascii_case(name)) {
            bail!("'{name}' is a built-in preset name; choose another name");
        }
        let mut p = Preset {
            name: name.into(),
            description: description.into(),
            permissions: e.profile.permissions.clone(),
            compatibility_notes: format!("Created from {}", e.display_name()),
            ..Default::default()
        };
        PresetStore::new(&self.paths).save(&mut p)?;
        Ok(p)
    }

    // ----------------------------------------------------------- queries

    pub fn evaluate(&self, perms: &PermissionSet, app: Option<&AppEntry>, backend: Option<BackendKind>, host: &HostInfo) -> Evaluation {
        let ctx = WarningContext {
            app_needs_network: app.map(app_needs_network),
            backend,
            host: Some(host),
            warn_x11: self.config.security.warn_x11,
            warn_full_home: self.config.security.warn_full_home,
            warn_firejail: self.config.security.warn_firejail,
        };
        Evaluation { risk: assess(perms, backend), warnings: evaluate(perms, &ctx) }
    }

    /// All warnings relevant to an app: permissions, extraction, detection, state.
    pub fn app_warnings(&self, e: &AppEntry, host: &HostInfo) -> Vec<Warning> {
        let backend = crate::select::select(&e.profile, &self.config, host).ok().map(|s| s.kind).or(e.profile.backend.fixed());
        let mut w = self.evaluate(&e.profile.permissions, Some(e), backend, host).warnings;
        if let Some(x) = &e.extraction {
            w.extend(x.warnings.iter().cloned());
        }
        if let Some(d) = &e.detection {
            w.extend(d.warnings.iter().cloned());
            if let Some(v) = d.verdict {
                let sev = match v {
                    IsolationVerdict::UnsafeToSandbox => Severity::Danger,
                    IsolationVerdict::LikelyBroken => Severity::Warning,
                    IsolationVerdict::WeaklyIsolated => Severity::Info,
                };
                w.push(Warning::new("isolation-verdict", sev, "Isolation assessment", v.message()));
            }
        }
        match e.state {
            AppState::Stale => w.push(Warning::warn("stale", "AppImage changed", "The AppImage changed since it was extracted. Re-extract to update the sandbox.")),
            AppState::Missing => w.push(Warning::warn("missing", "AppImage missing", "The source AppImage no longer exists. You can still run the extracted copy, relocate it, or remove the app.")),
            AppState::Broken => w.push(Warning::danger("broken", "Not runnable", e.last_error.clone().unwrap_or_else(|| "Extraction or launch failed.".into()))),
            _ => {}
        }
        if !e.pending_changes.is_empty() {
            w.push(Warning::warn(
                "new-permissions",
                "Update needs new permissions",
                format!("The updated AppImage likely needs: {}. Your customized profile was kept; review and grant if needed.", e.pending_changes.join(", ")),
            ));
        }
        if e.profile.compatibility_mode {
            w.push(Warning::warn("compat-mode", "Compatibility mode", sam_profile::COMPAT_WARNING));
        }
        w
    }

    pub fn scan(&self, dirs: Option<Vec<PathBuf>>) -> Result<Vec<ScanItem>> {
        let dirs = dirs.unwrap_or_else(|| self.config.scan_dirs());
        let apps = self.registry().list()?;
        let mut out: Vec<ScanItem> = Vec::new();
        fn walk(dir: &Path, depth: usize, found: &mut Vec<PathBuf>) {
            let Ok(rd) = fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                let Ok(m) = fs::metadata(&p) else { continue };
                if m.is_dir() {
                    if depth > 0 && !e.file_name().to_string_lossy().starts_with('.') {
                        walk(&p, depth - 1, found);
                    }
                } else if m.is_file() && m.len() > 4096 && looks_like_appimage(&p) {
                    found.push(p);
                }
            }
        }
        let mut found = Vec::new();
        for d in &dirs {
            walk(d, 2, &mut found);
        }
        found.sort();
        found.dedup();
        for p in found {
            let canon = fs::canonicalize(&p).unwrap_or(p.clone());
            let size = fs::metadata(&canon).map(|m| m.len()).unwrap_or(0);
            let registered = apps.iter().find(|a| a.source_path == canon).map(|a| a.id.clone());
            let mut moved_from = None;
            if registered.is_none() {
                let cands: Vec<&AppEntry> = apps.iter().filter(|a| !a.source_path.exists() && a.source.size == size).collect();
                if !cands.is_empty() {
                    if let Ok(sha) = fingerprint::sha256_file(&canon) {
                        moved_from = cands.iter().find(|a| a.source.sha256 == sha).map(|a| a.id.clone());
                    }
                }
            }
            out.push(ScanItem { path: canon, registered, moved_from, size });
        }
        Ok(out)
    }
}

/// Browsers and chat apps need the network; games do when they link networking libraries.
pub fn app_needs_network(a: &AppEntry) -> bool {
    let by_category = sam_profile::Category::parse(&a.category).is_some_and(|c| c.needs_network());
    let game_online = a.category == "game" && a.detection.as_ref().is_some_and(|d| d.requirements.network);
    by_category || game_online
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
