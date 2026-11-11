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
use sam_intake::{desktop, id, menu, metadata, peek};
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
    /// Hide other (unsandboxed) menu entries that start this AppImage.
    pub hide_duplicates: bool,
    /// Use these permissions instead of the recommendation (the settings
    /// the user saw and adjusted before creating the sandbox).
    pub permissions: Option<PermissionSet>,
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
            signature: Some(sam_detect::signature::check(&source)),
            ..Default::default()
        };
        // Extract into a temporary root; the final id depends on metadata.
        let root_base = self.extracted_root();
        let incoming = root_base.join(format!(".incoming-{}", &fp.sha256[..12]));
        if incoming.exists() {
            fs::remove_dir_all(&incoming)?;
        }
        let mut log = Vec::new();
        let req = ExtractRequest { source: &source, info: &info, root: &incoming, limits: self.limits(), allow_fallback: opts.consent_fallback && self.config.extraction.allow_fallback, isolation: self.extract_isolation() };
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
            } else {
                bail!("unknown preset '{preset}'");
            }
        }
        if let Some(p) = &opts.permissions {
            // `p` is the preview the user adjusted. The preview only knew the
            // metadata; the full recommendation also knows what the unpacked
            // app links (GPU, audio, X11, …). Keep every change the user made
            // and take the full recommendation for everything else.
            let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            let md = peek::peek(&canonical).map(|p| p.metadata).unwrap_or_default();
            let file_name = canonical.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let seen = sam_profile::recommend(&md, &file_name, None).permissions;
            entry.profile.permissions = merge_adjustments(&seen, p, &entry.recommended);
            entry.profile.preset = None;
            entry.profile.user_modified = entry.profile.permissions != entry.recommended;
        }
        entry.reviewed = opts.accept;
        if entry.extraction.is_some() && opts.launcher.unwrap_or(self.config.general.desktop_integration) {
            match desktop::install_launcher(&self.paths, &entry) {
                Ok(p) => entry.desktop_entry = Some(p),
                Err(e) => entry.last_error = Some(format!("launcher: {e:#}")),
            }
        }
        if opts.hide_duplicates && entry.desktop_entry.is_some() {
            self.hide_menu_entries(&mut entry);
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
            entry.profile.permissions = rec.permissions.clone();
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

    /// Re-extract after an update or failure.
    pub fn reextract(&self, query: &str, consent_fallback: bool) -> Result<AppEntry> {
        let mut entry = self.resolve(query)?;
        self.ensure_not_running(&entry, "unpack it again")?;
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
        let req = ExtractRequest { source: &entry.source_path, info: &info, root: &root, limits: self.limits(), allow_fallback: consent_fallback && self.config.extraction.allow_fallback, isolation: self.extract_isolation() };
        match extract(&req, &mut log) {
            Ok(out) => {
                entry.appimage_type = info.kind;
                if entry.source.sha256 != fp.sha256 {
                    let new_sig = sam_detect::signature::check(&entry.source_path);
                    entry.signing_key_changed = signing_key_change(entry.signature.as_ref(), &new_sig);
                    entry.signature = Some(new_sig);
                }
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

    /// Remove the sandbox. Returns the removed entry and problems that did
    /// not stop the removal (e.g. a hidden menu entry that could not be put back).
    /// Launches of this app that are running now. Each launch keeps
    /// `<runtime>/launch-<pid>-<time>/running.lock` locked while it runs;
    /// folders left by a killed runner are removed here.
    pub fn running(&self, id: &str) -> Vec<u32> {
        let mut pids = Vec::new();
        let Ok(rd) = fs::read_dir(self.paths.runtime_dir(id)) else { return pids };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(pid) = name.strip_prefix("launch-").and_then(|r| r.split('-').next()).and_then(|p| p.parse::<u32>().ok()) else { continue };
            let lock = e.path().join("running.lock");
            if crate::launch::lock_held(&lock) {
                pids.push(pid);
            } else if lock.exists() && !Path::new(&format!("/proc/{pid}")).exists() {
                // The runner was killed before it could clean up.
                let _ = fs::remove_dir_all(e.path());
            }
        }
        pids
    }

    /// Closes every running launch of this app. The app's own processes get
    /// SIGTERM first, so it can save and quit like on logout; launches still
    /// running after 10 seconds are ended by stopping their runner (Bubblewrap
    /// then takes the whole sandbox down). Returns how many launches ran.
    pub fn stop(&self, query: &str) -> Result<usize> {
        let entry = self.resolve(query)?;
        // Only processes that really hold their launch's lock open: a process
        // id reused by an unrelated program is never touched.
        let base = self.paths.runtime_dir(&entry.id);
        let mut runners = Vec::new();
        for p in self.running(&entry.id) {
            for e in fs::read_dir(&base).into_iter().flatten().flatten() {
                if e.file_name().to_string_lossy().starts_with(&format!("launch-{p}-")) && holds_open(p, &e.path().join("running.lock")) {
                    // So the launch is recorded as closed, not as a failed start.
                    let _ = fs::write(e.path().join(crate::launch::STOP_MARKER), b"");
                    runners.push(p);
                    break;
                }
            }
        }
        if runners.is_empty() {
            return Ok(0);
        }
        let signal = |pid: u32, sig: i32| unsafe {
            libc::kill(pid as libc::pid_t, sig);
        };
        for &r in &runners {
            for pid in descendants(r) {
                let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                // Not Bubblewrap itself (that would kill the app at once) and
                // not the D-Bus proxy the app may still need while quitting.
                if !matches!(comm.trim(), "bwrap" | "xdg-dbus-proxy") {
                    signal(pid, libc::SIGTERM);
                }
            }
        }
        let wait = |secs: u64| {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            while std::time::Instant::now() < end {
                if self.running(&entry.id).is_empty() {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            false
        };
        if !wait(10) {
            for &r in &runners {
                signal(r, libc::SIGTERM);
            }
            if !wait(3) {
                for &r in &runners {
                    signal(r, libc::SIGKILL);
                }
                if !wait(3) {
                    bail!("{} could not be closed", sam_core::util::display_safe(&entry.metadata.name, 80));
                }
            }
        }
        Ok(runners.len())
    }

    fn ensure_not_running(&self, entry: &AppEntry, what: &str) -> Result<()> {
        if !self.running(&entry.id).is_empty() {
            bail!("{} is running (maybe only in the system tray). Close it first, then {what}.", sam_core::util::display_safe(&entry.metadata.name, 80));
        }
        Ok(())
    }

    pub fn remove(&self, query: &str, keep_data: bool) -> Result<(AppEntry, Vec<String>)> {
        let entry = self.resolve(query)?;
        self.ensure_not_running(&entry, "remove its sandbox")?;
        let mut problems = Vec::new();
        desktop::remove_launcher(&self.paths, &entry.id)?;
        for h in &entry.hidden_entries {
            if let Err(e) = menu::restore(h, &entry.id) {
                problems.push(format!("could not restore the menu entry {}: {e:#}", h.original.display()));
            }
        }
        if let Some(x) = &entry.extraction {
            if x.root.starts_with(self.extracted_root()) && x.root.exists() {
                fs::remove_dir_all(&x.root)?;
            }
        }
        for ext in ["png", "svg", "xpm"] {
            let _ = fs::remove_file(self.paths.icons_dir().join(format!("sam-{}.{ext}", entry.id)));
        }
        let _ = fs::remove_dir_all(self.paths.runtime_dir(&entry.id));
        if !keep_data {
            let home = self.paths.app_home(&entry.id);
            if home.exists() {
                fs::remove_dir_all(&home)?;
            }
            Logs::new(&self.paths).remove_all(&entry.id)?;
            // Writable app folder layer (`advanced.writable_appdir`).
            let overlay = self.paths.data_dir.join("overlays").join(&entry.id);
            if overlay.exists() {
                remove_tree(&overlay)?;
            }
        }
        self.registry().remove(&entry.id)?;
        Ok((entry, problems))
    }

    /// Removes SAM from this computer: closes running apps, removes every
    /// sandbox (menu entries SAM hid come back), SAM's menu entries, its own
    /// taskbar entry and icon, its runtime files and (unless `keep_data`)
    /// its settings and the apps' private data. AppImage files stay.
    /// With `dry_run`, only lists what would be removed.
    pub fn uninstall(&self, keep_data: bool, dry_run: bool) -> Result<Uninstall> {
        let mut u = Uninstall::default();
        let apps = self.registry().list()?;
        for a in &apps {
            u.apps.push(a.display_name().to_string());
            if !dry_run {
                self.stop(&a.id)?;
                let (_, problems) = self.remove(&a.id, keep_data)?;
                u.problems.extend(problems);
            }
        }
        // SAM's menu entries left without a record, and SAM's own entry.
        let mut files = desktop::sam_launchers(&self.paths.applications_dir);
        let own = self.paths.applications_dir.join("io.github.gitzekatze.SAM.desktop");
        if fs::read_to_string(&own).is_ok_and(|t| t.contains("X-SAM-Self=true")) {
            files.push(own);
            if let Some(data_home) = self.paths.applications_dir.parent() {
                let icon = data_home.join("icons/hicolor/scalable/apps/io.github.gitzekatze.SAM.svg");
                if icon.exists() {
                    files.push(icon);
                }
            }
        }
        let runtime = self.paths.runtime_dir("x").parent().map(Path::to_path_buf);
        let mut dirs: Vec<PathBuf> = runtime.into_iter().filter(|d| d.exists()).collect();
        if !keep_data {
            for d in [self.paths.config_dir.clone(), self.paths.data_dir.clone(), self.extracted_root()] {
                if d.exists() && !dirs.iter().any(|o| d.starts_with(o)) {
                    safe_to_delete(&d)?;
                    dirs.push(d);
                }
            }
        }
        u.files = files.clone();
        u.dirs = dirs.clone();
        if !dry_run {
            for f in files {
                let _ = fs::remove_file(f);
            }
            for d in dirs {
                remove_tree(&d).with_context(|| format!("removing {}", d.display()))?;
            }
            desktop::refresh(&self.paths.applications_dir);
        }
        Ok(u)
    }

    /// Private data of apps that no longer have a sandbox: their home,
    /// writable app folder layer and logs (kept by `remove --keep-data`).
    /// Space one app takes: its unpacked copy, private home, writable app
    /// folder and logs.
    pub fn disk_usage(&self, entry: &AppEntry) -> DiskUsage {
        let unpacked = tree_size(&self.extracted_root().join(&entry.id));
        let home = tree_size(&self.paths.app_home(&entry.id));
        let overlay = tree_size(&self.paths.data_dir.join("overlays").join(&entry.id));
        let logs = tree_size(&self.paths.app_logs_dir(&entry.id));
        DiskUsage { id: entry.id.clone(), name: entry.display_name().to_string(), unpacked, home, overlay, logs, total: unpacked + home + overlay + logs, can_free: unpacked > 0 && entry.source_path.exists() }
    }

    /// Deletes an app's unpacked copy to free space. Its settings and
    /// private home stay; the next start unpacks the AppImage again (see
    /// [`Sam::ensure_unpacked`]). Returns the bytes freed.
    pub fn free_space(&self, query: &str) -> Result<u64> {
        let entry = self.resolve(query)?;
        self.ensure_not_running(&entry, "free its space")?;
        if !entry.source_path.exists() {
            bail!("the AppImage {} is missing, so the unpacked copy is the only one left; it is kept", tildify(&entry.source_path));
        }
        let root = self.extracted_root().join(&entry.id);
        let size = tree_size(&root);
        if root.exists() {
            remove_tree(&root).with_context(|| format!("removing {}", root.display()))?;
        }
        Ok(size)
    }

    /// Unpacks the AppImage again when its unpacked copy is gone (after
    /// *Free space*, or deleted by hand) and the file is unchanged. A
    /// changed file is left to `reextract`, which reviews new permissions.
    pub fn ensure_unpacked(&self, entry: &mut AppEntry) -> Result<bool> {
        let Some(x) = &entry.extraction else { return Ok(false) };
        if x.appdir.join(&x.entry).exists() || !entry.source_path.exists() {
            return Ok(false);
        }
        if !matches!(fingerprint::check(&entry.source_path, &x.source, false), Ok(SourceStatus::Unchanged)) {
            return Ok(false);
        }
        *entry = self.reextract(&entry.id, false)?;
        Ok(true)
    }

    pub fn leftover_data(&self) -> Result<Vec<LeftoverData>> {
        let ids: std::collections::HashSet<String> = self.registry().list()?.into_iter().map(|a| a.id).collect();
        let mut by_id: std::collections::BTreeMap<String, LeftoverData> = Default::default();
        for root in [self.paths.homes_dir(), self.paths.data_dir.join("overlays"), self.paths.logs_dir()] {
            let Ok(rd) = fs::read_dir(&root) else { continue };
            for e in rd.flatten() {
                let id = e.file_name().to_string_lossy().into_owned();
                if ids.contains(&id) || !e.path().is_dir() {
                    continue;
                }
                let d = by_id.entry(id.clone()).or_insert_with(|| LeftoverData { id, paths: vec![], size: 0 });
                d.size += tree_size(&e.path());
                d.paths.push(e.path());
            }
        }
        Ok(by_id.into_values().collect())
    }

    /// Deletes the data `leftover_data` lists.
    pub fn remove_leftover_data(&self) -> Result<Vec<LeftoverData>> {
        let list = self.leftover_data()?;
        for d in &list {
            for p in &d.paths {
                remove_tree(p)?;
            }
        }
        Ok(list)
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
        if on == e.profile.compatibility_mode {
            return Ok(e);
        }
        if on {
            e.profile.before_compat = Some(e.profile.permissions.clone());
            e.profile.permissions = compatibility_profile(&e.profile.permissions);
        } else {
            // Back to the settings from before, or the recommendation.
            e.profile.permissions = e.profile.before_compat.take().unwrap_or_else(|| e.recommended.clone());
        }
        e.profile.compatibility_mode = on;
        self.save_profile(&mut e)?;
        Ok(e)
    }

    /// Runs the sandbox check and stores its result with the app.
    pub fn verify(&self, query: &str) -> Result<crate::verify::Outcome> {
        let mut e = self.resolve(query)?;
        self.ensure_unpacked(&mut e)?;
        let out = crate::verify::verify(&e, &self.config, &self.paths, &self.host())?;
        let reg = self.registry();
        if let Some(mut fresh) = reg.get(&e.id)? {
            fresh.last_check = Some(out.record.clone());
            reg.save(&mut fresh)?;
        }
        Ok(out)
    }

    /// Sandbox check for an AppImage that has no sandbox yet, with the
    /// settings it would get (`perms`, or SAM's recommendation). Runs the
    /// same sandbox as a real start, but around an empty stand-in app folder
    /// and a throwaway private home; the AppImage is neither unpacked nor
    /// run, and nothing is stored.
    pub fn verify_preview(&self, path: &Path, perms: Option<PermissionSet>) -> Result<crate::verify::Outcome> {
        let path = fs::canonicalize(path).with_context(|| format!("{} does not exist", path.display()))?;
        if !path.is_file() {
            bail!("{} is not a file", path.display());
        }
        let md = peek::peek(&path).map(|p| p.metadata).unwrap_or_default();
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let rec = recommend(&md, &file_name, None);
        let permissions = perms.unwrap_or_else(|| rec.permissions.clone());

        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = remove_tree(&self.0);
                if let Some(parent) = self.0.parent() {
                    let _ = fs::remove_dir(parent); // only when empty
                }
            }
        }
        let root = self.paths.data_dir.join("check").join(format!("{}-{}", std::process::id(), now()));
        let scratch = Scratch(root.clone());
        let appdir = root.join("AppDir");
        fs::create_dir_all(&appdir)?;
        fs::write(appdir.join("AppRun"), "#!/bin/sh\n")?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(appdir.join("AppRun"), fs::Permissions::from_mode(0o755))?;
        }
        let paths = Paths { data_dir: root.join("data"), ..self.paths.clone() };
        let entry = AppEntry {
            id: "sam-check-preview".into(),
            name: if md.name.is_empty() { file_name.clone() } else { md.name.clone() },
            source_path: path,
            metadata: md,
            extraction: Some(ExtractionInfo { root: root.clone(), appdir, entry: "AppRun".into(), ..Default::default() }),
            recommended: rec.permissions,
            profile: SandboxProfile { permissions, ..Default::default() },
            ..Default::default()
        };
        let out = crate::verify::verify(&entry, &self.config, &paths, &self.host());
        drop(scratch);
        out
    }

    /// Replaces the extra arguments always passed to the app.
    pub fn set_args(&self, query: &str, args: Vec<String>) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        let args: Vec<String> = args.into_iter().map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect();
        for a in &args {
            if a.contains('\0') || a.len() > 4096 {
                bail!("invalid argument {a:?}");
            }
        }
        e.profile.args = args;
        self.registry().save(&mut e)?;
        Ok(e)
    }

    // ------------------------------------------------------------ repair

    /// Apply a first-run hint, log finding or repair step. Repair steps
    /// (`as_repair`) are remembered so "Undo repairs" can revert them all.
    pub fn apply_suggestion(&self, query: &str, sug: &Suggestion, as_repair: bool) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        if as_repair && e.repair_backup.is_none() {
            e.repair_backup = Some(e.profile.clone());
        }
        match &sug.action {
            FixAction::Set { key, value } => e.profile.permissions.set_key(key, value)?,
            FixAction::Add { key, value } => {
                let mut list: Vec<String> = serde_json::from_value(e.profile.permissions.get_key(key)?).with_context(|| format!("{key} is not a list"))?;
                if !list.contains(value) {
                    list.push(value.clone());
                }
                e.profile.permissions.set_key(key, &serde_json::to_string(&list)?)?;
            }
            FixAction::Compat => {
                if !e.profile.compatibility_mode {
                    e.profile.before_compat = Some(e.profile.permissions.clone());
                }
                e.profile.compatibility_mode = true;
                e.profile.permissions = compatibility_profile(&e.profile.permissions);
            }
            FixAction::AddArg { value } => {
                if !e.profile.args.contains(value) {
                    e.profile.args.push(value.clone());
                }
            }
            FixAction::None => bail!("“{}” is an explanation only; there is nothing to apply", sug.title),
        }
        e.profile.preset = None;
        if as_repair && !e.repairs_applied.contains(&sug.id) {
            e.repairs_applied.push(sug.id.clone());
        }
        self.save_profile(&mut e)?;
        Ok(e)
    }

    /// Find a suggestion by id among the app's hints, findings and repair steps.
    pub fn find_suggestion(&self, e: &AppEntry, id: &str) -> Option<Suggestion> {
        crate::repair::first_run_hints(e)
            .into_iter()
            .chain(crate::repair::ladder(e, &self.config))
            .chain(e.last_launch.iter().flat_map(|l| l.findings.clone()))
            .find(|s| s.id == id)
    }

    /// Restore the profile from before the first repair step.
    pub fn undo_repairs(&self, query: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        let Some(backup) = e.repair_backup.take() else { bail!("no repairs to undo for {}", e.display_name()) };
        e.profile = backup;
        e.repairs_applied.clear();
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

    pub fn apply_preset(&self, query: &str, preset_name: &str, confirm: bool) -> Result<PresetApply> {
        let mut e = self.resolve(query)?;
        let preset = find_preset(&self.paths, preset_name)?.with_context(|| format!("unknown preset '{preset_name}'"))?;
        let check = check_preset(&e, &preset);
        if check.needs_confirmation() && !confirm {
            return Ok(PresetApply { preset: preset.name, check, applied: false });
        }
        e.profile.permissions = preset.permissions.clone();
        e.profile.preset = Some(preset.name.clone());
        self.save_profile(&mut e)?;
        Ok(PresetApply { preset: preset.name, check, applied: true })
    }

    /// The preset check for an AppImage without a sandbox: against SAM's
    /// recommendation for it and the settings shown now (`current`, else the
    /// recommendation). Nothing is changed.
    pub fn check_preset_preview(&self, path: &Path, preset_name: &str, current: Option<PermissionSet>) -> Result<(Preset, sam_profile::PresetCheck)> {
        let path = fs::canonicalize(path).with_context(|| format!("{} does not exist", path.display()))?;
        let preset = find_preset(&self.paths, preset_name)?.with_context(|| format!("unknown preset '{preset_name}'"))?;
        let md = peek::peek(&path).map(|p| p.metadata).unwrap_or_default();
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let rec = recommend(&md, &file_name, None);
        let entry = AppEntry {
            source_path: path,
            metadata: md,
            profile: SandboxProfile { permissions: current.unwrap_or_else(|| rec.permissions.clone()), ..Default::default() },
            recommended: rec.permissions,
            ..Default::default()
        };
        let check = check_preset(&entry, &preset);
        Ok((preset, check))
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

    pub fn evaluate(&self, perms: &PermissionSet, app: Option<&AppEntry>, host: &HostInfo) -> Evaluation {
        let ctx = WarningContext {
            app_needs_network: app.map(app_needs_network),
            host: Some(host),
            warn_x11: self.config.security.warn_x11,
            warn_full_home: self.config.security.warn_full_home,
        };
        Evaluation { risk: assess(perms), warnings: evaluate(perms, &ctx) }
    }

    /// All warnings relevant to an app: permissions, extraction, detection, state.
    pub fn app_warnings(&self, e: &AppEntry, host: &HostInfo) -> Vec<Warning> {
        let mut w = self.evaluate(&e.profile.permissions, Some(e), host).warnings;
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
        if let Some(before) = &e.signing_key_changed {
            w.push(Warning::danger(
                "signing-key-changed",
                "Signed differently than before",
                format!("The previous version was {before}. The current file is {}. An update from the same developer normally keeps its key: make sure the file comes from where you expect.", e.signature.as_ref().map(sig_words).unwrap_or_else(|| "not checked".into())),
            ));
        }
        if e.signature.as_ref().is_some_and(|s| s.state == sam_core::model::SignatureState::Invalid) {
            w.push(Warning::danger("signature-invalid", "Signature does not match", e.signature.as_ref().map(|s| s.detail.clone()).unwrap_or_default()));
        }
        w
    }

    /// Extraction runs inside Bubblewrap when it is usable and this process
    /// is SAM's CLI (which provides the built-in reader as a subcommand).
    fn extract_isolation(&self) -> Option<sam_intake::extract::Isolation> {
        let exe = std::env::current_exe().ok()?;
        let is_cli = exe.file_name().is_some_and(|n| n == "sam-jail");
        let host = self.host();
        let bwrap = host.tools.bwrap.as_ref()?;
        (is_cli && host.userns.usable()).then(|| sam_intake::extract::Isolation { bwrap: bwrap.path.clone(), self_exe: exe })
    }

    // ---------------------------------------------------------- overview

    /// Folders the overview searches: configured ones, plus Downloads when
    /// `general.scan_downloads` is on.
    pub fn default_scan_dirs(&self) -> Vec<PathBuf> {
        let downloads = sam_core::host::xdg_user_dirs(&sam_core::util::home_dir()).get("downloads").cloned();
        self.config.scan_dirs(downloads.as_deref())
    }

    /// Every AppImage in the scanned folders or started by a menu entry,
    /// with name and icon read without unpacking. Nothing is executed.
    pub fn discover(&self) -> Result<Vec<DiscoveredApp>> {
        let scanned = self.scan(None)?;
        let foreign = menu::foreign_entries(&self.paths.applications_dir);
        let apps = self.registry().list()?;
        // (path, found via menu entry, added by hand)
        let mut paths: Vec<(PathBuf, bool, bool)> = scanned.iter().map(|s| (s.path.clone(), false, false)).collect();
        let add = |p: PathBuf, menu: bool, manual: bool, paths: &mut Vec<(PathBuf, bool, bool)>| {
            if p.is_file() && !paths.iter().any(|(q, _, _)| q == &p) {
                paths.push((p, menu, manual));
            }
        };
        for f in &self.config.general.scan_files {
            let p = fs::canonicalize(sam_core::util::expand_home(f)).unwrap_or_else(|_| sam_core::util::expand_home(f));
            if looks_like_appimage(&p) {
                add(p, false, true, &mut paths);
            }
        }
        for f in &foreign {
            add(f.appimage.clone(), true, false, &mut paths);
        }
        // Sandboxed apps whose files live outside the scanned locations.
        for a in &apps {
            add(a.source_path.clone(), false, false, &mut paths);
        }
        let previews_dir = self.paths.data_dir.join("previews");
        let mut out = Vec::new();
        for (path, from_menu, manual) in paths {
            let meta = fs::metadata(&path).ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let p = self.cached_preview(&path, meta.as_ref(), &previews_dir);
            let md = AppImageMetadata { name: p.name.clone(), comment: p.comment.clone(), categories: p.categories.clone(), ..Default::default() };
            let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let category = sam_profile::infer_category(&md, &file_name, None);
            let scan = scanned.iter().find(|s| s.path == path);
            let menu_entries = foreign
                .iter()
                .filter(|f| f.appimage == path && f.hidden_by.is_none() && !f.hidden_elsewhere)
                .map(|f| MenuEntryInfo { file: f.file.clone(), name: f.name.clone(), system: !f.file.starts_with(&self.paths.applications_dir) })
                .collect();
            out.push(DiscoveredApp {
                name: if p.name.is_empty() { id::slug_from_filename(&path) } else { p.name },
                comment: p.comment,
                version: p.version,
                categories: p.categories,
                category: category.as_str().to_string(),
                category_label: category.label().to_string(),
                icon: p.icon,
                sandboxed: apps.iter().find(|a| a.source_path == path).map(|a| a.id.clone()),
                moved_from: scan.and_then(|s| s.moved_from.clone()),
                menu_entries,
                from_menu,
                manual,
                size,
                path,
            });
        }
        out.sort_by_key(|d| d.name.to_lowercase());
        Ok(out)
    }

    fn cached_preview(&self, path: &Path, meta: Option<&fs::Metadata>, dir: &Path) -> Preview {
        let mtime = meta.and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        let key = format!("{}|{}|{mtime}", path.display(), meta.map(|m| m.len()).unwrap_or(0));
        let stem = fingerprint::short_hash(path.to_string_lossy().as_bytes());
        let cache = dir.join(format!("{stem}.json"));
        if let Some(p) = fs::read(&cache).ok().and_then(|b| serde_json::from_slice::<Preview>(&b).ok()) {
            if p.key == key {
                return p;
            }
        }
        let mut p = Preview { key, ..Default::default() };
        if let Ok(pk) = peek::peek(path) {
            p.name = pk.metadata.name;
            p.comment = pk.metadata.comment;
            p.version = pk.metadata.version;
            p.categories = pk.metadata.categories;
            if let Some((data, fmt)) = pk.icon {
                let icon = dir.join(format!("{stem}.{}", fmt.ext()));
                if fs::create_dir_all(dir).is_ok() && sam_core::util::atomic_write(&icon, &data).is_ok() {
                    p.icon = Some(icon);
                }
            }
        }
        if fs::create_dir_all(dir).is_ok() {
            let _ = sam_core::util::atomic_write(&cache, &serde_json::to_vec(&p).unwrap_or_default());
        }
        p
    }

    /// The settings SAM would use for an AppImage that has no sandbox yet,
    /// from its metadata only (nothing is unpacked or run). `perms` evaluates
    /// the user's adjusted settings instead.
    pub fn preview(&self, path: &Path, perms: Option<PermissionSet>) -> Result<serde_json::Value> {
        let path = fs::canonicalize(path).with_context(|| format!("{} does not exist", path.display()))?;
        let md = peek::peek(&path).map(|p| p.metadata).unwrap_or_default();
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let rec = sam_profile::recommend(&md, &file_name, None);
        let permissions = perms.unwrap_or_else(|| rec.permissions.clone());
        let host = self.host();
        let selection = crate::bwrap::check(&host).ok();
        let ev = self.evaluate(&permissions, None, &host);
        Ok(serde_json::json!({
            "category": rec.category.as_str(),
            "category_label": rec.category.label(),
            "recommended": rec.permissions,
            "permissions": permissions,
            "notes": rec.notes,
            "selection": selection,
            "risk": ev.risk,
            "warnings": ev.warnings,
        }))
    }

    /// Unsandboxed menu entries that start this app's AppImage.
    pub fn menu_duplicates(&self, entry: &AppEntry) -> Vec<menu::ForeignEntry> {
        menu::foreign_entries(&self.paths.applications_dir)
            .into_iter()
            .filter(|f| f.appimage == entry.source_path && f.hidden_by.is_none() && !f.hidden_elsewhere)
            .collect()
    }

    fn hide_menu_entries(&self, entry: &mut AppEntry) {
        for f in self.menu_duplicates(entry) {
            match menu::hide(&f.file, &self.paths.applications_dir, &entry.id) {
                Ok(h) => entry.hidden_entries.push(h),
                Err(e) => eprintln!("sam-jail: could not hide menu entry {}: {e:#}", f.file.display()),
            }
        }
    }

    /// Hide this app's unsandboxed duplicate menu entries now.
    pub fn hide_duplicates(&self, query: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        self.hide_menu_entries(&mut e);
        self.registry().save(&mut e)?;
        Ok(e)
    }

    /// Put back the menu entries SAM hid for this app.
    pub fn restore_menu_entries(&self, query: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        for h in std::mem::take(&mut e.hidden_entries) {
            menu::restore(&h, &e.id)?;
        }
        self.registry().save(&mut e)?;
        Ok(e)
    }

    pub fn scan(&self, dirs: Option<Vec<PathBuf>>) -> Result<Vec<ScanItem>> {
        let dirs = dirs.unwrap_or_else(|| self.default_scan_dirs());
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

/// Disk space of one app (bytes).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiskUsage {
    pub id: String,
    pub name: String,
    pub unpacked: u64,
    pub home: u64,
    pub overlay: u64,
    pub logs: u64,
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
fn sig_words(s: &sam_core::model::SignatureInfo) -> String {
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
fn signing_key_change(old: Option<&sam_core::model::SignatureInfo>, new: &sam_core::model::SignatureInfo) -> Option<String> {
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
