//! Creating a sandbox: unpack, detect, recommend, write the record.

use super::*;

impl Sam {
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
        let req = ExtractRequest {
            source: &source,
            info: &info,
            root: &incoming,
            limits: self.limits(),
            allow_fallback: opts.consent_fallback && self.config.extraction.allow_fallback,
            isolation: self.extract_isolation(),
        };
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

    pub(super) fn extraction_info(
        &self,
        root: &Path,
        appdir: &Path,
        out: &sam_intake::extract::ExtractOutcome,
        info: &sam_detect::AppImageInfo,
        fp: &Fingerprint,
    ) -> ExtractionInfo {
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
            warnings.push(Warning::info(
                "fallback-extraction",
                "Fallback extraction used",
                "The AppImage's own extractor was used inside a restricted sandbox.",
            ));
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
    pub(super) fn finish_intake(&self, entry: &mut AppEntry, extract_log: &[u8]) -> Result<()> {
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
        if (entry.name.is_empty() || entry.name == id::slug_from_filename(&entry.source_path)) && !entry.metadata.name.is_empty() {
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

    pub(super) fn detect(&self, entry: &mut AppEntry) -> Result<()> {
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
            log += &format!(
                "entry binary: {:?} (script: {})\nELF files: {}  bundled libraries: {}  arch: {}\n",
                r.entry_binary, r.entry_is_script, r.elf_count, r.bundled_libraries, r.arch
            );
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

    pub(super) fn write_log(&self, id: &str, kind: LogKind, data: &[u8]) {
        let logs = Logs::new(&self.paths);
        if let Ok(p) = logs.new_log_path(id, kind) {
            let _ = fs::write(p, data);
            let _ = logs.prune(id, kind, 5);
        }
    }
}
