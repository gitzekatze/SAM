//! Creating a sandbox: unpack, detect, recommend, write the record.

use super::*;
use sam_core::error::InFunctionExt;

/// Numbers the copies that adds running at the same time work from.
static ADDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A folder of SAM's own that is removed when this goes, on every way out.
struct RemovedAtEnd(PathBuf);
impl Drop for RemovedAtEnd {
    fn drop(&mut self) {
        let _ = remove_tree(&self.0);
    }
}

impl Sam {
    // ------------------------------------------------------------------ add

    pub fn add(&self, path: &Path, opts: &AddOptions) -> Result<AddOutcome> {
        let source = fs::canonicalize(path).with_context(|| {
            sam_core::i18n::trf("{file} does not exist", &[("file", &path.display())])
        })?;
        if !source.is_file() {
            bail!(
                "{}",
                sam_core::i18n::trf("{file} is not a file", &[("file", &source.display())])
            );
        }
        let pr = &opts.progress;
        let file_size = fs::metadata(&source).map(|m| m.len()).unwrap_or(0);
        pr.step(
            ADD_STEPS,
            0,
            0.0,
            sam_core::i18n::trf(
                "{size} AppImage: format, checksum and signature",
                &[("size", &progress::size(file_size))],
            ),
        );
        let reg = self.registry();
        let all = reg.list()?;
        if let Some(existing) = all.iter().find(|a| a.source_path == source) {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file} is already registered as '{app}' ({id})",
                    &[
                        ("file", &tildify(&source)),
                        ("app", &existing.display_name()),
                        ("id", &existing.id)
                    ]
                )
            );
        }
        // Everything below reads one copy in SAM's own folder: the file was
        // checksummed, its signature checked and then opened again for
        // unpacking, so another program could swap it in between, and SAM
        // recorded one file and unpacked another (audit I-F6).
        let work = self.download_folder(&format!(
            "add-{}-{}",
            std::process::id(),
            ADDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))?;
        let _work = RemovedAtEnd(work.clone());
        let copy = work.join("app.AppImage");
        let fp = fingerprint::copy_with_fingerprint(&source, &copy, 0o700)?;
        // Recognizing the file is function 2; unpacking (below) is function 3.
        let info = (|| -> Result<_> {
            let info = inspect(&copy)?;
            if !info.is_appimage() {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "{file} is not an AppImage ({why})",
                        &[("file", &tildify(&source)), ("why", &info.notes.join("; "))]
                    )
                );
            }
            if let Some(why) = sam_detect::appimage::wrong_processor(&info) {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "{file} cannot get a sandbox: {why}",
                        &[("file", &tildify(&source)), ("why", &why)]
                    )
                );
            }
            // A download that broke off: no sandbox for half a file, and letting
            // it unpack itself would not help either.
            if let Some((have, need)) = info.incomplete() {
                return Err(sam_core::error::CodedError::new(
                    "appimage-incomplete",
                    sam_core::i18n::trf(
                        "{file} is incomplete: it has {have} of the {need} its contents need, so the download probably broke off. Download it again.",
                        &[
                            ("file", &tildify(&source)),
                            ("have", &crate::progress::size(have)),
                            ("need", &crate::progress::size(need)),
                        ],
                    ),
                )
                .into());
            }
            Ok(info)
        })()
        .in_function(2)?;

        // Same content as a registered app whose file went missing: relocate.
        if let Some(mut moved) = all
            .into_iter()
            .find(|a| a.source.sha256 == fp.sha256 && !a.source_path.exists())
        {
            moved.source_path = source.clone();
            moved.source = fp;
            if let Some(x) = moved.extraction.as_mut() {
                x.source = moved.source.clone();
            }
            if moved.state == AppState::Missing {
                moved.state = AppState::Ready;
            }
            reg.save(&mut moved)?;
            return Ok(AddOutcome {
                entry: moved,
                created: false,
                relocated: true,
                needs_fallback_consent: false,
                missing_tool: None,
                warnings: vec![],
            });
        }

        let t = now();
        let mut entry = AppEntry {
            source_path: source.clone(),
            appimage_type: info.kind,
            source: fp.clone(),
            added_at: t,
            state: AppState::Registered,
            signature: Some(self.check_signature(&copy, false)),
            ..Default::default()
        };
        // Extract into a temporary root; the final id depends on metadata.
        let root_base = self.unpack_root()?;
        let incoming = root_base.join(format!(".incoming-{}", &fp.sha256[..12]));
        if incoming.exists() {
            fs::remove_dir_all(&incoming)?;
        }
        let mut log = Vec::new();
        let req = ExtractRequest {
            source: &copy,
            info: &info,
            root: &incoming,
            limits: self.limits(),
            allow_fallback: opts.consent_fallback && self.config.extraction.allow_fallback,
            isolation: self.extract_isolation()?,
        };
        pr.step(ADD_STEPS, 1, 0.0, "");
        // How much is unpacked so far. The final size is unknown until the
        // end; AppImages unpack to about 2.5 times their file size, so the
        // bar moves by that estimate and waits at 95 % if it is bigger.
        let sink = pr.clone();
        let expected = (file_size as f64 * 2.5).max(1.0);
        let extracted = progress::watch_bytes(
            &incoming,
            move |b| {
                sink.step(
                    ADD_STEPS,
                    1,
                    (b as f64 / expected).min(0.95),
                    format!("{} unpacked", progress::size(b)),
                )
            },
            || extract(&req, &mut log),
        );
        let md = match &extracted {
            Ok(out) => metadata::read_metadata(&out.appdir).unwrap_or_default(),
            Err(_) => AppImageMetadata::default(),
        };
        entry.id = id::generate_id(&md.name, &source, &fp.sha256, |cand| {
            reg.exists(cand) || self.kept_for_another(cand, &fp.sha256)
        });
        // Its own kept data is handed back now; the note is no longer needed.
        let _ = fs::remove_file(self.paths.data_dir.join("kept").join(&entry.id));
        entry.name = if md.name.is_empty() {
            id::slug_from_filename(&source)
        } else {
            md.name.clone()
        };
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
                self.finish_intake(&mut entry, &log, pr)?;
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
            let md = self
                .peek_file(&canonical)
                .map(|p| p.metadata)
                .unwrap_or_default();
            let file_name = canonical
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let seen = sam_profile::recommend(&md, &file_name, None).permissions;
            entry.profile.permissions = merge_adjustments(&seen, p, &entry.recommended);
            entry.profile.preset = None;
            entry.profile.user_modified = entry.profile.permissions != entry.recommended;
        }
        entry.reviewed = opts.accept;
        pr.step(ADD_STEPS, 4, 0.0, "");
        if entry.extraction.is_some()
            && opts
                .launcher
                .unwrap_or(self.config.general.desktop_integration)
        {
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
        pr.step(ADD_STEPS, 4, 1.0, "");
        let missing_tool = (needs_consent && info.payload == sam_detect::PayloadFormat::Dwarfs)
            .then_some("dwarfs");
        Ok(AddOutcome {
            entry,
            created: true,
            relocated: false,
            needs_fallback_consent: needs_consent,
            missing_tool,
            warnings,
        })
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
                sam_core::i18n::trn(
                    "{n} item was made safe while unpacking: {items}",
                    "{n} items were made safe while unpacking: {items}",
                    suspicious.len() as u64,
                    &[(
                        "items",
                        &suspicious
                            .iter()
                            .take(5)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("; "),
                    )],
                ),
            ));
        }
        if out.method.contains("appimage-extract") {
            warnings.push(Warning::info(
                "fallback-extraction",
                "The AppImage unpacked itself",
                "The AppImage unpacked itself inside a restricted sandbox.",
            ));
        }
        ExtractionInfo {
            root: root.to_path_buf(),
            appdir: appdir.to_path_buf(),
            entry: "AppRun".into(),
            method: out.method.clone(),
            compression: info.compression.clone().unwrap_or_else(|| {
                if info.kind == AppImageType::Type1 {
                    "iso9660".into()
                } else {
                    "unknown".into()
                }
            }),
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
    pub(super) fn finish_intake(
        &self,
        entry: &mut AppEntry,
        extract_log: &[u8],
        pr: &ProgressSink,
    ) -> Result<()> {
        pr.step(ADD_STEPS, 2, 0.0, "");
        let mut x = entry
            .extraction
            .clone()
            .context(sam_core::i18n::tr("the AppImage has not been unpacked yet; unpack it with Unpack Again (sam-jail reextract APP)"))?;
        if !x.appdir.join("AppRun").exists() {
            // Some AppImages ship without AppRun; fall back to the desktop Exec.
            if let Some(c) = entry_from_exec(&x.appdir, &entry.metadata.exec) {
                x.entry = c.display().to_string();
                entry.extraction = Some(x.clone());
            }
        }
        entry.metadata.icon_path = metadata::cache_icon(
            &x.appdir,
            &entry.metadata.icon_name,
            &entry.id,
            &self.paths.icons_dir(),
            &x.root,
        )
        .ok()
        .flatten();
        if (entry.name.is_empty() || entry.name == id::slug_from_filename(&entry.source_path))
            && !entry.metadata.name.is_empty()
        {
            entry.name = entry.metadata.name.clone();
        }
        // Written outside any sandbox, so never through a link that might
        // be there (audit I-F2). These three copies (the metadata, the
        // unpack tools' messages, the menu entry as the app ships it) are
        // for people looking into the unpacked folder; nothing in SAM reads
        // them, so one that cannot be written (refused because the unpack
        // left something in its place) is left out rather than stopping the
        // add. The record and the logs SAM reads are written with errors
        // checked.
        let _ = sam_core::util::write_new(
            &x.root.join("metadata.json"),
            &serde_json::to_vec_pretty(&entry.metadata)?,
        );
        // The unpack tools' messages name files from the AppImage: only
        // their text is kept (audit I-F11).
        let extract_log = sam_core::terminal::plain_text(extract_log);
        let _ = sam_core::util::write_new(&x.root.join("extraction.log"), extract_log.as_bytes());
        self.write_log(&entry.id, LogKind::Extract, extract_log.as_bytes());
        if let Some(df) = &entry.metadata.desktop_file {
            if let Some(src) = sam_intake::normalize::safe_resolve(&x.appdir, Path::new(df)) {
                let desktop = x.root.join("desktop");
                if sam_core::util::real_dir(&desktop).is_ok() {
                    if let Ok(data) = fs::read(&src) {
                        let _ = sam_core::util::write_new(
                            &desktop.join(Path::new(df).file_name().unwrap_or_default()),
                            &data,
                        );
                    }
                }
            }
        }
        self.detect(entry, pr)?;
        Ok(())
    }

    pub(super) fn detect(&self, entry: &mut AppEntry, pr: &ProgressSink) -> Result<()> {
        let x = entry
            .extraction
            .clone()
            .context(sam_core::i18n::tr("the AppImage has not been unpacked yet; unpack it with Unpack Again (sam-jail reextract APP)"))?;
        let report = if self.config.dependencies.static_analysis {
            let opts = AnalyzeOptions {
                entry: x.entry.clone(),
                exec_hint: (!entry.metadata.exec.is_empty()).then(|| entry.metadata.exec.clone()),
                ..Default::default()
            };
            pr.step(
                ADD_STEPS,
                3,
                0.0,
                sam_core::i18n::tr("Looking for the app's programs and libraries"),
            );
            let report = |n: usize, total: usize| {
                pr.step(
                    ADD_STEPS,
                    3,
                    n as f64 / total.max(1) as f64,
                    sam_core::i18n::trn(
                        "{done} of {n} program file read",
                        "{done} of {n} program files read",
                        total as u64,
                        &[("done", &n)],
                    ),
                )
            };
            match analyze_appdir_with(&x.appdir, &opts, &report) {
                Ok(r) => Some(r),
                Err(e) => {
                    entry.last_error = Some(sam_core::i18n::trf(
                        "dependency detection failed: {error}",
                        &[("error", &format!("{e:#}"))],
                    ));
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
            log += &format!(
                "requirements: {:?}\ncompatibility: {:?}  verdict: {:?}\n",
                r.requirements, r.compatibility, r.verdict
            );
            for m in &r.missing {
                log += &format!(
                    "needs {} [{:?}] host={} (by {})\n",
                    m.name,
                    m.class,
                    m.host_available,
                    m.needed_by.join(", ")
                );
            }
            for w in &r.warnings {
                log += &format!("warning: {}\n", w.message);
            }
            for n in &r.notes {
                log += &format!("note: {n}\n");
            }
            self.write_log(&entry.id, LogKind::Detect, log.as_bytes());
        }
        let file_name = entry
            .source_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let rec = recommend(&entry.metadata, &file_name, report.as_ref());
        let old_rec = entry.recommended.clone();
        entry.category = rec.category.as_str().into();
        entry.recommendation_notes = rec.notes.clone();
        entry.recommended = rec.permissions.clone();
        // The recommendation becomes the profile only when the app is added.
        // Afterwards (an update, Unpack Again) it is read from a file that
        // may have been replaced, so what it asks for more is only shown as
        // pending, never applied: an update keeps the sandbox it had
        // (regression, audit U-H3: v2 of a calculator could declare
        // Categories=Network and got the network without a question).
        if self.registry().exists(&entry.id) {
            entry.pending_changes =
                new_requirements(&old_rec, &rec.permissions, &entry.profile.permissions);
            entry.profile.user_modified = entry.profile.permissions != entry.recommended;
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

    /// Logs hold text from the app and its files: only that text is
    /// written, never escape codes for a terminal that shows the log
    /// (audit I-F11, L-F3).
    pub(super) fn write_log(&self, id: &str, kind: LogKind, data: &[u8]) {
        let logs = Logs::new(&self.paths);
        if let Ok((_, mut f)) = logs.create(id, kind) {
            let _ =
                std::io::Write::write_all(&mut f, sam_core::terminal::plain_text(data).as_bytes());
            let _ = logs.prune(id, kind, 5);
        }
    }
}

/// The program to start for an app without `AppRun`: the first word of its
/// menu entry's `Exec`, looked up in `usr/bin`, the app's top folder and
/// `bin`, and only a file inside the app: `Exec=/usr/bin/x` or `../../x`
/// never becomes the entry point (audit I-F9).
fn entry_from_exec(appdir: &Path, exec: &str) -> Option<PathBuf> {
    let exec = exec.split_whitespace().next().filter(|e| !e.is_empty())?;
    ["usr/bin", "", "bin"]
        .iter()
        .map(|d| Path::new(d).join(exec))
        .find(|p| sam_intake::normalize::safe_resolve(appdir, p).is_some_and(|r| r.is_file()))
}

#[cfg(test)]
mod entry_tests {
    use super::entry_from_exec;
    use std::fs;
    use std::path::Path;

    /// An app without AppRun starts the program its menu entry names, found
    /// inside the app; a name that points outside it is never used.
    #[test]
    fn the_entry_from_exec_stays_inside_the_app() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("AppDir");
        fs::create_dir_all(app.join("usr/bin")).unwrap();
        fs::write(app.join("usr/bin/tool"), "#!/bin/sh\n").unwrap();
        fs::write(app.join("top"), "#!/bin/sh\n").unwrap();
        fs::write(tmp.path().join("outside"), "#!/bin/sh\n").unwrap();
        assert_eq!(
            entry_from_exec(&app, "tool %F").as_deref(),
            Some(Path::new("usr/bin/tool"))
        );
        assert_eq!(
            entry_from_exec(&app, "top").as_deref(),
            Some(Path::new("top"))
        );
        for bad in [
            "/usr/bin/sh",
            "../outside",
            "usr/bin/../../outside",
            "",
            "   ",
        ] {
            assert_eq!(entry_from_exec(&app, bad), None, "{bad:?}");
        }
        fs::create_dir(app.join("usr/bin/folder")).unwrap();
        assert_eq!(
            entry_from_exec(&app, "folder"),
            None,
            "a folder is no program"
        );
    }
}
