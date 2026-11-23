//! Keeping sandboxes current: re-extract, refresh, relocate, stop, remove,
//! uninstall, disk space and cleanup.

use super::*;

impl Sam {
    // ------------------------------------------------------------ maintain

    /// Re-extract after an update or failure.
    /// Unpacks the AppImage again ("Unpack Again"). When its content changed
    /// and the change did not come from a SAM update, the app does not start
    /// until the person has looked at it: another app with access to the
    /// folder could have swapped the file, which would otherwise inherit the
    /// old app's permissions.
    pub fn reextract(&self, query: &str, consent_fallback: bool) -> Result<AppEntry> {
        self.reextract_as(query, consent_fallback, None)
    }

    /// [`reextract`](Self::reextract); `checked` for SAM's own updates and
    /// going back: the content then comes from the file SAM checked in its
    /// own folder, never from the AppImage's folder, where another app
    /// could swap the file between SAM's check and the unpacking (review
    /// 2026-11-23, U-1). Without it, SAM first copies the AppImage into its
    /// own folder and works from that copy alone, for the same reason: the
    /// file was checksummed, its signature checked and then opened again
    /// for unpacking, so a swap in between went unnoticed (audit I-F6).
    pub(super) fn reextract_as(
        &self,
        query: &str,
        consent_fallback: bool,
        checked: Option<&Checked<'_>>,
    ) -> Result<AppEntry> {
        if let Some(c) = checked {
            return self.reextract_from(query, consent_fallback, c);
        }
        let entry = self.resolve(query)?;
        self.ensure_not_running(&entry, &sam_core::i18n::tr("unpack it again"))?;
        if !entry.source_path.exists() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the AppImage {file} no longer exists; use `sam-jail relocate` to point SAM at its new location",
                    &[("file", &tildify(&entry.source_path))]
                )
            );
        }
        let work = self.download_folder(&format!("{}.unpack", entry.id))?;
        let copy = work.join("app.AppImage");
        let result = fingerprint::copy_with_fingerprint(&entry.source_path, &copy, 0o700).and_then(
            |placed| {
                self.reextract_from(
                    query,
                    consent_fallback,
                    &Checked {
                        file: &copy,
                        placed,
                        sams_update: false,
                    },
                )
            },
        );
        let _ = remove_tree(&work);
        result
    }

    /// [`reextract_as`](Self::reextract_as) from `checked.file`. Only SAM's
    /// own updates and going back (not a copy of the AppImage's file) leave
    /// a changed file unmarked.
    fn reextract_from(
        &self,
        query: &str,
        consent_fallback: bool,
        checked: &Checked<'_>,
    ) -> Result<AppEntry> {
        let mut entry = self.resolve(query)?;
        self.ensure_not_running(&entry, &sam_core::i18n::tr("unpack it again"))?;
        if !entry.source_path.exists() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the AppImage {file} no longer exists; use `sam-jail relocate` to point SAM at its new location",
                    &[("file", &tildify(&entry.source_path))]
                )
            );
        }
        let source = checked.file.to_path_buf();
        let info = inspect(&source)?;
        if !info.is_appimage() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file} is no longer a valid AppImage",
                    &[("file", &tildify(&entry.source_path))]
                )
            );
        }
        // The checksum of what is unpacked, with the details of the file in
        // the AppImage's folder (so a later swap there is noticed).
        let fp = Fingerprint {
            sha256: if checked.placed.sha256.is_empty() {
                fingerprint::sha256_file(&source)?
            } else {
                checked.placed.sha256.clone()
            },
            ..checked.placed.clone()
        };
        let root = self.unpack_root()?.join(&entry.id);
        let mut log = Vec::new();
        let req = ExtractRequest {
            source: &source,
            info: &info,
            root: &root,
            limits: self.limits(),
            allow_fallback: consent_fallback && self.config.extraction.allow_fallback,
            isolation: self.extract_isolation()?,
        };
        match extract(&req, &mut log) {
            Ok(out) => {
                entry.appimage_type = info.kind;
                // Compared with what was unpacked last, not with the file's
                // last seen checksum: the change check and relocate update
                // that one, so a swapped file looked known (regression,
                // audit U-H2).
                if unpacked_sha256(&entry) != fp.sha256 {
                    if !checked.sams_update {
                        entry.content_changed_outside = true;
                    }
                    let new_sig = self.check_signature(&source, false);
                    entry.signing_key_changed =
                        signing_key_change(entry.signature.as_ref(), &new_sig);
                    entry.signature = Some(new_sig);
                }
                entry.source = fp.clone();
                let appdir = root.join("AppDir");
                entry.extraction = Some(self.extraction_info(&root, &appdir, &out, &info, &fp));
                let icon_name = entry.metadata.icon_name.clone();
                let new_md = metadata::read_metadata(&appdir).unwrap_or_default();
                entry.metadata = AppImageMetadata {
                    icon_path: None,
                    ..new_md
                };
                if entry.metadata.icon_name.is_empty() {
                    entry.metadata.icon_name = icon_name;
                }
                entry.last_error = None;
                self.finish_intake(&mut entry, &log, &ProgressSink::default())?;
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
        self.detect(&mut entry, &ProgressSink::default())?;
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
            let known = a
                .extraction
                .as_ref()
                .map(|x| x.source.clone())
                .unwrap_or_else(|| a.source.clone());
            let (status, reasons) = match fingerprint::check(&a.source_path, &known, deep)? {
                SourceStatus::Unchanged => {
                    if matches!(a.state, AppState::Missing | AppState::Stale)
                        && a.extraction.is_some()
                    {
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
                    (
                        "touched",
                        vec![sam_core::i18n::tr(
                            "the file's details changed, its content is the same",
                        )],
                    )
                }
                SourceStatus::Changed { new, reasons } => {
                    a.source = new;
                    a.state = AppState::Stale;
                    a.last_error = Some(format!("AppImage changed: {}", reasons.join(", ")));
                    ("stale", reasons)
                }
                SourceStatus::Missing => {
                    a.state = AppState::Missing;
                    (
                        "missing",
                        vec![format!("{} not found", tildify(&a.source_path))],
                    )
                }
            };
            reg.save(&mut a)?;
            out.push(RefreshItem {
                id: a.id.clone(),
                name: a.display_name().into(),
                status: status.into(),
                reasons,
            });
        }
        Ok(out)
    }

    pub fn relocate(&self, query: &str, new_path: &Path) -> Result<AppEntry> {
        let mut entry = self.resolve(query)?;
        let p = fs::canonicalize(new_path)?;
        let fp = fingerprint::compute(&p)?;
        let same = entry
            .extraction
            .as_ref()
            .is_some_and(|x| x.source.sha256 == fp.sha256);
        entry.source_path = p;
        entry.source = fp;
        entry.state = if same {
            AppState::Ready
        } else {
            AppState::Stale
        };
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
    /// `<runtime>/l<pid>-<n>/running.lock` locked while it runs;
    /// folders left by a killed runner are removed here, and what its app
    /// left in start places is moved aside first (review 2026-11-23 F2:
    /// the runner's own last look never came).
    pub fn running(&self, id: &str) -> Vec<u32> {
        let mut pids = Vec::new();
        let Ok(rd) = fs::read_dir(self.paths.runtime_dir(id)) else {
            return pids;
        };
        let mut killed = false;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(pid) = crate::launch::launch_dir_pid(&name) else {
                continue;
            };
            let lock = e.path().join("running.lock");
            if crate::launch::lock_held(&lock) {
                pids.push(pid);
            } else if lock.exists() && !Path::new(&format!("/proc/{pid}")).exists() {
                // The runner was killed before it could clean up.
                let _ = fs::remove_dir_all(e.path());
                killed = true;
            }
        }
        if killed {
            crate::home_shared::settle_left_behind(&self.paths);
        }
        pids
    }

    /// Closes every running launch of this app. The app's own processes get
    /// SIGTERM first, so it can save and quit like on logout; launches still
    /// running after 10 seconds are ended by stopping their runner, which
    /// ends the sandbox at once (its grace time is over) and then finishes
    /// the launch: the last look at the start places, the record, the log.
    /// Only a runner that is still there 15 seconds later is killed.
    /// Returns how many launches ran.
    pub fn stop(&self, query: &str) -> Result<usize> {
        let entry = self.resolve(query)?;
        // Only processes that really hold their launch's lock open: a process
        // id reused by an unrelated program is never touched.
        let base = self.paths.runtime_dir(&entry.id);
        let mut runners = Vec::new();
        for p in self.running(&entry.id) {
            for e in fs::read_dir(&base).into_iter().flatten().flatten() {
                if crate::launch::launch_dir_pid(&e.file_name().to_string_lossy()) == Some(p)
                    && holds_open(p, &e.path().join("running.lock"))
                {
                    let sandbox = fs::read_to_string(e.path().join(crate::launch::SANDBOX_PID))
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok());
                    // So the launch is recorded as closed, not as a failed
                    // start; its time tells the runner when the app was asked.
                    let _ = fs::write(e.path().join(crate::launch::STOP_MARKER), b"");
                    runners.push((p, sandbox));
                    break;
                }
            }
        }
        if runners.is_empty() {
            return Ok(0);
        }
        // SAFETY: kill takes plain integers; a process that is already gone only makes it fail.
        let signal = |pid: u32, sig: i32| unsafe {
            libc::kill(pid as libc::pid_t, sig);
        };
        for &(r, sandbox) in &runners {
            match sandbox {
                Some(s) => super::ask_to_quit(r, s),
                // Not started yet: the runner asks the app itself.
                None => signal(r, libc::SIGTERM),
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
        let grace = crate::launch::QUIT_GRACE.as_secs();
        if !wait(grace) {
            for &(r, _) in &runners {
                signal(r, libc::SIGTERM);
            }
            // Longer than the runner's own grace time, in case it began
            // one anew (review 2026-11-23 F2: SIGKILL came after 3 seconds).
            if !wait(grace + 5) {
                for &(r, _) in &runners {
                    signal(r, libc::SIGKILL);
                }
                if !wait(3) {
                    bail!(
                        "{}",
                        sam_core::i18n::trf(
                            "{app} could not be closed",
                            &[(
                                "app",
                                &sam_core::util::display_safe(&entry.metadata.name, 80)
                            )]
                        )
                    );
                }
            }
        }
        Ok(runners.len())
    }

    /// Whether `id` still holds data kept from a removed sandbox of another
    /// AppImage than the one with `sha256`. An id is a name plus four hex
    /// digits of the file's checksum, so a crafted file can get the id of a
    /// removed app in about 65,000 tries; it must not inherit that app's
    /// kept private home (audit I-F5). Data kept before SAM recorded the
    /// owner counts as another's.
    pub(super) fn kept_for_another(&self, id: &str, sha256: &str) -> bool {
        let has_data = self.paths.app_home(id).exists()
            || self.paths.data_dir.join("overlays").join(id).exists();
        has_data
            && fs::read_to_string(self.paths.data_dir.join("kept").join(id))
                .map_or(true, |owner| owner.trim() != sha256)
    }

    /// A fresh folder for one download, `<data>/downloads/<name>`, that only
    /// SAM's user can enter. Apps never see SAM's data folder.
    pub(super) fn download_folder(&self, name: &str) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let base = self.paths.data_dir.join("downloads");
        let d = base.join(name);
        if d.exists() {
            remove_tree(&d)?;
        }
        fs::create_dir_all(&d)?;
        for f in [&base, &d] {
            fs::set_permissions(f, fs::Permissions::from_mode(0o700))?;
        }
        Ok(d)
    }

    pub(super) fn ensure_not_running(&self, entry: &AppEntry, what: &str) -> Result<()> {
        if !self.running(&entry.id).is_empty() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{app} is running (maybe only in the system tray). Close it first, then {what}.",
                    &[("app", &sam_core::util::display_safe(&entry.metadata.name, 80)), ("what", &what)]
                )
            );
        }
        Ok(())
    }

    pub fn remove(&self, query: &str, keep_data: bool) -> Result<(AppEntry, Vec<String>)> {
        let entry = self.resolve(query)?;
        self.ensure_not_running(&entry, &sam_core::i18n::tr("remove its sandbox"))?;
        let mut problems = Vec::new();
        desktop::remove_launcher(&self.paths, &entry.id)?;
        for h in &entry.hidden_entries {
            if let Err(e) = menu::restore(h, &entry.id) {
                problems.push(sam_core::i18n::trf(
                    "could not restore the menu entry {entry}: {error}",
                    &[
                        ("entry", &h.original.display()),
                        ("error", &format!("{e:#}")),
                    ],
                ));
            }
        }
        if let Some(x) = &entry.extraction {
            // Only inside SAM's own unpack folder, after resolving "..":
            // a record changed outside SAM must not make SAM delete
            // anything else (Path::starts_with does not resolve "..").
            if let (Ok(root), Ok(base)) = (
                fs::canonicalize(&x.root),
                fs::canonicalize(self.extracted_root()),
            ) {
                if root.starts_with(&base) && root != base {
                    fs::remove_dir_all(&root)?;
                }
            }
        }
        for ext in ["png", "svg", "xpm"] {
            let _ = fs::remove_file(
                self.paths
                    .icons_dir()
                    .join(format!("sam-{}.{ext}", entry.id)),
            );
        }
        let _ = fs::remove_dir_all(self.paths.runtime_dir(&entry.id));
        if keep_data {
            // Which file the kept data belongs to: only that AppImage gets it
            // back when it is added again (see `kept_for_another`).
            let kept = self.paths.data_dir.join("kept");
            fs::create_dir_all(&kept)?;
            fs::write(kept.join(&entry.id), &entry.source.sha256)?;
        } else {
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
            // The version an update replaced.
            let previous = self.paths.data_dir.join("update-backups").join(&entry.id);
            if previous.exists() {
                remove_tree(&previous)?;
            }
        }
        // A download that waited for an answer about its signature.
        let waiting = self.paths.data_dir.join("update-consent").join(&entry.id);
        if waiting.exists() {
            remove_tree(&waiting)?;
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
        let own = self
            .paths
            .applications_dir
            .join("io.github.gitzekatze.SAM.desktop");
        if fs::read_to_string(&own).is_ok_and(|t| t.contains("X-SAM-Self=true")) {
            files.push(own);
            if let Some(data_home) = self.paths.applications_dir.parent() {
                let icon =
                    data_home.join("icons/hicolor/scalable/apps/io.github.gitzekatze.SAM.svg");
                if icon.exists() {
                    files.push(icon);
                }
            }
        }
        let runtime = self.paths.runtime_dir("x").parent().map(Path::to_path_buf);
        let mut dirs: Vec<PathBuf> = runtime.into_iter().filter(|d| d.exists()).collect();
        // The runtime folder can be moved too (SAM_RUNTIME_DIR): the same
        // check as for the other folders, so a wrong setting never deletes
        // a folder that is not SAM's.
        for d in &dirs {
            safe_to_delete(d)?;
        }
        if !keep_data {
            // The unpack folder only when it is SAM's own; in a folder that
            // held other things (`~/Documents`) the apps' folders were removed
            // with each app above (audit U-L1).
            let unpack = self.unpack_root_is_sams().then(|| self.extracted_root());
            for d in [
                Some(self.paths.config_dir.clone()),
                Some(self.paths.data_dir.clone()),
                unpack,
            ]
            .into_iter()
            .flatten()
            {
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
        let previous = tree_size(&self.paths.data_dir.join("update-backups").join(&entry.id));
        DiskUsage {
            id: entry.id.clone(),
            name: entry.display_name().to_string(),
            unpacked,
            home,
            overlay,
            logs,
            previous,
            total: unpacked + home + overlay + logs + previous,
            can_free: unpacked > 0 && entry.source_path.exists(),
        }
    }

    /// Deletes an app's unpacked copy to free space. Its settings and
    /// private home stay; the next start unpacks the AppImage again (see
    /// [`Sam::ensure_unpacked`]). Returns the bytes freed.
    pub fn free_space(&self, query: &str) -> Result<u64> {
        let entry = self.resolve(query)?;
        self.ensure_not_running(&entry, &sam_core::i18n::tr("free its space"))?;
        if !entry.source_path.exists() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the AppImage {file} is missing, so the unpacked copy is the only one left; it is kept",
                    &[("file", &tildify(&entry.source_path))]
                )
            );
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
        let Some(x) = &entry.extraction else {
            return Ok(false);
        };
        if x.appdir.join(&x.entry).exists() || !entry.source_path.exists() {
            return Ok(false);
        }
        if !matches!(
            fingerprint::check(&entry.source_path, &x.source, false),
            Ok(SourceStatus::Unchanged)
        ) {
            return Ok(false);
        }
        *entry = self.reextract(&entry.id, false)?;
        Ok(true)
    }

    pub fn leftover_data(&self) -> Result<Vec<LeftoverData>> {
        let mut ids: std::collections::HashSet<String> =
            self.registry().list()?.into_iter().map(|a| a.id).collect();
        // Apps whose record SAM cannot read (from a newer SAM, or damaged
        // and moved aside) still own their data (audit U-L4).
        ids.extend(self.registry().record_ids());
        let mut by_id: std::collections::BTreeMap<String, LeftoverData> = Default::default();
        for root in [
            self.paths.homes_dir(),
            self.paths.data_dir.join("overlays"),
            self.paths.logs_dir(),
        ] {
            let Ok(rd) = fs::read_dir(&root) else {
                continue;
            };
            for e in rd.flatten() {
                let id = e.file_name().to_string_lossy().into_owned();
                if ids.contains(&id) || !e.path().is_dir() {
                    continue;
                }
                let d = by_id.entry(id.clone()).or_insert_with(|| LeftoverData {
                    id,
                    paths: vec![],
                    size: 0,
                });
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
                // Only folders SAM made, never a link, and a leftover only
                // when it is an hour old: another SAM may still be unpacking
                // into it (audit U-L1, I-F16).
                let Ok(meta) = fs::symlink_metadata(e.path()) else {
                    continue;
                };
                let recent = name.starts_with('.')
                    && meta
                        .modified()
                        .ok()
                        .and_then(|m| m.elapsed().ok())
                        .is_some_and(|age| age.as_secs() < 3600);
                if ids.contains(&name) || !meta.is_dir() || !sams_own_unpack_entry(&name) || recent
                {
                    continue;
                }
                remove_tree(&e.path())?;
                removed.push(e.path());
            }
        }
        Ok(removed)
    }

    /// Checks whether newer versions are published, for one app or all,
    /// and stores the result with each app. With `if_due`, only when
    /// `updates.check_on_start` is on, and only apps not checked for a day.
    pub fn check_updates(
        &self,
        query: Option<&str>,
        if_due: bool,
    ) -> Result<Vec<(String, UpdateStatus)>> {
        if if_due && !self.config.updates.check_on_start {
            return Ok(vec![]);
        }
        self.forget_old_waiting();
        let entries = match query {
            Some(q) => vec![self.resolve(q)?],
            None => self.registry().list()?,
        };
        let reg = self.registry();
        let mut out = Vec::new();
        for e in entries {
            if if_due
                && e.update
                    .as_ref()
                    .is_some_and(|u| now() - u.checked_at < 24 * 3600)
            {
                continue;
            }
            if !e.source_path.exists() {
                continue;
            }
            let status = crate::updates::check(&e.source_path);
            // The check takes a while: save onto the record as it is now.
            reg.update(&e.id, |fresh| fresh.update = Some(status.clone()))?;
            out.push((e.id.clone(), status));
        }
        Ok(out)
    }

    /// Downloads the newest published version of an app's AppImage and
    /// puts it in place of the old one. Everything is checked in SAM's own
    /// folder, which no app can reach:
    /// 1. a copy of the installed file must be what SAM unpacked last: a file
    ///    swapped outside SAM is not updated (its update source would decide
    ///    what runs with this app's permissions);
    /// 2. download and check it against the published SHA-1;
    /// 3. it must be an AppImage for this computer's processor, signed like
    ///    the installed one. If not, the download waits in
    ///    `<data>/update-consent/<id>/`, and `accept_key_change` installs
    ///    exactly that file (when it is still the published one), never a
    ///    new download;
    /// 4. the checked copy of the old file is kept in
    ///    `<data>/update-backups/<id>/` (so it is not listed as a second
    ///    AppImage), a copy of the new one takes its new name in the
    ///    AppImage's folder, and the sandbox is unpacked again from the checked
    ///    download, with its settings kept.
    pub fn update(&self, query: &str, accept_key_change: bool) -> Result<AppEntry> {
        let entry = self.resolve(query)?;
        self.forget_old_waiting();
        self.ensure_not_running(&entry, "update it")?;
        if !entry.source_path.exists() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the AppImage {file} is missing; relocate it first",
                    &[("file", &tildify(&entry.source_path))]
                )
            );
        }
        // Where SAM can build no sandbox, the new version could be neither
        // unpacked nor its signature checked: stop here with that reason,
        // before anything is downloaded or asked. Before, the update was
        // downloaded and the question about its signature said to install
        // GnuPG, which was not the cause (review of PR 95).
        self.extract_isolation()?;
        // Downloaded and checked in SAM's own folder: in the AppImage's
        // folder (often Downloads) another app could plant a link under the
        // download's name, or swap the file between the check and its use
        // (regression, audit U-H4; review 2026-11-23, U-1).
        let work = self.download_folder(&entry.id)?;
        let result = self.update_in(&entry, &work, accept_key_change);
        let _ = remove_tree(&work);
        result
    }

    /// The person said no to the question about an update's signature:
    /// the download kept for that answer is deleted now, not left in SAM's
    /// folder until the app's next update. Whether one was waiting.
    pub fn decline_update(&self, query: &str) -> Result<(AppEntry, bool)> {
        let entry = self.resolve(query)?;
        let waiting = self.paths.data_dir.join("update-consent").join(&entry.id);
        let was = fs::symlink_metadata(&waiting).is_ok();
        if was {
            remove_waiting(&waiting)?;
        }
        Ok((entry, was))
    }

    /// Deletes the downloads that have waited for an answer longer than
    /// [`WAITING_KEPT_FOR`] (a question never answered: the window was
    /// closed, or the command line was not run again).
    fn forget_old_waiting(&self) {
        forget_waiting_older_than(
            &self.paths.data_dir.join("update-consent"),
            std::time::Duration::from_secs(WAITING_KEPT_FOR),
        );
    }

    fn update_in(
        &self,
        entry: &AppEntry,
        work: &Path,
        accept_key_change: bool,
    ) -> Result<AppEntry> {
        use std::os::unix::fs::PermissionsExt;
        let old = entry.source_path.clone();
        // The installed version as SAM checked it. Its update information
        // names where updates come from, so it must be the file SAM
        // unpacked: another app could have put its own AppImage there,
        // naming its own server (review 2026-11-23, U-1).
        let installed = work.join(".installed");
        fs::copy(&old, &installed)?;
        let installed_sha256 = fingerprint::sha256_file(&installed)?;
        if installed_sha256 != unpacked_sha256(entry) {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file} changed outside SAM since it was last unpacked, so SAM does not update it: another program may have replaced it. Use Unpack Again and look at the app first.",
                    &[("file", &tildify(&old))]
                )
            );
        }
        let Some(p) = crate::updates::newest(&installed)? else {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{app} is already the newest published version",
                    &[(
                        "app",
                        &sam_core::util::display_safe(entry.display_name(), 80)
                    )]
                )
            );
        };
        let dir = old
            .parent()
            .context(sam_core::i18n::tr("no folder"))?
            .to_path_buf();
        let old_name = old
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = update_file_name(p.filename.as_deref(), &old_name, &dir);
        let target = dir.join(&name);
        let tmp = work.join(&name);
        // A consent covers exactly the file it was asked for: a download
        // refused for a changed or unchecked signature waits in SAM's own
        // folder, and accepting installs that file. Downloading again let a
        // server hand out another file, signed with any key, under the same
        // "yes" (review 2026-11-23, U-4).
        let waiting_dir = self.paths.data_dir.join("update-consent").join(&entry.id);
        let waiting = take_waiting(&waiting_dir, work).filter(|(w, _)| {
            accept_key_change
                && w.installed_sha256 == installed_sha256
                && w.published_sha1 == p.sha1
        });
        let (fetched, consented) = match waiting {
            Some((w, file))
                if fingerprint::sha256_file(&file).ok().as_deref() == Some(w.sha256.as_str()) =>
            {
                fs::rename(&file, &tmp)?;
                let total = fs::metadata(&tmp)?.len();
                (crate::updates::Fetched::Full { total }, Some(w))
            }
            _ => (crate::updates::download_update(&p, &installed, &tmp)?, None),
        };
        let info = inspect(&tmp)?;
        if !info.is_appimage() {
            bail!(
                "{}",
                sam_core::i18n::tr("the downloaded file is not an AppImage; it was deleted")
            );
        }
        // A build for another processor would not start: the working version
        // would be in the backups and the app broken until Undo (review
        // 2026-11-23, U-8). Adding an app refuses it the same way.
        if let Some(why) = sam_detect::appimage::wrong_processor(&info) {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the downloaded update was not installed and was deleted: {reason}",
                    &[("reason", &why)]
                )
            );
        }
        // What the new file is compared with: the recorded signature when it
        // was checked, otherwise the installed file checked now. A record
        // made while GnuPG was missing would otherwise let any key through
        // for good (review 2026-11-23, U-3).
        let before_sig = match &entry.signature {
            Some(s)
                if s.state == sam_core::model::SignatureState::Valid && s.fingerprint.is_some() =>
            {
                s.clone()
            }
            _ => self.check_signature(&installed, false),
        };
        let new_sha256 = fingerprint::sha256_file(&tmp)?;
        let new_sig = self.check_signature(&tmp, false);
        // Accepted earlier: this very file, for this very question.
        let consented_to = |code: &str| {
            consented
                .as_ref()
                .is_some_and(|w| w.code == code && w.sha256 == new_sha256)
        };
        // Asks, and keeps the download for the answer.
        let ask = |code: &'static str, message: String| -> anyhow::Error {
            let w = Waiting {
                code: code.to_string(),
                sha256: new_sha256.clone(),
                installed_sha256: installed_sha256.clone(),
                published_sha1: p.sha1.clone(),
            };
            // Not kept (no space): accepting then downloads and asks again.
            let _ = keep_waiting(&waiting_dir, &tmp, &w);
            sam_core::error::CodedError::new(code, message).into()
        };
        if let Some(before) = signing_key_change(Some(&before_sig), &new_sig) {
            if !consented_to("signing-key-changed") {
                return Err(ask(
                    "signing-key-changed",
                    sam_core::i18n::trf(
                        "The signing key changed: the installed version was {before}, the new file is {now}. Accept the change only if you trust it: SAM then installs exactly this file, never one downloaded later.",
                        &[("before", &before), ("now", &sig_words(&new_sig))],
                    ),
                ));
            }
        }
        if let Some((was, now)) = older_signed_version(Some(&before_sig), &new_sig) {
            return Err(older_version_error(was, now).into());
        }
        // Signed and checked before, but the new file cannot be checked
        // (GnuPG missing): SAM cannot tell whether the key changed, so it
        // asks like for a changed key (threat model: a key change is
        // refused until you accept it).
        if let Some(before) = signature_unconfirmed(Some(&before_sig), &new_sig) {
            if !consented_to("signature-unchecked") {
                return Err(ask(
                    "signature-unchecked",
                    sam_core::i18n::trf(
                        "The installed version was {before}, but the signature of the new file cannot be checked, so SAM cannot tell whether it comes from the same developer. Install GnuPG (gpg and gpgv) and update again; accept the update without the check only if you trust its source: SAM then installs exactly this file, never one downloaded later.",
                        &[("before", &before)],
                    ),
                ));
            }
        }
        let old_mode = fs::metadata(&old)
            .map(|m| m.permissions().mode())
            .unwrap_or(0o755)
            & 0o777;
        // Keep the checked copy of the old version, then put a copy of the
        // new one in place. Copies, never moves: what is unpacked below is
        // the checked download in SAM's own folder.
        let backup_dir = self.paths.data_dir.join("update-backups").join(&entry.id);
        if backup_dir.exists() {
            remove_tree(&backup_dir)?;
        }
        fs::create_dir_all(&backup_dir)?;
        let backup = backup_dir.join(&old_name);
        move_file(&installed, &backup)?;
        fs::remove_file(&old)?;
        let placed = match place_copy(&tmp, &target, old_mode | 0o500) {
            Ok(fp) => fp,
            Err(e) => {
                if place_copy(&backup, &old, old_mode).is_ok() {
                    let _ = remove_tree(&backup_dir);
                }
                return Err(e.context(sam_core::i18n::tr("putting the new version in place")));
            }
        };
        // The way back is recorded before unpacking: if unpacking the new
        // version fails, the old one can still be put back (audit U-L2).
        let way_back = UpdateBackup {
            file: backup,
            original_path: old,
            replaced_at: now(),
            sha256: Some(installed_sha256),
            placed_sha256: Some(new_sha256),
        };
        self.registry().update(&entry.id, |f| {
            f.source_path = target.clone();
            f.signature = Some(before_sig.clone());
            f.update_backup = Some(way_back.clone());
        })?;
        let mut e = self.reextract_as(
            &entry.id,
            false,
            Some(&Checked {
                file: &tmp,
                placed,
                sams_update: true,
            }),
        )?;
        e.update_backup = Some(way_back);
        e.update = Some(UpdateStatus {
            state: sam_core::model::UpdateState::Current,
            latest: p.filename.or(p.release),
            download_page: p.page,
            detail: match fetched {
                crate::updates::Fetched::Delta { bytes, total } => sam_core::i18n::trf(
                    "Updated; this is the newest published version. Only the changed parts were downloaded ({part} of {whole} MB).",
                    &[("part", &format!("{:.1}", bytes as f64 / 1e6)), ("whole", &format!("{:.1}", total as f64 / 1e6))],
                ),
                crate::updates::Fetched::Full { total } => sam_core::i18n::trf(
                    "Updated; this is the newest published version ({size} MB downloaded).",
                    &[("size", &format!("{:.1}", total as f64 / 1e6))],
                ),
            },
            checked_at: now(),
        });
        self.registry().save(&mut e)?;
        Ok(e)
    }

    /// Goes back to the version an update replaced. The newer file is kept
    /// in its place, so going back can itself be undone.
    pub fn undo_update(&self, query: &str) -> Result<AppEntry> {
        let entry = self.resolve(query)?;
        self.ensure_not_running(&entry, "go back")?;
        let b = entry.update_backup.clone().context(sam_core::i18n::tr(
            "there is no earlier version to go back to",
        ))?;
        if !b.file.exists() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the earlier version is no longer there ({file})",
                    &[("file", &tildify(&b.file))]
                )
            );
        }
        // SAM keeps earlier versions only in its own backup folder; a record
        // changed outside SAM must not make it move any other file.
        let backups = fs::canonicalize(self.paths.data_dir.join("update-backups")).ok();
        if !backups.is_some_and(|dir| fs::canonicalize(&b.file).is_ok_and(|f| f.starts_with(&dir)))
        {
            bail!(
                "{}",
                sam_core::i18n::trf("the earlier version is not in SAM's backup folder ({file}); SAM does not move it", &[("file", &tildify(&b.file))])
            );
        }
        // Where the earlier version goes: the app's folder, under the name
        // its kept copy carries (the name it had there). Not the place the
        // record names: a record changed outside SAM could put the old
        // AppImage anywhere under any name, for example as a command in
        // ~/.local/bin (audit U-L10).
        let back_to = entry
            .source_path
            .parent()
            .context(sam_core::i18n::tr("no folder"))?
            .join(b.file.file_name().context(sam_core::i18n::tr("no name"))?);
        if back_to.exists() && back_to != entry.source_path {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file} exists again; move it away first",
                    &[("file", &tildify(&back_to))]
                )
            );
        }
        let current = entry.source_path.clone();
        let keep = b
            .file
            .with_file_name(current.file_name().context(sam_core::i18n::tr("no name"))?);
        // The earlier version first steps aside inside the backup folder:
        // when both versions have the same name, `keep` is its own path,
        // and moving the current file there destroyed it while reporting
        // success (regression, audit U-H5).
        let earlier = b.file.with_file_name(".going-back");
        move_file(&b.file, &earlier)?;
        // The current file is kept as the newer version, and going forward
        // again unpacks it as SAM's own: so it must be what SAM unpacked (or
        // what the update put there, when unpacking that failed), checked
        // once it is in SAM's own folder (review 2026-11-23, U-1). A copy,
        // never a move: another app that can write to the AppImage's folder
        // may hold the file under a second name (a hard link) or open for
        // writing, and could change a moved file after SAM checked it.
        let current_mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&current)
                .map(|m| m.permissions().mode())
                .unwrap_or(0o755)
                & 0o777
        };
        let mut kept_sha256 = None;
        if current.exists() {
            if keep != earlier {
                // Left over from an interrupted run; never the earlier version.
                let _ = fs::remove_file(&keep);
            }
            if let Err(e) = place_copy(&current, &keep, current_mode) {
                let _ = move_file(&earlier, &b.file);
                return Err(e);
            }
            let sha = fingerprint::sha256_file(&keep).ok();
            let known = sha.as_deref().is_some_and(|s| {
                s == unpacked_sha256(&entry) || Some(s) == b.placed_sha256.as_deref()
            });
            if !known {
                let _ = fs::remove_file(&keep);
                let _ = move_file(&earlier, &b.file);
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "{file} changed outside SAM since it was last unpacked, so SAM does not go back: another program may have replaced it. Use Unpack Again and look at the app first.",
                        &[("file", &tildify(&current))]
                    )
                );
            }
            if let Err(e) = fs::remove_file(&current) {
                let _ = fs::remove_file(&keep);
                let _ = move_file(&earlier, &b.file);
                return Err(e.into());
            }
            kept_sha256 = sha;
        }
        // Only a version SAM checked when it kept it counts as SAM's own; one
        // kept by an older SAM (or changed since) asks for a review.
        let earlier_checked = b.sha256.is_some()
            && fingerprint::sha256_file(&earlier).ok().as_deref() == b.sha256.as_deref();
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&earlier)
                .map(|m| m.permissions().mode())
                .unwrap_or(0o755)
                & 0o777
        };
        let placed = match place_copy(&earlier, &back_to, mode) {
            Ok(fp) => fp,
            Err(e) => {
                // Put the current file back; the kept copy is never
                // overwritten while it is the only one.
                let mut restored = kept_sha256.is_none();
                if !restored && place_copy(&keep, &current, current_mode).is_ok() {
                    let _ = fs::remove_file(&keep);
                    restored = true;
                }
                if restored || keep != b.file {
                    let _ = move_file(&earlier, &b.file);
                }
                return Err(e);
            }
        };
        let back_at = match (back_to.parent(), back_to.file_name()) {
            (Some(dir), Some(name)) => fs::canonicalize(dir)
                .map(|d| d.join(name))
                .unwrap_or_else(|_| back_to.clone()),
            _ => back_to.clone(),
        };
        let way_forward = UpdateBackup {
            file: keep,
            original_path: current,
            replaced_at: now(),
            sha256: kept_sha256,
            placed_sha256: if earlier_checked {
                b.sha256.clone()
            } else {
                None
            },
        };
        self.registry().update(&entry.id, |f| {
            f.source_path = back_at.clone();
            f.update_backup = Some(way_forward.clone());
        })?;
        let unpacked = if earlier_checked {
            self.reextract_as(
                &entry.id,
                false,
                Some(&Checked {
                    file: &earlier,
                    placed,
                    sams_update: true,
                }),
            )
        } else {
            self.reextract_as(&entry.id, false, None)
        };
        let _ = fs::remove_file(&earlier);
        let mut e = unpacked?;
        e.update_backup = Some(way_forward);
        e.update = None;
        self.registry().save(&mut e)?;
        Ok(e)
    }

    /// Updates SAM's own AppImage (`appimage`, from `$APPIMAGE`): checks the
    /// update source written into it, and unless `check_only` downloads the
    /// new version (only the changed parts when possible), checks it, and
    /// puts it next to the old one under its published name. The old file
    /// moves to `<data>/update-backups/sam/`. SAM must be restarted.
    pub fn self_update(&self, appimage: &Path, check_only: bool) -> Result<SelfUpdate> {
        self.self_update_with_keys(appimage, check_only, crate::release_key::RELEASE_KEYS)
    }

    /// `self_update` with the release keys given (for tests).
    pub fn self_update_with_keys(
        &self,
        appimage: &Path,
        check_only: bool,
        keys: &[&str],
    ) -> Result<SelfUpdate> {
        if !appimage.is_absolute() || !appimage.is_file() {
            bail!(
                "{}",
                sam_core::i18n::tr(
                    "SAM is not running from an AppImage; update it with your package manager"
                )
            );
        }
        let Some(p) = crate::updates::newest(appimage)? else {
            return Ok(SelfUpdate {
                state: "current".into(),
                latest: None,
                path: appimage.to_path_buf(),
                detail: sam_core::i18n::tr("SAM is up to date."),
                page: None,
            });
        };
        let latest = p.filename.clone().or(p.release.clone());
        let page = p.page.clone();
        // Without a release key SAM cannot check where an update comes
        // from: it says so and points to the release page instead of
        // downloading anything (see release_key).
        if keys.is_empty() {
            let name = latest
                .clone()
                .unwrap_or_else(|| sam_core::i18n::tr("A newer version"));
            return Ok(SelfUpdate {
                state: "manual".into(),
                detail: sam_core::i18n::trf(
                    "{version} is published. This SAM cannot yet check where an update comes from, so it does not update itself: download the new version from the release page.",
                    &[("version", &sam_core::util::display_safe(&name, 120))],
                ),
                latest,
                path: appimage.to_path_buf(),
                page,
            });
        }
        if check_only {
            let name = latest
                .clone()
                .unwrap_or_else(|| sam_core::i18n::tr("A newer version"));
            return Ok(SelfUpdate {
                state: "available".into(),
                detail: sam_core::i18n::trf(
                    "{version} is published.",
                    &[("version", &sam_core::util::display_safe(&name, 120))],
                ),
                latest,
                path: appimage.to_path_buf(),
                page,
            });
        }
        let dir = appimage.parent().context(sam_core::i18n::tr("no folder"))?;
        let old_name = appimage
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = update_file_name(p.filename.as_deref(), &old_name, dir);
        let target = dir.join(&name);
        let tmp = self.download_folder("sam")?.join(&name);
        let fetched = crate::updates::download_update(&p, appimage, &tmp)?;
        let placed = (|| -> Result<()> {
            if !inspect(&tmp)?.is_appimage() {
                bail!(
                    "{}",
                    sam_core::i18n::tr("the downloaded file is not an AppImage; it was deleted")
                );
            }
            // Only SAM's makers may replace SAM (see release_key), and never
            // with an older release than the one running.
            let new_sig = self.check_signature(&tmp, true);
            crate::release_key::check(&new_sig, keys)?;
            let running = self.check_signature(appimage, true);
            if let Some((was, now)) = older_signed_version(Some(&running), &new_sig) {
                return Err(older_version_error(was, now).into());
            }
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
            let backup_dir = self.paths.data_dir.join("update-backups").join("sam");
            if backup_dir.exists() {
                remove_tree(&backup_dir)?;
            }
            fs::create_dir_all(&backup_dir)?;
            // A running AppImage can be moved: the old SAM keeps running
            // from its mounted image until it exits.
            move_file(appimage, &backup_dir.join(&old_name))?;
            if let Err(e) = move_file(&tmp, &target) {
                let _ = move_file(&backup_dir.join(&old_name), appimage);
                return Err(e.context(sam_core::i18n::tr("putting the new version in place")));
            }
            Ok(())
        })();
        if let Some(d) = tmp.parent() {
            let _ = remove_tree(d);
        }
        placed?;
        let how = match fetched {
            crate::updates::Fetched::Delta { bytes, total } => sam_core::i18n::trf(
                "only the changed parts were downloaded ({part} of {whole} MB)",
                &[
                    ("part", &format!("{:.1}", bytes as f64 / 1e6)),
                    ("whole", &format!("{:.1}", total as f64 / 1e6)),
                ],
            ),
            crate::updates::Fetched::Full { total } => {
                format!("{:.1} MB downloaded", total as f64 / 1e6)
            }
        };
        Ok(SelfUpdate {
            state: "updated".into(),
            latest,
            path: target,
            detail: sam_core::i18n::trf(
                "SAM was updated; {how}. Restart SAM to use the new version.",
                &[("how", &how)],
            ),
            page,
        })
    }
}

/// Rename, or copy and delete across file systems.
/// The refusal of an update that is an older signed version.
fn older_version_error(was: i64, now: i64) -> sam_core::error::CodedError {
    let day = |t: i64| {
        sam_core::util::format_utc_date(t)
            .chars()
            .take(16)
            .collect::<String>()
    };
    sam_core::error::CodedError::new(
        "older-version",
        sam_core::i18n::trf(
            "The download was signed on {now}, before the installed version ({was}): it is an older version, which may have security holes that were fixed since. It was deleted and nothing changed. To go back to an earlier version on purpose, use Undo after an update.",
            &[("now", &day(now)), ("was", &day(was))],
        ),
    )
}

/// A file SAM checked in its own folder, which no app can reach, and the
/// details of the copy it put in the AppImage's folder: what is unpacked
/// comes from `file`, what is recorded describes the copy.
pub(super) struct Checked<'a> {
    pub file: &'a Path,
    /// Size, time and inode of the copy; its checksum, when not empty, is
    /// that of `file`.
    pub placed: Fingerprint,
    /// The content comes from a SAM update or going back, not from the
    /// AppImage's folder: a changed checksum is then no swap to look at.
    pub sams_update: bool,
}

/// The checksum of the AppImage SAM unpacked last. Not the file's last seen
/// checksum: the change check and relocate update that one, so a swapped
/// file looked known (regression, audit U-H2).
fn unpacked_sha256(entry: &AppEntry) -> &str {
    entry
        .extraction
        .as_ref()
        .map_or(&entry.source.sha256, |x| &x.source.sha256)
}

/// An update download that waits for the person's answer (review
/// 2026-11-23, U-4): which question, which file, for which installed
/// version and which published one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Waiting {
    code: String,
    sha256: String,
    installed_sha256: String,
    published_sha1: String,
}

/// The download waiting in `dir`, moved into `work`. `dir` is emptied in
/// any case: a consent is used once, or not at all.
fn take_waiting(dir: &Path, work: &Path) -> Option<(Waiting, PathBuf)> {
    let found = (|| {
        let w: Waiting = serde_json::from_slice(&fs::read(dir.join("waiting.json")).ok()?).ok()?;
        let file = dir.join("download");
        if !fs::symlink_metadata(&file).ok()?.file_type().is_file() {
            return None;
        }
        let to = work.join(".waiting");
        fs::rename(&file, &to).ok()?;
        Some((w, to))
    })();
    if dir.exists() {
        let _ = remove_tree(dir);
    }
    found
}

/// How long an update download waits for the person's answer: a week.
/// The question comes right when the person updates, so an answer later
/// than that is unlikely; each waiting download can be as large as the
/// AppImage (up to 8 GiB), and a later yes only means downloading and
/// asking again, never anything less safe.
const WAITING_KEPT_FOR: u64 = 7 * 24 * 3600;

/// Deletes one waiting download's folder (or whatever else has its name).
fn remove_waiting(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.is_dir() {
        remove_tree(path)
    } else {
        Ok(fs::remove_file(path)?)
    }
}

/// Deletes what waits in `root` (`<data>/update-consent`) and was last
/// changed more than `max_age` ago; what it deleted. A time in the future
/// counts as new.
fn forget_waiting_older_than(root: &Path, max_age: std::time::Duration) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    let Ok(rd) = fs::read_dir(root) else {
        return removed;
    };
    for e in rd.flatten() {
        let old = fs::symlink_metadata(e.path())
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > max_age);
        if old && remove_waiting(&e.path()).is_ok() {
            removed.push(e.path());
        }
    }
    removed
}

/// Keeps `file` (in SAM's download folder) in `dir` until the answer.
fn keep_waiting(dir: &Path, file: &Path, w: &Waiting) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if dir.exists() {
        remove_tree(dir)?;
    }
    fs::create_dir_all(dir)?;
    for d in [dir.parent().unwrap_or(dir), dir] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
    }
    fs::rename(file, dir.join("download"))?;
    fs::write(dir.join("waiting.json"), serde_json::to_vec(w)?)?;
    Ok(())
}

/// Whether `name` is a plain AppImage file name: letters, digits and
/// `._+-` only, not hidden, ending in `.AppImage` (any case).
fn plain_appimage_name(name: &str) -> bool {
    const END: &str = ".appimage";
    name.len() > END.len()
        && name.len() < 200
        && !name.starts_with('.')
        && name.to_ascii_lowercase().ends_with(END)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// The name an update gets in the AppImage's folder: the published name
/// when it is a plain AppImage name that no other file in `dir` has,
/// otherwise the old name. The update server chooses the published name, and
/// SAM makes the file executable: a name such as `sudo` in a folder on the
/// command search path (~/.local/bin) would put the server's program in
/// place of a command, outside any sandbox (review 2026-11-23, U-2).
pub(crate) fn update_file_name(published: Option<&str>, old_name: &str, dir: &Path) -> String {
    published
        .filter(|n| plain_appimage_name(n))
        .filter(|n| *n == old_name || fs::symlink_metadata(dir.join(n)).is_err())
        .map_or_else(|| old_name.to_string(), str::to_string)
}

/// Copies `from` to `to`, which must not exist yet, never through a link,
/// with `mode`. Returns the copy's size, time and inode as SAM records them
/// (from the file it wrote, whatever is at `to` by then).
fn place_copy(from: &Path, to: &Path, mode: u32) -> Result<Fingerprint> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut src = fs::File::open(from)?;
    let mut dst = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(to)
        .with_context(|| format!("creating {}", to.display()))?;
    let copied = (|| -> Result<Fingerprint> {
        std::io::copy(&mut src, &mut dst)?;
        dst.set_permissions(fs::Permissions::from_mode(mode))?;
        dst.sync_all()?;
        let m = dst.metadata()?;
        Ok(Fingerprint {
            size: m.len(),
            mtime: m.mtime(),
            inode: m.ino(),
            device: m.dev(),
            sha256: String::new(),
        })
    })();
    if copied.is_err() {
        let _ = fs::remove_file(to);
    }
    copied.with_context(|| format!("copying {} to {}", from.display(), to.display()))
}

/// Moves a file. Within one file system a rename, which replaces whatever
/// is at `to` (also a link) and never writes through it. Across file
/// systems a copy into a new file that must not exist yet and is never
/// opened through a link (regression, audit U-H4: `fs::copy` follows a
/// link planted at `to`), then the original is removed.
fn move_file(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    let copy = || -> Result<()> {
        let mut src = fs::File::open(from)?;
        let mode = src.metadata()?.permissions().mode() & 0o777;
        let mut dst = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(mode)
            .open(to)?;
        std::io::copy(&mut src, &mut dst)?;
        dst.sync_all()?;
        Ok(())
    };
    copy().with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    fs::remove_file(from).with_context(|| format!("removing {}", from.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// Regression (audit U-L4): the data of an app whose record SAM could
    /// not read (damaged, or written by a newer SAM) was listed as left
    /// over, and "remove leftover data" deleted the app's private home.
    /// Only data without any record is offered now.
    #[test]
    fn data_of_an_unreadable_record_is_not_offered_for_deletion() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let apps = sam.paths.apps_dir();
        fs::create_dir_all(&apps).unwrap();
        fs::write(apps.join("appimage-broken-1234.json"), "{ damaged").unwrap();
        fs::write(
            apps.join("appimage-newer-1234.json"),
            r#"{"format": 999999, "id": "appimage-newer-1234"}"#,
        )
        .unwrap();
        for id in [
            "appimage-broken-1234",
            "appimage-newer-1234",
            "appimage-gone-1234",
        ] {
            fs::create_dir_all(sam.paths.app_home(id).join("Documents")).unwrap();
        }
        let left: Vec<String> = sam
            .leftover_data()
            .unwrap()
            .into_iter()
            .map(|d| d.id)
            .collect();
        assert_eq!(left, vec!["appimage-gone-1234"]);
        assert!(
            fs::read_dir(&apps).unwrap().flatten().any(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with("appimage-broken-1234.json.damaged-")),
            "the damaged record was moved aside"
        );
        sam.remove_leftover_data().unwrap();
        assert!(sam.paths.app_home("appimage-broken-1234").exists());
        assert!(sam.paths.app_home("appimage-newer-1234").exists());
        assert!(!sam.paths.app_home("appimage-gone-1234").exists());
    }

    /// A download that waited for an answer about an update for more
    /// than a week (the question was never answered) is deleted when
    /// updates are checked; a younger one stays for its answer. Before,
    /// it stayed until that app's next update or its removal.
    #[test]
    fn a_download_never_answered_is_deleted_after_a_week() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let root = sam.paths.data_dir.join("update-consent");
        let day = std::time::Duration::from_secs(24 * 3600);
        for (id, days) in [("appimage-old-1234", 8), ("appimage-young-1234", 6)] {
            let d = root.join(id);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("download"), "the update").unwrap();
            fs::File::open(&d)
                .unwrap()
                .set_modified(std::time::SystemTime::now() - day * days)
                .unwrap();
        }
        sam.check_updates(None, false).unwrap();
        assert!(!root.join("appimage-old-1234").exists(), "never answered");
        assert!(root.join("appimage-young-1234/download").exists());
    }

    /// An update keeps its published name only when that is a plain
    /// AppImage name no other file has: the update server chooses it, and a
    /// name like `sudo` in ~/.local/bin would replace a command outside any
    /// sandbox (review 2026-11-23, U-2).
    #[test]
    fn only_a_plain_appimage_name_is_taken_from_an_update() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        fs::write(dir.join("Other-2.0.AppImage"), "").unwrap();
        std::os::unix::fs::symlink(dir.join("nowhere"), dir.join("Link-2.0.AppImage")).unwrap();
        let name = |published: &str| update_file_name(Some(published), "Tool-1.0.AppImage", dir);
        for good in [
            "Tool-2.0-x86_64.AppImage",
            "tool_2.0+git.appimage",
            "Tool-1.0.AppImage",
        ] {
            assert_eq!(name(good), good);
        }
        for bad in [
            "sudo",
            "git",
            "python3",
            "Tool.AppImage.sh",
            ".AppImage",
            ".Tool.AppImage",
            "Tool 2.0.AppImage",
            "Tool;rm.AppImage",
            "../Tool.AppImage",
            "Tool\u{202e}.AppImage",
            "Other-2.0.AppImage",
            "Link-2.0.AppImage",
            "",
        ] {
            assert_eq!(name(bad), "Tool-1.0.AppImage", "{bad:?}");
        }
        assert_eq!(
            name(&format!("{}.AppImage", "a".repeat(200))),
            "Tool-1.0.AppImage"
        );
        assert_eq!(
            update_file_name(None, "Tool-1.0.AppImage", dir),
            "Tool-1.0.AppImage"
        );
    }

    /// The unpack location can be any folder, for example `~/Documents`.
    /// Cleaning up deleted every folder in it that was not an app, and
    /// uninstalling deleted it entirely (audit U-L1). Now SAM removes only
    /// what it put there (an unregistered app's folder, an unpacking leftover
    /// older than an hour), and the whole folder only when SAM created it.
    #[test]
    fn a_shared_unpack_folder_keeps_everything_that_is_not_sams() {
        let tmp = tempfile::tempdir().unwrap();
        let docs = tmp.path().join("Documents");
        fs::create_dir_all(docs.join("My Photos")).unwrap();
        fs::write(docs.join("My Photos/pic.jpg"), "photo").unwrap();
        fs::write(docs.join("notes.txt"), "notes").unwrap();
        fs::create_dir_all(docs.join("Projects")).unwrap();
        fs::create_dir_all(docs.join("appimage-orphan-1234/AppDir")).unwrap();
        fs::create_dir_all(docs.join("appimage-installed-5678/AppDir")).unwrap();
        fs::create_dir_all(docs.join(".unpack-999")).unwrap();
        fs::create_dir_all(docs.join(".incoming-abc")).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        fs::File::open(docs.join(".incoming-abc"))
            .unwrap()
            .set_modified(old)
            .unwrap();

        let mut sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
        sam.config.extraction.location = docs.to_string_lossy().into_owned();
        assert_eq!(sam.unpack_root().unwrap(), docs);
        assert!(
            !sam.unpack_root_is_sams(),
            "a folder with other things is not SAM's"
        );
        let mut installed = sam_core::model::AppEntry {
            id: "appimage-installed-5678".into(),
            name: "Installed".into(),
            ..Default::default()
        };
        sam.registry().save(&mut installed).unwrap();

        let mut removed = sam.cleanup().unwrap();
        removed.sort();
        assert_eq!(
            removed,
            vec![
                docs.join(".incoming-abc"),
                docs.join("appimage-orphan-1234")
            ]
        );
        assert!(docs.join("My Photos/pic.jpg").is_file());
        assert!(docs.join("notes.txt").is_file());
        assert!(docs.join("Projects").is_dir(), "a folder with a plain name");
        assert!(
            docs.join("appimage-installed-5678/AppDir").is_dir(),
            "an installed app"
        );
        assert!(
            docs.join(".unpack-999").is_dir(),
            "a recent leftover may still be in use"
        );

        sam.uninstall(false, false).unwrap();
        assert!(
            docs.join("My Photos/pic.jpg").is_file(),
            "uninstalling keeps the person's folder"
        );
        assert!(!sam.paths.data_dir.exists(), "SAM's own data is gone");

        // A folder SAM creates for itself is marked and is SAM's to remove.
        let mut own = Sam::with_paths(Paths::rooted(&tmp.path().join("sam2"))).unwrap();
        own.config.extraction.location = tmp.path().join("Unpacked").to_string_lossy().into_owned();
        own.unpack_root().unwrap();
        assert!(own.unpack_root_is_sams());
        let u = own.uninstall(false, true).unwrap();
        assert!(
            u.dirs.contains(&tmp.path().join("Unpacked")),
            "{:?}",
            u.dirs
        );
    }

    /// Updates are downloaded into a fresh folder inside SAM's data folder
    /// that only SAM's user can enter (audit U-H4): never the AppImage's
    /// folder, never one with leftovers.
    #[test]
    fn a_download_folder_is_fresh_private_and_sams_own() {
        let tmp = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(tmp.path())).unwrap();
        let leftover = sam.paths.data_dir.join("downloads").join("appimage-x-1");
        fs::create_dir_all(&leftover).unwrap();
        fs::write(leftover.join("planted"), "x").unwrap();
        let d = sam.download_folder("appimage-x-1").unwrap();
        assert_eq!(d, leftover);
        assert!(d.starts_with(&sam.paths.data_dir), "{}", d.display());
        assert_eq!(fs::read_dir(&d).unwrap().count(), 0, "no leftovers");
        for f in [&d, &sam.paths.data_dir.join("downloads")] {
            assert_eq!(fs::metadata(f).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

    /// Across file systems (a download in SAM's folder, the AppImage on
    /// another drive) a move is a copy: into a new file with the same
    /// permissions, never through a link planted at the target and never
    /// over a file that is there (audit U-H4: `fs::copy` followed links).
    #[test]
    fn a_move_across_drives_never_writes_through_a_link() {
        let here = std::env::temp_dir();
        let shm = std::path::Path::new("/dev/shm");
        let other =
            shm.is_dir() && fs::metadata(shm).unwrap().dev() != fs::metadata(&here).unwrap().dev();
        if !other {
            crate::contracts::not_here(
                "needs /dev/shm on another file system than the temp folder",
            );
            return;
        }
        let src_dir = tempfile::tempdir_in(shm).unwrap();
        let dst_dir = tempfile::tempdir_in(&here).unwrap();
        let src = src_dir.path().join("new.AppImage");
        let write_src = || {
            fs::write(&src, "new version").unwrap();
            fs::set_permissions(&src, fs::Permissions::from_mode(0o750)).unwrap();
        };

        write_src();
        let to = dst_dir.path().join("Tool.AppImage");
        move_file(&src, &to).unwrap();
        assert_eq!(fs::read_to_string(&to).unwrap(), "new version");
        assert_eq!(
            fs::metadata(&to).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert!(!src.exists(), "moved, not copied");

        // A link planted at the target: refused, the victim is untouched.
        write_src();
        let victim = dst_dir.path().join("victim.txt");
        fs::write(&victim, "the person's file").unwrap();
        let planted = dst_dir.path().join("Planted.AppImage");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        assert!(move_file(&src, &planted).is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "the person's file");
        assert!(src.exists(), "nothing lost when the move is refused");

        // A file that is already there is not overwritten.
        assert!(move_file(&src, &to).is_err());
        assert_eq!(fs::read_to_string(&to).unwrap(), "new version");
    }
}
