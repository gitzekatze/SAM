//! Keeping sandboxes current: re-extract, refresh, relocate, stop, remove,
//! uninstall, disk space and cleanup.

use super::*;

/// The moment after "Unpack Again" placed the new content and before it
/// saves the record, where a test lets another SAM process hold the record
/// lock; outside tests nothing happens here. A function of its own, so the
/// translation collector skips only it as test code.
fn before_closing_save() {
    #[cfg(test)]
    tests::before_closing_save();
}

impl Sam {
    // ------------------------------------------------------------ maintain

    /// Re-extract after an update or failure.
    /// Unpacks the AppImage again ("Unpack Again"). When its content changed
    /// and the change did not come from a SAM update, the app does not start
    /// until the person has looked at it: another app with access to the
    /// folder could have swapped the file, which would otherwise inherit the
    /// old app's permissions. The mark is saved before the new content is
    /// unpacked; when it cannot be saved, nothing is unpacked.
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
        let (_change, entry) =
            self.lock_for_change(&entry, &sam_core::i18n::tr("unpack it again"))?;
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
    /// a changed file unmarked. The mark is saved before the new content is
    /// unpacked; when it cannot be saved, nothing is unpacked.
    fn reextract_from(
        &self,
        query: &str,
        consent_fallback: bool,
        checked: &Checked<'_>,
    ) -> Result<AppEntry> {
        let entry = self.resolve(query)?;
        let (_change, mut entry) =
            self.lock_for_change(&entry, &sam_core::i18n::tr("unpack it again"))?;
        // Unpacking takes a while: only what it changes is saved onto the
        // record as it is then, so a switch changed in the window meanwhile
        // stays.
        let read = entry.clone();
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
        // Compared with what was unpacked last, not with the file's last
        // seen checksum: the change check and relocate update that one, so
        // a swapped file looked known (regression, audit U-H2).
        let changed_content = unpacked_sha256(&entry) != fp.sha256;
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
        if changed_content && !checked.sams_update {
            // The "look at it first" mark is saved before the new content
            // replaces the old one in the same folder: when SAM stops after
            // the swap, the closing save below fails (another SAM process
            // kept the record lock too long, a full disk) or the detection
            // after the unpack fails, the record still asks first, so the
            // new content does not start unconfirmed. Saved only once the
            // unpack is ready to start, so a failure before it leaves no
            // mark; when this save fails, nothing is unpacked and the
            // error says so. When the unpacking fails, the mark stays and
            // SAM asks once more about the old content.
            let name = sam_core::util::display_safe(entry.display_name(), 80);
            self.update_record(&entry.id, |f| f.content_changed_outside = true)
                .with_context(|| {
                    sam_core::i18n::trf(
                        "SAM did not unpack {app} again: it could not first save in the app's record that its new content must be looked at before it starts, so nothing was unpacked",
                        &[("app", &name)],
                    )
                })?;
        }
        match extract(&req, &mut log) {
            Ok(out) => {
                entry.appimage_type = info.kind;
                if changed_content {
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
                self.registry().save_changes(&read, &mut entry)?;
                return Err(e);
            }
        }
        before_closing_save();
        self.registry().save_changes(&read, &mut entry)?;
        Ok(entry)
    }

    pub fn redetect(&self, query: &str) -> Result<AppEntry> {
        let mut entry = self.resolve(query)?;
        let read = entry.clone();
        self.detect(&mut entry, &ProgressSink::default())?;
        self.registry().save_changes(&read, &mut entry)?;
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
            // A deep refresh reads the whole file: only what it finds is
            // saved onto the record as it is then.
            let read = a.clone();
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
                    note_seen_file(&mut a, new);
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
            reg.save_changes(&read, &mut a)?;
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
        let entry = self.resolve(query)?;
        // Held for the whole change, like an update or a go back: they
        // read and write the same record (review of the fix for R86).
        let (_change, entry) = self.lock_for_change(&entry, &sam_core::i18n::tr("relocate it"))?;
        // An update or go back stopped after it was recorded puts a version
        // in place at the old path, which may be gone (a renamed folder, an
        // unplugged drive): relocating ends that work instead. A go back's
        // copy, the only copy of the earlier version, becomes the named way
        // back; an update's download is dropped once the record no longer
        // names it (review of the fix for R86).
        let placing = entry.update_backup.as_ref().and_then(|b| b.placing.clone());
        let p = fs::canonicalize(new_path)?;
        let fp = fingerprint::compute(&p)?;
        // Half-written copies a stopped update or go back left next to the
        // old place would stay there for good (review of the fix for R89).
        remove_incoming_leftovers(&entry);
        let same = super::add::is_unpacked_content(&entry, &fp.sha256);
        let saved = self.registry().update(&entry.id, |e| {
            if let (Some(b), Some(pl)) = (e.update_backup.as_mut(), placing.as_ref()) {
                retire_placing(b, pl);
            }
            e.source_path = p.clone();
            note_seen_file(e, fp.clone());
            e.state = if same {
                AppState::Ready
            } else {
                AppState::Stale
            };
            if same {
                if let Some(x) = e.extraction.as_mut() {
                    x.source = fp.clone();
                }
            }
        })?;
        let saved = saved.with_context(|| {
            sam_core::i18n::trf("no registered app '{id}'", &[("id", &entry.id)])
        })?;
        if let Some(pl) = placing.filter(|pl| !pl.going_back) {
            let _ = fs::remove_file(&pl.file);
        }
        Ok(saved)
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
    /// Only the launches running when it begins are closed and waited for:
    /// one started meanwhile is left alone (review B2 S6, R85).
    /// Returns how many launches ran.
    pub fn stop(&self, query: &str) -> Result<usize> {
        let entry = self.resolve(query)?;
        // Only processes that really hold their launch's lock open, each
        // kept as a pidfd taken during that check: a process id reused by
        // an unrelated program is never touched, also when the closing
        // takes its full 25 seconds.
        let base = self.paths.runtime_dir(&entry.id);
        let mut runners = Vec::new();
        for p in self.running(&entry.id) {
            for e in fs::read_dir(&base).into_iter().flatten().flatten() {
                if crate::launch::launch_dir_pid(&e.file_name().to_string_lossy()) != Some(p) {
                    continue;
                }
                if let Some(runner) = Runner::holding(p, &e.path().join("running.lock")) {
                    let sandbox = fs::read_to_string(e.path().join(crate::launch::SANDBOX_PID))
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok());
                    // So the launch is recorded as closed, not as a failed
                    // start; its time tells the runner when the app was asked.
                    let _ = fs::write(e.path().join(crate::launch::STOP_MARKER), b"");
                    runners.push((runner, sandbox));
                    break;
                }
            }
        }
        if runners.is_empty() {
            return Ok(0);
        }
        for (r, sandbox) in &runners {
            match sandbox {
                Some(s) => super::ask_to_quit(r.pid(), *s),
                // Not started yet: the runner asks the app itself.
                None => r.signal(libc::SIGTERM),
            }
        }
        // Waits for the runners found above, not for every launch of the
        // app: a launch started meanwhile kept the closing waiting until it
        // failed (review B2 S6, R85).
        let wait = |secs: u64| {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            while std::time::Instant::now() < end {
                if runners.iter().all(|(r, _)| r.launch_ended()) {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            false
        };
        let grace = crate::launch::QUIT_GRACE.as_secs();
        if !wait(grace) {
            for (r, _) in &runners {
                r.signal(libc::SIGTERM);
            }
            // Longer than the runner's own grace time, in case it began
            // one anew (review 2026-11-23 F2: SIGKILL came after 3 seconds).
            if !wait(grace + 5) {
                for (r, _) in &runners {
                    r.signal(libc::SIGKILL);
                }
                if !wait(3) {
                    // What a killed runner left is cleared also here.
                    let _ = self.running(&entry.id);
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
        // One last look at the launches, as the waits took before: it
        // clears what a killed runner left (its folder, start files).
        let _ = self.running(&entry.id);
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

    /// Holds `entry`'s app for a change of its sandbox ([`crate::app_lock`])
    /// and returns its record as it is now, under the lock. Refused while
    /// the app runs, is starting, or is being changed elsewhere.
    pub(super) fn lock_for_change(
        &self,
        entry: &AppEntry,
        what: &str,
    ) -> Result<(crate::app_lock::ChangeLock, AppEntry)> {
        let Some(lock) = crate::app_lock::for_change(&self.paths, &entry.id)? else {
            self.ensure_not_running(entry, what)?;
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{app} is starting or being changed right now. Wait until that is done, then {what}.",
                    &[("app", &sam_core::util::display_safe(&entry.metadata.name, 80)), ("what", &what)]
                )
            );
        };
        self.ensure_not_running(entry, what)?;
        let fresh = self.registry().get(&entry.id)?.with_context(|| {
            sam_core::i18n::trf("no registered app '{id}'", &[("id", &entry.id)])
        })?;
        Ok((lock, fresh))
    }

    /// Holds `entry`'s app for a start ([`crate::app_lock`]) until the
    /// returned lock is dropped, and reads its record again into `entry`:
    /// what a change saved before the lock was taken (a new unpacked copy,
    /// its "look at it first" mark) is what this start checks and runs.
    /// Refused at once, without waiting, while the app's sandbox is being
    /// changed. Every way of starting an app takes it before
    /// [`Sam::check_before_start`] and keeps it until the start has ended.
    pub fn start_lock(&self, entry: &mut AppEntry) -> Result<crate::app_lock::StartLock> {
        let Some(lock) = crate::app_lock::for_start(&self.paths, &entry.id)? else {
            return Err(being_changed(entry));
        };
        *entry = self.registry().get(&entry.id)?.with_context(|| {
            sam_core::i18n::trf("no registered app '{id}'", &[("id", &entry.id)])
        })?;
        Ok(lock)
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
        let (_change, entry) =
            self.lock_for_change(&entry, &sam_core::i18n::tr("remove its sandbox"))?;
        // Half-written copies a stopped update or go back left in the
        // AppImage's folder (review of the fix for R89).
        remove_incoming_leftovers(&entry);
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
            // back when it is added again (see `kept_for_another`). The one
            // SAM unpacked, not the file last seen: after the change check
            // saw a swapped file, that was the swapped one, so the real file
            // was refused its data and a file made to match the id could
            // take it (review B2 S6, R96).
            let kept = self.paths.data_dir.join("kept");
            fs::create_dir_all(&kept)?;
            fs::write(kept.join(&entry.id), unpacked_sha256(&entry))?;
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

    /// Removes SAM from this computer: closes and removes, one after
    /// another, every app whose record it can read (menu entries SAM hid for
    /// them come back), SAM's menu entries, its own taskbar entry and icon, its
    /// runtime files and (unless `keep_data`) its settings, data and unpack
    /// folders; docs/guide.md, *Removing SAM*, says what stays. With
    /// `dry_run`, only lists what would be removed.
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
        let (_change, entry) =
            self.lock_for_change(&entry, &sam_core::i18n::tr("free its space"))?;
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
        // A start unpacks first: like the start itself it never waits for
        // a change of the sandbox (`app_lock`), it is refused at once.
        let Some(_change) =
            crate::app_lock::for_change_within(&self.paths, &entry.id, std::time::Duration::ZERO)?
        else {
            return Err(being_changed(entry));
        };
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
    /// An AppImage that changed outside SAM since it was unpacked is not
    /// checked (see [`crate::updates::check_unpacked`]).
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
            // Only the file SAM unpacked is checked: a swapped one would make
            // SAM ask a server of another app's choosing (review B2 S6, R88).
            // An app never unpacked (a first unpack failed) has nothing to
            // compare with: its record names the file it was added with, or,
            // when an earlier SAM saved it, possibly a swapped file its change
            // check saw, so it is not checked at all.
            let status = match &e.extraction {
                #[expect(clippy::disallowed_methods, reason = "way out: an app's update check")]
                Some(x) => crate::updates::check_unpacked(&e.source_path, &x.source),
                None => UpdateStatus {
                    state: sam_core::model::UpdateState::Failed,
                    detail: sam_core::i18n::tr(
                        "SAM has not unpacked this app yet, so it does not check it for updates. Use Unpack Again and look at the app first.",
                    ),
                    checked_at: now(),
                    ..Default::default()
                },
            };
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
    ///    AppImage's folder (written whole under a hidden name, then renamed
    ///    into place; the earlier backup goes only once the record names the
    ///    new one), and the sandbox is unpacked again from the checked
    ///    download, with its settings kept.
    pub fn update(&self, query: &str, accept_key_change: bool) -> Result<AppEntry> {
        let entry = self.resolve(query)?;
        self.forget_old_waiting();
        let (_change, entry) = self.lock_for_change(&entry, &sam_core::i18n::tr("update it"))?;
        // An update or go back stopped after it was recorded is finished
        // first (review B2 S6, R86, R89).
        remove_incoming_leftovers(&entry);
        let entry = self.finish_placing(&entry)?.unwrap_or(entry);
        if !entry.source_path.exists() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the AppImage {file} is missing; relocate it first",
                    &[("file", &tildify(&entry.source_path))]
                )
            );
        }
        // An interrupted go back left the earlier version aside; an update
        // would delete it with the old backups (review B2 S6, R86).
        settle_interrupted_going_back(&entry)?;
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
        #[expect(clippy::disallowed_methods, reason = "way out: an app's update")]
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
        // An app never unpacked (a first unpack failed) has nothing SAM
        // unpacked to compare with, so its file is not updated, as it is
        // not checked for updates: a record an earlier SAM saved may name a
        // swapped file there, whose update information would then decide
        // what runs with this app's permissions.
        if entry.extraction.is_none() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "SAM has not unpacked {app} yet, so it does not update it. Use Unpack Again and look at the app first.",
                    &[("app", &sam_core::util::display_safe(entry.display_name(), 80))]
                )
            );
        }
        // The installed version as SAM checked it. Its update information
        // names where updates come from, so it must be the file SAM
        // unpacked: another app could have put its own AppImage there,
        // naming its own server (review 2026-11-23, U-1).
        let installed = work.join(".installed");
        fs::copy(&old, &installed)?;
        // It becomes the kept version: on the disk before any record names
        // it (review B2 S6, R89).
        fs::File::open(&installed)?.sync_all()?;
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
        #[expect(clippy::disallowed_methods, reason = "way out: an app's update source")]
        let newest = crate::updates::newest(&installed)?;
        let Some(p) = newest else {
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
            #[expect(
                clippy::disallowed_methods,
                reason = "way out: an app's update download"
            )]
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
        // for good (review 2026-11-23, U-3). A record checked before SAM
        // kept the signing time (before 2026-11-18) cannot tell an older
        // release from a newer one: the installed copy, checked again, gives
        // the time when it still shows the recorded key (review B2 S6, R94).
        let before_sig = match &entry.signature {
            Some(s)
                if s.state == sam_core::model::SignatureState::Valid && s.fingerprint.is_some() =>
            {
                if s.signed_at.is_some() {
                    s.clone()
                } else {
                    let again = self.check_signature(&installed, false);
                    if again.state == sam_core::model::SignatureState::Valid
                        && again.fingerprint == s.fingerprint
                    {
                        again
                    } else {
                        s.clone()
                    }
                }
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
        // The same key, but a signing time could not be read: SAM cannot
        // tell whether the download is an older version, so it asks, with a
        // question of its own, the same way as for a signature it cannot
        // check (review B2 S6, R94).
        if signing_time_unknown(Some(&before_sig), &new_sig)
            && !consented_to("signing-time-unknown")
        {
            return Err(ask(
                "signing-time-unknown",
                sam_core::i18n::tr(
                    "The new file is signed with the same key as the installed version, but SAM could not read when one of them was signed, so it cannot tell whether the download is an older version, which may have security holes that were fixed since. Accept the update only if you trust its source: SAM then installs exactly this file, never one downloaded later.",
                ),
            ));
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
        //
        // The order keeps a way back at every moment (review B2 S6, R89).
        // Before, the earlier backup and the person's AppImage were deleted
        // first and the new copy written afterwards: a crash, a power loss
        // or a full disk in between left no AppImage (or half of one) and a
        // record that named a deleted backup. Now the AppImage's folder
        // always holds the complete old file or the complete new one, and
        // the earlier backup goes only once the record names the new one;
        // a failure before that changes nothing.
        let backups = self.paths.data_dir.join("update-backups").join(&entry.id);
        fs::create_dir_all(&backups)?;
        if let Some(all) = backups.parent() {
            sync_dir(all);
        }
        // A fresh folder for the new backup, next to the earlier one.
        let fresh = backups.join(format!("kept-{}", unique_suffix()));
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&fresh)?;
        }
        let backup = fresh.join(&old_name);
        if let Err(e) = move_file(&installed, &backup) {
            let _ = remove_tree(&fresh);
            return Err(e);
        }
        // The checked download waits next to it until it is unpacked: a
        // stop after the record is saved is finished from this copy
        // (`finish_placing`), and SAM's download folder is cleared by the
        // next update.
        let new_copy = fresh.join(PLACING_NAME);
        let kept_new =
            move_file(&tmp, &new_copy).and_then(|()| Ok(fs::File::open(&new_copy)?.sync_all()?));
        if let Err(e) = kept_new {
            let _ = remove_tree(&fresh);
            return Err(e);
        }
        sync_dir(&fresh);
        sync_dir(&backups);
        // The new copy is written whole under a hidden name in the same
        // folder; only a rename, which is complete or not done at all, gives
        // it the AppImage's name.
        let incoming = incoming_name(&dir, &entry.id);
        let placed = match place_copy(&new_copy, &incoming, old_mode | 0o500) {
            Ok(fp) => fp,
            Err(e) => {
                let _ = remove_tree(&fresh);
                return Err(e.context(sam_core::i18n::tr("putting the new version in place")));
            }
        };
        // Undoes what this update did before its record was saved.
        let give_up = |placed_at: &Path| {
            let _ = fs::remove_file(placed_at);
            let _ = remove_tree(&fresh);
        };
        // The way back is recorded before unpacking: if unpacking the new
        // version fails, the old one can still be put back (audit U-L2).
        let way_back = UpdateBackup {
            file: backup,
            original_path: old.clone(),
            replaced_at: now(),
            sha256: Some(installed_sha256),
            placed_sha256: Some(new_sha256.clone()),
            // What is being put in place, until it is unpacked (review B2
            // S6, R89): a stop after the save is finished from it.
            placing: Some(sam_core::model::Placing {
                file: new_copy.clone(),
                sha256: new_sha256,
                to: target.clone(),
                checked: true,
                going_back: false,
            }),
        };
        let save = || {
            self.registry().update(&entry.id, |f| {
                f.source_path = target.clone();
                f.signature = Some(before_sig.clone());
                f.update_backup = Some(way_back.clone());
            })
        };
        if target == old {
            // The same name: the record comes first, while the old file is
            // still in place, and the rename then replaces it in one step.
            // A record saved without the rename names a backup of that very
            // old file, so the way back still works.
            if let Err(e) = save() {
                give_up(&incoming);
                return Err(e);
            }
            if let Err(e) = fs::rename(&incoming, &target) {
                let restored = self.registry().update(&entry.id, |f| {
                    f.source_path = old.clone();
                    f.signature = entry.signature.clone();
                    f.update_backup = entry.update_backup.clone();
                });
                if restored.is_ok() {
                    give_up(&incoming);
                }
                return Err(anyhow::Error::from(e)
                    .context(sam_core::i18n::tr("putting the new version in place")));
            }
            sync_dir(&dir);
        } else {
            // Another name: the new file takes it (never replacing a file
            // that appeared there meanwhile), the record follows, and the
            // old file goes last. Until then both are complete.
            if let Err(e) = rename_noreplace(&incoming, &target) {
                give_up(&incoming);
                return Err(anyhow::Error::from(e)
                    .context(sam_core::i18n::tr("putting the new version in place")));
            }
            sync_dir(&dir);
            if let Err(e) = save() {
                give_up(&target);
                sync_dir(&dir);
                return Err(e);
            }
            // The update is done and recorded; an old file that stays
            // behind is a second complete copy, nothing is lost.
            let _ = fs::remove_file(&old);
            sync_dir(&dir);
        }
        // Only now is the earlier backup no longer anyone's way back.
        forget_earlier_backups(&backups, &fresh);
        let unpacked = self.reextract_as(
            &entry.id,
            false,
            Some(&Checked {
                file: &new_copy,
                placed,
                sams_update: true,
            }),
        );
        let mut done = way_back;
        done.placing = None;
        let e = match unpacked {
            Ok(e) => e,
            Err(err) => {
                // A failure, not a stop: the way back stays, nothing is
                // left to finish. The copy goes only once no record names
                // it.
                if self
                    .registry()
                    .update(&entry.id, |f| {
                        f.update_backup = Some(done.clone());
                    })
                    .is_ok()
                {
                    let _ = fs::remove_file(&new_copy);
                }
                return Err(err);
            }
        };
        let status = UpdateStatus {
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
        };
        let e = self.update_record(&e.id, |f| {
            f.update_backup = Some(done);
            f.update = Some(status);
        })?;
        let _ = fs::remove_file(&new_copy);
        Ok(e)
    }

    /// Goes back to the version an update replaced. The newer file is kept
    /// in its place, so going back can itself be undone.
    pub fn undo_update(&self, query: &str) -> Result<AppEntry> {
        let entry = self.resolve(query)?;
        let (_change, entry) = self.lock_for_change(&entry, &sam_core::i18n::tr("go back"))?;
        remove_incoming_leftovers(&entry);
        // A go back stopped after it was recorded is finished, and that is
        // this go back; a stopped update is finished, then SAM goes back
        // (review B2 S6, R86, R89).
        let was_going_back = entry
            .update_backup
            .as_ref()
            .and_then(|b| b.placing.as_ref())
            .is_some_and(|p| p.going_back);
        let entry = match self.finish_placing(&entry)? {
            Some(e) if was_going_back => return Ok(e),
            Some(e) => e,
            None => entry,
        };
        settle_interrupted_going_back(&entry)?;
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
        // A complete copy of the earlier version that a go back stopped
        // between placing it and saving the record left there: the same
        // file is about to be put there again, so it is removed just before
        // (after every check).
        let stray = back_to.exists()
            && back_to != entry.source_path
            && b.sha256.is_some()
            && fs::symlink_metadata(&back_to).is_ok_and(|m| m.file_type().is_file())
            && fingerprint::sha256_file(&back_to).ok() == b.sha256;
        if back_to.exists() && back_to != entry.source_path && !stray {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file} exists again; move it away first",
                    &[("file", &tildify(&back_to))]
                )
            );
        }
        let current = entry.source_path.clone();
        // Before the record is saved, nothing in the backup folder is
        // renamed or overwritten (review B2 S6, R86, and the reviews of its
        // fix): the earlier version stays at its kept name, is copied from
        // there, and the newer one is kept in a fresh folder. A stop or a
        // failure before the save leaves only a fresh folder and a hidden
        // incoming file, which the next update or go back removes. Before,
        // the earlier version stepped aside to `.going-back` and the newer
        // copy could take its name, and a stop or two failing copies lost
        // it or blocked every later go back.
        let root = self.paths.data_dir.join("update-backups").join(&entry.id);
        fs::create_dir_all(&root)?;
        if let Some(all) = root.parent() {
            sync_dir(all);
        }
        let fresh = root.join(format!("kept-{}", unique_suffix()));
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&fresh)?;
        }
        let keep = fresh.join(current.file_name().context(sam_core::i18n::tr("no name"))?);
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
        let give_up = || {
            let _ = remove_tree(&fresh);
        };
        let mut kept_sha256 = None;
        if current.exists() {
            if let Err(e) = place_copy(&current, &keep, current_mode) {
                give_up();
                return Err(e);
            }
            let sha = fingerprint::sha256_file(&keep).ok();
            let known = sha.as_deref().is_some_and(|s| {
                s == unpacked_sha256(&entry) || Some(s) == b.placed_sha256.as_deref()
            });
            if !known {
                give_up();
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "{file} changed outside SAM since it was last unpacked, so SAM does not go back: another program may have replaced it. Use Unpack Again and look at the app first.",
                        &[("file", &tildify(&current))]
                    )
                );
            }
            kept_sha256 = sha;
        }
        // Only a version SAM checked when it kept it counts as SAM's own; one
        // kept by an older SAM (or changed since) asks for a review.
        let earlier_sha256 = match fingerprint::sha256_file(&b.file) {
            Ok(sha) => sha,
            Err(e) => {
                give_up();
                return Err(e);
            }
        };
        let earlier_checked = b.sha256.as_deref() == Some(earlier_sha256.as_str());
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&b.file)
                .map(|m| m.permissions().mode())
                .unwrap_or(0o755)
                & 0o777
        };
        // Like an update, the earlier version is written whole under a
        // hidden name and then renamed into place, so the AppImage's folder
        // always holds one complete version (review B2 S6, R89).
        let dir = back_to.parent().context(sam_core::i18n::tr("no folder"))?;
        let incoming = incoming_name(dir, &entry.id);
        let placed = match place_copy(&b.file, &incoming, mode) {
            Ok(fp) => fp,
            Err(e) => {
                give_up();
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
            file: keep.clone(),
            original_path: current.clone(),
            replaced_at: now(),
            sha256: kept_sha256,
            placed_sha256: if earlier_checked {
                b.sha256.clone()
            } else {
                None
            },
            // What is being put in place, until it is unpacked: SAM's own
            // copy stays where it is, and a stop after the save is finished
            // from it. Before, a stop between the save and the rename left
            // it named by no record, and the next run deleted it (review B2
            // S6, R86).
            placing: Some(sam_core::model::Placing {
                file: b.file.clone(),
                sha256: earlier_sha256,
                to: back_at.clone(),
                checked: earlier_checked,
                going_back: true,
            }),
        };
        // The newer copy is on the disk before the record names it.
        sync_dir(&fresh);
        sync_dir(&root);
        let save = || {
            self.registry().update(&entry.id, |f| {
                f.source_path = back_at.clone();
                f.update_backup = Some(way_forward.clone());
            })
        };
        if back_to == current {
            // The same name: the record first, then one rename replaces the
            // current file (see `update_in`).
            if let Err(e) = save() {
                let _ = fs::remove_file(&incoming);
                give_up();
                return Err(e);
            }
            if let Err(e) = fs::rename(&incoming, &back_to) {
                let restored = self.registry().update(&entry.id, |f| {
                    f.source_path = current.clone();
                    f.update_backup = Some(b.clone());
                });
                if restored.is_ok() {
                    let _ = fs::remove_file(&incoming);
                    give_up();
                }
                return Err(anyhow::Error::from(e).context(sam_core::i18n::tr("go back")));
            }
            sync_dir(dir);
        } else {
            // Another name: the earlier version takes it, the record
            // follows, and the current file goes last. A stop before the
            // save leaves a complete copy of the earlier version there,
            // which the next go back takes as its own (see above); a record
            // that named a file not yet in place would lose the app instead.
            if stray {
                let _ = fs::remove_file(&back_to);
            }
            if let Err(e) = rename_noreplace(&incoming, &back_to) {
                let _ = fs::remove_file(&incoming);
                give_up();
                return Err(anyhow::Error::from(e).context(sam_core::i18n::tr("go back")));
            }
            sync_dir(dir);
            if let Err(e) = save() {
                let _ = fs::remove_file(&back_to);
                sync_dir(dir);
                give_up();
                return Err(e);
            }
            // Recorded; a current file that stays behind is a second
            // complete copy of the newer version, nothing is lost.
            let _ = fs::remove_file(&current);
            sync_dir(dir);
        }
        // Recorded and in place: unpacked from SAM's own copy, which the
        // record names until then; the old backup folder goes only after.
        let unpacked = if earlier_checked {
            self.reextract_as(
                &entry.id,
                false,
                Some(&Checked {
                    file: &b.file,
                    placed,
                    sams_update: true,
                }),
            )
        } else {
            self.reextract_as(&entry.id, false, None)
        };
        let mut done = way_forward;
        done.placing = None;
        let e = match unpacked {
            Ok(e) => e,
            Err(err) => {
                // A failure, not a stop: nothing is left to finish. The
                // earlier backup goes only once no record names it.
                if self
                    .registry()
                    .update(&entry.id, |f| {
                        f.update_backup = Some(done.clone());
                    })
                    .is_ok()
                {
                    forget_earlier_backups(&root, &fresh);
                }
                return Err(err);
            }
        };
        let e = self.update_record(&e.id, |f| {
            f.update_backup = Some(done);
            f.update = None;
        })?;
        forget_earlier_backups(&root, &fresh);
        Ok(e)
    }

    /// Finishes an update or a go back that was recorded but stopped before
    /// its version was unpacked (`UpdateBackup::placing`; review B2 S6, R86,
    /// R89): the version goes in place from SAM's own copy, checked by its
    /// SHA-256 (never from a hidden incoming file in the AppImage's folder,
    /// which another app can swap), is unpacked, and the mark is cleared.
    /// `None` when nothing waits. A mark that does not point into this
    /// app's backup folder and at the app's own file (a record changed
    /// outside SAM) is dropped without acting on it; a copy that is gone
    /// or changed is reported once.
    fn finish_placing(&self, entry: &AppEntry) -> Result<Option<AppEntry>> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Some(p) = entry.update_backup.as_ref().and_then(|b| b.placing.clone()) else {
            return Ok(None);
        };
        let root = self.paths.data_dir.join("update-backups").join(&entry.id);
        let clear = || {
            self.registry().update(&entry.id, |f| {
                if let Some(b) = f.update_backup.as_mut() {
                    b.placing = None;
                }
            })
        };
        let in_backups = fs::canonicalize(&root)
            .is_ok_and(|r| fs::canonicalize(&p.file).is_ok_and(|f| f.starts_with(&r)));
        if !in_backups {
            clear()?;
            return Ok(None);
        }
        if p.to != entry.source_path {
            // The app is somewhere else now (a record changed outside SAM):
            // nothing is put anywhere. An earlier version a go back was
            // putting in place stays as the named way back, never deleted
            // as an unnamed backup (review of the fix for R86); an update's
            // download is simply dropped, the way back it had stays.
            self.registry().update(&entry.id, |f| {
                if let Some(b) = f.update_backup.as_mut() {
                    retire_placing(b, &p);
                }
            })?;
            if !p.going_back {
                let _ = fs::remove_file(&p.file);
            }
            return Ok(None);
        }
        if fingerprint::sha256_file(&p.file).ok().as_deref() != Some(p.sha256.as_str()) {
            clear()?;
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "An earlier update or go back was stopped before it finished, and SAM's own copy of the version it was putting in place ({file}) is gone or changed, so SAM cannot finish it. The app's file stays as it is; use Unpack Again and look at the app first.",
                    &[("file", &tildify(&p.file))]
                )
            );
        }
        let in_place = fs::symlink_metadata(&p.to).is_ok_and(|m| m.file_type().is_file())
            && fingerprint::sha256_file(&p.to).ok().as_deref() == Some(p.sha256.as_str());
        let placed = if in_place {
            let m = fs::symlink_metadata(&p.to)?;
            Fingerprint {
                size: m.len(),
                mtime: m.mtime(),
                inode: m.ino(),
                device: m.dev(),
                sha256: String::new(),
            }
        } else {
            let dir = p.to.parent().context(sam_core::i18n::tr("no folder"))?;
            let mode = fs::metadata(&p.file)?.permissions().mode() & 0o777;
            let mode = if p.going_back { mode } else { mode | 0o500 };
            let incoming = incoming_name(dir, &entry.id);
            let fp = place_copy(&p.file, &incoming, mode)?;
            if let Err(e) = fs::rename(&incoming, &p.to) {
                let _ = fs::remove_file(&incoming);
                return Err(anyhow::Error::from(e)
                    .context(sam_core::i18n::tr("putting the new version in place")));
            }
            sync_dir(dir);
            fp
        };
        let unpacked = if p.checked {
            self.reextract_as(
                &entry.id,
                false,
                Some(&Checked {
                    file: &p.file,
                    placed,
                    sams_update: true,
                }),
            )
        } else {
            self.reextract_as(&entry.id, false, None)
        };
        let way = self
            .registry()
            .get(&entry.id)?
            .and_then(|e| e.update_backup)
            .map(|b| b.file);
        let tidy = || {
            let _ = fs::remove_file(&p.file);
            if let Some(keep) = way.as_deref().and_then(|w| top_in(&root, w)) {
                forget_earlier_backups(&root, &keep);
            }
        };
        let e = match unpacked {
            Ok(e) => e,
            Err(err) => {
                clear()?;
                tidy();
                return Err(err);
            }
        };
        let e = self.update_record(&e.id, |f| {
            if let Some(b) = f.update_backup.as_mut() {
                b.placing = None;
            }
            f.update = None;
        })?;
        tidy();
        Ok(Some(e))
    }

    /// Updates SAM's own AppImage (`appimage`, from `$APPIMAGE`): checks the
    /// update source written into it, and unless `check_only` downloads the
    /// new version (only the changed parts when possible), checks it, and
    /// puts it next to the old one under its published name. The old file
    /// moves to `<data>/update-backups/sam/`. SAM must be restarted. It
    /// works from a copy of `appimage` in SAM's own folder, and only one
    /// update of SAM runs at a time; a second is refused at once.
    pub fn self_update(&self, appimage: &Path, check_only: bool) -> Result<SelfUpdate> {
        let keys = crate::release_key::RELEASE_KEYS;
        #[expect(clippy::disallowed_methods, reason = "way out: SAM's own update")]
        let r = self.self_update_with_keys(appimage, check_only, keys);
        r
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
        if check_only {
            // A check only reads the update information and the checksum
            // (nothing is mapped) and writes nothing, so it needs neither
            // the lock nor a copy.
            #[expect(clippy::disallowed_methods, reason = "way out: SAM's own update check")]
            return self.self_update_from(appimage, appimage, true, keys);
        }
        // One update of SAM at a time, from start to end: a second one (the
        // window and the command line at once) shares `downloads/sam` and
        // `update-backups/sam` and would delete the first one's files, the
        // backup of the old SAM among them (review B2 S6, R95).
        let Some(_held) = crate::app_lock::for_self_update(&self.paths)? else {
            bail!(
                "{}",
                sam_core::i18n::tr(
                    "SAM is already updating itself. Wait until that is done, then try again."
                )
            );
        };
        // Like an app's update, SAM's update works from a copy of its
        // AppImage in SAM's own folder, which nothing else can change: the
        // update information, the checksum, the old blocks of a partial
        // download (mapped into memory, where a file shortened meanwhile
        // crashes SAM) and the running version's signature all come from
        // that copy. The file in the person's folder is only moved into
        // the backups at the end (review B2 S6, R87).
        let work = self.download_folder("sam.installed")?;
        let installed = work.join("sam.AppImage");
        let copied = fingerprint::copy_with_fingerprint(appimage, &installed, 0o700);
        let result = match copied {
            #[expect(clippy::disallowed_methods, reason = "way out: SAM's own update")]
            Ok(_) => self.self_update_from(appimage, &installed, false, keys),
            Err(e) => Err(e),
        };
        let _ = remove_tree(&work);
        result
    }

    /// [`self_update_with_keys`](Self::self_update_with_keys), reading SAM's
    /// running version from `installed` (the copy, or `appimage` itself for
    /// a check); `appimage` is the file that is replaced.
    fn self_update_from(
        &self,
        appimage: &Path,
        installed: &Path,
        check_only: bool,
        keys: &[&str],
    ) -> Result<SelfUpdate> {
        #[expect(clippy::disallowed_methods, reason = "way out: SAM's update source")]
        let newest = crate::updates::newest(installed)?;
        let Some(p) = newest else {
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
        #[expect(clippy::disallowed_methods, reason = "way out: SAM's update download")]
        let fetched = crate::updates::download_update(&p, installed, &tmp)?;
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
            let running = self.check_signature(installed, true);
            if let Some((was, now)) = older_signed_version(Some(&running), &new_sig) {
                return Err(older_version_error(was, now).into());
            }
            // A time that cannot be read cannot rule out an older release;
            // SAM does not replace itself on a guess (review B2 S6, R94).
            if signing_time_unknown(Some(&running), &new_sig) {
                bail!(
                    "{}",
                    sam_core::i18n::tr(
                        "SAM did not update itself: the download is signed with SAM's release key, but SAM could not read when it or the running version was signed, so it cannot tell whether the download is an older release. It was deleted and nothing changed."
                    )
                );
            }
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
            let backup_dir = self.paths.data_dir.join("update-backups").join("sam");
            if backup_dir.exists() {
                remove_tree(&backup_dir)?;
            }
            fs::create_dir_all(&backup_dir)?;
            // A running AppImage can be moved: the old SAM keeps running
            // from its mounted image until it exits. The backup is the file
            // SAM ran from, whatever is at `appimage` by now, not the copy
            // checked above: it is kept only for going back by hand.
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
/// A start refused because `entry`'s sandbox is being changed (code
/// `app-being-changed`): it is temporary, nothing needs repairing.
fn being_changed(entry: &AppEntry) -> anyhow::Error {
    sam_core::error::CodedError::new(
        "app-being-changed",
        sam_core::i18n::trf(
            "{app} is being changed right now (unpacked again, updated or removed). Start it when that is done.",
            &[("app", &sam_core::util::display_safe(&entry.metadata.name, 80))],
        ),
    )
    .into()
}

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

/// Notes `fp`, the file now at the app's place, on the record. For an app with
/// nothing unpacked yet (its first unpack failed), the record's `source` is
/// also what a later unpack compares with ([`unpacked_sha256`]): recording
/// a file with other content there would let *Unpack Again* take a swapped
/// file for the one the person added and unpack it unmarked. Such a file is
/// not recorded; the app still shows that its file changed (the caller sets
/// the state), and the first unpack marks the new content, as for an app
/// that was unpacked.
fn note_seen_file(app: &mut AppEntry, fp: Fingerprint) {
    if app.extraction.is_some() || app.source.sha256 == fp.sha256 {
        app.source = fp;
    }
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

/// The name the earlier version took in the backup folder while an older
/// SAM went back to it; going back no longer renames anything there.
const GOING_BACK: &str = ".going-back";

/// Settles a [`GOING_BACK`] file that a go back of an older SAM (or of an
/// earlier state of this fix) left next to the kept file of `entry`'s way
/// back; going back no longer moves anything there (review B2 S6, R86, and
/// the reviews of its fix). A file SAM can tell apart is repaired: one equal
/// to both the app's current file and the version that go back put in
/// place is a second copy and is deleted (equal to the current file alone
/// is not enough: another app can drop a public copy of the earlier version
/// there); one equal to the kept version whose kept name is free goes back
/// to that name. Otherwise the file at the kept name may be the newer copy,
/// and going on would replace the earlier version with it: going back and
/// updating stop, change nothing and say where both files are.
fn settle_interrupted_going_back(entry: &AppEntry) -> Result<()> {
    let Some(b) = &entry.update_backup else {
        return Ok(());
    };
    let earlier = b.file.with_file_name(GOING_BACK);
    let Ok(md) = fs::symlink_metadata(&earlier) else {
        return Ok(());
    };
    let sha = if md.file_type().is_file() {
        fingerprint::sha256_file(&earlier).ok()
    } else {
        None
    };
    if let Some(sha) = sha.as_deref() {
        if b.placed_sha256.as_deref() == Some(sha)
            && fingerprint::sha256_file(&entry.source_path).ok().as_deref() == Some(sha)
            && fs::remove_file(&earlier).is_ok()
        {
            return Ok(());
        }
        if fs::symlink_metadata(&b.file).is_err()
            && b.sha256.as_deref() == Some(sha)
            && rename_noreplace(&earlier, &b.file).is_ok()
        {
            return Ok(());
        }
    }
    bail!(
        "{}",
        sam_core::i18n::trf(
            "An earlier attempt to go back was interrupted: the earlier version is still at {earlier}, and {file} may hold the newer one. SAM changes nothing, so that neither version is lost. Move the version you want to keep out of SAM's backup folder and relocate the app to it; once {earlier} is gone, SAM goes back and updates again.",
            &[
                ("earlier", &tildify(&earlier)),
                ("file", &tildify(&b.file))
            ]
        )
    );
}

/// Renames `from` to `to` only when nothing is at `to` (not even a link),
/// in one step. Where the file system cannot do that (`renameat2` with
/// `RENAME_NOREPLACE` is missing), SAM looks first and then renames.
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
    };
    let (f, t) = (c(from)?, c(to)?);
    // SAFETY: both are valid NUL-terminated paths that live across the
    // call; renameat2 only reads them.
    let r = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            f.as_ptr(),
            libc::AT_FDCWD,
            t.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if r == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) => {
            if fs::symlink_metadata(to).is_ok() {
                return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
            }
            fs::rename(from, to)
        }
        _ => Err(e),
    }
}

/// A hidden name in `dir` for a file that is written there whole before a
/// rename gives it its real name. Unique, so it never meets a leftover or a
/// file another program put there; [`place_copy`] refuses one anyway.
fn incoming_name(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{}{}", incoming_prefix(id), unique_suffix()))
}

/// How the names of `id`'s incoming files begin.
fn incoming_prefix(id: &str) -> String {
    format!(".sam-incoming-{id}-")
}

/// Removes incoming files of `entry`'s app that a SAM stopped while
/// writing left in the AppImage's folder: hidden, executable and as large
/// as the app (review of the fix for R89). Only names SAM gives exactly
/// (the app's prefix, then `<process>-<hex time>`), only files and links,
/// and a link is removed itself, never followed. Called under the app's
/// lock, so no other change of this app is writing one.
fn remove_incoming_leftovers(entry: &AppEntry) {
    let Some(dir) = entry.source_path.parent() else {
        return;
    };
    let prefix = incoming_prefix(&entry.id);
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
            continue;
        };
        let ours = rest.split_once('-').is_some_and(|(pid, time)| {
            !pid.is_empty()
                && pid.bytes().all(|c| c.is_ascii_digit())
                && !time.is_empty()
                && time.bytes().all(|c| c.is_ascii_hexdigit())
        });
        if ours && e.file_type().is_ok_and(|t| t.is_file() || t.is_symlink()) {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// A name part no other run uses: the process and the time in nanoseconds.
fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}-{nanos:x}", std::process::id())
}

/// Writes a folder's list of names to the disk, so that a rename in it
/// survives a power loss. Where that fails, the rename itself still stands.
fn sync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Ends the work `p` describes without putting anything in place, when the
/// app's file is no longer where `p` puts it (relocated, or a record changed
/// outside SAM): a go back's copy, the only copy of the earlier version,
/// becomes the named way back; for an update only the mark goes (its
/// download is the caller's to delete once the record is saved), and the
/// way back it had stays (review of the fix for R86).
fn retire_placing(b: &mut UpdateBackup, p: &sam_core::model::Placing) {
    if p.going_back {
        *b = UpdateBackup {
            file: p.file.clone(),
            original_path: p.to.clone(),
            replaced_at: now(),
            sha256: p.checked.then(|| p.sha256.clone()),
            placed_sha256: None,
            placing: None,
        };
    } else {
        b.placing = None;
    }
}

/// The name SAM's checked download takes in the new backup's folder while
/// an update puts it in place and unpacks it.
const PLACING_NAME: &str = ".sam-placing";

/// The entry directly in `root` that holds `file` (or is it).
fn top_in(root: &Path, file: &Path) -> Option<PathBuf> {
    let rest = file.strip_prefix(root).ok()?;
    rest.components().next().map(|c| root.join(c.as_os_str()))
}

/// Deletes everything in an app's backup folder `backups` except `keep`:
/// the earlier backup and leftovers of interrupted runs. Called only once
/// the record names the backup in `keep` (review B2 S6, R89).
fn forget_earlier_backups(backups: &Path, keep: &Path) {
    let Ok(entries) = fs::read_dir(backups) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p == keep {
            continue;
        }
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = remove_tree(&p);
        } else {
            let _ = fs::remove_file(&p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::rc::Rc;

    thread_local! {
        /// What another SAM process does after "Unpack Again" placed the
        /// new content and before it saves the record.
        static AT_CLOSING_SAVE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    /// Called by `reextract_from` right before its closing save.
    pub(super) fn before_closing_save() {
        if let Some(h) = AT_CLOSING_SAVE.with(|h| h.borrow_mut().take()) {
            h();
        }
    }

    /// "Unpack Again" of an AppImage whose content changed outside SAM
    /// places the new content in the same folder before it saves the
    /// record. When that closing save fails (here: another SAM process
    /// keeps the record lock longer than SAM waits), the record still asks
    /// first and the start is refused. Before, the mark was only in the
    /// closing save, so the new content started with the old settings and
    /// was never asked about. The start's warning about the changed
    /// AppImage then says the unpacked copy may not be that file; before,
    /// it said the previous version runs, while the new content ran.
    #[test]
    fn a_changed_appimage_still_asks_first_when_the_closing_save_fails() {
        if crate::doctor::bwrap_functional(&HostInfo::probe()).is_err() {
            crate::contracts::skip(
                "bubblewrap is not functional here (SAM unpacks inside a sandbox)",
            )
            .unwrap_or_else(|e| panic!("{e}"));
            return;
        }
        use sam_intake::testkit::{build, FixtureSpec};
        let t = tempfile::tempdir().unwrap();
        let img = t.path().join("Tool.AppImage");
        build(&img, &FixtureSpec::hello("Tool")).unwrap();
        let paths = Paths::rooted(&t.path().join("sam"));
        let sam = Sam::with_paths(paths.clone()).unwrap();
        let id = sam
            .add(
                &img,
                &AddOptions {
                    accept: true,
                    launcher: Some(false),
                    ..Default::default()
                },
            )
            .unwrap()
            .entry
            .id;
        let mut spec = FixtureSpec::hello("Tool");
        spec.comment = "a different file under the same name".into();
        build(&img, &spec).unwrap();
        // Another SAM process takes the record lock once the new content is
        // in place, and keeps it.
        let held: Rc<RefCell<Option<fs::File>>> = Rc::default();
        let holder = held.clone();
        let lock_file = paths.apps_dir().join(".records.lock");
        AT_CLOSING_SAVE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&lock_file)
                    .unwrap();
                f.lock().unwrap();
                *holder.borrow_mut() = Some(f);
            }))
        });
        let err = sam
            .reextract(&id, false)
            .expect_err("the closing save was made without the record lock");
        assert!(
            format!("{err:#}").contains("kept the app records locked"),
            "{err:#}"
        );
        drop(
            held.borrow_mut()
                .take()
                .expect("the other process held the lock"),
        );
        let e = sam.resolve(&id).unwrap();
        assert!(
            e.content_changed_outside,
            "the record of the newly unpacked content asks first"
        );
        let errors = crate::launch::preflight(&e).0;
        assert!(
            errors
                .iter()
                .any(|m| m.contains("replaced by something other than a SAM update")),
            "the new content starts unconfirmed: {errors:?}"
        );
        // The unpacked copy holds the new content while the record still
        // names the file unpacked before: the start's warning about the
        // changed AppImage never says the previous version runs.
        let appdir = &e.extraction.as_ref().unwrap().appdir;
        let new_content_unpacked = fs::read_dir(appdir).unwrap().flatten().any(|d| {
            d.path().extension().is_some_and(|x| x == "desktop")
                && fs::read_to_string(d.path())
                    .is_ok_and(|s| s.contains("a different file under the same name"))
        });
        assert!(new_content_unpacked, "the new content is unpacked");
        // Both files were built within the same second at the same place:
        // a file put there at another time has another modification time,
        // which is what the start's quick look at the file compares.
        fs::File::options()
            .write(true)
            .open(&img)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(86_400))
            .unwrap();
        let warns = crate::launch::preflight(&e).1;
        let stale = warns
            .iter()
            .find(|w| w.code == "source-stale")
            .expect("the start warns that the AppImage changed");
        assert!(
            !stale.message.contains("previous version"),
            "the warning says the previous version runs, but the new content runs: {}",
            stale.message
        );
        assert!(
            stale.message.contains("may not be this file"),
            "{}",
            stale.message
        );
    }

    /// A change works on the app's record as it is once it holds the app,
    /// not on the copy read when the change was asked for: another change
    /// may have saved in between (review L2).
    #[test]
    fn a_change_works_on_the_record_as_it_is_under_the_lock() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let mut asked = AppEntry {
            id: "queued-1a2b".into(),
            ..Default::default()
        };
        sam.registry().save(&mut asked).unwrap();
        let mut saved = sam.registry().get(&asked.id).unwrap().unwrap();
        saved.source.sha256 = "0".repeat(64);
        sam.registry().save(&mut saved).unwrap();
        let (_change, entry) = sam.lock_for_change(&asked, "remove its sandbox").unwrap();
        assert_eq!(
            entry.source.sha256,
            "0".repeat(64),
            "as the other change left it"
        );
    }

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
