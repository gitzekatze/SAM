//! Keeping sandboxes current: re-extract, refresh, relocate, stop, remove,
//! uninstall, disk space and cleanup.

use super::*;

impl Sam {
    // ------------------------------------------------------------ maintain

    /// Re-extract after an update or failure.
    pub fn reextract(&self, query: &str, consent_fallback: bool) -> Result<AppEntry> {
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
        let info = inspect(&entry.source_path)?;
        if !info.is_appimage() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file} is no longer a valid AppImage",
                    &[("file", &tildify(&entry.source_path))]
                )
            );
        }
        let fp = fingerprint::compute(&entry.source_path)?;
        let root = self.extracted_root().join(&entry.id);
        let mut log = Vec::new();
        let req = ExtractRequest {
            source: &entry.source_path,
            info: &info,
            root: &root,
            limits: self.limits(),
            allow_fallback: consent_fallback && self.config.extraction.allow_fallback,
            isolation: self.extract_isolation()?,
        };
        match extract(&req, &mut log) {
            Ok(out) => {
                entry.appimage_type = info.kind;
                if entry.source.sha256 != fp.sha256 {
                    let new_sig = sam_detect::signature::check(&entry.source_path);
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
    /// `<runtime>/launch-<pid>-<time>/running.lock` locked while it runs;
    /// folders left by a killed runner are removed here.
    pub fn running(&self, id: &str) -> Vec<u32> {
        let mut pids = Vec::new();
        let Ok(rd) = fs::read_dir(self.paths.runtime_dir(id)) else {
            return pids;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(pid) = name
                .strip_prefix("launch-")
                .and_then(|r| r.split('-').next())
                .and_then(|p| p.parse::<u32>().ok())
            else {
                continue;
            };
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
                if e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("launch-{p}-"))
                    && holds_open(p, &e.path().join("running.lock"))
                {
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
        // SAFETY: kill takes plain integers; a process that is already gone only makes it fail.
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
            // The version an update replaced.
            let previous = self.paths.data_dir.join("update-backups").join(&entry.id);
            if previous.exists() {
                remove_tree(&previous)?;
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
            for d in [
                self.paths.config_dir.clone(),
                self.paths.data_dir.clone(),
                self.extracted_root(),
            ] {
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
        let ids: std::collections::HashSet<String> =
            self.registry().list()?.into_iter().map(|a| a.id).collect();
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
                if !ids.contains(&name) {
                    fs::remove_dir_all(e.path())?;
                    removed.push(e.path());
                }
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
        let entries = match query {
            Some(q) => vec![self.resolve(q)?],
            None => self.registry().list()?,
        };
        let reg = self.registry();
        let mut out = Vec::new();
        for mut e in entries {
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
            e.update = Some(status.clone());
            reg.save(&mut e)?;
            out.push((e.id.clone(), status));
        }
        Ok(out)
    }

    /// Downloads the newest published version of an app's AppImage and
    /// puts it in place of the old one:
    /// 1. download next to the old file (hidden, `.….sam-download`) and
    ///    check it against the published SHA-1;
    /// 2. it must be an AppImage, signed like the old one (or
    ///    `accept_key_change`);
    /// 3. the old file moves to `<data>/update-backups/<id>/` (so it is not
    ///    listed as a second AppImage), the new one takes its new name next
    ///    to it, and the sandbox is unpacked again with its settings kept.
    pub fn update(&self, query: &str, accept_key_change: bool) -> Result<AppEntry> {
        let entry = self.resolve(query)?;
        self.ensure_not_running(&entry, "update it")?;
        let old = entry.source_path.clone();
        if !old.exists() {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the AppImage {file} is missing; relocate it first",
                    &[("file", &tildify(&old))]
                )
            );
        }
        let Some(p) = crate::updates::newest(&old)? else {
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
        // The new file keeps its published name, if that is a plain name and
        // does not clash with another file.
        let name = p
            .filename
            .clone()
            .filter(|n| !n.is_empty() && !n.starts_with('.') && !n.contains('/') && n.len() < 200)
            .filter(|n| *n == old_name || !dir.join(n).exists())
            .unwrap_or(old_name.clone());
        let target = dir.join(&name);
        let tmp = dir.join(format!(".{name}.sam-download"));
        let fetched = crate::updates::download_update(&p, &old, &tmp)?;
        // From here on, any error removes the download again.
        let placed = (|| -> Result<PathBuf> {
            if !inspect(&tmp)?.is_appimage() {
                bail!(
                    "{}",
                    sam_core::i18n::tr("the downloaded file is not an AppImage; it was deleted")
                );
            }
            let new_sig = sam_detect::signature::check(&tmp);
            if let Some(before) = signing_key_change(entry.signature.as_ref(), &new_sig) {
                if !accept_key_change {
                    return Err(sam_core::error::CodedError::new(
                        "signing-key-changed",
                        sam_core::i18n::trf(
                            "The signing key changed: the installed version was {before}, the new file is {now}. The download was deleted; update again and accept the change only if you trust it.",
                            &[("before", &before), ("now", &sig_words(&new_sig))],
                        ),
                    )
                    .into());
                }
            }
            // Signed and checked before, but the new file cannot be checked
            // (GnuPG missing): SAM cannot tell whether the key changed, so it
            // asks like for a changed key (threat model: a key change is
            // refused until you accept it).
            if let Some(before) = signature_unconfirmed(entry.signature.as_ref(), &new_sig) {
                if !accept_key_change {
                    return Err(sam_core::error::CodedError::new(
                        "signature-unchecked",
                        sam_core::i18n::trf(
                            "The installed version was {before}, but the signature of the new file cannot be checked, so SAM cannot tell whether it comes from the same developer. Install GnuPG (gpg and gpgv) and update again; accept the update without the check only if you trust its source. The download was deleted.",
                            &[("before", &before)],
                        ),
                    )
                    .into());
                }
            }
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&old)
                    .map(|m| m.permissions().mode())
                    .unwrap_or(0o755)
                    | 0o500;
                fs::set_permissions(&tmp, fs::Permissions::from_mode(mode & 0o777))?;
            }
            // Keep the old version, then put the new one in place.
            let backup_dir = self.paths.data_dir.join("update-backups").join(&entry.id);
            if backup_dir.exists() {
                remove_tree(&backup_dir)?;
            }
            fs::create_dir_all(&backup_dir)?;
            let backup = backup_dir.join(&old_name);
            move_file(&old, &backup)?;
            if let Err(e) = fs::rename(&tmp, &target) {
                let _ = move_file(&backup, &old);
                return Err(anyhow::Error::new(e)
                    .context(sam_core::i18n::tr("putting the new version in place")));
            }
            Ok(backup)
        })();
        let backup = match placed {
            Ok(b) => b,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        self.relocate(&entry.id, &target)?;
        let mut e = self.reextract(&entry.id, false)?;
        e.update_backup = Some(UpdateBackup {
            file: backup,
            original_path: old,
            replaced_at: now(),
        });
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
        if b.original_path.exists() && b.original_path != entry.source_path {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file} exists again; move it away first",
                    &[("file", &tildify(&b.original_path))]
                )
            );
        }
        let current = entry.source_path.clone();
        let keep = b
            .file
            .with_file_name(current.file_name().context(sam_core::i18n::tr("no name"))?);
        if current.exists() {
            move_file(&current, &keep)?;
        }
        move_file(&b.file, &b.original_path)?;
        self.relocate(&entry.id, &b.original_path)?;
        let mut e = self.reextract(&entry.id, false)?;
        e.update_backup = Some(UpdateBackup {
            file: keep,
            original_path: current,
            replaced_at: now(),
        });
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
        let name = p
            .filename
            .clone()
            .filter(|n| !n.is_empty() && !n.starts_with('.') && !n.contains('/') && n.len() < 200)
            .filter(|n| *n == old_name || !dir.join(n).exists())
            .unwrap_or(old_name.clone());
        let target = dir.join(&name);
        let tmp = dir.join(format!(".{name}.sam-download"));
        let fetched = crate::updates::download_update(&p, appimage, &tmp)?;
        let placed = (|| -> Result<()> {
            if !inspect(&tmp)?.is_appimage() {
                bail!(
                    "{}",
                    sam_core::i18n::tr("the downloaded file is not an AppImage; it was deleted")
                );
            }
            // Only SAM's makers may replace SAM (see release_key).
            crate::release_key::check(&sam_detect::signature::check(&tmp), keys)?;
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
            if let Err(e) = fs::rename(&tmp, &target) {
                let _ = move_file(&backup_dir.join(&old_name), appimage);
                return Err(anyhow::Error::new(e)
                    .context(sam_core::i18n::tr("putting the new version in place")));
            }
            Ok(())
        })();
        if let Err(e) = placed {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
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
fn move_file(from: &Path, to: &Path) -> Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    fs::copy(from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    fs::remove_file(from).with_context(|| format!("removing {}", from.display()))?;
    Ok(())
}
