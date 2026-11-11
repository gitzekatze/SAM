//! Keeping sandboxes current: re-extract, refresh, relocate, stop, remove,
//! uninstall, disk space and cleanup.

use super::*;

impl Sam {
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
        let req = ExtractRequest {
            source: &entry.source_path,
            info: &info,
            root: &root,
            limits: self.limits(),
            allow_fallback: consent_fallback && self.config.extraction.allow_fallback,
            isolation: self.extract_isolation(),
        };
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

    pub(super) fn ensure_not_running(&self, entry: &AppEntry, what: &str) -> Result<()> {
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
        DiskUsage {
            id: entry.id.clone(),
            name: entry.display_name().to_string(),
            unpacked,
            home,
            overlay,
            logs,
            total: unpacked + home + overlay + logs,
            can_free: unpacked > 0 && entry.source_path.exists(),
        }
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

    /// Checks whether newer versions are published, for one app or all,
    /// and stores the result with each app. With `if_due`, only when
    /// `updates.check_on_start` is on, and only apps not checked for a day.
    pub fn check_updates(&self, query: Option<&str>, if_due: bool) -> Result<Vec<(String, UpdateStatus)>> {
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
            if if_due && e.update.as_ref().is_some_and(|u| now() - u.checked_at < 24 * 3600) {
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
}
