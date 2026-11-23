//! Queries and the overview: warnings, discovery of AppImages, previews,
//! other tools' menu entries and scanning.

use super::*;

impl Sam {
    // ----------------------------------------------------------- queries

    pub fn evaluate(
        &self,
        perms: &PermissionSet,
        app: Option<&AppEntry>,
        host: &HostInfo,
    ) -> Evaluation {
        self.evaluate_as(perms, app, app.is_some_and(|a| a.metadata.terminal), host)
    }

    /// `terminal_program`: for an AppImage without a sandbox, from its metadata.
    fn evaluate_as(
        &self,
        perms: &PermissionSet,
        app: Option<&AppEntry>,
        terminal_program: bool,
        host: &HostInfo,
    ) -> Evaluation {
        let ctx = WarningContext {
            app_needs_network: app.map(app_needs_network),
            host: Some(host),
            warn_x11: self.config.security.warn_x11,
            warn_full_home: self.config.security.warn_full_home,
            terminal_program,
        };
        Evaluation {
            risk: assess(perms),
            tags: sam_profile::tags::permission_tags(perms),
            warnings: evaluate(perms, &ctx),
        }
    }

    /// All warnings relevant to an app: permissions, extraction, detection, state.
    pub fn app_warnings(&self, e: &AppEntry, host: &HostInfo) -> Vec<Warning> {
        let mut w = self
            .evaluate(&e.profile.permissions, Some(e), host)
            .warnings;
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
                w.push(Warning::new(
                    "isolation-verdict",
                    sev,
                    "Isolation assessment",
                    v.message(),
                ));
            }
        }
        match e.state {
            AppState::Stale => {
                w.push(Warning::warn("stale", "AppImage changed", "The AppImage changed since it was unpacked. Unpack it again to update the sandbox."))
            }
            AppState::Missing => w.push(Warning::warn(
                "missing",
                "AppImage missing",
                "The AppImage no longer exists. You can still run the unpacked copy, point SAM at the moved file, or remove the app.",
            )),
            AppState::Broken => {
                w.push(Warning::danger("broken", "Not runnable", e.last_error.clone().unwrap_or_else(|| sam_core::i18n::tr("Unpacking or starting failed."))))
            }
            _ => {}
        }
        if !e.pending_changes.is_empty() {
            w.push(Warning::warn(
                "new-permissions",
                "Update needs new permissions",
                sam_core::i18n::trf(
                    "The updated AppImage likely needs: {needs}. Your own settings were kept; review them and grant access if needed.",
                    &[("needs", &e.pending_changes.join(", "))],
                ),
            ));
        }
        if e.profile.compatibility_mode {
            w.push(Warning::warn(
                "compat-mode",
                "Compatibility mode",
                sam_profile::COMPAT_WARNING,
            ));
        }
        if let Some(before) = &e.signing_key_changed {
            w.push(Warning::danger(
                "signing-key-changed",
                "Signed differently than before",
                sam_core::i18n::trf("The previous version was {before}. The current file is {now}. An update from the same developer normally keeps its key: make sure the file comes from where you expect.", &[("before", &before), ("now", &e.signature.as_ref().map(sig_words).unwrap_or_else(|| sam_core::i18n::tr("not checked")))]),
            ));
        }
        if e.signature
            .as_ref()
            .is_some_and(|s| s.state == sam_core::model::SignatureState::Invalid)
        {
            w.push(Warning::danger(
                "signature-invalid",
                "Signature does not match",
                e.signature
                    .as_ref()
                    .map(|s| s.detail.clone())
                    .unwrap_or_default(),
            ));
        }
        w
    }

    /// The sandbox an AppImage is unpacked in: Bubblewrap, running SAM's CLI
    /// (`sam-jail`, which provides the built-in reader as a subcommand). The
    /// CLI is this program or the `sam-jail` next to it, so a menu start
    /// (`sam-jail-run`) that unpacks again after *Free space* is isolated too.
    /// SAM's own programs never unpack without it (threat model: "SAM's own
    /// unpacker … run in a sandbox"); only tests and benchmarks may.
    pub(super) fn extract_isolation(&self) -> Result<Option<sam_intake::extract::Isolation>> {
        let exe = std::env::current_exe()?;
        let host = self.host();
        let bwrap = host
            .tools
            .bwrap
            .as_ref()
            .filter(|_| host.userns.usable())
            .map(|b| b.path.clone());
        unpack_isolation(&exe, bwrap, &host)
    }

    /// An AppImage's name and icon, read in the preview sandbox (audit
    /// I-F7). Where SAM can build no sandbox, nothing is read: the file
    /// name has to do. Only a program that is not SAM's (a test) reads in
    /// its own process.
    pub(crate) fn peek_file(&self, path: &Path) -> Option<peek::Peek> {
        match self.extract_isolation() {
            Ok(Some(iso)) => peek::peek_isolated(&iso, path).ok(),
            Ok(None) => peek::peek(path).ok(),
            Err(_) => None,
        }
    }

    // ---------------------------------------------------------- overview

    /// Folders the overview searches: configured ones, plus Downloads when
    /// `general.scan_downloads` is on.
    pub fn default_scan_dirs(&self) -> Vec<PathBuf> {
        let downloads = sam_core::host::xdg_user_dirs(&sam_core::util::home_dir())
            .get("downloads")
            .cloned();
        self.config.scan_dirs(downloads.as_deref())
    }

    /// Every AppImage in the scanned folders or started by a menu entry,
    /// with name and icon read without unpacking. Nothing is executed.
    pub fn discover(&self) -> Result<Vec<DiscoveredApp>> {
        let scanned = self.scan(None)?;
        let foreign = menu::foreign_entries(&self.paths.applications_dir);
        let apps = self.registry().list()?;
        // (path, found via menu entry, added by hand)
        let mut paths: Vec<(PathBuf, bool, bool)> = scanned
            .iter()
            .map(|s| (s.path.clone(), false, false))
            .collect();
        let add = |p: PathBuf, menu: bool, manual: bool, paths: &mut Vec<(PathBuf, bool, bool)>| {
            if p.is_file() && !paths.iter().any(|(q, _, _)| q == &p) {
                paths.push((p, menu, manual));
            }
        };
        for f in &self.config.general.scan_files {
            let p = fs::canonicalize(sam_core::util::expand_home(f))
                .unwrap_or_else(|_| sam_core::util::expand_home(f));
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
            let md = AppImageMetadata {
                name: p.name.clone(),
                comment: p.comment.clone(),
                categories: p.categories.clone(),
                ..Default::default()
            };
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let category = sam_profile::infer_category(&md, &file_name, None);
            let scan = scanned.iter().find(|s| s.path == path);
            let menu_entries = foreign
                .iter()
                .filter(|f| f.appimage == path && f.hidden_by.is_none() && !f.hidden_elsewhere)
                .map(|f| MenuEntryInfo {
                    file: f.file.clone(),
                    name: f.name.clone(),
                    system: !f.file.starts_with(&self.paths.applications_dir),
                })
                .collect();
            out.push(DiscoveredApp {
                name: if p.name.is_empty() {
                    id::slug_from_filename(&path)
                } else {
                    p.name
                },
                comment: p.comment,
                version: p.version,
                categories: p.categories,
                category: category.as_str().to_string(),
                category_label: category.label().to_string(),
                icon: p.icon,
                sandboxed: apps
                    .iter()
                    .find(|a| a.source_path == path)
                    .map(|a| a.id.clone()),
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

    pub(super) fn cached_preview(
        &self,
        path: &Path,
        meta: Option<&fs::Metadata>,
        dir: &Path,
    ) -> Preview {
        let mtime = meta
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = format!(
            "{}|{}|{mtime}",
            path.display(),
            meta.map(|m| m.len()).unwrap_or(0)
        );
        let stem = fingerprint::short_hash(path.to_string_lossy().as_bytes());
        let cache = dir.join(format!("{stem}.json"));
        if let Some(p) = fs::read(&cache)
            .ok()
            .and_then(|b| serde_json::from_slice::<Preview>(&b).ok())
        {
            if p.key == key {
                return p;
            }
        }
        let mut p = Preview {
            key,
            ..Default::default()
        };
        if let Some(pk) = self.peek_file(path) {
            p.name = pk.metadata.name;
            p.comment = pk.metadata.comment;
            p.version = pk.metadata.version;
            p.categories = pk.metadata.categories;
            if let Some((data, fmt)) = pk.icon {
                let icon = dir.join(format!("{stem}.{}", fmt.ext()));
                if fs::create_dir_all(dir).is_ok()
                    && sam_core::util::atomic_write(&icon, &data).is_ok()
                {
                    p.icon = Some(icon);
                }
            }
        }
        if fs::create_dir_all(dir).is_ok() {
            let _ =
                sam_core::util::atomic_write(&cache, &serde_json::to_vec(&p).unwrap_or_default());
        }
        p
    }

    /// The settings SAM would use for an AppImage that has no sandbox yet,
    /// from its metadata only (nothing is unpacked or run). `perms` evaluates
    /// the user's adjusted settings instead.
    pub fn preview(&self, path: &Path, perms: Option<PermissionSet>) -> Result<serde_json::Value> {
        let path = fs::canonicalize(path).with_context(|| {
            sam_core::i18n::trf("{file} does not exist", &[("file", &path.display())])
        })?;
        let md = self
            .peek_file(&path)
            .map(|p| p.metadata)
            .unwrap_or_default();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let rec = sam_profile::recommend(&md, &file_name, None);
        let permissions = perms.unwrap_or_else(|| rec.permissions.clone());
        let host = self.host();
        let selection = crate::bwrap::check(&host).ok();
        let ev = self.evaluate_as(&permissions, None, md.terminal, &host);
        Ok(serde_json::json!({
            "category": rec.category.as_str(),
            "category_label": rec.category.label(),
            "recommended": rec.permissions,
            "permissions": permissions,
            "notes": rec.notes,
            "selection": selection,
            "risk": ev.risk,
            "tags": ev.tags,
            "warnings": ev.warnings,
        }))
    }

    /// Unsandboxed menu entries that start this app's AppImage.
    pub fn menu_duplicates(&self, entry: &AppEntry) -> Vec<menu::ForeignEntry> {
        menu::foreign_entries(&self.paths.applications_dir)
            .into_iter()
            .filter(|f| {
                f.appimage == entry.source_path && f.hidden_by.is_none() && !f.hidden_elsewhere
            })
            .collect()
    }

    pub(super) fn hide_menu_entries(&self, entry: &mut AppEntry) {
        for f in self.menu_duplicates(entry) {
            match menu::hide(&f.file, &self.paths.applications_dir, &entry.id) {
                Ok(h) => menu::merge_hidden(&mut entry.hidden_entries, h),
                Err(e) => errln!(
                    "sam-jail: {}",
                    sam_core::i18n::trf(
                        "could not hide the menu entry {file}: {error}",
                        &[("file", &f.file.display()), ("error", &format!("{e:#}"))]
                    )
                ),
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
            let registered = apps
                .iter()
                .find(|a| a.source_path == canon)
                .map(|a| a.id.clone());
            let mut moved_from = None;
            if registered.is_none() {
                let cands: Vec<&AppEntry> = apps
                    .iter()
                    .filter(|a| !a.source_path.exists() && a.source.size == size)
                    .collect();
                if !cands.is_empty() {
                    if let Ok(sha) = fingerprint::sha256_file(&canon) {
                        moved_from = cands
                            .iter()
                            .find(|a| a.source.sha256 == sha)
                            .map(|a| a.id.clone());
                    }
                }
            }
            out.push(ScanItem {
                path: canon,
                registered,
                moved_from,
                size,
            });
        }
        Ok(out)
    }
}

/// SAM's own programs. They unpack AppImages only inside a sandbox.
const SAM_PROGRAMS: &[&str] = &["sam-jail", "sam-jail-run", "sam-jail-gui"];

/// The unpack sandbox for the program `exe`, given the Bubblewrap that can
/// run here (`None` when it cannot). The reader is `exe` itself when it is
/// SAM's CLI, else the `sam-jail` next to it. Without either, SAM's own
/// programs refuse with a coded error; other programs (tests, benchmarks)
/// unpack in their own process, as before.
fn unpack_isolation(
    exe: &Path,
    bwrap: Option<PathBuf>,
    host: &sam_core::HostInfo,
) -> Result<Option<sam_intake::extract::Isolation>> {
    let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let reader = if name == "sam-jail" {
        Some(exe.to_path_buf())
    } else {
        exe.parent()
            .map(|d| d.join("sam-jail"))
            .filter(|p| p.is_file())
    };
    match (bwrap, reader) {
        (Some(bwrap), Some(self_exe)) => {
            // The same system and the same baseline filter as an app; no
            // nested sandboxes, no Bluetooth (audit I-F17).
            let filter = crate::kernel::filter_bytes(&crate::kernel::SeccompSpec {
                strict: false,
                allow_userns: false,
                bluetooth: false,
                i386: false,
            })?;
            Ok(Some(sam_intake::extract::Isolation {
                bwrap,
                self_exe,
                system: sam_sandbox::helper_system_args(host),
                filter: Some(filter),
            }))
        }
        (bwrap, _) if SAM_PROGRAMS.contains(&name) => {
            let why = if bwrap.is_none() {
                sam_core::i18n::tr("Bubblewrap cannot run on this computer")
            } else {
                sam_core::i18n::tr("SAM's command line (sam-jail) is not next to this program")
            };
            Err(sam_core::error::CodedError::new(
                "unpack-needs-sandbox",
                sam_core::i18n::trf(
                    "SAM unpacks AppImages only inside a sandbox, and none can be built here: {reason}. Diagnostics (sam-jail doctor) says what is missing.",
                    &[("reason", &why)],
                ),
            )
            .into())
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod unpack_isolation_tests {
    use super::unpack_isolation;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn a_menu_start_unpacks_in_a_sandbox_with_the_cli_next_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("sam-jail");
        fs::write(&cli, b"").unwrap();
        let run = dir.path().join("sam-jail-run");
        let iso = unpack_isolation(
            &run,
            Some(PathBuf::from("/usr/bin/bwrap")),
            &sam_core::HostInfo::default(),
        )
        .unwrap()
        .expect("sam-jail-run unpacks in a sandbox");
        assert_eq!(iso.self_exe, cli, "the reader is the sam-jail next to it");
        // The same system view and baseline filter as an app (audit I-F17).
        assert!(iso
            .system
            .windows(3)
            .any(|w| w == ["--ro-bind", "/usr", "/usr"]));
        let filter = iso
            .filter
            .expect("the unpack sandbox has the syscall filter");
        assert_eq!(
            filter,
            crate::kernel::filter_bytes(&crate::kernel::SeccompSpec::default()).unwrap()
        );
    }

    #[test]
    fn sams_programs_never_unpack_without_a_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["sam-jail", "sam-jail-run", "sam-jail-gui"] {
            let exe = dir.path().join(name);
            let err = unpack_isolation(&exe, None, &sam_core::HostInfo::default()).unwrap_err();
            assert_eq!(
                sam_core::error::code_of(&err),
                Some("unpack-needs-sandbox"),
                "{name} without Bubblewrap refuses: {err:#}"
            );
        }
        // Bubblewrap works, but no sam-jail next to sam-jail-run.
        let err = unpack_isolation(
            &dir.path().join("sam-jail-run"),
            Some(PathBuf::from("/usr/bin/bwrap")),
            &sam_core::HostInfo::default(),
        )
        .unwrap_err();
        assert_eq!(sam_core::error::code_of(&err), Some("unpack-needs-sandbox"));
    }

    #[test]
    fn tests_and_benchmarks_may_unpack_in_their_own_process() {
        let dir = tempfile::tempdir().unwrap();
        let test_binary = dir.path().join("sandbox-0123abcd");
        assert!(
            unpack_isolation(&test_binary, None, &sam_core::HostInfo::default())
                .unwrap()
                .is_none()
        );
    }
}
