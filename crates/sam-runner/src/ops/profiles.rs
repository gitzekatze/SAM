//! Settings of a sandbox: permissions, compatibility mode, sandbox check,
//! launch arguments, repair steps, review and presets.

use super::*;

impl Sam {
    // ---------------------------------------------------------- profiles

    pub(super) fn save_profile(&self, entry: &mut AppEntry) -> Result<()> {
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
        e.repairs_applied.clear();
        e.applied_repairs.clear();
        e.repair_backup = None;
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
        let mut undo = sam_core::model::AppliedRepair { step: Some(sug.clone()), ..Default::default() };
        match &sug.action {
            FixAction::Set { key, value } => {
                undo.before.push((key.clone(), e.profile.permissions.get_key(key)?));
                e.profile.permissions.set_key(key, value)?
            }
            FixAction::Add { key, value } => {
                let mut list: Vec<String> = serde_json::from_value(e.profile.permissions.get_key(key)?).with_context(|| format!("{key} is not a list"))?;
                if !list.contains(value) {
                    list.push(value.clone());
                    undo.added = Some(value.clone());
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
                    undo.added = Some(value.clone());
                }
            }
            FixAction::None => bail!("“{}” is an explanation only; there is nothing to apply", sug.title),
        }
        e.profile.preset = None;
        if as_repair && !e.repairs_applied.contains(&sug.id) {
            e.repairs_applied.push(sug.id.clone());
            e.applied_repairs.push(undo);
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

    /// Switches off one applied repair step: puts back exactly what that
    /// step changed and keeps the other steps.
    pub fn undo_repair_step(&self, query: &str, step_id: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        let i = e
            .applied_repairs
            .iter()
            .position(|r| r.step.as_ref().is_some_and(|s| s.id == step_id))
            .with_context(|| format!("the repair step '{step_id}' is not applied"))?;
        let r = e.applied_repairs.remove(i);
        let step = r.step.clone().context("damaged repair record")?;
        match &step.action {
            FixAction::Set { .. } => {
                for (key, old) in &r.before {
                    e.profile.permissions.set_key(key, &serde_json::to_string(old)?)?;
                }
            }
            FixAction::Add { key, .. } => {
                if let Some(v) = &r.added {
                    let mut list: Vec<String> = serde_json::from_value(e.profile.permissions.get_key(key)?)?;
                    list.retain(|x| x != v);
                    e.profile.permissions.set_key(key, &serde_json::to_string(&list)?)?;
                }
            }
            FixAction::Compat => {
                e.profile.permissions = e.profile.before_compat.take().unwrap_or_else(|| e.recommended.clone());
                e.profile.compatibility_mode = false;
            }
            FixAction::AddArg { .. } => {
                if let Some(v) = &r.added {
                    e.profile.args.retain(|x| x != v);
                }
            }
            FixAction::None => {}
        }
        e.repairs_applied.retain(|id| id != step_id);
        if e.applied_repairs.is_empty() {
            e.repair_backup = None;
        }
        self.save_profile(&mut e)?;
        Ok(e)
    }

    /// Restore the profile from before the first repair step.
    pub fn undo_repairs(&self, query: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        let Some(backup) = e.repair_backup.take() else { bail!("no repairs to undo for {}", e.display_name()) };
        e.profile = backup;
        e.repairs_applied.clear();
        e.applied_repairs.clear();
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
        let check = check_change(&e, &preset.permissions);
        if check.needs_confirmation() && !confirm {
            return Ok(PresetApply { preset: preset.name, check, applied: false });
        }
        e.profile.permissions = preset.permissions.clone();
        e.profile.preset = Some(preset.name.clone());
        self.save_profile(&mut e)?;
        Ok(PresetApply { preset: preset.name, check, applied: true })
    }

    pub fn save_preset_from_app(&self, query: &str, name: &str, description: &str) -> Result<Preset> {
        let e = self.resolve(query)?;
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

    // ---------------------------------------------------------- groups

    /// All sandboxed apps with their permissions and tags, for the
    /// Permissions page.
    pub fn permission_overview(&self) -> Result<Vec<OverviewApp>> {
        Ok(self
            .registry()
            .list()?
            .into_iter()
            .map(|e| {
                let summary = AppSummary::from_entry(&e);
                OverviewApp {
                    tags: sam_profile::tags::permission_tags(&e.profile.permissions),
                    running: !self.running(&e.id).is_empty(),
                    needs_review: !e.reviewed,
                    may_not_start: summary.last_problem.is_some() || matches!(summary.badge, Badge::Broken | Badge::Missing | Badge::ChangedOutside),
                    permissions: e.profile.permissions.clone(),
                    summary,
                }
            })
            .collect())
    }

    /// Sets one permission to the same value for several apps. With
    /// `dry_run`, only reports what SAM's analysis says each app would lose;
    /// otherwise saves the apps whose value changes and returns their
    /// settings from before, so the whole change can be undone at once.
    pub fn group_change(&self, key: &str, value: &str, ids: &[String], dry_run: bool) -> Result<GroupChange> {
        let mut out = GroupChange { key: key.into(), value: value.into(), applied: !dry_run, apps: Vec::new(), previous: Default::default() };
        let mut entries = Vec::new();
        for id in ids {
            let e = self.resolve(id)?;
            let mut new = e.profile.permissions.clone();
            new.set_key(key, value)?;
            entries.push((e, new));
        }
        for (mut e, new) in entries {
            let changed = new != e.profile.permissions;
            out.apps.push(GroupApp {
                id: e.id.clone(),
                name: e.display_name().to_string(),
                check: check_change(&e, &new),
                running: !self.running(&e.id).is_empty(),
                changed,
            });
            if changed && !dry_run {
                out.previous.insert(e.id.clone(), std::mem::replace(&mut e.profile.permissions, new));
                e.profile.preset = None;
                self.save_profile(&mut e)?;
            }
        }
        Ok(out)
    }

    /// Puts back the settings a group change returned in `previous`.
    pub fn group_restore(&self, previous: BTreeMap<String, PermissionSet>) -> Result<usize> {
        let n = previous.len();
        for (id, perms) in previous {
            self.set_permissions(&id, perms)?;
        }
        Ok(n)
    }
}
