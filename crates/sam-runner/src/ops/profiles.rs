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
}
