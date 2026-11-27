//! Settings of a sandbox: permissions, compatibility mode, sandbox check,
//! launch arguments, repair steps, review and presets.

use super::*;

impl Sam {
    // ---------------------------------------------------------- profiles

    pub(super) fn save_profile(&self, entry: &mut AppEntry) -> Result<()> {
        entry.profile.user_modified = entry.profile.permissions != entry.recommended;
        entry.pending_changes.clear();
        // A changed switch is no confirmation that the person looked at a
        // record or file changed outside SAM: only `mark_reviewed` clears
        // those marks. Nor that they looked at the settings SAM chose from
        // what the app says about itself (`reviewed`): one switch changed
        // on the command line, in the window or for a group of apps leaves
        // the others unconfirmed (review F5). Only flows that set the whole
        // set confirm it: `mark_reviewed`, a preset, `set_permissions`.
        entry.clear_launch_failure();
        self.registry().save(entry)
    }

    /// Changes one setting. Leaves the app unconfirmed when it was.
    pub fn set_permission(&self, query: &str, key: &str, value: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        e.profile.permissions.set_key(key, value)?;
        e.profile.preset = None;
        self.save_profile(&mut e)?;
        Ok(e)
    }

    /// Replaces the whole set with one the person chose (`profile set`):
    /// none of SAM's choices is left unconfirmed, so this confirms them.
    pub fn set_permissions(&self, query: &str, perms: PermissionSet) -> Result<AppEntry> {
        self.store_permissions(query, perms, true)
    }

    /// Stores settings worked out from a change of some of them (the
    /// window's `profile change`, a group undo, SAM's own fixes): leaves the
    /// app unconfirmed when it was.
    pub fn change_permissions(&self, query: &str, perms: PermissionSet) -> Result<AppEntry> {
        self.store_permissions(query, perms, false)
    }

    fn store_permissions(
        &self,
        query: &str,
        perms: PermissionSet,
        confirms: bool,
    ) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        e.profile.permissions = perms;
        e.profile.preset = None;
        e.reviewed |= confirms;
        self.save_profile(&mut e)?;
        Ok(e)
    }

    /// The app's settings with `change` applied to what it has now: only
    /// what the change changes (audit G-F4: the window wrote back the whole
    /// set it had loaded, undoing changes made since). A setting changed
    /// elsewhere meanwhile to another value is refused with the code
    /// `changed-meanwhile`. Not saved: the caller checks the risk first.
    pub fn plan_change(
        &self,
        query: &str,
        change: &PermissionChange,
    ) -> Result<(AppEntry, PermissionSet)> {
        let e = self.resolve(query)?;
        match sam_profile::apply_change(&e.profile.permissions, &change.from, &change.to)? {
            Ok(merged) => Ok((e, merged)),
            Err(settings) => Err(sam_core::error::CodedError::new(
                "changed-meanwhile",
                sam_core::i18n::trf(
                    "{settings} of {app} changed elsewhere in the meantime. Nothing was changed: look at the settings as they are now and make the change again.",
                    &[
                        ("settings", &settings.join(", ")),
                        ("app", &e.display_name()),
                    ],
                ),
            )
            .into()),
        }
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
            bail!(
                "{}",
                sam_core::i18n::tr(
                    "compatibility mode is disabled in settings (compatibility.behavior = never)"
                )
            );
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
            e.profile.permissions = e
                .profile
                .before_compat
                .take()
                .unwrap_or_else(|| e.recommended.clone());
        }
        e.profile.compatibility_mode = on;
        self.save_profile(&mut e)?;
        Ok(e)
    }

    /// Runs the sandbox check and stores its result with the app.
    pub fn verify(&self, query: &str) -> Result<crate::verify::Outcome> {
        let mut e = self.resolve(query)?;
        self.ensure_unpacked(&mut e)?;
        self.verify_unpacked(&e)
    }

    /// [`Sam::verify`] of `e` as it is, without unpacking it again first:
    /// a start has done that before it took its lock (`app_lock`), and
    /// unpacking under its own start lock would wait for itself.
    fn verify_unpacked(&self, e: &AppEntry) -> Result<crate::verify::Outcome> {
        let out = crate::verify::verify(e, &self.config, &self.paths, &self.host())?;
        let reg = self.registry();
        if let Some(mut fresh) = reg.get(&e.id)? {
            fresh.last_check = Some(out.record.clone());
            reg.save(&mut fresh)?;
        }
        Ok(out)
    }

    /// *Preferences → Check the sandbox before each start*: runs the sandbox
    /// check when the settings, SAM or this computer changed since the last
    /// passing check, and stops the start (code `sandbox-check-failed`)
    /// when a setting does not apply. Every way of starting an app (menu,
    /// window, `sam-jail run`) calls this, so none can skip it.
    pub fn check_before_start(&self, entry: &mut AppEntry, host: &HostInfo) -> Result<()> {
        if !self.config.security.check_before_launch {
            return Ok(());
        }
        let key = crate::verify::check_key(entry, &self.config, &self.paths, host);
        let fresh = entry
            .last_check
            .as_ref()
            .is_some_and(|c| c.key == key && c.failed.is_empty());
        if fresh {
            return Ok(());
        }
        let out = self
            .verify_unpacked(entry)
            .context(sam_core::i18n::tr("checking the sandbox before starting"))?;
        if !out.record.failed.is_empty() {
            let list = out.record.failed.join(", ");
            return Err(sam_core::error::CodedError::new(
                "sandbox-check-failed",
                sam_core::i18n::trf("sandbox check failed: {list}", &[("list", &list)]),
            )
            .into());
        }
        entry.last_check = Some(out.record);
        Ok(())
    }

    /// Sandbox check for an AppImage that has no sandbox yet, with the
    /// settings it would get (`perms`, or SAM's recommendation). Runs the
    /// same sandbox as a real start, but around an empty stand-in app folder
    /// and a throwaway private home; the AppImage is neither unpacked nor
    /// run, and nothing is stored.
    pub fn verify_preview(
        &self,
        path: &Path,
        perms: Option<PermissionSet>,
    ) -> Result<crate::verify::Outcome> {
        let path = fs::canonicalize(path).with_context(|| {
            sam_core::i18n::trf("{file} does not exist", &[("file", &path.display())])
        })?;
        if !path.is_file() {
            bail!(
                "{}",
                sam_core::i18n::trf("{file} is not a file", &[("file", &path.display())])
            );
        }
        let md = self
            .peek_file(&path)
            .map(|p| p.metadata)
            .unwrap_or_default();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
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
        let root =
            self.paths
                .data_dir
                .join("check")
                .join(format!("{}-{}", std::process::id(), now()));
        let scratch = Scratch(root.clone());
        let appdir = root.join("AppDir");
        fs::create_dir_all(&appdir)?;
        fs::write(appdir.join("AppRun"), "#!/bin/sh\n")?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(appdir.join("AppRun"), fs::Permissions::from_mode(0o755))?;
        }
        let paths = Paths {
            data_dir: root.join("data"),
            ..self.paths.clone()
        };
        let entry = AppEntry {
            id: "sam-check-preview".into(),
            name: if md.name.is_empty() {
                file_name.clone()
            } else {
                md.name.clone()
            },
            source_path: path,
            metadata: md,
            extraction: Some(ExtractionInfo {
                root: root.clone(),
                appdir,
                entry: "AppRun".into(),
                ..Default::default()
            }),
            recommended: rec.permissions,
            profile: SandboxProfile {
                permissions,
                ..Default::default()
            },
            // Nothing of the app runs here, only SAM's stand-in above and its
            // test program, with the settings the person is looking at. The
            // start gate for unconfirmed settings (audit U-M11) keeps the
            // app's own code from running; for this scratch record nobody
            // could confirm it, so it refused every check before adding.
            reviewed: true,
            ..Default::default()
        };
        let out = crate::verify::verify(&entry, &self.config, &paths, &self.host());
        drop(scratch);
        out
    }

    /// Replaces the extra arguments always passed to the app.
    pub fn set_args(&self, query: &str, args: Vec<String>) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        let args: Vec<String> = args
            .into_iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
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
    /// A first-run hint rated Think twice or Dangerous, or one that turns
    /// on compatibility mode, needs `confirmed` (the person said yes),
    /// judged here on the record that is changed and saved, so no caller
    /// can skip it (owner decision 13 of 2026-11-23). Any other repair step
    /// rated Think twice or Dangerous, or one that turns on compatibility
    /// mode, needs it as well (owner decision A of 2026-11-25).
    pub fn apply_suggestion(
        &self,
        query: &str,
        sug: &Suggestion,
        as_repair: bool,
        confirmed: bool,
    ) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        crate::repair::confirm_hint(&e, sug, confirmed)?;
        crate::repair::confirm_step(&e, &self.config, &self.paths, sug, confirmed)?;
        if as_repair && e.repair_backup.is_none() {
            e.repair_backup = Some(e.profile.clone());
        }
        let mut undo = sam_core::model::AppliedRepair {
            step: Some(sug.clone()),
            on_trial: as_repair,
            ..Default::default()
        };
        crate::repair::apply_step(&mut e, sug, &mut undo)?;
        e.profile.preset = None;
        if as_repair && !e.repairs_applied.contains(&sug.id) {
            e.repairs_applied.push(sug.id.clone());
            e.applied_repairs.push(undo);
        }
        self.save_profile(&mut e)?;
        Ok(e)
    }

    /// Find a suggestion by id among the app's hints, findings and repair steps.
    ///
    /// A step that the app's own output raised at its last start counts as
    /// the app's request, whichever copy is found: a first-run hint or a
    /// ladder step with the same id (`network`, `keyring`, `x11`, `gpu`)
    /// was found first and carried no mark, so `repair --next` applied a
    /// step the app's printed text had put first with no yes, or asked for
    /// it as SAM's own hint (independent review of 2026-11-27; audit U-M2:
    /// what the app prints never grants access unasked).
    pub fn find_suggestion(&self, e: &AppEntry, id: &str) -> Option<Suggestion> {
        let raised_by_app = e
            .last_launch
            .iter()
            .flat_map(|l| &l.findings)
            .any(|f| f.id == id && f.from_app_output);
        let mut found = crate::repair::first_run_hints(e)
            .into_iter()
            .chain(crate::repair::ladder(e, &self.config, &self.paths))
            .chain(e.last_launch.iter().flat_map(|l| l.findings.clone()))
            .find(|s| s.id == id)?;
        found.from_app_output |= raised_by_app;
        Some(found)
    }

    /// Switches off one applied repair step: puts back exactly what that
    /// step changed and keeps the other steps.
    pub fn undo_repair_step(&self, query: &str, step_id: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        let i = e
            .applied_repairs
            .iter()
            .position(|r| r.step.as_ref().is_some_and(|s| s.id == step_id))
            .with_context(|| {
                sam_core::i18n::trf(
                    "the repair step '{step_id}' is not applied",
                    &[("step_id", &step_id)],
                )
            })?;
        let r = e.applied_repairs.remove(i);
        crate::repair::revert_step(&mut e, &r)?;
        self.save_profile(&mut e)?;
        Ok(e)
    }

    /// Undo every repair step, newest first, each taking back only what it
    /// changed: a change the person made since stays (audit G-F4: the whole
    /// profile from before the first step was put back). Older records
    /// without the steps' own records fall back to that copy.
    pub fn undo_repairs(&self, query: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        if !e.applied_repairs.is_empty() {
            for r in e.applied_repairs.clone().iter().rev() {
                crate::repair::revert_step(&mut e, r)?;
            }
            e.repair_backup = None;
        } else if let Some(backup) = e.repair_backup.take() {
            e.profile = backup;
        } else {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "no repair steps to undo for {app}",
                    &[("app", &e.display_name())]
                )
            )
        }
        e.repairs_applied.clear();
        e.applied_repairs.clear();
        e.tried_repairs.clear();
        self.save_profile(&mut e)?;
        Ok(e)
    }

    pub fn mark_reviewed(&self, query: &str) -> Result<AppEntry> {
        self.mark_reviewed_as_shown(query, None)
    }

    /// [`Sam::mark_reviewed`] from a page that showed the app with the
    /// review fingerprint `seen` (`sam_storage::review_fingerprint`). When
    /// the app changed since (a mark, a notice, a setting or the AppImage),
    /// nothing is confirmed and the error says to look again (code
    /// `review-out-of-date`): no button may confirm what its page never
    /// showed (review L4). Without `seen` (a person at the terminal), what
    /// is there now is confirmed.
    pub fn mark_reviewed_as_shown(&self, query: &str, seen: Option<&str>) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        if let Some(seen) = seen {
            if sam_storage::review_fingerprint(&e)? != seen {
                return Err(sam_core::error::CodedError::new(
                    "review-out-of-date",
                    sam_core::i18n::trf(
                        "{app} changed since this page showed it. Look at it again, then confirm.",
                        &[("app", &sam_core::util::display_safe(e.display_name(), 80))],
                    ),
                )
                .into());
            }
        }
        e.reviewed = true;
        e.pending_changes.clear();
        // The one place that confirms changes made outside SAM.
        e.changed_outside = false;
        e.content_changed_outside = false;
        self.registry().save_confirmed(&mut e)?;
        Ok(e)
    }

    /// Applies a preset; asks (returns it not applied) when it removes
    /// what the app needs or adds risk, unless `confirm`. With `expect`,
    /// only the preset as it was when the question was asked is applied:
    /// the window asks, then applies by name, and a preset changed in
    /// between would otherwise be applied unseen (audit G-F12/13).
    pub fn apply_preset(
        &self,
        query: &str,
        preset_name: &str,
        confirm: bool,
        expect: Option<&str>,
    ) -> Result<PresetApply> {
        let mut e = self.resolve(query)?;
        let preset = find_preset(&self.paths, preset_name)?
            .with_context(|| format!("unknown preset '{preset_name}'"))?;
        let fingerprint = sam_storage::fingerprint(&preset.permissions)?;
        if expect.is_some_and(|x| x != fingerprint) {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the preset “{preset}” changed after it was checked; nothing was applied. Check it again.",
                    &[("preset", &preset.name)]
                )
            );
        }
        let check = check_change(&e, &preset.permissions);
        if check.needs_confirmation() && !confirm {
            return Ok(PresetApply {
                preset: preset.name,
                check,
                applied: false,
                fingerprint,
            });
        }
        e.profile.permissions = preset.permissions.clone();
        e.profile.preset = Some(preset.name.clone());
        // The whole set is the preset the person picked.
        e.reviewed = true;
        self.save_profile(&mut e)?;
        Ok(PresetApply {
            preset: preset.name,
            check,
            applied: true,
            fingerprint,
        })
    }

    pub fn save_preset_from_app(
        &self,
        query: &str,
        name: &str,
        description: &str,
    ) -> Result<Preset> {
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
                    may_not_start: summary.last_problem.is_some()
                        || matches!(
                            summary.badge,
                            Badge::Broken | Badge::Missing | Badge::ChangedOutside
                        ),
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
    pub fn group_change(
        &self,
        key: &str,
        value: &str,
        ids: &[String],
        dry_run: bool,
    ) -> Result<GroupChange> {
        let mut out = GroupChange {
            key: key.into(),
            value: value.into(),
            applied: !dry_run,
            apps: Vec::new(),
            previous: Default::default(),
            undo: Default::default(),
        };
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
                out.undo.insert(
                    e.id.clone(),
                    PermissionChange {
                        from: new.clone(),
                        to: e.profile.permissions.clone(),
                    },
                );
                out.previous.insert(
                    e.id.clone(),
                    std::mem::replace(&mut e.profile.permissions, new),
                );
                e.profile.preset = None;
                self.save_profile(&mut e)?;
            }
        }
        Ok(out)
    }

    /// Takes back a group change (its `undo`): only the setting it
    /// changed, so later changes to the apps stay (audit G-F4: the whole
    /// sets from before were written back). `confirm` sees what the undo
    /// adds that is rated Think twice or Dangerous (the one rule for
    /// asking, which the old whole-set restore passed by). All apps or
    /// none: a setting changed meanwhile refuses the whole undo.
    pub fn group_restore(
        &self,
        undo: BTreeMap<String, PermissionChange>,
        confirm: impl FnOnce(&[sam_core::risk::RiskItem]) -> Result<()>,
    ) -> Result<usize> {
        let mut planned = Vec::new();
        let mut added: Vec<sam_core::risk::RiskItem> = Vec::new();
        for (id, change) in &undo {
            let (e, merged) = self.plan_change(id, change)?;
            for i in sam_core::risk::new_risks(&e.profile.permissions, &merged) {
                if !added.iter().any(|x| x.title == i.title) {
                    added.push(i);
                }
            }
            planned.push((e.id.clone(), merged));
        }
        confirm(&added)?;
        let n = planned.len();
        for (id, perms) in planned {
            self.change_permissions(&id, perms)?;
        }
        Ok(n)
    }
}
