//! Settings of a sandbox: permissions, compatibility mode, sandbox check,
//! launch arguments, repair steps, review and presets.

use super::*;

/// What a change of an app's settings changes, for
/// [`Sam::save_profile`]: every writer names it, so none merges a whole
/// set by mistake.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum SetChange {
    /// Some switches: only those are written, a switch another SAM process
    /// saved meanwhile stays.
    Switches,
    /// The whole set, chosen as one (a preset, the compatibility mode, a
    /// whole set the person confirmed): written as one value. A reset (SAM's
    /// recommendation, also written as one value) and an undo of the repair
    /// steps are made on the record as it is under the lock instead
    /// ([`Sam::reset_profile`], [`Sam::undo_repairs`]).
    WholeSet,
}

/// Whether a change of an app's settings may hold a grant of `/tmp` or of
/// a known socket folder in it (tmux, SSH, the X server …) that the
/// record did not hold before, for [`Sam::save_profile`]: every writer
/// names it, so none lets such a grant in by mistake (owner decision 10
/// of 2026-11-23).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Grants {
    /// Refused with the code `tmp-grant-refused`
    /// ([`crate::gate::refuse_tmp_grants`]): every change the person or a
    /// step makes.
    Refused,
    /// Not checked: the change puts back what the record held (turning
    /// compatibility mode off, an undo of repair steps) or takes SAM's
    /// recommendation, which names no extra folder. Refusing these would
    /// keep an app in compatibility mode or its steps applied.
    PutBack,
}

/// Makes `folder`, a folder of an app's own directly in `base`, for the
/// account `uid` only, and checks it. `base` must be a real folder owned
/// by `base_owner` (root for `/tmp`) with the sticky bit, so no other
/// account can rename or remove a folder this account owns there. The
/// folder is made with mode 0700 and never through a link (an existing
/// one is kept); then it must be a real folder, owned by `uid`, that no
/// other account can open, and each of the app's grants of it (`grants`,
/// `~` written out) must lead there as the sandbox resolves it
/// ([`sam_core::places::resolve`]), not through a link on the way to
/// another place. Otherwise the start stops with the code
/// `own-tmp-folder-unsafe` and nothing is changed or removed. `app` is
/// the app's name for the message.
pub(crate) fn make_own_tmp_folder_in(
    base: &Path,
    base_owner: u32,
    uid: u32,
    folder: &Path,
    grants: &[PathBuf],
    app: &str,
) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let app = sam_core::util::display_safe(app, 80);
    let shown = folder.display().to_string();
    let unsafe_base = || -> anyhow::Error {
        sam_core::error::CodedError::new(
            "own-tmp-folder-unsafe",
            sam_core::i18n::trf(
                "SAM did not start {app}: /tmp does not keep each user's folders apart on this computer, so the app's folder {folder} cannot be kept safe there. Take {folder} out of the app's folders, then start the app again.",
                &[("app", &app), ("folder", &shown)],
            ),
        )
        .into()
    };
    let base_ok = fs::symlink_metadata(base)
        .is_ok_and(|m| m.file_type().is_dir() && m.uid() == base_owner && m.mode() & 0o1000 != 0);
    if !base_ok || folder.parent() != Some(base) {
        return Err(unsafe_base());
    }
    match fs::DirBuilder::new().mode(0o700).create(folder) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(e)
                .with_context(|| sam_core::i18n::trf("making {folder}", &[("folder", &shown)]))
        }
    }
    let found = fs::symlink_metadata(folder).ok();
    // Another account's folder cannot be removed by you in a sticky /tmp:
    // a message of its own says what helps.
    if found.as_ref().is_some_and(|m| m.uid() != uid) {
        return Err(sam_core::error::CodedError::new(
            "own-tmp-folder-unsafe",
            sam_core::i18n::trf(
                "SAM did not start {app}: its folder {folder} belongs to another account, which may have made it to stop the app or to see its files. Take {folder} out of the app's folders, or ask the computer's administrator to remove it, then start the app again.",
                &[("app", &app), ("folder", &shown)],
            ),
        )
        .into());
    }
    // The place the sandbox mounts for each grant is the folder checked
    // here: `/tmp/x/../sam-<id>` with `/tmp/x` a link leads elsewhere.
    let own = found.is_some_and(|m| m.file_type().is_dir() && m.mode() & 0o077 == 0)
        && grants
            .iter()
            .all(|g| sam_core::places::resolve(g) == folder);
    if !own {
        return Err(sam_core::error::CodedError::new(
            "own-tmp-folder-unsafe",
            sam_core::i18n::trf(
                "SAM did not start {app}: its folder {folder} is not a folder, is a link or others can open it, so another program may have made or changed it. Remove {folder}, or take it out of the app's folders, then start the app again.",
                &[("app", &app), ("folder", &shown)],
            ),
        )
        .into());
    }
    Ok(())
}

/// The moment between a writer's read and its save, where a test lets
/// another SAM process save; outside tests nothing happens here. A function
/// of its own, so the translation collector skips only it as test code.
fn before_save() {
    #[cfg(test)]
    record_lock_tests::before_save();
}

impl Sam {
    // ---------------------------------------------------------- profiles

    /// Saves the change of an app's settings that `entry` holds, made on
    /// the copy `read`: under the record lock, only what the change
    /// changed is written onto the record as it is now, so what another
    /// SAM process saved meanwhile (an "unpack again", an update and their
    /// "look at it first" marks and notices) stays. With
    /// [`SetChange::WholeSet`] the settings are written as one value, so
    /// the saved set is exactly the one the writer chose (before, a switch
    /// saved meanwhile was merged into a preset or a confirmed set, which
    /// then held a set nobody chose). `entry` becomes the record as saved.
    pub(super) fn save_profile(
        &self,
        read: &AppEntry,
        entry: &mut AppEntry,
        kind: SetChange,
        grants: Grants,
    ) -> Result<()> {
        let id = entry.id.clone();
        let saved = self.change_profile(&id, grants, |now| {
            sam_storage::apply_changes(now, read, entry)?;
            if kind == SetChange::WholeSet {
                // A preset, the compatibility mode or a whole set the
                // person confirmed:
                // a switch another process saved meanwhile is replaced
                // too, never mixed in. The later save wins, as for any
                // one setting two saves change.
                now.profile.permissions = entry.profile.permissions.clone();
            }
            Ok(())
        })?;
        *entry = saved;
        Ok(())
    }

    /// Makes `change` on the record of `id` as it is under the record lock,
    /// then saves it as every change of an app's settings is saved; returns
    /// the record as saved. For a change that must see the record as it is
    /// now: a repair step changes switches and the list of applied steps
    /// together, so another process's step saved meanwhile stays in both
    /// (merged field by field, a switch and the list that names its step
    /// could come from two different saves). With [`Grants::Refused`], a
    /// change that gives the app a new grant of `/tmp` is refused and
    /// nothing is saved, judged on the record as it is under the lock.
    fn change_profile(
        &self,
        id: &str,
        grants: Grants,
        change: impl FnOnce(&mut AppEntry) -> Result<()>,
    ) -> Result<AppEntry> {
        before_save();
        let saved = self.registry().try_update(id, |now| {
            let before = now.profile.permissions.clone();
            change(now)?;
            if grants == Grants::Refused {
                crate::gate::refuse_tmp_grants(Some(&*now), &before, &now.profile.permissions)?;
            }
            now.profile.user_modified = now.profile.permissions != now.recommended;
            // The note of an update's needs keeps what is not granted yet: a
            // changed switch is not the person seeing it (review L5).
            settle_update_note(now, NoteEvent::SettingsChanged);
            // A changed switch is no confirmation that the person looked at a
            // record or file changed outside SAM: only `mark_reviewed` clears
            // those marks. Nor that they looked at the settings SAM chose from
            // what the app says about itself (`reviewed`): one switch changed
            // on the command line, in the window or for a group of apps leaves
            // the others unconfirmed (review F5). Only flows that set the whole
            // set confirm it: `mark_reviewed`, a preset, `set_permissions`.
            now.clear_launch_failure();
            Ok(())
        })?;
        saved.with_context(|| sam_core::i18n::trf("no registered app '{id}'", &[("id", &id)]))
    }

    /// Changes one setting. Leaves the app unconfirmed when it was.
    pub fn set_permission(&self, query: &str, key: &str, value: &str) -> Result<AppEntry> {
        let mut e = self.resolve(query)?;
        let read = e.clone();
        e.profile.permissions.set_key(key, value)?;
        e.profile.preset = None;
        self.save_profile(&read, &mut e, SetChange::Switches, Grants::Refused)?;
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
        let read = e.clone();
        e.profile.permissions = perms;
        e.profile.preset = None;
        e.reviewed |= confirms;
        let kind = if confirms {
            SetChange::WholeSet
        } else {
            SetChange::Switches
        };
        self.save_profile(&read, &mut e, kind, Grants::Refused)?;
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

    /// Puts SAM's recommended settings back and forgets the repair steps,
    /// on the record as it is under the record lock. It also takes off each
    /// argument (`--no-sandbox`) that a step listed with its own record
    /// added. Steps applied by SAM 0.1.0 are listed by name only, so their
    /// arguments are not covered.
    pub fn reset_profile(&self, query: &str) -> Result<AppEntry> {
        let id = self.resolve(query)?.id;
        self.change_profile(&id, Grants::PutBack, |e| {
            let added_args: Vec<String> = e
                .applied_repairs
                .iter()
                .filter(|r| {
                    r.step
                        .as_ref()
                        .is_some_and(|s| matches!(s.action, FixAction::AddArg { .. }))
                })
                .filter_map(|r| r.added.clone())
                .collect();
            e.profile.args.retain(|a| !added_args.contains(a));
            e.profile.permissions = e.recommended.clone();
            e.profile.compatibility_mode = false;
            e.repairs_applied.clear();
            e.applied_repairs.clear();
            e.repair_backup = None;
            e.profile.preset = None;
            Ok(())
        })
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
        let read = e.clone();
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
        // Turning it off puts back the settings from before.
        let grants = if on { Grants::Refused } else { Grants::PutBack };
        self.save_profile(&read, &mut e, SetChange::WholeSet, grants)?;
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
        self.registry()
            .update(&e.id, |fresh| fresh.last_check = Some(out.record.clone()))?;
        Ok(out)
    }

    /// *Preferences → Check the sandbox before each start*: runs the sandbox
    /// check when the settings, SAM or this computer changed since the last
    /// passing check, and stops the start (code `sandbox-check-failed`)
    /// when a setting does not apply. Every way of starting an app (menu,
    /// window, `sam-jail run`) calls this, so none can skip it.
    pub fn check_before_start(&self, entry: &mut AppEntry, host: &HostInfo) -> Result<()> {
        self.make_own_tmp_folder(entry)?;
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

    /// Makes the folder of the app's own in `/tmp`
    /// ([`sam_core::places::own_tmp_folder`]) when its extra folders name
    /// it, at each start before the sandbox is set up, as
    /// [`make_own_tmp_folder_in`] makes it in `/tmp` for this account. A
    /// folder that is no folder, is a link, belongs to another account or
    /// others can open, or a grant of it that leads elsewhere through a
    /// link, stops the start (code `own-tmp-folder-unsafe`); nothing is changed or
    /// removed (owner decision 10 of 2026-11-23). `sam-jail selftest` calls
    /// it too.
    pub fn make_own_tmp_folder(&self, e: &AppEntry) -> Result<()> {
        let folder = sam_core::places::own_tmp_folder(&e.id);
        let home = sam_core::util::home_dir();
        // Every grant that names it as written (`/tmp/x/../sam-<id>` too);
        // each must lead to the folder checked, as the sandbox resolves it.
        let grants: Vec<PathBuf> =
            sam_core::places::own_tmp_folder_grants(&e.profile.permissions, &folder, &home)
                .iter()
                .map(|g| sam_core::util::expand_home(g))
                .collect();
        if grants.is_empty() {
            return Ok(());
        }
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        make_own_tmp_folder_in(
            Path::new("/tmp"),
            0,
            uid,
            &folder,
            &grants,
            e.display_name(),
        )
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
        let e = self.resolve(query)?;
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
        self.update_record(&e.id, |f| f.profile.args = args)
    }

    // ------------------------------------------------------------ repair

    /// Apply a first-run hint, log finding or repair step. Repair steps
    /// (`as_repair`) are remembered so "Undo repairs" can revert them all.
    /// One rated Think twice or Dangerous, one that turns on compatibility
    /// mode, or one from what the app printed needs `confirmed` (the person
    /// said yes), judged by SAM's one gate on the record that is changed
    /// and saved, so no caller can skip it (owner decisions 13 of
    /// 2026-11-23 and A of 2026-11-25, audit U-M2).
    pub fn apply_suggestion(
        &self,
        query: &str,
        sug: &Suggestion,
        as_repair: bool,
        confirmed: bool,
    ) -> Result<AppEntry> {
        let id = self.resolve(query)?.id;
        // Judged, applied and listed on the record as it is under the
        // record lock: a step another SAM process applied meanwhile stays
        // in the switches and in the list of applied steps, so every
        // switch a step turned off can be undone by name. The gate reads
        // the record and this computer's settings; its one slower check
        // (whether overlays work here, a short Bubblewrap run) is made
        // once per process.
        self.change_profile(&id, Grants::Refused, |e| {
            crate::gate::confirm(
                &crate::gate::Change::Apply {
                    e: &*e,
                    cfg: &self.config,
                    paths: &self.paths,
                    sug,
                },
                confirmed,
            )?;
            if as_repair && e.repair_backup.is_none() {
                e.repair_backup = Some(e.profile.clone());
            }
            // A step that replaces a grant SAM no longer gives is a safety
            // step, judged at once: never on trial, so a failed start
            // neither undoes it nor reports it undone (owner decision 10 of
            // 2026-11-23; its undo never brings the grant back).
            let safety = matches!(sug.action, FixAction::Replace { .. });
            let mut undo = sam_core::model::AppliedRepair {
                step: Some(sug.clone()),
                on_trial: as_repair && !safety,
                ..Default::default()
            };
            crate::repair::apply_step(e, sug, &mut undo)?;
            e.profile.preset = None;
            if as_repair && !e.repairs_applied.contains(&sug.id) {
                e.repairs_applied.push(sug.id.clone());
                e.applied_repairs.push(undo);
            }
            Ok(())
        })
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
        let id = self.resolve(query)?.id;
        // On the record as it is under the record lock, as for applying a
        // step: a step applied meanwhile keeps its entry in the list.
        self.change_profile(&id, Grants::PutBack, |e| {
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
            crate::repair::revert_step(e, &r)
        })
    }

    /// Undo every repair step, newest first, each taking back only what it
    /// changed: a change the person made since stays (audit G-F4: the whole
    /// profile from before the first step was put back). Older records
    /// without the steps' own records fall back to that copy.
    pub fn undo_repairs(&self, query: &str) -> Result<AppEntry> {
        let id = self.resolve(query)?.id;
        // On the record as it is under the record lock, as for one step:
        // a step another SAM process applied meanwhile, with its own
        // record, is turned back too.
        self.change_profile(&id, Grants::PutBack, |e| {
            if !e.applied_repairs.is_empty() {
                for r in e.applied_repairs.clone().iter().rev() {
                    crate::repair::revert_step(e, r)?;
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
            Ok(())
        })
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
        let id = self.resolve(query)?.id;
        before_save();
        // Checked against `seen` and confirmed on the record as it is under
        // the record lock: a mark or notice another SAM process saved after
        // the page was drawn is never cleared unseen. Without `seen`, what
        // is there when the lock is taken is confirmed.
        let saved = self.registry().update_confirmed(&id, |e| {
            if let Some(seen) = seen {
                if sam_storage::review_fingerprint(e)? != seen {
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
            settle_update_note(e, NoteEvent::Seen);
            // The one place that confirms changes made outside SAM.
            e.changed_outside = false;
            e.content_changed_outside = false;
            Ok(())
        })?;
        saved.with_context(|| sam_core::i18n::trf("no registered app '{id}'", &[("id", &id)]))
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
        let read = e.clone();
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
        // Refused before any question: no yes lifts it.
        crate::gate::refuse_tmp_grants(Some(&e), &e.profile.permissions, &preset.permissions)
            .with_context(|| {
                sam_core::i18n::trf(
                    "applying the preset “{preset}”",
                    &[("preset", &preset.name)],
                )
            })?;
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
        self.save_profile(&read, &mut e, SetChange::WholeSet, Grants::Refused)?;
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
            // All apps or none: refused before the first one is saved, and
            // shown by a dry run as well.
            crate::gate::refuse_tmp_grants(Some(&e), &e.profile.permissions, &new)?;
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
                let read = e.clone();
                out.previous.insert(
                    e.id.clone(),
                    std::mem::replace(&mut e.profile.permissions, new),
                );
                e.profile.preset = None;
                self.save_profile(&read, &mut e, SetChange::Switches, Grants::Refused)?;
            }
        }
        Ok(out)
    }

    /// Takes back a group change (its `undo`): only the setting it
    /// changed, so later changes to the apps stay (audit G-F4: the whole
    /// sets from before were written back). `confirm` sees the undo as one
    /// change of all its apps, for SAM's one gate ([`crate::gate`]), which
    /// the old whole-set restore passed by. All apps or none: a setting
    /// changed meanwhile refuses the whole undo.
    pub fn group_restore(
        &self,
        undo: BTreeMap<String, PermissionChange>,
        confirm: impl FnOnce(&crate::gate::Change<'_>) -> Result<()>,
    ) -> Result<usize> {
        let mut planned = Vec::new();
        let mut pairs = Vec::new();
        for (id, change) in &undo {
            let (e, merged) = self.plan_change(id, change)?;
            pairs.push((e.profile.permissions, merged.clone()));
            planned.push((e.id, merged));
        }
        confirm(&crate::gate::Change::Group(&pairs))?;
        let n = planned.len();
        for (id, perms) in planned {
            self.change_permissions(&id, perms)?;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod update_note_tests {
    use super::*;

    /// An app whose update asked for the network and sound, which its
    /// settings do not give yet.
    fn updated_app(sam: &Sam) -> AppEntry {
        let mut e = AppEntry {
            id: "appimage-noted-1a2b".into(),
            pending_changes: vec!["network".into(), "audio".into()],
            ..Default::default()
        };
        e.recommended.network.mode = NetworkMode::Full;
        e.recommended.audio.enabled = true;
        e.profile.permissions.network.mode = NetworkMode::None;
        e.profile.permissions.audio.enabled = false;
        e.profile.permissions.devices.gpu = false;
        sam.registry().save(&mut e).unwrap();
        e
    }

    fn note(sam: &Sam, e: &AppEntry) -> Vec<String> {
        sam.registry().get(&e.id).unwrap().unwrap().pending_changes
    }

    /// A switch the note does not name, changed on the app's page or the
    /// command line, keeps the note: the person has not seen it by that
    /// (review L5; before, any change cleared it).
    #[test]
    fn a_switch_change_unrelated_to_the_note_keeps_it() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let e = updated_app(&sam);
        sam.set_permission(&e.id, "devices.gpu", "true").unwrap();
        assert_eq!(note(&sam, &e), ["network", "audio"]);
    }

    /// A change for a group of apps on the permissions page keeps the
    /// note of what it does not grant (review L5).
    #[test]
    fn a_group_change_from_the_permissions_page_keeps_the_note() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let e = updated_app(&sam);
        let done = sam
            .group_change("devices.gpu", "true", std::slice::from_ref(&e.id), false)
            .unwrap();
        assert!(done.apps[0].changed, "the group change saved the app");
        assert_eq!(note(&sam, &e), ["network", "audio"]);
    }

    /// Granting what the note asked for takes exactly that need off the
    /// note; the others stay.
    #[test]
    fn granting_exactly_the_requested_need_removes_it_from_the_note() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let e = updated_app(&sam);
        sam.set_permission(&e.id, "network.mode", "full").unwrap();
        assert_eq!(note(&sam, &e), ["audio"]);
        sam.set_permission(&e.id, "audio.enabled", "true").unwrap();
        assert!(note(&sam, &e).is_empty(), "both needs granted");
    }

    /// A folder need counts as granted only at the level the
    /// recommendation asks for: read access does not grant read and write.
    #[test]
    fn a_folder_need_is_granted_only_at_the_level_asked() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let mut e = updated_app(&sam);
        e.pending_changes = vec!["downloads folder".into()];
        e.recommended.filesystem.downloads = Access::Rw;
        e.profile.permissions.filesystem.downloads = Access::None;
        sam.registry().save(&mut e).unwrap();
        sam.set_permission(&e.id, "filesystem.downloads", "ro")
            .unwrap();
        assert_eq!(note(&sam, &e), ["downloads folder"]);
        sam.set_permission(&e.id, "filesystem.downloads", "rw")
            .unwrap();
        assert!(note(&sam, &e).is_empty());
    }

    /// The note kept through a change goes with its own "Got It" (the
    /// app's review), even with nothing granted.
    #[test]
    fn a_note_kept_through_a_change_goes_with_got_it() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let e = updated_app(&sam);
        sam.set_permission(&e.id, "devices.gpu", "true").unwrap();
        assert_eq!(note(&sam, &e), ["network", "audio"], "kept by the change");
        sam.mark_reviewed(&e.id).unwrap();
        assert!(note(&sam, &e).is_empty(), "cleared by Got It");
    }

    /// Reading the app again (an update, Unpack Again) adds what it newly
    /// asks for and keeps what an earlier update asked for and nobody saw;
    /// before, the new list replaced the note, so a second Unpack Again
    /// emptied it.
    #[test]
    fn reading_the_app_again_keeps_an_unseen_need() {
        let mut e = AppEntry {
            pending_changes: vec!["network".into()],
            ..Default::default()
        };
        e.recommended.network.mode = NetworkMode::Full;
        e.recommended.devices.gpu = true;
        e.profile.permissions.network.mode = NetworkMode::None;
        e.profile.permissions.devices.gpu = false;
        settle_update_note(&mut e, NoteEvent::Asked(Vec::new()));
        assert_eq!(e.pending_changes, ["network"]);
        settle_update_note(
            &mut e,
            NoteEvent::Asked(vec!["GPU".into(), "network".into()]),
        );
        assert_eq!(e.pending_changes, ["network", "GPU"]);
    }

    /// The note names the needs as before the one list (GPU, audio,
    /// network, X11, folders), only those newly asked for and missing.
    #[test]
    fn the_note_names_new_needs_the_settings_lack() {
        let old = PermissionSet::default();
        let mut new = old.clone();
        new.devices.gpu = true;
        new.audio.enabled = true;
        new.network.mode = NetworkMode::Full;
        new.display.x11 = true;
        new.filesystem.music = Access::Ro;
        new.filesystem.downloads = Access::Rw;
        let mut cur = old.clone();
        cur.audio.enabled = true;
        cur.filesystem.downloads = Access::Ro;
        cur.devices.gpu = false;
        cur.network.mode = NetworkMode::None;
        cur.display.x11 = false;
        cur.filesystem.music = Access::None;
        assert_eq!(
            new_requirements(&old, &new, &cur),
            ["GPU", "network", "X11", "downloads folder", "music folder"]
        );
    }

    /// A need the old recommendation already asked for is not new: when
    /// the person switched it off (the GPU) or gave less (the downloads
    /// folder read-only instead of read and write), the note after an
    /// update or Unpack Again does not name it again as if the app newly
    /// asked for it. Only what the app newly asks for (sound) is named.
    #[test]
    fn the_note_leaves_out_a_need_the_old_recommendation_already_asked_for() {
        let mut old = PermissionSet::default();
        old.devices.gpu = true;
        old.filesystem.downloads = Access::Rw;
        old.audio.enabled = false;
        let mut new = old.clone();
        new.audio.enabled = true;
        let mut cur = old.clone();
        cur.devices.gpu = false;
        cur.filesystem.downloads = Access::Ro;
        cur.audio.enabled = false;
        assert_eq!(new_requirements(&old, &new, &cur), ["audio"]);
    }

    /// The mark that the person changed an app's settings, which `sam
    /// profile get` shows, says whether they differ from SAM's
    /// recommendation after each change: set when a switch leaves it, and
    /// cleared when the switch goes back. Read from the saved record, not
    /// after reading the app again, which works the mark out anew.
    #[test]
    fn a_changed_switch_marks_the_profile_as_changed_and_undoing_it_clears_the_mark() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let mut e = AppEntry {
            id: "appimage-modified-1a2b".into(),
            ..Default::default()
        };
        e.recommended.devices.gpu = false;
        e.profile.permissions.devices.gpu = false;
        sam.registry().save(&mut e).unwrap();
        let changed = |sam: &Sam| {
            sam.registry()
                .get(&e.id)
                .unwrap()
                .unwrap()
                .profile
                .user_modified
        };
        sam.set_permission(&e.id, "devices.gpu", "true").unwrap();
        assert!(
            changed(&sam),
            "a switch that differs from the recommendation is saved as changed"
        );
        sam.set_permission(&e.id, "devices.gpu", "false").unwrap();
        assert!(
            !changed(&sam),
            "back on the recommendation is no longer changed"
        );
    }
}

#[cfg(test)]
mod record_lock_tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// What another SAM process saves between a writer's read and its
        /// save ([`meanwhile`]).
        static BEFORE_SAVE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    /// Called by a change of the settings (`save_profile`, a repair step)
    /// and by a confirmation before they take the record lock: the moment
    /// a save by another process can land between the writer's read and
    /// its save.
    pub(super) fn before_save() {
        if let Some(h) = BEFORE_SAVE.with(|h| h.borrow_mut().take()) {
            h();
        }
    }

    /// The next `save_profile` on this thread first runs `f`.
    fn meanwhile(f: impl FnOnce() + 'static) {
        BEFORE_SAVE.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    /// Grants a folder through another SAM process, as `sam-jail set`
    /// from a terminal does while the window saves.
    fn grant_meanwhile(paths: &Paths, id: &'static str) {
        let paths = paths.clone();
        meanwhile(move || {
            Sam::with_paths(paths)
                .unwrap()
                .update_record(id, |f| {
                    f.profile
                        .permissions
                        .filesystem
                        .custom_write
                        .push("~/Granted meanwhile".into())
                })
                .unwrap();
        });
    }

    fn granted_meanwhile(e: &AppEntry) -> bool {
        e.profile
            .permissions
            .filesystem
            .custom_write
            .iter()
            .any(|p| p.contains("meanwhile"))
    }

    /// Every writer that replaces the whole set (a whole set the person
    /// confirmed, a preset, a reset, the compatibility mode, an undo of
    /// the repair steps of an older record that lists no step of its own and
    /// goes back to the copy from before the first step) saves exactly the
    /// set it chose, also when another
    /// SAM process granted a folder between the writer's read and its
    /// save. Before, each setting the writer left as it read it kept the
    /// value on disk, so the saved set held a grant nobody chose while it
    /// counted as confirmed or carried the preset's name.
    #[test]
    fn a_whole_set_is_saved_as_chosen_when_a_switch_was_saved_meanwhile() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(t.path());
        let sam = Sam::with_paths(paths.clone()).unwrap();
        let base = PermissionSet::strict_gui();
        let mut start = base.clone();
        start.devices.gpu = !base.devices.gpu;
        let mut preset = Preset {
            name: "Offline".into(),
            permissions: base.clone(),
            ..Default::default()
        };
        PresetStore::new(&paths).save(&mut preset).unwrap();
        const ID: &str = "appimage-whole-1a2b";
        type Writer = Box<dyn Fn(&Sam)>;
        let writers: Vec<(&str, PermissionSet, Writer)> = vec![
            (
                "a whole set confirmed",
                base.clone(),
                Box::new(|s| {
                    s.set_permissions(ID, PermissionSet::strict_gui()).unwrap();
                }),
            ),
            (
                "a preset",
                base.clone(),
                Box::new(|s| {
                    assert!(s.apply_preset(ID, "Offline", true, None).unwrap().applied);
                }),
            ),
            (
                "a reset",
                base.clone(),
                Box::new(|s| {
                    s.reset_profile(ID).unwrap();
                }),
            ),
            (
                "the compatibility mode",
                compatibility_profile(&start),
                Box::new(|s| {
                    s.set_compat(ID, true).unwrap();
                }),
            ),
            (
                "an undo of the repair steps",
                base.clone(),
                Box::new(|s| {
                    s.undo_repairs(ID).unwrap();
                }),
            ),
        ];
        for (what, chosen, write) in writers {
            let mut e = AppEntry {
                id: ID.into(),
                name: "Whole".into(),
                recommended: base.clone(),
                repair_backup: Some(SandboxProfile {
                    permissions: base.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            e.profile.permissions = start.clone();
            sam.registry().save_confirmed(&mut e).unwrap();
            grant_meanwhile(&paths, ID);
            write(&sam);
            let back = sam.resolve(ID).unwrap();
            assert!(
                !granted_meanwhile(&back),
                "{what}: a folder nobody chose was mixed into the saved set"
            );
            assert_eq!(back.profile.permissions, chosen, "{what}");
        }
    }

    /// A writer that changes one switch still saves only that switch: a
    /// folder another SAM process granted between its read and its save
    /// stays.
    #[test]
    fn one_switch_changed_keeps_a_grant_saved_meanwhile() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(t.path());
        let sam = Sam::with_paths(paths.clone()).unwrap();
        const ID: &str = "appimage-switch-1a2b";
        let mut e = AppEntry {
            id: ID.into(),
            name: "Switch".into(),
            ..Default::default()
        };
        e.profile.permissions.devices.gpu = false;
        sam.registry().save_confirmed(&mut e).unwrap();
        grant_meanwhile(&paths, ID);
        sam.set_permission(ID, "devices.gpu", "true").unwrap();
        let back = sam.resolve(ID).unwrap();
        assert!(back.profile.permissions.devices.gpu, "the switch is saved");
        assert!(granted_meanwhile(&back), "the grant saved meanwhile stays");
    }

    /// A change of the settings made on a copy read before an "unpack
    /// again" or an update saved its result saves only the change: the
    /// new unpacked copy, the notice of a changed signing key and the
    /// "look at it first" mark that step saved stay (before, the whole
    /// copy was written back, and the next start ran the new content
    /// without the notice).
    #[test]
    fn a_settings_change_keeps_what_an_unpack_saved_meanwhile() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let mut e = AppEntry {
            id: "appimage-overlap-1a2b".into(),
            extraction: Some(Default::default()),
            ..Default::default()
        };
        e.profile.permissions.devices.gpu = false;
        sam.registry().save(&mut e).unwrap();
        let read = sam.resolve(&e.id).unwrap();
        // Saved by an "unpack again" while the settings change was made.
        sam.update_record(&e.id, |f| {
            f.content_changed_outside = true;
            f.signing_key_changed = Some("the earlier key".into());
            f.source.sha256 = "1".repeat(64);
            f.extraction.as_mut().unwrap().appdir = "/unpacked/again".into();
        })
        .unwrap();
        let mut changed = read.clone();
        changed.profile.permissions.devices.gpu = true;
        sam.save_profile(&read, &mut changed, SetChange::Switches, Grants::Refused)
            .unwrap();
        let back = sam.registry().get(&e.id).unwrap().unwrap();
        assert!(back.profile.permissions.devices.gpu, "the change is saved");
        assert!(back.profile.user_modified);
        assert_eq!(
            back.signing_key_changed.as_deref(),
            Some("the earlier key"),
            "the notice of a changed signing key stays"
        );
        assert_eq!(back.source.sha256, "1".repeat(64), "the new file stays");
        assert_eq!(
            back.extraction.unwrap().appdir,
            Path::new("/unpacked/again"),
            "the new unpacked copy stays"
        );
        assert!(back.content_changed_outside, "the mark stays");
        assert_eq!(changed.signing_key_changed, back.signing_key_changed);
    }

    /// A repair step that sets one switch, as SAM's ladder offers them.
    fn step(id: &str, key: &str, value: &str) -> Suggestion {
        Suggestion {
            id: id.into(),
            title: id.into(),
            explanation: String::new(),
            action: FixAction::Set {
                key: key.into(),
                value: value.into(),
            },
            risk: RiskLevel::High,
            from_app_output: false,
        }
    }

    fn seccomp_off() -> Suggestion {
        step("seccomp-baseline", "advanced.seccomp_baseline", "false")
    }

    fn userns_on() -> Suggestion {
        step("userns", "advanced.allow_userns", "true")
    }

    /// The steps the record lists as applied, by id.
    fn listed(e: &AppEntry) -> Vec<String> {
        e.applied_repairs
            .iter()
            .filter_map(|r| r.step.as_ref())
            .map(|s| s.id.clone())
            .collect()
    }

    /// A record with SAM's strict settings for a window app, confirmed.
    fn strict_app(sam: &Sam, id: &str) {
        let mut e = AppEntry {
            id: id.into(),
            name: "Steps".into(),
            recommended: PermissionSet::strict_gui(),
            ..Default::default()
        };
        e.profile.permissions = PermissionSet::strict_gui();
        sam.registry().save_confirmed(&mut e).unwrap();
    }

    /// Two repair steps applied at the same time (the window and
    /// `sam-jail repair` from a terminal) are both applied and both
    /// listed. Before, the switches were saved one by one but the list of
    /// applied steps as one value: the later save's list replaced the
    /// earlier one, and the syscall filter stayed off with no record of the
    /// step that turned it off.
    #[test]
    fn two_repair_steps_applied_at_once_are_both_listed() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(t.path());
        let sam = Sam::with_paths(paths.clone()).unwrap();
        const ID: &str = "appimage-steps-1a2b";
        strict_app(&sam, ID);
        let other = paths.clone();
        meanwhile(move || {
            Sam::with_paths(other)
                .unwrap()
                .apply_suggestion(ID, &userns_on(), true, true)
                .unwrap();
        });
        sam.apply_suggestion(ID, &seccomp_off(), true, true)
            .unwrap();
        let back = sam.resolve(ID).unwrap();
        let p = &back.profile.permissions.advanced;
        assert!(!p.seccomp_baseline && p.allow_userns, "both steps applied");
        assert_eq!(
            listed(&back),
            ["userns", "seccomp-baseline"],
            "a switch a step changed is not listed as that step"
        );
        assert_eq!(back.repairs_applied, ["userns", "seccomp-baseline"]);
        let undone = sam.undo_repairs(ID).unwrap();
        let p = &undone.profile.permissions.advanced;
        assert!(
            p.seccomp_baseline && !p.allow_userns,
            "\"Undo repairs\" turns every step back"
        );
    }

    /// Undoing one repair step while another SAM process applies another
    /// step keeps that other step applied and listed. Before, the undo
    /// saved its list without the new step, while the new step's switch
    /// (the syscall filter off) stayed.
    #[test]
    fn undoing_one_repair_step_keeps_a_step_applied_meanwhile() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(t.path());
        let sam = Sam::with_paths(paths.clone()).unwrap();
        const ID: &str = "appimage-undo-1a2b";
        strict_app(&sam, ID);
        sam.apply_suggestion(ID, &userns_on(), true, true).unwrap();
        let other = paths.clone();
        meanwhile(move || {
            Sam::with_paths(other)
                .unwrap()
                .apply_suggestion(ID, &seccomp_off(), true, true)
                .unwrap();
        });
        sam.undo_repair_step(ID, "userns").unwrap();
        let back = sam.resolve(ID).unwrap();
        let p = &back.profile.permissions.advanced;
        assert!(!p.allow_userns, "the undone step is undone");
        assert!(!p.seccomp_baseline, "the step applied meanwhile stays");
        assert_eq!(
            listed(&back),
            ["seccomp-baseline"],
            "the step applied meanwhile is no longer listed"
        );
        let undone = sam.undo_repair_step(ID, "seccomp-baseline").unwrap();
        assert!(undone.profile.permissions.advanced.seccomp_baseline);
    }

    /// "Undo repairs" and a reset made while another SAM process applies a
    /// repair step that adds an argument (`--no-sandbox`, which turns off
    /// the app's own Chromium sandbox) also take off that step's argument.
    /// Before, both worked on a copy read before that step was saved: the
    /// argument on disk stayed, and the lists that named the step were
    /// saved empty.
    #[test]
    fn undoing_repairs_or_a_reset_turns_back_an_argument_a_step_added_meanwhile() {
        let no_sandbox = || Suggestion {
            action: FixAction::AddArg {
                value: "--no-sandbox".into(),
            },
            ..step("chromium-no-sandbox", "", "")
        };
        type Writer = fn(&Sam, &str) -> Result<AppEntry>;
        let writers: [(&str, Writer); 2] = [
            ("\"Undo repairs\"", |s, id| s.undo_repairs(id)),
            ("a reset", |s, id| s.reset_profile(id)),
        ];
        for (what, write) in writers {
            let t = tempfile::tempdir().unwrap();
            let paths = Paths::rooted(t.path());
            let sam = Sam::with_paths(paths.clone()).unwrap();
            const ID: &str = "appimage-args-1a2b";
            strict_app(&sam, ID);
            sam.apply_suggestion(ID, &userns_on(), true, true).unwrap();
            let other = paths.clone();
            let step = no_sandbox();
            meanwhile(move || {
                Sam::with_paths(other)
                    .unwrap()
                    .apply_suggestion(ID, &step, true, true)
                    .unwrap();
            });
            write(&sam, ID).unwrap();
            let back = sam.resolve(ID).unwrap();
            assert!(
                !back.profile.args.iter().any(|a| a == "--no-sandbox"),
                "{what}: --no-sandbox stays on; the steps still listed: {:?}",
                listed(&back)
            );
            assert!(
                back.applied_repairs.is_empty() && back.repairs_applied.is_empty(),
                "{what}"
            );
            assert!(!back.profile.permissions.advanced.allow_userns, "{what}");
        }
    }

    /// Confirming from the app's page (`sam-jail review --seen`) checks
    /// what the page showed on the record as it is under the record lock:
    /// a "look at it first" mark another SAM process saves after the page
    /// was drawn and before the confirmation takes the lock makes the
    /// confirmation fail with `review-out-of-date`, and the mark stays.
    /// Checked before the lock was taken, the confirmation cleared a mark
    /// nobody saw.
    #[test]
    fn a_confirmation_from_the_page_never_clears_a_mark_saved_before_its_lock() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(t.path());
        let sam = Sam::with_paths(paths.clone()).unwrap();
        const ID: &str = "appimage-shown-1a2b";
        let mut e = AppEntry {
            id: ID.into(),
            name: "Shown".into(),
            ..Default::default()
        };
        sam.registry().save_confirmed(&mut e).unwrap();
        let shown = sam_storage::review_fingerprint(&sam.resolve(ID).unwrap()).unwrap();
        let other = paths.clone();
        meanwhile(move || {
            Sam::with_paths(other)
                .unwrap()
                .update_record(ID, |f| f.content_changed_outside = true)
                .unwrap();
        });
        let err = sam
            .mark_reviewed_as_shown(ID, Some(&shown))
            .expect_err("a mark the page never showed was confirmed");
        assert_eq!(
            sam_core::error::code_of(&err),
            Some("review-out-of-date"),
            "{err:#}"
        );
        let back = sam.resolve(ID).unwrap();
        assert!(back.content_changed_outside, "the mark stays");
        assert!(!back.reviewed, "nothing is confirmed");
    }
}

#[cfg(test)]
mod tmp_grant_tests {
    use super::*;
    use sam_core::error::code_of;

    const ID: &str = "appimage-grants-1a2b";

    /// A confirmed record with SAM's strict settings and these extra
    /// folders, saved as an older record would be (no check on the way).
    fn app(sam: &Sam, read: &[&str], write: &[&str]) -> AppEntry {
        let mut e = AppEntry {
            id: ID.into(),
            name: "Grants".into(),
            recommended: PermissionSet::strict_gui(),
            ..Default::default()
        };
        e.profile.permissions = PermissionSet::strict_gui();
        let f = &mut e.profile.permissions.filesystem;
        f.custom_read = read.iter().map(|x| x.to_string()).collect();
        f.custom_write = write.iter().map(|x| x.to_string()).collect();
        sam.registry().save_confirmed(&mut e).unwrap();
        sam.resolve(ID).unwrap()
    }

    fn refused<T: std::fmt::Debug>(what: &str, r: Result<T>) {
        let err = r.expect_err(what);
        assert_eq!(code_of(&err), Some("tmp-grant-refused"), "{what}: {err:#}");
    }

    fn with_tmp(p: &PermissionSet, path: &str) -> PermissionSet {
        let mut p = p.clone();
        p.filesystem.custom_read.push(path.into());
        p
    }

    /// Every way to change an app's settings refuses a new grant of /tmp
    /// or of a known socket folder in it (tmux, SSH, the X server …),
    /// also after a yes, and changes nothing: one setting, a whole set, a
    /// change of some, several apps at once and their undo, a preset, a
    /// hint, and adding an app with adjusted settings or a preset (owner
    /// decision 10 of 2026-11-23).
    #[test]
    fn every_way_to_change_settings_refuses_a_new_tmp_grant() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let e = app(&sam, &["/a"], &[]);
        let start = e.profile.permissions.clone();
        let unchanged = |what: &str| {
            assert_eq!(
                sam.resolve(ID).unwrap().profile.permissions,
                start,
                "{what}"
            );
        };
        refused(
            "set",
            sam.set_permission(ID, "filesystem.custom_read", "/a, /tmp"),
        );
        unchanged("set");
        refused(
            "profile set",
            sam.set_permissions(ID, with_tmp(&start, "/tmp/.X11-unix")),
        );
        unchanged("profile set");
        refused(
            "profile change",
            sam.change_permissions(ID, with_tmp(&start, "//tmp")),
        );
        unchanged("profile change");
        refused(
            "group set",
            sam.group_change(
                "filesystem.custom_write",
                "/tmp/tmux-1000",
                &[ID.into()],
                false,
            ),
        );
        refused(
            "group set, dry run",
            sam.group_change(
                "filesystem.custom_write",
                "/tmp/tmux-1000",
                &[ID.into()],
                true,
            ),
        );
        unchanged("group set");
        let mut undo = BTreeMap::new();
        undo.insert(
            ID.to_string(),
            PermissionChange {
                from: start.clone(),
                to: with_tmp(&start, "/tmp"),
            },
        );
        refused("group restore", sam.group_restore(undo.clone(), |_| Ok(())));
        refused(
            "group restore after a yes",
            sam.group_restore(undo, |c| crate::gate::confirm(c, true)),
        );
        unchanged("group restore");
        let preset = Preset {
            name: "Shares tmp".into(),
            permissions: with_tmp(&start, "/tmp"),
            ..Default::default()
        };
        fs::create_dir_all(sam.paths.presets_dir()).unwrap();
        fs::write(
            sam.paths.presets_dir().join("shares-tmp.toml"),
            sam_storage::preset_to_toml(&preset).unwrap(),
        )
        .unwrap();
        let err = sam.apply_preset(ID, "Shares tmp", true, None).unwrap_err();
        assert_eq!(code_of(&err), Some("tmp-grant-refused"), "{err:#}");
        assert!(format!("{err:#}").contains("Shares tmp"), "{err:#}");
        unchanged("preset apply");
        let hint = Suggestion {
            id: "folder".into(),
            title: "folder".into(),
            explanation: String::new(),
            action: FixAction::Add {
                key: "filesystem.custom_read".into(),
                value: "/tmp".into(),
            },
            risk: RiskLevel::Dangerous,
            from_app_output: false,
        };
        refused("a hint", sam.apply_suggestion(ID, &hint, true, true));
        unchanged("a hint");
        let missing = t.path().join("New.AppImage");
        let adjusted = AddOptions {
            permissions: Some(with_tmp(&PermissionSet::strict_gui(), "/tmp")),
            ..Default::default()
        };
        refused("add with settings", sam.add(&missing, &adjusted));
        let with_preset = AddOptions {
            preset: Some("Shares tmp".into()),
            ..Default::default()
        };
        refused("add with a preset", sam.add(&missing, &with_preset));
        assert_eq!(sam.registry().list().unwrap().len(), 1, "nothing added");
        // A new folder written relative is refused by its own code.
        let err = sam
            .set_permission(ID, "filesystem.custom_read", "/a, ../../../../tmp")
            .unwrap_err();
        assert_eq!(code_of(&err), Some("relative-grant-refused"), "{err:#}");
        unchanged("a relative folder");
        // Another folder in /tmp is no such grant.
        sam.set_permission(ID, "filesystem.custom_read", "/a, /tmp/exchange")
            .unwrap();
    }

    /// An older grant of /tmp stays through every change that puts back
    /// what the record held: compatibility mode on and off (also when the
    /// grant was taken out while it was on, by the switch or as a repair
    /// step undone), a repair step and its undo, an undo of all steps (also
    /// of an older record that keeps only its whole profile), and another
    /// setting changed. A reset takes SAM's recommendation, which names no
    /// extra folder.
    #[test]
    fn turning_compatibility_off_and_undoing_keep_an_older_tmp_grant() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        app(&sam, &["/tmp"], &[]);
        let still = |what: &str| {
            let back = sam.resolve(ID).unwrap();
            assert!(
                back.profile
                    .permissions
                    .filesystem
                    .custom_read
                    .contains(&"/tmp".to_string()),
                "{what}: {:?}",
                back.profile.permissions.filesystem
            );
        };
        sam.set_compat(ID, true).unwrap();
        still("compatibility mode on");
        sam.set_compat(ID, false).unwrap();
        still("compatibility mode off");
        // Taken out while compatibility mode is on, the grant comes back
        // with the settings from before when it is turned off: that is no
        // new grant, and refusing it would keep the app in that mode.
        sam.set_compat(ID, true).unwrap();
        sam.set_permission(ID, "filesystem.custom_read", "")
            .unwrap();
        sam.set_compat(ID, false).unwrap();
        still("the settings from before compatibility mode");
        sam.set_permission(ID, "devices.gpu", "true").unwrap();
        still("another setting");
        let step = Suggestion {
            id: "userns".into(),
            title: "userns".into(),
            explanation: String::new(),
            action: FixAction::Set {
                key: "advanced.allow_userns".into(),
                value: "true".into(),
            },
            risk: RiskLevel::Medium,
            from_app_output: false,
        };
        sam.apply_suggestion(ID, &step, true, true).unwrap();
        sam.undo_repair_step(ID, "userns").unwrap();
        still("one step undone");
        sam.apply_suggestion(ID, &step, true, true).unwrap();
        sam.undo_repairs(ID).unwrap();
        still("all steps undone");
        // Compatibility mode as a repair step, the grant taken out while it
        // is on, then that step undone: the settings from before come back.
        sam.apply_suggestion(ID, &crate::repair::compat_step(), true, true)
            .unwrap();
        sam.set_permission(ID, "filesystem.custom_read", "")
            .unwrap();
        sam.undo_repair_step(ID, "compat").unwrap();
        still("the compatibility step undone");
        // An older record that keeps only its whole profile from before the
        // first step: undoing all steps puts it back.
        let mut e = sam.resolve(ID).unwrap();
        e.repair_backup = Some(e.profile.clone());
        e.applied_repairs.clear();
        e.repairs_applied.clear();
        e.profile.permissions.filesystem.custom_read.clear();
        sam.registry().save_confirmed(&mut e).unwrap();
        sam.undo_repairs(ID).unwrap();
        still("an older record's undo of all steps");
        let back = sam.reset_profile(ID).unwrap();
        let f = &back.profile.permissions.filesystem;
        assert!(
            f.custom_read.is_empty() && f.custom_write.is_empty(),
            "{f:?}"
        );
        let rec = sam_profile::recommend(&Default::default(), "New.AppImage", None).permissions;
        assert!(rec.filesystem.custom_read.is_empty() && rec.filesystem.custom_write.is_empty());
    }

    /// Once an older grant of /tmp is replaced by the folder of the app's
    /// own, no undo brings it back: not the step's own undo, not an undo of
    /// all steps (also of an older record), not a failed start (the step is
    /// never on trial, and nothing is reported undone), and not turning
    /// compatibility mode off.
    #[test]
    fn no_undo_brings_tmp_back() {
        let t = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        let own = sam_core::places::own_tmp_folder(ID)
            .to_string_lossy()
            .into_owned();
        let check = |e: &AppEntry, what: &str| {
            let f = &e.profile.permissions.filesystem;
            assert_eq!(f.custom_write, vec![own.clone()], "{what}");
        };
        let replace = |sam: &Sam| {
            let e = sam.resolve(ID).unwrap();
            let hint = crate::repair::first_run_hints(&e)
                .into_iter()
                .find(|h| h.id == "tmp-own-folder")
                .expect("the hint");
            sam.apply_suggestion(ID, &hint, true, true).unwrap()
        };
        app(&sam, &[], &["/tmp"]);
        replace(&sam);
        check(
            &sam.undo_repair_step(ID, "tmp-own-folder").unwrap(),
            "its undo",
        );
        app(&sam, &[], &["/tmp"]);
        replace(&sam);
        check(&sam.undo_repairs(ID).unwrap(), "undo of all steps");
        app(&sam, &[], &["/tmp"]);
        let mut e = replace(&sam);
        assert!(
            e.applied_repairs.iter().all(|r| !r.on_trial),
            "a safety step is never on trial"
        );
        assert!(
            crate::repair::judge_trials(&mut e, false).is_empty(),
            "a failed start reports nothing undone"
        );
        check(&e, "a failed start");
        app(&sam, &[], &["/tmp"]);
        sam.set_compat(ID, true).unwrap();
        replace(&sam);
        check(
            &sam.set_compat(ID, false).unwrap(),
            "compatibility mode off",
        );
        // An older record in compatibility mode that keeps only its whole
        // profile from before the first step: the hint replaces the grant
        // there too, so undoing all steps and then turning compatibility
        // mode off bring nothing back.
        app(&sam, &[], &["/tmp"]);
        sam.set_compat(ID, true).unwrap();
        let mut e = sam.resolve(ID).unwrap();
        e.repair_backup = Some(e.profile.clone());
        sam.registry().save_confirmed(&mut e).unwrap();
        let hint = crate::repair::first_run_hints(&e)
            .into_iter()
            .find(|h| h.id == "tmp-own-folder")
            .unwrap();
        sam.apply_suggestion(ID, &hint, false, true).unwrap();
        sam.undo_repairs(ID).unwrap();
        check(
            &sam.set_compat(ID, false).unwrap(),
            "an older record's undo, then compatibility mode off",
        );
    }

    /// The folder of an app's own is made for this account only (mode
    /// 0700) in a base folder with the sticky bit; one that is there and
    /// only this account can open is kept with what it holds.
    #[test]
    fn the_folder_of_its_own_is_made_for_you_only_at_each_start() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let t = tempfile::tempdir().unwrap();
        // Where links on the way are resolved already, as the sandbox
        // resolves a grant.
        let base = fs::canonicalize(t.path()).unwrap().join("tmp");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o1777)).unwrap();
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let folder = base.join("sam-appimage-grants-1a2b");
        make_own_tmp_folder_in(
            &base,
            uid,
            uid,
            &folder,
            std::slice::from_ref(&folder),
            "Grants",
        )
        .unwrap();
        let m = fs::symlink_metadata(&folder).unwrap();
        assert!(m.is_dir());
        assert_eq!(m.mode() & 0o7777, 0o700);
        assert_eq!(m.uid(), uid);
        fs::write(folder.join("kept"), "x").unwrap();
        make_own_tmp_folder_in(
            &base,
            uid,
            uid,
            &folder,
            std::slice::from_ref(&folder),
            "Grants",
        )
        .unwrap();
        assert!(folder.join("kept").exists(), "an existing folder is kept");
    }

    /// Every start makes the folder of the app's own in /tmp (the
    /// container's own) when the app's folders name it in any form, for
    /// this account only, before the sandbox check; an app that does not
    /// name it gets none.
    #[test]
    fn every_start_makes_the_folder_of_its_own_in_tmp() {
        use std::os::unix::fs::MetadataExt;
        let t = tempfile::tempdir().unwrap();
        let mut sam = Sam::with_paths(Paths::rooted(t.path())).unwrap();
        sam.config.security.check_before_launch = false;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = format!("appimage-starts-{}-{nanos}", std::process::id());
        let own = sam_core::places::own_tmp_folder(&id);
        let mut e = AppEntry {
            id: id.clone(),
            name: "Starts".into(),
            ..Default::default()
        };
        e.profile.permissions = PermissionSet::strict_gui();
        e.profile.permissions.filesystem.custom_read = vec!["/tmp/exchange".into()];
        let host = sam_core::sandbox::sample_context().host;
        sam.check_before_start(&mut e, &host).unwrap();
        assert!(!own.exists(), "an app that does not name it gets none");
        e.profile.permissions.filesystem.custom_write = vec![format!("/tmp//./sam-{id}/")];
        sam.check_before_start(&mut e, &host).unwrap();
        let m = fs::symlink_metadata(&own).unwrap();
        fs::remove_dir(&own).unwrap();
        assert!(m.is_dir());
        assert_eq!(m.mode() & 0o7777, 0o700);
        // SAFETY: getuid has no preconditions and cannot fail.
        assert_eq!(m.uid(), unsafe { libc::getuid() });
    }

    /// A folder of the app's own that other accounts can open, one that is
    /// a link, a grant of it that leads elsewhere through a link on the
    /// way, one owned by another account, and a base folder without the
    /// sticky bit or owned by another account each stop the start, and
    /// nothing is changed or removed.
    #[test]
    fn a_folder_of_its_own_that_others_can_open_or_that_is_a_link_stops_the_start() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        // Where links on the way are resolved already, as the sandbox
        // resolves a grant.
        let base = fs::canonicalize(t.path()).unwrap().join("tmp");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o1777)).unwrap();
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let folder = base.join("sam-appimage-grants-1a2b");
        let stops = |base_owner: u32, uid: u32, what: &str| {
            let err = make_own_tmp_folder_in(&base, base_owner, uid, &folder, &[], "Grants")
                .expect_err(what);
            assert_eq!(
                code_of(&err),
                Some("own-tmp-folder-unsafe"),
                "{what}: {err:#}"
            );
            err.to_string()
        };
        fs::create_dir(&folder).unwrap();
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
        let text = stops(uid, uid, "others can open it");
        assert!(text.contains(&folder.display().to_string()), "{text}");
        assert_eq!(
            fs::metadata(&folder).unwrap().permissions().mode() & 0o777,
            0o755,
            "left as it was"
        );
        fs::remove_dir(&folder).unwrap();
        let elsewhere = t.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &folder).unwrap();
        stops(uid, uid, "a link");
        assert!(fs::symlink_metadata(&folder)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_file(&folder).unwrap();
        // A grant of it through a link on the way that leads elsewhere
        // (`base/x/../sam-<id>` with `x` a link to a folder outside base):
        // the sandbox would mount another place than the folder checked.
        let deep = elsewhere.join("deep");
        fs::create_dir(&deep).unwrap();
        std::os::unix::fs::symlink(&deep, base.join("x")).unwrap();
        let through = base.join("x/../sam-appimage-grants-1a2b");
        let err = make_own_tmp_folder_in(&base, uid, uid, &folder, &[through], "Grants")
            .expect_err("a grant through a link");
        assert_eq!(code_of(&err), Some("own-tmp-folder-unsafe"), "{err:#}");
        assert!(
            err.to_string().contains("is not a folder, is a link"),
            "{err}"
        );
        // The same folder named plainly is fine.
        make_own_tmp_folder_in(
            &base,
            uid,
            uid,
            &folder,
            std::slice::from_ref(&folder),
            "Grants",
        )
        .unwrap();
        fs::remove_dir(&folder).unwrap();
        fs::remove_file(base.join("x")).unwrap();
        let text = stops(uid, uid.wrapping_add(1), "another account's folder");
        assert!(text.contains("belongs to another account"), "{text}");
        fs::remove_dir(&folder).unwrap();
        stops(uid.wrapping_add(1), uid, "a base folder of another account");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).unwrap();
        let text = stops(uid, uid, "a base folder without the sticky bit");
        assert!(
            text.contains("does not keep each user's folders apart"),
            "{text}"
        );
        assert!(!folder.exists(), "nothing made");
    }
}
