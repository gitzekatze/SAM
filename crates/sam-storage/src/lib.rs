//! sam-storage: the app registry (`apps/<id>.json`), user presets
//! (`presets/<slug>.toml`) and per-app logs.

// The privacy check (crates/sam-jail-cli/tests/network_use.rs): every way
// this program could reach the network or start a program is an #[expect]
// listed there (clippy.toml: disallowed-methods, disallowed-types).
#![cfg_attr(not(test), deny(clippy::disallowed_methods, clippy::disallowed_types))]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use sam_core::util::{atomic_write, now, slugify};
use sam_core::{errln, AppEntry, Paths, PermissionSet, Preset};
use serde::{Deserialize, Serialize};

/// The app registry.
pub struct Registry {
    paths: Paths,
    /// How long a save waits for the record lock ([`RECORD_LOCK_WAIT`]).
    lock_wait: Duration,
    hooks: Hooks,
}

// The record lock. Several SAM processes change the
// same app records: the window, `sam-jail` commands, a start that stores
// its result, an update check. Each change reads a record, changes it and
// writes it back; two of them at once lost one of the two changes, a
// "look at it first" mark included. So every write of a record happens
// under one short lock:
// - Where: the file `.records.lock` in the apps folder, taken with flock.
//   The kernel releases it when its process ends, also a killed one, so a
//   crash never leaves it held. One lock for all records: it is held for
//   milliseconds, so apps rarely wait for each other, and no lock files
//   stay behind for removed apps.
// - How long: only around reading the record on disk, changing it and
//   writing it back. Never around unpacking, a download or a check: those
//   work on a copy and then save only the fields they changed
//   ([`Registry::save_changes`], [`Registry::update`]). Two saves that
//   change the same field (a list such as the granted folders counts as
//   one field) still follow each other: the later one wins.
// - When another process holds it: a save waits up to `lock_wait`, then
//   stops with an error that says so. Nothing is ever saved without it.
// - Within one process it is not re-entrant: a change passed to `update`
//   must not save a record itself (it would wait for its own lock).
// - Older SAM versions do not take it. Their records read as before (the
//   format is unchanged), but a save by an older SAM running at the same
//   time can still overwrite one of this SAM.
// Reading needs no lock: a record is replaced in one step (`atomic_write`).

/// How long a save of an app record waits for another SAM process to
/// finish its own save before it gives up with an error.
pub const RECORD_LOCK_WAIT: Duration = Duration::from_secs(10);

/// The record lock, held until dropped (closing the file releases it).
struct RecordLock {
    _file: fs::File,
}

/// Points in a save where a test makes another writer act.
#[cfg(test)]
#[derive(Default)]
struct Hooks {
    /// The record on disk has been read; it is written next.
    read: Option<Box<dyn Fn() + Send>>,
    /// The record lock is held by someone else; this save waits.
    waiting: Option<Box<dyn Fn() + Send>>,
}

#[cfg(test)]
impl Hooks {
    fn none() -> Self {
        Hooks::default()
    }
    fn at_read(&self) {
        if let Some(h) = &self.read {
            h();
        }
    }
    fn at_waiting(&self) {
        if let Some(h) = &self.waiting {
            h();
        }
    }
}

/// Outside tests nothing happens at these points (and the hooks take no
/// room).
#[cfg(not(test))]
struct Hooks;

#[cfg(not(test))]
impl Hooks {
    fn none() -> Self {
        Hooks
    }
    fn at_read(&self) {}
    fn at_waiting(&self) {}
}

/// Migrates an app record (JSON) from format `from` to the current one.
fn migrate_app(v: serde_json::Value, _from: u32) -> serde_json::Value {
    // 0 -> 1: same layout; removed options load through serde aliases.
    v
}

/// A record that cannot be read: moved aside, reported once.
fn damaged_record(p: &Path, err: &anyhow::Error) {
    match sam_core::format::quarantine(p) {
        Some(to) => errln!(
            "sam-jail: {}",
            sam_core::i18n::trf(
                "the app record {file} could not be read ({error}); it was moved to {moved}",
                &[
                    ("file", &p.display()),
                    ("error", &format!("{err:#}")),
                    ("moved", &to.display())
                ]
            )
        ),
        None => errln!(
            "sam-jail: {}",
            sam_core::i18n::trf(
                "the app record {file} could not be read: {error}",
                &[("file", &p.display()), ("error", &format!("{err:#}"))]
            )
        ),
    }
}

/// The first record format that carries SAM's checksum (`integrity`).
const CHECKSUM_SINCE: u32 = 1;
const _: () = assert!(CHECKSUM_SINCE <= sam_core::format::CURRENT);

impl Registry {
    pub fn new(paths: &Paths) -> Self {
        Registry {
            paths: paths.clone(),
            lock_wait: RECORD_LOCK_WAIT,
            hooks: Hooks::none(),
        }
    }

    /// The name of the app `id` for a message to a person: its name as its
    /// record on disk gives it, made safe to show, or its id when the
    /// record has none or cannot be read. Reads the file only: no
    /// migration, no moving aside, as a message must change nothing.
    fn name_for_message(&self, id: &str) -> String {
        let name = valid_id(id)
            .then(|| fs::read_to_string(self.paths.app_file(id)).ok())
            .flatten()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("name")?.as_str().map(str::to_string))
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| id.to_string());
        sam_core::util::display_safe(&name, 80)
    }

    /// Takes the record lock (see the comment at [`RECORD_LOCK_WAIT`]):
    /// waits while another SAM process holds it, up to `lock_wait`, then
    /// fails with an error that says so; it names the app `id` by its name.
    fn lock(&self, id: &str) -> Result<RecordLock> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let dir = self.paths.apps_dir();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let p = dir.join(".records.lock");
        // Never through a link someone placed there.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&p)
            .with_context(|| format!("opening {}", p.display()))?;
        let until = Instant::now() + self.lock_wait;
        let mut told = false;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(RecordLock { _file: file }),
                Err(fs::TryLockError::WouldBlock) if Instant::now() < until => {
                    if !told {
                        told = true;
                        self.hooks.at_waiting();
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                // Says only what is known: this save did not happen. Work
                // done before it (an unpacked copy) is not undone, so the
                // message promises nothing about it.
                Err(fs::TryLockError::WouldBlock) => bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "SAM could not save the record of {app}: another SAM process kept the app records locked for more than {seconds} seconds. Try again.",
                        &[
                            ("app", &self.name_for_message(id)),
                            ("seconds", &self.lock_wait.as_secs().max(1))
                        ]
                    )
                ),
                Err(fs::TryLockError::Error(e)) => {
                    return Err(e).with_context(|| format!("locking {}", p.display()))
                }
            }
        }
    }

    pub fn list(&self) -> Result<Vec<AppEntry>> {
        let dir = self.paths.apps_dir();
        let mut out = Vec::new();
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            match self.load_file(&p) {
                Ok(a) => out.push(a),
                // From a newer SAM: left alone, just not shown.
                Err(err) if err.downcast_ref::<serde_json::Error>().is_some() => {
                    damaged_record(&p, &err)
                }
                // From a newer SAM, or not readable right now: left alone.
                Err(err) => errln!("sam-jail: {err:#}"),
            }
        }
        out.sort_by_key(|a| a.display_name().to_lowercase());
        Ok(out)
    }

    /// The ids of every record file in the apps folder, also those SAM
    /// cannot read: one from a newer SAM (left in place) or a damaged one
    /// (moved aside as `<id>.json.damaged-…`). Their data still belongs to
    /// an app, so it is no leftover to delete (audit U-L4).
    pub fn record_ids(&self) -> std::collections::HashSet<String> {
        fs::read_dir(self.paths.apps_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let id = name.split_once(".json").map(|(id, _)| id.to_string())?;
                valid_id(&id).then_some(id)
            })
            .collect()
    }

    /// Reads one app record: migrated from older formats (original kept),
    /// an error for a newer one (left untouched).
    fn load_file(&self, p: &Path) -> Result<AppEntry> {
        let s = fs::read_to_string(p)?;
        let v: serde_json::Value = serde_json::from_str(&s)?;
        let found = sam_core::format::of_json(&v);
        sam_core::format::check_not_newer(p, found)?;
        let v = migrate_app(v, found);
        let mut e: AppEntry = serde_json::from_value(v)?;
        // The id names folders SAM creates and deletes (private home, logs,
        // runtime files). A record changed outside SAM must not point them
        // elsewhere ("../../.ssh"), so only safe ids that match the file
        // name are loaded.
        if !valid_id(&e.id) || p.file_stem().and_then(|s| s.to_str()) != Some(e.id.as_str()) {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "{file}: the app id {id} is not a safe name or does not match the file name; the record is ignored",
                    &[("file", &p.display()), ("id", &format!("{:?}", e.id))]
                )
            );
        }
        sam_core::format::backup_before_migration(p, found);
        // Changed by something other than SAM? Every record SAM writes carries
        // its checksum, so a missing one counts as a change too (regression:
        // deleting the checksum, or the checksum and the format number, hid
        // any change). Records from SAM versions before the checksum are
        // marked once and confirmed once. A checksum is compared only in the
        // current format: a record migrated from an older one is
        // re-serialized differently. No record from before the checksum's
        // format carries one, so one that does had its format lowered
        // (review F4: `"format": 0` hid any change). A genuine record of a
        // format between that one and the current one (once there is a
        // newer format) is migrated, not marked. A mark found earlier stays
        // until it is confirmed.
        let mismatch = match e.integrity.clone() {
            Some(stored) => {
                found < CHECKSUM_SINCE
                    || (found == sam_core::format::CURRENT && integrity_of(&e)? != stored)
            }
            None => true,
        };
        e.changed_outside = e.changed_outside || mismatch;
        e.format = sam_core::format::CURRENT;
        Ok(e)
    }

    pub fn get(&self, id: &str) -> Result<Option<AppEntry>> {
        if !valid_id(id) {
            return Ok(None);
        }
        let p = self.paths.app_file(id);
        if !p.exists() {
            return Ok(None);
        }
        match self.load_file(&p) {
            Ok(e) => Ok(Some(e)),
            Err(err) if err.downcast_ref::<serde_json::Error>().is_some() => {
                damaged_record(&p, &err);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    pub fn exists(&self, id: &str) -> bool {
        valid_id(id) && self.paths.app_file(id).exists()
    }

    /// Resolve a user-supplied reference: the exact id, or the one app
    /// that the reference names by any rule: an id prefix, its name slug,
    /// its name (case-insensitive) or a part of its name. The rules count
    /// together, never one before the other: an AppImage chooses its own
    /// name, so an app named `vlc` must not capture a command meant for
    /// "VLC media player", which `vlc` names too (audit G-F7). Of several
    /// apps named, one whose name is exactly the reference wins only if it
    /// was added before all the others: a name that was there first keeps
    /// its meaning when "Foo Pro" comes after "Foo", and an app added later
    /// can never take a reference over (audit U-L7). Otherwise the
    /// reference names more than one app and is refused.
    pub fn resolve(&self, query: &str) -> Result<AppEntry> {
        if let Some(a) = self.get(query)? {
            return Ok(a);
        }
        let all = self.list()?;
        let q = query.to_lowercase();
        let qslug = slugify(query);
        let m: Vec<&AppEntry> = all
            .iter()
            .filter(|a| {
                let name = a.name.to_lowercase();
                a.id.starts_with(&q)
                    || (!qslug.is_empty() && a.id.starts_with(&format!("appimage-{qslug}")))
                    || name.contains(&q)
            })
            .collect();
        // Of several, the app named exactly so, if it came before all the
        // others (equal times, as in records from before `added_at`, do
        // not count as before).
        if let [named] = m
            .iter()
            .filter(|a| a.name.to_lowercase() == q)
            .collect::<Vec<_>>()[..]
        {
            if m.iter()
                .all(|a| a.id == named.id || a.added_at > named.added_at)
            {
                return Ok((*named).clone());
            }
        }
        match m.as_slice() {
            [one] => Ok((*one).clone()),
            [] => bail!(
                "{}",
                sam_core::i18n::trf(
                    "no registered app matches '{query}' (see `sam-jail list`)",
                    &[("query", &query)]
                )
            ),
            many => bail!(
                "{}",
                sam_core::i18n::trf(
                    "'{query}' names more than one app: {apps}. Use the app's ID.",
                    &[
                        ("query", &query),
                        (
                            "apps",
                            &many
                                .iter()
                                .map(|a| format!("{} ({})", a.id, a.name))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    ]
                )
            ),
        }
    }

    /// Saves `entry` as a whole, under the record lock: for a new record,
    /// or a copy just read. A copy read a while ago goes through
    /// [`Registry::save_changes`] or [`Registry::update`] instead, so only
    /// the fields it changed are written.
    ///
    /// The marks that ask the person to look at the app first
    /// (`changed_outside`, `content_changed_outside`) stay set when the
    /// record on disk has them, also when `entry` is a copy read before
    /// they were set: saving such a copy (a refresh, a profile change that
    /// overlapped an "unpack again") must not undo them. The
    /// same holds for a change made to the record outside SAM since it was
    /// read. The record lock keeps another SAM process from setting a mark
    /// between that read and the write. Only a confirming save
    /// ([`Registry::update_confirmed`]) clears the marks.
    ///
    /// When the record on disk cannot be read, nothing it says is known,
    /// so nothing is dropped silently: a newer SAM's record is left
    /// unchanged (an error), a read error stops the save, and over a
    /// damaged or foreign record the copy is saved marked as changed
    /// outside SAM, so the person looks first.
    pub fn save(&self, entry: &mut AppEntry) -> Result<()> {
        let _held = self.lock(&entry.id)?;
        self.write_keeping_marks(entry)
    }

    /// [`Registry::save`] with the record lock already held.
    fn write_keeping_marks(&self, entry: &mut AppEntry) -> Result<()> {
        let p = self.paths.app_file(&entry.id);
        if valid_id(&entry.id) && p.exists() {
            match self.load_file(&p) {
                Ok(on_disk) => {
                    entry.changed_outside |= on_disk.changed_outside;
                    entry.content_changed_outside |= on_disk.content_changed_outside;
                }
                Err(e)
                    if e.downcast_ref::<sam_core::format::NewerFormat>().is_some()
                        || e.downcast_ref::<std::io::Error>().is_some() =>
                {
                    return Err(e);
                }
                Err(_) => entry.changed_outside = true,
            }
        }
        self.hooks.at_read();
        self.write(entry)
    }

    /// Saves `entry` exactly as it is, marks included, under the record
    /// lock. Every save by SAM itself goes through the other ways; the
    /// person's confirmation through [`Registry::update_confirmed`].
    pub fn save_confirmed(&self, entry: &mut AppEntry) -> Result<()> {
        let _held = self.lock(&entry.id)?;
        self.write(entry)
    }

    /// Writes `entry` as it is, with its checksum; the record lock is held.
    fn write(&self, entry: &mut AppEntry) -> Result<()> {
        if !valid_id(&entry.id) {
            bail!(
                "{}",
                sam_core::i18n::trf("invalid app id '{id}'", &[("id", &entry.id)])
            );
        }
        entry.updated_at = now();
        entry.format = sam_core::format::CURRENT;
        entry.integrity = Some(integrity_of(entry)?);
        let s = serde_json::to_string_pretty(entry)?;
        atomic_write(&self.paths.app_file(&entry.id), s.as_bytes())
    }

    /// Changes the record of `id` as it is on disk now: under the record
    /// lock, reads it again, applies `change` and saves it. For work that
    /// takes a while (an update check, a start): saving the copy read at
    /// the beginning would undo a change made meanwhile, for example a
    /// switch turned off in the window (regression: the update check
    /// turned it on again). `change` runs while the lock is held: it only
    /// sets fields, it never waits or saves records. `None` when the
    /// record is gone.
    pub fn update(&self, id: &str, change: impl FnOnce(&mut AppEntry)) -> Result<Option<AppEntry>> {
        self.try_update(id, |e| {
            change(e);
            Ok(())
        })
    }

    /// [`Registry::update`] with a change that can fail: then nothing is
    /// saved and the error is returned.
    pub fn try_update(
        &self,
        id: &str,
        change: impl FnOnce(&mut AppEntry) -> Result<()>,
    ) -> Result<Option<AppEntry>> {
        let _held = self.lock(id)?;
        let Some(mut fresh) = self.get(id)? else {
            return Ok(None);
        };
        change(&mut fresh)?;
        self.write_keeping_marks(&mut fresh)?;
        Ok(Some(fresh))
    }

    /// The person's confirmation that they looked at the app
    /// (`Sam::mark_reviewed`, the one caller outside tests): like
    /// [`Registry::try_update`], but the record is saved exactly as
    /// `change` leaves it, so it may clear the "look at it first" marks.
    /// `change` sees the record as it is under the lock, so a confirmation
    /// from the app's page checks there that the person saw what it
    /// confirms: a mark set just before is never cleared unseen. A
    /// confirmation at the terminal without the page's fingerprint checks
    /// nothing and confirms what is there then.
    pub fn update_confirmed(
        &self,
        id: &str,
        change: impl FnOnce(&mut AppEntry) -> Result<()>,
    ) -> Result<Option<AppEntry>> {
        let _held = self.lock(id)?;
        let Some(mut fresh) = self.get(id)? else {
            return Ok(None);
        };
        change(&mut fresh)?;
        self.write(&mut fresh)?;
        Ok(Some(fresh))
    }

    /// Saves what a writer changed on its copy `changed` of a record it
    /// read as `read`: under the record lock, only the fields that differ
    /// between the two are written onto the record as it is on disk now
    /// ([`apply_changes`]); every other field keeps what others saved
    /// meanwhile (before, a refresh or a profile change that
    /// overlapped an "unpack again" or an update wrote back the whole copy
    /// it had read and undid what that step saved). `changed` becomes the
    /// record as saved. Nothing is saved when the record is gone (an app
    /// removed meanwhile stays removed). Over a record that cannot be read,
    /// as [`Registry::save`]. A "look at it first" mark set on `changed` is
    /// always saved, also when `read` had it set already.
    pub fn save_changes(&self, read: &AppEntry, changed: &mut AppEntry) -> Result<()> {
        let _held = self.lock(&changed.id)?;
        let p = self.paths.app_file(&changed.id);
        if !valid_id(&changed.id) || !p.exists() {
            return Ok(());
        }
        match self.load_file(&p) {
            Ok(mut on_disk) => {
                apply_changes(&mut on_disk, read, changed)?;
                // A "look at it first" mark the writer's copy carries is
                // saved even when the writer read it already set: an
                // "unpack again" that sets it again for new content keeps
                // it, also when the person confirmed the older content
                // meanwhile (the same value in `read` and `changed` counts
                // as unchanged, so that confirmation would otherwise clear
                // the mark of content nobody saw). At worst SAM asks once
                // more, as the save of the whole copy did before.
                on_disk.changed_outside |= changed.changed_outside;
                on_disk.content_changed_outside |= changed.content_changed_outside;
                self.write_keeping_marks(&mut on_disk)?;
                *changed = on_disk;
                Ok(())
            }
            Err(_) => self.write_keeping_marks(changed),
        }
    }

    pub fn remove(&self, id: &str) -> Result<bool> {
        if !valid_id(id) {
            return Ok(false);
        }
        // Under the record lock: a change that read the record before
        // would otherwise write it back after it is gone.
        let _held = self.lock(id)?;
        let p = self.paths.app_file(id);
        match fs::remove_file(&p) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// The checksum SAM writes into every app record it saves: SHA-256 over
/// the record without the checksum, with the keys in a fixed order. A record
/// whose checksum does not match was changed by something other than SAM
/// (a script, another tool, a damaged file). It is no protection against a
/// program that targets SAM on purpose: such a program can compute the
/// checksum too (see docs/threat-model.md).
pub fn integrity_of(e: &AppEntry) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut v = serde_json::to_value(e)?;
    if let Some(o) = v.as_object_mut() {
        o.remove("integrity");
    }
    let digest = Sha256::digest(serde_json::to_vec(&v)?);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Writes onto `on_disk` (a record as it is on disk) what a writer changed on
/// its copy `changed` of the record it read as `read`, and nothing else:
/// a field that is the same in `read` and `changed` keeps the value in
/// `on_disk`. Fields inside a group (the settings, the unpacked copy) count one
/// by one, so a switch changed in the window and the unpacked copy's
/// details saved by an "unpack again" both stay; a list counts as one
/// value. A group whose `kind` differs is one value too, so two kinds are
/// never mixed. When the writer and another save both changed the same
/// field or list, the writer's value wins. Used by
/// [`Registry::save_changes`].
pub fn apply_changes(on_disk: &mut AppEntry, read: &AppEntry, changed: &AppEntry) -> Result<()> {
    fn merge(now: &mut serde_json::Value, read: &serde_json::Value, changed: &serde_json::Value) {
        use serde_json::Value::Object;
        match (now, read, changed) {
            (Object(n), Object(r), Object(c)) if r.get("kind") == c.get("kind") => {
                for (k, cv) in c {
                    let rv = r.get(k);
                    if rv == Some(cv) {
                        continue;
                    }
                    if let (Some(rv), Some(nv)) = (rv, n.get_mut(k)) {
                        merge(nv, rv, cv);
                        continue;
                    }
                    n.insert(k.clone(), cv.clone());
                }
                for k in r.keys().filter(|k| !c.contains_key(*k)) {
                    n.remove(k);
                }
            }
            (n, _, c) => *n = c.clone(),
        }
    }
    let mut v = serde_json::to_value(&*on_disk)?;
    merge(
        &mut v,
        &serde_json::to_value(read)?,
        &serde_json::to_value(changed)?,
    );
    *on_disk = serde_json::from_value(v)?;
    Ok(())
}

/// Fields of an app's record that change by themselves, without anything
/// a review would confirm: bookkeeping, the results of starts, checks and
/// update checks, the state a refresh finds, and the repair steps a start
/// tried. Every other field counts for [`review_fingerprint`].
const REVIEW_IGNORES: &[&str] = &[
    "integrity",
    "format",
    "updated_at",
    "last_launched",
    "last_launch",
    "last_error",
    "last_check",
    "update",
    "state",
    "tried_repairs",
];

/// What a review confirms, as a fingerprint (SHA-256): the whole record,
/// notices, settings, launch arguments and the unpacked copy included,
/// except the fields that change by themselves ([`REVIEW_IGNORES`]); the
/// AppImage and its unpacked copy count by their content's checksum (a
/// refresh updates the file's other details when it was only touched). A
/// page that shows an app sends it with its review; when the record no
/// longer has it, the person has not seen what the review would confirm
/// (review L4). A field added later counts too, until it is named above.
pub fn review_fingerprint(e: &AppEntry) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut v = serde_json::to_value(e)?;
    if let Some(o) = v.as_object_mut() {
        for k in REVIEW_IGNORES {
            o.remove(*k);
        }
        o.insert("source".into(), e.source.sha256.clone().into());
        if let (Some(x), Some(made_from)) = (
            o.get_mut("extraction")
                .and_then(serde_json::Value::as_object_mut),
            e.extraction.as_ref().map(|x| x.source.sha256.clone()),
        ) {
            x.insert("source".into(), made_from.into());
        }
    }
    let digest = Sha256::digest(serde_json::to_vec(&v)?);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// A fingerprint of a set of permissions (SHA-256 over its saved form):
/// what a question was asked about, so that only that is applied after the
/// answer (`preset apply --expect`).
pub fn fingerprint(p: &PermissionSet) -> Result<String> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(serde_json::to_vec(p)?);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// App ids are used as file names; keep them to a safe alphabet.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !id.starts_with('-')
}

/// On-disk preset format: `[preset]` metadata plus `[permissions]`.
#[derive(Debug, Serialize, Deserialize)]
struct PresetFile {
    preset: PresetMeta,
    #[serde(default = "empty_table")]
    permissions: toml::Value,
}

fn empty_table() -> toml::Value {
    toml::Value::Table(Default::default())
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(default)]
struct PresetMeta {
    /// File format (see `sam_core::format`).
    format: u32,
    name: String,
    description: String,
    risk: sam_core::RiskLevel,
    created_at: i64,
    modified_at: i64,
    compatibility_notes: String,
}

/// User presets stored as TOML in `~/.config/sam/presets/`.
pub struct PresetStore {
    dir: PathBuf,
}

impl PresetStore {
    pub fn new(paths: &Paths) -> Self {
        PresetStore {
            dir: paths.presets_dir(),
        }
    }

    pub fn file_for(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{}.toml", preset_slug(name)))
    }

    pub fn list(&self) -> Result<Vec<Preset>> {
        let mut out = Vec::new();
        let rd = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            match read_preset_file(&p) {
                Ok(pr) => out.push(pr),
                // Not readable as a preset: moved aside, so it is reported
                // once (sam-jail doctor lists it) instead of on every start.
                Err(err) if err.chain().any(|c| c.downcast_ref::<toml::de::Error>().is_some()) => match sam_core::format::quarantine(&p) {
                    Some(to) => errln!(
                        "sam-jail: {}",
                        sam_core::i18n::trf(
                            "the preset {file} could not be read ({error}); it was moved to {moved}",
                            &[("file", &p.display()), ("error", &format!("{err:#}")), ("moved", &to.display())]
                        )
                    ),
                    None => errln!(
                        "sam-jail: {}",
                        sam_core::i18n::trf("skipping the damaged preset {file}: {error}", &[("file", &p.display()), ("error", &format!("{err:#}"))])
                    ),
                },
                Err(err) => errln!("sam-jail: skipping preset {}: {err:#}", p.display()),
            }
        }
        out.sort_by_key(|a| a.name.to_lowercase());
        Ok(out)
    }

    pub fn get(&self, name: &str) -> Result<Option<Preset>> {
        Ok(self.list()?.into_iter().find(|p| {
            p.name.eq_ignore_ascii_case(name) || preset_slug(&p.name) == preset_slug(name)
        }))
    }

    pub fn save(&self, preset: &mut Preset) -> Result<PathBuf> {
        if preset.name.trim().is_empty() {
            bail!("{}", sam_core::i18n::tr("preset name must not be empty"));
        }
        let t = now();
        if preset.created_at == 0 {
            preset.created_at = t;
        }
        preset.modified_at = t;
        preset.risk = sam_core::risk::assess(&preset.permissions).level;
        let path = self.file_for(&preset.name);
        // "My Preset" and "my-preset" share a file: saving one must not
        // overwrite the other without a word (audit G-F19). The same name
        // in other letter case is the same preset.
        if let Ok(old) = read_preset_file(&path) {
            if !old.name.eq_ignore_ascii_case(&preset.name) {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "the preset “{other}” already uses the file for this name; choose another name",
                        &[("other", &old.name)]
                    )
                );
            }
        }
        atomic_write(&path, preset_to_toml(preset)?.as_bytes())?;
        Ok(path)
    }

    /// Saves a preset from a file under a name no preset has yet: the file's
    /// own name when it is free, otherwise "NAME (imported)", "NAME
    /// (imported 2)", … An imported file never replaces a preset of the same
    /// name, which would later be applied as the person's own (review F9).
    pub fn import(&self, preset: &mut Preset) -> Result<PathBuf> {
        let taken = |name: &str| -> Result<bool> {
            Ok(self.get(name)?.is_some() || self.file_for(name).exists())
        };
        // An empty name is refused by `save`, as before.
        if !preset.name.trim().is_empty() && taken(&preset.name)? {
            let base = preset.name.trim().to_string();
            let mut n = 1u32;
            loop {
                let candidate = match n {
                    1 => sam_core::i18n::trf("{name} (imported)", &[("name", &base)]),
                    _ => {
                        sam_core::i18n::trf("{name} (imported {n})", &[("name", &base), ("n", &n)])
                    }
                };
                if !taken(&candidate)? {
                    preset.name = candidate.trim().to_string();
                    break;
                }
                n += 1;
            }
        }
        self.save(preset)
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        let p = self.file_for(name);
        match fs::remove_file(&p) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

pub fn preset_slug(name: &str) -> String {
    let s = slugify(name);
    if s.is_empty() {
        "preset".into()
    } else {
        s
    }
}

pub fn preset_to_toml(p: &Preset) -> Result<String> {
    let file = PresetFile {
        preset: PresetMeta {
            format: sam_core::format::CURRENT,
            name: p.name.clone(),
            description: p.description.clone(),
            risk: p.risk,
            created_at: p.created_at,
            modified_at: p.modified_at,
            compatibility_notes: p.compatibility_notes.clone(),
        },
        permissions: toml::Value::try_from(&p.permissions)?,
    };
    Ok(toml::to_string_pretty(&file)?)
}

pub fn read_preset_file(path: &Path) -> Result<Preset> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_preset_toml(&s).with_context(|| format!("parsing {}", path.display()))
}

/// Parse a preset, accepting both the structured format and the flat
/// format (`network = "full"`, `gpu = true`, ...).
pub fn parse_preset_toml(s: &str) -> Result<Preset> {
    let file: PresetFile = toml::from_str(s)?;
    if file.preset.format > sam_core::format::CURRENT {
        bail!(
            "{}",
            sam_core::i18n::trf(
                "this preset was made by a newer SAM (format {format}); update SAM to use it",
                &[("format", &file.preset.format)]
            )
        );
    }
    let permissions = permissions_from_toml(file.permissions)?;
    Ok(Preset {
        name: file.preset.name,
        description: file.preset.description,
        // Worked out from the permissions, never taken from the file: a
        // preset file placed in the folder (copied, synced, written by a
        // script) said "low" for full home and network, and the lists showed
        // it as Harmless (review F6). The stored word is only written.
        risk: sam_core::risk::assess(&permissions).level,
        permissions,
        created_at: file.preset.created_at,
        modified_at: file.preset.modified_at,
        compatibility_notes: file.preset.compatibility_notes,
    })
}

fn permissions_from_toml(v: toml::Value) -> Result<PermissionSet> {
    let table = match v {
        toml::Value::Table(t) => t,
        _ => return Ok(PermissionSet::default()),
    };
    let is_flat = table.values().all(|v| !v.is_table());
    if !is_flat || table.is_empty() {
        return Ok(toml::Value::Table(table).try_into()?);
    }
    // Older flat format.
    let mut p = PermissionSet::default();
    for (k, v) in table {
        let raw = match &v {
            toml::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let key = match k.as_str() {
            "network" => "network.mode".to_string(),
            "home" | "documents" | "downloads" | "music" | "pictures" | "videos" | "desktop"
            | "ssh" | "gnupg" | "hidden_files" | "custom_read" | "custom_write" => {
                format!("filesystem.{k}")
            }
            "audio" => "audio.enabled".into(),
            "alsa" | "alsa_raw" => "audio.alsa_raw".into(),
            "gpu" | "webcam" | "input" | "usb" | "bluetooth" => format!("devices.{k}"),
            "x11" | "wayland" => format!("display.{k}"),
            "dbus_session" => "dbus.session.mode".into(),
            "dbus_system" => "dbus.system.mode".into(),
            other => bail!(
                "{}",
                sam_core::i18n::trf("unknown flat preset key '{other}'", &[("other", &other)])
            ),
        };
        p.set_key(&key, &raw)?;
    }
    Ok(p)
}

/// Per-app log files under `~/.config/sam/logs/<id>/`.
pub struct Logs {
    paths: Paths,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogKind {
    Launch,
    Extract,
    Detect,
    Diagnose,
}

impl LogKind {
    pub fn prefix(self) -> &'static str {
        match self {
            LogKind::Launch => "launch",
            LogKind::Extract => "extract",
            LogKind::Detect => "detect",
            LogKind::Diagnose => "diagnose",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "launch" => LogKind::Launch,
            "extract" | "extraction" => LogKind::Extract,
            "detect" | "detection" => LogKind::Detect,
            "diagnose" | "diagnostic" => LogKind::Diagnose,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LogFile {
    pub path: PathBuf,
    pub kind: LogKind,
    pub modified: i64,
    pub size: u64,
}

impl Logs {
    pub fn new(paths: &Paths) -> Self {
        Logs {
            paths: paths.clone(),
        }
    }

    /// A new log for this app ([`Logs::new_log_path`]), created readable by
    /// the user only.
    pub fn create(&self, id: &str, kind: LogKind) -> Result<(PathBuf, fs::File)> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.new_log_path(id, kind)?;
        let f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        Ok((path, f))
    }

    /// A new timestamped log path for this app.
    pub fn new_log_path(&self, id: &str, kind: LogKind) -> Result<PathBuf> {
        let dir = self.paths.app_logs_dir(id);
        // Logs hold what apps printed: for the user only (audit A2), also
        // when the folders were made by an older SAM.
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)?;
            for d in [self.paths.logs_dir(), dir.clone()] {
                let _ = fs::set_permissions(&d, fs::Permissions::from_mode(0o700));
            }
        }
        let ts = chrono_stamp();
        // Logs from the same second get a number above every existing one.
        // Reusing a free lower name (after older logs of that second were
        // pruned) would make the new log the oldest, and the next pruning
        // would delete it.
        let prefix = format!("{}-{ts}", kind.prefix());
        let highest = fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let rest = name
                    .strip_prefix(&prefix)?
                    .strip_suffix(".log")?
                    .to_string();
                if rest.is_empty() {
                    Some(0)
                } else {
                    rest.strip_prefix('-')?.parse::<u32>().ok()
                }
            })
            .max();
        Ok(match highest {
            None => dir.join(format!("{prefix}.log")),
            Some(n) => dir.join(format!("{prefix}-{}.log", n + 1)),
        })
    }

    pub fn list(&self, id: &str, kind: Option<LogKind>) -> Result<Vec<LogFile>> {
        let dir = self.paths.app_logs_dir(id);
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(&dir) else {
            return Ok(out);
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(k) = name.split('-').next().and_then(LogKind::parse) else {
                continue;
            };
            if kind.is_some_and(|want| want != k) {
                continue;
            }
            let meta = e.metadata()?;
            let modified = meta
                .modified()
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            out.push(LogFile {
                path: e.path(),
                kind: k,
                modified,
                size: meta.len(),
            });
        }
        // Newest first. Logs from the same second are `<kind>-<date>-<time>.log`,
        // then `...-1.log`, `...-2.log`: order by that sequence number, not by
        // name (where `.log` would sort after `-1.log`).
        out.sort_by(|a, b| {
            b.modified
                .cmp(&a.modified)
                .then_with(|| log_stamp(&b.path).cmp(&log_stamp(&a.path)))
        });
        Ok(out)
    }

    pub fn latest(&self, id: &str, kind: Option<LogKind>) -> Result<Option<LogFile>> {
        Ok(self.list(id, kind)?.into_iter().next())
    }

    /// Keep only the newest `keep` logs of a kind.
    pub fn prune(&self, id: &str, kind: LogKind, keep: usize) -> Result<()> {
        for old in self.list(id, Some(kind))?.into_iter().skip(keep.max(1)) {
            fs::remove_file(old.path).ok();
        }
        Ok(())
    }

    pub fn remove_all(&self, id: &str) -> Result<()> {
        let dir = self.paths.app_logs_dir(id);
        if dir.exists() {
            fs::remove_dir_all(dir)?;
        }
        Ok(())
    }
}

fn chrono_stamp() -> String {
    // YYYYmmdd-HHMMSS derived from the formatted local timestamp.
    sam_core::util::format_ts(now())
        .replace(['-', ':'], "")
        .replace(' ', "-")
}

/// `(date, time, sequence)` from a log file name like `launch-20261107-013613-1.log`.
fn log_stamp(path: &Path) -> (String, String, u32) {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut parts = stem.split('-').skip(1);
    let date = parts.next().unwrap_or_default().to_string();
    let time = parts.next().unwrap_or_default().to_string();
    let seq = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
    (date, time, seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With more launches in one second than logs are kept, the newest log
    /// survives the pruning after its launch (regression: on a fast machine
    /// a pruned name was reused, sorted as the oldest and deleted at once).
    #[test]
    fn the_newest_log_survives_pruning_within_one_second() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = Logs::new(&Paths::rooted(tmp.path()));
        for round in 0..12 {
            let p = logs.new_log_path("app", LogKind::Launch).unwrap();
            fs::write(&p, format!("round {round}")).unwrap();
            logs.prune("app", LogKind::Launch, 3).unwrap();
            assert!(
                p.exists(),
                "round {round}: the log just written was pruned ({})",
                p.display()
            );
        }
    }

    /// A record SAM saved loads as unchanged; a record changed afterwards
    /// by something else is recognized as changed outside SAM, and stays
    /// marked through SAM's own saves until it is confirmed; a record
    /// without SAM's checksum (removed, or from before the checksum) is
    /// marked too.
    #[test]
    fn records_changed_outside_sam_are_recognized() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let mut e = AppEntry {
            id: "appimage-x-1".into(),
            name: "X".into(),
            ..Default::default()
        };
        reg.save(&mut e).unwrap();
        assert!(!reg.get("appimage-x-1").unwrap().unwrap().changed_outside);
        let file = paths.app_file("appimage-x-1");
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        v["profile"]["permissions"]["network"]["mode"] = "full".into();
        fs::write(&file, v.to_string()).unwrap();
        let mut changed = reg.get("appimage-x-1").unwrap().unwrap();
        assert!(
            changed.changed_outside,
            "a change made outside SAM is noticed"
        );
        assert_eq!(changed.badge(), sam_core::Badge::ChangedOutside);
        // Regression (audit U-H1): a save by SAM confirmed the change.
        reg.save(&mut changed).unwrap();
        let again = reg.get("appimage-x-1").unwrap().unwrap();
        assert!(again.changed_outside, "a save by SAM is no confirmation");
        assert_eq!(
            again.profile.permissions.network.mode,
            changed.profile.permissions.network.mode
        );
        reg.update("appimage-x-1", |e| e.name = "Y".into()).unwrap();
        assert!(reg.get("appimage-x-1").unwrap().unwrap().changed_outside);
        // Only confirming clears it (`Sam::mark_reviewed` does this).
        let mut confirmed = reg.get("appimage-x-1").unwrap().unwrap();
        confirmed.changed_outside = false;
        reg.save_confirmed(&mut confirmed).unwrap();
        assert!(!reg.get("appimage-x-1").unwrap().unwrap().changed_outside);

        // Regression (audit U-L3): removing the checksum, or the checksum and
        // the format number, hid every change.
        for drop in [&["integrity"][..], &["integrity", "format"][..]] {
            let mut v: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            v["profile"]["permissions"]["network"]["mode"] = "full".into();
            for k in drop {
                v.as_object_mut().unwrap().remove(*k);
            }
            fs::write(&file, v.to_string()).unwrap();
            assert!(
                reg.get("appimage-x-1").unwrap().unwrap().changed_outside,
                "without {drop:?}"
            );
            let mut ok = reg.get("appimage-x-1").unwrap().unwrap();
            ok.changed_outside = false;
            reg.save_confirmed(&mut ok).unwrap();
        }
        // Regression (review F4): lowering the format number with the old
        // checksum left in place (`0`, or no number, which reads as 0)
        // skipped the comparison and hid the change. (`1.0` is no number a
        // record can have: such a record is moved aside as damaged.)
        for format in [Some(serde_json::json!(0)), None] {
            let mut v: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            assert!(v["integrity"].is_string(), "SAM's save wrote a checksum");
            v["profile"]["permissions"]["network"]["mode"] = "full".into();
            match &format {
                Some(f) => v["format"] = f.clone(),
                None => drop(v.as_object_mut().unwrap().remove("format")),
            }
            fs::write(&file, v.to_string()).unwrap();
            assert!(
                reg.get("appimage-x-1").unwrap().unwrap().changed_outside,
                "with format {format:?}"
            );
            let mut ok = reg.get("appimage-x-1").unwrap().unwrap();
            ok.changed_outside = false;
            reg.save_confirmed(&mut ok).unwrap();
            assert!(!reg.get("appimage-x-1").unwrap().unwrap().changed_outside);
        }
    }

    /// A copy of a record read before one of its "look at it first" marks
    /// was set, saved later, keeps the mark: a refresh or a profile change
    /// that overlapped an "unpack again" no longer undoes it.
    /// The same holds for a change made outside SAM after the copy was
    /// read. Only a confirming save clears the marks.
    #[test]
    fn a_save_of_an_older_copy_keeps_the_marks_set_meanwhile() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let mut e = AppEntry {
            id: "appimage-x-3".into(),
            name: "X".into(),
            ..Default::default()
        };
        reg.save(&mut e).unwrap();
        let older = reg.get("appimage-x-3").unwrap().unwrap();
        // Unpacked again meanwhile: the new content waits for a look.
        let mut marked = reg.get("appimage-x-3").unwrap().unwrap();
        marked.content_changed_outside = true;
        reg.save(&mut marked).unwrap();
        let mut late = AppEntry {
            name: "Y".into(),
            ..older.clone()
        };
        reg.save(&mut late).unwrap();
        let back = reg.get("appimage-x-3").unwrap().unwrap();
        assert!(back.content_changed_outside, "the older copy kept the mark");
        assert_eq!(back.name, "Y", "and its own change was saved");
        reg.update("appimage-x-3", |e| e.content_changed_outside = false)
            .unwrap();
        assert!(
            reg.get("appimage-x-3")
                .unwrap()
                .unwrap()
                .content_changed_outside
        );
        // Changed outside SAM after the older copy was read.
        let file = paths.app_file("appimage-x-3");
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        v["profile"]["permissions"]["network"]["mode"] = "full".into();
        fs::write(&file, v.to_string()).unwrap();
        let mut late = older.clone();
        reg.save(&mut late).unwrap();
        let back = reg.get("appimage-x-3").unwrap().unwrap();
        assert!(back.changed_outside, "a change outside SAM stays marked");
        // Confirming clears both.
        let mut seen = back;
        seen.changed_outside = false;
        seen.content_changed_outside = false;
        reg.save_confirmed(&mut seen).unwrap();
        let back = reg.get("appimage-x-3").unwrap().unwrap();
        assert!(!back.changed_outside && !back.content_changed_outside);
    }

    /// A save over a record SAM cannot read drops nothing silently: a
    /// newer SAM's record stays unchanged and the save fails, and over a
    /// damaged record or one with another id the copy is saved marked as
    /// changed outside SAM (review of PR 120).
    #[test]
    fn a_save_over_an_unreadable_record_drops_nothing_silently() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let mut e = AppEntry {
            id: "appimage-x-4".into(),
            name: "X".into(),
            ..Default::default()
        };
        reg.save(&mut e).unwrap();
        let copy = reg.get("appimage-x-4").unwrap().unwrap();
        let file = paths.app_file("appimage-x-4");
        let mut v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        v["format"] = (sam_core::format::CURRENT + 1).into();
        let newer = v.to_string();
        fs::write(&file, &newer).unwrap();
        assert!(
            reg.save(&mut copy.clone()).is_err(),
            "a newer record is not overwritten"
        );
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            newer,
            "and stays unchanged"
        );
        for unreadable in ["{ damaged", r#"{"id": "appimage-other-1"}"#] {
            fs::write(&file, unreadable).unwrap();
            reg.save(&mut copy.clone()).unwrap();
            assert!(
                reg.get("appimage-x-4").unwrap().unwrap().changed_outside,
                "over {unreadable:?}"
            );
            let mut seen = reg.get("appimage-x-4").unwrap().unwrap();
            seen.changed_outside = false;
            reg.save_confirmed(&mut seen).unwrap();
        }
    }

    /// The review fingerprint changes with every notice a review clears or
    /// that asks for a look, with the settings and with the AppImage, and
    /// stays the same through saves that change none of these (review L4).
    #[test]
    fn the_review_fingerprint_covers_what_a_review_confirms() {
        let base = AppEntry {
            id: "appimage-x-5".into(),
            name: "X".into(),
            extraction: Some(Default::default()),
            ..Default::default()
        };
        let fp = |e: &AppEntry| review_fingerprint(e).unwrap();
        type Change = (&'static str, fn(&mut AppEntry));
        let changes: [Change; 10] = [
            ("changed outside", |e| e.changed_outside = true),
            ("content changed", |e| e.content_changed_outside = true),
            ("signing key", |e| {
                e.signing_key_changed = Some("old key".into())
            }),
            ("update needs", |e| e.pending_changes = vec!["sound".into()]),
            ("reviewed", |e| e.reviewed = !e.reviewed),
            ("a setting", |e| e.profile.permissions.display.x11 = true),
            ("the AppImage", |e| e.source.sha256 = "1".repeat(64)),
            ("launch arguments", |e| {
                e.profile.args = vec!["--no-sandbox".into()]
            }),
            ("the unpacked copy", |e| {
                e.extraction.as_mut().unwrap().appdir = "/elsewhere".into()
            }),
            ("compatibility mode", |e| {
                e.profile.compatibility_mode = true
            }),
        ];
        for (what, change) in changes {
            let mut e = base.clone();
            change(&mut e);
            assert_ne!(fp(&e), fp(&base), "{what}");
        }
        // What a start, a check, an update check and a refresh write.
        let mut same = base.clone();
        same.updated_at = 42;
        same.last_launched = Some(42);
        same.last_launch = Some(Default::default());
        same.last_check = Some(Default::default());
        same.update = Some(Default::default());
        same.last_error = Some("a start failed".into());
        same.tried_repairs = vec!["some step".into()];
        same.source.size = 7;
        same.extraction.as_mut().unwrap().source.mtime = 7;
        assert_eq!(fp(&same), fp(&base), "a save that changes nothing of it");
    }

    /// `update` changes the record as it is on disk now, so work that took a
    /// while does not undo a change made meanwhile (audit U-M8: the update
    /// check turned a switch back on).
    #[test]
    fn a_late_save_keeps_a_change_made_meanwhile() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let mut e = AppEntry {
            id: "appimage-x-2".into(),
            name: "X".into(),
            ..Default::default()
        };
        e.profile.permissions.network.mode = sam_core::permissions::NetworkMode::Full;
        reg.save(&mut e).unwrap();
        // A long task reads the record ...
        let stale = reg.get("appimage-x-2").unwrap().unwrap();
        // ... the person turns the network off meanwhile ...
        let mut now = reg.get("appimage-x-2").unwrap().unwrap();
        now.profile.permissions.network.mode = sam_core::permissions::NetworkMode::None;
        reg.save(&mut now).unwrap();
        // ... and the task stores its result.
        let saved = reg
            .update(&stale.id, |f| f.last_error = Some("checked".into()))
            .unwrap()
            .unwrap();
        let back = reg.get("appimage-x-2").unwrap().unwrap();
        assert_eq!(
            back.profile.permissions.network.mode,
            sam_core::permissions::NetworkMode::None
        );
        assert_eq!(back.last_error.as_deref(), Some("checked"));
        assert_eq!(
            saved.profile.permissions.network.mode,
            back.profile.permissions.network.mode
        );
        assert!(!back.changed_outside);
        assert!(reg.update("appimage-gone", |_| {}).unwrap().is_none());
    }

    /// Two SAM processes save the same app at once (here two threads with
    /// their own handles, so each takes the record lock as a process
    /// does): one sets a "look at it first" mark while the other saves a
    /// copy it read before. The other has already read the record on disk
    /// when the mark is set; the mark survives, because setting it waits
    /// for the record lock until that save is written.
    #[test]
    fn a_mark_set_during_another_save_survives() {
        use std::sync::mpsc;
        let limit = Duration::from_secs(30);
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let id = "appimage-x-6";
        let mut e = AppEntry {
            id: id.into(),
            name: "X".into(),
            ..Default::default()
        };
        Registry::new(&paths).save(&mut e).unwrap();
        let older = Registry::new(&paths).get(id).unwrap().unwrap();
        // Once the first writer has read the record on disk, the second
        // starts; the first goes on when the second waits or is done.
        let (go, start) = mpsc::channel::<()>();
        let (said, heard) = mpsc::channel::<&str>();
        let mut first = Registry::new(&paths);
        first.hooks.read = Some(Box::new(move || {
            go.send(()).unwrap();
            heard
                .recv_timeout(limit)
                .expect("the second writer neither waited nor finished");
        }));
        let mut second = Registry::new(&paths);
        let waits = said.clone();
        second.hooks.waiting = Some(Box::new(move || {
            let _ = waits.send("waits");
        }));
        let marker = std::thread::spawn(move || {
            start
                .recv_timeout(limit)
                .expect("the first writer never read the record");
            second
                .update(id, |e| e.content_changed_outside = true)
                .unwrap();
            let _ = said.send("done");
        });
        let mut late = AppEntry {
            name: "Y".into(),
            ..older
        };
        first.save(&mut late).unwrap();
        marker.join().unwrap();
        let back = Registry::new(&paths).get(id).unwrap().unwrap();
        assert!(
            back.content_changed_outside,
            "the mark set during the other save was lost"
        );
        assert_eq!(back.name, "Y", "and the other save's change was kept");
    }

    /// A save while another SAM process holds the record lock waits, then
    /// succeeds once it is released; nothing is written meanwhile.
    #[test]
    fn a_save_waits_while_the_record_lock_is_held_and_then_succeeds() {
        use std::sync::mpsc;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let id = "appimage-x-7";
        let mut e = AppEntry {
            id: id.into(),
            name: "X".into(),
            ..Default::default()
        };
        Registry::new(&paths).save(&mut e).unwrap();
        let held = Registry::new(&paths).lock(id).unwrap();
        let (said, heard) = mpsc::channel::<()>();
        let mut waiting = Registry::new(&paths);
        waiting.hooks.waiting = Some(Box::new(move || {
            let _ = said.send(());
        }));
        let saver = std::thread::spawn(move || waiting.update(id, |e| e.name = "Y".into()));
        heard
            .recv_timeout(Duration::from_secs(30))
            .expect("the save did not wait for the record lock");
        assert_eq!(
            Registry::new(&paths).get(id).unwrap().unwrap().name,
            "X",
            "nothing is written while the lock is held"
        );
        drop(held);
        let saved = saver.join().unwrap().unwrap().unwrap();
        assert_eq!(saved.name, "Y");
        assert_eq!(Registry::new(&paths).get(id).unwrap().unwrap().name, "Y");
    }

    /// The storage step of a confirmation (`update_confirmed`) gives its
    /// check the record as it is once the record lock is taken: a "look at
    /// it first" mark that another SAM process saves while the
    /// confirmation waits for the lock is what the check sees, so a check
    /// of what the page showed fails and the mark stays. SAM's own
    /// confirmation, which makes that check, has its own test in
    /// sam-runner (`a_confirmation_from_the_page_never_clears_a_mark_saved_before_its_lock`).
    #[test]
    fn a_confirmation_never_clears_a_mark_saved_while_it_waits() {
        use std::sync::mpsc;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let id = "appimage-x-11";
        let mut e = AppEntry {
            id: id.into(),
            name: "X".into(),
            ..Default::default()
        };
        Registry::new(&paths).save(&mut e).unwrap();
        // What the person saw: the record without the mark.
        let seen = review_fingerprint(&Registry::new(&paths).get(id).unwrap().unwrap()).unwrap();
        let held = Registry::new(&paths).lock(id).unwrap();
        let (said, heard) = mpsc::channel::<()>();
        let mut confirming = Registry::new(&paths);
        confirming.hooks.waiting = Some(Box::new(move || {
            let _ = said.send(());
        }));
        let confirm = std::thread::spawn(move || {
            confirming.update_confirmed(id, |f| {
                if review_fingerprint(f)? != seen {
                    bail!("the page is out of date");
                }
                f.content_changed_outside = false;
                f.changed_outside = false;
                Ok(())
            })
        });
        heard
            .recv_timeout(Duration::from_secs(30))
            .expect("the confirmation did not wait for the record lock");
        // Another process, holding the lock, saves the mark.
        let mut marked = Registry::new(&paths).get(id).unwrap().unwrap();
        marked.content_changed_outside = true;
        Registry::new(&paths).write(&mut marked).unwrap();
        drop(held);
        let r = confirm.join().unwrap();
        assert!(r.is_err(), "a confirmation of an older page went ahead");
        assert!(
            Registry::new(&paths)
                .get(id)
                .unwrap()
                .unwrap()
                .content_changed_outside,
            "the mark saved meanwhile was cleared unseen"
        );
    }

    /// When the record lock stays held longer than a save waits, every way
    /// of writing a record stops with an error that says so and names the
    /// app by its name, and the record stays as it was: no save ever goes
    /// ahead without the lock.
    #[test]
    fn a_record_lock_held_too_long_stops_the_save_with_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let id = "appimage-x-8";
        let mut e = AppEntry {
            id: id.into(),
            name: "Lock Tester".into(),
            ..Default::default()
        };
        Registry::new(&paths).save(&mut e).unwrap();
        let read = Registry::new(&paths).get(id).unwrap().unwrap();
        let held = Registry::new(&paths).lock(id).unwrap();
        let mut reg = Registry::new(&paths);
        reg.lock_wait = Duration::from_millis(200);
        let mut changed = AppEntry {
            name: "Y".into(),
            ..read.clone()
        };
        let results = [
            reg.update(id, |e| e.name = "Y".into()).map(|_| ()),
            reg.try_update(id, |_| Ok(())).map(|_| ()),
            reg.update_confirmed(id, |_| Ok(())).map(|_| ()),
            reg.save(&mut changed.clone()),
            reg.save_confirmed(&mut changed.clone()),
            reg.save_changes(&read, &mut changed),
            reg.remove(id).map(|_| ()),
        ];
        for (n, r) in results.into_iter().enumerate() {
            let Err(err) = r else {
                panic!("way {n} saved without the lock");
            };
            let err = format!("{err:#}");
            // It names the app by its name, as every message to a person
            // does, and promises nothing about work done before the save.
            assert!(
                err.contains("SAM could not save the record of Lock Tester")
                    && err.contains("another SAM process"),
                "way {n}: {err}"
            );
            assert!(!err.contains(id), "way {n} names the internal id: {err}");
            assert!(!err.contains("changed"), "way {n}: {err}");
        }
        let back = Registry::new(&paths).get(id).unwrap().unwrap();
        assert_eq!(back.name, "Lock Tester", "the record stayed as it was");
        drop(held);
        reg.update(id, |e| e.name = "Y".into()).unwrap();
        assert_eq!(Registry::new(&paths).get(id).unwrap().unwrap().name, "Y");
    }

    /// A writer that worked on a copy read a while ago saves only what it
    /// changed: what others saved meanwhile in other fields stays, an
    /// "unpack again"'s new unpacked copy, its marks and notices and a
    /// switch changed in the window included (before, the whole copy was
    /// written back). An app removed meanwhile stays removed.
    #[test]
    fn a_save_of_changes_keeps_what_others_saved_meanwhile() {
        use sam_core::permissions::NetworkMode;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let id = "appimage-x-9";
        let mut e = AppEntry {
            id: id.into(),
            name: "X".into(),
            extraction: Some(Default::default()),
            ..Default::default()
        };
        e.profile.permissions.network.mode = NetworkMode::Full;
        reg.save(&mut e).unwrap();
        let read = reg.get(id).unwrap().unwrap();
        // Saved by others while this writer worked on its copy.
        reg.update(id, |f| {
            f.content_changed_outside = true;
            f.signing_key_changed = Some("old key".into());
            f.extraction.as_mut().unwrap().appdir = "/unpacked/again".into();
            f.profile.permissions.network.mode = NetworkMode::None;
        })
        .unwrap();
        let mut mine = read.clone();
        mine.profile.args = vec!["--mine".into()];
        mine.last_error = Some("checked".into());
        reg.save_changes(&read, &mut mine).unwrap();
        let back = reg.get(id).unwrap().unwrap();
        assert!(back.content_changed_outside, "the mark stays");
        assert_eq!(
            back.signing_key_changed.as_deref(),
            Some("old key"),
            "the notice of a changed signing key stays"
        );
        assert_eq!(
            back.extraction.as_ref().unwrap().appdir,
            Path::new("/unpacked/again"),
            "the new unpacked copy stays"
        );
        assert_eq!(
            back.profile.permissions.network.mode,
            NetworkMode::None,
            "the switch changed meanwhile stays"
        );
        assert_eq!(back.profile.args, ["--mine"], "the writer's own change");
        assert_eq!(back.last_error.as_deref(), Some("checked"));
        assert_eq!(mine.signing_key_changed, back.signing_key_changed);
        assert!(!back.changed_outside, "nothing looks changed outside SAM");
        // Removed meanwhile: not written back.
        reg.remove(id).unwrap();
        reg.save_changes(&read, &mut mine).unwrap();
        assert!(!reg.exists(id), "a removed app stays removed");
    }

    /// An "unpack again" of new content that read the record with the
    /// "look at it first" marks already set, and sets them again, keeps
    /// them when the person confirms the older content while it unpacks.
    #[test]
    fn a_mark_set_again_for_new_content_survives_a_confirmation_meanwhile() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let id = "appimage-x-10";
        let mut e = AppEntry {
            id: id.into(),
            name: "X".into(),
            extraction: Some(Default::default()),
            ..Default::default()
        };
        e.source.sha256 = "first swapped file".into();
        e.content_changed_outside = true;
        e.changed_outside = true;
        reg.save_confirmed(&mut e).unwrap();
        let read = reg.get(id).unwrap().unwrap();
        assert!(read.content_changed_outside && read.changed_outside);
        // The unpack of a second swapped file sets both marks again.
        let mut mine = read.clone();
        mine.source.sha256 = "second swapped file".into();
        mine.extraction.as_mut().unwrap().appdir = "/unpacked/second".into();
        mine.content_changed_outside = true;
        mine.changed_outside = true;
        // Meanwhile the person confirms the page of the first file.
        reg.update_confirmed(id, |f| {
            f.content_changed_outside = false;
            f.changed_outside = false;
            Ok(())
        })
        .unwrap();
        reg.save_changes(&read, &mut mine).unwrap();
        let back = reg.get(id).unwrap().unwrap();
        assert_eq!(back.source.sha256, "second swapped file");
        assert_eq!(
            back.extraction.as_ref().unwrap().appdir,
            Path::new("/unpacked/second")
        );
        assert!(
            back.content_changed_outside,
            "the new content still asks to be looked at first"
        );
        assert!(back.changed_outside, "the settings mark stays too");
        assert!(mine.content_changed_outside && mine.changed_outside);
    }

    /// A preset is always stored inside the presets folder, whatever its name:
    /// names like "../../evil" or "/etc/x" (typed, or from an imported file)
    /// cannot place a file elsewhere.
    #[test]
    fn preset_names_cannot_place_files_outside_the_presets_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let store = PresetStore::new(&paths);
        for name in ["../../evil", "/etc/evil", "..", "a/../../b"] {
            let mut p = Preset {
                name: name.into(),
                ..Default::default()
            };
            let file = store.save(&mut p).unwrap();
            assert_eq!(
                file.parent(),
                Some(paths.presets_dir().as_path()),
                "{name} → {}",
                file.display()
            );
        }
        assert!(
            !tmp.path().join("evil.toml").exists()
                && !tmp.path().parent().unwrap().join("evil.toml").exists()
        );
    }

    /// Regression (found in the test audit): a record changed outside SAM
    /// with an id like "../../.ssh" would have pointed the folders SAM
    /// deletes on removal (private home, logs) outside SAM's own folders.
    /// Such records, and records whose id differs from the file name, are
    /// not loaded.
    #[test]
    fn records_with_unsafe_or_mismatched_ids_are_not_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        fs::create_dir_all(paths.apps_dir()).unwrap();
        fs::write(
            paths.apps_dir().join("evil.json"),
            r#"{"id": "../../.ssh", "name": "Evil"}"#,
        )
        .unwrap();
        fs::write(
            paths.apps_dir().join("other.json"),
            r#"{"id": "appimage-real-1", "name": "Other"}"#,
        )
        .unwrap();
        fs::write(
            paths.apps_dir().join("appimage-ok-1.json"),
            r#"{"id": "appimage-ok-1", "name": "Ok"}"#,
        )
        .unwrap();
        let ids: Vec<String> = Registry::new(&paths)
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, vec!["appimage-ok-1"]);
    }

    /// The newest log is found even when two logs start within the same second.
    #[test]
    fn the_newest_log_is_found_even_within_one_second() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = Logs::new(&Paths::rooted(tmp.path()));
        let first = logs.new_log_path("appimage-x-1", LogKind::Launch).unwrap();
        fs::write(&first, "first").unwrap();
        let second = logs.new_log_path("appimage-x-1", LogKind::Launch).unwrap();
        fs::write(&second, "second").unwrap();
        // Same mtime second for both files, so the sequence number decides.
        let mtime = fs::metadata(&first).unwrap().modified().unwrap();
        fs::File::options()
            .write(true)
            .open(&second)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        assert_eq!(
            logs.latest("appimage-x-1", None).unwrap().unwrap().path,
            second
        );
    }

    /// Apps are found by name or ID, and an ambiguous name is refused.
    #[test]
    fn apps_are_found_by_name_or_id_and_ambiguous_names_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let reg = Registry::new(&paths);
        let mut a = AppEntry {
            id: "appimage-krita-9f3c".into(),
            name: "Krita".into(),
            ..Default::default()
        };
        reg.save(&mut a).unwrap();
        let mut b = AppEntry {
            id: "appimage-kate-1234".into(),
            name: "Kate".into(),
            ..Default::default()
        };
        reg.save(&mut b).unwrap();
        assert_eq!(reg.list().unwrap().len(), 2);
        assert_eq!(reg.resolve("krita").unwrap().id, a.id);
        assert_eq!(reg.resolve("appimage-kate").unwrap().id, b.id);
        assert!(reg.resolve("k").is_err(), "ambiguous");
        assert!(reg.resolve("gimp").is_err());
        assert!(reg.remove(&a.id).unwrap());
        assert!(reg.get(&a.id).unwrap().is_none());
        assert!(reg.get("../etc/passwd").unwrap().is_none());
    }

    /// Regression (audit U-L7): the name an AppImage gives itself came
    /// first, so one added later calling itself "firefox" was started for
    /// `sam-jail run firefox` instead of "Firefox Web Browser", with its own
    /// permissions. Now a later app's name cannot take a query over: it is
    /// ambiguous. A name that was there first keeps its meaning when
    /// another app with a longer name is added.
    #[test]
    fn a_name_an_app_chose_cannot_take_over_another_apps_query() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::new(&Paths::rooted(tmp.path()));
        let mut real = AppEntry {
            id: "appimage-firefox-web-browser-9f3c".into(),
            name: "Firefox Web Browser".into(),
            added_at: 100,
            ..Default::default()
        };
        reg.save(&mut real).unwrap();
        assert_eq!(reg.resolve("firefox").unwrap().id, real.id);
        let mut other = AppEntry {
            id: "appimage-firefox-1234".into(),
            name: "firefox".into(),
            added_at: 200,
            ..Default::default()
        };
        reg.save(&mut other).unwrap();
        let e = reg.resolve("firefox").unwrap_err().to_string();
        assert!(e.contains(&real.id) && e.contains(&other.id), "{e}");
        assert_eq!(reg.resolve("Firefox Web Browser").unwrap().id, real.id);
        assert_eq!(reg.resolve(&other.id).unwrap().id, other.id);

        // The other way round: "Foo" was there first, "Foo Pro" came later.
        let mut foo = AppEntry {
            id: "appimage-foo-1111".into(),
            name: "Foo".into(),
            added_at: 300,
            ..Default::default()
        };
        reg.save(&mut foo).unwrap();
        let mut pro = AppEntry {
            id: "appimage-foo-pro-2222".into(),
            name: "Foo Pro".into(),
            added_at: 400,
            ..Default::default()
        };
        reg.save(&mut pro).unwrap();
        assert_eq!(reg.resolve("foo").unwrap().id, foo.id);
        assert_eq!(reg.resolve("foo pro").unwrap().id, pro.id);
    }

    /// An AppImage chooses its own name: an app named `vlc` does not
    /// capture a command meant for "VLC media player", which `vlc` also
    /// names; the reference is refused as naming more than one app, and
    /// each app is still found by its ID or a reference only it matches
    /// (audit G-F7: the exact name won, so `sam-jail set vlc network.mode
    /// full` changed the hostile app without a word).
    #[test]
    fn an_apps_own_name_never_captures_a_reference_to_another_app() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry::new(&Paths::rooted(tmp.path()));
        let mut real = AppEntry {
            id: "appimage-vlc-media-player-9f3c".into(),
            name: "VLC media player".into(),
            ..Default::default()
        };
        reg.save(&mut real).unwrap();
        // Before the hostile app arrives, `vlc` names the real one.
        assert_eq!(reg.resolve("vlc").unwrap().id, real.id);
        let mut hostile = AppEntry {
            id: "appimage-vlc-1234".into(),
            name: "vlc".into(),
            ..Default::default()
        };
        reg.save(&mut hostile).unwrap();
        let err = reg.resolve("vlc").unwrap_err().to_string();
        assert!(
            err.contains(&real.id) && err.contains(&hostile.id),
            "not refused as naming both: {err}"
        );
        // A name the hostile app copies from part of the real one is
        // refused too ("media" names both).
        hostile.name = "media".into();
        reg.save(&mut hostile).unwrap();
        assert!(reg.resolve("media").is_err());
        assert_eq!(reg.resolve("vlc media player").unwrap().id, real.id);
        assert_eq!(reg.resolve(&real.id).unwrap().id, real.id);
        assert_eq!(reg.resolve("appimage-vlc-1").unwrap().id, hostile.id);
    }

    /// A damaged preset is moved aside once; a preset from a newer SAM is
    /// only skipped and stays where it is, for when SAM is updated
    /// (mutation run P14: moving every unreadable preset aside went
    /// unnoticed).
    #[test]
    fn only_a_damaged_preset_is_moved_aside() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PresetStore::new(&Paths::rooted(tmp.path()));
        fs::create_dir_all(&store.dir).unwrap();
        let damaged = store.dir.join("damaged.toml");
        fs::write(&damaged, "[preset\nname = ").unwrap();
        let newer = store.dir.join("newer.toml");
        let format = sam_core::format::CURRENT + 1;
        fs::write(
            &newer,
            format!("[preset]\nname = \"Newer\"\nformat = {format}\n\n[permissions]\n"),
        )
        .unwrap();
        assert!(store.list().unwrap().is_empty());
        assert!(!damaged.exists(), "the damaged preset is moved aside");
        assert_eq!(
            sam_core::format::damaged_files(&[store.dir.as_path()]).len(),
            1
        );
        assert!(newer.exists(), "a newer SAM's preset stays");
    }

    /// Presets in the older flat format still load.
    #[test]
    fn presets_in_the_older_flat_format_still_load() {
        let s = r#"
[preset]
name = "My Browser"
description = "Browser profile with no home access except Downloads"

[permissions]
network = "full"
home = false
downloads = "rw"
documents = false
audio = true
gpu = true
x11 = true
wayland = true
dbus_session = "filtered"
dbus_system = "none"
"#;
        let p = parse_preset_toml(s).unwrap();
        assert_eq!(p.name, "My Browser");
        assert_eq!(p.permissions.network.mode, sam_core::NetworkMode::Full);
        assert_eq!(p.permissions.filesystem.downloads, sam_core::Access::Rw);
        assert!(
            p.permissions.devices.gpu && p.permissions.audio.enabled && p.permissions.display.x11
        );
    }

    /// The risk word of a preset is worked out from its permissions, never
    /// taken from the file: a file placed in the presets folder that says
    /// "low" for full home and network is listed as Dangerous (review F6).
    #[test]
    fn a_presets_risk_word_comes_from_its_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let store = PresetStore::new(&paths);
        let mut perms = PermissionSet::strict_gui();
        perms.filesystem.home = true;
        perms.filesystem.home_access = sam_core::permissions::Access::Rw;
        perms.network.mode = sam_core::permissions::NetworkMode::Full;
        let mut p = Preset {
            name: "Looks Harmless".into(),
            permissions: perms.clone(),
            ..Default::default()
        };
        // The file claims the lowest word.
        p.risk = sam_core::RiskLevel::Low;
        let claimed = preset_to_toml(&p).unwrap();
        assert!(claimed.contains("risk = \"low\""), "{claimed}");
        fs::create_dir_all(paths.presets_dir()).unwrap();
        fs::write(store.file_for(&p.name), &claimed).unwrap();
        let want = sam_core::risk::assess(&perms).level;
        assert_eq!(want, sam_core::RiskLevel::Dangerous);
        assert_eq!(store.get("Looks Harmless").unwrap().unwrap().risk, want);
        assert_eq!(parse_preset_toml(&claimed).unwrap().risk, want);
    }

    /// Importing a preset file never replaces a preset of the same name: it
    /// gets a free name instead, and the person's own stays as it was
    /// (review F9).
    #[test]
    fn an_imported_preset_never_replaces_one_of_the_same_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PresetStore::new(&Paths::rooted(tmp.path()));
        let mut own = Preset {
            name: "Browser".into(),
            permissions: PermissionSet::strict_gui(),
            ..Default::default()
        };
        store.save(&mut own).unwrap();
        let mut wide = PermissionSet::strict_gui();
        wide.filesystem.home = true;
        let imported = |name: &str| Preset {
            name: name.into(),
            permissions: wide.clone(),
            ..Default::default()
        };
        // Same name, other letter case and the same file name: all kept.
        for (i, name) in ["Browser", "BROWSER", "browser!"].iter().enumerate() {
            let mut p = imported(name);
            let path = store.import(&mut p).unwrap();
            assert_ne!(path, store.file_for("Browser"), "{name}");
            assert_ne!(p.name.to_lowercase(), "browser", "{name}");
            assert!(p.name.contains("(imported"), "{name}: {}", p.name);
            assert_eq!(store.list().unwrap().len(), i + 2);
        }
        let kept = store.get("Browser").unwrap().unwrap();
        assert_eq!(kept.name, "Browser");
        assert_eq!(
            kept.permissions, own.permissions,
            "the own preset is unchanged"
        );
        assert!(store.get("Browser (imported)").unwrap().is_some());
        assert!(store.get("Browser (imported 2)").unwrap().is_some());
        // A free name is kept as it is.
        let mut fresh = imported("Editor");
        store.import(&mut fresh).unwrap();
        assert_eq!(fresh.name, "Editor");
    }

    /// A saved preset loads back unchanged, found by its name in any letter case.
    #[test]
    fn a_saved_preset_loads_back_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PresetStore::new(&Paths::rooted(tmp.path()));
        let mut p = Preset {
            name: "My Preset".into(),
            permissions: PermissionSet::strict_gui(),
            ..Default::default()
        };
        store.save(&mut p).unwrap();
        let got = store.get("my preset").unwrap().unwrap();
        assert_eq!(got.permissions, p.permissions);
        assert!(got.created_at > 0);
        assert!(store.delete("My Preset").unwrap());
        assert!(store.get("My Preset").unwrap().is_none());
    }
}
