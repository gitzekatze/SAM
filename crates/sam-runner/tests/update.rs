//! Going back after an update: the replaced version (kept in SAM's data
//! folder) returns to its old place, the newer file is kept for switching
//! again, settings stay. The download itself is tested against a local
//! HTTPS server in update_server.rs.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;

use sam_core::model::UpdateBackup;
use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

/// Undoing an update puts the previous version back.
#[test]
fn undo_puts_the_previous_version_back() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let apps = root.join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let v1 = apps.join("Tool-1.0-x86_64.AppImage");
    build(&v1, &FixtureSpec::hello("Tool")).unwrap();
    let paths = Paths::rooted(&root.join("sam"));
    let sam = Sam::with_paths(paths.clone()).unwrap();
    let id = sam
        .add(
            &v1,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    sam.set_permission(&id, "network.mode", "full").unwrap();

    // What `update` leaves behind: v1 kept in the data folder, v2 in place.
    let kept_dir = paths.data_dir.join("update-backups").join(&id);
    fs::create_dir_all(&kept_dir).unwrap();
    let kept = kept_dir.join("Tool-1.0-x86_64.AppImage");
    fs::rename(&v1, &kept).unwrap();
    let v2 = apps.join("Tool-2.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "Tool, version 2".into();
    build(&v2, &spec).unwrap();
    sam.relocate(&id, &v2).unwrap();
    let mut e = sam.reextract(&id, false).unwrap();
    e.update_backup = Some(UpdateBackup {
        file: kept.clone(),
        original_path: v1.clone(),
        replaced_at: 1,
        sha256: None,
        placed_sha256: None,
        placing: None,
    });
    sam.registry().save(&mut e).unwrap();
    assert!(
        sam.disk_usage(&e).previous > 0,
        "the kept version counts as disk space"
    );

    let back = sam.undo_update(&id).unwrap();
    assert_eq!(
        back.source_path,
        fs::canonicalize(&v1).unwrap(),
        "v1 is back in its place"
    );
    assert!(!v2.exists(), "v2 left the folder");
    let b = back
        .update_backup
        .clone()
        .expect("v2 kept for switching again");
    assert!(b.file.exists() && b.file.starts_with(&kept_dir));
    assert_eq!(
        back.profile.permissions.network.mode.as_str(),
        "full",
        "settings kept"
    );
    let x = back.extraction.clone().unwrap();
    assert!(x.appdir.join(&x.entry).exists(), "unpacked again");

    // Removing the sandbox also removes the kept version.
    sam.remove(&id, false).unwrap();
    assert!(!kept_dir.exists());
}

/// What `update` leaves behind, made by hand: v1 kept in SAM's backup
/// folder (recorded with `kept_sha256`), v2 in place, unpacked and looked at.
fn updated_by_hand(
    root: &std::path::Path,
    kept_sha256: bool,
) -> (Sam, String, std::path::PathBuf, std::path::PathBuf) {
    updated_by_hand_as(root, kept_sha256, "Tool-2.0-x86_64.AppImage")
}

/// [`updated_by_hand`] with the newer version named `newer`.
fn updated_by_hand_as(
    root: &std::path::Path,
    kept_sha256: bool,
    newer: &str,
) -> (Sam, String, std::path::PathBuf, std::path::PathBuf) {
    let apps = root.join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let v1 = apps.join("Tool-1.0-x86_64.AppImage");
    build(&v1, &FixtureSpec::hello("Tool")).unwrap();
    let paths = Paths::rooted(&root.join("sam"));
    let sam = Sam::with_paths(paths.clone()).unwrap();
    let id = sam
        .add(
            &v1,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let kept_dir = paths.data_dir.join("update-backups").join(&id);
    fs::create_dir_all(&kept_dir).unwrap();
    let kept = kept_dir.join("Tool-1.0-x86_64.AppImage");
    fs::rename(&v1, &kept).unwrap();
    let v2 = apps.join(newer);
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "Tool, version 2".into();
    build(&v2, &spec).unwrap();
    sam.relocate(&id, &v2).unwrap();
    sam.reextract(&id, false).unwrap();
    let mut e = sam.mark_reviewed(&id).unwrap();
    e.update_backup = Some(UpdateBackup {
        sha256: kept_sha256.then(|| sam_intake::fingerprint::sha256_file(&kept).unwrap()),
        file: kept.clone(),
        original_path: v1.clone(),
        replaced_at: 1,
        placed_sha256: None,
        placing: None,
    });
    sam.registry().save(&mut e).unwrap();
    (sam, id, v2, kept)
}

/// Regression (review 2026-11-23, U-1): going back kept the current file
/// as "the newer version" without looking at it, and going forward again
/// unpacked it as SAM's own work, without the review a replaced file needs.
/// An app with access to the AppImage's folder could swap its own program
/// in and wait. Now going back refuses a current file that is not the one
/// SAM unpacked.
#[test]
fn going_back_refuses_a_current_version_swapped_outside_sam() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, kept) = updated_by_hand(tmp.path(), true);
    let unpacked = sam.resolve(&id).unwrap().extraction.unwrap().source.sha256;
    let mut evil = FixtureSpec::hello("Tool");
    evil.comment = "another app's program".into();
    build(&tmp.path().join("evil.AppImage"), &evil).unwrap();
    fs::copy(tmp.path().join("evil.AppImage"), &v2).unwrap();
    let swapped = fs::read(&v2).unwrap();

    let Err(err) = sam.undo_update(&id) else {
        panic!("went back over a swapped file");
    };
    assert!(
        format!("{err:#}").contains("changed outside SAM"),
        "{err:#}"
    );
    assert_eq!(
        fs::read(&v2).unwrap(),
        swapped,
        "the file stays where it was"
    );
    assert!(kept.is_file(), "the earlier version is still kept");
    let e = sam.resolve(&id).unwrap();
    assert_eq!(
        e.extraction.unwrap().source.sha256,
        unpacked,
        "not unpacked"
    );
    assert_eq!(e.update_backup.unwrap().file, kept);
}

/// Regression (review 2026-11-23, U-1): a version kept by an earlier SAM
/// was moved out of the AppImage's folder without being checked, so it may
/// not be what SAM unpacked then. Going back to it now asks for a review,
/// like any file SAM did not check itself; a version SAM checked when it
/// kept it does not.
#[test]
fn going_back_to_a_version_kept_without_its_checksum_needs_a_review() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, _, _) = updated_by_hand(tmp.path(), false);
    let e = sam.undo_update(&id).unwrap();
    assert!(
        e.content_changed_outside,
        "the unchecked version waits for a review"
    );

    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, _, _) = updated_by_hand(tmp.path(), true);
    let e = sam.undo_update(&id).unwrap();
    assert!(!e.content_changed_outside, "a checked version is SAM's own");
}

/// Regression (review check 2026-11-23, U-1): going back moved the current
/// file from the AppImage's folder into SAM's backup folder and checked it
/// there. A move keeps the file itself: another app that still held it (a
/// second name, a hard link, in the same folder, or the file open for
/// writing) could change it after the check, and going forward again
/// unpacked its program as SAM's own. Now SAM keeps a copy that only it can
/// reach.
#[test]
fn going_back_keeps_a_copy_of_the_newer_version_no_other_app_can_change() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, _) = updated_by_hand(tmp.path(), true);
    let newer = fs::read(&v2).unwrap();
    let unpacked = sam.resolve(&id).unwrap().extraction.unwrap().source.sha256;
    // Another app keeps a second name for the current file.
    let held = v2.with_file_name(".held");
    fs::hard_link(&v2, &held).unwrap();

    let e = sam.undo_update(&id).unwrap();
    let kept_newer = e.update_backup.unwrap().file;
    // It writes its own program through that name.
    let mut evil = FixtureSpec::hello("Tool");
    evil.comment = "another app's program".into();
    build(&tmp.path().join("evil.AppImage"), &evil).unwrap();
    fs::write(&held, fs::read(tmp.path().join("evil.AppImage")).unwrap()).unwrap();
    assert!(
        fs::read(&kept_newer).unwrap() == newer,
        "the newer version kept in SAM's folder is SAM's own copy"
    );

    // Going forward again brings back the newer version as it was checked.
    let e = sam.undo_update(&id).unwrap();
    assert_eq!(e.extraction.unwrap().source.sha256, unpacked);
    assert!(!e.content_changed_outside, "it is the version SAM checked");
}

/// The mode of `p` (permission bits only).
fn mode(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Going back keeps each file's own mode: neither the version put back
/// nor the newer one kept in SAM's folder becomes writable for others
/// (mutation run 2026-11-24: a mode of 0777 went unnoticed).
#[test]
fn going_back_keeps_the_files_modes() {
    let tmp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    let (sam, id, v2, kept) = updated_by_hand(tmp.path(), true);
    // Modes of their own, unlike SAM's fallback (0755) and each other.
    fs::set_permissions(&kept, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&v2, fs::Permissions::from_mode(0o750)).unwrap();
    let e = sam.undo_update(&id).unwrap();
    assert_eq!(mode(&e.source_path), 0o700, "the version put back");
    let newer = e.update_backup.unwrap().file;
    assert_eq!(mode(&newer), 0o750, "the newer version kept");
}

/// A version SAM checked when it kept it, but changed since, asks for a
/// review when SAM goes back to it (mutation run 2026-11-24: a recorded
/// checksum alone could count as checked).
#[test]
fn going_back_to_a_kept_version_changed_since_needs_a_review() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, _, kept) = updated_by_hand(tmp.path(), true);
    let mut other = FixtureSpec::hello("Tool");
    other.comment = "changed after SAM kept it".into();
    let swapped = tmp.path().join("other.AppImage");
    build(&swapped, &other).unwrap();
    fs::write(&kept, fs::read(&swapped).unwrap()).unwrap();
    let e = sam.undo_update(&id).unwrap();
    assert!(
        e.content_changed_outside,
        "the changed version waits for a review"
    );
}

/// When the earlier version cannot be put back (here: it cannot be read),
/// going back fails and leaves both versions where they were: the newer
/// one in place and the earlier one in SAM's backup folder, also when both
/// have the same file name (mutation run 2026-11-24: losing either went
/// unnoticed).
#[test]
fn a_failed_going_back_leaves_both_versions_where_they_were() {
    use std::os::unix::fs::PermissionsExt;
    for newer_name in ["Tool-2.0-x86_64.AppImage", "Tool-1.0-x86_64.AppImage"] {
        let tmp = tempfile::tempdir().unwrap();
        let (sam, id, v2, kept) = updated_by_hand_as(tmp.path(), true, newer_name);
        let (newer, earlier) = (fs::read(&v2).unwrap(), fs::read(&kept).unwrap());
        fs::set_permissions(&kept, fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::File::open(&kept).is_ok();
        let result = sam.undo_update(&id);
        let _ = fs::set_permissions(&kept, fs::Permissions::from_mode(0o644));
        assert!(
            !readable,
            "mode 000 must lock the file: run as a normal user"
        );
        assert!(result.is_err(), "{newer_name}: going back failed");
        assert_eq!(
            fs::read(&v2).unwrap(),
            newer,
            "{newer_name}: the newer version"
        );
        assert_eq!(
            fs::read(&kept).unwrap(),
            earlier,
            "{newer_name}: the earlier one"
        );
        let folder: Vec<_> = fs::read_dir(kept.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            folder,
            [kept.file_name().unwrap()],
            "{newer_name}: nothing left over"
        );
        let e = sam.resolve(&id).unwrap();
        assert_eq!(
            e.source_path,
            fs::canonicalize(&v2).unwrap(),
            "{newer_name}"
        );
        assert_eq!(e.update_backup.unwrap().file, kept, "{newer_name}");
    }
}

/// The names in `dir`, sorted.
fn names_in(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Regression (review B2 S6, R86): when putting the earlier version in
/// place failed and putting the current one back failed too (a full disk:
/// two failing copies), the earlier version stayed at `.going-back` and the
/// newer copy at the backup's name. The next go back renamed the newer file
/// over `.going-back`, so the earlier version was lost and the newer one
/// installed as "earlier". Here the state those failures (or a power loss)
/// leave is made by hand; going back and updating now stop, name both
/// files and change nothing.
#[test]
fn an_interrupted_going_back_never_loses_the_earlier_version() {
    let tmp = tempfile::tempdir().unwrap();
    // Both versions with the same name, as many projects publish.
    let (sam, id, v2, kept) = updated_by_hand_as(tmp.path(), true, "Tool-1.0-x86_64.AppImage");
    let (newer, earlier) = (fs::read(&v2).unwrap(), fs::read(&kept).unwrap());
    let aside = kept.with_file_name(".going-back");
    fs::rename(&kept, &aside).unwrap();
    fs::write(&kept, &newer).unwrap();
    let record = sam.resolve(&id).unwrap();

    let Err(err) = sam.undo_update(&id) else {
        panic!("went back over an interrupted go back");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("interrupted"), "{msg}");
    assert!(
        msg.contains(".going-back"),
        "names the earlier version: {msg}"
    );
    assert_eq!(fs::read(&aside).unwrap(), earlier, "the earlier version");
    assert_eq!(fs::read(&kept).unwrap(), newer, "the newer copy");
    assert_eq!(fs::read(&v2).unwrap(), newer, "the app's file");
    let after = sam.resolve(&id).unwrap();
    assert_eq!(after.source_path, record.source_path);
    assert_eq!(after.update_backup, record.update_backup);

    // An update would delete the old backups, the earlier version with them.
    let Err(err) = sam.update(&id, false) else {
        panic!("updated over an interrupted go back");
    };
    assert!(format!("{err:#}").contains("interrupted"), "{err:#}");
    assert_eq!(fs::read(&aside).unwrap(), earlier, "still there");
}

/// Regression (review B2 S6, R86, R89): going back removed the current
/// file before the earlier version was in place and recorded. When saving
/// the record failed (here: the record's folder is read-only), the app's
/// folder held the earlier version while the record still named the newer
/// one. Now a failure before the record is saved leaves both versions and
/// the record as they were, also when both have the same file name.
#[test]
fn a_going_back_whose_record_cannot_be_saved_changes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    for newer_name in ["Tool-2.0-x86_64.AppImage", "Tool-1.0-x86_64.AppImage"] {
        let tmp = tempfile::tempdir().unwrap();
        let (sam, id, v2, kept) = updated_by_hand_as(tmp.path(), true, newer_name);
        let (newer, earlier) = (fs::read(&v2).unwrap(), fs::read(&kept).unwrap());
        let record = sam.resolve(&id).unwrap();
        let records = sam.paths.apps_dir();
        fs::set_permissions(&records, fs::Permissions::from_mode(0o555)).unwrap();
        let locked = fs::File::create(records.join("probe")).is_err();
        let result = sam.undo_update(&id);
        fs::set_permissions(&records, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(locked, "a read-only folder must lock: run as a normal user");
        assert!(
            result.is_err(),
            "{newer_name}: the record could not be saved"
        );
        assert_eq!(names_in(v2.parent().unwrap()), [newer_name], "{newer_name}");
        assert_eq!(
            fs::read(&v2).unwrap(),
            newer,
            "{newer_name}: the newer version"
        );
        assert_eq!(
            names_in(kept.parent().unwrap()),
            [kept.file_name().unwrap().to_string_lossy()],
            "{newer_name}: nothing left over"
        );
        assert_eq!(
            fs::read(&kept).unwrap(),
            earlier,
            "{newer_name}: the earlier one"
        );
        let after = sam.resolve(&id).unwrap();
        assert_eq!(after.source_path, record.source_path, "{newer_name}");
        assert_eq!(after.update_backup, record.update_backup, "{newer_name}");
    }
}

/// Review of the fix for R86: a go back that SAM was stopped in (killed,
/// a power loss) left the earlier version at `.going-back`, and from then
/// on every go back and update refused. Going back no longer moves the
/// earlier version aside, and SAM repairs what an older run left: here
/// (made by hand) a stop after the record was saved, where `.going-back`
/// is a second copy of the version put in place, and a stop right after
/// the earlier version stepped aside, where its kept name is still free.
#[test]
fn a_go_back_stopped_midway_still_lets_the_app_go_back_and_update() {
    use sam_intake::fingerprint::sha256_file;
    // Stopped after the record was saved, while unpacking.
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, kept) = updated_by_hand(tmp.path(), true);
    let (newer, earlier) = (fs::read(&v2).unwrap(), fs::read(&kept).unwrap());
    let backups = kept.parent().unwrap();
    let keep = backups.join(v2.file_name().unwrap());
    fs::copy(&v2, &keep).unwrap();
    let aside = backups.join(".going-back");
    fs::rename(&kept, &aside).unwrap();
    let v1 = v2.with_file_name("Tool-1.0-x86_64.AppImage");
    fs::copy(&aside, &v1).unwrap();
    fs::remove_file(&v2).unwrap();
    let mut e = sam.resolve(&id).unwrap();
    e.source_path = fs::canonicalize(&v1).unwrap();
    e.update_backup = Some(UpdateBackup {
        file: keep.clone(),
        original_path: v2.clone(),
        replaced_at: 1,
        sha256: Some(sha256_file(&keep).unwrap()),
        placed_sha256: Some(sha256_file(&v1).unwrap()),
        placing: None,
    });
    sam.registry().save(&mut e).unwrap();

    let e = sam
        .undo_update(&id)
        .unwrap_or_else(|e| panic!("going back was refused: {e:#}"));
    assert_eq!(fs::read(&e.source_path).unwrap(), newer, "forward again");
    assert!(!aside.exists(), "the second copy is gone");
    let e = sam
        .undo_update(&id)
        .unwrap_or_else(|e| panic!("going back again was refused: {e:#}"));
    assert_eq!(fs::read(&e.source_path).unwrap(), earlier, "and back");
    let err = sam.update(&id, false).unwrap_err();
    assert!(!format!("{err:#}").contains("interrupted"), "{err:#}");

    // Stopped right after the earlier version stepped aside.
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, _, kept) = updated_by_hand(tmp.path(), true);
    let earlier = fs::read(&kept).unwrap();
    fs::rename(&kept, kept.with_file_name(".going-back")).unwrap();
    let e = sam
        .undo_update(&id)
        .unwrap_or_else(|e| panic!("going back was refused: {e:#}"));
    assert_eq!(fs::read(&e.source_path).unwrap(), earlier, "back");
}

/// Review of the fix for R89: a SAM stopped while writing the new version
/// left a hidden, executable copy of the app in the person's folder for
/// good. An update or a go back of that app now removes such leftovers of
/// its own (files and links, never what a link points to) and nothing
/// else: not another app's, not a name SAM does not give, not a folder.
#[test]
fn leftover_incoming_files_of_the_app_are_removed_and_nothing_else() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, _) = updated_by_hand(tmp.path(), true);
    let apps = v2.parent().unwrap().to_path_buf();
    let victim = tmp.path().join("victim.txt");
    fs::write(&victim, "the person's file").unwrap();
    let plant = || {
        fs::write(apps.join(format!(".sam-incoming-{id}-123-abc")), "half").unwrap();
        let _ = fs::remove_file(apps.join(format!(".sam-incoming-{id}-124-def")));
        std::os::unix::fs::symlink(&victim, apps.join(format!(".sam-incoming-{id}-124-def")))
            .unwrap();
    };
    let others = [
        format!(".sam-incoming-{id}-notours"),
        ".sam-incoming-appimage-other-1a2b-1-a".to_string(),
        "notes.txt".to_string(),
    ];
    for o in &others {
        fs::write(apps.join(o), "keep").unwrap();
    }
    fs::create_dir_all(apps.join(format!(".sam-incoming-{id}-125-beef"))).unwrap();

    for step in ["update", "go back"] {
        plant();
        if step == "update" {
            let _ = sam.update(&id, false);
        } else {
            sam.undo_update(&id).unwrap();
        }
        let names = names_in(&apps);
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with("-123-abc") || n.ends_with("-124-def")),
            "{step}: {names:?}"
        );
        for o in &others {
            assert!(names.contains(o), "{step}: {o} stays");
        }
        assert!(
            apps.join(format!(".sam-incoming-{id}-125-beef")).is_dir(),
            "{step}"
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "the person's file");
    }
}

/// Second review of the fix for R86: with the same name for both versions
/// (the common case), going back wrote the newer copy over the earlier
/// version's kept name before the record was saved, so a stop while
/// copying left a state that blocked every later go back. Now nothing in
/// the backup folder is renamed or overwritten before the save. Here the
/// states a stop at each step before the save leaves (made by hand): a
/// half-written kept copy in a fresh folder, then also a half-written
/// incoming file in the app's folder. The app still goes back and
/// forward, updates are not blocked, and nothing is lost or left over.
#[test]
fn a_same_name_go_back_stopped_before_its_record_was_saved_loses_nothing() {
    for step in ["copy of the current version", "copy of the earlier version"] {
        let tmp = tempfile::tempdir().unwrap();
        let (sam, id, v2, kept) = updated_by_hand_as(tmp.path(), true, "Tool-1.0-x86_64.AppImage");
        let (newer, earlier) = (fs::read(&v2).unwrap(), fs::read(&kept).unwrap());
        let root = kept.parent().unwrap();
        let fresh = root.join("kept-1-a");
        fs::create_dir_all(&fresh).unwrap();
        let name = v2.file_name().unwrap();
        if step == "copy of the current version" {
            fs::write(fresh.join(name), &newer[..newer.len() / 2]).unwrap();
        } else {
            fs::write(fresh.join(name), &newer).unwrap();
            let incoming = v2.with_file_name(format!(".sam-incoming-{id}-1-a"));
            fs::write(incoming, &earlier[..earlier.len() / 2]).unwrap();
        }

        let e = sam
            .undo_update(&id)
            .unwrap_or_else(|e| panic!("{step}: going back was refused: {e:#}"));
        assert_eq!(fs::read(&e.source_path).unwrap(), earlier, "{step}: back");
        let way = e.update_backup.unwrap().file;
        assert_eq!(fs::read(&way).unwrap(), newer, "{step}: the newer one kept");
        assert_eq!(
            names_in(v2.parent().unwrap()),
            [name.to_string_lossy()],
            "{step}"
        );
        assert!(!fresh.exists(), "{step}: the stopped run's folder is gone");
        let e = sam
            .undo_update(&id)
            .unwrap_or_else(|e| panic!("{step}: going forward was refused: {e:#}"));
        assert_eq!(fs::read(&e.source_path).unwrap(), newer, "{step}: forward");
        let way = e.update_backup.unwrap().file;
        assert_eq!(
            fs::read(&way).unwrap(),
            earlier,
            "{step}: the earlier one kept"
        );
        let err = sam.update(&id, false).unwrap_err();
        assert!(
            !format!("{err:#}").contains("interrupted"),
            "{step}: {err:#}"
        );
    }
}

/// Second review of the fix for R86: a `.going-back` left by an older SAM
/// was deleted as a second copy when the app's current file had the same
/// content. Another app that can write to the AppImage's folder can put a
/// public copy of the earlier version there, and that alone must never make
/// SAM delete its own checked copy. It is deleted only when it is also the
/// version that go back put in place; here it is not, so SAM refuses.
#[test]
fn a_public_copy_of_the_earlier_version_never_makes_sam_delete_its_own() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, kept) = updated_by_hand_as(tmp.path(), true, "Tool-1.0-x86_64.AppImage");
    let (newer, earlier) = (fs::read(&v2).unwrap(), fs::read(&kept).unwrap());
    let aside = kept.with_file_name(".going-back");
    fs::rename(&kept, &aside).unwrap();
    fs::write(&kept, &newer).unwrap();
    // Another app drops the earlier version over the app's file.
    fs::write(&v2, &earlier).unwrap();

    let err = sam.undo_update(&id).unwrap_err();
    assert!(format!("{err:#}").contains("interrupted"), "{err:#}");
    assert_eq!(
        fs::read(&aside).unwrap(),
        earlier,
        "SAM's checked copy stays"
    );
    assert_eq!(fs::read(&kept).unwrap(), newer);
}

/// Second review of the fix for R86: with different names, a go back
/// stopped after the earlier version took its name but before the record
/// was saved left a complete copy there, and every later go back refused
/// ("exists again"). That copy is now taken as the go back's own, since
/// the same file is about to be put there; any other file at that name
/// still stops going back and is left alone.
#[test]
fn a_go_back_stopped_after_placing_under_a_new_name_goes_on() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, kept) = updated_by_hand(tmp.path(), true);
    let earlier = fs::read(&kept).unwrap();
    let back_to = v2.with_file_name(kept.file_name().unwrap());

    fs::write(&back_to, "the person's own file").unwrap();
    let err = sam.undo_update(&id).unwrap_err();
    assert!(format!("{err:#}").contains("exists again"), "{err:#}");
    assert_eq!(
        fs::read_to_string(&back_to).unwrap(),
        "the person's own file"
    );

    fs::write(&back_to, &earlier).unwrap();
    let e = sam
        .undo_update(&id)
        .unwrap_or_else(|e| panic!("going back was refused: {e:#}"));
    assert_eq!(fs::read(&e.source_path).unwrap(), earlier);
    assert_eq!(
        names_in(v2.parent().unwrap()),
        [back_to.file_name().unwrap().to_string_lossy()]
    );
}

/// Third review of the fix for R86: a same-name go back stopped after its
/// record was saved but before the earlier version took the app's place
/// left that version named by no record; the next go back removed the
/// placed copy as a leftover, "went back" to the newer one, and deleted
/// SAM's copy of the earlier version. Now the record says what is being
/// put in place until it is unpacked. Here that state is made by hand:
/// the next go back finishes it from SAM's own copy, and so does the next
/// update; the earlier version survives either way.
#[test]
fn a_same_name_go_back_stopped_after_its_record_was_saved_is_finished() {
    use sam_intake::fingerprint::sha256_file;
    for next in ["go back", "update"] {
        let tmp = tempfile::tempdir().unwrap();
        let (sam, id, v2, kept) = updated_by_hand_as(tmp.path(), true, "Tool-1.0-x86_64.AppImage");
        let (newer, earlier) = (fs::read(&v2).unwrap(), fs::read(&kept).unwrap());
        let fresh = kept.parent().unwrap().join("kept-1-a");
        fs::create_dir_all(&fresh).unwrap();
        let newer_kept = fresh.join(v2.file_name().unwrap());
        fs::write(&newer_kept, &newer).unwrap();
        // The incoming copy (another app could have swapped it).
        let incoming = v2.with_file_name(format!(".sam-incoming-{id}-1-a"));
        fs::write(&incoming, "swapped by another app").unwrap();
        let mut e = sam.resolve(&id).unwrap();
        let k = sha256_file(&kept).unwrap();
        e.update_backup = Some(UpdateBackup {
            file: newer_kept.clone(),
            original_path: v2.clone(),
            replaced_at: 1,
            sha256: Some(sha256_file(&newer_kept).unwrap()),
            placed_sha256: Some(k.clone()),
            placing: Some(sam_core::model::Placing {
                file: kept.clone(),
                sha256: k.clone(),
                to: e.source_path.clone(),
                checked: true,
                going_back: true,
            }),
        });
        sam.registry().save(&mut e).unwrap();

        if next == "go back" {
            let e = sam
                .undo_update(&id)
                .unwrap_or_else(|e| panic!("going back was refused: {e:#}"));
            assert_eq!(
                fs::read(&e.source_path).unwrap(),
                earlier,
                "{next}: reaches it"
            );
        } else {
            let err = sam.update(&id, false).unwrap_err();
            assert!(!format!("{err:#}").contains("changed outside"), "{err:#}");
        }
        let e = sam.resolve(&id).unwrap();
        assert_eq!(
            fs::read(&e.source_path).unwrap(),
            earlier,
            "{next}: in place"
        );
        assert_eq!(e.extraction.unwrap().source.sha256, k, "{next}: unpacked");
        let b = e.update_backup.unwrap();
        assert_eq!(b.placing, None, "{next}: finished");
        assert_eq!(
            fs::read(&b.file).unwrap(),
            newer,
            "{next}: the newer one kept"
        );
        assert!(!incoming.exists(), "{next}: no leftover");
        // And forward again.
        let e = sam.undo_update(&id).unwrap();
        assert_eq!(fs::read(&e.source_path).unwrap(), newer, "{next}: forward");
        assert_eq!(
            fs::read(e.update_backup.unwrap().file).unwrap(),
            earlier,
            "{next}"
        );
    }
}

/// Third review of the fix for R89: an update stopped after its record was
/// saved but before the new version was in place (or unpacked) left the
/// old file with a way back to itself, and the next update said another
/// program had changed it. Now the next update or go back first finishes
/// it from SAM's checked copy of the download. Here that state is made by
/// hand; the next update finishes it.
#[test]
fn an_update_stopped_after_its_record_was_saved_is_finished_first() {
    use sam_intake::fingerprint::sha256_file;
    let tmp = tempfile::tempdir().unwrap();
    let apps = tmp.path().join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let installed = apps.join("Tool-x86_64.AppImage");
    build(&installed, &FixtureSpec::hello("Tool")).unwrap();
    let old = fs::read(&installed).unwrap();
    let paths = Paths::rooted(&tmp.path().join("sam"));
    let sam = Sam::with_paths(paths.clone()).unwrap();
    let id = sam
        .add(
            &installed,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let fresh = paths
        .data_dir
        .join("update-backups")
        .join(&id)
        .join("kept-1-a");
    fs::create_dir_all(&fresh).unwrap();
    let way_back = fresh.join("Tool-x86_64.AppImage");
    fs::write(&way_back, &old).unwrap();
    let download = fresh.join(".sam-placing");
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "Tool, version 2".into();
    build(&download, &spec).unwrap();
    let new = fs::read(&download).unwrap();
    let n = sha256_file(&download).unwrap();
    let mut e = sam.resolve(&id).unwrap();
    e.update_backup = Some(UpdateBackup {
        file: way_back.clone(),
        original_path: installed.clone(),
        replaced_at: 1,
        sha256: Some(sha256_file(&way_back).unwrap()),
        placed_sha256: Some(n.clone()),
        placing: Some(sam_core::model::Placing {
            file: download.clone(),
            sha256: n.clone(),
            to: e.source_path.clone(),
            checked: true,
            going_back: false,
        }),
    });
    sam.registry().save(&mut e).unwrap();

    let err = sam.update(&id, false).unwrap_err();
    assert!(!format!("{err:#}").contains("changed outside"), "{err:#}");
    let e = sam.resolve(&id).unwrap();
    assert_eq!(fs::read(&e.source_path).unwrap(), new, "finished");
    assert_eq!(e.extraction.unwrap().source.sha256, n, "unpacked");
    assert!(!e.content_changed_outside, "SAM's own change");
    let b = e.update_backup.unwrap();
    assert_eq!(b.placing, None);
    assert_eq!(fs::read(&b.file).unwrap(), old, "the way back");
    assert!(!download.exists(), "the checked download is gone");
}

/// Third review of the fix for R89: removing the sandbox or relocating the
/// app left this app's half-written incoming copies in the AppImage's
/// folder for good. Both remove them now.
#[test]
fn removing_or_relocating_an_app_removes_its_incoming_leftovers() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, _) = updated_by_hand(tmp.path(), true);
    let leftover = |dir: &std::path::Path| dir.join(format!(".sam-incoming-{id}-7-beef"));
    fs::write(leftover(v2.parent().unwrap()), "half").unwrap();
    let elsewhere = tmp.path().join("Elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let moved = elsewhere.join(v2.file_name().unwrap());
    fs::rename(&v2, &moved).unwrap();
    sam.relocate(&id, &moved).unwrap();
    assert!(!leftover(v2.parent().unwrap()).exists(), "relocating");

    fs::write(leftover(&elsewhere), "half").unwrap();
    sam.remove(&id, false).unwrap();
    assert!(!leftover(&elsewhere).exists(), "removing");
}

/// A stopped update is finished only from SAM's own copy as it was
/// checked: one changed since is never put in place. SAM says so once,
/// leaves the app's file as it is and drops the mark, so the app is not
/// blocked for good.
#[test]
fn a_stopped_update_whose_own_copy_changed_is_not_finished() {
    use sam_intake::fingerprint::sha256_file;
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, kept) = updated_by_hand(tmp.path(), true);
    let current = fs::read(&v2).unwrap();
    let fresh = kept.parent().unwrap().join("kept-1-a");
    fs::create_dir_all(&fresh).unwrap();
    let copy = fresh.join(".sam-placing");
    fs::write(&copy, "SAM's copy, changed since").unwrap();
    let mut e = sam.resolve(&id).unwrap();
    let mut b = e.update_backup.clone().unwrap();
    b.placing = Some(sam_core::model::Placing {
        file: copy.clone(),
        sha256: sha256_file(&kept).unwrap(),
        to: e.source_path.clone(),
        checked: true,
        going_back: false,
    });
    e.update_backup = Some(b);
    sam.registry().save(&mut e).unwrap();

    let err = sam.update(&id, false).unwrap_err();
    assert!(format!("{err:#}").contains("cannot finish"), "{err:#}");
    assert_eq!(fs::read(&v2).unwrap(), current, "the app's file stays");
    let e = sam.resolve(&id).unwrap();
    assert_eq!(
        e.update_backup.unwrap().placing,
        None,
        "not blocked for good"
    );
}

/// The state a same-name go back leaves when SAM is stopped after its
/// record was saved and before the earlier version took the app's place:
/// the earlier version exists only as SAM's copy that the mark names.
/// Returns SAM, the app, its file, that copy and the earlier version.
fn stopped_after_saving_a_go_back(
    root: &std::path::Path,
) -> (Sam, String, std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
    use sam_intake::fingerprint::sha256_file;
    let (sam, id, v2, kept) = updated_by_hand_as(root, true, "Tool-1.0-x86_64.AppImage");
    let (newer, earlier) = (fs::read(&v2).unwrap(), fs::read(&kept).unwrap());
    let fresh = kept.parent().unwrap().join("kept-1-a");
    fs::create_dir_all(&fresh).unwrap();
    let newer_kept = fresh.join(v2.file_name().unwrap());
    fs::write(&newer_kept, &newer).unwrap();
    let k = sha256_file(&kept).unwrap();
    let mut e = sam.resolve(&id).unwrap();
    e.update_backup = Some(UpdateBackup {
        file: newer_kept.clone(),
        original_path: v2.clone(),
        replaced_at: 1,
        sha256: Some(sha256_file(&newer_kept).unwrap()),
        placed_sha256: Some(k.clone()),
        placing: Some(sam_core::model::Placing {
            file: kept.clone(),
            sha256: k,
            to: e.source_path.clone(),
            checked: true,
            going_back: true,
        }),
    });
    sam.registry().save(&mut e).unwrap();
    (sam, id, v2, kept, earlier)
}

/// Reviews of the fix for R86: a same-name go back stopped after its record
/// was saved keeps the earlier version only in SAM's copy that the record's
/// mark names. When the app's folder is then gone (renamed, an unplugged
/// drive), the work cannot be finished there, and relocating dropped the
/// mark so that the next run deleted that copy (or refused, leaving only
/// Remove, which deletes it too). Now relocating ends the work: SAM's copy
/// becomes the named way back, and going back reaches the earlier version.
/// A mark whose target is no longer the app's file (a record changed
/// outside SAM) is ended the same way.
#[test]
fn a_version_being_put_in_place_survives_relocating() {
    // The app's folder was renamed.
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, kept, earlier) = stopped_after_saving_a_go_back(tmp.path());
    let renamed = tmp.path().join("Renamed");
    fs::rename(v2.parent().unwrap(), &renamed).unwrap();
    assert!(sam.undo_update(&id).is_err(), "the old folder is gone");
    assert!(sam.update(&id, false).is_err());
    let moved = renamed.join(v2.file_name().unwrap());
    sam.relocate(&id, &moved)
        .unwrap_or_else(|e| panic!("relocating was refused: {e:#}"));
    let b = sam.resolve(&id).unwrap().update_backup.unwrap();
    assert_eq!(b.placing, None);
    assert_eq!(b.file, kept, "SAM's copy is the named way back");
    assert_eq!(fs::read(&kept).unwrap(), earlier, "and it is still there");
    let e = sam
        .undo_update(&id)
        .unwrap_or_else(|e| panic!("going back was refused: {e:#}"));
    assert_eq!(fs::read(&e.source_path).unwrap(), earlier, "reached");

    // A record changed outside SAM points the app elsewhere.
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id, v2, kept, earlier) = stopped_after_saving_a_go_back(tmp.path());
    let elsewhere = tmp.path().join("Elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let copied = elsewhere.join(v2.file_name().unwrap());
    fs::copy(&v2, &copied).unwrap();
    let mut e = sam.resolve(&id).unwrap();
    e.source_path = fs::canonicalize(&copied).unwrap();
    sam.registry().save(&mut e).unwrap();
    let _ = sam.update(&id, false);
    let b = sam.resolve(&id).unwrap().update_backup.unwrap();
    assert_eq!(b.placing, None);
    assert_eq!(b.file, kept, "SAM's copy is the named way back");
    assert_eq!(fs::read(&kept).unwrap(), earlier, "and it is still there");
}
