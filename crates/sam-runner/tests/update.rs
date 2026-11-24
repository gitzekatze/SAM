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
