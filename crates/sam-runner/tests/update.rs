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
