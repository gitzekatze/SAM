//! App records changed outside SAM (by a program that is not sandboxed, or
//! by a damaged disk) must never make SAM delete anything outside its own
//! folders. Regression tests for holes found in the test audit.

use std::fs;

use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

fn one_app(root: &std::path::Path) -> (Sam, String) {
    let img = root.join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
    let id = sam
        .add(
            &img,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    (sam, id)
}

/// Regression: the unpack folder in a record was only checked with
/// Path::starts_with, which does not resolve "..": "extracted/../../victim"
/// passed, and removing the sandbox deleted the victim folder.
#[test]
fn removing_a_sandbox_never_deletes_outside_sams_unpack_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    let victim = tmp.path().join("victim");
    fs::create_dir_all(&victim).unwrap();
    fs::write(victim.join("precious.txt"), "keep me").unwrap();
    // Point the record's unpack folder at the victim through "..".
    let file = sam.paths.app_file(&id);
    let mut rec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    let base = sam.paths.default_extracted_dir();
    rec["extraction"]["root"] = serde_json::json!(base.join("../../../victim"));
    fs::write(&file, rec.to_string()).unwrap();
    assert!(
        sam.resolve(&id)
            .unwrap()
            .extraction
            .unwrap()
            .root
            .starts_with(&base),
        "the trap: it looks inside"
    );
    sam.remove(&id, false).unwrap();
    assert!(
        victim.join("precious.txt").exists(),
        "a folder outside SAM was deleted"
    );
}

/// A record whose id climbs out of SAM's folders cannot be loaded, so no
/// operation can reach the folders that id would name.
#[test]
fn a_record_with_a_climbing_id_reaches_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    let file = sam.paths.app_file(&id);
    let mut rec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    rec["id"] = serde_json::json!("../../victim");
    fs::write(&file, rec.to_string()).unwrap();
    let victim = sam.paths.app_home("../../victim");
    fs::create_dir_all(&victim).unwrap();
    assert!(
        sam.registry().list().unwrap().is_empty(),
        "the changed record is ignored"
    );
    assert!(sam.remove("../../victim", false).is_err());
    assert!(victim.exists());
}

/// Regression (found in the test audit): "go back to the earlier version"
/// moved the file a record named as the backup, wherever it was. A record
/// changed outside SAM could make SAM move any of the user's files. Only
/// files in SAM's own backup folder are moved now.
#[test]
fn undoing_an_update_never_moves_files_outside_sams_backup_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    let victim = tmp.path().join("id_rsa");
    fs::write(&victim, "secret").unwrap();
    let file = sam.paths.app_file(&id);
    let mut rec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    rec["update_backup"] = serde_json::json!({"file": victim, "original_path": tmp.path().join("stolen"), "replaced_at": 0});
    fs::write(&file, rec.to_string()).unwrap();
    assert!(sam.undo_update(&id).is_err());
    assert!(victim.exists(), "the user's file was moved");
    assert!(!tmp.path().join("stolen").exists());
}

/// An app whose settings were changed outside SAM does not start until the
/// user has confirmed them; changes SAM makes itself never count as such.
#[test]
fn an_app_changed_outside_sam_starts_only_after_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    sam.set_permission(&id, "devices.gpu", "true").unwrap();
    assert!(
        sam_runner::launch::preflight(&sam.resolve(&id).unwrap())
            .0
            .is_empty(),
        "SAM's own change is fine"
    );
    let file = sam.paths.app_file(&id);
    let mut rec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    rec["profile"]["permissions"]["filesystem"]["home"] = true.into();
    fs::write(&file, rec.to_string()).unwrap();
    let errors = sam_runner::launch::preflight(&sam.resolve(&id).unwrap()).0;
    assert!(
        errors
            .iter()
            .any(|e| e.contains("changed outside SAM")
                && e.contains(&format!("sam-jail review {id}"))),
        "{errors:?}"
    );
    sam.mark_reviewed(&id).unwrap();
    assert!(
        sam_runner::launch::preflight(&sam.resolve(&id).unwrap())
            .0
            .is_empty(),
        "after confirming, it starts again"
    );
}
