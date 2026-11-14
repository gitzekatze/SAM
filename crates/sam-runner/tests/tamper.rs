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
    let id = sam.add(&img, &AddOptions { accept: true, launcher: Some(false), ..Default::default() }).unwrap().entry.id;
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
    let mut rec: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    let base = sam.paths.default_extracted_dir();
    rec["extraction"]["root"] = serde_json::json!(base.join("../../../victim"));
    fs::write(&file, rec.to_string()).unwrap();
    assert!(sam.resolve(&id).unwrap().extraction.unwrap().root.starts_with(&base), "the trap: it looks inside");
    sam.remove(&id, false).unwrap();
    assert!(victim.join("precious.txt").exists(), "a folder outside SAM was deleted");
}

/// A record whose id climbs out of SAM's folders cannot be loaded, so no
/// operation can reach the folders that id would name.
#[test]
fn a_record_with_a_climbing_id_reaches_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    let file = sam.paths.app_file(&id);
    let mut rec: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    rec["id"] = serde_json::json!("../../victim");
    fs::write(&file, rec.to_string()).unwrap();
    let victim = sam.paths.app_home("../../victim");
    fs::create_dir_all(&victim).unwrap();
    assert!(sam.registry().list().unwrap().is_empty(), "the changed record is ignored");
    assert!(sam.remove("../../victim", false).is_err());
    assert!(victim.exists());
}
