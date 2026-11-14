//! Changing a permission for several apps at once (the Permissions page,
//! `sam-jail group`), and the user's own presets after the built-in presets
//! were removed. Regression tests for the promises of phase 1.

use std::collections::BTreeMap;
use std::fs;

use sam_core::permissions::{Access, NetworkMode, PermissionSet};
use sam_core::{Paths, Preset};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};
use sam_storage::PresetStore;

/// Three sandboxed apps: a browser (needs the network), a player (needs
/// sound) and a plain tool.
fn three_apps(root: &std::path::Path) -> (Sam, Vec<String>) {
    let dir = root.join("Applications");
    fs::create_dir_all(&dir).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
    let mut ids = Vec::new();
    for (name, cats) in [("Browser", "Network;WebBrowser;"), ("Player", "AudioVideo;Audio;Player;"), ("Tool", "Utility;")] {
        let img = dir.join(format!("{name}.AppImage"));
        build(&img, &FixtureSpec { categories: cats.into(), ..FixtureSpec::hello(name) }).unwrap();
        let out = sam.add(&img, &AddOptions { accept: true, launcher: Some(false), ..Default::default() }).unwrap();
        ids.push(out.entry.id);
    }
    (sam, ids)
}

fn perms(sam: &Sam, id: &str) -> PermissionSet {
    sam.resolve(id).unwrap().profile.permissions
}

#[test]
fn a_dry_run_changes_nothing_and_names_what_would_stop_working() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, ids) = three_apps(tmp.path());
    let before: Vec<PermissionSet> = ids.iter().map(|id| perms(&sam, id)).collect();
    let r = sam.group_change("network.mode", "none", &ids, true).unwrap();
    assert!(!r.applied);
    assert!(r.previous.is_empty(), "a dry run has nothing to undo");
    let after: Vec<PermissionSet> = ids.iter().map(|id| perms(&sam, id)).collect();
    assert_eq!(before, after, "a dry run saves nothing");
    let browser = r.apps.iter().find(|a| a.id == ids[0]).unwrap();
    assert!(browser.changed);
    assert!(browser.check.removes_needed.iter().any(|s| s == "network access"), "{:?}", browser.check);
}

#[test]
fn only_changed_apps_are_saved_and_one_undo_restores_all_of_them() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, ids) = three_apps(tmp.path());
    let before: BTreeMap<String, PermissionSet> = ids.iter().map(|id| (id.clone(), perms(&sam, id))).collect();
    let r = sam.group_change("filesystem.documents", "ro", &ids, false).unwrap();
    assert!(r.applied);
    for id in &ids {
        assert_eq!(perms(&sam, id).filesystem.documents, Access::Ro);
        let was_ro = before[id].filesystem.documents == Access::Ro;
        assert_eq!(r.previous.contains_key(id), !was_ro, "only apps whose value changed can be undone");
    }
    let n = sam.group_restore(r.previous.clone()).unwrap();
    assert_eq!(n, r.previous.len());
    for id in &ids {
        assert_eq!(perms(&sam, id), before[id], "undo restores every changed app completely");
    }
}

#[test]
fn an_invalid_value_or_unknown_app_changes_no_app() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, ids) = three_apps(tmp.path());
    let before: Vec<PermissionSet> = ids.iter().map(|id| perms(&sam, id)).collect();
    assert!(sam.group_change("network.mode", "sideways", &ids, false).is_err());
    let mut with_unknown = ids.clone();
    with_unknown.push("no-such-app".into());
    assert!(sam.group_change("network.mode", "none", &with_unknown, false).is_err());
    let after: Vec<PermissionSet> = ids.iter().map(|id| perms(&sam, id)).collect();
    assert_eq!(before, after, "a failing group change leaves every app as it was");
}

#[test]
fn the_overview_lists_every_sandboxed_app_with_tags_and_states() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, ids) = three_apps(tmp.path());
    let list = sam.permission_overview().unwrap();
    assert_eq!(list.len(), ids.len());
    let browser = list.iter().find(|a| a.summary.id == ids[0]).unwrap();
    assert!(browser.tags.iter().any(|t| t.key == "network.mode"), "{:?}", browser.tags);
    assert!(list.iter().all(|a| !a.running && !a.needs_review && !a.may_not_start));
}

#[test]
fn sam_ships_no_presets_and_old_built_in_names_are_free_for_the_user() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, ids) = three_apps(tmp.path());
    assert!(sam_profile::all_presets(&sam.paths).unwrap().is_empty(), "no built-in presets");
    // "Untrusted Utility" was a built-in name; the user may use it now.
    let mut offline = PermissionSet::strict_gui();
    offline.network.mode = NetworkMode::None;
    let mut p = Preset { name: "Untrusted Utility".into(), permissions: offline, ..Default::default() };
    PresetStore::new(&sam.paths).save(&mut p).unwrap();
    // Applying it to the browser asks first: it removes the network.
    let r = sam.apply_preset(&ids[0], "untrusted utility", false).unwrap();
    assert!(!r.applied && r.check.removes_needed.iter().any(|s| s == "network access"));
    assert_ne!(perms(&sam, &ids[0]).network.mode, NetworkMode::None, "nothing applied without confirmation");
    assert!(sam.apply_preset(&ids[0], "Untrusted Utility", true).unwrap().applied);
    assert_eq!(perms(&sam, &ids[0]).network.mode, NetworkMode::None);
}

#[test]
fn saving_an_apps_settings_as_a_preset_keeps_them_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, ids) = three_apps(tmp.path());
    let p = sam.save_preset_from_app(&ids[1], "Like the player", "").unwrap();
    assert_eq!(p.permissions, perms(&sam, &ids[1]));
    assert_eq!(sam_profile::find_preset(&sam.paths, "like the player").unwrap().unwrap().permissions, p.permissions);
}
