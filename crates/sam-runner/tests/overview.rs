//! The overview flow: AppImages are listed before they have a sandbox; only
//! "create sandbox" adds SAM's menu entry, optionally hiding an existing
//! unsandboxed one, and removing the sandbox puts that entry back.

use std::fs;

use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

/// AppImages are listed before they have a sandbox; only creating the sandbox adds SAM's menu entry and hides unsandboxed ones, and removing it puts them back.
#[test]
fn found_appimages_get_a_menu_entry_only_with_a_sandbox() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let apps_dir = root.join("Applications");
    fs::create_dir_all(&apps_dir).unwrap();
    let img = apps_dir.join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let img = fs::canonicalize(&img).unwrap();

    let paths = Paths::rooted(&root.join("sam"));
    // An unsandboxed menu entry, as AppImageLauncher would write it.
    fs::create_dir_all(&paths.applications_dir).unwrap();
    let foreign = paths.applications_dir.join("appimagekit_123-Tool.desktop");
    let foreign_text = format!(
        "[Desktop Entry]\nType=Application\nName=Tool\nExec=\"{}\" %U\n",
        img.display()
    );
    fs::write(&foreign, &foreign_text).unwrap();

    let mut sam = Sam::with_paths(paths.clone()).unwrap();
    sam.config.general.scan_directories = vec![apps_dir.display().to_string()];

    // Listed, not sandboxed, nothing installed yet.
    let found = sam.discover().unwrap();
    let d = found
        .iter()
        .find(|d| d.path == img)
        .expect("AppImage discovered");
    assert_eq!(d.name, "Tool");
    assert!(d.sandboxed.is_none());
    assert!(
        d.icon.as_ref().is_some_and(|i| i.exists()),
        "preview icon cached"
    );
    assert_eq!(d.menu_entries.len(), 1, "the unsandboxed entry is reported");
    assert!(
        !paths.data_dir.join("extracted").exists()
            || fs::read_dir(paths.data_dir.join("extracted"))
                .unwrap()
                .next()
                .is_none(),
        "nothing unpacked"
    );

    // A single file added by hand is listed even outside the scan folders.
    let elsewhere = root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let single = elsewhere.join("Single.AppImage");
    build(&single, &FixtureSpec::hello("Single")).unwrap();
    sam.config.general.scan_files = vec![single.display().to_string()];
    let d = sam
        .discover()
        .unwrap()
        .into_iter()
        .find(|d| d.name == "Single")
        .expect("manual file listed");
    assert!(d.manual && d.sandboxed.is_none());
    // The preview shows settings without unpacking anything.
    let pv = sam.preview(&single, None).unwrap();
    assert!(pv["permissions"]["display"]["wayland"].as_bool().unwrap());

    // Create the sandbox and hide the duplicate.
    let added = sam
        .add(
            &img,
            &AddOptions {
                launcher: Some(true),
                hide_duplicates: true,
                ..Default::default()
            },
        )
        .unwrap();
    let id = added.entry.id.clone();
    assert!(
        added
            .entry
            .desktop_entry
            .as_ref()
            .is_some_and(|p| p.exists()),
        "SAM launcher created"
    );
    assert_eq!(added.entry.hidden_entries.len(), 1);
    assert!(fs::read_to_string(&foreign)
        .unwrap()
        .contains("NoDisplay=true"));
    let d = sam
        .discover()
        .unwrap()
        .into_iter()
        .find(|d| d.path == img)
        .unwrap();
    assert_eq!(d.sandboxed.as_deref(), Some(id.as_str()));
    assert!(d.menu_entries.is_empty(), "hidden entry no longer reported");

    // Remove the sandbox: launcher gone, original entry restored exactly.
    sam.remove(&id, false).unwrap();
    assert!(!added.entry.desktop_entry.unwrap().exists());
    assert_eq!(fs::read_to_string(&foreign).unwrap(), foreign_text);
    assert!(sam
        .discover()
        .unwrap()
        .iter()
        .any(|d| d.path == img && d.sandboxed.is_none()));
}
