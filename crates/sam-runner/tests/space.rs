//! Disk space: an app's unpacked copy can be deleted ("Free space") and is
//! unpacked again before the next start, with settings kept. A changed or
//! missing AppImage is never unpacked behind the user's back.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;

use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

/// Freeing space deletes the unpacked copy, and unpacking again brings the app back.
#[test]
fn freeing_space_deletes_the_unpacked_copy_and_unpacking_restores_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let img = root.join("Roomy.AppImage");
    build(&img, &FixtureSpec::hello("Roomy")).unwrap();
    let paths = Paths::rooted(&root.join("sam"));
    let sam = Sam::with_paths(paths).unwrap();
    let id = sam
        .add(
            &img,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    sam.set_permission(&id, "network.mode", "full").unwrap();

    let e = sam.resolve(&id).unwrap();
    let before = sam.disk_usage(&e);
    assert!(before.unpacked > 0 && before.can_free, "{before:?}");

    let freed = sam.free_space(&id).unwrap();
    assert_eq!(freed, before.unpacked);
    let mut e = sam.resolve(&id).unwrap();
    assert_eq!(sam.disk_usage(&e).unpacked, 0);

    // Unpacked again (same file), settings kept.
    assert!(sam.ensure_unpacked(&mut e).unwrap(), "unpacked again");
    let x = e.extraction.clone().unwrap();
    assert!(x.appdir.join(&x.entry).exists());
    assert_eq!(
        e.profile.permissions.network.mode.as_str(),
        "full",
        "settings kept"
    );
    assert!(
        !sam.ensure_unpacked(&mut e).unwrap(),
        "nothing to do when present"
    );

    // A missing AppImage: the unpacked copy is the only one and stays.
    fs::rename(&img, root.join("moved.AppImage")).unwrap();
    assert!(sam.free_space(&id).is_err());
    assert!(sam.disk_usage(&sam.resolve(&id).unwrap()).unpacked > 0);
}
