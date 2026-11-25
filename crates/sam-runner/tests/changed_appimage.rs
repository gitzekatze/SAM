//! An AppImage file swapped outside SAM (by another app with access to its
//! folder, a script, or a download over it) would keep the old app's
//! permissions after "Unpack Again". It is marked instead, and does not start
//! until the person has looked at it; confirming clears the mark. SAM's own
//! updates are not marked (`reextract_as`, used by update and undo).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;

use sam_core::AppState;
use sam_core::{Badge, HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::preflight;
use sam_runner::ops::{AddOptions, Sam};

#[test]
fn a_swapped_appimage_does_not_start_until_it_is_confirmed() {
    if sam_runner::doctor::bwrap_functional(&HostInfo::probe()).is_err() {
        sam_runner::contracts::skip(
            "bubblewrap is not functional here (SAM unpacks inside a sandbox)",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
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

    // The same file unpacked again: nothing to look at.
    let e = sam.reextract(&id, false).unwrap();
    assert!(!e.content_changed_outside);
    assert!(preflight(&e).0.is_empty(), "{:?}", preflight(&e).0);

    // Another file in its place, then "Unpack Again".
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "a different file under the same name".into();
    build(&img, &spec).unwrap();
    let e = sam.reextract(&id, false).unwrap();
    assert!(e.content_changed_outside, "marked");
    assert_eq!(e.badge(), Badge::ChangedOutside);
    let errors = preflight(&e).0;
    assert!(
        errors
            .iter()
            .any(|m| m.contains("replaced by something other than a SAM update")),
        "a start is refused: {errors:?}"
    );
    // The mark is kept when SAM reads the record again, and the record itself
    // is not taken for one changed outside SAM.
    let again = sam.resolve(&id).unwrap();
    assert!(again.content_changed_outside && !again.changed_outside);

    // Confirming (`sam-jail review`, or the button on the app's page) clears it.
    let e = sam.mark_reviewed(&id).unwrap();
    assert!(!e.content_changed_outside);
    assert!(preflight(&e).0.is_empty(), "{:?}", preflight(&e).0);
}

/// Regression (audit U-H1, Part 5): changing any switch cleared the mark of
/// a swapped AppImage file, so it started without the person looking at it.
#[test]
fn a_swapped_appimage_stays_marked_when_a_switch_changes() {
    if sam_runner::doctor::bwrap_functional(&HostInfo::probe()).is_err() {
        sam_runner::contracts::skip(
            "bubblewrap is not functional here (SAM unpacks inside a sandbox)",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
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
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "a different file under the same name".into();
    build(&img, &spec).unwrap();
    assert!(sam.reextract(&id, false).unwrap().content_changed_outside);
    let e = sam.set_permission(&id, "devices.gpu", "true").unwrap();
    assert!(e.content_changed_outside, "a switch is no confirmation");
    assert!(!preflight(&sam.resolve(&id).unwrap()).0.is_empty());
    assert!(!sam.mark_reviewed(&id).unwrap().content_changed_outside);
}

/// Regression (audit U-H2): "Check all AppImages for changes" (or moving
/// the file with relocate) recorded the swapped file's checksum, so the
/// following "Unpack Again" compared the file with itself: the swapped
/// content ran with the old app's permissions, unmarked, and its signature
/// was not checked again. The comparison is now with what was unpacked.
#[test]
fn a_swapped_appimage_is_marked_also_after_the_change_check() {
    if sam_runner::doctor::bwrap_functional(&HostInfo::probe()).is_err() {
        sam_runner::contracts::skip(
            "bubblewrap is not functional here (SAM unpacks inside a sandbox)",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
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
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "a different file under the same name".into();
    build(&img, &spec).unwrap();
    // The change check first, as the window's "Check all AppImages" does.
    sam.refresh(Some(&id), true).unwrap();
    let e = sam.reextract(&id, false).unwrap();
    assert!(
        e.content_changed_outside,
        "still marked after the change check"
    );
    assert!(!preflight(&e).0.is_empty());

    // The same through relocate: the app pointed at another, different file.
    sam.mark_reviewed(&id).unwrap();
    let other = tmp.path().join("Other.AppImage");
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "yet another file".into();
    build(&other, &spec).unwrap();
    sam.relocate(&id, &other).unwrap();
    let e = sam.reextract(&id, false).unwrap();
    assert!(e.content_changed_outside, "marked after relocate too");
}

fn add_tool(sam: &Sam, img: &std::path::Path) -> sam_runner::ops::AddOutcome {
    sam.add(
        img,
        &AddOptions {
            accept: true,
            launcher: Some(false),
            ..Default::default()
        },
    )
    .unwrap()
}

fn unpacked_sha256(sam: &Sam, id: &str) -> String {
    sam.resolve(id)
        .unwrap()
        .extraction
        .expect("unpacked")
        .source
        .sha256
}

/// Regression (review B2 S6, R96): another app swaps an AppImage, the change
/// check records the swapped file as the file last seen, and the app moves
/// the swapped file elsewhere. The window offered it as the app's moved
/// file, and adding it made the swapped content count as what SAM unpacked,
/// which the update check and the update then trusted. A file is now the
/// app's moved file only with the content SAM unpacked; the swapped one
/// becomes an app of its own, and the real file, once back, is followed.
#[test]
fn a_swapped_appimage_moved_elsewhere_is_not_taken_for_the_apps_own_file() {
    if sam_runner::doctor::bwrap_functional(&HostInfo::probe()).is_err() {
        sam_runner::contracts::skip(
            "bubblewrap is not functional here (SAM unpacks inside a sandbox)",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    // The person keeps a copy of the real file.
    let backup = tmp.path().join("Backup");
    fs::create_dir_all(&backup).unwrap();
    fs::copy(&img, backup.join("Tool.AppImage")).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = add_tool(&sam, &img).entry.id;
    let unpacked = unpacked_sha256(&sam, &id);
    let place = sam.resolve(&id).unwrap().source_path;

    // Another app swaps the file; the change check records the swapped one.
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "another app's choice".into();
    build(&img, &spec).unwrap();
    sam.refresh(Some(&id), true).unwrap();
    let seen = sam.resolve(&id).unwrap();
    assert_eq!(seen.state, AppState::Stale);
    assert_ne!(seen.source.sha256, unpacked, "the swapped file was seen");

    // It moves the swapped file elsewhere.
    let elsewhere = tmp.path().join("Elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let swapped = elsewhere.join("Tool.AppImage");
    fs::rename(&img, &swapped).unwrap();
    let found = sam.scan(Some(vec![elsewhere.clone()])).unwrap();
    let item = found
        .iter()
        .find(|i| i.path.file_name() == swapped.file_name())
        .expect("the swapped file is listed");
    assert_eq!(item.moved_from, None, "not offered as the app's moved file");

    // Adding it gives it a sandbox of its own; the app keeps what SAM unpacked.
    let out = add_tool(&sam, &swapped);
    assert!(!out.relocated, "the app did not follow the swapped file");
    assert_ne!(out.entry.id, id, "an app of its own");
    let e = sam.resolve(&id).unwrap();
    assert_eq!(
        unpacked_sha256(&sam, &id),
        unpacked,
        "unpacked checksum kept"
    );
    assert_eq!(e.source_path, place);
    assert_eq!(e.state, AppState::Stale);

    // The real file from the copy: the app follows it and is ready again,
    // because the file is again the one SAM unpacked.
    let out = add_tool(&sam, &backup.join("Tool.AppImage"));
    assert!(out.relocated && !out.created);
    assert_eq!(out.entry.id, id);
    assert_eq!(out.entry.state, AppState::Ready);
    assert_eq!(unpacked_sha256(&sam, &id), unpacked);
}

/// An AppImage moved to another folder and added there is followed, as
/// before: the app keeps its sandbox, its unpacked checksum and its marks.
#[test]
fn a_moved_appimage_added_again_is_followed_with_its_marks() {
    if sam_runner::doctor::bwrap_functional(&HostInfo::probe()).is_err() {
        sam_runner::contracts::skip(
            "bubblewrap is not functional here (SAM unpacks inside a sandbox)",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = add_tool(&sam, &img).entry.id;
    let unpacked = unpacked_sha256(&sam, &id);

    let elsewhere = tmp.path().join("Elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let moved = elsewhere.join("Renamed.AppImage");
    fs::rename(&img, &moved).unwrap();
    sam.refresh(Some(&id), false).unwrap();
    assert_eq!(sam.resolve(&id).unwrap().state, AppState::Missing);
    let found = sam.scan(Some(vec![elsewhere.clone()])).unwrap();
    let item = found
        .iter()
        .find(|i| i.path.file_name() == moved.file_name())
        .expect("the moved file is listed");
    assert_eq!(item.moved_from.as_deref(), Some(id.as_str()));
    let out = add_tool(&sam, &moved);
    assert!(out.relocated && !out.created);
    assert_eq!(out.entry.id, id);
    assert_eq!(out.entry.source_path, fs::canonicalize(&moved).unwrap());
    assert_eq!(out.entry.state, AppState::Ready);
    assert_eq!(unpacked_sha256(&sam, &id), unpacked);

    // A swapped file unpacked again is marked; moving that file keeps the mark.
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "a different file under the same name".into();
    build(&moved, &spec).unwrap();
    assert!(sam.reextract(&id, false).unwrap().content_changed_outside);
    let again = elsewhere.join("Again.AppImage");
    fs::rename(&moved, &again).unwrap();
    let out = add_tool(&sam, &again);
    assert!(out.relocated);
    assert!(out.entry.content_changed_outside, "the mark stays");
    assert!(!preflight(&out.entry).0.is_empty(), "still no start");
}
