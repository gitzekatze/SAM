//! An AppImage file swapped outside SAM (by another app with access to its
//! folder, a script, or a download over it) would keep the old app's
//! permissions after "Unpack Again". It is marked instead, and does not start
//! until the person has looked at it; confirming clears the mark. SAM's own
//! updates are not marked (`reextract_as`, used by update and undo).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

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
