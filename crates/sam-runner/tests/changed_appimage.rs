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
