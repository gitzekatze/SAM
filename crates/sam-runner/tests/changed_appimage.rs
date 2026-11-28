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

/// Regression (review B2 S6, R96): adding a moved AppImage read the app's
/// record before copying and checking the file, which can take a while, and
/// saved that copy: a change made meanwhile, such as a switch changed in
/// the window, was undone. The app now follows its file on the record as
/// it is when the check is done.
#[test]
fn following_a_moved_appimage_keeps_a_change_made_while_it_was_checked() {
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
    let before = sam.resolve(&id).unwrap().profile.permissions;
    let elsewhere = tmp.path().join("Elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let moved = elsewhere.join("Renamed.AppImage");
    fs::rename(&img, &moved).unwrap();

    // The window changes a switch while SAM copies and checks the file
    // (SAM reports the start of that step).
    let changed = std::sync::Arc::new(std::sync::Mutex::new(None));
    let (paths, app, slot) = (sam.paths.clone(), id.clone(), changed.clone());
    let progress = sam_runner::progress::ProgressSink::new(move |_| {
        let mut slot = slot.lock().unwrap();
        if slot.is_none() {
            let window = Sam::with_paths(paths.clone()).unwrap();
            let e = window
                .set_permission(&app, "filesystem.music", "ro")
                .unwrap();
            *slot = Some(e.profile.permissions);
        }
    });
    let out = sam
        .add(
            &moved,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                progress,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(out.relocated);
    let changed = changed.lock().unwrap().clone().expect("the switch changed");
    assert_ne!(changed, before, "the switch changed something");
    assert_eq!(out.entry.profile.permissions, changed);
    assert_eq!(sam.resolve(&id).unwrap().profile.permissions, changed);
}

/// Regression (review B2 S6, R96): "keep my data" recorded the file last
/// seen as the owner of the kept data. After the change check saw a
/// swapped file, that was the swapped one: the real file, added again, was
/// refused its data (and a file made to match the app's id could take it).
/// The owner is now the file SAM unpacked.
#[test]
fn kept_data_goes_back_to_the_unpacked_file_after_a_swap_was_seen() {
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
    let real = tmp.path().join("Real.AppImage.copy");
    fs::copy(&img, &real).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = add_tool(&sam, &img).entry.id;
    let home = sam.paths.app_home(&id);
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("settings.ini"), "mine").unwrap();

    // Another app swaps the file; the change check sees it.
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "another app's choice".into();
    build(&img, &spec).unwrap();
    sam.refresh(Some(&id), true).unwrap();
    assert_eq!(sam.resolve(&id).unwrap().state, AppState::Stale);
    sam.remove(&id, true).unwrap();

    // The real file comes back and gets its id and its data.
    fs::remove_file(&img).unwrap();
    fs::copy(&real, &img).unwrap();
    let out = add_tool(&sam, &img);
    assert_eq!(out.entry.id, id, "the real file gets its data back");
    assert_eq!(
        fs::read_to_string(sam.paths.app_home(&id).join("settings.ini")).unwrap(),
        "mine"
    );
}

fn bwrap_or_skip() -> bool {
    if sam_runner::doctor::bwrap_functional(&HostInfo::probe()).is_err() {
        sam_runner::contracts::skip(
            "bubblewrap is not functional here (SAM unpacks inside a sandbox)",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        return false;
    }
    true
}

/// When SAM cannot save the "look at it first" mark of new content, it does
/// not unpack that content: a SAM stopped after the unpack would otherwise
/// leave it unpacked and unmarked. Here every save of the app's record
/// fails (a folder sits at the name of the record's temporary file), so
/// "Unpack Again" stops before it unpacks, says so, and the app keeps the
/// unpacked copy and the record it had. A failure before the unpack (here:
/// the unpack folder cannot be made) leaves no mark for content that was
/// never unpacked. Once saving works again, "Unpack Again" unpacks and marks
/// the new content.
#[test]
fn new_content_is_not_unpacked_when_its_mark_cannot_be_saved() {
    use std::os::unix::fs::MetadataExt;
    if !bwrap_or_skip() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let paths = Paths::rooted(&tmp.path().join("sam"));
    let mut sam = Sam::with_paths(paths.clone()).unwrap();
    let id = add_tool(&sam, &img).entry.id;
    let appdir = sam.resolve(&id).unwrap().extraction.unwrap().appdir;
    let inode = fs::metadata(&appdir).unwrap().ino();
    let record = fs::read(paths.app_file(&id)).unwrap();
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "a different file under the same name".into();
    build(&img, &spec).unwrap();

    // The unpack cannot start: no mark for content that was not unpacked.
    let location = sam.config.extraction.location.clone();
    let not_a_folder = tmp.path().join("not-a-folder");
    fs::write(&not_a_folder, "a file").unwrap();
    sam.config.extraction.location = not_a_folder.join("unpacked").display().to_string();
    sam.reextract(&id, false)
        .expect_err("the unpack folder could not be made");
    assert!(
        !sam.resolve(&id).unwrap().content_changed_outside,
        "a mark was saved for an unpack that never started"
    );
    assert_eq!(fs::metadata(&appdir).unwrap().ino(), inode);
    sam.config.extraction.location = location;

    let blocker = paths
        .apps_dir()
        .join(format!(".{id}.json.tmp-{}", std::process::id()));
    fs::create_dir(&blocker).unwrap();
    let err = sam
        .reextract(&id, false)
        .expect_err("the mark could not be saved");
    assert_eq!(
        fs::metadata(&appdir).unwrap().ino(),
        inode,
        "the new content was unpacked although its mark was not saved"
    );
    assert_eq!(
        fs::read(paths.app_file(&id)).unwrap(),
        record,
        "the record is unchanged"
    );
    let msg = format!("{err:#}");
    assert!(
        msg.contains("could not first save in the app's record")
            && msg.contains("so nothing was unpacked")
            && msg.contains(&blocker.display().to_string()),
        "the error names the mark save and its cause: {msg}"
    );

    fs::remove_dir(&blocker).unwrap();
    let e = sam.reextract(&id, false).unwrap();
    assert_ne!(fs::metadata(&appdir).unwrap().ino(), inode, "unpacked now");
    assert!(e.content_changed_outside, "the new content is marked");
}

/// An app whose first unpack failed (for example without consent for the
/// fallback, or without the DwarFS tool) has nothing unpacked, so the file it was
/// added with is what a later "Unpack Again" compares with. The change
/// check, or relocate, recorded a swapped file's checksum in its place, and
/// "Unpack Again" then took the swapped file for the added one and unpacked
/// it unmarked, with the permissions granted for the added file. Such an
/// app now keeps the added file's checksum, so the first unpack of other
/// content is marked; the same file is still unpacked without a mark.
#[test]
fn a_swapped_appimage_of_a_never_unpacked_app_is_marked_when_it_is_unpacked() {
    if !bwrap_or_skip() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = add_tool(&sam, &img).entry.id;
    // Nothing unpacked yet, as after a first unpack that failed.
    let never_unpacked = || {
        sam.registry()
            .update(&id, |e| e.extraction = None)
            .unwrap()
            .expect("the app's record");
    };

    // The file it was added with: nothing to look at.
    never_unpacked();
    sam.refresh(Some(&id), true).unwrap();
    let e = sam.reextract(&id, false).unwrap();
    assert!(!e.content_changed_outside, "the added file is not marked");

    // Another file in its place, seen by the change check first.
    never_unpacked();
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "a different file under the same name".into();
    build(&img, &spec).unwrap();
    let seen = sam.refresh(Some(&id), true).unwrap();
    assert_eq!(seen[0].status, "stale", "the change check saw the swap");
    let e = sam.reextract(&id, false).unwrap();
    assert!(
        e.content_changed_outside,
        "the swapped file is marked after the change check"
    );
    assert!(!preflight(&e).0.is_empty(), "a start is refused");

    // The same through relocate: the app pointed at another, different file.
    sam.mark_reviewed(&id).unwrap();
    never_unpacked();
    let other = tmp.path().join("Other.AppImage");
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "yet another file".into();
    build(&other, &spec).unwrap();
    sam.relocate(&id, &other).unwrap();
    let e = sam.reextract(&id, false).unwrap();
    assert!(e.content_changed_outside, "marked after relocate too");
}

/// An app whose first unpack failed is not updated: nothing SAM unpacked
/// tells whether the file at its place is the one the person added, and a
/// record an earlier SAM saved may name a swapped file there, whose update
/// information would then decide what runs with this app's permissions.
#[test]
fn a_never_unpacked_app_is_not_updated() {
    if !bwrap_or_skip() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = add_tool(&sam, &img).entry.id;
    sam.registry()
        .update(&id, |e| e.extraction = None)
        .unwrap()
        .expect("the app's record");
    let err = sam
        .update(&id, false)
        .expect_err("a never-unpacked app was updated");
    assert!(
        format!("{err:#}").contains("has not unpacked Tool yet, so it does not update it"),
        "{err:#}"
    );
}
