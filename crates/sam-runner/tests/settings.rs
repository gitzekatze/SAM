//! The user's settings survive SAM's own buttons: compatibility mode, repair
//! steps, "reset to recommendation" and removing a sandbox each do exactly
//! what they promise and can be taken back where SAM says so.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;

use sam_core::permissions::{Access, NetworkMode};
use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

fn one_app(root: &std::path::Path) -> (Sam, String) {
    named_app(root, "Tool")
}

/// An app with its own name, so its id (and runtime folder) differs from
/// the other tests' apps when tests run at the same time.
fn named_app(root: &std::path::Path, name: &str) -> (Sam, String) {
    let dir = root.join("Applications");
    fs::create_dir_all(&dir).unwrap();
    let img = dir.join(format!("{name}.AppImage"));
    build(&img, &FixtureSpec::hello(name)).unwrap();
    let mut sam = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
    sam.config.general.scan_directories = vec![dir.display().to_string()];
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

/// Turning compatibility mode off restores exactly the settings the user had before.
#[test]
fn turning_compatibility_mode_off_restores_exactly_the_settings_from_before() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    sam.set_permission(&id, "filesystem.music", "ro").unwrap();
    let mine = sam.resolve(&id).unwrap().profile.permissions;
    let on = sam.set_compat(&id, true).unwrap();
    assert_ne!(
        on.profile.permissions, mine,
        "compatibility mode widens the settings"
    );
    let off = sam.set_compat(&id, false).unwrap();
    assert_eq!(off.profile.permissions, mine);
    assert!(!off.profile.compatibility_mode);
}

/// Undoing repair steps restores the settings from before the first step.
#[test]
fn undoing_repair_steps_restores_the_settings_from_before_the_first_step() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    let before = sam.resolve(&id).unwrap().profile;
    let steps = sam_runner::repair::ladder(&sam.resolve(&id).unwrap(), &sam.config, &sam.paths);
    assert!(!steps.is_empty(), "the repair ladder offers steps");
    for step in steps.iter().take(2) {
        let e = sam.resolve(&id).unwrap();
        if let Some(s) = sam.find_suggestion(&e, &step.id) {
            let _ = sam.apply_suggestion(&id, &s, true);
        }
    }
    assert_ne!(
        sam.resolve(&id).unwrap().profile.permissions,
        before.permissions,
        "the steps changed something"
    );
    let back = sam.undo_repairs(&id).unwrap();
    assert_eq!(back.profile.permissions, before.permissions);
    assert!(back.repairs_applied.is_empty());
}

/// Undoing repair steps takes back only what the steps changed: a setting
/// the person changed afterwards stays as they set it, also the one a step
/// had changed (audit G-F4: the whole profile from before the first step
/// came back).
#[test]
fn undoing_repair_steps_keeps_what_the_person_changed_since() {
    use sam_core::model::FixAction;
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = named_app(tmp.path(), "Later");
    let e = sam.resolve(&id).unwrap();
    let steps = sam_runner::repair::ladder(&e, &sam.config, &sam.paths);
    let (step, key) = steps
        .iter()
        .find_map(|st| {
            let s = sam.find_suggestion(&e, &st.id)?;
            match &s.action {
                FixAction::Set { key, .. } if key != "filesystem.music" => {
                    Some((s.clone(), key.clone()))
                }
                _ => None,
            }
        })
        .expect("the ladder has a step that sets one permission");
    let before = e.profile.permissions.get_key(&key).unwrap();
    sam.apply_suggestion(&id, &step, true).unwrap();
    // Afterwards the person changes another setting.
    sam.set_permission(&id, "filesystem.music", "ro").unwrap();
    let back = sam.undo_repairs(&id).unwrap();
    assert_eq!(
        back.profile.permissions.get_key(&key).unwrap(),
        before,
        "the step is undone"
    );
    assert_eq!(
        back.profile.permissions.filesystem.music,
        Access::Ro,
        "the later change stays"
    );
    assert!(back.applied_repairs.is_empty() && back.repair_backup.is_none());

    // The person changes the very setting a step changed, to a value of
    // their own: undoing the step leaves it.
    let network = sam_core::model::Suggestion {
        id: "network".into(),
        title: "Network".into(),
        explanation: String::new(),
        action: FixAction::Set {
            key: "network.mode".into(),
            value: "full".into(),
        },
        risk: sam_core::risk::RiskLevel::High,
        from_app_output: false,
    };
    sam.apply_suggestion(&id, &network, true).unwrap();
    sam.set_permission(&id, "network.mode", "localhost")
        .unwrap();
    let back = sam.undo_repairs(&id).unwrap();
    assert_eq!(
        back.profile.permissions.network.mode,
        NetworkMode::Localhost,
        "the person's own value stays"
    );
}

/// "Reset to recommendation" brings back SAM's recommended settings and turns compatibility mode off.
#[test]
fn reset_to_recommendation_brings_back_the_recommended_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    sam.set_permission(&id, "network.mode", "full").unwrap();
    sam.set_permission(&id, "filesystem.documents", "rw")
        .unwrap();
    sam.set_compat(&id, true).unwrap();
    let e = sam.reset_profile(&id).unwrap();
    assert_eq!(e.profile.permissions, e.recommended);
    assert!(!e.profile.compatibility_mode);
    assert_ne!(e.profile.permissions.network.mode, NetworkMode::Full);
    assert_eq!(
        e.profile.permissions.filesystem.documents,
        e.recommended.filesystem.documents
    );
    let _ = Access::None;
}

/// A running app keeps its sandbox: removing it is refused until the app
/// is closed (a launch holds a lock in the app's runtime folder).
#[test]
fn removing_a_sandbox_while_its_app_runs_is_refused() {
    use std::os::fd::AsRawFd;
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = named_app(tmp.path(), "Busy");
    let launch = sam
        .paths
        .runtime_dir(&id)
        .join(format!("l{}-1", std::process::id()));
    fs::create_dir_all(&launch).unwrap();
    let lock = fs::File::create(launch.join("running.lock")).unwrap();
    // SAFETY: `lock` is an open file; flock only takes its descriptor.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let err = sam.remove(&id, false).unwrap_err().to_string();
    assert!(err.contains("is running"), "{err}");
    assert!(sam.resolve(&id).is_ok(), "the sandbox is still there");
    drop(lock);
    let _ = fs::remove_dir_all(sam.paths.runtime_dir(&id));
}

/// `f` once a lock just dropped is free. Another test of this process may
/// fork at that moment; its child holds a copy of the lock until it runs
/// its program (close-on-exec), so `f` gets a second to succeed.
fn soon<T, E: std::fmt::Display>(mut f: impl FnMut() -> Result<T, E>) -> T {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        match f() {
            Ok(v) => return v,
            Err(e) if std::time::Instant::now() >= until => panic!("{e}"),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
}

/// While an app is starting (from its checks until it has ended), its
/// sandbox is not changed: removing it or unpacking it again waits a
/// moment, then is refused and says why, and the sandbox stays (review L2).
#[test]
fn a_sandbox_is_not_changed_while_its_app_is_starting() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = named_app(tmp.path(), "Starting");
    let mut e = sam.resolve(&id).unwrap();
    let start = sam.start_lock(&mut e).unwrap();
    let changes = [
        sam.remove(&id, false).map(drop),
        sam.reextract(&id, false).map(drop),
    ];
    for change in changes {
        let err = change.unwrap_err().to_string();
        assert!(err.contains("is starting or being changed"), "{err}");
    }
    let x = sam.resolve(&id).unwrap().extraction.unwrap();
    assert!(
        x.appdir.join(&x.entry).exists(),
        "the sandbox is still there"
    );
    drop(start);
    sam.remove(&id, false).unwrap();
}

/// While an app's sandbox is being changed, a start is refused at once
/// and says why; the change itself goes on, also a step of it (an update
/// unpacks again), and the app starts once it is done (review L2).
#[test]
fn a_start_is_refused_while_the_sandbox_is_being_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = named_app(tmp.path(), "Changing");
    let change = sam_runner::app_lock::for_change(&sam.paths, &id)
        .unwrap()
        .unwrap();
    let mut e = sam.resolve(&id).unwrap();
    let t = std::time::Instant::now();
    let err = sam.start_lock(&mut e).unwrap_err().to_string();
    assert!(err.contains("is being changed"), "{err}");
    assert!(t.elapsed() < std::time::Duration::from_secs(1), "at once");
    sam.reextract(&id, false).unwrap();
    drop(change);
    soon(|| sam.start_lock(&mut e));
}

/// A start whose unpacked copy is gone (after "Free space") unpacks it
/// again first; while another step changes the sandbox, that is refused at
/// once with the start's message, as the start itself is (review L2).
#[test]
fn unpacking_for_a_start_is_refused_at_once_while_the_sandbox_is_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = named_app(tmp.path(), "Freed");
    sam.free_space(&id).unwrap();
    let (held_tx, held) = std::sync::mpsc::channel::<()>();
    let (done, done_rx) = std::sync::mpsc::channel::<()>();
    let (paths, app) = (sam.paths.clone(), id.clone());
    let changing = std::thread::spawn(move || {
        let _change = sam_runner::app_lock::for_change(&paths, &app)
            .unwrap()
            .unwrap();
        held_tx.send(()).unwrap();
        let _ = done_rx.recv();
    });
    held.recv().unwrap();
    let mut e = sam.resolve(&id).unwrap();
    let t = std::time::Instant::now();
    let err = sam.ensure_unpacked(&mut e).unwrap_err().to_string();
    assert!(err.contains("is being changed"), "{err}");
    assert!(t.elapsed() < std::time::Duration::from_secs(1), "at once");
    done.send(()).unwrap();
    changing.join().unwrap();
    assert!(
        soon(|| sam.ensure_unpacked(&mut e)),
        "unpacked once the change is done"
    );
}

/// A start reads the app's record again once it holds the app: what a
/// change saved after the caller read it (a new unpacked copy marked
/// "look at it first", or the sandbox removed) is what the start checks
/// and runs (review L2: the mark was skipped).
#[test]
fn a_start_sees_what_a_change_saved_before_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = named_app(tmp.path(), "Reread");
    let mut e = sam.resolve(&id).unwrap();
    assert!(!e.content_changed_outside);
    let mut saved = sam.registry().get(&id).unwrap().unwrap();
    saved.content_changed_outside = true;
    sam.registry().save(&mut saved).unwrap();
    let start = sam.start_lock(&mut e).unwrap();
    assert!(e.content_changed_outside, "the start sees the mark");
    drop(start);
    sam.remove(&id, false).unwrap();
    let err = sam.start_lock(&mut e).unwrap_err().to_string();
    assert!(err.contains("no registered app"), "{err}");
}

/// Removing a sandbox with "keep my data" keeps the app's private home; without it, the home is deleted.
#[test]
fn removing_with_keep_my_data_keeps_the_private_home_and_without_deletes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    let home = sam.paths.app_home(&id);
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("settings.ini"), "mine").unwrap();
    sam.remove(&id, true).unwrap();
    assert!(home.join("settings.ini").exists(), "kept with keep my data");

    let (sam2, id2) = one_app(&tmp.path().join("second"));
    let home2 = sam2.paths.app_home(&id2);
    fs::create_dir_all(&home2).unwrap();
    sam2.remove(&id2, false).unwrap();
    assert!(!home2.exists(), "deleted without keep my data");
}

/// The app's icon is copied into SAM's own icon folder, named after the
/// app, and goes with its sandbox; nothing lands in the folder SAM was
/// started in.
#[test]
fn an_apps_icon_is_kept_in_sams_icon_folder_and_goes_with_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = named_app(tmp.path(), "Painter");
    let icon = sam.resolve(&id).unwrap().metadata.icon_path.unwrap();
    assert_eq!(
        icon,
        sam.paths.data_dir.join(format!("icons/sam-{id}.svg")),
        "{}",
        icon.display()
    );
    assert!(icon.is_file());
    let here = std::env::current_dir()
        .unwrap()
        .join(format!("sam-{id}.svg"));
    assert!(!here.exists(), "{}", here.display());
    sam.remove(&id, false).unwrap();
    assert!(!icon.exists(), "removed with the sandbox");
}

/// When a sandboxed app's AppImage is moved to another searched folder, SAM
/// recognizes it by its content and offers to follow it.
#[test]
fn a_moved_appimage_is_recognized_by_its_content() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = one_app(tmp.path());
    let old = sam.resolve(&id).unwrap().source_path;
    let other = tmp.path().join("Elsewhere");
    fs::create_dir_all(&other).unwrap();
    let new = other.join("Renamed.AppImage");
    fs::rename(&old, &new).unwrap();
    let found = sam.scan(Some(vec![other.clone()])).unwrap();
    let item = found
        .iter()
        .find(|i| i.path.file_name() == new.file_name())
        .expect("the moved file is listed");
    assert_eq!(item.moved_from.as_deref(), Some(id.as_str()));
    let e = sam.relocate(&id, &new).unwrap();
    assert_eq!(e.source_path, fs::canonicalize(&new).unwrap());
}

/// A repair step can be switched off on its own: exactly what that step
/// changed goes back, and the other applied steps stay.
#[test]
fn switching_off_one_repair_step_keeps_the_others() {
    let tmp = tempfile::tempdir().unwrap();
    let (sam, id) = named_app(tmp.path(), "Steps");
    let e = sam.resolve(&id).unwrap();
    let steps: Vec<_> = sam_runner::repair::ladder(&e, &sam.config, &sam.paths)
        .into_iter()
        .filter(|s| matches!(s.action, sam_core::FixAction::Set { .. }))
        .take(2)
        .collect();
    assert_eq!(steps.len(), 2, "two setting steps to apply");
    let before = sam.resolve(&id).unwrap().profile.permissions;
    for s in &steps {
        sam.apply_suggestion(&id, s, true).unwrap();
    }
    let both = sam.resolve(&id).unwrap().profile.permissions;
    let e = sam.undo_repair_step(&id, &steps[0].id).unwrap();
    assert_eq!(e.repairs_applied, vec![steps[1].id.clone()]);
    let key = |s: &sam_core::Suggestion| match &s.action {
        sam_core::FixAction::Set { key, .. } => key.clone(),
        _ => unreachable!(),
    };
    let p = &e.profile.permissions;
    assert_eq!(
        p.get_key(&key(&steps[0])).unwrap(),
        before.get_key(&key(&steps[0])).unwrap(),
        "the first step is undone"
    );
    assert_eq!(
        p.get_key(&key(&steps[1])).unwrap(),
        both.get_key(&key(&steps[1])).unwrap(),
        "the second step stays"
    );
    let e = sam.undo_repair_step(&id, &steps[1].id).unwrap();
    assert_eq!(
        e.profile.permissions, before,
        "with every step off, the settings are as before"
    );
    assert!(e.repair_backup.is_none());
}
