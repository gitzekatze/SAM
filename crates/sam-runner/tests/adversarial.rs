//! Attacks from the 2026-11-07 audit, as regression tests: a sandboxed app
//! or a hostile AppImage must not be able to steer SAM through text it
//! controls (stderr, desktop-file metadata, file names) or crash it with
//! malformed input.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;

use sam_core::permissions::PermissionSet;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// SAM's own check (it also mounts /proc, which fails in some containers).
fn bwrap_works() -> bool {
    sam_runner::doctor::bwrap_functional(&HostInfo::probe()).is_ok()
}

/// H1: an app printing a fake Bubblewrap error is not a sandbox failure.
#[test]
fn fake_bwrap_error_is_not_a_sandbox_failure() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Liar.AppImage");
    let mut spec = FixtureSpec::hello("Liar");
    spec.apprun = "#!/bin/sh\necho \"bwrap: Can't mount proc on /newroot/proc: Operation not permitted\" >&2\nexit 1\n".into();
    build(&img, &spec).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let mut e = sam
        .add(
            &img,
            &AddOptions {
                launcher: Some(false),
                accept: true,
                ..Default::default()
            },
        )
        .unwrap()
        .entry;
    let rec = run(
        &mut e,
        &LaunchOptions {
            quiet: true,
            ..Default::default()
        },
        &sam.config,
        &sam.paths,
        &sam_runner::testenv::test_host(HostInfo::probe()),
    )
    .unwrap();
    assert!(
        !rec.setup_failed,
        "the sandbox was built; the error text came from the app"
    );
    assert!(!rec.sandbox_failure, "{}", rec.summary);
    if sam_runner::find_helper().is_some() {
        assert!(
            rec.enforcement
                .as_deref()
                .is_some_and(|s| s.contains("seccomp")),
            "helper reported what it enforced: {:?}",
            rec.enforcement
        );
    }
}

/// H2/M4: suggestions derived from app output never grant escape-capable
/// services or protected folders, and are always marked as app-derived.
#[test]
fn app_output_cannot_buy_dangerous_grants() {
    let p = PermissionSet::strict_gui();
    let home = sam_core::util::home_dir().display().to_string();
    let output = format!(
        "org.freedesktop.DBus.Error.ServiceUnknown: The name org.freedesktop.systemd1 was not provided\n\
         EACCES: permission denied, open '{home}/.ssh/id_ed25519'\n"
    );
    let found = sam_runner::repair::analyze(&output, &p, None);
    assert!(!found.is_empty());
    for s in &found {
        assert!(s.from_app_output);
        assert!(
            matches!(s.action, sam_core::FixAction::None),
            "refused, not offered: {s:?}"
        );
    }
}

/// H3: markup in an AppImage's name or comment is neutralized before it is
/// stored or shown.
#[test]
fn markup_in_metadata_is_neutralized() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Evil.AppImage");
    build(
        &img,
        &FixtureSpec::hello("<b>Safe</b><img src=\"http://example.invalid/t.png\">"),
    )
    .unwrap();
    let p = sam_intake::peek::peek(&img).unwrap();
    assert!(
        !p.metadata.name.contains('<') && !p.metadata.name.contains('>'),
        "{}",
        p.metadata.name
    );
    assert!(!p.metadata.comment.contains('<'));
}

/// M1: a launcher never registers URL schemes, directories or executables.
#[test]
fn launcher_drops_hijack_mime_types() {
    let mut e = sam_core::AppEntry {
        id: "appimage-x-1".into(),
        ..Default::default()
    };
    e.metadata.mime_types = vec![
        "x-scheme-handler/https".into(),
        "inode/directory".into(),
        "image/png".into(),
    ];
    let text = sam_intake::desktop::launcher_contents(&e, "sam-jail-run");
    assert!(text.contains("MimeType=image/png;"), "{text}");
    assert!(!text.contains("x-scheme-handler") && !text.contains("inode/"));
}

/// Robustness: malformed desktop files and files that only look like
/// AppImages must not crash the parsers (simple deterministic fuzzing).
#[test]
fn parsers_survive_garbage() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let tmp = tempfile::tempdir().unwrap();
    for round in 0..200 {
        let len = (next() % 4096) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
        if round % 3 == 0 {
            bytes.splice(0..0, b"[Desktop Entry]\nName=".iter().copied());
        }
        let text = String::from_utf8_lossy(&bytes);
        let _ = sam_intake::metadata::metadata_from_desktop(&text, "x.desktop");
        // An ELF-ish header with AppImage magic and a random tail.
        let mut fake = b"\x7fELF\x02\x01\x01\x00AI\x02".to_vec();
        fake.extend_from_slice(&bytes);
        let path = tmp.path().join(format!("f{round}.AppImage"));
        fs::write(&path, &fake).unwrap();
        let _ = sam_intake::peek::peek(&path);
        let _ = sam_detect::inspect(&path);
    }
}

/// B27: a hostile AppImage cannot add lines to the menu entry SAM writes
/// for it. Its desktop file names itself with escaped line breaks
/// (`\n`, which the desktop-file format turns into real ones), followed by
/// an `Exec=` of its own and `Terminal=true`. SAM's entry still starts
/// only SAM's launcher (verification audit 2026-11-19: only a unit test of
/// the text writer showed this). Two layers keep it so: reading the
/// AppImage drops control characters from its texts (`display_safe`), and
/// writing the entry escapes line breaks again; this test passes while
/// either one holds.
#[test]
fn a_hostile_name_adds_no_line_to_sams_menu_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Menu.AppImage");
    let mut spec = FixtureSpec::hello("Menu");
    let evil = r"\nExec=/tmp/evil %F\nTerminal=true\nX-Evil=1";
    spec.name = format!("Menu{evil}");
    spec.comment = format!("A menu entry{evil}");
    build(&img, &spec).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let added = sam
        .add(
            &img,
            &AddOptions {
                launcher: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    let entry = added.entry.desktop_entry.as_ref().expect("a menu entry");
    let text = fs::read_to_string(entry).unwrap();
    let exec: Vec<&str> = text.lines().filter(|l| l.starts_with("Exec=")).collect();
    assert_eq!(exec.len(), 1, "{text}");
    assert!(
        exec[0].contains(&format!("--app-id {}", added.entry.id)),
        "the one Exec line starts SAM's launcher: {text}"
    );
    assert!(
        !text.contains("/tmp/evil\n") && !text.lines().any(|l| l.starts_with("X-Evil")),
        "{text}"
    );
    assert_eq!(
        text.lines().filter(|l| l.starts_with("Terminal=")).count(),
        1,
        "{text}"
    );
    assert!(text.lines().any(|l| l == "Terminal=false"), "{text}");
}
