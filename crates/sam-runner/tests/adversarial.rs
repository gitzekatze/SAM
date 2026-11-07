//! Attacks from the 2026-11-07 audit, as regression tests: a sandboxed app
//! or a hostile AppImage must not be able to steer SAM through text it
//! controls (stderr, desktop-file metadata, file names) or crash it with
//! malformed input.

use std::fs;
use std::process::Command;

use sam_core::permissions::PermissionSet;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run_auto, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

fn bwrap_works() -> bool {
    Command::new("bwrap")
        .args(["--unshare-user", "--ro-bind", "/", "/", "--", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

/// H1: an app printing a fake Bubblewrap error must not get a weaker backend.
#[test]
fn fake_bwrap_error_does_not_downgrade_the_backend() {
    if !bwrap_works() {
        eprintln!("skipping: bubblewrap is not functional here");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Liar.AppImage");
    let mut spec = FixtureSpec::hello("Liar");
    spec.apprun = "#!/bin/sh\necho \"bwrap: Can't mount proc on /newroot/proc: Operation not permitted\" >&2\nexit 1\n".into();
    build(&img, &spec).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let mut e = sam.add(&img, &AddOptions { launcher: Some(false), accept: true, ..Default::default() }).unwrap().entry;
    let rec = run_auto(&mut e, &LaunchOptions { quiet: true, ..Default::default() }, &sam.config, &sam.paths, &HostInfo::probe()).unwrap();
    assert!(!rec.setup_failed, "the sandbox was built; the error text came from the app");
    assert!(!rec.sandbox_failure, "{}", rec.summary);
    assert_eq!(rec.backend, Some(sam_core::BackendKind::Bubblewrap));
    assert!(sam.resolve(&e.id).unwrap().profile.auto_backend.is_none(), "nothing learned from app output");
    if sam_runner::find_helper().is_some() {
        assert!(rec.enforcement.as_deref().is_some_and(|s| s.contains("seccomp")), "helper reported what it enforced: {:?}", rec.enforcement);
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
        assert!(matches!(s.action, sam_core::FixAction::None), "refused, not offered: {s:?}");
    }
}

/// H3: markup in an AppImage's name or comment is neutralized before it is
/// stored or shown.
#[test]
fn markup_in_metadata_is_neutralized() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Evil.AppImage");
    build(&img, &FixtureSpec::hello("<b>Safe</b><img src=\"http://example.invalid/t.png\">")).unwrap();
    let p = sam_intake::peek::peek(&img).unwrap();
    assert!(!p.metadata.name.contains('<') && !p.metadata.name.contains('>'), "{}", p.metadata.name);
    assert!(!p.metadata.comment.contains('<'));
}

/// M1: a launcher never registers URL schemes, directories or executables.
#[test]
fn launcher_drops_hijack_mime_types() {
    let mut e = sam_core::AppEntry { id: "appimage-x-1".into(), ..Default::default() };
    e.metadata.mime_types = vec!["x-scheme-handler/https".into(), "inode/directory".into(), "image/png".into()];
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
