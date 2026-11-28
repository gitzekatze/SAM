//! The app page (`sam-jail evaluate APP`, the window's editor) and
//! `sam-jail info APP` name the incomplete socket limit of a 32-bit app:
//! its syscall filter has a 32-bit part with one gap, as in Flatpak, the
//! old socketcall call. The note follows the settings being
//! looked at, not only the stored ones, and the global filter setting.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use sam_core::permissions::PermissionSet;
use sam_core::{AppEntry, DependencyReport, Paths, Severity};
use sam_runner::ops::Sam;

const NOTE: &str = "socket-limit-32-bit";

/// An app whose start program is `arch`, stored with `perms`.
fn entry(arch: &str, perms: PermissionSet) -> AppEntry {
    let mut e = AppEntry {
        detection: Some(DependencyReport {
            arch: arch.into(),
            entry_is_script: false,
            entry_binary: Some("usr/bin/game".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    e.profile.permissions = perms;
    e
}

/// Settings with the baseline filter on or off and the strict switch off.
fn with_baseline(on: bool) -> PermissionSet {
    let mut p = PermissionSet::strict_gui();
    p.advanced.seccomp_baseline = on;
    p.advanced.seccomp_strict = false;
    p
}

fn codes(w: &[sam_core::Warning]) -> Vec<&str> {
    w.iter().map(|w| w.code.as_str()).collect()
}

/// The app page and `sam-jail info` name the socket note of a 32-bit app
/// exactly when the settings being looked at load the filter's 32-bit part.
#[test]
fn the_app_page_names_the_incomplete_socket_limit_of_a_32_bit_app() {
    // Outside /tmp: SAM's rules treat places there specially.
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let mut sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    sam.config.security.baseline_seccomp = true;
    let host = sam_core::sandbox::sample_context().host;
    // The filter's 32-bit part exists only on x86-64; elsewhere no app
    // gets the note.
    let x86 = cfg!(target_arch = "x86_64");

    // (a) Stored settings with the filter on: the page and `info` name it
    // once, as information.
    let stored = with_baseline(true);
    let e = entry("i686", stored.clone());
    let page = sam.evaluate(&stored, Some(&e), &host).warnings;
    let notes: Vec<_> = page.iter().filter(|w| w.code == NOTE).collect();
    assert_eq!(
        notes.len(),
        usize::from(x86),
        "the app page: {:?}",
        codes(&page)
    );
    if let Some(n) = notes.first() {
        assert_eq!(n.severity, Severity::Info, "{n:?}");
        assert!(n.key.is_none(), "no single switch belongs to it: {n:?}");
    }
    let info = sam.app_warnings(&e, &host);
    assert_eq!(
        info.iter().filter(|w| w.code == NOTE).count(),
        usize::from(x86),
        "sam-jail info: {:?}",
        codes(&info)
    );

    // (b) The page edits the filter off: no note (there is no limit at
    // all then), and the page says the filter is off.
    let edited_off = with_baseline(false);
    let page = sam.evaluate(&edited_off, Some(&e), &host).warnings;
    assert!(
        !codes(&page).contains(&NOTE),
        "the filter switched off on the page: {:?}",
        codes(&page)
    );
    assert!(codes(&page).contains(&"seccomp-off"), "{:?}", codes(&page));

    // (c) The reverse: stored off, switched on on the page.
    let e_off = entry("i686", with_baseline(false));
    let page = sam.evaluate(&stored, Some(&e_off), &host).warnings;
    assert_eq!(
        codes(&page).contains(&NOTE),
        x86,
        "the filter switched on on the page: {:?}",
        codes(&page)
    );

    // (d) The strict switch alone loads the filter with every baseline row.
    let mut strict_only = with_baseline(false);
    strict_only.advanced.seccomp_strict = true;
    let page = sam.evaluate(&strict_only, Some(&e), &host).warnings;
    assert_eq!(
        codes(&page).contains(&NOTE),
        x86,
        "the strict switch alone: {:?}",
        codes(&page)
    );

    // (e) A 64-bit app, and settings looked at without an app: no note.
    let e64 = entry("x86_64", stored.clone());
    let page = sam.evaluate(&stored, Some(&e64), &host).warnings;
    assert!(
        !codes(&page).contains(&NOTE),
        "a 64-bit app: {:?}",
        codes(&page)
    );
    let page = sam.evaluate(&stored, None, &host).warnings;
    assert!(!codes(&page).contains(&NOTE), "no app: {:?}", codes(&page));

    // (f) The filter off for every app (and no strict switch): no note.
    // Last, because it changes the config every case above shares.
    sam.config.security.baseline_seccomp = false;
    let page = sam.evaluate(&stored, Some(&e), &host).warnings;
    assert!(
        !codes(&page).contains(&NOTE),
        "the filter off for every app: {:?}",
        codes(&page)
    );
}
