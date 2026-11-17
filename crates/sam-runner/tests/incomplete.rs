//! A download that broke off is refused with a clear message, before
//! anything is unpacked or registered.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

#[test]
fn a_download_that_broke_off_is_refused_and_nothing_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Half-1.0-x86_64.AppImage");
    build(&img, &FixtureSpec::hello("Half")).unwrap();
    // Cut the image (not the program in front of it) in half, as a download
    // that broke off does.
    let full = std::fs::read(&img).unwrap();
    let start = sam_detect::appimage::inspect(&img)
        .unwrap()
        .payload_offset
        .unwrap() as usize;
    std::fs::write(&img, &full[..start + (full.len() - start) / 2]).unwrap();
    let app = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let err = app
        .add(
            &img,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(
        sam_core::error::code_of(&err),
        Some("appimage-incomplete"),
        "{err:#}"
    );
    assert!(format!("{err:#}").contains("Download it again"));
    assert!(
        app.registry().list().unwrap().is_empty(),
        "nothing registered"
    );
}
