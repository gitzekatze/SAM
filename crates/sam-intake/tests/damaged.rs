//! Regression: a damaged SquashFS image (found by the fuzzer in
//! crates/sam-runner/tests/fuzz.rs) made the SquashFS reader panic. Reading
//! names and icons runs in SAM's own process for every AppImage in the
//! searched folders, so one such file stopped the whole list from loading.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::path::PathBuf;

fn damaged() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/squashfs-reader-panic.AppImage")
}

/// Regression: reading the name and icon of an AppImage whose SquashFS
/// image makes the reader panic gives an error instead of crashing SAM.
#[test]
fn a_damaged_squashfs_image_gives_an_error_instead_of_a_crash() {
    let r = sam_intake::peek::peek(&damaged());
    let err = r.err().expect("a damaged image is refused").to_string();
    assert!(err.contains("damaged"), "{err}");
}

/// When SAM's own readers cannot unpack an AppImage, its own unpacker (code
/// from the AppImage) runs only after the user agreed: without consent the
/// unpacking stops and asks, and nothing of the AppImage runs.
#[test]
fn without_consent_the_appimages_own_unpacker_never_runs() {
    use sam_intake::extract::{extract, ExtractRequest, NeedsFallbackConsent};
    use sam_intake::normalize::Limits;
    let Ok(info) = sam_detect::inspect(&damaged()) else {
        return; // not even recognized: nothing to unpack
    };
    let d = tempfile::tempdir().unwrap();
    let req = ExtractRequest {
        source: &damaged(),
        info: &info,
        root: &d.path().join("x"),
        limits: Limits::default(),
        allow_fallback: false,
        isolation: None,
    };
    let e = extract(&req, &mut Vec::new()).expect_err("a damaged image is not unpacked");
    assert!(
        e.downcast_ref::<NeedsFallbackConsent>().is_some(),
        "asks for consent instead of running the AppImage: {e:#}"
    );
}
