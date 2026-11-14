//! Regression: a damaged SquashFS image (found by the fuzzer in
//! crates/sam-runner/tests/fuzz.rs) made the SquashFS reader panic. Reading
//! names and icons runs in SAM's own process for every AppImage in the
//! searched folders, so one such file stopped the whole list from loading.

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
