//! An AppImage built for another processor gets no sandbox.

use std::fs;

use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

/// An AppImage for ARM is refused on an x86-64 computer with a sentence
/// that names both processors and what to download instead, and nothing
/// is stored (regression: SAM created a sandbox for an arm64 Neovim and
/// failed only at the start, with "permission denied or wrong format").
#[test]
fn an_appimage_for_another_processor_gets_no_sandbox() {
    if sam_detect::appimage::host_arch() != "x86_64" {
        eprintln!("skipping: the test changes an x86-64 AppImage into an ARM one");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Tool-1.0-aarch64.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    // The ELF machine field (offset 18, little endian): 0xB7 is aarch64.
    let mut data = fs::read(&img).unwrap();
    data[18] = 0xB7;
    data[19] = 0x00;
    fs::write(&img, &data).unwrap();
    assert_eq!(sam_detect::inspect(&img).unwrap().arch.as_deref(), Some("aarch64"));

    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let e = sam.add(&img, &AddOptions { launcher: Some(false), ..Default::default() }).unwrap_err().to_string();
    assert!(e.contains("built for ARM (aarch64) processors") && e.contains("processor is x86-64") && e.contains("Download the x86_64 version"), "{e}");
    assert!(sam.registry().list().unwrap().is_empty(), "nothing is stored");
}
