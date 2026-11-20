//! An AppImage whose image holds an entry named `..` cannot make SAM write
//! outside the folder it unpacks into (audit B20; verification audit
//! 2026-11-19: only a unit test of the path check showed this). No tool
//! writes such an image, so the test makes one by hand, as an attacker
//! would: a normal SquashFS image with its metadata left uncompressed, in
//! which one folder's name is changed to `..`. Three locks keep the files
//! inside: the reader SAM uses (backhand) refuses the whole image, so does
//! `unsquashfs`, and SAM's own path check would skip the entry (its unit
//! test, `paths_climbing_out_of_the_image_are_refused`). Without the
//! person's consent SAM does not let the AppImage unpack itself, so the
//! image is refused and nothing is written anywhere. Should a reader ever
//! accept such a name, this test fails and shows what happened.
//!
//! Needs mksquashfs (squashfs-tools); a missing one fails the test where
//! the run must prove everything (CI).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use sam_core::AppImageType;
use sam_detect::appimage::{AppImageInfo, PayloadFormat};
use sam_intake::extract::{extract, ExtractRequest};
use sam_intake::normalize::Limits;

/// Every file named `name` below `dir`.
fn find(dir: &Path, name: &str, out: &mut Vec<std::path::PathBuf>) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            find(&p, name, out);
        } else if e.file_name() == name {
            out.push(p);
        }
    }
}

/// Whether `dir` exists and holds anything.
fn out_dir_has_files(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|mut d| d.next().is_some())
}

/// A SquashFS image of `tree` whose folder `Zq` is renamed `..`.
fn image_with_a_climbing_folder(tree: &Path, dest: &Path) {
    let st = Command::new("mksquashfs")
        .arg(tree)
        .arg(dest)
        // Uncompressed metadata, so the name can be changed in place.
        .args([
            "-noI",
            "-noD",
            "-noF",
            "-noX",
            "-all-root",
            "-no-progress",
            "-quiet",
        ])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "mksquashfs made the image");
    let mut data = fs::read(dest).unwrap();
    // The superblock names where the folder table starts and ends.
    let at = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap()) as usize;
    let (dirs, fragments) = (at(72), at(80));
    let table = &data[dirs..fragments];
    let i = table
        .windows(2)
        .position(|w| w == b"Zq")
        .expect("the folder name is in the folder table");
    assert_eq!(
        table.windows(2).filter(|w| *w == b"Zq").count(),
        1,
        "the name appears once"
    );
    data[dirs + i..dirs + i + 2].copy_from_slice(b"..");
    fs::write(dest, data).unwrap();
}

#[test]
fn an_entry_named_dot_dot_writes_nothing_outside_the_app() {
    if sam_core::util::which("mksquashfs").is_none() {
        assert!(
            std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
            "SAM_REQUIRE_SANDBOX=1, but mksquashfs (squashfs-tools) is not installed"
        );
        eprintln!("skipped: mksquashfs (squashfs-tools) is not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let tree = d.join("tree");
    fs::create_dir_all(tree.join("Zq")).unwrap();
    fs::write(tree.join("AppRun"), "#!/bin/sh\n").unwrap();
    fs::write(tree.join("Zq/escaped.txt"), "written outside the app").unwrap();
    let source = d.join("Climb.AppImage");
    image_with_a_climbing_folder(&tree, &source);
    fs::remove_dir_all(&tree).unwrap();
    let size = fs::metadata(&source).unwrap().len();
    let info = AppImageInfo {
        path: source.clone(),
        size,
        is_elf: true,
        magic: true,
        kind: AppImageType::Type2,
        payload: PayloadFormat::Squashfs,
        payload_offset: Some(0),
        payload_size: None,
        compression: None,
        arch: Some("x86_64".into()),
        notes: vec![],
    };
    // Deep enough that a climb of one or two levels stays inside `d`.
    let root = d.join("data/extracted/appimage-climb-1234");
    let mut log = Vec::new();
    let result = extract(
        &ExtractRequest {
            source: &source,
            info: &info,
            root: &root,
            limits: Limits::default(),
            allow_fallback: false,
            isolation: None,
        },
        &mut log,
    );
    let log = String::from_utf8_lossy(&log);
    let mut found = Vec::new();
    find(d, "escaped.txt", &mut found);
    assert!(
        found.is_empty(),
        "nothing written for the `..` entry: {found:?}\n{log}"
    );
    let err = result
        .err()
        .unwrap_or_else(|| panic!("the image is refused:\n{log}"));
    assert!(
        log.contains("builtin-squashfs failed") && log.contains("unsquashfs"),
        "both readers refused it: {err:#}\n{log}"
    );
    assert!(
        !out_dir_has_files(&root.join("AppDir")),
        "no half-unpacked app is left:\n{log}"
    );
}
