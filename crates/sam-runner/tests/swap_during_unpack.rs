//! Regression (audit I-F6): SAM checksummed the AppImage, checked its
//! signature and then opened it again to unpack it. Another program with
//! write access to its folder could swap the file in between: SAM then
//! recorded the checksum of one file and unpacked another, so "Unpack
//! Again" gave the other file's program the app's permissions without the
//! mark a swapped AppImage gets. Now SAM copies the file into its own
//! folder once and does everything from that copy. Here the unpacking tool
//! itself (a stand-in for `dwarfsextract`) swaps the file the moment it
//! starts, the latest point a swap could come: what is unpacked is still
//! what SAM checked and recorded, when adding and when unpacking again.
//!
//! One test in this file: it sets `PATH` for the stand-in.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sam_core::Paths;
use sam_runner::ops::{AddOptions, Sam};

/// An AppImage with a DwarFS image (only its header) followed by `payload`:
/// a 64-byte ELF header with the AppImage marker that ends right there.
fn appimage(payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 64];
    d[..4].copy_from_slice(b"\x7fELF");
    d[4] = 2; // 64-bit
    d[5] = 1; // little-endian
    d[6] = 1;
    d[8..11].copy_from_slice(b"AI\x02");
    d[16] = 2; // an executable
    let machine: u16 = match std::env::consts::ARCH {
        "aarch64" => 0xB7,
        _ => 0x3E,
    };
    d[18..20].copy_from_slice(&machine.to_le_bytes());
    d[0x28..0x30].copy_from_slice(&64u64.to_le_bytes()); // no section headers after it
    d.extend(b"DWARFS\x02\x05");
    d.extend(payload);
    d
}

/// The SHA-256 of `data`, as SAM records it.
fn hex(dir: &Path, data: &[u8]) -> String {
    let f = dir.join("to-hash");
    fs::write(&f, data).unwrap();
    sam_intake::fingerprint::sha256_file(&f).unwrap()
}

#[test]
fn what_is_unpacked_is_what_sam_checked_even_if_the_file_is_swapped() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let good = appimage(b"payload: the app SAM checked\n");
    let evil = appimage(b"payload: another program's file\n");
    let img = d.join("Tool.AppImage");
    fs::write(&img, &good).unwrap();
    fs::set_permissions(&img, fs::Permissions::from_mode(0o755)).unwrap();
    let swapped_in = d.join("evil");
    fs::write(&swapped_in, &evil).unwrap();
    let arm = d.join("swap-now");

    // The unpacking tool: when armed, another program swaps the AppImage
    // first; then it unpacks whatever file SAM gave it.
    let bin = d.join("bin");
    fs::create_dir(&bin).unwrap();
    let tool = bin.join("dwarfsextract");
    fs::write(
        &tool,
        format!(
            "#!/bin/sh\n\
             while [ $# -gt 0 ]; do case $1 in -i) src=$2;; -o) dst=$2;; esac; shift; done\n\
             if [ -e '{arm}' ]; then rm '{arm}'; cat '{evil}' > '{img}'; fi\n\
             mkdir -p \"$dst\"\n\
             printf '#!/bin/sh\\n' > \"$dst/AppRun\" && chmod 755 \"$dst/AppRun\"\n\
             printf '[Desktop Entry]\\nType=Application\\nName=Tool\\nExec=AppRun\\n' > \"$dst/tool.desktop\"\n\
             tail -c +73 \"$src\" > \"$dst/payload\"\n",
            arm = arm.display(),
            evil = swapped_in.display(),
            img = img.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{path}", bin.display()));
    // The stand-in belongs to the user: SAM runs it only from this folder.
    std::env::set_var("SAM_TRUST_TOOLS_IN", &bin);

    let sam = Sam::with_paths(Paths::rooted(&d.join("sam"))).unwrap();
    // The checksum of the AppImage whose payload was unpacked.
    let unpacked_from = |e: &sam_core::AppEntry| {
        let appdir = &e.extraction.as_ref().expect("unpacked").appdir;
        let payload = fs::read(appdir.join("payload")).unwrap();
        hex(d, &appimage(&payload))
    };

    // 1. Swapped while it is added.
    fs::write(&arm, "").unwrap();
    let added = sam
        .add(
            &img,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry;
    assert!(!arm.exists(), "the swap happened");
    assert_eq!(
        unpacked_from(&added),
        added.source.sha256,
        "adding recorded one file and unpacked another"
    );
    assert_eq!(added.source.sha256, hex(d, &good));

    // 2. Swapped while it is unpacked again: what the earlier add unpacked
    //    was the file SAM checked, so put that back first.
    fs::write(&img, &good).unwrap();
    let id = added.id;
    let again = sam.reextract(&id, false).unwrap();
    assert!(!again.content_changed_outside);
    fs::write(&arm, "").unwrap();
    let e = sam.reextract(&id, false).unwrap();
    assert!(!arm.exists(), "the swap happened");
    let unpacked = unpacked_from(&e);
    assert_eq!(
        unpacked,
        e.extraction.as_ref().unwrap().source.sha256,
        "unpacking again recorded one file and unpacked another"
    );
    assert!(
        unpacked == hex(d, &good) || e.content_changed_outside,
        "another program's file got the app's permissions unmarked"
    );
    assert_eq!(fs::read(&img).unwrap(), evil, "the folder holds the swapped file");
}
