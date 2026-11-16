//! The unpacking limits hold exactly: SAM's own SquashFS reader unpacks an
//! AppImage that reaches a limit and refuses one that goes one past it, with
//! the error code the window recognizes.
#![allow(clippy::unwrap_used)] // a test: a panic is a failed test

use std::fs;
use std::path::Path;

use sam_intake::extract::builtin_squashfs_entry;
use sam_intake::normalize::Limits;
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};

/// Regular files and their bytes, and all entries, below `dir`.
fn measure(dir: &Path) -> (u64, u64) {
    let (mut entries, mut bytes) = (0, 0);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            entries += 1;
            let t = e.file_type().unwrap();
            if t.is_dir() {
                stack.push(e.path());
            } else if t.is_file() {
                bytes += e.metadata().unwrap().len();
            }
        }
    }
    (entries, bytes)
}

fn unpack(img: &Path, offset: u64, out: &Path, limits: Limits) -> anyhow::Result<()> {
    let _ = fs::remove_dir_all(out);
    builtin_squashfs_entry(img, offset, out, &limits)
}

fn is_limit(r: &anyhow::Result<()>) -> bool {
    r.as_ref()
        .err()
        .is_some_and(|e| sam_core::error::code_of(e) == Some("extraction-limit"))
}

/// The file-count and size limits let an app through that reaches them
/// exactly and stop one entry or one byte more; a time limit of zero stops
/// at once.
#[test]
fn unpacking_stops_exactly_at_its_limits() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("Big.AppImage");
    let mut spec = FixtureSpec::hello("Big");
    for i in 0..20 {
        spec.files.push(FixtureFile {
            path: format!("usr/share/big/part-{i}.bin"),
            data: vec![i as u8; 40_000 + i],
            mode: 0o644,
        });
    }
    build(&img, &spec).unwrap();
    let offset = sam_detect::inspect(&img)
        .unwrap()
        .payload_offset
        .expect("payload offset");
    let out = tmp.path().join("out");
    let roomy = Limits {
        max_files: 100_000,
        max_bytes: 1 << 40,
        max_seconds: 600,
    };
    unpack(&img, offset, &out, roomy).unwrap();
    let (entries, bytes) = measure(&out);
    // The reader also counts the image's root folder.
    let files = entries + 1;
    assert!(bytes > 800_000, "the parts were unpacked: {bytes} bytes");
    // Modes come through: a data file stays non-executable, the entry point
    // stays executable.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(out.join("usr/share/big/part-0.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(out.join("AppRun"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0o111
    );

    assert!(
        unpack(
            &img,
            offset,
            &out,
            Limits {
                max_files: files,
                ..roomy
            }
        )
        .is_ok(),
        "exactly {files} entries are allowed"
    );
    let r = unpack(
        &img,
        offset,
        &out,
        Limits {
            max_files: files - 1,
            ..roomy
        },
    );
    assert!(is_limit(&r), "one entry over the limit is refused: {r:?}");

    assert!(
        unpack(
            &img,
            offset,
            &out,
            Limits {
                max_bytes: bytes,
                ..roomy
            }
        )
        .is_ok(),
        "exactly {bytes} bytes are allowed"
    );
    let r = unpack(
        &img,
        offset,
        &out,
        Limits {
            max_bytes: bytes - 1,
            ..roomy
        },
    );
    assert!(is_limit(&r), "one byte over the limit is refused: {r:?}");

    let r = unpack(
        &img,
        offset,
        &out,
        Limits {
            max_seconds: 0,
            ..roomy
        },
    );
    assert!(is_limit(&r), "a time limit of zero stops at once: {r:?}");
}
