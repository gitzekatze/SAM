//! Regression (review 2026-11-23, F1, F5): the unpacking limits held only
//! for SAM's own SquashFS reader. `unsquashfs`, `bsdtar`, `dwarfsextract`
//! and the AppImage's own extractor were checked only after they had
//! finished, and had no memory limit, so a crafted image that SAM's reader
//! cannot read (LZO compression, a DwarFS or ISO image) chose a tool that
//! could fill the disk or the memory first. Here stand-ins play such a tool
//! inside the real unpack sandbox: the kernel limits reach it, and it is
//! stopped as soon as it passes the file or size limit, long before the
//! time limit. SAM's reader running out of the memory it may use stops
//! unpacking too, instead of handing the image to the next tool.
//!
//! Needs a working Bubblewrap; with SAM_REQUIRE_SANDBOX=1 (CI) a missing one
//! fails the test instead of skipping it. One test in this file: it sets
//! `PATH` for the stand-ins.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sam_core::AppImageType;
use sam_detect::appimage::{AppImageInfo, PayloadFormat};
use sam_intake::extract::{extract, ExtractRequest, Isolation};
use sam_intake::normalize::Limits;

fn bwrap_works() -> Option<PathBuf> {
    let bwrap = sam_core::util::which("bwrap")?;
    Command::new(&bwrap)
        .args(["--ro-bind", "/", "/", "true"])
        .status()
        .ok()?
        .success()
        .then_some(bwrap)
}

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Finds the folder `unsquashfs` is told to write (`-d DIR`).
const DEST: &str =
    "while [ $# -gt 0 ]; do [ \"$1\" = -d ] && dst=$2; shift; done\nmkdir -p \"$dst\"";
/// A minimal app, as a real tool leaves it.
const APP: &str = "printf '#!/bin/sh\\n' > \"$dst/AppRun\" && chmod 755 \"$dst/AppRun\"";

#[test]
fn every_unpacking_tool_meets_the_limits_while_it_runs() {
    let Some(bwrap) = bwrap_works() else {
        assert!(
            std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
            "SAM_REQUIRE_SANDBOX=1, but Bubblewrap does not work here"
        );
        eprintln!("skipped: Bubblewrap does not work here");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let bin = d.join("bin");
    fs::create_dir(&bin).unwrap();
    let tool = bin.join("unsquashfs");
    let path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{path}", bin.display()));
    // The stand-ins belong to the user: SAM runs them only from this folder.
    std::env::set_var("SAM_TRUST_TOOLS_IN", &bin);

    let source = d.join("App.AppImage");
    fs::write(&source, vec![0u8; 4096]).unwrap();
    let info = AppImageInfo {
        path: source.clone(),
        size: 4096,
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
    // SAM's own reader cannot read the image (as with LZO), so `unsquashfs`
    // gets it.
    let reader = bin.join("reader");
    script(&reader, "exit 1");
    let iso = Isolation {
        bwrap,
        self_exe: reader.clone(),
        system: sam_sandbox::helper_system_args(&sam_core::HostInfo::probe()),
        filter: None,
    };
    let limits = Limits {
        max_files: 100,
        max_bytes: 8 * 1024 * 1024,
        // Far longer than any of the stops below needs; without them each
        // stand-in would run into this one.
        max_seconds: 120,
        max_memory: 3 * 1024 * 1024 * 1024,
    };
    let mut n = 0;
    let mut unpack = |limits: Limits| {
        n += 1;
        let root = d.join("extracted").join(format!("app-{n}"));
        let mut log = Vec::new();
        let r = extract(
            &ExtractRequest {
                source: &source,
                info: &info,
                root: &root,
                limits,
                allow_fallback: false,
                isolation: Some(iso.clone()),
            },
            &mut log,
        );
        (r, String::from_utf8_lossy(&log).into_owned())
    };

    // 1. The kernel holds the size of each file and the memory for the tool
    //    inside the sandbox.
    script(
        &tool,
        &format!("{DEST}\ncat /proc/self/limits > \"$dst/limits\"\n{APP}"),
    );
    let (r, log) = unpack(limits);
    let out = r.unwrap_or_else(|e| panic!("{e:#}\n{log}"));
    let seen = fs::read_to_string(out.appdir.join("limits")).unwrap();
    let limit = |name: &str| {
        seen.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(name.split(' ').count()))
            .map(str::to_string)
    };
    assert_eq!(
        limit("Max file size").as_deref(),
        Some("8388608"),
        "file size:\n{seen}"
    );
    assert_eq!(
        limit("Max address space").as_deref(),
        Some("3221225472"),
        "memory:\n{seen}"
    );

    // 2. A tool that keeps making files is stopped at the file limit.
    script(
        &tool,
        &format!(
            "{DEST}\ni=0; while [ $i -lt 5000 ]; do : > \"$dst/f$i\"; i=$((i+1)); done\nsleep 600"
        ),
    );
    let (r, log) = unpack(limits);
    let e = format!("{:#}", r.unwrap_err());
    assert!(e.contains("more than 100 files"), "{e}\n{log}");

    // 3. One that keeps writing is stopped at the size limit.
    script(
        &tool,
        &format!(
            "{DEST}\ni=0; while [ $i -lt 40 ]; do head -c 1048576 /dev/zero > \"$dst/part$i\"; i=$((i+1)); done\nsleep 600"
        ),
    );
    let (r, log) = unpack(limits);
    let e = format!("{:#}", r.unwrap_err());
    assert!(e.contains("more than 8.0 MiB unpacked"), "{e}\n{log}");

    // 4. SAM's own reader runs out of the memory it may use (Rust says so,
    //    then aborts): unpacking stops there, the next tool never runs.
    script(
        &reader,
        "echo 'memory allocation of 4294967296 bytes failed' >&2\nkill -ABRT $$",
    );
    script(&tool, &format!("{DEST}\n{APP}"));
    let (r, log) = unpack(limits);
    let e = format!("{:#}", r.unwrap_err());
    assert!(e.contains("of memory"), "{e}\n{log}");
    assert!(!log.contains("trying unsquashfs"), "{log}");
}
