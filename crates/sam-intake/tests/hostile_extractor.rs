//! An unpacking tool tricked by a crafted AppImage (a bug in a SquashFS or
//! DwarFS parser) runs inside SAM's unpack sandbox. Regression (audit I-F2,
//! top-rule finding F-B): that sandbox could write the app's whole folder,
//! so the tool planted links where SAM writes afterwards, outside any
//! sandbox (`metadata.json` → `~/.bashrc`, `desktop` → autostart). Now only
//! a fresh box for the unpacked files is writable.
//!
//! Needs a working Bubblewrap; with SAM_REQUIRE_SANDBOX=1 (CI) a missing one
//! fails the test instead of skipping it.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

use std::fs;
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

#[test]
fn a_hostile_unpacking_tool_cannot_plant_links_in_sams_app_folder() {
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
    let victim = d.join("victim.txt");
    fs::write(&victim, "the person's file").unwrap();
    let outside = d.join("autostart");
    fs::create_dir(&outside).unwrap();

    // The "unpacking tool": plants links one and two folders above its
    // output (where SAM's app folder was and is), then unpacks a minimal
    // app as a real tool would.
    let bin = d.join("bin");
    fs::create_dir(&bin).unwrap();
    let tool = bin.join("dwarfsextract");
    fs::write(
        &tool,
        format!(
            "#!/bin/sh\n\
             while [ $# -gt 0 ]; do [ \"$1\" = -o ] && dst=$2; shift; done\n\
             for root in \"$(dirname \"$dst\")\" \"$(dirname \"$(dirname \"$dst\")\")\"; do\n\
               ln -s {victim} \"$root/metadata.json\" 2>/dev/null\n\
               ln -s {outside} \"$root/desktop\" 2>/dev/null\n\
               ln -s {victim} \"$root/extraction.log\" 2>/dev/null\n\
             done\n\
             mkdir -p \"$dst\" && printf '#!/bin/sh\\n' > \"$dst/AppRun\" && chmod 755 \"$dst/AppRun\"\n",
            victim = victim.display(),
            outside = outside.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{path}", bin.display()));
    // The stand-in belongs to the user: SAM runs it only from this folder.
    std::env::set_var("SAM_TRUST_TOOLS_IN", &bin);

    let source = d.join("App.AppImage");
    fs::write(&source, vec![0u8; 4096]).unwrap();
    let info = AppImageInfo {
        path: source.clone(),
        size: 4096,
        is_elf: true,
        magic: true,
        kind: AppImageType::Type2,
        payload: PayloadFormat::Dwarfs,
        payload_offset: Some(0),
        payload_size: None,
        compression: None,
        arch: Some("x86_64".into()),
        notes: vec![],
    };
    let root = d.join("extracted").join("appimage-app-1234");
    let iso = Isolation {
        bwrap,
        self_exe: PathBuf::from("/usr/bin/true"),
        system: sam_sandbox::helper_system_args(&sam_core::HostInfo::probe()),
        filter: None,
    };
    let mut log = Vec::new();
    let out = extract(
        &ExtractRequest {
            source: &source,
            info: &info,
            root: &root,
            limits: Limits::default(),
            allow_fallback: false,
            isolation: Some(iso),
        },
        &mut log,
    )
    .unwrap_or_else(|e| panic!("{e:#}\n{}", String::from_utf8_lossy(&log)));
    assert!(out.appdir.join("AppRun").is_file(), "the app was unpacked");

    for name in ["metadata.json", "desktop", "extraction.log"] {
        let p = root.join(name);
        assert!(
            fs::symlink_metadata(&p).is_err(),
            "{name}: the tool could write into SAM's app folder"
        );
    }
    assert!(
        fs::read_dir(&root)
            .unwrap()
            .all(|e| e.unwrap().file_name() == "AppDir"),
        "only the unpacked app is left: {:?}",
        fs::read_dir(&root).unwrap().collect::<Vec<_>>()
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), "the person's file");
    assert!(empty(&outside));
}

fn empty(dir: &Path) -> bool {
    fs::read_dir(dir).unwrap().next().is_none()
}
