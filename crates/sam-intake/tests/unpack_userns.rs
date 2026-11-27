//! Review K-2: nothing inside SAM's unpack sandboxes may make a user
//! namespace of its own. One gives the program inside full rights over a
//! fresh network namespace, and through it the kernel's netfilter, the
//! usual way into kernel bugs. The AppImage's own extractor (run after the
//! person agreed) and an unpacking tool tricked by a crafted image both run
//! untrusted code there, and the sandbox let them.
//!
//! The syscall filter is left out on purpose: it refuses this too, and the
//! test shows the sandbox holds by itself.
//!
//! Needs a working Bubblewrap and util-linux's `unshare`; with
//! SAM_REQUIRE_SANDBOX=1 (CI) a missing one fails the test instead of
//! skipping it.
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

/// Shell lines that try to make a user namespace and write "made" or
/// "refused" to the file `$where`.
const TRY_USERNS: &str = "if unshare --user true 2>/dev/null; then echo made > \"$where\"; \
                          else echo refused > \"$where\"; fi";

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn nothing_in_the_unpack_sandbox_can_make_a_user_namespace() {
    let unshare = sam_core::util::which("unshare");
    let Some(bwrap) = bwrap_works().filter(|_| unshare.is_some()) else {
        assert!(
            std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
            "SAM_REQUIRE_SANDBOX=1, but Bubblewrap or unshare does not work here"
        );
        eprintln!("skipped: Bubblewrap or unshare does not work here");
        return;
    };
    // The control: outside SAM's sandbox this computer lets an ordinary
    // user make one, so a "refused" below is the sandbox's doing.
    let outside = Command::new("unshare")
        .args(["--user", "true"])
        .status()
        .unwrap();
    if !outside.success() {
        assert!(
            std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
            "SAM_REQUIRE_SANDBOX=1, but this computer allows no user namespaces"
        );
        eprintln!("skipped: no user namespaces for ordinary users here");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let bin = d.join("bin");
    fs::create_dir(&bin).unwrap();
    let tool = bin.join("dwarfsextract");
    let path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{path}", bin.display()));
    // The stand-in belongs to the user: SAM runs it only from this folder.
    std::env::set_var("SAM_TRUST_TOOLS_IN", &bin);

    // The "AppImage": its own extractor tries, then unpacks a minimal app.
    let source = d.join("App.AppImage");
    script(
        &source,
        &format!(
            "[ \"$1\" = --appimage-extract ] || exit 2\n\
             mkdir -p squashfs-root && where=squashfs-root/userns\n\
             {TRY_USERNS}\n\
             printf '#!/bin/sh\\n' > squashfs-root/AppRun && chmod 755 squashfs-root/AppRun"
        ),
    );
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
    let iso = Isolation {
        bwrap,
        self_exe: PathBuf::from("/usr/bin/true"),
        system: sam_sandbox::helper_system_args(&sam_core::HostInfo::probe()),
        filter: None,
    };
    let unpack = |n: &str| {
        let root = d.join("extracted").join(n);
        let mut log = Vec::new();
        let out = extract(
            &ExtractRequest {
                source: &source,
                info: &info,
                root: &root,
                limits: Limits::default(),
                allow_fallback: true,
                isolation: Some(iso.clone()),
            },
            &mut log,
        )
        .unwrap_or_else(|e| panic!("{e:#}\n{}", String::from_utf8_lossy(&log)));
        let log = String::from_utf8_lossy(&log).into_owned();
        let got =
            fs::read_to_string(out.appdir.join("userns")).unwrap_or_else(|e| panic!("{e}\n{log}"));
        (got.trim().to_string(), log)
    };

    // 1. An unpacking tool tricked by a crafted image.
    script(
        &tool,
        &format!(
            "while [ $# -gt 0 ]; do [ \"$1\" = -o ] && dst=$2; shift; done\n\
             mkdir -p \"$dst\" && where=\"$dst/userns\"\n\
             {TRY_USERNS}\n\
             printf '#!/bin/sh\\n' > \"$dst/AppRun\" && chmod 755 \"$dst/AppRun\""
        ),
    );
    let (got, log) = unpack("by-tool");
    assert!(
        !log.contains("trying sandboxed --appimage-extract"),
        "{log}"
    );
    assert_eq!(got, "refused", "an unpacking tool made a user namespace");

    // 2. The AppImage's own extractor, once no tool could unpack it.
    script(&tool, "exit 1");
    let (got, log) = unpack("by-itself");
    assert!(log.contains("trying sandboxed --appimage-extract"), "{log}");
    assert_eq!(
        got, "refused",
        "the AppImage's own extractor made a user namespace"
    );
}
