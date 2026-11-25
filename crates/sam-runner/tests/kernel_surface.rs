//! The kernel's rarely used doors stay shut from inside a real sandbox, for
//! an app and for unpacking (audit S-F7, S-F9, I-F17):
//! - kernel crypto (`AF_ALG`) and virtual-machine (`AF_VSOCK`) sockets do
//!   not open; an internet socket does (the control);
//! - nor does a pair of crypto sockets (`socketpair`, review R66); a
//!   local pair does (the control);
//! - a call through the x32 ABI is refused by the filter (`EPERM`; without
//!   the filter the kernel answers it or says it has no such call);
//! - the same holds for an unpacking tool run on untrusted input, and for
//!   the AppImage's own extractor (`--appimage-extract`, run when SAM's
//!   reader cannot unpack it), which before had no filter at all.
//!
//! On the computer itself the probe shows which of these sockets open
//! without SAM, so each refusal is the filter's.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use sam_core::permissions::PermissionSet;
use sam_core::{AppImageType, HostInfo, Paths};
use sam_detect::appimage::{AppImageInfo, PayloadFormat};
use sam_intake::extract::{extract, ExtractRequest, Isolation};
use sam_intake::normalize::Limits;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// Prints NAME=open or NAME=<errno name> for each door.
const PROBE: &str = r#"
import socket, ctypes, errno
def fam(n, f, t):
    try:
        socket.socket(f, t).close(); print(n + "=open")
    except OSError as e:
        print(n + "=" + errno.errorcode.get(e.errno, str(e.errno)))
fam("ALG", socket.AF_ALG, socket.SOCK_SEQPACKET)
fam("VSOCK", socket.AF_VSOCK, socket.SOCK_STREAM)
fam("INET", socket.AF_INET, socket.SOCK_DGRAM)
def pair(n, f, t):
    try:
        a, b = socket.socketpair(f, t); a.close(); b.close(); print(n + "=open")
    except OSError as e:
        print(n + "=" + errno.errorcode.get(e.errno, str(e.errno)))
pair("PAIR_ALG", socket.AF_ALG, socket.SOCK_SEQPACKET)
pair("PAIR_UNIX", socket.AF_UNIX, socket.SOCK_STREAM)
libc = ctypes.CDLL(None, use_errno=True)
r = libc.syscall(39 | 0x40000000)
print("X32=" + ("ok" if r >= 0 else errno.errorcode.get(ctypes.get_errno(), "?")))
"#;

fn parse(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// What the doors answer here, without SAM.
fn on_this_computer() -> HashMap<String, String> {
    let out = Command::new("python3")
        .args(["-c", PROBE])
        .output()
        .unwrap();
    parse(&String::from_utf8_lossy(&out.stdout))
}

fn sandbox_works() -> bool {
    let host = HostInfo::probe();
    let ok = host.tools.bwrap.is_some() && sam_runner::doctor::bwrap_functional(&host).is_ok();
    let python = Command::new("python3").arg("-V").output().is_ok();
    if !(ok && python) {
        sam_runner::contracts::skip("bubblewrap or python3 is not available here")
            .unwrap_or_else(|e| panic!("{e}"));
    }
    ok && python
}

/// The filter's answers, compared with the computer's own.
fn assert_shut(text: &str, what: &str) {
    let inside = &parse(text);
    if inside.is_empty() {
        panic!("{what}: the probe said nothing: {text}");
    }
    let host = on_this_computer();
    assert_eq!(
        inside.get("INET").map(String::as_str),
        Some("open"),
        "{what}: {inside:?}"
    );
    for door in ["ALG", "VSOCK"] {
        assert_eq!(
            inside.get(door).map(String::as_str),
            Some("EAFNOSUPPORT"),
            "{what}: {door} (here without SAM: {:?})",
            host.get(door)
        );
    }
    // A pair of sockets keeps to the same families (review R66). Where
    // the kernel has no crypto sockets it refuses the pair itself, and the
    // refusal below would not be the filter's: a run that must prove
    // everything fails then, never passes silently.
    if host.get("PAIR_ALG").map(String::as_str) == Some("EAFNOSUPPORT") {
        sam_runner::contracts::skip("this kernel has no crypto sockets (AF_ALG)")
            .unwrap_or_else(|e| panic!("{e}"));
    }
    assert_eq!(
        inside.get("PAIR_UNIX").map(String::as_str),
        Some("open"),
        "{what}: {inside:?}"
    );
    assert_eq!(
        inside.get("PAIR_ALG").map(String::as_str),
        Some("EAFNOSUPPORT"),
        "{what}: PAIR_ALG (here without SAM: {:?})",
        host.get("PAIR_ALG")
    );
    assert_eq!(
        inside.get("X32").map(String::as_str),
        Some("EPERM"),
        "{what}: {inside:?}"
    );
    assert_ne!(
        host.get("X32").map(String::as_str),
        Some("EPERM"),
        "without the filter: {host:?}"
    );
}

#[test]
fn an_app_cannot_open_the_kernels_rarely_used_doors() {
    if !sandbox_works() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    let img = root.join("Doors-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Doors");
    spec.apprun = format!("#!/bin/sh\npython3 - <<'EOF'\n{PROBE}\nEOF\necho END=1\n");
    build(&img, &spec).unwrap();
    let app = Sam::with_paths(Paths::rooted(&root.join("samroot"))).unwrap();
    let id = app
        .add(
            &img,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let mut e = app
        .set_permissions(&id, PermissionSet::strict_gui())
        .unwrap();
    let rec = run(
        &mut e,
        &LaunchOptions {
            quiet: true,
            owd: Some(home.clone()),
            ..Default::default()
        },
        &app.config,
        &app.paths,
        &sam_runner::testenv::test_host(HostInfo::probe()),
    )
    .unwrap();
    let log = fs::read_to_string(rec.log_file.unwrap()).unwrap();
    let r = parse(&log);
    assert_eq!(r.get("END").map(String::as_str), Some("1"), "{log}");
    assert_shut(&log, "app");
}

#[test]
fn an_unpacking_tool_cannot_open_the_kernels_rarely_used_doors() {
    if !sandbox_works() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    // The "unpacking tool": probes, writes its answers into what it
    // unpacks, then unpacks a minimal app.
    let bin = d.join("bin");
    fs::create_dir(&bin).unwrap();
    // The probe is part of the tool: a file of its own in the test's
    // temporary folder would be hidden where that folder is /tmp (the
    // sandbox has a fresh /tmp).
    let tool = bin.join("dwarfsextract");
    fs::write(
        &tool,
        format!(
            "#!/bin/sh\n\
             while [ $# -gt 0 ]; do [ \"$1\" = -o ] && dst=$2; shift; done\n\
             mkdir -p \"$dst\" && python3 - > \"$dst/doors.txt\" 2>&1 <<'EOF'\n{PROBE}\nEOF\n\
             printf '#!/bin/sh\\n' > \"$dst/AppRun\" && chmod 755 \"$dst/AppRun\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
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
    // SAM's unpack sandbox as the runner builds it: the shared system view
    // and the baseline filter.
    let host = HostInfo::probe();
    let iso = Isolation {
        bwrap: host.tools.bwrap.as_ref().unwrap().path.clone(),
        self_exe: PathBuf::from("/usr/bin/true"),
        system: sam_sandbox::helper_system_args(&host),
        filter: Some(sam_runner::kernel::filter_bytes(&Default::default()).unwrap()),
    };
    let path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{path}", bin.display()));
    // The stand-in belongs to the user: SAM runs it only from this folder.
    std::env::set_var("SAM_TRUST_TOOLS_IN", &bin);
    let root = d.join("extracted").join("appimage-app-1234");
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
    let text = fs::read_to_string(out.appdir.join("doors.txt")).unwrap();
    assert_shut(&text, "unpacking");
}

/// The AppImage's own extractor runs code from the AppImage: here a
/// "runtime" that probes the doors when asked to unpack itself, after
/// SAM's own reader failed on it and the person allowed the fallback.
#[test]
fn an_appimages_own_extractor_cannot_open_the_kernels_rarely_used_doors() {
    if !sandbox_works() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let source = d.join("App.AppImage");
    fs::write(
        &source,
        format!(
            "#!/bin/sh\n\
             [ \"$1\" = --appimage-extract ] || exit 1\n\
             mkdir -p squashfs-root\n\
             python3 - > squashfs-root/doors.txt 2>&1 <<'EOF'\n{PROBE}\nEOF\n\
             printf '#!/bin/sh\\n' > squashfs-root/AppRun && chmod 755 squashfs-root/AppRun\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&source, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let info = AppImageInfo {
        path: source.clone(),
        size: fs::metadata(&source).unwrap().len(),
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
    let host = HostInfo::probe();
    // SAM's reader is `false` here: it fails, so the fallback runs.
    let iso = Isolation {
        bwrap: host.tools.bwrap.as_ref().unwrap().path.clone(),
        self_exe: PathBuf::from("/usr/bin/false"),
        system: sam_sandbox::helper_system_args(&host),
        filter: Some(sam_runner::kernel::filter_bytes(&Default::default()).unwrap()),
    };
    let root = d.join("extracted").join("appimage-app-1234");
    let mut log = Vec::new();
    let out = extract(
        &ExtractRequest {
            source: &source,
            info: &info,
            root: &root,
            limits: Limits::default(),
            allow_fallback: true,
            isolation: Some(iso),
        },
        &mut log,
    )
    .unwrap_or_else(|e| panic!("{e:#}\n{}", String::from_utf8_lossy(&log)));
    let log = String::from_utf8_lossy(&log);
    assert!(log.contains("appimage-extract"), "the fallback ran: {log}");
    let text = fs::read_to_string(out.appdir.join("doors.txt")).unwrap();
    assert_shut(&text, "the AppImage's own extractor");
}
