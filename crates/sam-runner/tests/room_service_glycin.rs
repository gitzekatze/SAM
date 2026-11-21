//! GTK's real image loader (glycin, gdk-pixbuf 2.44 and newer) inside a SAM
//! sandbox: it builds a Bubblewrap sandbox for every loader. Without Room
//! service that fails inside SAM, and glycin loads images without any
//! sandbox ("Glycin running without sandbox"). With it, the loader runs in
//! a room. Needs glycin and python3 with GdkPixbuf (gi) on this computer.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod rooms_common;

use std::process::{Command, Stdio};

use rooms_common::{cases, World};

/// The control on the computer itself: GTK loads the test image through
/// glycin, and glycin starts Bubblewrap for it (a stand-in first on PATH
/// records the call, then runs the real one). Otherwise this computer's
/// image loading does not use glycin's sandbox, and there is nothing here
/// for Room service to serve.
fn glycin_sandboxes_here(dir: &std::path::Path) -> bool {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let called = dir.join("bwrap-called");
    let real = sam_core::util::which("bwrap").unwrap();
    let standin = bin.join("bwrap");
    std::fs::write(
        &standin,
        format!(
            "#!/bin/sh\ntouch '{}'\nexec '{}' \"$@\"\n",
            called.display(),
            real.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        &standin,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let pic = dir.join("pic.svg");
    std::fs::write(&pic, SVG).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let loaded = Command::new("python3")
        .args(["-c", LOAD_PY])
        .arg(&pic)
        .env("PATH", path)
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("loaded=24x16"));
    loaded && called.exists()
}

const SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="16"><rect width="24" height="16" fill="#3a7"/></svg>"##;

const LOAD_PY: &str = r#"
import sys
import gi
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf
p = GdkPixbuf.Pixbuf.new_from_file(sys.argv[1])
print(f"CASE loaded={p.get_width()}x{p.get_height()}", flush=True)
"#;

fn glycin_here() -> bool {
    let loaders =
        std::fs::read_dir("/usr/share/glycin-loaders").is_ok_and(|mut d| d.next().is_some());
    loaders
        && Command::new("python3")
            .args(["-c", "import gi; gi.require_version('GdkPixbuf', '2.0'); from gi.repository import GdkPixbuf"])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

/// An image loaded through GTK's real image loader inside a SAM sandbox is
/// decoded in a room of its own, never without a sandbox.
#[test]
fn glycin_loads_images_in_a_room_never_without_a_sandbox() {
    if !rooms_common::require() {
        return;
    }
    if !glycin_here() {
        sam_runner::contracts::not_here(
            "GTK's image loader glycin (or GdkPixbuf for python3) is not installed here",
        );
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "kernel-seccomp"])
        .unwrap_or_else(|e| panic!("{e}"));
    let w = World::new();
    if !glycin_sandboxes_here(&w.root.join("control")) {
        sam_runner::contracts::not_here(
            "GTK's image loading here does not start glycin's Bubblewrap sandbox",
        );
        return;
    }
    let id = w.add(
        "RoomGlycin",
        r##"
cat > "$HOME/pic.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="16"><rect width="24" height="16" fill="#3a7"/></svg>
SVG
python3 - "$HOME/pic.svg" <<'PY'
import sys
import gi
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf
p = GdkPixbuf.Pixbuf.new_from_file(sys.argv[1])
print(f"CASE loaded={p.get_width()}x{p.get_height()}", flush=True)
PY
"##,
    );
    let log = w.start(&id, |_| {}, 120);
    let mut failures = Vec::new();
    if cases(&log).get("loaded").map(String::as_str) != Some("24x16") {
        failures.push("the image did not load".to_string());
    }
    if log.contains("without sandbox") {
        failures.push("glycin ran its loader without a sandbox".into());
    }
    if !log
        .lines()
        .any(|l| l.contains("sam-room: built") && l.contains("glycin"))
    {
        failures.push("the start record names no room for glycin's loader".into());
    }
    assert!(failures.is_empty(), "{}\nlog:\n{log}", failures.join("\n"));
}
