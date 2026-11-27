//! Builds SAM's room helper (room-exec/main.rs) as a static program, which
//! `room_service` embeds: it starts inside a room's file layout, so it must
//! need no loader and no library from it. Uses only Rust's standard library
//! (and sam-core's place_check.rs, a file of the helper written that way);
//! needs the static C library (Debian/Ubuntu: libc6-dev, Fedora:
//! glibc-static, Arch: glibc). Without it the build goes on, warns, and
//! Room service is off in that build (every start says so).
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// A line for cargo (build scripts talk to cargo on standard output).
fn cargo(line: &str) {
    let _ = writeln!(std::io::stdout(), "cargo:{line}");
}

fn main() {
    cargo("rerun-if-changed=room-exec/main.rs");
    // Part of the helper: SAM's one place check (included with #[path]).
    cargo("rerun-if-changed=../sam-core/src/place_check.rs");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("sam-room-exec");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let target = std::env::var("TARGET").expect("TARGET");
    let built = Command::new(rustc)
        .args(["--edition", "2021", "--crate-name", "sam_room_exec", "-O"])
        .args([
            "-C",
            "panic=abort",
            "-C",
            "target-feature=+crt-static",
            "-C",
            "debuginfo=0",
        ])
        .args(["--target", &target, "-o"])
        .arg(&out)
        .arg("room-exec/main.rs")
        .status()
        .is_ok_and(|s| s.success());
    if !built {
        let _ = std::fs::write(&out, b"");
        // Build again once the static C library is installed.
        for lib in [
            "/usr/lib/libc.a",
            "/usr/lib64/libc.a",
            "/usr/lib/x86_64-linux-gnu/libc.a",
            "/usr/lib/aarch64-linux-gnu/libc.a",
        ] {
            cargo(&format!("rerun-if-changed={lib}"));
        }
        cargo(
            "warning=SAM's room helper could not be built as a static program (is the static C library installed? Debian/Ubuntu: libc6-dev, Fedora: glibc-static); Room service is off in this build"
        );
    }
}
