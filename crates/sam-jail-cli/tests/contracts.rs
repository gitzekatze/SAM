//! The quick checks of SAM's contracts with the outside world must notice a
//! broken assumption, not only confirm a working one. Fake tools stand in
//! for real ones that changed: a Bubblewrap that lost an option and cannot
//! build a sandbox, a pasta without --splice-only, and missing programs.
//! `sam-jail doctor --contracts` must name exactly those contracts.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn fake(dir: &Path, name: &str, script: &str) {
    let p = dir.join(name);
    fs::write(&p, format!("#!/bin/sh\n{script}\n")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
}

/// contract id -> state, from `sam-jail --json doctor --contracts` with only
/// the fake tools on PATH.
fn states(bin: &Path, root: &Path) -> BTreeMap<String, String> {
    let out = Command::new(env!("CARGO_BIN_EXE_sam-jail"))
        .args(["--json", "doctor", "--contracts"])
        .env("PATH", bin)
        .env("SAM_TRUST_TOOLS_IN", bin)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(text.lines().last().unwrap_or("null")).unwrap();
    v["data"]["contracts"]
        .as_array()
        .unwrap_or_else(|| panic!("no contracts in: {text}"))
        .iter()
        .map(|c| {
            (
                c["id"].as_str().unwrap().to_string(),
                c["state"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn the_quick_checks_notice_a_broken_or_missing_tool() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    // A Bubblewrap from before --disable-userns, which cannot build a sandbox.
    fake(
        &bin,
        "bwrap",
        r#"case "$1" in
  --version) echo "bubblewrap 0.4.0" ;;
  --help) echo "usage: bwrap [OPTIONS...] [--] COMMAND"; echo "  --unshare-user"; echo "  --ro-bind SRC DEST" ;;
  *) echo "bwrap: setting up uid map: Permission denied" >&2; exit 1 ;;
esac"#,
    );
    // A pasta without --splice-only (it would give the app the internet).
    fake(
        &bin,
        "pasta",
        r#"echo "Usage: pasta [OPTION]... [COMMAND] [ARG]..."; echo "  -t, --tcp-ports SPEC""#,
    );
    let s = states(&bin, tmp.path());
    assert_eq!(
        s["bwrap-core"], "broken",
        "a Bubblewrap that cannot build a sandbox"
    );
    assert_eq!(
        s["bwrap-disable-userns"], "broken",
        "a Bubblewrap without --disable-userns"
    );
    assert_eq!(
        s["pasta-splice-only"], "broken",
        "a pasta without --splice-only"
    );
    // Programs that are not there at all.
    assert_eq!(s["updates-curl"], "absent", "no curl");
    assert_eq!(s["unpack-tools"], "absent", "no unsquashfs");
    assert_eq!(s["dbus-proxy-filter"], "absent", "no xdg-dbus-proxy");
}
