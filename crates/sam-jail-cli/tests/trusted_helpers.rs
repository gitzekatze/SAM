//! SAM runs its helper programs outside the sandbox, so it must never run
//! a copy the user (and with it any app with write access to the home) can
//! change (audit L-F12). Here a folder of the user's comes first on
//! `$PATH`, as `~/.cargo/bin` or `~/.nix-profile/bin` often do, with planted
//! copies of every helper; each leaves a mark when it runs and then hands
//! over to the real one. SAM's checks, adding an app and starting it must
//! leave no mark. Skipped where Bubblewrap cannot run.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn bwrap_works() -> bool {
    Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-user",
            "--unshare-pid",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

const PLANTED: &[&str] = &[
    "bwrap",
    "pasta",
    "xdg-dbus-proxy",
    "unsquashfs",
    "bsdtar",
    "gpg",
    "gpgv",
    "notify-send",
    "update-desktop-database",
    "sam-jail-run",
    "pipewire",
    "pactl",
    "curl",
];

fn sam(root: &Path, path: &str, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env("PATH", path)
        .env("LC_ALL", "C")
        .stdin(Stdio::null());
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    c.output().unwrap()
}

#[test]
fn sam_never_runs_a_helper_the_user_can_change() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["config", "home"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let planted = root.join("home/.cargo/bin");
    fs::create_dir_all(&planted).unwrap();
    let marks = root.join("marks");
    fs::create_dir_all(&marks).unwrap();
    for name in PLANTED {
        let p = planted.join(name);
        fs::write(
            &p,
            format!(
                "#!/bin/sh\ntouch {}/{name}\nPATH=/usr/bin:/bin exec {name} \"$@\"\n",
                marks.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:/usr/bin:/bin", planted.display());

    // An app, made and added with the planted folder first on PATH.
    let script = root.join("apprun");
    fs::write(&script, "#!/bin/sh\necho started\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let img = root.join("Plain-1.0-x86_64.AppImage");
    let (img_s, script_s) = (img.to_str().unwrap(), script.to_str().unwrap());
    let ok = |o: Output| {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        o
    };
    ok(sam(
        root,
        &path,
        &[
            "dev",
            "make-fixture",
            "--name",
            "Plain",
            "--apprun",
            script_s,
            img_s,
        ],
    ));
    let add = ok(sam(root, &path, &["--json", "add", img_s, "--accept"]));
    let v: serde_json::Value = serde_json::from_slice(
        add.stdout
            .split(|b| *b == b'\n')
            .rfind(|l| !l.is_empty())
            .unwrap(),
    )
    .unwrap();
    let id = v["data"]["app"]["id"].as_str().unwrap().to_string();
    // Its menu entry names SAM's launcher by its whole path, not one the
    // desktop would look up on PATH.
    let entry = fs::read_dir(root.join("applications"))
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("sam-"))
        .map(|e| fs::read_to_string(e.path()).unwrap())
        .unwrap_or_default();
    let exec = entry.lines().find(|l| l.starts_with("Exec=")).unwrap_or("");
    assert!(
        exec.starts_with("Exec=/") || exec.starts_with("Exec=\"/"),
        "{exec}"
    );
    assert!(!exec.contains(".cargo"), "{exec}");

    // Started, with "This computer only" (pasta) and the D-Bus filter.
    ok(sam(root, &path, &["set", &id, "network.mode", "localhost"]));
    let run = sam(root, &path, &["run", &id]);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("started"),
        "the app ran: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    // SAM's checks of this computer and of its outside contracts.
    sam(root, &path, &["--json", "doctor"]);
    sam(root, &path, &["--json", "doctor", "--contracts"]);
    sam(root, &path, &["--json", "verify", &id]);

    let ran: Vec<String> = fs::read_dir(&marks)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(ran.is_empty(), "SAM ran planted helpers: {ran:?}");
}
