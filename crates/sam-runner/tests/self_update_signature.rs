//! SAM's self-update check end to end with the real GnuPG (threat-model
//! row 61): a downloaded SAM is accepted only when its embedded signature
//! was really made with a release key. The unit test in release_key.rs
//! covers the decision on hand-made results; this one runs the signature
//! check that feeds it, including the forgery of audit finding C1.
//!
//! Runs only with SAM_TEST_GPG=1 (CI sets it; then missing tools fail the
//! test instead of skipping it). Needs gpg, gpgv and objcopy.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::path::{Path, PathBuf};
use std::process::Command;

use sam_detect::signature::{check, sign_for_test, sign_with_key_block_for_test};
use sam_runner::release_key;

fn gpg(home: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .args([
            "--batch",
            "--quiet",
            "--passphrase",
            "",
            "--pinentry-mode",
            "loopback",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "gpg {args:?}");
    out.stdout
}

fn new_key(home: &Path, uid: &str, email: &str) -> String {
    gpg(home, &["--quick-gen-key", uid, "ed25519", "sign", "never"]);
    let listing = String::from_utf8(gpg(
        home,
        &["--with-colons", "--fingerprint", "--list-keys", email],
    ))
    .unwrap();
    listing
        .lines()
        .find(|l| l.starts_with("fpr:"))
        .and_then(|l| l.split(':').nth(9))
        .unwrap()
        .to_string()
}

/// A stand-in for a downloaded SAM: a runtime with empty signature sections.
fn download(dir: &Path, name: &str) -> PathBuf {
    std::fs::write(dir.join("sig0"), vec![0u8; 1024]).unwrap();
    std::fs::write(dir.join("key0"), vec![0u8; 8192]).unwrap();
    let img = dir.join(name);
    let st = Command::new("objcopy")
        .arg(format!(
            "--add-section=.sha256_sig={}",
            dir.join("sig0").display()
        ))
        .arg(format!(
            "--add-section=.sig_key={}",
            dir.join("key0").display()
        ))
        .arg("/bin/true")
        .arg(&img)
        .status()
        .unwrap();
    assert!(st.success());
    img
}

/// SAM installs an update of itself only when it was really signed with its
/// release key. A forged download that carries the (public) release key
/// next to the attacker's key, signed by the attacker, is refused; so is an
/// update honestly signed with any other key.
#[test]
fn sam_refuses_a_forged_update_that_carries_its_release_key() {
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") {
        eprintln!("skipping: set SAM_TEST_GPG=1 (with gpg, gpgv and objcopy installed)");
        return;
    }
    assert!(
        ["gpg", "gpgv", "objcopy"]
            .iter()
            .all(|t| sam_core::util::which(t).is_some()),
        "SAM_TEST_GPG=1, but gpg, gpgv or objcopy is not installed"
    );
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let home = dir.join("gnupg");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let release = new_key(
        &home,
        "SAM Release <release@example.invalid>",
        "release@example.invalid",
    );
    new_key(
        &home,
        "Attacker <attacker@example.invalid>",
        "attacker@example.invalid",
    );
    let keys = [release.as_str()];

    let genuine = download(dir, "SAM-genuine.AppImage");
    sign_for_test(&genuine, &home, "release@example.invalid").unwrap();
    assert!(release_key::check(&check(&genuine), &keys).is_ok());

    let forged = download(dir, "SAM-forged.AppImage");
    let mut block = gpg(&home, &["--armor", "--export", "release@example.invalid"]);
    block.extend(gpg(
        &home,
        &["--armor", "--export", "attacker@example.invalid"],
    ));
    sign_with_key_block_for_test(&forged, &home, "attacker@example.invalid", &block).unwrap();
    let e = release_key::check(&check(&forged), &keys)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("changed after signing") || e.contains("not installed"),
        "{e}"
    );

    let other = download(dir, "SAM-other.AppImage");
    sign_for_test(&other, &home, "attacker@example.invalid").unwrap();
    let e = release_key::check(&check(&other), &keys)
        .unwrap_err()
        .to_string();
    assert!(e.contains("not with SAM's release key"), "{e}");

    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&home)
        .args(["--kill", "all"])
        .status();
}
