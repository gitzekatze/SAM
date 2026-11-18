//! Embedded signatures, end to end with the real GnuPG: a test runtime gets
//! empty signature sections (as the AppImage runtime has), throwaway keys
//! sign it, and SAM's check must name the key that really signed.
//!
//! Runs only with SAM_TEST_GPG=1 (CI sets it; then missing tools fail the
//! tests instead of skipping them): signing starts a gpg-agent, which puts
//! its sockets under /run/user/<uid>/gnupg. Needs gpg, gpgv and objcopy.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::path::{Path, PathBuf};
use std::process::Command;

use sam_core::model::SignatureState;
use sam_detect::signature::{check, gnupg_contract, sign_for_test, sign_with_key_block_for_test};

/// A throwaway GnuPG folder and a work folder; the agent is stopped at the end.
struct Kit {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    home: PathBuf,
}

impl Drop for Kit {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.home)
            .args(["--kill", "all"])
            .status();
    }
}

/// `None` when the GnuPG tests are not wanted here; with SAM_TEST_GPG=1 the
/// tools must be there.
fn kit() -> Option<Kit> {
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") {
        eprintln!("skipping: set SAM_TEST_GPG=1 (with gpg, gpgv and objcopy installed)");
        return None;
    }
    let tools = ["gpg", "gpgv", "objcopy"]
        .iter()
        .all(|t| sam_core::util::which(t).is_some());
    assert!(
        tools,
        "SAM_TEST_GPG=1, but gpg, gpgv or objcopy is not installed"
    );
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let home = dir.join("gnupg");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    Some(Kit {
        _tmp: tmp,
        dir,
        home,
    })
}

impl Kit {
    fn gpg(&self, args: &[&str]) -> Vec<u8> {
        let out = Command::new("gpg")
            .arg("--homedir")
            .arg(&self.home)
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

    /// A new key that can sign; returns its fingerprint.
    fn key(&self, uid: &str) -> String {
        self.gpg(&["--quick-gen-key", uid, "ed25519", "sign", "never"]);
        self.fingerprint(uid)
    }

    fn fingerprint(&self, uid: &str) -> String {
        let listing =
            String::from_utf8(self.gpg(&["--with-colons", "--fingerprint", "--list-keys", uid]))
                .unwrap();
        listing
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .unwrap()
            .to_string()
    }

    fn export(&self, uid: &str) -> Vec<u8> {
        self.gpg(&["--armor", "--export", uid])
    }

    /// A runtime with empty signature sections, like the AppImage runtime.
    fn image(&self, name: &str) -> PathBuf {
        let d = &self.dir;
        std::fs::write(d.join("sig0"), vec![0u8; 1024]).unwrap();
        std::fs::write(d.join("key0"), vec![0u8; 8192]).unwrap();
        let img = d.join(name);
        let st = Command::new("objcopy")
            .arg(format!(
                "--add-section=.sha256_sig={}",
                d.join("sig0").display()
            ))
            .arg(format!(
                "--add-section=.sig_key={}",
                d.join("key0").display()
            ))
            .arg("/bin/true")
            .arg(&img)
            .status()
            .unwrap();
        assert!(st.success());
        img
    }
}

fn flip_last_byte(img: &Path) {
    let mut data = std::fs::read(img).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xff;
    std::fs::write(img, data).unwrap();
}

/// The signature of a signed AppImage is checked with GnuPG: unsigned,
/// valid with the signer's fingerprint and name, invalid after one changed
/// byte.
#[test]
fn signed_appimage_is_checked() {
    let Some(k) = kit() else { return };
    let fpr = k.key("SAM Test <test@example.invalid>");
    let img = k.image("Signed-x86_64.AppImage");
    let unsigned = check(&img);
    assert_eq!(
        unsigned.state,
        SignatureState::Unsigned,
        "{}",
        unsigned.detail
    );

    sign_for_test(&img, &k.home, "test@example.invalid").unwrap();
    let ok = check(&img);
    assert_eq!(ok.state, SignatureState::Valid, "{}", ok.detail);
    assert_eq!(ok.fingerprint.as_deref(), Some(fpr.as_str()));
    assert!(ok.detail.contains("SAM Test"), "{}", ok.detail);

    flip_last_byte(&img);
    let bad = check(&img);
    assert_eq!(bad.state, SignatureState::Invalid);
    assert_eq!(
        bad.fingerprint, None,
        "no signer is named for a broken signature"
    );
}

/// The attack of audit finding C1: a file carries a trusted key (here it
/// stands for SAM's release key, which is public) first and the attacker's
/// key second, and is signed with the attacker's key. gpgv accepts that, and
/// SAM used to name the first key as the signer, so a forged update of SAM
/// or a forged app update looked like it came from the trusted key. SAM
/// must refuse such a file and never name the trusted key.
#[test]
fn a_second_key_in_the_file_cannot_borrow_a_trusted_name() {
    let Some(k) = kit() else { return };
    let trusted = k.key("Trusted Maker <trusted@example.invalid>");
    let attacker = k.key("Attacker <attacker@example.invalid>");
    let img = k.image("Forged-x86_64.AppImage");
    let mut block = k.export("trusted@example.invalid");
    block.extend(k.export("attacker@example.invalid"));
    sign_with_key_block_for_test(&img, &k.home, "attacker@example.invalid", &block).unwrap();

    let r = check(&img);
    assert_eq!(r.state, SignatureState::Invalid, "{}", r.detail);
    assert_ne!(r.fingerprint.as_deref(), Some(trusted.as_str()));
    assert!(r.detail.contains("2 keys"), "{}", r.detail);

    // The same order reversed: still refused.
    let img2 = k.image("Forged2-x86_64.AppImage");
    let mut block2 = k.export("attacker@example.invalid");
    block2.extend(k.export("trusted@example.invalid"));
    sign_with_key_block_for_test(&img2, &k.home, "attacker@example.invalid", &block2).unwrap();
    assert_eq!(check(&img2).state, SignatureState::Invalid);

    // Only the trusted key in the file, but signed by the attacker: gpgv
    // cannot verify it, so it is not valid and names nobody.
    let img3 = k.image("Forged3-x86_64.AppImage");
    let only_trusted = k.export("trusted@example.invalid");
    sign_with_key_block_for_test(&img3, &k.home, "attacker@example.invalid", &only_trusted)
        .unwrap();
    let r3 = check(&img3);
    assert_eq!(r3.state, SignatureState::Invalid, "{}", r3.detail);
    assert_eq!(r3.fingerprint, None);

    // Honestly signed by the attacker with its own key: valid, and named as
    // what it is.
    let img4 = k.image("Honest-x86_64.AppImage");
    sign_for_test(&img4, &k.home, "attacker@example.invalid").unwrap();
    let r4 = check(&img4);
    assert_eq!(r4.state, SignatureState::Valid, "{}", r4.detail);
    assert_eq!(r4.fingerprint.as_deref(), Some(attacker.as_str()));
}

/// A key whose signatures come from a signing subkey: SAM names the primary
/// key (the fingerprint people publish and SAM compares), not the subkey.
#[test]
fn a_signature_by_a_subkey_names_its_primary_key() {
    let Some(k) = kit() else { return };
    k.gpg(&[
        "--quick-gen-key",
        "Sub Signer <sub@example.invalid>",
        "ed25519",
        "cert",
        "never",
    ]);
    let primary = k.fingerprint("sub@example.invalid");
    k.gpg(&["--quick-add-key", &primary, "ed25519", "sign", "never"]);
    let img = k.image("Subkey-x86_64.AppImage");
    sign_for_test(&img, &k.home, "sub@example.invalid").unwrap();
    let r = check(&img);
    assert_eq!(r.state, SignatureState::Valid, "{}", r.detail);
    assert_eq!(r.fingerprint.as_deref(), Some(primary.as_str()));
}

/// The contract with GnuPG (docs/contracts.toml, `signatures-gnupg`) holds
/// with the GnuPG installed here: gpgv accepts a signature by any key in its
/// keyring, and its status output names the key that really signed. If a
/// GnuPG version changes either, this test and `sam-jail doctor` say so.
#[test]
fn gnupg_names_the_real_signer() {
    let Some(_k) = kit() else { return };
    if let Err(e) = gnupg_contract() {
        panic!("the GnuPG contract is broken here: {e}");
    }
}
