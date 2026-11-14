//! Embedded signatures, end to end with GnuPG: a test runtime gets empty
//! signature sections (as the AppImage runtime has), a throwaway key signs
//! it, and the check must accept it and refuse it after one changed byte.
//!
//! Runs only with SAM_TEST_GPG=1 (CI sets it): signing starts a gpg-agent,
//! which puts its sockets under /run/user/<uid>/gnupg. Needs gpg, gpgv and
//! objcopy.

use std::process::Command;

use sam_core::model::SignatureState;
use sam_detect::signature::{check, sign_for_test};

fn have(tool: &str) -> bool {
    sam_core::util::which(tool).is_some()
}

/// The signature of a signed AppImage is checked with GnuPG.
#[test]
fn signed_appimage_is_checked() {
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") || !["gpg", "gpgv", "objcopy"].iter().all(|t| have(t)) {
        eprintln!("skipping: set SAM_TEST_GPG=1 and install gpg, gpgv and objcopy");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let home = d.join("gnupg");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let gpg = |args: &[&str]| {
        assert!(Command::new("gpg").arg("--homedir").arg(&home).args(["--batch", "--quiet"]).args(args).status().unwrap().success(), "gpg {args:?}")
    };
    gpg(&["--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key", "SAM Test <test@example.invalid>", "ed25519", "sign", "never"]);

    // A runtime with empty signature sections, like the AppImage runtime.
    std::fs::write(d.join("sig0"), vec![0u8; 1024]).unwrap();
    std::fs::write(d.join("key0"), vec![0u8; 8192]).unwrap();
    let img = d.join("Signed-x86_64.AppImage");
    let st = Command::new("objcopy")
        .arg(format!("--add-section=.sha256_sig={}", d.join("sig0").display()))
        .arg(format!("--add-section=.sig_key={}", d.join("key0").display()))
        .arg("/bin/true")
        .arg(&img)
        .status()
        .unwrap();
    assert!(st.success());
    let unsigned = check(&img);
    assert_eq!(unsigned.state, SignatureState::Unsigned, "{}", unsigned.detail);

    sign_for_test(&img, &home, "test@example.invalid").unwrap();
    let ok = check(&img);
    assert_eq!(ok.state, SignatureState::Valid, "{}", ok.detail);
    assert!(ok.fingerprint.as_deref().is_some_and(|f| f.len() == 40), "{:?}", ok.fingerprint);
    assert!(ok.detail.contains("SAM Test"), "{}", ok.detail);

    // One changed byte outside the sections: the signature no longer matches.
    let mut data = std::fs::read(&img).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xff;
    std::fs::write(&img, data).unwrap();
    assert_eq!(check(&img).state, SignatureState::Invalid);

    let _ = Command::new("gpgconf").arg("--homedir").arg(&home).args(["--kill", "all"]).status();
}
