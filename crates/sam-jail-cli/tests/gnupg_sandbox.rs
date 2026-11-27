//! Regression (review 2026-11-23, F6; audit I-F18): every parser of an
//! AppImage's bytes ran in the unpack sandbox except GnuPG. `gpg --import`
//! and `gpgv` read the key and the signature the file carries (an
//! attacker's OpenPGP packets) as the user, with the home folder and the
//! network, at every add, before anyone agreed to run anything. Here
//! `sam-jail add` checks a really signed AppImage, and GnuPG is a stand-in
//! that first does what code smuggled in through a parser bug would do,
//! writing a file into the user's folders, and then runs the real GnuPG.
//! The signature is still found valid, and nothing is written.
//!
//! Runs only with SAM_TEST_GPG=1 (CI sets it; then missing tools fail the
//! test), and needs a working Bubblewrap (with SAM_REQUIRE_SANDBOX=1 a
//! missing one fails the test). Needs gpg, gpgv and objcopy.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

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
    assert!(out.status.success(), "gpg {} failed", args[0]);
    out.stdout
}

/// The throwaway GnuPG folder's agent is stopped at the end.
struct Agent<'a>(&'a Path);
impl Drop for Agent<'_> {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.0)
            .args(["--kill", "all"])
            .status();
    }
}

#[test]
fn gnupg_reads_an_appimages_key_and_signature_only_in_a_sandbox() {
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
    if sam_runner::doctor::bwrap_functional(&sam_core::HostInfo::probe()).is_err() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["bin", "tools", "run", "gnupg"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let home = root.join("gnupg");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let _agent = Agent(&home);
    gpg(
        &home,
        &[
            "--quick-gen-key",
            "Signer <signer@example.org>",
            "ed25519",
            "sign",
            "never",
        ],
    );
    let listing = String::from_utf8(gpg(
        &home,
        &[
            "--with-colons",
            "--fingerprint",
            "--list-keys",
            "signer@example.org",
        ],
    ))
    .unwrap();
    let fpr = listing
        .lines()
        .find(|l| l.starts_with("fpr:"))
        .and_then(|l| l.split(':').nth(9))
        .unwrap()
        .to_string();

    let img = root.join("Signed-1.0-x86_64.AppImage");
    let mut spec = sam_intake::testkit::FixtureSpec::hello("Signed");
    spec.signature_sections = true;
    sam_intake::testkit::build(&img, &spec).unwrap();
    sam_detect::signature::sign_for_test(&img, &home, &fpr).unwrap();

    // GnuPG as code from a crafted key would run it: it writes into the
    // user's folders, then does the real work.
    let victim = root.join("written-by-gnupg");
    for tool in ["gpg", "gpgv"] {
        let p = root.join("tools").join(tool);
        fs::write(
            &p,
            format!(
                "#!/bin/sh\necho {tool} >> '{}' 2>/dev/null\nexec /usr/bin/{tool} \"$@\"\n",
                victim.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let sam = root.join("bin/sam-jail");
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), &sam).unwrap();
    let run = |args: &[&str]| {
        Command::new(&sam)
            .args(args)
            .env("SAM_CONFIG_DIR", root.join("config"))
            .env("SAM_DATA_DIR", root.join("data"))
            .env("SAM_APPLICATIONS_DIR", root.join("applications"))
            .env("XDG_RUNTIME_DIR", root.join("run"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", root.join("tools").display()),
            )
            // The stand-ins belong to the user: SAM runs them only from here.
            .env("SAM_TRUST_TOOLS_IN", root.join("tools"))
            .env("LC_ALL", "C")
            .env_remove("LANGUAGE")
            .output()
            .unwrap()
    };
    let added = run(&["--json", "add", img.to_str().unwrap(), "--no-launcher"]);
    let text = String::from_utf8_lossy(&added.stdout);
    assert!(
        added.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let reply: serde_json::Value =
        serde_json::from_str(text.lines().last().unwrap_or("null")).unwrap();
    let sig = reply
        .pointer("/data/entry/signature")
        .unwrap_or_else(|| panic!("no signature in {reply}"));
    assert_eq!(sig["state"], "valid", "the real GnuPG checked it: {sig}");
    assert_eq!(sig["fingerprint"], fpr.as_str(), "{sig}");
    assert!(
        !victim.exists(),
        "GnuPG wrote into the user's folders: {:?}",
        fs::read_to_string(&victim)
    );
}
