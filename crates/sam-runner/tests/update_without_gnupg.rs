//! An update whose signature cannot be checked, because GnuPG is missing
//! when the update runs, after the installed version's signature was
//! checked. Against the local HTTPS server of the update tests.
//!
//! In its own file because it changes the command search path (`PATH`) of
//! the test process: SAM looks for GnuPG there.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

mod gpg_agent;
mod update_common;

use std::fs;
use std::path::Path;
use std::process::Command;

use sam_core::model::SignatureState;
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use update_common::{add_reviewed, have, publish, server_or_skip, unpacked_version};

/// Fills `bin` with links to every program SAM would run from the current
/// command search path, except GnuPG (`gpg` and `gpgv`): the computer as it
/// is, without GnuPG. Only programs SAM already trusts are linked, so naming
/// the folder in `SAM_TRUST_TOOLS_IN` trusts nothing new.
fn programs_without_gnupg(bin: &Path) {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name == "gpg" || name == "gpgv" || fs::symlink_metadata(bin.join(name)).is_ok() {
                continue;
            }
            if let Some(real) = sam_core::util::which(name) {
                std::os::unix::fs::symlink(real, bin.join(name)).unwrap();
            }
        }
    }
}

/// An update whose signature cannot be checked waits for a yes when the
/// installed version's signature was checked. The installed version was
/// checked with GnuPG; the update is signed too, but GnuPG has gone missing
/// since, so SAM cannot tell whether the same developer signed it. SAM asks
/// first (`signature-unchecked`) and the installed version stays as it
/// was. A yes covers only the file shown: a newer one published meanwhile
/// is asked about again, and a yes to it installs exactly that file. Runs
/// with SAM_TEST_GPG=1 (CI), where missing GnuPG tools fail it.
///
/// Mutation run 2026-11-24: no test noticed the update installed without
/// a question when the check of the recorded signature, or of the yes,
/// was turned around.
#[test]
fn an_update_that_cannot_be_checked_after_a_checked_signature_waits_for_consent() {
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") {
        sam_runner::contracts::skip("set SAM_TEST_GPG=1 (with gpg, gpgv and objcopy installed)")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    assert!(
        ["gpg", "gpgv", "objcopy"].iter().all(|t| have(t)),
        "SAM_TEST_GPG=1, but gpg, gpgv or objcopy is not installed"
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    sam_runner::testenv::isolate_this_process(&root);
    let Some((server, url)) = server_or_skip(&root) else {
        return;
    };
    let gpg_home = root.join("gnupg");
    fs::create_dir(&gpg_home).unwrap();
    let _agent = gpg_agent::Stop::new(&gpg_home);
    fs::set_permissions(
        &gpg_home,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let st = Command::new("gpg")
        .arg("--homedir")
        .arg(&gpg_home)
        .args(["--batch", "--quiet", "--passphrase", ""])
        .args(["--pinentry-mode", "loopback", "--quick-gen-key"])
        .args([
            "Tool Maker <maker@example.invalid>",
            "ed25519",
            "sign",
            "never",
        ])
        .status()
        .unwrap();
    assert!(st.success(), "gpg could not make a key");
    // Both versions signed with the same key, while GnuPG is still there.
    let signed = |path: &Path, version: &str| {
        let mut spec = FixtureSpec::hello("Tool");
        spec.comment = format!("Tool, version {version}");
        spec.files.push(FixtureFile {
            path: "usr/share/tool/data.bin".into(),
            data: vec![7u8; 300_000],
            mode: 0o644,
        });
        spec.files.push(FixtureFile {
            path: "usr/share/tool/version".into(),
            data: version.as_bytes().to_vec(),
            mode: 0o644,
        });
        spec.update_info = Some(format!("zsync|{url}"));
        spec.signature_sections = true;
        build(path, &spec).unwrap();
        sam_detect::signature::sign_for_test(path, &gpg_home, "maker@example.invalid").unwrap();
    };
    let apps = root.join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let installed = apps.join("Tool-1.0-x86_64.AppImage");
    signed(&installed, "1.0");
    let v2 = root.join("v2.AppImage");
    signed(&v2, "2.0");
    let v3 = root.join("v3.AppImage");
    signed(&v3, "3.0");
    publish(&server, &v2, "Tool-2.0-x86_64.AppImage");

    // Added with GnuPG: the installed version's signature is checked.
    let (sam, id) = add_reviewed(&root, &installed);
    let sig = sam.resolve(&id).unwrap().signature.unwrap();
    assert_eq!(sig.state, SignatureState::Valid, "{sig:?}");
    assert!(sig.fingerprint.is_some(), "{sig:?}");
    // The update is the same developer's, as GnuPG can still tell.
    let v2_sig = sam_detect::signature::check(&v2, &sam_detect::signature::GnuPg::Direct);
    assert_eq!(v2_sig.state, SignatureState::Valid, "{v2_sig:?}");
    assert_eq!(v2_sig.fingerprint, sig.fingerprint, "the same key");

    // GnuPG goes missing: every other program stays where SAM finds it.
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    programs_without_gnupg(&bin);
    std::env::set_var("PATH", &bin);
    // The folder and its links belong to the user: SAM runs its programs
    // only because they are named here.
    std::env::set_var("SAM_TRUST_TOOLS_IN", &bin);
    assert!(
        !have("gpg") && !have("gpgv"),
        "GnuPG is out of the search path"
    );
    assert!(
        ["curl", "python3", "objcopy"].iter().all(|t| have(t)),
        "the other programs are still found"
    );
    // The new file's signature really cannot be checked now (the case
    // under test, not another refusal).
    let new_sig = sam_detect::signature::check(&v2, &sam_detect::signature::GnuPg::Direct);
    assert_eq!(new_sig.state, SignatureState::Unchecked, "{new_sig:?}");
    assert!(new_sig.detail.contains("gpgv"), "{new_sig:?}");
    let before = fs::read(&installed).unwrap();

    // Asked first, and nothing changes.
    let Err(err) = sam.update(&id, false) else {
        panic!("the update was installed although its signature could not be checked");
    };
    assert_eq!(
        sam_core::error::code_of(&err),
        Some("signature-unchecked"),
        "asked about the unchecked signature: {err:#}"
    );
    assert_eq!(
        fs::read(&installed).unwrap(),
        before,
        "the installed version is untouched"
    );
    let e = sam.resolve(&id).unwrap();
    assert!(e.update_backup.is_none(), "nothing was replaced");
    assert_eq!(unpacked_version(&sam, &id), "1.0", "version 1 still runs");
    assert!(
        root.join("sam/data/update-consent").join(&id).exists(),
        "the download waits for the answer"
    );

    // A yes covers only the file shown: a newer one published meanwhile
    // is asked about again.
    publish(&server, &v3, "Tool-3.0-x86_64.AppImage");
    let Err(err) = sam.update(&id, true) else {
        panic!("a yes to version 2 installed another file");
    };
    assert_eq!(
        sam_core::error::code_of(&err),
        Some("signature-unchecked"),
        "asked again for the new file: {err:#}"
    );
    assert_eq!(unpacked_version(&sam, &id), "1.0", "version 1 still runs");

    // A yes to exactly the file shown installs it.
    let e = sam
        .update(&id, true)
        .unwrap_or_else(|e| panic!("the accepted update was refused: {e:#}"));
    assert_eq!(fs::read(&e.source_path).unwrap(), fs::read(&v3).unwrap());
    assert_eq!(unpacked_version(&sam, &id), "3.0");
}
