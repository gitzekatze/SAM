//! Updates whose signing time cannot be read, against the local HTTPS
//! server of the update tests (review B2 S6, R94). A stand-in for gpgv
//! hides the time of a good signature; everything else is the real GnuPG.
//!
//! In its own file because it changes the command search path (`PATH`) of
//! the test process: SAM looks for gpgv there.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod gpg_agent;
mod update_common;

use std::fs;
use std::path::Path;
use std::process::Command;

use sam_core::model::SignatureState;
use sam_detect::signature::{check, GnuPg};
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use update_common::{add_reviewed, have, publish, server_or_skip, unpacked_version};

/// Puts a stand-in for gpgv into `bin`: the real `gpgv` run as it is, with
/// the signature time in its `VALIDSIG` line replaced by `-`, as if gpgv had
/// not reported it. Good and bad signatures stay what they are.
fn gpgv_without_time(bin: &Path) {
    let real = sam_core::util::which("gpgv").unwrap();
    let script = format!(
        "#!/bin/sh\nout=$('{}' \"$@\") || exit $?\nprintf '%s\\n' \"$out\" | sed 's/^\\(\\[GNUPG:\\] VALIDSIG [^ ]* [^ ]*\\) [^ ]*/\\1 -/'\n",
        real.display()
    );
    let gpgv = bin.join("gpgv");
    fs::write(&gpgv, script).unwrap();
    fs::set_permissions(&gpgv, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
}

/// When SAM cannot read when the installed version or the download was
/// signed, it cannot tell an older release signed with the same key from a
/// newer one, and nothing older gets through on that guess. An app's update
/// waits for a yes (`signature-unchecked`, the question for a signature SAM
/// cannot check) and changes nothing until then; a yes installs exactly the
/// file shown. SAM's own update is refused, even for a newer release signed
/// with its release key. Runs with SAM_TEST_GPG=1 (CI), where missing GnuPG
/// tools fail it.
#[test]
fn a_signing_time_that_cannot_be_read_lets_no_older_release_through() {
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") {
        sam_runner::contracts::skip("set SAM_TEST_GPG=1 (with gpg, gpgv and objcopy installed)")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    assert!(
        ["gpg", "gpgv", "objcopy", "sed"].iter().all(|t| have(t)),
        "SAM_TEST_GPG=1, but gpg, gpgv, objcopy or sed is not installed"
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
    let gpg = |args: &[&str]| {
        let out = Command::new("gpg")
            .arg("--homedir")
            .arg(&gpg_home)
            .args(["--batch", "--quiet", "--passphrase", ""])
            .args(["--pinentry-mode", "loopback"])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "gpg {} failed", args[0]);
        String::from_utf8(out.stdout).unwrap()
    };
    gpg(&[
        "--faked-system-time",
        "20200101T000000!",
        "--quick-gen-key",
        "Tool Maker <maker@example.invalid>",
        "ed25519",
        "sign",
        "never",
    ]);
    let fingerprint = gpg(&[
        "--with-colons",
        "--fingerprint",
        "--list-keys",
        "maker@example.invalid",
    ])
    .lines()
    .find(|l| l.starts_with("fpr:"))
    .and_then(|l| l.split(':').nth(9))
    .unwrap()
    .to_string();
    let signed = |path: &Path, version: &str, when: &str| {
        let mut spec = FixtureSpec::hello("Tool");
        spec.comment = format!("Tool, version {version}");
        spec.files.push(FixtureFile {
            path: "usr/share/tool/version".into(),
            data: version.as_bytes().to_vec(),
            mode: 0o644,
        });
        spec.update_info = Some(format!("zsync|{url}"));
        spec.signature_sections = true;
        build(path, &spec).unwrap();
        sam_detect::signature::sign_at_for_test(path, &gpg_home, "maker@example.invalid", when)
            .unwrap();
    };

    // SAM's own AppImage (a stand-in, signed with a stand-in release key)
    // and a newer release of it; an app and an older release of it.
    let sam_dir = root.join("sam-appimage");
    fs::create_dir_all(&sam_dir).unwrap();
    let sam_appimage = sam_dir.join("SAM-x86_64.AppImage");
    signed(&sam_appimage, "sam 1", "20260601T000000");
    let sam_newer = root.join("sam-newer.AppImage");
    signed(&sam_newer, "sam 2", "20260701T000000");
    let apps = root.join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let installed = apps.join("Tool-x86_64.AppImage");
    signed(&installed, "2.0", "20260601T000000");
    let old_release = root.join("old.AppImage");
    signed(&old_release, "1.0", "20230101T000000");
    let with_time = check(&installed, &GnuPg::Direct);
    assert!(with_time.signed_at.is_some(), "{with_time:?}");

    // From here on gpgv reports no signing time.
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    gpgv_without_time(&bin);
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs = vec![bin.clone()];
    dirs.extend(std::env::split_paths(&path));
    std::env::set_var("PATH", std::env::join_paths(dirs).unwrap());
    // The stand-in belongs to the user: SAM runs it only because its
    // folder is named here.
    std::env::set_var("SAM_TRUST_TOOLS_IN", &bin);
    assert_eq!(
        sam_core::util::which("gpgv").as_deref(),
        Some(bin.join("gpgv").as_path()),
        "SAM finds the stand-in"
    );
    // The case under test: a good signature by the same key, time unknown.
    for file in [&installed, &old_release, &sam_appimage, &sam_newer] {
        let sig = check(file, &GnuPg::Direct);
        assert_eq!(sig.state, SignatureState::Valid, "{sig:?}");
        assert_eq!(sig.fingerprint, with_time.fingerprint, "the same key");
        assert_eq!(sig.signed_at, None, "{sig:?}");
    }

    // SAM's own update: refused, although the release is newer and signed
    // with the release key, because SAM cannot see that.
    publish(&server, &sam_newer, "SAM-x86_64.AppImage");
    let sam_before = fs::read(&sam_appimage).unwrap();
    let sam =
        sam_runner::ops::Sam::with_paths(sam_core::Paths::rooted(&root.join("self"))).unwrap();
    let err = match sam.self_update_with_keys(&sam_appimage, false, &[&fingerprint]) {
        Ok(done) => panic!(
            "SAM updated itself without knowing when the release was signed: {}",
            done.detail
        ),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("could not read when"), "{err}");
    assert_eq!(
        fs::read(&sam_appimage).unwrap(),
        sam_before,
        "the running SAM stays"
    );
    assert_eq!(
        fs::read_dir(&sam_dir).unwrap().count(),
        1,
        "nothing was put next to it"
    );

    // An app's update: asked first, and nothing changes.
    publish(&server, &old_release, "Tool-x86_64.AppImage");
    let (sam, id) = add_reviewed(&root, &installed);
    let before = fs::read(&installed).unwrap();
    let Err(err) = sam.update(&id, false) else {
        panic!("an update was installed although SAM could not tell whether it is older");
    };
    assert_eq!(
        sam_core::error::code_of(&err),
        Some("signature-unchecked"),
        "asked about the unknown time: {err:#}"
    );
    assert!(
        format!("{err:#}").contains("could not read when"),
        "{err:#}"
    );
    assert_eq!(fs::read(&installed).unwrap(), before, "nothing changed");
    assert!(
        sam.resolve(&id).unwrap().update_backup.is_none(),
        "nothing was replaced"
    );
    assert_eq!(unpacked_version(&sam, &id), "2.0", "version 2 still runs");

    // A yes installs exactly the file shown.
    let e = sam
        .update(&id, true)
        .unwrap_or_else(|e| panic!("the accepted update was refused: {e:#}"));
    assert_eq!(
        fs::read(&e.source_path).unwrap(),
        fs::read(&old_release).unwrap()
    );
    assert_eq!(unpacked_version(&sam, &id), "1.0");
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&gpg_home)
        .args(["--kill", "all"])
        .status();
}
