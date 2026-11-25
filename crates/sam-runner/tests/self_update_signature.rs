//! SAM's self-update check end to end with the real GnuPG (threat-model
//! row 61): a downloaded SAM is accepted only when its embedded signature
//! was really made with a release key. The unit test in release_key.rs
//! covers the decision on hand-made results; this one runs the signature
//! check that feeds it, including the forgery of audit finding C1.
//!
//! Runs only with SAM_TEST_GPG=1 (CI sets it; then missing tools fail the
//! test instead of skipping it). Needs gpg, gpgv and objcopy.
//!
//! The whole self-update runs too, against a local HTTPS server
//! (update_common; also needs python3, openssl and curl): SAM works from a
//! copy of its AppImage in its own folder, and one update of SAM runs at a
//! time (review B2 S6, R87 and R95).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod gpg_agent;
mod update_common;

use std::path::{Path, PathBuf};
use std::process::Command;

use sam_detect::signature::{check, sign_for_test, sign_with_key_block_for_test, GnuPg};
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
    assert!(out.status.success(), "gpg {} failed", args[0]);
    out.stdout
}

fn new_key(home: &Path, signer: &str, email: &str) -> String {
    gpg(
        home,
        &["--quick-gen-key", signer, "ed25519", "sign", "never"],
    );
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
    let _agent = gpg_agent::Stop::new(&home);
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
    assert!(release_key::check(&check(&genuine, &GnuPg::Direct), &keys).is_ok());

    let forged = download(dir, "SAM-forged.AppImage");
    let mut block = gpg(&home, &["--armor", "--export", "release@example.invalid"]);
    block.extend(gpg(
        &home,
        &["--armor", "--export", "attacker@example.invalid"],
    ));
    sign_with_key_block_for_test(&forged, &home, "attacker@example.invalid", &block).unwrap();
    let e = release_key::check(&check(&forged, &GnuPg::Direct), &keys)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("changed after signing") || e.contains("not installed"),
        "{e}"
    );

    let other = download(dir, "SAM-other.AppImage");
    sign_for_test(&other, &home, "attacker@example.invalid").unwrap();
    let e = release_key::check(&check(&other, &GnuPg::Direct), &keys)
        .unwrap_err()
        .to_string();
    assert!(e.contains("not with SAM's release key"), "{e}");

    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&home)
        .args(["--kill", "all"])
        .status();
}

/// The local server sets process-wide variables (CURL_CA_BUNDLE): the
/// tests that use it run one at a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A stand-in for SAM's releases: a GnuPG home with a release key made in
/// 2020 (so signatures dated later are valid), and the update address of
/// the local server. None where SAM_TEST_GPG is not set.
struct Releases {
    _agent: gpg_agent::Stop,
    home: PathBuf,
    key: String,
    server: update_common::Server,
    url: String,
}

fn releases(dir: &Path) -> Option<Releases> {
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") {
        eprintln!("skipping: set SAM_TEST_GPG=1 (with gpg, gpgv and objcopy installed)");
        return None;
    }
    assert!(
        ["gpg", "gpgv", "objcopy"]
            .iter()
            .all(|t| sam_core::util::which(t).is_some()),
        "SAM_TEST_GPG=1, but gpg, gpgv or objcopy is not installed"
    );
    let (server, url) = update_common::server_or_skip(dir)?;
    let home = dir.join("gnupg");
    std::fs::create_dir(&home).unwrap();
    let agent = gpg_agent::Stop::new(&home);
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    gpg(
        &home,
        &[
            "--faked-system-time",
            "20200101T000000!",
            "--quick-gen-key",
            "SAM Release <release@example.invalid>",
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
            "release@example.invalid",
        ],
    ))
    .unwrap();
    let key = listing
        .lines()
        .find(|l| l.starts_with("fpr:"))
        .and_then(|l| l.split(':').nth(9))
        .unwrap()
        .to_string();
    Some(Releases {
        _agent: agent,
        home,
        key,
        server,
        url,
    })
}

impl Releases {
    /// A SAM `version` at `path`, signed with the release key on `when`,
    /// whose update information names the local server. Most of the file
    /// is 1 MB of data that cannot be compressed, made from `seed`: SAMs
    /// with the same seed share it, so a partial download is worth it.
    fn sam(&self, path: &Path, version: &str, when: &str, seed: u64) {
        let mut x = seed;
        let data = (0..1_000_000)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (x >> 56) as u8
            })
            .collect();
        let mut spec = sam_intake::testkit::FixtureSpec::hello("SAM");
        spec.comment = format!("SAM, version {version}");
        spec.files.push(sam_intake::testkit::FixtureFile {
            path: "usr/share/sam/data.bin".into(),
            data,
            mode: 0o644,
        });
        spec.files.push(sam_intake::testkit::FixtureFile {
            path: "usr/share/sam/version".into(),
            data: version.as_bytes().to_vec(),
            mode: 0o644,
        });
        spec.update_info = Some(format!("zsync|{}", self.url));
        spec.signature_sections = true;
        sam_intake::testkit::build(path, &spec).unwrap();
        sam_detect::signature::sign_at_for_test(path, &self.home, "release@example.invalid", when)
            .unwrap();
    }

    fn requests(&self) -> usize {
        std::fs::read_to_string(&self.server.log)
            .unwrap_or_default()
            .lines()
            .count()
    }
}

impl Drop for Releases {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.home)
            .args(["--kill", "all"])
            .status();
    }
}

/// Regression (review B2 S6, R87): SAM's update of itself read its
/// AppImage in the person's folder while it worked: the update information,
/// the old blocks of a partial download (mapped into memory, where a file
/// shortened meanwhile crashes SAM) and the running version's signature.
/// Now it takes a copy in its own folder first and reads only that. Here
/// the file in the person's folder is replaced by a later signed SAM with
/// other data as soon as SAM asks the server: read from there, the
/// published release would look older than the running SAM and be
/// refused, and none of its blocks would fit a partial download.
#[test]
fn sam_updates_itself_from_its_own_copy_even_if_the_file_is_replaced() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let Some(r) = releases(tmp.path()) else {
        return;
    };
    let apps = tmp.path().join("Applications");
    std::fs::create_dir_all(&apps).unwrap();
    let running = apps.join("SAM-x86_64.AppImage");
    r.sam(&running, "1.0", "20260101T000000", 1);
    let release = tmp.path().join("v2.AppImage");
    r.sam(&release, "2.0", "20260601T000000", 1);
    update_common::publish(&r.server, &release, "SAM-2.0-x86_64.AppImage");
    let later = tmp.path().join("later.AppImage");
    r.sam(&later, "1.1", "20260901T000000", 2);
    let hook = tmp.path().join("swap-on-request");
    std::fs::write(&hook, format!("{}\n{}", later.display(), running.display())).unwrap();

    let paths = sam_core::Paths::rooted(&tmp.path().join("sam"));
    let sam = sam_runner::ops::Sam::with_paths(paths.clone()).unwrap();
    let done = sam
        .self_update_with_keys(&running, false, &[r.key.as_str()])
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        !hook.exists(),
        "the file was replaced while SAM was working"
    );
    assert_eq!(done.state, "updated", "{}", done.detail);
    assert_eq!(
        std::fs::read(&done.path).unwrap(),
        std::fs::read(&release).unwrap(),
        "the new SAM is exactly the published one"
    );
    let log = std::fs::read_to_string(&r.server.log).unwrap();
    assert!(
        log.lines().any(|l| l.contains(".AppImage bytes=")),
        "only the changed parts were downloaded:\n{log}"
    );
    assert!(
        !log.lines().any(|l| l.ends_with(".AppImage None")),
        "the update was put together from the copy's blocks, not fetched whole:\n{log}"
    );
    let backup = paths
        .data_dir
        .join("update-backups/sam/SAM-x86_64.AppImage");
    assert!(backup.is_file(), "the file in the person's folder is kept");
    assert!(
        !paths.data_dir.join("downloads/sam.installed").exists(),
        "the copy is removed once SAM is done"
    );
}

/// Regression (review B2 S6, R95): two updates of SAM at once (the window
/// and the command line) shared their download and backup folders and
/// deleted each other's files, the backup of the old SAM among them. While
/// one runs (its lock is held here), a second is refused at once and
/// touches nothing; a check still works. Once the first ends, an update
/// goes through.
#[test]
fn a_second_update_of_sam_is_refused_while_one_runs() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let Some(r) = releases(tmp.path()) else {
        return;
    };
    let apps = tmp.path().join("Applications");
    std::fs::create_dir_all(&apps).unwrap();
    let running = apps.join("SAM-x86_64.AppImage");
    r.sam(&running, "1.0", "20260101T000000", 1);
    let release = tmp.path().join("v2.AppImage");
    r.sam(&release, "2.0", "20260601T000000", 1);
    update_common::publish(&r.server, &release, "SAM-2.0-x86_64.AppImage");
    let keys = [r.key.as_str()];

    let paths = sam_core::Paths::rooted(&tmp.path().join("sam"));
    let sam = sam_runner::ops::Sam::with_paths(paths.clone()).unwrap();
    // What the update that runs has in SAM's folders.
    let its_files = [
        "update-backups/sam/SAM-0.9-x86_64.AppImage",
        "downloads/sam/SAM-2.0-x86_64.AppImage",
        "downloads/sam.installed/sam.AppImage",
    ]
    .map(|f| paths.data_dir.join(f));
    for f in &its_files {
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, b"the other update's file").unwrap();
    }
    let held = sam_runner::app_lock::for_self_update(&paths)
        .unwrap()
        .expect("the stand-in for the update that runs");

    let check = sam
        .self_update_with_keys(&running, true, &keys)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(check.state, "available", "a check needs no lock");
    let before = std::fs::read(&running).unwrap();
    let asked = r.requests();
    let t = std::time::Instant::now();
    let e = sam
        .self_update_with_keys(&running, false, &keys)
        .expect_err("a second update while one runs");
    assert!(
        format!("{e:#}").contains("already updating itself"),
        "{e:#}"
    );
    assert!(
        t.elapsed() < std::time::Duration::from_secs(2),
        "refused at once, after {:?}",
        t.elapsed()
    );
    for f in &its_files {
        assert_eq!(
            std::fs::read(f).ok().as_deref(),
            Some(&b"the other update's file"[..]),
            "{} is untouched",
            f.display()
        );
    }
    assert_eq!(std::fs::read(&running).unwrap(), before, "SAM is unchanged");
    assert_eq!(
        std::fs::read_dir(&apps).unwrap().count(),
        1,
        "nothing new in SAM's folder"
    );
    assert_eq!(r.requests(), asked, "nothing was downloaded");

    drop(held);
    let done = sam
        .self_update_with_keys(&running, false, &keys)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(done.state, "updated", "{}", done.detail);
}
