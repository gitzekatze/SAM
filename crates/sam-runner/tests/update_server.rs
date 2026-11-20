//! Updates end to end, against a local HTTPS server with a throwaway
//! certificate: SAM finds the newer version, downloads only the changed
//! parts (HTTP range requests), checks the result and swaps the file while
//! keeping the old one; a download that does not match the published
//! checksum is refused and leaves nothing behind; plain HTTP is refused,
//! also as the file's address and after a redirect from HTTPS.
//!
//! Needs python3, openssl, objcopy and curl; skipped without them.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use sam_core::model::UpdateState;
use sam_core::Paths;
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

const SERVER: &str = r#"
import http.server, ssl, sys, os, threading
root, cert, key, log = sys.argv[1:5]
class Handler(http.server.SimpleHTTPRequestHandler):
    tag = ""
    def __init__(self, *a, **k):
        super().__init__(*a, directory=root, **k)
    def do_GET(self):
        rng = self.headers.get("Range")
        with open(log, "a") as f:
            f.write(f"{self.tag}{self.path} {rng}\n")
        # /redirect/NAME sends the client to NAME on the plain HTTP server.
        if self.path.startswith("/redirect/"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{plain.server_address[1]}/{self.path[10:]}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = self.translate_path(self.path)
        if not os.path.isfile(path):
            self.send_error(404)
            return
        data = open(path, "rb").read()
        if rng and rng.startswith("bytes="):
            a, b = rng[6:].split("-")
            a = int(a)
            b = int(b) if b else len(data) - 1
            part = data[a:b + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {a}-{a + len(part) - 1}/{len(data)}")
            self.send_header("Content-Length", str(len(part)))
            self.end_headers()
            self.wfile.write(part)
        else:
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    def log_message(self, *a):
        pass
class Plain(Handler):
    tag = "plain "
# The same files over plain HTTP, which SAM must never use.
plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Plain)
threading.Thread(target=plain.serve_forever, daemon=True).start()
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(srv.server_address[1], plain.server_address[1], flush=True)
srv.serve_forever()
"#;

/// The server's certificate is trusted through process-wide variables
/// (CURL_CA_BUNDLE), so the tests of this file run one at a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Server {
    child: Child,
    port: u16,
    /// The same files over plain HTTP.
    plain_port: u16,
    root: PathBuf,
    log: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn have(tool: &str) -> bool {
    sam_core::util::which(tool).is_some()
}

/// A local HTTPS server for `dir`, trusted by curl through CURL_CA_BUNDLE.
fn start_server(tmp: &Path) -> Server {
    let root = tmp.join("www");
    fs::create_dir_all(&root).unwrap();
    let (cert, key) = (tmp.join("cert.pem"), tmp.join("key.pem"));
    let st = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
        ])
        .args(["-addext", "subjectAltName=IP:127.0.0.1"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "openssl could not make a certificate");
    let log = tmp.join("requests.log");
    let mut child = Command::new("python3")
        .args(["-c", SERVER])
        .arg(&root)
        .arg(&cert)
        .arg(&key)
        .arg(&log)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let mut ports = line
        .split_whitespace()
        .map(|p| p.parse().expect("the server prints its ports"));
    let (port, plain_port) = (ports.next().unwrap(), ports.next().unwrap());
    // curl (which SAM uses for downloads) trusts the test certificate.
    std::env::set_var("CURL_CA_BUNDLE", &cert);
    // The same result behind any proxy of the person running it.
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    std::env::set_var("no_proxy", "127.0.0.1,localhost");
    // SAM's curl never reads a ~/.curlrc: one that sends every request to a
    // dead proxy changes nothing (curl looks in CURL_HOME first).
    let curl_home = tmp.join("curl-home");
    fs::create_dir_all(&curl_home).unwrap();
    fs::write(
        curl_home.join(".curlrc"),
        "proxy = \"http://127.0.0.1:9\"\nnoproxy = \"\"\n",
    )
    .unwrap();
    std::env::set_var("CURL_HOME", &curl_home);
    Server {
        child,
        port,
        plain_port,
        root,
        log,
    }
}

/// A test AppImage whose update information points at `url`; `version`
/// changes its contents.
fn appimage(path: &Path, url: &str, version: &str) {
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
    build(path, &spec).unwrap();
}

/// Publishes `file` as `name` with its .zsync update description.
fn publish(server: &Server, file: &Path, name: &str) {
    fs::copy(file, server.root.join(name)).unwrap();
    let zsync =
        sam_runner::zsync::make(file, name, name, "Tue, 10 Nov 2026 10:00:00 +0000").unwrap();
    fs::write(server.root.join("Tool-x86_64.AppImage.zsync"), zsync).unwrap();
}

#[test]
fn updates_download_only_changes_check_them_and_refuse_tampering() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    if !["python3", "openssl", "objcopy", "curl"]
        .iter()
        .all(|t| have(t))
    {
        sam_runner::contracts::skip("needs python3, openssl, objcopy and curl")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts =
        sam_runner::contracts::guard(&["updates-curl"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let server = start_server(tmp.path());
    let url = format!(
        "https://127.0.0.1:{}/Tool-x86_64.AppImage.zsync",
        server.port
    );
    let apps = tmp.path().join("Applications");
    fs::create_dir_all(&apps).unwrap();

    // Version 1 is installed, version 2 is published.
    let v1 = apps.join("Tool-1.0-x86_64.AppImage");
    appimage(&v1, &url, "1.0");
    let v2 = tmp.path().join("v2.AppImage");
    appimage(&v2, &url, "2.0");
    publish(&server, &v2, "Tool-2.0-x86_64.AppImage");

    let paths = Paths::rooted(&tmp.path().join("sam"));
    let sam = Sam::with_paths(paths.clone()).unwrap();
    let id = sam
        .add(
            &v1,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;

    let checks = sam.check_updates(Some(&id), false).unwrap();
    assert_eq!(
        checks[0].1.state,
        UpdateState::Available,
        "{}",
        checks[0].1.detail
    );

    let e = sam.update(&id, false).unwrap();
    // SAM's own update is not taken for a file swapped outside SAM.
    assert!(!e.content_changed_outside, "an update by SAM is not marked");
    assert_eq!(
        fs::read(&e.source_path).unwrap(),
        fs::read(&v2).unwrap(),
        "the new file is exactly the published one"
    );
    let backup = e.update_backup.as_ref().expect("the old version is kept");
    assert!(backup.file.is_file(), "the old version can be restored");
    let log = fs::read_to_string(&server.log).unwrap();
    assert!(
        log.lines().any(|l| l.contains("bytes=")),
        "only the changed parts were downloaded:\n{log}"
    );
    // The delta itself worked: SAM did not have to fall back to fetching
    // the whole file (which it does when a delta goes wrong).
    assert!(
        !log.lines().any(|l| l.ends_with(".AppImage None")),
        "the update was put together from the changed parts, not fetched whole:\n{log}"
    );
    let checks = sam.check_updates(Some(&id), false).unwrap();
    assert_eq!(
        checks[0].1.state,
        UpdateState::Current,
        "{}",
        checks[0].1.detail
    );

    // Version 3 is published, but the server hands out a damaged file: it
    // does not match the published checksum, so nothing changes.
    let v3 = tmp.path().join("v3.AppImage");
    appimage(&v3, &url, "3.0");
    publish(&server, &v3, "Tool-3.0-x86_64.AppImage");
    let mut damaged = fs::read(&v3).unwrap();
    // Damage a byte where version 3 differs from version 2: SAM must
    // download that part (an unchanged part is taken from the old file).
    let v2_bytes = fs::read(&v2).unwrap();
    let at = (0..damaged.len().min(v2_bytes.len()))
        .rev()
        .find(|&i| damaged[i] != v2_bytes[i])
        .expect("versions 2 and 3 differ");
    damaged[at] ^= 0xff;
    fs::write(server.root.join("Tool-3.0-x86_64.AppImage"), &damaged).unwrap();
    let before = fs::read(&e.source_path).unwrap();
    let err = sam.update(&id, false).unwrap_err();
    assert!(format!("{err:#}").contains("checksum"), "{err:#}");
    assert_eq!(
        fs::read(&e.source_path).unwrap(),
        before,
        "the installed version is untouched"
    );
    let leftovers: Vec<_> = fs::read_dir(&apps)
        .unwrap()
        .flatten()
        .filter(|f| f.file_name().to_string_lossy().contains("sam-download"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no half-downloaded file is left: {leftovers:?}"
    );

    // An update source over plain HTTP is refused.
    let plain = apps.join("Plain-x86_64.AppImage");
    appimage(
        &plain,
        &format!(
            "http://127.0.0.1:{}/Tool-x86_64.AppImage.zsync",
            server.port
        ),
        "1.0",
    );
    let status = sam_runner::updates::check(&plain);
    assert_ne!(status.state, UpdateState::Available);
    assert!(
        status.detail.to_lowercase().contains("https"),
        "{}",
        status.detail
    );
}

/// Starts the server and returns it with the update URL, or `None` where
/// the tools are missing (a skip that fails under SAM_REQUIRE_SANDBOX).
fn server_or_skip(tmp: &Path) -> Option<(Server, String)> {
    if !["python3", "openssl", "objcopy", "curl"]
        .iter()
        .all(|t| have(t))
    {
        sam_runner::contracts::skip("needs python3, openssl, objcopy and curl")
            .unwrap_or_else(|e| panic!("{e}"));
        return None;
    }
    let server = start_server(tmp);
    let url = format!(
        "https://127.0.0.1:{}/Tool-x86_64.AppImage.zsync",
        server.port
    );
    Some((server, url))
}

/// Regressions (audit U-H4, U-H3): updates were downloaded next to the
/// AppImage under a guessable name (`.<name>.sam-download`) with tools that
/// follow links, so an app with write access to that folder (often
/// Downloads) could plant a link there and SAM wrote the update through it
/// into any file of the person. And an update silently took the new
/// version's recommendation: a version that declares itself a network app
/// got the network without a question. Now the download happens in SAM's
/// own folder, nothing is written through a link, and an update keeps the
/// sandbox it had; what the new version asks for more is only shown.
#[test]
fn an_update_writes_through_no_planted_link_and_keeps_the_sandbox() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let Some((server, url)) = server_or_skip(tmp.path()) else {
        return;
    };
    let apps = tmp.path().join("Downloads");
    fs::create_dir_all(&apps).unwrap();
    let v1 = apps.join("Tool-1.0-x86_64.AppImage");
    appimage(&v1, &url, "1.0");
    // Version 2 declares itself a network app.
    let v2 = tmp.path().join("v2.AppImage");
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = "Tool, version 2.0".into();
    spec.categories = "Network;Chat;".into();
    spec.files.push(FixtureFile {
        path: "usr/share/tool/data.bin".into(),
        data: vec![7u8; 300_000],
        mode: 0o644,
    });
    spec.update_info = Some(format!("zsync|{url}"));
    build(&v2, &spec).unwrap();
    publish(&server, &v2, "Tool-2.0-x86_64.AppImage");

    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = sam
        .add(
            &v1,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let before = sam.resolve(&id).unwrap().profile.permissions;
    assert_ne!(
        before.network.mode,
        sam_core::permissions::NetworkMode::Full,
        "version 1 starts without the network"
    );

    // Another app with access to Downloads plants links under every name
    // the old code downloaded to.
    let victim = tmp.path().join("victim.txt");
    fs::write(&victim, "the person's file").unwrap();
    for n in [
        ".Tool-2.0-x86_64.AppImage.sam-download",
        ".Tool-1.0-x86_64.AppImage.sam-download",
    ] {
        std::os::unix::fs::symlink(&victim, apps.join(n)).unwrap();
    }

    let e = sam.update(&id, false).unwrap();
    assert_eq!(
        fs::read_to_string(&victim).unwrap(),
        "the person's file",
        "nothing was written through a planted link"
    );
    assert!(
        fs::symlink_metadata(&e.source_path)
            .unwrap()
            .file_type()
            .is_file(),
        "the new version is a plain file"
    );
    assert_eq!(fs::read(&e.source_path).unwrap(), fs::read(&v2).unwrap());
    assert_eq!(
        e.profile.permissions, before,
        "the update kept the sandbox it had"
    );
    assert!(
        e.pending_changes.iter().any(|c| c == "network"),
        "what the new version asks for more is shown: {:?}",
        e.pending_changes
    );
    assert!(
        !tmp.path()
            .join("sam")
            .join("data")
            .join("downloads")
            .join(&id)
            .exists(),
        "the download folder is cleaned up"
    );
}

/// Regression (audit U-H5): when the new version had the same file name as
/// the old one, going back moved the current file onto the kept old version
/// (destroying it), then "restored" the new file and reported that the app
/// was back. Now going back puts the old version back and keeps the newer
/// one, and going back again returns to the newer one.
#[test]
fn going_back_with_an_unchanged_file_name_keeps_both_versions() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let Some((server, url)) = server_or_skip(tmp.path()) else {
        return;
    };
    let apps = tmp.path().join("Applications");
    fs::create_dir_all(&apps).unwrap();
    // The same name for both versions, as many projects publish.
    let installed = apps.join("Tool-x86_64.AppImage");
    appimage(&installed, &url, "1.0");
    let v1 = fs::read(&installed).unwrap();
    let v2_file = tmp.path().join("v2.AppImage");
    appimage(&v2_file, &url, "2.0");
    publish(&server, &v2_file, "Tool-x86_64.AppImage");
    let v2 = fs::read(&v2_file).unwrap();

    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = sam
        .add(
            &installed,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let e = sam.update(&id, false).unwrap();
    assert_eq!(e.source_path, installed);
    assert_eq!(fs::read(&installed).unwrap(), v2, "updated");

    let e = sam.undo_update(&id).unwrap();
    assert_eq!(
        fs::read(&e.source_path).unwrap(),
        v1,
        "the old version is back"
    );
    let kept = e.update_backup.as_ref().expect("the newer one is kept");
    assert_eq!(
        fs::read(&kept.file).unwrap(),
        v2,
        "the newer version is kept"
    );

    let e = sam.undo_update(&id).unwrap();
    assert_eq!(fs::read(&e.source_path).unwrap(), v2, "and back again");
    let kept = e.update_backup.as_ref().unwrap();
    assert_eq!(fs::read(&kept.file).unwrap(), v1);
}

/// Regression (audit U-M6): whoever controls the download could hand out an
/// older, validly signed release (with holes fixed since) as the update:
/// any file other than the installed one counted as newer. A signed update
/// signed earlier than the installed version is now refused, and nothing
/// changes. With the real GnuPG (SAM_TEST_GPG=1).
#[test]
fn an_older_signed_version_is_not_installed_as_an_update() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") {
        eprintln!("skipping: set SAM_TEST_GPG=1 (with gpg and gpgv installed)");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((server, url)) = server_or_skip(tmp.path()) else {
        return;
    };
    let home = tmp.path().join("gnupg");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let st = Command::new("gpg")
        .arg("--homedir")
        .arg(&home)
        .args([
            "--batch",
            "--quiet",
            "--passphrase",
            "",
            "--pinentry-mode",
            "loopback",
        ])
        .args(["--faked-system-time", "20200101T000000!"])
        .args([
            "--quick-gen-key",
            "Tool Maker <maker@example.invalid>",
            "ed25519",
            "sign",
            "never",
        ])
        .status()
        .unwrap();
    assert!(st.success());

    // The installed version was signed in 2026, the "update" in 2023.
    let apps = tmp.path().join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let installed = apps.join("Tool-x86_64.AppImage");
    let signed = |path: &Path, version: &str, when: &str| {
        let mut spec = FixtureSpec::hello("Tool");
        spec.comment = format!("Tool, version {version}");
        spec.update_info = Some(format!("zsync|{url}"));
        spec.signature_sections = true;
        build(path, &spec).unwrap();
        sam_detect::signature::sign_at_for_test(path, &home, "maker@example.invalid", when)
            .unwrap();
    };
    signed(&installed, "2.0", "20260601T000000");
    let old_release = tmp.path().join("old.AppImage");
    signed(&old_release, "1.0", "20230101T000000");
    publish(&server, &old_release, "Tool-x86_64.AppImage");
    let before = fs::read(&installed).unwrap();

    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = sam
        .add(
            &installed,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let e = sam.update(&id, false).unwrap_err().to_string();
    assert!(e.contains("older version"), "{e}");
    assert_eq!(fs::read(&installed).unwrap(), before, "nothing changed");
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&home)
        .args(["--kill", "all"])
        .status();
}

/// Updates come over HTTPS only, wherever the address comes from (audit
/// B22, verification audit 2026-11-19: no test noticed the download's own
/// check gone, and none tried a redirect). The same newer version is
/// published on a plain HTTP server too, so an update that took HTTP would
/// succeed and the test would see it.
#[test]
fn an_update_never_comes_over_plain_http() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let Some((server, url)) = server_or_skip(tmp.path()) else {
        return;
    };
    let _contracts =
        sam_runner::contracts::guard(&["updates-curl"]).unwrap_or_else(|e| panic!("{e}"));
    let apps = tmp.path().join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let v1 = apps.join("Tool-1.0-x86_64.AppImage");
    appimage(&v1, &url, "1.0");
    let v2 = tmp.path().join("v2.AppImage");
    appimage(&v2, &url, "2.0");
    let name = "Tool-2.0-x86_64.AppImage";
    fs::copy(&v2, server.root.join(name)).unwrap();
    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = sam
        .add(
            &v1,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let before = fs::read(&v1).unwrap();
    let describe = |file_url: &str| {
        let z = sam_runner::zsync::make(&v2, name, file_url, "Tue, 10 Nov 2026 10:00:00 +0000")
            .unwrap();
        fs::write(server.root.join("Tool-x86_64.AppImage.zsync"), z).unwrap();
    };

    // 1. The update description names the file at a plain HTTP address.
    describe(&format!("http://127.0.0.1:{}/{name}", server.plain_port));
    let checks = sam.check_updates(Some(&id), false).unwrap();
    assert_ne!(
        checks[0].1.state,
        UpdateState::Available,
        "{}",
        checks[0].1.detail
    );
    assert!(
        checks[0].1.detail.contains("HTTPS"),
        "{}",
        checks[0].1.detail
    );
    assert!(
        sam.update(&id, false).is_err(),
        "no update from an http:// file"
    );

    // 2. An HTTPS address that redirects to plain HTTP.
    describe(&format!("redirect/{name}"));
    let checks = sam.check_updates(Some(&id), false).unwrap();
    assert_eq!(
        checks[0].1.state,
        UpdateState::Available,
        "the description itself is fine: {}",
        checks[0].1.detail
    );
    let err = sam.update(&id, false).unwrap_err();
    let log = fs::read_to_string(&server.log).unwrap();
    assert!(
        log.lines().any(|l| l.starts_with("/redirect/")),
        "SAM asked the HTTPS address, which redirected:\n{log}"
    );
    assert!(
        !log.lines().any(|l| l.starts_with("plain ")),
        "SAM never followed the redirect to plain HTTP ({err:#}):\n{log}"
    );

    assert_eq!(
        fs::read(&v1).unwrap(),
        before,
        "the installed version is untouched"
    );
}

/// A new signing key: refused until the person accepts it (audit B24;
/// verification audit 2026-11-19: only a unit test of the comparison
/// showed this). Version 1 is signed with one key and installed; version 2
/// is published, signed with another. The update is refused and the
/// download deleted; accepting the change lets it through. Runs with
/// SAM_TEST_GPG=1 (CI), where missing GnuPG tools fail it.
#[test]
fn an_update_signed_with_another_key_waits_for_consent() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    if std::env::var("SAM_TEST_GPG").as_deref() != Ok("1") {
        eprintln!("skipping: set SAM_TEST_GPG=1 (with gpg, gpgv and objcopy installed)");
        return;
    }
    assert!(
        ["gpg", "gpgv", "objcopy"].iter().all(|t| have(t)),
        "SAM_TEST_GPG=1, but gpg, gpgv or objcopy is not installed"
    );
    let tmp = tempfile::tempdir().unwrap();
    let Some((server, url)) = server_or_skip(tmp.path()) else {
        return;
    };
    let gpg_home = tmp.path().join("gnupg");
    fs::create_dir(&gpg_home).unwrap();
    fs::set_permissions(
        &gpg_home,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let gpg = |args: &[&str]| {
        let out = Command::new("gpg")
            .arg("--homedir")
            .arg(&gpg_home)
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
        String::from_utf8(out.stdout).unwrap()
    };
    for uid in [
        "First Key <first@example.invalid>",
        "Second Key <second@example.invalid>",
    ] {
        gpg(&["--quick-gen-key", uid, "ed25519", "sign", "never"]);
    }
    let signed = |path: &Path, version: &str, key: &str| {
        let mut spec = FixtureSpec::hello("Tool");
        spec.comment = format!("Tool, version {version}");
        spec.files.push(FixtureFile {
            path: "usr/share/tool/data.bin".into(),
            data: vec![7u8; 300_000],
            mode: 0o644,
        });
        spec.update_info = Some(format!("zsync|{url}"));
        spec.signature_sections = true;
        build(path, &spec).unwrap();
        sam_detect::signature::sign_for_test(path, &gpg_home, key).unwrap();
    };

    let apps = tmp.path().join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let v1 = apps.join("Tool-1.0-x86_64.AppImage");
    signed(&v1, "1.0", "first@example.invalid");
    let v2 = tmp.path().join("v2.AppImage");
    signed(&v2, "2.0", "second@example.invalid");
    publish(&server, &v2, "Tool-2.0-x86_64.AppImage");

    let sam = Sam::with_paths(Paths::rooted(&tmp.path().join("sam"))).unwrap();
    let id = sam
        .add(
            &v1,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let sig = sam.resolve(&id).unwrap().signature.unwrap();
    assert_eq!(sig.state, sam_core::model::SignatureState::Valid, "{sig:?}");
    let before = fs::read(&v1).unwrap();

    let err = sam.update(&id, false).unwrap_err();
    assert!(
        format!("{err:#}").contains("signing key changed"),
        "refused for the new key: {err:#}"
    );
    assert_eq!(
        fs::read(&v1).unwrap(),
        before,
        "the installed version is untouched"
    );
    let leftovers: Vec<_> = fs::read_dir(&apps)
        .unwrap()
        .flatten()
        .filter(|f| f.path() != v1)
        .map(|f| f.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "the download was deleted: {leftovers:?}"
    );

    // Accepted: the update goes through.
    let e = sam.update(&id, true).unwrap();
    assert_eq!(fs::read(&e.source_path).unwrap(), fs::read(&v2).unwrap());
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&gpg_home)
        .args(["--kill", "all"])
        .status();
}
