//! What SAM sends when the person asks for an update check and an update,
//! recorded by the local HTTPS server of the update tests
//! (`update_common`), which writes down every request whatever its method.
//!
//! In its own file because the server sets process-wide variables
//! (`update_common::start_server`).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

mod update_common;

use std::fs;

use update_common::{add_reviewed, appimage, server_or_skip, unpacked_version};

/// Whether `word` stands in `text` as a whole: not next to a letter, a
/// digit or a dot (so SAM's version `0.1.0` is not found inside `10.1.0`).
fn names(text: &str, word: &str) -> bool {
    let fits = |c: Option<char>| c.is_none_or(|c| !(c.is_alphanumeric() || c == '.'));
    text.match_indices(word).any(|(i, _)| {
        fits(text[..i].chars().next_back()) && fits(text[i + word.len()..].chars().next())
    })
}

/// For an app whose update source is a `.zsync` address, reached through
/// a redirect to another address on the same HTTPS server: the update
/// check, then the update (a part of the new version, which the server
/// answers with the whole file, then the whole file) send exactly this and
/// nothing else. Every request is a GET for one of the listed paths, with
/// no query, over HTTPS. Its headers are exactly `Host`, `User-Agent` and
/// `Accept`, each once, and at most one `Range`, with exact values
/// (`User-Agent: SAM-AppImage-update-check`; `Accept` either
/// `application/json, */*` or `*/*`; `Range: bytes=<digits>-<digits>`).
/// No request names the user, the login, this computer's name, the home,
/// the test's folder, the app's record, the installed file's name or SAM's
/// version (the address itself names the app, as every update check must).
/// All three kinds are seen: a description, a part, a whole file. The
/// request line may say HTTP/1.1 or HTTP/1.0: the stand-in answers in 1.0,
/// and curl then speaks 1.0 to it after the redirect.
#[test]
fn update_requests_carry_nothing_about_the_person_or_their_apps() {
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    sam_runner::testenv::isolate_this_process(&root);
    let Some((server, _)) = server_or_skip(&root) else {
        return;
    };
    let _contracts =
        sam_runner::contracts::guard(&["updates-curl"]).unwrap_or_else(|e| panic!("{e}"));
    // The app names the redirect; the update description names a file next
    // to it, so that file is reached through the redirect too.
    let url = format!(
        "https://127.0.0.1:{}/redirect-https/Tool-x86_64.AppImage.zsync",
        server.port
    );
    let apps = root.join("Applications");
    fs::create_dir_all(&apps).unwrap();
    let v1 = apps.join("Tool-1.0-x86_64.AppImage");
    appimage(&v1, &url, "1.0");
    // Version 2 is published; its update description sends SAM to
    // norange/, where the server answers a request for a part with the
    // whole file, so SAM also downloads the whole file once: all three
    // kinds of request SAM makes (the description, a part, the file).
    let v2 = root.join("v2.AppImage");
    appimage(&v2, &url, "2.0");
    let name = "Tool-2.0-x86_64.AppImage";
    fs::copy(&v2, server.root.join(name)).unwrap();
    let zsync = sam_runner::zsync::make(
        &v2,
        name,
        &format!("norange/{name}"),
        "Tue, 10 Nov 2026 10:00:00 +0000",
    )
    .unwrap();
    fs::write(server.root.join("Tool-x86_64.AppImage.zsync"), zsync).unwrap();

    let (sam, id) = add_reviewed(&root, &v1);
    let checks = sam.check_updates(Some(&id), false).unwrap();
    assert_eq!(
        checks[0].1.state,
        sam_core::model::UpdateState::Available,
        "{}",
        checks[0].1.detail
    );
    sam.update(&id, false)
        .unwrap_or_else(|e| panic!("the update failed: {e:#}"));
    assert_eq!(
        unpacked_version(&sam, &id),
        "2.0",
        "the update was installed"
    );

    let log = format!("{}.headers", server.log.display());
    let requests: Vec<serde_json::Value> = fs::read_to_string(&log)
        .unwrap_or_else(|e| panic!("the server wrote no request log {log}: {e}"))
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let allowed_paths = [
        "/redirect-https/Tool-x86_64.AppImage.zsync".to_string(),
        "/Tool-x86_64.AppImage.zsync".to_string(),
        format!("/redirect-https/norange/{name}"),
        format!("/norange/{name}"),
    ];
    let host = format!("127.0.0.1:{}", server.port);
    // What would identify the person, this computer or the app, where it
    // is long enough to be told apart from an address.
    let home = std::env::var("HOME").unwrap_or_default();
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let secrets: Vec<(String, &str)> = [
        (std::env::var("USER").unwrap_or_default(), "the user name"),
        (
            std::env::var("LOGNAME").unwrap_or_default(),
            "the login name",
        ),
        (hostname.trim().to_string(), "this computer's name"),
        (home, "the home folder"),
        (root.display().to_string(), "the test's folder"),
        (id.clone(), "the app's record"),
        ("Tool-1.0".to_string(), "the installed version's file name"),
        (sam_core::SAM_VERSION.to_string(), "SAM's version"),
    ]
    .into_iter()
    .filter(|(s, _)| s.len() >= 3)
    .collect();

    let (mut descriptions, mut parts, mut whole, mut redirected) = (0, 0, 0, 0);
    for r in &requests {
        let tag = r["tag"].as_str().unwrap();
        let line = r["line"].as_str().unwrap();
        assert_eq!(tag, "", "a request went over plain HTTP: {r}");
        let path = line
            .strip_prefix("GET ")
            // The stand-in answers in HTTP/1.0, and curl then speaks 1.0
            // to it after a redirect.
            .and_then(|l| {
                l.strip_suffix(" HTTP/1.1")
                    .or_else(|| l.strip_suffix(" HTTP/1.0"))
            })
            .unwrap_or_else(|| panic!("not a plain GET request: {line}"));
        assert!(
            allowed_paths.iter().any(|p| p == path),
            "SAM asked for {path}, which is not one of the listed paths {allowed_paths:?} (a query or another file)"
        );
        let headers: Vec<(String, String)> = r["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                (
                    h[0].as_str().unwrap().to_string(),
                    h[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let count = |k: &str| {
            headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(k))
                .count()
        };
        for k in ["host", "user-agent", "accept"] {
            assert_eq!(
                count(k),
                1,
                "{path} carries the header {k} {} times, not once",
                count(k)
            );
        }
        assert!(
            count("range") <= 1,
            "{path} carries more than one Range header"
        );
        assert_eq!(
            headers.len(),
            3 + count("range"),
            "{path} carries other headers than Host, User-Agent, Accept and Range: {headers:?}"
        );
        let mut range = false;
        for (k, v) in &headers {
            match k.to_ascii_lowercase().as_str() {
                "host" => assert_eq!(v, &host, "the Host header of {path}"),
                "user-agent" => assert_eq!(
                    v, "SAM-AppImage-update-check",
                    "the user agent of {path} is not SAM's fixed one"
                ),
                "accept" => assert!(
                    v == "*/*" || v == "application/json, */*",
                    "the Accept header of {path}: {v}"
                ),
                _ => {
                    range = true;
                    let spec = v.strip_prefix("bytes=").unwrap_or("");
                    let ends: Vec<&str> = spec.split('-').collect();
                    assert!(
                        ends.len() == 2
                            && ends
                                .iter()
                                .all(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())),
                        "the Range header of {path}: {v}"
                    );
                }
            }
            for (s, what) in &secrets {
                assert!(!names(v, s), "the header {k} of {path} names {what} ({s})");
            }
        }
        for (s, what) in &secrets {
            assert!(!names(line, s), "the request {line} names {what}");
        }
        if path.starts_with("/redirect-https/") {
            redirected += 1;
        }
        match (path.ends_with(".zsync"), range) {
            (true, _) => descriptions += 1,
            (false, true) => parts += 1,
            (false, false) => whole += 1,
        }
    }
    assert!(
        descriptions > 0 && parts > 0 && whole > 0 && redirected > 0,
        "not every kind of request was recorded (descriptions {descriptions}, parts {parts}, whole files {whole}, through the redirect {redirected}):\n{requests:#?}"
    );
}

/// The whole-word match finds a word alone or between other characters,
/// never inside a longer version number.
#[test]
fn a_version_is_found_only_as_a_whole_word() {
    assert!(names("SAM 0.1.0", "0.1.0"));
    assert!(names("x/0.1.0;", "0.1.0"));
    assert!(!names("10.1.0", "0.1.0"));
    assert!(!names("0.1.01", "0.1.0"));
    assert!(!names("0.1.0.2", "0.1.0"));
}
