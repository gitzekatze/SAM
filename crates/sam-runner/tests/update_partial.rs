//! The partial (zsync) download of an update against a local HTTPS server
//! that ignores range requests or sends slowly: one time limit covers the
//! partial download and the whole file after it, and a server that ignores
//! ranges ends the partial download at its first answer (review B2 S6, R90).
//!
//! The tests call the download directly with a time limit of seconds; SAM's
//! updates (apps and SAM itself) use the same code with an hour.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

mod update_common;

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sam_runner::updates::{download_update_within, Fetched, Published};
use update_common::{server_or_skip, Server};

/// `start_server` sets process-wide variables: one test at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// `n` bytes that differ from block to block.
fn sample(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect()
}

/// Publishes a new version of 1 MiB as `new.bin` with its update
/// description, and writes the installed version to `old`: the same file
/// with eight stretches of 16 KiB changed, far enough apart that the
/// partial download asks for them in eight range requests.
fn publish(server: &Server, old: &Path, mode: &str) -> (Published, Vec<u8>) {
    let new = sample(1 << 20, 7);
    let file = server.root.join("new.bin");
    fs::write(&file, &new).unwrap();
    let z = sam_runner::zsync::make(
        &file,
        "new.bin",
        "new.bin",
        "Tue, 10 Nov 2026 10:00:00 +0000",
    )
    .unwrap();
    fs::write(server.root.join("new.bin.zsync"), &z).unwrap();
    let mut before = new.clone();
    for k in 0..8 {
        let at = (16 << 10) + k * (128 << 10);
        for b in &mut before[at..at + (16 << 10)] {
            *b ^= 0x5a;
        }
    }
    fs::write(old, &before).unwrap();
    let base = format!("https://127.0.0.1:{}", server.port);
    let p = Published {
        file_url: format!("{base}/{mode}/new.bin"),
        sha1: sam_runner::zsync::parse(&z).unwrap().sha1,
        filename: Some("new.bin".into()),
        length: Some(new.len() as u64),
        release: None,
        page: None,
        zsync_url: format!("{base}/new.bin.zsync"),
    };
    (p, new)
}

/// The requests for `path`, as the server logged them (`PATH RANGE`).
fn requests(server: &Server, path: &str) -> Vec<String> {
    fs::read_to_string(&server.log)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with(&format!("{path} ")))
        .map(str::to_string)
        .collect()
}

/// A server that ignores Range sends the whole file to every range
/// request. SAM kept the first bytes of each answer and dropped the rest
/// silently, so all eight "ranges" passed, each one a whole download, and
/// only the final checksum failed. Now the first answer with more bytes
/// than asked for ends the partial download, and the update is downloaded
/// whole, once, and installed.
#[test]
fn a_server_that_ignores_ranges_gets_one_range_request_then_the_whole_file() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let Some((server, _)) = server_or_skip(&root) else {
        return;
    };
    let _contracts =
        sam_runner::contracts::guard(&["updates-curl"]).unwrap_or_else(|e| panic!("{e}"));
    let old = root.join("old.bin");
    let (p, new) = publish(&server, &old, "norange");
    let dest = root.join("download").join("new.bin");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let got = download_update_within(&p, &old, &dest, Duration::from_secs(120))
        .unwrap_or_else(|e| panic!("the update was not downloaded: {e:#}"));
    assert_eq!(
        got,
        Fetched::Full {
            total: new.len() as u64
        }
    );
    assert!(
        fs::read(&dest).unwrap() == new,
        "exactly the published file"
    );
    let asked = requests(&server, "/norange/new.bin");
    let ranges = asked.iter().filter(|l| l.contains("bytes=")).count();
    assert_eq!(ranges, 1, "one range request, then no more: {asked:#?}");
    assert_eq!(
        asked.last().map(String::as_str),
        Some("/norange/new.bin None"),
        "then the whole file: {asked:#?}"
    );
    assert_eq!(asked.len(), 2, "{asked:#?}");
}

/// A slow server: eight ranges of 16 KiB at 8 KiB a second take about
/// twelve seconds, the whole file two minutes. With a limit of three seconds,
/// the update download ends at three seconds, during the partial download,
/// and the whole file is not started with a fresh limit. Before, each
/// request had its own limit (five minutes per range, an hour for the
/// whole file), so a slow server kept the app locked for about a day.
#[test]
fn the_whole_update_download_stops_at_one_deadline() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let Some((server, _)) = server_or_skip(&root) else {
        return;
    };
    let _contracts =
        sam_runner::contracts::guard(&["updates-curl"]).unwrap_or_else(|e| panic!("{e}"));
    let old = root.join("old.bin");
    let (p, _) = publish(&server, &old, "slow");
    let dest = root.join("download").join("new.bin");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let started = Instant::now();
    let res = download_update_within(&p, &old, &dest, Duration::from_secs(3));
    let took = started.elapsed();
    let err = match res {
        Ok(f) => panic!("the slow download was not stopped ({took:?}, {f:?})"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        err.contains("did not finish within 3 seconds"),
        "the update's time limit stopped it: {err}"
    );
    assert!(
        took < Duration::from_secs(6),
        "stopped at the deadline, not later: {took:?}"
    );
    assert!(!dest.exists(), "nothing half-downloaded is left");
    let asked = requests(&server, "/slow/new.bin");
    assert!(
        asked.iter().any(|l| l.contains("bytes=")),
        "the partial download ran: {asked:#?}"
    );
    assert!(
        !asked.iter().any(|l| l.ends_with(" None")),
        "the whole file was not started after the time was up: {asked:#?}"
    );
}
