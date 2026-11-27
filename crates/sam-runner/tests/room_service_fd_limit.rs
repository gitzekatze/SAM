//! Room service under a low descriptor limit: what it holds for rooms (the
//! places it opens, the connections passed to it) stays within what SAM's
//! launcher has free, so a room with many places is refused for that,
//! never by running the launcher out of descriptors ("Too many open
//! files"). Its own file: the limit is lowered for this whole process.
//!
//! The test measures this computer first (what the launcher holds while an
//! app runs, how many places a room of /usr has: about 44 on one system,
//! over 300 on another), then sets the limit and the room sizes from that.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

mod rooms_common;

use rooms_common::{cases, World};

/// SAM's launcher keeps this many descriptors for itself (FD_RESERVE).
const KEPT: usize = 256;
/// The most places a room may have (MAX_PLACES).
const MOST_PLACES: usize = 2000;
/// Copies of /usr in the request that measures a room's places.
const MEASURE: usize = 230;

/// The script's helper: `many N` asks for /usr N times.
const MANY: &str = r#"many() { n=$1; out=""; while [ "$n" -gt 0 ]; do out="$out --ro-bind /usr /usr"; n=$((n-1)); done; echo "$out"; }"#;

/// The most descriptors this process holds while `run` runs.
fn most_held_during(run: impl FnOnce() -> String) -> (usize, String) {
    let count = || std::fs::read_dir("/proc/self/fd").map_or(0, |d| d.count());
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let most = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(count()));
    let watcher = {
        let (stop, most) = (stop.clone(), most.clone());
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                most.fetch_max(count(), std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        })
    };
    let log = run();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    watcher.join().unwrap();
    (most.load(std::sync::atomic::Ordering::SeqCst), log)
}

#[test]
fn rooms_never_run_the_launcher_out_of_descriptors() {
    if !rooms_common::require() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "bwrap-rooms"])
        .unwrap_or_else(|e| panic!("{e}"));
    let w = World::new();
    // 1. At the usual limit: what the launcher holds while an app runs, and
    //    how many places one /usr brings (from the count the refusal of a
    //    room over the place limit names).
    let measure = w.add(
        "RoomFdMeasure",
        &format!(
            "{MANY}\n# shellcheck disable=SC2046\nsay measured \"$(rv room $(many {MEASURE}) -- /usr/bin/echo ok)\"\nsleep 1\n"
        ),
    );
    let (held, log) = most_held_during(|| w.start(&measure, |_| {}, 60));
    let per_usr = log
        .lines()
        .find_map(|l| {
            let at = l.find("too many places (")? + "too many places (".len();
            l[at..].split(',').next()?.trim().parse::<usize>().ok()
        })
        .map(|n| n.div_ceil(MEASURE))
        .unwrap_or_else(|| panic!("no place count in the start record:\n{log}"));
    // 2. A limit that leaves rooms room for two of /usr (a small room
    //    fits), and rooms of k times /usr that do not fit in what is left
    //    for rooms, and would not even fit in what the launcher has free
    //    without the budget, but stay within a room's place limit.
    let room_for = 2 * per_usr + 100;
    let limit = held + KEPT + room_for;
    let first_k = (KEPT + room_for) / per_usr + 1;
    let last_k = (MOST_PLACES / per_usr).max(first_k);
    // SAFETY: getrlimit and setrlimit write and read the struct given.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        lim.rlim_cur = (limit as libc::rlim_t).min(lim.rlim_max);
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
    }
    let ks: Vec<String> = (first_k..=last_k).map(|k| k.to_string()).collect();
    let id = w.add(
        "RoomFdLimit",
        &format!(
            r#"{MANY}
say control "$(rv room -- /usr/bin/echo ok)"
for k in {ks}; do
  # shellcheck disable=SC2046
  say "big_$k" "$(rv room $(many "$k") -- /usr/bin/echo ok)"
done
"#,
            ks = ks.join(" ")
        ),
    );
    let log = w.start(&id, |_| {}, 60);
    let c = cases(&log);
    let room_lines: Vec<&str> = log.lines().filter(|l| l.starts_with("sam-room:")).collect();
    let mut failures = Vec::new();
    // A room of a few places still fits: the budget refuses only big ones.
    if c.get("control").map(String::as_str) != Some("ok") {
        failures.push(format!(
            "a small room was not built under the low limit ({:?})",
            c.get("control")
        ));
    }
    if room_lines.iter().any(|l| l.contains("Too many open files")) {
        failures.push("a room ran SAM's launcher out of descriptors".to_string());
    }
    let big: Vec<&String> = ks
        .iter()
        .filter_map(|k| c.get(&format!("big_{k}")))
        .collect();
    if big.len() != ks.len() || big.iter().any(|v| v.as_str() != "refused") {
        failures.push(format!(
            "rooms of many places were built or not asked: {big:?}"
        ));
    }
    if !room_lines
        .iter()
        .any(|l| l.contains("refused echo") && l.contains("too many places held for rooms at once"))
    {
        failures
            .push("no room of many places was refused for the launcher's descriptors".to_string());
    }
    assert!(
        failures.is_empty(),
        "{}\n(the launcher held {held} while an app ran; one /usr brings {per_usr} places; limit {limit}; k {first_k}..={last_k})\nthe start record:\n{}",
        failures.join("\n"),
        room_lines.join("\n")
    );
}
