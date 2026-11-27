//! Room service under a descriptor limit that fits only a couple of room
//! builds at once (most desktops start programs with a soft limit of
//! 1024): rooms asked at the same moment wait for the descriptors of the
//! rooms being built before them, which are given back as soon as each
//! room has started, and every one is built. A room that could never fit,
//! even with nothing else held, is still refused at once. Its own file:
//! the limit is lowered for this whole process.
//!
//! The test measures this computer first (what the launcher holds while an
//! app runs, how many places the test's room has: about 50 on one system,
//! over 300 on another), then sets the limit from that.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

mod rooms_common;

use rooms_common::{cases, World};

/// SAM's launcher keeps this many descriptors for itself (FD_RESERVE).
const KEPT: usize = 256;
/// SAM's own descriptors for one room while it is built (ROOM_FDS).
const ROOM_FDS: usize = 12;
/// The most places a room may have (MAX_PLACES).
const MOST_PLACES: usize = 2000;
/// Rooms asked for at the same moment.
const ROOMS: usize = 40;
/// Connections each of those requests passes, counted generously (the
/// stand-in passes the program's standard streams: three).
const PASSED: usize = 4;
/// Room builds the budget holds at once (besides every request's
/// connections): far fewer than the sixteen room slots.
const BUILDS: usize = 2;
/// Copies of /usr in the requests that measure a room's places.
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

/// The places named in the refusal of `program`'s room for having too many.
fn places_refused(log: &str, program: &str) -> usize {
    log.lines()
        .filter(|l| l.contains(&format!("refused {program} ")))
        .find_map(|l| {
            let at = l.find("too many places (")? + "too many places (".len();
            l[at..].split(',').next()?.trim().parse::<usize>().ok()
        })
        .unwrap_or_else(|| panic!("no place count for {program} in the start record:\n{log}"))
}

#[test]
fn rooms_asked_at_once_wait_for_descriptors_and_are_all_built() {
    if !rooms_common::require() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "bwrap-rooms"])
        .unwrap_or_else(|e| panic!("{e}"));
    let w = World::new();
    // 1. At the usual limit: what the launcher holds while an app runs, and
    //    the places of the test's room (from the counts the refusals of two
    //    rooms over the place limit name: one /usr more in the second).
    let measure = w.add(
        "RoomFdWaitMeasure",
        &format!(
            r#"{MANY}
# shellcheck disable=SC2046
say m1 "$(rv room $(many {MEASURE}) -- /usr/bin/echo ok)"
# shellcheck disable=SC2046
say m2 "$(rv room $(many {more}) -- /usr/bin/printf ok)"
sleep 1
"#,
            more = MEASURE + 1
        ),
    );
    let (held, log) = most_held_during(|| w.start(&measure, |_| {}, 60));
    let (p1, p2) = (places_refused(&log, "echo"), places_refused(&log, "printf"));
    let per_usr = p2 - p1;
    let room_places = p1 - MEASURE * per_usr;
    // 2. A limit that leaves rooms room for every request's connections and
    //    BUILDS rooms being built: the rooms asked at once cannot all be
    //    built at the same moment (the service would build up to sixteen),
    //    so most must wait for the ones before them.
    let one_build = room_places + ROOM_FDS;
    let budget = ROOMS * PASSED + BUILDS * one_build;
    let limit = held + KEPT + budget;
    assert!(
        (budget + KEPT) / one_build < 16,
        "the limit would fit too many builds at once for this test ({budget}, one build {one_build})"
    );
    // A room that never fits, even with nothing else held: more places than
    // the whole budget (and whatever the launcher held less when the
    // service started than at its most), but within a room's place limit.
    let k = (budget + KEPT) / per_usr + 1;
    let too_big = room_places + k * per_usr;
    assert!(
        too_big <= MOST_PLACES,
        "a room over the budget would be over the place limit here ({too_big} places), so this test cannot tell the two apart"
    );
    // SAFETY: getrlimit and setrlimit write and read the struct given.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        assert!(
            limit as libc::rlim_t <= lim.rlim_max,
            "the hard descriptor limit is below {limit}"
        );
        lim.rlim_cur = limit as libc::rlim_t;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
    }
    let id = w.add(
        "RoomFdWait",
        &format!(
            r#"{MANY}
# Many rooms asked for at the same moment.
pids=""
i=0
while [ $i -lt {ROOMS} ]; do room -- /usr/bin/true </dev/null & pids="$pids $!"; i=$((i+1)); done
ok=0
for p in $pids; do wait "$p" && ok=$((ok+1)); done
say together "$ok"
# A room that never fits: refused at once, not after a wait.
start=$(date +%s%N)
# shellcheck disable=SC2046
say never_fits "$(rv room $(many {k}) -- /usr/bin/echo ok)"
say never_fits_ms "$(( ($(date +%s%N) - start) / 1000000 ))"
say control "$(rv room -- /usr/bin/printf ok)"
"#
        ),
    );
    let log = w.start(&id, |_| {}, 120);
    let c = cases(&log);
    let room_lines: Vec<&str> = log.lines().filter(|l| l.starts_with("sam-room:")).collect();
    let mut failures = Vec::new();
    if c.get("together") != Some(&ROOMS.to_string()) {
        failures.push(format!(
            "of {ROOMS} rooms asked for at once, {:?} were built",
            c.get("together")
        ));
    }
    if c.get("control").map(String::as_str) != Some("ok") {
        failures.push(format!(
            "a small room after them was not built ({:?})",
            c.get("control")
        ));
    }
    if room_lines.iter().any(|l| l.contains("Too many open files")) {
        failures.push("a room ran SAM's launcher out of descriptors".to_string());
    }
    if c.get("never_fits").map(String::as_str) != Some("refused")
        || !room_lines.iter().any(|l| {
            l.contains("refused echo") && l.contains("too many places held for rooms at once")
        })
    {
        failures.push(format!(
            "a room over the whole budget was not refused for the launcher's descriptors ({:?})",
            c.get("never_fits")
        ));
    }
    // At once: far below the longest a room waits for descriptors.
    match c.get("never_fits_ms").and_then(|v| v.parse::<u64>().ok()) {
        Some(ms) if ms < 10_000 => {}
        other => failures.push(format!(
            "a room over the whole budget was not refused at once ({other:?} ms)"
        )),
    }
    assert!(
        failures.is_empty(),
        "{}\n(the launcher held {held} while an app ran; the room has {room_places} places, one /usr {per_usr}; budget {budget}, limit {limit}; the big room {too_big} places)\nthe start record:\n{}",
        failures.join("\n"),
        room_lines.join("\n")
    );
}
