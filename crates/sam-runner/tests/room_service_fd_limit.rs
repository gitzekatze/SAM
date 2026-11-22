//! Room service under a low descriptor limit: what it holds for rooms (the
//! places it opens, the connections passed to it) stays within what SAM's
//! launcher has free, so a room with many places is refused for that,
//! never by running the launcher out of descriptors ("Too many open
//! files"). Its own file: the limit is lowered for this whole process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod rooms_common;

use rooms_common::{cases, World};

/// The soft limit for this test: low enough that one room of many places
/// would take every descriptor the launcher has, without the budget.
const SOFT_LIMIT: libc::rlim_t = 520;

#[test]
fn rooms_never_run_the_launcher_out_of_descriptors() {
    if !rooms_common::require() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "bwrap-rooms"])
        .unwrap_or_else(|e| panic!("{e}"));
    // SAFETY: getrlimit and setrlimit write and read the struct given.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        lim.rlim_cur = SOFT_LIMIT.min(lim.rlim_max);
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
    }
    let w = World::new();
    let id = w.add(
        "RoomFdLimit",
        r#"
say control "$(rv room -- /usr/bin/echo ok)"
many() { n=$1; out=""; while [ "$n" -gt 0 ]; do out="$out --ro-bind /usr /usr"; n=$((n-1)); done; echo "$out"; }
# Each /usr brings SAM's own places below it (about 44 here, more or
# less elsewhere): of 8 to 16 of them, some stay within a room's 600
# places but need more descriptors than this launcher has free.
for k in 8 9 10 11 12 13 14 15 16; do
  # shellcheck disable=SC2046
  say "big_$k" "$(rv room $(many "$k") -- /usr/bin/echo ok)"
done
# The limit of places per room, for comparison (its count is recorded).
# shellcheck disable=SC2046
say too_many "$(rv room $(many 230) -- /usr/bin/echo ok)"
"#,
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
    let big: Vec<&String> = (8..=16)
        .filter_map(|k| c.get(&format!("big_{k}")))
        .collect();
    if big.len() != 9 || big.iter().any(|v| v.as_str() != "refused") {
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
    if !room_lines
        .iter()
        .any(|l| l.contains("too many places (") && l.contains("at most 600"))
    {
        failures.push("the room over the place limit was not refused for that".into());
    }
    assert!(
        failures.is_empty(),
        "{}\nthe start record:\n{}",
        failures.join("\n"),
        room_lines.join("\n")
    );
}
