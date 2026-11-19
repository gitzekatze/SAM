//! The baseline syscall filter is a deny list: a syscall that a newer kernel
//! adds is allowed until someone looks at it. This test reads the syscall
//! table from the kernel headers of the computer it runs on and fails for
//! every syscall missing from docs/syscalls-reviewed.txt, so a new one is
//! reviewed instead of passing unnoticed. In CI it runs on today's
//! distributions; the nightly early-warning run checks tomorrow's (Fedora
//! Rawhide, Debian testing, Arch) weeks before they reach users. Skipped
//! where no kernel headers are installed.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// The syscalls the installed kernel headers name (x86_64 and the generic
/// table that aarch64 and newer architectures use).
fn kernel_syscalls() -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut found = false;
    for f in [
        "/usr/include/asm/unistd_64.h",
        "/usr/include/asm-generic/unistd.h",
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/aarch64-linux-gnu/asm/unistd.h",
    ] {
        let Ok(text) = fs::read_to_string(f) else {
            continue;
        };
        found = true;
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("#define") else {
                continue;
            };
            let mut parts = rest.split_whitespace();
            let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
                continue;
            };
            // Only real syscall numbers, not aliases or counters.
            let Some(n) = name
                .strip_prefix("__NR3264_")
                .or_else(|| name.strip_prefix("__NR_"))
            else {
                continue;
            };
            if n == "syscalls" || n == "arch_specific_syscall" {
                continue;
            }
            if value.chars().all(|c| c.is_ascii_digit()) || value.starts_with("(__NR_") {
                names.insert(n.to_string());
            }
        }
    }
    found.then_some(names)
}

fn reviewed() -> BTreeSet<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/syscalls-reviewed.txt");
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split('\t').next())
        .map(String::from)
        .collect()
}

#[test]
fn every_known_syscall_has_been_reviewed() {
    let Some(kernel) = kernel_syscalls() else {
        sam_runner::contracts::skip("no kernel headers installed")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    };
    let reviewed = reviewed();
    let new: Vec<&String> = kernel.difference(&reviewed).collect();
    assert!(
        new.is_empty(),
        "the kernel names syscalls nobody has reviewed for SAM's baseline filter: {new:?}. \
         Decide whether crates/sam-runner/src/kernel.rs blocks each one, then add it to \
         docs/syscalls-reviewed.txt (contract kernel-seccomp)."
    );
}

/// The review list says what the filter does with each syscall; it must
/// say exactly that, or the review describes a filter that does not exist.
/// Every status is compared with the filter's own lists, not only the
/// names (audit S-F10: the list said "blocked" for calls only the strict
/// filter blocks, and for the mount family that nested sandboxes keep).
#[test]
fn the_review_list_matches_the_filter() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/syscalls-reviewed.txt"),
    )
    .unwrap();
    let listed: BTreeMap<&str, &str> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split_once('\t'))
        .collect();
    let filter = sam_runner::kernel::review_statuses();
    for (name, status) in &filter {
        assert_eq!(
            listed.get(name),
            Some(status),
            "docs/syscalls-reviewed.txt must say {name}\t{status}"
        );
    }
    for (name, status) in &listed {
        if !filter.contains_key(name) {
            assert_eq!(
                *status, "allowed",
                "{name}: the filter does not name it, so it is allowed"
            );
        }
    }
    assert_eq!(filter.get("ptrace"), Some(&"blocked by the strict filter"));
    assert_eq!(
        filter.get("mount"),
        Some(&"blocked unless nested sandboxes")
    );
}
