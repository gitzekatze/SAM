//! A test that keeps SAM away from the person's own folders and tools with
//! SAM's developer variables (`SAM_CONFIG_DIR`, `SAM_TRUST_TOOLS_IN`, ...)
//! is only isolated in a developer build: a release build ignores those
//! variables (`DeveloperVars`), so under `cargo test --release` it would
//! add, change and remove app records and settings in the real
//! `~/.config/sam` and `~/.local/share/sam`, and might still pass. Every
//! such test file therefore refuses to compile in a release build, with a
//! message that says why.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::path::{Path, PathBuf};

/// The variables only a developer build reads (`DeveloperVars`).
const DEVELOPER_VARS: &[&str] = &[
    "SAM_CONFIG_DIR",
    "SAM_DATA_DIR",
    "SAM_APPLICATIONS_DIR",
    "SAM_RUNTIME_DIR",
    "SAM_TRUST_TOOLS_IN",
    "SAM_CLI",
    "SAM_RUN",
    "SAM_LOCALE_DIR",
    "SAM_DBUS_LOG",
];

/// The guard each such test file carries.
const GUARD: &str = "#[cfg(not(debug_assertions))]\ncompile_error!(";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether `text` names a developer variable or uses the test helpers that
/// set one (`testenv::isolate_*` sets `SAM_RUNTIME_DIR`).
fn uses_developer_vars(text: &str) -> bool {
    if text.contains("testenv::isolate") {
        return true;
    }
    text.match_indices("SAM_").any(|(at, _)| {
        let name: String = text[at..]
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || *c == '_')
            .collect();
        DEVELOPER_VARS.contains(&name.as_str())
    })
}

/// A test file with the modules it declares from its tests folder
/// (`mod rooms_common;` -> `tests/rooms_common/mod.rs` or `.rs`).
fn with_its_modules(file: &Path) -> String {
    let mut text = fs::read_to_string(file).unwrap();
    let dir = file.parent().unwrap();
    let modules: Vec<String> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("mod ")?.strip_suffix(';'))
        .map(str::to_string)
        .collect();
    for m in modules {
        for p in [dir.join(&m).join("mod.rs"), dir.join(format!("{m}.rs"))] {
            if let Ok(t) = fs::read_to_string(p) {
                text.push_str(&t);
            }
        }
    }
    text
}

/// Every integration test file of every SAM part.
fn test_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for part in fs::read_dir(root().join("crates")).unwrap().flatten() {
        let Ok(entries) = fs::read_dir(part.path().join("tests")) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn tests_isolated_by_developer_variables_refuse_a_release_build() {
    let files = test_files();
    assert!(files.len() > 20, "found only {files:?}");
    let mut unguarded = Vec::new();
    let mut guarded = 0;
    for f in &files {
        // This check names the variables but starts nothing.
        if f.file_name()
            .is_some_and(|n| n == "developer_build_tests.rs")
        {
            continue;
        }
        let own = fs::read_to_string(f).unwrap();
        if uses_developer_vars(&with_its_modules(f)) {
            if own.contains(GUARD) && own.contains("--release") {
                guarded += 1;
            } else {
                unguarded.push(f.strip_prefix(root()).unwrap_or(f).to_path_buf());
            }
        }
    }
    assert!(
        unguarded.is_empty(),
        "these tests isolate SAM with variables only a developer build reads, \
         but would also compile in a release build and then use the real \
         folders; add `{GUARD}\"... run it without --release\");` after \
         their module comment: {unguarded:#?}"
    );
    assert!(guarded > 20, "only {guarded} guarded test files found");
}

/// The finder itself: it sees the variables and the helpers, and not a
/// longer name that only begins like one.
#[test]
fn the_finder_sees_developer_variables_and_nothing_else() {
    assert!(uses_developer_vars(r#".env("SAM_DATA_DIR", d)"#));
    assert!(uses_developer_vars(
        "sam_runner::testenv::isolate_command(&mut c, r);"
    ));
    assert!(uses_developer_vars("SAM_RUN"));
    assert!(!uses_developer_vars("SAM_TEST_SESSION"));
    assert!(!uses_developer_vars("SAM_RUNNER_X"));
    assert!(!uses_developer_vars("sam_data_dir"));
}
