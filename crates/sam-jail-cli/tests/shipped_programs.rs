//! The test and release tools stay out of the programs SAM ships: a release
//! build of `sam-jail` has no `dev make-fixture`, `bench`,
//! `set-update-info`, `make-zsync` or `sign-appimage`, and `sam-jail-gui`
//! has no `--screenshot`, `--size`, `--delay` or `--focus-walk`. The tests
//! run development builds, which have the tools, so these tests check the
//! switch that leaves them out of release builds; the release gate
//! (tests/shipped/in-container.sh) checks the finished AppImage itself.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::path::{Path, PathBuf};

/// The switch: development builds and the `dev-tools` feature only.
const GATE: &str = r#"#[cfg(any(debug_assertions, feature = "dev-tools"))]"#;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Every line of `rel` that `is_item` picks must have the switch among the
/// attributes directly above it; at least one such line must exist.
fn assert_gated(rel: &str, what: &str, is_item: impl Fn(&str) -> bool) {
    let text = read(rel);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let items: Vec<usize> = (0..lines.len()).filter(|&i| is_item(lines[i])).collect();
    assert!(!items.is_empty(), "{rel}: {what} not found");
    for i in items {
        let gated = lines[..i]
            .iter()
            .rev()
            .take_while(|l| l.starts_with("#["))
            .any(|l| *l == GATE);
        assert!(
            gated,
            "{rel}:{}: {what} is no longer left out of release builds (missing {GATE})",
            i + 1
        );
    }
}

/// The Rust files under `dir` (relative to the repository) that contain
/// `needle`, relative to the repository.
fn files_with(dir: &str, needle: &str) -> Vec<String> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root().join(dir), &mut files);
    let mut found: Vec<String> = files
        .into_iter()
        .filter(|p| fs::read_to_string(p).unwrap().contains(needle))
        .map(|p| {
            p.strip_prefix(root())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    found
}

/// `sam-jail dev make-fixture`, `bench`, `set-update-info`, `make-zsync`
/// and `sign-appimage` are defined only in dev_tools.rs, and that module,
/// the benchmark and the command that reaches them are behind the switch.
/// `dev peek` and `dev extract-squashfs` stay in every build: SAM runs them
/// inside its unpack sandbox.
#[test]
fn the_test_and_release_commands_are_left_out_of_release_builds() {
    let main = "crates/sam-jail-cli/src/main.rs";
    let cli = "crates/sam-jail-cli/src/cli.rs";
    assert_gated(main, "the tools module", |l| l == "mod dev_tools;");
    assert_gated(main, "the benchmark module", |l| l == "mod bench;");
    assert_gated(cli, "the tools command", |l| {
        l == "Tools(crate::dev_tools::ToolCmd),"
    });
    // The arm that runs them: `Cmd::Dev { cmd: DevCmd::Tools(cmd) }`.
    let text = read(main);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let arm = lines
        .iter()
        .position(|l| *l == "cmd: DevCmd::Tools(cmd),")
        .expect("the arm that runs the tools");
    assert_eq!(lines[arm - 1], "Cmd::Dev {");
    assert_eq!(
        lines[arm - 2],
        GATE,
        "{main}: the arm that runs the tools is no longer left out of release builds"
    );
    for name in [
        "MakeFixture",
        "SetUpdateInfo",
        "MakeZsync",
        "SignAppimage",
        "Bench {",
    ] {
        assert_eq!(
            files_with("crates/sam-jail-cli/src", name),
            ["crates/sam-jail-cli/src/dev_tools.rs"],
            "{name} must be defined only in dev_tools.rs"
        );
    }
    for name in ["sam_intake::testkit", "testkit::"] {
        for f in files_with("crates/sam-jail-cli/src", name) {
            assert!(
                f.ends_with("/dev_tools.rs") || f.ends_with("/bench.rs"),
                "{f} uses the test AppImages outside the tools"
            );
        }
    }
    // What SAM needs in every build stays there.
    let cli_text = read(cli);
    for kept in ["Peek {", "ExtractSquashfs {"] {
        let i = cli_text.find(kept).expect(kept);
        let above: Vec<&str> = cli_text[..i].lines().rev().take(4).collect();
        assert!(
            !above.iter().any(|l| l.contains("dev-tools")),
            "dev {kept} must stay in release builds"
        );
    }
}

/// `--screenshot`, `--size`, `--delay` and `--focus-walk` are read only in
/// screenshot.rs, and the window uses that module only behind the switch.
#[test]
fn the_window_screenshot_options_are_left_out_of_release_builds() {
    let main = "crates/sam-gtk/src/main.rs";
    assert_gated(main, "the screenshot module", |l| l == "mod screenshot;");
    assert_gated(main, "a use of the screenshot options", |l| {
        (l.contains(".shot") || l.contains("shot:") || l.contains("screenshot::"))
            && !l.starts_with("//")
    });
    for option in [
        "\"--screenshot\"",
        "\"--size\"",
        "\"--delay\"",
        "\"--focus-walk\"",
    ] {
        assert_eq!(
            files_with("crates/sam-gtk/src", option),
            ["crates/sam-gtk/src/screenshot.rs"],
            "{option} must be read only in screenshot.rs"
        );
    }
}

/// The test AppImages and the test signing are left out of release builds
/// of the libraries too.
#[test]
fn the_test_helpers_of_the_libraries_are_left_out_of_release_builds() {
    assert_gated("crates/sam-intake/src/lib.rs", "testkit", |l| {
        l == "pub mod testkit;"
    });
    assert_gated(
        "crates/sam-detect/src/signature.rs",
        "a test signing function",
        |l| l.starts_with("pub fn sign_") && l.contains("_for_test("),
    );
}

/// Nothing turns the switch on for what SAM ships: the packages, the
/// Makefile and the build of the AppImage's programs never ask for the
/// dev-tools feature. (That they never turn debug assertions on is
/// `release_builds_never_turn_on_debug_assertions` in automation.rs.)
#[test]
fn release_builds_never_turn_the_tools_on() {
    let mut shipped = vec!["Makefile".to_string()];
    let mut stack = vec![root().join("packaging")];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                shipped.push(
                    p.strip_prefix(root())
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    for f in &shipped {
        let text = fs::read_to_string(root().join(f)).unwrap_or_default();
        for word in ["dev-tools", "--all-features"] {
            assert!(!text.contains(word), "{f} names {word}");
        }
    }
    let appimage = read("scripts/make-appimage.sh");
    let builds: Vec<&str> = appimage
        .lines()
        .filter(|l| l.contains("cargo build") && l.contains("sam-gtk"))
        .collect();
    assert_eq!(builds.len(), 1, "one build of the AppImage's programs");
    assert!(
        !builds[0].contains("--features") && !builds[0].contains("--all-features"),
        "the AppImage's programs are built without features: {}",
        builds[0]
    );
}
