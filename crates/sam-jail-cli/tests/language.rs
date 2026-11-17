//! The command line speaks the user's language: the German catalog is
//! compiled from po/de.po and the real `sam-jail` binary uses it.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::path::Path;
use std::process::Command;

/// A locale other than C, which gettext needs before it honours LANGUAGE.
fn real_locale() -> Option<String> {
    let out = Command::new("locale").arg("-a").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("C") && *l != "POSIX")
        .map(str::to_string)
}

#[test]
fn the_command_line_speaks_german_when_asked() {
    let tmp = tempfile::tempdir().unwrap();
    let po = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../po/de.po");
    let mo_dir = tmp.path().join("locale/de/LC_MESSAGES");
    std::fs::create_dir_all(&mo_dir).unwrap();
    let Ok(built) = Command::new("msgfmt")
        .arg("-o")
        .arg(mo_dir.join("sam.mo"))
        .arg(&po)
        .status()
    else {
        sam_runner::contracts::skip("msgfmt (gettext) is not installed")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    };
    assert!(built.success(), "po/de.po does not compile");
    let Some(locale) = real_locale() else {
        sam_runner::contracts::not_here("no locale other than C is installed");
        return;
    };
    let run = |language: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_sam-jail"))
            .arg("list")
            .env("SAM_CONFIG_DIR", tmp.path().join("config"))
            .env("SAM_DATA_DIR", tmp.path().join("data"))
            .env("SAM_APPLICATIONS_DIR", tmp.path().join("applications"))
            .env("SAM_LOCALE_DIR", tmp.path().join("locale"))
            .env("LC_ALL", &locale)
            .env("LANGUAGE", language)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert!(
        run("de").contains("Keine Apps eingetragen"),
        "German was asked for: {}",
        run("de")
    );
    // Without a German wish the same command stays English.
    assert!(
        run("en").contains("No apps are registered"),
        "English was asked for: {}",
        run("en")
    );
}
