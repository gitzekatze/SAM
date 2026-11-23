//! Translations for every part of SAM, through gettext (text domain `sam`).
//!
//! Texts for people are marked with [`tr`] (plain text), [`trf`] (text with
//! named placeholders such as `{name}`, which a translation may move) or
//! [`trn`] (text that depends on a number, with the language's plural
//! forms). `make pot` collects them into `po/sam.pot`; `make mo` compiles
//! the translations in `po/*.po`. Without a translation for the user's
//! language, or before [`init`] is called (as in tests), the English text
//! is used.
//!
//! Codes, keys and anything a program reads stay untranslated; programs
//! decide by codes ([`crate::error::CodedError`]), never by a message.

use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::path::{Path, PathBuf};

pub const DOMAIN: &str = "sam";

unsafe extern "C" {
    fn dgettext(domain: *const libc::c_char, msgid: *const libc::c_char) -> *mut libc::c_char;
    fn dngettext(
        domain: *const libc::c_char,
        msgid: *const libc::c_char,
        plural: *const libc::c_char,
        n: libc::c_ulong,
    ) -> *mut libc::c_char;
    fn bindtextdomain(domain: *const libc::c_char, dir: *const libc::c_char) -> *mut libc::c_char;
    fn bind_textdomain_codeset(
        domain: *const libc::c_char,
        codeset: *const libc::c_char,
    ) -> *mut libc::c_char;
}

/// The languages SAM speaks, each with its name in its own language. The
/// setting `general.language` is one of the codes, or empty to follow the
/// system.
pub const LANGUAGES: &[(&str, &str)] = &[
    ("en", "English"),
    ("de", "Deutsch"),
    ("es", "Español"),
    ("fr", "Français"),
];

/// Set by SAM's window when it shows a language of its own: the system's
/// `LANGUAGE` from before (empty when it had none). Apps get that one, so
/// SAM's language setting never changes the language of the apps.
pub const SYSTEM_LANGUAGE_VAR: &str = "SAM_SYSTEM_LANGUAGE";

/// Sets up translations. `set_locale` is for programs without GTK (the
/// command line); GTK sets the locale itself when it starts. Call once at
/// the start, before other threads exist.
pub fn init(set_locale: bool) {
    let (Ok(domain), Ok(dir)) = (
        CString::new(DOMAIN),
        CString::new(locale_dir().as_os_str().as_encoded_bytes()),
    ) else {
        return;
    };
    // SAFETY: valid NUL-terminated strings; called once at start, before any
    // other thread exists; glibc copies both values.
    unsafe {
        if set_locale {
            libc::setlocale(libc::LC_ALL, c"".as_ptr());
            // Numbers and dates in a fixed form: SAM writes them into files
            // and JSON, and only the texts are translated.
            libc::setlocale(libc::LC_NUMERIC, c"C".as_ptr());
        }
        bindtextdomain(domain.as_ptr(), dir.as_ptr());
        bind_textdomain_codeset(domain.as_ptr(), c"UTF-8".as_ptr());
    }
}

/// Where the compiled translations are: `SAM_LOCALE_DIR`, next to the
/// program (`../share/locale`, also inside SAM's AppImage), a source
/// checkout's `target/locale`, or the system's.
pub fn locale_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("SAM_LOCALE_DIR").filter(|v| !v.is_empty()) {
        return d.into();
    }
    if let Some(d) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        for c in program_locale_dirs(&d) {
            if has_catalogs(&c) {
                return c;
            }
        }
    }
    PathBuf::from("/usr/share/locale")
}

/// Where translations may lie next to a program in `dir`. A source
/// checkout's `target/locale` only for a program that cargo built there
/// (`target/debug`, `target/release`): an installed SAM in ~/.local/bin
/// read `~/target/locale`, a folder any program with access to the home
/// could fill with its own wording for SAM's questions (audit U-L11).
fn program_locale_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![dir.join("../share/locale"), dir.join("../locale")];
    let built_by_cargo = dir
        .file_name()
        .is_some_and(|n| n == "debug" || n == "release")
        && dir
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n == "target");
    if built_by_cargo {
        out.push(dir.join("../../target/locale"));
    }
    out
}

/// Whether `dir` holds at least one compiled SAM translation.
fn has_catalogs(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|rd| {
        rd.flatten().any(|l| {
            l.path()
                .join("LC_MESSAGES")
                .join(format!("{DOMAIN}.mo"))
                .is_file()
        })
    })
}

/// Marks a text for translation where no translation can run, such as a
/// constant table; it is translated with [`tr`] where it is shown.
pub const fn n_(s: &'static str) -> &'static str {
    s
}

/// The translation of `s`, or `s` itself.
pub fn tr(s: &str) -> String {
    let (Ok(domain), Ok(id)) = (CString::new(DOMAIN), CString::new(s)) else {
        return s.to_string();
    };
    // SAFETY: both strings are NUL-terminated and live until the result is
    // copied; dgettext returns either `id` or a string from the loaded
    // catalogue, both valid NUL-terminated strings.
    let out = unsafe { CStr::from_ptr(dgettext(domain.as_ptr(), id.as_ptr())) };
    out.to_string_lossy().into_owned()
}

/// The translation of `s` with its `{name}` placeholders filled in.
pub fn trf(s: &str, args: &[(&str, &dyn Display)]) -> String {
    fill(&tr(s), args)
}

/// The singular or plural translation for `n`, with `{n}` and the other
/// placeholders filled in.
pub fn trn(singular: &str, plural: &str, n: u64, args: &[(&str, &dyn Display)]) -> String {
    let mut all: Vec<(&str, &dyn Display)> = vec![("n", &n)];
    all.extend_from_slice(args);
    let (Ok(d), Ok(s1), Ok(p1)) = (
        CString::new(DOMAIN),
        CString::new(singular),
        CString::new(plural),
    ) else {
        return fill(if n == 1 { singular } else { plural }, &all);
    };
    // SAFETY: all strings are NUL-terminated and live until the result is
    // copied; dngettext returns one of them or a catalogue string.
    let text = unsafe {
        CStr::from_ptr(dngettext(
            d.as_ptr(),
            s1.as_ptr(),
            p1.as_ptr(),
            n as libc::c_ulong,
        ))
    }
    .to_string_lossy()
    .into_owned();
    fill(&text, &all)
}

/// Replaces `{name}` with the value given for `name`, in one pass: a value
/// is never read for placeholders itself. Filling them one after another
/// filled a `{other}` inside a value (a file name, an app's own name)
/// again (audit U-L11). An unknown `{…}` stays as written.
fn fill(text: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let value = after.find('}').and_then(|close| {
            let name = &after[..close];
            args.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (v.to_string(), close))
        });
        match value {
            Some((v, close)) => {
                out.push_str(&v);
                rest = &after[close + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a translation, texts come back as written, placeholders are
    /// filled in by name (so a translation may reorder them), and the
    /// plural form follows the number.
    /// Every language with a translation (po/LINGUAS) can be chosen, and
    /// English, which needs none.
    #[test]
    fn every_translated_language_can_be_chosen() {
        let linguas =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../po/LINGUAS"))
                .unwrap();
        for l in linguas.split_whitespace() {
            assert!(
                LANGUAGES.iter().any(|(c, _)| *c == l),
                "{l} is translated but cannot be chosen"
            );
        }
        assert!(LANGUAGES.iter().any(|(c, _)| *c == "en"));
    }

    /// Regression (audit U-L11): placeholders were filled one after
    /// another, so a value holding `{other}` (a file or app name from
    /// outside) was filled again with the next value. Each value now goes
    /// in as it is; a name without a value stays as written.
    #[test]
    fn a_value_is_never_filled_in_again() {
        assert_eq!(
            trf(
                "{app} cannot open {file}",
                &[("app", &"Evil {file}"), ("file", &"notes.txt")]
            ),
            "Evil {file} cannot open notes.txt"
        );
        assert_eq!(
            trn(
                "{n} file in {dir}",
                "{n} files in {dir}",
                2,
                &[("dir", &"{n}")]
            ),
            "2 files in {n}"
        );
        assert_eq!(fill("{a} {b} {", &[("a", &"{b}")]), "{b} {b} {");
        assert_eq!(fill("{{a}}", &[("a", &"x")]), "{x}");
    }

    /// Regression (audit U-L11): every build also looked for translations
    /// in `../../target/locale` next to the program, so SAM installed in
    /// ~/.local/bin read `~/target/locale`. Only a program cargo built in
    /// a source checkout looks there now.
    #[test]
    fn only_a_program_cargo_built_reads_a_checkouts_translations() {
        let installed = program_locale_dirs(Path::new("/home/ann/.local/bin"));
        assert!(
            !installed.iter().any(|d| d.ends_with("target/locale")),
            "{installed:?}"
        );
        assert!(installed.contains(&PathBuf::from("/home/ann/.local/bin/../share/locale")));
        let built = program_locale_dirs(Path::new("/src/sam/target/debug"));
        assert!(built.contains(&PathBuf::from("/src/sam/target/debug/../../target/locale")));
    }

    #[test]
    fn texts_without_a_translation_come_back_with_their_values() {
        assert_eq!(tr("Create Sandbox"), "Create Sandbox");
        assert_eq!(
            trf(
                "{app} needs {what}.",
                &[("what", &"the network"), ("app", &"Krita")]
            ),
            "Krita needs the network."
        );
        assert_eq!(trn("{n} app", "{n} apps", 1, &[]), "1 app");
        assert_eq!(
            trn(
                "{n} app in {folder}",
                "{n} apps in {folder}",
                3,
                &[("folder", &"Downloads")]
            ),
            "3 apps in Downloads"
        );
    }
}
