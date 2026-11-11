// SPDX-License-Identifier: GPL-3.0-or-later
//! Translations through gettext (text domain `sam`).
//!
//! Strings are marked with [`tr`]; `make pot` collects them into `po/sam.pot`
//! and `make mo` compiles the translations in `po/*.po`. Without a
//! translation for the user's language the English text is shown.

use std::path::PathBuf;

pub const DOMAIN: &str = "sam";

/// Sets up gettext for the user's locale. Translations are looked up in
/// `SAM_LOCALE_DIR`, next to the program (`../share/locale`, also inside
/// SAM's AppImage), or in a source checkout's `target/locale`.
/// GTK sets the locale itself when it starts (`setlocale(LC_ALL, "")`);
/// this only tells gettext where SAM's catalogue is.
pub fn init() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn bindtextdomain(domain: *const libc::c_char, dir: *const libc::c_char) -> *mut libc::c_char;
        fn bind_textdomain_codeset(domain: *const libc::c_char, codeset: *const libc::c_char) -> *mut libc::c_char;
    }
    let (Ok(domain), Ok(dir)) = (CString::new(DOMAIN), CString::new(locale_dir().as_os_str().as_bytes())) else { return };
    // SAFETY: valid NUL-terminated strings; called once at start, before
    // any other thread exists. glibc copies both values.
    unsafe {
        bindtextdomain(domain.as_ptr(), dir.as_ptr());
        bind_textdomain_codeset(domain.as_ptr(), c"UTF-8".as_ptr());
    }
}

fn locale_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("SAM_LOCALE_DIR").filter(|v| !v.is_empty()) {
        return d.into();
    }
    let exe_dir = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf()));
    if let Some(d) = &exe_dir {
        for c in [d.join("../share/locale"), d.join("../locale")] {
            if has_catalogs(&c) {
                return c;
            }
        }
    }
    PathBuf::from("/usr/share/locale")
}

/// Whether `dir` holds at least one compiled SAM translation.
fn has_catalogs(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|rd| rd.flatten().any(|l| l.path().join("LC_MESSAGES").join(format!("{DOMAIN}.mo")).is_file()))
}

/// The translation of `s`, or `s` itself.
pub fn tr(s: &str) -> String {
    gtk::glib::dgettext(Some(DOMAIN), s).into()
}
