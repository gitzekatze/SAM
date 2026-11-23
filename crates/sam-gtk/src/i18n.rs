// SPDX-License-Identifier: GPL-3.0-or-later
//! Translations: the window uses the same gettext setup as the rest of
//! SAM (`sam_core::i18n`), so texts from the window and from `sam-jail`
//! come from one catalogue per language.

pub use sam_core::i18n::{n_, tr, trf, trn};

/// Sets up gettext for the user's locale. GTK sets the locale itself when
/// it starts (`setlocale(LC_ALL, "")`); this only tells gettext where SAM's
/// catalogue is.
pub fn init() {
    sam_core::i18n::init(false);
}

/// Set when the window should start again after it closes (a new language).
pub static RESTART: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Applies SAM's own language setting before any text is loaded: asks
/// `sam-jail` for `general.language` and sets `LANGUAGE` for the window and
/// the `sam-jail` calls it makes (their messages then match). The system's
/// value is kept in `SYSTEM_LANGUAGE_VAR`, which the sandbox gives to apps.
/// Call it first in `main`, before any thread exists.
pub fn apply_language_setting() {
    let chosen = configured_language().unwrap_or_default();
    let (language, system) = language_env(
        &chosen,
        std::env::var("LANGUAGE").ok(),
        std::env::var(sam_core::i18n::SYSTEM_LANGUAGE_VAR).ok(),
    );
    // No other thread exists yet, so changing the environment is safe.
    match language {
        Some(v) => std::env::set_var("LANGUAGE", v),
        None => std::env::remove_var("LANGUAGE"),
    }
    match system {
        Some(v) => std::env::set_var(sam_core::i18n::SYSTEM_LANGUAGE_VAR, v),
        None => std::env::remove_var(sam_core::i18n::SYSTEM_LANGUAGE_VAR),
    }
}

fn configured_language() -> Option<String> {
    let out = std::process::Command::new(crate::backend::find_tool("sam-jail", "SAM_CLI"))
        .args(["--json", "config", "get", "general.language"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(text.lines().last()?).ok()?;
    v.get("data")?.as_str().map(str::to_string)
}

/// What `LANGUAGE` and the saved system value become, for the chosen
/// language ("" = the system's), the current `LANGUAGE` and the value saved
/// by an earlier start of the window. Returns (LANGUAGE, saved system value).
pub(crate) fn language_env(
    chosen: &str,
    current: Option<String>,
    saved_system: Option<String>,
) -> (Option<String>, Option<String>) {
    // The system's own value: saved by an earlier start, or the current one.
    let system = saved_system.unwrap_or_else(|| current.unwrap_or_default());
    if chosen.is_empty() {
        ((!system.is_empty()).then_some(system), None)
    } else {
        (Some(chosen.to_string()), Some(system))
    }
}

/// The name of the language the window shows now, in that language, or
/// None when it follows the system.
pub fn chosen_language_name(code: &str) -> Option<&'static str> {
    sam_core::i18n::LANGUAGES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| *n)
}

#[cfg(test)]
mod tests {
    use super::language_env;

    /// Text the window builds itself, outside tr/trf/trn: every `format!`
    /// and every `"…".into()` / `.to_string()` with words in it, in the
    /// window's code (not its tests). Technical strings (style classes,
    /// keys, paths, markup) have no words left once placeholders, tags and
    /// options are taken out; the few that do are listed.
    fn untranslated(src: &str) -> Vec<String> {
        const TECHNICAL: [&str; 4] = [
            "[Desktop Entry]",
            "max-width: {}px",
            "{} \\\"{}\\\" [page {page}]",
            "list row",
        ];
        let code = src.split("#[cfg(test)]").next().unwrap_or_default();
        let mut found = Vec::new();
        let mut check = |lit: &str| {
            if !lit.chars().any(char::is_whitespace) || TECHNICAL.iter().any(|t| lit.starts_with(t))
            {
                return;
            }
            let mut words = String::new();
            let mut depth = (0, 0);
            let mut chars = lit.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    '{' => depth.0 += 1,
                    '}' => depth.0 -= 1,
                    '<' => depth.1 += 1,
                    '>' => depth.1 -= 1,
                    '-' if chars.peek() == Some(&'-') => {
                        while chars.peek().is_some_and(|c| !c.is_whitespace()) {
                            chars.next();
                        }
                    }
                    _ if depth == (0, 0) => words.push(c),
                    _ => {}
                }
            }
            let mut run = 0;
            for c in words.chars() {
                run = if c.is_ascii_alphabetic() { run + 1 } else { 0 };
                if run >= 3 {
                    found.push(lit.to_string());
                    return;
                }
            }
        };
        // `format!("…"`
        for (i, _) in code.match_indices("format!(") {
            let rest = code[i + 8..].trim_start();
            if let Some(body) = rest.strip_prefix('"') {
                let mut end = 0;
                let b = body.as_bytes();
                while end < b.len() && (b[end] != b'"' || (end > 0 && b[end - 1] == b'\\')) {
                    end += 1;
                }
                check(&body[..end]);
            }
        }
        // `"…".into()` and the like
        for tail in ["\".into()", "\".to_string()", "\".to_owned()"] {
            for (i, _) in code.match_indices(tail) {
                let b = code.as_bytes();
                let mut start = i;
                while start > 0 && (b[start - 1] != b'"' || (start > 1 && b[start - 2] == b'\\')) {
                    start -= 1;
                }
                check(&code[start..i]);
            }
        }
        found
    }

    /// Every text the window shows goes through the translations (audit
    /// part 5: "1 app selected", "{n} apps selected" and the Permission
    /// Manager's switch names stayed English in every language).
    #[test]
    fn every_text_the_window_builds_is_translated() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![dir.clone()];
        let mut bad = Vec::new();
        while let Some(d) = files.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    files.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    for t in untranslated(&std::fs::read_to_string(&p).unwrap()) {
                        bad.push(format!("{}: {t}", p.display()));
                    }
                }
            }
        }
        assert!(bad.is_empty(), "not translated: {bad:#?}");
        // The scan sees the kinds it looks for.
        assert_eq!(
            untranslated(
                "let a = format!(\"{n} apps selected\"); let b = \"1 app selected\".into();"
            )
            .len(),
            2
        );
        assert!(
            untranslated("format!(\"sam-badge-{t}\"); format!(\"{} --app-id {}\", a, b);")
                .is_empty()
        );
    }

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    /// Choosing a language sets it for the window and remembers the
    /// system's; going back to the system restores exactly what it had,
    /// also after several restarts.
    #[test]
    fn the_chosen_language_and_the_systems_are_kept_apart() {
        // The system has French; the user chooses German.
        assert_eq!(language_env("de", s("fr"), None), (s("de"), s("fr")));
        // After a restart the window has German and remembers French.
        assert_eq!(language_env("es", s("de"), s("fr")), (s("es"), s("fr")));
        // Back to the system: French again, and nothing remembered.
        assert_eq!(language_env("", s("es"), s("fr")), (s("fr"), None));
        // A system without LANGUAGE stays without it.
        assert_eq!(language_env("de", None, None), (s("de"), s("")));
        assert_eq!(language_env("", s("de"), s("")), (None, None));
        // Following the system from the start changes nothing.
        assert_eq!(language_env("", s("fr"), None), (s("fr"), None));
        assert_eq!(language_env("", None, None), (None, None));
    }
}
