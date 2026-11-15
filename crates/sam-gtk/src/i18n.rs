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
