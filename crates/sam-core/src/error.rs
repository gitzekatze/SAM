//! Errors that callers recognize by a fixed code.
//!
//! SAM's messages are written for people and will be translated, so no
//! program may decide anything by reading them. An error that a caller
//! must react to (the window offers a choice, a script retries) carries a
//! code; `sam-jail --json` reports it next to the message.

use std::fmt;

/// How SAM's launcher (`sam-jail-run`) ends when it did not start the app
/// because a protection its settings ask for is missing (B2 R75, R77): its
/// notification offers "Start anyway", so SAM's window says no more than
/// that. 75 is "try again later" (`EX_TEMPFAIL`); an app that ends with
/// 75 itself gets the same words in the window, nothing else.
pub const EXIT_PROTECTION_MISSING: i32 = 75;

/// An error with a fixed code, such as `signing-key-changed`.
#[derive(Debug, Clone)]
pub struct CodedError {
    pub code: &'static str,
    pub message: String,
}

impl CodedError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        CodedError {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for CodedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CodedError {}

/// The code of the first coded error in an error chain, if any. Code that
/// must return an `io::Error` (a `Read` implementation) carries its coded
/// error inside it; that one is found too.
pub fn code_of(e: &anyhow::Error) -> Option<&'static str> {
    e.chain().find_map(|c| {
        // A function marker hides the error it wraps from the chain.
        if let Some(f) = c.downcast_ref::<InFunction>() {
            return code_of(&f.source);
        }
        c.downcast_ref::<CodedError>()
            .or_else(|| {
                c.downcast_ref::<std::io::Error>()
                    .and_then(|io| io.get_ref())
                    .and_then(|inner| inner.downcast_ref::<CodedError>())
            })
            .map(|c| c.code)
    })
}

/// Which of SAM's functions (docs/functions.md) an error happened in: the
/// "tiny gear" a failure points at, so a bug report or a script knows which
/// promise and which tests to look at. Attached with `.in_function(id)` at
/// the step that can fail; the innermost one is the most precise.
#[derive(Debug)]
pub struct InFunction {
    pub id: u16,
    source: anyhow::Error,
}

// The marker is invisible: it shows the error it wraps, and its causes
// follow it as before, so every message reads exactly as without it.
impl fmt::Display for InFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for InFunction {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

/// Attaches the SAM function an error belongs to.
pub trait InFunctionExt<T> {
    fn in_function(self, id: u16) -> anyhow::Result<T>;
}

impl<T, E: Into<anyhow::Error>> InFunctionExt<T> for Result<T, E> {
    fn in_function(self, id: u16) -> anyhow::Result<T> {
        self.map_err(|e| {
            anyhow::Error::new(InFunction {
                id,
                source: e.into(),
            })
        })
    }
}

/// The SAM function an error happened in: the innermost one attached.
pub fn function_of(e: &anyhow::Error) -> Option<u16> {
    e.chain()
        .find_map(|c| c.downcast_ref::<InFunction>())
        .map(|f| function_of(&f.source).unwrap_or(f.id))
}

/// The error's message for people (the function markers add nothing to it).
pub fn message_of(e: &anyhow::Error) -> String {
    format!("{e:#}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The code of an error survives being wrapped in context, so the
    /// window recognizes it whatever language the message is in.
    /// An error names the SAM function it happened in, the innermost one,
    /// and its message for people stays as it was.
    #[test]
    fn an_error_names_its_sam_function_and_keeps_its_message() {
        use anyhow::Context;
        let inner: anyhow::Result<()> = Err(anyhow::anyhow!("the image is damaged"));
        let e = inner
            .in_function(3)
            .context("adding the app")
            .in_function(19)
            .unwrap_err();
        assert_eq!(function_of(&e), Some(3), "the innermost function");
        assert_eq!(message_of(&e), "adding the app: the image is damaged");
        assert_eq!(e.to_string(), "adding the app", "the marker is invisible");
        let coded: anyhow::Result<()> =
            Err(CodedError::new("signing-key-changed", "another key").into());
        let e = coded.in_function(28).unwrap_err();
        assert_eq!(
            code_of(&e),
            Some("signing-key-changed"),
            "codes still found"
        );
        assert_eq!(function_of(&e), Some(28));
        assert_eq!(function_of(&anyhow::anyhow!("plain")), None);
    }

    #[test]
    fn an_error_code_survives_added_context() {
        use anyhow::Context;
        let e: anyhow::Error = Err::<(), _>(CodedError::new(
            "signing-key-changed",
            "Der Schlüssel hat sich geändert.",
        ))
        .context("updating Krita")
        .unwrap_err();
        assert_eq!(code_of(&e), Some("signing-key-changed"));
        let inside_io: anyhow::Error = anyhow::Error::new(std::io::Error::other(CodedError::new(
            "extraction-limit",
            "zu groß",
        )))
        .context("usr/lib/x.so");
        assert_eq!(
            code_of(&inside_io),
            Some("extraction-limit"),
            "a code inside an I/O error is found"
        );
        assert_eq!(code_of(&anyhow::anyhow!("plain")), None);
    }
}
