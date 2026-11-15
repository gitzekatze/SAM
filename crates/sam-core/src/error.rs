//! Errors that callers recognize by a fixed code.
//!
//! SAM's messages are written for people and will be translated, so no
//! program may decide anything by reading them. An error that a caller
//! must react to (the window offers a choice, a script retries) carries a
//! code; `sam-jail --json` reports it next to the message.

use std::fmt;

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
    e.chain()
        .find_map(|c| {
            c.downcast_ref::<CodedError>().or_else(|| {
                c.downcast_ref::<std::io::Error>()
                    .and_then(|io| io.get_ref())
                    .and_then(|inner| inner.downcast_ref::<CodedError>())
            })
        })
        .map(|c| c.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The code of an error survives being wrapped in context, so the
    /// window recognizes it whatever language the message is in.
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
