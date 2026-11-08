//! SAM has one sandbox backend: Bubblewrap. This module checks that it can
//! run here and explains what is missing when it cannot.

use anyhow::{bail, Result};
use sam_core::{BackendStatus, HostInfo};
use serde::Serialize;

/// The sandbox SAM will use, for display ("Sandbox: Bubblewrap").
#[derive(Debug, Clone, Serialize)]
pub struct Selection {
    pub kind: &'static str,
    pub reason: String,
}

pub fn status(host: &HostInfo) -> BackendStatus {
    sam_backend_bubblewrap::Bubblewrap.status(host)
}

/// Bubblewrap, or an error that says what to install or enable.
pub fn select(host: &HostInfo) -> Result<Selection> {
    let s = status(host);
    if s.usable {
        return Ok(Selection { kind: "bubblewrap", reason: s.version.unwrap_or_else(|| "Bubblewrap".into()) });
    }
    let hint = if !host.userns.usable() {
        host.userns.explain()
    } else {
        "Bubblewrap is not installed. Install the 'bubblewrap' package.".into()
    };
    bail!("the sandbox cannot be created here. {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::backend::sample_context;

    #[test]
    fn bubblewrap_or_guidance() {
        let host = sample_context().host;
        assert_eq!(select(&host).unwrap().kind, "bubblewrap");
        let mut h = host.clone();
        h.tools.bwrap = None;
        assert!(select(&h).unwrap_err().to_string().contains("bubblewrap"));
    }
}
