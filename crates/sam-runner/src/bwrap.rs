//! SAM's sandbox is Bubblewrap. This module checks that it can run here
//! and explains what is missing when it cannot.

use anyhow::{bail, Result};
use sam_core::{BubblewrapStatus, HostInfo};
use serde::Serialize;

/// The sandbox SAM uses, for display ("Sandbox: Bubblewrap 0.11").
#[derive(Debug, Clone, Serialize)]
pub struct SandboxInfo {
    pub kind: &'static str,
    pub reason: String,
}

pub fn status(host: &HostInfo) -> BubblewrapStatus {
    sam_sandbox::Bubblewrap.status(host)
}

/// Bubblewrap, or an error that says what to install or enable.
pub fn check(host: &HostInfo) -> Result<SandboxInfo> {
    let s = status(host);
    if s.usable {
        return Ok(SandboxInfo { kind: "bubblewrap", reason: s.version.unwrap_or_else(|| "Bubblewrap".into()) });
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
    use sam_core::sandbox::sample_context;

    #[test]
    fn bubblewrap_or_guidance() {
        let host = sample_context().host;
        assert_eq!(check(&host).unwrap().kind, "bubblewrap");
        let mut h = host.clone();
        h.tools.bwrap = None;
        assert!(check(&h).unwrap_err().to_string().contains("bubblewrap"));
    }
}
