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
    let hint = if !host.userns.usable() { host.userns.explain() } else { "Bubblewrap is not installed. Install the 'bubblewrap' package.".into() };
    bail!("the sandbox cannot be created here. {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::sandbox::sample_context;

    /// Without Bubblewrap, the message says which package to install.
    #[test]
    fn missing_bubblewrap_names_the_package_to_install() {
        let mut host = sample_context().host;
        host.tools.bwrap = None;
        let msg = check(&host).unwrap_err().to_string();
        assert!(msg.contains("Install the 'bubblewrap' package"), "{msg}");
    }

    /// When the system forbids user namespaces, the message explains that and
    /// never claims Bubblewrap is missing: the user already has it, and an
    /// "install bubblewrap" hint would send them the wrong way.
    #[test]
    fn disabled_user_namespaces_are_explained_not_called_missing() {
        let mut host = sample_context().host;
        host.userns.bwrap_setuid = false;
        host.userns.max_user_namespaces = Some(0);
        let msg = check(&host).unwrap_err().to_string();
        assert!(msg.contains("User namespaces are disabled"), "{msg}");
        assert!(!msg.contains("not installed"), "{msg}");
        host.userns.max_user_namespaces = None;
        host.userns.unprivileged_clone = Some(false);
        let msg = check(&host).unwrap_err().to_string();
        assert!(msg.contains("sysctl kernel.unprivileged_userns_clone=1"), "the message says how to enable them: {msg}");
    }

    /// A setuid Bubblewrap works without unprivileged user namespaces, so
    /// SAM does not refuse it.
    #[test]
    fn setuid_bubblewrap_works_without_user_namespaces() {
        let mut host = sample_context().host;
        host.userns.max_user_namespaces = Some(0);
        host.userns.bwrap_setuid = true;
        assert!(check(&host).is_ok());
    }
}
