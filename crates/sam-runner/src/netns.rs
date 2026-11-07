//! "Local network only" (`network.mode = localhost`) for the Bubblewrap
//! backend. `pasta --splice-only` creates the network namespace and starts
//! Bubblewrap inside it (Bubblewrap then does not create its own). The
//! namespace has only loopback, no route to the internet. pasta forwards:
//! - the app's own listening ports to the host (detected automatically), so
//!   its web page opens in the user's browser;
//! - only the host ports listed in `network.host_ports` into the sandbox
//!   (e.g. 11434 for Ollama). Other local services stay unreachable.
//!
//! (Attaching pasta to a namespace Bubblewrap already created fails with
//! EPERM when pasta isolates itself, so pasta has to be the outer process.)

use anyhow::{Context, Result};
use sam_core::util::which;
use sam_core::SandboxCommand;

/// pasta arguments for the given host ports.
pub fn pasta_args(host_ports: &[u16]) -> Vec<String> {
    let to_host = if host_ports.is_empty() { "none".to_string() } else { host_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",") };
    ["--quiet", "--splice-only", "-t", "auto", "-T", &to_host, "-u", "none", "-U", "none"].iter().map(|s| s.to_string()).collect()
}

/// Run `cmd` inside a pasta loopback-only network namespace.
pub fn wrap_localhost(cmd: &mut SandboxCommand, host_ports: &[u16]) -> Result<()> {
    let pasta = which("pasta").context("'Local network only' needs pasta (package 'passt')")?;
    let mut args = pasta_args(host_ports);
    args.push("--".into());
    args.push(cmd.program.to_string_lossy().into_owned());
    args.append(&mut cmd.args);
    cmd.program = pasta;
    cmd.args = args;
    cmd.notes.push(format!(
        "local network only (pasta --splice-only): no internet, no DNS; host ports reachable: {}",
        if host_ports.is_empty() { "none".to_string() } else { host_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ") }
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_host_ports() {
        let a = pasta_args(&[]);
        assert_eq!(a[a.iter().position(|x| x == "-T").unwrap() + 1], "none");
        let a = pasta_args(&[11434, 1234]);
        assert_eq!(a[a.iter().position(|x| x == "-T").unwrap() + 1], "11434,1234");
    }
}
