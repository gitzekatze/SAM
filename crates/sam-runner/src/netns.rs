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

/// Ports an app must never take over on the host's loopback when its ports
/// are detected automatically: privileged ports and well-known local
/// services (databases, caches, local AI servers, sync tools, admin UIs).
const NEVER_FORWARD_FROM_APP: &[&str] = &["~1-1023", "~1234", "~3306", "~5432", "~5984", "~6379", "~8384", "~9090", "~11211", "~11434", "~27017"];

/// pasta arguments: `app_ports` from the app to the host (empty = automatic
/// with exclusions), `host_ports` from the host into the sandbox.
pub fn pasta_args(host_ports: &[u16], app_ports: &[u16]) -> Vec<String> {
    let join = |v: &[u16]| v.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let to_host = if host_ports.is_empty() { "none".to_string() } else { join(host_ports) };
    let from_app = if app_ports.is_empty() { format!("auto,{}", NEVER_FORWARD_FROM_APP.join(",")) } else { join(app_ports) };
    ["--quiet", "--splice-only", "-t", &from_app, "-T", &to_host, "-u", "none", "-U", "none"].iter().map(|s| s.to_string()).collect()
}

/// Run `cmd` inside a pasta loopback-only network namespace.
pub fn wrap_localhost(cmd: &mut SandboxCommand, host_ports: &[u16], app_ports: &[u16]) -> Result<()> {
    let pasta = which("pasta").context("'Local network only' needs pasta (package 'passt')")?;
    let mut args = pasta_args(host_ports, app_ports);
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
        let a = pasta_args(&[], &[]);
        assert_eq!(a[a.iter().position(|x| x == "-T").unwrap() + 1], "none");
        assert!(a[a.iter().position(|x| x == "-t").unwrap() + 1].starts_with("auto,~1-1023"));
        let a = pasta_args(&[11434, 1234], &[8080]);
        assert_eq!(a[a.iter().position(|x| x == "-T").unwrap() + 1], "11434,1234");
        assert_eq!(a[a.iter().position(|x| x == "-t").unwrap() + 1], "8080");
    }
}
