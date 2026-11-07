//! "Local network only" (`network.mode = localhost`) for the Bubblewrap
//! backend. `pasta --splice-only` creates the network namespace and starts
//! Bubblewrap inside it (Bubblewrap then does not create its own). The
//! namespace has only loopback, no route to the internet. pasta forwards
//! loopback ports in both directions, detected automatically, except DNS
//! (port 53). So a local AI model on the host (e.g. Ollama on
//! 127.0.0.1:11434) stays reachable from the app, and the app's own web page
//! stays reachable from the user's browser.
//!
//! (Attaching pasta to a namespace Bubblewrap already created fails with
//! EPERM when pasta isolates itself, so pasta has to be the outer process.)

use anyhow::{Context, Result};
use sam_core::util::which;
use sam_core::SandboxCommand;

pub const PASTA_ARGS: &[&str] = &["--quiet", "--splice-only", "-t", "auto", "-T", "auto,~53", "-u", "none", "-U", "none"];

/// Run `cmd` inside a pasta loopback-only network namespace.
pub fn wrap_localhost(cmd: &mut SandboxCommand) -> Result<()> {
    let pasta = which("pasta").context("'Local network only' needs pasta (package 'passt')")?;
    let mut args: Vec<String> = PASTA_ARGS.iter().map(|s| s.to_string()).collect();
    args.push("--".into());
    args.push(cmd.program.to_string_lossy().into_owned());
    args.append(&mut cmd.args);
    cmd.program = pasta;
    cmd.args = args;
    cmd.notes.push("local network only: started inside pasta --splice-only (loopback ports forwarded, no internet, no DNS)".into());
    Ok(())
}
