//! `sam-jail-run`: the launcher used by desktop entries
//! (`Exec=sam-jail-run --app-id <id> %F`), and the in-sandbox helper that
//! applies Landlock before exec (`--sandbox-exec <spec> -- <cmd>`).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use sam_core::util::which;
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::Sam;

fn usage() -> ! {
    eprintln!("usage: sam-jail-run --app-id <id> [files...]\n       sam-jail-run <id> [args...]");
    std::process::exit(2);
}

/// Desktop launches have no terminal: tell the user through a notification.
fn notify(title: &str, body: &str) {
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        return;
    }
    if let Some(n) = which("notify-send") {
        // App names and messages are untrusted; notification bodies render
        // markup, so neutralize it.
        let clean = |s: &str| sam_core::util::display_safe(s, 400).replace('&', "&amp;");
        let _ = Command::new(n).args(["--app-name=SAM", "--icon=dialog-warning", &clean(title), &clean(body)]).status();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--sandbox-exec") {
        let spec = args.get(1).map(PathBuf::from).unwrap_or_else(|| usage());
        let rest: Vec<String> = match args.iter().position(|a| a == "--") {
            Some(i) => args[i + 1..].to_vec(),
            None => usage(),
        };
        if let Err(e) = sam_runner::kernel::sandbox_exec(&spec, &rest) {
            eprintln!("sam-jail-run: {e:#}");
            std::process::exit(127);
        }
        return;
    }
    match launch(args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("sam-jail-run: {e:#}");
            notify("SAM could not start the app", &format!("{e:#}\nOpen SAM to repair it."));
            std::process::exit(1);
        }
    }
}

fn launch(args: Vec<String>) -> Result<i32> {
    let (id, rest) = match args.first().map(String::as_str) {
        Some("--app-id") => (args.get(1).cloned().unwrap_or_else(|| usage()), args[2.min(args.len())..].to_vec()),
        Some("-h") | Some("--help") | None => usage(),
        Some(_) => (args[0].clone(), args[1..].to_vec()),
    };
    // Strip a leading "--" separator.
    let rest: Vec<String> = match rest.first().map(String::as_str) {
        Some("--") => rest[1..].to_vec(),
        _ => rest,
    };
    let app = Sam::open()?;
    let mut entry = app.registry().get(&id)?.or_else(|| app.resolve(&id).ok()).with_context(|| format!("no registered app '{id}'"))?;
    let host = sam_core::HostInfo::probe();
    let rec = run(&mut entry, &LaunchOptions { args: rest, ..Default::default() }, &app.config, &app.paths, &host)?;
    if rec.sandbox_failure {
        notify(&format!("{} failed to start", entry.display_name()), &format!("{}\nOpen SAM → {} → Details & Repair.", rec.summary, entry.display_name()));
        bail!("{}", rec.summary);
    }
    // A crash within the first seconds usually means the sandbox is missing
    // something: say what the output suggests.
    if !rec.success && rec.finished_at - rec.started_at <= 10 {
        let hint = rec.findings.first().map(|f| format!("Likely cause: {}.", f.title)).unwrap_or_else(|| "Try the repair steps.".into());
        notify(&format!("{} stopped right after starting", entry.display_name()), &format!("{} {hint}\nOpen SAM → {} → Details & Repair.", rec.summary, entry.display_name()));
    }
    Ok(rec.exit_code.unwrap_or(if rec.success { 0 } else { 1 }))
}
