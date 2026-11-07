//! `appseal-run`: the launcher used by desktop entries
//! (`Exec=appseal-run --app-id <id> %F`), and the in-sandbox helper that
//! applies Landlock before exec (`--sandbox-exec <spec> -- <cmd>`).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use appseal_core::util::which;
use appseal_runner::launch::{run, LaunchOptions};
use appseal_runner::ops::Appseal;

fn usage() -> ! {
    eprintln!("usage: appseal-run --app-id <id> [files...]\n       appseal-run <id> [args...]");
    std::process::exit(2);
}

/// Desktop launches have no terminal: tell the user through a notification.
fn notify(title: &str, body: &str) {
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        return;
    }
    if let Some(n) = which("notify-send") {
        let _ = Command::new(n).args(["--app-name=Appseal", "--icon=dialog-warning", title, body]).status();
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
        if let Err(e) = appseal_runner::kernel::sandbox_exec(&spec, &rest) {
            eprintln!("appseal-run: {e:#}");
            std::process::exit(127);
        }
        return;
    }
    match launch(args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("appseal-run: {e:#}");
            notify("Appseal could not start the app", &format!("{e:#}\nOpen Appseal to repair it."));
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
    let app = Appseal::open()?;
    let mut entry = app.registry().get(&id)?.or_else(|| app.resolve(&id).ok()).with_context(|| format!("no registered app '{id}'"))?;
    let host = appseal_core::HostInfo::probe();
    let rec = run(&mut entry, &LaunchOptions { args: rest, ..Default::default() }, &app.config, &app.paths, &host)?;
    if rec.sandbox_failure {
        notify(&format!("{} failed to start", entry.display_name()), &format!("{}\nOpen Appseal → {} → Repair.", rec.summary, entry.display_name()));
        bail!("{}", rec.summary);
    }
    Ok(rec.exit_code.unwrap_or(if rec.success { 0 } else { 1 }))
}
