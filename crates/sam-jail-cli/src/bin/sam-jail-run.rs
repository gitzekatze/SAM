//! `sam-jail-run`: the launcher used by desktop entries
//! (`Exec=sam-jail-run --app-id <id> %F`), and the in-sandbox helper that
//! applies Landlock before exec (`--sandbox-exec <spec> -- <cmd>`).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use sam_core::error::InFunctionExt;
use sam_core::util::which;
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::Sam;

fn usage() -> ! {
    eprintln!("usage: sam-jail-run --app-id <id> [files...]\n       sam-jail-run <id> [args...]");
    std::process::exit(2);
}

/// Like `notify`, with a "Show the fix" button that opens SAM at the app.
/// The button is waited for in a background process, so the launcher can
/// exit; names and messages are passed as arguments, never as shell code.
fn notify_with_fix(title: &str, body: &str, app_id: &str) {
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        return;
    }
    let (Some(n), Some(gui)) = (which("notify-send"), sam_gui()) else {
        return notify(title, body);
    };
    let clean = |s: &str| sam_core::util::display_safe(s, 400).replace('&', "&amp;");
    let script = r#"a=$("$1" --app-name="SAM - Sandboxed AppImage Manager" --icon=dialog-warning --action=open="$6" "$2" "$3") && [ "$a" = open ] && exec "$4" --page app-repair --app "$5""#;
    let spawned = Command::new("/bin/sh")
        .args(["-c", script, "sh"])
        .arg(n)
        .args([clean(title), clean(body)])
        .arg(gui)
        .arg(app_id)
        // The button's label, as an argument too (never part of the script).
        .arg(clean(&sam_core::i18n::tr("Show the fix")))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if spawned.is_err() {
        notify(title, body);
    }
}

/// SAM's window: SAM's own AppImage, next to this program, or on $PATH.
fn sam_gui() -> Option<PathBuf> {
    if let Some(a) = std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
    {
        return Some(a);
    }
    let here = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("sam-jail-gui")))
        .filter(|p| p.is_file());
    here.or_else(|| which("sam-jail-gui"))
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
        let _ = Command::new(n)
            .args([
                "--app-name=SAM - Sandboxed AppImage Manager",
                "--icon=dialog-warning",
                &clean(title),
                &clean(body),
            ])
            .status();
    }
}

fn main() {
    sam_core::i18n::init(true);
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
    // Starting from the menu is function 19; steps of another function
    // (unpacking again: 3) mark their errors themselves.
    match launch(args).in_function(19) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            let message = sam_core::error::message_of(&e);
            let function = sam_core::error::function_of(&e).unwrap_or(19);
            let part = sam_core::i18n::trf("SAM function {id}", &[("id", &function)]);
            eprintln!("sam-jail-run: {message} ({part})");
            notify(
                &sam_core::i18n::tr("SAM could not start the app"),
                &sam_core::i18n::trf(
                    "{error}\nOpen SAM to repair it.",
                    &[("error", &format!("{message} ({part})"))],
                ),
            );
            std::process::exit(1);
        }
    }
}

fn launch(args: Vec<String>) -> Result<i32> {
    let (id, rest) = match args.first().map(String::as_str) {
        Some("--app-id") => (
            args.get(1).cloned().unwrap_or_else(|| usage()),
            args[2.min(args.len())..].to_vec(),
        ),
        Some("-h") | Some("--help") | None => usage(),
        Some(_) => (args[0].clone(), args[1..].to_vec()),
    };
    // Strip a leading "--" separator.
    let rest: Vec<String> = match rest.first().map(String::as_str) {
        Some("--") => rest[1..].to_vec(),
        _ => rest,
    };
    let app = Sam::open()?;
    let mut entry = app
        .registry()
        .get(&id)?
        .or_else(|| app.resolve(&id).ok())
        .with_context(|| sam_core::i18n::trf("no registered app '{id}'", &[("id", &id)]))?;
    // After "Free space": unpack again first (the file is unchanged).
    app.ensure_unpacked(&mut entry)
        .context(sam_core::i18n::tr("unpacking the AppImage again"))
        .in_function(3)?;
    let host = sam_core::HostInfo::probe();
    if app.config.security.check_before_launch {
        // Only when the settings, SAM or this computer changed since the
        // last passing check; a failed check stops the start.
        let key = sam_runner::verify::check_key(&entry, &app.config, &host);
        let fresh = entry
            .last_check
            .as_ref()
            .is_some_and(|c| c.key == key && c.failed.is_empty());
        if !fresh {
            let out = app
                .verify(&entry.id)
                .context(sam_core::i18n::tr("checking the sandbox before starting"))?;
            if !out.record.failed.is_empty() {
                let list = out.record.failed.join(", ");
                notify(
                    &sam_core::i18n::trf("{app} was not started", &[("app", &entry.display_name())]),
                    &sam_core::i18n::trf(
                        "The sandbox check found settings that do not apply: {list}.\nOpen SAM → {app} → Sandbox Check.",
                        &[("list", &list), ("app", &entry.display_name())],
                    ),
                );
                bail!(
                    "{}",
                    sam_core::i18n::trf("sandbox check failed: {list}", &[("list", &list)])
                );
            }
            entry.last_check = Some(out.record);
        }
    }
    let rec = run(
        &mut entry,
        &LaunchOptions {
            args: rest,
            ..Default::default()
        },
        &app.config,
        &app.paths,
        &host,
    )?;
    // A terminal program from the menu: its window closes with it, so a
    // failure would flash by unread.
    if entry.metadata.terminal && rec.exit_code != Some(0) && sam_runner::pty::is_tty(0) {
        if rec.success {
            eprintln!(
                "\n{}",
                sam_core::i18n::trf(
                    "{app} ended: {summary}",
                    &[("app", &entry.display_name()), ("summary", &rec.summary)]
                )
            );
        } else {
            eprintln!(
                "\n{}",
                sam_core::i18n::trf(
                    "{app} did not run: {summary}",
                    &[("app", &entry.display_name()), ("summary", &rec.summary)]
                )
            );
            if let Some(f) = rec.findings.first() {
                eprintln!(
                    "{}",
                    sam_core::i18n::trf(
                        "SAM found a likely fix: {fix}. Open SAM to apply it.",
                        &[("fix", &f.title)]
                    )
                );
            }
        }
        eprint!(
            "{}",
            sam_core::i18n::tr("Press Enter to close this window.")
        );
        let _ = std::io::stdin().read_line(&mut String::new());
    }
    if rec.sandbox_failure {
        notify_with_fix(
            &sam_core::i18n::trf("{app} failed to start", &[("app", &entry.display_name())]),
            &rec.summary,
            &entry.id,
        );
        bail!("{}", rec.summary);
    }
    // A crash within the first seconds usually means the sandbox is missing
    // something: say what the output suggests.
    if !rec.success && rec.finished_at - rec.started_at <= 10 {
        let hint = match rec.findings.first() {
            Some(f) => sam_core::i18n::trf("SAM found a likely fix: {fix}.", &[("fix", &f.title)]),
            None => sam_core::i18n::tr("SAM's repair steps may help."),
        };
        notify_with_fix(
            &sam_core::i18n::trf(
                "{app} stopped right after starting",
                &[("app", &entry.display_name())],
            ),
            &format!("{} {hint}", rec.summary),
            &entry.id,
        );
    }
    Ok(rec.exit_code.unwrap_or(if rec.success { 0 } else { 1 }))
}
