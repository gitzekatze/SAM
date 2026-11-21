//! `sam-jail-run`: the launcher used by desktop entries
//! (`Exec=sam-jail-run --app-id <id> %F`), and the in-sandbox helper that
//! applies Landlock before exec (`--sandbox-exec <spec> -- <cmd>`).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use sam_core::errln;
use sam_core::error::InFunctionExt;
use sam_core::util::which;
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::Sam;

fn usage() -> ! {
    errln!("usage: sam-jail-run --app-id <id> [files...]\n       sam-jail-run <id> [args...]");
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

/// The arguments as text, or the first one that is not (shown with its
/// odd bytes replaced).
fn text_args(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Vec<String>, String> {
    args.map(|a| {
        a.into_string()
            .map_err(|a| a.to_string_lossy().into_owned())
    })
    .collect()
}

fn main() {
    sam_core::i18n::init(true);
    // A file name that is not valid text (Linux allows any bytes) ends the
    // start with a message: std::env::args() would panic on it, and a
    // replaced character would name another file (audit S-F15).
    // Inside an app's sandbox in place of `bwrap` (Room service's stand-in),
    // before anything else: its arguments are a program's, not file names
    // given to SAM (one that is not text is refused like any bad option).
    if std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == "--room-standin")
    {
        let args: Vec<String> = std::env::args_os()
            .skip(2)
            .map(|a| a.into_string().unwrap_or_else(|_| "--not-text".into()))
            .collect();
        let version = args.first().cloned().unwrap_or_default();
        std::process::exit(sam_runner::room_service::standin(
            &version,
            &args[1.min(args.len())..],
        ));
    }
    let args = match text_args(std::env::args_os().skip(1)) {
        Ok(a) => a,
        Err(name) => {
            let message = sam_core::i18n::trf(
                "SAM cannot pass on {path}: its name is not valid text. Rename it, then start the app again.",
                &[("path", &name)],
            );
            errln!("sam-jail-run: {message}");
            notify(&sam_core::i18n::tr("SAM could not start the app"), &message);
            std::process::exit(1);
        }
    };
    if args.first().map(String::as_str) == Some("--sandbox-exec") {
        let spec = args.get(1).map(PathBuf::from).unwrap_or_else(|| usage());
        let rest: Vec<String> = match args.iter().position(|a| a == "--") {
            Some(i) => args[i + 1..].to_vec(),
            None => usage(),
        };
        if let Err(e) = sam_runner::kernel::sandbox_exec(&spec, &rest) {
            errln!("sam-jail-run: {e:#}");
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
            errln!("sam-jail-run: {message} ({part})");
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
    if let Err(e) = app.check_before_start(&mut entry, &host) {
        // Only a failed check gets the notification: it names what to look at.
        if sam_core::error::code_of(&e) == Some("sandbox-check-failed") {
            notify(
                &sam_core::i18n::trf("{app} was not started", &[("app", &entry.display_name())]),
                &sam_core::i18n::trf(
                    "{reason}.\nOpen SAM → {app} → Test.",
                    &[
                        ("reason", &format!("{e:#}")),
                        ("app", &entry.display_name()),
                    ],
                ),
            );
        }
        return Err(e);
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
            errln!(
                "\n{}",
                sam_core::i18n::trf(
                    "{app} ended: {summary}",
                    &[("app", &entry.display_name()), ("summary", &rec.summary)]
                )
            );
        } else {
            errln!(
                "\n{}",
                sam_core::i18n::trf(
                    "{app} did not run: {summary}",
                    &[("app", &entry.display_name()), ("summary", &rec.summary)]
                )
            );
            if let Some(f) = rec.findings.first() {
                errln!(
                    "{}",
                    sam_core::i18n::trf(
                        "SAM found a likely fix: {fix}. Open SAM to apply it.",
                        &[("fix", &f.title)]
                    )
                );
            }
        }
        sam_core::terminal::print_err_raw_end(&sam_core::i18n::tr(
            "Press Enter to close this window.",
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    /// A file name with bytes that are not text is named in the message,
    /// never passed on changed and never a crash (audit S-F15).
    #[test]
    fn a_file_name_that_is_not_text_is_refused_by_name() {
        let ok = vec!["--app-id".into(), "x".into(), "/home/a b.txt".into()];
        assert_eq!(
            text_args(ok.clone().into_iter()),
            Ok(vec![
                "--app-id".to_string(),
                "x".into(),
                "/home/a b.txt".into()
            ])
        );
        let odd = std::ffi::OsString::from_vec(b"/home/j\xffo.txt".to_vec());
        let e = text_args(vec!["--app-id".into(), "x".into(), odd].into_iter()).unwrap_err();
        assert_eq!(e, "/home/j\u{FFFD}o.txt");
    }
}
