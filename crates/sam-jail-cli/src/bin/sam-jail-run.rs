//! `sam-jail-run`: the launcher used by desktop entries
//! (`Exec=sam-jail-run --app-id <id> %F`), and the in-sandbox helper that
//! applies Landlock before exec (`--sandbox-exec <spec> -- <cmd>`).

// The privacy check (crates/sam-jail-cli/tests/network_use.rs): every way
// this program could reach the network or start a program is an #[expect]
// listed there (clippy.toml: disallowed-methods, disallowed-types).
#![cfg_attr(not(test), deny(clippy::disallowed_methods, clippy::disallowed_types))]

use std::path::{Path, PathBuf};
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
    // A notify-send without buttons (libnotify before 0.8) shows the
    // notification without one (review of B2 R75).
    let script = r#"if a=$("$1" --app-name="SAM - Sandboxed AppImage Manager" --icon=dialog-warning --action=open="$6" "$2" "$3"); then
  [ "$a" = open ] && exec "$4" --page app-repair --app "$5"
else
  exec "$1" --app-name="SAM - Sandboxed AppImage Manager" --icon=dialog-warning "$2" "$3"
fi"#;
    #[expect(
        clippy::disallowed_methods,
        reason = "way out: /bin/sh for a desktop notice"
    )]
    let mut cmd = Command::new("/bin/sh");
    let spawned = cmd
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

/// The first argument that starts the app although a protection its
/// settings ask for is missing this time (B2 R75, R77).
const START_ANYWAY: &str = "--start-anyway";

/// The refusal of a start that lacks a protection, with a "Start anyway"
/// button that starts the same app with the same files once more, for this
/// one start. Waited for in a background process, so the launcher can
/// exit; names, files and messages are arguments, never shell code.
fn notify_start_anyway(title: &str, body: &str, asked: &[String]) {
    // The program menu entries start (SAM's AppImage, or this launcher),
    // which outlives this start: a launcher inside SAM's mounted AppImage
    // would be gone by the time the button is pressed.
    let me = sam_intake::desktop::runner_command();
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        // Also said where it was started, with the command as it runs.
        let mut command = vec![sam_core::util::shell_quote(&me), START_ANYWAY.to_string()];
        command.extend(asked.iter().map(|a| sam_core::util::shell_quote(a)));
        errln!(
            "{}",
            sam_core::i18n::trf(
                "To start it anyway this one time: {command}",
                &[("command", &command.join(" "))]
            )
        );
    }
    let Some(n) = which("notify-send") else {
        return notify(title, body);
    };
    let clean = |s: &str| sam_core::util::display_safe(s, 400).replace('&', "&amp;");
    let spawned = start_anyway_command(
        &n,
        Path::new(&me),
        &clean(title),
        &clean(body),
        &clean(&sam_core::i18n::tr("Start anyway")),
        asked,
    )
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn();
    if spawned.is_err() {
        notify(title, body);
    }
}

/// The background process of [`notify_start_anyway`]: the notification
/// with its button (`notify_send`), and on "start" the same start once
/// more through `me` with [`START_ANYWAY`] first. A `notify-send` without
/// buttons (libnotify before 0.8) shows the notification without one.
fn start_anyway_command(
    notify_send: &Path,
    me: &Path,
    title: &str,
    body: &str,
    label: &str,
    asked: &[String],
) -> Command {
    let script = r#"n=$1 title=$2 body=$3 label=$4 me=$5; shift 5
if a=$("$n" --app-name="SAM - Sandboxed AppImage Manager" --icon=dialog-warning --action=start="$label" "$title" "$body"); then
  [ "$a" = start ] && exec "$me" --start-anyway "$@"
else
  exec "$n" --app-name="SAM - Sandboxed AppImage Manager" --icon=dialog-warning "$title" "$body"
fi"#;
    #[expect(
        clippy::disallowed_methods,
        reason = "way out: /bin/sh for a desktop notice"
    )]
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", script, "sh"])
        .arg(notify_send)
        .args([title, body, label])
        .arg(me)
        .args(asked);
    cmd
}

/// "Start anyway" as the first argument (only there, as the notice starts
/// it): whether it was given, and the arguments after it.
fn start_anyway_first(args: Vec<String>) -> (bool, Vec<String>) {
    match args.split_first() {
        Some((first, rest)) if first == START_ANYWAY => (true, rest.to_vec()),
        _ => (false, args),
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
        #[expect(clippy::disallowed_methods, reason = "way out: notify-send")]
        let mut cmd = Command::new(n);
        let _ = cmd
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
    // The stand-in is a link named `bwrap` to this helper (no shell in
    // between, see room_service::STANDIN_TARGET): started under that name,
    // every argument is Bubblewrap's, and the version it answers comes
    // from the file beside the link, never from the program.
    if sam_runner::room_service::started_as_standin() {
        // Named as Bubblewrap is, also when started by this helper's own
        // path, as the program that started it expects of its `bwrap`. The
        // name decides nothing for SAM: SAM's "please quit" (Close, logout)
        // asks the stand-in like any process of the app, and the stand-in
        // passes it on to its room (room_service::standin), so the program
        // in the room gets its time to save and quit, and its room ends
        // when it has.
        // SAFETY: PR_SET_NAME reads a NUL-terminated name of at most 16
        // bytes, which this static string is.
        unsafe {
            libc::prctl(
                libc::PR_SET_NAME,
                c"bwrap".as_ptr() as libc::c_ulong,
                0,
                0,
                0,
            );
        }
        let mut args: Vec<String> = Vec::new();
        let mut not_text = false;
        for a in std::env::args_os().skip(1) {
            match a.into_string() {
                Ok(a) => args.push(a),
                Err(_) => {
                    not_text = true;
                    args.push("--not-text".into());
                }
            }
        }
        let version = sam_runner::room_service::standin_version();
        // An argument that is not text is never replaced and passed on: the
        // request starts with an option no room accepts, so it is refused
        // (and recorded) as a whole.
        if not_text {
            args.insert(0, "--not-text".into());
        }
        std::process::exit(sam_runner::room_service::standin(&version, &args));
    }
    // What this program inherited (a menu launcher's or terminal's open
    // descriptors) never reaches the app, from the menu or inside the
    // sandbox (review F6). Not as Room service's stand-in above: the
    // descriptors a program hands to it are its request.
    sam_core::util::close_inherited_on_exec();
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
    // "Start anyway, this time" (B2 R75, R77): only as the first argument,
    // as the refusal's notification starts it.
    let (start_anyway, args) = start_anyway_first(args);
    let asked = args.clone();
    match launch(args, start_anyway).in_function(19) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            let message = sam_core::error::message_of(&e);
            let function = sam_core::error::function_of(&e).unwrap_or(19);
            let part = sam_core::i18n::trf("SAM function {id}", &[("id", &function)]);
            errln!("sam-jail-run: {message} ({part})");
            // Refused for the moment (its sandbox is being changed):
            // nothing to repair, it starts once that is done.
            if sam_core::error::code_of(&e) == Some("app-being-changed") {
                notify(&sam_core::i18n::tr("SAM could not start the app"), &message);
                std::process::exit(1);
            }
            // A protection is missing for this start: the person decides.
            if sam_core::error::code_of(&e) == Some(sam_runner::launch::PROTECTION_MISSING) {
                notify_start_anyway(
                    &sam_core::i18n::tr("SAM did not start the app"),
                    &message,
                    &asked,
                );
                std::process::exit(sam_core::error::EXIT_PROTECTION_MISSING);
            }
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

/// How a start from the menu runs: with the files it was given, and told
/// at once when it lacks a protection layer.
fn launch_options(args: Vec<String>, start_anyway: bool) -> LaunchOptions {
    LaunchOptions {
        args,
        on_missing_layers: Some(tell_missing_layers),
        start_anyway,
        ..Default::default()
    }
}

/// A start from the menu has no terminal for the warning that it lacks a
/// protection layer its settings ask for (Landlock that could not be
/// applied, SAM's helper not found): a notification says it while the app
/// runs, with a button to SAM's page for the app (review K-4).
fn tell_missing_layers(app_id: &str, app_name: &str, missing: &[String]) {
    let (title, body) = missing_layers_notice(app_name, missing);
    notify_with_fix(&title, &body, app_id);
}

/// The notification's title and text for [`tell_missing_layers`].
fn missing_layers_notice(app_name: &str, missing: &[String]) -> (String, String) {
    (
        sam_core::i18n::trf(
            "{app} is running without some of its protection",
            &[("app", &app_name)],
        ),
        sam_core::i18n::trf(
            "This start runs without {layers}, which its settings ask for. It still runs in its sandbox. SAM's page for the app says why.",
            &[("layers", &missing.join(", "))],
        ),
    )
}

/// The app's id and the arguments for the app, from `--app-id <id>
/// [files...]` or `<id> [args...]`; one leading `--` before them is a
/// separator, not an argument. None asks for the usage.
fn parse_launch_args(args: &[String]) -> Option<(String, Vec<String>)> {
    let (id, rest) = match args.first().map(String::as_str) {
        Some("--app-id") => (args.get(1)?.clone(), args[2.min(args.len())..].to_vec()),
        Some("-h") | Some("--help") | None => return None,
        Some(_) => (args[0].clone(), args[1..].to_vec()),
    };
    // Strip a leading "--" separator.
    let rest: Vec<String> = match rest.first().map(String::as_str) {
        Some("--") => rest[1..].to_vec(),
        _ => rest,
    };
    Some((id, rest))
}

/// A terminal program from the menu: its window closes with it, so a
/// failure would flash by unread. Only then (a terminal app, a failed end,
/// someone at the terminal) does the window wait for Enter.
fn hold_terminal_window(terminal: bool, exit_code: Option<i32>, stdin_tty: bool) -> bool {
    terminal && exit_code != Some(0) && stdin_tty
}

fn launch(args: Vec<String>, start_anyway: bool) -> Result<i32> {
    let (id, rest) = parse_launch_args(&args).unwrap_or_else(|| usage());
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
    // No change of the sandbox until this start has ended (app_lock).
    let start = app.start_lock(&mut entry)?;
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
        } else if sam_core::error::code_of(&e) == Some("own-tmp-folder-unsafe") {
            // The message names the folder and what to do.
            notify(
                &sam_core::i18n::trf("{app} was not started", &[("app", &entry.display_name())]),
                &format!("{e:#}"),
            );
        }
        return Err(e);
    }
    let first = run(
        &mut entry,
        &launch_options(rest.clone(), start_anyway),
        &app.config,
        &app.paths,
        &host,
    );
    // A terminal program asks in its own window, which would otherwise
    // close before anyone read the refusal (review of B2 R75).
    let rec = match first {
        Err(e)
            if sam_core::error::code_of(&e) == Some(sam_runner::launch::PROTECTION_MISSING)
                && entry.metadata.terminal
                && sam_runner::pty::is_tty(0) =>
        {
            errln!("sam-jail-run: {}", sam_core::error::message_of(&e));
            sam_core::terminal::print_err_raw_end(&sam_core::i18n::tr(
                "Start it anyway, this one time? [y/N] ",
            ));
            let mut answer = String::new();
            let _ = std::io::stdin().read_line(&mut answer);
            // "yes" in the languages SAM speaks (the question offers y, j, s, o).
            let yes = ["y", "yes", "j", "ja", "s", "si", "sí", "o", "oui"];
            if !yes.contains(&answer.trim().to_lowercase().as_str()) {
                std::process::exit(sam_core::error::EXIT_PROTECTION_MISSING);
            }
            run(
                &mut entry,
                &launch_options(rest, true),
                &app.config,
                &app.paths,
                &host,
            )?
        }
        other => other?,
    };
    // Ended: the window's "press Enter" below must not hold it.
    drop(start);
    if hold_terminal_window(
        entry.metadata.terminal,
        rec.exit_code,
        sam_runner::pty::is_tty(0),
    ) {
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
    if rec.stopped_right_after_start() {
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
    use std::fs;
    use std::os::unix::ffi::OsStringExt;

    /// B2 R75: "Start anyway" counts only as the first argument, as the
    /// notice starts it; anywhere else it is a file for the app.
    #[test]
    fn start_anyway_counts_only_as_the_first_argument() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            start_anyway_first(v(&["--start-anyway", "--app-id", "x", "f"])),
            (true, v(&["--app-id", "x", "f"]))
        );
        assert_eq!(
            start_anyway_first(v(&["--app-id", "x", "--start-anyway"])),
            (false, v(&["--app-id", "x", "--start-anyway"]))
        );
        assert_eq!(start_anyway_first(vec![]), (false, vec![]));
    }

    /// B2 R75: the notice's button starts the same app with the same files
    /// once more, each exactly as given (names that look like options,
    /// `--`, spaces), with "Start anyway" first; a `notify-send` without
    /// buttons still shows the notice, and nothing is started then.
    #[test]
    fn the_start_anyway_button_starts_the_same_files_once_more() {
        let t = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| {
            let p = t.path().join(name);
            fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
            p
        };
        let calls = t.path().join("calls");
        let me = script(
            "me",
            &format!(
                "for a in \"$@\"; do printf '%s\\n' \"$a\"; done > {}",
                calls.display()
            ),
        );
        // Presses the button.
        let presses = script("presses", "echo start");
        let asked: Vec<String> = ["--app-id", "x", "-x", "--", "--start-anyway", "a b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let run = |n: &Path| {
            start_anyway_command(n, &me, "T", "B", "Start anyway", &asked)
                .status()
                .unwrap()
        };
        assert!(run(&presses).success());
        let got = fs::read_to_string(&calls).unwrap();
        let mut want = vec!["--start-anyway".to_string()];
        want.extend(asked.iter().cloned());
        assert_eq!(got.lines().collect::<Vec<_>>(), want, "{got}");

        // Too old for buttons: it refuses --action, then shows the notice.
        fs::remove_file(&calls).unwrap();
        let shown = t.path().join("shown");
        let old = script(
            "old",
            &format!(
                "case \"$*\" in *--action=*) exit 1 ;; esac\nprintf '%s\\n' \"$@\" > {}",
                shown.display()
            ),
        );
        assert!(run(&old).success());
        let notice = fs::read_to_string(&shown).unwrap();
        assert!(
            notice.lines().any(|l| l == "T") && notice.lines().any(|l| l == "B"),
            "{notice}"
        );
        assert!(!calls.exists(), "nothing started");

        // Closed without pressing: nothing started, no second notice.
        fs::remove_file(&shown).unwrap();
        let closes = script("closes", &format!("echo > {}", shown.display()));
        let _ = run(&closes);
        assert!(!calls.exists(), "nothing started");
        assert_eq!(fs::read_to_string(&shown).unwrap(), "\n", "shown once");
    }

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

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// The files from the menu and the arguments typed after the id reach
    /// the app as given; only one leading `--` is a separator (the app never
    /// sees it as its first argument), a later one is the app's.
    #[test]
    fn the_app_gets_its_arguments_without_the_separator() {
        let parse = |a: &[&str]| parse_launch_args(&strings(a));
        for (given, id, rest) in [
            (&["ID"][..], "ID", &[][..]),
            (&["ID", "--", "a", "b"], "ID", &["a", "b"]),
            (&["ID", "a", "--"], "ID", &["a", "--"]),
            (&["ID", "--", "--"], "ID", &["--"]),
            (&["--app-id", "ID", "--", "f"], "ID", &["f"]),
            (
                &["--app-id", "ID", "/home/a b.txt"],
                "ID",
                &["/home/a b.txt"],
            ),
        ] {
            assert_eq!(
                parse(given),
                Some((id.to_string(), strings(rest))),
                "{given:?}"
            );
        }
        for usage in [&[][..], &["-h"], &["--help"], &["--app-id"]] {
            assert_eq!(parse(usage), None, "{usage:?} asks for the usage");
        }
    }

    /// A terminal app's window waits for Enter only after a failed end, and
    /// only with someone at the terminal; a clean end closes it at once, and
    /// a graphical app never waits.
    #[test]
    fn only_a_failed_terminal_app_keeps_its_window_open() {
        for (terminal, exit_code, stdin_tty, hold) in [
            (true, Some(1), true, true),
            (true, None, true, true),
            (true, Some(0), true, false),
            (true, Some(1), false, false),
            (false, Some(1), true, false),
            (false, Some(0), true, false),
            (false, Some(1), false, false),
        ] {
            assert_eq!(
                hold_terminal_window(terminal, exit_code, stdin_tty),
                hold,
                "terminal {terminal}, exit code {exit_code:?}, at a terminal {stdin_tty}"
            );
        }
    }

    /// "Show the fix" opens SAM's own AppImage when SAM runs from one; with
    /// no SAM window anywhere there is no button (a plain notice), never a
    /// button that runs nothing. The only test here that changes the
    /// environment, and the others do not read it.
    #[test]
    fn the_fix_button_opens_sam_only_when_sam_is_found() {
        let tmp = tempfile::tempdir().unwrap();
        let gui = tmp.path().join("SAM-x86_64.AppImage");
        std::fs::write(&gui, "").unwrap();
        let empty = tmp.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        assert!(
            !std::env::current_exe()
                .unwrap()
                .with_file_name("sam-jail-gui")
                .exists(),
            "no SAM window next to the test program"
        );
        let path = std::env::var_os("PATH");
        std::env::set_var("PATH", &empty);
        std::env::set_var("APPIMAGE", &gui);
        let found = sam_gui();
        std::env::set_var("APPIMAGE", tmp.path().join("gone.AppImage"));
        let missing = sam_gui();
        std::env::remove_var("APPIMAGE");
        let unset = sam_gui();
        match path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        assert_eq!(found, Some(gui));
        assert_eq!(missing, None, "a missing AppImage file is no SAM window");
        assert_eq!(unset, None);
    }

    /// Review K-4: a start from the menu is told at once when it lacks a
    /// protection layer, and the notification names each missing layer.
    #[test]
    fn a_menu_start_is_told_when_a_protection_layer_is_missing() {
        let opts = launch_options(vec!["a.txt".into()], false);
        assert_eq!(opts.args, ["a.txt"]);
        assert!(
            opts.on_missing_layers.is_some(),
            "the menu start asks to be told"
        );
        let (title, body) = missing_layers_notice("Notes", &["Landlock".into(), "seccomp".into()]);
        assert!(title.contains("Notes"), "{title}");
        assert!(body.contains("Landlock, seccomp"), "{body}");
    }
}
