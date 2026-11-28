// SPDX-License-Identifier: GPL-3.0-or-later
//! Bridge to SAM's command line tools. The GUI never touches SAM's files
//! itself: every operation runs `sam-jail --json …` asynchronously and reads
//! the `{"ok": …, "data"|"error": …}` envelope, and apps start through
//! `sam-jail-run`, exactly like the menu launchers.

use std::cell::Cell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::SystemTime;

use gtk::gio;
use gtk::gio::prelude::AppInfoExt;
use gtk::glib;
use serde_json::Value;

#[derive(Clone)]
pub struct Backend {
    pub cli: PathBuf,
    pub runner: PathBuf,
    busy: Rc<Cell<u32>>,
    busy_changed: Rc<dyn Fn(bool)>,
}

pub type Reply = Result<Value, CliError>;

/// An error from `sam-jail`: the message for people, plus the code the
/// window may react to (`signing-key-changed`, `cli-not-started`). The
/// message may be translated, so decisions go by the code only. It reads
/// like the message everywhere a string is expected.
#[derive(Debug, Clone, PartialEq)]
pub struct CliError {
    pub code: Option<String>,
    pub message: String,
}

impl CliError {
    pub fn coded(code: &str, message: impl Into<String>) -> Self {
        CliError {
            code: Some(code.to_string()),
            message: message.into(),
        }
    }
    pub fn is(&self, code: &str) -> bool {
        self.code.as_deref() == Some(code)
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        CliError {
            code: None,
            message: message.to_string(),
        }
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        CliError {
            code: None,
            message,
        }
    }
}

impl std::ops::Deref for CliError {
    type Target = str;
    fn deref(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Backend {
    pub fn new(busy_changed: impl Fn(bool) + 'static) -> Self {
        Backend {
            cli: find_tool("sam-jail", "SAM_CLI"),
            runner: find_tool("sam-jail-run", "SAM_RUN"),
            busy: Rc::new(Cell::new(0)),
            busy_changed: Rc::new(busy_changed),
        }
    }

    /// Runs `sam-jail --json <args>`, optionally with JSON on stdin. It
    /// refuses the commands that go online (`updates`, `update`,
    /// `self-update`): the window runs those only through
    /// [`Backend::call_online`], whose every caller is listed in
    /// crates/sam-jail-cli/tests/network_use.rs, so a new place that goes
    /// online cannot hide behind a list of words.
    pub async fn call(&self, args: &[&str], input: Option<String>) -> Reply {
        refuse_online(args)?;
        self.counted(args, input).await
    }

    /// [`Backend::call`] for the commands that go online. Every caller is
    /// a place where the person asked for an update check or an update (or
    /// the window's start, which checks only when the person switched that
    /// on), listed in crates/sam-jail-cli/tests/network_use.rs.
    pub async fn call_online(&self, args: &[&str], input: Option<String>) -> Reply {
        self.counted(args, input).await
    }

    /// Runs the command while the window shows that it is busy.
    async fn counted(&self, args: &[&str], input: Option<String>) -> Reply {
        self.busy.set(self.busy.get() + 1);
        (self.busy_changed)(true);
        let r = self.call_inner(args, input).await;
        self.busy.set(self.busy.get() - 1);
        (self.busy_changed)(self.busy.get() > 0);
        r
    }

    /// Like [`Backend::call`], for commands run with `--progress`: each
    /// `{"progress": …}` line they print on stderr goes to `on_progress`
    /// while they run.
    pub async fn call_with_progress(
        &self,
        args: &[&str],
        input: Option<String>,
        on_progress: impl Fn(&Value) + 'static,
    ) -> Reply {
        refuse_online(args)?;
        self.busy.set(self.busy.get() + 1);
        (self.busy_changed)(true);
        let r = self.call_progress_inner(args, input, on_progress).await;
        self.busy.set(self.busy.get() - 1);
        (self.busy_changed)(self.busy.get() > 0);
        r
    }

    async fn call_progress_inner(
        &self,
        args: &[&str],
        input: Option<String>,
        on_progress: impl Fn(&Value) + 'static,
    ) -> Reply {
        use gtk::gio::prelude::*;
        let mut argv: Vec<OsString> = vec![self.cli.clone().into(), "--json".into()];
        argv.extend(args.iter().map(OsString::from));
        let argv_ref: Vec<&std::ffi::OsStr> = argv.iter().map(|a| a.as_os_str()).collect();
        let mut flags = gio::SubprocessFlags::STDOUT_PIPE | gio::SubprocessFlags::STDERR_PIPE;
        if input.is_some() {
            flags |= gio::SubprocessFlags::STDIN_PIPE;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "way out: sam-jail, SAM's command line tool"
        )]
        let started = gio::Subprocess::newv(&argv_ref, flags);
        let proc = started.map_err(|e| {
            CliError::coded(
                "cli-not-started",
                crate::i18n::trf(
                    "Could not start {program}: {error}. Is SAM installed correctly?",
                    &[("program", &self.cli.display()), ("error", &e)],
                ),
            )
        })?;
        if let (Some(text), Some(stdin)) = (input, proc.stdin_pipe()) {
            let _ = stdin
                .write_all_future(text.into_bytes(), glib::Priority::DEFAULT)
                .await;
            let _ = stdin.close_future(glib::Priority::DEFAULT).await;
        }
        // stderr: progress lines as they come, everything else kept for an
        // error message.
        let errors = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
        let stderr_done = proc.stderr_pipe().map(|err| {
            let errors = errors.clone();
            glib::spawn_future_local(async move {
                let lines = gio::DataInputStream::new(&err);
                while let Ok(Some(line)) =
                    lines.read_line_utf8_future(glib::Priority::DEFAULT).await
                {
                    match serde_json::from_str::<Value>(line.trim()) {
                        Ok(v) if v.get("progress").is_some() => on_progress(&v["progress"]),
                        _ => {
                            let mut e = errors.borrow_mut();
                            e.push_str(&line);
                            e.push('\n');
                        }
                    }
                }
            })
        });
        let mut out = Vec::new();
        if let Some(stdout) = proc.stdout_pipe() {
            while let Ok(chunk) = stdout
                .read_bytes_future(64 * 1024, glib::Priority::DEFAULT)
                .await
            {
                if chunk.is_empty() {
                    break;
                }
                out.extend_from_slice(&chunk);
            }
        }
        let _ = proc.wait_future().await;
        if let Some(h) = stderr_done {
            let _ = h.await;
        }
        let out = String::from_utf8_lossy(&out);
        if let Some(r) = envelope(&out) {
            return r;
        }
        let err = errors.borrow().trim().to_string();
        Err(CliError::from(if err.is_empty() {
            crate::i18n::tr("No response from the sam-jail command line tool.")
        } else {
            err
        }))
    }

    async fn call_inner(&self, args: &[&str], input: Option<String>) -> Reply {
        let mut argv: Vec<OsString> = vec![self.cli.clone().into(), "--json".into()];
        argv.extend(args.iter().map(OsString::from));
        let argv_ref: Vec<&std::ffi::OsStr> = argv.iter().map(|a| a.as_os_str()).collect();
        let mut flags = gio::SubprocessFlags::STDOUT_PIPE | gio::SubprocessFlags::STDERR_PIPE;
        if input.is_some() {
            flags |= gio::SubprocessFlags::STDIN_PIPE;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "way out: sam-jail, SAM's command line tool"
        )]
        let started = gio::Subprocess::newv(&argv_ref, flags);
        let proc = started.map_err(|e| {
            CliError::coded(
                "cli-not-started",
                crate::i18n::trf(
                    "Could not start {program}: {error}. Is SAM installed correctly?",
                    &[("program", &self.cli.display()), ("error", &e)],
                ),
            )
        })?;
        let (out, err) = proc
            .communicate_utf8_future(input)
            .await
            .map_err(|e| crate::i18n::trf("sam-jail failed: {error}", &[("error", &e)]))?;
        let out = out.map(|s| s.to_string()).unwrap_or_default();
        if let Some(r) = envelope(&out) {
            return r;
        }
        let err = err.map(|s| s.trim().to_string()).unwrap_or_default();
        Err(CliError::from(if err.is_empty() {
            crate::i18n::tr("No response from the sam-jail command line tool.")
        } else {
            err
        }))
    }

    /// Starts an app in its sandbox. The app keeps running when SAM closes;
    /// `on_exit` gets the exit code while SAM is open.
    /// A terminal program: opened in the user's terminal emulator (GIO picks
    /// it), like a menu entry with `Terminal=true`.
    pub fn launch_in_terminal(&self, app_id: &str, name: &str) -> Result<(), String> {
        let cmd = format!(
            "{} --app-id {}",
            glib::shell_quote(&self.runner).to_string_lossy(),
            glib::shell_quote(app_id).to_string_lossy()
        );
        let flags = gio::AppInfoCreateFlags::NEEDS_TERMINAL;
        #[expect(clippy::disallowed_methods, reason = "way out: the terminal GIO picks")]
        let info = gio::AppInfo::create_from_commandline(&cmd, Some(name), flags);
        let info = info.map_err(|e| {
            crate::i18n::trf("Could not start a terminal: {error}", &[("error", &e)])
        })?;
        info.launch(&[], gio::AppLaunchContext::NONE)
            .map_err(|e| crate::i18n::trf("Could not start a terminal: {error}", &[("error", &e)]))
    }

    pub fn launch(
        &self,
        app_id: &str,
        files: &[String],
        on_exit: impl FnOnce(i32) + 'static,
    ) -> Result<(), String> {
        let mut argv: Vec<OsString> =
            vec![self.runner.clone().into(), "--app-id".into(), app_id.into()];
        argv.extend(files.iter().map(OsString::from));
        let argv_ref: Vec<&std::ffi::OsStr> = argv.iter().map(|a| a.as_os_str()).collect();
        #[expect(
            clippy::disallowed_methods,
            reason = "way out: sam-jail-run, to start an app"
        )]
        let started = gio::Subprocess::newv(&argv_ref, gio::SubprocessFlags::NONE);
        let proc = started.map_err(|e| {
            crate::i18n::trf("Could not start sam-jail-run: {error}", &[("error", &e)])
        })?;
        glib::spawn_future_local(async move {
            let _ = proc.wait_future().await;
            let code = if proc.has_exited() {
                proc.exit_status()
            } else {
                -1
            };
            on_exit(code);
        });
        Ok(())
    }
}

/// The arguments for `sam-jail preset SUB`: options first, then `--`, then
/// the names and files. A preset called `-x` is then a name, never an
/// option (audit G-F20).
pub(crate) fn preset_args<'a>(
    sub: &'a str,
    options: &[&'a str],
    operands: &[&'a str],
) -> Vec<&'a str> {
    let mut v = vec!["preset", sub];
    v.extend_from_slice(options);
    v.push("--");
    v.extend_from_slice(operands);
    v
}

/// Where the window finds SAM's command line tools: next to this program,
/// then on `$PATH` where the user cannot change it
/// ([`sam_core::util::which`]). Only a developer build also takes the
/// newest build of its source checkout (`target/release` or
/// `target/debug`): a release build that looked there would run
/// `~/.local/debug/sam-jail`, which an app with write access to the home
/// can create, when SAM is installed in `~/.local/bin` (audit G-F10).
pub(crate) fn find_tool(name: &str, env: &str) -> PathBuf {
    find_tool_in(name, env, &sam_core::util::DeveloperVars::of_this_build())
}

/// [`find_tool`] with the developer variables `dev`. Only a developer
/// build takes a program named in the variable `env` (`SAM_CLI`,
/// `SAM_RUN`): in a release build a line planted in the desktop's
/// environment would make the window run another program outside any
/// sandbox (owner decision 16 of 2026-11-23).
fn find_tool_in(name: &str, env: &str, dev: &sam_core::util::DeveloperVars) -> PathBuf {
    if let Some(p) = dev.get(env) {
        return PathBuf::from(p);
    }
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf));
    tool_from(exe_dir.as_deref(), name, dev.developer_build())
        .or_else(|| sam_core::util::which(name))
        // Not found: a path that starts nothing, never a bare name that
        // the system would look up on `$PATH` without SAM's check.
        .unwrap_or_else(|| PathBuf::from("/nonexistent").join(name))
}

/// find_tool's rule for the program folder `exe_dir`: next to it, and in a
/// developer build also the newest sibling build folder.
fn tool_from(exe_dir: Option<&Path>, name: &str, developer_build: bool) -> Option<PathBuf> {
    let d = exe_dir?;
    let mut candidates = vec![d.join(name)];
    if developer_build {
        for profile in ["release", "debug"] {
            candidates.push(d.join("..").join(profile).join(name));
        }
    }
    let newest = candidates
        .into_iter()
        .filter(|p| p.is_file())
        .max_by_key(|p| {
            p.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH)
        })?;
    Some(newest.canonicalize().unwrap_or(newest))
}

/// Whether `args` is a `sam-jail` command that goes online: its first word
/// that is not an option is `updates`, `update` or `self-update`.
fn online_command(args: &[&str]) -> bool {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .is_some_and(|c| matches!(*c, "updates" | "update" | "self-update"))
}

/// An error for a command that goes online, which only
/// [`Backend::call_online`] runs.
fn refuse_online(args: &[&str]) -> Result<(), CliError> {
    if online_command(args) {
        return Err(CliError::coded(
            "online-command",
            crate::i18n::tr(
                "SAM did not run this command: the window goes online only through its update actions.",
            ),
        ));
    }
    Ok(())
}

/// The reply in `sam-jail --json` output: the last JSON object line on
/// stdout with an `ok` field.
fn envelope(out: &str) -> Option<Reply> {
    for line in out.lines().rev() {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(line.trim()) {
            if let Some(ok) = m.get("ok").and_then(Value::as_bool) {
                return Some(if ok {
                    Ok(m.get("data").cloned().unwrap_or(Value::Null))
                } else {
                    Err(CliError {
                        code: m.get("code").and_then(Value::as_str).map(str::to_string),
                        message: m
                            .get("error")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                            .unwrap_or_else(|| crate::i18n::tr("Unknown error")),
                    })
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// The window's ordinary way to run a command refuses the three that go
    /// online, also after an option, so they run only through
    /// `call_online`, whose callers are listed; every other command passes.
    #[test]
    fn the_window_runs_update_commands_only_through_call_online() {
        for args in [
            &["updates"][..],
            &["updates", "--if-due"],
            &["update", "appimage-a-1"],
            &["update", "appimage-a-1", "--undo"],
            &["self-update", "--check"],
            &["--json", "self-update"],
        ] {
            assert!(online_command(args), "{args:?}");
            assert!(
                refuse_online(args).is_err_and(|e| e.is("online-command")),
                "{args:?}"
            );
        }
        for args in [
            &[][..],
            &["list"],
            &["config", "get", "updates.check_on_start"],
            &["preset", "show", "--", "update"],
            &["--json", "doctor"],
        ] {
            assert!(!online_command(args), "{args:?}");
            assert!(refuse_online(args).is_ok(), "{args:?}");
        }
    }

    /// Preset names reach SAM after `--`, so one that starts with `-` is
    /// not read as an option (audit G-F20).
    #[test]
    fn preset_names_are_never_read_as_options() {
        assert_eq!(
            preset_args("apply", &["--yes"], &["-x", "appimage-a-1"]),
            ["preset", "apply", "--yes", "--", "-x", "appimage-a-1"]
        );
        assert_eq!(
            preset_args("delete", &[], &["-x"]),
            ["preset", "delete", "--", "-x"]
        );
    }

    /// An installed (release) window runs only the command line tool next
    /// to it, never one in a neighbouring `debug` or `release` folder that
    /// an app with write access to the home could create (audit G-F10). A
    /// developer build takes the newest of its checkout's builds.
    #[test]
    fn an_installed_window_runs_only_the_tool_next_to_it() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let debug = tmp.path().join("debug");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&debug).unwrap();
        fs::write(debug.join("sam-jail"), "planted").unwrap();
        assert_eq!(tool_from(Some(&bin), "sam-jail", false), None);
        assert_eq!(
            tool_from(Some(&bin), "sam-jail", true),
            Some(debug.join("sam-jail").canonicalize().unwrap())
        );
        fs::write(bin.join("sam-jail"), "installed").unwrap();
        assert_eq!(
            tool_from(Some(&bin), "sam-jail", false),
            Some(bin.join("sam-jail").canonicalize().unwrap())
        );
        assert_eq!(tool_from(None, "sam-jail", true), None);
    }

    /// An installed (release) window never runs a program that a variable
    /// in its environment names (`SAM_CLI`, `SAM_RUN`); only a developer
    /// build does (owner decision 16 of 2026-11-23). The variables are a
    /// stand-in's.
    #[test]
    fn an_installed_window_ignores_a_program_named_in_its_environment() {
        use sam_core::util::DeveloperVars;
        let tmp = tempfile::tempdir().unwrap();
        let planted = tmp.path().join("planted-sam-jail");
        fs::write(&planted, "planted").unwrap();
        let env = |name: &str| (name == "SAM_CLI").then(|| planted.clone().into());
        let release = find_tool_in("sam-jail", "SAM_CLI", &DeveloperVars::new(false, &env));
        assert_ne!(
            release, planted,
            "a release window ran the program in SAM_CLI"
        );
        assert_eq!(
            find_tool_in("sam-jail", "SAM_CLI", &DeveloperVars::new(true, &env)),
            planted
        );
    }
}
