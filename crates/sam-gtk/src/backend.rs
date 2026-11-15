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

    /// Runs `sam-jail --json <args>`, optionally with JSON on stdin.
    pub async fn call(&self, args: &[&str], input: Option<String>) -> Reply {
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
        let proc = gio::Subprocess::newv(&argv_ref, flags).map_err(|e| {
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
        let proc = gio::Subprocess::newv(&argv_ref, flags).map_err(|e| {
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
            .map_err(|e| format!("sam-jail failed: {e}"))?;
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
        let info = gio::AppInfo::create_from_commandline(
            &cmd,
            Some(name),
            gio::AppInfoCreateFlags::NEEDS_TERMINAL,
        )
        .map_err(|e| crate::i18n::trf("Could not start a terminal: {error}", &[("error", &e)]))?;
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
        let proc = gio::Subprocess::newv(&argv_ref, gio::SubprocessFlags::NONE).map_err(|e| {
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

/// Lookup order: an environment override, next to this binary, the newest
/// build of a source checkout (`target/release` or `target/debug`), $PATH.
pub(crate) fn find_tool(name: &str, env: &str) -> PathBuf {
    if let Some(p) = std::env::var_os(env).filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf));
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(d) = &exe_dir {
        candidates.push(d.join(name));
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
        });
    if let Some(p) = newest {
        return p.canonicalize().unwrap_or(p);
    }
    if let Some(path) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&path) {
            let c = d.join(name);
            if c.is_file() {
                return c;
            }
        }
    }
    PathBuf::from(name)
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
