//! Launching (build plan §3.6 tasks 7-9): environment checks, command
//! generation, launch logging and crash capture.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use sam_core::permissions::DbusMode;
use sam_core::util::{format_ts, now, shell_join};
use sam_core::warnings::{evaluate, WarningContext};
use sam_core::{
    AppEntry, AppState, BackendKind, Config, HostInfo, LaunchContext, LaunchRecord, Paths, SandboxCommand, Warning,
};
use sam_intake::fingerprint::{self, SourceStatus};
use sam_storage::{LogKind, Logs, Registry};
use serde::Serialize;

use crate::dbus_proxy::DbusProxy;
use crate::kernel;
use crate::select::{select, Selection};

#[derive(Debug, Clone, Default)]
pub struct LaunchOptions {
    pub args: Vec<String>,
    pub owd: Option<PathBuf>,
    /// Wrap the entry point with a tracer (diagnostic mode).
    pub tracer: Option<Vec<String>>,
    pub extra_binds: Vec<(PathBuf, PathBuf, bool)>,
    /// Kill the app after this many seconds (diagnostic runs).
    pub timeout_secs: Option<u64>,
    /// Don't echo the app's output to our stdout/stderr.
    pub quiet: bool,
}

/// Everything needed to start a sandbox, plus the explanation for the user.
pub struct Prepared {
    pub selection: Selection,
    pub command: SandboxCommand,
    pub context: LaunchContext,
    pub warnings: Vec<Warning>,
    pub landlock: bool,
    pub seccomp: bool,
    proxy: Option<DbusProxy>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandPreview {
    pub backend: BackendKind,
    pub reason: String,
    pub command: String,
    pub argv: Vec<String>,
    pub notes: Vec<String>,
    pub warnings: Vec<Warning>,
    pub landlock: bool,
    pub seccomp: bool,
    pub dbus_proxy: Option<Vec<String>>,
}

impl Prepared {
    pub fn preview(&self) -> CommandPreview {
        let mut argv = vec![self.command.program.to_string_lossy().into_owned()];
        argv.extend(self.command.args.iter().cloned());
        CommandPreview {
            backend: self.selection.kind,
            reason: self.selection.reason.clone(),
            command: self.command.display(),
            argv,
            notes: self.command.notes.clone(),
            warnings: self.warnings.clone(),
            landlock: self.landlock,
            seccomp: self.seccomp,
            dbus_proxy: self.proxy.as_ref().map(|p| p.args.clone()),
        }
    }
}

/// Environment checks before launching (§2.13.4). Returns blocking errors
/// and non-blocking warnings.
pub fn preflight(app: &AppEntry) -> (Vec<String>, Vec<Warning>) {
    let mut errors = Vec::new();
    let mut warns = Vec::new();
    match &app.extraction {
        None => errors.push("The AppImage has not been extracted. Use 'Re-extract' (sam-jail reextract).".into()),
        Some(x) => {
            if !x.appdir.join(&x.entry).exists() {
                errors.push(format!(
                    "The extracted payload is missing or incomplete ({}). Re-extract the AppImage.",
                    x.appdir.display()
                ));
            }
        }
    }
    if !app.source_path.exists() {
        warns.push(Warning::warn(
            "source-missing",
            "AppImage missing",
            "The selected AppImage no longer exists. SAM will run the last extracted copy; APPIMAGE is unset.",
        ));
    } else if let Some(x) = &app.extraction {
        if let Ok(SourceStatus::Changed { .. }) = fingerprint::check(&app.source_path, &x.source, false) {
            warns.push(Warning::warn(
                "source-stale",
                "AppImage changed",
                "The AppImage changed since it was extracted. Running the previous version; re-extract to update.",
            ));
        }
    }
    (errors, warns)
}

pub fn prepare(app: &AppEntry, opts: &LaunchOptions, cfg: &Config, paths: &Paths, host: &HostInfo) -> Result<Prepared> {
    let (errors, mut warnings) = preflight(app);
    if let Some(e) = errors.first() {
        bail!("{e}");
    }
    let x = app.extraction.as_ref().unwrap();
    let selection = select(&app.profile, cfg, host)?;
    let kind = selection.kind;
    let perms = &app.profile.permissions;

    let ctx_w = WarningContext {
        app_needs_network: Some(crate::ops::app_needs_network(app)),
        backend: Some(kind),
        host: Some(host),
        warn_x11: cfg.security.warn_x11,
        warn_full_home: cfg.security.warn_full_home,
        warn_firejail: cfg.security.warn_firejail,
    };
    warnings.extend(evaluate(perms, &ctx_w));

    let runtime_dir = paths.runtime_dir(&app.id);
    fs::create_dir_all(&runtime_dir)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700));
    }
    let owd = opts.owd.clone().or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| host.home.clone());
    let source_exists = app.source_path.exists();
    let appimage_env = if !source_exists {
        None
    } else if kind == BackendKind::Bubblewrap {
        app.source_path.file_name().map(|n| format!("/run/sam/{}", n.to_string_lossy()))
    } else {
        Some(app.source_path.display().to_string())
    };
    let mut app_env: Vec<(String, String)> = vec![
        ("APPDIR".into(), "@APPDIR@".into()),
        ("OWD".into(), owd.display().to_string()),
        ("ARGV0".into(), app.source_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
        ("XDG_DATA_DIRS".into(), "@APPDIR@/usr/share:/usr/local/share:/usr/share".into()),
        ("XDG_CONFIG_DIRS".into(), "@APPDIR@/etc/xdg:/etc/xdg".into()),
        ("SAM_APP_ID".into(), app.id.clone()),
    ];
    if let Some(v) = appimage_env {
        app_env.push(("APPIMAGE".into(), v));
    }

    let mut ctx = LaunchContext {
        app_id: app.id.clone(),
        app_name: app.display_name().to_string(),
        appdir: x.appdir.clone(),
        sandbox_appdir: PathBuf::from("/opt/app"),
        entry: x.entry.clone(),
        appimage_path: source_exists.then(|| app.source_path.clone()),
        owd,
        args: app.profile.args.iter().cloned().chain(opts.args.iter().cloned()).collect(),
        permissions: perms.clone(),
        host: host.clone(),
        private_home: paths.app_home(&app.id),
        runtime_dir: runtime_dir.clone(),
        app_env,
        dbus_proxy_socket: None,
        helper: None,
        seccomp_fd: None,
        compatibility_mode: app.profile.compatibility_mode,
        tracer: opts.tracer.clone(),
        extra_binds: opts.extra_binds.clone(),
    };

    if perms.advanced.persistent_home {
        fs::create_dir_all(&ctx.private_home)
            .with_context(|| format!("creating private home {}", ctx.private_home.display()))?;
    }

    let mut proxy = None;
    let mut landlock = false;
    let mut seccomp = false;
    if kind == BackendKind::Bubblewrap {
        sam_backend_bubblewrap::write_identity_files(&ctx)?;
        if perms.dbus.session.mode == DbusMode::Filtered && host.tools.xdg_dbus_proxy.is_some() && host.sockets.dbus_session.is_some() {
            match DbusProxy::start(host, &perms.dbus.session, &runtime_dir, &app.id) {
                Ok(p) => {
                    ctx.dbus_proxy_socket = Some(p.socket.clone());
                    proxy = Some(p);
                }
                Err(e) => warnings.push(Warning::warn("dbus-proxy-failed", "D-Bus proxy failed", format!("{e:#}; session bus disabled"))),
            }
        }
        let want_landlock = perms.advanced.landlock.unwrap_or(cfg.security.experimental_landlock);
        if want_landlock && host.landlock_abi.is_some() {
            if let Some(helper) = crate::find_helper() {
                let spec = kernel::SandboxSpec {
                    landlock: Some(kernel::landlock_spec(perms, host, &format!("/run/user/{}", host.uid))),
                };
                let spec_path = runtime_dir.join("sandbox.json");
                fs::write(&spec_path, serde_json::to_vec_pretty(&spec)?)?;
                ctx.helper = Some(sam_core::backend::SandboxHelper { binary: helper, spec: spec_path });
                landlock = true;
            }
        }
        if perms.advanced.seccomp_strict {
            if cfg.security.experimental_seccomp {
                ctx.seccomp_fd = Some(kernel::seccomp_fd(perms.advanced.allow_userns)?);
                seccomp = true;
            } else {
                warnings.push(Warning::info(
                    "seccomp-disabled",
                    "Seccomp strict mode ignored",
                    "Enable experimental seccomp in Settings -> Security to use the strict filter.",
                ));
            }
        }
    }

    let command = match kind {
        BackendKind::Unsandboxed => unsandboxed_command(&ctx),
        k => crate::backend_for(k).unwrap().build(&ctx)?,
    };
    Ok(Prepared { selection, command, context: ctx, warnings, landlock, seccomp, proxy })
}

fn unsandboxed_command(ctx: &LaunchContext) -> SandboxCommand {
    let appdir = ctx.appdir.to_string_lossy().into_owned();
    let mut env = ctx.resolved_app_env(&appdir);
    env.extend(ctx.permissions.environment.set.iter().map(|(k, v)| (k.clone(), v.clone())));
    SandboxCommand {
        program: ctx.appdir.join(&ctx.entry),
        args: ctx.args.clone(),
        env,
        clear_env: false,
        keep_fds: vec![],
        notes: vec!["running without any sandbox".into()],
        generated_files: vec![],
    }
}

/// Did the failure come from the sandbox setup rather than the app?
fn classify_failure(code: Option<i32>, stderr_head: &str, kind: BackendKind) -> (bool, String) {
    let first_bwrap = stderr_head.lines().find(|l| l.starts_with("bwrap:")).map(str::to_string);
    match (code, kind) {
        (Some(_), BackendKind::Bubblewrap) if first_bwrap.is_some() => (true, format!("sandbox setup failed: {}", first_bwrap.unwrap())),
        (Some(126), _) => (true, "the entry point could not be executed (permission denied or wrong format)".into()),
        (Some(127), _) => (true, "the entry point or one of its interpreters was not found inside the sandbox".into()),
        _ => (false, String::new()),
    }
}

const STDERR_HEAD_LIMIT: usize = 16 * 1024;

pub fn run(app: &mut AppEntry, opts: &LaunchOptions, cfg: &Config, paths: &Paths, host: &HostInfo) -> Result<LaunchRecord> {
    let logs = Logs::new(paths);
    let log_path = logs.new_log_path(&app.id, if opts.tracer.is_some() { LogKind::Diagnose } else { LogKind::Launch })?;
    let started_at = now();
    let mut log = fs::File::create(&log_path).with_context(|| format!("creating {}", log_path.display()))?;
    writeln!(log, "# SAM launch log\n# app: {} ({})\n# started: {}", app.display_name(), app.id, format_ts(started_at))?;

    let prepared = match prepare(app, opts, cfg, paths, host) {
        Ok(p) => p,
        Err(e) => {
            writeln!(log, "# preparation failed: {e:#}")?;
            let rec = LaunchRecord {
                started_at,
                finished_at: now(),
                success: false,
                sandbox_failure: true,
                log_file: Some(log_path),
                summary: format!("{e:#}"),
                ..Default::default()
            };
            app.last_launch = Some(rec.clone());
            app.last_error = Some(rec.summary.clone());
            Registry::new(paths).save(app)?;
            return Err(e);
        }
    };
    let kind = prepared.selection.kind;
    writeln!(log, "# backend: {} ({})", kind, prepared.selection.reason)?;
    writeln!(log, "# landlock: {}  seccomp: {}", prepared.landlock, prepared.seccomp)?;
    if let Some(p) = &prepared.proxy {
        writeln!(log, "# dbus proxy: xdg-dbus-proxy {}", shell_join(&p.args))?;
    }
    for n in &prepared.command.notes {
        writeln!(log, "# note: {n}")?;
    }
    for w in &prepared.warnings {
        writeln!(log, "# warning [{}]: {}", w.code, w.message)?;
    }
    writeln!(log, "# command: {}", prepared.command.display())?;
    writeln!(log, "# ---- output ----")?;
    log.flush()?;

    for w in &prepared.warnings {
        if !opts.quiet && w.severity != sam_core::Severity::Info {
            eprintln!("sam-jail: warning: {}", w.message);
        }
    }

    let mut cmd = Command::new(&prepared.command.program);
    cmd.args(&prepared.command.args).stdin(Stdio::inherit()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if prepared.command.clear_env {
        cmd.env_clear();
    }
    for (k, v) in &prepared.command.env {
        cmd.env(k, v);
    }
    if !matches!(kind, BackendKind::Unsandboxed) {
        cmd.current_dir(&host.home);
    } else {
        cmd.current_dir(&prepared.context.owd);
    }
    let mut child = cmd.spawn().with_context(|| format!("starting {}", prepared.command.program.display()))?;
    if let Some(fd) = prepared.context.seccomp_fd {
        unsafe { libc::close(fd) };
    }

    let log = Arc::new(Mutex::new(log));
    let head = Arc::new(Mutex::new(String::new()));
    let pump = |src: Box<dyn Read + Send>, is_err: bool, log: Arc<Mutex<fs::File>>, head: Arc<Mutex<String>>, quiet: bool| {
        std::thread::spawn(move || {
            let reader = BufReader::new(src);
            for line in reader.split(b'\n') {
                let Ok(line) = line else { break };
                let text = String::from_utf8_lossy(&line);
                if let Ok(mut l) = log.lock() {
                    let _ = writeln!(l, "{}{text}", if is_err { "[err] " } else { "" });
                }
                if is_err {
                    if let Ok(mut h) = head.lock() {
                        if h.len() < STDERR_HEAD_LIMIT {
                            h.push_str(&text);
                            h.push('\n');
                        }
                    }
                }
                if !quiet {
                    if is_err {
                        eprintln!("{text}");
                    } else {
                        println!("{text}");
                    }
                }
            }
        })
    };
    let t1 = pump(Box::new(child.stdout.take().unwrap()), false, log.clone(), head.clone(), opts.quiet);
    let t2 = pump(Box::new(child.stderr.take().unwrap()), true, log.clone(), head.clone(), opts.quiet);

    let status = match opts.timeout_secs {
        None => child.wait()?,
        Some(secs) => {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            loop {
                if let Some(st) = child.try_wait()? {
                    break st;
                }
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    break child.wait()?;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    };
    let _ = t1.join();
    let _ = t2.join();
    drop(prepared.proxy);

    let code = status.code();
    let signal = status.signal();
    let head = head.lock().map(|h| h.clone()).unwrap_or_default();
    let (sandbox_failure, mut summary) = classify_failure(code, &head, kind);
    let success = status.success();
    if summary.is_empty() {
        summary = match (code, signal) {
            (Some(0), _) => "exited normally".into(),
            (Some(c), _) => format!("exited with code {c}"),
            (None, Some(s)) => format!("terminated by signal {s}{}", if s == 11 { " (segmentation fault)" } else if s == 6 { " (abort)" } else { "" }),
            _ => "finished".into(),
        };
    }
    {
        let mut l = log.lock().unwrap();
        writeln!(l, "# ---- end ----\n# finished: {}\n# result: {summary}", format_ts(now()))?;
    }

    let rec = LaunchRecord {
        started_at,
        finished_at: now(),
        backend: Some(kind),
        exit_code: code,
        signal,
        success,
        sandbox_failure,
        log_file: Some(log_path),
        summary,
    };
    app.last_launched = Some(started_at);
    app.last_launch = Some(rec.clone());
    if sandbox_failure {
        app.last_error = Some(rec.summary.clone());
    } else if app.state == AppState::Broken && app.extraction.is_some() {
        app.state = AppState::Ready;
        app.last_error = None;
    }
    // Save against the latest on-disk entry so concurrent GUI edits survive.
    let reg = Registry::new(paths);
    if let Some(mut fresh) = reg.get(&app.id)? {
        fresh.last_launched = app.last_launched;
        fresh.last_launch = app.last_launch.clone();
        fresh.last_error = app.last_error.clone();
        fresh.state = app.state;
        reg.save(&mut fresh)?;
    }
    let _ = logs.prune(&app.id, LogKind::Launch, cfg.diagnostics.keep_logs);
    Ok(rec)
}

/// Last lines of a log file (for reports and the GUI).
pub fn tail(path: &Path, max_lines: usize) -> String {
    let Ok(text) = fs::read_to_string(path) else { return String::new() };
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(max_lines)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_classification() {
        assert!(classify_failure(Some(1), "bwrap: Can't mount proc", BackendKind::Bubblewrap).0);
        assert!(classify_failure(Some(127), "", BackendKind::Bubblewrap).0);
        assert!(!classify_failure(Some(1), "app error", BackendKind::Bubblewrap).0);
        assert!(!classify_failure(None, "", BackendKind::Bubblewrap).0);
    }
}
