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
    AppEntry, AppState, Config, HostInfo, LaunchContext, LaunchRecord, Paths, SandboxCommand, Warning,
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
    portal_instance: Option<crate::portal_identity::Instance>,
    _runtime: RuntimeDir,
}

/// Removes a per-launch runtime directory when the launch is over.
struct RuntimeDir(PathBuf);
impl Drop for RuntimeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandPreview {
    pub backend: &'static str,
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
    let x = app.extraction.as_ref().context("the AppImage has not been extracted")?;
    let selection = select(host)?;
    let perms = &app.profile.permissions;

    let ctx_w = WarningContext {
        app_needs_network: Some(crate::ops::app_needs_network(app)),
        host: Some(host),
        warn_x11: cfg.security.warn_x11,
        warn_full_home: cfg.security.warn_full_home,
    };
    warnings.extend(evaluate(perms, &ctx_w));

    // One runtime directory per launch (two instances of an app never share
    // proxy sockets or spec files); removed when `Prepared` is dropped.
    let runtime_dir = paths.runtime_dir(&app.id).join(format!("launch-{}-{}", std::process::id(), now()));
    fs::create_dir_all(&runtime_dir)?;
    let runtime_guard = RuntimeDir(runtime_dir.clone());
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700));
    }
    let owd = opts.owd.clone().or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| host.home.clone());
    let source_exists = app.source_path.exists();
    let appimage_env = if source_exists { app.source_path.file_name().map(|n| format!("/run/sam/{}", n.to_string_lossy())) } else { None };
    let mut app_env: Vec<(String, String)> = vec![
        ("APPDIR".into(), "@APPDIR@".into()),
        ("OWD".into(), owd.display().to_string()),
        ("ARGV0".into(), app.source_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
        ("XDG_DATA_DIRS".into(), "@APPDIR@/usr/share:/usr/local/share:/usr/share".into()),
        ("XDG_CONFIG_DIRS".into(), "@APPDIR@/etc/xdg:/etc/xdg".into()),
        ("SAM_APP_ID".into(), app.id.clone()),
        // AppImages started from inside the sandbox (launchers, self-restarts)
        // cannot use FUSE there; let their runtime extract to /tmp instead.
        ("APPIMAGE_EXTRACT_AND_RUN".into(), "1".into()),
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
        appdir_overlay: None,
        portal_identity: None,
    };
    if perms.advanced.writable_appdir {
        let base = paths.data_dir.join("overlays").join(&app.id);
        fs::create_dir_all(base.join("upper"))?;
        fs::create_dir_all(base.join("work"))?;
        ctx.appdir_overlay = Some(base);
    }

    if perms.advanced.persistent_home {
        fs::create_dir_all(&ctx.private_home)
            .with_context(|| format!("creating private home {}", ctx.private_home.display()))?;
    }

    // Portal identity (Bubblewrap with a filtered session bus). Not with
    // 'Local network only': pasta does not pass bwrap's --info-fd on.
    let mut portal_instance = None;
    if cfg.security.portal_identity
        && perms.dbus.session.mode == DbusMode::Filtered
        && perms.network.mode != sam_core::permissions::NetworkMode::Localhost
        && host.tools.xdg_dbus_proxy.is_some()
    {
        match crate::portal_identity::Instance::create(&runtime_dir, host.uid, &app.id) {
            Ok(inst) => {
                ctx.portal_identity = Some(inst.identity.clone());
                portal_instance = Some(inst);
            }
            Err(e) => warnings.push(Warning::info("portal-identity", "Portal identity unavailable", format!("{e:#}"))),
        }
    }

    let mut proxy = None;
    let mut landlock = false;
    let mut seccomp = false;
    {
        sam_backend_bubblewrap::write_identity_files(&ctx)?;
        if perms.dbus.session.mode == DbusMode::Filtered && host.tools.xdg_dbus_proxy.is_some() && host.sockets.dbus_session.is_some() {
            let mut bus = perms.effective_session_bus();
            if ctx.portal_identity.is_some() {
                // With an identity the document portal applies per-app rules.
                bus.allow.push("org.freedesktop.portal.Documents".into());
            }
            let identity_file = ctx.portal_identity.as_ref().map(|i| i.info_file.clone());
            match DbusProxy::start(host, &bus, &runtime_dir, &app.id, identity_file.as_deref()) {
                Ok(p) => {
                    ctx.dbus_proxy_socket = Some(p.socket.clone());
                    proxy = Some(p);
                }
                Err(e) => warnings.push(Warning::warn("dbus-proxy-failed", "D-Bus proxy failed", format!("{e:#}; session bus disabled"))),
            }
        }
        // Landlock and seccomp are applied by SAM's helper inside the sandbox.
        let want_landlock = perms.advanced.landlock.unwrap_or(cfg.security.experimental_landlock) && host.landlock_abi.is_some();
        let strict = perms.advanced.seccomp_strict && cfg.security.experimental_seccomp;
        if perms.advanced.seccomp_strict && !cfg.security.experimental_seccomp {
            warnings.push(Warning::info(
                "seccomp-disabled",
                "Seccomp strict mode ignored",
                "Enable experimental seccomp in Settings -> Security to use the strict filter.",
            ));
        }
        let want_seccomp = (cfg.security.baseline_seccomp && perms.advanced.seccomp_baseline) || strict;
        if want_landlock || want_seccomp {
            match crate::find_helper() {
                Some(helper) => {
                    let spec = kernel::SandboxSpec {
                        landlock: want_landlock.then(|| kernel::landlock_spec(perms, host, &format!("/run/user/{}", host.uid), &launch_writable_paths(&ctx))),
                        seccomp: want_seccomp.then_some(kernel::SeccompSpec { strict, allow_userns: perms.advanced.allow_userns }),
                    };
                    let spec_path = runtime_dir.join("sandbox.json");
                    fs::write(&spec_path, serde_json::to_vec_pretty(&spec)?)?;
                    ctx.helper = Some(sam_core::backend::SandboxHelper { binary: helper, spec: spec_path });
                    landlock = want_landlock;
                    seccomp = want_seccomp;
                }
                None => warnings.push(Warning::warn("helper-missing", "Kernel restrictions unavailable", "sam-jail-run was not found next to sam-jail; Landlock and seccomp are not applied.")),
            }
        }
    }

    let mut command = sam_backend_bubblewrap::Bubblewrap.build(&ctx)?;
    if perms.network.mode == sam_core::permissions::NetworkMode::Localhost {
        if let Err(e) = crate::netns::wrap_localhost(&mut command, &perms.network.valid_host_ports(), &perms.network.valid_app_ports()) {
            // Without pasta, fall back to no network at all.
            command.args.insert(0, "--unshare-net".into());
            warnings.push(Warning::warn("localhost-unavailable", "Local network unavailable", format!("{e:#}. The app has no network.")));
        }
    }
    Ok(Prepared { selection, command, context: ctx, warnings, landlock, seccomp, proxy, portal_instance, _runtime: runtime_guard })
}

/// Paths mounted writable only for this launch: files passed on the command
/// line ("Open with") and writable extra binds.
fn launch_writable_paths(ctx: &LaunchContext) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = if ctx.permissions.filesystem.opened_files == sam_core::permissions::Access::Rw {
        ctx.args.iter().map(PathBuf::from).filter(|p| p.is_absolute() && p.is_file()).collect()
    } else {
        vec![]
    };
    out.extend(ctx.extra_binds.iter().filter(|(_, _, rw)| *rw).map(|(_, dest, _)| dest.clone()));
    if ctx.permissions.advanced.writable_appdir {
        out.push(ctx.sandbox_appdir.clone());
    }
    out
}

/// Did the failure come from the sandbox setup rather than the app?
fn classify_failure(code: Option<i32>, stderr_head: &str) -> (bool, String) {
    let first_bwrap = stderr_head.lines().find(|l| l.starts_with("bwrap:")).map(str::to_string);
    match code {
        Some(_) if first_bwrap.is_some() => (true, format!("sandbox setup failed: {}", first_bwrap.unwrap_or_default())),
        Some(126) => (true, "the entry point could not be executed (permission denied or wrong format)".into()),
        Some(127) => (true, "the entry point or one of its interpreters was not found inside the sandbox".into()),
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
    writeln!(log, "# sandbox: {}", prepared.selection.reason)?;
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
    cmd.current_dir(&host.home);
    // Status channels the app cannot write to (H1/M3 in the audit):
    // bwrap's --json-status-fd announces "child-pid" once the sandbox exists,
    // and SAM's helper reports what it enforced before it execs the app.
    // pasta (local network only) does not pass extra fds, so these exist
    // only when bwrap is started directly.
    let direct_bwrap = host.tools.bwrap.as_ref().is_some_and(|b| b.path == prepared.command.program);
    let mut bwrap_status = None;
    let mut helper_status = None;
    if direct_bwrap {
        let (r, w) = status_pipe()?;
        let mut args = vec!["--json-status-fd".to_string(), w.to_string()];
        args.extend(prepared.command.args.iter().cloned());
        let mut helper_w = None;
        if prepared.context.helper.is_some() {
            let (hr, hw) = status_pipe()?;
            // After --clearenv: right before bwrap's "--" separator.
            let sep = args.iter().position(|a| a == "--").unwrap_or(args.len());
            args.splice(sep..sep, ["--setenv".to_string(), "SAM_STATUS_FD".into(), hw.to_string()]);
            helper_status = Some(hr);
            helper_w = Some(hw);
        }
        cmd = Command::new(&prepared.command.program);
        cmd.args(&args).stdin(Stdio::inherit()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if prepared.command.clear_env {
            cmd.env_clear();
        }
        for (k, v) in &prepared.command.env {
            cmd.env(k, v);
        }
        cmd.current_dir(&host.home);
        bwrap_status = Some((r, w, helper_w));
    }
    let mut child = cmd.spawn().with_context(|| format!("starting {}", prepared.command.program.display()))?;
    // Close our copies of the write ends so the readers see EOF.
    let bwrap_status_reader = bwrap_status.map(|(r, w, hw)| {
        unsafe { libc::close(w) };
        if let Some(hw) = hw {
            unsafe { libc::close(hw) };
        }
        read_fd_in_thread(r)
    });
    let helper_status_reader = helper_status.map(read_fd_in_thread);
    if let Some(fd) = prepared.context.seccomp_fd {
        unsafe { libc::close(fd) };
    }
    let mut prepared = prepared;
    if let Some(inst) = prepared.portal_instance.as_mut() {
        inst.started();
        writeln!(log, "# portal identity: {}", inst.identity.app_id)?;
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
    let t1 = pump(Box::new(child.stdout.take().context("no stdout pipe")?), false, log.clone(), head.clone(), opts.quiet);
    let t2 = pump(Box::new(child.stderr.take().context("no stderr pipe")?), true, log.clone(), head.clone(), opts.quiet);

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
    let bwrap_json = bwrap_status_reader.and_then(|t| t.join().ok());
    let enforcement = helper_status_reader.and_then(|t| t.join().ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let (mut sandbox_failure, mut summary) = classify_failure(code, &head);
    // Verified setup failure: bwrap never announced the app's process.
    let setup_failed = bwrap_json.as_ref().is_some_and(|j| !j.contains("\"child-pid\""));
    if bwrap_json.is_some() && summary.starts_with("sandbox setup failed") && !setup_failed {
        // The sandbox was built; "bwrap:" lines came from the app itself.
        sandbox_failure = false;
        summary.clear();
    }
    if setup_failed {
        sandbox_failure = true;
        if !summary.starts_with("sandbox setup failed") {
            summary = "sandbox setup failed (Bubblewrap could not build the sandbox)".into();
        }
    }
    let success = status.success();
    if summary.is_empty() {
        summary = match (code, signal) {
            (Some(0), _) => "exited normally".into(),
            (Some(c), _) => format!("exited with code {c}"),
            (None, Some(s)) => format!("terminated by signal {s}{}", if s == 11 { " (segmentation fault)" } else if s == 6 { " (abort)" } else { "" }),
            _ => "finished".into(),
        };
    }
    if let Ok(mut l) = log.lock() {
        if let Some(e) = &enforcement {
            writeln!(l, "# enforced: {e}")?;
        } else if prepared.landlock || prepared.seccomp {
            writeln!(l, "# enforced: unknown (no status from SAM's helper)")?;
        }
        writeln!(l, "# ---- end ----\n# finished: {}\n# result: {summary}", format_ts(now()))?;
    }

    let rec = LaunchRecord {
        started_at,
        finished_at: now(),
        exit_code: code,
        signal,
        success,
        sandbox_failure,
        setup_failed,
        enforcement,
        log_file: Some(log_path),
        findings: if success { vec![] } else { crate::repair::analyze(&head, &app.profile.permissions, signal) },
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

/// A pipe whose write end is inherited by child processes.
fn status_pipe() -> Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    unsafe { libc::fcntl(fds[1], libc::F_SETFD, 0) };
    Ok((fds[0], fds[1]))
}

fn read_fd_in_thread(fd: i32) -> std::thread::JoinHandle<String> {
    use std::os::fd::FromRawFd;
    std::thread::spawn(move || {
        let f = unsafe { fs::File::from_raw_fd(fd) };
        let mut s = String::new();
        let _ = f.take(64 * 1024).read_to_string(&mut s);
        s
    })
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
        assert!(classify_failure(Some(1), "bwrap: Can't mount proc").0);
        assert!(classify_failure(Some(127), "").0);
        assert!(!classify_failure(Some(1), "app error").0);
        assert!(!classify_failure(None, "").0);
    }
}
