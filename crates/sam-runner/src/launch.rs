//! Launching: environment checks, command
//! generation, launch logging and crash capture.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use sam_core::permissions::DbusMode;
use sam_core::util::{format_ts, now, shell_join};
use sam_core::warnings::{evaluate, WarningContext};
use sam_core::{
    AppEntry, AppState, Config, HostInfo, LaunchContext, LaunchRecord, Paths, SandboxCommand,
    Warning,
};
use sam_intake::fingerprint::{self, SourceStatus};
use sam_storage::{LogKind, Logs, Registry};
use serde::Serialize;

use crate::bwrap::SandboxInfo;
use crate::dbus_proxy::DbusProxy;
use crate::kernel;
use crate::pty::{self, Pty, TerminalMode};

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
    /// Sandbox check: the helper runs these checks instead of the app.
    pub probe: Option<crate::probe::ProbePlan>,
}

/// Everything needed to start a sandbox, plus the explanation for the user.
/// Left in a launch's runtime folder by `Sam::stop` before it signals the app.
pub const STOP_MARKER: &str = "stop-requested";

pub struct Prepared {
    pub sandbox: SandboxInfo,
    pub command: SandboxCommand,
    pub context: LaunchContext,
    pub warnings: Vec<Warning>,
    pub landlock: bool,
    pub seccomp: bool,
    /// The kernel layers the settings ask for, applied or not (without SAM's
    /// helper they cannot be): what a start is checked against.
    pub wanted_landlock: bool,
    pub wanted_seccomp: bool,
    /// How the app's terminal is handled (see `pty`).
    pub terminal: TerminalMode,
    proxy: Option<DbusProxy>,
    /// Whether the app's Wayland socket carries a security context.
    pub wayland_context: bool,
    wayland: Option<crate::wayland_ctx::WaylandContext>,
    _runtime: RuntimeDir,
}

/// Removes a per-launch runtime directory when the launch is over.
struct RuntimeDir(PathBuf);
impl Drop for RuntimeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        // The app's runtime folder and SAM's, once no other launch uses them.
        if let Some(app_dir) = self.0.parent() {
            if fs::remove_dir(app_dir).is_ok() {
                if let Some(sam_dir) = app_dir.parent() {
                    let _ = fs::remove_dir(sam_dir);
                }
            }
        }
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
            backend: self.sandbox.kind,
            reason: self.sandbox.reason.clone(),
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

/// Environment checks before launching. Returns blocking errors
/// and non-blocking warnings.
pub fn preflight(app: &AppEntry) -> (Vec<String>, Vec<Warning>) {
    let mut errors = Vec::new();
    let mut warns = Vec::new();
    if app.changed_outside {
        errors.push(sam_core::i18n::trf(
            "The settings of {app} were changed outside SAM (by a script, another program or a damaged file). SAM does not start the app until you have looked at them: open the app in SAM and confirm its settings, or run `sam-jail review {id}`.",
            &[("app", &sam_core::util::display_safe(app.display_name(), 80)), ("id", &app.id)],
        ));
    }
    if app.content_changed_outside {
        errors.push(sam_core::i18n::trf(
            "The AppImage file of {app} was replaced by something other than a SAM update since it was last unpacked, and it still has the old settings. SAM does not start it until you have looked at it: open the app in SAM and confirm, or run `sam-jail review {id}`.",
            &[("app", &sam_core::util::display_safe(app.display_name(), 80)), ("id", &app.id)],
        ));
    }
    match &app.extraction {
        None => errors.push(sam_core::i18n::tr(
            "The AppImage has not been unpacked. Use Unpack Again (sam-jail reextract).",
        )),
        Some(x) => {
            if !x.appdir.join(&x.entry).exists() {
                errors.push(sam_core::i18n::trf(
                    "The unpacked app is missing or incomplete ({folder}). Unpack the AppImage again.",
                    &[("folder", &x.appdir.display())],
                ));
            }
        }
    }
    if !app.source_path.exists() {
        warns.push(Warning::warn(
            "source-missing",
            "AppImage missing",
            "The selected AppImage no longer exists. SAM runs the last unpacked copy; APPIMAGE is not set.",
        ));
    } else if let Some(x) = &app.extraction {
        if let Ok(SourceStatus::Changed { .. }) =
            fingerprint::check(&app.source_path, &x.source, false)
        {
            warns.push(Warning::warn(
                "source-stale",
                "AppImage changed",
                "The AppImage changed since it was unpacked. SAM runs the previous version until you unpack it again.",
            ));
        }
    }
    (errors, warns)
}

pub fn prepare(
    app: &AppEntry,
    opts: &LaunchOptions,
    cfg: &Config,
    paths: &Paths,
    host: &HostInfo,
) -> Result<Prepared> {
    let (errors, mut warnings) = preflight(app);
    if let Some(e) = errors.first() {
        bail!("{e}");
    }
    let x = app
        .extraction
        .as_ref()
        .context(sam_core::i18n::tr("the AppImage has not been unpacked"))?;
    let sandbox = crate::bwrap::check(host)?;
    let perms = &app.profile.permissions;

    let ctx_w = WarningContext {
        app_needs_network: Some(crate::ops::app_needs_network(app)),
        host: Some(host),
        warn_x11: cfg.security.warn_x11,
        warn_full_home: cfg.security.warn_full_home,
        terminal_program: app.metadata.terminal,
    };
    warnings.extend(evaluate(perms, &ctx_w));
    // A terminal of its own for a user's start from a terminal, and for a
    // terminal program's test start (see `pty`).
    let interactive = opts.timeout_secs.is_none() && opts.probe.is_none();
    let terminal = TerminalMode::choose(app.metadata.terminal, pty::is_tty(0), interactive);

    // One runtime directory per launch (two instances of an app never share
    // proxy sockets or spec files); removed when `Prepared` is dropped.
    let runtime_dir =
        paths
            .runtime_dir(&app.id)
            .join(format!("launch-{}-{}", std::process::id(), now()));
    fs::create_dir_all(&runtime_dir)?;
    let runtime_guard = RuntimeDir(runtime_dir.clone());
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700));
    }
    let owd = opts
        .owd
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| host.home.clone());
    let source_exists = app.source_path.exists();
    let appimage_env = if source_exists {
        app.source_path
            .file_name()
            .map(|n| format!("/run/sam/{}", n.to_string_lossy()))
    } else {
        None
    };
    let mut app_env: Vec<(String, String)> = vec![
        ("APPDIR".into(), "@APPDIR@".into()),
        ("OWD".into(), owd.display().to_string()),
        (
            "ARGV0".into(),
            app.source_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
        (
            "XDG_DATA_DIRS".into(),
            "@APPDIR@/usr/share:/usr/local/share:/usr/share".into(),
        ),
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
        args: app
            .profile
            .args
            .iter()
            .cloned()
            .chain(opts.args.iter().cloned())
            .collect(),
        permissions: perms.clone(),
        host: host.clone(),
        private_home: paths.app_home(&app.id),
        runtime_dir: runtime_dir.clone(),
        app_env,
        dbus_proxy_socket: None,
        wayland_socket: None,
        helper: None,
        seccomp_fd: None,
        own_terminal: terminal != TerminalMode::None,
        compatibility_mode: app.profile.compatibility_mode,
        tracer: opts.tracer.clone(),
        extra_binds: opts.extra_binds.clone(),
        appdir_overlay: None,
        sam_dirs: vec![
            paths.config_dir.clone(),
            paths.data_dir.clone(),
            paths.extracted_root(&cfg.extraction.location),
        ],
    };
    if perms.advanced.writable_appdir && !sam_core::host::bwrap_supports_overlay() {
        warnings.push(Warning::warn(
            "writable-appdir-unavailable",
            "Writable app folder unavailable",
            "The writable app folder needs Bubblewrap 0.10 or newer; the installed one is older, so the app folder stays read-only. Update Bubblewrap to use this setting.",
        ));
    } else if perms.advanced.writable_appdir
        && !sam_core::host::overlay_works_in(&paths.overlays_dir())
    {
        warnings.push(Warning::warn(
            "writable-appdir-unavailable",
            "Writable app folder unavailable",
            format!(
                "The writable app folder keeps the app's changes in {}, but that folder is on a filesystem that cannot hold them (for example a network drive, an encrypted folder or a container's filesystem). The app starts with a read-only app folder instead. Moving SAM's data folder to a local disk makes this setting work.",
                sam_core::util::tildify(&paths.overlays_dir())
            ),
        ));
    } else if perms.advanced.writable_appdir {
        let base = paths.overlays_dir().join(&app.id);
        fs::create_dir_all(base.join("upper"))?;
        fs::create_dir_all(base.join("work"))?;
        ctx.appdir_overlay = Some(base);
    }

    if perms.advanced.persistent_home {
        fs::create_dir_all(&ctx.private_home).with_context(|| {
            sam_core::i18n::trf(
                "creating the private home {folder}",
                &[("folder", &ctx.private_home.display())],
            )
        })?;
    }

    let mut proxy = None;
    let mut wayland = None;
    let mut landlock = false;
    let mut seccomp = false;
    let wanted_landlock: bool;
    let wanted_seccomp: bool;
    {
        sam_sandbox::write_identity_files(&ctx)?;
        sam_sandbox::prepare_home_protection(perms, &host.home);
        if perms.dbus.session.mode == DbusMode::Filtered
            && host.tools.xdg_dbus_proxy.is_some()
            && host.sockets.dbus_session.is_some()
        {
            let bus = perms.effective_session_bus();
            match DbusProxy::start(host, &bus, &runtime_dir, &app.id) {
                Ok(p) => {
                    ctx.dbus_proxy_socket = Some(p.socket.clone());
                    for (name, why) in &p.refused {
                        warnings.push(Warning::warn(
                            "dbus-own-refused",
                            "D-Bus name not allowed",
                            sam_core::i18n::trf(
                                "The app may not own {name}: {why}.",
                                &[("name", &name), ("why", &why)],
                            ),
                        ));
                    }
                    proxy = Some(p);
                }
                Err(e) => warnings.push(Warning::warn(
                    "dbus-proxy-failed",
                    "D-Bus proxy failed",
                    sam_core::i18n::trf(
                        "{error}; the session bus is off for this start",
                        &[("error", &format!("{e:#}"))],
                    ),
                )),
            }
        }
        if perms.display.wayland && !perms.display.wayland_privileged {
            if let Some(display) = &host.sockets.wayland {
                let instance = runtime_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                // The compositor names the app's windows after this ID (KWin
                // uses it instead of the app's own); it must be the name of
                // SAM's menu entry, or the taskbar shows a generic icon.
                match crate::wayland_ctx::start(display, &runtime_dir, &Paths::launcher_id(&app.id), &instance) {
                    Ok(Some(w)) => {
                        ctx.wayland_socket = Some(w.socket.clone());
                        wayland = Some(w);
                    }
                    Ok(None) => warnings.push(Warning::info(
                        "wayland-context-unsupported",
                        "Wayland functions not restricted",
                        "This desktop does not support Wayland security contexts, so the app can use every Wayland function it offers, including privileged ones some desktops provide (clipboard history, screen capture).",
                    )),
                    Err(e) => warnings.push(Warning::warn("wayland-context-failed", "Wayland security context failed", sam_core::i18n::trf("{error}; the app uses the normal Wayland socket", &[("error", &format!("{e:#}"))]))),
                }
            }
        }
        // Landlock and seccomp are applied by SAM's helper inside the sandbox.
        let want_landlock = perms
            .advanced
            .landlock
            .unwrap_or(cfg.security.experimental_landlock)
            && host.landlock_abi.is_some();
        let strict = perms.advanced.seccomp_strict && cfg.security.experimental_seccomp;
        if perms.advanced.seccomp_strict && !cfg.security.experimental_seccomp {
            warnings.push(Warning::info(
                "seccomp-disabled",
                "Seccomp strict mode ignored",
                "Enable experimental seccomp in Settings -> Security to use the strict filter.",
            ));
        }
        let want_seccomp =
            (cfg.security.baseline_seccomp && perms.advanced.seccomp_baseline) || strict;
        wanted_landlock = want_landlock;
        wanted_seccomp = want_seccomp;
        if want_landlock || want_seccomp || opts.probe.is_some() {
            match crate::find_helper() {
                Some(helper) => {
                    let spec = kernel::SandboxSpec {
                        landlock: want_landlock.then(|| kernel::landlock_spec(perms, host, &format!("/run/user/{}", host.uid), &launch_writable_paths(&ctx))),
                        seccomp: want_seccomp.then_some(kernel::SeccompSpec { strict, allow_userns: perms.advanced.allow_userns }),
                        probe: opts.probe.clone(),
                    };
                    let spec_path = runtime_dir.join("sandbox.json");
                    fs::write(&spec_path, serde_json::to_vec_pretty(&spec)?)?;
                    ctx.helper = Some(sam_core::sandbox::SandboxHelper { binary: helper, spec: spec_path });
                    landlock = want_landlock;
                    seccomp = want_seccomp;
                }
                None => warnings.push(Warning::warn(
                    "helper-missing",
                    "Kernel restrictions unavailable",
                    "sam-jail-run was not found next to sam-jail; Landlock and seccomp are not applied.",
                )),
            }
        }
    }

    let mut command = sam_sandbox::Bubblewrap.build(&ctx)?;
    if perms.network.mode == sam_core::permissions::NetworkMode::Localhost {
        if let Err(e) = crate::netns::wrap_localhost(
            &mut command,
            &perms.network.valid_host_ports(),
            &perms.network.valid_app_ports(),
        ) {
            // Without pasta, fall back to no network at all.
            command.args.insert(0, "--unshare-net".into());
            warnings.push(Warning::warn(
                "localhost-unavailable",
                "\"This computer only\" unavailable",
                sam_core::i18n::trf("{error}. Until then the app starts with no network at all, never with internet access.", &[("error", &format!("{e:#}"))]),
            ));
        }
    }
    let wayland_context = wayland.is_some();
    Ok(Prepared {
        sandbox,
        command,
        context: ctx,
        warnings,
        landlock,
        seccomp,
        wanted_landlock,
        wanted_seccomp,
        terminal,
        proxy,
        wayland_context,
        wayland,
        _runtime: runtime_guard,
    })
}

/// Paths mounted writable only for this launch: files and folders named on
/// the command line and writable extra binds.
fn launch_writable_paths(ctx: &LaunchContext) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = sam_sandbox::opened_paths(ctx)
        .into_iter()
        .filter(|(_, rw)| *rw)
        .map(|(p, _)| p)
        .collect();
    out.extend(
        ctx.extra_binds
            .iter()
            .filter(|(_, _, rw)| *rw)
            .map(|(_, dest, _)| dest.clone()),
    );
    if ctx.permissions.advanced.writable_appdir {
        out.push(ctx.sandbox_appdir.clone());
    }
    out
}

/// Did the failure come from the sandbox setup rather than the app? Also
/// whether Bubblewrap itself reported it (decisions go by that, never by
/// the summary, which is translated).
fn classify_failure(code: Option<i32>, stderr_head: &str) -> (bool, String, bool) {
    let first_bwrap = stderr_head
        .lines()
        .find(|l| l.starts_with("bwrap:"))
        .map(str::to_string);
    match code {
        Some(_) if first_bwrap.is_some() => (
            true,
            sam_core::i18n::trf(
                "sandbox setup failed: {reason}",
                &[("reason", &first_bwrap.unwrap_or_default())],
            ),
            true,
        ),
        Some(126) => (
            true,
            sam_core::i18n::tr(
                "the entry point could not be executed (permission denied or wrong format)",
            ),
            false,
        ),
        // The loader names the missing library itself: say that first.
        Some(127) if missing_library(stderr_head).is_some() => (
            true,
            sam_core::i18n::trf(
                "a library the app needs is not available inside the sandbox: {library}",
                &[("library", &missing_library(stderr_head).unwrap_or_default())],
            ),
            false,
        ),
        Some(127) => (
            true,
            sam_core::i18n::tr(
                "the entry point or one of its interpreters was not found inside the sandbox",
            ),
            false,
        ),
        _ => (false, String::new(), false),
    }
}

/// The library the loader could not find (`error while loading shared
/// libraries: libfoo.so.1: cannot open …`), if it said so.
fn missing_library(stderr_head: &str) -> Option<String> {
    let rest = stderr_head
        .lines()
        .find_map(|l| l.split_once("error while loading shared libraries: "))?
        .1;
    let name = rest.split(':').next()?.trim();
    (!name.is_empty() && name.len() < 200).then(|| sam_core::util::display_safe(name, 120))
}

const STDERR_HEAD_LIMIT: usize = 16 * 1024;

/// Starts the app in its sandbox and waits until it ends (or until
/// `opts.timeout_secs`). Writes the launch log and saves the outcome in the
/// app's entry.
pub fn run(
    app: &mut AppEntry,
    opts: &LaunchOptions,
    cfg: &Config,
    paths: &Paths,
    host: &HostInfo,
) -> Result<LaunchRecord> {
    let logs = Logs::new(paths);
    let log_path = logs.new_log_path(
        &app.id,
        if opts.tracer.is_some() {
            LogKind::Diagnose
        } else {
            LogKind::Launch
        },
    )?;
    let started_at = now();
    let mut log =
        fs::File::create(&log_path).with_context(|| format!("creating {}", log_path.display()))?;
    writeln!(
        log,
        "# SAM launch log\n# app: {} ({})\n# started: {}",
        app.display_name(),
        app.id,
        format_ts(started_at)
    )?;

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
    write_log_header(&mut log, &prepared)?;
    for w in &prepared.warnings {
        // A terminal program's start shows its own line (`terminal_banner`).
        if !opts.quiet && w.severity != sam_core::Severity::Info && w.code != "terminal-program" {
            eprintln!("sam-jail: warning: {}", w.message);
        }
    }

    // Start the sandbox.
    let channels = StatusChannels::new(&prepared, host)?;
    let mut cmd = Command::new(&prepared.command.program);
    cmd.args(channels.args.as_ref().unwrap_or(&prepared.command.args));
    // The sandbox dies with this launcher, however the launcher ends (even
    // SIGKILL, when no clean-up code runs). Bubblewrap's --die-with-parent
    // covers the processes inside; this covers the process started here,
    // which is pasta with "This computer only": without it pasta, and with
    // it the sandbox, would outlive the launcher.
    let launcher = std::process::id();
    // SAFETY: runs between fork and exec and calls only prctl, getppid and
    // _exit, which are async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            // The launcher may have died before prctl took effect.
            if libc::getppid() as u32 != launcher {
                libc::_exit(1);
            }
            Ok(())
        });
    }
    // The app never gets the user's terminal itself (see `pty`).
    let mode = prepared.terminal;
    let pty = match mode {
        TerminalMode::None => None,
        TerminalMode::Relay => {
            pty::end_with_the_terminal();
            Some(Pty::open(Some(pty::Outer::STDIO))?)
        }
        TerminalMode::Headless => Some(Pty::open(None)?),
    };
    if let Some(p) = &pty {
        cmd.stdin(p.stdio()?).stdout(p.stdio()?).stderr(p.stdio()?);
        // SAFETY: only async-signal-safe calls (setsid, ioctl).
        unsafe { cmd.pre_exec(Pty::become_controlling_terminal) };
        if mode == TerminalMode::Relay && app.metadata.terminal && !opts.quiet {
            eprintln!("{}", terminal_banner(app, &prepared));
        }
    } else {
        cmd.stdin(if pty::is_tty(0) {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    }
    if prepared.command.clear_env {
        cmd.env_clear();
    }
    for (k, v) in &prepared.command.env {
        cmd.env(k, v);
    }
    cmd.current_dir(&host.home);
    // Held until this launch is over: `Sam::running` sees the app as running.
    let _running = hold_lock(&prepared.context.runtime_dir.join("running.lock"))?;
    let spawned = cmd
        .spawn()
        .with_context(|| format!("starting {}", prepared.command.program.display()));
    // Close our copies of the write ends so the readers see EOF.
    for fd in channels
        .close_after_spawn
        .iter()
        .chain(prepared.context.seccomp_fd.as_ref())
    {
        // SAFETY: the descriptor belongs to this launch and is closed exactly once here.
        unsafe { libc::close(*fd) };
    }
    let mut child = spawned?;
    // `cmd` holds copies of the app's terminal: without them, the relay
    // sees when the app's side is closed.
    drop(cmd);
    let child_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bwrap_status_reader = channels
        .bwrap_status
        .map(|r| read_fd_in_thread(r, child_done.clone()));
    let helper_status_reader = channels
        .helper_status
        .map(|r| read_fd_in_thread(r, child_done.clone()));

    // Collect its output while it runs. The first part of each stream:
    // stderr decides whether the sandbox failed; both are searched for known
    // problems (some apps, such as Audacity, log errors to stdout).
    let log = Arc::new(Mutex::new(log));
    let err_head = Arc::new(Mutex::new(String::new()));
    let out_head = Arc::new(Mutex::new(String::new()));
    let mut pumps = Vec::new();
    let relay = match pty {
        // On a terminal both streams are one.
        Some(p) => Some(p.start(pty::OutputSink {
            head: err_head.clone(),
            head_limit: STDERR_HEAD_LIMIT,
            log: log.clone(),
            log_limit: 256 * 1024,
        })),
        None => {
            pumps.push(pump_output(
                Box::new(
                    child
                        .stdout
                        .take()
                        .context(sam_core::i18n::tr("no stdout pipe"))?,
                ),
                false,
                log.clone(),
                out_head.clone(),
                opts.quiet,
            ));
            pumps.push(pump_output(
                Box::new(
                    child
                        .stderr
                        .take()
                        .context(sam_core::i18n::tr("no stderr pipe"))?,
                ),
                true,
                log.clone(),
                err_head.clone(),
                opts.quiet,
            ));
            None
        }
    };
    let (status, timed_out) = wait_until(&mut child, opts.timeout_secs)?;
    child_done.store(true, std::sync::atomic::Ordering::SeqCst);
    for t in pumps {
        let _ = t.join();
    }
    let relay_end = relay.map(pty::Relay::finish);
    drop(prepared.proxy);
    drop(prepared.wayland);

    // Judge the outcome.
    let err_head = err_head.lock().map(|h| h.clone()).unwrap_or_default();
    let out_head = out_head.lock().map(|h| h.clone()).unwrap_or_default();
    let bwrap_json = bwrap_status_reader.and_then(|t| t.join().ok());
    let enforcement = helper_status_reader
        .and_then(|t| t.join().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let closed_by_sam = prepared.context.runtime_dir.join(STOP_MARKER).exists();
    let mut outcome = judge_outcome(
        status,
        &err_head,
        bwrap_json.as_deref(),
        closed_by_sam,
        timed_out.then_some(opts.timeout_secs.unwrap_or(0)),
    );
    if relay_end.as_ref().is_some_and(|r| r.hung_up)
        && !outcome.sandbox_failure
        && !outcome.setup_failed
    {
        // The user closed the terminal window: not a failed start.
        outcome.success = true;
        outcome.summary = sam_core::i18n::tr("ended when its terminal was closed");
    } else if app.metadata.terminal && ran_to_its_end(&outcome, status) {
        // A command-line tool that ends with an error code (wrong
        // arguments, nothing to do) has run fine in its sandbox; the code
        // stays in the record for scripts.
        outcome.success = true;
    }
    if let Ok(mut l) = log.lock() {
        if mode != TerminalMode::None {
            let what = if mode == TerminalMode::Relay {
                "connected to the user's terminal"
            } else {
                "80x24, no input (test start)"
            };
            writeln!(l, "\n# terminal: a terminal of its own, {what}")?;
        }
        if let Some(b) = relay_end
            .as_ref()
            .map(|r| &r.blocked)
            .filter(|b| !b.is_empty())
        {
            writeln!(
                l,
                "# terminal: blocked escape codes for {}",
                b.iter().copied().collect::<Vec<_>>().join(", ")
            )?;
        }
        if let Some(e) = &enforcement {
            writeln!(l, "# enforced: {e}")?;
        } else if prepared.landlock || prepared.seccomp {
            writeln!(l, "# enforced: unknown (no status from SAM's helper)")?;
        }
        writeln!(
            l,
            "# ---- end ----\n# finished: {}\n# result: {}",
            format_ts(now()),
            outcome.summary
        )?;
    }

    let rec = LaunchRecord {
        started_at,
        finished_at: now(),
        exit_code: status.code(),
        signal: status.signal(),
        success: outcome.success,
        sandbox_failure: outcome.sandbox_failure,
        setup_failed: outcome.setup_failed,
        missing_layers: missing_layers(
            enforcement.as_deref(),
            prepared.wanted_landlock,
            prepared.wanted_seccomp,
        ),
        enforcement,
        log_file: Some(log_path),
        findings: if outcome.success {
            vec![]
        } else {
            let mut f = crate::repair::analyze(
                &format!("{err_head}\n{out_head}"),
                &app.profile.permissions,
                status.signal(),
            );
            // Suggested only where it can work (see overlay_works_in).
            f.retain(|s| {
                s.id != "writable-appdir" || sam_core::host::overlay_works_in(&paths.overlays_dir())
            });
            f
        },
        summary: outcome.summary,
    };
    if !rec.missing_layers.is_empty() && !opts.quiet {
        eprintln!(
            "sam-jail: {}",
            sam_core::i18n::trf(
                "warning: this start ran without {layers}, which its settings ask for",
                &[("layers", &rec.missing_layers.join(", "))]
            )
        );
    }
    save_launch(app, &rec, paths)?;
    let _ = logs.prune(&app.id, LogKind::Launch, cfg.diagnostics.keep_logs);
    Ok(rec)
}

/// The line a terminal program's start shows first: what it can reach.
fn terminal_banner(app: &AppEntry, prepared: &Prepared) -> String {
    let ctx = &prepared.context;
    let fs = &ctx.permissions.filesystem;
    let mut sees: Vec<String> = Vec::new();
    if fs.home {
        sees.push(sam_core::i18n::tr("your home folder"));
    }
    for key in sam_core::permissions::XDG_DIR_KEYS {
        if !fs.home && fs.xdg_access(key).is_granted() {
            if let Some(d) = ctx.host.xdg_dir(key) {
                sees.push(sam_core::util::tildify(d));
            }
        }
    }
    sees.extend(fs.custom_read.iter().chain(&fs.custom_write).cloned());
    sees.extend(
        sam_sandbox::opened_paths(ctx)
            .iter()
            .map(|(p, _)| sam_core::util::tildify(p)),
    );
    let sees = if sees.is_empty() {
        sam_core::i18n::tr("only its private home")
    } else {
        sam_core::i18n::trf(
            "{folders} and its private home",
            &[("folders", &sees.join(", "))],
        )
    };
    format!(
        "\x1b[2msam-jail: {}\x1b[0m",
        sam_core::i18n::trf(
            "{app} runs sandboxed, in a terminal of its own. It sees {sees} (files it saves anywhere else stay there). It cannot type into this shell or use the clipboard through the terminal.",
            &[("app", &app.display_name()), ("sees", &sees)],
        )
    )
}

/// What the launch log says before the app's output: how the sandbox is
/// built and the full command.
fn write_log_header(log: &mut fs::File, prepared: &Prepared) -> Result<()> {
    writeln!(log, "# sandbox: {}", prepared.sandbox.reason)?;
    writeln!(
        log,
        "# landlock: {}  seccomp: {}  wayland security context: {}",
        prepared.landlock, prepared.seccomp, prepared.wayland_context
    )?;
    if let Some(p) = &prepared.proxy {
        writeln!(log, "# dbus proxy: xdg-dbus-proxy {}", shell_join(&p.args))?;
    }
    for n in &prepared.command.notes {
        writeln!(log, "# note: {n}")?;
    }
    for w in &prepared.warnings {
        writeln!(log, "# warning [{}]: {}", w.code, w.message)?;
    }
    // Values the person gave the app (API keys, tokens) stay out of the log:
    // bug reports quote its end, and a short run's end is this header.
    let env = &prepared.context.permissions.environment;
    let given: Vec<&str> = env
        .set
        .keys()
        .map(String::as_str)
        .chain(env.passthrough.iter().map(String::as_str))
        .collect();
    writeln!(
        log,
        "# command: {}",
        prepared.command.display_hiding(&given)
    )?;
    writeln!(log, "# ---- output ----")?;
    log.flush()?;
    Ok(())
}

/// Status channels the app cannot write to (H1/M3 in the audit): bwrap's
/// --json-status-fd announces "child-pid" once the sandbox exists, and SAM's
/// helper reports what it enforced before it execs the app.
///
/// Started directly, bwrap inherits two pipes. pasta (this computer only)
/// closes every inherited fd, so there the channels are FIFOs in the private
/// runtime dir, which a shell inside pasta's namespace opens as fds 3 and 4
/// right before it execs bwrap.
struct StatusChannels {
    /// The command's arguments with the status options added (None: unchanged).
    args: Option<Vec<String>>,
    /// Write ends to close in SAM once the child has its copies.
    close_after_spawn: Vec<i32>,
    bwrap_status: Option<i32>,
    helper_status: Option<i32>,
}

impl StatusChannels {
    fn new(prepared: &Prepared, host: &HostInfo) -> Result<Self> {
        let command = &prepared.command;
        let bwrap_path = host.tools.bwrap.as_ref().map(|b| b.path.clone());
        let direct_bwrap = bwrap_path.as_ref() == Some(&command.program);
        let pasta_bwrap = !direct_bwrap
            && command.program.file_name().is_some_and(|n| n == "pasta")
            && bwrap_path
                .as_ref()
                .is_some_and(|b| command.args.iter().any(|a| Path::new(a) == b));
        let with_helper = prepared.context.helper.is_some();
        let mut ch = StatusChannels {
            args: None,
            close_after_spawn: Vec::new(),
            bwrap_status: None,
            helper_status: None,
        };
        if direct_bwrap {
            let (r, w) = status_pipe()?;
            ch.bwrap_status = Some(r);
            ch.close_after_spawn.push(w);
            let mut helper_w = None;
            if with_helper {
                let (hr, hw) = status_pipe()?;
                ch.helper_status = Some(hr);
                ch.close_after_spawn.push(hw);
                helper_w = Some(hw);
            }
            ch.args = Some(with_status_options(&command.args, w, helper_w));
        } else if pasta_bwrap {
            let rt = &prepared.context.runtime_dir;
            let status_fifo = rt.join("bwrap-status");
            let helper_fifo = rt.join("helper-status");
            ch.bwrap_status = Some(open_fifo_reader(&status_fifo)?);
            if with_helper {
                ch.helper_status = Some(open_fifo_reader(&helper_fifo)?);
            }
            ch.args = Some(pasta_with_status(
                &command.args,
                &status_fifo,
                with_helper.then_some(helper_fifo.as_path()),
            )?);
        }
        Ok(ch)
    }
}

/// bwrap's own arguments with the status options inserted.
/// The kernel layers a start asked for but did not get, judged from what
/// SAM's helper reported from inside the sandbox. No report while layers
/// were wanted means none of them was applied (the helper did not run).
/// A partly enforced Landlock (an older kernel) counts as applied.
pub fn missing_layers(enforcement: Option<&str>, landlock: bool, seccomp: bool) -> Vec<String> {
    let report = enforcement.unwrap_or("");
    let mut missing = Vec::new();
    if landlock
        && !(report.contains("landlock: fully enforced")
            || report.contains("landlock: partially enforced"))
    {
        missing.push("Landlock".to_string());
    }
    if seccomp && !report.contains("seccomp: ") {
        missing.push("seccomp".to_string());
    }
    missing
}

/// The pasta command with bwrap's status pipes opened inside pasta's
/// namespace: `pasta … -- PROG ARGS…` becomes `pasta … -- /bin/sh -c '…'
/// PROG ARGS…` with the status options added to PROG's arguments. A command
/// without a program after `--` is refused, never indexed past its end.
fn pasta_with_status(
    args: &[String],
    status_fifo: &Path,
    helper_fifo: Option<&Path>,
) -> Result<Vec<String>> {
    let sep = args
        .iter()
        .position(|a| a == "--")
        .context(sam_core::i18n::tr("pasta command without '--'"))?;
    let (prog, rest) = args[sep + 1..].split_first().context(sam_core::i18n::tr(
        "pasta command without a program after '--'",
    ))?;
    let mut out: Vec<String> = args[..=sep].to_vec();
    out.extend([
        "/bin/sh".into(),
        "-c".into(),
        r#"exec 3>"$1"; if [ -n "$2" ]; then exec 4>"$2"; fi; shift 2; exec "$@""#.into(),
        "sh".into(),
        status_fifo.display().to_string(),
        helper_fifo
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        prog.clone(),
    ]);
    out.extend(with_status_options(rest, 3, helper_fifo.map(|_| 4)));
    Ok(out)
}

fn with_status_options(
    bwrap_args: &[String],
    status_fd: i32,
    helper_fd: Option<i32>,
) -> Vec<String> {
    let mut args = vec!["--json-status-fd".to_string(), status_fd.to_string()];
    args.extend(bwrap_args.iter().cloned());
    if let Some(hw) = helper_fd {
        // After --clearenv: right before bwrap's "--" separator.
        let sep = args.iter().position(|a| a == "--").unwrap_or(args.len());
        args.splice(
            sep..sep,
            [
                "--setenv".to_string(),
                "SAM_STATUS_FD".into(),
                hw.to_string(),
            ],
        );
    }
    args
}

/// The most a launch log grows (both streams together). An app that prints
/// without end would otherwise fill the disk; the rest of its output is
/// still read, so the app never blocks, but no longer written.
const LOG_LIMIT: u64 = 16 * 1024 * 1024;
/// The longest piece read at once: a "line" without an end is split, so it
/// cannot fill SAM's memory.
const LINE_LIMIT: u64 = 64 * 1024;

/// Copies one output stream of the app into the launch log (and, unless
/// quiet, to SAM's own output), keeping its first part in `head`. The log
/// stops at `LOG_LIMIT` with a note; the output is still read to its end.
fn pump_output(
    src: Box<dyn Read + Send>,
    is_err: bool,
    log: Arc<Mutex<fs::File>>,
    head: Arc<Mutex<String>>,
    quiet: bool,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(src);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader
                .by_ref()
                .take(LINE_LIMIT)
                .read_until(b'\n', &mut line)
            {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            let text = String::from_utf8_lossy(&line);
            if let Ok(mut l) = log.lock() {
                let size = l.metadata().map(|m| m.len()).unwrap_or(0);
                if size < LOG_LIMIT {
                    let _ = writeln!(l, "{}{text}", if is_err { "[err] " } else { "" });
                    if l.metadata().map(|m| m.len()).unwrap_or(0) >= LOG_LIMIT {
                        let _ = writeln!(
                            l,
                            "[sam] this log reached {} MiB; the rest of the app's output is not kept",
                            LOG_LIMIT / 1024 / 1024
                        );
                    }
                }
            }
            if let Ok(mut h) = head.lock() {
                if h.len() < STDERR_HEAD_LIMIT {
                    h.push_str(&text);
                    h.push('\n');
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
}

/// Waits for the child; with a time limit, ends it when the time is up
/// (a test start or diagnostic run). Returns whether SAM ended it.
fn wait_until(
    child: &mut std::process::Child,
    timeout_secs: Option<u64>,
) -> Result<(std::process::ExitStatus, bool)> {
    let Some(secs) = timeout_secs else {
        return Ok((child.wait()?, false));
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok((st, false));
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            return Ok((child.wait()?, true));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

struct Outcome {
    success: bool,
    sandbox_failure: bool,
    setup_failed: bool,
    summary: String,
}

/// Whether a finished launch worked, failed in the app, or failed to build
/// the sandbox. `bwrap_json` is bwrap's status channel (None when there was
/// none), `kept_running_for` the time limit when SAM ended the app.
fn judge_outcome(
    status: std::process::ExitStatus,
    err_head: &str,
    bwrap_json: Option<&str>,
    stop_marker: bool,
    kept_running_for: Option<u64>,
) -> Outcome {
    let code = status.code();
    let signal = status.signal();
    let (mut sandbox_failure, mut summary, bwrap_said) = classify_failure(code, err_head);
    // Verified setup failure: bwrap never announced the app's process.
    let setup_failed = bwrap_json.is_some_and(|j| !j.contains("\"child-pid\""));
    if bwrap_json.is_some() && bwrap_said && !setup_failed {
        // The sandbox was built; "bwrap:" lines came from the app itself.
        sandbox_failure = false;
        summary.clear();
    }
    if setup_failed {
        sandbox_failure = true;
        if !bwrap_said {
            summary =
                sam_core::i18n::tr("sandbox setup failed (Bubblewrap could not build the sandbox)");
        }
    }
    // `Sam::stop` (Close and Remove, `sam-jail stop`) asked the app to quit:
    // however it exits, that is not a failed start.
    let closed_by_sam = !setup_failed && stop_marker;
    if closed_by_sam {
        sandbox_failure = false;
        summary = sam_core::i18n::tr("closed by SAM");
    }
    // Still running when the time was up: it started fine.
    let kept_running = kept_running_for.is_some() && !setup_failed && !sandbox_failure;
    if kept_running {
        summary = sam_core::i18n::trf(
            "kept running for {seconds} s (test start, ended by SAM)",
            &[("seconds", &kept_running_for.unwrap_or(0))],
        );
    }
    let success = status.success() || closed_by_sam || kept_running;
    if summary.is_empty() {
        summary = match (code, signal) {
            (Some(0), _) => sam_core::i18n::tr("exited normally"),
            (Some(c), _) => sam_core::i18n::trf("exited with code {code}", &[("code", &c)]),
            (None, Some(11)) => sam_core::i18n::tr("ended by signal 11 (segmentation fault)"),
            (None, Some(6)) => sam_core::i18n::tr("ended by signal 6 (abort)"),
            (None, Some(s)) => sam_core::i18n::trf("ended by signal {signal}", &[("signal", &s)]),
            _ => sam_core::i18n::tr("finished"),
        };
    }
    Outcome {
        success,
        sandbox_failure,
        setup_failed,
        summary,
    }
}

/// For a terminal program: it started in the sandbox and ended by itself
/// (any exit code), rather than failing to start or crashing.
fn ran_to_its_end(o: &Outcome, status: std::process::ExitStatus) -> bool {
    !o.sandbox_failure && !o.setup_failed && status.signal().is_none()
}

/// Stores the launch in the app's entry. Saves against the latest on-disk
/// entry so concurrent GUI edits survive.
fn save_launch(app: &mut AppEntry, rec: &LaunchRecord, paths: &Paths) -> Result<()> {
    app.last_launched = Some(rec.started_at);
    app.last_launch = Some(rec.clone());
    if rec.sandbox_failure {
        app.last_error = Some(rec.summary.clone());
    } else if app.state == AppState::Broken && app.extraction.is_some() {
        app.state = AppState::Ready;
        app.last_error = None;
    }
    let reg = Registry::new(paths);
    if let Some(mut fresh) = reg.get(&app.id)? {
        fresh.last_launched = app.last_launched;
        fresh.last_launch = app.last_launch.clone();
        fresh.last_error = app.last_error.clone();
        fresh.state = app.state;
        reg.save(&mut fresh)?;
    }
    Ok(())
}

/// A pipe whose write end is inherited by child processes.
fn status_pipe() -> Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid array of two ints for pipe2 to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    // SAFETY: fds[1] is the pipe end pipe2 just created; F_SETFD only changes its flags.
    unsafe { libc::fcntl(fds[1], libc::F_SETFD, 0) };
    Ok((fds[0], fds[1]))
}

/// Creates `path` and holds an exclusive lock on it while the file is open.
fn hold_lock(path: &Path) -> Result<fs::File> {
    use std::os::fd::AsRawFd;
    let f = fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    // SAFETY: `f` is an open file; flock only takes its descriptor.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!(
            "locking {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(f)
}

/// True if another process holds the lock on `path`.
pub fn lock_held(path: &Path) -> bool {
    use std::os::fd::AsRawFd;
    let Ok(f) = fs::File::open(path) else {
        return false;
    };
    // SAFETY: `f` is an open file; flock only takes its descriptor.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) != 0 }
}

/// Opens the read end of a new FIFO without waiting for a writer.
fn open_fifo_reader(path: &Path) -> Result<i32> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `c` is a NUL-terminated path.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        bail!(
            "mkfifo {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: `c` is a NUL-terminated path; the returned descriptor is checked and closed below.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        bail!(
            "open {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(fd)
}

/// Reads a status channel until its writers are gone. Works for pipes and
/// for FIFOs a writer may never open: on Linux, poll() reports a hangup on a
/// FIFO only after a writer was connected, and `done` ends the wait once the
/// sandbox process has exited.
fn read_fd_in_thread(
    fd: i32,
    done: Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` is one valid pollfd.
            let n = unsafe { libc::poll(&mut pfd, 1, 200) };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if n == 0 {
                if done.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                continue;
            }
            // SAFETY: `buf` is a valid, writable buffer of buf.len() bytes and `fd` is open.
            let r = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if r > 0 {
                out.extend_from_slice(&buf[..r as usize]);
                if out.len() > 64 * 1024 {
                    break;
                }
            } else if r == 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock
            {
                break;
            }
        }
        // SAFETY: the FIFO descriptor opened above is closed exactly once here.
        unsafe { libc::close(fd) };
        String::from_utf8_lossy(&out).into_owned()
    })
}

/// Last lines of a log file (for reports and the GUI).
pub fn tail(path: &Path, max_lines: usize) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(max_lines)..].join("\n")
}

#[cfg(test)]
mod log_limit_tests {
    use super::*;

    /// An app that prints without end cannot fill the disk or SAM's memory:
    /// the launch log stops at its limit with a note, a line without an end
    /// is read in pieces, and the whole output is still read.
    #[test]
    fn a_launch_log_stops_growing_at_its_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("launch.log");
        let log = Arc::new(Mutex::new(fs::File::create(&path).unwrap()));
        let head = Arc::new(Mutex::new(String::new()));
        // 24 MiB in lines, then 8 MiB without a single line break.
        let mut data = b"0123456789abcdef\n".repeat(24 * 1024 * 1024 / 17);
        data.extend(std::iter::repeat_n(b'x', 8 * 1024 * 1024));
        let total = data.len();
        let src = std::io::Cursor::new(data);
        let counted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        struct Counting(
            std::io::Cursor<Vec<u8>>,
            Arc<std::sync::atomic::AtomicUsize>,
        );
        impl Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(buf)?;
                self.1.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                Ok(n)
            }
        }
        pump_output(
            Box::new(Counting(src, counted.clone())),
            false,
            log,
            head,
            true,
        )
        .join()
        .unwrap();
        let size = fs::metadata(&path).unwrap().len();
        assert!(
            (LOG_LIMIT..LOG_LIMIT + 2 * LINE_LIMIT).contains(&size),
            "the log stops near its limit: {size}"
        );
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("the rest of the app's output is not kept"));
        assert_eq!(
            counted.load(std::sync::atomic::Ordering::Relaxed),
            total,
            "the whole output is still read, so the app never blocks"
        );
    }
}

#[cfg(test)]
mod pasta_status_tests {
    use super::*;

    #[test]
    fn a_wanted_layer_that_was_not_applied_is_reported_missing() {
        let full = "landlock: fully enforced; seccomp: baseline loaded";
        assert!(missing_layers(Some(full), true, true).is_empty());
        assert!(missing_layers(
            Some("landlock: partially enforced; seccomp: strict loaded"),
            true,
            true
        )
        .is_empty());
        assert_eq!(
            missing_layers(
                Some("landlock: NOT applied (no kernel support); seccomp: baseline loaded"),
                true,
                true
            ),
            vec!["Landlock"]
        );
        // No report at all: the helper did not run, nothing was applied.
        assert_eq!(
            missing_layers(None, true, true),
            vec!["Landlock", "seccomp"]
        );
        // Layers that were not asked for are never missing.
        assert!(missing_layers(None, false, false).is_empty());
    }

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_pasta_command_ending_in_the_separator_is_refused_not_a_panic() {
        let fifo = Path::new("/run/s");
        assert!(pasta_with_status(&v(&["pasta", "--config-net", "--"]), fifo, None).is_err());
        assert!(pasta_with_status(&v(&["pasta", "--config-net"]), fifo, None).is_err());
    }

    #[test]
    fn the_status_shell_goes_between_the_separator_and_the_program() {
        let out = pasta_with_status(
            &v(&["pasta", "--", "bwrap", "--unshare-all", "--", "app"]),
            Path::new("/run/s"),
            None,
        )
        .unwrap();
        assert_eq!(&out[..4], &v(&["pasta", "--", "/bin/sh", "-c"]));
        assert_eq!(out[6], "/run/s");
        assert_eq!(out[7], "", "no helper pipe");
        assert_eq!(out[8], "bwrap");
        assert!(out[9..].contains(&"--unshare-all".to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without Bubblewrap, starting an app stops while it is being prepared,
    /// before any process is started, and the error says what to install.
    #[test]
    fn a_start_without_bubblewrap_stops_before_anything_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let appdir = tmp.path().join("AppDir");
        std::fs::create_dir_all(&appdir).unwrap();
        std::fs::write(appdir.join("AppRun"), "#!/bin/sh\n").unwrap();
        let app = AppEntry {
            id: "appimage-x-1".into(),
            extraction: Some(sam_core::model::ExtractionInfo {
                root: tmp.path().into(),
                appdir,
                entry: "AppRun".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut host = sam_core::sandbox::sample_context().host;
        host.tools.bwrap = None;
        let paths = Paths::rooted(tmp.path());
        let err = prepare(
            &app,
            &LaunchOptions::default(),
            &Config::default(),
            &paths,
            &host,
        )
        .err()
        .expect("refused")
        .to_string();
        assert!(err.contains("bubblewrap"), "{err}");
        assert!(
            !paths.runtime_dir(&app.id).exists(),
            "nothing was set up for a start"
        );
    }

    /// Bubblewrap setup errors are told apart from errors of the app itself.
    #[test]
    fn sandbox_setup_errors_are_told_apart_from_app_errors() {
        assert!(classify_failure(Some(1), "bwrap: Can't mount proc").0);
        assert!(classify_failure(Some(127), "").0);
        let (_, summary, _) = classify_failure(
            Some(127),
            "./app: error while loading shared libraries: libkeybinder-3.0.so.0: cannot open shared object file: No such file or directory",
        );
        assert!(
            summary.contains("libkeybinder-3.0.so.0") && !summary.contains("entry point"),
            "a missing library is named first: {summary}"
        );
        assert!(!classify_failure(Some(1), "app error").0);
        assert!(!classify_failure(None, "").0);
    }

    fn exited(code: i32) -> std::process::ExitStatus {
        std::process::ExitStatus::from_raw(code << 8)
    }

    /// A start is judged by whether Bubblewrap announced the app, not by what the app printed.
    #[test]
    fn a_start_is_judged_by_whether_the_app_started() {
        let started = Some(r#"{"child-pid": 7}"#);
        let never_started = Some(r#"{"exit-code": 1}"#);

        let o = judge_outcome(exited(0), "", started, false, None);
        assert!(o.success && !o.sandbox_failure && o.summary == "exited normally");

        // bwrap never announced the app: a setup failure, whatever stderr says.
        let o = judge_outcome(exited(1), "", never_started, false, None);
        assert!(!o.success && o.sandbox_failure && o.setup_failed);
        // Even a stop request does not turn that into "closed by SAM".
        assert!(judge_outcome(exited(1), "", never_started, true, None).setup_failed);

        // "bwrap:" lines from inside a sandbox that was built (nested bwrap).
        let o = judge_outcome(
            exited(1),
            "bwrap: Creating new namespace failed",
            started,
            false,
            None,
        );
        assert!(!o.sandbox_failure && o.summary == "exited with code 1");
        // Without the status channel, such lines count as a setup failure.
        assert!(
            judge_outcome(exited(1), "bwrap: Can't mount proc", None, false, None).sandbox_failure
        );

        let o = judge_outcome(
            std::process::ExitStatus::from_raw(15),
            "",
            started,
            true,
            None,
        );
        assert!(o.success && o.summary == "closed by SAM");

        let o = judge_outcome(
            std::process::ExitStatus::from_raw(9),
            "",
            started,
            false,
            Some(20),
        );
        assert!(o.success && o.summary.starts_with("kept running for 20 s"));
        // A time limit does not hide an entry point that could not run.
        assert!(!judge_outcome(exited(127), "", started, false, Some(20)).success);

        assert_eq!(
            judge_outcome(
                std::process::ExitStatus::from_raw(11),
                "",
                started,
                false,
                None
            )
            .summary,
            "ended by signal 11 (segmentation fault)"
        );

        // Terminal programs: an exit code of their own is no failed start;
        // a crash, a missing entry point or a sandbox failure is.
        let ran = |st: std::process::ExitStatus| {
            ran_to_its_end(&judge_outcome(st, "", started, false, None), st)
        };
        assert!(ran(exited(1)) && ran(exited(2)));
        assert!(!ran(exited(127)) && !ran(std::process::ExitStatus::from_raw(11)));
        assert!(!ran_to_its_end(
            &judge_outcome(exited(1), "", never_started, false, None),
            exited(1)
        ));
    }
}
