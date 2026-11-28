//! Launching: environment checks, command
//! generation, launch logging and crash capture.

use std::fs;
use std::io::{Read, Write};
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
use sam_core::errln;

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
    /// Echo the app's standard output on SAM's standard error, so SAM's
    /// own standard output holds only its JSON reply (`--json run`; audit
    /// G-F18).
    pub app_output_to_stderr: bool,
    /// Sandbox check: the helper runs these checks instead of the app.
    pub probe: Option<crate::probe::ProbePlan>,
    /// This is SAM's one automatic restart after the app was refused a
    /// bus name it may now own; never restart again.
    pub name_retry: bool,
    /// Called at once, while the app runs, when this start lacks a
    /// protection layer its settings ask for (app id, app name, the missing
    /// layers): a start from the menu has no terminal for the warning, and
    /// the app may run for hours (review K-4).
    pub on_missing_layers: Option<MissingLayersHook>,
    /// "Start anyway, this time": a protection the settings ask for that
    /// this start cannot set up (SAM's helper missing, the Wayland security
    /// context refused) is reported instead of stopping the start (B2 R75,
    /// R77). Never saved; each start decides again.
    pub start_anyway: bool,
    /// Only the command is shown (`sam-jail command`, the app page): a
    /// missing protection is not a refusal there, the command shows it.
    pub preview: bool,
}

/// See [`LaunchOptions::on_missing_layers`].
pub type MissingLayersHook = fn(&str, &str, &[String]);

/// Everything needed to start a sandbox, plus the explanation for the user.
/// Left in a launch's runtime folder by `Sam::stop` before it signals the app.
pub const STOP_MARKER: &str = "stop-requested";
/// In a launch's runtime folder: the process id of the program the launcher
/// started (Bubblewrap, or pasta with "This computer only"). `Sam::stop`
/// asks only the processes below it to quit (`ops::ask_to_quit`).
pub const SANDBOX_PID: &str = "sandbox-pid";
/// In SAM's data folder: what an app left in places that make the computer
/// run something, moved aside (one folder per app and start).
const MOVED_ASIDE: &str = "moved-aside";

pub struct Prepared {
    pub sandbox: SandboxInfo,
    pub command: SandboxCommand,
    pub context: LaunchContext,
    pub warnings: Vec<Warning>,
    pub landlock: bool,
    pub seccomp: bool,
    /// The app may make namespaces of its own (Advanced setting).
    pub allow_userns: bool,
    /// The kernel layers the settings ask for, applied or not (without SAM's
    /// helper they cannot be): what a start is checked against.
    pub wanted_landlock: bool,
    pub wanted_seccomp: bool,
    /// The start relies on Landlock's fence around abstract sockets: the
    /// app shares the host's network namespace, where the X server's and
    /// other abstract sockets of the desktop live, and the kernel has the
    /// fence (Linux 6.12, Landlock ABI 6). Checked like a layer (review K-1).
    pub wanted_fence: bool,
    /// How the app's terminal is handled (see `pty`).
    pub terminal: TerminalMode,
    proxy: Option<DbusProxy>,
    /// SAM's sound relay for this start, if the app has sound.
    sound: Option<crate::sound_relay::SoundRelay>,
    /// Whether the app's Wayland socket carries a security context.
    pub wayland_context: bool,
    /// The compositor offers security contexts, but making one failed: the
    /// app got the normal socket. Reported as a missing layer.
    pub wayland_context_failed: bool,
    /// The writable home's protected places before the start (full home
    /// read/write); looked at again when the app has ended.
    pub home_watch: Option<sam_sandbox::HomeWatch>,
    /// The same, kept on disk while the launch runs (`home_shared`).
    home_record: Option<crate::home_shared::Registration>,
    /// Where what the app leaves in those places is moved.
    home_aside: PathBuf,
    /// What another running app had left in those places, moved aside
    /// before this start.
    moved_at_start: Vec<sam_sandbox::MovedAside>,
    wayland: Option<crate::wayland_ctx::WaylandContext>,
    /// Room service for this start, if the app has it.
    rooms: Option<crate::room_service::RoomService>,
    _runtime: RuntimeDir,
}

/// Removes a per-launch runtime directory when the launch is over.
/// The name of a launch's runtime folder: `l<process>-<n>`, `n` counting
/// the launches of this process. Short on purpose: the folder holds the
/// app's sockets (Wayland, bus, sound), whose whole path may have at most
/// 107 characters, below the runtime folder and an app id of up to 46
/// (the 240-app run of 2026-11-20: longer names cost apps with long ids
/// their sound, their bus and the Wayland security context).
fn launch_dir_name() -> String {
    static COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("l{}-{n}", std::process::id())
}

/// The process that made a launch's runtime folder, from its name.
pub(crate) fn launch_dir_pid(name: &str) -> Option<u32> {
    name.strip_prefix('l')?.split_once('-')?.0.parse().ok()
}

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
    /// The app's own variables when SAM's helper sets them for the app,
    /// once its layers are in place: they are then not in `argv` (review
    /// SB-5), and a preview without them would hide what the app gets.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub app_variables: Vec<(String, String)>,
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
            app_variables: self.command.exec_env.clone(),
        }
    }
}

/// The protection layers SAM's helper applies for this start: Landlock
/// where the app's switch (or the global default) wants it and the kernel
/// has it; the syscall filter where the baseline is on in both the
/// configuration and the app, or the app's own strict switch is on. The
/// strict switch decides by itself (audit D-M13: it did nothing unless a
/// Whether the app gets Room service, and whether SAM's helper goes into
/// its sandbox: for Landlock, the syscall filter, a probe, or Room service
/// (its stand-in), each on its own. A probe start has no rooms.
fn helper_wanted(landlock: bool, seccomp: bool, room_service: bool, probe: bool) -> Wanted {
    let rooms = room_service && !probe;
    let layers = landlock || seccomp || probe;
    Wanted {
        rooms,
        layers,
        helper: layers || rooms,
    }
}

/// What a start wants SAM's helper for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Wanted {
    /// Room service (never on a probe start).
    rooms: bool,
    /// Landlock, the syscall filter or a probe.
    layers: bool,
    /// The helper in the sandbox at all.
    helper: bool,
}

/// The warnings when SAM's helper is missing: each names only what is
/// really lost (the kernel layers the app wanted, Room service).
fn helper_missing_warnings(want_layers: bool, want_rooms: bool) -> Vec<Warning> {
    let mut out = Vec::new();
    if want_layers {
        out.push(Warning::warn(
            "helper-missing",
            "Kernel restrictions unavailable",
            "sam-jail-run was not found next to sam-jail; Landlock and seccomp are not applied.",
        ));
    }
    if want_rooms {
        out.push(Warning::warn(
            "room-service-failed",
            "Room service unavailable",
            sam_core::i18n::trf(
                "{error}; programs in this app that build a sandbox of their own fail this time",
                &[(
                    "error",
                    &"sam-jail-run was not found next to sam-jail".to_string(),
                )],
            ),
        ));
    }
    out
}

/// The code of the error that stops a start lacking a protection its
/// settings ask for: callers offer "Start anyway, this time"
/// ([`LaunchOptions::start_anyway`]).
pub const PROTECTION_MISSING: &str = "protection-missing";

/// What a start could not set up before the app starts: the kernel
/// layers its settings ask for, because SAM's helper was not found, and
/// the Wayland security context the desktop offers but refused (its
/// error). A desktop without security contexts is not in it: there is
/// nothing SAM could have applied.
struct MissingAtStart<'a> {
    landlock: bool,
    seccomp: bool,
    wayland: Option<&'a str>,
}

/// Stops the start when it lacks a protection its settings ask for (B2
/// R75, R77; owner, 2026-11-25: "refuse, with override"), unless the person
/// chose "Start anyway" for this start, or it is the sandbox check, which
/// reports each layer itself. Before, such a start went on with a warning
/// only: without its syscall filter and Landlock, or with the
/// compositor's own socket and every privileged Wayland function.
fn protection_check(missing: &MissingAtStart, opts: &LaunchOptions) -> Result<()> {
    if opts.start_anyway || opts.preview || opts.probe.is_some() {
        return Ok(());
    }
    let mut what = Vec::new();
    if missing.landlock {
        what.push(sam_core::i18n::tr("Landlock write protection"));
    }
    if missing.seccomp {
        what.push(sam_core::i18n::tr("the syscall filter"));
    }
    let mut why = Vec::new();
    if missing.landlock || missing.seccomp {
        why.push(sam_core::i18n::tr(
            "SAM's helper sam-jail-run was not found next to sam-jail",
        ));
    }
    if let Some(e) = missing.wayland {
        what.push(sam_core::i18n::tr("the Wayland security context"));
        why.push(sam_core::i18n::trf(
            "the desktop did not set up the Wayland security context: {error}",
            &[("error", &e)],
        ));
    }
    if what.is_empty() {
        return Ok(());
    }
    Err(sam_core::error::CodedError::new(
        PROTECTION_MISSING,
        sam_core::i18n::trf(
            "SAM did not start the app: it would run without {layers}, which its settings ask for ({why}). Start it anyway only if you trust it without that protection; this applies to that one start.",
            &[("layers", &what.join(", ")), ("why", &why.join("; "))],
        ),
    )
    .into())
}

/// second, global setting was on).
fn wanted_layers(
    perms: &sam_core::permissions::PermissionSet,
    cfg: &Config,
    host: &sam_core::host::HostInfo,
) -> (bool, bool) {
    let landlock = perms
        .advanced
        .landlock
        .unwrap_or(cfg.security.experimental_landlock)
        && host.landlock_abi.is_some();
    let seccomp = (cfg.security.baseline_seccomp && perms.advanced.seccomp_baseline)
        || perms.advanced.seccomp_strict;
    (landlock, seccomp)
}

/// The syscall filter for a start of `app`: its switches, and whether the
/// program it starts is 32-bit, whose 32-bit calls the filter then takes
/// instead of ending the app (review K-3).
fn seccomp_spec(app: &AppEntry) -> kernel::SeccompSpec {
    let perms = &app.profile.permissions;
    kernel::SeccompSpec {
        strict: perms.advanced.seccomp_strict,
        allow_userns: perms.advanced.allow_userns,
        bluetooth: perms.devices.bluetooth,
        i386: app
            .detection
            .as_ref()
            .is_some_and(sam_core::DependencyReport::starts_32_bit_program),
    }
}

/// A start of `app` with `perms` gets the syscall filter with its 32-bit
/// part, whose socket limit has a gap: a 32-bit socket made through the
/// old `socketcall` call can be of any type
/// ([`kernel::SeccompSpec::socketcall_unlimited`]). The app page and the
/// sandbox check say so. `perms` are the settings being looked at, which
/// on the app page may differ from the stored ones.
pub(crate) fn socket_limit_incomplete(
    app: &AppEntry,
    perms: &sam_core::permissions::PermissionSet,
    cfg: &Config,
    host: &sam_core::host::HostInfo,
) -> bool {
    wanted_layers(perms, cfg, host).1 && seccomp_spec(app).socketcall_unlimited()
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
    // Settings nobody has looked at yet (added on the command line without
    // --accept): what the app says about itself chose them (its name and
    // description decide category and network), so the app does not start
    // until a person has confirmed them (audit U-M11).
    if !app.reviewed {
        errors.push(sam_core::i18n::trf(
            "The settings of {app} have not been confirmed yet: SAM chose them partly from what the app says about itself. SAM does not start the app until you have looked at them: open the app in SAM and confirm its settings, or run `sam-jail review {id}`.",
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
            // "May not be": when the closing save of an "Unpack Again"
            // failed (another SAM process kept the record lock too long, a
            // full disk), the unpacked copy already holds this file while
            // the record still names the file unpacked before.
            warns.push(Warning::warn(
                "source-stale",
                "AppImage changed",
                "The AppImage changed since SAM last recorded unpacking it, so the unpacked copy SAM starts may not be this file. Unpack it again so that SAM starts this file and its record describes it.",
            ));
        }
    }
    (errors, warns)
}

/// The folder that holds every app's runtime folders, where SAM's helpers
/// (the D-Bus proxy, the sound relay) listen: the app page and the sandbox
/// check count a user folder or bind that leads there as one that leads to
/// where programs outside the sandbox listen, as the sandbox does for its
/// start ([`sam_core::places::ThisStart`]).
pub fn sam_runtime_folders(paths: &Paths) -> Vec<PathBuf> {
    paths
        .runtime_dir("app")
        .parent()
        .map(Path::to_path_buf)
        .into_iter()
        .collect()
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

    let own_dirs = paths.sam_dirs(&cfg.extraction.location);
    let sam_runtime = sam_runtime_folders(paths);
    let ctx_w = WarningContext {
        app_needs_network: Some(crate::ops::app_needs_network(app)),
        host: Some(host),
        warn_x11: cfg.security.warn_x11,
        warn_full_home: cfg.security.warn_full_home,
        terminal_program: app.metadata.terminal,
        sam_dirs: &own_dirs,
        sam_runtime: &sam_runtime,
    };
    warnings.extend(evaluate(perms, &ctx_w));
    // A terminal of its own for a user's start from a terminal, and for a
    // terminal program's test start (see `pty`).
    let interactive = opts.timeout_secs.is_none() && opts.probe.is_none();
    let terminal = TerminalMode::choose(
        app.metadata.terminal,
        pty::is_tty(0),
        pty::is_tty(1),
        interactive,
    );

    // One runtime directory per launch (two instances of an app never share
    // proxy sockets or spec files); removed when `Prepared` is dropped.
    let runtime_dir = paths.runtime_dir(&app.id).join(launch_dir_name());
    // A folder of a finished process that had the same number.
    let _ = fs::remove_dir_all(&runtime_dir);
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
        app.source_path.file_name().map(|n| {
            sam_core::sandbox::appimage_inside(n)
                .to_string_lossy()
                .into_owned()
        })
    } else {
        None
    };
    let mut app_env: Vec<(String, String)> = vec![
        ("APPDIR".into(), "@APPDIR@".into()),
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
        sound_socket: None,
        wayland_socket: None,
        helper: None,
        own_terminal: terminal != TerminalMode::None,
        tracer: opts.tracer.clone(),
        extra_binds: opts.extra_binds.clone(),
        appdir_overlay: None,
        sam_dirs: own_dirs,
        sam_programs: sam_core::util::own_programs(),
        room_socket: None,
    };
    // The folders that hold apps' data are for this user only, also when
    // an older SAM made them readable for everyone (review F4).
    for d in [
        paths.homes_dir(),
        paths.overlays_dir(),
        paths.data_dir.join(MOVED_ASIDE),
    ] {
        if d.is_dir() {
            let _ = sam_core::util::private_dirs(&paths.data_dir, &d);
        }
    }
    if perms.advanced.writable_appdir && !sam_core::host::bwrap_supports_overlay() {
        warnings.push(Warning::warn(
            "writable-appdir-unavailable",
            "Writable app folder unavailable",
            "The writable app folder needs overlays, which the installed Bubblewrap does not offer (they came with Bubblewrap 0.11), so the app folder stays read-only. Update Bubblewrap to use this setting.",
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
        // Its own layers inside stay as made: the upper one is the app
        // folder's top as the app sees it.
        sam_core::util::private_dirs(&paths.data_dir, &base)?;
        fs::create_dir_all(base.join("upper"))?;
        fs::create_dir_all(base.join("work"))?;
        ctx.appdir_overlay = Some(base);
    }

    if perms.advanced.persistent_home {
        sam_core::util::private_dirs(&paths.data_dir, &ctx.private_home).with_context(|| {
            sam_core::i18n::trf(
                "creating the private home {folder}",
                &[("folder", &ctx.private_home.display())],
            )
        })?;
    }

    let mut proxy = None;
    let mut sound = None;
    let mut wayland = None;
    let mut wayland_context_failed = false;
    // The Wayland security context's error, if making one failed (B2 R77;
    // see `protection_check`).
    let mut wayland_error: Option<String> = None;
    let home_watch;
    let mut home_record = None;
    let mut moved_at_start = Vec::new();
    let home_aside = paths
        .data_dir
        .join(MOVED_ASIDE)
        .join(&app.id)
        .join(now().to_string());
    let mut landlock = false;
    let mut seccomp = false;
    // SAM's helper's file, written once the sandbox is built (it holds the
    // app's own variables from the build).
    let mut helper_spec: Option<kernel::SandboxSpec> = None;
    let wanted_landlock: bool;
    let wanted_seccomp: bool;
    // Room service needs SAM's helper in the sandbox (its stand-in for
    // Bubblewrap), even where the app itself gets no layer from it.
    let (want_landlock, want_seccomp) = wanted_layers(perms, cfg, host);
    let wanted = helper_wanted(
        want_landlock,
        want_seccomp,
        perms.advanced.room_service,
        opts.probe.is_some(),
    );
    let helper_found = if wanted.helper {
        crate::find_helper()
    } else {
        None
    };
    // The Wayland security context first too, so that a start that cannot
    // have it stops before anything else is set up for it.
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
                Err(e) => {
                    wayland_context_failed = true;
                    wayland_error = Some(format!("{e:#}"));
                    warnings.push(Warning::warn("wayland-context-failed", "Wayland security context failed", sam_core::i18n::trf("{error}; the app uses the normal Wayland socket", &[("error", &format!("{e:#}"))])));
                }
            }
        }
    }
    // A protection the settings ask for and this start could not set up
    // stops the start, unless the person chose "Start anyway" for this one
    // start (B2 R75, R77; owner, 2026-11-25). Before anything is taken over
    // or started for it: the shared home's planted files, the bus filter,
    // the sound relay (review of the fix).
    let helper_missing = wanted.helper && helper_found.is_none();
    protection_check(
        &MissingAtStart {
            landlock: helper_missing && want_landlock,
            seccomp: helper_missing && want_seccomp,
            wayland: wayland_error.as_deref(),
        },
        opts,
    )?;
    {
        sam_sandbox::write_identity_files(&ctx)?;
        // Launches that can write start places take turns here: each takes
        // over what the running ones saw at their start and keeps its own
        // record on disk (`home_shared`, review 2026-11-23 F1 and F2). This
        // wait for the records of the running apps has no time limit yet.
        let shared = if sam_sandbox::writes_start_places(&ctx) {
            // What is moved aside comes from the person's home: for them
            // only (review F4).
            let _ =
                sam_core::util::private_dirs(&paths.data_dir, &paths.data_dir.join(MOVED_ASIDE));
            Some(crate::home_shared::Shared::open(paths)?)
        } else {
            None
        };
        let others = shared
            .as_ref()
            .map(crate::home_shared::Shared::running)
            .unwrap_or_default();
        // Not where a running launch saw nothing: its watch would move it
        // aside at once (review B2 R52).
        sam_sandbox::prepare_home_protection_alongside(&ctx, &others);
        // After the folders above are made, so they do not count as new.
        home_watch = sam_sandbox::HomeWatch::before_alongside(&ctx, &others);
        if let (Some(s), Some(w)) = (&shared, &home_watch) {
            let name = format!(
                "{}-{}",
                runtime_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                app.id
            );
            let record = s.register(&name, w, &home_aside)?;
            // What a running app planted in a place this launch takes over
            // as empty, or in place of a link, goes before this one starts
            // (in this launch's turn).
            moved_at_start = record.first_look();
            home_record = Some(record);
        }
        drop(shared);
        if perms.dbus.session.mode == DbusMode::Filtered
            && host.tools.xdg_dbus_proxy.is_some()
            && host.sockets.dbus_session.is_some()
        {
            let mut bus = perms.effective_session_bus();
            // Every name the app may own, checked again at every start: a
            // name an app installed since then, another SAM app or a
            // desktop service has is left out (audit D-M6, L-F13).
            let check = crate::own_names::NameCheck::for_app(app, host, paths);
            let tray = bus.tray_own_names();
            bus.own.retain(|name| {
                if tray.contains(name) {
                    return true;
                }
                match check.refused(name) {
                    None => true,
                    Some(why) => {
                        warnings.push(Warning::warn(
                            "dbus-own-refused",
                            "D-Bus name not allowed",
                            sam_core::i18n::trf(
                                "The app may not own {name}: {why}.",
                                &[("name", name), ("why", &why)],
                            ),
                        ));
                        false
                    }
                }
            });
            match DbusProxy::start(host, &bus, &runtime_dir, &app.id, &|n| {
                check.refused(n).is_none()
            }) {
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
        if perms.audio.enabled {
            match crate::sound_relay::SoundRelay::start(host, &runtime_dir) {
                Ok(r) => {
                    ctx.sound_socket = Some(r.socket.clone());
                    sound = Some(r);
                }
                Err(e) => warnings.push(sound_without_relay(&perms.audio, host, &format!("{e:#}"))),
            }
        }
        // Landlock and seccomp are applied by SAM's helper inside the sandbox
        // (found above, before the protection check).
        wanted_landlock = want_landlock;
        wanted_seccomp = want_seccomp;
        if wanted.helper {
            match helper_found {
                Some(helper) => {
                    let spec = kernel::SandboxSpec {
                        landlock: want_landlock.then(|| {
                            kernel::landlock_spec(
                                perms,
                                host,
                                &format!("/run/user/{}", host.uid),
                                &launch_writable_paths(&ctx),
                            )
                        }),
                        seccomp: want_seccomp.then(|| seccomp_spec(app)),
                        probe: opts.probe.clone(),
                        env: Vec::new(),
                    };
                    helper_spec = Some(spec);
                    ctx.helper = Some(sam_core::sandbox::SandboxHelper {
                        binary: helper,
                        spec: runtime_dir.join("sandbox.json"),
                    });
                    landlock = want_landlock;
                    seccomp = want_seccomp;
                }
                None => warnings.extend(helper_missing_warnings(wanted.layers, wanted.rooms)),
            }
        }
    }

    // Room service: its socket exists before the sandbox is built (the
    // sandbox shows it), its rules come from the sandbox once built. It
    // needs SAM's helper in the app's sandbox (the stand-in for bwrap).
    let mut rooms = None;
    if let (true, true, Some(bwrap)) = (
        helper_wanted(
            false,
            false,
            perms.advanced.room_service,
            opts.probe.is_some(),
        )
        .rooms,
        ctx.helper.is_some(),
        host.tools.bwrap.as_ref().map(|t| t.path.clone()),
    ) {
        if !crate::room_service::bwrap_builds_rooms(&bwrap) {
            // No room could be built: programs keep the computer's own
            // Bubblewrap, as before Room service.
            warnings.push(Warning::warn(
                "room-service-failed",
                "Room service unavailable",
                "This Bubblewrap cannot show places by handle (--ro-bind-fd, Bubblewrap 0.10 or newer); programs in this app that build a sandbox of their own use it as before Room service.",
            ));
        } else {
            match crate::room_service::RoomService::open(&runtime_dir)
            .and_then(|r| write_room_standin(&runtime_dir, &bwrap).map(|()| r))
        {
            Ok(r) => {
                ctx.room_socket = Some(r.socket.clone());
                rooms = Some((r, bwrap));
            }
            Err(e) => warnings.push(Warning::warn(
                "room-service-failed",
                "Room service unavailable",
                sam_core::i18n::trf(
                    "{error}; programs in this app that build a sandbox of their own fail this time",
                    &[("error", &format!("{e:#}"))],
                ),
            )),
        }
        }
    }
    let mut command = sam_sandbox::Bubblewrap.build(&ctx)?;
    if let (Some(mut spec), Some(helper)) = (helper_spec, &ctx.helper) {
        spec.env = command.exec_env.clone();
        fs::write(&helper.spec, serde_json::to_vec_pretty(&spec)?)?;
    }
    let rooms = rooms.map(|(mut service, bwrap)| {
        let watched: Vec<PathBuf> = command
            .watched_devices
            .iter()
            .map(|d| d.path.clone())
            .collect();
        let plan = crate::room_rules::FloorPlan::from_bwrap_args(&command.args)
            .map(|p| p.without_devices(&watched));
        let room_ctx = crate::room_service::RoomContext {
            plan: plan.clone().unwrap_or_default(),
            facts: crate::room_rules::AppFacts {
                full_network: perms.network.mode == sam_core::permissions::NetworkMode::Full,
            },
            bwrap,
            landlock: kernel::landlock_spec(
                perms,
                host,
                &format!("/run/user/{}", host.uid),
                &launch_writable_paths(&ctx),
            ),
            seccomp: kernel::SeccompSpec {
                strict: perms.advanced.seccomp_strict,
                allow_userns: false,
                bluetooth: perms.devices.bluetooth,
                // A room's program gets no 32-bit branch: a 32-bit call
                // there ends it, never passes unfiltered.
                i386: false,
            },
        };
        match plan {
            Ok(_) => {
                service.serve(room_ctx);
                // A place of the app could not be opened: no room this start.
                if let Some(e) = service.refusing() {
                    warnings.push(Warning::warn(
                        "room-service-failed",
                        "Room service unavailable",
                        sam_core::i18n::trf(
                            "{error}; programs in this app that build a sandbox of their own fail this time",
                            &[("error", &e)],
                        ),
                    ));
                }
            }
            Err(e) => {
                warnings.push(Warning::warn(
                    "room-service-failed",
                    "Room service unavailable",
                    sam_core::i18n::trf(
                        "{error}; programs in this app that build a sandbox of their own fail this time",
                        &[("error", &e)],
                    ),
                ));
                // The sandbox shows the socket: it stays, and refuses.
                service.serve_refusing(room_ctx, e);
            }
        }
        service
    });
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
        allow_userns: perms.advanced.allow_userns,
        wanted_landlock,
        wanted_seccomp,
        wanted_fence: wanted_landlock
            && perms.network.mode == sam_core::permissions::NetworkMode::Full
            && host.landlock_abi.is_some_and(|v| v >= 6),
        terminal,
        proxy,
        sound,
        wayland_context,
        wayland_context_failed,
        home_watch,
        home_record,
        home_aside,
        moved_at_start,
        wayland,
        rooms,
        _runtime: runtime_guard,
    })
}

/// Room service's stand-in for Bubblewrap, first on the app's PATH: a link
/// named `bwrap` to SAM's helper (its place inside the sandbox), which
/// serves as the stand-in when started under that name, and beside it the
/// computer's Bubblewrap version line, which the stand-in answers to
/// `--version`. No script: a shell in between could leave its script's
/// file open in the helper, and the room would get it (see
/// room_service::STANDIN_TARGET). In `bin` (with the link openers) and in
/// `bin-rooms` (for apps without the session bus, which get no link
/// openers).
fn write_room_standin(runtime_dir: &Path, bwrap: &Path) -> Result<()> {
    use crate::room_service::{plain_version, STANDIN_NAME, STANDIN_TARGET, STANDIN_VERSION_FILE};
    let version = Command::new(bwrap)
        .arg("--version")
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    // Only plain characters go into the file.
    let version = plain_version(&version);
    for dir in ["bin", "bin-rooms"] {
        let d = runtime_dir.join(dir);
        fs::create_dir_all(&d)?;
        // Every start has a new, empty runtime folder (see prepare), so
        // no stand-in is in the way. The link leads nowhere outside the
        // sandbox; inside, it leads to SAM's helper.
        std::os::unix::fs::symlink(STANDIN_TARGET, d.join(STANDIN_NAME))?;
        // The app reads it as the same user, whatever the umask.
        fs::write(d.join(STANDIN_VERSION_FILE), &version)?;
    }
    Ok(())
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
    // What this start has told about missing layers: the restart below
    // tells it again only when it lacks something more, so a start from
    // the menu shows its notification once.
    let told = Arc::new(Mutex::new(Vec::new()));
    let rec = run_once(app, opts, cfg, paths, host, &told)?;
    // Refused a name it may now own and did not run: one restart, at once,
    // so the person does not have to start it again (option D). After the
    // first start has ended and given back its folder and lock.
    if !rec.success && !rec.learned_names.is_empty() && !opts.name_retry {
        if !opts.quiet {
            errln!(
                "sam-jail: {}",
                sam_core::i18n::trf(
                    "the app needed its own bus name {names}; SAM allowed it and starts the app again",
                    &[("names", &rec.learned_names.join(", "))]
                )
            );
        }
        let again = LaunchOptions {
            name_retry: true,
            ..opts.clone()
        };
        return run_once(app, &again, cfg, paths, host, &told);
    }
    Ok(rec)
}

/// One start of the app: prepare, run, judge, record. `told` holds the
/// missing layers already told for this start (by an earlier try).
fn run_once(
    app: &mut AppEntry,
    opts: &LaunchOptions,
    cfg: &Config,
    paths: &Paths,
    host: &HostInfo,
    told: &Arc<Mutex<Vec<String>>>,
) -> Result<LaunchRecord> {
    let logs = Logs::new(paths);
    let (log_path, mut log) = logs.create(
        &app.id,
        if opts.tracer.is_some() {
            LogKind::Diagnose
        } else {
            LogKind::Launch
        },
    )?;
    let started_at = now();
    writeln!(
        log,
        "# SAM launch log\n# app: {} ({})\n# started: {}",
        app.display_name(),
        app.id,
        format_ts(started_at)
    )?;

    let mut prepared = match prepare(app, opts, cfg, paths, host) {
        Ok(p) => p,
        Err(e) => {
            writeln!(log, "# preparation failed: {e:#}")?;
            // A start stopped for a missing protection did not fail: the
            // person decides (B2 R75, R77). Recorded as a failed start, it
            // would make the repair steps offer to turn protections off.
            if sam_core::error::code_of(&e) == Some(PROTECTION_MISSING) {
                return Err(e);
            }
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
            // Onto the record as it is on disk, which also keeps any mark
            // that stopped this start.
            Registry::new(paths).update(&app.id, |fresh| {
                fresh.last_launch = Some(rec.clone());
                fresh.last_error = Some(rec.summary.clone());
            })?;
            return Err(e);
        }
    };
    write_log_header(&mut log, &prepared)?;
    for w in &prepared.warnings {
        // A terminal program's start shows its own line (`terminal_banner`).
        if !opts.quiet && w.severity != sam_core::Severity::Info && w.code != "terminal-program" {
            errln!("sam-jail: warning: {}", w.message);
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
        TerminalMode::None => {
            // At logout the launcher, started from the menu, gets SIGTERM
            // (audit L-F9).
            pty::end_cleanly_on_signal();
            None
        }
        TerminalMode::Relay => {
            pty::end_cleanly_on_signal();
            Some(Pty::open(Some(pty::Outer::STDIO))?)
        }
        TerminalMode::Headless => Some(Pty::open(None)?),
    };
    if let Some(p) = &pty {
        cmd.stdin(p.stdio()?).stdout(p.stdio()?).stderr(p.stdio()?);
        // SAFETY: only async-signal-safe calls (setsid, ioctl).
        unsafe { cmd.pre_exec(Pty::become_controlling_terminal) };
        if mode == TerminalMode::Relay && app.metadata.terminal && !opts.quiet {
            errln!("{}", terminal_banner(app, &prepared.context));
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
    cmd.current_dir(&host.home);
    // Held until this launch is over: `Sam::running` sees the app as running.
    let _running = hold_lock(&prepared.context.runtime_dir.join("running.lock"))?;
    // What the app leaves in places that make the computer run something is
    // moved aside while it runs (Linux reports each change), and once more
    // after it ends.
    let aside = prepared.home_aside.clone();
    if let Some(r) = prepared.home_record.as_mut() {
        r.arm(&log_path);
    }
    let (live_watch, watch_warning) = match prepared.home_watch.as_ref() {
        Some(w) => crate::home_live::LiveWatch::start(
            w,
            aside.clone(),
            crate::home_shared::Turns::of(paths),
        ),
        None => (None, None),
    };
    if let Some(warn) = &watch_warning {
        let _ = writeln!(log, "# warning: {warn}");
        if !opts.quiet {
            errln!(
                "sam-jail: {}",
                sam_core::i18n::trf("warning: {text}", &[("text", warn)])
            );
        }
    }
    let spawned = cmd
        .spawn()
        .with_context(|| format!("starting {}", prepared.command.program.display()));
    // Close our copies of the write ends so the readers see EOF.
    for fd in channels.close_after_spawn.iter() {
        // SAFETY: the descriptor belongs to this launch and is closed exactly once here.
        unsafe { libc::close(*fd) };
    }
    let mut child = spawned?;
    let _ = fs::write(
        prepared.context.runtime_dir.join(SANDBOX_PID),
        child.id().to_string(),
    );
    // `cmd` holds copies of the app's terminal: without them, the relay
    // sees when the app's side is closed.
    drop(cmd);
    let child_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Bubblewrap's first status line names the sandbox, which the watch of
    // the game controllers needs to take one out (`device_watch`).
    let (status_line, sandbox_status) = std::sync::mpsc::channel();
    let bwrap_status_reader = channels
        .bwrap_status
        .map(|r| read_fd_in_thread(r, child_done.clone(), Some(status_line)));
    // Taking an unplugged controller out is enough only where Landlock
    // refuses every new open of it (also through a handle the app holds)
    // and the app makes no namespaces of its own (which would keep copies
    // of it); elsewhere SAM ends the app when one is unplugged.
    let helper_report: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let unplugged = if !prepared.landlock {
        crate::device_watch::Unplugged::EndApp(sam_core::i18n::tr(
            "Landlock is not in place, so a handle the app holds could still reach the next device",
        ))
    } else if prepared.allow_userns {
        crate::device_watch::Unplugged::EndApp(sam_core::i18n::tr(
            "the app may make namespaces of its own, which SAM cannot reach",
        ))
    } else {
        crate::device_watch::Unplugged::TakeOut {
            helper_report: helper_report.clone(),
        }
    };
    let device_watch = crate::device_watch::DeviceWatch::start(
        prepared.command.watched_devices.clone(),
        sandbox_status,
        unplugged,
        crate::device_watch::end_launched(child.id()),
    );
    // What the start lacks is told as soon as it is known: at once without
    // a report from SAM's helper, else when the helper has reported (right
    // before the app starts). A helper that never reported has not started
    // the app, which the start's failure says.
    let tell = opts
        .on_missing_layers
        .map(|f| (f, app.id.clone(), app.display_name().to_string()));
    let asked = (
        prepared.wanted_landlock,
        prepared.wanted_seccomp,
        prepared.wanted_fence,
        prepared.wayland_context_failed,
    );
    let told = told.clone();
    let tell_missing = move |report: Option<&str>| {
        if let Some((f, id, name)) = &tell {
            let missing = layers_missing(report, asked.0, asked.1, asked.2, asked.3);
            let mut told = told.lock().unwrap_or_else(|e| e.into_inner());
            if missing.iter().any(|m| !told.contains(m)) {
                f(id, name, &missing);
                told.extend(missing);
            }
        }
    };
    let helper_status_reader = match channels.helper_status {
        Some(r) => {
            let reader = read_fd_in_thread(r, child_done.clone(), None);
            Some(std::thread::spawn(move || {
                let report = reader.join().unwrap_or_default();
                if let Ok(mut r) = helper_report.lock() {
                    *r = Some(report.trim().to_string());
                }
                if !report.trim().is_empty() {
                    tell_missing(Some(report.trim()));
                }
                report
            }))
        }
        None => {
            tell_missing(None);
            None
        }
    };

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
                opts.app_output_to_stderr,
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
                true,
            ));
            None
        }
    };
    let (status, timed_out) = wait_until(
        &mut child,
        opts.timeout_secs,
        &prepared.context.runtime_dir,
        mode,
    )?;
    // An end request (SIGTERM, SIGHUP, or `Sam::stop` in this program) was
    // for this launch, which has ended now.
    pty::end_request_done();
    child_done.store(true, std::sync::atomic::Ordering::SeqCst);
    let devices = device_watch.map(|w| w.finish()).unwrap_or_default();
    // Every room ends with the app's start, before SAM waits for the app's
    // output: a room holds the program's output, and one left running must
    // not hold up the end of the start. What was built or refused goes into
    // the start record (never a room's environment).
    let room_lines = prepared.rooms.take().map(|r| r.stop()).unwrap_or_default();
    for t in pumps {
        let _ = t.join();
    }
    let relay_end = relay.map(pty::Relay::finish);
    let wanted = prepared
        .proxy
        .as_ref()
        .map(DbusProxy::wanted_names)
        .unwrap_or_default();
    drop(prepared.proxy);
    drop(prepared.sound);
    drop(prepared.wayland);
    if let Ok(mut l) = log.lock() {
        for line in room_lines.iter().chain(&devices.lines) {
            let _ = writeln!(l, "{line}");
        }
    }

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
    if devices.ended_app {
        // Not the app's doing: SAM ended it to keep its promise.
        outcome.success = false;
        outcome.summary = sam_core::i18n::tr(
            "ended by SAM: a game controller was unplugged and SAM could not safely take it out of the sandbox",
        );
    } else if relay_end.as_ref().is_some_and(|r| r.hung_up)
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
    // What the app left in places that make the computer run something:
    // moved aside before anything can act on it. The live watch caught what
    // appeared while it ran; one last look now catches the rest.
    let mut found = std::mem::take(&mut prepared.moved_at_start);
    found.extend(live_watch.map(|l| l.finish()).unwrap_or_default());
    // In this launch's turn. A launch has a home watch exactly when it has
    // a record (both come with `writes_start_places`), so the record's look
    // is the look of every watched launch.
    if let Some(r) = prepared.home_record.take() {
        found.extend(r.last_look());
    }
    let moved: Vec<String> = found.iter().map(describe_moved).collect();
    // Best effort: a full disk (which the app may have caused on purpose)
    // must not stop the record below, with what the start was missing and
    // what was moved aside, from being saved (regression, audit L-F5).
    if let Ok(mut l) = log.lock() {
        for m in &moved {
            writeln!(l, "# moved aside (it would act outside the sandbox): {m}").ok();
        }
        if mode != TerminalMode::None {
            let what = if mode == TerminalMode::Relay {
                "connected to the user's terminal"
            } else {
                "80x24, no input (test start)"
            };
            writeln!(l, "\n# terminal: a terminal of its own, {what}").ok();
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
            )
            .ok();
        }
        if let Some(e) = &enforcement {
            writeln!(l, "# enforced: {e}").ok();
        } else if prepared.landlock || prepared.seccomp {
            writeln!(l, "# enforced: unknown (no status from SAM's helper)").ok();
        }
        writeln!(
            l,
            "# ---- end ----\n# finished: {}\n# result: {}",
            format_ts(now()),
            outcome.summary
        )
        .ok();
    }

    let (learned_names, refused_names) = learn_names(app, &wanted, host, paths);
    if let Ok(mut l) = log.lock() {
        for n in &learned_names {
            writeln!(
                l,
                "# learned bus name: {n} (nobody on this computer uses it)"
            )
            .ok();
        }
        for n in &refused_names {
            writeln!(l, "# bus name not allowed: {n}").ok();
        }
    }
    let rec = LaunchRecord {
        learned_names,
        refused_names,
        undone_repairs: vec![],
        started_at,
        finished_at: now(),
        exit_code: status.code(),
        signal: status.signal(),
        success: outcome.success,
        sandbox_failure: outcome.sandbox_failure,
        setup_failed: outcome.setup_failed,
        missing_layers: layers_missing(
            enforcement.as_deref(),
            prepared.wanted_landlock,
            prepared.wanted_seccomp,
            prepared.wanted_fence,
            prepared.wayland_context_failed,
        ),
        moved_aside: moved,
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
            // Suggested only where it can work (see overlay_works_in), and
            // not a step already tried that did not help.
            f.retain(|s| {
                (s.id != "writable-appdir"
                    || sam_core::host::overlay_works_in(&paths.overlays_dir()))
                    && !app.tried_repairs.contains(&s.id)
            });
            f
        },
        summary: outcome.summary,
    };
    if !rec.missing_layers.is_empty() && !opts.quiet {
        errln!(
            "sam-jail: {}",
            sam_core::i18n::trf(
                "warning: this start ran without {layers}, which its settings ask for",
                &[("layers", &rec.missing_layers.join(", "))]
            )
        );
    }
    if !rec.moved_aside.is_empty() && !opts.quiet {
        errln!(
            "sam-jail: {}",
            sam_core::i18n::trf(
                "the app left something that would run outside its sandbox; SAM moved it aside: {items}",
                &[("items", &rec.moved_aside.join("; "))]
            )
        );
    }
    // Repair steps on trial: this start decides. Not a diagnostic run, and
    // not a start that failed for a bus name SAM just allowed (its restart
    // decides).
    let judge = judges_trials(opts, &rec);
    let mut rec = rec;
    rec.undone_repairs = save_launch(app, &rec, paths, judge)?;
    if !rec.undone_repairs.is_empty() && !opts.quiet {
        errln!(
            "sam-jail: {}",
            sam_core::i18n::trf(
                "the repair step did not help, so SAM undid it: {steps}",
                &[("steps", &rec.undone_repairs.join(", "))]
            )
        );
    }
    let _ = logs.prune(&app.id, LogKind::Launch, cfg.diagnostics.keep_logs);
    Ok(rec)
}

/// The bus names the app asked for (from the D-Bus filter's record) that
/// it may own from now on, and those it may not ("name: why"). A name it
/// may own already is not asked about again.
fn learn_names(
    app: &AppEntry,
    wanted: &[String],
    host: &HostInfo,
    paths: &Paths,
) -> (Vec<String>, Vec<String>) {
    let own = &app.profile.permissions.dbus.session.own;
    let wanted: Vec<&String> = wanted.iter().filter(|n| !own.contains(n)).collect();
    if wanted.is_empty() {
        return (vec![], vec![]);
    }
    let check = crate::own_names::NameCheck::for_app(app, host, paths);
    let deny = &app.profile.permissions.dbus.session.deny;
    let (mut learned, mut refused) = (Vec::new(), Vec::new());
    for name in wanted {
        // A name the person blocked is never learned: it would stay blocked
        // anyway, and the app would only be started again for nothing.
        if sam_core::permissions::bus_name_denied(deny, name) {
            let why = sam_core::i18n::tr("you blocked it (always blocked names)");
            refused.push(format!("{name}: {why}"));
            continue;
        }
        match check.not_learned(name) {
            None => learned.push(name.clone()),
            Some(why) => refused.push(format!("{name}: {why}")),
        }
    }
    (learned, refused)
}

/// The line a terminal program's start shows first: what it can reach.
fn terminal_banner(app: &AppEntry, ctx: &LaunchContext) -> String {
    let fs = &ctx.permissions.filesystem;
    let mut sees: Vec<String> = Vec::new();
    if fs.home {
        sees.push(sam_core::i18n::tr("your home folder"));
    }
    // The user folders the sandbox shows, as it decides them: never one it
    // refuses, such as one set inside SAM's own folders (independent
    // re-review of decision 9). With the whole home, the home names those
    // inside it; one outside it is shown too and named.
    for d in sam_sandbox::shown_user_folders(ctx) {
        if !fs.home || !d.starts_with(&ctx.host.home) {
            sees.push(sam_core::util::tildify(&d));
        }
    }
    // Only what the sandbox shows: never a grant inside SAM's own folders
    // (independent review of decision 9).
    sees.extend(sam_sandbox::shown_extra_folders(ctx));
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
    let mut line = sam_core::i18n::trf(
        "{app} runs sandboxed, in a terminal of its own. It sees {sees} (files it saves anywhere else stay there). It cannot type into this shell or use the clipboard through the terminal.",
        &[("app", &app.display_name()), ("sees", &sees)],
    );
    // A file named here that the app does not get ("No access"): said
    // plainly, so the app's "file not found" does not look like a fault.
    let withheld: Vec<String> = sam_sandbox::withheld_opened_paths(ctx)
        .iter()
        .map(|p| sam_core::util::tildify(p))
        .collect();
    if !withheld.is_empty() {
        line.push(' ');
        line.push_str(&sam_core::i18n::trf(
            "SAM did not share {files} with it, because files you open with this app are set to No access.",
            &[("files", &withheld.join(", "))],
        ));
    }
    format!("\x1b[2msam-jail: {line}\x1b[0m")
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
    if let Some(r) = &prepared.sound {
        writeln!(
            log,
            "# sound: through SAM's relay ({}), which cannot load modules",
            r.socket.display()
        )?;
    }
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
    if !prepared.command.exec_env.is_empty() {
        let shown: Vec<String> = prepared
            .command
            .exec_env
            .iter()
            .map(|(k, v)| {
                let v = if given.contains(&k.as_str()) {
                    "<hidden>"
                } else {
                    v.as_str()
                };
                shell_join([format!("{k}={v}")])
            })
            .collect();
        writeln!(
            log,
            "# {}",
            sam_core::i18n::trf(
                "set by SAM's helper for the app, after its layers: {variables}",
                &[("variables", &shown.join(" "))]
            )
        )?;
    }
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
/// A partly enforced Landlock (an older kernel) counts as applied. `fence`:
/// the start relies on Landlock's abstract-socket fence (see
/// [`Prepared::wanted_fence`]), which then must be reported in place on
/// its own (review K-1: "partially enforced" hid that it was not).
pub fn missing_layers(
    enforcement: Option<&str>,
    landlock: bool,
    seccomp: bool,
    fence: bool,
) -> Vec<String> {
    let report = enforcement.unwrap_or("");
    let mut missing = Vec::new();
    if landlock
        && !(report.contains("landlock: fully enforced")
            || report.contains("landlock: partially enforced"))
    {
        missing.push("Landlock".to_string());
    } else if landlock && fence && !report.contains(crate::kernel::ABSTRACT_SCOPED) {
        missing.push("Landlock socket fence".to_string());
    }
    if seccomp && !report.contains("seccomp: ") {
        missing.push("seccomp".to_string());
    }
    missing
}

/// [`missing_layers`], and the Wayland security context when making one
/// failed although the compositor offers them (a compositor without them is
/// not a missing layer: there is nothing SAM could have applied).
pub fn layers_missing(
    enforcement: Option<&str>,
    landlock: bool,
    seccomp: bool,
    fence: bool,
    wayland_failed: bool,
) -> Vec<String> {
    let mut m = missing_layers(enforcement, landlock, seccomp, fence);
    if wayland_failed {
        m.push("Wayland security context".to_string());
    }
    m
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
        // After --clearenv: right before bwrap's own "--" separator, found
        // the way Bubblewrap reads its options, so an option's value that
        // reads "--" is never taken for it (review F5).
        let sep = crate::room_rules::options_end(&args)
            .or_else(|| args.iter().position(|a| a == "--"))
            .unwrap_or(args.len());
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
///
/// SAM's own output gets the app's bytes unchanged and at once, as they
/// arrive: data in a pipe (`sam-jail run jq . < f > g`) stays exact, and a
/// prompt without a line end ("Password: ") shows. Only the log is kept
/// line by line (a line longer than `LINE_LIMIT` is split there).
fn pump_output(
    mut src: Box<dyn Read + Send>,
    is_err: bool,
    log: Arc<Mutex<fs::File>>,
    head: Arc<Mutex<String>>,
    quiet: bool,
    on_stderr: bool,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // Shown in a terminal, the app's output goes through the same filter
        // as on SAM's terminal relay: with its input redirected (a script,
        // `< file`) the app has no relay, but could still reach the terminal
        // with escape codes (clipboard, title reports).
        // Without the relay, the terminal's answers to requests would land
        // in the shell: the filter removes requests too.
        let mut filter = (!quiet && pty::is_tty(if on_stderr { 2 } else { 1 }))
            .then(pty::OutputFilter::for_pipe);
        let keep = |line: &[u8]| {
            // Only the text goes into the log (audit L-F3).
            let text = sam_core::terminal::plain_text(line);
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
        };
        let mut buf = vec![0u8; 16 * 1024];
        let mut line: Vec<u8> = Vec::new();
        loop {
            let n = match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let chunk = &buf[..n];
            if !quiet {
                let shown = for_terminal(filter.as_mut(), chunk);
                if on_stderr {
                    let mut o = std::io::stderr().lock();
                    let _ = o.write_all(&shown).and_then(|()| o.flush());
                } else {
                    let mut o = std::io::stdout().lock();
                    let _ = o.write_all(&shown).and_then(|()| o.flush());
                }
            }
            line.extend_from_slice(chunk);
            let mut from = 0;
            while let Some(i) = line[from..].iter().position(|b| *b == b'\n') {
                keep(&line[from..from + i]);
                from += i + 1;
            }
            line.drain(..from);
            while line.len() >= LINE_LIMIT as usize {
                let rest = line.split_off(LINE_LIMIT as usize);
                keep(&line);
                line = rest;
            }
        }
        if !line.is_empty() {
            keep(&line);
        }
        // An unfinished last sequence is dropped; modes the app left on are
        // switched off again.
        if let Some(f) = filter.as_mut() {
            let tail = f.finish();
            if on_stderr {
                let _ = std::io::stderr().lock().write_all(&tail);
            } else {
                let _ = std::io::stdout().lock().write_all(&tail);
            }
        }
    })
}

/// What SAM shows of a piece of the app's output: filtered for a
/// terminal, otherwise unchanged.
fn for_terminal(filter: Option<&mut pty::OutputFilter>, piece: &[u8]) -> Vec<u8> {
    match filter {
        Some(f) => f.filter(piece),
        None => piece.to_vec(),
    }
}

/// One line for something moved out of a start place: where it went, or
/// that it could not be removed.
pub(crate) fn describe_moved(m: &sam_sandbox::MovedAside) -> String {
    let to = sam_core::util::tildify(&m.to);
    match m.how {
        sam_sandbox::Aside::Moved => format!("~/{} → {to}", m.place),
        sam_sandbox::Aside::Renamed => sam_core::i18n::trf(
            "~/{place} → {to} (renamed in place: SAM's folder could not take it)",
            &[("place", &m.place), ("to", &to)],
        ),
        sam_sandbox::Aside::Deleted => sam_core::i18n::trf(
            "~/{place}: deleted (it could not be moved)",
            &[("place", &m.place)],
        ),
        sam_sandbox::Aside::Failed => sam_core::i18n::trf(
            "~/{place}: COULD NOT BE REMOVED; it may run outside the sandbox: remove it yourself",
            &[("place", &m.place)],
        ),
    }
}

/// How long an app asked to quit (SIGTERM) may take before its sandbox is
/// ended.
pub const QUIT_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Waits for the sandbox to end. After `timeout_secs` it is ended and
/// reported as timed out. Without SAM's terminal relay (`mode` None),
/// SIGTERM or SIGHUP to SAM asks the app to quit, marks the launch as
/// closed and ends the sandbox after [`QUIT_GRACE`]. With the relay, the
/// relay hangs up the app's terminal instead.
///
/// When `Sam::stop` had asked the app already (its [`STOP_MARKER`]), the
/// grace time runs from then, not again from now: `stop` signals the
/// launcher only once that time is over, and before, the launcher began a
/// new 10 seconds that `stop` cut short with SIGKILL 3 seconds later. The
/// last look at the start places, the record and the end of the log never
/// came (review 2026-11-23 F2).
fn wait_until(
    child: &mut std::process::Child,
    timeout_secs: Option<u64>,
    runtime_dir: &Path,
    mode: TerminalMode,
) -> Result<(std::process::ExitStatus, bool)> {
    let start = std::time::Instant::now();
    let deadline = timeout_secs.map(|s| start + std::time::Duration::from_secs(s));
    let mut asked: Option<std::time::Instant> = None;
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok((st, false));
        }
        if asked.is_none() && mode != TerminalMode::Headless && pty::end_requested() {
            let marker = runtime_dir.join(STOP_MARKER);
            // When `Sam::stop` asked the app to quit.
            let stop_asked = fs::metadata(&marker)
                .and_then(|m| m.modified())
                .ok()
                .map(|t| t.elapsed().unwrap_or_default())
                .and_then(|age| std::time::Instant::now().checked_sub(age));
            if mode == TerminalMode::None {
                if stop_asked.is_none() {
                    let _ = fs::write(&marker, b"");
                }
                // Asked (again) only while the app still has time to save.
                if stop_asked.is_none_or(|t| t.elapsed() < QUIT_GRACE) {
                    crate::ops::ask_to_quit(std::process::id(), child.id());
                }
                asked = Some(stop_asked.unwrap_or_else(std::time::Instant::now));
            } else {
                asked = stop_asked;
            }
        }
        if asked.is_some_and(|t| t.elapsed() > QUIT_GRACE) {
            let _ = child.kill();
            return Ok((child.wait()?, false));
        }
        if deadline.is_some_and(|d| std::time::Instant::now() > d) {
            let _ = child.kill();
            return Ok((child.wait()?, true));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
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
/// Whether a start decides the repair steps on trial: not a diagnostic run
/// (traced, or the sandbox check), and not a start that failed for a bus
/// name SAM just allowed (its restart decides).
fn judges_trials(opts: &LaunchOptions, rec: &LaunchRecord) -> bool {
    opts.tracer.is_none() && opts.probe.is_none() && rec.learned_names.is_empty()
}

/// Saves the start onto the record as it is on disk and, with `judge`,
/// decides the repair steps on trial there (kept when the start worked,
/// undone when it failed). Returns the titles of the undone steps.
fn save_launch(
    app: &mut AppEntry,
    rec: &LaunchRecord,
    paths: &Paths,
    judge: bool,
) -> Result<Vec<String>> {
    app.last_launched = Some(rec.started_at);
    app.last_launch = Some(rec.clone());
    if rec.sandbox_failure {
        app.last_error = Some(rec.summary.clone());
    } else if app.state == AppState::Broken && app.extraction.is_some() {
        app.state = AppState::Ready;
        app.last_error = None;
    }
    for n in &rec.learned_names {
        if !app.profile.permissions.dbus.session.own.contains(n) {
            app.profile.permissions.dbus.session.own.push(n.clone());
        }
    }
    let mut undone = Vec::new();
    let fresh = Registry::new(paths).update(&app.id, |fresh| {
        fresh.last_launched = app.last_launched;
        fresh.last_error = app.last_error.clone();
        fresh.state = app.state;
        for n in &rec.learned_names {
            let own = &mut fresh.profile.permissions.dbus.session.own;
            if !own.contains(n) {
                own.push(n.clone());
            }
        }
        if judge {
            undone = crate::repair::judge_trials(fresh, rec.success);
        }
        let mut last = rec.clone();
        last.undone_repairs = undone.clone();
        fresh.last_launch = Some(last);
    })?;
    // The copy in hand follows what was saved.
    if let Some(f) = fresh {
        app.profile = f.profile;
        app.applied_repairs = f.applied_repairs;
        app.repairs_applied = f.repairs_applied;
        app.tried_repairs = f.tried_repairs;
        app.repair_backup = f.repair_backup;
        app.last_launch = f.last_launch;
    }
    Ok(undone)
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

/// What the start says when SAM's sound relay cannot run (`why`): the app
/// has no sound, or, when the person allowed sound without the relay, it
/// gets the sound server's own connection, with a warning every time
/// (audit S-F1; the person's decision of 2026-11-18).
fn sound_without_relay(
    p: &sam_core::permissions::AudioPerms,
    host: &HostInfo,
    why: &str,
) -> Warning {
    if p.direct && host.sockets.pulse.is_some() {
        Warning::danger(
            "sound-without-relay",
            "Sound without SAM's relay",
            sam_core::i18n::trf(
                "SAM's sound relay could not run ({why}), and sound without it is allowed for this app: it talks to your sound server directly and could make it load code outside the sandbox.",
                &[("why", &why)],
            ),
        )
    } else {
        Warning::warn(
            "sound-off",
            "No sound",
            sam_core::i18n::trf(
                "The app has no sound: SAM's sound relay could not run ({why}). Sound straight from the sound server would let the app load code outside the sandbox; to allow that anyway, turn on \"Sound without SAM's relay\" for this app.",
                &[("why", &why)],
            ),
        )
    }
}

/// How long a launch waits for its own `running.lock`.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Creates `path` and holds an exclusive lock on it while the file is open.
/// Waits at most [`LOCK_WAIT`] for it.
fn hold_lock(path: &Path) -> Result<fs::File> {
    use std::os::fd::AsRawFd;
    let f = fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    // Each launch has its own folder, so only running-checks ([`lock_held`],
    // from every caller of `Sam::running`) take this lock, shared and for an
    // instant. A check that meets the start must not end it: the launch
    // tries again, but never waits without a limit.
    let until = std::time::Instant::now() + LOCK_WAIT;
    loop {
        // SAFETY: `f` is an open file; flock only takes its descriptor.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(f);
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                if std::time::Instant::now() < until =>
            {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            std::io::ErrorKind::WouldBlock => bail!(
                "locking {}: still taken after waiting {} seconds",
                path.display(),
                LOCK_WAIT.as_secs()
            ),
            _ => bail!("locking {}: {err}", path.display()),
        }
    }
}

/// True if another process holds the lock on `path`. Only a regular file
/// counts, never one reached through a link (review B2 S6, R85).
pub fn lock_held(path: &Path) -> bool {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(f) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    else {
        return false;
    };
    if !f.metadata().is_ok_and(|m| m.is_file()) {
        return false;
    }
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
/// Reads a status channel until the sandbox ends; `first_line` gets its
/// first line as soon as it is complete (dropped without one otherwise).
fn read_fd_in_thread(
    fd: i32,
    done: Arc<std::sync::atomic::AtomicBool>,
    mut first_line: Option<std::sync::mpsc::Sender<String>>,
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
                if let Some(end) = out.iter().position(|&b| b == b'\n') {
                    if let Some(tx) = first_line.take() {
                        let _ = tx.send(String::from_utf8_lossy(&out[..end]).into_owned());
                    }
                }
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
/// The last `max_lines` lines of a log, as text: escape codes and hidden
/// characters an app wrote are removed, also from logs written before SAM
/// kept only the text (audit L-F3).
pub fn tail(path: &Path, max_lines: usize) -> String {
    let Ok(data) = fs::read(path) else {
        return String::new();
    };
    let text = sam_core::terminal::plain_text(&data);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(max_lines)..].join("\n")
}

#[cfg(test)]
mod log_limit_tests {
    use super::*;

    /// A log written before SAM kept only the text, or edited by hand,
    /// still shows only text (audit L-F3): `sam-jail logs` and bug reports
    /// read it through `tail`.
    #[test]
    fn an_old_log_shows_only_its_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("launch.log");
        fs::write(
            &path,
            b"# SAM launch log\n[err] a\x1b]52;c;ZGF0YQ==\x07b\xe2\x80\xaec\r\nlast \xff\x1b[21t line\n",
        )
        .unwrap();
        assert_eq!(tail(&path, 10), "# SAM launch log\n[err] abc\nlast  line");
        assert_eq!(tail(&path, 1), "last  line");
    }

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
            false,
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

    /// The first status line reaches the controllers' watch as soon as it
    /// is complete, while the whole channel is still read to its end;
    /// without a line the watch hears that none comes (review R56).
    #[test]
    fn the_first_status_line_is_handed_on_at_once() {
        for (text, first) in [
            (
                "{\"child-pid\": 7}\n{\"exit-code\": 0}\n",
                Some("{\"child-pid\": 7}"),
            ),
            ("", None),
        ] {
            let (r, w) = status_pipe().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader = read_fd_in_thread(r, done.clone(), Some(tx));
            // SAFETY: writes the text to the pipe's write end, then closes it once.
            unsafe {
                libc::write(w, text.as_ptr().cast(), text.len());
                libc::close(w);
            }
            let got = rx.recv_timeout(std::time::Duration::from_secs(5)).ok();
            assert_eq!(got.as_deref(), first);
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(reader.join().unwrap(), text);
        }
    }

    /// Review K-1: a start that relies on Landlock's abstract-socket fence
    /// (it shares the host's network, the kernel has the fence) counts it
    /// as missing unless the helper reported it in place, also when
    /// Landlock itself reads "fully enforced" (a helper too old to report
    /// it). One that does not rely on it is not warned about.
    #[test]
    fn a_missing_socket_fence_is_reported_when_the_start_relies_on_it() {
        let fenced = "landlock: fully enforced; abstract sockets: scoped; seccomp: baseline loaded";
        let unfenced = "landlock: partially enforced; abstract sockets: NOT scoped (needs Linux 6.12); seccomp: baseline loaded";
        let unreported = "landlock: fully enforced; seccomp: baseline loaded";
        assert!(missing_layers(Some(fenced), true, true, true).is_empty());
        for report in [unfenced, unreported] {
            assert_eq!(
                missing_layers(Some(report), true, true, true),
                vec!["Landlock socket fence"],
                "{report}"
            );
            assert!(
                missing_layers(Some(report), true, true, false).is_empty(),
                "not relied on: {report}"
            );
        }
    }

    #[test]
    fn a_wanted_layer_that_was_not_applied_is_reported_missing() {
        let full = "landlock: fully enforced; seccomp: baseline loaded";
        assert!(missing_layers(Some(full), true, true, false).is_empty());
        assert!(missing_layers(
            Some("landlock: partially enforced; seccomp: strict loaded"),
            true,
            true,
            false
        )
        .is_empty());
        assert_eq!(
            missing_layers(
                Some("landlock: NOT applied (no kernel support); seccomp: baseline loaded"),
                true,
                true,
                true
            ),
            vec!["Landlock"]
        );
        // No report at all: the helper did not run, nothing was applied.
        assert_eq!(
            missing_layers(None, true, true, false),
            vec!["Landlock", "seccomp"]
        );
        // Layers that were not asked for are never missing.
        assert!(missing_layers(None, false, false, false).is_empty());
        // A Wayland security context that could not be made is missing too.
        assert_eq!(
            layers_missing(Some(full), true, true, false, true),
            vec!["Wayland security context"]
        );
        assert!(layers_missing(Some(full), true, true, false, false).is_empty());
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

    /// Review F5: the helper's status channel goes right before
    /// Bubblewrap's own separator, never into an option whose value reads
    /// `--` (an AppImage file called `--`, a variable set to it), and the
    /// helper's own `--` after the separator stays where it is.
    #[test]
    fn the_status_channel_goes_before_bubblewraps_own_separator() {
        let bwrap = v(&[
            "--clearenv",
            "--setenv",
            "ARGV0",
            "--",
            "--setenv",
            "TERM",
            "--",
            "--chdir",
            "/home/u",
            "--",
            "/run/sam/sam-jail-run",
            "--sandbox-exec",
            "/run/sam/sandbox.json",
            "--",
            "/opt/app/AppRun",
        ]);
        let out = with_status_options(&bwrap, 3, Some(4));
        assert_eq!(&out[..2], &v(&["--json-status-fd", "3"]));
        assert_eq!(
            &out[2..],
            &v(&[
                "--clearenv",
                "--setenv",
                "ARGV0",
                "--",
                "--setenv",
                "TERM",
                "--",
                "--chdir",
                "/home/u",
                "--setenv",
                "SAM_STATUS_FD",
                "4",
                "--",
                "/run/sam/sam-jail-run",
                "--sandbox-exec",
                "/run/sam/sandbox.json",
                "--",
                "/opt/app/AppRun",
            ])[..]
        );
        // Bubblewrap ends its options at the first word that is not one.
        assert_eq!(
            crate::room_rules::options_end(&v(&["--die-with-parent", "app", "--"])),
            Some(1)
        );
        // An option without its values is no end at all.
        assert_eq!(crate::room_rules::options_end(&v(&["--setenv", "A"])), None);
    }
}

#[cfg(test)]
mod tests {

    /// Only an ordinary start decides the repair steps on trial: not a
    /// traced or checking run, and not a start that failed for a bus name
    /// SAM just allowed.
    #[test]
    fn only_an_ordinary_start_judges_repair_steps() {
        let opts = LaunchOptions::default();
        let rec = LaunchRecord::default();
        assert!(judges_trials(&opts, &rec));
        let traced = LaunchOptions {
            tracer: Some(vec!["strace".into()]),
            ..Default::default()
        };
        assert!(!judges_trials(&traced, &rec));
        let checking = LaunchOptions {
            probe: Some(Default::default()),
            ..Default::default()
        };
        assert!(!judges_trials(&checking, &rec));
        let named = LaunchRecord {
            learned_names: vec!["org.example.App".into()],
            ..Default::default()
        };
        assert!(!judges_trials(&opts, &named));
    }

    use super::*;

    /// A running-check (`lock_held`, as the window or `sam-jail list` run
    /// it) that meets a start at that moment never ends the start: while
    /// two threads keep checking, every one of many starts gets its lock.
    #[test]
    fn a_running_check_at_the_start_never_ends_the_launch() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("running.lock");
        fs::File::create(&lock).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let counts: Vec<_> = (0..2).map(|_| Arc::new(AtomicU64::new(0))).collect();
        let checkers: Vec<_> = counts
            .iter()
            .map(|count| {
                let (lock, stop, count) = (lock.clone(), stop.clone(), count.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        lock_held(&lock);
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        let total = || {
            counts
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .sum::<u64>()
        };
        // The starts begin only once both checkers are checking.
        let ready = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while counts.iter().any(|c| c.load(Ordering::Relaxed) == 0) {
            assert!(
                std::time::Instant::now() < ready,
                "the running-checks never ran"
            );
            std::thread::yield_now();
        }
        let before = total();
        let mut failed = Vec::new();
        // At least 500 starts over at least 300 ms: many time slices, so
        // the checks run between the starts even on a single busy core.
        let (mut starts, end) = (
            0,
            std::time::Instant::now() + std::time::Duration::from_millis(300),
        );
        while starts < 500 || std::time::Instant::now() < end {
            match hold_lock(&lock) {
                Ok(f) => drop(f),
                Err(e) => failed.push(e.to_string()),
            }
            starts += 1;
        }
        let during = total() - before;
        stop.store(true, Ordering::Relaxed);
        for t in checkers {
            t.join().unwrap();
        }
        assert!(during > 0, "no running-check ran while the starts ran");
        assert!(
            failed.is_empty(),
            "{} of {starts} starts failed: {}",
            failed.len(),
            failed[0]
        );
    }

    /// A lock that stays taken longer than the wait still stops the start,
    /// with a message that names the lock, and in bounded time.
    #[test]
    fn a_lock_held_too_long_stops_the_launch_in_bounded_time() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("running.lock");
        let held = fs::File::create(&lock).unwrap();
        // SAFETY: `held` is an open file; flock only takes its descriptor.
        let taken = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        assert_eq!(taken, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let path = lock.clone();
        let started = std::time::Instant::now();
        std::thread::spawn(move || {
            let _ = tx.send(hold_lock(&path).map(drop).map_err(|e| e.to_string()));
        });
        let result = rx
            .recv_timeout(LOCK_WAIT + std::time::Duration::from_secs(10))
            .expect("the start waited for the lock without a limit");
        let waited = started.elapsed();
        let err = result.expect_err("the start took a lock another process held");
        assert!(
            err.contains(&lock.display().to_string()) && err.contains("still taken after waiting"),
            "unclear message: {err}"
        );
        assert!(
            waited >= LOCK_WAIT,
            "gave up after {waited:?}, before the wait was over"
        );
        drop(held);
    }

    /// With its input redirected an app has no terminal relay; its output
    /// shown in a terminal still loses clipboard codes and title reports,
    /// even split over two pieces. Output not shown in a terminal passes
    /// unchanged, without a line end added.
    #[test]
    fn output_shown_in_a_terminal_is_filtered_without_the_relay() {
        let mut f = crate::pty::OutputFilter::for_pipe();
        assert_eq!(
            for_terminal(Some(&mut f), b"a\x1b]52;c;aGk=\x07b\n"),
            b"ab\n"
        );
        assert_eq!(for_terminal(Some(&mut f), b"x\x1b[21t"), b"x");
        let mut f = crate::pty::OutputFilter::for_pipe();
        let first = for_terminal(Some(&mut f), b"a\x1b]52;c;");
        let second = for_terminal(Some(&mut f), b"aGk=\x07b");
        assert_eq!(
            [first, second].concat(),
            b"ab",
            "a code split over two pieces"
        );
        assert_eq!(
            for_terminal(None, b"a\x1b]52;c;x\x07b"),
            b"a\x1b]52;c;x\x07b"
        );
    }

    /// Landlock is wanted only where the app's switch wants it and the
    /// kernel has it; the app's strict filter switch works by itself,
    /// without a global setting (audit D-M13).
    #[test]
    fn the_wanted_layers_follow_the_apps_switches() {
        let mut host = sam_core::sandbox::sample_context().host;
        let mut cfg = Config::default();
        let mut p = sam_core::permissions::PermissionSet::strict_gui();
        host.landlock_abi = Some(3);
        p.advanced.landlock = Some(true);
        assert!(wanted_layers(&p, &cfg, &host).0, "switch on, kernel has it");
        p.advanced.landlock = Some(false);
        assert!(
            !wanted_layers(&p, &cfg, &host).0,
            "switched off for this app"
        );
        p.advanced.landlock = Some(true);
        host.landlock_abi = None;
        assert!(
            !wanted_layers(&p, &cfg, &host).0,
            "the kernel has no Landlock"
        );
        cfg.security.baseline_seccomp = false;
        p.advanced.seccomp_strict = false;
        assert!(!wanted_layers(&p, &cfg, &host).1, "no filter wanted");
        p.advanced.seccomp_strict = true;
        assert!(wanted_layers(&p, &cfg, &host).1, "the strict switch alone");
        p.advanced.seccomp_strict = false;
        cfg.security.baseline_seccomp = true;
        p.advanced.seccomp_baseline = true;
        assert!(wanted_layers(&p, &cfg, &host).1, "the baseline in both");
        p.advanced.seccomp_baseline = false;
        assert!(
            !wanted_layers(&p, &cfg, &host).1,
            "the baseline off for this app"
        );
    }

    /// An app whose detection report names `arch` for its start program,
    /// a script when `script` is set.
    fn analyzed(arch: &str, script: bool) -> AppEntry {
        AppEntry {
            detection: Some(sam_core::DependencyReport {
                arch: arch.into(),
                entry_is_script: script,
                entry_binary: Some("usr/bin/game".into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// A 32-bit start program gets the filter's 32-bit part (review K-3);
    /// a script among 32-bit files, or an app nobody analyzed, does not.
    #[test]
    fn a_32_bit_start_program_gets_the_filters_32_bit_part() {
        assert!(seccomp_spec(&analyzed("i686", false)).i386);
        assert!(!seccomp_spec(&analyzed("i686", true)).i386, "a script");
        assert!(
            !seccomp_spec(&analyzed("x86_64", false)).i386,
            "a 64-bit program"
        );
        assert!(!seccomp_spec(&AppEntry::default()).i386, "not analyzed");
    }

    /// The app page's and the check's socket note (review R72) appears
    /// exactly where a start loads the filter with its 32-bit part, whose
    /// socket limit has the socketcall gap: a 32-bit start program with the
    /// filter wanted, by the baseline or by the strict switch alone. Never
    /// for a script, a 64-bit program, an app nobody analyzed, or with the
    /// filter off for the app or for every app; never on a processor
    /// without the 32-bit part.
    #[test]
    fn the_socket_note_follows_the_filters_32_bit_part() {
        let host = sam_core::sandbox::sample_context().host;
        let x86 = cfg!(target_arch = "x86_64");
        let mut cfg = Config::default();
        let mut on = sam_core::permissions::PermissionSet::strict_gui();
        on.advanced.seccomp_baseline = true;
        on.advanced.seccomp_strict = false;
        cfg.security.baseline_seccomp = true;
        let game = analyzed("i686", false);
        assert_eq!(
            socket_limit_incomplete(&game, &on, &cfg, &host),
            x86,
            "a 32-bit start program with the baseline filter"
        );
        let mut strict_only = on.clone();
        strict_only.advanced.seccomp_baseline = false;
        strict_only.advanced.seccomp_strict = true;
        let mut no_baseline = cfg.clone();
        no_baseline.security.baseline_seccomp = false;
        assert_eq!(
            socket_limit_incomplete(&game, &strict_only, &no_baseline, &host),
            x86,
            "the strict switch alone loads the filter"
        );
        assert!(
            !socket_limit_incomplete(&analyzed("i686", true), &on, &cfg, &host),
            "a script among 32-bit files"
        );
        assert!(
            !socket_limit_incomplete(&analyzed("x86_64", false), &on, &cfg, &host),
            "a 64-bit program"
        );
        assert!(
            !socket_limit_incomplete(&AppEntry::default(), &on, &cfg, &host),
            "an app nobody analyzed"
        );
        let mut off = on.clone();
        off.advanced.seccomp_baseline = false;
        assert!(
            !socket_limit_incomplete(&game, &off, &cfg, &host),
            "the filter off for this app"
        );
        assert!(
            !socket_limit_incomplete(&game, &on, &no_baseline, &host),
            "the filter off for every app"
        );
        assert_eq!(
            kernel::SeccompSpec {
                i386: true,
                ..Default::default()
            }
            .filters_32_bit_calls(),
            x86
        );
        for strict in [false, true] {
            for allow_userns in [false, true] {
                for bluetooth in [false, true] {
                    let spec = kernel::SeccompSpec {
                        strict,
                        allow_userns,
                        bluetooth,
                        i386: true,
                    };
                    assert_eq!(
                        spec.socketcall_unlimited(),
                        x86,
                        "no row limits 32-bit socketcall: strict {strict}, nested {allow_userns}, bluetooth {bluetooth}"
                    );
                }
            }
        }
    }

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
            // Confirmed settings: only the missing Bubblewrap stops it.
            reviewed: true,
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

    /// A terminal app's start line names the extra folders the sandbox
    /// shows, never one inside SAM's own folders, which the sandbox leaves
    /// out wherever SAM keeps them (SAM's data in `~/Games/sam`): read-only
    /// or writable, it was listed as seen (independent review of
    /// decision 9). With the whole home, a user folder outside the home,
    /// which the sandbox shows on its own, is named too.
    #[test]
    fn a_terminal_apps_start_line_names_only_the_folders_it_sees() {
        let tmp = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(tmp.path()).unwrap().join("home");
        let at = |rel: &str| home.join(rel).to_string_lossy().into_owned();
        for d in ["Games/sam/saves", "Games/sam/shared", "work", "notes"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let mut ctx = sam_core::sandbox::sample_context();
        ctx.host.home = home.clone();
        ctx.owd = home.clone();
        ctx.sam_dirs = vec![home.join("Games/sam")];
        ctx.permissions.filesystem.custom_write = vec![at("Games/sam/saves"), at("work")];
        ctx.permissions.filesystem.custom_read = vec![at("Games/sam/shared"), at("notes")];
        let app = AppEntry {
            name: "Tool".into(),
            ..Default::default()
        };
        let line = terminal_banner(&app, &ctx);
        assert!(line.contains(&at("work")), "{line}");
        assert!(line.contains(&at("notes")), "{line}");
        assert!(!line.contains(&at("Games/sam")), "{line}");
        // A user folder set inside SAM's folders, which the sandbox
        // refuses, is not named either; one elsewhere is (independent
        // re-review of decision 9).
        for d in ["Games/sam/docs", "Pictures"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        ctx.host.xdg_dirs = [("documents", "Games/sam/docs"), ("pictures", "Pictures")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), home.join(v)))
            .collect();
        ctx.permissions.filesystem.home = false;
        ctx.permissions.filesystem.documents = sam_core::permissions::Access::Ro;
        ctx.permissions.filesystem.pictures = sam_core::permissions::Access::Ro;
        let line = terminal_banner(&app, &ctx);
        assert!(line.contains(&at("Pictures")), "{line}");
        assert!(!line.contains(&at("Games/sam")), "{line}");
        // A file named on the command line is listed as seen while files
        // opened with the app are shared; with "No access" it is not seen,
        // and the line says that SAM did not share it.
        std::fs::write(home.join("plan.txt"), "x").unwrap();
        ctx.args = vec!["plan.txt".into()];
        ctx.permissions.filesystem.opened_files = sam_core::permissions::Access::Ro;
        let line = terminal_banner(&app, &ctx);
        assert!(line.contains(&at("plan.txt")), "{line}");
        assert!(!line.contains("did not share"), "{line}");
        ctx.permissions.filesystem.opened_files = sam_core::permissions::Access::None;
        let line = terminal_banner(&app, &ctx);
        let sees = line.split(" (files it saves").next().unwrap_or_default();
        assert!(!sees.contains(&at("plan.txt")), "{line}");
        assert!(
            line.contains(&format!("SAM did not share {} with it", at("plan.txt"))),
            "{line}"
        );
        // The checks below name no file on the command line.
        ctx.args = Vec::new();
        // With the whole home, a user folder outside it is shown on its own
        // and named; one inside it is part of the home.
        let outside = home.parent().unwrap().join("data/Documents");
        std::fs::create_dir_all(&outside).unwrap();
        ctx.host
            .xdg_dirs
            .insert("documents".into(), outside.clone());
        ctx.permissions.filesystem.home = true;
        let line = terminal_banner(&app, &ctx);
        assert!(
            line.contains(&outside.to_string_lossy().into_owned()),
            "{line}"
        );
        assert!(!line.contains(&at("Pictures")), "{line}");
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
    /// Every socket SAM makes for a launch fits a Unix socket path (107
    /// characters), even for the longest app id (one that grew twice for
    /// names that were taken), the highest process number Linux hands out
    /// and the longest user number (the 240-app run of 2026-11-20: apps
    /// with long ids lost their sound, bus and Wayland security context).
    #[test]
    fn a_launchs_sockets_fit_even_for_the_longest_app_id() {
        let id = sam_intake::id::generate_id(
            &"a long name for an app".repeat(4),
            Path::new("A.AppImage"),
            &"f".repeat(64),
            |id| id.len() < 50,
        );
        assert_eq!(id.len(), 50, "{id}");
        let name = launch_dir_name();
        assert_eq!(launch_dir_pid(&name), Some(std::process::id()));
        assert_ne!(name, launch_dir_name(), "each launch has its own folder");
        let longest = name.replacen(&std::process::id().to_string(), "4194304", 1);
        let dir = Path::new("/run/user/4294967294/sam")
            .join(&id)
            .join(longest);
        for socket in ["wayland-0", "bus", "sound/native"] {
            let p = dir.join(socket);
            assert!(p.as_os_str().len() <= 107, "{} is too long", p.display());
        }
        assert_eq!(launch_dir_pid("l12-3"), Some(12));
        assert_eq!(launch_dir_pid("12-3"), None);
        assert_eq!(launch_dir_pid("lx-3"), None);
    }
}

#[cfg(test)]
mod helper_missing_tests {
    use super::*;

    /// SAM's helper goes into the sandbox for each of its jobs on its own
    /// (Landlock, the syscall filter, a probe, Room service), so an app
    /// with Room service off still gets its layers; a probe has no rooms.
    #[test]
    fn the_helper_comes_for_each_of_its_jobs() {
        for l in [false, true] {
            for s in [false, true] {
                for r in [false, true] {
                    for p in [false, true] {
                        let w = helper_wanted(l, s, r, p);
                        assert_eq!(w.rooms, r && !p, "{l} {s} {r} {p}");
                        assert_eq!(w.layers, l || s || p, "{l} {s} {r} {p}");
                        assert_eq!(w.helper, l || s || (r && !p) || p, "{l} {s} {r} {p}");
                    }
                }
            }
        }
    }

    /// Without SAM's helper, each warning names only what is really lost:
    /// no word about Landlock and seccomp when the app wanted neither, and
    /// Room service named when it is lost.
    #[test]
    fn a_missing_helper_names_only_what_is_lost() {
        let codes = |l, r| -> Vec<String> {
            helper_missing_warnings(l, r)
                .into_iter()
                .map(|w| w.code)
                .collect()
        };
        assert_eq!(codes(false, true), vec!["room-service-failed"]);
        assert_eq!(codes(true, false), vec!["helper-missing"]);
        assert_eq!(
            codes(true, true),
            vec!["helper-missing", "room-service-failed"]
        );
        assert!(codes(false, false).is_empty());
    }

    /// B2 R75, R77: a start that lacks a protection its settings ask for
    /// (SAM's helper missing for Landlock or the syscall filter, the
    /// Wayland security context refused) stops with its own code and names
    /// each missing layer; "Start anyway" lets that one start go on, and
    /// the sandbox check, which reports each layer itself, is never stopped.
    #[test]
    fn a_start_without_a_protection_it_asks_for_stops_unless_started_anyway() {
        let none = MissingAtStart {
            landlock: false,
            seccomp: false,
            wayland: None,
        };
        let opts = LaunchOptions::default();
        assert!(protection_check(&none, &opts).is_ok());
        for (missing, names) in [
            (
                MissingAtStart {
                    landlock: true,
                    seccomp: true,
                    wayland: None,
                },
                vec!["Landlock", "syscall filter", "sam-jail-run"],
            ),
            (
                MissingAtStart {
                    landlock: false,
                    seccomp: true,
                    wayland: None,
                },
                vec!["syscall filter", "sam-jail-run"],
            ),
            (
                MissingAtStart {
                    landlock: true,
                    seccomp: false,
                    wayland: None,
                },
                vec!["Landlock", "sam-jail-run"],
            ),
            (
                MissingAtStart {
                    landlock: false,
                    seccomp: false,
                    wayland: Some("the compositor refused"),
                },
                vec!["Wayland security context", "the compositor refused"],
            ),
        ] {
            let e = protection_check(&missing, &opts).expect_err("stops");
            assert_eq!(sam_core::error::code_of(&e), Some(PROTECTION_MISSING));
            let text = format!("{e:#}");
            for name in names {
                assert!(text.contains(name), "{name}: {text}");
            }
            if missing.wayland.is_none() {
                assert!(!text.contains("Wayland"), "{text}");
            }
            let anyway = LaunchOptions {
                start_anyway: true,
                ..Default::default()
            };
            assert!(protection_check(&missing, &anyway).is_ok());
            let check = LaunchOptions {
                probe: Some(crate::probe::ProbePlan { checks: vec![] }),
                ..Default::default()
            };
            assert!(protection_check(&missing, &check).is_ok());
            // `sam-jail command` and the app page show the command only.
            let preview = LaunchOptions {
                preview: true,
                ..Default::default()
            };
            assert!(protection_check(&missing, &preview).is_ok());
        }
    }
}
