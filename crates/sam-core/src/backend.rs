//! Backend adapter API (whitepaper §2.13, build plan §3.6).

use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::host::HostInfo;
use crate::permissions::PermissionSet;
use crate::util::shell_join;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Bubblewrap,
    Bubblejail,
    Firejail,
    Unsandboxed,
}

impl BackendKind {
    pub const ALL: [BackendKind; 4] = [
        BackendKind::Bubblewrap,
        BackendKind::Bubblejail,
        BackendKind::Firejail,
        BackendKind::Unsandboxed,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Bubblewrap => "bubblewrap",
            BackendKind::Bubblejail => "bubblejail",
            BackendKind::Firejail => "firejail",
            BackendKind::Unsandboxed => "unsandboxed",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            BackendKind::Bubblewrap => "Bubblewrap",
            BackendKind::Bubblejail => "Bubblejail",
            BackendKind::Firejail => "Firejail",
            BackendKind::Unsandboxed => "Unsandboxed",
        }
    }
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Installation / health of a backend on this host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub kind: BackendKind,
    pub installed: bool,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    /// Usable right now (installed, enabled and prerequisites present).
    pub usable: bool,
    pub recommended: bool,
    /// Plain-language risk notes.
    pub risks: Vec<String>,
    pub notes: Vec<String>,
}

/// Helper used to apply in-sandbox restrictions (Landlock) before exec.
#[derive(Debug, Clone)]
pub struct SandboxHelper {
    /// Host path of the `sam-jail-run` binary.
    pub binary: PathBuf,
    /// Host path of the JSON spec describing the restrictions.
    pub spec: PathBuf,
}

/// Everything a backend needs to build a sandbox command.
#[derive(Debug, Clone)]
pub struct LaunchContext {
    pub app_id: String,
    pub app_name: String,
    /// Extracted AppDir on the host.
    pub appdir: PathBuf,
    /// Where the AppDir appears inside the sandbox (`/opt/app` for bwrap).
    pub sandbox_appdir: PathBuf,
    /// Entry point relative to the AppDir.
    pub entry: String,
    /// The original AppImage, if it still exists.
    pub appimage_path: Option<PathBuf>,
    /// Original working directory of the launch.
    pub owd: PathBuf,
    pub args: Vec<String>,
    pub permissions: PermissionSet,
    pub host: HostInfo,
    /// Host directory used as the private `$HOME`.
    pub private_home: PathBuf,
    /// Host scratch directory for this launch.
    pub runtime_dir: PathBuf,
    /// AppImage runtime variables computed by the runner (APPDIR, OWD, ...).
    /// Values may reference `@APPDIR@`, which backends replace with their AppDir path.
    pub app_env: Vec<(String, String)>,
    /// Host path of a filtered D-Bus session proxy socket, if one is running.
    pub dbus_proxy_socket: Option<PathBuf>,
    pub helper: Option<SandboxHelper>,
    /// File descriptor holding a compiled seccomp program (bwrap `--seccomp`).
    pub seccomp_fd: Option<i32>,
    pub compatibility_mode: bool,
    /// Diagnostic mode: wrap the entry point with this tracer command.
    pub tracer: Option<Vec<String>>,
    /// Extra bind mounts requested by the runner: (host, sandbox, writable).
    pub extra_binds: Vec<(PathBuf, PathBuf, bool)>,
    /// Per-app folder holding `upper/` and `work/` for the writable app
    /// folder overlay (`advanced.writable_appdir`).
    pub appdir_overlay: Option<PathBuf>,
    /// Portal identity (see sam-runner `portal_identity`): bind the identity
    /// file and the app's document view, and write bwrap's instance info.
    pub portal_identity: Option<PortalIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalIdentity {
    pub app_id: String,
    pub info_file: PathBuf,
    /// Inherited fd for `bwrap --info-fd`.
    pub info_fd: Option<i32>,
    /// `/run/user/<uid>/doc/by-app/<app id>` when the document portal runs.
    pub doc_view: Option<PathBuf>,
}

impl LaunchContext {
    pub fn appdir_in_sandbox(&self) -> String {
        self.sandbox_appdir.to_string_lossy().into_owned()
    }
    pub fn entry_in_sandbox(&self) -> String {
        format!("{}/{}", self.appdir_in_sandbox(), self.entry)
    }
    /// app_env with the `@APPDIR@` placeholder substituted.
    pub fn resolved_app_env(&self, appdir: &str) -> Vec<(String, String)> {
        self.app_env
            .iter()
            .map(|(k, v)| (k.clone(), v.replace("@APPDIR@", appdir)))
            .collect()
    }
}

/// A fully built command line, ready to spawn.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Environment for the backend process itself.
    pub env: Vec<(String, String)>,
    /// Start the backend process with an empty environment plus `env`.
    pub clear_env: bool,
    /// File descriptors that must survive exec.
    pub keep_fds: Vec<i32>,
    /// Human readable notes (e.g. features that were downgraded).
    pub notes: Vec<String>,
    /// Files the backend generated (e.g. bubblejail services.toml).
    pub generated_files: Vec<PathBuf>,
}

impl SandboxCommand {
    pub fn display(&self) -> String {
        let mut parts = vec![self.program.to_string_lossy().into_owned()];
        parts.extend(self.args.iter().cloned());
        shell_join(parts)
    }
}

pub trait Backend: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn status(&self, host: &HostInfo) -> BackendStatus;
    fn build(&self, ctx: &LaunchContext) -> Result<SandboxCommand>;
}

/// Fixed, host-independent launch context for backend unit tests.
pub fn sample_context() -> LaunchContext {
    use crate::host::{Sockets, Tool, Tools};
    use std::collections::BTreeMap;
    let mut xdg = BTreeMap::new();
    for (k, v) in [("documents", "Documents"), ("downloads", "Downloads"), ("music", "Music"), ("pictures", "Pictures"), ("videos", "Videos"), ("desktop", "Desktop")] {
        xdg.insert(k.to_string(), PathBuf::from(format!("/home/tester/{v}")));
    }
    let host = HostInfo {
        uid: 1000,
        gid: 1000,
        user: "tester".into(),
        home: "/home/tester".into(),
        runtime_dir: Some("/run/user/1000".into()),
        session_type: "wayland".into(),
        desktop: "KDE".into(),
        arch: "x86_64".into(),
        sockets: Sockets {
            wayland: Some("/run/user/1000/wayland-0".into()),
            wayland_display: "wayland-0".into(),
            x11: Some("/tmp/.X11-unix/X0".into()),
            x11_display: Some(":0".into()),
            xauthority: Some("/run/user/1000/xauth_abc".into()),
            pipewire: Some("/run/user/1000/pipewire-0".into()),
            pulse: Some("/run/user/1000/pulse/native".into()),
            dbus_session_address: Some("unix:path=/run/user/1000/bus".into()),
            dbus_session: Some("/run/user/1000/bus".into()),
            dbus_system: Some("/run/dbus/system_bus_socket".into()),
            ssh_agent: None,
            cups: None,
        },
        tools: Tools {
            bwrap: Some(Tool { path: "/usr/bin/bwrap".into(), version: Some("bubblewrap 0.11.0".into()) }),
            bubblejail: Some(Tool { path: "/usr/bin/bubblejail".into(), version: None }),
            firejail: Some(Tool { path: "/usr/bin/firejail".into(), version: None }),
            xdg_dbus_proxy: Some(Tool { path: "/usr/bin/xdg-dbus-proxy".into(), version: None }),
            ..Default::default()
        },
        gpu_devices: vec!["/dev/dri/card0".into(), "/dev/dri/renderD128".into()],
        xdg_dirs: xdg,
        ..Default::default()
    };
    LaunchContext {
        app_id: "appimage-hello-1234".into(),
        app_name: "Hello".into(),
        appdir: "/data/extracted/appimage-hello-1234/AppDir".into(),
        sandbox_appdir: "/opt/app".into(),
        entry: "AppRun".into(),
        appimage_path: Some("/home/tester/Applications/Hello.AppImage".into()),
        owd: "/home/tester".into(),
        args: vec![],
        permissions: PermissionSet::strict_gui(),
        host,
        private_home: "/data/homes/appimage-hello-1234".into(),
        runtime_dir: "/run/user/1000/sam/appimage-hello-1234".into(),
        app_env: vec![("APPDIR".into(), "@APPDIR@".into())],
        dbus_proxy_socket: None,
        helper: None,
        seccomp_fd: None,
        compatibility_mode: false,
        tracer: None,
        extra_binds: vec![],
        appdir_overlay: None,
        portal_identity: None,
    }
}
