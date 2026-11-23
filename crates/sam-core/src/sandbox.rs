//! What the Bubblewrap command builder needs to build a sandbox (`LaunchContext`)
//! and what it produces (`SandboxCommand`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::host::HostInfo;
use crate::permissions::PermissionSet;
use crate::util::shell_join;

/// Whether Bubblewrap is installed and usable on this host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BubblewrapStatus {
    pub installed: bool,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    /// Usable right now (installed and user namespaces available).
    pub usable: bool,
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

/// Everything needed to build a sandbox command.
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
    /// Values may reference `@APPDIR@`, which the command builder replaces with the AppDir path.
    pub app_env: Vec<(String, String)>,
    /// Host path of a filtered D-Bus session proxy socket, if one is running.
    pub dbus_proxy_socket: Option<PathBuf>,
    /// Host path of SAM's sound relay for this app, if one is running: a
    /// PulseAudio socket that plays and records but cannot load modules
    /// into the sound server (audit S-F1).
    pub sound_socket: Option<PathBuf>,
    /// Host path of a Wayland socket with a security context for this app
    /// (privileged protocols hidden); `None` = the compositor's own socket.
    pub wayland_socket: Option<PathBuf>,
    pub helper: Option<SandboxHelper>,
    /// The app's standard streams are a terminal of SAM's own (`sam_runner::pty`),
    /// never the user's: the sandbox keeps the session, so resizing and
    /// Ctrl+C reach the app. Otherwise it gets a new session, cut off from
    /// any terminal (Bubblewrap's protection against typed-in commands).
    pub own_terminal: bool,
    /// Diagnostic mode: wrap the entry point with this tracer command.
    pub tracer: Option<Vec<String>>,
    /// Extra bind mounts requested by the runner: (host, sandbox, writable).
    pub extra_binds: Vec<(PathBuf, PathBuf, bool)>,
    /// Per-app folder holding `upper/` and `work/` for the writable app
    /// folder overlay (`advanced.writable_appdir`).
    pub appdir_overlay: Option<PathBuf>,
    /// SAM's own folders (config, data, extraction): hidden whenever a
    /// granted folder would make them visible, so an app cannot change its
    /// own permissions or another app's files.
    pub sam_dirs: Vec<PathBuf>,
    /// SAM's own programs outside the sandbox (`util::own_programs`): its
    /// AppImage file and `sam-jail-run`, which every menu entry runs.
    /// Never writable inside, and the folders above them cannot be renamed
    /// away, so an app cannot put its own program in their place.
    pub sam_programs: Vec<PathBuf>,
    /// Room service's socket for this start (shown at /run/sam/rooms).
    pub room_socket: Option<PathBuf>,
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

/// Names SAM itself uses in `/run/sam` inside the sandbox.
const RUN_SAM_OWN: &[&str] = &["bin", "sam-jail-run", "sandbox.json", "app", "rooms"];

/// Where the AppImage file `name` is shown inside the sandbox (`$APPIMAGE`):
/// `/run/sam/<name>`, or `/run/sam/app/<name>` for a name SAM uses there
/// itself (an AppImage called `bin` covered SAM's tools and never started;
/// audit S-F17).
pub fn appimage_inside(name: &std::ffi::OsStr) -> PathBuf {
    let base = PathBuf::from("/run/sam");
    if RUN_SAM_OWN.iter().any(|n| std::ffi::OsStr::new(n) == name) {
        base.join("app").join(name)
    } else {
        base.join(name)
    }
}

/// A fully built command line, ready to spawn.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Human readable notes (e.g. features that were downgraded).
    pub notes: Vec<String>,
    /// Files the sandbox builder generated.
    pub generated_files: Vec<PathBuf>,
}

impl SandboxCommand {
    pub fn display(&self) -> String {
        let mut parts = vec![self.program.to_string_lossy().into_owned()];
        parts.extend(self.args.iter().cloned());
        shell_join(parts)
    }

    /// [`display`](Self::display) with the values of these environment
    /// variables hidden: the ones a person gave the app (often API keys or
    /// tokens) must not end up in logs, which bug reports quote.
    pub fn display_hiding(&self, keys: &[&str]) -> String {
        let mut parts = vec![self.program.to_string_lossy().into_owned()];
        let mut args = self.args.iter();
        while let Some(a) = args.next() {
            parts.push(a.clone());
            if a == "--setenv" {
                if let (Some(k), Some(v)) = (args.next(), args.next()) {
                    parts.push(k.clone());
                    parts.push(if keys.contains(&k.as_str()) {
                        "<hidden>".into()
                    } else {
                        v.clone()
                    });
                }
            }
        }
        shell_join(parts)
    }
}

/// Fixed, host-independent launch context for unit tests.
pub fn sample_context() -> LaunchContext {
    use crate::host::{Sockets, Tool, Tools};
    use std::collections::BTreeMap;
    let mut xdg = BTreeMap::new();
    for (k, v) in [
        ("documents", "Documents"),
        ("downloads", "Downloads"),
        ("music", "Music"),
        ("pictures", "Pictures"),
        ("videos", "Videos"),
        ("desktop", "Desktop"),
    ] {
        xdg.insert(k.to_string(), PathBuf::from(format!("/home/tester/{v}")));
    }
    let host = HostInfo {
        uid: 1000,
        // Not the same number as the user's, so a mix-up shows.
        gid: 1001,
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
            bwrap: Some(Tool {
                path: "/usr/bin/bwrap".into(),
                version: Some("bubblewrap 0.11.0".into()),
            }),
            xdg_dbus_proxy: Some(Tool {
                path: "/usr/bin/xdg-dbus-proxy".into(),
                version: None,
            }),
            ..Default::default()
        },
        // As the host lists them: the render nodes and NVIDIA's own nodes.
        gpu_devices: vec![
            "/dev/dri/card0".into(),
            "/dev/dri/renderD128".into(),
            "/dev/nvidia0".into(),
            "/dev/nvidiactl".into(),
        ],
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
        sound_socket: None,
        wayland_socket: None,
        helper: None,
        own_terminal: false,
        tracer: None,
        extra_binds: vec![],
        appdir_overlay: None,
        sam_dirs: vec![],
        sam_programs: vec![],
        room_socket: None,
    }
}

#[cfg(test)]
mod display_tests {
    use super::*;

    /// Values of variables a person gave the app never reach the shown
    /// command; the names and SAM's own variables stay.
    #[test]
    fn given_environment_values_are_hidden_in_the_shown_command() {
        let c = SandboxCommand {
            program: "bwrap".into(),
            args: [
                "--setenv",
                "OPENAI_API_KEY",
                "sk-secret",
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--",
                "app",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            notes: vec![],
            generated_files: vec![],
        };
        let shown = c.display_hiding(&["OPENAI_API_KEY"]);
        assert!(!shown.contains("sk-secret"), "{shown}");
        assert!(
            shown.contains("OPENAI_API_KEY")
                && shown.contains("<hidden>")
                && shown.contains("C.UTF-8"),
            "{shown}"
        );
        assert!(
            c.display().contains("sk-secret"),
            "display itself is unchanged"
        );
    }
}

#[cfg(test)]
mod appimage_place_tests {
    use super::appimage_inside;
    use std::ffi::OsStr;
    use std::path::Path;

    /// An AppImage file named like one of SAM's own files in the sandbox
    /// gets a folder of its own instead of covering SAM's (audit S-F17).
    #[test]
    fn an_appimage_never_covers_sams_own_files() {
        assert_eq!(
            appimage_inside(OsStr::new("Krita.AppImage")),
            Path::new("/run/sam/Krita.AppImage")
        );
        for own in ["bin", "sam-jail-run", "sandbox.json", "app", "rooms"] {
            assert_eq!(
                appimage_inside(OsStr::new(own)),
                Path::new("/run/sam/app").join(own)
            );
        }
    }
}
