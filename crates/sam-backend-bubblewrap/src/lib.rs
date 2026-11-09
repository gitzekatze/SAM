//! Bubblewrap backend (default, §2.13.1 / build plan §3.6).
//!
//! Sandbox layout (§2.14):
//!
//! ```text
//! /opt/app              extracted AppImage payload, read-only
//! /usr/lib, /usr/bin    host runtime, read-only (all of /usr in compatibility mode)
//! /usr/share/<x>        whitelisted shared data (fonts, icons, locale, ...)
//! /etc/<x>              whitelisted configuration, generated passwd/group
//! /tmp, /var/tmp        private tmpfs
//! /run/user/<uid>       only the sockets that are granted
//! $HOME                 private per-app home (or tmpfs), plus granted folders
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sam_core::permissions::*;
use sam_core::util::expand_home;
use sam_core::{BackendStatus, HostInfo, LaunchContext, SandboxCommand};

pub struct Bubblewrap;

/// `/usr/share` entries exposed in minimal runtime mode. Safe, read-only data.
const SHARE_BASE: &[&str] = &[
    "fonts", "fontconfig", "icons", "locale", "zoneinfo", "themes", "mime", "X11", "glib-2.0", "pixmaps",
    "ca-certificates", "terminfo", "icu", "iso-codes", "misc", "file", "hwdata", "color-schemes", "kf6",
    "kf5", "qt", "qt5", "qt6", "gtk-2.0", "gtk-3.0", "gtk-4.0", "xml", "p11-kit", "libthai", "hunspell",
    "myspell", "mime-info", "sounds",
    // Keyboard layouts for xkbcommon. Newer distributions keep them here and
    // make /usr/share/X11/xkb a symlink to it; without it GTK and Electron
    // abort with "Failed to create XKB keymap".
    "xkeyboard-config-2", "xkeyboard-config",
];
const SHARE_GPU: &[&str] = &["vulkan", "glvnd", "egl", "drirc.d", "libdrm", "nvidia"];
const SHARE_AUDIO: &[&str] = &["alsa", "pipewire", "pulseaudio"];
const SHARE_DBUS: &[&str] = &["dbus-1"];

/// `/etc` entries always exposed (read-only).
const ETC_BASE: &[&str] = &[
    "ld.so.cache", "ld.so.conf", "ld.so.conf.d", "fonts", "ssl", "ca-certificates", "pki", "crypto-policies",
    "localtime", "locale.conf", "locale.alias", "os-release", "xdg", "mime.types", "nsswitch.conf",
    "gtk-2.0", "gtk-3.0", "gtk-4.0", "timezone", "drirc", "glvnd",
    // Debian/Ubuntu: /usr/bin/java etc. are symlinks into /etc/alternatives.
    "alternatives",
];
const ETC_NETWORK: &[&str] = &["resolv.conf", "hosts", "gai.conf", "services", "protocols", "host.conf"];
const ETC_GPU: &[&str] = &["vulkan", "OpenCL", "nvidia"];
const ETC_AUDIO: &[&str] = &["alsa", "asound.conf", "pulse", "pipewire"];

/// Sensitive dotfiles hidden when full home access is granted with
/// `hidden_files = false`.
const SENSITIVE_DOTFILES: &[&str] = &[
    ".password-store", ".local/share/keyrings", ".pki", ".aws", ".kube", ".docker", ".config/gcloud",
    ".azure", ".netrc", ".git-credentials", ".config/keepassxc", ".mozilla", ".config/chromium",
    ".config/google-chrome", ".config/BraveSoftware", ".thunderbird", ".local/share/kwalletd",
];

/// Paths kept read-only even with full home read/write: SAM's own state
/// and common persistence vectors.
const PROTECTED_RO: &[&str] = &[
    ".config/sam", ".local/share/sam", ".local/share/applications", ".config/autostart",
    ".config/systemd", ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".config/fish",
    ".config/environment.d", ".config/plasma-workspace", ".xinitrc", ".xprofile",
];

/// Host theme configuration (read-only) when `advanced.host_themes` is on.
const THEME_FILES: &[&str] = &[
    ".config/gtk-3.0", ".config/gtk-4.0", ".gtkrc-2.0", ".config/kdeglobals", ".config/Trolltech.conf",
    ".config/qt5ct", ".config/qt6ct", ".config/Kvantum", ".config/breezerc", ".config/kcminputrc",
    ".icons", ".local/share/icons", ".themes", ".local/share/themes", ".config/xsettingsd", ".local/share/color-schemes",
];

/// Host env vars forwarded by default (locale, scaling, theming).
const ENV_FORWARD: &[&str] = &[
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY",
    "LC_MESSAGES", "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT",
    "LC_IDENTIFICATION", "TERM", "COLORTERM", "TZ", "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP",
    "DESKTOP_SESSION", "KDE_FULL_SESSION", "KDE_SESSION_VERSION", "GTK_THEME", "XCURSOR_THEME",
    "XCURSOR_SIZE", "QT_SCALE_FACTOR", "QT_SCREEN_SCALE_FACTORS", "QT_AUTO_SCREEN_SCALE_FACTOR",
    "QT_ENABLE_HIGHDPI_SCALING", "GDK_SCALE", "GDK_DPI_SCALE", "QT_QPA_PLATFORMTHEME", "QT_STYLE_OVERRIDE",
    "XMODIFIERS", "GTK_IM_MODULE", "QT_IM_MODULE",
];

struct Args {
    v: Vec<String>,
}

impl Args {
    fn push<S: Into<String>>(&mut self, s: S) -> &mut Self {
        self.v.push(s.into());
        self
    }
    fn op2(&mut self, op: &str, a: impl AsRef<Path>, b: impl AsRef<Path>) {
        // Optional binds: skip sources that cannot be mounted, e.g. files that
        // were unlinked while still open (link count 0).
        if op.ends_with("-try") {
            use std::os::unix::fs::MetadataExt;
            if fs::metadata(a.as_ref()).is_ok_and(|m| m.nlink() == 0) {
                return;
            }
        }
        self.v.push(op.into());
        self.v.push(a.as_ref().to_string_lossy().into_owned());
        self.v.push(b.as_ref().to_string_lossy().into_owned());
    }
    fn ro(&mut self, p: impl AsRef<Path>) {
        let p = p.as_ref();
        self.op2("--ro-bind-try", p, p);
    }
    fn setenv(&mut self, k: &str, v: impl AsRef<str>) {
        self.v.extend(["--setenv".to_string(), k.to_string(), v.as_ref().to_string()]);
    }
}

/// Bind a whitelisted host path read-only, plus the targets of symlinks
/// that point outside it (the path itself, or entries one level inside).
/// Example: `/usr/share/X11/xkb -> /usr/share/xkeyboard-config-2`; without
/// the target, xkbcommon finds no keymaps and GTK/Electron abort.
fn ro_follow(a: &mut Args, path: &Path) {
    a.ro(path);
    let Ok(md) = fs::symlink_metadata(path) else { return };
    let mut targets = Vec::new();
    if md.file_type().is_symlink() {
        targets.extend(fs::canonicalize(path).ok());
    } else if md.is_dir() {
        if let Ok(rd) = fs::read_dir(path) {
            for e in rd.flatten() {
                if e.file_type().is_ok_and(|t| t.is_symlink()) {
                    if let Ok(t) = fs::canonicalize(e.path()) {
                        if !t.starts_with(path) {
                            targets.push(t);
                        }
                    }
                }
            }
        }
    }
    for t in targets {
        // /usr/lib and /usr/bin are bound already; skip anything else outside
        // the shared-data and configuration trees.
        let interesting = (t.starts_with("/usr/share") || t.starts_with("/etc") || t.starts_with("/run")) && t.exists();
        if interesting && !a.v.windows(2).any(|w| w[0] == "--ro-bind-try" && Path::new(&w[1]) == t) {
            a.ro(&t);
        }
    }
}

/// Small helper scripts placed at `/run/sam/bin` (first on `$PATH`):
/// `xdg-open` and friends ask the desktop portal to open links and files
/// **outside** the sandbox, in the user's normal browser or app, instead of
/// starting a second, empty browser inside it.
pub const OPEN_SHIM: &str = r#"#!/bin/sh
# SAM: open URLs and files outside the sandbox via the desktop portal.
# Local files go through OpenURI.OpenFile with a file descriptor, so the
# host opens exactly this file (a path inside the sandbox means something
# else on the host). URLs go through OpenURI.OpenURI.
target="$1"
[ -n "$target" ] || { echo "usage: $(basename "$0") URL|FILE" >&2; exit 1; }
case "$target" in
  file://*) target="${target#file://}" ;;
esac
if [ "$(basename "$0")" = xdg-email ] && [ "${target#mailto:}" = "$target" ] && [ ! -e "$target" ]; then target="mailto:$target"; fi
if [ -e "$target" ]; then
  if command -v python3 >/dev/null 2>&1 && python3 - "$target" <<'PY' 2>/dev/null; then exit 0; fi
import os, sys
from gi.repository import Gio, GLib
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_CLOEXEC)
bus = Gio.bus_get_sync(Gio.BusType.SESSION)
bus.call_with_unix_fd_list_sync("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop",
    "org.freedesktop.portal.OpenURI", "OpenFile", GLib.Variant("(sha{sv})", ("", 0, {})), None, 0, -1,
    Gio.UnixFDList.new_from_array([fd]), None)
PY
  echo "sam: cannot open $target outside the sandbox (needs python3-gobject in the host system)" >&2
  exit 3
fi
if command -v gdbus >/dev/null 2>&1 && gdbus call --session --dest org.freedesktop.portal.Desktop \
     --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.OpenURI.OpenURI \
     "" "$target" "@a{sv} {}" >/dev/null 2>&1; then exit 0; fi
if command -v busctl >/dev/null 2>&1 && busctl --user call org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop \
     org.freedesktop.portal.OpenURI OpenURI 'ssa{sv}' "" "$target" 0 >/dev/null 2>&1; then exit 0; fi
echo "sam: could not open $target: the desktop portal is not reachable (session D-Bus off?)" >&2
exit 3
"#;
pub const OPEN_SHIM_NAMES: &[&str] =
    &["xdg-open", "xdg-email", "kde-open", "kde-open5", "kde-open6", "gnome-open", "sensible-browser", "x-www-browser", "www-browser"];

/// Replicate a top-level path from the host: symlink stays a symlink,
/// a real directory is bound read-only.
fn mirror(a: &mut Args, path: &str) {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            if let Ok(t) = fs::read_link(path) {
                a.op2("--symlink", t, path);
            }
        }
        Ok(m) if m.is_dir() => a.ro(path),
        _ => {}
    }
}

impl Bubblewrap {
    fn runtime_dir(ctx: &LaunchContext) -> String {
        format!("/run/user/{}", ctx.host.uid)
    }
}

/// Is `p` visible inside the sandbox given the granted folders?
fn visible_in_sandbox(p: &Path, ctx: &LaunchContext) -> bool {
    let fs = &ctx.permissions.filesystem;
    if fs.home && p.starts_with(&ctx.host.home) {
        return true;
    }
    for key in XDG_DIR_KEYS {
        if fs.xdg_access(key).is_granted() {
            if let Some(d) = ctx.host.xdg_dir(key) {
                if p.starts_with(d) {
                    return true;
                }
            }
        }
    }
    fs.custom_read.iter().chain(fs.custom_write.iter()).any(|c| p.starts_with(expand_home(c)))
}

impl Bubblewrap {
    /// Whether Bubblewrap is installed and can create sandboxes here.
    pub fn status(&self, host: &HostInfo) -> BackendStatus {
        let tool = host.tools.bwrap.as_ref();
        let mut notes = vec![];
        let installed = tool.is_some();
        if !installed {
            notes.push("Bubblewrap is not installed. Install the 'bubblewrap' package.".into());
        }
        if !host.userns.usable() {
            notes.push(host.userns.explain());
        }
        if host.tools.xdg_dbus_proxy.is_none() {
            notes.push("xdg-dbus-proxy not found: filtered session D-Bus will be disabled".into());
        }
        BackendStatus {
            installed,
            path: tool.map(|t| t.path.clone()),
            version: tool.and_then(|t| t.version.clone()),
            usable: installed && host.userns.usable(),
            notes,
        }
    }

    /// The bwrap command line for this launch.
    pub fn build(&self, ctx: &LaunchContext) -> Result<SandboxCommand> {
        let bwrap = ctx.host.tools.bwrap.as_ref().context("bubblewrap (bwrap) is not installed")?;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let home = h.home.clone();
        let run = Self::runtime_dir(ctx);
        let mut notes: Vec<String> = Vec::new();
        let mut a = Args { v: Vec::new() };
        let mut keep_fds = Vec::new();

        // Namespaces & process hygiene.
        a.push("--die-with-parent").push("--new-session");
        a.push("--unshare-user").push("--unshare-pid").push("--unshare-ipc").push("--unshare-uts").push("--unshare-cgroup-try");
        match p.network.mode {
            NetworkMode::Full => {}
            NetworkMode::None => {
                a.push("--unshare-net");
            }
            NetworkMode::Localhost => {
                // The launcher starts bwrap inside a pasta loopback-only
                // namespace (sam-runner netns.rs), so no --unshare-net here.
            }
            m => {
                a.push("--unshare-net");
                notes.push(format!("network mode '{}' is experimental and not supported by bubblewrap; network disabled", m.as_str()));
            }
        }
        if !p.advanced.allow_userns {
            a.push("--disable-userns");
        }
        // No --hostname: sethostname() is blocked by seccomp on some hardened
        // hosts and nested sandboxes; the UTS namespace alone is sufficient.
        a.push("--cap-drop").push("ALL");
        a.push("--clearenv");

        // Base filesystem.
        a.push("--proc").push("/proc");
        a.push("--dev").push("/dev");
        a.push("--tmpfs").push("/tmp");
        a.push("--tmpfs").push("/var/tmp");
        a.push("--dir").push("/run");
        a.push("--perms").push("0700").push("--tmpfs").push(run.clone());

        match p.advanced.host_runtime {
            HostRuntime::Full => a.op2("--ro-bind", "/usr", "/usr"),
            HostRuntime::Minimal => {
                a.op2("--ro-bind", "/usr/lib", "/usr/lib");
                a.op2("--ro-bind-try", "/usr/bin", "/usr/bin");
                for d in ["/usr/lib64", "/usr/lib32", "/usr/libexec", "/usr/sbin"] {
                    mirror(&mut a, d);
                }
                let mut share: Vec<&str> = SHARE_BASE.to_vec();
                if p.devices.gpu {
                    share.extend(SHARE_GPU);
                }
                if p.audio.enabled || p.audio.alsa_raw {
                    share.extend(SHARE_AUDIO);
                }
                if p.dbus.session.mode != DbusMode::None {
                    share.extend(SHARE_DBUS);
                }
                for s in share {
                    ro_follow(&mut a, &Path::new("/usr/share").join(s));
                }
            }
        }
        for d in ["/bin", "/sbin", "/lib", "/lib64", "/lib32"] {
            mirror(&mut a, d);
        }

        // /etc
        let mut etc: Vec<&str> = ETC_BASE.to_vec();
        if p.network.mode == NetworkMode::Full {
            etc.extend(ETC_NETWORK);
            a.ro("/run/systemd/resolve");
        }
        // ro_follow below also binds symlink targets, e.g. resolv.conf ->
        // /run/NetworkManager/resolv.conf on NetworkManager systems.
        if p.devices.gpu {
            etc.extend(ETC_GPU);
        }
        if p.audio.enabled || p.audio.alsa_raw {
            etc.extend(ETC_AUDIO);
        }
        if p.dbus.session.mode != DbusMode::None || p.dbus.system.mode != DbusMode::None {
            etc.push("machine-id");
        }
        for e in etc {
            ro_follow(&mut a, &Path::new("/etc").join(e));
        }
        // Synthetic passwd/group with only the current user.
        let passwd = ctx.runtime_dir.join("passwd");
        let group = ctx.runtime_dir.join("group");
        a.op2("--ro-bind-try", &passwd, "/etc/passwd");
        a.op2("--ro-bind-try", &group, "/etc/group");

        // The app payload: read-only, or an overlay that keeps the app's own
        // changes in a separate per-app layer.
        match &ctx.appdir_overlay {
            Some(base) if p.advanced.writable_appdir => {
                a.push("--overlay-src").push(ctx.appdir.to_string_lossy());
                a.push("--overlay").push(base.join("upper").to_string_lossy()).push(base.join("work").to_string_lossy()).push(ctx.sandbox_appdir.to_string_lossy());
            }
            _ => a.op2("--ro-bind", &ctx.appdir, &ctx.sandbox_appdir),
        }
        if let Some(img) = &ctx.appimage_path {
            if let Some(name) = img.file_name() {
                a.op2("--ro-bind-try", img, Path::new("/run/sam").join(name));
            }
        }

        // /sys: CPU topology always; device trees when GPU/USB/input/webcam is granted.
        a.ro("/sys/devices/system/cpu");
        if p.devices.gpu || p.devices.usb || p.devices.input || p.devices.gamepads || p.devices.webcam {
            for s in ["/sys/dev", "/sys/devices", "/sys/bus", "/sys/class"] {
                a.ro(s);
            }
            a.ro("/run/udev/data");
        }
        // NVIDIA's driver reads its kernel module's information
        // (/sys/module/nvidia/version); without it, OpenGL and Vulkan fall
        // back to software rendering. Only the NVIDIA modules are exposed.
        if p.devices.gpu {
            for m in gpu_module_dirs(Path::new("/sys/module")) {
                a.ro(&m);
            }
        }

        // Home.
        let fsp = &p.filesystem;
        if fsp.home {
            let op = if fsp.home_access == Access::Rw { "--bind" } else { "--ro-bind" };
            a.op2(op, &home, &home);
            let mut masks: Vec<&str> = Vec::new();
            if !fsp.ssh {
                masks.push(".ssh");
            }
            if !fsp.gnupg {
                masks.push(".gnupg");
            }
            if !fsp.hidden_files {
                masks.extend(SENSITIVE_DOTFILES);
            }
            for m in masks {
                let path = home.join(m);
                match fs::symlink_metadata(&path) {
                    Ok(md) if md.is_dir() => {
                        a.push("--tmpfs").push(path.to_string_lossy());
                    }
                    Ok(md) if md.is_file() => a.op2("--ro-bind", "/dev/null", &path),
                    _ => {}
                }
            }
            for prot in PROTECTED_RO {
                let path = home.join(prot);
                if matches!(*prot, ".config/sam" | ".local/share/sam") {
                    if path.is_dir() {
                        a.push("--tmpfs").push(path.to_string_lossy());
                    }
                } else if fsp.home_access == Access::Rw && path.exists() {
                    a.ro(&path);
                }
            }
        } else {
            if p.advanced.persistent_home {
                // The launch pipeline creates the directory; build() has no side effects.
                a.op2("--bind", &ctx.private_home, &home);
            } else {
                a.push("--tmpfs").push(home.to_string_lossy());
            }
            for key in XDG_DIR_KEYS {
                let acc = fsp.xdg_access(key);
                if !acc.is_granted() {
                    continue;
                }
                match h.xdg_dir(key) {
                    Some(dir) if dir.exists() => {
                        let op = if acc == Access::Rw { "--bind-try" } else { "--ro-bind-try" };
                        a.op2(op, dir, dir);
                    }
                    _ => notes.push(format!("{key} folder does not exist on the host; not bound")),
                }
            }
        }
        // Safe read-only user resources.
        for r in [".local/share/fonts", ".fonts", ".config/fontconfig"] {
            a.ro(home.join(r));
        }
        if p.advanced.host_themes && !fsp.home {
            for t in THEME_FILES {
                a.ro(home.join(t));
            }
        }
        for c in &fsp.custom_read {
            let path = expand_home(c);
            a.op2("--ro-bind-try", &path, &path);
        }
        for c in &fsp.custom_write {
            let path = expand_home(c);
            a.op2("--bind-try", &path, &path);
        }
        // Files explicitly passed on the command line (e.g. "Open with") are
        // granted individually, like a document portal.
        for arg in &ctx.args {
            let ap = Path::new(arg);
            if ap.is_absolute() && ap.is_file() && !visible_in_sandbox(ap, ctx) && !sam_core::risk::is_sensitive_path(arg) {
                let op = if fsp.opened_files == Access::Rw { "--bind-try" } else { "--ro-bind-try" };
                a.op2(op, ap, ap);
                notes.push(format!("granted access to the opened file {arg}"));
            }
        }
        for (host_p, sb, rw) in &ctx.extra_binds {
            a.op2(if *rw { "--bind" } else { "--ro-bind" }, host_p, sb);
        }

        // Display.
        let mut session_type = "tty";
        if p.display.wayland {
            match &h.sockets.wayland {
                Some(sock) => {
                    a.op2("--ro-bind", sock, format!("{run}/wayland-0"));
                    a.setenv("WAYLAND_DISPLAY", "wayland-0");
                    session_type = "wayland";
                }
                None => notes.push("Wayland socket not available".into()),
            }
        }
        if p.display.x11 {
            match (&h.sockets.x11, &h.sockets.x11_display) {
                (Some(sock), Some(display)) => {
                    a.op2("--ro-bind", sock, sock);
                    let num = sam_core::host::x11_display_number(display).unwrap_or_else(|| "0".into());
                    a.setenv("DISPLAY", format!(":{num}"));
                    if let Some(xa) = &h.sockets.xauthority {
                        a.op2("--ro-bind", xa, format!("{run}/Xauthority"));
                        a.setenv("XAUTHORITY", format!("{run}/Xauthority"));
                    }
                    if session_type == "tty" {
                        session_type = "x11";
                    }
                }
                _ => notes.push("X11 display not available".into()),
            }
        }
        a.setenv("XDG_SESSION_TYPE", session_type);
        let (qt, gdk, sdl) = match (p.display.wayland && h.sockets.wayland.is_some(), p.display.x11 && h.sockets.x11.is_some()) {
            (true, true) => ("wayland;xcb", "wayland,x11", "wayland,x11"),
            (true, false) => ("wayland", "wayland", "wayland"),
            (false, true) => ("xcb", "x11", "x11"),
            (false, false) => ("offscreen", "", ""),
        };
        a.setenv("QT_QPA_PLATFORM", qt);
        if !gdk.is_empty() {
            a.setenv("GDK_BACKEND", gdk);
            a.setenv("SDL_VIDEODRIVER", sdl);
        }

        // Audio.
        if p.audio.enabled {
            let mut any = false;
            if let Some(pw) = &h.sockets.pipewire {
                a.op2("--ro-bind", pw, format!("{run}/pipewire-0"));
                any = true;
            }
            if let Some(pulse) = &h.sockets.pulse {
                a.op2("--ro-bind", pulse, format!("{run}/pulse/native"));
                a.setenv("PULSE_SERVER", format!("unix:{run}/pulse/native"));
                any = true;
            }
            if !any {
                notes.push("PipeWire socket not found. Audio may not work.".into());
            }
        }
        if p.audio.alsa_raw {
            a.op2("--dev-bind-try", "/dev/snd", "/dev/snd");
        }

        // Devices.
        if p.devices.gpu {
            a.op2("--dev-bind-try", "/dev/dri", "/dev/dri");
            for d in &h.gpu_devices {
                if d.file_name().is_some_and(|n| n.to_string_lossy().starts_with("nvidia")) {
                    a.op2("--dev-bind-try", d, d);
                }
            }
        }
        if p.devices.webcam {
            if let Ok(rd) = fs::read_dir("/dev") {
                let mut cams: Vec<PathBuf> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("video")))
                    .collect();
                cams.sort();
                for c in cams {
                    a.op2("--dev-bind-try", &c, &c);
                }
            }
        }
        if p.devices.input {
            a.op2("--dev-bind-try", "/dev/input", "/dev/input");
            a.op2("--dev-bind-try", "/dev/uinput", "/dev/uinput");
        } else if p.devices.gamepads {
            let pads = gamepad_nodes(Path::new("/dev/input"), Path::new("/run/udev/data"));
            if pads.is_empty() {
                notes.push("No game controller is plugged in; controllers connected later are not seen until the app restarts".into());
            }
            for d in pads {
                a.op2("--dev-bind-try", &d, &d);
            }
        }
        if p.devices.usb {
            a.op2("--dev-bind-try", "/dev/bus/usb", "/dev/bus/usb");
        }
        if p.devices.bluetooth && p.dbus.system.mode == DbusMode::None {
            notes.push("Bluetooth needs the system D-Bus; not granted".into());
        }
        // Private shared memory: the host's /dev/shm would be a side channel
        // to other programs' segments.
        a.push("--tmpfs").push("/dev/shm");

        // Input methods: IBus talks to its portal frontend instead of its
        // private socket (Fcitx5 finds its portal frontend on its own).
        if p.integrations.input_method {
            a.setenv("IBUS_USE_PORTAL", "1");
            if p.dbus.session.mode == DbusMode::None {
                notes.push("Input method needs the session D-Bus; not granted".into());
            }
        }

        // D-Bus.
        match p.dbus.session.mode {
            DbusMode::None => a.setenv("NO_AT_BRIDGE", "1"),
            DbusMode::Full => match &h.sockets.dbus_session {
                Some(sock) => {
                    a.op2("--ro-bind", sock, format!("{run}/bus"));
                    a.setenv("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"));
                }
                None => notes.push("session D-Bus socket not found".into()),
            },
            DbusMode::Filtered => match &ctx.dbus_proxy_socket {
                Some(proxy) => {
                    a.op2("--ro-bind", proxy, format!("{run}/bus"));
                    a.setenv("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"));
                }
                None => {
                    a.setenv("NO_AT_BRIDGE", "1");
                    notes.push("filtered D-Bus requested but no proxy is running (install xdg-dbus-proxy); session bus disabled".into());
                }
            },
        }
        match p.dbus.system.mode {
            DbusMode::None => {}
            DbusMode::Full => {
                if let Some(sys) = &h.sockets.dbus_system {
                    a.op2("--ro-bind", sys, sys);
                }
            }
            DbusMode::Filtered => notes.push("filtered system D-Bus is not supported by the bubblewrap backend; denied".into()),
        }

        // Sockets.
        if p.sockets.ssh_agent {
            if let Some(s) = &h.sockets.ssh_agent {
                a.op2("--ro-bind", s, format!("{run}/ssh-agent.sock"));
                a.setenv("SSH_AUTH_SOCK", format!("{run}/ssh-agent.sock"));
            }
        }
        if p.sockets.cups {
            a.ro("/run/cups/cups.sock");
        }
        for s in &p.sockets.custom {
            let sp = expand_home(s);
            a.op2("--bind-try", &sp, &sp);
        }

        // Environment.
        a.setenv("HOME", home.to_string_lossy());
        a.setenv("USER", &h.user);
        a.setenv("LOGNAME", &h.user);
        a.setenv("SHELL", "/bin/sh");
        if p.dbus.session.mode != DbusMode::None {
            // Link opener shims (see OPEN_SHIM), written by write_identity_files.
            a.op2("--ro-bind-try", ctx.runtime_dir.join("bin"), "/run/sam/bin");
            a.setenv("PATH", "/run/sam/bin:/usr/local/bin:/usr/bin:/bin");
        } else {
            a.setenv("PATH", "/usr/local/bin:/usr/bin:/bin");
        }
        a.setenv("XDG_RUNTIME_DIR", &run);
        a.setenv("SAM_SANDBOX", "bubblewrap");
        for k in ENV_FORWARD.iter().map(|s| s.to_string()).chain(p.environment.passthrough.iter().cloned()) {
            if let Ok(v) = std::env::var(&k) {
                a.setenv(&k, v);
            }
        }
        for (k, v) in ctx.resolved_app_env(&ctx.appdir_in_sandbox()) {
            a.setenv(&k, v);
        }
        for (k, v) in &p.environment.set {
            a.setenv(k, v);
        }

        // Working directory.
        let chdir = if visible_in_sandbox(&ctx.owd, ctx) { ctx.owd.clone() } else { home.clone() };
        a.push("--chdir").push(chdir.to_string_lossy());

        // Seccomp.
        if let Some(fd) = ctx.seccomp_fd {
            a.push("--seccomp").push(fd.to_string());
            keep_fds.push(fd);
        }

        // Landlock helper.
        let mut cmd: Vec<String> = Vec::new();
        if let Some(helper) = &ctx.helper {
            a.op2("--ro-bind", &helper.binary, "/run/sam/sam-jail-run");
            a.op2("--ro-bind", &helper.spec, "/run/sam/sandbox.json");
            cmd.extend(["/run/sam/sam-jail-run".into(), "--sandbox-exec".into(), "/run/sam/sandbox.json".into(), "--".into()]);
        }
        if let Some(tracer) = &ctx.tracer {
            cmd.extend(tracer.iter().cloned());
        }
        for extra in &p.advanced.extra_backend_args {
            a.push(extra.clone());
        }
        // Everything is mounted: make the sandbox root itself read-only.
        // (/tmp, /var/tmp, $XDG_RUNTIME_DIR and $HOME are separate mounts.)
        a.push("--remount-ro").push("/");
        a.push("--");
        cmd.push(ctx.entry_in_sandbox());
        cmd.extend(ctx.args.iter().cloned());
        a.v.extend(cmd);

        Ok(SandboxCommand {
            program: bwrap.path.clone(),
            args: a.v,
            env: vec![],
            clear_env: false,
            keep_fds,
            notes,
            generated_files: vec![passwd, group],
        })
    }
}

/// Write the synthetic passwd/group files referenced by the command.
pub fn write_identity_files(ctx: &LaunchContext) -> Result<()> {
    fs::create_dir_all(&ctx.runtime_dir)?;
    let h = &ctx.host;
    fs::write(
        ctx.runtime_dir.join("passwd"),
        format!("{u}:x:{uid}:{gid}:{u}:{home}:/bin/sh\nnobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n", u = h.user, uid = h.uid, gid = h.gid, home = h.home.display()),
    )?;
    fs::write(ctx.runtime_dir.join("group"), format!("{u}:x:{gid}:\nnobody:x:65534:\n", u = h.user, gid = h.gid))?;
    let bin = ctx.runtime_dir.join("bin");
    fs::create_dir_all(&bin)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let shim = bin.join("sam-open");
        fs::write(&shim, OPEN_SHIM)?;
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))?;
        for name in OPEN_SHIM_NAMES {
            let link = bin.join(name);
            let _ = fs::remove_file(&link);
            std::os::unix::fs::symlink("sam-open", &link)?;
        }
    }
    Ok(())
}

/// Kernel module folders a GPU driver needs to see: NVIDIA's (`nvidia`,
/// `nvidia_drm`, `nvidia_modeset`, `nvidia_uvm`).
fn gpu_module_dirs(sys_module: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(sys_module)
        .map(|rd| rd.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("nvidia")).map(|e| e.path()).collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// Joystick device nodes: `js*`, plus `event*` nodes udev tagged as a
/// joystick (`E:ID_INPUT_JOYSTICK=1` in `/run/udev/data/c13:<minor>`).
/// Keyboards and mice are left out, so the app cannot log keystrokes.
fn gamepad_nodes(dev_input: &Path, udev_data: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dev_input) else { return out };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = e.path();
        let Ok(md) = fs::metadata(&path) else { continue };
        if !md.file_type().is_char_device() {
            continue;
        }
        let keep = if name.starts_with("js") {
            true
        } else if name.starts_with("event") {
            let rdev = md.rdev();
            let (major, minor) = (libc_major(rdev), libc_minor(rdev));
            fs::read_to_string(udev_data.join(format!("c{major}:{minor}")))
                .map(|t| t.lines().any(|l| l.trim() == "E:ID_INPUT_JOYSTICK=1"))
                .unwrap_or(false)
        } else {
            false
        };
        if keep {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn libc_major(dev: u64) -> u64 {
    ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff)
}

fn libc_minor(dev: u64) -> u64 {
    ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::backend::sample_context;

    fn args_of(ctx: &LaunchContext) -> Vec<String> {
        Bubblewrap.build(ctx).unwrap().args
    }

    fn has_seq(v: &[String], seq: &[&str]) -> bool {
        v.windows(seq.len()).any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
    }

    #[test]
    fn strict_profile() {
        let ctx = sample_context();
        let a = args_of(&ctx);
        assert!(a.contains(&"--unshare-net".to_string()));
        assert!(a.contains(&"--clearenv".to_string()));
        assert!(has_seq(&a, &["--cap-drop", "ALL"]));
        assert!(has_seq(&a, &["--ro-bind", "/data/extracted/appimage-hello-1234/AppDir", "/opt/app"]));
        assert!(has_seq(&a, &["--bind", "/data/homes/appimage-hello-1234", "/home/tester"]), "private home");
        assert!(!a.iter().any(|x| x == "/dev/dri"), "no GPU by default");
        assert!(!a.iter().any(|x| x.ends_with("/pipewire-0")), "no audio by default");
        assert!(!a.iter().any(|x| x == "/tmp/.X11-unix/X0"), "no X11 by default");
        assert!(has_seq(&a, &["--ro-bind", "/run/user/1000/wayland-0", "/run/user/1000/wayland-0"]));
        assert!(!a.iter().any(|x| x == "/home/tester/Documents"));
        assert!(has_seq(&a, &["--setenv", "APPDIR", "/opt/app"]));
        assert_eq!(a.last().unwrap(), "/opt/app/AppRun");
        assert!(!a.iter().any(|x| x == "/run/dbus/system_bus_socket"));
    }

    #[test]
    fn permissions_change_command() {
        let mut ctx = sample_context();
        let p = &mut ctx.permissions;
        p.network.mode = NetworkMode::Full;
        p.devices.gpu = true;
        p.audio.enabled = true;
        p.display.x11 = true;
        p.filesystem.documents = Access::Ro;
        p.dbus.session.mode = DbusMode::Full;
        let a = args_of(&ctx);
        assert!(!a.contains(&"--unshare-net".to_string()));
        assert!(has_seq(&a, &["--dev-bind-try", "/dev/dri", "/dev/dri"]));
        assert!(has_seq(&a, &["--ro-bind", "/run/user/1000/pipewire-0", "/run/user/1000/pipewire-0"]));
        assert!(has_seq(&a, &["--ro-bind", "/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0"]));
        assert!(has_seq(&a, &["--setenv", "DISPLAY", ":0"]));
        assert!(has_seq(&a, &["--setenv", "QT_QPA_PLATFORM", "wayland;xcb"]));
        assert!(has_seq(&a, &["--ro-bind", "/run/user/1000/bus", "/run/user/1000/bus"]));
        // Documents is never mounted read/write when granted read-only.
        assert!(!has_seq(&a, &["--bind-try", "/home/tester/Documents"]));
    }

    #[test]
    fn filtered_dbus_uses_proxy() {
        let mut ctx = sample_context();
        ctx.dbus_proxy_socket = Some("/run/user/1000/sam/x/bus".into());
        let a = args_of(&ctx);
        assert!(has_seq(&a, &["--ro-bind", "/run/user/1000/sam/x/bus", "/run/user/1000/bus"]));
        ctx.dbus_proxy_socket = None;
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(cmd.notes.iter().any(|n| n.contains("no proxy")));
        assert!(!has_seq(&cmd.args, &["--setenv", "DBUS_SESSION_BUS_ADDRESS"]));
    }

    #[test]
    fn experimental_network_falls_back_to_none() {
        let mut ctx = sample_context();
        ctx.permissions.network.mode = NetworkMode::Filtered;
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(cmd.args.contains(&"--unshare-net".to_string()));
        assert!(!cmd.notes.is_empty());
        // Localhost: the launcher wraps bwrap in pasta, which owns the netns.
        ctx.permissions.network.mode = NetworkMode::Localhost;
        assert!(!Bubblewrap.build(&ctx).unwrap().args.contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn writable_appdir_uses_overlay() {
        let mut ctx = sample_context();
        ctx.permissions.advanced.writable_appdir = true;
        ctx.appdir_overlay = Some("/data/overlays/x".into());
        let a = Bubblewrap.build(&ctx).unwrap().args;
        assert!(has_seq(&a, &["--overlay-src", "/data/extracted/appimage-hello-1234/AppDir", "--overlay", "/data/overlays/x/upper", "/data/overlays/x/work", "/opt/app"]));
    }

    #[test]
    fn helper_and_userns() {
        let mut ctx = sample_context();
        ctx.permissions.advanced.allow_userns = false;
        ctx.helper = Some(sam_core::backend::SandboxHelper { binary: "/usr/bin/sam-jail-run".into(), spec: "/tmp/spec.json".into() });
        let a = args_of(&ctx);
        assert!(a.contains(&"--disable-userns".to_string()));
        assert!(has_seq(&a, &["--", "/run/sam/sam-jail-run", "--sandbox-exec", "/run/sam/sandbox.json", "--", "/opt/app/AppRun"]));
    }

    #[test]
    fn gamepads_only_exposes_joysticks() {
        let t = tempfile::tempdir().unwrap();
        let (dev, udev) = (t.path().join("input"), t.path().join("udev"));
        fs::create_dir_all(&dev).unwrap();
        fs::create_dir_all(&udev).unwrap();
        // /dev/null is c1:3, /dev/zero is c1:5: stand-ins for a gamepad and a keyboard.
        std::os::unix::fs::symlink("/dev/null", dev.join("js0")).unwrap();
        std::os::unix::fs::symlink("/dev/null", dev.join("event7")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dev.join("event3")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dev.join("mice")).unwrap();
        fs::write(udev.join("c1:3"), "E:ID_INPUT=1\nE:ID_INPUT_JOYSTICK=1\n").unwrap();
        fs::write(udev.join("c1:5"), "E:ID_INPUT=1\nE:ID_INPUT_KEYBOARD=1\n").unwrap();
        let got = gamepad_nodes(&dev, &udev);
        assert_eq!(got, vec![dev.join("event7"), dev.join("js0")]);
    }


    #[test]
    fn nvidia_modules_are_exposed_with_the_gpu() {
        let t = tempfile::tempdir().unwrap();
        for m in ["nvidia", "nvidia_drm", "snd_hda_intel", "i915"] {
            fs::create_dir(t.path().join(m)).unwrap();
        }
        assert_eq!(gpu_module_dirs(t.path()), vec![t.path().join("nvidia"), t.path().join("nvidia_drm")]);
        assert!(gpu_module_dirs(&t.path().join("missing")).is_empty());
    }

}
