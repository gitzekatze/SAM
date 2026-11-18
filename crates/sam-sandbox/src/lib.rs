//! The Bubblewrap command builder.
//!
//! Sandbox layout:
//!
//! ```text
//! /opt/app              extracted AppImage payload, read-only
//! /usr/lib, /usr/bin    host runtime, read-only (all of /usr in compatibility mode)
//! /usr/share/<x>        whitelisted shared data (fonts, icons, locale, ...)
//! /etc/<x>              whitelisted configuration, generated passwd/group
//! /var/cache/fontconfig the system's font cache, read-only
//! /tmp, /var/tmp        private tmpfs
//! /run/user/<uid>       only the sockets that are granted
//! $HOME                 private per-app home (or tmpfs), plus granted folders
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sam_core::permissions::*;
use sam_core::places::{PROTECTED_RO, SENSITIVE_DOTFILES};
use sam_core::util::expand_home;
use sam_core::{BubblewrapStatus, HostInfo, LaunchContext, SandboxCommand};

pub struct Bubblewrap;

/// `/usr/share` entries exposed in minimal runtime mode. Safe, read-only data.
/// Host programs that ask a service outside the sandbox to start a program
/// (which would then run unsandboxed). Inside every sandbox each is
/// replaced by a stand-in from `TOOL_SHIMS` (see the /usr binding).
const HIDDEN_HOST_TOOLS: &[&str] = &["/usr/bin/systemd-run", "/usr/bin/flatpak-spawn"];

/// Stand-ins, written by `write_identity_files` into `<runtime>/tools`.
/// `systemd-run [options] CMD...` runs CMD directly, so it stays in the
/// sandbox; some AppRun scripts use systemd-run whenever it exists (e.g.
/// KeePassXC's, for a separate scope). `flatpak-spawn` refuses.
pub const TOOL_SHIMS: &[(&str, &str)] = &[
    (
        "systemd-run",
        r#"#!/bin/sh
# SAM: inside the sandbox, systemd-run runs the command directly (sandboxed).
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
    -u|-p|-E|-M|-H|--unit|--property|--slice|--description|--setenv|--uid|--gid|--nice|--working-directory|--machine|--host|--service-type|--on-active|--on-boot|--on-startup|--on-unit-active|--on-unit-inactive|--on-calendar|--timer-property|--path-property|--socket-property|--background|--json) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { echo "systemd-run: not available in SAM's sandbox" >&2; exit 1; }
exec "$@"
"#,
    ),
    (
        "flatpak-spawn",
        "#!/bin/sh\necho \"flatpak-spawn: not available in SAM's sandbox\" >&2\nexit 1\n",
    ),
];

const SHARE_BASE: &[&str] = &[
    // Which OpenGL/EGL driver to load: without these, an app that draws
    // with OpenGL (Flutter, GTK's GL area) finds no EGL at all, even for
    // drawing in software when it has no GPU access.
    "glvnd",
    "egl",
    "fonts",
    "fontconfig",
    "icons",
    // Image loaders of GTK (gdk-pixbuf 2.44+): without their configuration
    // GTK finds no loader and aborts at the first icon.
    "glycin-loaders",
    "locale",
    "zoneinfo",
    "themes",
    "mime",
    "X11",
    "glib-2.0",
    "pixmaps",
    "ca-certificates",
    "terminfo",
    "icu",
    "iso-codes",
    "misc",
    "file",
    "hwdata",
    "color-schemes",
    "kf6",
    "kf5",
    "qt",
    "qt5",
    "qt6",
    "gtk-2.0",
    "gtk-3.0",
    "gtk-4.0",
    "xml",
    "p11-kit",
    "libthai",
    "hunspell",
    "myspell",
    "mime-info",
    "sounds",
    // Keyboard layouts for xkbcommon. Newer distributions keep them here and
    // make /usr/share/X11/xkb a symlink to it; without it GTK and Electron
    // abort with "Failed to create XKB keymap".
    "xkeyboard-config-2",
    "xkeyboard-config",
];
const SHARE_GPU: &[&str] = &["vulkan", "drirc.d", "libdrm", "nvidia"];
const SHARE_AUDIO: &[&str] = &["alsa", "pipewire", "pulseaudio"];
const SHARE_DBUS: &[&str] = &["dbus-1"];

/// `/etc` entries always exposed (read-only).
const ETC_BASE: &[&str] = &[
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "fonts",
    "ssl",
    "ca-certificates",
    "pki",
    "crypto-policies",
    "localtime",
    "locale.conf",
    "locale.alias",
    "os-release",
    "xdg",
    "mime.types",
    "nsswitch.conf",
    "gtk-2.0",
    "gtk-3.0",
    "gtk-4.0",
    "timezone",
    "drirc",
    "glvnd",
    // Debian/Ubuntu: /usr/bin/java etc. are symlinks into /etc/alternatives.
    "alternatives",
];
const ETC_NETWORK: &[&str] = &[
    "resolv.conf",
    "hosts",
    "gai.conf",
    "services",
    "protocols",
    "host.conf",
];
const ETC_GPU: &[&str] = &["vulkan", "OpenCL", "nvidia"];
const ETC_AUDIO: &[&str] = &["alsa", "asound.conf", "pulse", "pipewire"];

/// Protected paths created (empty) before a full-home read/write start when
/// they are missing, so they can be mounted read-only: an app could create
/// them otherwise. Only where an empty one behaves like a missing one
/// (not `.bash_profile`, which hides `.profile`, `.xinitrc` or `.vimrc`).
const PROTECTED_CREATE_DIRS: &[&str] = &[
    ".local/share/applications",
    ".config/autostart",
    ".config/systemd",
    ".config/environment.d",
    ".local/bin",
    ".local/share/dbus-1",
    ".local/share/kwin",
    // An empty settings folder behaves like a missing one for these programs.
    ".config/fish",
    ".config/plasma-workspace",
    ".local/share/plasma",
    ".local/share/kservices5",
    ".local/share/kio/servicemenus",
    ".local/share/nautilus/scripts",
    ".config/git",
    ".config/nvim",
    ".config/tmux",
];
const PROTECTED_CREATE_FILES: &[&str] = &[
    ".bashrc",
    ".profile",
    ".gitconfig",
    ".config/mimeapps.list",
    // An empty one behaves like a missing one (`xdg-user-dir` answers the
    // home folder for both), and an app cannot create its own (checked for
    // audit S-F16, which assumed otherwise).
    ".config/user-dirs.dirs",
];

/// The protected places relative to the home: `PROTECTED_RO`, and the same
/// places under `XDG_CONFIG_HOME` and `XDG_DATA_HOME` when those point to
/// other folders inside the home (desktops and programs follow them, so
/// `~/cfg/autostart` starts programs as `~/.config/autostart` does; audit
/// S-F6).
fn protected_places(home: &Path) -> Vec<String> {
    let var = |v: &str| std::env::var_os(v).map(PathBuf::from);
    protected_places_with(home, var("XDG_CONFIG_HOME"), var("XDG_DATA_HOME"))
}

fn protected_places_with(
    home: &Path,
    config: Option<PathBuf>,
    data: Option<PathBuf>,
) -> Vec<String> {
    let mut out: Vec<String> = PROTECTED_RO.iter().map(|p| p.to_string()).collect();
    for (dir, default) in [(config, ".config/"), (data, ".local/share/")] {
        let Some(dir) = dir else {
            continue;
        };
        let Ok(rel) = dir.strip_prefix(home) else {
            continue;
        };
        let rel = rel.to_string_lossy().trim_end_matches('/').to_string();
        if rel.is_empty() || format!("{rel}/") == default {
            continue;
        }
        for p in PROTECTED_RO {
            if let Some(rest) = p.strip_prefix(default) {
                let alt = format!("{rel}/{rest}");
                if !out.contains(&alt) {
                    out.push(alt);
                }
            }
        }
    }
    out
}

/// Whether this start shows a place that makes the computer run something
/// (a start file, a menu entry, the folders above them, a key folder the
/// app was not given) writable, through any grant: the whole home, a user
/// folder, an extra folder, or a link to one of them. The one answer to
/// "can this start write the home's start places", for creating the
/// missing ones before the start and for looking again after it (audit
/// D-M3: only grants of the whole home counted, so a writable `~/.config`
/// let an app create `~/.config/autostart` and nobody looked).
pub fn writes_start_places(ctx: &LaunchContext) -> bool {
    let views = Views::base(ctx);
    let home = &ctx.host.home;
    watched_places(&ctx.permissions, home)
        .iter()
        .any(|rel| shown_writable(&views, &home.join(rel)))
}

/// Whether the sandbox shows `p` writable at any place.
fn shown_writable(views: &Views, p: &Path) -> bool {
    views.seen_at(p).iter().any(|c| views.writable(c))
}

/// The places whose appearance makes the computer run something later:
/// the start places, the folders above them, and the key folders the app
/// was not given (a planted ~/.ssh/authorized_keys or
/// ~/.gnupg/gpg-agent.conf would act later). Not the places hidden for
/// holding secrets: a browser creating its profile is fine.
fn watched_places(p: &PermissionSet, home: &Path) -> Vec<String> {
    let fs = &p.filesystem;
    let keys = [(".ssh", fs.ssh), (".gnupg", fs.gnupg)]
        .into_iter()
        .filter(|(_, granted)| !granted)
        .map(|(k, _)| k.to_string());
    protected_places(home)
        .into_iter()
        .chain(ancestors_of(
            protected_places(home).iter().map(String::as_str),
        ))
        .chain(keys)
        .collect()
}

/// Creates the missing protected paths of `PROTECTED_CREATE_*` in the real
/// home that this start would show writable ([`writes_start_places`]), so
/// they can be mounted read-only. Called by the launcher.
pub fn prepare_home_protection(ctx: &LaunchContext) {
    if !writes_start_places(ctx) {
        return;
    }
    let home = &ctx.host.home;
    let views = Views::base(ctx);
    for d in PROTECTED_CREATE_DIRS {
        let path = home.join(d);
        if fs::symlink_metadata(&path).is_err() && shown_writable(&views, &path) {
            let _ = fs::create_dir_all(&path);
        }
    }
    for f in PROTECTED_CREATE_FILES {
        let path = home.join(f);
        if fs::symlink_metadata(&path).is_err() && shown_writable(&views, &path) {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path);
        }
    }
}

/// The folders between the home and each protected path and each hidden
/// credential store (`.config`, `.local`, `.local/share`,
/// `.local/share/kio`, …), parents first: they are pinned so that nothing
/// under them can be renamed away.
fn protected_ancestors(home: &Path) -> Vec<String> {
    let places = protected_places(home);
    ancestors_of(
        places
            .iter()
            .map(String::as_str)
            .chain(SENSITIVE_DOTFILES.iter().copied()),
    )
}

/// The folders above each of `places` (relative to the home), parents first.
fn ancestors_of<'a>(places: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in places {
        let parts: Vec<&str> = p.split('/').collect();
        for n in 1..parts.len() {
            let a = parts[..n].join("/");
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out.sort_by_key(|a| a.matches('/').count());
    out
}

/// What a writable home held before a start, for the places whose mere
/// presence makes the computer run something and the links to protected
/// places. A mount cannot protect a file that does not exist yet (making
/// the mount point would create it), nor a link the app can replace: so
/// SAM looks again after the start ([`HomeWatch::settle`]).
#[derive(Debug, Default, Clone)]
pub struct HomeWatch {
    home: PathBuf,
    /// Protected paths that did not exist.
    absent: Vec<String>,
    /// Protected paths (and their parents) that were links: (path, target).
    links: Vec<(String, PathBuf)>,
}

/// Something an app left in a protected place, and where SAM moved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedAside {
    /// The place in the home, e.g. `.bash_profile`.
    pub place: String,
    /// Where it is now.
    pub to: PathBuf,
    /// How, when it could not go into SAM's folder: renamed in place,
    /// deleted, or (it must be said loudly) still there.
    pub how: Aside,
}

/// How something an app left in a protected place was taken out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aside {
    /// Moved into SAM's moved-aside folder.
    Moved,
    /// SAM's folder could not take it (another drive, a full disk): renamed
    /// next to where it was, to a name nothing reads.
    Renamed,
    /// Neither worked: deleted.
    Deleted,
    /// Nothing worked: it is still in its place and may act outside the
    /// sandbox.
    Failed,
}

impl HomeWatch {
    /// The snapshot before a start that can write a start place
    /// ([`writes_start_places`]); `None` otherwise.
    pub fn before(ctx: &LaunchContext) -> Option<HomeWatch> {
        if !writes_start_places(ctx) {
            return None;
        }
        let home = &ctx.host.home;
        let mut w = HomeWatch {
            home: home.to_path_buf(),
            ..Default::default()
        };
        for rel in watched_places(&ctx.permissions, home) {
            let path = home.join(&rel);
            match fs::symlink_metadata(&path) {
                Err(_) => w.absent.push(rel),
                Ok(m) if m.file_type().is_symlink() => {
                    if let Ok(t) = fs::read_link(&path) {
                        w.links.push((rel, t));
                    }
                }
                Ok(_) => {}
            }
        }
        Some(w)
    }

    /// The folders that hold the watched places: a change in one of them is
    /// the moment to look again (SAM's launcher watches them while the app
    /// runs, so a new startup file is moved aside at once, not only when the
    /// app ends).
    pub fn watched_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = Vec::new();
        for rel in self.absent.iter().chain(self.links.iter().map(|(r, _)| r)) {
            if let Some(parent) = self.home.join(rel).parent() {
                let parent = parent.to_path_buf();
                if parent.is_dir() && !dirs.contains(&parent) {
                    dirs.push(parent);
                }
            }
        }
        dirs
    }

    /// After the start: whatever appeared in a place that was empty, and
    /// whatever replaced a link, is moved into `aside` (keeping its place
    /// in the name), and the links are put back. Returns what was moved.
    pub fn settle(&self, aside: &Path) -> Vec<MovedAside> {
        let mut moved = Vec::new();
        // Never gives up silently (regression, audit L-F2: after 1000 names
        // per place, with SAM's folder on another drive or a full disk, the
        // file simply stayed, and nothing said so).
        let put_aside = |rel: &str| -> Option<(PathBuf, Aside)> {
            let from = self.home.join(rel);
            let name = rel.replace('/', "__");
            // A free name in `dir`; the same place moved again keeps both.
            let free = |dir: &Path, base: &str| {
                (0u64..)
                    .map(|n| {
                        dir.join(if n == 0 {
                            base.to_string()
                        } else {
                            format!("{base}.{n}")
                        })
                    })
                    .find(|p| fs::symlink_metadata(p).is_err())
            };
            if fs::create_dir_all(aside).is_ok() {
                if let Some(to) = free(aside, &name) {
                    if fs::rename(&from, &to).is_ok() {
                        return Some((to, Aside::Moved));
                    }
                }
            }
            // SAM's folder cannot take it: a name nothing reads, next to it.
            if let (Some(dir), Some(base)) = (from.parent(), from.file_name()) {
                let base = format!("{}.sam-moved-aside", base.to_string_lossy());
                if let Some(to) = free(dir, &base) {
                    if fs::rename(&from, &to).is_ok() {
                        return Some((to, Aside::Renamed));
                    }
                }
            }
            let gone = match fs::symlink_metadata(&from) {
                Ok(m) if m.is_dir() => fs::remove_dir_all(&from).is_ok(),
                Ok(_) => fs::remove_file(&from).is_ok(),
                Err(_) => true,
            };
            Some(if gone {
                (from, Aside::Deleted)
            } else {
                (from, Aside::Failed)
            })
        };
        for rel in &self.absent {
            // Inside a link's target or a moved folder only once.
            if fs::symlink_metadata(self.home.join(rel)).is_ok()
                && !self
                    .absent
                    .iter()
                    .any(|o| o != rel && rel.starts_with(&format!("{o}/")))
            {
                if let Some((to, how)) = put_aside(rel) {
                    moved.push(MovedAside {
                        place: rel.clone(),
                        to,
                        how,
                    });
                }
            }
        }
        for (rel, target) in &self.links {
            let path = self.home.join(rel);
            let same = fs::read_link(&path).is_ok_and(|t| &t == target);
            if !same {
                if fs::symlink_metadata(&path).is_ok() {
                    if let Some((to, how)) = put_aside(rel) {
                        moved.push(MovedAside {
                            place: rel.clone(),
                            to,
                            how,
                        });
                    }
                }
                let _ = std::os::unix::fs::symlink(target, &path);
            }
        }
        moved
    }
}

/// Host theme configuration (read-only) when `advanced.host_themes` is on.
const THEME_FILES: &[&str] = &[
    ".config/gtk-3.0",
    ".config/gtk-4.0",
    ".gtkrc-2.0",
    ".config/kdeglobals",
    ".config/Trolltech.conf",
    ".config/qt5ct",
    ".config/qt6ct",
    ".config/Kvantum",
    ".config/breezerc",
    ".config/kcminputrc",
    ".icons",
    ".local/share/icons",
    ".themes",
    ".local/share/themes",
    ".config/xsettingsd",
    ".local/share/color-schemes",
];

/// The value a forwarded variable gets inside the sandbox. When SAM's
/// window shows a language of its own, `LANGUAGE` is the system's from
/// before, so an app started from the window keeps the user's language.
fn forwarded_value(key: &str, get: impl Fn(&str) -> Option<String>) -> Option<String> {
    if key == "LANGUAGE" {
        if let Some(system) = get(sam_core::i18n::SYSTEM_LANGUAGE_VAR) {
            return (!system.is_empty()).then_some(system);
        }
    }
    get(key)
}

/// Host env vars forwarded by default (locale, scaling, theming).
const ENV_FORWARD: &[&str] = &[
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
    "TERM",
    "COLORTERM",
    "TZ",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
    "DESKTOP_SESSION",
    "KDE_FULL_SESSION",
    "KDE_SESSION_VERSION",
    "GTK_THEME",
    "XCURSOR_THEME",
    "XCURSOR_SIZE",
    "QT_SCALE_FACTOR",
    "QT_SCREEN_SCALE_FACTORS",
    "QT_AUTO_SCREEN_SCALE_FACTOR",
    "QT_ENABLE_HIGHDPI_SCALING",
    "GDK_SCALE",
    "GDK_DPI_SCALE",
    "QT_QPA_PLATFORMTHEME",
    "QT_STYLE_OVERRIDE",
    "XMODIFIERS",
    "GTK_IM_MODULE",
    "QT_IM_MODULE",
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
        self.v.extend([
            "--setenv".to_string(),
            k.to_string(),
            v.as_ref().to_string(),
        ]);
    }
}

/// Bind a whitelisted host path read-only, plus the targets of symlinks
/// that point outside it (the path itself, or entries one level inside).
/// Example: `/usr/share/X11/xkb -> /usr/share/xkeyboard-config-2`; without
/// the target, xkbcommon finds no keymaps and GTK/Electron abort.
fn ro_follow(a: &mut Args, path: &Path) {
    a.ro(path);
    let Ok(md) = fs::symlink_metadata(path) else {
        return;
    };
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
        let interesting =
            (t.starts_with("/usr/share") || t.starts_with("/etc") || t.starts_with("/run"))
                && t.exists();
        if interesting
            && !a
                .v
                .windows(2)
                .any(|w| w[0] == "--ro-bind-try" && Path::new(&w[1]) == t)
        {
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
pub const OPEN_SHIM_NAMES: &[&str] = &[
    "xdg-open",
    "xdg-email",
    "kde-open",
    "kde-open5",
    "kde-open6",
    "gnome-open",
    "sensible-browser",
    "x-www-browser",
    "www-browser",
];

/// The system every sandbox SAM builds rests on, after `/usr`: the
/// top-level links and folders (`/lib` → `usr/lib` …), the library folders
/// the system's loader searches outside /usr, and the basic files of /etc.
/// Shared by the apps' sandbox and the helpers SAM holds in a sandbox of
/// their own (the sound relay), so both see the same system on every
/// distribution.
fn common_system(a: &mut Args, host: &HostInfo) {
    for d in ["/bin", "/sbin", "/lib", "/lib64", "/lib32"] {
        mirror(a, d);
    }
    // Library folders the system's loader searches outside /usr (CUDA in
    // /opt/cuda/lib64, /usr/local/lib): /etc/ld.so.cache points there,
    // and SAM's analysis counts libraries found there as present.
    for d in &host.extra_lib_dirs {
        a.ro(d);
    }
    for e in ETC_BASE {
        ro_follow(a, &Path::new("/etc").join(e));
    }
    // openSUSE (and others following the "hermetic /usr" idea) keep the
    // vendor defaults of these files in /usr/etc and leave /etc for the
    // administrator's changes; glibc reads them from there. Only these
    // files, never all of /usr/etc (contract etc-identity-and-names).
    for e in [
        "nsswitch.conf",
        "services",
        "protocols",
        "gai.conf",
        "host.conf",
    ] {
        ro_follow(a, &Path::new("/usr/etc").join(e));
    }
}

/// The system part of a sandbox for one of SAM's own helpers (the sound
/// relay): `/usr` read-only and [`common_system`]. Nothing of the home, of
/// SAM's folders or of the devices; the caller adds what the helper needs.
pub fn helper_system_args(host: &HostInfo) -> Vec<String> {
    let mut a = Args { v: Vec::new() };
    a.op2("--ro-bind", "/usr", "/usr");
    common_system(&mut a, host);
    a.v
}

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

/// Where the sandbox shows the host's files: every grant (the home, the
/// user folders, extra folders, opened files, SAM's own binds), as the
/// paths they are mounted at, and whether each is writable. The checks
/// below ask "is this host path visible, and writable?" through it,
/// comparing resolved paths: Bubblewrap follows links, so comparing path
/// text missed a grant of `/data` when `/home` is a link to `/data/home`
/// (regression, audit S-F3).
pub struct Views {
    grants: Vec<(PathBuf, bool)>,
}

impl Views {
    /// Every grant, including files opened with the app and SAM's binds.
    pub fn of(ctx: &LaunchContext) -> Views {
        Views::with_opened(ctx, &opened_paths(ctx))
    }

    /// [`Views::of`] with the opened files already worked out.
    fn with_opened(ctx: &LaunchContext, opened: &[(PathBuf, bool)]) -> Views {
        let mut v = Views::base(ctx);
        v.grants.extend(opened.iter().cloned());
        for (_, sb, rw) in &ctx.extra_binds {
            v.grants.push((sb.clone(), *rw));
        }
        v
    }

    /// The grants of the permissions alone: the home, the user folders and
    /// extra folders (what `opened_paths` checks against).
    pub fn base(ctx: &LaunchContext) -> Views {
        let fsp = &ctx.permissions.filesystem;
        let mut grants = Vec::new();
        if fsp.home {
            grants.push((ctx.host.home.clone(), fsp.home_access == Access::Rw));
        }
        for key in XDG_DIR_KEYS {
            let acc = fsp.xdg_access(key);
            if acc.is_granted() {
                if let Ok(d) = user_dir(ctx, key) {
                    grants.push((d, acc == Access::Rw));
                }
            }
        }
        for c in &fsp.custom_read {
            grants.push((grant_path(c), false));
        }
        for c in &fsp.custom_write {
            grants.push((grant_path(c), true));
        }
        Views { grants }
    }

    /// The deepest grant that shows `p`, if any (a later, deeper mount wins).
    fn grant_of(&self, p: &Path) -> Option<&(PathBuf, bool)> {
        self.grants
            .iter()
            .filter(|(g, _)| p.starts_with(g))
            .max_by_key(|(g, _)| g.components().count())
    }

    pub fn visible(&self, p: &Path) -> bool {
        self.grant_of(p).is_some()
    }

    pub fn writable(&self, p: &Path) -> bool {
        self.grant_of(p).is_some_and(|(_, rw)| *rw)
    }

    /// Whether the sandbox shows `p`, or anything inside it.
    fn shows_any_of(&self, p: &Path) -> bool {
        self.visible(p) || self.grants.iter().any(|(g, _)| g.starts_with(p))
    }

    /// Every place in the sandbox where host path `p` is shown: its own path
    /// and, when that differs, its resolved one.
    pub fn seen_at(&self, p: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for c in [p.to_path_buf(), resolve(p)] {
            if self.visible(&c) && !out.contains(&c) {
                out.push(c);
            }
        }
        out
    }
}

/// Why a user folder (Documents, Downloads, …) is not shown.
#[derive(Debug, PartialEq)]
enum NotShown {
    Missing,
    /// It is the home, a folder above it, a system folder, a credential
    /// store, a start place or one of SAM's folders.
    Refused(PathBuf),
}

/// A granted user folder as it is bound: where `user-dirs.dirs` says it is,
/// with links resolved (what the app sees, as for extra folders). Never a
/// place that would show more than the folder: `user-dirs.dirs` is a plain
/// text file, and a line like `XDG_DOCUMENTS_DIR="/"` or one pointing at a
/// link to `/home` granted the whole computer or every home, without the
/// protections inside (audit S-F11).
fn user_dir(ctx: &LaunchContext, key: &str) -> std::result::Result<PathBuf, NotShown> {
    let dir = ctx.host.xdg_dir(key).ok_or(NotShown::Missing)?;
    let real = resolve(dir);
    let home = &ctx.host.home;
    if resolve(home).starts_with(&real) || refused_host_path(&real, home) || inside_sam(ctx, &real)
    {
        return Err(NotShown::Refused(dir.to_path_buf()));
    }
    Ok(real)
}

/// A host path SAM never shows on its own (a system folder, the home, a
/// key or credential store, a start place): the risk words call it
/// dangerous. Compared with the home as it is named and as it is reached
/// (a home under a link).
fn refused_host_path(p: &Path, home: &Path) -> bool {
    let p = p.to_string_lossy();
    sam_core::risk::is_sensitive_path_in(&p, home)
        || sam_core::risk::is_sensitive_path_in(&p, &resolve(home))
}

/// Whether `real` (a resolved path) is one of SAM's folders or inside one.
/// A folder that only holds one may be shown: SAM's folder is hidden
/// inside it, wherever the sandbox shows it.
fn inside_sam(ctx: &LaunchContext, real: &Path) -> bool {
    ctx.sam_dirs
        .iter()
        .map(|d| resolve(d))
        .any(|d| real.starts_with(&d))
}

/// A granted folder as it is bound: with `~` expanded and links resolved,
/// so the checks see what the app sees.
fn grant_path(c: &str) -> PathBuf {
    resolve(&expand_home(c))
}

/// `p` with links resolved as far as it exists (the rest appended).
fn resolve(p: &Path) -> PathBuf {
    if let Ok(r) = fs::canonicalize(p) {
        return r;
    }
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) if parent != p => resolve(parent).join(name),
        _ => p.to_path_buf(),
    }
}

/// Step 1 of the protections inside the shown parts of the real home: the
/// folders above protected places and above SAM's own folders that the
/// sandbox shows writable. Each becomes a mount point of its own (bound onto
/// itself, in the depth order of the other mounts), so it cannot be renamed
/// away together with the protection (`mv ~/.local/share ~/.local/s2` moved
/// SAM's records; regression, audit S-F4).
fn pins(home: &Path, views: &Views, sam_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut pins: Vec<PathBuf> = Vec::new();
    let mut pin = |p: &Path| {
        for c in views.seen_at(p) {
            // Never `/` or one folder below it: those are not renamed.
            if views.writable(&c)
                && c.components().count() > 2
                && fs::metadata(&c).is_ok_and(|m| m.is_dir())
                && !pins.contains(&c)
            {
                pins.push(c);
            }
        }
    };
    for d in protected_ancestors(home) {
        pin(&home.join(d));
    }
    for d in sam_dirs {
        for anc in d.ancestors().skip(1) {
            pin(anc);
        }
    }
    pins
}

/// Step 2 of the protections, after every mount (a later mount covers an
/// earlier one: a grant of `/home` or `~/.local` after them showed `~/.ssh`
/// and made autostart writable again; regression, audit S-F2): credential
/// stores hidden, start files and menu entries read-only, SAM's own folders
/// replaced by an empty folder, at every place the sandbox shows them.
fn guard_home(a: &mut Args, home: &Path, fsp: &FilesystemPerms, views: &Views) {
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
        let Ok(md) = fs::symlink_metadata(&path) else {
            continue;
        };
        // A link (dotfiles kept elsewhere, `stow`): hidden where it points,
        // which the app could reach through the link otherwise.
        let places = if md.file_type().is_symlink() {
            if !views.visible(&path) {
                continue;
            }
            fs::canonicalize(&path).into_iter().collect()
        } else {
            views.seen_at(&path)
        };
        for c in places {
            match fs::metadata(&c) {
                Ok(t) if t.is_dir() => {
                    a.push("--tmpfs").push(c.to_string_lossy());
                }
                Ok(t) if t.is_file() => a.op2("--ro-bind", "/dev/null", &c),
                _ => {}
            }
        }
    }
    for prot in protected_places(home) {
        let path = home.join(&prot);
        for c in views.seen_at(&path) {
            // A link (dotfiles kept elsewhere) cannot be mounted on: what it
            // points to is locked (also in `seen_at`), and the link itself
            // is put back after the start if the app replaces it
            // (regression: with `~/.bashrc` a link and the whole home
            // granted, Bubblewrap refused and no app started).
            if fs::symlink_metadata(&c).is_ok_and(|m| m.file_type().is_symlink()) {
                continue;
            }
            if matches!(prot.as_str(), ".config/sam" | ".local/share/sam") {
                if c.is_dir() {
                    a.push("--tmpfs").push(c.to_string_lossy());
                }
            } else if views.writable(&c) && c.exists() {
                a.ro(&c);
            }
        }
    }
}

/// Files and folders named on the command line ("Open with", or typed in a
/// terminal: `hx notes.txt`, `hx .`), granted for this launch only, like a
/// document portal; `true` means writable (`filesystem.opened_files`).
/// Relative names count from the folder the app was started in.
///
/// Never granted this way: options (`-x`), sensitive paths (keys and
/// credential stores, `~/.config`, `~/.local`, system folders), files and
/// folders that can make the desktop run something outside the sandbox
/// (start files of shells and the session, menu entries), SAM's own
/// folders wherever they are, the root, the home folder or a folder that
/// contains it, and folders outside the home folder and mounted drives.
/// Each is compared as named and as reached through links: with
/// `~/.bashrc` a link into `~/dotfiles`, opening `~/dotfiles` would share
/// the real start file (audit D-M2, S-F13).
pub fn opened_paths(ctx: &LaunchContext) -> Vec<(PathBuf, bool)> {
    let rw = ctx.permissions.filesystem.opened_files == Access::Rw;
    let home = &ctx.host.home;
    let on_drive = |p: &Path| {
        ["/media", "/mnt", "/run/media"]
            .iter()
            .any(|d| p.starts_with(d))
    };
    let views = Views::base(ctx);
    // Every place never shared, as named and where it really is. A folder
    // holding one of SAM's folders may be opened (SAM's folder is hidden
    // inside it); one holding a start place or a credential store not.
    let both = |p: PathBuf| {
        let r = resolve(&p);
        [p, r]
    };
    let keep_out: Vec<PathBuf> = protected_places(home)
        .iter()
        .map(String::as_str)
        .chain(SENSITIVE_DOTFILES.iter().copied())
        .chain([".ssh", ".gnupg"])
        .flat_map(|p| both(home.join(p)))
        .collect();
    let sam: Vec<PathBuf> = ctx.sam_dirs.iter().cloned().flat_map(both).collect();
    let mut out: Vec<(PathBuf, bool)> = Vec::new();
    for arg in &ctx.args {
        if arg.is_empty() || arg.starts_with('-') {
            continue;
        }
        let given = Path::new(arg);
        let joined = if given.is_absolute() {
            given.to_path_buf()
        } else {
            ctx.owd.join(given)
        };
        let Ok(real) = fs::canonicalize(&joined) else {
            continue;
        };
        let Ok(meta) = fs::metadata(&real) else {
            continue;
        };
        if refused_host_path(&joined, home)
            || refused_host_path(&real, home)
            || views.visible(&real)
        {
            continue;
        }
        let kept_out = keep_out
            .iter()
            .any(|p| real.starts_with(p) || (meta.is_dir() && p.starts_with(&real)))
            || sam.iter().any(|d| real.starts_with(d));
        if kept_out {
            continue;
        }
        if meta.is_dir() {
            if resolve(home).starts_with(&real)
                || !(real.starts_with(resolve(home)) || on_drive(&real))
            {
                continue;
            }
        } else if !meta.is_file() {
            continue;
        }
        if !out.iter().any(|(p, _)| real.starts_with(p)) {
            out.retain(|(p, _)| !p.starts_with(&real));
            out.push((real, rw));
        }
    }
    out
}

impl Bubblewrap {
    /// Whether Bubblewrap is installed and can create sandboxes here.
    pub fn status(&self, host: &HostInfo) -> BubblewrapStatus {
        let tool = host.tools.bwrap.as_ref();
        let mut notes = vec![];
        let installed = tool.is_some();
        if !installed {
            notes.push(sam_core::i18n::tr(
                "Bubblewrap is not installed. Install the 'bubblewrap' package.",
            ));
        }
        if !host.userns.usable() {
            notes.push(host.userns.explain());
        }
        if host.tools.xdg_dbus_proxy.is_none() {
            notes.push(sam_core::i18n::tr(
                "xdg-dbus-proxy not found: filtered session D-Bus will be disabled",
            ));
        }
        BubblewrapStatus {
            installed,
            path: tool.map(|t| t.path.clone()),
            version: tool.and_then(|t| t.version.clone()),
            usable: installed && host.userns.usable(),
            notes,
        }
    }

    /// The bwrap command line for this launch.
    pub fn build(&self, ctx: &LaunchContext) -> Result<SandboxCommand> {
        // Without a real home folder, "the home" is `/` or a relative path:
        // full home access would then bind the whole computer (audit S-F12).
        let home = &ctx.host.home;
        if !home.is_absolute() || home.components().count() < 2 {
            anyhow::bail!(
                "{}",
                sam_core::i18n::trf(
                    "the home folder is not set (HOME is \"{home}\"); SAM does not start apps without one",
                    &[("home", &home.display())]
                )
            );
        }
        let bwrap = ctx
            .host
            .tools
            .bwrap
            .as_ref()
            .context(sam_core::i18n::tr("bubblewrap (bwrap) is not installed"))?;
        // Each step adds its part of the Bubblewrap command, in this order.
        let opened = opened_paths(ctx);
        let views = Views::with_opened(ctx, &opened);
        let mut s = Section {
            ctx,
            a: Args { v: Vec::new() },
            notes: Vec::new(),
            keep_fds: Vec::new(),
            opened,
            views,
        };
        s.namespaces();
        s.system();
        s.identity_app_sys();
        s.home();
        s.display();
        s.audio();
        s.devices();
        s.dbus();
        s.sockets();
        s.environment();
        s.finish_command();
        let generated_files = vec![
            ctx.runtime_dir.join("passwd"),
            ctx.runtime_dir.join("group"),
            ctx.runtime_dir.join("hosts"),
        ];
        Ok(SandboxCommand {
            program: bwrap.path.clone(),
            args: s.a.v,
            env: vec![],
            clear_env: false,
            keep_fds: s.keep_fds,
            notes: s.notes,
            generated_files,
        })
    }
}

/// The Bubblewrap command, one part per method (see `Bubblewrap::build`).
struct Section<'c> {
    ctx: &'c LaunchContext,
    a: Args,
    notes: Vec<String>,
    keep_fds: Vec<i32>,
    /// The files named on the command line that are granted, worked out
    /// once per start (audit S-F13: four times before).
    opened: Vec<(PathBuf, bool)>,
    /// Every grant ([`Views::of`]).
    views: Views,
}

impl Section<'_> {
    /// Namespaces, ids and process hygiene.
    fn namespaces(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let a = &mut self.a;
        // Namespaces & process hygiene.
        a.push("--die-with-parent");
        if !ctx.own_terminal {
            a.push("--new-session");
        }
        a.push("--unshare-user")
            .push("--unshare-pid")
            .push("--unshare-uts")
            .push("--unshare-cgroup-try");
        // X11 apps share the IPC namespace (as with Flatpak's --share=ipc):
        // X11's shared-memory extension (MIT-SHM) needs the X server to see
        // the app's SysV shared memory, or GTK and Electron apps die with
        // BadAccess. X11 itself already exposes far more than that.
        if !(p.display.x11 && h.sockets.x11.is_some()) {
            a.push("--unshare-ipc");
        }
        // The user's own ids, also when bwrap runs inside pasta's namespace
        // (This computer only), where it would otherwise map to root: apps
        // then refuse to run (Electron) and the D-Bus proxy rejects them.
        a.push("--uid")
            .push(ctx.host.uid.to_string())
            .push("--gid")
            .push(ctx.host.gid.to_string());
        match p.network.mode {
            NetworkMode::Full => {}
            NetworkMode::None => {
                a.push("--unshare-net");
            }
            NetworkMode::Localhost => {
                // The launcher starts bwrap inside a pasta loopback-only
                // namespace (sam-runner netns.rs), so no --unshare-net here.
            }
        }
        if !p.advanced.allow_userns {
            a.push("--disable-userns");
        }
        // No --hostname: sethostname() is blocked by seccomp on some hardened
        // hosts and nested sandboxes; the UTS namespace alone is sufficient.
        a.push("--cap-drop").push("ALL");
        a.push("--clearenv");
    }

    /// The read-only system: /usr, selected /etc and /var, hidden host tools.
    fn system(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let run = Bubblewrap::runtime_dir(ctx);
        let a = &mut self.a;
        // Base filesystem.
        a.push("--proc").push("/proc");
        a.push("--dev").push("/dev");
        a.push("--tmpfs").push("/tmp");
        a.push("--tmpfs").push("/var/tmp");
        a.push("--dir").push("/run");
        a.push("--perms")
            .push("0700")
            .push("--tmpfs")
            .push(run.clone());

        match p.advanced.host_runtime {
            HostRuntime::Full => a.op2("--ro-bind", "/usr", "/usr"),
            HostRuntime::Minimal => {
                a.op2("--ro-bind", "/usr/lib", "/usr/lib");
                a.op2("--ro-bind-try", "/usr/bin", "/usr/bin");
                for d in ["/usr/lib64", "/usr/lib32", "/usr/libexec", "/usr/sbin"] {
                    mirror(a, d);
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
                    ro_follow(a, &Path::new("/usr/share").join(s));
                }
            }
        }
        common_system(a, &ctx.host);
        // Tools that ask a service outside the sandbox to start a program
        // (systemd, Flatpak). They would run it unsandboxed if the service
        // is reachable, and otherwise fail: some AppRun scripts use
        // systemd-run whenever it exists, so hiding it lets them start
        // normally. Hidden as an empty, non-executable file.
        // Links (run0 -> systemd-run) lead to a replaced file anyway, and
        // Bubblewrap cannot mount over a link.
        for t in HIDDEN_HOST_TOOLS {
            if fs::symlink_metadata(t).is_ok_and(|m| m.file_type().is_file()) {
                let name = Path::new(t).file_name().unwrap_or_default();
                a.op2("--ro-bind", ctx.runtime_dir.join("tools").join(name), *t);
            }
        }

        // /etc, beyond the basic files of `common_system`.
        let mut etc: Vec<&str> = Vec::new();
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
            ro_follow(a, &Path::new("/etc").join(e));
        }
        // The system's font cache: only names, paths and properties of the
        // fonts above. Without it every app builds its own on its first
        // start, which takes half a minute with many fonts (WezTerm: 35 s
        // before its window appeared).
        a.ro("/var/cache/fontconfig");
    }

    /// Generated passwd/group, the app folder (read-only or an overlay) and /sys.
    fn identity_app_sys(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let a = &mut self.a;
        // Synthetic passwd/group with only the current user.
        let passwd = ctx.runtime_dir.join("passwd");
        let group = ctx.runtime_dir.join("group");
        a.op2("--ro-bind-try", &passwd, "/etc/passwd");
        a.op2("--ro-bind-try", &group, "/etc/group");
        // Without the network, the real /etc/hosts stays hidden, but
        // "localhost" must still resolve: apps talk to their own helpers
        // and, with "This computer only", to local servers by that name.
        // Distributions without the myhostname module (Ubuntu, Debian)
        // resolve it only through /etc/hosts.
        if p.network.mode != NetworkMode::Full {
            a.op2("--ro-bind-try", ctx.runtime_dir.join("hosts"), "/etc/hosts");
        }

        // The app payload: read-only, or an overlay that keeps the app's own
        // changes in a separate per-app layer.
        match &ctx.appdir_overlay {
            Some(base) if p.advanced.writable_appdir => {
                a.push("--overlay-src").push(ctx.appdir.to_string_lossy());
                a.push("--overlay")
                    .push(base.join("upper").to_string_lossy())
                    .push(base.join("work").to_string_lossy())
                    .push(ctx.sandbox_appdir.to_string_lossy());
            }
            _ => a.op2("--ro-bind", &ctx.appdir, &ctx.sandbox_appdir),
        }
        // Bundled libraries replaced by the system's copy, read-only.
        for (host, inside) in system_library_binds(ctx) {
            a.op2("--ro-bind", host, inside);
        }
        if let Some(img) = &ctx.appimage_path {
            if let Some(name) = img.file_name() {
                a.op2("--ro-bind-try", img, Path::new("/run/sam").join(name));
            }
        }

        // /sys: CPU topology always; device trees when GPU/USB/input/webcam is granted.
        a.ro("/sys/devices/system/cpu");
        if p.devices.gpu
            || p.devices.usb
            || p.devices.input
            || p.devices.gamepads
            || p.devices.webcam
        {
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
    }

    /// The private home, granted folders and files, and the protections inside.
    ///
    /// The mounts are sorted by depth: a mount covers whatever was mounted
    /// at or below its place before it, so a shallow mount after a deep one
    /// would undo the deep one. The protections come after every grant
    /// (`guard_home`); SAM's own binds come last.
    fn home(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let home = h.home.clone();
        let notes = &mut self.notes;
        let fsp = &p.filesystem;
        let mut mounts: Vec<(usize, Args)> = Vec::new();
        let mut mount = |at: &Path, f: &dyn Fn(&mut Args)| {
            let mut m = Args { v: Vec::new() };
            f(&mut m);
            if !m.v.is_empty() {
                mounts.push((at.components().count(), m));
            }
        };
        // Home.
        if fsp.home {
            let op = if fsp.home_access == Access::Rw {
                "--bind"
            } else {
                "--ro-bind"
            };
            mount(&home, &|m| m.op2(op, &home, &home));
            // With the home read-only, a folder set to read/write must still
            // be writable (the switch says so; regression: it stayed
            // read-only).
            if fsp.home_access != Access::Rw {
                for key in XDG_DIR_KEYS {
                    if fsp.xdg_access(key) == Access::Rw {
                        if let Ok(dir) = user_dir(ctx, key) {
                            mount(&dir, &|m| m.op2("--bind-try", &dir, &dir));
                        }
                    }
                }
            }
        } else {
            if p.advanced.persistent_home {
                // The launch pipeline creates the directory; build() has no side effects.
                mount(&home, &|m| m.op2("--bind", &ctx.private_home, &home));
            } else {
                mount(&home, &|m| {
                    m.push("--tmpfs").push(home.to_string_lossy());
                });
            }
            // The folders every home has: some apps create theirs with a
            // plain mkdir and fail without the parent (night run 2026-11-18:
            // Widelands could not create ~/.local/share/widelands).
            for d in [".config", ".local/share", ".local/state", ".cache"] {
                let dir = home.join(d);
                mount(&dir, &|m| {
                    m.push("--dir").push(dir.to_string_lossy());
                });
            }
            for key in XDG_DIR_KEYS {
                let acc = fsp.xdg_access(key);
                if !acc.is_granted() {
                    continue;
                }
                match user_dir(ctx, key).and_then(|r| {
                    if r.exists() {
                        Ok(r)
                    } else {
                        Err(NotShown::Missing)
                    }
                }) {
                    Ok(real) => {
                        let op = if acc == Access::Rw {
                            "--bind-try"
                        } else {
                            "--ro-bind-try"
                        };
                        // At its real place, and a link where the app
                        // looks for it when that is a link on the host.
                        mount(&real, &|m| m.op2(op, &real, &real));
                        if let Some(dir) = h.xdg_dir(key).filter(|d| *d != real) {
                            mount(dir, &|m| m.op2("--symlink", &real, dir));
                        }
                    }
                    Err(NotShown::Missing) => notes.push(sam_core::i18n::trf(
                        "{key} folder does not exist on the host; not bound",
                        &[("key", &key)],
                    )),
                    Err(NotShown::Refused(dir)) => notes.push(sam_core::i18n::trf(
                        "{key} folder is set to {path}, which shows more than a user folder (the home, a folder above it, a system or SAM folder, or a protected place); not bound",
                        &[("key", &key), ("path", &dir.display())],
                    )),
                }
            }
        }
        // Safe read-only user resources.
        for r in [".local/share/fonts", ".fonts", ".config/fontconfig"] {
            let at = home.join(r);
            mount(&at, &|m| m.ro(&at));
        }
        if p.advanced.host_themes && !fsp.home {
            for t in THEME_FILES {
                let at = home.join(t);
                mount(&at, &|m| m.ro(&at));
            }
        }
        // Extra folders, at their resolved place: what the app sees there.
        for c in &fsp.custom_read {
            let path = grant_path(c);
            mount(&path, &|m| m.op2("--ro-bind-try", &path, &path));
        }
        for c in &fsp.custom_write {
            let path = grant_path(c);
            mount(&path, &|m| m.op2("--bind-try", &path, &path));
        }
        // Files and folders named on the command line, one by one.
        for (path, rw) in self.opened.clone() {
            mount(&path, &|m| {
                m.op2(
                    if rw { "--bind-try" } else { "--ro-bind-try" },
                    &path,
                    &path,
                )
            });
            notes.push(if path.is_dir() {
                sam_core::i18n::trf(
                    "granted access to the opened folder {path}",
                    &[("path", &path.display())],
                )
            } else {
                sam_core::i18n::trf(
                    "granted access to the opened file {path}",
                    &[("path", &path.display())],
                )
            });
        }
        let views = &self.views;
        for p in pins(&home, views, &ctx.sam_dirs) {
            mount(&p, &|m| m.op2("--bind", &p, &p));
        }
        // Stable: at equal depth, the order above stays (a pin after the
        // grant it is in).
        mounts.sort_by_key(|(d, _)| *d);
        let a = &mut self.a;
        for (_, m) in mounts {
            a.v.extend(m.v);
        }
        guard_home(a, &home, fsp, views);
        for (host_p, sb, rw) in &ctx.extra_binds {
            a.op2(if *rw { "--bind" } else { "--ro-bind" }, host_p, sb);
        }
    }

    /// Wayland and X11.
    fn display(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let run = Bubblewrap::runtime_dir(ctx);
        let a = &mut self.a;
        let notes = &mut self.notes;
        // Display.
        let mut session_type = "tty";
        if p.display.wayland {
            // The socket with a security context when the runner made one.
            match ctx.wayland_socket.as_ref().or(h.sockets.wayland.as_ref()) {
                Some(sock) => {
                    a.op2("--ro-bind", sock, format!("{run}/wayland-0"));
                    a.setenv("WAYLAND_DISPLAY", "wayland-0");
                    session_type = "wayland";
                }
                None => notes.push(sam_core::i18n::tr("Wayland socket not available")),
            }
        }
        if p.display.x11 {
            match (&h.sockets.x11, &h.sockets.x11_display) {
                (Some(sock), _) => {
                    // The display gets a number of its own inside (see
                    // SANDBOX_X11_DISPLAY), with the cookie rewritten to match.
                    let inner = sandbox_x11_display(&h.sockets);
                    a.op2("--ro-bind", sock, format!("/tmp/.X11-unix/X{inner}"));
                    a.setenv("DISPLAY", format!(":{inner}"));
                    let cookie = ctx.runtime_dir.join("Xauthority");
                    if h.sockets.xauthority.is_some() && cookie.exists() {
                        a.op2("--ro-bind", &cookie, format!("{run}/Xauthority"));
                        a.setenv("XAUTHORITY", format!("{run}/Xauthority"));
                    }
                    if session_type == "tty" {
                        session_type = "x11";
                    }
                }
                _ => notes.push(sam_core::i18n::tr("X11 display not available")),
            }
        }
        a.setenv("XDG_SESSION_TYPE", session_type);
        let (qt, gdk, sdl) = match (
            p.display.wayland && h.sockets.wayland.is_some(),
            p.display.x11 && h.sockets.x11.is_some(),
        ) {
            // Both: Qt chooses (Qt 6 takes Wayland in a Wayland session,
            // Qt 5 X11). The list form "wayland;xcb" stops Qt before 5.12.
            (true, true) => ("", "wayland,x11", "wayland,x11"),
            (true, false) => ("wayland", "wayland", "wayland"),
            (false, true) => ("xcb", "x11", "x11"),
            (false, false) => ("offscreen", "", ""),
        };
        if !qt.is_empty() {
            a.setenv("QT_QPA_PLATFORM", qt);
        }
        if !gdk.is_empty() {
            a.setenv("GDK_BACKEND", gdk);
            a.setenv("SDL_VIDEODRIVER", sdl);
        }
    }

    /// Sound.
    fn audio(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let run = Bubblewrap::runtime_dir(ctx);
        let a = &mut self.a;
        let notes = &mut self.notes;
        // Audio.
        // Sound goes through SAM's sound relay: a PulseAudio socket that
        // plays and records but cannot make the sound server load modules
        // (the sound server's own socket can: audit S-F1). Only when the
        // person allowed it, and the relay cannot run, the sound server's
        // own socket. The raw PipeWire socket reaches cameras and other
        // apps' screen-cast streams (PipeWire restricts only Flatpak apps),
        // so it needs its own permission. Webcam and screen sharing work
        // without it: their portals hand the app a PipeWire connection
        // limited to what the user picked.
        if p.audio.enabled {
            let pulse =
                ctx.sound_socket
                    .as_ref()
                    .or(h.sockets.pulse.as_ref().filter(|_| p.audio.direct));
            if let Some(pulse) = pulse {
                a.op2("--ro-bind", pulse, format!("{run}/pulse/native"));
                a.setenv("PULSE_SERVER", format!("unix:{run}/pulse/native"));
            } else if h.sockets.pulse.is_some() || h.sockets.pipewire.is_some() {
                notes.push(sam_core::i18n::tr("SAM's sound relay is not running, so the app has no sound (the sound server's own connection would let it load code outside the sandbox). The start message says why."));
            } else {
                notes.push(sam_core::i18n::tr(
                    "No sound server found. Audio may not work.",
                ));
            }
        }
        if p.audio.pipewire {
            if let Some(pw) = &h.sockets.pipewire {
                a.op2("--ro-bind", pw, format!("{run}/pipewire-0"));
            }
        }
        if p.audio.alsa_raw {
            a.op2("--dev-bind-try", "/dev/snd", "/dev/snd");
        }
    }

    /// GPU, webcam, game controllers, input, USB, Bluetooth.
    fn devices(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let a = &mut self.a;
        let notes = &mut self.notes;
        // Devices.
        if p.devices.gpu {
            a.op2("--dev-bind-try", "/dev/dri", "/dev/dri");
            for d in &h.gpu_devices {
                if d.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("nvidia"))
                {
                    a.op2("--dev-bind-try", d, d);
                }
            }
        }
        if p.devices.webcam {
            if let Ok(rd) = fs::read_dir("/dev") {
                let mut cams: Vec<PathBuf> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("video"))
                    })
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
                notes.push(sam_core::i18n::tr("No game controller is plugged in; controllers connected later are not seen until the app restarts"));
            }
            for d in pads {
                a.op2("--dev-bind-try", &d, &d);
            }
        }
        if p.devices.usb {
            a.op2("--dev-bind-try", "/dev/bus/usb", "/dev/bus/usb");
        }
        if p.devices.bluetooth && p.dbus.system.mode == DbusMode::None {
            notes.push(sam_core::i18n::tr(
                "Bluetooth needs the system D-Bus; not granted",
            ));
        }
        // Private shared memory: the host's /dev/shm would be a side channel
        // to other programs' segments.
        a.push("--tmpfs").push("/dev/shm");

        // Input methods: IBus talks to its portal frontend instead of its
        // private socket (Fcitx5 finds its portal frontend on its own).
        if p.integrations.input_method {
            a.setenv("IBUS_USE_PORTAL", "1");
            if p.dbus.session.mode == DbusMode::None {
                notes.push(sam_core::i18n::tr(
                    "Input method needs the session D-Bus; not granted",
                ));
            }
        }
    }

    /// Session and system bus (filtered through the proxy, full, or none).
    fn dbus(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let run = Bubblewrap::runtime_dir(ctx);
        let a = &mut self.a;
        let notes = &mut self.notes;
        // D-Bus.
        match p.dbus.session.mode {
            DbusMode::None => a.setenv("NO_AT_BRIDGE", "1"),
            DbusMode::Full => match &h.sockets.dbus_session {
                Some(sock) => {
                    a.op2("--ro-bind", sock, format!("{run}/bus"));
                    a.setenv("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"));
                }
                None => notes.push(sam_core::i18n::tr("session D-Bus socket not found")),
            },
            DbusMode::Filtered => match &ctx.dbus_proxy_socket {
                Some(proxy) => {
                    a.op2("--ro-bind", proxy, format!("{run}/bus"));
                    a.setenv("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"));
                }
                None => {
                    a.setenv("NO_AT_BRIDGE", "1");
                    notes.push(sam_core::i18n::tr("filtered D-Bus requested but no proxy is running (install xdg-dbus-proxy); session bus disabled"));
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
            DbusMode::Filtered => {} // loads as none; nothing is passed in
        }
    }

    /// Other sockets (SSH agent, …).
    fn sockets(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let run = Bubblewrap::runtime_dir(ctx);
        let a = &mut self.a;
        let notes = &mut self.notes;
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
        // Extra sockets: only real socket files, so this setting can never
        // grant access to a folder or an ordinary file.
        for s in &p.sockets.custom {
            let sp = expand_home(s);
            if is_socket(&sp) {
                a.op2("--bind-try", &sp, &sp);
            } else {
                notes.push(sam_core::i18n::trf(
                    "{path} is not a socket; it is not passed into the sandbox",
                    &[("path", &sp.display())],
                ));
            }
        }

        // SAM's own folders, wherever they are: an empty, throwaway folder
        // in their place whenever anything would show them: a grant, a
        // folder opened with the app ("Open with", a path on the command
        // line) or a bind of SAM's runner. Otherwise an app could change
        // another app's unpacked files (regression: an opened folder on a
        // drive that held SAM's moved unpack folder showed it, writable).
        // Every place the sandbox shows them, also through a link in a
        // granted path (audit S-F3).
        let views = &self.views;
        for d in &ctx.sam_dirs {
            // A folder inside another hidden one is hidden with it.
            let nested = ctx.sam_dirs.iter().any(|o| o != d && d.starts_with(o));
            if nested || !d.is_dir() {
                continue;
            }
            // Also where a grant shows only something inside it (audit
            // S-F13: a folder granted inside SAM's moved folder was shown).
            let mut places = views.seen_at(d);
            for c in [d.clone(), resolve(d)] {
                if views.shows_any_of(&c) && !places.contains(&c) {
                    places.push(c);
                }
            }
            for c in places {
                a.push("--tmpfs").push(c.to_string_lossy());
            }
            // Where a bind shows it under another path in the sandbox.
            for (h, sb, _) in &ctx.extra_binds {
                if h != sb {
                    if let Ok(rel) = d.strip_prefix(h) {
                        a.push("--tmpfs").push(sb.join(rel).to_string_lossy());
                    }
                }
            }
        }
    }

    /// The cleared environment, then only safe variables.
    fn environment(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let home = h.home.clone();
        let run = Bubblewrap::runtime_dir(ctx);
        let a = &mut self.a;
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
        let sound = p.audio.enabled
            && (ctx.sound_socket.is_some() || (p.audio.direct && h.sockets.pulse.is_some()));
        if !sound && !p.audio.alsa_raw {
            // Without sound access, SDL (games, emulators) finds no audio
            // output and refuses to start; its silent driver lets it run.
            // Before the settings below, which may choose otherwise.
            a.setenv("SDL_AUDIODRIVER", "dummy");
            a.setenv("SDL_AUDIO_DRIVER", "dummy");
        }
        for k in ENV_FORWARD
            .iter()
            .map(|s| s.to_string())
            .chain(p.environment.passthrough.iter().cloned())
        {
            if let Some(v) = forwarded_value(&k, |n| std::env::var(n).ok()) {
                a.setenv(&k, v);
            }
        }
        for (k, v) in ctx.resolved_app_env(&ctx.appdir_in_sandbox()) {
            a.setenv(&k, v);
        }
        for (k, v) in &p.environment.set {
            // Only proper variable names; values may be anything but NUL.
            let valid = k
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if valid && !v.contains('\0') {
                a.setenv(k, v);
            }
        }
    }

    /// Working directory, seccomp, SAM's helper (Landlock, syscall filter, the app's start), extra arguments, and the command itself.
    fn finish_command(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        let h = &ctx.host;
        let home = h.home.clone();
        let a = &mut self.a;
        let keep_fds = &mut self.keep_fds;
        // Working directory.
        // The folder it was started in, if the app sees it: granted, or
        // holding a file named on the command line (`hx notes.txt`), so that
        // relative names find the file.
        let in_owd = self
            .opened
            .iter()
            .any(|(p, _)| p.starts_with(&ctx.owd) || ctx.owd.starts_with(p));
        let views = &self.views;
        let chdir = if views.visible(&ctx.owd) || views.visible(&resolve(&ctx.owd)) || in_owd {
            ctx.owd.clone()
        } else {
            home.clone()
        };
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
            cmd.extend([
                "/run/sam/sam-jail-run".into(),
                "--sandbox-exec".into(),
                "/run/sam/sandbox.json".into(),
                "--".into(),
            ]);
        }
        if let Some(tracer) = &ctx.tracer {
            cmd.extend(tracer.iter().cloned());
        }
        for extra in &p.advanced.extra_bwrap_args {
            a.push(extra.clone());
        }
        // Everything is mounted: make the sandbox root itself read-only.
        // (/tmp, /var/tmp, $XDG_RUNTIME_DIR and $HOME are separate mounts.)
        a.push("--remount-ro").push("/");
        a.push("--");
        cmd.push(ctx.entry_in_sandbox());
        cmd.extend(ctx.args.iter().cloned());
        a.v.extend(cmd);
    }
}

/// Folders where AppImages bundle libraries, relative to the app folder.
const BUNDLED_LIB_DIRS: &[&str] = &[
    "usr/lib",
    "lib",
    "usr/lib64",
    "lib64",
    "usr/lib/x86_64-linux-gnu",
    "lib/x86_64-linux-gnu",
    "usr/lib/aarch64-linux-gnu",
    "lib/aarch64-linux-gnu",
];
/// Where the system keeps its libraries.
const SYSTEM_LIB_DIRS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
];

/// `(system copy, place inside the sandbox)` for every bundled library in
/// `advanced.system_libraries`. Only plain library names count, the
/// system copy must exist and resolve to a file under /usr or /lib, and
/// only libraries the app really bundles are replaced.
pub fn system_library_binds(ctx: &LaunchContext) -> Vec<(PathBuf, PathBuf)> {
    let mut out = Vec::new();
    for name in &ctx.permissions.advanced.system_libraries {
        if !is_library_name(name) {
            continue;
        }
        let Some(host) = SYSTEM_LIB_DIRS
            .iter()
            .filter_map(|d| fs::canonicalize(Path::new(d).join(name)).ok())
            .find(|p| p.is_file() && (p.starts_with("/usr") || p.starts_with("/lib")))
        else {
            continue;
        };
        for d in BUNDLED_LIB_DIRS {
            let rel = Path::new(d).join(name);
            if fs::symlink_metadata(ctx.appdir.join(&rel)).is_ok() {
                out.push((host.clone(), ctx.sandbox_appdir.join(&rel)));
            }
        }
    }
    out
}

/// Write the synthetic passwd/group files referenced by the command.
/// Display number of X11 inside every sandbox.
///
/// X11 libraries look for the display's *abstract* socket first. SAM's
/// Landlock layer blocks abstract sockets outside the sandbox, which newer
/// libxcb answers by using the socket file, but the older libxcb many
/// AppImages bundle stops at "permission denied" (Qt and Java apps then
/// cannot open a window even with X11 allowed). Under a number the host does
/// not use, the abstract lookup finds nothing ("not found"), and every libxcb
/// goes on to the socket file, which is the real display.
pub const SANDBOX_X11_DISPLAY: u32 = 99;

fn sandbox_x11_display(s: &sam_core::host::Sockets) -> u32 {
    let host = s
        .x11_display
        .as_deref()
        .and_then(sam_core::host::x11_display_number)
        .and_then(|n| n.parse::<u32>().ok());
    if host == Some(SANDBOX_X11_DISPLAY) {
        SANDBOX_X11_DISPLAY + 1
    } else {
        SANDBOX_X11_DISPLAY
    }
}

/// Copies the X11 cookies for the host display into the launch folder, with
/// the display number changed to the one the sandbox uses. Cookies for other
/// displays are left out.
fn write_xauthority(ctx: &LaunchContext) -> Result<()> {
    let s = &ctx.host.sockets;
    let (Some(src), Some(display)) = (&s.xauthority, &s.x11_display) else {
        return Ok(());
    };
    let Some(host_num) = sam_core::host::x11_display_number(display) else {
        return Ok(());
    };
    let Ok(data) = fs::read(src) else {
        return Ok(());
    };
    let out = rewrite_xauthority(&data, &host_num, &sandbox_x11_display(s).to_string());
    let dest = ctx.runtime_dir.join("Xauthority");
    fs::write(&dest, out)?;
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Xauthority records are: family (u16), then address, number, name and
/// data, each as a big-endian u16 length and the bytes. Records for display
/// `from` (or for any display, empty number) are kept with number `to`.
fn rewrite_xauthority(data: &[u8], from: &str, to: &str) -> Vec<u8> {
    fn field(d: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
        let len = u16::from_be_bytes([*d.get(*pos)?, *d.get(*pos + 1)?]) as usize;
        let v = d.get(*pos + 2..*pos + 2 + len)?.to_vec();
        *pos += 2 + len;
        Some(v)
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let family = [data[pos], data[pos + 1]];
        pos += 2;
        let (Some(addr), Some(num), Some(name), Some(cookie)) = (
            field(data, &mut pos),
            field(data, &mut pos),
            field(data, &mut pos),
            field(data, &mut pos),
        ) else {
            break;
        };
        if num != from.as_bytes() && !num.is_empty() {
            continue;
        }
        out.extend_from_slice(&family);
        for f in [
            addr.as_slice(),
            to.as_bytes(),
            name.as_slice(),
            cookie.as_slice(),
        ] {
            out.extend_from_slice(&(f.len() as u16).to_be_bytes());
            out.extend_from_slice(f);
        }
    }
    out
}

/// The /etc/hosts of a sandbox without the network: only the loopback names.
pub const LOCALHOST_ONLY_HOSTS: &str =
    "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n";

pub fn write_identity_files(ctx: &LaunchContext) -> Result<()> {
    fs::create_dir_all(&ctx.runtime_dir)?;
    let h = &ctx.host;
    if ctx.permissions.display.x11 {
        write_xauthority(ctx)?;
    }
    fs::write(
        ctx.runtime_dir.join("passwd"),
        format!(
            "{u}:x:{uid}:{gid}:{u}:{home}:/bin/sh\nnobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n",
            u = h.user,
            uid = h.uid,
            gid = h.gid,
            home = h.home.display()
        ),
    )?;
    fs::write(
        ctx.runtime_dir.join("group"),
        format!("{u}:x:{gid}:\nnobody:x:65534:\n", u = h.user, gid = h.gid),
    )?;
    fs::write(ctx.runtime_dir.join("hosts"), LOCALHOST_ONLY_HOSTS)?;
    let bin = ctx.runtime_dir.join("bin");
    fs::create_dir_all(&bin)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let tools = ctx.runtime_dir.join("tools");
        fs::create_dir_all(&tools)?;
        for (name, script) in TOOL_SHIMS {
            let f = tools.join(name);
            fs::write(&f, script)?;
            fs::set_permissions(&f, fs::Permissions::from_mode(0o755))?;
        }
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

/// True for an existing Unix socket (not a folder, file or device).
pub fn is_socket(p: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
}

/// Kernel module folders a GPU driver needs to see: NVIDIA's (`nvidia`,
/// `nvidia_drm`, `nvidia_modeset`, `nvidia_uvm`).
fn gpu_module_dirs(sys_module: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(sys_module)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("nvidia"))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Joystick device nodes: `js*`, plus `event*` nodes udev tagged as a
/// joystick (`E:ID_INPUT_JOYSTICK=1` in `/run/udev/data/c13:<minor>`).
/// Keyboards and mice are left out, so the app cannot log keystrokes.
pub fn gamepad_nodes(dev_input: &Path, udev_data: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dev_input) else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = e.path();
        let Ok(md) = fs::metadata(&path) else {
            continue;
        };
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
    use sam_core::sandbox::sample_context;

    fn args_of(ctx: &LaunchContext) -> Vec<String> {
        Bubblewrap.build(ctx).unwrap().args
    }

    fn has_seq(v: &[String], seq: &[&str]) -> bool {
        v.windows(seq.len())
            .any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
    }

    /// With the home read-only, a folder set to read/write stays writable;
    /// one set to read-only adds nothing (the home shows it read-only).
    #[test]
    fn a_writable_folder_stays_writable_in_a_read_only_home() {
        let mut ctx = sample_context();
        ctx.permissions.filesystem.home = true;
        ctx.permissions.filesystem.home_access = Access::Ro;
        ctx.permissions.filesystem.documents = Access::Rw;
        ctx.permissions.filesystem.pictures = Access::Ro;
        let a = args_of(&ctx);
        let home = a
            .windows(3)
            .position(|w| w == ["--ro-bind", "/home/tester", "/home/tester"])
            .expect("home read-only");
        let docs = a
            .windows(3)
            .position(|w| {
                w == [
                    "--bind-try",
                    "/home/tester/Documents",
                    "/home/tester/Documents",
                ]
            })
            .expect("Documents writable");
        assert!(docs > home, "after the home, so it wins");
        assert!(
            !a.iter().any(|x| x == "/home/tester/Pictures"),
            "read-only adds nothing"
        );
    }

    /// A helper's sandbox (the sound relay) shows the same system as an
    /// app's (with the whole /usr), and nothing outside the system's own
    /// folders: no home, no runtime folder, no devices.
    #[test]
    fn a_helper_sees_the_apps_system_and_nothing_else() {
        let mut ctx = sample_context();
        ctx.host.extra_lib_dirs = vec!["/opt/cuda/lib64".into()];
        ctx.permissions.advanced.host_runtime = HostRuntime::Full;
        let helper = helper_system_args(&ctx.host);
        let app = args_of(&ctx);
        assert!(has_seq(&helper, &["--ro-bind", "/usr", "/usr"]));
        let mut i = 0;
        while i < helper.len() {
            let op = helper[i].as_str();
            let n = if op == "--symlink" || op.starts_with("--ro-bind") {
                3
            } else {
                1
            };
            let part: Vec<&str> = helper[i..i + n].iter().map(String::as_str).collect();
            assert!(
                matches!(op, "--ro-bind" | "--ro-bind-try" | "--symlink"),
                "only read-only views and links: {part:?}"
            );
            let at = Path::new(part[n - 1]);
            assert!(
                [
                    "/usr",
                    "/etc",
                    "/bin",
                    "/sbin",
                    "/lib",
                    "/lib32",
                    "/lib64",
                    "/opt/cuda"
                ]
                .iter()
                .any(|r| at.starts_with(r)),
                "a system folder: {part:?}"
            );
            assert!(
                has_seq(&app, &part),
                "the app's sandbox has it too: {part:?}"
            );
            i += n;
        }
    }

    /// Games built with SDL get a silent sound driver when they have no
    /// sound, so they start instead of failing: sound off, or on but with
    /// SAM's relay not running (audit S-F1); not when sound reaches them.
    #[test]
    fn sdl_gets_its_silent_driver_without_sound_access() {
        let mut ctx = sample_context();
        let silent =
            |ctx: &LaunchContext| has_seq(&args_of(ctx), &["--setenv", "SDL_AUDIODRIVER", "dummy"]);
        assert!(silent(&ctx), "sound off");
        ctx.permissions.audio.enabled = true;
        assert!(silent(&ctx), "sound on, but no relay");
        ctx.sound_socket = Some("/run/user/1000/sam/x/sound/native".into());
        assert!(!args_of(&ctx).iter().any(|x| x == "SDL_AUDIODRIVER"));
        ctx.sound_socket = None;
        ctx.permissions.audio.direct = true;
        assert!(!silent(&ctx), "sound without the relay, allowed");
    }

    /// Sound comes from SAM's relay, never from the sound server's own
    /// socket; that one only when the person allowed sound without the
    /// relay (audit S-F1).
    #[test]
    fn sound_comes_from_the_relay_or_only_when_allowed_from_the_server() {
        let mut ctx = sample_context();
        ctx.permissions.audio.enabled = true;
        let host_pulse = "/run/user/1000/pulse/native";
        let shown = |ctx: &LaunchContext, from: &str| {
            has_seq(&args_of(ctx), &["--ro-bind", from, host_pulse])
        };
        assert!(!shown(&ctx, host_pulse), "no relay: no sound");
        ctx.sound_socket = Some("/run/user/1000/sam/x/sound/native".into());
        assert!(shown(&ctx, "/run/user/1000/sam/x/sound/native"));
        assert!(!shown(&ctx, host_pulse));
        ctx.permissions.audio.direct = true;
        assert!(
            shown(&ctx, "/run/user/1000/sam/x/sound/native"),
            "the relay wins when it runs"
        );
        ctx.sound_socket = None;
        assert!(shown(&ctx, host_pulse), "allowed without the relay");
        ctx.permissions.audio.enabled = false;
        assert!(!shown(&ctx, host_pulse), "sound off");
        // Without the relay the start says why there is no sound, also
        // where only PipeWire runs.
        ctx.permissions.audio.enabled = true;
        ctx.permissions.audio.direct = false;
        ctx.host.sockets.pulse = None;
        let notes = Bubblewrap.build(&ctx).unwrap().notes;
        assert!(notes.iter().any(|n| n.contains("relay")), "{notes:?}");
    }

    /// Extra library folders of the system loader (for example CUDA) are visible to the app read-only.
    #[test]
    fn the_loaders_extra_library_folders_are_shown_read_only() {
        let mut ctx = sample_context();
        ctx.host.extra_lib_dirs = vec!["/opt/cuda/lib64".into()];
        assert!(has_seq(
            &args_of(&ctx),
            &["--ro-bind-try", "/opt/cuda/lib64", "/opt/cuda/lib64"]
        ));
    }

    /// The app gets a new terminal session, unless it runs on SAM's terminal relay.
    #[test]
    fn a_new_session_unless_the_app_is_on_sams_own_terminal() {
        let mut ctx = sample_context();
        assert!(args_of(&ctx).iter().any(|a| a == "--new-session"));
        ctx.own_terminal = true;
        assert!(!args_of(&ctx).iter().any(|a| a == "--new-session"));
    }

    /// The machine ID identifies this computer; an app sees it only with
    /// D-Bus, which needs it, never without.
    #[test]
    fn the_machine_id_reaches_only_apps_with_dbus() {
        let mut ctx = sample_context();
        ctx.permissions.dbus.session.mode = DbusMode::None;
        ctx.permissions.dbus.system.mode = DbusMode::None;
        assert!(
            !args_of(&ctx).iter().any(|a| a == "/etc/machine-id"),
            "no D-Bus, no machine ID"
        );
        ctx.permissions.dbus.session.mode = DbusMode::Filtered;
        if Path::new("/etc/machine-id").exists() {
            assert!(
                args_of(&ctx).iter().any(|a| a == "/etc/machine-id"),
                "D-Bus needs the machine ID"
            );
        }
    }

    /// Files and folders named when starting an app are passed in, but never sensitive folders like autostart.
    #[test]
    fn files_and_folders_named_on_the_command_line() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        let proj = home.join("proj");
        fs::create_dir_all(proj.join("src")).unwrap();
        fs::create_dir_all(home.join(".config/autostart")).unwrap();
        fs::write(proj.join("notes.txt"), "x").unwrap();
        fs::write(home.join(".bashrc"), "x").unwrap();
        let outside = fs::canonicalize(t.path()).unwrap().join("elsewhere");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("file.txt"), "x").unwrap();
        let mut ctx = sample_context();
        ctx.host.home = home.clone();
        ctx.host.xdg_dirs.clear();
        ctx.owd = proj.clone();
        let granted = |args: &[&str], ctx: &mut LaunchContext| {
            ctx.args = args.iter().map(|a| a.to_string()).collect();
            opened_paths(ctx)
                .into_iter()
                .map(|(p, _)| p)
                .collect::<Vec<_>>()
        };
        // Relative to the start folder, and absolute; a folder covers its files.
        assert_eq!(
            granted(&["notes.txt"], &mut ctx),
            vec![proj.join("notes.txt")]
        );
        assert_eq!(granted(&["."], &mut ctx), vec![proj.clone()]);
        assert_eq!(
            granted(&["notes.txt", ".", "src"], &mut ctx),
            vec![proj.clone()]
        );
        assert_eq!(
            granted(&[outside.join("file.txt").to_str().unwrap()], &mut ctx),
            vec![outside.join("file.txt")],
            "a file anywhere"
        );
        // Never: options, missing files, the home folder or above, the
        // root, start files of the shell and the session, sensitive system
        // paths, folders outside the home folder and mounted drives.
        for args in [
            &["-c"][..],
            &["missing.txt"],
            &[".."],
            &[home.to_str().unwrap()],
            &["/"],
            &["../.bashrc"],
            &["../.config/autostart"],
            &["/etc/hosts"],
            // Sensitive and not otherwise visible in the sandbox: only the
            // sensitive-path rule keeps it out.
            &["/etc/shadow"],
            &[outside.to_str().unwrap()],
        ] {
            assert_eq!(granted(args, &mut ctx), Vec::<PathBuf>::new(), "{args:?}");
        }
        // Writable unless the profile shares opened files read-only.
        ctx.args = vec!["notes.txt".into()];
        assert!(opened_paths(&ctx)[0].1);
        ctx.permissions.filesystem.opened_files = Access::Ro;
        assert!(!opened_paths(&ctx)[0].1);
        // The sandbox binds it, and starts the app in that folder so the
        // relative name finds it.
        let a = args_of(&ctx);
        let f = proj.join("notes.txt").display().to_string();
        assert!(has_seq(&a, &["--ro-bind-try", &f, &f]));
        assert!(has_seq(&a, &["--chdir", proj.to_str().unwrap()]));
        ctx.args.clear();
        assert!(
            has_seq(&args_of(&ctx), &["--chdir", home.to_str().unwrap()]),
            "nothing named: the private home"
        );
    }

    /// The strictest profile builds a sandbox without network, environment or capabilities, with the app read-only.
    #[test]
    fn the_strictest_profile_shares_nothing_and_keeps_the_app_read_only() {
        let ctx = sample_context();
        let a = args_of(&ctx);
        assert!(a.contains(&"--unshare-net".to_string()));
        assert!(a.contains(&"--clearenv".to_string()));
        assert!(has_seq(&a, &["--cap-drop", "ALL"]));
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/data/extracted/appimage-hello-1234/AppDir",
                "/opt/app"
            ]
        ));
        assert!(
            has_seq(
                &a,
                &["--bind", "/data/homes/appimage-hello-1234", "/home/tester"]
            ),
            "private home"
        );
        assert!(!a.iter().any(|x| x == "/dev/dri"), "no GPU by default");
        assert!(
            !a.iter().any(|x| x.ends_with("/pipewire-0")),
            "no audio by default"
        );
        assert!(
            !a.iter().any(|x| x.starts_with("/tmp/.X11-unix")),
            "no X11 by default"
        );
        assert!(
            a.iter().any(|x| x == "--unshare-ipc"),
            "own IPC namespace without X11"
        );
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1000/wayland-0",
                "/run/user/1000/wayland-0"
            ]
        ));
        assert!(!a.iter().any(|x| x == "/home/tester/Documents"));
        assert!(has_seq(&a, &["--setenv", "APPDIR", "/opt/app"]));
        assert_eq!(a.last().unwrap(), "/opt/app/AppRun");
        assert!(!a.iter().any(|x| x == "/run/dbus/system_bus_socket"));
    }

    /// The X11 login cookie is rewritten for the display number inside the sandbox.
    #[test]
    fn xauthority_gets_the_sandbox_display_number() {
        fn rec(num: &str, cookie: &[u8]) -> Vec<u8> {
            let mut v = vec![0x01, 0x00]; // FamilyLocal
            for f in [
                b"host".as_slice(),
                num.as_bytes(),
                b"MIT-MAGIC-COOKIE-1".as_slice(),
                cookie,
            ] {
                v.extend_from_slice(&(f.len() as u16).to_be_bytes());
                v.extend_from_slice(f);
            }
            v
        }
        let mut file = rec("0", b"secret-for-0");
        file.extend(rec("1", b"secret-for-1"));
        let out = rewrite_xauthority(&file, "0", "99");
        assert_eq!(
            out,
            rec("99", b"secret-for-0"),
            "only display 0's cookie, renumbered"
        );
        assert!(
            rewrite_xauthority(&[1, 2, 3], "0", "99").is_empty(),
            "garbage is dropped"
        );
    }

    /// With a Wayland security context, the app sees only that socket, not the desktop's own.
    #[test]
    fn wayland_security_context_socket_is_used() {
        let mut ctx = sample_context();
        ctx.wayland_socket = Some("/run/user/1000/sam/x/launch-1/wayland-0".into());
        let a = args_of(&ctx);
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1000/sam/x/launch-1/wayland-0",
                "/run/user/1000/wayland-0"
            ]
        ));
        assert!(
            !has_seq(
                &a,
                &[
                    "--ro-bind",
                    "/run/user/1000/wayland-0",
                    "/run/user/1000/wayland-0"
                ]
            ),
            "not the compositor's own socket"
        );
    }

    /// Each granted permission adds exactly its part to the Bubblewrap command.
    #[test]
    fn each_permission_adds_exactly_its_part_to_the_command() {
        let mut ctx = sample_context();
        let p = &mut ctx.permissions;
        p.network.mode = NetworkMode::Full;
        p.devices.gpu = true;
        p.audio.enabled = true;
        p.display.x11 = true;
        p.filesystem.documents = Access::Ro;
        p.dbus.session.mode = DbusMode::Full;
        ctx.sound_socket = Some("/run/user/1000/sam/x/sound/native".into());
        let a = args_of(&ctx);
        assert!(!a.contains(&"--unshare-net".to_string()));
        assert!(has_seq(&a, &["--dev-bind-try", "/dev/dri", "/dev/dri"]));
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1000/sam/x/sound/native",
                "/run/user/1000/pulse/native"
            ]
        ));
        assert!(
            !a.iter().any(|x| x.ends_with("/pipewire-0")),
            "sound never brings the raw PipeWire socket"
        );
        assert!(
            has_seq(
                &a,
                &["--ro-bind", "/tmp/.X11-unix/X0", "/tmp/.X11-unix/X99"]
            ),
            "the host display under the sandbox's own number"
        );
        assert!(
            !a.iter().any(|x| x == "--unshare-ipc"),
            "X11 apps share IPC for MIT-SHM"
        );
        assert!(has_seq(&a, &["--setenv", "DISPLAY", ":99"]));
        assert!(
            !a.iter().any(|x| x == "QT_QPA_PLATFORM"),
            "with both displays Qt chooses itself"
        );
        assert!(has_seq(
            &a,
            &["--ro-bind", "/run/user/1000/bus", "/run/user/1000/bus"]
        ));
        // Documents is never mounted read/write when granted read-only.
        assert!(!has_seq(&a, &["--bind-try", "/home/tester/Documents"]));
    }

    /// The filtered desktop bus reaches the app only through SAM's proxy.
    #[test]
    fn filtered_dbus_uses_proxy() {
        let mut ctx = sample_context();
        ctx.dbus_proxy_socket = Some("/run/user/1000/sam/x/bus".into());
        let a = args_of(&ctx);
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1000/sam/x/bus",
                "/run/user/1000/bus"
            ]
        ));
        ctx.dbus_proxy_socket = None;
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(cmd.notes.iter().any(|n| n.contains("no proxy")));
        assert!(!has_seq(
            &cmd.args,
            &["--setenv", "DBUS_SESSION_BUS_ADDRESS"]
        ));
    }

    /// The app runs with the user's IDs, and host tools that could leave the sandbox (systemd-run) are replaced by harmless stand-ins.
    #[test]
    fn the_app_runs_as_the_user_and_host_tools_are_replaced_by_stand_ins() {
        let ctx = sample_context();
        let a = Bubblewrap.build(&ctx).unwrap().args;
        assert!(has_seq(
            &a,
            &[
                "--uid",
                &ctx.host.uid.to_string(),
                "--gid",
                &ctx.host.gid.to_string()
            ]
        ));
        if fs::symlink_metadata("/usr/bin/systemd-run").is_ok_and(|m| m.file_type().is_file()) {
            let shim = ctx
                .runtime_dir
                .join("tools/systemd-run")
                .display()
                .to_string();
            assert!(has_seq(&a, &["--ro-bind", &shim, "/usr/bin/systemd-run"]));
        }
        // The stand-in runs the command, skipping systemd-run's options.
        let (_, script) = TOOL_SHIMS
            .iter()
            .find(|(n, _)| *n == "systemd-run")
            .unwrap();
        let out = std::process::Command::new("sh")
            .args([
                "-c",
                script,
                "systemd-run",
                "--user",
                "--scope",
                "--slice=app.slice",
                "--unit",
                "x.scope",
                "echo",
                "ran",
            ])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ran");
    }

    /// With "this computer only", the network namespace is left to pasta.
    #[test]
    fn localhost_network_leaves_netns_to_pasta() {
        let mut ctx = sample_context();
        // Localhost: the launcher wraps bwrap in pasta, which owns the netns.
        ctx.permissions.network.mode = NetworkMode::Localhost;
        assert!(!Bubblewrap
            .build(&ctx)
            .unwrap()
            .args
            .contains(&"--unshare-net".to_string()));
    }

    /// A writable app folder uses an overlay; the unpacked app itself stays unchanged.
    #[test]
    fn writable_appdir_uses_overlay() {
        let mut ctx = sample_context();
        ctx.permissions.advanced.writable_appdir = true;
        ctx.appdir_overlay = Some("/data/overlays/x".into());
        let a = Bubblewrap.build(&ctx).unwrap().args;
        assert!(has_seq(
            &a,
            &[
                "--overlay-src",
                "/data/extracted/appimage-hello-1234/AppDir",
                "--overlay",
                "/data/overlays/x/upper",
                "/data/overlays/x/work",
                "/opt/app"
            ]
        ));
    }

    /// Without nested namespaces, the sandbox disables user namespaces and starts through SAM's helper.
    #[test]
    fn without_nested_namespaces_user_namespaces_are_disabled() {
        let mut ctx = sample_context();
        ctx.permissions.advanced.allow_userns = false;
        ctx.helper = Some(sam_core::sandbox::SandboxHelper {
            binary: "/usr/bin/sam-jail-run".into(),
            spec: "/tmp/spec.json".into(),
        });
        let a = args_of(&ctx);
        assert!(a.contains(&"--disable-userns".to_string()));
        assert!(has_seq(
            &a,
            &[
                "--",
                "/run/sam/sam-jail-run",
                "--sandbox-exec",
                "/run/sam/sandbox.json",
                "--",
                "/opt/app/AppRun"
            ]
        ));
    }

    /// "Game controllers" exposes only joysticks, never keyboards or mice.
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

    /// With the GPU, the NVIDIA driver modules are visible; other kernel modules are not.
    #[test]
    fn nvidia_modules_are_exposed_with_the_gpu() {
        let t = tempfile::tempdir().unwrap();
        for m in ["nvidia", "nvidia_drm", "snd_hda_intel", "i915"] {
            fs::create_dir(t.path().join(m)).unwrap();
        }
        assert_eq!(
            gpu_module_dirs(t.path()),
            vec![t.path().join("nvidia"), t.path().join("nvidia_drm")]
        );
        assert!(gpu_module_dirs(&t.path().join("missing")).is_empty());
    }

    /// Extra sockets are passed in only when they really are sockets.
    #[test]
    fn extra_sockets_must_be_sockets() {
        let t = tempfile::tempdir().unwrap();
        let sock = t.path().join("svc.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(is_socket(&sock));
        assert!(!is_socket(t.path()), "a folder is not a socket");
        let mut ctx = sample_context();
        ctx.permissions.sockets.custom =
            vec![sock.display().to_string(), t.path().display().to_string()];
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(cmd
            .args
            .windows(2)
            .any(|w| w[0] == "--bind-try" && w[1] == sock.display().to_string()));
        assert!(
            !cmd.args
                .iter()
                .any(|a| a == &t.path().display().to_string()),
            "folder not bound"
        );
    }

    /// A bundled library listed in advanced.system_libraries is replaced by
    /// the system's copy at its place in the app folder; names with folders
    /// or `..`, libraries the app does not bundle and libraries the system
    /// does not have are ignored.
    #[test]
    fn system_copies_replace_only_bundled_libraries_by_plain_name() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = sample_context();
        ctx.appdir = tmp.path().to_path_buf();
        fs::create_dir_all(tmp.path().join("usr/lib")).unwrap();
        // A library every Linux system has, bundled by the "app".
        let libc = [
            "/usr/lib/libc.so.6",
            "/usr/lib64/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/x86_64-linux-gnu/libc.so.6",
        ]
        .into_iter()
        .find(|p| Path::new(p).exists());
        let Some(_) = libc else { return };
        fs::write(tmp.path().join("usr/lib/libc.so.6"), "old").unwrap();
        ctx.permissions.advanced.system_libraries = vec![
            "libc.so.6".into(),
            "../../etc/shadow".into(),
            "libnotbundled.so.1".into(),
            "libz.so.1/../../x".into(),
        ];
        let binds = system_library_binds(&ctx);
        assert_eq!(binds.len(), 1, "{binds:?}");
        assert_eq!(binds[0].1, ctx.sandbox_appdir.join("usr/lib/libc.so.6"));
        assert!(binds[0].0.starts_with("/usr") || binds[0].0.starts_with("/lib"));
    }
}

/// Found by mutation testing: each of these changes weakened the sandbox
/// without any test noticing.
#[cfg(test)]
mod guard_tests {
    /// Whether the sandbox shows `p`, as named or as reached.
    fn visible_in_sandbox(p: &Path, ctx: &LaunchContext) -> bool {
        let v = Views::base(ctx);
        v.visible(p) || v.visible(&resolve(p))
    }

    use super::*;
    use sam_core::sandbox::sample_context;

    /// An app started from SAM's window keeps the system's language, even
    /// when the window itself shows another one.
    #[test]
    fn apps_keep_the_system_language_whatever_sams_window_shows() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let sys = sam_core::i18n::SYSTEM_LANGUAGE_VAR;
        // No language of its own: forwarded as it is.
        assert_eq!(
            forwarded_value("LANGUAGE", env(&[("LANGUAGE", "fr")])).as_deref(),
            Some("fr")
        );
        // The window shows German; the system had French.
        let both: &'static [(&str, &str)] = &[("LANGUAGE", "de"), ("SAM_SYSTEM_LANGUAGE", "fr")];
        assert_eq!(sys, "SAM_SYSTEM_LANGUAGE");
        assert_eq!(
            forwarded_value("LANGUAGE", env(both)).as_deref(),
            Some("fr")
        );
        // The window shows German; the system had no LANGUAGE at all.
        assert_eq!(
            forwarded_value(
                "LANGUAGE",
                env(&[("LANGUAGE", "de"), ("SAM_SYSTEM_LANGUAGE", "")])
            ),
            None
        );
        // Other variables are untouched.
        assert_eq!(forwarded_value("LANG", env(both)), None);
    }

    fn args_of(ctx: &LaunchContext) -> Vec<String> {
        Bubblewrap.build(ctx).unwrap().args
    }

    fn has_seq(v: &[String], seq: &[&str]) -> bool {
        v.windows(seq.len())
            .any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
    }

    /// The app's own folder stays read-only unless "writable app folder" is
    /// granted, even when SAM has an overlay for it prepared.
    #[test]
    fn the_app_folder_stays_read_only_unless_writable_is_granted() {
        let mut ctx = sample_context();
        ctx.appdir_overlay = Some("/data/overlays/app".into());
        let appdir = ctx.appdir.to_string_lossy().into_owned();
        let inside = ctx.sandbox_appdir.to_string_lossy().into_owned();
        let a = args_of(&ctx);
        assert!(has_seq(&a, &["--ro-bind", &appdir, &inside]), "{a:?}");
        assert!(
            !a.iter().any(|x| x == "--overlay"),
            "no writable layer without the grant"
        );
        ctx.permissions.advanced.writable_appdir = true;
        let a = args_of(&ctx);
        assert!(
            a.iter().any(|x| x == "--overlay") && !has_seq(&a, &["--ro-bind", &appdir, &inside])
        );
    }

    /// After a start with a writable home, only what could make the
    /// computer run something is moved aside: a new startup file, a replaced
    /// link to a protected folder, a key folder the app was not given. A
    /// browser creating its profile, or an app writing to ~/.ssh it was
    /// given, keeps its files.
    #[test]
    fn only_what_would_run_later_is_moved_aside() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(home.join(".config")).unwrap();
        fs::create_dir_all(home.join("dots/git")).unwrap();
        std::os::unix::fs::symlink(home.join("dots/git"), home.join(".config/git")).unwrap();
        let mut p = PermissionSet::default();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        assert!(
            HomeWatch::before(&ctx_for(&PermissionSet::default(), &home)).is_none(),
            "nothing to watch without a writable home"
        );
        let w = HomeWatch::before(&ctx_for(&p, &home)).unwrap();
        // What the app does.
        fs::write(home.join(".bash_profile"), "x").unwrap();
        fs::create_dir_all(home.join(".mozilla/firefox")).unwrap();
        fs::remove_file(home.join(".config/git")).unwrap();
        fs::create_dir_all(home.join(".config/git")).unwrap();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        let aside = t.path().join("aside");
        let moved: Vec<String> = w.settle(&aside).into_iter().map(|m| m.place).collect();
        assert!(moved.contains(&".bash_profile".to_string()), "{moved:?}");
        assert!(moved.contains(&".config/git".to_string()), "{moved:?}");
        assert!(
            moved.contains(&".ssh".to_string()),
            "a key folder the app was not given: {moved:?}"
        );
        assert!(
            !moved.iter().any(|m| m.starts_with(".mozilla")),
            "a browser profile stays: {moved:?}"
        );
        assert!(!home.join(".bash_profile").exists());
        assert_eq!(
            fs::read_link(home.join(".config/git")).unwrap(),
            home.join("dots/git"),
            "the link is back"
        );
        assert!(home.join(".mozilla/firefox").is_dir());
        // An app given ~/.ssh keeps what it creates there.
        fs::remove_dir_all(home.join(".ssh")).ok();
        p.filesystem.ssh = true;
        let w = HomeWatch::before(&ctx_for(&p, &home)).unwrap();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        assert!(w.settle(&aside).is_empty());
        assert!(home.join(".ssh").is_dir());
    }

    /// With a writable home, the folders above protected places are mount
    /// points of their own (so they cannot be renamed away), and a key
    /// folder that is a link is hidden where it points.
    #[test]
    fn protected_parents_are_locked_and_linked_keys_hidden() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        for d in [".config", ".local/share/kio", "dots/ssh"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(home.join("dots/ssh"), home.join(".ssh")).unwrap();
        let mut ctx = sample_context();
        ctx.host.home = home.clone();
        ctx.host.xdg_dirs.clear();
        ctx.permissions.filesystem.home = true;
        ctx.permissions.filesystem.home_access = Access::Rw;
        let a = args_of(&ctx);
        for d in [".config", ".local", ".local/share", ".local/share/kio"] {
            let p = home.join(d).to_string_lossy().into_owned();
            assert!(
                has_seq(&a, &["--bind", &p, &p]),
                "{d} is a mount point of its own"
            );
        }
        let target = home.join("dots/ssh").to_string_lossy().into_owned();
        assert!(
            has_seq(&a, &["--tmpfs", &target]),
            "the linked key folder is hidden where it points"
        );
        // Read-only home: nothing to lock.
        ctx.permissions.filesystem.home_access = Access::Ro;
        let c = home.join(".config").to_string_lossy().into_owned();
        assert!(!has_seq(&args_of(&ctx), &["--bind", &c, &c]));
    }

    /// A start of `p` with `home` as the home and no user folders.
    fn ctx_for(p: &PermissionSet, home: impl AsRef<Path>) -> LaunchContext {
        let mut c = sample_context();
        c.host.home = home.as_ref().to_path_buf();
        c.host.xdg_dirs.clear();
        c.permissions = p.clone();
        c
    }

    fn full_rw() -> PermissionSet {
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        p
    }

    /// A new start file is taken out of its place whatever happens, and
    /// never silently (audit L-F2): past 1000 earlier copies, into SAM's
    /// folder; when SAM's folder cannot take it, renamed in place to a name
    /// nothing reads; when nothing works, reported as still there.
    #[test]
    fn a_new_start_file_never_stays_silently() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let w = HomeWatch::before(&ctx_for(&full_rw(), &home)).unwrap();

        // 1001 earlier copies in SAM's folder.
        let aside = t.path().join("aside");
        fs::create_dir_all(&aside).unwrap();
        fs::write(aside.join(".bash_profile"), "old").unwrap();
        for n in 1..=1000 {
            fs::write(aside.join(format!(".bash_profile.{n}")), "old").unwrap();
        }
        fs::write(home.join(".bash_profile"), "evil").unwrap();
        let m = w.settle(&aside);
        let it = m.iter().find(|m| m.place == ".bash_profile").unwrap();
        assert_eq!(
            (it.how, it.to.clone()),
            (Aside::Moved, aside.join(".bash_profile.1001"))
        );
        assert!(!home.join(".bash_profile").exists());

        // SAM's folder cannot take it (here: its place is a file).
        let blocked = t.path().join("blocked");
        fs::write(&blocked, "").unwrap();
        fs::write(home.join(".bash_profile"), "evil").unwrap();
        let m = w.settle(&blocked.join("aside"));
        let it = m.iter().find(|m| m.place == ".bash_profile").unwrap();
        assert_eq!(it.how, Aside::Renamed);
        assert_eq!(it.to, home.join(".bash_profile.sam-moved-aside"));
        assert!(!home.join(".bash_profile").exists());

        // Nothing works (a home folder SAM cannot change): said so.
        let locked = t.path().join("locked");
        fs::create_dir_all(&locked).unwrap();
        let w2 = HomeWatch::before(&ctx_for(&full_rw(), &locked)).unwrap();
        fs::write(locked.join(".zshrc"), "evil").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
        let m = w2.settle(&blocked.join("aside"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        let it = m.iter().find(|m| m.place == ".zshrc").unwrap();
        assert_eq!(it.how, Aside::Failed, "{m:?}");
    }

    /// Start folders under another config or data folder in the home
    /// (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`) are protected like the usual
    /// ones, and the new places are on the list (audit S-F6).
    #[test]
    fn start_places_follow_other_config_and_data_folders() {
        let home = Path::new("/home/u");
        let p = protected_places_with(home, Some(home.join("cfg")), Some(home.join("data/")));
        for want in [
            "cfg/autostart",
            "cfg/systemd",
            "data/applications",
            "data/systemd",
            ".config/autostart",
            ".local/share/systemd",
            ".config/pipewire",
            ".config/sway",
        ] {
            assert!(p.iter().any(|x| x == want), "{want} missing");
        }
        // The usual folders, or ones outside the home, add nothing.
        let plain =
            protected_places_with(home, Some(home.join(".config")), Some("/elsewhere".into()));
        assert_eq!(plain.len(), PROTECTED_RO.len());
        // A config folder that is the home itself adds nothing either.
        let same = protected_places_with(home, Some(home.to_path_buf()), None);
        assert_eq!(
            same.len(),
            PROTECTED_RO.len(),
            "{:?}",
            &same[PROTECTED_RO.len()..]
        );
    }

    /// Paths are resolved through links also where they do not exist yet,
    /// the way Bubblewrap and the app see them (audit S-F3).
    #[test]
    fn paths_are_resolved_through_links_also_where_they_do_not_exist_yet() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("real")).unwrap();
        std::os::unix::fs::symlink(t.path().join("real"), t.path().join("link")).unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        assert_eq!(
            resolve(&t.path().join("link/missing/deeper")),
            base.join("real/missing/deeper")
        );
        assert_eq!(resolve(Path::new("/")), PathBuf::from("/"));
    }

    /// A path that leads into a granted folder through a link counts as
    /// visible, and one outside every grant does not (audit S-F3).
    #[test]
    fn a_path_through_a_link_into_a_grant_is_visible() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("file"), "x").unwrap();
        std::os::unix::fs::symlink(&real, t.path().join("link")).unwrap();
        let mut ctx = sample_context();
        ctx.permissions.filesystem.custom_read = vec![real.to_string_lossy().into_owned()];
        assert!(visible_in_sandbox(&t.path().join("link/file"), &ctx));
        assert!(visible_in_sandbox(&real.join("file"), &ctx));
        assert!(!visible_in_sandbox(&t.path().join("other"), &ctx));
    }

    /// Without a real home folder nothing starts: full home access would
    /// otherwise bind the whole computer (audit S-F12).
    #[test]
    fn a_missing_home_folder_stops_the_start() {
        for bad in ["/", "relative/home", ""] {
            let mut ctx = sample_context();
            ctx.host.home = PathBuf::from(bad);
            let e = Bubblewrap
                .build(&ctx)
                .map(|c| c.args)
                .unwrap_err()
                .to_string();
            assert!(e.contains("home folder is not set"), "{bad:?}: {e}");
        }
        assert!(Bubblewrap.build(&sample_context()).is_ok());
        // The root user's home is one folder below `/`: that is a home.
        let mut ctx = sample_context();
        ctx.host.home = PathBuf::from("/root");
        assert!(Bubblewrap.build(&ctx).is_ok());
    }

    /// SAM's own folders stay hidden when a granted folder contains them,
    /// and nothing extra is added when no grant shows them.
    #[test]
    fn sams_own_folders_stay_hidden_inside_a_granted_folder() {
        let t = tempfile::tempdir().unwrap();
        let sam = t.path().join("samdata");
        fs::create_dir(&sam).unwrap();
        let mut ctx = sample_context();
        ctx.sam_dirs = vec![sam.clone()];
        let sam_s = sam.to_string_lossy().into_owned();
        assert!(
            !has_seq(&args_of(&ctx), &["--tmpfs", &sam_s]),
            "not hidden when nothing shows it"
        );
        ctx.permissions.filesystem.custom_read = vec![t.path().to_string_lossy().into_owned()];
        assert!(
            has_seq(&args_of(&ctx), &["--tmpfs", &sam_s]),
            "hidden inside the granted folder"
        );
    }

    /// Keys, credential stores, start places (also behind a link) and SAM's
    /// own files named on the command line are never shared, whatever the
    /// home is called; an ordinary file is, and so is a folder that only
    /// holds SAM's folder (SAM's folder is hidden inside it) (audit D-M2,
    /// S-F13).
    #[test]
    fn keys_start_places_and_sams_files_are_never_opened() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        for d in [
            ".ssh",
            ".config/vivaldi/Default",
            "dotfiles",
            "Games/sam",
            "work",
        ] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        for f in [
            ".ssh/id_ed25519",
            ".netrc",
            ".config/vivaldi/Default/Login Data",
            "dotfiles/bashrc",
            "Games/sam/record.json",
            "work/a.txt",
        ] {
            fs::write(home.join(f), "x").unwrap();
        }
        std::os::unix::fs::symlink(home.join("dotfiles/bashrc"), home.join(".bashrc")).unwrap();
        let mut ctx = sample_context();
        ctx.host.home = home.clone();
        ctx.host.xdg_dirs.clear();
        ctx.owd = home.clone();
        ctx.sam_dirs = vec![home.join("Games/sam")];
        ctx.permissions.filesystem.opened_files = Access::Rw;
        for arg in [
            ".ssh/id_ed25519",
            ".netrc",
            ".config/vivaldi/Default/Login Data",
            ".bashrc",
            "dotfiles",
            "dotfiles/bashrc",
            "Games/sam/record.json",
        ] {
            ctx.args = vec![arg.into()];
            assert_eq!(opened_paths(&ctx), vec![], "{arg} is not shared");
        }
        for arg in ["work/a.txt", "Games"] {
            ctx.args = vec![arg.into()];
            assert_eq!(opened_paths(&ctx).len(), 1, "{arg} is shared");
        }
    }

    /// SAM's folder is hidden also when a grant shows only something inside
    /// it (audit S-F13): the grant does not reach SAM's files.
    #[test]
    fn a_grant_inside_sams_folder_does_not_show_it() {
        let t = tempfile::tempdir().unwrap();
        let sam = t.path().join("sam");
        fs::create_dir_all(sam.join("data/apps")).unwrap();
        let mut ctx = ctx_for(&PermissionSet::strict_gui(), t.path().join("home"));
        ctx.sam_dirs = vec![sam.clone()];
        let s = sam.to_string_lossy().into_owned();
        assert!(
            !has_seq(&args_of(&ctx), &["--tmpfs", &s]),
            "nothing shows it"
        );
        ctx.permissions.filesystem.custom_read =
            vec![sam.join("data/apps").to_string_lossy().into_owned()];
        assert!(has_seq(&args_of(&ctx), &["--tmpfs", &s]), "hidden");
    }

    /// Files named on the command line are judged with the home as named
    /// and as reached (a home under a link), by the name they are given
    /// (a file reached through `~/.config` is not shared), and a file a
    /// grant already shows is not added again.
    #[test]
    fn opened_files_are_judged_by_name_and_by_where_they_lead() {
        let t = tempfile::tempdir().unwrap();
        let real_home = t.path().join("real");
        for d in [".config/myapp", "work", "Documents"] {
            fs::create_dir_all(real_home.join(d)).unwrap();
        }
        for f in [".config/myapp/settings", "work/a.txt", "Documents/b.txt"] {
            fs::write(real_home.join(f), "x").unwrap();
        }
        std::os::unix::fs::symlink(real_home.join("work/a.txt"), real_home.join(".config/lnk"))
            .unwrap();
        let home = t.path().join("home");
        std::os::unix::fs::symlink(&real_home, &home).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.opened_files = Access::Rw;
        let mut ctx = ctx_for(&p, &home);
        ctx.owd = home.clone();
        let opened = |ctx: &mut LaunchContext, arg: PathBuf| {
            ctx.args = vec![arg.to_string_lossy().into_owned()];
            opened_paths(ctx)
        };
        assert_eq!(
            opened(&mut ctx, real_home.join(".config/myapp/settings")),
            vec![],
            "settings under the home as reached"
        );
        assert_eq!(
            opened(&mut ctx, home.join(".config/lnk")),
            vec![],
            "named through ~/.config"
        );
        assert_eq!(
            opened(&mut ctx, home.join("work/a.txt")).len(),
            1,
            "control"
        );
        ctx.permissions.filesystem.documents = Access::Rw;
        ctx.host
            .xdg_dirs
            .insert("documents".into(), home.join("Documents"));
        assert_eq!(
            opened(&mut ctx, home.join("Documents/b.txt")),
            vec![],
            "already shown by the Documents grant"
        );
    }

    /// A user folder set to the root, the folder above the home, a link to
    /// it, a key folder or SAM's folder is never shown; a usual one is, at
    /// its real place with a link where the app looks (audit S-F11).
    #[test]
    fn a_user_folder_that_shows_more_is_not_shown() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home/ann");
        for d in [".ssh", "real-docs", "sam"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(t.path().join("home"), home.join("up")).unwrap();
        std::os::unix::fs::symlink(home.join("real-docs"), home.join("Docs")).unwrap();
        let mut ctx = sample_context();
        ctx.host.home = home.clone();
        ctx.sam_dirs = vec![home.join("sam")];
        ctx.permissions.filesystem.documents = Access::Rw;
        let docs = |ctx: &mut LaunchContext, at: PathBuf| {
            ctx.host.xdg_dirs.clear();
            ctx.host.xdg_dirs.insert("documents".into(), at);
            user_dir(ctx, "documents")
        };
        for bad in [
            PathBuf::from("/"),
            t.path().join("home"),
            home.join("up"),
            home.join("up/ann/.ssh"),
            home.join(".ssh"),
            home.join("sam"),
            PathBuf::from("/etc"),
        ] {
            assert!(
                matches!(docs(&mut ctx, bad.clone()), Err(NotShown::Refused(_))),
                "{bad:?}"
            );
            let a = args_of(&ctx);
            assert!(
                !a.windows(2)
                    .any(|w| w[0] == "--bind-try" && Path::new(&w[1]) == bad),
                "{bad:?} not bound"
            );
        }
        // A folder that holds SAM's folder is shown, SAM's folder hidden
        // inside it.
        ctx.sam_dirs = vec![home.join("real-docs/sam")];
        fs::create_dir_all(home.join("real-docs/sam")).unwrap();
        let real = fs::canonicalize(home.join("real-docs")).unwrap();
        assert_eq!(docs(&mut ctx, home.join("Docs")), Ok(real.clone()));
        let sam = real.join("sam").to_string_lossy().into_owned();
        assert!(
            has_seq(&args_of(&ctx), &["--tmpfs", &sam]),
            "SAM's folder hidden"
        );
        let a = args_of(&ctx);
        let r = real.to_string_lossy().into_owned();
        let d = home.join("Docs").to_string_lossy().into_owned();
        assert!(has_seq(&a, &["--bind-try", &r, &r]), "{a:?}");
        assert!(has_seq(&a, &["--symlink", &r, &d]), "{a:?}");
    }

    /// Only a start that shows a start place writable is watched and
    /// prepared: a writable `~/.config` is (audit D-M3), a writable
    /// `~/.config/myapp` or Documents folder is not.
    #[test]
    fn a_writable_part_of_the_home_holding_start_places_is_watched() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        for d in [".config/myapp", "Documents"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![home.join(".config/myapp").to_string_lossy().into()];
        p.filesystem.documents = Access::Rw;
        let mut ctx = ctx_for(&p, &home);
        ctx.host
            .xdg_dirs
            .insert("documents".into(), home.join("Documents"));
        assert!(!writes_start_places(&ctx));
        assert!(HomeWatch::before(&ctx).is_none());
        prepare_home_protection(&ctx);
        assert!(!home.join(".config/autostart").exists(), "left alone");
        ctx.permissions.filesystem.custom_write =
            vec![home.join(".config").to_string_lossy().into()];
        assert!(writes_start_places(&ctx));
        let w = HomeWatch::before(&ctx).expect("watched");
        prepare_home_protection(&ctx);
        assert!(
            home.join(".config/autostart").is_dir(),
            "made, so it can be locked"
        );
        assert!(
            !home.join(".bashrc").exists(),
            "only what the grant shows is made"
        );
        fs::create_dir_all(home.join(".config/sway")).unwrap();
        fs::write(home.join(".config/sway/config"), "exec evil").unwrap();
        let moved: Vec<String> = w
            .settle(&t.path().join("aside"))
            .into_iter()
            .map(|m| m.place)
            .collect();
        assert!(moved.contains(&".config/sway".to_string()), "{moved:?}");
    }

    /// SAM's own folders stay hidden inside a folder opened with the app, and
    /// inside a runner's bind, at the path the bind shows them under.
    #[test]
    fn sams_own_folders_stay_hidden_inside_an_opened_folder() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let games = home.join("Games");
        let sam = games.join("sam-apps");
        fs::create_dir_all(&sam).unwrap();
        let mut ctx = sample_context();
        ctx.host.home = home.clone();
        ctx.host.xdg_dirs.clear();
        ctx.owd = home.clone();
        ctx.sam_dirs = vec![sam.clone()];
        let sam_s = sam.to_string_lossy().into_owned();
        assert!(
            !has_seq(&args_of(&ctx), &["--tmpfs", &sam_s]),
            "nothing shows it"
        );
        ctx.args = vec![games.to_string_lossy().into_owned()];
        assert_eq!(opened_paths(&ctx).len(), 1, "the folder is opened");
        assert!(
            has_seq(&args_of(&ctx), &["--tmpfs", &sam_s]),
            "hidden inside the opened folder"
        );
        ctx.args.clear();
        ctx.extra_binds = vec![(games.clone(), "/run/x".into(), true)];
        assert!(
            has_seq(&args_of(&ctx), &["--tmpfs", "/run/x/sam-apps"]),
            "hidden where a bind shows it"
        );
    }

    /// With the home writable, the file that says where the user folders
    /// are stays read-only, so an app cannot point other apps' Documents or
    /// Downloads grant at another folder.
    #[test]
    fn user_folder_locations_stay_read_only_with_a_writable_home() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path();
        fs::create_dir_all(home.join(".config")).unwrap();
        fs::write(
            home.join(".config/user-dirs.dirs"),
            "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n",
        )
        .unwrap();
        let mut ctx = sample_context();
        ctx.host.home = home.to_path_buf();
        ctx.permissions.filesystem.home = true;
        ctx.permissions.filesystem.home_access = Access::Rw;
        let f = home
            .join(".config/user-dirs.dirs")
            .to_string_lossy()
            .into_owned();
        assert!(
            has_seq(&args_of(&ctx), &["--ro-bind-try", &f, &f]),
            "read-only"
        );
        let empty = tempfile::tempdir().unwrap();
        prepare_home_protection(&ctx_for(&ctx.permissions, empty.path()));
        assert!(
            empty.path().join(".config/user-dirs.dirs").is_file(),
            "created empty when missing, so an app cannot create it"
        );
    }

    /// With the whole home granted, credential files are replaced by an
    /// empty file and credential folders by an empty folder.
    #[test]
    fn credential_files_and_folders_in_the_home_are_masked() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path();
        fs::write(home.join(".netrc"), "machine x password y").unwrap();
        fs::create_dir(home.join(".aws")).unwrap();
        fs::create_dir(home.join(".ssh")).unwrap();
        let mut ctx = sample_context();
        ctx.host.home = home.to_path_buf();
        ctx.permissions.filesystem.home = true;
        ctx.permissions.filesystem.home_access = Access::Rw;
        let a = args_of(&ctx);
        let p = |n: &str| home.join(n).to_string_lossy().into_owned();
        assert!(
            has_seq(&a, &["--ro-bind", "/dev/null", &p(".netrc")]),
            "{a:?}"
        );
        assert!(has_seq(&a, &["--tmpfs", &p(".aws")]));
        assert!(has_seq(&a, &["--tmpfs", &p(".ssh")]));
        assert!(
            !has_seq(&a, &["--tmpfs", &p(".netrc")]),
            "a file is not covered by a folder"
        );
    }

    /// Protected folders are created in the real home only before a start
    /// that can write the home, never otherwise.
    #[test]
    fn home_protection_is_prepared_only_for_a_writable_home() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path();
        let mut p = sample_context().permissions;
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        prepare_home_protection(&ctx_for(&p, home));
        assert!(
            !home.join(".config/autostart").exists(),
            "a read-only home is left alone"
        );
        p.filesystem.home_access = Access::Rw;
        prepare_home_protection(&ctx_for(&p, home));
        assert!(home.join(".config/autostart").is_dir() && home.join(".bashrc").is_file());
    }

    /// Only proper variable names are set inside the sandbox, and no value
    /// with a NUL byte.
    #[test]
    fn only_proper_variable_names_are_set() {
        let mut ctx = sample_context();
        for (k, v) in [
            ("_OK", "1"),
            ("Z9", "2"),
            ("9BAD", "3"),
            ("A-B", "4"),
            ("NUL", "a\0b"),
        ] {
            ctx.permissions.environment.set.insert(k.into(), v.into());
        }
        let a = args_of(&ctx);
        assert!(has_seq(&a, &["--setenv", "_OK", "1"]) && has_seq(&a, &["--setenv", "Z9", "2"]));
        for bad in ["9BAD", "A-B", "NUL"] {
            assert!(!has_seq(&a, &["--setenv", bad]), "{bad} is refused");
        }
    }
}
