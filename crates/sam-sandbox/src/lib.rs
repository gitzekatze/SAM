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

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use sam_core::permissions::*;
use sam_core::places::{
    protected_places, resolve, sensitive_places, start_place_of_bound_write_grant,
    UserFolderRefused,
};
use sam_core::util::expand_home;
use sam_core::{BubblewrapStatus, HostInfo, LaunchContext, SandboxCommand};

pub struct Bubblewrap;

/// Host programs that ask a service outside the sandbox to start a program
/// (which would then run unsandboxed). Inside every sandbox each is
/// replaced by a stand-in from `TOOL_SHIMS` (see the /usr binding).
pub const HIDDEN_HOST_TOOLS: &[&str] = &["/usr/bin/systemd-run", "/usr/bin/flatpak-spawn"];

/// For each host tool that exists: its name and the file to cover with
/// the stand-in, which is the file a link (or a chain of links) leads to.
fn hidden_tool_targets(tools: &[&str]) -> Vec<(std::ffi::OsString, PathBuf)> {
    tools
        .iter()
        .filter_map(|t| {
            let real = fs::canonicalize(t).ok().filter(|r| r.is_file())?;
            Some((Path::new(t).file_name()?.to_os_string(), real))
        })
        .collect()
}

/// Covers each of `tools` that exists with its stand-in from
/// `<runtime_dir>/tools` (written by [`write_identity_files`]).
fn cover_host_tools(a: &mut Args, runtime_dir: &Path, tools: &[&str]) {
    for (name, target) in hidden_tool_targets(tools) {
        a.op2("--ro-bind", runtime_dir.join("tools").join(name), target);
    }
}

/// The Bubblewrap arguments with which every sandbox covers the host tools
/// `tools` by their stand-ins ([`HIDDEN_HOST_TOOLS`] in every sandbox; a
/// test passes tools of its own, since not every computer has them all).
pub fn host_tool_stand_in_args(runtime_dir: &Path, tools: &[&str]) -> Vec<String> {
    let mut a = Args::default();
    cover_host_tools(&mut a, runtime_dir, tools);
    a.v
}

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
    -u|-p|-E|-M|-H|-C|--unit|--property|--slice|--description|--setenv|--uid|--gid|--nice|--working-directory|--machine|--host|--capsule|--service-type|--job-mode|--on-active|--on-boot|--on-startup|--on-unit-active|--on-unit-inactive|--on-calendar|--timer-property|--path-property|--socket-property|--background|--json|--expand-environment|-g|--group|-D|--chdir|--area|--shell-prefix|--lightweight) shift 2 ;;
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

/// `/usr/share` entries exposed in minimal runtime mode. Safe, read-only data.
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

/// Protected paths created (empty) before a start that shows them writable
/// when they are missing, so they can be mounted read-only: an app could
/// create them otherwise. Not while another launch watches one as empty
/// ([`prepare_home_protection_alongside`]). Only where an empty one behaves
/// like a missing one (not `.bash_profile`, which hides `.profile`,
/// `.xinitrc` or `.vimrc`).
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
    // audit S-F16, which assumed otherwise). Made also where it follows
    // `XDG_CONFIG_HOME` ([`prepare_home_protection_alongside`]).
    ".config/user-dirs.dirs",
];

/// `XDG_CONFIG_HOME` or `XDG_DATA_HOME` when its name is not valid text or
/// holds `..`: the start places below it could not be named, or not
/// without `..`, which a record of them may not hold, so they would go
/// unprotected (independent reviews of PR 131 and PR 134).
pub fn odd_config_folder(config: Option<&Path>, data: Option<&Path>) -> Option<PathBuf> {
    [config, data]
        .into_iter()
        .flatten()
        .find(|d| d.to_str().is_none() || d.components().any(|c| matches!(c, Component::ParentDir)))
        .map(Path::to_path_buf)
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
    let keys = [(".ssh", fs.ssh_given()), (".gnupg", fs.gnupg_given())]
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
/// home, and `user-dirs.dirs` where it follows `XDG_CONFIG_HOME` inside
/// the home, that this start would show writable
/// ([`writes_start_places`]), so they can be mounted read-only.
pub fn prepare_home_protection(ctx: &LaunchContext) {
    prepare_home_protection_alongside(ctx, &[]);
}

/// [`prepare_home_protection`] while other launches that watch the same home
/// are running (`running`); called by the launcher. A place that one of them
/// saw empty at its start is not made: their watch moves whatever appears
/// there aside, SAM's own empty folder too. The new launch would then lose
/// its read-only mount at once, and the person would be told of something
/// moved aside that no app had made (review B2 R52). Such a place stays
/// empty and watched by every launch, as the places SAM never makes
/// (`.bash_profile`) are.
pub fn prepare_home_protection_alongside(ctx: &LaunchContext, running: &[HomeWatch]) {
    if !writes_start_places(ctx) {
        return;
    }
    let home = &ctx.host.home;
    let views = Views::base(ctx);
    // A folder above the place counts too: a record from an older SAM may
    // not name every place this one makes.
    let watched_empty = |place: &str| {
        running.iter().any(|r| {
            &r.home == home
                && r.absent
                    .iter()
                    .any(|a| a == place || place.starts_with(&format!("{a}/")))
        })
    };
    for d in PROTECTED_CREATE_DIRS {
        let path = home.join(d);
        if fs::symlink_metadata(&path).is_err()
            && shown_writable(&views, &path)
            && !watched_empty(d)
        {
            let _ = fs::create_dir_all(&path);
        }
    }
    // The file SAM reads the user folders from also where it follows
    // `XDG_CONFIG_HOME` (`~/cfg/user-dirs.dirs`, or `~/user-dirs.dirs` when
    // the variable names the home): only an existing one is locked, and
    // one the app wrote while it was missing told a start running at the
    // same time where Documents is.
    let user_dirs = protected_places(home)
        .into_iter()
        .filter(|p| Path::new(p).file_name() == Some("user-dirs.dirs".as_ref()));
    let files: Vec<String> = PROTECTED_CREATE_FILES
        .iter()
        .map(|f| f.to_string())
        .chain(user_dirs)
        .collect();
    for f in &files {
        let path = home.join(f);
        if fs::symlink_metadata(&path).is_err()
            && shown_writable(&views, &path)
            && !watched_empty(f)
        {
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
    let stores = sensitive_places(home);
    ancestors_of(places.iter().chain(&stores).map(String::as_str))
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
        HomeWatch::before_alongside(ctx, &[])
    }

    /// [`HomeWatch::before`] while other launches that watch the same home
    /// are running (`running`, oldest first). What they saw at their start
    /// is taken over, not what is there now: a place that was empty then
    /// stays empty, a link stays the link it was. Otherwise a second launch
    /// took a link another app had planted while it ran for the user's own,
    /// and put it back each time it was moved aside (review 2026-11-23 F1).
    pub fn before_alongside(ctx: &LaunchContext, running: &[HomeWatch]) -> Option<HomeWatch> {
        if !writes_start_places(ctx) {
            return None;
        }
        let home = &ctx.host.home;
        let mut w = HomeWatch {
            home: home.to_path_buf(),
            ..Default::default()
        };
        let running: Vec<&HomeWatch> = running.iter().filter(|r| &r.home == home).collect();
        for rel in watched_places(&ctx.permissions, home) {
            if running.iter().any(|r| r.absent.contains(&rel)) {
                w.absent.push(rel);
                continue;
            }
            if let Some(t) = running
                .iter()
                .find_map(|r| r.links.iter().find(|(l, _)| l == &rel).map(|(_, t)| t))
            {
                w.links.push((rel, t.clone()));
                continue;
            }
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
        // The way a protected place leads, inside the home: every further
        // link on it, and the first part of it that does not exist. The
        // app could replace such a link (`~/.profile` to `cfg/profile`,
        // `~/cfg` a link of its own) or create the missing part
        // (`~/.zshrc` to `.dotfiles/zshrc`, no `~/.dotfiles`): the
        // protected link stays as it was and leads to the app's file
        // outside the sandbox (review B2 S3, R51). Taken over from running
        // launches as above.
        let real_home = resolve(home);
        let in_home = |p: &Path| -> Option<String> {
            [home, real_home.as_path()]
                .iter()
                .find_map(|h| p.strip_prefix(h).ok())
                .filter(|r| !r.as_os_str().is_empty())
                .and_then(|r| r.to_str().map(String::from))
        };
        for rel in watched_places(&ctx.permissions, home) {
            let (links, missing) = way_to(&home.join(&rel));
            let found = links
                .into_iter()
                .filter_map(|(at, t)| Some((in_home(&at)?, Some(t))))
                .chain(missing.and_then(|m| Some((in_home(&m)?, None))));
            for (r, target) in found {
                if w.absent.contains(&r) || w.links.iter().any(|(l, _)| l == &r) {
                    continue;
                }
                if running.iter().any(|o| o.absent.contains(&r)) {
                    w.absent.push(r);
                } else if let Some(t) = running
                    .iter()
                    .find_map(|o| o.links.iter().find(|(l, _)| l == &r).map(|(_, t)| t))
                {
                    w.links.push((r, t.clone()));
                } else if let Some(t) = target {
                    w.links.push((r, t));
                } else {
                    w.absent.push(r);
                }
            }
        }
        // And every other place a launch alongside recorded: what the app
        // there already changed (a link replaced, a missing place made) is
        // no longer on today's way, yet must stay watched here as well.
        for o in &running {
            for a in &o.absent {
                if !w.absent.contains(a) && !w.links.iter().any(|(l, _)| l == a) {
                    w.absent.push(a.clone());
                }
            }
            for (l, t) in &o.links {
                if !w.absent.contains(l) && !w.links.iter().any(|(x, _)| x == l) {
                    w.links.push((l.clone(), t.clone()));
                }
            }
        }
        Some(w)
    }

    /// The watch as lines of text, for keeping it on disk while the app
    /// runs: SAM can then still look again when its launcher was killed.
    /// Paths are written as hex, so any name survives.
    pub fn to_lines(&self) -> Vec<String> {
        use std::os::unix::ffi::OsStrExt;
        let hex = |p: &Path| -> String {
            p.as_os_str()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        let mut out = vec![format!("home {}", hex(&self.home))];
        for a in &self.absent {
            out.push(format!("absent {}", hex(Path::new(a))));
        }
        for (l, t) in &self.links {
            out.push(format!("link {} {}", hex(Path::new(l)), hex(t)));
        }
        out
    }

    /// A watch read back from [`HomeWatch::to_lines`]; lines of other kinds
    /// are left out. `None` without a home or with a line that is damaged.
    pub fn from_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<HomeWatch> {
        use std::os::unix::ffi::OsStringExt;
        let unhex = |s: &str| -> Option<PathBuf> {
            if !s.len().is_multiple_of(2) {
                return None;
            }
            let bytes = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()?;
            Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
        };
        // A place is always below the home: `home.join` of an absolute
        // path would leave it, and of an empty one is the home itself.
        // Only plain names are acted on: one with `..` would let `settle`
        // rename or delete outside the home (review B2 R54). An older SAM
        // wrote such names for an `XDG_CONFIG_HOME` holding `..`, so that
        // line alone is left out (`Some(None)`) and the rest of the record
        // still counts (independent review of PR 134); any other damage
        // makes the whole record unreadable (`None`).
        let place = |p: PathBuf| -> Option<Option<String>> {
            let all = |ok: fn(&Component) -> bool| {
                !p.as_os_str().is_empty() && p.components().all(|c| ok(&c))
            };
            if all(|c| matches!(c, Component::Normal(_))) {
                return Some(Some(p.to_str()?.to_string()));
            }
            all(|c| matches!(c, Component::Normal(_) | Component::ParentDir)).then_some(None)
        };
        let mut home = None;
        let mut w = HomeWatch::default();
        for line in lines {
            let mut parts = line.split(' ');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some("home"), Some(h), None, None) => home = Some(unhex(h)?),
                (Some("absent"), Some(a), None, None) => w.absent.extend(place(unhex(a)?)?),
                (Some("link"), Some(l), Some(t), None) => {
                    let target = unhex(t)?;
                    w.links.extend(place(unhex(l)?)?.map(|l| (l, target)));
                }
                (Some("home" | "absent" | "link"), ..) => return None,
                _ => {}
            }
        }
        w.home = home.filter(|h| h.is_absolute())?;
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
        // The protected places themselves (and the folders above them, and
        // the key folders): what cannot be moved from them is deleted. A
        // place only on the way a link leads (`~/Sync`, which the person's
        // sync tool may create while an app runs) is never deleted: it is
        // moved aside or said to be still there (review of PR 128).
        let named: Vec<String> = {
            let places = protected_places(&self.home);
            let above = ancestors_of(places.iter().map(String::as_str));
            places
                .into_iter()
                .chain(above)
                .chain([".ssh".to_string(), ".gnupg".to_string()])
                .collect()
        };
        // A folder on the way to a watched place that is now a link: the app
        // renamed the folder and put a link of its own in its place, so a
        // link it holds with the same text, or a place it made, leads where
        // the app chooses (review of PR 128). Moved aside first, so that
        // the way leads nowhere rather than into the app's folder. At
        // the start every folder before a watched place was a real folder
        // or a watched link (the way is recorded as Linux follows it).
        let mut swapped: Vec<String> = Vec::new();
        for rel in self.absent.iter().chain(self.links.iter().map(|(r, _)| r)) {
            let parts: Vec<Component> = Path::new(rel).components().collect();
            let mut at = PathBuf::new();
            for c in parts.iter().take(parts.len().saturating_sub(1)) {
                at.push(c);
                let Some(p) = at.to_str() else {
                    break;
                };
                if self.links.iter().any(|(l, _)| l == p) {
                    break;
                }
                if fs::symlink_metadata(self.home.join(&at))
                    .is_ok_and(|m| m.file_type().is_symlink())
                {
                    if !swapped.iter().any(|s| s == p) {
                        swapped.push(p.to_string());
                    }
                    break;
                }
            }
        }
        for rel in &swapped {
            if let Some((to, how)) = put_aside(&self.home, aside, rel, false) {
                moved.push(MovedAside {
                    place: rel.clone(),
                    to,
                    how,
                });
            }
        }
        for rel in &self.absent {
            // Inside a link's target or a moved folder only once.
            if fs::symlink_metadata(self.home.join(rel)).is_ok()
                && !self
                    .absent
                    .iter()
                    .any(|o| o != rel && rel.starts_with(&format!("{o}/")))
            {
                if let Some((to, how)) = put_aside(&self.home, aside, rel, named.contains(rel)) {
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
                    if let Some((to, how)) = put_aside(&self.home, aside, rel, named.contains(rel))
                    {
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

/// Takes what is at `rel` in `home` out of its place: into `aside`
/// (keeping its place in the name), else renamed next to it to a name
/// nothing reads, else (`may_delete`) deleted; `None` when nothing is there
/// any more. Never gives up silently (regression, audit L-F2: after 1000
/// names per place, with SAM's folder on another drive or a full disk, the
/// file simply stayed, and nothing said so). A place that is already empty
/// when SAM moves it is not reported: another launch's look took it a
/// moment before, and said so in its own record; before, this look then
/// reported it as deleted, or as still there in capitals.
fn put_aside(home: &Path, aside: &Path, rel: &str, may_delete: bool) -> Option<(PathBuf, Aside)> {
    let from = home.join(rel);
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
    // Gone, not refused: only "not found" counts. Any other error (a folder
    // the app made unreadable) still ends in deleting it or saying so.
    if matches!(fs::symlink_metadata(&from), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return None;
    }
    Some(if may_delete && remove_any(&from) {
        (from, Aside::Deleted)
    } else {
        (from, Aside::Failed)
    })
}

/// The way to `p` as Linux follows it, link by link: every link met (its
/// place and its target), and the first place on the way that does not
/// exist. Stops after 40 links, as Linux does.
fn way_to(p: &Path) -> (Vec<(PathBuf, PathBuf)>, Option<PathBuf>) {
    let mut links = Vec::new();
    let mut todo: Vec<OsString> = Vec::new();
    let add = |todo: &mut Vec<OsString>, path: &Path| {
        for c in path.components().rev() {
            match c {
                Component::Normal(n) => todo.push(n.to_os_string()),
                Component::ParentDir => todo.push("..".into()),
                _ => {}
            }
        }
    };
    add(&mut todo, p);
    let mut at = PathBuf::from("/");
    while let Some(c) = todo.pop() {
        if c == ".." {
            at.pop();
            continue;
        }
        let next = at.join(&c);
        match fs::symlink_metadata(&next) {
            Err(_) => return (links, Some(next)),
            Ok(m) if m.file_type().is_symlink() => {
                let Ok(target) = fs::read_link(&next) else {
                    return (links, None);
                };
                if links.len() >= 40 {
                    return (links, None);
                }
                if target.is_absolute() {
                    at = PathBuf::from("/");
                }
                add(&mut todo, &target);
                links.push((next, target));
            }
            Ok(_) => at = next,
        }
    }
    (links, None)
}

/// Removes whatever is at `p`: a folder with all in it, a file, or a link
/// (never what it points to). True when nothing is left there.
fn remove_any(p: &Path) -> bool {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p).is_ok(),
        Ok(_) => fs::remove_file(p).is_ok(),
        Err(_) => true,
    }
}

/// The places of the home SAM shows an app on its own, read-only, each
/// only where neither it nor a folder on its way in the home is a link
/// ([`sam_core::places::own_home_places`]). SAM's sandbox check takes the
/// same list.
pub use sam_core::places::own_home_places;

/// Files inside the theme folders ([`sam_core::places::THEME_FILES`])
/// that are not theme settings: the
/// file chooser's bookmarks and server list name the person's folders and
/// servers. With only the theme settings shown, they stay out (an empty
/// file); a grant that shows them anyway (the whole home, the folder
/// itself) keeps them.
const THEME_PRIVATE_FILES: &[&str] = &[
    ".config/gtk-3.0/bookmarks",
    ".config/gtk-3.0/servers",
    ".config/gtk-4.0/bookmarks",
    ".config/gtk-4.0/servers",
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

#[derive(Default)]
struct Args {
    v: Vec<String>,
    /// Paths of required mounts that are not valid UTF-8: Bubblewrap's
    /// arguments are text here, and a replaced character would name another
    /// file (audit S-F15), so the start is refused instead.
    bad: Vec<PathBuf>,
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
        let (Some(sa), Some(sb)) = (a.as_ref().to_str(), b.as_ref().to_str()) else {
            // An optional mount is left out, so the app sees nothing there;
            // a required one stops the start.
            if !op.ends_with("-try") {
                let odd = if a.as_ref().to_str().is_none() {
                    a.as_ref()
                } else {
                    b.as_ref()
                };
                self.bad.push(odd.to_path_buf());
            }
            return;
        };
        self.v.push(op.into());
        self.v.push(sa.to_string());
        self.v.push(sb.to_string());
    }
    /// A path as one argument. A name that is not valid text stops the
    /// start, as for a required mount: written with a replaced character it
    /// named another place, so an empty folder meant to hide SAM's own or a
    /// key folder landed elsewhere and the real one stayed visible (review
    /// B2 R57).
    fn path(&mut self, p: impl AsRef<Path>) -> &mut Self {
        match p.as_ref().to_str() {
            Some(s) => self.v.push(s.to_string()),
            None => self.bad.push(p.as_ref().to_path_buf()),
        }
        self
    }
    fn ro(&mut self, p: impl AsRef<Path>) {
        let p = p.as_ref();
        self.op2("--ro-bind-try", p, p);
    }
    /// Read-only onto itself, as a protection: a name that is not valid
    /// text stops the start, where [`Args::ro`] would leave the place out
    /// and so writable (review B2 R57).
    fn lock(&mut self, p: impl AsRef<Path>) {
        let p = p.as_ref();
        if p.to_str().is_none() {
            self.bad.push(p.to_path_buf());
            return;
        }
        self.ro(p);
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
        let interesting = fs::metadata(&t).is_ok_and(|m| may_follow(&t, m.file_type()));
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

/// Whether the target `t` of a link found in /etc may be shown as well:
/// only shared data and settings (/usr/lib and /usr/bin are shown
/// already), and only plain files and folders. In /run only plain files
/// (`resolv.conf` → /run/NetworkManager/resolv.conf). Never a socket or a
/// device: Debian's `/etc/alternatives/php-fpm.sock` points to the PHP
/// server's socket in /run/php, and every app's sandbox showed it (found
/// by a test on CI, 2026-11-19).
fn may_follow(t: &Path, kind: fs::FileType) -> bool {
    if t.starts_with("/run") {
        return kind.is_file();
    }
    (t.starts_with("/usr/share") || t.starts_with("/etc")) && (kind.is_file() || kind.is_dir())
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
# Web and mail links open in the person's browser or mail program; any
# other kind (steam://, vscode://, a program's own scheme) starts whatever
# program handles it, so the portal asks first, with its app chooser.
case "$target" in
  http://*|https://*|mailto:*) gopts="@a{sv} {}"; bopts="0" ;;
  *) gopts="{'ask': <true>}"; bopts="1 ask b true" ;;
esac
if command -v gdbus >/dev/null 2>&1 && gdbus call --session --dest org.freedesktop.portal.Desktop \
     --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.OpenURI.OpenURI \
     "" "$target" "$gopts" >/dev/null 2>&1; then exit 0; fi
# shellcheck disable=SC2086
if command -v busctl >/dev/null 2>&1 && busctl --user call org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop \
     org.freedesktop.portal.OpenURI OpenURI 'ssa{sv}' "" "$target" $bopts >/dev/null 2>&1; then exit 0; fi
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
    let mut a = Args::default();
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
        let base = Views::base(ctx);
        let opened = opened_paths_in(ctx, &base);
        Views::with_opened(ctx, base, &opened)
    }

    /// The views `base` ([`Views::of_writes`]) with the opened files
    /// already worked out and SAM's binds.
    fn with_opened(ctx: &LaunchContext, base: Views, opened: &[(PathBuf, bool)]) -> Views {
        let mut v = base;
        v.grants.extend(opened.iter().cloned());
        for (_, sb, rw) in &ctx.extra_binds {
            v.grants.push((sb.clone(), *rw));
        }
        v
    }

    /// The grants of the permissions alone: the home, the user folders and
    /// extra folders (what `opened_paths` checks against).
    pub fn base(ctx: &LaunchContext) -> Views {
        Views::of_writes(ctx, &write_grants(ctx))
    }

    /// [`Views::base`] with the extra writable folders decided once
    /// ([`write_grants`]): an extra writable folder in a start place counts
    /// read-only and one below a folder the app can already change is not
    /// bound, exactly as it is mounted. So the checks of what this start
    /// can write (`writes_start_places`, the home watch, the pins) agree
    /// with the mounts.
    fn of_writes(ctx: &LaunchContext, writes: &[WriteGrant]) -> Views {
        let mut v = Views::without_writes(ctx);
        for g in writes {
            match g.how {
                WriteBind::Writable => v.grants.push((g.bound.clone(), true)),
                WriteBind::ReadOnly(_) => v.grants.push((g.bound.clone(), false)),
                WriteBind::Below(_) | WriteBind::InsideSam | WriteBind::LeftOut(_) => {}
            }
        }
        v
    }

    /// The home, the user folders and the extra read-only folders. Each
    /// user folder at the access the start shows it at
    /// ([`sam_core::places::user_folder_access`]): two set to one place at
    /// different access are both read-only, as mounted.
    fn without_writes(ctx: &LaunchContext) -> Views {
        let fsp = &ctx.permissions.filesystem;
        let mut grants = Vec::new();
        if fsp.home {
            grants.push((ctx.host.home.clone(), fsp.home_access == Access::Rw));
        }
        for key in XDG_DIR_KEYS {
            let acc = sam_core::places::user_folder_access(&ctx.permissions, &ctx.host, key);
            if acc.is_granted() {
                if let Ok(d) = user_dir(ctx, key) {
                    grants.push((d, acc == Access::Rw));
                }
            }
        }
        // Never one SAM leaves out ([`read_grant_left_out`]): its place
        // is not shown.
        for c in &fsp.custom_read {
            if read_grant_left_out(ctx, c).is_none() {
                grants.push((grant_path(c), false));
            }
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

    /// Every place in the sandbox where host path `p` is shown: its own path,
    /// its resolved one and, for a grant kept behind a link (the home, when
    /// `/home/u` is a link to `/data/u`), the resolved one under the grant's
    /// own name, where the sandbox mounts it. A link naming the home's real
    /// path (`~/.config` to `/data/u/dots/config`) leads nowhere inside, yet
    /// the app reaches its target as `/home/u/dots/config`: without that
    /// place autostart there stayed writable and a linked key folder shown
    /// (review of SB-6 and SB-2).
    pub fn seen_at(&self, p: &Path) -> Vec<PathBuf> {
        let real = resolve(p);
        let mut cands = vec![p.to_path_buf(), real.clone()];
        for (g, _) in &self.grants {
            let rg = resolve(g);
            if rg != *g {
                if let Ok(rel) = real.strip_prefix(&rg) {
                    cands.push(g.join(rel));
                }
            }
        }
        let mut out = Vec::new();
        for c in cands {
            if self.visible(&c) && !out.contains(&c) {
                out.push(c);
            }
        }
        out
    }

    /// Where the app reaches host path `p` inside the sandbox, one part
    /// after the other as Linux reads a path: a link is followed where a
    /// grant shows the folder it lies in (a grant's own place is a mount
    /// point inside, never a link). `None` when the way ends outside what
    /// the sandbox shows, or loops.
    fn reached_at(&self, p: &Path) -> Option<PathBuf> {
        if !p.is_absolute() {
            return None;
        }
        // The parts still to read, the next one last.
        let mut todo: Vec<OsString> = Vec::new();
        let add = |todo: &mut Vec<OsString>, path: &Path| {
            for c in path.components().rev() {
                match c {
                    Component::Normal(n) => todo.push(n.to_os_string()),
                    Component::ParentDir => todo.push("..".into()),
                    _ => {}
                }
            }
        };
        add(&mut todo, p);
        let mut at = PathBuf::from("/");
        // As many links as Linux follows in one path.
        let mut links = 0;
        while let Some(c) = todo.pop() {
            if c == ".." {
                at.pop();
                continue;
            }
            at.push(&c);
            let inside = self.grant_of(&at).is_some_and(|(g, _)| at != *g);
            if !inside {
                continue;
            }
            if let Ok(target) = fs::read_link(&at) {
                links += 1;
                if links > 40 {
                    return None;
                }
                at.pop();
                if target.is_absolute() {
                    at = PathBuf::from("/");
                }
                add(&mut todo, &target);
            }
        }
        self.visible(&at).then_some(at)
    }

    /// The places to mount on to cover host path `p` inside the sandbox:
    /// every place the app reaches it ([`Views::seen_at`], with links
    /// followed as the app follows them). None of them is or leads through
    /// a link: Bubblewrap refuses to mount on a link, or through one that
    /// leads nowhere inside, so `~/.config` as a link stopped every start
    /// with the whole home granted; and a pin through a relative one landed
    /// on the folder it points to, writable over a read-only grant
    /// (security review 2026-11-23, SB-6).
    fn mount_points(&self, p: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for c in self.seen_at(p) {
            if let Some(r) = self.reached_at(&c) {
                if !out.contains(&r) {
                    out.push(r);
                }
            }
        }
        out
    }

    /// Where SAM binds `target`, the place a link at a font or theme
    /// place leads to (links resolved), read-only: every place the app
    /// reaches it ([`Views::mount_points`]) that lies strictly inside a
    /// writable grant, never on the grant's own place, the home or a folder
    /// above it. The bind only takes write access away; it shows nothing a
    /// grant does not show. With a read-only home, an extra writable
    /// `~/dotfiles` and your own link `~/.config/fontconfig` to
    /// `dotfiles/fontconfig`, the app cannot change the link, yet it could
    /// write the font settings there that programs outside the sandbox
    /// load.
    ///
    /// None where a place SAM would bind the target at has a name that is
    /// not valid text (always so for a target by such a name, since each
    /// place is the target under one of its names): Bubblewrap cannot be
    /// given such a name, and
    /// stopping the start instead let anyone who can write next to the
    /// target (another app with the whole home writable) stop every start
    /// with a planted link. The link is then only named, as every other
    /// skipped link, the start runs, and no note says the target is kept
    /// read-only ([`sam_core::places::GrantsShown::keeps_read_only`]
    /// answers alike).
    fn read_only_targets(&self, home: &Path, target: &Path) -> Vec<PathBuf> {
        let real_home = resolve(home);
        let out: Vec<PathBuf> = self
            .mount_points(target)
            .into_iter()
            .filter(|m| {
                !(home.starts_with(m) || real_home.starts_with(m))
                    && self.grant_of(m).is_some_and(|(g, rw)| *rw && g != m)
            })
            .collect();
        if out.iter().any(|m| m.to_str().is_none()) {
            return Vec::new();
        }
        out
    }
}

/// Where SAM binds a place of the home it shows on its own
/// ([`sam_core::places::OwnBind::Bind`]), read-only: wherever the app
/// reaches it through a grant ([`Views::mount_points`], never on a link),
/// also at the home's real place when an extra folder is recorded there
/// (`/data/u/.config` with `/home/u` a link to `/data/u`), and at its name
/// when no grant shows that name (the sandbox's own home, where the app
/// looks for it).
fn own_mount_points(views: &Views, named: &Path) -> Vec<PathBuf> {
    let mut out = views.mount_points(named);
    if !views.visible(named) && !out.iter().any(|m| m == named) {
        out.push(named.to_path_buf());
    }
    out
}

/// Why a user folder (Documents, Downloads, …) is not shown.
#[derive(Debug, PartialEq)]
enum NotShown {
    Missing,
    /// It is the home, a folder above it, a system folder, a credential
    /// store, a start place or one of SAM's folders.
    Refused(PathBuf),
    /// It is a folder in `/tmp` where programs outside the sandbox listen.
    Sockets(PathBuf),
    /// The way to it (the first path) holds a link (the second) in a
    /// folder the app can change, which the app could have put there.
    Link(PathBuf, PathBuf),
    /// Its way (as `user-dirs.dirs` names it) leads through a link the app
    /// could have planted, or to where programs outside the sandbox listen
    /// ([`sam_core::places::user_folder_left_out`]).
    LeftOut(PathBuf, sam_core::places::LeftOut),
}

/// A granted user folder as it is bound: where `user-dirs.dirs` says it is,
/// with links resolved (what the app sees, as for extra folders). Never a
/// place that would show more than the folder: `user-dirs.dirs` is a plain
/// text file, and a line like `XDG_DOCUMENTS_DIR="/"` or one pointing at a
/// link to `/home` granted the whole computer or every home, without the
/// protections inside (audit S-F11). The same place the list of what a
/// start shows takes ([`sam_core::places::user_folder_place`]), which
/// decides about SAM's folders by name, and never in SAM's folders.
///
/// Nor one reached through a link the app could have put there, in a
/// folder this start lets it change
/// ([`sam_core::places::user_folder_link_the_app_can_change`]): with the
/// whole home writable, `ln -s /tmp ~/Downloads` in one start showed the
/// host's `/tmp` in the next. Nor a folder in `/tmp` where programs outside
/// the sandbox listen, which also the person may have set.
///
/// Nor one whose way leads through a link the app could have planted out
/// of what it is shown, also in a folder only this start shows writable,
/// nor one that leads to where programs outside the sandbox listen
/// ([`sam_core::places::user_folder_left_out`]): with `~/Sync` writable
/// and `XDG_DOCUMENTS_DIR` set to `~/Sync/Documents`, not made yet, the
/// app made it a link to `/tmp/tmux-1000`, and the next start bound the
/// host's tmux sockets over the sandbox's own `/tmp`. Each rule refuses
/// on its own, so the folder is shown only where both let it.
///
/// Where both rules refuse a folder, the rule for planted links and
/// listening programs decides what the start says ([`NotShown::LeftOut`]):
/// its note names the danger (a link to where programs outside the sandbox
/// listen) or the link and that it leads out of what the home shows, and
/// tells the person how to show the folder if they made the link
/// themselves. The note for a link the app can change
/// ([`NotShown::Link`]) is left for the links only that rule refuses: in
/// a folder the app can change, to a place the home shows anyway.
fn user_dir(ctx: &LaunchContext, key: &str) -> std::result::Result<PathBuf, NotShown> {
    let dir = ctx.host.xdg_dir(key).ok_or(NotShown::Missing)?;
    // In the order the app page asks too, so it names the folder with the
    // words of the launch note ([`sam_core::places::user_folder_refused`]).
    match sam_core::places::user_folder_refused(&ctx.permissions, &ctx.host, key, &this_start(ctx))
    {
        Some(UserFolderRefused::LeftOut(why)) => {
            return Err(NotShown::LeftOut(dir.to_path_buf(), why))
        }
        Some(UserFolderRefused::Link(link)) => return Err(NotShown::Link(dir.to_path_buf(), link)),
        Some(UserFolderRefused::Sockets) => return Err(NotShown::Sockets(dir.to_path_buf())),
        None => {}
    }
    match sam_core::places::user_folder_place(dir, &ctx.host.home) {
        Some(real) if !inside_sam(ctx, &real) => Ok(real),
        _ => Err(NotShown::Refused(dir.to_path_buf())),
    }
}

/// What the start says about the user folder `key` that it does not show;
/// `write`: the folder is set to read/write.
fn user_folder_note(key: &str, why: &NotShown, write: bool) -> String {
    match why {
        NotShown::Missing => sam_core::i18n::trf(
            "{key} folder does not exist on the host; not bound",
            &[("key", &key)],
        ),
        NotShown::Refused(dir) => sam_core::i18n::trf(
            "{key} folder is set to {path}, which shows more than a user folder (the home, a folder above it, a system or SAM folder, or a protected place); not bound",
            &[("key", &key), ("path", &dir.display())],
        ),
        // The words the app page and `sam-jail info` take as well.
        NotShown::Sockets(dir) => refused_note(key, dir, UserFolderRefused::Sockets, write),
        NotShown::Link(dir, link) => {
            refused_note(key, dir, UserFolderRefused::Link(link.clone()), write)
        }
        NotShown::LeftOut(dir, why) => {
            refused_note(key, dir, UserFolderRefused::LeftOut(why.clone()), write)
        }
    }
}

/// [`sam_core::places::user_folder_refused_note`].
fn refused_note(key: &str, dir: &Path, why: UserFolderRefused, write: bool) -> String {
    sam_core::places::user_folder_refused_note(key, dir, &why, write)
}

/// Whether the whole home, mounted at `home`, already shows the user folder
/// that really is at `real` exactly at its own access (`rw`): the deepest
/// grant above it is the home (as named, or as reached when the home is
/// kept behind a link), at that same access. Then the folder needs no
/// mount of its own; otherwise it gets one (read-only in a writable home,
/// writable in a read-only one, below another grant, or outside the home),
/// so the mounts give the answer the views give ([`Views::without_writes`]
/// records every granted user folder at its own access).
fn home_shows_exactly(views: &Views, home: &Path, real: &Path, rw: bool) -> bool {
    let real_home = resolve(home);
    let above = |g: &Path| real.starts_with(g) || (g == home && real.starts_with(&real_home));
    views
        .grants
        .iter()
        .filter(|(g, _)| g != real && above(g))
        .max_by_key(|(g, _)| g.components().count())
        .is_some_and(|(g, g_rw)| g == home && *g_rw == rw)
}

/// Whether `real` (a resolved path) is one of SAM's folders in this start
/// ([`sams_folders`]) or inside one. A folder that only holds one may be
/// shown: SAM's folder is hidden inside it, wherever the sandbox shows it.
/// The same answer SAM's sandbox check and start texts take
/// ([`sam_core::places::inside_sams_folders`]).
fn inside_sam(ctx: &LaunchContext, real: &Path) -> bool {
    sam_core::places::inside_sams_folders(real, &sams_folders(ctx))
}

/// SAM's own folders in this start: where this SAM keeps its own
/// (`ctx.sam_dirs`) and the folders named like them (`~/.config/sam`,
/// `~/.local/share/sam`, also under `XDG_CONFIG_HOME` and `XDG_DATA_HOME`)
/// that count as SAM's for what this start shows
/// ([`sam_core::places::sams_folders`]): hidden wherever a grant would
/// show them, links followed, unless hiding one would cover too much (the
/// home, or a link to a folder of which the start shows only parts).
/// Decided here from the start itself, so no caller can leave out a
/// folder by those names (always hidden by name before), and SAM's
/// sandbox check and a terminal app's start line take the same list
/// (independent reviews of decision 9).
pub fn sams_folders(ctx: &LaunchContext) -> Vec<PathBuf> {
    let mut shown = sam_core::places::shown_folders(&ctx.permissions, &ctx.host);
    // SAM's own binds count as showing what they hold: a folder by those
    // names that one of them shows stays hidden.
    shown.extend(ctx.extra_binds.iter().map(|(h, _, _)| resolve(h)));
    sam_core::places::sams_folders(&ctx.host.home, &ctx.sam_dirs, &shown)
}

/// An extra writable folder (`filesystem.custom_write`) as this start
/// shows it, decided once per start on the path it binds: the views and
/// the mounts take this one answer. Resolved again for each, an app
/// running alongside could turn the folder into a link to a start place
/// in between, so the check saw an ordinary folder and Bubblewrap bound
/// the start place writable (independent review of decision 9).
#[derive(Debug, Clone)]
struct WriteGrant {
    /// As the person wrote it.
    written: String,
    /// Where it is bound: `~` expanded and links resolved, once.
    bound: PathBuf,
    /// How it is shown.
    how: WriteBind,
}

/// How an extra writable folder is shown ([`WriteGrant`]).
#[derive(Debug, Clone, PartialEq)]
enum WriteBind {
    /// Bound writable where it leads.
    Writable,
    /// A start place, inside one or where one really is: bound read-only
    /// where it leads, with or without the whole home, also below a folder
    /// the app can change (owner decision 9 of 2026-11-23). Left out
    /// there, a start place kept through a link in it (`conf.d` a link to
    /// `~/work/fishconf`, `~/work` granted) stayed writable. The folders
    /// above it are pinned ([`pins`]), so renaming one cannot carry the
    /// read-only mount away.
    ReadOnly(sam_core::places::StartPlaceGrant),
    /// Below this folder, which the app can already change (a writable
    /// grant, a writable opened folder, a writable bind of SAM's): not
    /// bound at all. That folder shows it already, and the app could swap
    /// a part of the way for a link before Bubblewrap follows it.
    Below(PathBuf),
    /// In SAM's own folders, which the app never sees: not bound.
    InsideSam,
    /// Reached through a link the app could have planted, out of what it
    /// is shown, or through a link to where programs outside the sandbox
    /// listen ([`sam_core::places::linked_place_left_out`]): not bound.
    LeftOut(sam_core::places::LeftOut),
}

/// The extra writable folders of this start, each decided once
/// ([`WriteGrant`]).
fn write_grants(ctx: &LaunchContext) -> Vec<WriteGrant> {
    let home = &ctx.host.home;
    let sams = sams_folders(ctx);
    let found: Vec<(String, PathBuf, Option<sam_core::places::StartPlaceGrant>)> = ctx
        .permissions
        .filesystem
        .custom_write
        .iter()
        .map(|c| {
            let written = expand_home(c);
            let bound = resolve(&written);
            let place = start_place_of_bound_write_grant(&written, &bound, home);
            (c.clone(), bound, place)
        })
        .collect();
    // What the app can change: every grant, a write grant left out below
    // too (what lies below it lies below the writable folder above it as
    // well), and the folders named on the command line, worked out
    // without the extra writable folders (independent review of
    // decision 9: `app ~/work` with writable opened files and a grant of
    // `~/work/a/proj` was missed).
    let all = {
        let mut v = Views::without_writes(ctx);
        let opened = opened_paths_in(ctx, &v);
        for (_, bound, place) in &found {
            v.grants.push((bound.clone(), place.is_none()));
        }
        v.grants.extend(opened);
        v
    };
    let this = this_start(ctx);
    let app_can_change = |d: &Path| {
        shown_writable(&all, d)
            || sam_core::places::inside_sams_folders(d, &sams)
            || ctx
                .extra_binds
                .iter()
                .any(|(h, _, rw)| *rw && d.starts_with(resolve(h)))
    };
    found
        .into_iter()
        .map(|(written, bound, place)| {
            // One answer for the sandbox and its check (independent review
            // of decision 9: the check missed SAM's folders kept elsewhere).
            let how = if let Some(why) = sam_core::places::linked_place_left_out(
                &ctx.permissions,
                &ctx.host,
                &expand_home(&written),
                true,
                &this,
            ) {
                WriteBind::LeftOut(why)
            } else if sam_core::places::write_grant_in_sams_folders(
                &bound,
                place.as_ref(),
                &sams,
                home,
            ) {
                WriteBind::InsideSam
            } else if let Some(place) = place {
                WriteBind::ReadOnly(place)
            } else if let Some(folder) = bound.parent().filter(|a| app_can_change(a)) {
                // Judged on the folder right above it, as the deepest
                // grant there shows it: below a read-only grant inside a
                // writable one (`~/Documents/proj` with Documents
                // read-only under the writable home), the app cannot
                // change the way: the read-only grant is a mount of its
                // own it cannot rename, and the folders above it that the
                // app can change are pinned (`Section::home`), so the
                // folder is bound writable after it. Judged on any folder
                // above, it was left out,
                // read-only under that grant, while the start said the
                // app could already change it and the sandbox check
                // expected it writable.
                WriteBind::Below(folder.to_path_buf())
            } else {
                WriteBind::Writable
            };
            WriteGrant {
                written,
                bound,
                how,
            }
        })
        .collect()
}

/// A granted folder as it is bound: with `~` expanded and links resolved,
/// so the checks see what the app sees.
fn grant_path(c: &str) -> PathBuf {
    resolve(&expand_home(c))
}

/// Why this start leaves out the extra read-only folder `c` (as the
/// person wrote it), if it does: reached through a link the app could have
/// planted, out of what it is shown, or through a link to where programs
/// outside the sandbox listen ([`sam_core::places::linked_place_left_out`]).
/// With the whole home writable, an extra folder not made yet was turned
/// into a link to `/tmp/tmux-1000` in one start, and the next start bound
/// the host's tmux sockets.
fn read_grant_left_out(ctx: &LaunchContext, c: &str) -> Option<sam_core::places::LeftOut> {
    sam_core::places::linked_place_left_out(
        &ctx.permissions,
        &ctx.host,
        &expand_home(c),
        false,
        &this_start(ctx),
    )
}

/// What this start adds to its permissions for the binds SAM makes where
/// their links lead ([`sam_core::places::ThisStart`]):
/// - the folders it shows writable besides them, as `write_grants` counts
///   them: SAM's writable binds and, when opened files are writable, every
///   folder opened with the app, judged against no grant at all (a folder
///   another grant already shows counts too, which leaves out more, never
///   less; judged against the grants, they would depend on this answer);
/// - SAM's runtime folders: this start's own (`<base>/<app>/<start>`) and
///   the two folders above it that hold every app's and every start's,
///   never a folder at the top of the computer (`/tmp`) or one that holds
///   the home.
fn this_start(ctx: &LaunchContext) -> sam_core::places::ThisStart {
    let mut writable: Vec<PathBuf> = ctx
        .extra_binds
        .iter()
        .filter(|(_, _, rw)| *rw)
        .map(|(h, _, _)| resolve(h))
        .collect();
    if ctx.permissions.filesystem.opened_files == Access::Rw {
        let none = Views { grants: Vec::new() };
        writable.extend(opened_paths_in(ctx, &none).into_iter().map(|(p, _)| p));
    }
    let homes = [ctx.host.home.clone(), resolve(&ctx.host.home)];
    let sam_runtime = ctx
        .runtime_dir
        .ancestors()
        .take(3)
        .filter(|a| a.components().count() > 2 && !homes.iter().any(|h| h.starts_with(a)))
        .map(Path::to_path_buf)
        .collect();
    sam_core::places::ThisStart {
        writable,
        sam_runtime,
    }
}

/// The places bound read-only that the views do not record (the fonts, the
/// font settings, the theme files), and every place bound writable below
/// the home, mounted after them where deeper: together they say where a
/// read-only bind is still the topmost mount ([`pins`]).
struct ReadOnlyBinds<'a> {
    places: &'a [PathBuf],
    writable_mounts: &'a [PathBuf],
}

/// Step 1 of the protections inside the shown parts of the real home: the
/// folders above protected places, above SAM's own folders (`sam_dirs`:
/// [`sams_folders`], with the folders that `SAM_CONFIG_DIR` and
/// `SAM_DATA_DIR` name) and above SAM's
/// own programs that the sandbox shows writable. Each becomes a mount point
/// of its own (bound onto itself, in the depth order of the other mounts),
/// so it cannot be renamed away together with the protection (`mv
/// ~/.local/share ~/.local/s2` moved SAM's records; regression, audit
/// S-F4). Each where the app reaches it, never through a link
/// ([`Views::mount_points`]): a link itself is no folder to pin, and a pin
/// through a relative one landed on the folder it points to, writable,
/// over a read-only grant (security review 2026-11-23, SB-6).
///
/// Also every folder above the place where a guard lands (`guarded`, SAM's
/// folders and programs, and a font or theme place SAM keeps read-only
/// behind a link in a folder the app cannot change): a protected place or credential store kept
/// through a link (dotfiles, `stow`) is guarded where the link leads, below
/// folders that are not above its name. Renamed (`mv ~/dotfiles ~/y`), the
/// guard moved along, and a new `~/dotfiles/bashrc` ran outside the sandbox
/// at the next shell while the link `~/.bashrc` stayed as it was (review
/// B2 S3, R50). A grant's own place is a mount point already.
///
/// Never where a place bound read-only that the views do not record
/// (`read_only.places`: the fonts, the font settings and the theme files,
/// each only where no writable place is bound after it at its own place)
/// is still the topmost mount: on it, or inside it with no place bound
/// writable (`read_only.writable_mounts`) between it and the folder. The
/// app cannot rename anything there, and a pin, bound after the read-only
/// bind at equal depth or deeper, made it writable (`~/.fonts` above an
/// extra read-only folder `~/.fonts/licensed` with the whole home
/// writable). Judged from what is mounted, not from the views: a writable
/// user folder inside `~/.fonts` that the writable home already shows
/// has no mount of its own, so the read-only bind still covers it. Inside
/// a place bound writable within such a place (`~/.fonts/work`) the app
/// can rename, so the folders there are pinned as everywhere: skipped on
/// or inside the whole place, a start file kept as a link into
/// `~/.fonts/work/dots` lost the pin of `dots`.
fn pins(
    home: &Path,
    views: &Views,
    guarded: &[PathBuf],
    sam_dirs: &[PathBuf],
    programs: &[PathBuf],
    read_only: &ReadOnlyBinds,
) -> Vec<PathBuf> {
    // The read-only bind is the topmost mount at `c`: it shows `c`, and no
    // place bound writable deeper than it does (mounted after it, by
    // depth). Judged from the mounts, never from the views: a writable
    // user folder inside `~/.fonts` that the writable whole home already
    // shows gets no mount of its own, so the read-only bind still covers
    // it, and a pin there made the font folder writable.
    let read_only_on_top = |c: &Path| {
        read_only.places.iter().any(|r| {
            c.starts_with(r)
                && !read_only
                    .writable_mounts
                    .iter()
                    .any(|g| g != r && g.starts_with(r) && c.starts_with(g))
        })
    };
    let mut pins: Vec<PathBuf> = Vec::new();
    let mut pin = |p: &Path| {
        for c in views.mount_points(p) {
            // Never `/` or one folder below it: those are not renamed.
            if views.writable(&c)
                && !read_only_on_top(&c)
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
    // A grant's own place (the whole home above `~/.config/sam`) is a
    // mount point already, and not bound a second time.
    for d in sam_dirs {
        for anc in d.ancestors().skip(1) {
            if !views.grants.iter().any(|(g, _)| g == anc) {
                pin(anc);
            }
        }
    }
    // Also under the home's name when the home is kept behind a link
    // (`Views::seen_at`): SAM's own path names the real place.
    for p in programs {
        for anc in p.ancestors().skip(1) {
            pin(anc);
        }
    }
    for place in guarded.iter().chain(sam_dirs).chain(programs) {
        for c in views.mount_points(place) {
            for anc in c.ancestors().skip(1) {
                if !views.grants.iter().any(|(g, _)| g == anc) {
                    pin(anc);
                }
            }
        }
    }
    pins
}

/// The credential stores in the home that this start hides: the key
/// folders not given, and the other stores unless hidden files are, also
/// under `XDG_CONFIG_HOME` and `XDG_DATA_HOME` inside the home
/// ([`sensitive_places`]: with `XDG_CONFIG_HOME=~/cfg`, Git's passwords in
/// `~/cfg/git/credentials` stayed readable with the whole home).
/// "Given" counts only with the whole home
/// ([`FilesystemPerms::ssh_given`]): a switch stored "on" without it showed
/// the keys wherever a granted extra folder showed them, though the window
/// greys the switch out and the sandbox check expected them hidden.
fn masked_places(home: &Path, fsp: &FilesystemPerms) -> Vec<String> {
    let mut masks: Vec<String> = Vec::new();
    if !fsp.ssh_given() {
        masks.push(".ssh".into());
    }
    if !fsp.gnupg_given() {
        masks.push(".gnupg".into());
    }
    if !fsp.hidden_files_given() {
        masks.extend(sensitive_places(home));
    }
    masks
}

/// Every place in the home that [`guard_home`] guards in this start: the
/// protected places and the hidden credential stores.
fn guarded_places(home: &Path, fsp: &FilesystemPerms) -> Vec<PathBuf> {
    protected_places(home)
        .iter()
        .map(|p| home.join(p))
        .chain(masked_places(home, fsp).iter().map(|m| home.join(m)))
        .collect()
}

/// Step 3, after every mount: SAM's own programs (its AppImage file, the
/// `sam-jail-run` that menu entries run) read-only wherever the sandbox
/// shows them writable. Bound onto themselves, they can be neither
/// written nor renamed or deleted (a mount point), and the folders above
/// them are pinned (step 1): an app could otherwise put its own program in
/// their place, run unsandboxed at the next click on any menu entry
/// (security review 2026-11-23, SB-1).
fn guard_programs(a: &mut Args, programs: &[PathBuf], views: &Views) {
    for p in programs {
        for c in views.mount_points(p) {
            if views.writable(&c) && c.is_file() {
                a.lock(&c);
            }
        }
    }
}

/// Step 2 of the protections, after every mount (a later mount covers an
/// earlier one: a grant of `/home` or `~/.local` after them showed `~/.ssh`
/// and made autostart writable again; regression, audit S-F2): start files
/// and menu entries read-only, SAM's own folders replaced by an empty
/// folder, and last the credential stores hidden, whatever kind of file
/// they are, at every place the sandbox shows them.
fn guard_home(a: &mut Args, home: &Path, fsp: &FilesystemPerms, views: &Views, sams: &[PathBuf]) {
    for prot in protected_places(home) {
        let path = home.join(&prot);
        // Never on a link (dotfiles kept elsewhere): what it points to is
        // locked, and the link itself is put back after the start if the
        // app replaces it (regression: with `~/.bashrc` a link and the
        // whole home granted, Bubblewrap refused and no app started; the
        // same with `~/.config` a link, SB-6).
        // SAM's own folders by name, also under `XDG_CONFIG_HOME` and
        // `XDG_DATA_HOME` (`~/cfg/sam`): an empty folder wherever the app
        // reaches them, links followed, when they are in this start's list
        // of SAM's folders (`sams`, [`sams_folders`]), which the sandbox
        // check and the start line read too. `~/cfg/sam` was only locked
        // read-only, so the app could read SAM's settings there; and with
        // every link taken for an ordinary start place, another SAM's
        // `~/.local/share/sam` kept as a link to `~/Sync/sam` showed its
        // settings with the whole home. One whose hiding would cover too
        // much (the home, or a planted link to a folder of which the start
        // shows only parts) is locked read-only like any protected place
        // (independent reviews of decision 9). Anything there that is not
        // a folder stays read-only too. A place that really is the home
        // (`~/.config/sam` planted as a link to it) is locked where the app
        // reaches it, which is the whole home: with the whole home
        // writable, the app sees it read-only, as the start's note, the
        // sandbox check and the app page say
        // ([`sam_core::places::protected_place_at_home`]).
        let hide = sams.contains(&path);
        for c in views.mount_points(&path) {
            if hide && c.is_dir() {
                a.push("--tmpfs").path(&c);
            } else if views.writable(&c) && c.exists() {
                a.lock(&c);
            }
        }
    }
    // The credential stores last: a later bind of a folder above one
    // covers the hiding. With `~/.git-credentials` a link into
    // `~/.config/git`, the protected place bound read-only after it showed
    // the real file again (mutation run 2026-11-23).
    for m in masked_places(home, fsp) {
        let path = home.join(m);
        let Ok(md) = fs::symlink_metadata(&path) else {
            continue;
        };
        // A link (dotfiles kept elsewhere, `stow`): hidden where it points,
        // also when only the folder it points into is granted (security
        // review 2026-11-23, SB-2: `~/.gnupg` a link to `~/Sync/gnupg` and
        // `~/Sync` granted showed the keys, writable).
        let mut places = views.mount_points(&path);
        if md.file_type().is_symlink() && views.visible(&path) {
            if let Ok(target) = fs::canonicalize(&path) {
                if !places.contains(&target) {
                    places.push(target);
                }
            }
        }
        for c in places {
            match fs::metadata(&c) {
                Ok(t) if t.is_dir() => {
                    a.push("--tmpfs").path(&c);
                }
                // A file, and also a named pipe or a socket: `~/.netrc` as
                // a pipe a password manager feeds stayed readable
                // (mutation run 2026-11-23).
                Ok(_) => a.op2("--ro-bind", "/dev/null", &c),
                Err(_) => {}
            }
        }
    }
}

/// Files and folders named on the command line ("Open with", or typed in a
/// terminal: `hx notes.txt`, `hx .`), granted for this launch only, like a
/// document portal; `true` means writable (`filesystem.opened_files`).
/// With "No access" (`none`) nothing is granted this way.
/// Relative names count from the folder the app was started in.
///
/// Never granted this way: options (`-x`), a path
/// [`sam_core::places::RefusedForOpened`] refuses (docs/security.md,
/// *Files named on the command line*: the home or a folder above it, a
/// system folder, a key folder, a start place, a credential store,
/// `~/.config`, `~/.local` and the folders `XDG_CONFIG_HOME` and
/// `XDG_DATA_HOME` name, as written, where it leads and at each link on its
/// way, also where a key folder, start place or credential store really
/// leads: one leading to the home or a folder above it refuses all of
/// it), anything inside SAM's own folders wherever they are; and a
/// folder also never when it holds such a place or the home, or lies
/// outside the home and the mounted drives. Each is judged on one walk,
/// and the path judged is the one bound: with `~/.bashrc` a link into
/// `~/dotfiles`, opening `~/dotfiles` would share the real start file
/// (audit D-M2, S-F13). Bubblewrap follows that path again when it
/// mounts it; a second program that swaps a part of the way for a link
/// in between is not covered (docs/security.md).
pub fn opened_paths(ctx: &LaunchContext) -> Vec<(PathBuf, bool)> {
    opened_paths_in(ctx, &Views::base(ctx))
}

/// The extra folders (`filesystem.custom_read`, then `custom_write`, as
/// the person wrote them) that this start shows the app, for what SAM
/// tells the person: one inside SAM's own folders is left out, as the
/// sandbox leaves it out (a writable one is not bound, a read-only one is
/// covered by the empty folder in place of SAM's). Listed anyway, a
/// terminal app's start line named a folder the app never sees
/// (independent review of decision 9).
pub fn shown_extra_folders(ctx: &LaunchContext) -> Vec<String> {
    let sams = sams_folders(ctx);
    let reads = ctx
        .permissions
        .filesystem
        .custom_read
        .iter()
        .filter(|c| {
            !sam_core::places::inside_sams_folders(&grant_path(c), &sams)
                && read_grant_left_out(ctx, c).is_none()
        })
        .cloned();
    let writes = write_grants(ctx)
        .into_iter()
        .filter(|g| !matches!(g.how, WriteBind::InsideSam | WriteBind::LeftOut(_)))
        .map(|g| g.written);
    reads.chain(writes).collect()
}

/// The user folders (Documents, Downloads, …) that this start shows the
/// app, where the app looks for them (`user-dirs.dirs`), for what SAM tells
/// the person: every granted one the sandbox does not refuse
/// ([`user_dir`]: the home, a folder above it, a system or key folder, a
/// start place or one inside SAM's folders), with or without the whole
/// home, inside the home or outside it.
pub fn shown_user_folders(ctx: &LaunchContext) -> Vec<PathBuf> {
    XDG_DIR_KEYS
        .iter()
        .filter(|key| ctx.permissions.filesystem.xdg_access(key).is_granted())
        .filter(|key| user_dir(ctx, key).is_ok())
        .filter_map(|key| ctx.host.xdg_dir(key).map(Path::to_path_buf))
        .collect()
}

/// [`opened_paths`] against the grants `views` ([`Views::base`]) worked out
/// once for this start.
fn opened_paths_in(ctx: &LaunchContext, views: &Views) -> Vec<(PathBuf, bool)> {
    // "No access" shares nothing named on the command line, not even
    // read-only: it used to share like "Read-only", so the setting said
    // less than the sandbox gave.
    let rw = match ctx.permissions.filesystem.opened_files {
        Access::None => return Vec::new(),
        Access::Ro => false,
        Access::Rw => true,
    };
    shareable_paths_in(ctx, views, rw)
}

/// The files and folders named on the command line that SAM would share
/// but does not, because files opened with the app are set to "No access"
/// (`filesystem.opened_files = "none"`): what the start line and the
/// launch log name, so that a person learns why the app cannot open the
/// file. A file the app sees anyway (inside a granted folder) is not
/// named, and nothing is named under "Read-only" or "Read & write".
pub fn withheld_opened_paths(ctx: &LaunchContext) -> Vec<PathBuf> {
    withheld_opened_paths_in(ctx, &Views::base(ctx))
}

/// [`withheld_opened_paths`] against the grants `views` ([`Views::base`]).
fn withheld_opened_paths_in(ctx: &LaunchContext, views: &Views) -> Vec<PathBuf> {
    if ctx.permissions.filesystem.opened_files != Access::None {
        return Vec::new();
    }
    shareable_paths_in(ctx, views, false)
        .into_iter()
        .map(|(p, _)| p)
        .collect()
}

/// Every file and folder named on the command line that may be shared
/// (the rules of [`opened_paths`]), each with `rw`; what the setting
/// allows of them decides the caller.
fn shareable_paths_in(ctx: &LaunchContext, views: &Views, rw: bool) -> Vec<(PathBuf, bool)> {
    let refused = sam_core::places::refused_for_opened(&ctx.host.home);
    shareable_paths_with(ctx, views, rw, &refused)
}

/// [`shareable_paths_in`] against the places `refused`, built once per
/// call.
fn shareable_paths_with(
    ctx: &LaunchContext,
    views: &Views,
    rw: bool,
    refused: &sam_core::places::RefusedForOpened,
) -> Vec<(PathBuf, bool)> {
    let home = &ctx.host.home;
    let on_drive = |p: &Path| {
        ["/media", "/mnt", "/run/media"]
            .iter()
            .any(|d| p.starts_with(d))
    };
    // SAM's folders, as named and where they really are. A folder holding
    // one of them may be opened (SAM's folder is hidden inside it); one
    // holding a start place, a credential store or the home not
    // (`refused.holds`).
    let sam: Vec<PathBuf> = sams_folders(ctx)
        .into_iter()
        .flat_map(|p| {
            let r = resolve(&p);
            [p, r]
        })
        .collect();
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
        // One walk: the path judged is the path bound (Bubblewrap
        // follows it again when it mounts it).
        let way = sam_core::places::follow(&joined);
        if refused.refuses(&joined, &way) {
            continue;
        }
        let real = way.leads;
        let Ok(meta) = fs::metadata(&real) else {
            continue;
        };
        if views.visible(&real)
            || sam.iter().any(|d| real.starts_with(d))
            || (meta.is_dir() && refused.holds(&real))
        {
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
        // The person's raw arguments come right before SAM's last ones
        // (`--remount-ro /`, then its helper): an option there missing its
        // values would take them, and a word where an option belongs would
        // run instead of the app; either way the root would stay writable
        // without a word (review B2 R58, independent review of PR 133).
        if let Some(problem) = raw_problem(&ctx.permissions.advanced.extra_bwrap_args) {
            anyhow::bail!(
                "{}",
                match problem {
                    RawProblem::Unfinished(option) => sam_core::i18n::trf(
                        "the extra Bubblewrap arguments end with {option}, which needs more values; SAM does not start the app until the setting is complete",
                        &[("option", &option)]
                    ),
                    RawProblem::NotAnOption(word) => sam_core::i18n::trf(
                        "the extra Bubblewrap arguments hold {word} where an option belongs, which Bubblewrap would run instead of the app; SAM does not start the app until the setting is fixed",
                        &[("word", &word)]
                    ),
                    RawProblem::Unknown(option) => sam_core::i18n::trf(
                        "the extra Bubblewrap arguments hold {option}, an option SAM does not know; SAM does not start the app until the setting is changed",
                        &[("option", &option)]
                    ),
                }
            );
        }
        let var = |v: &str| std::env::var_os(v).map(PathBuf::from);
        if let Some(odd) = odd_config_folder(
            var("XDG_CONFIG_HOME").as_deref(),
            var("XDG_DATA_HOME").as_deref(),
        ) {
            if odd.to_str().is_none() {
                anyhow::bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "SAM cannot pass on {path}: its name is not valid text. Rename it, then start the app again.",
                        &[("path", &odd.display())]
                    )
                );
            }
            anyhow::bail!(
                "{}",
                sam_core::i18n::trf(
                    "SAM cannot pass on {path}: its name holds \"..\". Set the folder without \"..\", then start the app again.",
                    &[("path", &odd.display())]
                )
            );
        }
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
        // The extra writable folders decided once, for the views and the
        // mounts alike ([`WriteGrant`]).
        let writes = write_grants(ctx);
        let base = Views::of_writes(ctx, &writes);
        let opened = opened_paths_in(ctx, &base);
        let withheld = withheld_opened_paths_in(ctx, &base);
        let views = Views::with_opened(ctx, base, &opened);
        let mut s = Section {
            ctx,
            a: Args::default(),
            notes: Vec::new(),
            exec_env: Vec::new(),
            opened,
            withheld,
            writes,
            views,
            sams: sams_folders(ctx),
            watched_devices: Vec::new(),
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
        if let Some(odd) = s.a.bad.first() {
            anyhow::bail!(
                "{}",
                sam_core::i18n::trf(
                    "SAM cannot pass on {path}: its name is not valid text. Rename it, then start the app again.",
                    &[("path", &odd.display())]
                )
            );
        }
        let generated_files = vec![
            ctx.runtime_dir.join("passwd"),
            ctx.runtime_dir.join("group"),
            ctx.runtime_dir.join("hosts"),
        ];
        Ok(SandboxCommand {
            program: bwrap.path.clone(),
            args: s.a.v,
            exec_env: s.exec_env,
            notes: s.notes,
            generated_files,
            watched_devices: s.watched_devices,
        })
    }
}

/// The Bubblewrap command, one part per method (see `Bubblewrap::build`).
struct Section<'c> {
    ctx: &'c LaunchContext,
    a: Args,
    notes: Vec<String>,
    /// The app's own variables, for SAM's helper to set ([`SandboxCommand::exec_env`]).
    exec_env: Vec<(String, String)>,
    /// The files named on the command line that are granted, worked out
    /// once per start (audit S-F13: four times before).
    opened: Vec<(PathBuf, bool)>,
    /// The files named on the command line that are not shared because of
    /// "No access" ([`withheld_opened_paths`]), named in the notes.
    withheld: Vec<PathBuf>,
    /// The extra writable folders, decided once ([`write_grants`]).
    writes: Vec<WriteGrant>,
    /// Every grant ([`Views::of`]).
    views: Views,
    /// SAM's own folders in this start ([`sams_folders`]).
    sams: Vec<PathBuf>,
    /// Devices shown by name ([`SandboxCommand::watched_devices`]).
    watched_devices: Vec<sam_core::sandbox::WatchedDevice>,
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
        // normally. Each is covered by its stand-in from `TOOL_SHIMS`.
        // Bubblewrap cannot mount over a link, so the stand-in goes over the
        // file a link leads to (audit S-F14: a systemd-run that was a link
        // stayed the real one).
        cover_host_tools(a, &ctx.runtime_dir, HIDDEN_HOST_TOOLS);

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
                a.push("--overlay-src").path(&ctx.appdir);
                a.push("--overlay")
                    .path(base.join("upper"))
                    .path(base.join("work"))
                    .path(&ctx.sandbox_appdir);
            }
            _ => a.op2("--ro-bind", &ctx.appdir, &ctx.sandbox_appdir),
        }
        // Bundled libraries replaced by the system's copy, read-only.
        for (host, inside) in system_library_binds(ctx) {
            a.op2("--ro-bind", host, inside);
        }
        if let Some(img) = &ctx.appimage_path {
            if let Some(name) = img.file_name() {
                a.op2(
                    "--ro-bind-try",
                    img,
                    sam_core::sandbox::appimage_inside(name),
                );
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
        // The user folders bound at a place of their own, for the pins.
        let mut own_mounts: Vec<PathBuf> = Vec::new();
        // Every place bound writable below the home, for the pins: what is
        // mounted, never what the views record (a writable user folder the
        // whole home already shows gets no mount of its own).
        let mut writable_mounts: Vec<PathBuf> = Vec::new();
        // User folders set to one place at different access are all shown
        // read-only there ([`sam_core::places::user_folder_access`]); the
        // start says which and why, as the app page does.
        for (place, keys) in sam_core::places::user_folders_at_one_place(p, h) {
            if !inside_sam(ctx, &place) {
                notes.push(sam_core::places::user_folders_at_one_place_note(
                    &keys, &place,
                ));
            }
        }
        let mut mounts: Vec<(usize, Args)> = Vec::new();
        let mut mount = |at: &Path, f: &dyn Fn(&mut Args)| {
            let mut m = Args::default();
            f(&mut m);
            if !m.v.is_empty() || !m.bad.is_empty() {
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
            // Each granted user folder at its own access, as the switch
            // says and as the views record it, wherever the home does not
            // already show it at exactly that access: writable in a
            // read-only home (regression: it stayed read-only), read-only
            // in a writable home (finding R63: a start file kept as a link
            // into a "read-only" Documents stayed writable through the
            // home, and no lock reached it), and outside the home at all
            // (`XDG_DOCUMENTS_DIR=/data/Documents` was not shown). The
            // protections inside come after it (`guard_home`).
            for key in XDG_DIR_KEYS {
                let acc = sam_core::places::user_folder_access(p, h, key);
                if !acc.is_granted() {
                    continue;
                }
                let real = match user_dir(ctx, key) {
                    Ok(real) => real,
                    // Seen through the home where it lies in it, at the
                    // home's access, as before.
                    Err(NotShown::Missing | NotShown::Refused(_)) => continue,
                    Err(why) => {
                        notes.push(user_folder_note(
                            key,
                            &why,
                            fsp.xdg_access(key) == Access::Rw,
                        ));
                        continue;
                    }
                };
                // Two user folders at one place (Music read and write,
                // Pictures read-only, both `~/Media`) take the stricter
                // access, as the views record it and the sandbox check
                // expects it ([`sam_core::places::user_folder_access`]),
                // and are mounted once, for the last of them. Judged one by
                // one against the home, the read-only one was mounted and
                // the writable one left to the home, so the folder was
                // read-only while the views said writable.
                let later_at_same_place = XDG_DIR_KEYS
                    .iter()
                    .skip_while(|k| **k != key)
                    .skip(1)
                    .any(|k| {
                        fsp.xdg_access(k).is_granted() && user_dir(ctx, k).as_ref() == Ok(&real)
                    });
                if later_at_same_place {
                    continue;
                }
                let rw = acc == Access::Rw;
                if home_shows_exactly(&self.views, &home, &real, rw) {
                    continue;
                }
                let op = if rw { "--bind-try" } else { "--ro-bind-try" };
                mount(&real, &|m| m.op2(op, &real, &real));
                own_mounts.push(real.clone());
                if rw {
                    writable_mounts.push(real.clone());
                }
                // A link where the app looks for it when that is a link
                // outside the home; one in the home is shown with it.
                if let Some(dir) = h
                    .xdg_dir(key)
                    .filter(|d| *d != real && !d.starts_with(&home) && real.exists())
                {
                    mount(dir, &|m| m.op2("--symlink", &real, dir));
                }
            }
        } else {
            if p.advanced.persistent_home {
                // The launch pipeline creates the directory; build() has no side effects.
                mount(&home, &|m| m.op2("--bind", &ctx.private_home, &home));
            } else {
                mount(&home, &|m| {
                    m.push("--tmpfs").path(&home);
                });
            }
            // The folders every home has: some apps create theirs with a
            // plain mkdir and fail without the parent (night run 2026-11-18:
            // Widelands could not create ~/.local/share/widelands).
            for d in [".config", ".local/share", ".local/state", ".cache"] {
                let dir = home.join(d);
                mount(&dir, &|m| {
                    m.push("--dir").path(&dir);
                });
            }
            for key in XDG_DIR_KEYS {
                // Two at one place both at the stricter access, as above.
                let acc = sam_core::places::user_folder_access(p, h, key);
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
                        own_mounts.push(real.clone());
                        if acc == Access::Rw {
                            writable_mounts.push(real.clone());
                        }
                        if let Some(dir) = h.xdg_dir(key).filter(|d| *d != real) {
                            mount(dir, &|m| m.op2("--symlink", &real, dir));
                        }
                    }
                    Err(why) => notes.push(user_folder_note(
                        key,
                        &why,
                        fsp.xdg_access(key) == Access::Rw,
                    )),
                }
            }
        }
        // The places bound read-only below, for the pins: the views do not
        // record them, so a pin on or inside one (`~/.fonts` above an extra
        // read-only folder `~/.fonts/licensed`) counted writable, landed
        // after the read-only bind and made the place writable. Not one
        // where a writable place is bound after it at its own place (an
        // extra writable folder, an opened folder, a bind of SAM's): that
        // bind covers it, and the place is writable.
        let mut read_only: Vec<PathBuf> = Vec::new();
        let bound_writable_after = |at: &Path| {
            self.writes
                .iter()
                .any(|g| g.how == WriteBind::Writable && g.bound == at)
                || self.opened.iter().any(|(o, rw)| *rw && o == at)
                || ctx.extra_binds.iter().any(|(_, sb, rw)| *rw && sb == at)
        };
        // The fonts, the fonts settings and, with host themes, the theme
        // files, read-only, only where neither the place nor a folder on
        // its way in the home is a link
        // ([`sam_core::places::own_place_decision`]): anyone who can write
        // in the home (another app with the whole home writable, an
        // earlier start with more rights) can make `~/.fonts` a link to
        // any folder, and a private home showed that folder as the fonts.
        // Where a grant shows the place already at its name, the bind
        // lands wherever the app reaches it and only takes write access
        // away; in a private home it lands at its name too, never at or
        // around a guarded place. That holds where a grant shows the place
        // only under another name (with `/home/u` a link to `/data/u`, an
        // extra `~/.config` recorded at `/data/u/.config`): the bind at
        // `/home/u/.config/fontconfig` in the private home is a mount of
        // its own, which the home's protections at `/data/u` never reach,
        // so a credential kept as a link into it was shown there. For a
        // guarded place, only the narrowing binds where the grant shows
        // it. One note names every link skipped.
        let guarded_named = sam_core::places::guarded_places_named(&home, &self.sams);
        let guarded = sam_core::places::guarded_places_everywhere(&home, &self.sams);
        let shown = |at: &Path| !self.views.seen_at(at).is_empty();
        let shown_at_name = |at: &Path| self.views.visible(at);
        let mut own_bound: Vec<PathBuf> = Vec::new();
        // The places kept read-only behind a link in a folder the app
        // cannot change: the folders above each are pinned like those
        // above a guarded place.
        let mut own_locked: Vec<PathBuf> = Vec::new();
        let mut bound_rels: Vec<&str> = Vec::new();
        let mut skipped: Vec<sam_core::places::OwnLinkSkipped> = Vec::new();
        let mut kept: Vec<PathBuf> = Vec::new();
        let real_home = resolve(&home);
        for rel in own_home_places(p) {
            let named = home.join(rel);
            // `lock`: a bind at a place a writable grant shows, which a
            // note says SAM keeps read-only. `read_only_targets` gives no
            // name that is not valid text (such a link is only named, and
            // the start runs); [`Args::lock`] still makes sure no such bind
            // is ever dropped without a word while the note claims it.
            let (places, lock) = match sam_core::places::own_place_decision(
                h,
                rel,
                &shown_at_name,
                &guarded_named,
                &guarded,
            ) {
                sam_core::places::OwnBind::Bind => {
                    bound_rels.push(rel);
                    (own_mount_points(&self.views, &named), false)
                }
                sam_core::places::OwnBind::Missing => (Vec::new(), false),
                sam_core::places::OwnBind::Link(link) => {
                    // A link whose target a writable grant shows: that
                    // target stays read-only there, as before the rule;
                    // it protects something where the app cannot change
                    // the link itself. Only narrowing: the bind shows
                    // nothing a grant does not show already, and the
                    // folders above it are pinned (`own_locked`). Never for a
                    // target by a name that is not valid text
                    // ([`Views::read_only_targets`]).
                    let mut targets = Vec::new();
                    if link.exists {
                        let target = resolve(&real_home.join(rel));
                        targets = self.views.read_only_targets(&home, &target);
                        if !targets.is_empty() && !kept.contains(&target) {
                            kept.push(target);
                        }
                        // Pinned only where the app cannot change the
                        // folder that holds the link: where it can (the
                        // whole home writable), it can replace the link
                        // itself, and pins there only made `mv ~/dotfiles`
                        // fail.
                        let link_fixed =
                            link.link.parent().is_some_and(|d| !self.views.writable(d));
                        if link_fixed {
                            own_locked.extend(targets.iter().cloned());
                        }
                    }
                    skipped.push(sam_core::places::OwnLinkSkipped {
                        rel,
                        shown: shown(&named),
                        link,
                    });
                    (targets, true)
                }
                why => {
                    notes.extend(sam_core::places::own_place_guarded_note(h, rel, &why));
                    // Never at its name; only where a grant shows it under
                    // another name, which takes write access away.
                    (self.views.mount_points(&named), false)
                }
            };
            for at in places {
                if own_bound.contains(&at) {
                    continue;
                }
                if lock {
                    mount(&at, &|m| m.lock(&at));
                } else {
                    mount(&at, &|m| m.ro(&at));
                }
                if !bound_writable_after(&at) {
                    read_only.push(at.clone());
                }
                own_bound.push(at);
            }
        }
        notes.extend(sam_core::places::own_place_links_note(
            h,
            &this_start(ctx),
            &skipped,
            &kept,
        ));
        if p.advanced.host_themes && !fsp.home {
            // Deeper than its folder, so mounted after it, and only below
            // a theme folder bound above: below one skipped for a link,
            // the mask followed the link and left an empty file in the
            // sandbox's home or the private home on disk. Only a plain
            // file: Bubblewrap cannot mount over a link.
            for f in THEME_PRIVATE_FILES {
                let at = home.join(f);
                if bound_rels.iter().any(|r| Path::new(f).starts_with(r))
                    && !self.views.visible(&at)
                    && fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_file())
                {
                    mount(&at, &|m| m.op2("--ro-bind", "/dev/null", &at));
                }
            }
        }
        // Extra folders, at their resolved place: what the app sees there.
        // Never one reached through a link that could take it somewhere it
        // must not lead ([`read_grant_left_out`]).
        for c in &fsp.custom_read {
            if let Some(why) = read_grant_left_out(ctx, c) {
                notes.push(sam_core::places::left_out_note(
                    c,
                    &why,
                    sam_core::places::LeftOutPlace::Extra,
                    false,
                ));
                continue;
            }
            let path = grant_path(c);
            mount(&path, &|m| m.op2("--ro-bind-try", &path, &path));
        }
        // One inside a start place (`~/.config/fish/conf.d`) read-only,
        // with or without the whole home: without it the place itself is
        // not shown, so `guard_home` does not lock it, and a file planted
        // there ran at the next shell outside the sandbox (owner decision 9
        // of 2026-11-23).
        // Each at the place decided once ([`WriteGrant`]), never resolved
        // again; one below a folder the app can already change not at all.
        for g in &self.writes {
            let op = match &g.how {
                WriteBind::Writable => "--bind-try",
                WriteBind::ReadOnly(found) => {
                    // Read-only words also for a place named like SAM's
                    // folders that only counts as a start place (a link),
                    // saying where it leads when that is the home or above.
                    notes.push(sam_core::places::start_place_note(&g.written, found));
                    "--ro-bind-try"
                }
                WriteBind::Below(folder) => {
                    notes.push(sam_core::i18n::trf(
                        "{path} lies inside {folder}, which the app can already change, so SAM does not bind it a second time.",
                        &[("path", &g.written), ("folder", &sam_core::util::tildify(folder))],
                    ));
                    continue;
                }
                WriteBind::InsideSam => {
                    notes.push(sam_core::places::inside_sams_folders_note(&g.written));
                    continue;
                }
                WriteBind::LeftOut(why) => {
                    notes.push(sam_core::places::left_out_note(
                        &g.written,
                        why,
                        sam_core::places::LeftOutPlace::Extra,
                        true,
                    ));
                    continue;
                }
            };
            let path = &g.bound;
            mount(path, &|m| m.op2(op, path, path));
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
        // Named, not shared: the log says why the app cannot open it.
        for path in self.withheld.clone() {
            notes.push(sam_core::i18n::trf(
                "did not share {path}, named when starting the app: files you open with this app are set to No access",
                &[("path", &path.display())],
            ));
        }
        let views = &self.views;
        // An extra folder shown read-only for a start place counts as a
        // guarded place: the folders above it that the app can change are
        // pinned, so renaming one (`mv ~/work/dots ~/work/x`) cannot carry
        // the read-only mount away and leave a writable fresh folder in its
        // place (as R50 for start places kept through links).
        let mut guarded = guarded_places(&home, fsp);
        guarded.extend(
            self.writes
                .iter()
                .filter(|g| matches!(g.how, WriteBind::ReadOnly(_)))
                .map(|g| g.bound.clone()),
        );
        // So is every other folder bound at an access of its own inside a
        // folder the app can change: a user folder bound at its own access
        // (Documents read-only in `~/Sync` under the writable home), a
        // read-only extra folder, and an extra writable folder bound
        // inside a read-only one ([`write_grants`]). A second start of this
        // app with these permissions (starts take the app lock shared)
        // could otherwise rename a folder above it (`mv ~/Sync ~/S2`),
        // which carries the mount along, and put a link in its place
        // between SAM's look and Bubblewrap's mount: the next start bound
        // where the link led, a key folder read-only or a start place
        // writable (review of finding R63). That start has the same pins,
        // so the rename fails.
        guarded.extend(own_mounts);
        // And a place SAM keeps read-only behind a font or theme link
        // ([`Views::read_only_targets`]), strictly inside a writable grant:
        // renaming a folder between the grant and it (`mv
        // ~/dotfiles/fontconfig ~/dotfiles/x` with `~/.config/fontconfig` a
        // link to `../dotfiles/fontconfig/.config/fontconfig`) carried the
        // read-only bind away, and the app put new font rules at the old
        // place, which programs outside the sandbox load through the link.
        guarded.extend(own_locked);
        guarded.extend(fsp.custom_read.iter().map(|c| grant_path(c)));
        guarded.extend(
            self.writes
                .iter()
                .filter(|g| g.how == WriteBind::Writable)
                .map(|g| g.bound.clone()),
        );
        // Bound writable after the places bound read-only below, by depth:
        // the extra writable folders, the opened ones and SAM's own binds,
        // besides the user folders above.
        writable_mounts.extend(
            self.writes
                .iter()
                .filter(|g| g.how == WriteBind::Writable)
                .map(|g| g.bound.clone()),
        );
        writable_mounts.extend(
            self.opened
                .iter()
                .filter(|(_, rw)| *rw)
                .map(|(o, _)| o.clone()),
        );
        writable_mounts.extend(
            ctx.extra_binds
                .iter()
                .filter(|(_, _, rw)| *rw)
                .map(|(_, sb, _)| sb.clone()),
        );
        // The folders above SAM's own folders in this start
        // ([`sams_folders`]): where this SAM keeps its own, and the folders
        // that `SAM_CONFIG_DIR` and `SAM_DATA_DIR` name, which an installed
        // SAM hides but never uses. Renamed (`mv ~/Games ~/G` with
        // `SAM_DATA_DIR=~/Games/sam`), the empty folder moved along, and
        // the next start no longer found the old folder to hide (batch
        // review of the change that made release builds ignore these
        // switches). Those above the folders named like them are pinned as
        // above every protected place, which they are
        // (`protected_ancestors`, and where a link among them leads through
        // `guarded`).
        let sams = &self.sams;
        for p in pins(
            &home,
            views,
            &guarded,
            sams,
            &ctx.sam_programs,
            &ReadOnlyBinds {
                places: &read_only,
                writable_mounts: &writable_mounts,
            },
        ) {
            mount(&p, &|m| m.op2("--bind", &p, &p));
        }
        // With the whole home writable, a protected place this start does
        // not hide that really is the home (`~/.config/sam` planted as a
        // link to it) is locked read-only where the app reaches it, which
        // is the whole home (`guard_home`): the start says so, from the
        // answer the sandbox check and the app page take (independent
        // review of decision 9: the home turned read-only without a word).
        if fsp.home && fsp.home_access == Access::Rw {
            if let Some(place) = sam_core::places::protected_place_at_home(&home, sams) {
                notes.push(sam_core::places::home_read_only_note(&place));
            }
        }
        // Stable: at equal depth, the order above stays (a pin after the
        // grant it is in).
        mounts.sort_by_key(|(d, _)| *d);
        let a = &mut self.a;
        for (_, m) in mounts {
            a.v.extend(m.v);
            a.bad.extend(m.bad);
        }
        guard_home(a, &home, fsp, views, sams);
        guard_programs(a, &ctx.sam_programs, views);
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
            let found = sort_gamepad_nodes(&h.input_devices.nodes, &h.input_devices.udev_data);
            let list = |v: &[PathBuf]| {
                v.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            if !found.refused.is_empty() {
                notes.push(sam_core::i18n::trf(
                    "Not shown as game controllers, as they also report themselves as a keyboard or mouse: {nodes}",
                    &[("nodes", &list(&found.refused))],
                ));
            }
            if !found.unknown.is_empty() {
                notes.push(sam_core::i18n::trf(
                    "Not shown as game controllers, as udev has no record of what they are: {nodes}",
                    &[("nodes", &list(&found.unknown))],
                ));
            }
            if found.shown.is_empty() && found.refused.is_empty() && found.unknown.is_empty() {
                notes.push(sam_core::i18n::tr("No game controller is plugged in; controllers connected later are not seen until the app restarts"));
            }
            bind_watched(
                a,
                &mut self.watched_devices,
                &h.input_devices.nodes,
                found.shown,
            );
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
        // grant access to a folder or an ordinary file. Bound from where
        // their links lead, checked there (review SB-4: an app that could
        // write the socket's folder replaced the socket with a link to the
        // real session bus, and the bind followed it).
        let views = &self.views;
        // Writable for the app: its grants (seen at their real place),
        // SAM's folders (its private home among them) and the host side of
        // a writable extra bind (the views know only where those are shown).
        // `shown_writable`: also under another name of the same place (the
        // home kept behind a link, `/home` to `/var/home`).
        let app_can_change = |d: &Path| {
            shown_writable(views, d)
                || inside_sam(ctx, d)
                || ctx
                    .extra_binds
                    .iter()
                    .any(|(h, _, rw)| *rw && d.starts_with(resolve(h)))
        };
        for s in &p.sockets.custom {
            let sp = expand_home(s);
            if link_the_app_can_change(&sp, &app_can_change) {
                notes.push(sam_core::i18n::trf(
                    "{path} is reached through a link in a folder the app can change; it is not passed into the sandbox. List the socket by its real place.",
                    &[("path", &sp.display())],
                ));
                continue;
            }
            let real = resolve(&sp);
            // Checked here, bound by name later: in a folder the app can
            // change, a running copy of it could swap the socket for a
            // link to another one (the session bus) in between, and the
            // bind would follow that link (review B2 R55). Every folder
            // above it counts too: a folder the app can rename moves a
            // read-only grant below it along, and a new one takes its name.
            if real.ancestors().skip(1).any(app_can_change) {
                notes.push(sam_core::i18n::trf(
                    "{path} lies below a folder the app can change, so the app could swap it for another socket during the start; this setting does not pass it in. Where the app may use that folder, it still reaches the socket there.",
                    &[("path", &sp.display())],
                ));
                continue;
            }
            if !is_socket(&real) {
                notes.push(sam_core::i18n::trf(
                    "{path} is not a socket; it is not passed into the sandbox",
                    &[("path", &sp.display())],
                ));
                continue;
            }
            let shown = sp.to_string_lossy();
            let lands = real.to_string_lossy();
            // Passed in only when the listed name was rated dangerous in
            // the same way as where it leads: a name that looks like a key
            // agent must not open the session bus, while Docker's name may
            // lead to Podman (review of owner decision 11 of 2026-11-23).
            let kind = sam_core::permissions::dangerous_socket_kind;
            if let Some(why) = sam_core::permissions::dangerous_socket(&lands)
                .filter(|_| kind(&shown) != kind(&lands))
            {
                notes.push(sam_core::i18n::trf(
                    "{path} leads elsewhere: {why}. It is not passed into the sandbox; list that socket by its real place if the app needs it.",
                    &[("path", &sp.display()), ("why", &why)],
                ));
                continue;
            }
            a.op2("--bind-try", &real, &sp);
        }

        // SAM's own folders, wherever they are: an empty, throwaway folder
        // in their place whenever anything would show them: a grant, a
        // folder opened with the app ("Open with", a path on the command
        // line) or a bind of SAM's runner. Otherwise an app could change
        // another app's unpacked files (regression: an opened folder on a
        // drive that held SAM's moved unpack folder showed it, writable).
        // Every place the sandbox shows them, also through a link in a
        // granted path (audit S-F3). Also the folders named like them that
        // count as SAM's in this start ([`sams_folders`]), wherever they
        // lead (independent reviews of decision 9).
        let views = &self.views;
        let sams = &self.sams;
        for d in sams {
            // A folder inside another hidden one is hidden with it.
            let nested = sams.iter().any(|o| o != d && d.starts_with(o));
            if nested || !d.is_dir() {
                continue;
            }
            // Where the app reaches it, never through a link
            // (`Views::mount_points`): with `~/.config` a link to a place
            // nothing grants, the empty folder on `~/.config/sam` stopped
            // every start with the whole home granted (security review
            // 2026-11-23, SB-6). Also where a grant shows only something
            // inside it (audit S-F13: a folder granted inside SAM's moved
            // folder was shown); no grant shows a folder above that place,
            // so the way there leads through no link inside.
            let mut places = views.mount_points(d);
            for c in [d.clone(), resolve(d)] {
                if !views.visible(&c) && views.shows_any_of(&c) && !places.contains(&c) {
                    places.push(c);
                }
            }
            for c in places {
                a.push("--tmpfs").path(&c);
            }
            // Where a bind shows it under another path in the sandbox.
            for (h, sb, _) in &ctx.extra_binds {
                if h != sb {
                    if let Ok(rel) = d.strip_prefix(h) {
                        a.push("--tmpfs").path(sb.join(rel));
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
        // Where the app starts, never a folder it cannot see (audit L-F16:
        // `cd ~/private/clientX && sam-jail run app` told the app that
        // path, even without access to the home).
        // As text here: a name that is not text has already stopped the
        // start where the home is mounted and at `--chdir`.
        let start_dir = self.start_dir().to_string_lossy().into_owned();
        let a = &mut self.a;
        // Environment.
        a.setenv("HOME", home.to_string_lossy());
        a.setenv("USER", &h.user);
        a.setenv("LOGNAME", &h.user);
        a.setenv("SHELL", "/bin/sh");
        if p.dbus.session.mode != DbusMode::None {
            // Link opener shims (see OPEN_SHIM), written by write_identity_files,
            // and Room service's stand-in for Bubblewrap.
            a.op2("--ro-bind-try", ctx.runtime_dir.join("bin"), "/run/sam/bin");
            a.setenv("PATH", "/run/sam/bin:/usr/local/bin:/usr/bin:/bin");
        } else if ctx.room_socket.is_some() {
            // Without the bus, no link openers (they need it): only Room
            // service's stand-in for Bubblewrap.
            a.op2(
                "--ro-bind-try",
                ctx.runtime_dir.join("bin-rooms"),
                "/run/sam/bin",
            );
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
        for k in ENV_FORWARD {
            if let Some(v) = forwarded_value(k, |n| std::env::var(n).ok()) {
                a.setenv(k, v);
            }
        }
        // The app's own variables, last, so they win as before. With SAM's
        // helper they go to the helper's file instead: it sets them for the
        // app alone once its layers are in place. Its own loader never sees
        // them, so `LD_PRELOAD=/opt/app/lib/x.so` or `LD_LIBRARY_PATH` cannot
        // run the app's code before Landlock and the syscall filter (review
        // SB-5).
        let mut own: Vec<(String, String)> = Vec::new();
        for k in &p.environment.passthrough {
            if let Some(v) = forwarded_value(k, |n| std::env::var(n).ok()) {
                own.push((k.clone(), v));
            }
        }
        for (k, v) in ctx.resolved_app_env(&ctx.appdir_in_sandbox()) {
            own.push((k, v));
        }
        own.push(("OWD".into(), start_dir));
        for (k, v) in &p.environment.set {
            // Only proper variable names; values may be anything but NUL.
            let valid = k
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if valid && !v.contains('\0') {
                own.push((k.clone(), v.clone()));
            }
        }
        if ctx.helper.is_some() {
            self.exec_env = own;
        } else {
            for (k, v) in own {
                a.setenv(&k, v);
            }
        }
    }

    /// The folder the app starts in: the one it was started from, if the app
    /// sees it (granted, or holding a file named on the command line, `hx
    /// notes.txt`, so that relative names find the file); else its home.
    fn start_dir(&self) -> PathBuf {
        let ctx = self.ctx;
        let in_owd = self
            .opened
            .iter()
            .any(|(p, _)| p.starts_with(&ctx.owd) || ctx.owd.starts_with(p));
        let views = &self.views;
        if views.visible(&ctx.owd) || views.visible(&resolve(&ctx.owd)) || in_owd {
            ctx.owd.clone()
        } else {
            ctx.host.home.clone()
        }
    }

    /// Working directory, SAM's helper (Landlock, syscall filter, the app's start), extra arguments, and the command itself.
    fn finish_command(&mut self) {
        let ctx = self.ctx;
        let p = &ctx.permissions;
        // Working directory: the same folder as `$OWD`.
        let chdir = self.start_dir();
        let a = &mut self.a;
        a.push("--chdir").path(&chdir);

        // Room service's socket.
        if let Some(socket) = &ctx.room_socket {
            a.op2("--bind", socket, "/run/sam/rooms");
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

/// What is wrong with the person's raw Bubblewrap arguments, read the way
/// Bubblewrap reads them, each option with its values.
#[derive(Debug, PartialEq, Eq)]
enum RawProblem {
    /// The list ends inside this option, still missing values: they would
    /// be taken from SAM's own arguments after it.
    Unfinished(String),
    /// A word where an option belongs (or `--`): Bubblewrap would take it
    /// as the program to run, before SAM's read-only root and its helper.
    NotAnOption(String),
    /// An option SAM does not know: how many values follow is unknown.
    Unknown(String),
}

/// The first problem in the raw arguments `args`, if any.
fn raw_problem(args: &[String]) -> Option<RawProblem> {
    let mut i = 0;
    while let Some(word) = args.get(i) {
        if word == "--" || !word.starts_with("--") {
            return Some(RawProblem::NotAnOption(word.clone()));
        }
        let Some(n) = sam_core::sandbox::bwrap_values(word) else {
            return Some(RawProblem::Unknown(word.clone()));
        };
        if i + n >= args.len() && n > 0 {
            return Some(RawProblem::Unfinished(word.clone()));
        }
        i += 1 + n;
    }
    None
}

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
            .find(|p| system_copy_ok(p))
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

/// Whether `p` (a resolved path) may replace a bundled library: a plain
/// file of the system's, under /usr or /lib.
fn system_copy_ok(p: &Path) -> bool {
    p.is_file() && (p.starts_with("/usr") || p.starts_with("/lib"))
}

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
    // Readable by the user alone from the moment it exists, and a link
    // left at its place is replaced, not followed (audit S-F18).
    sam_core::util::atomic_write(&ctx.runtime_dir.join("Xauthority"), &out)
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

/// Write the synthetic passwd/group files referenced by the command.
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

/// Whether reaching `p` passes a link that sits in a folder the app can
/// change (`app_can_change`, asked with the folder's real place): the app
/// could have put that link there, pointing anywhere. Followed the way the
/// kernel does, link by link; a path with too many links counts as one
/// (the one rule every bind through links takes,
/// [`sam_core::places::link_the_app_could_plant`]).
fn link_the_app_can_change(p: &Path, app_can_change: &dyn Fn(&Path) -> bool) -> bool {
    let way = sam_core::places::follow(p);
    sam_core::places::link_the_app_could_plant(&way, app_can_change).is_some()
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

/// Shows each device node by name and notes what it is now, so that SAM
/// takes it out of the running sandbox once its name shows anything else
/// (unplugged, or another device at its number: sam-runner `device_watch`,
/// review R56). A node that is gone already is not shown. Their folder
/// (`dir`) is a read-only folder of its own: as a mount point it cannot be
/// renamed or replaced from inside, so the node SAM takes out is always at
/// the name SAM knows.
fn bind_watched(
    a: &mut Args,
    watched: &mut Vec<sam_core::sandbox::WatchedDevice>,
    dir: &Path,
    nodes: Vec<PathBuf>,
) {
    use std::os::unix::fs::MetadataExt;
    a.push("--tmpfs").path(dir);
    for d in nodes {
        let Ok(md) = fs::metadata(&d) else {
            continue;
        };
        let before = a.v.len();
        a.op2("--dev-bind-try", &d, &d);
        if a.v.len() == before {
            continue;
        }
        watched.push(sam_core::sandbox::WatchedDevice {
            path: d,
            dev: md.dev(),
            ino: md.ino(),
            rdev: md.rdev(),
        });
    }
    a.push("--remount-ro").path(dir);
}

/// What udev records for an input device that also makes it a keyboard
/// or a pointer (a mouse or something that moves the pointer like one).
/// A device with any of these is never passed as a game controller, also
/// when it reports itself as a joystick too (review R56). Any value but
/// `0` counts.
const NOT_A_GAME_CONTROLLER: [&str; 6] = [
    "ID_INPUT_KEYBOARD",
    "ID_INPUT_MOUSE",
    "ID_INPUT_TOUCHPAD",
    "ID_INPUT_TOUCHSCREEN",
    "ID_INPUT_TABLET",
    "ID_INPUT_POINTINGSTICK",
];

/// The input nodes "Game controllers" looked at, sorted by what is done
/// with them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GamepadNodes {
    /// Joysticks, shown to the app.
    pub shown: Vec<PathBuf>,
    /// Joysticks that also report themselves as a keyboard or pointer.
    pub refused: Vec<PathBuf>,
    /// Joystick nodes (`js*`) and other input nodes udev has no record
    /// for: what they are cannot be told.
    pub unknown: Vec<PathBuf>,
}

/// Joystick device nodes: `js*` and `event*` nodes that udev recorded as
/// a joystick (`E:ID_INPUT_JOYSTICK=1` in `/run/udev/data/c13:<minor>`)
/// and not also as a keyboard or pointer ([`NOT_A_GAME_CONTROLLER`]), so
/// the app cannot log keystrokes or follow the pointer. A node udev has no
/// record for is left out: what it is cannot be told.
pub fn gamepad_nodes(dev_input: &Path, udev_data: &Path) -> Vec<PathBuf> {
    sort_gamepad_nodes(dev_input, udev_data).shown
}

/// [`gamepad_nodes`], with what was left out and why.
pub fn sort_gamepad_nodes(dev_input: &Path, udev_data: &Path) -> GamepadNodes {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut out = GamepadNodes::default();
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
        let js = name.starts_with("js");
        if !(js || name.starts_with("event")) {
            continue;
        }
        let rdev = md.rdev();
        let (major, minor) = (libc_major(rdev), libc_minor(rdev));
        let Ok(record) = fs::read_to_string(udev_data.join(format!("c{major}:{minor}"))) else {
            if js {
                out.unknown.push(path);
            }
            continue;
        };
        // `E:NAME=VALUE` lines: udev's properties of the device.
        let value = |key: &str| {
            record.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("E:")
                    .and_then(|kv| kv.strip_prefix(key))
                    .and_then(|v| v.strip_prefix('='))
            })
        };
        if value("ID_INPUT_JOYSTICK") != Some("1") {
            continue;
        }
        if NOT_A_GAME_CONTROLLER
            .iter()
            .any(|k| value(k).is_some_and(|v| v != "0"))
        {
            out.refused.push(path);
        } else {
            out.shown.push(path);
        }
    }
    out.shown.sort();
    out.refused.sort();
    out.unknown.sort();
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

    /// The stand-in for a tool that would start programs outside the
    /// sandbox covers the real file, also where the tool is a link (audit
    /// S-F14); a tool that is not installed needs none.
    #[test]
    fn stand_ins_cover_the_real_tool_also_behind_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("usr/bin");
        let lib = tmp.path().join("usr/lib/systemd");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&lib).unwrap();
        fs::write(lib.join("systemd-run"), "real").unwrap();
        std::os::unix::fs::symlink("../lib/systemd/systemd-run", bin.join("systemd-run")).unwrap();
        fs::write(bin.join("flatpak-spawn"), "real").unwrap();
        let (a, b, c) = (
            bin.join("systemd-run"),
            bin.join("flatpak-spawn"),
            bin.join("missing"),
        );
        let tools = [
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            c.to_str().unwrap(),
        ];
        let got = hidden_tool_targets(&tools);
        assert_eq!(
            got,
            vec![
                (
                    "systemd-run".into(),
                    lib.join("systemd-run").canonicalize().unwrap()
                ),
                ("flatpak-spawn".into(), b.canonicalize().unwrap()),
            ]
        );
    }
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

    /// A link in /etc never brings a socket or a device into the sandbox,
    /// wherever it points; plain files and folders of the system's data and
    /// settings do, and in /run only plain files (regression: Debian's
    /// `/etc/alternatives/php-fpm.sock` showed the PHP server's socket).
    #[test]
    fn links_in_etc_never_bring_sockets_or_devices() {
        let t = tempfile::tempdir().unwrap();
        let sock = t.path().join("s.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let socket = fs::metadata(&sock).unwrap().file_type();
        fs::write(t.path().join("f"), "x").unwrap();
        let file = fs::metadata(t.path().join("f")).unwrap().file_type();
        let dir = fs::metadata(t.path()).unwrap().file_type();
        let null = fs::metadata("/dev/null").unwrap().file_type();
        let p = Path::new;
        assert!(!may_follow(p("/run/php/php8.3-fpm.sock"), socket));
        assert!(!may_follow(p("/etc/x.sock"), socket));
        assert!(!may_follow(p("/usr/share/x"), null), "a device");
        assert!(may_follow(p("/run/NetworkManager/resolv.conf"), file));
        assert!(
            !may_follow(p("/run/user/1000"), dir),
            "a folder in /run may hold sockets"
        );
        assert!(may_follow(p("/usr/share/zoneinfo"), dir));
        assert!(may_follow(p("/etc/ssl/cert.pem"), file));
        assert!(
            !may_follow(p("/home/ann/x"), file),
            "outside the system's data"
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
                .any(|r| at.starts_with(r))
                    || (at.starts_with("/run") && at.is_file()),
                "a system folder (or a plain file a system link leads to): {part:?}"
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
        assert_eq!(withheld_opened_paths(&ctx), Vec::<PathBuf>::new());
        // "No access" shares nothing, not even read-only (it used to share
        // like "Read-only"): no bind, the app starts in its private home
        // rather than in a folder it cannot see, and the log names the file
        // it did not share.
        ctx.permissions.filesystem.opened_files = Access::None;
        assert_eq!(opened_paths(&ctx), vec![], "none shares no opened file");
        let a = args_of(&ctx);
        assert!(!a.contains(&f), "no bind of the opened file");
        assert!(has_seq(&a, &["--chdir", home.to_str().unwrap()]));
        assert_eq!(withheld_opened_paths(&ctx), vec![proj.join("notes.txt")]);
        let notes = Bubblewrap.build(&ctx).unwrap().notes;
        assert!(
            notes
                .iter()
                .any(|n| n.contains(&f) && n.contains("No access")),
            "{notes:?}"
        );
        // A file nobody may open is not named either.
        ctx.args = vec!["../.bashrc".into()];
        assert_eq!(withheld_opened_paths(&ctx), Vec::<PathBuf>::new());
        ctx.permissions.filesystem.opened_files = Access::Ro;
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
    /// The copy of the X11 key for the sandbox is the user's alone from the
    /// start, and a link put at its place does not carry the key elsewhere
    /// (audit S-F18).
    #[test]
    fn the_x11_key_copy_is_private_and_follows_no_link() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = sample_context();
        ctx.runtime_dir = tmp.path().join("run");
        fs::create_dir_all(&ctx.runtime_dir).unwrap();
        // One record for display 0: family, address, number, name, data.
        let mut rec = vec![1, 0];
        for part in [
            &b"host"[..],
            b"0",
            b"MIT-MAGIC-COOKIE-1",
            b"secretsecret0000",
        ] {
            rec.extend((part.len() as u16).to_be_bytes());
            rec.extend_from_slice(part);
        }
        let src = tmp.path().join("Xauthority.host");
        fs::write(&src, &rec).unwrap();
        ctx.host.sockets.xauthority = Some(src);
        ctx.host.sockets.x11_display = Some(":0".into());
        let victim = tmp.path().join("victim");
        fs::write(&victim, "mine").unwrap();
        std::os::unix::fs::symlink(&victim, ctx.runtime_dir.join("Xauthority")).unwrap();
        write_xauthority(&ctx).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "mine");
        let dest = ctx.runtime_dir.join("Xauthority");
        let m = fs::symlink_metadata(&dest).unwrap();
        assert!(m.file_type().is_file());
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        assert!(fs::read(&dest)
            .unwrap()
            .windows(12)
            .any(|w| w == b"secretsecret"));
    }

    /// A folder whose name is not valid text (Linux allows any bytes) is
    /// never passed on with a replaced character, which would name another
    /// folder (audit S-F15): the start is refused with the folder named.
    #[test]
    fn a_folder_name_that_is_not_text_stops_the_start() {
        use std::os::unix::ffi::OsStrExt;
        let mut ctx = sample_context();
        ctx.private_home = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/sam-home-\xff"));
        let e = Bubblewrap.build(&ctx).unwrap_err().to_string();
        assert!(
            e.contains("not valid text") && e.contains("sam-home-"),
            "{e}"
        );
        let mut a = Args::default();
        a.op2("--ro-bind-try", ctx.private_home.as_path(), "/x");
        assert!(
            a.v.is_empty() && a.bad.is_empty(),
            "an optional mount is left out"
        );
    }

    /// A place SAM hides or locks whose name is not valid text stops the
    /// start: SAM's own folders, key folders, start files and SAM's own
    /// programs, also the start folder and a writable app folder. Review B2
    /// R57: written with a replaced character, the empty folder meant to
    /// hide one landed elsewhere and the real one stayed visible; a lock
    /// was left out, so the place stayed writable.
    #[test]
    fn a_protected_place_whose_name_is_not_text_stops_the_start() {
        use std::os::unix::ffi::OsStrExt;
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let odd = root.join(std::ffi::OsStr::from_bytes(b"sam-\xff"));
        fs::create_dir(&odd).unwrap();
        let not_text = |ctx: &LaunchContext| {
            Bubblewrap
                .build(ctx)
                .err()
                .is_some_and(|e| e.to_string().contains("not valid text"))
        };
        let mut ctx = sample_context();
        ctx.permissions.filesystem.custom_read = vec![root.display().to_string()];
        assert!(!not_text(&ctx), "nothing odd is passed on");
        // SAM's folder inside a granted one.
        ctx.sam_dirs = vec![odd.clone()];
        assert!(not_text(&ctx), "SAM's folder");
        // SAM's folder shown under another path by an extra bind.
        ctx.permissions.filesystem.custom_read.clear();
        ctx.extra_binds = vec![(root.clone(), "/run/x".into(), false)];
        assert!(not_text(&ctx), "SAM's folder below an extra bind");
        ctx.extra_binds.clear();
        ctx.sam_dirs.clear();
        ctx.permissions.filesystem.custom_read = vec![root.display().to_string()];
        assert!(!not_text(&ctx));
        // A key folder kept through a link in a granted home.
        let home = root.join("home");
        fs::create_dir(&home).unwrap();
        std::os::unix::fs::symlink(&odd, home.join(".ssh")).unwrap();
        let mut keys = ctx.clone();
        keys.host.home = home.clone();
        keys.host.xdg_dirs.clear();
        keys.permissions.filesystem.home = true;
        keys.permissions.filesystem.home_access = Access::Ro;
        assert!(not_text(&keys), "the key folder");
        // A start file kept through a link to a file whose name is not
        // text, in a writable home: its lock.
        let mut locks = keys.clone();
        fs::remove_file(home.join(".ssh")).unwrap();
        fs::create_dir(home.join("dots")).unwrap();
        let file = home
            .join("dots")
            .join(std::ffi::OsStr::from_bytes(b"bashrc-\xff"));
        fs::write(&file, "echo mine\n").unwrap();
        std::os::unix::fs::symlink(&file, home.join(".bashrc")).unwrap();
        locks.permissions.filesystem.home_access = Access::Rw;
        locks.permissions.filesystem.ssh = true;
        assert!(not_text(&locks), "the start file's lock");
        // One of SAM's own programs in a writable home: its lock.
        fs::remove_file(home.join(".bashrc")).unwrap();
        assert!(!not_text(&locks));
        locks.sam_programs = vec![file.clone()];
        assert!(not_text(&locks), "SAM's program's lock");
        locks.sam_programs.clear();
        // SAM's folder in the home kept through a link.
        fs::create_dir_all(home.join(".config")).unwrap();
        let sam_dir = home
            .join("dots")
            .join(std::ffi::OsStr::from_bytes(b"sam-\xff"));
        fs::create_dir(&sam_dir).unwrap();
        assert!(!not_text(&locks));
        std::os::unix::fs::symlink(&sam_dir, home.join(".config/sam")).unwrap();
        assert!(not_text(&locks), "SAM's folder in the home");
        // A home whose name is not text, not granted: its empty folder (the
        // home's other mounts stop such a start too).
        let mut odd_home = sample_context();
        odd_home.host.home = odd.clone();
        odd_home.owd = PathBuf::from("/");
        assert!(not_text(&odd_home), "the home's empty folder");
        // The start folder.
        ctx.owd = odd.clone();
        assert!(not_text(&ctx), "the start folder");
        ctx.owd = ctx.host.home.clone();
        // A writable app folder.
        ctx.permissions.advanced.writable_appdir = true;
        ctx.appdir_overlay = Some(root.join("overlay"));
        assert!(!not_text(&ctx));
        ctx.appdir_overlay = Some(odd.clone());
        assert!(not_text(&ctx), "the app folder's writable layer");
        ctx.appdir_overlay = Some(root.join("overlay"));
        ctx.appdir = odd.clone();
        assert!(not_text(&ctx), "the app folder");
    }

    /// The app's user and group are the person's own, each where it
    /// belongs: on bwrap's command line and in the passwd and group files
    /// the sandbox shows (the group is never the user's number, nor root's).
    #[test]
    fn the_app_gets_the_users_own_user_and_group_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = sample_context();
        assert_ne!(ctx.host.uid, ctx.host.gid, "the sample tells them apart");
        ctx.runtime_dir = tmp.path().join("run");
        let a = args_of(&ctx);
        assert!(has_seq(&a, &["--uid", "1000", "--gid", "1001"]), "{a:?}");
        write_identity_files(&ctx).unwrap();
        assert_eq!(
            fs::read_to_string(ctx.runtime_dir.join("passwd")).unwrap(),
            "tester:x:1000:1001:tester:/home/tester:/bin/sh\n\
             nobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n"
        );
        assert_eq!(
            fs::read_to_string(ctx.runtime_dir.join("group")).unwrap(),
            "tester:x:1001:\nnobody:x:65534:\n"
        );
    }

    /// With the GPU allowed the app gets the render nodes (`/dev/dri` as a
    /// whole) and NVIDIA's own device nodes; no other device the host
    /// lists is bound on its own. Without it, none of them.
    #[test]
    fn the_gpu_brings_exactly_the_render_and_nvidia_nodes() {
        let mut ctx = sample_context();
        let binds = |a: &[String]| -> Vec<String> {
            a.windows(2)
                .filter(|w| w[0] == "--dev-bind-try")
                .map(|w| w[1].clone())
                .filter(|d| d.starts_with("/dev/dri") || d.starts_with("/dev/nvidia"))
                .collect()
        };
        ctx.permissions.devices.gpu = true;
        assert_eq!(
            binds(&args_of(&ctx)),
            ["/dev/dri", "/dev/nvidia0", "/dev/nvidiactl"]
        );
        ctx.permissions.devices.gpu = false;
        assert!(binds(&args_of(&ctx)).is_empty());
    }

    /// Bubblewrap's status says when xdg-dbus-proxy is missing (the
    /// filtered session bus is then off), and only then.
    #[test]
    fn the_status_names_a_missing_dbus_proxy() {
        let mut host = sample_context().host;
        let named = |h: &HostInfo| {
            Bubblewrap
                .status(h)
                .notes
                .iter()
                .any(|n| n.contains("xdg-dbus-proxy"))
        };
        assert!(!named(&host), "installed");
        host.tools.xdg_dbus_proxy = None;
        assert!(named(&host), "missing");
    }

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

    /// Extra Bubblewrap arguments that end with an option missing its
    /// values stop the start: the option would take SAM's `--remount-ro /`
    /// after it, and the root would stay writable (review B2 R58).
    #[test]
    fn raw_arguments_missing_a_value_stop_the_start() {
        let mut ctx = sample_context();
        let refused = |ctx: &LaunchContext| {
            Bubblewrap.build(ctx).err().is_some_and(|e| {
                let e = e.to_string();
                e.contains("needs more values")
                    || e.contains("where an option belongs")
                    || e.contains("SAM does not know")
            })
        };
        for raw in [
            &["--ro-bind-try"][..],
            &["--ro-bind-try", "/a"],
            &["--setenv", "A", "1", "--chdir"],
            &["--overlay", "/u", "/w"],
            &["--ro-bind", "/a", "/b", "/c"],
            &["--"],
            &["--unshare-ipc", "--", "/bin/sh"],
            &["--setenv", "A", "1", "--not-yet-an-option", "x"],
        ] {
            ctx.permissions.advanced.extra_bwrap_args = raw.iter().map(|s| s.to_string()).collect();
            assert!(refused(&ctx), "{raw:?}");
        }
        for raw in [
            &["--ro-bind-try", "/a", "/b"][..],
            &["--unshare-ipc"],
            &["--setenv", "A", "--chdir"],
        ] {
            ctx.permissions.advanced.extra_bwrap_args = raw.iter().map(|s| s.to_string()).collect();
            assert!(!refused(&ctx), "{raw:?}");
            let a = args_of(&ctx);
            assert!(has_seq(&a, &["--remount-ro", "/", "--"]), "{raw:?}");
        }
        // Each problem by its kind.
        let problem =
            |raw: &[&str]| raw_problem(&raw.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(
            problem(&["--ro-bind", "/a", "/b", "/c"]),
            Some(RawProblem::NotAnOption("/c".into()))
        );
        assert_eq!(problem(&["--"]), Some(RawProblem::NotAnOption("--".into())));
        assert_eq!(
            problem(&["--nope"]),
            Some(RawProblem::Unknown("--nope".into()))
        );
        assert_eq!(
            problem(&["--setenv", "A", "1", "--chdir"]),
            Some(RawProblem::Unfinished("--chdir".into()))
        );
        assert_eq!(problem(&["--setenv", "A", "--chdir"]), None);
    }

    /// The systemd-run stand-in skips every option of systemd-run that takes
    /// its value as the next argument, so that value never runs as the
    /// command (review B2 R61: `--job-mode fail` ran `fail`).
    #[test]
    fn the_systemd_run_stand_in_skips_options_with_a_value() {
        let (_, script) = TOOL_SHIMS
            .iter()
            .find(|(n, _)| *n == "systemd-run")
            .unwrap();
        for (opt, value) in [
            ("--job-mode", "fail"),
            ("--capsule", "work"),
            ("-C", "work"),
            ("--expand-environment", "no"),
            // run0, a link to systemd-run, has value options of its own.
            ("-g", "wheel"),
            ("--group", "wheel"),
            ("-D", "/tmp"),
            ("--chdir", "/tmp"),
            ("--area", "work"),
            ("--shell-prefix", "x"),
            // A value that ends at once if it runs (never `yes`, which runs
            // forever and fills memory through the captured output).
            ("--lightweight", "true"),
        ] {
            let out = std::process::Command::new("sh")
                .args([
                    "-c",
                    script,
                    "systemd-run",
                    "--user",
                    opt,
                    value,
                    "echo",
                    "ran",
                ])
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                "ran",
                "{opt} {value}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
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

    /// "All input devices" names every device it shows the app, and says
    /// what the virtual one allows: typing and moving the mouse as the
    /// person (audit: /dev/uinput was shown without being named).
    #[test]
    fn the_input_switch_names_every_device_it_shows() {
        let devices = |input: bool| -> std::collections::BTreeSet<String> {
            let mut ctx = sample_context();
            ctx.permissions.devices.input = input;
            ctx.permissions.devices.gamepads = false;
            args_of(&ctx)
                .windows(3)
                .filter(|w| w[0].starts_with("--dev-bind"))
                .map(|w| w[2].clone())
                .collect()
        };
        let shown: Vec<String> = devices(true).difference(&devices(false)).cloned().collect();
        assert!(shown.contains(&"/dev/uinput".to_string()), "{shown:?}");
        let text = sam_core::permissions::permission_catalog()
            .into_iter()
            .find(|i| i.key == "devices.input")
            .unwrap()
            .description;
        for d in &shown {
            assert!(text.contains(d.as_str()), "{d} is not named in: {text}");
        }
        assert!(text.contains("type or move the mouse"), "{text}");
    }

    /// "Game controllers" exposes only joysticks, never keyboards or mice:
    /// also not a device that reports itself as a joystick and a keyboard
    /// or mouse at once, nor a node udev has no record for (review R56).
    #[test]
    fn gamepads_only_exposes_joysticks() {
        let t = tempfile::tempdir().unwrap();
        let (dev, udev) = (t.path().join("input"), t.path().join("udev"));
        fs::create_dir_all(&dev).unwrap();
        fs::create_dir_all(&udev).unwrap();
        // Stand-ins by device number: /dev/null (c1:3) a gamepad, /dev/zero
        // (c1:5) a keyboard, /dev/full (c1:7) a joystick that is also a
        // keyboard, /dev/random (c1:8) a joystick that is also a mouse,
        // /dev/urandom (c1:9) a node udev has no record for.
        let link = |to: &str, name: &str| std::os::unix::fs::symlink(to, dev.join(name)).unwrap();
        link("/dev/null", "js0");
        link("/dev/null", "event7");
        link("/dev/zero", "event3");
        link("/dev/zero", "mice");
        link("/dev/full", "event4");
        link("/dev/full", "js1");
        link("/dev/random", "event5");
        link("/dev/urandom", "js2");
        let joystick = "E:ID_INPUT=1\nE:ID_INPUT_JOYSTICK=1\n";
        fs::write(udev.join("c1:3"), joystick).unwrap();
        fs::write(udev.join("c1:5"), "E:ID_INPUT=1\nE:ID_INPUT_KEYBOARD=1\n").unwrap();
        fs::write(
            udev.join("c1:7"),
            format!("{joystick}E:ID_INPUT_KEYBOARD=1\n"),
        )
        .unwrap();
        fs::write(udev.join("c1:8"), format!("{joystick}E:ID_INPUT_MOUSE=1\n")).unwrap();
        let got = gamepad_nodes(&dev, &udev);
        assert_eq!(got, vec![dev.join("event7"), dev.join("js0")]);
        // What is left out is told apart: the start's notes name it.
        let sorted = sort_gamepad_nodes(&dev, &udev);
        assert_eq!(
            sorted.refused,
            vec![dev.join("event4"), dev.join("event5"), dev.join("js1")]
        );
        assert_eq!(sorted.unknown, vec![dev.join("js2")]);
        // A tag counts with any value but 0, not only with 1.
        fs::write(
            udev.join("c1:7"),
            format!("{joystick}E:ID_INPUT_KEYBOARD=yes\nE:ID_INPUT_MOUSE=0\n"),
        )
        .unwrap();
        fs::write(udev.join("c1:8"), format!("{joystick}E:ID_INPUT_MOUSE=0\n")).unwrap();
        assert_eq!(
            sort_gamepad_nodes(&dev, &udev).shown,
            vec![dev.join("event5"), dev.join("event7"), dev.join("js0")]
        );
        // Any one keyboard or pointer tag is enough to leave a device out.
        fs::remove_file(udev.join("c1:8")).unwrap();
        for kind in [
            "KEYBOARD",
            "MOUSE",
            "TOUCHPAD",
            "TOUCHSCREEN",
            "TABLET",
            "POINTINGSTICK",
        ] {
            fs::write(
                udev.join("c1:3"),
                format!("{joystick}E:ID_INPUT_{kind}=1\n"),
            )
            .unwrap();
            assert!(gamepad_nodes(&dev, &udev).is_empty(), "{kind}");
        }
    }

    /// Every game controller shown by name is watched while the app runs,
    /// with what it was when it was chosen; one already gone is neither
    /// shown nor watched (review R56).
    #[test]
    fn every_controller_shown_is_watched() {
        let t = tempfile::tempdir().unwrap();
        let (pad, gone) = (t.path().join("event7"), t.path().join("event8"));
        std::os::unix::fs::symlink("/dev/null", &pad).unwrap();
        let mut a = Args::default();
        let mut watched = Vec::new();
        bind_watched(&mut a, &mut watched, t.path(), vec![pad.clone(), gone]);
        let null = fs::metadata("/dev/null").unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            watched,
            vec![sam_core::sandbox::WatchedDevice {
                path: pad.clone(),
                dev: null.dev(),
                ino: null.ino(),
                rdev: null.rdev(),
            }]
        );
        // In a read-only folder of their own, which the app cannot rename.
        let (p, d) = (pad.display().to_string(), t.path().display().to_string());
        let want: Vec<String> = ["--tmpfs", &d, "--dev-bind-try", &p, &p, "--remount-ro", &d]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(a.v, want);
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

    /// An extra socket the app could have swapped for a link (it sits in a
    /// folder the app may write) is not passed in when it is a link: the
    /// bind followed the link to whatever socket it named, such as the
    /// real session bus (review SB-4). The same link in a folder the app
    /// cannot change is followed, and the socket it leads to is bound at
    /// the listed place.
    #[test]
    fn an_extra_socket_swapped_for_a_link_by_the_app_is_not_passed_in() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let (shared, other) = (root.join("shared"), root.join("other"));
        fs::create_dir(&shared).unwrap();
        fs::create_dir(&other).unwrap();
        let target = other.join("target.sock");
        let _l = std::os::unix::net::UnixListener::bind(&target).unwrap();
        let listed = shared.join("app.sock");
        std::os::unix::fs::symlink("../other/target.sock", &listed).unwrap();
        let (listed_s, target_s) = (listed.display().to_string(), target.display().to_string());
        let mut ctx = sample_context();
        ctx.permissions.sockets.custom = vec![listed_s.clone()];
        ctx.permissions.filesystem.custom_write = vec![shared.display().to_string()];
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(
            !cmd.args.iter().any(|a| a == &target_s),
            "the link's target is bound: {:?}",
            cmd.args
        );
        assert!(
            !has_seq(&cmd.args, &["--bind-try", &listed_s, &listed_s]),
            "the link is bound"
        );
        assert!(
            cmd.notes
                .iter()
                .any(|n| n.contains(&listed_s) && n.contains("link")),
            "{:?}",
            cmd.notes
        );
        // Read-only: the app cannot have made the link.
        ctx.permissions.filesystem.custom_write.clear();
        ctx.permissions.filesystem.custom_read = vec![shared.display().to_string()];
        let a = args_of(&ctx);
        assert!(has_seq(&a, &["--bind-try", &target_s, &listed_s]), "{a:?}");
        // Also when the link is a folder on the way.
        let dir_link = shared.join("dir");
        std::os::unix::fs::symlink("../other", &dir_link).unwrap();
        ctx.permissions.filesystem.custom_read.clear();
        ctx.permissions.filesystem.custom_write = vec![shared.display().to_string()];
        ctx.permissions.sockets.custom = vec![dir_link.join("target.sock").display().to_string()];
        assert!(!args_of(&ctx).iter().any(|a| a == &target_s));
        // Also when the folder is writable through an extra bind (shown
        // elsewhere in the sandbox, as for the diagnosis run).
        ctx.permissions.filesystem.custom_write.clear();
        ctx.permissions.sockets.custom = vec![listed_s.clone()];
        ctx.extra_binds = vec![(shared.clone(), "/run/x".into(), true)];
        assert!(!args_of(&ctx).iter().any(|a| a == &target_s));
        // A read-only extra bind lets the app change nothing there: the
        // link is followed (mutation run over PR 95).
        ctx.extra_binds = vec![(shared.clone(), "/run/x".into(), false)];
        let a = args_of(&ctx);
        assert!(has_seq(&a, &["--bind-try", &target_s, &listed_s]), "{a:?}");
    }

    /// An extra socket below a folder the app can change is not passed in,
    /// with a note; in a folder the app may only read, it is. SAM checks the
    /// socket when it builds the command and Bubblewrap binds it by name
    /// later: a running copy of the app could swap it for a link to the
    /// session bus in between (review B2 R55).
    #[test]
    fn an_extra_socket_in_a_folder_the_app_can_change_is_not_passed_in() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let shared = root.join("shared");
        fs::create_dir_all(shared.join("deep")).unwrap();
        let sock = shared.join("deep/app.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let sock_s = sock.display().to_string();
        let bound = |ctx: &LaunchContext| has_seq(&args_of(ctx), &["--bind-try", &sock_s, &sock_s]);
        let mut ctx = sample_context();
        ctx.permissions.sockets.custom = vec![sock_s.clone()];
        ctx.permissions.filesystem.custom_read = vec![shared.display().to_string()];
        assert!(bound(&ctx), "read-only: passed in");
        for writable in [shared.join("deep"), shared.clone()] {
            ctx.permissions.filesystem.custom_read.clear();
            ctx.permissions.filesystem.custom_write = vec![writable.display().to_string()];
            assert!(!bound(&ctx), "{} is writable", writable.display());
            let cmd = Bubblewrap.build(&ctx).unwrap();
            assert!(
                cmd.notes
                    .iter()
                    .any(|n| n.contains(&sock_s) && n.contains("can change")),
                "{:?}",
                cmd.notes
            );
        }
        // A read-only grant inside a writable one: the folder between them
        // can be renamed, and the read-only mount moves along.
        fs::create_dir_all(shared.join("deep/ro")).unwrap();
        let inner = shared.join("deep/ro/app.sock");
        let _i = std::os::unix::net::UnixListener::bind(&inner).unwrap();
        let inner_s = inner.display().to_string();
        ctx.permissions.sockets.custom = vec![inner_s.clone()];
        ctx.permissions.filesystem.custom_write = vec![shared.display().to_string()];
        ctx.permissions.filesystem.custom_read = vec![shared.join("deep/ro").display().to_string()];
        assert!(
            !has_seq(&args_of(&ctx), &["--bind-try", &inner_s, &inner_s]),
            "below a writable folder"
        );
        ctx.permissions.filesystem.custom_write.clear();
        assert!(has_seq(&args_of(&ctx), &["--bind-try", &inner_s, &inner_s]));
        ctx.permissions.filesystem.custom_read.clear();
        ctx.permissions.sockets.custom = vec![sock_s.clone()];
        // Also when only an extra bind makes the folder writable.
        ctx.extra_binds = vec![(shared.clone(), "/run/x".into(), true)];
        assert!(!bound(&ctx), "writable through an extra bind");
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(
            cmd.notes.iter().any(|n| n.contains(&sock_s)),
            "{:?}",
            cmd.notes
        );
        ctx.extra_binds.clear();
        // A writable home kept behind a link: the socket's real place is
        // the home's too.
        let real_home = root.join("real-home");
        fs::create_dir(&real_home).unwrap();
        let home_sock = real_home.join("svc.sock");
        let _h = std::os::unix::net::UnixListener::bind(&home_sock).unwrap();
        std::os::unix::fs::symlink(&real_home, root.join("home")).unwrap();
        let home_s = home_sock.display().to_string();
        ctx.host.home = root.join("home");
        ctx.host.xdg_dirs.clear();
        ctx.permissions.sockets.custom = vec![home_s.clone()];
        assert!(
            has_seq(&args_of(&ctx), &["--bind-try", &home_s, &home_s]),
            "home not granted"
        );
        ctx.permissions.filesystem.home = true;
        ctx.permissions.filesystem.home_access = Access::Rw;
        assert!(
            !has_seq(&args_of(&ctx), &["--bind-try", &home_s, &home_s]),
            "the home writable under its linked name"
        );
    }

    /// An extra socket whose link leads to a socket SAM calls dangerous
    /// (here a D-Bus socket) is not passed in: what the app gets is rated,
    /// not the name it was listed by (review SB-4). Listed by its real
    /// name, it is passed in (that name was rated Dangerous when added).
    #[test]
    fn an_extra_socket_that_leads_to_a_dangerous_one_is_not_passed_in() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        fs::create_dir(root.join("d")).unwrap();
        let bus = root.join("d/bus");
        let _l = std::os::unix::net::UnixListener::bind(&bus).unwrap();
        let listed = root.join("helper.sock");
        std::os::unix::fs::symlink(&bus, &listed).unwrap();
        let (listed_s, bus_s) = (listed.display().to_string(), bus.display().to_string());
        let mut ctx = sample_context();
        ctx.permissions.sockets.custom = vec![listed_s.clone()];
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(!cmd.args.iter().any(|a| a == &bus_s), "{:?}", cmd.args);
        assert!(
            cmd.notes.iter().any(|n| n.contains(&listed_s)),
            "{:?}",
            cmd.notes
        );
        ctx.permissions.sockets.custom = vec![bus_s.clone()];
        assert!(has_seq(&args_of(&ctx), &["--bind-try", &bus_s, &bus_s]));
    }

    /// A link whose listed name is dangerous for another reason than where
    /// it leads is not passed in either: a name that looks like a key agent
    /// (`x-ssh-agent.sock`) leading to the session bus was rated as a key
    /// agent, not as the bus (review of owner decision 11 of 2026-11-23).
    /// A name dangerous for the same reason (a key agent leading to a key
    /// agent) is passed in, as listed.
    #[test]
    fn an_extra_socket_is_passed_in_only_as_dangerous_as_its_name() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        fs::create_dir(root.join("d")).unwrap();
        fs::create_dir(root.join("gnupg")).unwrap();
        let bus = root.join("d/bus");
        let _b = std::os::unix::net::UnixListener::bind(&bus).unwrap();
        let gpg = root.join("gnupg/S.gpg-agent");
        let _g = std::os::unix::net::UnixListener::bind(&gpg).unwrap();
        let to_bus = root.join("x-ssh-agent.sock");
        std::os::unix::fs::symlink(&bus, &to_bus).unwrap();
        let to_gpg = root.join("y-ssh-agent.sock");
        std::os::unix::fs::symlink(&gpg, &to_gpg).unwrap();
        let s = |p: &Path| p.display().to_string();
        let mut ctx = sample_context();
        ctx.permissions.sockets.custom = vec![s(&to_bus)];
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(!cmd.args.iter().any(|a| a == &s(&bus)), "{:?}", cmd.args);
        assert!(
            cmd.notes.iter().any(|n| n.contains(&s(&to_bus))),
            "{:?}",
            cmd.notes
        );
        ctx.permissions.sockets.custom = vec![s(&to_gpg)];
        assert!(has_seq(
            &args_of(&ctx),
            &["--bind-try", &s(&gpg), &s(&to_gpg)]
        ));
    }

    /// Docker, Podman and containerd count as one kind: podman-docker's
    /// `docker.sock` linked to Podman's socket is passed in, while a
    /// `docker.sock` leading to the session bus is not (review of owner
    /// decision 11 of 2026-11-23).
    #[test]
    fn a_docker_socket_may_lead_to_podman_but_not_to_the_bus() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        for d in ["podman", "d", "a", "b"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let podman = root.join("podman/podman.sock");
        let _p = std::os::unix::net::UnixListener::bind(&podman).unwrap();
        let bus = root.join("d/bus");
        let _b = std::os::unix::net::UnixListener::bind(&bus).unwrap();
        let to_podman = root.join("a/docker.sock");
        std::os::unix::fs::symlink(&podman, &to_podman).unwrap();
        let to_bus = root.join("b/docker.sock");
        std::os::unix::fs::symlink(&bus, &to_bus).unwrap();
        let s = |p: &Path| p.display().to_string();
        let mut ctx = sample_context();
        ctx.permissions.sockets.custom = vec![s(&to_podman)];
        assert!(has_seq(
            &args_of(&ctx),
            &["--bind-try", &s(&podman), &s(&to_podman)]
        ));
        ctx.permissions.sockets.custom = vec![s(&to_bus)];
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(!cmd.args.iter().any(|a| a == &s(&bus)), "{:?}", cmd.args);
        assert!(
            cmd.notes.iter().any(|n| n.contains(&s(&to_bus))),
            "{:?}",
            cmd.notes
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
        // A library every Linux system has, bundled by the "app". Never a
        // silent skip: a run that must prove everything fails without it.
        let libc = SYSTEM_LIB_DIRS
            .iter()
            .map(|d| Path::new(d).join("libc.so.6"))
            .find(|p| p.exists());
        let Some(_) = libc else {
            assert!(
                std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
                "SAM_REQUIRE_SANDBOX=1, but no libc.so.6 in {SYSTEM_LIB_DIRS:?}"
            );
            sam_core::errln!("skipped: no libc.so.6 in {SYSTEM_LIB_DIRS:?}");
            return;
        };
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
    use sam_core::places::{protected_places_with, PROTECTED_RO};

    /// Whether the sandbox shows `p`, as named or as reached.
    fn visible_in_sandbox(p: &Path, ctx: &LaunchContext) -> bool {
        let v = Views::base(ctx);
        v.visible(p) || v.visible(&resolve(p))
    }

    use super::*;
    use sam_core::sandbox::sample_context;
    use sam_core::util::tildify;

    /// Whether the launch note `note` names the place `p`: by its full
    /// path, or as SAM shows a place below the real home to people (`~/…`),
    /// which happens wherever the test folders lie in the home (CI).
    fn names(note: &str, p: &Path) -> bool {
        note.contains(p.to_string_lossy().as_ref()) || note.contains(&tildify(p))
    }

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

    /// A key folder kept behind a link is hidden where it points also when
    /// only the folder it points into is granted, not the home (security
    /// review 2026-11-23, SB-2: `~/.gnupg` a link into a granted `~/Sync`
    /// showed the keys, writable).
    #[test]
    fn a_linked_key_folder_is_hidden_also_when_only_its_target_is_granted() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap();
        fs::create_dir_all(home.join("Sync/gnupg")).unwrap();
        std::os::unix::fs::symlink(home.join("Sync/gnupg"), home.join(".gnupg")).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![home.join("Sync").display().to_string()];
        let a = args_of(&ctx_for(&p, &home));
        let target = home.join("Sync/gnupg").to_string_lossy().into_owned();
        assert!(has_seq(&a, &["--tmpfs", &target]), "{a:?}");
        // Given the key folder with the whole home, the app sees it (the
        // switch alone counts for nothing:
        // `key_switches_without_the_whole_home_hide_the_keys`).
        p.filesystem.gnupg = true;
        p.filesystem.home = true;
        let a = args_of(&ctx_for(&p, &home));
        assert!(!has_seq(&a, &["--tmpfs", &target]), "{a:?}");
    }

    /// The key and credential switches count only with the whole home
    /// ([`FilesystemPerms::ssh_given`]): stored "on" without it (an old
    /// profile, a hand-edited file), `~/.ssh`, `~/.gnupg` and the other
    /// credential stores stay hidden where a granted extra folder shows
    /// them, and a key folder there is watched like one not given, as the
    /// window and the sandbox check say. With the whole home the same
    /// switches show them.
    #[test]
    fn key_switches_without_the_whole_home_hide_the_keys() {
        let t = scratch();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in ["Sync/ssh", "Sync/gnupg"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        fs::write(home.join("Sync/netrc"), "machine example password secret\n").unwrap();
        let link = |to: &str, at: &str| {
            std::os::unix::fs::symlink(home.join(to), home.join(at)).unwrap();
        };
        link("Sync/ssh", ".ssh");
        link("Sync/gnupg", ".gnupg");
        link("Sync/netrc", ".netrc");
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![home.join("Sync").display().to_string()];
        p.filesystem.ssh = true;
        p.filesystem.gnupg = true;
        p.filesystem.hidden_files = true;
        let s = |r: &str| home.join(r).to_string_lossy().into_owned();
        let ctx = ctx_for(&p, &home);
        let a = args_of(&ctx);
        assert!(has_seq(&a, &["--tmpfs", &s("Sync/ssh")]), "SSH keys: {a:?}");
        assert!(
            has_seq(&a, &["--tmpfs", &s("Sync/gnupg")]),
            "GnuPG keys: {a:?}"
        );
        assert!(
            has_seq(&a, &["--ro-bind", "/dev/null", &s("Sync/netrc")]),
            "the credential store ~/.netrc: {a:?}"
        );
        assert!(
            writes_start_places(&ctx),
            "the key folders shown writable through ~/Sync are watched"
        );
        // Each key folder on its own: the check above holds while either
        // one is watched, so it alone would miss one switch read raw.
        let watched = watched_places(&p, &home);
        for k in [".ssh", ".gnupg"] {
            assert!(
                watched.iter().any(|w| w == k),
                "the key folder ~/{k} is watched while its switch is on without the whole home: {watched:?}"
            );
        }
        // With the whole home, the switches show them.
        p.filesystem.home = true;
        let watched = watched_places(&p, &home);
        for k in [".ssh", ".gnupg"] {
            assert!(
                !watched.iter().any(|w| w == k),
                "the key folder ~/{k} given with the whole home is not watched: {watched:?}"
            );
        }
        let a = args_of(&ctx_for(&p, &home));
        for (r, what) in [("Sync/ssh", "SSH keys"), ("Sync/gnupg", "GnuPG keys")] {
            assert!(!has_seq(&a, &["--tmpfs", &s(r)]), "{what}: {a:?}");
        }
        assert!(
            !has_seq(&a, &["--ro-bind", "/dev/null", &s("Sync/netrc")]),
            "{a:?}"
        );
    }

    /// A start file or credential store kept through a link (dotfiles,
    /// `stow`) is guarded where the link leads: every writable folder above
    /// that place is a mount point of its own, mounted before the guard, so
    /// the app cannot rename it away and put a file of its own where the
    /// unchanged link leads (review B2 S3, R50). A grant's own place is not
    /// bound again, and nothing is pinned in a read-only home.
    #[test]
    fn the_folders_above_where_a_linked_protection_lands_are_pinned() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in ["dotfiles/bash", "secrets", "deep/a/b"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        for f in ["dotfiles/bash/bashrc", "secrets/netrc", "deep/a/b/profile"] {
            fs::write(home.join(f), "").unwrap();
        }
        let link = |to: &Path, at: &str| std::os::unix::fs::symlink(to, home.join(at)).unwrap();
        link(Path::new("dotfiles/bash/bashrc"), ".bashrc");
        link(Path::new("secrets/netrc"), ".netrc");
        link(&home.join("deep/a/b/profile"), ".profile");
        let s = |p: &str| home.join(p).to_string_lossy().into_owned();
        let at = |a: &[String], seq: &[&str]| {
            a.windows(seq.len())
                .position(|w| w.iter().zip(seq).all(|(x, y)| x == y))
        };
        let a = args_of(&ctx_for(&full_rw(), &home));
        for d in [
            "dotfiles",
            "dotfiles/bash",
            "secrets",
            "deep",
            "deep/a",
            "deep/a/b",
        ] {
            assert!(
                at(&a, &["--bind", &s(d), &s(d)]).is_some(),
                "{d} is a mount point of its own: {a:?}"
            );
        }
        let pin = at(&a, &["--bind", &s("dotfiles"), &s("dotfiles")]).unwrap();
        let bashrc = s("dotfiles/bash/bashrc");
        let guard = at(&a, &["--ro-bind-try", &bashrc, &bashrc]).expect("bashrc read-only");
        assert!(pin < guard, "the pin comes before the guard");
        let pin = at(&a, &["--bind", &s("secrets"), &s("secrets")]).unwrap();
        let mask = at(&a, &["--ro-bind", "/dev/null", &s("secrets/netrc")]).expect("netrc hidden");
        assert!(pin < mask, "the pin comes before the hiding");
        let h = s("");
        let h = h.trim_end_matches('/');
        assert_eq!(
            a.windows(3).filter(|w| w == &["--bind", h, h]).count(),
            1,
            "the home is bound once"
        );
        // Read-only home: nothing to pin.
        let mut p = full_rw();
        p.filesystem.home_access = Access::Ro;
        let a = args_of(&ctx_for(&p, &home));
        assert!(at(&a, &["--bind", &s("dotfiles"), &s("dotfiles")]).is_none());
        // Only the dotfiles folder granted: the folders inside it are
        // pinned, the grant's own place is not bound again.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![s("dotfiles")];
        let a = args_of(&ctx_for(&p, &home));
        let bash = s("dotfiles/bash");
        assert!(at(&a, &["--bind", &bash, &bash]).is_some(), "{a:?}");
        assert!(at(&a, &["--bind", &s("dotfiles"), &s("dotfiles")]).is_none());
        // SAM's own folder reached through a link (an unpack folder in
        // `~/Games`, a link into `~/vault`): the folder above where it
        // lands is pinned too.
        fs::create_dir_all(home.join("vault/games/sam")).unwrap();
        link(Path::new("vault/games"), "Games");
        let mut ctx = ctx_for(&full_rw(), &home);
        ctx.sam_dirs = vec![home.join("Games/sam")];
        let a = args_of(&ctx);
        assert!(
            at(&a, &["--bind", &s("vault"), &s("vault")]).is_some(),
            "{a:?}"
        );
    }

    /// The folders above each credential store are pinned with the whole
    /// home writable also when hidden files are granted and the stores are
    /// shown (`~/.var` above `~/.var/app`, `~/.cargo` above
    /// `~/.cargo/credentials`): nothing else guards them then, so without
    /// the pin the app could rename them away. With hidden files off, the
    /// hidden store pins them as well.
    #[test]
    fn the_folders_above_a_shown_credential_store_are_pinned() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in [".var/app", ".cargo"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let s = |p: &str| home.join(p).to_string_lossy().into_owned();
        for hidden_files in [true, false] {
            let mut p = full_rw();
            p.filesystem.hidden_files = hidden_files;
            let a = args_of(&ctx_for(&p, &home));
            for d in [".var", ".cargo"] {
                assert!(
                    has_seq(&a, &["--bind", &s(d), &s(d)]),
                    "{d} is pinned, hidden files {hidden_files}: {a:?}"
                );
            }
            assert!(!a.contains(&s("xyzzy")), "no pin where no folder is: {a:?}");
        }
    }

    /// The app's way to a host path is followed link by link as Linux
    /// reads it inside the sandbox: a relative link or one with a whole
    /// path, also behind another link and with `..`, ends where the
    /// sandbox shows the place; a link at a grant's own place is a mount
    /// point inside and not followed; a link out of what is shown, or a
    /// loop, ends nowhere (security review 2026-11-23, SB-6).
    #[test]
    fn the_way_to_a_place_is_followed_link_by_link_as_the_app_follows_it() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        for d in ["dots/config/autostart", "dots/local"] {
            fs::create_dir_all(real.join(d)).unwrap();
        }
        fs::create_dir_all(base.join("home")).unwrap();
        fs::create_dir_all(base.join("outside/x")).unwrap();
        // The home itself behind a link, as on some systems.
        std::os::unix::fs::symlink(&real, &named).unwrap();
        std::os::unix::fs::symlink("dots/config", real.join(".config")).unwrap();
        std::os::unix::fs::symlink(named.join("dots/local"), real.join(".local")).unwrap();
        std::os::unix::fs::symlink("../config/autostart", real.join("dots/local/as")).unwrap();
        std::os::unix::fs::symlink(base.join("outside/x"), real.join("out")).unwrap();
        std::os::unix::fs::symlink("loop", real.join("loop")).unwrap();
        let mut ctx = ctx_for(&full_rw(), &named);
        let v = Views::of(&ctx);
        assert_eq!(
            v.reached_at(&named.join(".config/autostart")),
            Some(named.join("dots/config/autostart")),
            "relative link"
        );
        assert_eq!(
            v.reached_at(&named.join(".local/as/f")),
            Some(named.join("dots/config/autostart/f")),
            "a link with a whole path, then a relative one with `..`"
        );
        assert_eq!(
            v.reached_at(&named.join("dots")),
            Some(named.join("dots")),
            "the home's own link is a mount point inside"
        );
        assert_eq!(
            v.reached_at(&named.join("out/f")),
            None,
            "out of the grants"
        );
        assert_eq!(v.reached_at(&named.join("loop/f")), None, "a loop");
        assert_eq!(v.reached_at(&base.join("outside/x")), None, "not shown");
        // Shown also where the link leads: reached there.
        ctx.permissions.filesystem.custom_read = vec![base.join("outside").display().to_string()];
        let v = Views::of(&ctx);
        assert_eq!(
            v.reached_at(&named.join("out/f")),
            Some(base.join("outside/x/f"))
        );
        // The places to mount on lead through no link.
        assert_eq!(
            v.mount_points(&named.join(".config")),
            vec![named.join("dots/config")]
        );
    }

    /// Both walks follow links as Linux does: a way through 40 links ends
    /// where they lead, one through 41 counts as a loop (reached nowhere,
    /// and possibly made by the app), and the check of a listed socket
    /// ends in time on a loop (the walk to a place has its loop test
    /// above). The mutation run over PR 95 found the exact limit and the
    /// count untested.
    #[test]
    fn a_way_through_forty_links_is_followed_and_one_through_more_is_not() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap();
        fs::create_dir(home.join("end")).unwrap();
        // `n` links in a row, the last one to `end`.
        let chain = |name: &str, n: usize| {
            for i in 0..n {
                let to = match i + 1 == n {
                    true => "end".to_string(),
                    false => format!("{name}{}", i + 1),
                };
                std::os::unix::fs::symlink(to, home.join(format!("{name}{i}"))).unwrap();
            }
            home.join(format!("{name}0/f"))
        };
        let (forty, more) = (chain("a", 40), chain("b", 41));
        std::os::unix::fs::symlink("loop", home.join("loop")).unwrap();
        let v = Views::of(&ctx_for(&full_rw(), &home));
        assert_eq!(v.reached_at(&forty), Some(home.join("end/f")));
        assert_eq!(v.reached_at(&more), None, "41 links");
        let nobody_changes = |_: &Path| false;
        assert!(!link_the_app_can_change(&forty, &nobody_changes));
        assert!(link_the_app_can_change(&more, &nobody_changes), "41 links");
        let (tx, rx) = std::sync::mpsc::channel();
        let looped = home.join("loop/f");
        std::thread::spawn(move || {
            let _ = tx.send(link_the_app_can_change(&looped, &|_: &Path| false));
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(true),
            "a loop counts as a link the app may have made, and ends"
        );
    }

    /// With the home kept behind a link (`/home/u` a link to `/data/u`),
    /// a link in it that names the home's real path (`~/.config` to
    /// `/data/u/dots/config`, as tools that resolve the folder they run in
    /// write it) leads nowhere inside, where only `/home/u` is shown; yet
    /// the app reaches the place it points to under the home's name
    /// (`/home/u/dots/config`). The protections land there: autostart
    /// read-only, the folder above it pinned, a key folder hidden.
    #[test]
    fn places_named_by_the_homes_real_path_are_protected_where_the_app_sees_them() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        for d in ["dots/config/autostart", "Sync/gnupg"] {
            fs::create_dir_all(real.join(d)).unwrap();
        }
        fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        std::os::unix::fs::symlink(real.join("dots/config"), real.join(".config")).unwrap();
        std::os::unix::fs::symlink(real.join("Sync/gnupg"), real.join(".gnupg")).unwrap();
        let a = args_of(&ctx_for(&full_rw(), &named));
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        let autostart = s(named.join("dots/config/autostart"));
        assert!(
            has_seq(&a, &["--ro-bind-try", &autostart, &autostart]),
            "{a:?}"
        );
        let config = s(named.join("dots/config"));
        assert!(has_seq(&a, &["--bind", &config, &config]), "{a:?}");
        let gnupg = s(named.join("Sync/gnupg"));
        assert!(has_seq(&a, &["--tmpfs", &gnupg]), "{a:?}");
    }

    /// SAM's own folders kept behind a link (`~/.config` a link, SAM's
    /// settings in `~/.config/sam`) are hidden where the app reaches them,
    /// never through the link: with the link leading to a place nothing
    /// grants, the empty folder on `~/.config/sam` stopped every start with
    /// the whole home writable (Bubblewrap could not make the folders above
    /// it); with the link leading into the home, the folder is hidden where
    /// it points (security review 2026-11-23, SB-6).
    #[test]
    fn sams_own_folders_behind_a_link_are_hidden_where_the_app_reaches_them() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        fs::create_dir_all(home.join("dots/config/sam")).unwrap();
        fs::create_dir_all(base.join("elsewhere/config/sam")).unwrap();
        std::os::unix::fs::symlink(base.join("elsewhere/config"), home.join(".config")).unwrap();
        let mut ctx = ctx_for(&full_rw(), &home);
        ctx.sam_dirs = vec![home.join(".config/sam")];
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        let through_link = s(home.join(".config/sam"));
        let a = args_of(&ctx);
        assert!(!has_seq(&a, &["--tmpfs", &through_link]), "{a:?}");
        assert!(
            !has_seq(&a, &["--tmpfs", &s(base.join("elsewhere/config/sam"))]),
            "nothing shows the place the link leads to: {a:?}"
        );
        // The link leads into the home: hidden there.
        fs::remove_file(home.join(".config")).unwrap();
        std::os::unix::fs::symlink(home.join("dots/config"), home.join(".config")).unwrap();
        let a = args_of(&ctx);
        assert!(!has_seq(&a, &["--tmpfs", &through_link]), "{a:?}");
        assert!(
            has_seq(&a, &["--tmpfs", &s(home.join("dots/config/sam"))]),
            "{a:?}"
        );
    }

    /// SAM's own programs are bound read-only onto themselves where the app
    /// could write them, also where the app sees them under the home's own
    /// name, and the folders above them are pinned; where the app sees them
    /// read-only or not at all, nothing is added (security review
    /// 2026-11-23, SB-1).
    #[test]
    fn sams_own_programs_are_read_only_wherever_an_app_could_write_them() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        fs::create_dir_all(real.join("Downloads")).unwrap();
        fs::create_dir_all(real.join("Applications")).unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        let sam = real.join("Applications/SAM.AppImage");
        let run = real.join("Downloads/sam-jail-run");
        fs::write(&sam, "").unwrap();
        fs::write(&run, "").unwrap();
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let ro = |a: &[String], p: &Path| has_seq(a, &["--ro-bind-try", &s(p), &s(p)]);
        let pinned = |a: &[String], p: &Path| has_seq(a, &["--bind", &s(p), &s(p)]);

        // The whole home writable, under its own name.
        let mut ctx = ctx_for(&full_rw(), &named);
        ctx.sam_programs = vec![sam.clone(), run.clone()];
        let a = args_of(&ctx);
        let seen = named.join("Applications/SAM.AppImage");
        assert!(ro(&a, &seen), "{a:?}");
        assert!(ro(&a, &named.join("Downloads/sam-jail-run")));
        assert!(pinned(&a, &named.join("Applications")));
        assert!(pinned(&a, &named.join("Downloads")));
        // After the home and the pins (a later mount would cover it).
        let at = |v: &str| a.iter().position(|x| x == v).unwrap();
        let pin = a
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == s(&named.join("Applications")))
            .unwrap();
        assert!(at(&s(&named)) < pin && pin < at(&s(&seen)), "{a:?}");

        // Only Downloads, writable, as a user folder.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.downloads = Access::Rw;
        let mut ctx = ctx_for(&p, &named);
        ctx.host
            .xdg_dirs
            .insert("downloads".into(), named.join("Downloads"));
        ctx.sam_programs = vec![sam.clone(), run.clone()];
        let a = args_of(&ctx);
        assert!(ro(&a, &run), "{a:?}");
        assert!(!a.contains(&s(&sam)), "not shown, nothing added: {a:?}");

        // Read-only: nothing to add.
        ctx.permissions.filesystem.downloads = Access::Ro;
        let a = args_of(&ctx);
        assert!(!ro(&a, &run), "{a:?}");
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

    /// The start's note for the fonts and theme files SAM skips for a link
    /// ([`sam_core::places::own_place_links_note`]), if it names `~/{rel}`.
    fn link_note<'a>(notes: &'a [String], rel: &str) -> Option<&'a String> {
        let place = format!("~/{rel}");
        notes.iter().find(|n| {
            n.contains("SAM does not follow such a link for your fonts and theme files")
                && n.contains(&place)
        })
    }

    /// Whether a note says that SAM does not bind `~/{rel}` on its own, in
    /// any of its forms: for a guarded place, or for a link
    /// ([`link_note`]).
    fn own_note(notes: &[String], rel: &str) -> bool {
        link_note(notes, rel).is_some()
            || notes.iter().any(|n| {
                n.contains(&format!(
                    "SAM does not bind ~/{rel} for this app on its own"
                ))
            })
    }

    /// The watch kept on disk while an app runs comes back as it was, odd
    /// names included; a damaged record never names a place outside the
    /// home or the home itself, which the last look would move aside.
    #[test]
    fn a_watch_read_back_from_disk_never_reaches_outside_the_home() {
        use std::os::unix::ffi::OsStrExt;
        let hex = |s: &[u8]| -> String { s.iter().map(|b| format!("{b:02x}")).collect() };
        let w = HomeWatch {
            home: PathBuf::from("/home/u"),
            absent: vec![".bash_profile".into(), ".config/auto start\nx".into()],
            links: vec![(".config/git".into(), PathBuf::from("/home/u/dots/git"))],
        };
        let lines = w.to_lines();
        let back = HomeWatch::from_lines(lines.iter().map(String::as_str)).unwrap();
        assert_eq!(back.home, w.home);
        assert_eq!(back.absent, w.absent);
        assert_eq!(back.links, w.links);
        for bad in [b"/etc/profile".as_slice(), b"".as_slice()] {
            let rec = [
                format!("home {}", hex(Path::new("/home/u").as_os_str().as_bytes())),
                format!("absent {}", hex(bad)),
            ];
            assert!(
                HomeWatch::from_lines(rec.iter().map(String::as_str)).is_none(),
                "{:?} was taken as a place",
                String::from_utf8_lossy(bad)
            );
        }
        // A line of a known kind with parts missing or too many is a
        // damaged record, not one to pass over (mutation run over PR 95).
        let h = hex(b"/home/u");
        let home = format!("home {h}");
        let place = hex(b".bashrc");
        let good = format!("absent {place}");
        assert!(HomeWatch::from_lines([home.as_str(), good.as_str()].into_iter()).is_some());
        for bad in [
            "home".to_string(),
            format!("home {h} {h}"),
            "absent".to_string(),
            format!("absent {place} {place}"),
            format!("link {place}"),
            format!("link {place} {place} {place}"),
        ] {
            let rec = [home.as_str(), bad.as_str()];
            assert!(HomeWatch::from_lines(rec.into_iter()).is_none(), "{bad:?}");
        }
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

    /// Two launches watching one place both look when an app plants a file
    /// there; the first moves it aside. For the second, the place is already
    /// empty: it reports nothing, never "deleted" or "COULD NOT BE REMOVED"
    /// for a file that sits in the first one's folder. A place that is still
    /// there is reported as before, whichever way it went. (`put_aside` was
    /// a closure before this check; the mutant without the check is the old
    /// code and reports the empty place as `Deleted` or `Failed`.)
    #[test]
    fn a_place_another_look_already_emptied_is_not_reported() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let aside = t.path().join("aside");
        // SAM's folder cannot be made: a file is in its way.
        let blocked = t.path().join("blocked");
        fs::write(&blocked, "").unwrap();
        let unusable = blocked.join("aside");

        // Already empty: nothing to report, whatever else would fail.
        for may_delete in [true, false] {
            for to in [&aside, &unusable] {
                assert_eq!(
                    put_aside(&home, to, ".bash_profile", may_delete),
                    None,
                    "may_delete {may_delete}, aside {to:?}"
                );
            }
        }

        // Still there: moved, or renamed in place, as before.
        fs::write(home.join(".bash_profile"), "evil").unwrap();
        assert_eq!(
            put_aside(&home, &aside, ".bash_profile", true),
            Some((aside.join(".bash_profile"), Aside::Moved))
        );
        assert_eq!(
            fs::read_to_string(aside.join(".bash_profile")).unwrap(),
            "evil"
        );
        fs::write(home.join(".bash_profile"), "evil").unwrap();
        assert_eq!(
            put_aside(&home, &unusable, ".bash_profile", false),
            Some((home.join(".bash_profile.sam-moved-aside"), Aside::Renamed))
        );

        // Still there and nothing can move it: deleted where that is
        // allowed (a name too long for the in-place rename), else said.
        let long = "x".repeat(250);
        fs::write(home.join(&long), "evil").unwrap();
        assert_eq!(
            put_aside(&home, &unusable, &long, true),
            Some((home.join(&long), Aside::Deleted))
        );
        assert!(fs::symlink_metadata(home.join(&long)).is_err());
        let locked = t.path().join("locked");
        fs::create_dir_all(&locked).unwrap();
        fs::write(locked.join(".zshrc"), "evil").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
        let stuck = [true, false].map(|d| put_aside(&locked, &unusable, ".zshrc", d));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        for got in stuck {
            assert_eq!(got, Some((locked.join(".zshrc"), Aside::Failed)));
        }
        assert!(locked.join(".zshrc").exists());
    }

    /// Start folders under another config or data folder in the home
    /// (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`) are protected like the usual
    /// ones, and the new places are on the list (audit S-F6).
    #[test]
    fn start_places_follow_other_config_and_data_folders() {
        let t = tempfile::tempdir().unwrap();
        let home = &fs::canonicalize(t.path()).unwrap().join("u");
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
        // A config folder that is the home itself adds only the file SAM
        // reads the user folders from, never the start places at the top of
        // the home (`~/autostart`), nor the home itself.
        let same = protected_places_with(home, Some(home.to_path_buf()), None);
        assert_eq!(
            same.len(),
            PROTECTED_RO.len() + 1,
            "{:?}",
            &same[PROTECTED_RO.len()..]
        );
        assert_eq!(&same[PROTECTED_RO.len()..], ["user-dirs.dirs"]);
    }

    /// Start places follow `XDG_CONFIG_HOME` and `XDG_DATA_HOME` also when
    /// they name the home's real place or hold `..`; a name that is not
    /// text is found, and a record read back holds only plain names
    /// (review B2 R53, R54).
    #[test]
    fn start_places_follow_config_folders_by_where_they_lead() {
        use std::os::unix::ffi::OsStrExt;
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let real = root.join("data/u");
        fs::create_dir_all(real.join("cfg")).unwrap();
        fs::create_dir_all(real.join("x")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        let home = root.join("home/u");
        std::os::unix::fs::symlink(&real, &home).unwrap();
        for config in [
            real.join("cfg"),
            home.join("x/../cfg"),
            real.join("x/../cfg"),
        ] {
            let p = protected_places_with(&home, Some(config.clone()), None);
            assert!(
                p.iter().any(|x| x == "cfg/autostart"),
                "{}: {:?}",
                config.display(),
                &p[PROTECTED_RO.len()..]
            );
            assert!(p.iter().all(|x| !x.contains("..")), "{p:?}");
        }
        let outside = protected_places_with(&home, Some(home.join("../elsewhere")), None);
        assert_eq!(
            outside.len(),
            PROTECTED_RO.len(),
            "{:?}",
            &outside[PROTECTED_RO.len()..]
        );
        // A name that is not text.
        let odd = home.join(std::ffi::OsStr::from_bytes(b"cfg-\xff"));
        assert_eq!(odd_config_folder(None, Some(&odd)), Some(odd.clone()));
        assert_eq!(odd_config_folder(Some(&home.join("cfg")), None), None);
        // Records read back.
        let line = |kind: &str, p: &str| {
            let hex: String = p.bytes().map(|b| format!("{b:02x}")).collect();
            format!("{kind} {hex}")
        };
        let home_line = line("home", "/home/u");
        // A place with `..` (an older SAM wrote such names) is left out;
        // the rest of the record still counts. Any other damage makes the
        // whole record unreadable.
        let good = line("absent", ".config/x");
        for bad in ["./x", "/x", ""] {
            assert!(
                HomeWatch::from_lines([home_line.as_str(), line("absent", bad).as_str()]).is_none(),
                "{bad} accepted"
            );
        }
        for bad in ["../x", ".config/../../x", "x/../cfg/autostart"] {
            let w = HomeWatch::from_lines([
                home_line.as_str(),
                line("absent", bad).as_str(),
                format!("{} {}", line("link", bad), &line("", "/x")[1..]).as_str(),
                good.as_str(),
            ])
            .unwrap();
            assert_eq!(w.absent, [".config/x"], "{bad}");
            assert!(w.links.is_empty(), "{bad}");
        }
        // A name that holds `..` stops the start as well.
        assert_eq!(
            odd_config_folder(Some(&home.join("x/../cfg")), None),
            Some(home.join("x/../cfg"))
        );
    }

    /// A config folder reached through a link in the home is protected
    /// under both names, and the link itself stays watched: the desktop
    /// follows the name, so an app that swapped the link for its own
    /// folder would otherwise go unnoticed (independent review of PR 134).
    #[test]
    fn a_linked_config_folder_stays_watched_under_both_names() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("u");
        fs::create_dir_all(home.join("dotfiles/cfg")).unwrap();
        std::os::unix::fs::symlink(home.join("dotfiles/cfg"), home.join("cfg")).unwrap();
        let p = protected_places_with(&home, Some(home.join("cfg")), None);
        for want in ["cfg/autostart", "dotfiles/cfg/autostart"] {
            assert!(p.iter().any(|x| x == want), "{want} missing: {p:?}");
        }
        let watched = ancestors_of(p.iter().map(String::as_str));
        assert!(watched.iter().any(|x| x == "cfg"), "{watched:?}");
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

    /// Links leave the sandbox through the portal: web and mail links go to
    /// the person's browser or mail program as asked; any other kind
    /// (`steam://`, `vscode://`, a program's own scheme) makes the portal
    /// ask first with its app chooser, so an app cannot start another
    /// program by a link (audit L-F14). The real script, with a stand-in
    /// for gdbus that records what it was asked to send.
    #[test]
    fn links_to_other_programs_ask_first() {
        let t = tempfile::tempdir().unwrap();
        let shim = t.path().join("xdg-open");
        fs::write(&shim, OPEN_SHIM).unwrap();
        let rec = t.path().join("sent");
        let gdbus = t.path().join("gdbus");
        fs::write(
            &gdbus,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n", rec.display()),
        )
        .unwrap();
        fs::set_permissions(&gdbus, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let sent = |url: &str| {
            let ok = std::process::Command::new("sh")
                .arg(&shim)
                .arg(url)
                .env("PATH", format!("{}:/usr/bin:/bin", t.path().display()))
                .status()
                .unwrap()
                .success();
            assert!(ok, "{url}");
            fs::read_to_string(&rec).unwrap()
        };
        for plain in [
            "https://example.org/?q=1",
            "http://example.org",
            "mailto:a@example.org",
        ] {
            let s = sent(plain);
            assert!(
                s.contains("@a{sv} {}") && !s.contains("ask"),
                "{plain}: {s}"
            );
            assert!(s.lines().any(|l| l == plain), "{s}");
        }
        for other in ["steam://run/1", "vscode://file/x", "x-custom:anything"] {
            let s = sent(other);
            assert!(s.contains("{'ask': <true>}"), "{other}: {s}");
        }
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

    /// Files and folders named on the command line are not shared wherever
    /// SAM refuses a place for them (docs/security.md, *Files named on the
    /// command line*), with `XDG_CONFIG_HOME` given to the refused places
    /// and the process's own left alone:
    /// - with the variable at the home, two start places and a store at
    ///   the top of the home (`~/autostart/x.desktop`, `~/git/...`,
    ///   `~/gh/hosts.yml`), which are shared without it;
    /// - with it at `~/cfg`, anything in that folder; with it outside the
    ///   home (`/data/cfg`), its start places and stores, read and write or
    ///   read-only, and the folder itself; a file beside it is shared;
    /// - with `XDG_DATA_HOME` outside the home (`/share`), a store in it;
    /// - with either variable at `/`, the start places and stores at the
    ///   top of the root (`/autostart/x.desktop`, `/gh/hosts.yml`,
    ///   `/applications/x.desktop`, `/keyrings/login.keyring`), judged by
    ///   their names alone, so they need not exist; a file in the home is
    ///   still shared;
    /// - a file reached through a link in `~/.config` (`~/x`), or through a
    ///   start place's own link to a file elsewhere;
    /// - a file where a start place really leads when the settings folder
    ///   outside the home, or the start place in it, is a link;
    /// - a file where a settings folder outside the home really is when the
    ///   folder that holds it is a link (`/data6` a link to `/disk6`);
    /// - a file reached through a link that lies where a start place really
    ///   leads;
    /// - a file written with `..` after a link (`~/up/../.bashrc`), by its
    ///   written name, while the file it leads to is shared when named so;
    /// - a folder holding a moved settings folder, also one kept as a link,
    ///   or a credential store (`~/.cargo`); an ordinary folder is shared.
    ///
    /// Known gaps (each assertion flips when its gap is closed): a file a
    /// link inside `~/.config/fish` points to, named by its real place, and
    /// one in a folder an unlisted `~/.config/helix` leads to, are shared.
    #[test]
    fn opened_files_are_refused_wherever_a_protected_place_is_named_or_leads() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/ann");
        for d in [
            "autostart",
            "git/proj",
            "gh",
            "work",
            "cfg/fish",
            "cfg/helix",
            ".config/fish",
            "dotfiles/fish",
            "dotfiles/helix",
            "d/cfg",
            ".cargo",
            "e",
            "work/sub",
        ] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        for d in [
            "data/cfg/autostart",
            "data/cfg/gh",
            "data/cfg/fish",
            "disk4/cfg/autostart",
            "data4",
            "data5/auto",
            "data5/cfg",
            "far/cfg",
            "disk6/cfg",
            "share/keyrings",
        ] {
            fs::create_dir_all(base.join(d)).unwrap();
        }
        for f in [
            "autostart/x.desktop",
            "git/proj/a.rs",
            "gh/hosts.yml",
            ".bashrc",
            "work/a.txt",
            "cfg/fish/config.fish",
            "cfg/helix/config.toml",
            "dotfiles/fish/config.fish",
            "dotfiles/helix/config.toml",
            ".cargo/credentials",
            "work/.bashrc",
        ] {
            fs::write(home.join(f), "x").unwrap();
        }
        for f in [
            "data/cfg/autostart/x.desktop",
            "data/cfg/gh/hosts.yml",
            "data/cfg/fish/config.fish",
            "data/notes.txt",
            "disk4/cfg/autostart/x.desktop",
            "data5/auto/x.desktop",
            "disk6/cfg/notes.txt",
            "share/keyrings/login.keyring",
        ] {
            fs::write(base.join(f), "x").unwrap();
        }
        let link = |to: PathBuf, at: PathBuf| std::os::unix::fs::symlink(to, at).unwrap();
        link(home.join("work/a.txt"), home.join(".config/lnk"));
        link(home.join(".config/lnk"), home.join("x"));
        link(
            home.join("dotfiles/fish/config.fish"),
            home.join(".config/fish/config.fish"),
        );
        link(home.join("dotfiles/helix"), home.join(".config/helix"));
        link(base.join("disk4/cfg"), base.join("data4/cfg"));
        link(base.join("data5/auto"), base.join("data5/cfg/autostart"));
        link(base.join("far/cfg"), home.join("e/cfg"));
        link(base.join("disk6"), base.join("data6"));
        link(base.join("data/notes.txt"), base.join("data5/auto/lnk"));
        link(home.join("work/sub"), home.join("up"));
        let shared = |config: Option<PathBuf>, arg: PathBuf, rw: bool| {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.opened_files = Access::Rw;
            let mut ctx = ctx_for(&p, &home);
            ctx.owd = home.clone();
            ctx.args = vec![arg.to_string_lossy().into_owned()];
            let refused = sam_core::places::refused_for_opened_with(&home, config, None);
            !shareable_paths_with(&ctx, &Views::base(&ctx), rw, &refused).is_empty()
        };
        let at_home = || Some(home.clone());
        for f in ["autostart/x.desktop", "git/proj/a.rs", "gh/hosts.yml"] {
            assert!(
                !shared(at_home(), home.join(f), true),
                "{f}, the variable at the home"
            );
            assert!(shared(None, home.join(f), true), "{f} without the variable");
        }
        assert!(!shared(at_home(), home.join(".bashrc"), true));
        assert!(shared(at_home(), home.join("work/a.txt"), true), "control");
        for f in ["cfg/fish/config.fish", "cfg/helix/config.toml"] {
            assert!(!shared(Some(home.join("cfg")), home.join(f), true), "{f}");
        }
        let data = || Some(base.join("data/cfg"));
        for (f, rw) in [
            ("data/cfg/autostart/x.desktop", true),
            ("data/cfg/gh/hosts.yml", false),
            ("data/cfg/fish/config.fish", true),
            ("data/cfg", true),
        ] {
            assert!(!shared(data(), base.join(f), rw), "{f}");
            assert!(
                f == "data/cfg" || shared(None, base.join(f), rw),
                "{f} without the variable"
            );
        }
        assert!(shared(data(), base.join("data/notes.txt"), true), "control");
        let keyring = base.join("share/keyrings/login.keyring");
        let opened_with_data = |data: Option<PathBuf>| {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.opened_files = Access::Rw;
            let mut ctx = ctx_for(&p, &home);
            ctx.args = vec![keyring.to_string_lossy().into_owned()];
            let refused = sam_core::places::refused_for_opened_with(&home, None, data);
            !shareable_paths_with(&ctx, &Views::base(&ctx), false, &refused).is_empty()
        };
        assert!(!opened_with_data(Some(base.join("share"))), "{keyring:?}");
        assert!(opened_with_data(None), "{keyring:?} without the variable");
        let root = || Some(PathBuf::from("/"));
        for (config, data, f) in [
            (root(), None, "/autostart/x.desktop"),
            (root(), None, "/gh/hosts.yml"),
            (None, root(), "/applications/x.desktop"),
            (None, root(), "/keyrings/login.keyring"),
        ] {
            let refused = sam_core::places::refused_for_opened_with(&home, config, data);
            let f = Path::new(f);
            assert!(
                refused.refuses(f, &sam_core::places::follow(f)),
                "{f:?} with a variable at /"
            );
        }
        assert!(
            shared(root(), home.join("work/a.txt"), true),
            "control: the variable at /"
        );
        assert!(!shared(None, home.join("x"), true), "a link in ~/.config");
        assert!(!shared(None, home.join(".config/fish/config.fish"), true));
        assert!(
            !shared(
                Some(base.join("data4/cfg")),
                base.join("disk4/cfg/autostart/x.desktop"),
                true
            ),
            "where a linked settings folder leads"
        );
        assert!(
            !shared(
                Some(base.join("data5/cfg")),
                base.join("data5/auto/x.desktop"),
                true
            ),
            "where a linked start place leads"
        );
        assert!(
            shared(None, base.join("data5/auto/x.desktop"), true),
            "data5/auto/x.desktop without the variable"
        );
        assert!(
            !shared(
                Some(base.join("data5/cfg")),
                base.join("data5/auto/lnk"),
                true
            ),
            "through a link where a linked start place leads"
        );
        assert!(
            !shared(
                Some(base.join("data6/cfg")),
                base.join("disk6/cfg/notes.txt"),
                true
            ),
            "where a settings folder in a linked folder really is"
        );
        assert!(
            shared(None, base.join("disk6/cfg/notes.txt"), true),
            "disk6/cfg/notes.txt without the variable"
        );
        assert!(
            !shared(None, home.join("up/../.bashrc"), true),
            "~/up/../.bashrc by its written name"
        );
        assert!(shared(None, home.join("work/.bashrc"), true), "control");
        assert!(
            !shared(Some(home.join("d/cfg")), home.join("d"), true),
            "~/d"
        );
        assert!(
            shared(None, home.join("d"), true),
            "~/d without the variable"
        );
        assert!(
            !shared(Some(home.join("e/cfg")), home.join("e"), true),
            "~/e"
        );
        assert!(!shared(None, home.join(".cargo"), true), "~/.cargo");
        assert!(shared(None, home.join("work"), true), "control");
        assert!(
            shared(None, home.join("dotfiles/fish/config.fish"), true),
            "known gap: a file a link inside ~/.config/fish points to"
        );
        assert!(
            shared(None, home.join("dotfiles/helix/config.toml"), true),
            "known gap: a file where an unlisted ~/.config/helix leads"
        );
    }

    /// A user folder set to the root, the folder above the home, a link to
    /// it, a key folder or SAM's folder is never shown; a usual one is, at
    /// its real place with a link where the app looks (audit S-F11). Built
    /// outside `/tmp`: a link to a folder above the home that lies in
    /// `/tmp` leads to where programs outside the sandbox listen, which is
    /// the reason the start gives then ([`user_dir`]), checked at the end.
    #[test]
    fn a_user_folder_that_shows_more_is_not_shown() {
        let t = scratch();
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
        // The same link in a home kept in `/tmp`: not shown, for where it
        // leads.
        let in_tmp = tempfile::tempdir().unwrap();
        let above = in_tmp.path().join("home");
        let tmp_home = above.join("ann");
        fs::create_dir_all(&tmp_home).unwrap();
        std::os::unix::fs::symlink(&above, tmp_home.join("up")).unwrap();
        ctx.host.home = tmp_home.clone();
        ctx.sam_dirs = vec![tmp_home.join("sam")];
        assert!(matches!(
            docs(&mut ctx, tmp_home.join("up")),
            Err(NotShown::LeftOut(
                _,
                sam_core::places::LeftOut::HostServices(_)
            ))
        ));
        let a = args_of(&ctx);
        assert!(
            !a.iter().any(|x| Path::new(x) == above),
            "{above:?} not bound: {a:?}"
        );
    }

    /// An extra writable folder that is a start place, lies inside one or
    /// is where one really is, is bound read-only, without, with a
    /// read-only and with a writable whole home, as named, through a link to
    /// the place and with `..`; the views count it read-only and the start
    /// says so. An ordinary extra folder stays writable (with the writable
    /// home it is shown by the home, not bound again). Owner decision 9 of
    /// 2026-11-23: a writable `~/.config/fish/conf.d` let an app plant a
    /// file run at the next shell outside the sandbox.
    #[test]
    fn a_writable_grant_inside_a_start_place_is_bound_read_only() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("u");
        for d in [
            ".config/fish/conf.d",
            ".config/autostart",
            "work",
            "dotfiles/git/hooks",
        ] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(home.join(".config/fish"), home.join("fishlink")).unwrap();
        // `~/.config/git` kept in a dotfiles folder: its real place counts.
        std::os::unix::fs::symlink(home.join("dotfiles/git"), home.join(".config/git")).unwrap();
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        let conf_d = s(home.join(".config/fish/conf.d"));
        let work = s(home.join("work"));
        let hooks = s(home.join("dotfiles/git/hooks"));
        let autostart = s(home.join(".config/autostart"));
        let read_only_notes = |notes: &[String]| {
            notes
                .iter()
                .filter(|n| n.contains("SAM shows it read-only"))
                .count()
        };
        for whole_home in [None, Some(Access::Ro), Some(Access::Rw)] {
            for (grant, bound) in [
                (conf_d.clone(), conf_d.clone()),
                (s(home.join("fishlink/conf.d")), conf_d.clone()),
                (s(home.join("work/../.config/fish/conf.d")), conf_d.clone()),
                (hooks.clone(), hooks.clone()),
                (s(home.join(".config/git/hooks")), hooks.clone()),
                (autostart.clone(), autostart.clone()),
            ] {
                let mut p = PermissionSet::strict_gui();
                if let Some(access) = whole_home {
                    p.filesystem.home = true;
                    p.filesystem.home_access = access;
                }
                p.filesystem.custom_write = vec![grant.clone(), work.clone()];
                let ctx = ctx_for(&p, &home);
                let cmd = Bubblewrap.build(&ctx).unwrap();
                let a = &cmd.args;
                let case = format!("{grant} (whole home: {whole_home:?})");
                assert!(
                    has_seq(a, &["--ro-bind-try", &bound, &bound]),
                    "{case}: {a:?}"
                );
                assert!(
                    !has_seq(a, &["--bind-try", &bound, &bound]),
                    "{case}: {a:?}"
                );
                assert_eq!(
                    has_seq(a, &["--bind-try", &work, &work]),
                    whole_home != Some(Access::Rw),
                    "{case}: {a:?}"
                );
                let views = Views::base(&ctx);
                assert!(!views.writable(Path::new(&bound)), "{case}");
                assert!(views.writable(Path::new(&work)), "{case}");
                assert!(
                    cmd.notes
                        .iter()
                        .any(|n| n.contains(&grant) && n.contains("SAM shows it read-only")),
                    "{case}: {:?}",
                    cmd.notes
                );
                // Only the grant in the start place is named, not `work`.
                assert_eq!(read_only_notes(&cmd.notes), 1, "{case}: {:?}", cmd.notes);
            }
        }
        // Without the whole home nothing else shows a start place writable:
        // the home watch is not needed, and agrees with the mounts.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![conf_d.clone(), autostart.clone()];
        let ctx = ctx_for(&p, &home);
        assert!(!writes_start_places(&ctx));
        assert!(HomeWatch::before(&ctx).is_none());
    }

    /// An extra writable folder below a folder the app can already change
    /// (another writable extra folder, the writable home, a folder opened
    /// writable) is not bound at all: a running copy of the app could turn
    /// a part of its way into a link to a start place after SAM looked, and
    /// Bubblewrap would follow it (independent reviews of decision 9). One
    /// in a start place is bound read-only all the same, where it leads,
    /// with the folders above it pinned: `conf.d` kept as a link into a
    /// granted `~/work` (stow) stayed writable when it was left out.
    #[test]
    fn a_write_grant_below_a_folder_the_app_can_change_is_not_bound() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("u");
        for d in [
            ".config/fish",
            "work/a/proj",
            "work/b",
            "work/dots/fishconf",
        ] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(home.join(".config/fish"), home.join("work/b/proj")).unwrap();
        std::os::unix::fs::symlink(
            home.join("work/dots/fishconf"),
            home.join(".config/fish/conf.d"),
        )
        .unwrap();
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        let work = s(home.join("work"));
        let proj = s(home.join("work/a/proj"));
        let fish = s(home.join(".config/fish"));
        let dots = s(home.join("work/dots"));
        let fishconf = s(home.join("work/dots/fishconf"));
        let binds = |a: &[String], p: &str| {
            a.windows(3)
                .any(|w| matches!(w[0].as_str(), "--bind-try" | "--ro-bind-try") && w[1] == p)
        };
        let skipped = |notes: &[String], p: &str| {
            notes
                .iter()
                .any(|n| n.contains(p) && n.contains("does not bind it a second time"))
        };
        // Below a writable extra folder: only that folder is bound.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![work.clone(), proj.clone()];
        let ctx = ctx_for(&p, &home);
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(
            has_seq(&cmd.args, &["--bind-try", &work, &work]),
            "{:?}",
            cmd.args
        );
        assert!(!binds(&cmd.args, &proj), "{:?}", cmd.args);
        assert!(skipped(&cmd.notes, &proj), "{:?}", cmd.notes);
        // Left out, it adds no mount at all, not even a pin of the folder
        // above it.
        let wa = s(home.join("work/a"));
        assert!(!has_seq(&cmd.args, &["--bind", &wa, &wa]), "{:?}", cmd.args);
        // Shown all the same, writable, through the folder above it.
        assert!(Views::base(&ctx).writable(Path::new(&proj)));
        // Below a folder opened writable on the command line: the same.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.opened_files = Access::Rw;
        p.filesystem.custom_write = vec![proj.clone()];
        let mut ctx = ctx_for(&p, &home);
        ctx.owd = home.clone();
        ctx.args = vec!["work".into()];
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(
            has_seq(&cmd.args, &["--bind-try", &work, &work]),
            "opened: {:?}",
            cmd.args
        );
        assert!(!binds(&cmd.args, &proj), "{:?}", cmd.args);
        assert!(skipped(&cmd.notes, &proj), "{:?}", cmd.notes);
        // Below the writable whole home: not bound either.
        let mut p = full_rw();
        p.filesystem.custom_write = vec![proj.clone()];
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        assert!(!binds(&cmd.args, &proj), "{:?}", cmd.args);
        assert!(!has_seq(&cmd.args, &["--bind", &wa, &wa]), "{:?}", cmd.args);
        // Below a read-only whole home it is bound as usual.
        p.filesystem.home_access = Access::Ro;
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        assert!(
            has_seq(&cmd.args, &["--bind-try", &proj, &proj]),
            "{:?}",
            cmd.args
        );
        // A link to a start place when SAM looks: read-only where it leads,
        // never writable.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = vec![s(home.join("work/b/proj"))];
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        assert!(
            has_seq(&cmd.args, &["--ro-bind-try", &fish, &fish]),
            "{:?}",
            cmd.args
        );
        assert!(
            !has_seq(&cmd.args, &["--bind-try", &fish, &fish]),
            "{:?}",
            cmd.args
        );
        // A start place kept through a link into a writable folder (stow):
        // read-only where it leads, also below the writable folder or home,
        // and the folder between them pinned so it cannot be renamed away.
        for whole_home in [false, true] {
            let mut p = if whole_home {
                full_rw()
            } else {
                PermissionSet::strict_gui()
            };
            p.filesystem.custom_write = vec![work.clone(), s(home.join(".config/fish/conf.d"))];
            let ctx = ctx_for(&p, &home);
            let cmd = Bubblewrap.build(&ctx).unwrap();
            let a = &cmd.args;
            assert!(
                has_seq(a, &["--ro-bind-try", &fishconf, &fishconf]),
                "{whole_home}: {a:?}"
            );
            assert!(
                !has_seq(a, &["--bind-try", &fishconf, &fishconf]),
                "{whole_home}: {a:?}"
            );
            assert!(has_seq(a, &["--bind", &dots, &dots]), "{whole_home}: {a:?}");
            assert!(!Views::base(&ctx).writable(Path::new(&fishconf)));
            assert!(
                cmd.notes
                    .iter()
                    .any(|n| n.contains("SAM shows it read-only")),
                "{whole_home}: {:?}",
                cmd.notes
            );
        }
    }

    /// An extra writable folder inside SAM's own folders is not shown at
    /// all, and the start says so in words that fit (independent review of
    /// decision 9: it was said to be shown read-only).
    #[test]
    fn a_write_grant_inside_sams_folders_is_not_shown() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("u");
        for d in [".config/sam/apps", "Games/sam/x"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        for grant in [
            s(home.join(".config/sam/apps")),
            s(home.join("Games/sam/x")),
        ] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.custom_write = vec![grant.clone()];
            let mut ctx = ctx_for(&p, &home);
            ctx.sam_dirs = vec![home.join("Games/sam")];
            let cmd = Bubblewrap.build(&ctx).unwrap();
            assert!(!cmd.args.contains(&grant), "{grant}: {:?}", cmd.args);
            assert!(!Views::base(&ctx).visible(Path::new(&grant)), "{grant}");
            assert!(
                cmd.notes
                    .iter()
                    .any(|n| n.contains(&grant) && n.contains("SAM's own folders")),
                "{grant}: {:?}",
                cmd.notes
            );
            assert!(
                !cmd.notes.iter().any(|n| n.contains("read-only")),
                "{grant}: {:?}",
                cmd.notes
            );
        }
    }

    /// The folders where SAM keeps its own unless told otherwise
    /// (`~/.config/sam`, `~/.local/share/sam`) are among SAM's folders
    /// (`Paths::sam_dirs`) also while this SAM keeps its own elsewhere
    /// (`SAM_DATA_DIR=~/Games/sam`): a grant of something inside one is
    /// hidden with or without the whole home, and a terminal app's start
    /// line leaves it out, as the sandbox check expects. Before, without
    /// the whole home it was shown read-only and named on the start line,
    /// and with it the check expected it shown while the sandbox hid it by
    /// name (independent re-review of decision 9).
    #[test]
    fn folders_named_like_sams_are_hidden_while_sam_keeps_its_own_elsewhere() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        for d in [".local/share/sam/x", ".config/sam/y", "Games/sam", "notes"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let paths = sam_core::Paths {
            config_dir: base.join("elsewhere/config"),
            data_dir: home.join("Games/sam"),
            applications_dir: base.join("applications"),
            runtime_root: None,
        };
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        for whole_home in [false, true] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = whole_home;
            p.filesystem.home_access = Access::Rw;
            p.filesystem.custom_read = [".local/share/sam/x", ".config/sam/y", "notes"]
                .iter()
                .map(|g| s(home.join(g)))
                .collect();
            let mut ctx = ctx_for(&p, &home);
            ctx.sam_dirs = paths.sam_dirs("");
            let a = args_of(&ctx);
            for (d, grant) in [
                (".local/share/sam", ".local/share/sam/x"),
                (".config/sam", ".config/sam/y"),
            ] {
                assert!(
                    has_seq(&a, &["--tmpfs", &s(home.join(d))]),
                    "{d}, whole home {whole_home}: {a:?}"
                );
                // The empty folder comes after every bind of the grant
                // inside it: a later mount covers an earlier one, so a bind
                // after it would show the folder again.
                assert!(
                    hidden_after(&a, &s(home.join(d)), &s(home.join(grant))),
                    "{d}, whole home {whole_home}: {a:?}"
                );
            }
            assert_eq!(
                shown_extra_folders(&ctx),
                vec![s(home.join("notes"))],
                "whole home {whole_home}"
            );
        }
    }

    /// Where `seq` starts in `v`, every time.
    fn at_seq(v: &[String], seq: &[&str]) -> Vec<usize> {
        v.windows(seq.len())
            .enumerate()
            .filter(|(_, w)| w.iter().zip(seq).all(|(a, b)| a == b))
            .map(|(i, _)| i)
            .collect()
    }

    /// Whether an empty folder on `dir` comes after the last bind of
    /// `grant` (any bind onto it, read-only or writable): a later mount
    /// covers an earlier one, so the grant bound again after the empty
    /// folder would show what lies there. Compared with the first bind
    /// only, a second bind after the hiding went unnoticed (independent
    /// review of decision 9).
    fn hidden_after(a: &[String], dir: &str, grant: &str) -> bool {
        let binds: Vec<usize> = a
            .windows(3)
            .enumerate()
            .filter(|(_, w)| {
                matches!(
                    w[0].as_str(),
                    "--bind" | "--bind-try" | "--ro-bind" | "--ro-bind-try"
                ) && w[2] == grant
            })
            .map(|(i, _)| i)
            .collect();
        let hide = at_seq(a, &["--tmpfs", dir]);
        binds
            .last()
            .is_some_and(|last| hide.iter().any(|h| h > last))
    }

    /// A folder named like SAM's that is a link (`~/.config/sam` planted
    /// as a link to the home by an app that could write `~/.config`) never
    /// makes the home count as SAM's folder: no start covers the home with
    /// an empty folder, a grant below it stays shown and a writable one is
    /// shown read-only as below any start place, not left out. Before,
    /// with SAM's folders kept elsewhere, every grant in the home was
    /// hidden and the home covered (independent re-review of decision 9).
    /// With the whole home writable, the link is locked read-only where
    /// the app reaches it, which is the whole home: the lock on the home
    /// comes after the home's own bind and after every bind of a grant in
    /// it, so the home and those grants are read-only, and the start says
    /// so in words that name where the link leads, never that `~/work` is
    /// "inside ~/.config/sam" (independent review of decision 9).
    #[test]
    fn a_link_named_like_sams_folder_never_hides_the_home() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        for d in [".config", "notes", "work"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(&home, home.join(".config/sam")).unwrap();
        let paths = sam_core::Paths {
            config_dir: base.join("elsewhere/config"),
            data_dir: base.join("elsewhere/data"),
            applications_dir: base.join("applications"),
            runtime_root: None,
        };
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        let (notes, work) = (s(home.join("notes")), s(home.join("work")));
        for whole_home in [false, true] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = whole_home;
            p.filesystem.home_access = Access::Rw;
            p.filesystem.custom_read = vec![notes.clone()];
            p.filesystem.custom_write = vec![work.clone()];
            let mut ctx = ctx_for(&p, &home);
            ctx.sam_dirs = paths.sam_dirs("");
            let a = args_of(&ctx);
            assert!(
                !has_seq(&a, &["--tmpfs", &s(home.clone())]),
                "whole home {whole_home}: {a:?}"
            );
            assert!(
                has_seq(&a, &["--ro-bind-try", &notes, &notes]),
                "whole home {whole_home}: {a:?}"
            );
            assert!(
                has_seq(&a, &["--ro-bind-try", &work, &work]),
                "whole home {whole_home}: {a:?}"
            );
            assert_eq!(
                shown_extra_folders(&ctx),
                vec![notes.clone(), work.clone()],
                "whole home {whole_home}"
            );
            let home_s = s(home.clone());
            let lock = at_seq(&a, &["--ro-bind-try", &home_s, &home_s]);
            let said = Bubblewrap.build(&ctx).unwrap().notes;
            let home_note = said
                .iter()
                .any(|n| n.contains("~/.config/sam, a folder SAM protects, is not a real folder but a shortcut to your whole home folder"));
            if whole_home {
                let home_bind = at_seq(&a, &["--bind", &home_s, &home_s]);
                assert_eq!(home_bind.len(), 1, "{a:?}");
                for g in [&notes, &work] {
                    assert!(
                        locked_after(&a, &home_s, g) && lock.iter().any(|l| *l > home_bind[0]),
                        "{g}: {a:?}"
                    );
                }
                assert!(home_note, "{said:?}");
            } else {
                assert!(lock.is_empty(), "{a:?}");
                assert!(!home_note, "{said:?}");
            }
            assert!(
                said.iter().any(|n| n.contains(&work)
                    && n.contains("~/.config/sam, a folder SAM protects, is not a real folder but a shortcut to your home folder or a folder above it")),
                "whole home {whole_home}: {said:?}"
            );
            assert!(
                !said.iter().any(|n| n.contains("is inside")),
                "whole home {whole_home}: {said:?}"
            );
        }
    }

    /// Whether a read-only lock of `dir` onto itself comes after the last
    /// bind of `grant` (any bind onto it, read-only or writable): a later
    /// mount covers an earlier one, so the grant is read-only below it.
    fn locked_after(a: &[String], dir: &str, grant: &str) -> bool {
        let last = a.windows(3).rposition(|w| {
            matches!(
                w[0].as_str(),
                "--bind" | "--bind-try" | "--ro-bind" | "--ro-bind-try"
            ) && w[2] == grant
        });
        let lock = at_seq(a, &["--ro-bind-try", dir, dir]);
        last.is_some_and(|last| lock.iter().any(|l| *l > last))
    }

    /// Another SAM's folders kept elsewhere through a link
    /// (`~/.local/share/sam` a link to `~/Sync/sam`, or `~/.config` a link
    /// out of the home) stay hidden where the app reaches them while this
    /// SAM keeps its own in `~/Games/sam`: with the whole home, with a
    /// grant of the folder above (`~/Sync`) and with a grant of exactly
    /// that folder, an empty folder comes after every bind that shows it,
    /// and the start line does not name a grant it covers. Taken for an
    /// ordinary start place because it was a link, or because it led out
    /// of the home, it was only kept read-only, and the app read the other
    /// SAM's settings and its apps' private homes (independent review of
    /// decision 9).
    #[test]
    fn another_sams_folders_behind_a_link_stay_hidden() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        for d in [".local/share", "Sync/sam/apps", "Games/sam"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        fs::create_dir_all(base.join("outside/cfg/sam/presets")).unwrap();
        std::os::unix::fs::symlink(home.join("Sync/sam"), home.join(".local/share/sam")).unwrap();
        std::os::unix::fs::symlink(base.join("outside/cfg"), home.join(".config")).unwrap();
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        let (sync, other) = (s(home.join("Sync")), s(home.join("Sync/sam")));
        let (outside, cfg_sam) = (s(base.join("outside")), s(base.join("outside/cfg/sam")));
        let start = |whole_home: bool, read: &[&str]| {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = whole_home;
            p.filesystem.home_access = Access::Rw;
            p.filesystem.custom_read = read.iter().map(|g| g.to_string()).collect();
            let mut ctx = ctx_for(&p, &home);
            ctx.sam_dirs = vec![base.join("elsewhere/config"), home.join("Games/sam")];
            (args_of(&ctx), shown_extra_folders(&ctx))
        };
        // The whole home: hidden where the link leads.
        let (a, _) = start(true, &[]);
        assert!(hidden_after(&a, &other, &s(home.clone())), "{a:?}");
        // A grant of the folder above it, or of exactly that folder.
        let (a, shown) = start(false, &[sync.as_str()]);
        assert!(hidden_after(&a, &other, &sync), "{a:?}");
        assert_eq!(shown, vec![sync.clone()]);
        let (a, shown) = start(false, &[other.as_str()]);
        assert!(hidden_after(&a, &other, &other), "{a:?}");
        assert_eq!(shown, Vec::<String>::new());
        // `~/.config` a link out of the home, the folder it leads to granted.
        let (a, _) = start(false, &[outside.as_str()]);
        assert!(hidden_after(&a, &cfg_sam, &outside), "{a:?}");
    }

    /// `~/.config/sam` planted as a link to `~/work` by an app that could
    /// write `~/.config`, while SAM keeps its own elsewhere, never covers a
    /// grant inside `~/work` with an empty folder: a writable `~/work/proj`
    /// is shown read-only, as inside any start place, and the start line
    /// names it. Where the start shows `~/work` itself (granted exactly, or
    /// with the whole home), SAM cannot tell the link from another SAM's
    /// folder kept there, and `~/work` stays hidden as it always was:
    /// nothing hidden before becomes visible (independent review of
    /// decision 9).
    #[test]
    fn a_link_named_like_sams_folder_covers_no_grant_it_only_holds() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        for d in [".config", "work/proj"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(home.join("work"), home.join(".config/sam")).unwrap();
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        let (work, proj) = (s(home.join("work")), s(home.join("work/proj")));
        let start = |whole_home: bool, read: &[&String], write: &[&String]| {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = whole_home;
            p.filesystem.home_access = Access::Rw;
            p.filesystem.custom_read = read.iter().map(|g| g.to_string()).collect();
            p.filesystem.custom_write = write.iter().map(|g| g.to_string()).collect();
            let mut ctx = ctx_for(&p, &home);
            ctx.sam_dirs = vec![base.join("elsewhere/config"), base.join("elsewhere/data")];
            (args_of(&ctx), shown_extra_folders(&ctx))
        };
        let (a, shown) = start(false, &[], &[&proj]);
        assert!(has_seq(&a, &["--ro-bind-try", &proj, &proj]), "{a:?}");
        assert!(!has_seq(&a, &["--bind-try", &proj, &proj]), "{a:?}");
        assert!(!has_seq(&a, &["--tmpfs", &work]), "{a:?}");
        assert_eq!(shown, vec![proj.clone()]);
        // `~/work` itself shown: hidden after every bind that shows it.
        let (a, shown) = start(false, &[&work], &[]);
        assert!(hidden_after(&a, &work, &work), "{a:?}");
        assert_eq!(shown, Vec::<String>::new());
        let (a, _) = start(true, &[], &[&proj]);
        assert!(hidden_after(&a, &work, &s(home.clone())), "{a:?}");
    }

    /// The views and the mounts take one answer per extra writable folder
    /// ([`write_grants`]): each is in the views exactly as it is bound
    /// (writable, read-only, or not at all), and the views of a start are
    /// those of its decided grants (independent review of decision 9).
    #[test]
    fn the_views_and_the_mounts_take_one_answer_per_write_grant() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("u");
        for d in [".config/fish/conf.d", "work/a", "dots/x"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_write = ["work", "work/a", ".config/fish/conf.d", "dots/x"]
            .into_iter()
            .map(|g| s(home.join(g)))
            .collect();
        let ctx = ctx_for(&p, &home);
        let writes = write_grants(&ctx);
        assert_eq!(writes.len(), 4);
        let cmd = Bubblewrap.build(&ctx).unwrap();
        let views = Views::base(&ctx);
        assert_eq!(views.grants, Views::of_writes(&ctx, &writes).grants);
        let mut kinds = Vec::new();
        for g in &writes {
            let b = s(g.bound.clone());
            let rw = has_seq(&cmd.args, &["--bind-try", &b, &b]);
            let ro = has_seq(&cmd.args, &["--ro-bind-try", &b, &b]);
            let in_views = views.grants.iter().find(|(v, _)| *v == g.bound);
            match &g.how {
                WriteBind::Below(_) | WriteBind::InsideSam => {
                    assert!(!rw && !ro && in_views.is_none(), "{g:?}");
                    kinds.push("left out");
                }
                WriteBind::LeftOut(_) => {
                    assert!(!rw && !ro && in_views.is_none(), "{g:?}");
                    kinds.push("left out");
                }
                WriteBind::ReadOnly(_) => {
                    assert!(
                        ro && !rw && in_views == Some(&(g.bound.clone(), false)),
                        "{g:?}"
                    );
                    kinds.push("read-only");
                }
                WriteBind::Writable => {
                    assert!(
                        rw && !ro && in_views == Some(&(g.bound.clone(), true)),
                        "{g:?}"
                    );
                    kinds.push("writable");
                }
            }
        }
        assert_eq!(kinds, ["writable", "left out", "read-only", "writable"]);
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
        // Folders too (mutation run P14: a missing folder outside the grant
        // was made in the person's home unnoticed).
        for d in [".local/bin", ".local/share/applications"] {
            assert!(!home.join(d).exists(), "{d} is not shown, so not made");
        }
        fs::create_dir_all(home.join(".config/sway")).unwrap();
        fs::write(home.join(".config/sway/config"), "exec evil").unwrap();
        let moved: Vec<String> = w
            .settle(&t.path().join("aside"))
            .into_iter()
            .map(|m| m.place)
            .collect();
        assert!(moved.contains(&".config/sway".to_string()), "{moved:?}");
    }

    /// A launch never makes a start place that another running launch on
    /// the same home watches as empty: nothing is reported moved aside, both
    /// watches still move aside what an app puts there, and without such a
    /// launch the place is made. Review B2 R52: launch A may write
    /// `~/.config` only and saw `~/.local/bin` missing; launch B, which may
    /// write the whole home, starts while A runs. A's watch (and B's, which
    /// takes A's over) moved the empty folder SAM made for B aside at once
    /// and said so.
    fn hex_of(p: &Path) -> String {
        use std::os::unix::ffi::OsStrExt;
        p.as_os_str()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn a_launch_alongside_another_never_makes_a_place_the_other_watches_as_empty() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(home.join(".config")).unwrap();
        let mut narrow = PermissionSet::strict_gui();
        narrow.filesystem.custom_write = vec![home.join(".config").to_string_lossy().into()];
        let (ctx_a, ctx_b) = (ctx_for(&narrow, &home), ctx_for(&full_rw(), &home));
        let (aside_a, aside_b) = (t.path().join("aside-a"), t.path().join("aside-b"));

        // A starts: `~/.local/bin` is not shown, so not made.
        prepare_home_protection(&ctx_a);
        let a = HomeWatch::before(&ctx_a).expect("A watches");
        assert!(fs::symlink_metadata(home.join(".local/bin")).is_err());

        // B starts while A runs.
        let running = std::slice::from_ref(&a);
        prepare_home_protection_alongside(&ctx_b, running);
        let b = HomeWatch::before_alongside(&ctx_b, running).expect("B watches");
        for d in [".local/bin", ".local"] {
            assert!(
                fs::symlink_metadata(home.join(d)).is_err(),
                "{d} was made although A watches it as empty"
            );
        }
        assert!(b.settle(&aside_b).is_empty(), "B reports nothing");
        assert!(a.settle(&aside_a).is_empty(), "A reports nothing");

        // B's app makes the place: both watches still catch it.
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        fs::write(home.join(".local/bin/ls"), "#!/bin/sh\necho evil\n").unwrap();
        let moved: Vec<String> = b.settle(&aside_b).into_iter().map(|m| m.place).collect();
        assert_eq!(moved, [".local"], "watched by B");
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        let moved: Vec<String> = a.settle(&aside_a).into_iter().map(|m| m.place).collect();
        assert_eq!(moved, [".local"], "watched by A");

        // A running launch on another home changes nothing here.
        let elsewhere = HomeWatch::from_lines([
            format!("home {}", hex_of(&t.path().join("other"))).as_str(),
            format!("absent {}", hex_of(Path::new(".local/bin"))).as_str(),
        ])
        .unwrap();
        prepare_home_protection_alongside(&ctx_b, std::slice::from_ref(&elsewhere));
        assert!(home.join(".local/bin").is_dir(), "another home's record");
        // A record that names only a folder above the place (an older SAM).
        fs::remove_dir_all(home.join(".local")).unwrap();
        let older = HomeWatch::from_lines([
            format!("home {}", hex_of(&home)).as_str(),
            format!("absent {}", hex_of(Path::new(".local"))).as_str(),
        ])
        .unwrap();
        prepare_home_protection_alongside(&ctx_b, std::slice::from_ref(&older));
        assert!(
            fs::symlink_metadata(home.join(".local")).is_err(),
            "below a watched place"
        );
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

    /// With the whole home granted, a user folder is mounted at its own
    /// access wherever the home does not already show it at exactly that
    /// access: read-only in a writable home (finding R63), writable in a
    /// read-only one, and outside the home at all
    /// (`XDG_DOCUMENTS_DIR=/data/Documents`), read-only or writable. A link
    /// outside the home is put where the app looks; one in the home comes
    /// with it. The views give the same answer as the mounts. Built outside
    /// `/tmp`, where a link counts as one to where programs outside the
    /// sandbox listen: there it is left out as well, checked at the end.
    #[test]
    fn a_user_folder_is_mounted_at_its_own_access_with_the_whole_home() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        let outside = base.join("data/Documents");
        for d in [
            home.join("Documents"),
            home.join("Pictures"),
            outside.clone(),
        ] {
            fs::create_dir_all(d).unwrap();
        }
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let start = |home_access: Access, docs: Access, docs_at: &Path| {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            p.filesystem.home_access = home_access;
            p.filesystem.documents = docs;
            p.filesystem.pictures = home_access;
            let mut ctx = ctx_for(&p, &home);
            ctx.host
                .xdg_dirs
                .insert("documents".into(), docs_at.to_path_buf());
            ctx.host
                .xdg_dirs
                .insert("pictures".into(), home.join("Pictures"));
            ctx
        };
        let op = |acc: Access| {
            if acc == Access::Rw {
                "--bind-try"
            } else {
                "--ro-bind-try"
            }
        };
        let home_bind = |a: &[String], acc: Access| {
            let op = if acc == Access::Rw {
                "--bind"
            } else {
                "--ro-bind"
            };
            at_seq(a, &[op, &st(&home), &st(&home)])[0]
        };
        let docs = home.join("Documents");
        let pics = st(&home.join("Pictures"));
        for (home_access, acc) in [(Access::Rw, Access::Ro), (Access::Ro, Access::Rw)] {
            let ctx = start(home_access, acc, &docs);
            let a = args_of(&ctx);
            let at = at_seq(&a, &[op(acc), &st(&docs), &st(&docs)]);
            assert!(
                at.iter().any(|i| *i > home_bind(&a, home_access)),
                "{home_access:?} home, {acc:?} Documents: its own mount after the home: {a:?}"
            );
            assert!(
                !a.contains(&pics),
                "Pictures at the home's access needs no mount: {a:?}"
            );
            assert_eq!(
                Views::base(&ctx).writable(&docs.join("x")),
                acc == Access::Rw,
                "the views agree"
            );
        }
        // At the home's own access: shown through the home alone.
        for acc in [Access::Rw, Access::Ro] {
            let a = args_of(&start(acc, acc, &docs));
            assert!(!a.iter().any(|x| *x == st(&docs)), "{acc:?}: {a:?}");
        }
        // Outside the home: bound at its own access, whatever the home's.
        for home_access in [Access::Rw, Access::Ro] {
            for acc in [Access::Rw, Access::Ro] {
                let ctx = start(home_access, acc, &outside);
                let a = args_of(&ctx);
                assert!(
                    has_seq(&a, &[op(acc), &st(&outside), &st(&outside)]),
                    "{home_access:?} home, {acc:?} {outside:?}: {a:?}"
                );
                assert_eq!(
                    Views::base(&ctx).writable(&outside.join("x")),
                    acc == Access::Rw
                );
            }
        }
        // A link outside the home: shown where it leads, with the link
        // where the app looks for it.
        let link = base.join("data/Docs");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let a = args_of(&start(Access::Rw, Access::Ro, &link));
        assert!(
            has_seq(&a, &["--ro-bind-try", &st(&outside), &st(&outside)]),
            "{a:?}"
        );
        assert!(
            has_seq(&a, &["--symlink", &st(&outside), &st(&link)]),
            "{a:?}"
        );
        // A link in a read-only home: the home shows the link itself.
        let in_home = home.join("Docs");
        std::os::unix::fs::symlink(&outside, &in_home).unwrap();
        let a = args_of(&start(Access::Ro, Access::Rw, &in_home));
        assert!(
            has_seq(&a, &["--bind-try", &st(&outside), &st(&outside)]),
            "{a:?}"
        );
        assert!(!a.iter().any(|x| *x == st(&in_home)), "{a:?}");
        // In a writable home the app could have put that link there: where
        // it leads is not shown, and the start names the link. Both rules
        // for user folders refuse it; the one for planted links that lead
        // out of what the home shows says why ([`user_dir`]).
        let ctx = start(Access::Rw, Access::Ro, &in_home);
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(
            !cmd.args.iter().any(|x| *x == st(&outside)),
            "{:?}",
            cmd.args
        );
        assert!(
            cmd.notes
                .iter()
                .any(|n| names(n, &in_home) && n.contains("may have made that link")),
            "{:?}",
            cmd.notes
        );
        assert!(!Views::base(&ctx).visible(&outside.join("x")));
        assert_eq!(
            sam_core::places::user_folder_link_the_app_can_change(
                &ctx.permissions,
                &ctx.host,
                &in_home
            ),
            Some(in_home.clone())
        );
        assert!(matches!(
            user_dir(&ctx, "documents"),
            Err(NotShown::LeftOut(_, sam_core::places::LeftOut::Link(l))) if l == in_home
        ));
        // A user folder that shows more than one is still not shown.
        fs::create_dir_all(home.join(".ssh")).unwrap();
        let a = args_of(&start(Access::Rw, Access::Ro, &home.join(".ssh")));
        let ssh = st(&home.join(".ssh"));
        assert!(
            !has_seq(&a, &["--ro-bind-try", &ssh, &ssh]),
            "refused: {a:?}"
        );
        // A link outside the home in `/tmp`: whoever made it, it leads to
        // where programs outside the sandbox listen, so it is not mounted,
        // read-only or writable, and the start says why.
        let in_tmp = tempfile::tempdir().unwrap();
        let tmp_link = fs::canonicalize(in_tmp.path()).unwrap().join("Docs");
        std::os::unix::fs::symlink(&outside, &tmp_link).unwrap();
        for (home_access, acc) in [(Access::Rw, Access::Ro), (Access::Ro, Access::Rw)] {
            let ctx = start(home_access, acc, &tmp_link);
            let cmd = Bubblewrap.build(&ctx).unwrap();
            assert!(
                !cmd.args.iter().any(|x| *x == st(&outside)),
                "{home_access:?} home, {acc:?}: {:?}",
                cmd.args
            );
            assert!(
                cmd.notes.iter().any(|n| n.contains(&st(&tmp_link))
                    && n.contains("where programs outside the sandbox listen")),
                "{:?}",
                cmd.notes
            );
            assert!(!Views::base(&ctx).visible(&outside.join("x")));
        }
    }

    /// A start file kept as a link into a read-only user folder
    /// (`~/.bashrc` to `~/Documents/dotfiles/bashrc`) with the whole home
    /// writable is read-only: the folder's own read-only mount comes after
    /// the home (finding R63). A writable user folder inside it that holds
    /// the file (Desktop set to `~/Documents/dotfiles`) is mounted writable
    /// after the read-only one, though the home has that access too, and
    /// the start file is locked after both.
    #[test]
    fn a_start_file_linked_into_a_read_only_user_folder_is_never_writable() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        let dots = home.join("Documents/dotfiles");
        fs::create_dir_all(&dots).unwrap();
        fs::write(dots.join("bashrc"), "# rc\n").unwrap();
        std::os::unix::fs::symlink(dots.join("bashrc"), home.join(".bashrc")).unwrap();
        let mut p = full_rw();
        p.filesystem.documents = Access::Ro;
        let mut ctx = ctx_for(&p, &home);
        ctx.host
            .xdg_dirs
            .insert("documents".into(), home.join("Documents"));
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let docs = st(&home.join("Documents"));
        let a = args_of(&ctx);
        let h = at_seq(&a, &["--bind", &st(&home), &st(&home)])[0];
        let ro = at_seq(&a, &["--ro-bind-try", &docs, &docs]);
        assert!(ro.iter().any(|i| *i > h), "{a:?}");
        assert!(!Views::base(&ctx).writable(&dots.join("bashrc")));
        // A writable user folder inside the read-only one: mounted after
        // it, and the start file locked after both.
        ctx.permissions.filesystem.desktop = Access::Rw;
        ctx.host.xdg_dirs.insert("desktop".into(), dots.clone());
        let a = args_of(&ctx);
        let rw = at_seq(&a, &["--bind-try", &st(&dots), &st(&dots)]);
        assert!(
            rw.iter()
                .any(|i| *i > at_seq(&a, &["--ro-bind-try", &docs, &docs])[0]),
            "{a:?}"
        );
        assert!(Views::base(&ctx).writable(&dots.join("bashrc")));
        assert!(
            locked_after(&a, &st(&dots.join("bashrc")), &st(&dots)),
            "{a:?}"
        );
    }

    /// A user folder reached through a link the app could have put there
    /// is not shown where the link leads: with the whole home writable,
    /// `mv ~/Downloads ~/D; ln -s /data/elsewhere ~/Downloads` in one start
    /// showed `/data/elsewhere` writable in the next, any place on the
    /// computer the app chose. Also a link in a writable user folder
    /// (Downloads set to `~/Documents/dl`, Documents writable) without the
    /// whole home, and a link inside a link's target. A link in a folder
    /// the app cannot change is followed as before. The start names the
    /// link, and the views agree with the mounts. Where the link leads out
    /// of what the home shows, the rule for planted links refuses it too
    /// and says why ([`user_dir`]); one to a place the home shows anyway is
    /// refused by this rule alone. Built outside `/tmp`, where every link
    /// counts as one to where programs outside the sandbox listen.
    #[test]
    fn a_user_folder_behind_a_link_the_app_could_plant_is_not_shown() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        let elsewhere = base.join("data/elsewhere");
        for d in [home.join("Documents"), home.join("D"), elsewhere.clone()] {
            fs::create_dir_all(d).unwrap();
        }
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let planted = home.join("Downloads");
        std::os::unix::fs::symlink(&elsewhere, &planted).unwrap();
        let start = |p: &PermissionSet, downloads: &Path| {
            let mut ctx = ctx_for(p, &home);
            ctx.permissions.filesystem.downloads = Access::Rw;
            ctx.host
                .xdg_dirs
                .insert("downloads".into(), downloads.to_path_buf());
            ctx.host
                .xdg_dirs
                .insert("documents".into(), home.join("Documents"));
            ctx
        };
        let refused = |ctx: &LaunchContext, link: &Path| {
            let cmd = Bubblewrap.build(ctx).unwrap();
            assert!(
                !cmd.args.iter().any(|x| *x == st(&elsewhere)),
                "{:?}",
                cmd.args
            );
            assert!(
                cmd.notes
                    .iter()
                    .any(|n| names(n, link) && n.contains("may have made that link")),
                "{:?}",
                cmd.notes
            );
            assert!(!Views::base(ctx).visible(&elsewhere.join("x")));
            let dir = ctx.host.xdg_dir("downloads").unwrap();
            assert_eq!(
                sam_core::places::user_folder_link_the_app_can_change(
                    &ctx.permissions,
                    &ctx.host,
                    dir
                )
                .as_deref(),
                Some(link)
            );
            assert!(matches!(
                user_dir(ctx, "downloads"),
                Err(NotShown::LeftOut(_, sam_core::places::LeftOut::Link(l))) if l == link
            ));
        };
        // The writable whole home holds the link.
        refused(&start(&full_rw(), &planted), &planted);
        // One to a place the writable home shows anyway (`~/D`), set
        // read-only: refused by this rule alone, which names the link, so
        // it gets no read-only mount of its own there.
        let to_home = home.join("Dl");
        std::os::unix::fs::symlink(home.join("D"), &to_home).unwrap();
        let mut ctx = start(&full_rw(), &to_home);
        ctx.permissions.filesystem.downloads = Access::Ro;
        let cmd = Bubblewrap.build(&ctx).unwrap();
        let d = st(&home.join("D"));
        assert!(
            !has_seq(&cmd.args, &["--ro-bind-try", &d, &d]),
            "{:?}",
            cmd.args
        );
        assert!(
            cmd.notes
                .iter()
                .any(|n| n.contains(&st(&to_home)) && n.contains("the app may have put it there")),
            "{:?}",
            cmd.notes
        );
        assert!(matches!(
            user_dir(&ctx, "downloads"),
            Err(NotShown::Link(_, l)) if l == to_home
        ));
        // A writable user folder holds it, without the whole home.
        let dl = home.join("Documents/dl");
        std::os::unix::fs::symlink(&elsewhere, &dl).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Rw;
        refused(&start(&p, &dl), &dl);
        // A link inside a link's target: `~/D/dl` reached through `/data/d`,
        // a link the app cannot change, into the writable home.
        let into_home = base.join("data/d");
        std::os::unix::fs::symlink(home.join("D"), &into_home).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join("D/dl")).unwrap();
        refused(
            &start(&full_rw(), &into_home.join("dl")),
            &home.join("D/dl"),
        );
        // A link in a folder the app cannot change is followed: the home
        // read-only, or Documents read-only.
        let mut p = full_rw();
        p.filesystem.home_access = Access::Ro;
        let a = args_of(&start(&p, &planted));
        assert!(
            has_seq(&a, &["--bind-try", &st(&elsewhere), &st(&elsewhere)]),
            "{a:?}"
        );
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Ro;
        let a = args_of(&start(&p, &dl));
        assert!(
            has_seq(&a, &["--bind-try", &st(&elsewhere), &st(&elsewhere)]),
            "{a:?}"
        );
    }

    /// A user folder set to `/tmp` or to a folder in it where programs
    /// outside the sandbox listen (`/tmp/tmux-1000`) is not shown, with or
    /// without the whole home: bound over the sandbox's own `/tmp`, it
    /// handed the app the host's terminal multiplexers and SSH agents,
    /// read-only too (`tmux -S /tmp/tmux-1000/default new-window …` runs
    /// outside the sandbox). The start says why. An ordinary folder in
    /// `/tmp` is shown.
    #[test]
    fn a_user_folder_where_outside_programs_listen_is_not_shown() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        fs::create_dir_all(&home).unwrap();
        for p in [full_rw(), PermissionSet::strict_gui()] {
            for (at, acc) in [("/tmp", Access::Ro), ("/tmp/tmux-1000", Access::Rw)] {
                let mut ctx = ctx_for(&p, &home);
                ctx.permissions.filesystem.downloads = acc;
                ctx.host.xdg_dirs.insert("downloads".into(), at.into());
                let cmd = Bubblewrap.build(&ctx).unwrap();
                assert!(
                    !cmd.args
                        .windows(2)
                        .any(|w| w[0].ends_with("bind-try") && w[1] == at),
                    "{at}: {:?}",
                    cmd.args
                );
                assert!(
                    cmd.notes.iter().any(
                        |n| n.contains(at) && n.contains("programs outside the sandbox listen")
                    ),
                    "{at}: {:?}",
                    cmd.notes
                );
                assert!(matches!(
                    user_dir(&ctx, "downloads"),
                    Err(NotShown::Sockets(_))
                ));
            }
        }
        assert!(sam_core::places::user_folder_place(Path::new("/tmp/exchange"), &home).is_some());
    }

    /// An extra folder granted read and write inside a read-only user
    /// folder under the writable whole home (`~/Documents/proj`, Documents
    /// read-only) is bound writable after the read-only folder, as the
    /// switch says and the sandbox check expects: the app cannot change
    /// its way, since the read-only folder is a mount of its own. Before,
    /// it was taken as lying below the writable home, left out, and so
    /// read-only, while the start said the app could already change it.
    /// The same inside a read-only extra folder. One right below the
    /// writable home is still not bound a second time.
    #[test]
    fn a_write_grant_inside_a_read_only_user_folder_stays_writable() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in ["Documents/proj", "ref/proj", "work"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let docs = st(&home.join("Documents"));
        let reference = st(&home.join("ref"));
        let below = |notes: &[String], p: &str| {
            notes
                .iter()
                .any(|n| n.contains(p) && n.contains("does not bind it a second time"))
        };
        for (inside, ro) in [("Documents/proj", &docs), ("ref/proj", &reference)] {
            let proj = st(&home.join(inside));
            let mut p = full_rw();
            p.filesystem.documents = Access::Ro;
            p.filesystem.custom_read = vec![reference.clone()];
            p.filesystem.custom_write = vec![proj.clone(), st(&home.join("work"))];
            let mut ctx = ctx_for(&p, &home);
            ctx.host
                .xdg_dirs
                .insert("documents".into(), home.join("Documents"));
            let cmd = Bubblewrap.build(&ctx).unwrap();
            let ro_at = at_seq(&cmd.args, &["--ro-bind-try", ro, ro]);
            let rw_at = at_seq(&cmd.args, &["--bind-try", &proj, &proj]);
            assert!(
                rw_at.iter().any(|w| ro_at.iter().any(|r| w > r)),
                "{inside}: writable after the read-only folder: {:?}",
                cmd.args
            );
            assert!(!below(&cmd.notes, &proj), "{inside}: {:?}", cmd.notes);
            assert!(Views::base(&ctx).writable(&home.join(inside).join("x")));
            // Right below the writable home: shown by it, not bound again.
            let work = st(&home.join("work"));
            assert!(
                !has_seq(&cmd.args, &["--bind-try", &work, &work]),
                "{:?}",
                cmd.args
            );
            assert!(below(&cmd.notes, &work), "{:?}", cmd.notes);
        }
    }

    /// A link inside a read-only folder under the writable whole home
    /// counts as one the app could have put there: such a folder is not
    /// mounted at all when the sandbox refuses it (Documents itself a link
    /// to `~/Dropbox/Documents` in the writable home), so the home shows
    /// it writable; and where it is mounted, the app may have written
    /// there in an earlier start, before it was set read-only. Taken as
    /// read-only, `mv ~/Dropbox/Documents/Downloads ~/x; ln -s /srv/data
    /// ~/Dropbox/Documents/Downloads` in one start bound `/srv/data`
    /// writable as Downloads in the next (review of finding R63). The same
    /// inside a read-only extra folder. Each such link leads out of what
    /// the home shows, so the rule for planted links refuses it too and
    /// says why ([`user_dir`]). Built outside `/tmp`, where every link
    /// counts as one to where programs outside the sandbox listen.
    #[test]
    fn a_link_inside_a_read_only_folder_in_the_writable_home_is_not_followed() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        let elsewhere = base.join("srv/data");
        let dropbox_docs = home.join("Dropbox/Documents");
        for d in [
            dropbox_docs.clone(),
            home.join("Docs"),
            home.join("ref"),
            elsewhere.clone(),
        ] {
            fs::create_dir_all(d).unwrap();
        }
        std::os::unix::fs::symlink(&dropbox_docs, home.join("Documents")).unwrap();
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let start = |docs: &Path, downloads: &Path, custom_read: Vec<String>| {
            let mut p = full_rw();
            p.filesystem.documents = Access::Ro;
            p.filesystem.downloads = Access::Rw;
            p.filesystem.custom_read = custom_read;
            let mut ctx = ctx_for(&p, &home);
            ctx.host
                .xdg_dirs
                .insert("documents".into(), docs.to_path_buf());
            ctx.host
                .xdg_dirs
                .insert("downloads".into(), downloads.to_path_buf());
            ctx
        };
        let refused = |ctx: &LaunchContext, link: &Path| {
            let cmd = Bubblewrap.build(ctx).unwrap();
            assert!(
                !cmd.args.iter().any(|x| *x == st(&elsewhere)),
                "{link:?}: {:?}",
                cmd.args
            );
            assert!(
                cmd.notes
                    .iter()
                    .any(|n| names(n, link) && n.contains("may have made that link")),
                "{:?}",
                cmd.notes
            );
            assert!(!Views::base(ctx).visible(&elsewhere.join("x")));
            let dir = ctx.host.xdg_dir("downloads").unwrap();
            assert_eq!(
                sam_core::places::user_folder_link_the_app_can_change(
                    &ctx.permissions,
                    &ctx.host,
                    dir
                )
                .as_deref(),
                Some(link)
            );
            assert!(matches!(
                user_dir(ctx, "downloads"),
                Err(NotShown::LeftOut(_, sam_core::places::LeftOut::Link(l))) if l == link
            ));
        };
        // The review's case: Documents is refused and not mounted.
        let planted = dropbox_docs.join("Downloads");
        std::os::unix::fs::symlink(&elsewhere, &planted).unwrap();
        let ctx = start(&home.join("Documents"), &planted, Vec::new());
        assert!(matches!(
            user_dir(&ctx, "documents"),
            Err(NotShown::Link(..))
        ));
        refused(&ctx, &planted);
        // A read-only Documents the sandbox mounts.
        let dl = home.join("Docs/dl");
        std::os::unix::fs::symlink(&elsewhere, &dl).unwrap();
        let ctx = start(&home.join("Docs"), &dl, Vec::new());
        assert!(user_dir(&ctx, "documents").is_ok());
        refused(&ctx, &dl);
        // A read-only extra folder.
        let in_ref = home.join("ref/dl");
        std::os::unix::fs::symlink(&elsewhere, &in_ref).unwrap();
        refused(
            &start(&home.join("Docs"), &in_ref, vec![st(&home.join("ref"))]),
            &in_ref,
        );
    }

    /// The folders above a folder bound at an access of its own inside a
    /// folder the app can change are pinned: above a read-only user folder
    /// (`~/Sync/Documents` read-only under the writable home), above a
    /// read-only extra folder (`~/work/ref`), and so above a writable
    /// extra folder inside a read-only one (`~/Sync/Documents/proj`), with
    /// or without the whole home. A second start of the app with these
    /// permissions could otherwise rename a folder above (`mv ~/Sync
    /// ~/S2`), which carries the mount along, and put a link in its place
    /// between SAM's look and the mount, so the next start bound where the
    /// link led (review of finding R63). A folder that is a grant of its
    /// own, such as the home, is a mount already.
    #[test]
    fn the_folders_above_a_folder_bound_at_its_own_access_are_pinned() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in ["Sync/Documents/proj", "work/ref", "Sync/a/Documents"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let pinned_before = |a: &[String], pin: &Path, op: &str, inside: &Path| {
            let (pin, inside) = (st(pin), st(inside));
            let pins = at_seq(a, &["--bind", &pin, &pin]);
            let mounts = at_seq(a, &[op, &inside, &inside]);
            assert!(
                !mounts.is_empty() && pins.iter().any(|p| mounts.iter().any(|m| p < m)),
                "{pin} pinned before {op} {inside}: {a:?}"
            );
        };
        let mut p = full_rw();
        p.filesystem.documents = Access::Ro;
        p.filesystem.custom_read = vec![st(&home.join("work/ref"))];
        p.filesystem.custom_write = vec![st(&home.join("Sync/Documents/proj"))];
        let mut ctx = ctx_for(&p, &home);
        ctx.host
            .xdg_dirs
            .insert("documents".into(), home.join("Sync/Documents"));
        let a = args_of(&ctx);
        pinned_before(
            &a,
            &home.join("Sync"),
            "--ro-bind-try",
            &home.join("Sync/Documents"),
        );
        pinned_before(
            &a,
            &home.join("work"),
            "--ro-bind-try",
            &home.join("work/ref"),
        );
        pinned_before(
            &a,
            &home.join("Sync"),
            "--bind-try",
            &home.join("Sync/Documents/proj"),
        );
        assert_eq!(
            at_seq(&a, &["--bind", &st(&home), &st(&home)]).len(),
            1,
            "the home is bound once: {a:?}"
        );
        // Without the whole home: below a writable extra folder.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Ro;
        p.filesystem.custom_write = vec![st(&home.join("Sync"))];
        let mut ctx = ctx_for(&p, &home);
        ctx.host
            .xdg_dirs
            .insert("documents".into(), home.join("Sync/a/Documents"));
        let a = args_of(&ctx);
        pinned_before(
            &a,
            &home.join("Sync/a"),
            "--ro-bind-try",
            &home.join("Sync/a/Documents"),
        );
        // Below a folder opened read-only inside a writable extra folder:
        // the start shows the opened `~/work/sub` through `~/work`, so it
        // binds nothing for it, but the write grant `~/work/sub/proj` lies
        // below a read-only grant and is bound writable on its own. Its
        // own place is the only guarded one below `~/work`, so only that
        // pins `~/work/sub`.
        fs::create_dir_all(home.join("work/sub/proj")).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.opened_files = Access::Ro;
        p.filesystem.custom_write = vec![st(&home.join("work")), st(&home.join("work/sub/proj"))];
        let mut ctx = ctx_for(&p, &home);
        ctx.owd = home.clone();
        ctx.args = vec!["work/sub".into()];
        let a = args_of(&ctx);
        let proj = st(&home.join("work/sub/proj"));
        assert!(
            has_seq(&a, &["--bind-try", &proj, &proj]),
            "{proj} bound writable: {a:?}"
        );
        pinned_before(
            &a,
            &home.join("work/sub"),
            "--bind-try",
            &home.join("work/sub/proj"),
        );
    }

    /// Two user folders set to one place with different access (Music
    /// read and write, Pictures read-only, both `~/Media`) take the
    /// stricter one, whatever their order in `XDG_DIR_KEYS`: `~/Media` is
    /// read-only, in the mounts as in the views, with the whole home
    /// writable, read-only or not granted, and the start names the folders
    /// and the rule (owner decision of 2026-11-27). The folder listed last
    /// decided before, so Pictures read-only and Videos read and write at
    /// one place showed it writable. All at one access, nothing changes.
    #[test]
    fn user_folders_at_one_place_take_the_stricter_access() {
        fn user_folder_switch<'a>(f: &'a mut FilesystemPerms, key: &str) -> &'a mut Access {
            match key {
                "documents" => &mut f.documents,
                "downloads" => &mut f.downloads,
                "music" => &mut f.music,
                "pictures" => &mut f.pictures,
                "videos" => &mut f.videos,
                "desktop" => &mut f.desktop,
                _ => unreachable!("{key}"),
            }
        }
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        let media = home.join("Media");
        fs::create_dir_all(&media).unwrap();
        let m = media.to_string_lossy().into_owned();
        // What the mounts show at `~/Media`: the last bind of it, or the
        // home's access.
        let mounted_rw = |a: &[String], home_rw: bool| {
            let rw = at_seq(a, &["--bind-try", &m, &m]).last().copied();
            let ro = at_seq(a, &["--ro-bind-try", &m, &m]).last().copied();
            match (rw, ro) {
                (None, None) => home_rw,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (Some(w), Some(r)) => w > r,
            }
        };
        let (rw, ro) = (Access::Rw, Access::Ro);
        // Every ordered pair of user folders, one read and write and one
        // read-only, and two at one access for the control.
        let mut cases: Vec<(Vec<(&str, Access)>, bool)> = Vec::new();
        for a in XDG_DIR_KEYS {
            for b in XDG_DIR_KEYS.iter().filter(|b| **b != a) {
                cases.push((vec![(a, rw), (b, ro)], false));
            }
        }
        cases.push((vec![("music", rw), ("videos", rw)], true));
        cases.push((vec![("music", ro), ("videos", ro)], false));
        // Every case checked, so each order and each part shows when it
        // goes wrong.
        let mut wrong = Vec::new();
        for home_access in [Some(rw), Some(ro), None] {
            for (set, want) in &cases {
                let mut p = PermissionSet::strict_gui();
                if let Some(acc) = home_access {
                    p.filesystem.home = true;
                    p.filesystem.home_access = acc;
                }
                let mut ctx = ctx_for(&p, &home);
                for (key, acc) in set {
                    *user_folder_switch(&mut ctx.permissions.filesystem, key) = *acc;
                    ctx.host.xdg_dirs.insert((*key).into(), media.clone());
                }
                let cmd = Bubblewrap.build(&ctx).unwrap();
                let a = cmd.args.clone();
                let case = format!("{home_access:?} home, {set:?}");
                if mounted_rw(&a, home_access == Some(rw)) != *want {
                    wrong.push(format!("{case}: mounted writable is not {want}"));
                }
                if Views::base(&ctx).writable(&media.join("x")) != *want {
                    wrong.push(format!("{case}: the views say writable is not {want}"));
                }
                let named = cmd
                    .notes
                    .iter()
                    .any(|n| n.contains("/Media") && n.contains("stricter setting wins"));
                let mixed = set.iter().any(|(_, a)| *a == rw) && set.iter().any(|(_, a)| *a == ro);
                if named != mixed {
                    wrong.push(format!("{case}: named {named}: {:?}", cmd.notes));
                }
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// The folders SAM always binds read-only (the fonts and the font
    /// settings) are never pinned where their read-only bind is still the
    /// topmost mount, on them or inside them: with the whole home writable
    /// and an extra read-only folder inside a font folder
    /// (`~/.fonts/licensed`), a pin of `~/.fonts` was bound after its
    /// read-only bind (equal depth, stable order) and made the font folder
    /// writable, which the start never allowed before the pins of finding
    /// R63. The folders above it the app can change are still pinned.
    #[test]
    fn a_folder_bound_read_only_for_the_fonts_is_never_pinned() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in [
            ".fonts/licensed",
            ".local/share/fonts/a/licensed",
            ".config/fontconfig/conf.d",
        ] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let mut p = full_rw();
        p.filesystem.custom_read = vec![
            st(&home.join(".fonts/licensed")),
            st(&home.join(".local/share/fonts/a/licensed")),
            st(&home.join(".config/fontconfig/conf.d")),
        ];
        let ctx = ctx_for(&p, &home);
        let a = args_of(&ctx);
        for (ro, inside) in [
            (".fonts", ".fonts"),
            (".local/share/fonts", ".local/share/fonts/a"),
            (".config/fontconfig", ".config/fontconfig"),
        ] {
            let (ro, inside) = (st(&home.join(ro)), st(&home.join(inside)));
            assert!(
                !at_seq(&a, &["--ro-bind-try", &ro, &ro]).is_empty(),
                "{ro} bound read-only: {a:?}"
            );
            for pin in [&ro, &inside] {
                assert!(
                    at_seq(&a, &["--bind", pin, pin]).is_empty(),
                    "{pin} never pinned: {a:?}"
                );
            }
        }
        let share = st(&home.join(".local/share"));
        assert!(
            !at_seq(&a, &["--bind", &share, &share]).is_empty(),
            "the folder above is pinned: {a:?}"
        );
    }

    /// A place bound writable somewhere else (an extra writable folder, a
    /// file opened writable, a writable bind of SAM's, each outside the
    /// home) does not cover the fonts and the font settings: their
    /// read-only bind is still the topmost mount, so they are never pinned
    /// writable, as in a start without it. Counted as bound writable after
    /// a font place, or as a writable mount between it and the folder,
    /// any writable bind anywhere had the pin of `~/.fonts` made the font
    /// folder writable. Each way is checked on its own, so each one shows
    /// when it counts.
    #[test]
    fn a_place_bound_writable_elsewhere_leaves_the_font_folders_unpinned() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let mut lost = Vec::new();
        for way in [
            "extra writable folder",
            "opened file",
            "SAM's writable bind",
        ] {
            let t = tempfile::tempdir().unwrap();
            let home = fs::canonicalize(t.path()).unwrap().join("home");
            for d in [
                ".fonts/licensed",
                ".local/share/fonts/a/licensed",
                ".config/fontconfig/conf.d",
            ] {
                fs::create_dir_all(home.join(d)).unwrap();
            }
            let shared = home.parent().unwrap().join("shared");
            fs::create_dir_all(&shared).unwrap();
            let doc = home.parent().unwrap().join("doc.txt");
            fs::write(&doc, "").unwrap();
            let mut p = full_rw();
            p.filesystem.custom_read = vec![
                st(&home.join(".fonts/licensed")),
                st(&home.join(".local/share/fonts/a/licensed")),
                st(&home.join(".config/fontconfig/conf.d")),
            ];
            if way == "extra writable folder" {
                p.filesystem.custom_write = vec![st(&shared)];
            }
            let mut ctx = ctx_for(&p, &home);
            if way == "opened file" {
                ctx.permissions.filesystem.opened_files = Access::Rw;
                ctx.args = vec![st(&doc)];
                assert_eq!(opened_paths(&ctx), vec![(doc.clone(), true)]);
            } else if way == "SAM's writable bind" {
                ctx.extra_binds = vec![(shared.clone(), "/run/x".into(), true)];
            }
            let a = args_of(&ctx);
            let shared = st(&shared);
            let doc = st(&doc);
            let bound = match way {
                "extra writable folder" => has_seq(&a, &["--bind-try", &shared, &shared]),
                "opened file" => has_seq(&a, &["--bind-try", &doc, &doc]),
                _ => has_seq(&a, &["--bind", &shared, "/run/x"]),
            };
            assert!(bound, "{way}: bound writable: {a:?}");
            for (ro, inside) in [
                (".fonts", ".fonts"),
                (".local/share/fonts", ".local/share/fonts/a"),
                (".config/fontconfig", ".config/fontconfig"),
            ] {
                let (ro, inside) = (st(&home.join(ro)), st(&home.join(inside)));
                assert!(
                    !at_seq(&a, &["--ro-bind-try", &ro, &ro]).is_empty(),
                    "{way}: {ro} bound read-only: {a:?}"
                );
                for pin in [&ro, &inside] {
                    if !at_seq(&a, &["--bind", pin, pin]).is_empty() {
                        lost.push(format!("{way}: {pin} pinned writable"));
                    }
                }
            }
        }
        assert!(lost.is_empty(), "{lost:#?}");
    }

    /// A writable extra folder inside a place SAM binds read-only for the
    /// fonts or the themes, or at one, is bound after it and writable: a
    /// start file kept as a link into it (`~/.bashrc` to
    /// `~/.fonts/work/dots/bashrc`) keeps the pins of the folders above
    /// where its guard lands (review B2 S3, R50), so the app cannot rename
    /// `dots` away with the guard. Skipped on or inside the whole read-only
    /// place, those pins were lost. The read-only place itself, where it
    /// is still the topmost mount, stays unpinned.
    ///
    /// SAM does not bind a font or theme place on its own that holds a
    /// place it protects ([`sam_core::places::own_place_decision`]),
    /// except where a grant shows it anyway (the whole home writable, the
    /// writable folder at the place itself); so with the start file's
    /// target inside, the
    /// place is bound read-only only there or where it is also an extra
    /// read-only folder; the pins stay all the same. The same with an extra
    /// read-only folder inside instead (`~/.fonts/work/dots/licensed`),
    /// where SAM's own read-only bind is made: `dots` is pinned after the
    /// writable folder and before the extra one.
    #[test]
    fn a_writable_folder_inside_a_read_only_font_or_theme_place_keeps_its_pins() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        // The read-only place, the writable extra folder, the permissions:
        // the whole home writable with the font folder an extra read-only
        // folder (so the writable one inside is bound on its own), no home
        // with the writable folder at the font folder, and no home with the
        // host themes shown.
        let mut fonts = full_rw();
        fonts.filesystem.custom_read = vec![".fonts".into()];
        let mut themes = PermissionSet::strict_gui();
        themes.advanced.host_themes = true;
        let cases = [
            (".fonts", ".fonts/work", fonts),
            (".fonts", ".fonts", PermissionSet::strict_gui()),
            (".config/gtk-3.0", ".config/gtk-3.0", themes.clone()),
            (".config/gtk-3.0", ".config/gtk-3.0/work", themes),
        ];
        let mut lost = Vec::new();
        for ((ro_rel, work, p), start_file) in cases
            .iter()
            .flat_map(|c| [(c.clone(), true), (c.clone(), false)])
        {
            let mut p = p.clone();
            let t = scratch();
            let home = fs::canonicalize(t.path()).unwrap().join("home");
            let dots = home.join(work).join("dots");
            let licensed = dots.join("licensed");
            fs::create_dir_all(&licensed).unwrap();
            let in_home =
                |v: &[String]| -> Vec<String> { v.iter().map(|c| st(&home.join(c))).collect() };
            p.filesystem.custom_read = in_home(&p.filesystem.custom_read);
            p.filesystem.custom_write = in_home(&[work.to_string()]);
            let guarded = if start_file {
                fs::write(dots.join("bashrc"), "").unwrap();
                std::os::unix::fs::symlink(dots.join("bashrc"), home.join(".bashrc")).unwrap();
                format!("{}/bashrc", st(&dots))
            } else {
                p.filesystem.custom_read.push(st(&licensed));
                st(&licensed)
            };
            let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
            let a = cmd.args;
            let (ro, work, dots) = (st(&home.join(ro_rel)), st(&home.join(work)), st(&dots));
            let first = |seq: &[&str]| at_seq(&a, seq).first().copied();
            let case = format!("{ro} ({}, start file {start_file})", p.filesystem.home);
            let ro_bind = first(&["--ro-bind-try", &ro, &ro]);
            // With the start file's target inside, SAM's own bind of the
            // place is left out in a private home, and says why; an extra
            // read-only folder at the place is still bound. With the whole
            // home writable, or the writable folder at the place itself,
            // which show the place anyway, SAM's own bind is made all the
            // same.
            let home_rw = p.filesystem.home && p.filesystem.home_access == Access::Rw;
            let shown_writable = home_rw || ro == work;
            let notes_own = |says: &str| {
                cmd.notes.iter().any(|n| {
                    (n.contains(&format!(
                        "SAM does not bind ~/{ro_rel} for this app on its own"
                    )) || link_note(std::slice::from_ref(n), ro_rel).is_some())
                        && n.contains(says)
                })
            };
            assert_eq!(
                notes_own("a place SAM protects"),
                start_file && !shown_writable,
                "{case}: {:?}",
                cmd.notes
            );
            if shown_writable {
                assert!(!notes_own(""), "{case}: own bind made: {:?}", cmd.notes);
            }
            let extra_at_place = p.filesystem.custom_read.contains(&ro);
            assert_eq!(
                ro_bind.is_some(),
                !start_file || shown_writable || extra_at_place,
                "{case}: bound read-only: {a:?}"
            );
            let write = first(&["--bind-try", &work, &work]).expect("bound writable");
            if let Some(ro_bind) = ro_bind {
                assert!(ro_bind < write, "{case}: {work} after {ro}: {a:?}");
            }
            let pin = first(&["--bind", &dots, &dots]);
            let guard = first(&["--ro-bind-try", &guarded, &guarded]).expect("guarded");
            // Every case checked, so each one shows when its pin is lost.
            if !pin.is_some_and(|pin| write < pin && pin < guard) {
                lost.push(format!(
                    "{case}: {dots} pinned after {work} ({write}) and before the guard ({guard}): {pin:?}"
                ));
            }
            if ro != work {
                assert!(
                    first(&["--bind", &ro, &ro]).is_none(),
                    "{case}: {ro} never pinned: {a:?}"
                );
            }
        }
        assert!(lost.is_empty(), "{lost:#?}");
    }

    /// A writable user folder inside a font folder under the writable
    /// whole home (`XDG_MUSIC_DIR=~/.fonts/work`) gets no mount of its own,
    /// since the home already shows it writable, so the read-only bind of
    /// `~/.fonts` stays the topmost mount there. The folders above a start
    /// file kept as a link into it (`~/.bashrc` to
    /// `~/.fonts/work/dots/bashrc`) are then not pinned: judged from the
    /// views, which record the user folder writable, `dots` was pinned
    /// after the read-only bind and made writable inside the read-only font
    /// folder. The font folder stays read-only, and nothing in it is bound
    /// writable. The same for an extra read-only folder inside
    /// (`~/.fonts/work/dots/licensed`), whose folders above are pinned as
    /// those above a start file.
    ///
    /// With the start file's target inside, the font folder holds a place
    /// SAM protects; with the whole home writable SAM binds it read-only
    /// all the same ([`sam_core::places::own_place_decision`]): the home
    /// shows it anyway, and the start file is still locked after it.
    #[test]
    fn a_writable_user_folder_the_home_shows_inside_a_font_folder_adds_no_pin() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        for start_file in [false, true] {
            let t = scratch();
            let home = fs::canonicalize(t.path()).unwrap().join("home");
            let work = home.join(".fonts/work");
            let dots = work.join("dots");
            let licensed = dots.join("licensed");
            fs::create_dir_all(&licensed).unwrap();
            let mut p = full_rw();
            p.filesystem.music = Access::Rw;
            if start_file {
                fs::write(dots.join("bashrc"), "").unwrap();
                std::os::unix::fs::symlink(dots.join("bashrc"), home.join(".bashrc")).unwrap();
            } else {
                p.filesystem.custom_read = vec![st(&licensed)];
            }
            let mut ctx = ctx_for(&p, &home);
            ctx.host.xdg_dirs.insert("music".into(), work.clone());
            let cmd = Bubblewrap.build(&ctx).unwrap();
            let a = &cmd.args;
            let fonts = st(&home.join(".fonts"));
            if start_file {
                assert!(!own_note(&cmd.notes, ".fonts"), "{:?}", cmd.notes);
                let bashrc = st(&dots.join("bashrc"));
                assert!(
                    has_seq(a, &["--ro-bind-try", &bashrc, &bashrc]),
                    "the start file stays locked: {a:?}"
                );
            }
            assert!(
                !at_seq(a, &["--ro-bind-try", &fonts, &fonts]).is_empty(),
                "start file {start_file}: {fonts} bound read-only: {a:?}"
            );
            let writable_inside: Vec<&[String]> = a
                .windows(3)
                .filter(|w| {
                    (w[0] == "--bind" || w[0] == "--bind-try")
                        && w[1] == w[2]
                        && Path::new(&w[1]).starts_with(&fonts)
                })
                .collect();
            assert!(
                writable_inside.is_empty(),
                "nothing inside {fonts} bound writable: {writable_inside:?}"
            );
        }
    }

    /// With the whole home writable and hidden files on, the app made
    /// `~/.aws` a link to the home in one start: in the next, every font
    /// place led into a guarded place, SAM left out their read-only binds,
    /// and the home showed `~/.fonts`, `~/.local/share/fonts` and
    /// `~/.config/fontconfig` writable, so the app could plant fonts and
    /// fontconfig rules that programs outside the sandbox load. They stay
    /// bound read-only, as without the link
    /// ([`sam_core::places::own_place_decision`]), and no note says SAM
    /// skipped them.
    #[test]
    fn a_guarded_link_to_the_home_keeps_the_font_places_read_only() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let t = scratch();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        let places = [".fonts", ".local/share/fonts", ".config/fontconfig"];
        for d in places {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(&home, home.join(".aws")).unwrap();
        let mut p = full_rw();
        p.filesystem.hidden_files = true;
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        for rel in places {
            let at = st(&home.join(rel));
            assert!(
                has_seq(&cmd.args, &["--ro-bind-try", &at, &at]),
                "~/{rel} bound read-only: {:?}",
                cmd.args
            );
            assert!(!own_note(&cmd.notes, rel), "{:?}", cmd.notes);
        }
    }

    /// With the home kept behind a link (`/home/u` a link to `/data/u`) and
    /// writable, the app made a missing `~/.fonts` a link to the real place
    /// of `~/.ssh` (`/data/u/.ssh`, which it can read in
    /// `/proc/self/mountinfo`): that place lies in the home where it really
    /// is, so the whole home counted as showing it writable, and the next
    /// start bound `/data/u/.ssh` read-only at that name. The sandbox shows
    /// the home only as `/home/u`, so the keys were hidden there and stayed
    /// readable at `/data/u/.ssh`. The same with SAM's own folder
    /// (`/data/u/.local/share/sam`, which holds other apps' private homes).
    /// SAM follows no link at a font place
    /// ([`sam_core::places::own_place_decision`]): here it leaves `~/.fonts`
    /// out and names the link and where it leads. Where the fonts are real
    /// folders, they stay bound read-only under the home's name, also with
    /// `~/.aws` made a link to the home's real place (hidden files on).
    #[test]
    fn a_font_link_to_the_real_place_of_a_home_behind_a_link_binds_no_guarded_place() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        for guarded_rel in [".ssh", ".local/share/sam"] {
            let t = scratch();
            let base = fs::canonicalize(t.path()).unwrap();
            let real = base.join("data/u");
            let named = base.join("home/u");
            fs::create_dir_all(real.join(guarded_rel)).unwrap();
            fs::write(real.join(guarded_rel).join("id_ed25519"), "secret").unwrap();
            fs::create_dir_all(base.join("home")).unwrap();
            std::os::unix::fs::symlink(&real, &named).unwrap();
            let target = real.join(guarded_rel);
            std::os::unix::fs::symlink(&target, real.join(".fonts")).unwrap();
            let mut ctx = ctx_for(&full_rw(), &named);
            ctx.sam_dirs = vec![named.join(".local/share/sam")];
            let cmd = Bubblewrap.build(&ctx).unwrap();
            let target = st(&target);
            let bound: Vec<&[String]> = cmd
                .args
                .windows(3)
                .filter(|w| w[0].contains("bind") && (w[1] == target || w[2] == target))
                .collect();
            assert!(
                bound.is_empty(),
                "~/.fonts a link to {target}: never bound there: {bound:?}"
            );
            let rel = target.strip_prefix(&st(&real)).unwrap();
            assert!(
                link_note(&cmd.notes, ".fonts")
                    .is_some_and(|n| n.contains(&format!("~/.fonts (a link to ~{rel})"))),
                "{guarded_rel}: {:?}",
                cmd.notes
            );
        }
        // SAM's own folder at a name no protected place has
        // (`SAM_DATA_DIR=~/Games/sam`): guarded only as named, so
        // `/data/u/Games/sam` was bound beside the home. And in a private
        // home, the unpack folder set to `~/Apps/sam` with `~/Apps` a link
        // to another disk: `~/.fonts` made a link to the real place of that
        // folder in an earlier start with the whole home writable was
        // bound and showed every unpacked app.
        for private in [false, true] {
            let t = scratch();
            let base = fs::canonicalize(t.path()).unwrap();
            let (named, target, sams, p) = if private {
                let named = base.join("home/u");
                let disk = base.join("mnt/disk/Apps");
                fs::create_dir_all(&named).unwrap();
                fs::create_dir_all(disk.join("sam")).unwrap();
                std::os::unix::fs::symlink(&disk, named.join("Apps")).unwrap();
                (
                    named.clone(),
                    disk.join("sam"),
                    named.join("Apps/sam"),
                    PermissionSet::strict_gui(),
                )
            } else {
                let real = base.join("data/u");
                let named = base.join("home/u");
                fs::create_dir_all(real.join("Games/sam")).unwrap();
                fs::create_dir_all(base.join("home")).unwrap();
                std::os::unix::fs::symlink(&real, &named).unwrap();
                (
                    named.clone(),
                    real.join("Games/sam"),
                    named.join("Games/sam"),
                    full_rw(),
                )
            };
            fs::write(target.join("id_ed25519"), "secret").unwrap();
            std::os::unix::fs::symlink(&target, named.join(".fonts")).unwrap();
            let mut ctx = ctx_for(&p, &named);
            ctx.sam_dirs = vec![sams];
            let cmd = Bubblewrap.build(&ctx).unwrap();
            let target = st(&target);
            let fonts = st(&named.join(".fonts"));
            let bound: Vec<&[String]> = cmd
                .args
                .windows(3)
                .filter(|w| {
                    w[0].contains("bind")
                        && [&target, &fonts]
                            .iter()
                            .any(|at| w[1] == **at || w[2] == **at)
                })
                .collect();
            assert!(
                bound.is_empty(),
                "private home {private}: ~/.fonts a link to {target}: never bound: {bound:?}"
            );
            assert!(
                link_note(&cmd.notes, ".fonts").is_some(),
                "private home {private}: {:?}",
                cmd.notes
            );
        }
        // The control: real font folders in a home behind a link, also
        // with `~/.aws` a link to the home's real place, stay bound
        // read-only where the app reaches them.
        let places = [".fonts", ".local/share/fonts", ".config/fontconfig"];
        for aws in [false, true] {
            let t = scratch();
            let base = fs::canonicalize(t.path()).unwrap();
            let real = base.join("data/u");
            let named = base.join("home/u");
            for d in places {
                fs::create_dir_all(real.join(d)).unwrap();
            }
            fs::create_dir_all(base.join("home")).unwrap();
            std::os::unix::fs::symlink(&real, &named).unwrap();
            if aws {
                std::os::unix::fs::symlink(&real, real.join(".aws")).unwrap();
            }
            let mut p = full_rw();
            p.filesystem.hidden_files = true;
            let cmd = Bubblewrap.build(&ctx_for(&p, &named)).unwrap();
            for rel in places {
                let at = st(&named.join(rel));
                assert!(
                    has_seq(&cmd.args, &["--ro-bind-try", &at, &at]),
                    "~/.aws a link {aws}: ~/{rel} bound read-only: {:?}",
                    cmd.args
                );
                assert!(
                    !own_note(&cmd.notes, rel),
                    "~/.aws a link {aws}: {:?}",
                    cmd.notes
                );
            }
        }
    }

    /// In a private or read-only home with hidden files on, a font or
    /// theme place inside an extra writable folder stays bound read-only
    /// after it, although a sensitive place leads to it: the app made
    /// `~/.config/vivaldi` a link to `~/.config/fontconfig` (or
    /// `~/.local/share/keyrings` one to `~/.local/share/fonts`, or
    /// `~/.config/vivaldi` one to `~/.config/gtk-3.0`) in one start, so in
    /// the next SAM left the read-only bind out as leading into a guarded
    /// place, and the writable folder showed the fonts settings, the fonts
    /// or the theme files writable: rules that programs outside the
    /// sandbox load ([`sam_core::places::own_place_decision`]). A font
    /// place the views do not show, made a link to a credential store
    /// inside that writable folder, stays left out: it is a link, which
    /// SAM never follows for the fonts, and bound at its own name it would
    /// show the store.
    #[test]
    fn a_writable_extra_folder_keeps_the_font_and_theme_places_in_it_read_only() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let mut ro_home = PermissionSet::strict_gui();
        ro_home.filesystem.home = true;
        ro_home.filesystem.home_access = Access::Ro;
        let mut themes = PermissionSet::strict_gui();
        themes.advanced.host_themes = true;
        // The permissions, the extra writable folder, the planted link and
        // the place SAM binds read-only on its own.
        let cases = [
            (
                PermissionSet::strict_gui(),
                ".config",
                ".config/vivaldi",
                ".config/fontconfig",
            ),
            (ro_home, ".config", ".config/vivaldi", ".config/fontconfig"),
            (
                PermissionSet::strict_gui(),
                ".local/share",
                ".local/share/keyrings",
                ".local/share/fonts",
            ),
            (themes, ".config", ".config/vivaldi", ".config/gtk-3.0"),
        ];
        for (p, write, link, place) in cases {
            let mut p = p.clone();
            let t = scratch();
            let home = fs::canonicalize(t.path()).unwrap().join("home");
            fs::create_dir_all(home.join(place)).unwrap();
            std::os::unix::fs::symlink(home.join(place), home.join(link)).unwrap();
            p.filesystem.hidden_files = true;
            p.filesystem.custom_write = vec![st(&home.join(write))];
            let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
            let a = &cmd.args;
            let case = format!("~/{link} a link to ~/{place}, home {}", p.filesystem.home);
            let (write, at) = (st(&home.join(write)), st(&home.join(place)));
            let writable = at_seq(a, &["--bind-try", &write, &write]);
            let read_only = at_seq(a, &["--ro-bind-try", &at, &at]);
            assert!(
                !writable.is_empty(),
                "{case}: {write} bound writable: {a:?}"
            );
            assert!(
                read_only.last() > writable.last(),
                "{case}: {at} bound read-only after {write}: {a:?}"
            );
            assert!(!own_note(&cmd.notes, place), "{case}: {:?}", cmd.notes);
        }
        // The control: `~/.fonts`, which the views do not show, made a link
        // to the token in the writable `~/.config`, stays left out.
        let t = scratch();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        fs::create_dir_all(home.join(".config/gh")).unwrap();
        std::os::unix::fs::symlink(home.join(".config/gh"), home.join(".fonts")).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.hidden_files = true;
        p.filesystem.custom_write = vec![st(&home.join(".config"))];
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        let fonts = st(&home.join(".fonts"));
        assert!(
            !has_seq(&cmd.args, &["--ro-bind-try", &fonts, &fonts]),
            "{:?}",
            cmd.args
        );
        assert!(
            link_note(&cmd.notes, ".fonts")
                .is_some_and(|n| n.contains("~/.fonts (a link to ~/.config/gh)")),
            "{:?}",
            cmd.notes
        );
    }

    /// A writable user folder set to a font folder itself
    /// (`XDG_MUSIC_DIR=~/.fonts`), without the whole home or with the home
    /// read-only, gets its own writable mount at the same place as the
    /// font folder's read-only bind. That one comes after it (equal depth,
    /// stable order), so the read-only bind stays the topmost mount and
    /// the folder above an extra read-only folder inside
    /// (`~/.fonts/dots/licensed`) is not pinned: a pin there was bound
    /// after the read-only bind and made `dots` writable inside the
    /// read-only font folder. Only a writable mount strictly inside the
    /// font folder lets the app rename something there.
    #[test]
    fn a_writable_user_folder_at_a_font_folder_adds_no_pin_inside() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let mut read_only_home = PermissionSet::strict_gui();
        read_only_home.filesystem.home = true;
        read_only_home.filesystem.home_access = Access::Ro;
        let mut lost = Vec::new();
        for (case, mut p) in [
            ("no home", PermissionSet::strict_gui()),
            ("read-only home", read_only_home),
        ] {
            let t = tempfile::tempdir().unwrap();
            let home = fs::canonicalize(t.path()).unwrap().join("home");
            let fonts = home.join(".fonts");
            let dots = fonts.join("dots");
            fs::create_dir_all(dots.join("licensed")).unwrap();
            p.filesystem.music = Access::Rw;
            p.filesystem.custom_read = vec![st(&dots.join("licensed"))];
            let mut ctx = ctx_for(&p, &home);
            ctx.host.xdg_dirs.insert("music".into(), fonts.clone());
            let a = args_of(&ctx);
            let (fonts, dots) = (st(&fonts), st(&dots));
            let first = |seq: &[&str]| at_seq(&a, seq).first().copied();
            let write = first(&["--bind-try", &fonts, &fonts]).expect("Music bound writable");
            let ro_bind = first(&["--ro-bind-try", &fonts, &fonts]).expect("bound read-only");
            assert!(write < ro_bind, "{case}: read-only on top: {a:?}");
            if first(&["--bind", &dots, &dots]).is_some() {
                lost.push(format!("{case}: {dots} pinned writable: {a:?}"));
            }
        }
        assert!(lost.is_empty(), "{lost:#?}");
    }

    /// A writable user folder inside a font folder in a start without the
    /// whole home (`XDG_MUSIC_DIR=~/.fonts/work`) gets its own writable
    /// mount, after the read-only bind of `~/.fonts`, so the app can
    /// rename what lies inside it. A start file kept as a link into it
    /// (`~/.bashrc` to `~/.fonts/work/dots/bashrc`) keeps the pin of
    /// `dots`, between that mount and the guard (review B2 S3, R50): left
    /// out of the writable mounts, the user folder counted as covered by
    /// the read-only bind, `dots` lost its pin, and the app could rename
    /// it away with the guard. `~/.fonts` itself stays unpinned. The same
    /// for an extra read-only folder inside (`~/.fonts/work/dots/licensed`).
    ///
    /// SAM does not bind a font folder on its own that holds a place it
    /// protects ([`sam_core::places::own_place_decision`]): with the start
    /// file's target inside,
    /// `~/.fonts` is not bound read-only, the start says why, and `dots`
    /// keeps its pin.
    #[test]
    fn a_writable_user_folder_inside_a_font_folder_in_a_private_home_keeps_its_pins() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        for start_file in [false, true] {
            let t = scratch();
            let home = fs::canonicalize(t.path()).unwrap().join("home");
            let work = home.join(".fonts/work");
            let dots = work.join("dots");
            let licensed = dots.join("licensed");
            fs::create_dir_all(&licensed).unwrap();
            let mut p = PermissionSet::strict_gui();
            p.filesystem.music = Access::Rw;
            let guarded = if start_file {
                fs::write(dots.join("bashrc"), "").unwrap();
                std::os::unix::fs::symlink(dots.join("bashrc"), home.join(".bashrc")).unwrap();
                st(&dots.join("bashrc"))
            } else {
                p.filesystem.custom_read = vec![st(&licensed)];
                st(&licensed)
            };
            let mut ctx = ctx_for(&p, &home);
            ctx.host.xdg_dirs.insert("music".into(), work.clone());
            let cmd = Bubblewrap.build(&ctx).unwrap();
            let a = &cmd.args;
            let (fonts, work, dots) = (st(&home.join(".fonts")), st(&work), st(&dots));
            let first = |seq: &[&str]| at_seq(a, seq).first().copied();
            let ro_bind = first(&["--ro-bind-try", &fonts, &fonts]);
            let write = first(&["--bind-try", &work, &work]).expect("Music bound writable");
            if start_file {
                assert!(ro_bind.is_none(), "{fonts} holds a protected place: {a:?}");
                assert!(
                    cmd.notes.iter().any(|n| n
                        .contains("SAM does not bind ~/.fonts for this app on its own")
                        && n.contains("a place SAM protects")),
                    "{:?}",
                    cmd.notes
                );
            } else {
                let ro_bind = ro_bind.expect("bound read-only");
                assert!(ro_bind < write, "{work} after {fonts}: {a:?}");
            }
            let guard = first(&["--ro-bind-try", &guarded, &guarded]).expect("guarded");
            let pin = first(&["--bind", &dots, &dots]);
            assert!(
                pin.is_some_and(|pin| write < pin && pin < guard),
                "start file {start_file}: {dots} pinned after {work} ({write}) and before the guard ({guard}): {pin:?}: {a:?}"
            );
            assert!(
                first(&["--bind", &fonts, &fonts]).is_none(),
                "{fonts} never pinned: {a:?}"
            );
        }
    }

    /// A font folder opened with the app, or bound writable by SAM itself,
    /// is bound writable after its read-only bind at its own place, so it
    /// is writable and the folders inside it are pinned as everywhere: the
    /// folder above an extra read-only folder inside it
    /// (`~/.fonts/dots/licensed`) cannot be renamed away with that mount.
    /// Counted as read-only on top, `~/.fonts/dots` lost its pin. Each
    /// way of binding it writable is checked on its own, so each one shows
    /// when it is no longer counted.
    #[test]
    fn a_font_folder_opened_or_bound_writable_keeps_the_pins_inside() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let mut lost = Vec::new();
        for way in ["opened", "SAM's bind"] {
            let t = tempfile::tempdir().unwrap();
            let home = fs::canonicalize(t.path()).unwrap().join("home");
            let fonts = home.join(".fonts");
            let dots = fonts.join("dots");
            fs::create_dir_all(dots.join("licensed")).unwrap();
            let shared = home.parent().unwrap().join("shared");
            fs::create_dir_all(&shared).unwrap();
            let mut p = PermissionSet::strict_gui();
            p.filesystem.custom_read = vec![st(&dots.join("licensed"))];
            let mut ctx = ctx_for(&p, &home);
            if way == "opened" {
                ctx.permissions.filesystem.opened_files = Access::Rw;
                ctx.args = vec![st(&fonts)];
                assert_eq!(opened_paths(&ctx), vec![(fonts.clone(), true)]);
            } else {
                ctx.extra_binds = vec![(shared.clone(), fonts.clone(), true)];
            }
            let a = args_of(&ctx);
            let (fonts, dots) = (st(&fonts), st(&dots));
            let first = |seq: &[&str]| at_seq(&a, seq).first().copied();
            first(&["--ro-bind-try", &fonts, &fonts]).expect("bound read-only");
            if way == "opened" {
                first(&["--bind-try", &fonts, &fonts]).expect("opened writable");
            }
            if first(&["--bind", &dots, &dots]).is_none() {
                lost.push(format!("{way}: {dots} not pinned: {a:?}"));
            }
        }
        assert!(lost.is_empty(), "{lost:#?}");
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

    /// Review SB-5: with SAM's helper, the app's own variables (set ones,
    /// its AppImage variables, `$OWD`) are not given to Bubblewrap, whose
    /// first program is the helper, but handed to the helper to set for the
    /// app alone; SAM's own variables stay with Bubblewrap. Without the
    /// helper, Bubblewrap sets them all, as before. Audit L-F16: `$OWD` is
    /// the folder the app starts in.
    #[test]
    fn the_apps_variables_go_to_the_helper_never_to_its_start() {
        let mut ctx = sample_context();
        ctx.permissions
            .environment
            .set
            .insert("LD_PRELOAD".into(), "/opt/app/usr/lib/libx.so".into());
        ctx.owd = "/home/u/private/clientX".into();
        let direct = Bubblewrap.build(&ctx).unwrap();
        assert!(has_seq(
            &direct.args,
            &["--setenv", "LD_PRELOAD", "/opt/app/usr/lib/libx.so"]
        ));
        assert!(direct.exec_env.is_empty());
        ctx.helper = Some(sam_core::sandbox::SandboxHelper {
            binary: "/usr/bin/sam-jail-run".into(),
            spec: "/tmp/spec.json".into(),
        });
        let helped = Bubblewrap.build(&ctx).unwrap();
        for own in ["LD_PRELOAD", "APPDIR", "OWD"] {
            assert!(
                !has_seq(&helped.args, &["--setenv", own]),
                "{own} not for the helper's start"
            );
            assert!(
                helped.exec_env.iter().any(|(k, _)| k == own),
                "{own} for the app"
            );
        }
        assert!(has_seq(
            &helped.args,
            &["--setenv", "SAM_SANDBOX", "bubblewrap"]
        ));
        let owd: Vec<&str> = helped
            .exec_env
            .iter()
            .filter(|(k, _)| k == "OWD")
            .map(|(_, v)| v.as_str())
            .collect();
        let home = ctx.host.home.to_string_lossy();
        assert_eq!(owd, [home.as_ref()], "the folder the app starts in");
        assert!(has_seq(&helped.args, &["--chdir", &home]));
    }

    /// SAM's helper folder /run/sam/bin comes first on the app's PATH only
    /// when there is something in it for the app: the link openers (they
    /// need the desktop bus) and Room service's stand-in for Bubblewrap.
    /// With the bus the app gets the full folder; without the bus but with
    /// Room service only the stand-in's folder; with neither, no folder
    /// and a PATH without it.
    #[test]
    fn the_helper_folder_comes_first_on_path_only_where_it_holds_helpers() {
        const WITH: &str = "/run/sam/bin:/usr/local/bin:/usr/bin:/bin";
        const WITHOUT: &str = "/usr/local/bin:/usr/bin:/bin";
        // The two folders SAM prepares in the app's own runtime folder.
        let run = sample_context().runtime_dir;
        let full = run.join("bin").to_string_lossy().into_owned();
        let rooms_only = run.join("bin-rooms").to_string_lossy().into_owned();
        for bus in [DbusMode::None, DbusMode::Filtered, DbusMode::Full] {
            for rooms in [false, true] {
                let mut ctx = sample_context();
                ctx.permissions.dbus.session.mode = bus;
                ctx.room_socket = rooms.then(|| "/run/user/1000/sam/x/rooms".into());
                let a = args_of(&ctx);
                let case = format!("bus {bus:?}, Room service {rooms}");
                let (folder, path) = match (bus, rooms) {
                    (DbusMode::None, false) => (None, WITHOUT),
                    (DbusMode::None, true) => (Some(rooms_only.as_str()), WITH),
                    _ => (Some(full.as_str()), WITH),
                };
                // PATH is set exactly once, so no later value can win.
                let paths: Vec<&str> = a
                    .windows(3)
                    .filter(|w| w[0] == "--setenv" && w[1] == "PATH")
                    .map(|w| w[2].as_str())
                    .collect();
                assert_eq!(paths, [path], "{case}: PATH");
                let shown: Vec<&str> = a
                    .windows(3)
                    .filter(|w| w[2] == "/run/sam/bin")
                    .map(|w| {
                        assert_eq!(w[0], "--ro-bind-try", "{case}: shown read-only");
                        w[1].as_str()
                    })
                    .collect();
                assert_eq!(shown, folder.into_iter().collect::<Vec<_>>(), "{case}");
            }
        }
    }

    /// The value of the last `--setenv key` in `a`: the one the app sees.
    fn env_in(a: &[String], key: &str) -> Option<String> {
        a.windows(3)
            .rev()
            .find(|w| w[0] == "--setenv" && w[1] == key)
            .map(|w| w[2].clone())
    }

    /// The last way out of a start place, when SAM can neither move nor
    /// rename what an app put there, deletes it: a file, a folder with
    /// everything in it, and a link (never what it points to).
    #[test]
    fn what_cannot_be_moved_aside_is_deleted_whatever_it_is() {
        let t = tempfile::tempdir().unwrap();
        let file = t.path().join("evil.desktop");
        fs::write(&file, "x").unwrap();
        let dir = t.path().join("autostart");
        fs::create_dir_all(dir.join("deep/er")).unwrap();
        fs::write(dir.join("deep/er/evil.desktop"), "x").unwrap();
        let kept = t.path().join("kept");
        fs::create_dir(&kept).unwrap();
        fs::write(kept.join("mine"), "x").unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&kept, &link).unwrap();
        for p in [&file, &dir, &link] {
            assert!(remove_any(p), "{p:?} reported as still there");
            assert!(fs::symlink_metadata(p).is_err(), "{p:?} is still there");
        }
        assert!(
            kept.join("mine").is_file(),
            "the link's target is left alone"
        );
        assert!(remove_any(&t.path().join("never-was")), "nothing there");
    }

    /// A start place that appears with the folder above it (`~/.config`
    /// and `~/.config/autostart` both new) is moved aside once, inside the
    /// folder above, not once more on its own.
    #[test]
    fn a_new_folder_above_start_places_is_moved_aside_once_as_a_whole() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let w = HomeWatch::before(&ctx_for(&full_rw(), &home)).unwrap();
        assert!(w.absent.iter().any(|a| a == ".config/autostart"));
        fs::create_dir_all(home.join(".config/autostart")).unwrap();
        fs::write(home.join(".config/autostart/evil.desktop"), "x").unwrap();
        let aside = t.path().join("aside");
        let m = w.settle(&aside);
        let places: Vec<&str> = m.iter().map(|m| m.place.as_str()).collect();
        assert_eq!(places, [".config"], "{m:?}");
        assert!(aside.join(".config/autostart/evil.desktop").is_file());
        assert!(!home.join(".config").exists());
    }

    /// The watch follows the way a protected link leads inside the home:
    /// a further link on it that the app replaces, or a missing part of it
    /// that the app creates, is moved aside after the start and the link
    /// put back, so the protected name leads where it led before; a launch
    /// alongside another takes over what that one saw (review B2 S3, R51).
    #[test]
    fn the_way_a_protected_link_leads_is_watched() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        fs::create_dir_all(home.join("store/cfg")).unwrap();
        fs::write(home.join("store/cfg/profile"), "echo mine\n").unwrap();
        let link = |to: &str, at: &str| std::os::unix::fs::symlink(to, home.join(at)).unwrap();
        link("cfg/profile", ".profile");
        link("store/cfg", "cfg");
        link(".dotfiles/zshrc", ".zshrc");
        let ctx = ctx_for(&full_rw(), &home);
        let w = HomeWatch::before(&ctx).unwrap();
        let cfg = ("cfg".to_string(), PathBuf::from("store/cfg"));
        assert!(w.links.contains(&cfg), "{w:?}");
        assert!(w.absent.contains(&".dotfiles".to_string()), "{w:?}");
        // Kept on disk, the watch keeps these places.
        let back = HomeWatch::from_lines(w.to_lines().iter().map(String::as_str)).unwrap();
        assert_eq!((&back.links, &back.absent), (&w.links, &w.absent));
        // A launch alongside another takes over what that one saw.
        let other = HomeWatch {
            home: home.clone(),
            absent: vec!["cfg".into()],
            links: vec![(".dotfiles".into(), PathBuf::from("elsewhere"))],
        };
        let w2 = HomeWatch::before_alongside(&ctx, &[other]).unwrap();
        assert!(w2.absent.contains(&"cfg".to_string()), "{w2:?}");
        assert!(
            w2.links
                .contains(&(".dotfiles".to_string(), PathBuf::from("elsewhere"))),
            "{w2:?}"
        );
        // The app replaces the second link and creates the missing part.
        fs::remove_file(home.join("cfg")).unwrap();
        fs::create_dir(home.join("cfg")).unwrap();
        fs::write(home.join("cfg/profile"), "echo pwned\n").unwrap();
        fs::create_dir(home.join(".dotfiles")).unwrap();
        fs::write(home.join(".dotfiles/zshrc"), "echo pwned\n").unwrap();
        let m = w.settle(&t.path().join("aside"));
        assert_eq!(
            fs::read_to_string(home.join(".profile")).unwrap(),
            "echo mine\n"
        );
        assert!(!home.join(".zshrc").exists(), "{m:?}");
        let places: Vec<&str> = m.iter().map(|m| m.place.as_str()).collect();
        assert!(
            places.contains(&"cfg") && places.contains(&".dotfiles"),
            "{m:?}"
        );
    }

    /// A folder on the way to a watched link that the app swaps for a link
    /// of its own is moved aside, also when the link it holds has the same
    /// text; a launch alongside another takes over every place that one
    /// recorded, also those no longer on today's way; and a place only on
    /// the way is never deleted, only moved aside or reported (review of
    /// PR 128).
    #[test]
    fn a_way_turned_into_a_link_is_undone_and_never_by_deleting() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in ["dots", "stow/zsh"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        fs::write(home.join("stow/zsh/zshrc"), "echo mine\n").unwrap();
        let link = |to: &str, at: &Path| std::os::unix::fs::symlink(to, at).unwrap();
        link("dots/zsh/zshrc", &home.join(".zshrc"));
        link("../stow/zsh", &home.join("dots/zsh"));
        let ctx = ctx_for(&full_rw(), &home);
        let w = HomeWatch::before(&ctx).unwrap();
        let zsh = ("dots/zsh".to_string(), PathBuf::from("../stow/zsh"));
        assert!(w.links.contains(&zsh), "{w:?}");
        // The app renames `~/dots`, builds the same link in a folder of
        // its own and puts a link to that folder in the place of `~/dots`.
        fs::rename(home.join("dots"), home.join("dots-old")).unwrap();
        for d in ["p/dots", "p/stow/zsh"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        fs::write(home.join("p/stow/zsh/zshrc"), "echo pwned\n").unwrap();
        link("../stow/zsh", &home.join("p/dots/zsh"));
        link("p/dots", &home.join("dots"));
        let m = w.settle(&t.path().join("aside"));
        assert!(m.iter().any(|m| m.place == "dots"), "{m:?}");
        assert!(
            !fs::read_to_string(home.join(".zshrc")).is_ok_and(|s| s.contains("pwned")),
            "{m:?}"
        );
        // A launch alongside: every place the other one recorded.
        let other = HomeWatch {
            home: home.clone(),
            absent: vec!["gone/way".into()],
            links: vec![("old/link".into(), PathBuf::from("x"))],
        };
        let w2 = HomeWatch::before_alongside(&ctx, &[other]).unwrap();
        assert!(w2.absent.contains(&"gone/way".to_string()), "{w2:?}");
        assert!(
            w2.links
                .contains(&("old/link".to_string(), PathBuf::from("x"))),
            "{w2:?}"
        );
        // A place only on the way that cannot be moved (SAM's folder is a
        // file, the home cannot be changed) is reported, never deleted.
        let locked = fs::canonicalize(t.path()).unwrap().join("locked");
        fs::create_dir_all(&locked).unwrap();
        link(".dotfiles/zprofile", &locked.join(".zprofile"));
        let w3 = HomeWatch::before(&ctx_for(&full_rw(), &locked)).unwrap();
        assert!(w3.absent.contains(&".dotfiles".to_string()), "{w3:?}");
        fs::create_dir(locked.join(".dotfiles")).unwrap();
        fs::write(locked.join(".dotfiles/zprofile"), "echo pwned\n").unwrap();
        let blocked = t.path().join("blocked");
        fs::write(&blocked, "").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
        let m = w3.settle(&blocked.join("aside"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        let it = m.iter().find(|m| m.place == ".dotfiles").unwrap();
        assert_eq!(it.how, Aside::Failed, "{m:?}");
        assert!(locked.join(".dotfiles/zprofile").exists(), "never deleted");
    }

    /// Next to a shown system path, links to the system's data and settings
    /// are shown too (`/usr/share/X11/xkb` → `xkeyboard-config-2`), once;
    /// links to anywhere else are not, and neither are links that stay
    /// inside the path (shown already).
    #[test]
    fn links_beside_a_shown_system_path_bring_only_allowed_targets() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let shown = root.join("shown");
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(shown.join("sub")).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        let link = |to: &Path, at: &Path| std::os::unix::fs::symlink(to, at).unwrap();
        link(Path::new("/etc"), &shown.join("settings"));
        link(Path::new("/etc"), &shown.join("settings-again"));
        link(&elsewhere, &shown.join("out"));
        link(&shown.join("sub"), &shown.join("inner"));
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let ro = |p: &str| ["--ro-bind-try".to_string(), p.into(), p.into()];
        let mut a = Args::default();
        ro_follow(&mut a, &shown);
        assert_eq!(a.v, [ro(&s(&shown)), ro("/etc")].concat());
        // The path itself a link: to an allowed place, or anywhere else.
        link(Path::new("/etc"), &root.join("to-etc"));
        link(&elsewhere, &root.join("to-elsewhere"));
        let mut a = Args::default();
        ro_follow(&mut a, &root.join("to-etc"));
        ro_follow(&mut a, &root.join("to-elsewhere"));
        assert_eq!(
            a.v,
            [
                ro(&s(&root.join("to-etc"))),
                ro("/etc"),
                ro(&s(&root.join("to-elsewhere")))
            ]
            .concat()
        );
    }

    /// A top-level path of the system is copied as it is on the host: a
    /// link stays a link, a real folder is shown read-only, and anything
    /// else (a file, nothing) is left out.
    #[test]
    fn top_level_system_paths_are_copied_as_they_are() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("lib64");
        fs::create_dir(&dir).unwrap();
        let link = t.path().join("lib");
        std::os::unix::fs::symlink("usr/lib", &link).unwrap();
        let file = t.path().join("lib32");
        fs::write(&file, "").unwrap();
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let of = |p: &Path| {
            let mut a = Args::default();
            mirror(&mut a, &s(p));
            a.v
        };
        assert_eq!(of(&dir), ["--ro-bind-try", &s(&dir), &s(&dir)]);
        assert_eq!(of(&link), ["--symlink", "usr/lib", &s(&link)]);
        assert!(of(&file).is_empty(), "a file");
        assert!(of(&t.path().join("libx32")).is_empty(), "nothing there");
    }

    /// An empty argument (the folder the app was started in) and options
    /// are never taken as files to share, even where a file of that name
    /// exists.
    #[test]
    fn empty_arguments_and_options_open_nothing() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap();
        let proj = home.join("proj");
        fs::create_dir(&proj).unwrap();
        fs::write(proj.join("-v"), "").unwrap();
        fs::write(proj.join("notes.txt"), "").unwrap();
        let mut ctx = ctx_for(&PermissionSet::strict_gui(), &home);
        ctx.owd = proj.clone();
        for arg in ["", "-v"] {
            ctx.args = vec![arg.into()];
            assert_eq!(opened_paths(&ctx), [], "{arg:?}");
        }
        // Control: a plain name there is shared.
        ctx.args = vec!["notes.txt".into()];
        assert_eq!(opened_paths(&ctx), [(proj.join("notes.txt"), true)]);
    }

    /// The host's name server settings are shown with the network only:
    /// an app without it sees none of them.
    #[test]
    fn name_server_settings_are_shown_with_the_network_only() {
        for mode in [NetworkMode::None, NetworkMode::Localhost, NetworkMode::Full] {
            let mut ctx = sample_context();
            ctx.permissions.network.mode = mode;
            let a = args_of(&ctx);
            let full = mode == NetworkMode::Full;
            for p in ["/etc/resolv.conf", "/etc/services", "/run/systemd/resolve"] {
                assert_eq!(
                    has_seq(&a, &["--ro-bind-try", p, p]),
                    full,
                    "{p} with network {mode:?}"
                );
            }
        }
    }

    /// The host's theme settings in the home are shown, read-only, only
    /// when asked for and the home is not shown anyway (and only where
    /// they are there, with no link on their way in the home).
    #[test]
    fn host_themes_are_shown_only_when_asked_for_without_the_home() {
        let t = scratch();
        let dir = fs::canonicalize(t.path()).unwrap().join("home");
        fs::create_dir_all(dir.join(".config/gtk-3.0")).unwrap();
        fs::create_dir_all(dir.join(".icons")).unwrap();
        fs::write(dir.join(".config/kdeglobals"), "").unwrap();
        for (themes, home, shown) in [
            (false, false, false),
            (true, false, true),
            (true, true, false),
            (false, true, false),
        ] {
            let mut ctx = ctx_for(&PermissionSet::strict_gui(), &dir);
            ctx.permissions.advanced.host_themes = themes;
            ctx.permissions.filesystem.home = home;
            ctx.permissions.filesystem.home_access = Access::Rw;
            let a = args_of(&ctx);
            for t in [".config/gtk-3.0", ".config/kdeglobals", ".icons"] {
                let p = dir.join(t).to_string_lossy().into_owned();
                assert_eq!(
                    has_seq(&a, &["--ro-bind-try", &p, &p]),
                    shown,
                    "{t}: themes {themes}, home {home}"
                );
                if !shown {
                    assert!(!a.contains(&p), "{t} is not named at all: {a:?}");
                }
            }
        }
    }

    /// The file chooser's bookmarks and servers in the theme folders are
    /// hidden (an empty read-only file in their place) only where SAM shows
    /// the theme settings on its own, with no home shown. Without the
    /// theme settings, an empty read-only file there kept the app from
    /// saving bookmarks of its own and told it that the host has such a
    /// file. Built in a real home, where the files exist.
    #[test]
    fn theme_private_files_are_hidden_only_when_the_theme_settings_are_shown() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        fs::create_dir_all(home.join(".config/gtk-3.0")).unwrap();
        let files = [".config/gtk-3.0/bookmarks", ".config/gtk-3.0/servers"];
        for f in files {
            fs::write(home.join(f), "file:///x\n").unwrap();
        }
        let st = |p: &Path| p.to_string_lossy().into_owned();
        for (themes, whole_home) in [(false, false), (true, false), (true, true), (false, true)] {
            let mut p = PermissionSet::strict_gui();
            p.advanced.host_themes = themes;
            p.filesystem.home = whole_home;
            p.filesystem.home_access = Access::Ro;
            let a = args_of(&ctx_for(&p, &home));
            for f in files {
                let at = st(&home.join(f));
                assert_eq!(
                    has_seq(&a, &["--ro-bind", "/dev/null", &at]),
                    themes && !whole_home,
                    "{f}: themes {themes}, home {whole_home}: {a:?}"
                );
                if !themes && !whole_home {
                    assert!(!a.contains(&at), "{f} is not named at all: {a:?}");
                }
            }
        }
    }

    /// A bundled library is replaced only by a plain file of the system's
    /// own (the copy found is checked by
    /// `system_copies_replace_only_bundled_libraries_by_plain_name`):
    /// never by a file elsewhere, nor by a folder.
    #[test]
    fn only_a_system_file_replaces_a_bundled_library() {
        let t = tempfile::tempdir().unwrap();
        let elsewhere = t.path().join("libc.so.6");
        fs::write(&elsewhere, "").unwrap();
        assert!(!system_copy_ok(&elsewhere), "a file outside /usr and /lib");
        assert!(!system_copy_ok(Path::new("/usr/lib")), "a folder");
        assert!(!system_copy_ok(Path::new("/usr/lib/no-such-lib.so.1")));
    }

    /// What SAM says about Bubblewrap names what is wrong, and only that.
    #[test]
    fn the_bubblewrap_status_says_what_is_missing_and_nothing_else() {
        let ok = sample_context().host;
        let s = Bubblewrap.status(&ok);
        assert!(s.installed && s.usable && s.notes.is_empty(), "{s:?}");

        let mut none = ok.clone();
        none.tools.bwrap = None;
        let s = Bubblewrap.status(&none);
        let hint =
            sam_core::i18n::tr("Bubblewrap is not installed. Install the 'bubblewrap' package.");
        assert!(!s.installed && !s.usable);
        assert_eq!(s.notes, [hint]);

        let mut closed = ok.clone();
        closed.userns.max_user_namespaces = Some(0);
        let s = Bubblewrap.status(&closed);
        assert!(s.installed && !s.usable);
        assert_eq!(s.notes, [closed.userns.explain()]);
    }

    /// Without the whole system (`host_runtime` Minimal), the shared data
    /// of sound and of D-Bus is shown with their permissions, and only
    /// then; the sound settings in /etc in any case. Either sound
    /// permission is enough.
    #[test]
    fn sound_and_bus_data_come_with_their_permissions() {
        for (sound, raw, bus) in [
            (false, false, DbusMode::None),
            (true, false, DbusMode::None),
            (false, true, DbusMode::None),
            (false, false, DbusMode::Filtered),
        ] {
            let mut ctx = sample_context();
            let p = &mut ctx.permissions;
            p.advanced.host_runtime = HostRuntime::Minimal;
            p.audio.enabled = sound;
            p.audio.alsa_raw = raw;
            p.dbus.session.mode = bus;
            let a = args_of(&ctx);
            let case = format!("sound {sound}, raw {raw}, bus {bus:?}");
            let ro = |p: &str| has_seq(&a, &["--ro-bind-try", p, p]);
            assert_eq!(ro("/usr/share/alsa"), sound || raw, "{case}");
            assert_eq!(ro("/usr/share/pipewire"), sound || raw, "{case}");
            assert_eq!(ro("/etc/asound.conf"), sound || raw, "{case}");
            assert_eq!(ro("/etc/pulse"), sound || raw, "{case}");
            assert_eq!(ro("/usr/share/dbus-1"), bus != DbusMode::None, "{case}");
        }
    }

    /// The device trees in /sys and udev's device data are shown with any
    /// one device permission that needs them, and never without one.
    #[test]
    fn device_information_comes_with_each_device_permission() {
        type Grant = fn(&mut DevicePerms);
        let grants: [(&str, Grant); 6] = [
            ("none", |_| {}),
            ("gpu", |d| d.gpu = true),
            ("usb", |d| d.usb = true),
            ("input", |d| d.input = true),
            ("gamepads", |d| d.gamepads = true),
            ("webcam", |d| d.webcam = true),
        ];
        for (name, grant) in grants {
            let mut ctx = sample_context();
            grant(&mut ctx.permissions.devices);
            let a = args_of(&ctx);
            for p in [
                "/sys/dev",
                "/sys/devices",
                "/sys/bus",
                "/sys/class",
                "/run/udev/data",
            ] {
                assert_eq!(
                    has_seq(&a, &["--ro-bind-try", p, p]),
                    name != "none",
                    "{p} with {name}"
                );
            }
        }
    }

    /// The X11 cookie is passed on only when the host has one and SAM
    /// wrote the sandbox's copy: a cookie bind of a missing file stops the
    /// start, and a copy left from before is not the host's.
    #[test]
    fn the_x11_cookie_is_passed_on_only_when_both_are_there() {
        let t = tempfile::tempdir().unwrap();
        for (host_cookie, written) in [(true, false), (false, true), (true, true)] {
            let run = t.path().join(format!("{host_cookie}-{written}"));
            fs::create_dir_all(&run).unwrap();
            if written {
                fs::write(run.join("Xauthority"), "cookie").unwrap();
            }
            let mut ctx = sample_context();
            ctx.permissions.display.x11 = true;
            ctx.runtime_dir = run.clone();
            if !host_cookie {
                ctx.host.sockets.xauthority = None;
            }
            let a = args_of(&ctx);
            let both = host_cookie && written;
            let cookie = run.join("Xauthority").to_string_lossy().into_owned();
            assert_eq!(
                has_seq(&a, &["--ro-bind", &cookie, "/run/user/1000/Xauthority"]),
                both,
                "host cookie {host_cookie}, written {written}"
            );
            assert_eq!(
                env_in(&a, "XAUTHORITY").is_some(),
                both,
                "host cookie {host_cookie}, written {written}"
            );
        }
    }

    /// The display kind and the toolkits' backends follow what the app may
    /// use and what the host has: never a display the sandbox does not
    /// show, and none at all without a display.
    #[test]
    fn display_variables_name_only_displays_the_sandbox_shows() {
        // (Wayland allowed, X11 allowed, host has Wayland, host has X11)
        // → (XDG_SESSION_TYPE, QT_QPA_PLATFORM, GDK_BACKEND = SDL_VIDEODRIVER)
        type Want = (&'static str, Option<&'static str>, Option<&'static str>);
        let cases: [((bool, bool, bool, bool), Want); 7] = [
            (
                (true, true, true, true),
                ("wayland", None, Some("wayland,x11")),
            ),
            (
                (true, false, true, true),
                ("wayland", Some("wayland"), Some("wayland")),
            ),
            ((false, true, true, true), ("x11", Some("xcb"), Some("x11"))),
            ((false, false, true, true), ("tty", Some("offscreen"), None)),
            ((true, true, false, true), ("x11", Some("xcb"), Some("x11"))),
            (
                (true, true, true, false),
                ("wayland", Some("wayland"), Some("wayland")),
            ),
            ((true, true, false, false), ("tty", Some("offscreen"), None)),
        ];
        for ((wl, x, host_wl, host_x), (session, qt, gdk)) in cases {
            let mut ctx = sample_context();
            ctx.permissions.display.wayland = wl;
            ctx.permissions.display.x11 = x;
            if !host_wl {
                ctx.host.sockets.wayland = None;
            }
            if !host_x {
                ctx.host.sockets.x11 = None;
            }
            let a = args_of(&ctx);
            let case = format!("allowed {wl}/{x}, host {host_wl}/{host_x}");
            assert_eq!(
                env_in(&a, "XDG_SESSION_TYPE").as_deref(),
                Some(session),
                "{case}"
            );
            assert_eq!(env_in(&a, "QT_QPA_PLATFORM").as_deref(), qt, "{case}");
            assert_eq!(env_in(&a, "GDK_BACKEND").as_deref(), gdk, "{case}");
            assert_eq!(env_in(&a, "SDL_VIDEODRIVER").as_deref(), gdk, "{case}");
        }
    }

    /// The notes that a device or input method needs a bus come only when
    /// it is asked for and the bus is not granted.
    #[test]
    fn notes_about_a_missing_bus_come_only_when_it_is_missing() {
        let bt = sam_core::i18n::tr("Bluetooth needs the system D-Bus; not granted");
        let im = sam_core::i18n::tr("Input method needs the session D-Bus; not granted");
        for asked in [false, true] {
            for bus in [DbusMode::None, DbusMode::Filtered] {
                let mut ctx = sample_context();
                ctx.permissions.devices.bluetooth = asked;
                ctx.permissions.dbus.system.mode = bus;
                let notes = Bubblewrap.build(&ctx).unwrap().notes;
                let want = asked && bus == DbusMode::None;
                assert_eq!(notes.contains(&bt), want, "Bluetooth {asked}, bus {bus:?}");

                let mut ctx = sample_context();
                ctx.permissions.integrations.input_method = asked;
                ctx.permissions.dbus.session.mode = bus;
                let c = Bubblewrap.build(&ctx).unwrap();
                assert_eq!(
                    c.notes.contains(&im),
                    want,
                    "input method {asked}, bus {bus:?}"
                );
                assert_eq!(
                    env_in(&c.args, "IBUS_USE_PORTAL").is_some(),
                    asked,
                    "input method {asked}"
                );
            }
        }
    }

    /// An app started in a folder it reaches only through a link (`~/link`
    /// to a granted `/data/proj`) starts there, so relative names work.
    #[test]
    fn the_start_folder_reached_through_a_link_is_kept() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let real = root.join("proj");
        fs::create_dir(&real).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut ctx = sample_context();
        ctx.permissions.filesystem.custom_read = vec![real.to_string_lossy().into_owned()];
        ctx.owd = link.clone();
        let a = args_of(&ctx);
        assert!(has_seq(&a, &["--chdir", &link.to_string_lossy()]), "{a:?}");
        // Control: a folder not shown at all falls back to the home.
        ctx.owd = root.clone();
        assert!(has_seq(&args_of(&ctx), &["--chdir", "/home/tester"]));
    }

    /// The sandbox's X11 display number is never the host's: 99, or 100
    /// when the host's display is :99 itself.
    #[test]
    fn the_sandbox_display_number_is_never_the_hosts() {
        let with = |d: Option<&str>| sam_core::host::Sockets {
            x11_display: d.map(String::from),
            ..Default::default()
        };
        assert_eq!(sandbox_x11_display(&with(Some(":99"))), 100);
        assert_eq!(sandbox_x11_display(&with(Some(":99.0"))), 100);
        assert_eq!(sandbox_x11_display(&with(Some(":0"))), 99);
        assert_eq!(sandbox_x11_display(&with(None)), 99);
    }

    /// The cookie copy keeps every record for the host's display, wherever
    /// it stands in the file, and an empty file gives an empty copy.
    #[test]
    fn every_cookie_for_the_display_is_copied() {
        assert!(rewrite_xauthority(&[], "0", "99").is_empty());
        let rec = |num: &str, cookie: &[u8]| {
            let mut r = vec![0x01, 0x00];
            for f in [
                b"host".as_slice(),
                num.as_bytes(),
                b"MIT-MAGIC-COOKIE-1",
                cookie,
            ] {
                r.extend_from_slice(&(f.len() as u16).to_be_bytes());
                r.extend_from_slice(f);
            }
            r
        };
        let data = [rec("1", b"a"), rec("2", b"b"), rec("0", b"c")].concat();
        assert_eq!(rewrite_xauthority(&data, "0", "99"), rec("99", b"c"));
        let data = [
            rec("0", b"a"),
            rec("1", b"b"),
            rec("2", b"c"),
            rec("0", b"d"),
        ]
        .concat();
        assert_eq!(
            rewrite_xauthority(&data, "0", "99"),
            [rec("99", b"a"), rec("99", b"d")].concat()
        );
    }

    /// Device numbers are split as the kernel numbers them: udev's data
    /// for a game controller is found under `c<major>:<minor>`.
    #[test]
    fn device_numbers_split_into_major_and_minor() {
        use std::os::unix::fs::MetadataExt;
        // Fixed by the kernel's list of devices: /dev/null is 1:3, /dev/tty 5:0.
        for (dev, major, minor) in [("/dev/null", 1, 3), ("/dev/tty", 5, 0)] {
            let rdev = fs::metadata(dev).unwrap().rdev();
            assert_eq!(
                (libc_major(rdev), libc_minor(rdev)),
                (major, minor),
                "{dev}"
            );
        }
        // An input event node 13:300 and a large major (259:5), encoded as
        // glibc's makedev does: minor bits 0-7 and 20-43, major bits 8-19
        // and 44-63.
        assert_eq!(
            (libc_major(0x0010_0d2c), libc_minor(0x0010_0d2c)),
            (13, 300)
        );
        assert_eq!((libc_major(0x0001_0305), libc_minor(0x0001_0305)), (259, 5));
    }

    /// A hidden credential is never shown again by a bind after it: with
    /// `~/.git-credentials` a link into `~/.config/git` (a protected place,
    /// bound read-only onto itself), the protected place came after the
    /// hiding and showed the real file (mutation run 2026-11-23). No hidden
    /// place has a bind of itself or of a folder above it later on, with the
    /// home writable or read-only.
    #[test]
    fn no_later_bind_shows_a_hidden_credential_again() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap();
        fs::create_dir_all(home.join(".config/git")).unwrap();
        fs::write(home.join(".config/git/credentials"), "secret").unwrap();
        std::os::unix::fs::symlink(
            home.join(".config/git/credentials"),
            home.join(".git-credentials"),
        )
        .unwrap();
        fs::write(home.join(".netrc"), "secret").unwrap();
        fs::create_dir(home.join(".ssh")).unwrap();
        for access in [Access::Rw, Access::Ro] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            p.filesystem.home_access = access;
            let a = args_of(&ctx_for(&p, &home));
            let s = |n: &str| home.join(n).to_string_lossy().into_owned();
            let hidden: Vec<(usize, PathBuf)> = a
                .windows(3)
                .enumerate()
                .filter_map(|(i, w)| match (w[0].as_str(), w[1].as_str()) {
                    ("--ro-bind", "/dev/null") => Some((i, PathBuf::from(&w[2]))),
                    ("--tmpfs", _) => Some((i, PathBuf::from(&w[1]))),
                    _ => None,
                })
                .filter(|(_, p)| p.starts_with(&home) && *p != home)
                .collect();
            for want in [".config/git/credentials", ".netrc", ".ssh"] {
                assert!(
                    hidden.iter().any(|(_, p)| p == Path::new(&s(want))),
                    "{want} hidden, home {access:?}: {a:?}"
                );
            }
            for (i, place) in &hidden {
                let later = a[i + 1..].windows(3).find(|w| {
                    w[0].contains("bind") && w[1] != "/dev/null" && place.starts_with(&w[2])
                });
                assert!(
                    later.is_none(),
                    "{place:?} is shown again by {later:?}, home {access:?}"
                );
            }
        }
    }

    /// A credential place that is neither a file nor a folder is hidden
    /// too: `~/.netrc` as a named pipe a password manager feeds (so the
    /// secret never lies on disk) or a socket was left showing, and the app
    /// could read the secret from it.
    #[test]
    fn credential_places_of_any_kind_are_hidden() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(home.join(".netrc")).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        let a = args_of(&ctx_for(&p, &home));
        let netrc = home.join(".netrc").to_string_lossy().into_owned();
        assert!(has_seq(&a, &["--ro-bind", "/dev/null", &netrc]), "{a:?}");
    }

    /// The extra folders never follow a link the app could have planted out
    /// of what it is shown, nor a link to where programs outside the
    /// sandbox listen: with the whole home writable and `~/.fonts` a link
    /// to `/tmp/tmux-…`, the start bound the host's folder over its own
    /// `/tmp`. The places SAM shows on its own (`~/.fonts`,
    /// `~/.local/share/fonts`, `~/.config/fontconfig`, the theme files)
    /// follow no link at all, wherever it leads and whoever made it: to the
    /// sockets, to the keys, to a folder outside the home or inside it.
    /// The start says why (for a link to the sockets that danger, also
    /// where the app may have planted it), and the views and the list of
    /// extra folders agree. With the whole home writable, the place a link
    /// in the home leads to stays read-only where the home shows it, and
    /// the start says so.
    #[test]
    fn fonts_themes_and_extra_folders_never_follow_a_planted_link() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        let outside = base.join("outside");
        for d in [
            home.join(".config"),
            home.join(".local/share"),
            home.join(".ssh"),
            home.join("myfonts"),
            home.join("shared"),
            outside.clone(),
        ] {
            fs::create_dir_all(d).unwrap();
        }
        let sockets = tempfile::Builder::new()
            .prefix("tmux-")
            .tempdir_in("/tmp")
            .unwrap();
        let sock = sockets.path().to_path_buf();
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let link = |to: &Path, at: &Path| {
            let _ = fs::remove_file(at);
            std::os::unix::fs::symlink(to, at).unwrap();
        };
        let said = |notes: &[String], place: &str, why: &str| {
            assert!(
                notes.iter().any(|n| n.contains(place) && n.contains(why)),
                "{place}: {notes:?}"
            );
        };
        // The whole home writable: every place planted.
        link(&sock, &home.join(".fonts"));
        link(&sock, &home.join(".config/fontconfig"));
        link(&outside, &home.join(".local/share/fonts"));
        link(&sock, &home.join("shared/ro"));
        link(&outside, &home.join("shared/rw"));
        let mut p = full_rw();
        p.filesystem.custom_read = vec![st(&home.join("shared/ro"))];
        p.filesystem.custom_write = vec![st(&home.join("shared/rw"))];
        let ctx = ctx_for(&p, &home);
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(
            !cmd.args.iter().any(|a| a.starts_with(&st(&sock))),
            "{:?}",
            cmd.args
        );
        assert!(
            !cmd.args.iter().any(|a| *a == st(&outside)),
            "{:?}",
            cmd.args
        );
        // A planted link to the sockets gets the note that names them,
        // with no way out; one to a folder the app is not shown, the note
        // for a planted link.
        let listen = "where programs outside the sandbox listen";
        let sock_at = format!("(a link to {}, {listen})", sock.display());
        for (place, why) in [
            ("~/.fonts".to_string(), sock_at.as_str()),
            ("~/.config/fontconfig".to_string(), sock_at.as_str()),
            (
                "~/.local/share/fonts".to_string(),
                &*format!("~/.local/share/fonts (a link to {})", outside.display()),
            ),
            (st(&home.join("shared/ro")), listen),
            (st(&home.join("shared/rw")), "may have made that link"),
        ] {
            said(&cmd.notes, &place, why);
            if why.contains(listen) {
                assert!(
                    !cmd.notes
                        .iter()
                        .any(|n| n.contains(&place) && n.contains("may have made that link")),
                    "{place}: {:?}",
                    cmd.notes
                );
            }
        }
        assert!(!Views::of(&ctx).visible(&sock.join("x")));
        assert!(!Views::of(&ctx).visible(&outside.join("x")));
        assert!(shown_extra_folders(&ctx).is_empty());

        // The theme files without the whole home: a writable `~/.config`
        // holds the planted link.
        let mut p = PermissionSet::strict_gui();
        p.advanced.host_themes = true;
        p.filesystem.custom_write = vec![st(&home.join(".config"))];
        link(&outside, &home.join(".config/gtk-3.0"));
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        assert!(
            !cmd.args.iter().any(|a| *a == st(&outside)),
            "{:?}",
            cmd.args
        );
        said(
            &cmd.notes,
            &format!("~/.config/gtk-3.0 (a link to {})", outside.display()),
            "SAM does not follow such a link",
        );

        // A private home: the app cannot change the home, yet a link made
        // there by someone else is not followed: to the sockets, to the
        // keys, or to an ordinary folder.
        let private = PermissionSet::strict_gui();
        let fonts = home.join(".fonts");
        let bound = |ctx: &LaunchContext| {
            let a = args_of(ctx);
            has_seq(&a, &["--ro-bind-try", &st(&fonts), &st(&fonts)])
        };
        link(&sock, &fonts);
        let cmd = Bubblewrap.build(&ctx_for(&private, &home)).unwrap();
        assert!(!bound(&ctx_for(&private, &home)), "{:?}", cmd.args);
        said(&cmd.notes, "~/.fonts", &sock_at);
        link(&home.join(".ssh"), &fonts);
        let cmd = Bubblewrap.build(&ctx_for(&private, &home)).unwrap();
        assert!(!bound(&ctx_for(&private, &home)), "{:?}", cmd.args);
        said(
            &cmd.notes,
            "~/.fonts (a link to ~/.ssh)",
            "SAM does not follow",
        );
        link(&outside, &fonts);
        let cmd = Bubblewrap.build(&ctx_for(&private, &home)).unwrap();
        assert!(!bound(&ctx_for(&private, &home)), "{:?}", cmd.args);
        said(
            &cmd.notes,
            &format!("~/.fonts (a link to {})", outside.display()),
            "If you made the link yourself, keeping the real files at that place lets SAM show them.",
        );
        // An extra folder named by its link to the sockets, in a private
        // home: left out, the start says why.
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_read = vec![st(&home.join("shared/ro"))];
        let ctx = ctx_for(&p, &home);
        let cmd = Bubblewrap.build(&ctx).unwrap();
        assert!(
            !cmd.args.iter().any(|a| a.starts_with(&st(&sock))),
            "{:?}",
            cmd.args
        );
        said(
            &cmd.notes,
            &st(&home.join("shared/ro")),
            "where programs outside the sandbox listen",
        );
        assert!(!Views::of(&ctx).visible(&sock));

        // With the whole home writable, a link that stays in the home is
        // not bound at `~/.fonts`; the place it leads to stays read-only
        // where the home shows it, and the note says so, with no advice:
        // the home shows the place anyway.
        link(&home.join("myfonts"), &fonts);
        let ctx = ctx_for(&full_rw(), &home);
        let cmd = Bubblewrap.build(&ctx).unwrap();
        let mine = st(&home.join("myfonts"));
        assert!(
            has_seq(&cmd.args, &["--ro-bind-try", &mine, &mine]),
            "{:?}",
            cmd.args
        );
        assert!(
            !has_seq(&cmd.args, &["--ro-bind-try", &st(&fonts), &st(&fonts)]),
            "{:?}",
            cmd.args
        );
        let note = link_note(&cmd.notes, ".fonts").expect("the note names ~/.fonts");
        assert!(
            note.contains("~/.fonts (a link to ~/myfonts)")
                && note.contains("SAM keeps ~/myfonts read-only")
                && !note.contains("If you made the link yourself"),
            "{note}"
        );
    }
    /// GNU Stow and similar tools keep the font and theme settings as
    /// links (`~/.config/fontconfig` a relative link to
    /// `../dotfiles/fontconfig`, `~/.config/gtk-3.0` an absolute one), or
    /// fold a whole `~/.config` into one link. SAM binds none of them on
    /// its own, nor where they lead, and says so in one note that names
    /// each link and where it leads: a folded `~/.config` once, with only
    /// the places behind it that exist, and a link that leads nowhere as
    /// it says. Where a writable grant shows the place such a link leads
    /// to, that place stays read-only there.
    #[test]
    fn a_stow_style_link_binds_no_font_or_theme_place_and_says_so_once() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        for d in ["dotfiles/fontconfig", "dotfiles/gtk-3.0", ".config"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink("../dotfiles/fontconfig", home.join(".config/fontconfig"))
            .unwrap();
        std::os::unix::fs::symlink(home.join("dotfiles/gtk-3.0"), home.join(".config/gtk-3.0"))
            .unwrap();
        let mut p = PermissionSet::strict_gui();
        p.advanced.host_themes = true;
        let linked = |cmd: &SandboxCommand| -> Vec<String> {
            cmd.notes
                .iter()
                .filter(|n| n.contains("SAM does not follow such a link"))
                .cloned()
                .collect()
        };
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        for at in [
            ".config/fontconfig",
            ".config/gtk-3.0",
            "dotfiles/fontconfig",
            "dotfiles/gtk-3.0",
        ] {
            let at = st(&home.join(at));
            assert!(
                !cmd.args.iter().any(|a| a.starts_with(&at)),
                "{at} never bound: {:?}",
                cmd.args
            );
        }
        let notes = linked(&cmd);
        assert_eq!(notes.len(), 1, "{:?}", cmd.notes);
        assert!(
            notes[0].contains("~/.config/fontconfig (a link to ~/dotfiles/fontconfig); ~/.config/gtk-3.0 (a link to ~/dotfiles/gtk-3.0)")
                && notes[0].contains("If you made the link yourself"),
            "{}",
            notes[0]
        );
        // `~/.config` folded into one link: named once, with the places
        // behind it that exist.
        fs::remove_file(home.join(".config/fontconfig")).unwrap();
        fs::remove_file(home.join(".config/gtk-3.0")).unwrap();
        fs::remove_dir(home.join(".config")).unwrap();
        fs::create_dir_all(home.join("dotfiles/config/fontconfig")).unwrap();
        std::os::unix::fs::symlink("dotfiles/config", home.join(".config")).unwrap();
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        let notes = linked(&cmd);
        assert_eq!(notes.len(), 1, "{:?}", cmd.notes);
        assert!(
            notes[0].contains(
                "SAM does not bind ~/.config/fontconfig (behind ~/.config, a link to ~/dotfiles/config) for this app"
            ) && notes[0].matches("~/.config").count() == 2,
            "{}",
            notes[0]
        );
        let behind = st(&home.join("dotfiles/config/fontconfig"));
        assert!(
            !cmd.args.contains(&behind),
            "{behind} never bound: {:?}",
            cmd.args
        );
        // A `~/.fonts` that leads nowhere now (a second disk not mounted).
        let gone = base.join("disk/fonts");
        std::os::unix::fs::symlink(&gone, home.join(".fonts")).unwrap();
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        let notes = linked(&cmd);
        assert_eq!(notes.len(), 1, "{:?}", cmd.notes);
        assert!(
            notes[0].starts_with(&format!(
                "SAM does not bind ~/.fonts (a link to {}, which leads nowhere now); ~/.config/fontconfig",
                gone.display()
            )),
            "{}",
            notes[0]
        );
        // Where a writable grant shows the place such a link leads to,
        // that place stays read-only there, strictly inside the grant: an
        // extra writable `~/.config` you name through its link (bound at
        // `~/dotfiles/config`), and the whole home writable when it is
        // kept behind a link and `~/.config` names the home's real place
        // (`/data/u/dots/config`), where the app reaches it under the
        // home's name.
        let mut q = PermissionSet::strict_gui();
        q.filesystem.custom_write = vec![st(&home.join(".config"))];
        let cmd = Bubblewrap.build(&ctx_for(&q, &home)).unwrap();
        let grant = st(&home.join("dotfiles/config"));
        let write = at_seq(&cmd.args, &["--bind-try", &grant, &grant]);
        let ro = at_seq(&cmd.args, &["--ro-bind-try", &behind, &behind]);
        assert!(
            !write.is_empty() && ro.last() > write.last(),
            "{behind} read-only after {grant}: {:?}",
            cmd.args
        );
        assert!(
            linked(&cmd)[0].contains("SAM keeps ~/dotfiles/config/fontconfig read-only"),
            "{:?}",
            cmd.notes
        );
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let (real, named) = (base.join("data/u"), base.join("home/u"));
        fs::create_dir_all(real.join("dots/config/fontconfig")).unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(real.join("dots/config"), real.join(".config")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        let cmd = Bubblewrap.build(&ctx_for(&full_rw(), &named)).unwrap();
        let at = st(&named.join("dots/config/fontconfig"));
        assert!(
            has_seq(&cmd.args, &["--ro-bind-try", &at, &at]),
            "{at} read-only: {:?}",
            cmd.args
        );
        let beside = st(&real.join("dots/config/fontconfig"));
        assert!(!cmd.args.contains(&beside), "{:?}", cmd.args);
    }

    /// A home kept behind a link (`/home/u` a link to `/data/u`, as
    /// Fedora Atomic's `/home` a link to `/var/home`) keeps its fonts: the
    /// link that holds the home is not one below it, so SAM binds the real
    /// font folders read-only under the home's name, in a private home and
    /// with the whole home, and says nothing about links.
    #[test]
    fn a_home_kept_behind_a_link_keeps_its_fonts() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        let places = [".fonts", ".local/share/fonts", ".config/fontconfig"];
        for d in places {
            fs::create_dir_all(real.join(d)).unwrap();
        }
        fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        for p in [PermissionSet::strict_gui(), full_rw()] {
            let cmd = Bubblewrap.build(&ctx_for(&p, &named)).unwrap();
            for rel in places {
                let at = st(&named.join(rel));
                assert!(
                    has_seq(&cmd.args, &["--ro-bind-try", &at, &at]),
                    "home {}: ~/{rel} bound read-only: {:?}",
                    p.filesystem.home,
                    cmd.args
                );
                assert!(!own_note(&cmd.notes, rel), "{:?}", cmd.notes);
            }
        }
    }

    /// A link at a guarded name never knocks out the read-only bind of the
    /// fonts settings where a grant shows them: in a private home with an
    /// extra writable `~/.config`, `~/.config/vivaldi` made a link to
    /// `~/.config/fontconfig`; in a private home `~/.aws` made a link to
    /// the home (a check of where guarded links lead, at or around the
    /// font places, left them all out); with the whole home writable, the
    /// same. And with the home kept behind a link (`/home/u` a link to
    /// `/data/u`), an extra writable `~/.config` is recorded at its real
    /// place `/data/u/.config`: the fonts settings are bound read-only
    /// there too, where that grant shows them (bound at their name only,
    /// they stayed writable there), with or without the planted link; at
    /// their name, which the private home shows anew, only without it.
    #[test]
    fn a_protected_link_never_knocks_out_the_read_only_font_settings() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let places = [".fonts", ".local/share/fonts", ".config/fontconfig"];
        // (a) The extra writable `~/.config` in a private home.
        let t = scratch();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in places {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(
            home.join(".config/fontconfig"),
            home.join(".config/vivaldi"),
        )
        .unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.hidden_files = true;
        p.filesystem.custom_write = vec![st(&home.join(".config"))];
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        let (config, at) = (
            st(&home.join(".config")),
            st(&home.join(".config/fontconfig")),
        );
        let write = at_seq(&cmd.args, &["--bind-try", &config, &config]);
        let ro = at_seq(&cmd.args, &["--ro-bind-try", &at, &at]);
        assert!(
            !write.is_empty() && ro.last() > write.last(),
            "{:?}",
            cmd.args
        );
        assert!(
            !own_note(&cmd.notes, ".config/fontconfig"),
            "{:?}",
            cmd.notes
        );
        fs::remove_file(home.join(".config/vivaldi")).unwrap();
        // (b), (c) `~/.aws` a link to the home, private and whole home.
        std::os::unix::fs::symlink(&home, home.join(".aws")).unwrap();
        let mut private = PermissionSet::strict_gui();
        private.filesystem.hidden_files = true;
        let mut whole = full_rw();
        whole.filesystem.hidden_files = true;
        for p in [private, whole] {
            let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
            for rel in places {
                let at = st(&home.join(rel));
                assert!(
                    has_seq(&cmd.args, &["--ro-bind-try", &at, &at]),
                    "home {}: ~/{rel}: {:?}",
                    p.filesystem.home,
                    cmd.args
                );
                assert!(!own_note(&cmd.notes, rel), "{:?}", cmd.notes);
            }
        }
        // (d) The home kept behind a link.
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        fs::create_dir_all(real.join(".config/fontconfig")).unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.hidden_files = true;
        p.filesystem.custom_write = vec![st(&named.join(".config"))];
        for planted in [false, true] {
            if planted {
                std::os::unix::fs::symlink(
                    named.join(".config/fontconfig"),
                    real.join(".config/vivaldi"),
                )
                .unwrap();
            }
            let cmd = Bubblewrap.build(&ctx_for(&p, &named)).unwrap();
            let config = st(&real.join(".config"));
            let write = at_seq(&cmd.args, &["--bind-try", &config, &config]);
            assert!(!write.is_empty(), "{:?}", cmd.args);
            let at = st(&real.join(".config/fontconfig"));
            let ro = at_seq(&cmd.args, &["--ro-bind-try", &at, &at]);
            assert!(
                ro.last() > write.last(),
                "planted {planted}: {at} bound read-only after {config}: {:?}",
                cmd.args
            );
            // At the home's name, in the private home, the bind is one of
            // its own that shows the place anew: only where no guarded
            // link leads into it, and the start says why.
            let at = st(&named.join(".config/fontconfig"));
            let ro = at_seq(&cmd.args, &["--ro-bind-try", &at, &at]);
            assert_eq!(
                ro.is_empty(),
                planted,
                "planted {planted}: {at}: {:?}",
                cmd.args
            );
            assert!(
                planted || ro.last() > write.last(),
                "{at} bound read-only after {config}: {:?}",
                cmd.args
            );
            assert_eq!(
                own_note(&cmd.notes, ".config/fontconfig"),
                planted,
                "{:?}",
                cmd.notes
            );
        }
    }

    /// A grant that shows a folder above a home kept behind a link (an
    /// extra read-only folder holding `/home/u`, a link to `/data/u`)
    /// shows the fonts only through that link, which leads out of what the
    /// sandbox shows: SAM binds no font place there, neither at the
    /// home's real place beside the grants nor through the link, which
    /// Bubblewrap refuses (as with `~/.config` a link, SB-6), and the start
    /// is built.
    #[test]
    fn a_grant_above_a_home_kept_behind_a_link_binds_no_font_place_beside_it() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        fs::create_dir_all(real.join(".fonts")).unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_read = vec![st(&base.join("home"))];
        let cmd = Bubblewrap.build(&ctx_for(&p, &named)).unwrap();
        for at in [real.join(".fonts"), named.join(".fonts")] {
            let at = st(&at);
            assert!(!cmd.args.contains(&at), "{at} not bound: {:?}", cmd.args);
        }
        assert!(!own_note(&cmd.notes, ".fonts"), "{:?}", cmd.notes);
    }

    /// With the home kept behind a link (`/home/u` a link to `/data/u`), a
    /// private home and an extra `~/.config`, read-only or writable, that
    /// grant is recorded at `/data/u/.config`, where the home's protections
    /// mask a credential kept as a link into the font settings
    /// (`~/.git-credentials` a link to `~/.config/fontconfig/gc`). A second
    /// bind of the font settings at the home's name in the private home was
    /// a mount of its own that no mask reached, so the app read the
    /// credential at `~/.config/fontconfig/gc`. Now SAM binds the settings
    /// only where the grant shows them, and the start says why. Without the
    /// link they are bound at the home's name too.
    #[test]
    fn a_font_place_holding_a_credential_is_bound_only_where_a_grant_shows_it() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        fs::create_dir_all(real.join(".config/fontconfig")).unwrap();
        fs::write(real.join(".config/fontconfig/gc"), "secret").unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        let at_real = st(&real.join(".config/fontconfig"));
        let at_name = st(&named.join(".config/fontconfig"));
        let cred = real.join(".git-credentials");
        for writable in [false, true] {
            let mut p = PermissionSet::strict_gui();
            let config = vec![st(&named.join(".config"))];
            if writable {
                p.filesystem.custom_write = config;
            } else {
                p.filesystem.custom_read = config;
            }
            for linked in [true, false] {
                if linked {
                    std::os::unix::fs::symlink(named.join(".config/fontconfig/gc"), &cred).unwrap();
                }
                let cmd = Bubblewrap.build(&ctx_for(&p, &named)).unwrap();
                let case = format!("writable {writable}, linked {linked}");
                assert!(
                    has_seq(&cmd.args, &["--ro-bind-try", &at_real, &at_real]),
                    "{case}: bound where the grant shows it: {:?}",
                    cmd.args
                );
                assert_eq!(
                    has_seq(&cmd.args, &["--ro-bind-try", &at_name, &at_name]),
                    !linked,
                    "{case}: bound at the home's name: {:?}",
                    cmd.args
                );
                assert_eq!(
                    cmd.notes.iter().any(|n| n.contains(
                        "SAM does not bind ~/.config/fontconfig for this app on its own because it holds"
                    )),
                    linked,
                    "{case}: {:?}",
                    cmd.notes
                );
                if linked {
                    fs::remove_file(&cred).unwrap();
                }
            }
        }
    }

    /// A link at a font place whose target lies inside a writable grant, by
    /// a name that is not valid text, never stops the start: anyone who can
    /// write next to the target (another app with the whole home writable)
    /// could plant `~/.fonts` as a link to `~/fonts\xff` and so stop every
    /// later start of every app with such a grant. SAM makes no read-only
    /// bind there, names the link in its one note, as every other skipped
    /// link, and neither the start nor the app page says it keeps the
    /// target read-only. Both with the home read-only and `~/dotfiles`
    /// writable, and with the whole home writable. The control: by a name
    /// that is text, the target is bound read-only and the note says so.
    #[test]
    fn a_link_target_whose_name_is_not_text_is_only_named_and_the_start_runs() {
        use std::os::unix::ffi::OsStrExt;
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let t = scratch();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        let mut ro_home = PermissionSet::strict_gui();
        ro_home.filesystem.home = true;
        ro_home.filesystem.home_access = Access::Ro;
        ro_home.filesystem.custom_write = vec![st(&home.join("dotfiles"))];
        let mut rw_home = PermissionSet::strict_gui();
        rw_home.filesystem.home = true;
        rw_home.filesystem.home_access = Access::Rw;
        fs::create_dir_all(home.join(".config")).unwrap();
        let cases: [(&str, &PermissionSet, &str, &str); 2] = [
            ("read-only home", &ro_home, ".config/fontconfig", "dotfiles"),
            ("whole home writable", &rw_home, ".fonts", ""),
        ];
        for (case, p, rel, dir) in cases {
            let link = home.join(rel);
            for name in [&b"font\xffs"[..], b"fonts"] {
                let name = std::ffi::OsStr::from_bytes(name);
                let target = home.join(dir).join(name);
                fs::create_dir_all(&target).unwrap();
                let _ = fs::remove_file(&link);
                std::os::unix::fs::symlink(&target, &link).unwrap();
                let text = name.to_str().is_some();
                let case = format!("{case}, name is text {text}");
                let ctx = ctx_for(p, &home);
                let cmd = Bubblewrap
                    .build(&ctx)
                    .unwrap_or_else(|e| panic!("{case}: the start runs: {e}"));
                let shown = st(&target);
                assert_eq!(
                    has_seq(&cmd.args, &["--ro-bind-try", &shown, &shown]),
                    text,
                    "{case}: the target bound read-only: {:?}",
                    cmd.args
                );
                let at = format!("SAM does not bind ~/{rel} (a link to ");
                let note = cmd
                    .notes
                    .iter()
                    .find(|n| n.contains(&at))
                    .unwrap_or_else(|| panic!("{case}: the note names the link: {:?}", cmd.notes));
                let keeps = note.contains("read-only where the app's other folders show them");
                assert_eq!(keeps, text, "{case}: the note: {note}");
                let page = sam_core::places::own_place_links_note_from_settings(
                    p,
                    &ctx.host,
                    &sams_folders(&ctx),
                    &this_start(&ctx),
                )
                .unwrap_or_else(|| panic!("{case}: the page names the link"));
                assert!(page.contains(&at), "{case}: the page: {page}");
                assert_eq!(
                    page.contains("read-only where the app's other folders show them"),
                    text,
                    "{case}: the page: {page}"
                );
                fs::remove_file(&link).unwrap();
            }
        }
    }

    /// The file chooser's bookmarks and servers are masked only below a
    /// theme folder SAM binds: below `~/.config/gtk-3.0` kept as a link
    /// (dotfiles), which SAM does not bind, the mask followed the link and
    /// made an empty file in the sandbox's home, or in a private home kept
    /// on disk. Below a real theme folder the mask stays.
    #[test]
    fn theme_private_files_are_masked_only_below_a_bound_theme_folder() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let t = scratch();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in ["dots/gtk", ".config/gtk-4.0"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        fs::write(home.join("dots/gtk/bookmarks"), "file:///home\n").unwrap();
        fs::write(home.join(".config/gtk-4.0/bookmarks"), "file:///home\n").unwrap();
        std::os::unix::fs::symlink(home.join("dots/gtk"), home.join(".config/gtk-3.0")).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.advanced.host_themes = true;
        let cmd = Bubblewrap.build(&ctx_for(&p, &home)).unwrap();
        let linked = st(&home.join(".config/gtk-3.0/bookmarks"));
        assert!(
            !cmd.args.contains(&linked),
            "{linked} not masked: {:?}",
            cmd.args
        );
        let real = st(&home.join(".config/gtk-4.0/bookmarks"));
        assert!(
            has_seq(&cmd.args, &["--ro-bind", "/dev/null", &real]),
            "{real} masked: {:?}",
            cmd.args
        );
    }

    /// The app page and the sandbox check judge SAM's own binds from the
    /// settings alone ([`sam_core::places::GrantsShown`]): for every
    /// setting here, whether a grant shows a place, and whether SAM keeps a
    /// linked font place's target read-only, is the answer the sandbox
    /// gives ([`Views::base`]). Settings: a private home, the whole home
    /// writable and read-only, a home kept behind a link with an extra
    /// folder written by its name and by its real place, an extra folder
    /// the app may have planted as a link, and a user folder the sandbox
    /// refuses.
    #[test]
    fn the_page_and_the_sandbox_judge_own_binds_alike() {
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        let outside = base.join("outside");
        for d in [
            ".fonts",
            ".config/fontconfig",
            ".local/share/fonts",
            "dotfiles/fontconfig",
            "Sync",
        ] {
            fs::create_dir_all(real.join(d)).unwrap();
        }
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        std::os::unix::fs::symlink(&outside, real.join("shared")).unwrap();
        std::os::unix::fs::symlink(&outside, real.join("Sync/Documents")).unwrap();
        let ro_home = {
            let mut p = full_rw();
            p.filesystem.home_access = Access::Ro;
            p
        };
        let mut cases: Vec<(&str, PermissionSet)> = vec![
            ("private", PermissionSet::strict_gui()),
            ("whole home writable", full_rw()),
            ("whole home read-only", ro_home.clone()),
        ];
        let mut by_name = PermissionSet::strict_gui();
        by_name.filesystem.custom_write = vec![st(&named.join(".config"))];
        cases.push(("extra writable by name", by_name));
        let mut by_real = ro_home.clone();
        by_real.filesystem.custom_write = vec![st(&real.join("dotfiles"))];
        by_real.filesystem.custom_read = vec![st(&real.join(".local"))];
        cases.push(("extra folders by real place", by_real));
        let mut planted = full_rw();
        planted.filesystem.custom_read = vec![st(&named.join("shared"))];
        cases.push(("planted extra folder", planted));
        let mut refused = PermissionSet::strict_gui();
        refused.filesystem.custom_write = vec![st(&named.join("Sync"))];
        refused.filesystem.documents = Access::Ro;
        cases.push(("refused user folder", refused));
        // Also a grant's own place and the home itself, which SAM never
        // keeps read-only for a link.
        let probes: Vec<PathBuf> = [
            ".fonts",
            ".config/fontconfig",
            ".local/share/fonts",
            "dotfiles/fontconfig",
            "dotfiles",
            "Sync/Documents",
            "shared",
            "",
        ]
        .iter()
        .flat_map(|rel| [named.join(rel), real.join(rel)])
        .chain([outside.clone()])
        .collect();
        for (case, p) in cases {
            let mut ctx = ctx_for(&p, &named);
            ctx.host
                .xdg_dirs
                .insert("documents".into(), named.join("Sync/Documents"));
            let views = Views::base(&ctx);
            let sams = sams_folders(&ctx);
            let page = sam_core::places::GrantsShown::of(&p, &ctx.host, &sams, &this_start(&ctx));
            for at in &probes {
                assert_eq!(
                    page.shows(at),
                    !views.seen_at(at).is_empty(),
                    "{case}: {} shown: {page:?} / {:?}",
                    at.display(),
                    views.grants
                );
                assert_eq!(
                    page.shows_at_name(at),
                    views.visible(at),
                    "{case}: {} shown at its name: {page:?} / {:?}",
                    at.display(),
                    views.grants
                );
                let target = resolve(at);
                assert_eq!(
                    page.keeps_read_only(&named, &target),
                    !views.read_only_targets(&named, &target).is_empty(),
                    "{case}: {} kept read-only",
                    target.display()
                );
            }
        }
    }

    /// With the home read-only and Downloads writable, an extra writable
    /// folder in Downloads not made yet is not bound; the app makes it a
    /// link to the home, and the next start bound the whole home writable
    /// over its read-only bind. Now it is left out, and the start says why,
    /// as a writable folder left out: the read-only home still shows the
    /// place, so the note never says the app is not shown it. One the app
    /// makes a link to a writable user folder is still shown.
    #[test]
    fn a_planted_link_never_makes_a_read_only_home_writable() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap().join("home");
        for d in ["Downloads", "Documents/sub"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let out = home.join("Downloads/out");
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        p.filesystem.downloads = Access::Rw;
        p.filesystem.documents = Access::Rw;
        p.filesystem.custom_write = vec![st(&out)];
        let ctx = |p: &PermissionSet| {
            let mut c = ctx_for(p, &home);
            c.host
                .xdg_dirs
                .insert("downloads".into(), home.join("Downloads"));
            c.host
                .xdg_dirs
                .insert("documents".into(), home.join("Documents"));
            c
        };
        let h = st(&home);
        std::os::unix::fs::symlink(&home, &out).unwrap();
        let c = ctx(&p);
        let cmd = Bubblewrap.build(&c).unwrap();
        assert!(has_seq(&cmd.args, &["--ro-bind", &h, &h]), "{:?}", cmd.args);
        assert!(
            !has_seq(&cmd.args, &["--bind-try", &h, &h]),
            "the read-only home was bound writable: {:?}",
            cmd.args
        );
        assert!(!Views::of(&c).writable(&home.join("notes.txt")));
        assert!(
            cmd.notes
                .iter()
                .any(|n| n.contains(&st(&out)) && n.contains("may have made that link")),
            "{:?}",
            cmd.notes
        );
        assert!(
            cmd.notes.iter().any(|n| n.contains(&st(&out))
                && n.contains("leaves out the writable folder")
                && !n.contains("not shown otherwise")),
            "{:?}",
            cmd.notes
        );
        // Into a writable user folder: the folder shows it writable anyway.
        fs::remove_file(&out).unwrap();
        std::os::unix::fs::symlink(home.join("Documents/sub"), &out).unwrap();
        let cmd = Bubblewrap.build(&ctx(&p)).unwrap();
        assert!(
            !cmd.notes
                .iter()
                .any(|n| n.contains("may have made that link")),
            "{:?}",
            cmd.notes
        );
    }

    /// A user folder bound on its own never follows a link the app could
    /// have planted, nor one to where programs outside the sandbox listen:
    /// with `~/Sync` writable and Documents set to `~/Sync/Documents`, not
    /// made yet, the app made it a link to `/tmp/tmux-…`, and the next
    /// start bound the host's sockets over its own `/tmp`. Left out in a
    /// private home and as a writable folder in a read-only home; the start
    /// says why (for a writable folder as one left out writable, since a
    /// read-only home may still show the place), naming the danger and no
    /// way out, also where the link is one the app could have planted, and
    /// the views agree. A
    /// user folder you made a link in the home is still shown where it
    /// leads.
    #[test]
    fn a_user_folder_never_follows_a_planted_link() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        let outside = base.join("outside");
        for d in [home.join("Sync"), outside.clone()] {
            fs::create_dir_all(d).unwrap();
        }
        let sockets = tempfile::Builder::new()
            .prefix("tmux-")
            .tempdir_in("/tmp")
            .unwrap();
        let sock = sockets.path().to_path_buf();
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let docs = home.join("Sync/Documents");
        std::os::unix::fs::symlink(&sock, &docs).unwrap();
        let ctx = |p: &PermissionSet| {
            let mut c = ctx_for(p, &home);
            c.host.xdg_dirs.insert("documents".into(), docs.clone());
            c
        };
        let mut private = PermissionSet::strict_gui();
        private.filesystem.documents = Access::Ro;
        private.filesystem.custom_write = vec![st(&home.join("Sync"))];
        let mut read_only_home = private.clone();
        read_only_home.filesystem.home = true;
        read_only_home.filesystem.home_access = Access::Ro;
        read_only_home.filesystem.documents = Access::Rw;
        let mut private_rw = private.clone();
        private_rw.filesystem.documents = Access::Rw;
        for (p, says) in [
            (&private, "SAM leaves out the user folder"),
            (&read_only_home, "leaves out the writable user folder"),
            (&private_rw, "leaves out the writable user folder"),
        ] {
            let c = ctx(p);
            let cmd = Bubblewrap.build(&c).unwrap();
            assert!(
                !cmd.args.iter().any(|a| a.starts_with(&st(&sock))),
                "{:?}",
                cmd.args
            );
            // The note names the danger and gives no way out: the one for
            // a planted link says to set the folder to where it leads.
            assert!(
                cmd.notes.iter().any(|n| names(n, &docs)
                    && names(n, &sock)
                    && n.contains("where programs outside the sandbox listen")),
                "{:?}",
                cmd.notes
            );
            assert!(
                !cmd.notes.iter().any(|n| names(n, &docs)
                    && (n.contains("may have made that link") || n.contains("user-dirs.dirs"))),
                "{:?}",
                cmd.notes
            );
            assert!(
                cmd.notes
                    .iter()
                    .any(|n| names(n, &docs) && n.contains(says)),
                "{says}: {:?}",
                cmd.notes
            );
            assert!(!Views::of(&c).visible(&sock.join("default")));
            // The rule for links in a folder the app can change refuses it
            // as well, and so does the one for planted links; the reason
            // the start gives is the listening programs ([`user_dir`]).
            assert_eq!(
                sam_core::places::user_folder_link_the_app_can_change(
                    &c.permissions,
                    &c.host,
                    &docs
                ),
                Some(docs.clone())
            );
            assert!(matches!(
                user_dir(&c, "documents"),
                Err(NotShown::LeftOut(_, sam_core::places::LeftOut::HostServices(l))) if l == sock
            ));
        }
        // Not plantable by this app, but still the sockets.
        let mut only_docs = PermissionSet::strict_gui();
        only_docs.filesystem.documents = Access::Ro;
        let cmd = Bubblewrap.build(&ctx(&only_docs)).unwrap();
        assert!(
            !cmd.args.iter().any(|a| a.starts_with(&st(&sock))),
            "{:?}",
            cmd.args
        );
        assert!(
            cmd.notes
                .iter()
                .any(|n| n.contains("where programs outside the sandbox listen")),
            "{:?}",
            cmd.notes
        );
        // The control: a link you made in the home, which the app cannot
        // change, to a folder outside it.
        fs::remove_file(&docs).unwrap();
        let mine = home.join("Documents");
        std::os::unix::fs::symlink(&outside, &mine).unwrap();
        let mut c = ctx_for(&only_docs, &home);
        c.host.xdg_dirs.insert("documents".into(), mine);
        let o = st(&outside);
        assert!(
            has_seq(&args_of(&c), &["--ro-bind-try", &o, &o]),
            "{:?}",
            args_of(&c)
        );
    }

    /// A scratch folder outside `/tmp` and `/var/tmp`, beside the test
    /// program: there a link's target is an ordinary folder, while
    /// anything in `/tmp` counts as a place where programs outside the
    /// sandbox listen ([`sam_core::places::leads_to_host_services`]).
    fn scratch() -> tempfile::TempDir {
        let exe = std::env::current_exe().unwrap();
        let t = tempfile::Builder::new()
            .prefix("sandbox-")
            .tempdir_in(exe.parent().unwrap())
            .unwrap();
        let real = fs::canonicalize(t.path()).unwrap();
        assert!(
            !real.starts_with("/tmp") && !real.starts_with("/var/tmp"),
            "the test program lies in a temp folder: {}",
            real.display()
        );
        t
    }

    /// A folder this start shows writable besides the permissions holds
    /// links the app may have made, as `write_grants` counts it: a folder
    /// opened with the app while opened files are writable, and a writable
    /// bind of SAM's. In a private home, an extra read-only folder named
    /// by a link in such a folder to a folder the app is not shown is left
    /// out, and the start says why; opened read-only, or bound read-only
    /// by SAM, the folder holds no link of the app's.
    #[test]
    fn a_folder_this_start_shows_writable_holds_links_the_app_may_have_made() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        let secret = base.join("secret");
        for d in [home.join("work"), secret.clone()] {
            fs::create_dir_all(d).unwrap();
        }
        let planted = home.join("work/fonts");
        std::os::unix::fs::symlink(&secret, &planted).unwrap();
        let st = |p: &Path| p.to_string_lossy().into_owned();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.custom_read = vec![st(&planted)];
        let left_out = |p: &PermissionSet, opened: bool, bind: Option<bool>| {
            let mut c = ctx_for(p, &home);
            c.owd = home.clone();
            c.args = if opened {
                vec![st(&home.join("work"))]
            } else {
                Vec::new()
            };
            c.extra_binds = bind
                .map(|rw| vec![(home.join("work"), PathBuf::from("/run/x"), rw)])
                .unwrap_or_default();
            let cmd = Bubblewrap.build(&c).unwrap();
            let s = st(&secret);
            let bound = has_seq(&cmd.args, &["--ro-bind-try", &s, &s]);
            let said = cmd
                .notes
                .iter()
                .any(|n| n.contains(&st(&planted)) && n.contains("may have made that link"));
            assert_eq!(bound, !said, "{:?} {:?}", cmd.args, cmd.notes);
            said
        };
        assert!(!left_out(&p, false, None), "nothing the app can change");
        p.filesystem.opened_files = Access::Ro;
        assert!(!left_out(&p, true, None), "opened read-only");
        p.filesystem.opened_files = Access::Rw;
        assert!(left_out(&p, true, None), "opened writable");
        p.filesystem.opened_files = Access::Ro;
        assert!(!left_out(&p, false, Some(false)), "bound read-only by SAM");
        assert!(left_out(&p, false, Some(true)), "bound writable by SAM");
    }

    /// SAM's runtime folders hold the sockets of SAM's helpers for every
    /// running app (the D-Bus proxy, the sound relay): wherever they are,
    /// a link to them is not followed, whoever made it. In a private home,
    /// `~/.fonts` a link to the folder of another app's starts is left out
    /// with the note that programs outside the sandbox listen there.
    #[test]
    fn a_link_to_sams_runtime_folders_is_never_followed() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        let runtime = base.join("sam-run");
        for d in [
            home.clone(),
            runtime.join("other-app/l1"),
            runtime.join("app/l1"),
        ] {
            fs::create_dir_all(d).unwrap();
        }
        let fonts = home.join(".fonts");
        std::os::unix::fs::symlink(runtime.join("other-app"), &fonts).unwrap();
        let mut c = ctx_for(&PermissionSet::strict_gui(), &home);
        c.runtime_dir = runtime.join("app/l1");
        let cmd = Bubblewrap.build(&c).unwrap();
        let f = fonts.to_string_lossy().into_owned();
        assert!(
            !has_seq(&cmd.args, &["--ro-bind-try", &f, &f]),
            "{:?}",
            cmd.args
        );
        assert!(
            cmd.notes.iter().any(|n| n.contains("~/.fonts")
                && n.contains("where programs outside the sandbox listen")),
            "{:?}",
            cmd.notes
        );
    }

    /// SAM's runtime folders are this start's folder and the two above it,
    /// never a folder at the top of the computer: with the runtime base
    /// there (`XDG_RUNTIME_DIR=/` gives `/sam`, `SAM_RUNTIME_DIR=/srv`),
    /// counting `/usr` as one left out every extra folder that leads
    /// anywhere in it (`/usr/share`) as a place where programs outside the
    /// sandbox listen. Nor a folder that holds the home: the home is no
    /// such place.
    #[test]
    fn a_runtime_base_at_the_top_of_the_computer_never_counts_as_sams_runtime_folder() {
        let t = scratch();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        fs::create_dir_all(&home).unwrap();
        let link = base.join("share-link");
        std::os::unix::fs::symlink("/usr/share", &link).unwrap();
        let link = link.to_string_lossy().into_owned();
        let mut c = ctx_for(&PermissionSet::strict_gui(), &home);
        c.runtime_dir = PathBuf::from("/usr/sam-app/l1");
        c.permissions.filesystem.custom_read = vec![link.clone()];
        assert_eq!(
            this_start(&c).sam_runtime,
            vec![
                PathBuf::from("/usr/sam-app/l1"),
                PathBuf::from("/usr/sam-app")
            ]
        );
        assert_eq!(read_grant_left_out(&c, &link), None);
        let cmd = Bubblewrap.build(&c).unwrap();
        assert!(
            !cmd.notes
                .iter()
                .any(|n| n.contains("where programs outside the sandbox listen")),
            "{:?}",
            cmd.notes
        );
        // The folders above this start's that hold the home are none either.
        let mut c = ctx_for(&PermissionSet::strict_gui(), "/srv/sam-run/app/h");
        c.runtime_dir = PathBuf::from("/srv/sam-run/app/l1");
        assert_eq!(
            this_start(&c).sam_runtime,
            vec![PathBuf::from("/srv/sam-run/app/l1")]
        );
    }
}
