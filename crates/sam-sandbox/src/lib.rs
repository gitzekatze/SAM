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
use sam_core::places::{PROTECTED_RO, SENSITIVE_DOTFILES};
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
    // Compared as written and by where they lead: the variable may name
    // the home's real place (`/home/u` a link to `/data/u`), and a link on
    // the way (`~/cfg` to `~/dotfiles/cfg`) must stay watched as well as
    // the folder it leads to, since the desktop follows the name (review
    // B2 R53). A name that is not text or holds `..` stops the start
    // ([`odd_config_folder`]).
    let homes = [home.to_path_buf(), resolve(home)];
    for (dir, default) in [(config, ".config/"), (data, ".local/share/")] {
        let Some(dir) = dir else {
            continue;
        };
        let mut rels: Vec<String> = Vec::new();
        for d in [dir.clone(), resolve(&dir)] {
            for h in &homes {
                let Some(r) = d
                    .strip_prefix(h)
                    .ok()
                    .filter(|r| r.components().all(|c| matches!(c, Component::Normal(_))))
                    .and_then(Path::to_str)
                else {
                    continue;
                };
                let r = r.trim_end_matches('/').to_string();
                if !r.is_empty() && format!("{r}/") != default && !rels.contains(&r) {
                    rels.push(r);
                }
            }
        }
        for rel in rels {
            for p in PROTECTED_RO {
                if let Some(rest) = p.strip_prefix(default) {
                    let alt = format!("{rel}/{rest}");
                    if !out.contains(&alt) {
                        out.push(alt);
                    }
                }
            }
        }
    }
    out
}

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
/// they can be mounted read-only.
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
    for f in PROTECTED_CREATE_FILES {
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
        // Never gives up silently (regression, audit L-F2: after 1000 names
        // per place, with SAM's folder on another drive or a full disk, the
        // file simply stayed, and nothing said so).
        let put_aside = |rel: &str, may_delete: bool| -> Option<(PathBuf, Aside)> {
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
            Some(if may_delete && remove_any(&from) {
                (from, Aside::Deleted)
            } else {
                (from, Aside::Failed)
            })
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
            if let Some((to, how)) = put_aside(rel, false) {
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
                if let Some((to, how)) = put_aside(rel, named.contains(rel)) {
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
                    if let Some((to, how)) = put_aside(rel, named.contains(rel)) {
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

/// Files inside the theme folders above that are not theme settings: the
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
/// folders above protected places, above SAM's own folders and above SAM's
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
/// folders and programs): a protected place or credential store kept
/// through a link (dotfiles, `stow`) is guarded where the link leads, below
/// folders that are not above its name. Renamed (`mv ~/dotfiles ~/y`), the
/// guard moved along, and a new `~/dotfiles/bashrc` ran outside the sandbox
/// at the next shell while the link `~/.bashrc` stayed as it was (review
/// B2 S3, R50). A grant's own place is a mount point already.
fn pins(
    home: &Path,
    views: &Views,
    guarded: &[PathBuf],
    sam_dirs: &[PathBuf],
    programs: &[PathBuf],
) -> Vec<PathBuf> {
    let mut pins: Vec<PathBuf> = Vec::new();
    let mut pin = |p: &Path| {
        for c in views.mount_points(p) {
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
/// folders not given, and the other stores unless hidden files are.
fn masked_places(fsp: &FilesystemPerms) -> Vec<&'static str> {
    let mut masks: Vec<&'static str> = Vec::new();
    if !fsp.ssh {
        masks.push(".ssh");
    }
    if !fsp.gnupg {
        masks.push(".gnupg");
    }
    if !fsp.hidden_files {
        masks.extend(SENSITIVE_DOTFILES);
    }
    masks
}

/// Every place in the home that [`guard_home`] guards in this start: the
/// protected places and the hidden credential stores.
fn guarded_places(home: &Path, fsp: &FilesystemPerms) -> Vec<PathBuf> {
    protected_places(home)
        .iter()
        .map(|p| home.join(p))
        .chain(masked_places(fsp).iter().map(|m| home.join(m)))
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

/// Where to bind host path `at` of the home onto itself: where the app
/// reaches it when a grant shows it, never through a link
/// ([`Views::mount_points`]; with `~/.config` a link to a place not
/// granted, the read-only fonts settings stopped every start, security
/// review 2026-11-23, SB-6), or where it lies when the link leads out of
/// what is shown. In a private home, where it is named.
fn bind_place(views: &Views, at: &Path) -> PathBuf {
    if !views.visible(at) {
        return at.to_path_buf();
    }
    views.reached_at(at).unwrap_or_else(|| resolve(at))
}

/// Step 2 of the protections, after every mount (a later mount covers an
/// earlier one: a grant of `/home` or `~/.local` after them showed `~/.ssh`
/// and made autostart writable again; regression, audit S-F2): start files
/// and menu entries read-only, SAM's own folders replaced by an empty
/// folder, and last the credential stores hidden, whatever kind of file
/// they are, at every place the sandbox shows them.
fn guard_home(a: &mut Args, home: &Path, fsp: &FilesystemPerms, views: &Views) {
    for prot in protected_places(home) {
        let path = home.join(&prot);
        // Never on a link (dotfiles kept elsewhere): what it points to is
        // locked, and the link itself is put back after the start if the
        // app replaces it (regression: with `~/.bashrc` a link and the
        // whole home granted, Bubblewrap refused and no app started; the
        // same with `~/.config` a link, SB-6).
        for c in views.mount_points(&path) {
            if matches!(prot.as_str(), ".config/sam" | ".local/share/sam") {
                if c.is_dir() {
                    a.push("--tmpfs").path(&c);
                }
            } else if views.writable(&c) && c.exists() {
                a.lock(&c);
            }
        }
    }
    // The credential stores last: a later bind of a folder above one
    // covers the hiding. With `~/.git-credentials` a link into
    // `~/.config/git`, the protected place bound read-only after it showed
    // the real file again (mutation run 2026-11-23).
    for m in masked_places(fsp) {
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
        let opened = opened_paths(ctx);
        let views = Views::with_opened(ctx, &opened);
        let mut s = Section {
            ctx,
            a: Args::default(),
            notes: Vec::new(),
            exec_env: Vec::new(),
            opened,
            views,
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
    /// Every grant ([`Views::of`]).
    views: Views,
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
            let at = bind_place(&self.views, &home.join(r));
            mount(&at, &|m| m.ro(&at));
        }
        if p.advanced.host_themes && !fsp.home {
            for t in THEME_FILES {
                let at = bind_place(&self.views, &home.join(t));
                mount(&at, &|m| m.ro(&at));
            }
            // Deeper than its folder, so mounted after it. Only a plain
            // file: a link inside leads where the sandbox shows nothing,
            // and Bubblewrap cannot mount over a link.
            for f in THEME_PRIVATE_FILES {
                let at = home.join(f);
                if !self.views.visible(&at)
                    && fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_file())
                {
                    mount(&at, &|m| m.op2("--ro-bind", "/dev/null", &at));
                }
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
        let guarded = guarded_places(&home, fsp);
        for p in pins(&home, views, &guarded, &ctx.sam_dirs, &ctx.sam_programs) {
            mount(&p, &|m| m.op2("--bind", &p, &p));
        }
        // Stable: at equal depth, the order above stays (a pin after the
        // grant it is in).
        mounts.sort_by_key(|(d, _)| *d);
        let a = &mut self.a;
        for (_, m) in mounts {
            a.v.extend(m.v);
            a.bad.extend(m.bad);
        }
        guard_home(a, &home, fsp, views);
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
            if let Some(why) = sam_core::permissions::dangerous_socket(&lands)
                .filter(|_| sam_core::permissions::dangerous_socket(&shown).is_none())
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
        // granted path (audit S-F3).
        let views = &self.views;
        for d in &ctx.sam_dirs {
            // A folder inside another hidden one is hidden with it.
            let nested = ctx.sam_dirs.iter().any(|o| o != d && d.starts_with(o));
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
/// kernel does, link by link; a path with too many links counts as one.
fn link_the_app_can_change(p: &Path, app_can_change: &dyn Fn(&Path) -> bool) -> bool {
    use std::ffi::OsString;
    use std::path::Component;
    // The parts still to walk, as owned names ("/" for the root).
    let parts = |p: &Path| -> Vec<OsString> {
        p.components()
            .map(|c| match c {
                Component::RootDir | Component::Prefix(_) => OsString::from("/"),
                other => other.as_os_str().to_os_string(),
            })
            .collect()
    };
    let p = match p.is_absolute() {
        true => p.to_path_buf(),
        false => std::env::current_dir().unwrap_or_default().join(p),
    };
    let mut todo: std::collections::VecDeque<OsString> = parts(&p).into();
    let mut at = PathBuf::from("/");
    let mut links = 0;
    while let Some(c) = todo.pop_front() {
        if c == "/" {
            at = PathBuf::from("/");
        } else if c == ".." {
            at.pop();
        } else if c != "." {
            let next = at.join(&c);
            if !fs::symlink_metadata(&next).is_ok_and(|m| m.file_type().is_symlink()) {
                at = next;
                continue;
            }
            links += 1;
            if app_can_change(&at) || links > 40 {
                return true;
            }
            let Ok(target) = fs::read_link(&next) else {
                return true;
            };
            for t in parts(&target).into_iter().rev() {
                todo.push_front(t);
            }
        }
    }
    false
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
        // Given the key folder, the app sees it.
        p.filesystem.gnupg = true;
        let a = args_of(&ctx_for(&p, &home));
        assert!(!has_seq(&a, &["--tmpfs", &target]), "{a:?}");
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
        // A config folder that is the home itself adds nothing either.
        let same = protected_places_with(home, Some(home.to_path_buf()), None);
        assert_eq!(
            same.len(),
            PROTECTED_RO.len(),
            "{:?}",
            &same[PROTECTED_RO.len()..]
        );
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
    /// when asked for and the home is not shown anyway.
    #[test]
    fn host_themes_are_shown_only_when_asked_for_without_the_home() {
        for (themes, home, shown) in [
            (false, false, false),
            (true, false, true),
            (true, true, false),
            (false, true, false),
        ] {
            let mut ctx = sample_context();
            ctx.permissions.advanced.host_themes = themes;
            ctx.permissions.filesystem.home = home;
            ctx.permissions.filesystem.home_access = Access::Rw;
            let a = args_of(&ctx);
            for t in [".config/gtk-3.0", ".config/kdeglobals", ".icons"] {
                let p = format!("/home/tester/{t}");
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
}
