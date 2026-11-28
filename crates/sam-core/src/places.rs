//! Places in the home folder that SAM treats specially, shared by the
//! sandbox (which hides or locks them) and the risk words (which call a
//! grant of them dangerous), so both always mean the same places.

use std::path::{Component, Path, PathBuf};

use crate::host::HostInfo;
use crate::permissions::{Access, PermissionSet, XDG_DIR_KEYS};

/// Sensitive dotfiles hidden when full home access is granted with
/// `hidden_files = false`.
pub const SENSITIVE_DOTFILES: &[&str] = &[
    ".password-store",
    ".local/share/keyrings",
    ".pki",
    ".aws",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".azure",
    ".netrc",
    ".git-credentials",
    // git-credential-store's other default file, passwords in plain text
    // (`$XDG_CONFIG_HOME/git/credentials`, found there too by
    // [`sensitive_places`]). `~/.config/git` is a start place kept only
    // read-only, so the app could still read it.
    ".config/git/credentials",
    ".config/keepassxc",
    ".mozilla",
    ".config/chromium",
    ".config/google-chrome",
    ".config/BraveSoftware",
    ".thunderbird",
    ".local/share/kwalletd",
    // More browsers, password managers, developer and cloud logins, and the
    // data of apps installed as Flatpak or Snap (their browser profiles and
    // logins), hidden as well (audit 2026-11-18: the list had 17 places).
    ".config/google-chrome-beta",
    ".config/google-chrome-unstable",
    ".config/vivaldi",
    ".config/microsoft-edge",
    ".config/opera",
    ".librewolf",
    ".waterfox",
    ".floorp",
    ".zen",
    ".config/epiphany",
    ".local/share/epiphany",
    ".config/falkon",
    ".var/app",
    "snap",
    ".config/Bitwarden",
    ".config/1Password",
    ".config/op",
    ".config/rbw",
    ".local/share/keepassxc",
    ".authinfo",
    ".authinfo.gpg",
    ".config/gh",
    ".config/hub",
    ".config/glab-cli",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".config/rclone",
    ".s3cfg",
    ".boto",
    ".config/doctl",
    ".terraform.d/credentials.tfrc.json",
    ".vault-token",
    ".config/hcloud",
    ".oci",
    // Key agents' sockets in the home: a read-only home still lets the
    // app connect to them and use your unlocked keys (owner decision 11 of
    // 2026-11-23). OpenSSH's `~/.ssh/agent` is hidden with `~/.ssh`.
    ".1password",
    ".bitwarden-ssh-agent.sock",
];

/// Paths kept read-only even with full home read/write: common
/// persistence vectors, and SAM's own folders by name (`.config/sam`,
/// `.local/share/sam`), which the sandbox hides instead unless hiding them
/// would cover too much ([`sams_folder_by_name`]).
pub const PROTECTED_RO: &[&str] = &[
    ".config/sam",
    ".local/share/sam",
    ".local/share/applications",
    ".config/autostart",
    ".config/systemd",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".config/fish",
    ".config/environment.d",
    ".config/plasma-workspace",
    ".xinitrc",
    ".xprofile",
    // Programs on $PATH, D-Bus services the session bus starts outside the
    // sandbox, default apps for files and links, desktop scripting and
    // service menus, and configs that can run commands (git hooks, editors).
    ".local/bin",
    "bin",
    ".local/share/dbus-1",
    ".config/mimeapps.list",
    // Where Documents, Downloads and the other user folders are: changed, it
    // would point other apps' folder grants at any folder.
    ".config/user-dirs.dirs",
    ".local/share/kwin",
    ".local/share/plasma",
    ".local/share/kservices5",
    ".local/share/kio/servicemenus",
    ".local/share/nautilus/scripts",
    ".gitconfig",
    ".config/git",
    ".vimrc",
    ".config/nvim",
    ".pam_environment",
    // More files that run commands at login, logout, in a shell, an X
    // session, an editor, a terminal multiplexer or a version control tool.
    ".bash_login",
    ".bash_logout",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".xsessionrc",
    ".xsession",
    ".gvimrc",
    ".exrc",
    ".tmux.conf",
    ".config/tmux",
    ".screenrc",
    ".hgrc",
    // Services, sound-server and compositor settings that start programs
    // (audit S-F6): `systemd --user` units under ~/.local/share, PipeWire's
    // `context.exec`, shell additions, and the start files of Wayland and X
    // compositors and window managers.
    ".local/share/systemd",
    ".config/pipewire",
    ".config/wireplumber",
    ".bash_aliases",
    ".bash_completion",
    ".config/autostart-scripts",
    ".config/sway",
    ".config/hypr",
    ".config/i3",
    ".config/niri",
    ".config/labwc",
    ".config/river",
    ".config/wayfire.ini",
    ".config/openbox",
];

/// The protected places that follow `XDG_CONFIG_HOME` also where it names
/// the home itself, to the top of the home: the file SAM reads the user
/// folders from (`~/user-dirs.dirs` then, [`crate::host::xdg_user_dirs`]).
/// Unlocked there, an app with the whole home writable rewrote it, and at
/// its next start SAM showed other folders as its Documents or Downloads.
/// The start places do not follow there ([`sensitive_places`] says why).
const PROTECTED_AT_HOME_TOO: &[&str] = &[".config/user-dirs.dirs"];

/// The protected places relative to the home: `PROTECTED_RO`, and the same
/// places under `XDG_CONFIG_HOME` and `XDG_DATA_HOME` when those point to
/// other folders inside the home (desktops and programs follow them, so
/// `~/cfg/autostart` starts programs as `~/.config/autostart` does; audit
/// S-F6), and `~/user-dirs.dirs` when `XDG_CONFIG_HOME` names the home
/// itself ([`PROTECTED_AT_HOME_TOO`]). Shared by the sandbox, which locks
/// them, the warnings, which say when a grant inside one is shown
/// read-only, and the files opened for a start, which never share them
/// ([`RefusedForOpened`]).
pub fn protected_places(home: &Path) -> Vec<String> {
    let var = |v: &str| std::env::var_os(v).map(PathBuf::from);
    protected_places_with(home, var("XDG_CONFIG_HOME"), var("XDG_DATA_HOME"))
}

/// [`protected_places`] with the two variables given.
pub fn protected_places_with(
    home: &Path,
    config: Option<PathBuf>,
    data: Option<PathBuf>,
) -> Vec<String> {
    places_following(PROTECTED_RO, home, config, data, PROTECTED_AT_HOME_TOO)
}

/// The credential stores relative to the home: `SENSITIVE_DOTFILES`, and
/// the same places under `XDG_CONFIG_HOME` and `XDG_DATA_HOME` when those
/// point to other folders inside the home, as [`protected_places`] finds
/// them. Programs keep their secrets where those variables say: with
/// `XDG_CONFIG_HOME=~/cfg`, git-credential-store keeps its passwords in
/// `~/cfg/git/credentials`, and only the fixed `~/.config/git/credentials`
/// was hidden, so an app with the whole home could read them (`~/cfg/git`
/// is only locked read-only). Unlike the start places, the stores also
/// follow a variable that names the home itself: with
/// `XDG_CONFIG_HOME=$HOME`, Git keeps its passwords in `~/git/credentials`
/// and the GitHub tool its token in `~/gh`, which an app with the whole
/// home read while only the usual places were hidden. Hiding more is the
/// safe side; locking the start places at the top of the home too would
/// lock folders such as `~/autostart` that the person may use otherwise,
/// so of the protected places only the file SAM reads the user folders
/// from follows there ([`PROTECTED_AT_HOME_TOO`]).
/// Shared by the sandbox, which hides them, and the files opened for a
/// start, which never share them ([`RefusedForOpened`]).
pub fn sensitive_places(home: &Path) -> Vec<String> {
    let var = |v: &str| std::env::var_os(v).map(PathBuf::from);
    sensitive_places_with(home, var("XDG_CONFIG_HOME"), var("XDG_DATA_HOME"))
}

/// [`sensitive_places`] with the two variables given.
pub fn sensitive_places_with(
    home: &Path,
    config: Option<PathBuf>,
    data: Option<PathBuf>,
) -> Vec<String> {
    places_following(SENSITIVE_DOTFILES, home, config, data, SENSITIVE_DOTFILES)
}

/// `list`, and each of its places under `.config/` or `.local/share/`
/// again under `config` and `data` where those are other folders inside
/// the home, and those of them in `at_home` also where they are the home
/// itself (the places then sit at the top of the home: `git/credentials`).
fn places_following(
    list: &[&str],
    home: &Path,
    config: Option<PathBuf>,
    data: Option<PathBuf>,
    at_home: &[&str],
) -> Vec<String> {
    let mut out: Vec<String> = list.iter().map(|p| p.to_string()).collect();
    // Compared as written and by where they lead: the variable may name
    // the home's real place (`/home/u` a link to `/data/u`), and a link on
    // the way (`~/cfg` to `~/dotfiles/cfg`) must stay watched as well as
    // the folder it leads to, since the desktop follows the name (review
    // B2 R53). A name that is not text or holds `..` stops the start (the
    // sandbox's `odd_config_folder`).
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
                if format!("{r}/") != default && !rels.contains(&r) {
                    rels.push(r);
                }
            }
        }
        for rel in rels {
            for p in list {
                if rel.is_empty() && !at_home.contains(p) {
                    continue;
                }
                if let Some(rest) = p.strip_prefix(default) {
                    let alt = if rel.is_empty() {
                        rest.to_string()
                    } else {
                        format!("{rel}/{rest}")
                    };
                    if !out.contains(&alt) {
                        out.push(alt);
                    }
                }
            }
        }
    }
    out
}

/// `p` with links resolved as far as it exists (the rest appended).
pub fn resolve(p: &Path) -> PathBuf {
    if let Ok(r) = std::fs::canonicalize(p) {
        return r;
    }
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) if parent != p => resolve(parent).join(name),
        _ => p.to_path_buf(),
    }
}

/// `p` without `.`, and with each `..` taking back the folder before it,
/// as written (never above `/`).
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if out.parent().is_some() {
                    out.pop();
                } else if !out.has_root() {
                    out.push("..");
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// The start place an extra writable folder lies in, found by
/// [`start_place_of_write_grant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartPlaceGrant {
    /// The protected place, relative to the home (`.config/fish`).
    pub place: String,
    /// The folder lies inside the place; `false`: it is the place itself
    /// (as named or where the place really is).
    pub inside: bool,
    /// The place really is the home or a folder above it, links resolved
    /// (`~/.config/sam` planted as a link to the home): every folder there
    /// counts as part of it, and SAM's words say where the place leads.
    /// Called "inside ~/.config/sam", a grant of `~/work` puzzled the
    /// person (independent review of decision 9).
    pub home_or_above: bool,
}

/// Whether a place under `home` that really is at `real` (links resolved)
/// is the home or a folder above it, compared with the home as named and
/// where it really is (`real_home`). Such a place holds everything in the
/// home: SAM never hides it as one of its own folders by name
/// ([`sams_folder_by_name`]), and its words say where it leads
/// ([`StartPlaceGrant::home_or_above`]).
fn is_home_or_above(home: &Path, real_home: &Path, real: &Path) -> bool {
    real_home.starts_with(real) || home.starts_with(real)
}

/// Whether the extra writable folder `grant` (with `~` already expanded)
/// is a protected start place, lies inside one, or is where one really
/// is: then the sandbox shows it read-only, with or without the whole
/// home (owner decision 9 of 2026-11-23). Without the whole home the
/// place itself was not shown, so nothing locked it, and a writable
/// `~/.config/fish/conf.d` let an app plant `conf.d/evil.fish`, run at the
/// next shell outside the sandbox.
///
/// Compared as named and as reached: the grant as written, with `..` taken
/// back and with links resolved; each place under the home as named, under
/// the home's real place, and where it really leads (`~/.config/fish` a
/// link to `~/dotfiles/fish` makes `~/dotfiles/fish/conf.d` count), also
/// under `XDG_CONFIG_HOME` and `XDG_DATA_HOME` ([`protected_places`]).
pub fn start_place_of_write_grant(grant: &Path, home: &Path) -> Option<StartPlaceGrant> {
    start_place_of_bound_write_grant(grant, &resolve(grant), home)
}

/// [`start_place_of_write_grant`] for a grant whose links the caller has
/// resolved once (`bound`, the place it binds): the sandbox decides on
/// exactly the path it mounts, never on a second look an app running
/// alongside could change in between (independent review of decision 9).
pub fn start_place_of_bound_write_grant(
    written: &Path,
    bound: &Path,
    home: &Path,
) -> Option<StartPlaceGrant> {
    start_place_of_write_grant_in(written, bound, home, &protected_places(home))
}

/// [`start_place_of_bound_write_grant`] for the protected places `places`.
pub fn start_place_of_write_grant_in(
    written: &Path,
    bound: &Path,
    home: &Path,
    places: &[String],
) -> Option<StartPlaceGrant> {
    let mut grants = vec![written.to_path_buf(), lexical(written), bound.to_path_buf()];
    grants.dedup();
    let real_home = resolve(home);
    let mut found: Option<StartPlaceGrant> = None;
    for rel in places {
        let at = home.join(rel);
        let real = resolve(&at);
        let home_or_above = is_home_or_above(home, &real_home, &real);
        let spots = [real, real_home.join(rel), at];
        for g in &grants {
            for s in &spots {
                if !g.starts_with(s) {
                    continue;
                }
                let inside = g != s;
                // The place itself wins over a place it lies in: the
                // note then names the grant as what it is.
                if found.as_ref().is_none_or(|f| f.inside && !inside) {
                    found = Some(StartPlaceGrant {
                        place: rel.clone(),
                        inside,
                        home_or_above,
                    });
                }
            }
        }
    }
    found
}

/// What SAM says about an extra writable folder (`shown`, as the person
/// wrote it) that it shows read-only for lying in a start place, or being
/// one: the launch note and the warning on the app page and in `sam-jail
/// info`. Also for a place named like SAM's folders that SAM keeps
/// read-only instead of hiding it ([`sams_folder_by_name`]), so the words
/// never say a folder is not shown that the app sees. Where the place
/// really is the home or a folder above it, the words say where it leads,
/// since everything there counts as part of it (independent review of
/// decision 9).
pub fn start_place_note(shown: &str, found: &StartPlaceGrant) -> String {
    if found.home_or_above {
        crate::i18n::trf(
            "SAM shows {path} read-only to this app because {place}, a folder SAM protects, is not a real folder but a shortcut to your home folder or a folder above it. Another app may have made this shortcut. If you did not make it yourself, delete the shortcut {place}; your files stay where they are. In a file manager, Ctrl+H shows hidden folders, whose names begin with a dot.",
            &[("path", &shown), ("place", &format!("~/{}", found.place))],
        )
    } else if found.inside {
        crate::i18n::trf(
            "{path} is inside {place}, which SAM protects because changing it can make your computer run programs or change what SAM does; SAM shows it read-only.",
            &[("path", &shown), ("place", &format!("~/{}", found.place))],
        )
    } else {
        crate::i18n::trf(
            "{path} is a place SAM protects because changing it can make your computer run programs or change what SAM does; SAM shows it read-only.",
            &[("path", &shown)],
        )
    }
}

/// Whether the protected place `place` (relative to the home, as
/// [`protected_places`] names it) is named like SAM's own folders:
/// `.config/sam`, `.local/share/sam`, and the same under `XDG_CONFIG_HOME`
/// or `XDG_DATA_HOME` (`cfg/sam`). Whether a start hides such a place as
/// SAM's is [`sams_folder_by_name`].
pub fn is_sams_name(place: &str) -> bool {
    Path::new(place).file_name() == Some("sam".as_ref())
}

/// The places SAM never shares as a file or folder named on the command
/// line or opened with the app (docs/security.md, *Files named on the
/// command line*): one list, asked once per path on its one walk
/// ([`follow`]); the sandbox then binds the path it judged
/// ([`RefusedForOpened::refuses`]). Bubblewrap follows that path again
/// when it mounts it, so a second program that swaps a part of the way
/// for a link in between is not covered (docs/security.md).
///
/// The places are named, never resolved: the key folders, start places
/// and credential stores ([`PROTECTED_RO`], [`SENSITIVE_DOTFILES`], also
/// where `XDG_CONFIG_HOME` and `XDG_DATA_HOME` put them inside the home,
/// [`protected_places_with`], [`sensitive_places_with`]) and the folders
/// `~/.config` and `~/.local`, under the home as named and where it really
/// is; the same start places and stores under the folder each variable
/// names when it is absolute, also outside the home, and at the top of the
/// home when it names the home itself; and those folders as a whole,
/// unless one is the home or a folder above it. A variable folder is taken
/// as written and in the folder that really holds it, not where a link at
/// its own name leads. Besides, where each key folder, start place and
/// credential store really leads (`~/.bashrc` a link to
/// `~/dotfiles/bashrc`); one that leads to the home or a folder above it
/// refuses all of it (`~/.config/fish` or `~/.oci` a link to the home
/// refuses every file in the home).
#[derive(Debug, Clone)]
pub struct RefusedForOpened {
    home: PathBuf,
    /// The home where it really is ([`follow`]).
    real_home: PathBuf,
    /// The links on the way to the home: a home kept behind a link in a
    /// system folder (`/home` a link to `/var/home`) passes them on every
    /// path, so they never refuse a path for a system folder.
    home_way: Vec<PathBuf>,
    /// Every named place, sorted, with no duplicates.
    named: Vec<PathBuf>,
    /// Where each named key folder, start place and credential store
    /// really leads, sorted; one made a link to the home refuses all of
    /// it.
    led_to: Vec<PathBuf>,
    /// `/`; a test judges the system folders below a scratch folder.
    root: PathBuf,
}

/// The places SAM refuses for files opened in a start with the home
/// `home`, with `XDG_CONFIG_HOME` and `XDG_DATA_HOME` of SAM's own
/// environment ([`RefusedForOpened`]).
pub fn refused_for_opened(home: &Path) -> RefusedForOpened {
    let var = |v: &str| std::env::var_os(v).map(PathBuf::from);
    refused_for_opened_with(home, var("XDG_CONFIG_HOME"), var("XDG_DATA_HOME"))
}

/// [`refused_for_opened`] with the two variables given.
pub fn refused_for_opened_with(
    home: &Path,
    config: Option<PathBuf>,
    data: Option<PathBuf>,
) -> RefusedForOpened {
    let home_way = follow(home);
    let real_home = home_way.leads;
    let mut homes = vec![home.to_path_buf(), real_home.clone()];
    homes.dedup();
    // The places relative to the home, as the sandbox locks and hides
    // them (a variable folder inside the home included), and the folders
    // refused as a whole there (the `~/` entries of the risk list): the
    // key folders and start places (`keys`) and the credential stores
    // (`stores`).
    let keys_in_home: Vec<String> = protected_places_with(home, config.clone(), data.clone())
        .into_iter()
        .chain([".ssh".to_string(), ".gnupg".to_string()])
        .collect();
    let stores_in_home = sensitive_places_with(home, config.clone(), data.clone());
    let whole_in_home: Vec<&str> = crate::risk::SENSITIVE_PATHS
        .iter()
        .filter_map(|s| s.strip_prefix("~/"))
        .collect();
    let mut keys: Vec<PathBuf> = Vec::new();
    let mut stores: Vec<PathBuf> = Vec::new();
    let mut named: Vec<PathBuf> = Vec::new();
    for h in &homes {
        keys.extend(keys_in_home.iter().map(|rel| h.join(rel)));
        stores.extend(stores_in_home.iter().map(|rel| h.join(rel)));
        named.extend(whole_in_home.iter().map(|rel| h.join(rel)));
    }
    for (dir, default) in [(config, ".config/"), (data, ".local/share/")] {
        for base in variable_folder(dir) {
            keys.extend(moved_places(&base, default, PROTECTED_RO));
            stores.extend(moved_places(&base, default, SENSITIVE_DOTFILES));
            if !is_home_or_above(home, &real_home, &base) {
                named.push(base);
            }
        }
    }
    // Where each place really leads. One that leads to the home or a
    // folder above it refuses all of it, as SAM always did: with
    // `~/.config/fish` a link to the home, fish reads `~/config.fish` and
    // `~/conf.d/*.fish` outside the sandbox, so a writable `~/conf.d` would
    // let the app plant a file that runs at the next shell; with `~/.oci`
    // a link to the home, the OCI tool reads `~/config`.
    let mut led_to: Vec<PathBuf> = keys.iter().chain(&stores).map(|p| resolve(p)).collect();
    led_to.sort();
    led_to.dedup();
    named.extend(keys);
    named.extend(stores);
    named.sort();
    named.dedup();
    RefusedForOpened {
        home: home.to_path_buf(),
        real_home,
        home_way: home_way.links,
        named,
        led_to,
        root: PathBuf::from("/"),
    }
}

/// The folder `XDG_CONFIG_HOME` or `XDG_DATA_HOME` names (`dir`), as
/// written (with `..` taken back) and in the folder that really holds it,
/// never where a link at its own name leads (`/data` a link to
/// `/disk/data` makes `XDG_CONFIG_HOME=/data/cfg` also `/disk/data/cfg`).
/// Where the start places and stores in it really lead is added by
/// [`refused_for_opened_with`]. For `/` itself (also written `//` or `/.`)
/// just `/`: programs then keep their start places and stores at the top
/// of the root (`/autostart`, `/gh`). Nothing for a value that is relative
/// or ends in `..` (the sandbox does not start with a `..` in either
/// variable): the XDG Base Directory specification has programs ignore a
/// relative one (a relative one inside the home still counts as the
/// sandbox's locks take it, [`protected_places_with`]).
fn variable_folder(dir: Option<PathBuf>) -> Vec<PathBuf> {
    let Some(dir) = dir.filter(|d| d.is_absolute()) else {
        return Vec::new();
    };
    if dir
        .components()
        .all(|c| matches!(c, Component::RootDir | Component::CurDir))
    {
        return vec![PathBuf::from("/")];
    }
    let (Some(parent), Some(Component::Normal(name))) =
        (dir.parent(), dir.components().next_back())
    else {
        return Vec::new();
    };
    let mut out = vec![lexical(&dir), resolve(parent).join(name)];
    out.sort();
    out.dedup();
    out
}

/// The places under `.config/` or `.local/share/` (`default`) of the list
/// `list` (the start places or the credential stores), again under `base`:
/// where a program puts them when `XDG_CONFIG_HOME` or `XDG_DATA_HOME` is
/// `base`.
fn moved_places<'a>(
    base: &'a Path,
    default: &'a str,
    list: &'a [&'a str],
) -> impl Iterator<Item = PathBuf> + 'a {
    list.iter()
        .filter_map(move |p| p.strip_prefix(default).map(|rest| base.join(rest)))
}

/// Whether `p` is or lies inside one of the sorted paths `list`.
fn inside_any(list: &[PathBuf], p: &Path) -> bool {
    p.ancestors()
        .any(|a| list.binary_search_by(|n| n.as_path().cmp(a)).is_ok())
}

impl RefusedForOpened {
    /// Whether SAM refuses to share the file or folder named `written` on
    /// the command line, whose way is `way` (`follow(written)`):
    /// - the way does not end (a loop of links, one it cannot read);
    /// - it leads to the home or a folder above it;
    /// - it leads into a system folder ([`crate::risk::is_system_folder`]),
    ///   or a link on its way lies in one, outside the home (as named and
    ///   as it really is) and not on the way to the home; with the home at
    ///   `/`, nothing counts as in the home;
    /// - as written (with `..` taken back), where it leads, or at a link on
    ///   its way, it is or lies inside a named place;
    /// - where it leads, or at a link on its way, it is or lies inside the
    ///   place a key folder, start place or credential store really leads
    ///   to.
    pub fn refuses(&self, written: &Path, way: &Way) -> bool {
        if way.stuck || is_home_or_above(&self.home, &self.real_home, &way.leads) {
            return true;
        }
        let in_home = |p: &Path| {
            [&self.home, &self.real_home]
                .iter()
                .any(|h| h.as_path() != Path::new("/") && p.starts_with(h))
        };
        let system = std::iter::once(&way.leads)
            .chain(way.links.iter().filter(|l| !self.home_way.contains(l)))
            .any(|p| !in_home(p) && self.system(p));
        if system {
            return true;
        }
        let as_written = lexical(&match written.is_absolute() {
            true => written.to_path_buf(),
            false => std::env::current_dir().unwrap_or_default().join(written),
        });
        let walked = || std::iter::once(&way.leads).chain(&way.links);
        inside_any(&self.named, &as_written)
            || walked().any(|p| inside_any(&self.named, p))
            || walked().any(|p| inside_any(&self.led_to, p))
    }

    /// Whether the folder `dir` (where it really is) holds the home, a named
    /// place or where a listed place leads: such a folder is not shared.
    pub fn holds(&self, dir: &Path) -> bool {
        [&self.home, &self.real_home]
            .into_iter()
            .chain(&self.named)
            .chain(&self.led_to)
            .any(|n| n.starts_with(dir))
    }

    /// Whether `p` is a system folder or lies in one, below `root`.
    fn system(&self, p: &Path) -> bool {
        p.strip_prefix(&self.root)
            .is_ok_and(|rest| crate::risk::is_system_folder(&Path::new("/").join(rest)))
    }

    /// These places with the system folders judged below `root`, so a test
    /// builds them in a scratch folder whatever the computer's own layout.
    #[cfg(test)]
    fn under_root(mut self, root: PathBuf) -> Self {
        self.root = root;
        self
    }
}

/// Where a user folder (Documents, Downloads, …) set to `dir` is shown:
/// where it really is (links resolved), unless that would show more than a
/// user folder: the home, a folder above it, a system folder, a key or
/// credential store, a start place (`user-dirs.dirs` is a plain text
/// file, audit S-F11), or a folder in `/tmp` where programs outside the
/// sandbox listen (`/tmp` itself, `/tmp/tmux-1000`): bound over the
/// sandbox's own `/tmp`, it handed the app the host's terminal
/// multiplexers, SSH agents and X server, read-only too, since connecting
/// to a socket needs no write access. The sandbox also refuses one inside
/// SAM's own folders; that is left to the caller, since which folders
/// count as SAM's depends on what the start shows ([`shown_folders`]).
/// Whether the way there holds a link the app could have put there is
/// [`user_folder_shown`].
pub fn user_folder_place(dir: &Path, home: &Path) -> Option<PathBuf> {
    let real = resolve(dir);
    let text = real.to_string_lossy();
    let real_home = resolve(home);
    let refused = real_home.starts_with(&real)
        || crate::risk::is_sensitive_path_in(&text, home)
        || crate::risk::is_sensitive_path_in(&text, &real_home)
        || crate::risk::shows_host_sockets(&text);
    (!refused).then_some(real)
}

/// Where the user folder set to `dir` is shown in a start with the
/// permissions `p` ([`user_folder_place`]), unless the way there holds a
/// link the app could have put there ([`user_folder_link_the_app_can_change`]).
/// The answer the sandbox, its check and the list of what a start shows
/// take.
pub fn user_folder_shown(p: &PermissionSet, host: &HostInfo, dir: &Path) -> Option<PathBuf> {
    if user_folder_link_the_app_can_change(p, host, dir).is_some() {
        return None;
    }
    user_folder_place(dir, &host.home)
}

/// The first link on the way to the user folder set to `dir` that lies in
/// a folder the permissions `p` let the app change (the writable whole
/// home, a writable extra folder, a writable user folder), if any. The app
/// could have put that link there in an earlier start (`mv ~/Downloads
/// ~/D; ln -s /tmp ~/Downloads`), so where it leads is not where the
/// person put the folder: shown there, a writable home let the app pick
/// any place on the computer as its Downloads (`user-dirs.dirs` stays
/// locked, but the folder it names did not). A link SAM cannot tell from
/// one the person made is refused as well; the start says so.
///
/// A folder counts as one the app can change when any writable grant
/// shows it, also where a read-only grant lies in between (Documents
/// read-only under the writable home): the app may have written there in
/// an earlier start, before the folder was set read-only or existed, and a
/// read-only user folder the sandbox refuses (one that is itself a link in
/// the writable home) is not mounted at all, so the home shows it
/// writable. Taken as read-only there, a link the app planted inside it
/// was followed and its target bound writable (review of finding R63).
/// Judged from the permissions alone, so the sandbox, its check and the
/// app page take one answer: a writable grant counts also where the
/// sandbox shows it read-only (inside a start place) or not at all, which
/// refuses more, never less.
pub fn user_folder_link_the_app_can_change(
    p: &PermissionSet,
    host: &HostInfo,
    dir: &Path,
) -> Option<PathBuf> {
    let fs = &p.filesystem;
    let mut writable: Vec<PathBuf> = Vec::new();
    if fs.home && fs.home_access == Access::Rw {
        writable.push(host.home.clone());
        writable.push(resolve(&host.home));
    }
    for key in XDG_DIR_KEYS {
        if fs.xdg_access(key) == Access::Rw {
            if let Some(real) = host
                .xdg_dir(key)
                .and_then(|d| user_folder_place(d, &host.home))
            {
                writable.push(real);
            }
        }
    }
    for c in &fs.custom_write {
        writable.push(resolve(&crate::util::expand_home(c)));
    }
    let can_change = |d: &Path| writable.iter().any(|g| d.starts_with(g));
    links_on_the_way(dir)
        .into_iter()
        .find(|l| l.parent().is_some_and(can_change))
}

/// The access at which a start shows the user folder `key`: its own,
/// unless another granted user folder is shown at the same place
/// ([`user_folder_shown`]; Music read and write, Pictures read-only, both
/// set to `~/Media`) at a stricter one. Then the stricter one decides for
/// all of them, whatever their order: read-only wins (owner decision of
/// 2026-11-27, as "read-only means read-only"). The sandbox's mounts and
/// views, its check, a terminal app's start line and the app page take
/// this one answer, so none expects one folder at two accesses.
pub fn user_folder_access(p: &PermissionSet, host: &HostInfo, key: &str) -> Access {
    let own = p.filesystem.xdg_access(key);
    let Some(real) = shown_user_folder(p, host, key) else {
        return own;
    };
    let stricter_at_same_place = XDG_DIR_KEYS.iter().any(|k| {
        p.filesystem.xdg_access(k) == Access::Ro
            && shown_user_folder(p, host, k).as_ref() == Some(&real)
    });
    if stricter_at_same_place {
        Access::Ro
    } else {
        own
    }
}

/// Where the granted user folder `key` is shown ([`user_folder_shown`]),
/// if it is granted and shown.
fn shown_user_folder(p: &PermissionSet, host: &HostInfo, key: &str) -> Option<PathBuf> {
    host.xdg_dir(key)
        .filter(|_| p.filesystem.xdg_access(key).is_granted())
        .and_then(|d| user_folder_shown(p, host, d))
}

/// Every place where granted user folders set to it differ in access
/// (Music read and write, Pictures read-only, both `~/Media`), with those
/// folders in the order of [`XDG_DIR_KEYS`]: all of them are shown
/// read-only there ([`user_folder_access`]), and the start, the app page
/// and `sam-jail info` say so ([`user_folders_at_one_place_note`]).
pub fn user_folders_at_one_place(
    p: &PermissionSet,
    host: &HostInfo,
) -> Vec<(PathBuf, Vec<&'static str>)> {
    let mut out: Vec<(PathBuf, Vec<&'static str>)> = Vec::new();
    for key in XDG_DIR_KEYS {
        let Some(real) = shown_user_folder(p, host, key) else {
            continue;
        };
        match out.iter_mut().find(|(r, _)| *r == real) {
            Some((_, keys)) => keys.push(key),
            None => out.push((real, vec![key])),
        }
    }
    out.retain(|(_, keys)| {
        let acc = |k: &&str| p.filesystem.xdg_access(k);
        keys.iter().map(acc).any(|a| a == Access::Rw)
            && keys.iter().map(acc).any(|a| a == Access::Ro)
    });
    out
}

/// What a start, the app page and `sam-jail info` say about the user
/// folders `keys` set to the one place `place` with different access
/// ([`user_folders_at_one_place`]): the folders, the rule and the way out.
pub fn user_folders_at_one_place_note(keys: &[&str], place: &Path) -> String {
    crate::i18n::trf(
        "The {keys} folders are all set to {path}, some read and write, some read-only. The stricter setting wins: the app sees {path} read-only. To let it write there, set each of these folders to read and write, or give them places of their own.",
        &[
            ("keys", &keys.join(", ")),
            ("path", &crate::util::tildify(place)),
        ],
    )
}

/// What a start says about the user folder `key` set to `dir`, a folder in
/// `/tmp` where programs outside the sandbox listen, which it does not
/// show; also the app page and `sam-jail info`, before the start. The app
/// then sees its own empty `/tmp` there, so what it saves there is gone
/// when it quits (`XDG_DOWNLOAD_DIR=/tmp`, set so downloads clear
/// themselves).
pub fn user_folder_sockets_note(key: &str, dir: &Path) -> String {
    crate::i18n::trf(
        "{key} folder is set to {path}, where programs outside the sandbox listen; not bound. The app sees its own empty /tmp there instead, and what it saves there is gone when it quits. Set the folder to one of its own, such as /tmp/{key}, to keep what the app saves.",
        &[("key", &key), ("path", &dir.display())],
    )
}

/// What a start says about the user folder `key` set to `dir` whose way
/// holds the link `link` in a folder the app can change, which it does not
/// show ([`user_folder_link_the_app_can_change`]); also the app page and
/// `sam-jail info`, before the start.
pub fn user_folder_link_note(key: &str, dir: &Path, link: &Path) -> String {
    crate::i18n::trf(
        "{key} folder is set to {path}, whose way leads through the link {link} in a folder the app can change, so the app may have put it there; not bound",
        &[
            ("key", &key),
            ("path", &dir.display()),
            ("link", &link.display()),
        ],
    )
}

/// Every link on the way to the absolute path `p`, in the order the system
/// follows them, each named in the folder that really holds it (the links
/// before it resolved), also the links inside a link's target. A part
/// that does not exist ends the walk. At most 40 links, as the kernel
/// follows.
pub fn links_on_the_way(p: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !p.is_absolute() {
        return out;
    }
    let mut todo: std::collections::VecDeque<std::ffi::OsString> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        })
        .collect();
    let mut at = PathBuf::from("/");
    while let Some(c) = todo.pop_front() {
        if c == ".." {
            at.pop();
            continue;
        }
        let next = at.join(&c);
        let Ok(m) = std::fs::symlink_metadata(&next) else {
            break;
        };
        if !m.file_type().is_symlink() {
            at = next;
            continue;
        }
        if out.len() == 40 {
            break;
        }
        let Ok(target) = std::fs::read_link(&next) else {
            break;
        };
        out.push(next);
        if target.is_absolute() {
            at = PathBuf::from("/");
        }
        for t in target.components().rev() {
            match t {
                Component::Normal(n) => todo.push_front(n.to_os_string()),
                Component::ParentDir => todo.push_front("..".into()),
                _ => {}
            }
        }
    }
    out
}

/// Every folder the permissions `p` show in a start, where it really is
/// (links resolved): the whole home, the user folders the sandbox shows
/// ([`user_folder_place`]) and the extra folders, read-only and writable,
/// before any of SAM's own folders are taken out. It decides which
/// folders named like SAM's count as SAM's ([`sams_folder_by_name`]), so
/// the sandbox, its check and the app page decide from the same list.
pub fn shown_folders(p: &PermissionSet, host: &HostInfo) -> Vec<PathBuf> {
    let fs = &p.filesystem;
    let mut out = Vec::new();
    if fs.home {
        out.push(resolve(&host.home));
    }
    for key in XDG_DIR_KEYS {
        if fs.xdg_access(key).is_granted() {
            if let Some(real) = host
                .xdg_dir(key)
                .and_then(|d| user_folder_shown(p, host, d))
            {
                out.push(real);
            }
        }
    }
    // As the sandbox binds them (`~` from `HOME`), links resolved.
    for c in fs.custom_read.iter().chain(&fs.custom_write) {
        out.push(resolve(&crate::util::expand_home(c)));
    }
    out
}

/// Whether the protected place `rel` (relative to `home`) counts as one of
/// SAM's own folders in a start that shows the folders `shown`
/// ([`shown_folders`], each with its links resolved): the sandbox then
/// hides it wherever the app reaches it, links followed, also where a
/// grant shows only something inside it, and a writable grant inside it
/// is not bound.
///
/// Where this SAM keeps its own (`own`: [`crate::Paths::sam_dirs`]) always
/// counts, wherever it leads. Any other place named like SAM's folders
/// ([`is_sams_name`]) counts as well, also as a link: another SAM may keep
/// its settings in `~/Sync/sam` with `~/.local/share/sam` a link there, and
/// with the whole home or a grant of `~/Sync` the app read them and its
/// apps' private homes (independent review of decision 9: every link had
/// counted as an ordinary start place). Such a place is kept read-only
/// like a start place instead only where hiding it would cover too much:
/// - where it really is the home or a folder above it;
/// - where it leads elsewhere through a link, the start shows a folder
///   inside the place it leads to, and nothing the start shows holds that
///   place itself.
///
/// An app that can write `~/.config` could otherwise plant `~/.config/sam`
/// as a link to the home, or to `~/work` holding a grant, and make later
/// starts cover the home or that grant with an empty folder. Where the
/// start shows the place a link leads to itself (the whole home, `~/Sync`
/// or exactly that folder), a planted link cannot be told from another
/// SAM's folder kept elsewhere, and the place stays hidden as before:
/// nothing that was hidden becomes visible.
pub fn sams_folder_by_name(home: &Path, rel: &str, own: &[PathBuf], shown: &[PathBuf]) -> bool {
    is_sams_name(rel) && counts_as_sams(home, &home.join(rel), own, shown)
}

/// Whether the folder `at`, named like SAM's folders or named by one of
/// SAM's folder switches, counts as one of SAM's own folders in a start
/// that shows the folders `shown`: the rules of [`sams_folder_by_name`],
/// whatever the folder's name. Where this SAM keeps its own (`own`) always
/// counts; the home or a folder above it never does; a folder reached
/// through a link does not where the start shows only folders inside the
/// place it leads to. A link on the way to the home itself (`/home` a
/// link to `/var/home`) is no such link.
fn counts_as_sams(home: &Path, at: &Path, own: &[PathBuf], shown: &[PathBuf]) -> bool {
    let real = resolve(at);
    if own
        .iter()
        .any(|d| d.as_path() == at || real.starts_with(resolve(d)))
    {
        return true;
    }
    let real_home = resolve(home);
    if is_home_or_above(home, &real_home, &real) {
        return false;
    }
    // Where it would be without a link on the way: below the home's real
    // place when it lies in the home, else as written with `..` taken
    // back.
    let unlinked = at
        .strip_prefix(home)
        .map_or_else(|_| lexical(at), |rel| real_home.join(rel));
    let through_link = real != unlinked;
    let shown_whole = shown.iter().any(|s| real.starts_with(s));
    let shown_inside = shown.iter().any(|s| s.starts_with(&real));
    !(through_link && shown_inside && !shown_whole)
}

/// SAM's own folders in a start that shows the folders `shown`
/// ([`shown_folders`]): where this SAM keeps its own (`own`:
/// [`crate::Paths::sam_dirs`]), the protected places named like them that
/// count as SAM's ([`sams_folder_by_name`]), and the folders SAM's folder
/// switches `SAM_CONFIG_DIR` and `SAM_DATA_DIR` name
/// ([`crate::paths::folders_named_by_switches`]) that count by the same
/// rules: a release build never keeps anything there, yet an installed SAM
/// may once have kept its app records and the other apps' private homes
/// there. The sandbox hides them, its check expects them hidden, and the
/// start line and the app page leave them out, all from this one list.
pub fn sams_folders(home: &Path, own: &[PathBuf], shown: &[PathBuf]) -> Vec<PathBuf> {
    sams_folders_in(
        home,
        own,
        shown,
        &protected_places(home),
        &crate::paths::folders_named_by_switches(),
    )
}

/// [`sams_folders`] among the protected places `places`, with the folders
/// that SAM's folder switches name `switched`.
pub fn sams_folders_in(
    home: &Path,
    own: &[PathBuf],
    shown: &[PathBuf],
    places: &[String],
    switched: &[PathBuf],
) -> Vec<PathBuf> {
    let mut out = own.to_vec();
    for rel in places {
        let at = home.join(rel);
        if !out.contains(&at) && sams_folder_by_name(home, rel, own, shown) {
            out.push(at);
        }
    }
    for at in switched {
        if !out.contains(at) && counts_as_sams(home, at, own, shown) {
            out.push(at.clone());
        }
    }
    out
}

/// Whether `real` (a path with its links resolved) is one of SAM's own
/// folders (`sam_dirs`, the list of [`sams_folders`]) or lies inside one.
/// The sandbox hides what lies there, and SAM's sandbox check and start
/// texts ask this same question, so they never expect a folder the
/// sandbox does not show (independent review of decision 9: SAM's data
/// kept in `~/Games/sam`).
pub fn inside_sams_folders(real: &Path, sam_dirs: &[PathBuf]) -> bool {
    sam_dirs
        .iter()
        .map(|d| resolve(d))
        .any(|d| real.starts_with(&d))
}

/// Whether the sandbox leaves out the extra writable folder bound at
/// `bound` (its links resolved once) for lying in SAM's own folders
/// (`sam_dirs`, the list of [`sams_folders`]): in one of them, or in a
/// start place (`place`, what [`start_place_of_bound_write_grant`] found
/// under `home`) that is one of them. A start place named like SAM's
/// folders that SAM only keeps read-only is not in that list: the grant
/// is shown read-only, never left out. The sandbox decides each writable
/// grant with this, and the sandbox check and the app page say what it
/// says.
pub fn write_grant_in_sams_folders(
    bound: &Path,
    place: Option<&StartPlaceGrant>,
    sam_dirs: &[PathBuf],
    home: &Path,
) -> bool {
    inside_sams_folders(bound, sam_dirs)
        || place.is_some_and(|f| sam_dirs.contains(&home.join(&f.place)))
}

/// What SAM says about an extra folder (`shown`, as the person wrote it)
/// inside SAM's own folders, which it does not show.
pub fn inside_sams_folders_note(shown: &str) -> String {
    crate::i18n::trf(
        "{path} lies inside SAM's own folders, which apps never see; SAM does not show it.",
        &[("path", &shown)],
    )
}

/// The protected place (relative to `home`) that really is the home,
/// links resolved, in a start whose own folders are `sams`
/// ([`sams_folders`]), if any: `~/.config/sam` planted as a link to the
/// home, which hiding would cover the whole home with an empty folder
/// ([`sams_folder_by_name`]), or any other start place leading there. The
/// sandbox locks each protected place it does not hide read-only where the
/// app reaches it, so with the whole home writable that lock lands on the
/// home, and the app sees the whole home read-only (its keys and SAM's own
/// folders still hidden). The sandbox's note, its check and the app page
/// take this one answer, so the check expects the home read-only where the
/// sandbox shows it so (independent review of decision 9: it expected the
/// home writable and failed). One that the start hides as SAM's is not
/// named: that hiding lands on the home instead.
pub fn protected_place_at_home(home: &Path, sams: &[PathBuf]) -> Option<String> {
    protected_place_at_home_in(home, sams, &protected_places(home))
}

/// [`protected_place_at_home`] among the protected places `places`.
pub fn protected_place_at_home_in(
    home: &Path,
    sams: &[PathBuf],
    places: &[String],
) -> Option<String> {
    let real_home = resolve(home);
    places
        .iter()
        .find(|rel| {
            let at = home.join(rel);
            !sams.contains(&at) && resolve(&at) == real_home
        })
        .cloned()
}

/// What SAM says when the whole home is shown read-only because the
/// protected place `place` (relative to the home) leads to it
/// ([`protected_place_at_home`]): the launch note and the warning on the
/// app page and in `sam-jail info`.
pub fn home_read_only_note(place: &str) -> String {
    crate::i18n::trf(
        "SAM shows your home folder read-only to this app because {place}, a folder SAM protects, is not a real folder but a shortcut to your whole home folder. Another app may have made this shortcut. If you did not make it yourself, delete the shortcut {place}; your files stay where they are. In a file manager, Ctrl+H shows hidden folders, whose names begin with a dot.",
        &[("place", &format!("~/{place}"))],
    )
}

/// Where a path leads, followed as Linux follows it ([`follow`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Way {
    /// Where it leads, every link followed, also one whose target does not
    /// exist yet (the rest of the path appended): a bind made a moment
    /// later shows that place if it appears in between.
    pub leads: PathBuf,
    /// Every link on the way, in the order Linux follows them, each named
    /// in the folder that really holds it (the links before it followed).
    pub links: Vec<PathBuf>,
    /// The way ends at the last link of `links`, which Linux would not
    /// follow: one too many (more than 40, a loop) or one that cannot be
    /// read.
    pub stuck: bool,
}

/// The way to `p`, part after part as Linux reads a path: a link is
/// followed where it lies, `..` goes back from where the way really is. A
/// relative path counts from the current folder.
pub fn follow(p: &Path) -> Way {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    let names = |p: &Path| -> Vec<OsString> {
        p.components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_os_string()),
                Component::ParentDir => Some("..".into()),
                _ => None,
            })
            .collect()
    };
    let p = match p.is_absolute() {
        true => p.to_path_buf(),
        false => std::env::current_dir().unwrap_or_default().join(p),
    };
    let mut todo: VecDeque<OsString> = names(&p).into();
    let mut at = PathBuf::from("/");
    let mut links: Vec<PathBuf> = Vec::new();
    while let Some(c) = todo.pop_front() {
        if c == ".." {
            at.pop();
            continue;
        }
        let next = at.join(&c);
        if !std::fs::symlink_metadata(&next).is_ok_and(|m| m.file_type().is_symlink()) {
            at = next;
            continue;
        }
        let target = std::fs::read_link(&next).ok().filter(|_| links.len() < 40);
        links.push(next.clone());
        let Some(target) = target else {
            let leads = todo.iter().fold(next, |l, n| l.join(n));
            return Way {
                leads,
                links,
                stuck: true,
            };
        };
        if target.is_absolute() {
            at = PathBuf::from("/");
        }
        for n in names(&target).into_iter().rev() {
            todo.push_front(n);
        }
    }
    Way {
        leads: at,
        links,
        stuck: false,
    }
}

/// The first link on `way` that lies in a folder `can_change` names (asked
/// with the folder's real place), or the link where the way is stuck: the
/// app could have put it there, pointing anywhere. SAM cannot tell such a
/// link from one the person made.
pub fn link_the_app_could_plant(way: &Way, can_change: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let last = way.links.len().saturating_sub(1);
    way.links
        .iter()
        .enumerate()
        .find(|(i, l)| (way.stuck && *i == last) || l.parent().is_some_and(can_change))
        .map(|(_, l)| l.clone())
}

/// What one start adds to its permissions for the places SAM binds where
/// their links lead ([`linked_place_left_out`]). SAM's sandbox check passes
/// SAM's runtime folders and nothing writable: its start opens no folder,
/// and SAM adds no bind of its own to it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThisStart {
    /// The folders this start shows writable besides the permissions: the
    /// folders opened with the app when opened files are writable, and
    /// SAM's own writable binds. A link in one of them may be the app's
    /// too, as a link in a writable grant.
    pub writable: Vec<PathBuf>,
    /// SAM's runtime folders, wherever they are (with the D-Bus proxy's
    /// socket and the sound relay's): programs outside the sandbox listen
    /// there ([`leads_to_host_services`]).
    pub sam_runtime: Vec<PathBuf>,
}

/// Whether a place reached through a link holds what programs outside the
/// sandbox listen on, as far as SAM can tell:
/// - the whole computer;
/// - anything in `/tmp` or `/var/tmp`, or a folder holding one: any program
///   may put its socket there, directly (`/tmp/.s.PGSQL.5432`) or in a
///   folder of its own (`/tmp/tmate-1000`), so no list of names is
///   complete ([`crate::risk::shows_host_sockets`] keeps its list for
///   rating a grant by its name). Not a place in the home when the home
///   itself lies there (a guest session's home in `/tmp`): the home holds
///   the person's files, judged by the other rules;
/// - the host's runtime folder (`XDG_RUNTIME_DIR`, with the session bus,
///   systemd's and GnuPG's sockets) and SAM's runtime folders
///   (`this.sam_runtime`) wherever they are (`/mnt/wslg/runtime-dir`, one
///   under `/tmp`), or a folder holding one; not one that holds the home
///   (a container's `XDG_RUNTIME_DIR=/tmp`, which the rule for `/tmp`
///   covers);
/// - anything under `/run` (the system bus, Docker's socket) except drives
///   under `/run/media`, and `/proc` and `/dev` (`/dev/log`, `/dev/shm`).
///
/// Connecting to a socket needs no write access, so a read-only bind of
/// such a place hands them over: through tmux's socket the app runs
/// commands outside the sandbox.
pub fn leads_to_host_services(real: &Path, host: &HostInfo, this: &ThisStart) -> bool {
    host_services_at(real, host, this, true)
}

/// Whether the link `place`, on the way to a bind, lies where programs
/// outside the sandbox listen: in `/tmp` or `/var/tmp` (not in a home kept
/// there), in the host's or SAM's runtime folders, or under `/proc` and
/// `/dev`, as [`leads_to_host_services`] counts them; not in a folder that
/// only holds one (a link in `/` or `/mnt`).
///
/// Where the way ends is not all: any program may make a link in `/tmp`,
/// pointing wherever it likes, also to a place SAM does not know as one
/// where programs listen. On WSLg the host's `/tmp/.X11-unix` is a link
/// to `/mnt/wslg/.X11-unix`, and `~/.fonts` made a link to
/// `/tmp/.X11-unix` bound the X server's socket folder there. A link in
/// `/proc` (`/proc/<pid>/root`) leads into another program's view of the
/// computer. Only root makes links in the rest of `/run`, to the system's
/// own places: NixOS's `/run/current-system` leads to the fonts and themes
/// in `/nix/store`, and that way stays open.
pub fn passes_host_services(place: &Path, host: &HostInfo, this: &ThisStart) -> bool {
    host_services_at(place, host, this, false)
}

/// [`leads_to_host_services`] (`holds`: also a folder holding such a place)
/// and [`passes_host_services`] (only what lies in one).
fn host_services_at(real: &Path, host: &HostInfo, this: &ThisStart, holds: bool) -> bool {
    let under = |d: &str| real.starts_with(d);
    let at_or_holds = |d: &Path| real.starts_with(d) || (holds && d.starts_with(real));
    let homes = [host.home.clone(), resolve(&host.home)];
    let in_home_kept_in = |t: &Path| {
        homes
            .iter()
            .any(|h| h.starts_with(t) && h != t && real.starts_with(h))
    };
    let temp = ["/tmp", "/var/tmp"]
        .iter()
        .map(Path::new)
        .any(|t| at_or_holds(t) && !in_home_kept_in(t));
    let runtime = host
        .runtime_dir
        .iter()
        .chain(&this.sam_runtime)
        .flat_map(|r| [r.clone(), resolve(r)])
        .filter(|r| r.is_absolute() && !homes.iter().any(|h| h.starts_with(r)))
        .any(|r| at_or_holds(&r));
    let system = real == Path::new("/") || (under("/run") && !under("/run/media"));
    (holds && system)
        || crate::risk::shows_host_sockets(&real.to_string_lossy())
        || temp
        || runtime
        || under("/proc")
        || under("/dev")
}

/// Why SAM leaves out a place it would bind where its links lead: an extra
/// folder (`filesystem.custom_read`, `custom_write`) or a user folder.
/// The places of the home SAM shows on its own (the fonts, the fonts
/// settings, the theme files) follow no link at all
/// ([`own_place_decision`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeftOut {
    /// The way there holds this link, in a folder the app can change, and
    /// leads out of what the app is shown: the app may have made the link
    /// in an earlier start (`ln -s /tmp/tmux-1000 ~/.fonts`).
    Link(PathBuf),
    /// Through a link it leads to this place, or passes it on the way,
    /// where programs outside the sandbox listen ([`leads_to_host_services`],
    /// [`passes_host_services`]), whoever made the link.
    HostServices(PathBuf),
}

/// The folders the app can change in a start with the permissions `p`,
/// each where it really is: the whole home when writable (as named and as
/// reached), the writable user folders, the writable extra folders and
/// the folders `this` start shows writable besides them (writable opened
/// folders, SAM's writable binds); never the user folder `without`
/// (judged for itself, [`user_folder_left_out`]). Judged from the
/// permissions alone, so the sandbox, its check and the app page take one
/// answer: a writable extra folder counts writable also where the sandbox
/// shows it read-only (inside a start place), which leaves out more,
/// never less. A user folder in a writable home counts as one the app can
/// change whatever its own switch says: the app may have changed it
/// through the home in an earlier start, before it was set read-only, and
/// one the sandbox refuses is shown through the home, writable (with the
/// home writable and Downloads read-only, a link the app made in
/// `~/Downloads` was followed out of what it is shown). Whether a place
/// is shown writable is another question, which [`shows_writable`]
/// answers as the sandbox mounts it: there a read-only user folder is
/// read-only, also under a writable home.
///
/// A read-only grant never makes a folder one the app cannot change: it
/// may lead there through a link the app planted itself. With the whole
/// home writable and `~/x` an extra read-only folder, the app made `~/x` a
/// link to `~/.local/share` and `~/.local/share/fonts` a link to a folder
/// it is not shown; counted read-only by `~/x`, `~/.local/share` hid the
/// second link, and the next start bound that folder as the fonts.
fn writable_grants(
    p: &PermissionSet,
    host: &HostInfo,
    without: Option<&str>,
    this: &ThisStart,
) -> Vec<PathBuf> {
    use crate::permissions::Access;
    let fs = &p.filesystem;
    let home_rw = fs.home && fs.home_access == Access::Rw;
    let mut grants: Vec<PathBuf> = Vec::new();
    if home_rw {
        grants.push(host.home.clone());
        grants.push(resolve(&host.home));
    }
    for key in XDG_DIR_KEYS.iter().filter(|k| Some(**k) != without) {
        let acc = fs.xdg_access(key);
        if acc.is_granted() {
            if let Some(real) = host
                .xdg_dir(key)
                .and_then(|d| user_folder_place(d, &host.home))
            {
                if acc == Access::Rw || (home_rw && in_home(host, &real)) {
                    grants.push(real);
                }
            }
        }
    }
    for c in &fs.custom_write {
        grants.push(resolve(&crate::util::expand_home(c)));
    }
    grants.extend(this.writable.iter().map(|w| resolve(w)));
    grants
}

/// Whether `real` lies in the home of `host`, as named or where it really
/// is.
fn in_home(host: &HostInfo, real: &Path) -> bool {
    real.starts_with(&host.home) || real.starts_with(resolve(&host.home))
}

/// Whether the whole home shows `leads` at all, as a read-only bind there
/// needs it.
fn home_shows(p: &PermissionSet, host: &HostInfo, leads: &Path) -> bool {
    p.filesystem.home && in_home(host, leads)
}

/// Whether a start with the permissions `p` shows `leads` writable, as a
/// writable bind there needs it: the deepest of the places the sandbox
/// shows that holds `leads` decides, read-only winning a tie, each at the
/// access the sandbox shows it at. Those places are the whole home (as
/// named and as reached), each granted user folder where it really is, at
/// [`user_folder_access`] (Documents set to read-only is read-only under a
/// writable home; Music read and write and Pictures read-only, both set to
/// `~/Media`, are both read-only there), and the extra read-only folders.
/// With the home writable and Documents read-only, a writable extra folder
/// `~/x` the app made a link to `~/Documents/Taxes` was followed because
/// the home counted as showing everything in it writable, and the next
/// start bound `~/Documents/Taxes` writable inside the read-only Documents.
///
/// Asked for an extra folder (`without` is `None`), a user folder counts
/// only where the sandbox shows it ([`user_folder_refused`]), and an extra
/// read-only folder only where it is not left out itself
/// ([`linked_place_left_out`]): one it does not mount is shown by the
/// folders around it. Asked for the user folder `without`
/// ([`user_folder_left_out`]), whose rule the sandbox asks for every user
/// folder, no other user folder makes a place writable (as before, the
/// home alone does), and every other granted user folder and extra
/// read-only folder makes a place read-only wherever it is set: judging
/// whether the sandbox shows them would ask this rule again. Both leave
/// out more, never less. A user folder inside SAM's own folders, which
/// the sandbox refuses, may count as showing a place writable there; an
/// extra writable folder that leads there is not bound anyway
/// ([`write_grant_in_sams_folders`]).
fn shows_writable(
    p: &PermissionSet,
    host: &HostInfo,
    leads: &Path,
    without: Option<&str>,
    this: &ThisStart,
) -> bool {
    use crate::permissions::Access;
    let fs = &p.filesystem;
    let mut shows: Vec<(PathBuf, bool)> = Vec::new();
    if fs.home {
        let rw = fs.home_access == Access::Rw;
        shows.push((host.home.clone(), rw));
        shows.push((resolve(&host.home), rw));
    }
    for key in XDG_DIR_KEYS.iter().filter(|k| Some(**k) != without) {
        if !fs.xdg_access(key).is_granted() {
            continue;
        }
        let Some(real) = host
            .xdg_dir(key)
            .and_then(|d| user_folder_place(d, &host.home))
        else {
            continue;
        };
        let rw = user_folder_access(p, host, key) == Access::Rw;
        let counts = match without {
            None => user_folder_refused(p, host, key, this).is_none(),
            Some(_) => !rw,
        };
        if counts {
            shows.push((real, rw));
        }
    }
    for c in &fs.custom_read {
        let named = crate::util::expand_home(c);
        if without.is_some() || linked_place_left_out(p, host, &named, false, this).is_none() {
            shows.push((resolve(&named), false));
        }
    }
    shows
        .iter()
        .filter(|(g, _)| leads.starts_with(g))
        .map(|(g, rw)| (g.components().count(), !rw))
        .max()
        .is_some_and(|(_, read_only)| !read_only)
}

/// The rule for a bind where the links of `way` lead ([`linked_place_left_out`],
/// [`user_folder_left_out`]): `writable` names the folders the app can
/// change ([`writable_grants`]), `shown` whether the place the way leads to
/// is shown anyway; `host` and `this` say where programs outside the
/// sandbox listen ([`leads_to_host_services`]). Where a way both leads
/// through a planted link and to such a place, the answer is the place
/// ([`LeftOut::HostServices`]), whose note names the danger and no way
/// out; only a way stuck at a link Linux would not follow answers with
/// that link first.
fn left_out_by_rule(
    way: Way,
    writable: &[PathBuf],
    shown: &dyn Fn(&Path) -> bool,
    host: &HostInfo,
    this: &ThisStart,
) -> Option<LeftOut> {
    // Any writable grant that shows a folder makes it one the app can
    // change, also below a deeper read-only one: the app may have made
    // that grant lead there itself ([`writable_grants`]). This leaves out
    // more, never less.
    let can_change = |d: &Path| writable.iter().any(|g| d.starts_with(g));
    let planted = link_the_app_could_plant(&way, &can_change);
    // A way that ends at a link Linux would not follow leads nowhere SAM
    // can judge: the link is the answer.
    if let Some(link) = planted.as_ref().filter(|_| way.stuck) {
        return Some(LeftOut::Link(link.clone()));
    }
    // Before a planted link: where both refuse, the note names the danger
    // and gives no way out. The note for a planted link tells the person
    // to show the place it leads to, and for `/tmp/tmate-1000` that handed
    // tmate's socket to the app (with the whole home writable and
    // Downloads a link there).
    if !way.links.is_empty() && leads_to_host_services(&way.leads, host, this) {
        return Some(LeftOut::HostServices(way.leads));
    }
    // Where the way ends is not all: a link in `/tmp` the host made may
    // send it on to a socket folder SAM does not know by its place. A link
    // that only points into such a place either ends there (judged above)
    // or meets the next link there.
    if let Some(link) = way
        .links
        .iter()
        .find(|link| passes_host_services(link, host, this))
    {
        return Some(LeftOut::HostServices(link.clone()));
    }
    match planted {
        Some(link) if !shown(&way.leads) => Some(LeftOut::Link(link)),
        _ => None,
    }
}

/// Whether SAM leaves out the place `named` (with `~` expanded) that it
/// binds where its links lead, in a start with the permissions `p`: an
/// extra folder, read-only or writable (`write`). One rule for every such
/// bind, so no bind follows a link the app could have planted to a place
/// it must not reach:
/// - a link on the way that lies in a folder the app can change
///   ([`writable_grants`]: any writable grant shows it, also below a
///   read-only one, or `this` start shows it writable) is not followed
///   out of what the whole home and the user folders show, and
///   for a writable bind out of what they and the extra read-only folders
///   show writable, each at the access the sandbox shows it at
///   ([`shows_writable`]: Documents set to read-only is read-only under a
///   writable home) (with the whole
///   home writable, `~/.fonts` missing and an extra folder not made yet,
///   the app made them links to `/tmp/tmux-1000` or any folder on the
///   computer, and the next start bound what they named; with the home
///   read-only, a writable extra folder in a writable user folder made a
///   link to the home bound the whole home writable);
/// - a link that leads to a place where programs outside the sandbox listen
///   ([`leads_to_host_services`]: anything in `/tmp` and `/var/tmp`, the
///   host's and SAM's runtime folders wherever they are), or whose way
///   passes a link in such a place ([`passes_host_services`]: a link in
///   `/tmp` that sends the way on elsewhere, a way through `/proc`), is
///   not followed, whoever made it: that place is bound over the sandbox's
///   own `/tmp` or runtime folder and hands their sockets over.
///
/// An extra folder named by its real place (no link on the way) is shown
/// as written: its name was rated, and warned about, as it is.
pub fn linked_place_left_out(
    p: &PermissionSet,
    host: &HostInfo,
    named: &Path,
    write: bool,
    this: &ThisStart,
) -> Option<LeftOut> {
    let fs = &p.filesystem;
    let shown = |leads: &Path| {
        if write {
            return shows_writable(p, host, leads, None, this);
        }
        home_shows(p, host, leads)
            || XDG_DIR_KEYS.iter().any(|key| {
                fs.xdg_access(key).is_granted()
                    && user_folder_left_out(p, host, key, this).is_none()
                    && host
                        .xdg_dir(key)
                        .and_then(|d| user_folder_place(d, &host.home))
                        .is_some_and(|real| leads.starts_with(&real))
            })
    };
    let writable = writable_grants(p, host, None, this);
    left_out_by_rule(follow(named), &writable, &shown, host, this)
}

/// Whether SAM leaves out the user folder `key` (Documents, Downloads, …)
/// that it binds on its own where `user-dirs.dirs` and its links lead
/// (in a private home, or writable in a read-only home), by the same rule
/// as [`linked_place_left_out`]: a link on the way that lies in a folder
/// the app can change (not counting this folder's own grant) is followed
/// only into a home shown as the folder needs it (for a writable folder,
/// not into another user folder or an extra folder set read-only there,
/// [`shows_writable`]), and a link to where
/// programs outside the sandbox listen never. `~/Sync/Documents`, missing
/// while `~/Sync` was granted writable, was made a link to
/// `/tmp/tmux-1000`, and the next start bound the host's tmux sockets.
pub fn user_folder_left_out(
    p: &PermissionSet,
    host: &HostInfo,
    key: &str,
    this: &ThisStart,
) -> Option<LeftOut> {
    let dir = host.xdg_dir(key)?;
    let write = p.filesystem.xdg_access(key) == crate::permissions::Access::Rw;
    let shown = |leads: &Path| match write {
        true => shows_writable(p, host, leads, Some(key), this),
        false => home_shows(p, host, leads),
    };
    let writable = writable_grants(p, host, Some(key), this);
    left_out_by_rule(follow(dir), &writable, &shown, host, this)
}

/// Why SAM does not show the granted user folder `key` although the
/// person set it, by the rules about links and about places where
/// programs outside the sandbox listen ([`user_folder_refused`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserFolderRefused {
    /// Its way leads through a link the app could have planted out of what
    /// the home shows, or to where programs outside the sandbox listen
    /// ([`user_folder_left_out`]).
    LeftOut(LeftOut),
    /// Its way holds this link in a folder the app can change
    /// ([`user_folder_link_the_app_can_change`]).
    Link(PathBuf),
    /// It is `/tmp` or a folder there known by its name as one where
    /// programs outside the sandbox listen
    /// ([`crate::risk::shows_host_sockets`]).
    Sockets,
}

/// Whether SAM refuses the user folder `key` for a link or for programs
/// listening there, and why, in the order the sandbox asks: first
/// [`user_folder_left_out`], whose note names the danger (a link to where
/// programs outside the sandbox listen, with no way out) or the link the
/// app could have planted and how to show the folder if the person made
/// it, then [`user_folder_link_the_app_can_change`], whose note names
/// only the link, then the socket folders by name, whose note says to set
/// the folder to one of its own. One answer for the sandbox, which leaves the
/// folder out, and the app page and `sam-jail info`, which name it before
/// the start with the same words ([`user_folder_refused_note`]). Told only
/// in the launch log, a Downloads set to a link to `/tmp/dl` (so
/// downloads clear themselves) looked as before on the app page, while
/// what the app saved there was gone when it quit. `this` is what the
/// start adds ([`ThisStart`]); the app page cannot know the folders a
/// start opens, so it passes only SAM's runtime folders and may name a
/// little less than the start refuses.
pub fn user_folder_refused(
    p: &PermissionSet,
    host: &HostInfo,
    key: &str,
    this: &ThisStart,
) -> Option<UserFolderRefused> {
    let dir = host.xdg_dir(key)?;
    if let Some(why) = user_folder_left_out(p, host, key, this) {
        return Some(UserFolderRefused::LeftOut(why));
    }
    if let Some(link) = user_folder_link_the_app_can_change(p, host, dir) {
        return Some(UserFolderRefused::Link(link));
    }
    if crate::risk::shows_host_sockets(&resolve(dir).to_string_lossy()) {
        return Some(UserFolderRefused::Sockets);
    }
    None
}

/// What the start, the app page and `sam-jail info` say about the user
/// folder `key` set to `dir` that SAM refuses for `why`
/// ([`user_folder_refused`]); `write`: the folder is set to read and
/// write.
pub fn user_folder_refused_note(
    key: &str,
    dir: &Path,
    why: &UserFolderRefused,
    write: bool,
) -> String {
    match why {
        UserFolderRefused::LeftOut(why) => left_out_note(
            &crate::util::tildify(dir),
            why,
            LeftOutPlace::UserFolder,
            write,
        ),
        UserFolderRefused::Link(link) => user_folder_link_note(key, dir, link),
        UserFolderRefused::Sockets => user_folder_sockets_note(key, dir),
    }
}

/// Every guarded place a font or theme place that no grant shows must
/// never hold ([`own_place_decision`]): the protected places, the key
/// folders and the credential stores of the home `home`, each under the
/// home as named, under its real place and where it really leads, and
/// SAM's own folders (`sams`), as named and where they lead. The protected
/// places and the credential stores follow `XDG_CONFIG_HOME` and
/// `XDG_DATA_HOME` ([`protected_places`], [`sensitive_places`]), also
/// where those folders lie outside the home (`XDG_CONFIG_HOME=/data/cfg`).
/// In a private home `~/.git-credentials` kept as a link into
/// `~/.fonts/dots` is hidden nowhere else: the sandbox shows no name of
/// that link to mask.
pub fn guarded_places_everywhere(home: &Path, sams: &[PathBuf]) -> Vec<PathBuf> {
    let var = |v: &str| std::env::var_os(v).map(PathBuf::from);
    guarded_places_everywhere_with(home, sams, var("XDG_CONFIG_HOME"), var("XDG_DATA_HOME"))
}

/// [`guarded_places_everywhere`] with `XDG_CONFIG_HOME` and
/// `XDG_DATA_HOME` given.
pub fn guarded_places_everywhere_with(
    home: &Path,
    sams: &[PathBuf],
    config: Option<PathBuf>,
    data: Option<PathBuf>,
) -> Vec<PathBuf> {
    guarded_places_with(home, sams, config, data, true)
}

/// The places of [`guarded_places_everywhere`] by their names only: each
/// guarded name under the home as named and under its real place, under
/// `XDG_CONFIG_HOME` and `XDG_DATA_HOME` as set and under their real
/// place, and SAM's folders as configured, never where a link at such a
/// name leads. A font or theme place that no grant shows is never bound
/// at or inside one of them ([`own_place_decision`]). Where links lead
/// does not count here: anyone who can write in the home can make
/// `~/.aws` a link to the home, which puts the whole home on
/// [`guarded_places_everywhere`], and every font place lies inside it.
pub fn guarded_places_named(home: &Path, sams: &[PathBuf]) -> Vec<PathBuf> {
    let var = |v: &str| std::env::var_os(v).map(PathBuf::from);
    guarded_places_named_with(home, sams, var("XDG_CONFIG_HOME"), var("XDG_DATA_HOME"))
}

/// [`guarded_places_named`] with `XDG_CONFIG_HOME` and `XDG_DATA_HOME`
/// given.
pub fn guarded_places_named_with(
    home: &Path,
    sams: &[PathBuf],
    config: Option<PathBuf>,
    data: Option<PathBuf>,
) -> Vec<PathBuf> {
    guarded_places_with(home, sams, config, data, false)
}

/// The guarded places of [`guarded_places_everywhere`] (`leads`: also
/// where each one really leads) or of [`guarded_places_named`].
fn guarded_places_with(
    home: &Path,
    sams: &[PathBuf],
    config: Option<PathBuf>,
    data: Option<PathBuf>,
    leads: bool,
) -> Vec<PathBuf> {
    let homes = [home.to_path_buf(), resolve(home)];
    let rels = protected_places_with(home, config.clone(), data.clone())
        .into_iter()
        .chain(sensitive_places_with(home, config.clone(), data.clone()))
        .chain([".ssh".to_string(), ".gnupg".to_string()]);
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |at: PathBuf| {
        let real = leads.then(|| resolve(&at));
        for g in real.into_iter().chain([at]) {
            if !out.contains(&g) {
                out.push(g);
            }
        }
    };
    for rel in rels {
        for h in &homes {
            add(h.join(&rel));
        }
    }
    // Where those folders lie, also outside the home, which the lists
    // above, relative to the home, do not reach: with
    // `XDG_CONFIG_HOME=/data/cfg`, `~/.fonts` made a link to `/data/cfg/gh`
    // in an earlier start with the whole home writable was bound in a
    // private home. As named and where they lead.
    for (dir, default) in [(config, ".config/"), (data, ".local/share/")] {
        let Some(dir) = dir.filter(|d| d.is_absolute()) else {
            continue;
        };
        for p in PROTECTED_RO.iter().chain(SENSITIVE_DOTFILES) {
            if let Some(rest) = p.strip_prefix(default) {
                add(dir.join(rest));
                add(resolve(&dir).join(rest));
            }
        }
    }
    // SAM's own folders, like the places above: as named and where they
    // lead (through a link in the way, also the home kept behind a link:
    // the part that exists is resolved, the rest appended). As named only,
    // a folder named through a link was not guarded where it really is:
    // with the unpack folder set to `~/Apps/sam` and `~/Apps` a link to
    // `/mnt/disk/Apps`, a font folder holding `/mnt/disk/Apps/sam` showed
    // every unpacked app in a private home.
    for s in sams {
        add(s.clone());
    }
    out
}

/// The places of the home (relative to it) that SAM shows an app with the
/// permissions `p` on its own, read-only: the fonts, the fonts settings
/// and, with `advanced.host_themes` and without the whole home, the theme
/// files. Each only where neither it nor a folder on its way in the home
/// is a link ([`own_place_decision`]). The sandbox, its check and the app
/// page take the same list.
pub fn own_home_places(p: &PermissionSet) -> Vec<&'static str> {
    let mut own: Vec<&'static str> = vec![".local/share/fonts", ".fonts", ".config/fontconfig"];
    if p.advanced.host_themes && !p.filesystem.home {
        own.extend(THEME_FILES);
    }
    own
}

/// Host theme configuration (read-only) when `advanced.host_themes` is on.
pub const THEME_FILES: &[&str] = &[
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

/// A link on the way to a place SAM shows on its own ([`own_place_way`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnPlaceLink {
    /// The link, under the home as the person names it (`~/.config`).
    pub link: PathBuf,
    /// Whether the place can be reached through the link.
    pub exists: bool,
    /// Where the link leads, every link followed ([`follow`]).
    pub leads: PathBuf,
    /// What the link itself says (`dotfiles/config`): named for a link
    /// that leads nowhere now.
    pub says: PathBuf,
}

/// The way from the home to a place SAM shows on its own
/// ([`own_place_way`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnPlaceWay {
    /// No part below the home's real place is a link: every folder on the
    /// way is a real folder, and the place a folder or a regular file.
    Plain,
    /// A part is missing, a part on the way is no folder, or the place is
    /// neither a folder nor a regular file (a named pipe, a socket, a
    /// device): nothing to bind. Also a link on the way behind which the
    /// place does not exist.
    Missing,
    /// The place itself, or a folder on its way below the home's real
    /// place, is this link.
    Link(OwnPlaceLink),
}

/// The way from the home `home` to its place `rel` (one of SAM's fixed
/// names, never with `..` or `.`), one part at a time from the home's
/// real place, never following a link ([`OwnPlaceWay`]). A link that
/// holds the home itself (`/home/u` a link to `/data/u`, or Fedora
/// Atomic's `/home` a link to `/var/home`) is part of the home's real
/// place and never counts: such a home keeps its fonts. Below it, a link
/// counts whoever made it and wherever it leads: anyone who can write in
/// the home (another app with the whole home writable, or an earlier
/// start with more rights) can make `~/.fonts` a link to any folder, and
/// a private home would show that folder as the fonts.
pub fn own_place_way(home: &Path, rel: &str) -> OwnPlaceWay {
    let real_home = resolve(home);
    let parts: Vec<Component> = Path::new(rel).components().collect();
    if parts.is_empty() {
        return OwnPlaceWay::Missing;
    }
    let mut prefix = PathBuf::new();
    for (i, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return OwnPlaceWay::Missing;
        };
        prefix.push(name);
        let at = real_home.join(&prefix);
        let Ok(m) = std::fs::symlink_metadata(&at) else {
            return OwnPlaceWay::Missing;
        };
        let last = i + 1 == parts.len();
        if m.file_type().is_symlink() {
            let exists = std::fs::metadata(real_home.join(rel)).is_ok();
            // Nothing to name behind a link on the way that leads
            // nowhere, or to a folder without the place.
            if !last && !exists {
                return OwnPlaceWay::Missing;
            }
            return OwnPlaceWay::Link(OwnPlaceLink {
                link: home.join(&prefix),
                exists,
                leads: follow(&at).leads,
                says: std::fs::read_link(&at).unwrap_or_default(),
            });
        }
        let fits = if last {
            m.is_dir() || m.is_file()
        } else {
            m.is_dir()
        };
        if !fits {
            return OwnPlaceWay::Missing;
        }
    }
    OwnPlaceWay::Plain
}

/// What SAM does with a place of the home it shows on its own
/// ([`own_place_decision`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnBind {
    /// Bound read-only.
    Bind,
    /// Not there: nothing to bind, nothing to say.
    Missing,
    /// The place, or a folder on its way in the home, is a link: SAM does
    /// not bind it on its own and names the link.
    Link(OwnPlaceLink),
    /// No grant shows the place at its name, and it holds this guarded
    /// place, by its name or where a link at a guarded name really leads:
    /// SAM binds it only where a grant shows it under another name, which
    /// takes write access away and shows nothing new.
    Holds(PathBuf),
    /// No grant shows the place at its name, and it lies in this guarded
    /// place, by its name: bound as for [`OwnBind::Holds`].
    Inside(PathBuf),
}

/// What SAM does with the place `rel` of the home that it shows on its
/// own (the fonts, the fonts settings, the theme files), read-only:
/// - where the place, or a folder on its way below the home's real place,
///   is a link ([`own_place_way`]), nothing, whoever made the link and
///   wherever it leads, and the start names the link
///   ([`own_place_links_note`]);
/// - where a grant of this start shows the place already at its name
///   (`shown`: the whole home, an extra folder or a user folder above it,
///   an opened folder, a bind of SAM's), a read-only bind where the app
///   reaches it: it shows nothing new, it only takes write access away,
///   and the protections inside come after it. A link at a guarded name
///   that leads into the place (`~/.config/vivaldi` made a link to
///   `~/.config/fontconfig` with an extra writable `~/.config`) cannot
///   knock that bind out;
/// - where no grant shows it at its name (a private home), a read-only
///   bind at its name only when the place lies in no guarded place by its
///   name (`guarded_named`, [`guarded_places_named`]) and holds none, as
///   named or where a link at a guarded name really leads
///   (`guarded_everywhere`, [`guarded_places_everywhere`]):
///   `~/.git-credentials` kept as a link into `~/.fonts/dots` stays
///   hidden, since the private home shows no name of that link where it
///   could be masked. Also where a grant shows the place only under
///   another name: with the home kept behind a link (`/home/u` a link to
///   `/data/u`) and an extra `~/.config`, that grant is recorded at
///   `/data/u/.config`, and a second bind at the home's name in the
///   private home is a mount of its own that the home's protections at
///   `/data/u` never reach ([`OwnBind::Holds`] binds only where the grant
///   shows it).
pub fn own_place_decision(
    host: &HostInfo,
    rel: &str,
    shown: &dyn Fn(&Path) -> bool,
    guarded_named: &[PathBuf],
    guarded_everywhere: &[PathBuf],
) -> OwnBind {
    match own_place_way(&host.home, rel) {
        OwnPlaceWay::Missing => OwnBind::Missing,
        OwnPlaceWay::Link(link) => OwnBind::Link(link),
        OwnPlaceWay::Plain => {
            let named = host.home.join(rel);
            if shown(&named) {
                return OwnBind::Bind;
            }
            let real = resolve(&host.home).join(rel);
            if let Some(g) = guarded_named
                .iter()
                .find(|g| named.starts_with(g) || real.starts_with(g))
            {
                return OwnBind::Inside(g.clone());
            }
            if let Some(g) = guarded_everywhere
                .iter()
                .find(|g| g.starts_with(&named) || g.starts_with(&real))
            {
                return OwnBind::Holds(g.clone());
            }
            OwnBind::Bind
        }
    }
}

/// What the grants of a start show, judged from its permissions alone, as
/// the sandbox records them without the folders opened with the app and
/// SAM's own binds: the whole home as named, the user folders it shows
/// where they really are, the extra read-only folders it does not leave
/// out and the extra writable folders it binds, each at the access the
/// sandbox shows it at. The app page and the sandbox check decide about
/// the fonts and theme files from it ([`own_places_from_settings`]); a
/// test holds it to the sandbox's own answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantsShown {
    /// Each grant where it is recorded, and whether it is writable.
    pub grants: Vec<(PathBuf, bool)>,
}

impl GrantsShown {
    /// The grants of a start with the permissions `p`, with SAM's folders
    /// `sams` ([`sams_folders`]) and what the start adds (`this`).
    pub fn of(p: &PermissionSet, host: &HostInfo, sams: &[PathBuf], this: &ThisStart) -> Self {
        let fs = &p.filesystem;
        let mut grants: Vec<(PathBuf, bool)> = Vec::new();
        if fs.home {
            grants.push((host.home.clone(), fs.home_access == Access::Rw));
        }
        for key in XDG_DIR_KEYS {
            let acc = user_folder_access(p, host, key);
            let Some(dir) = host.xdg_dir(key).filter(|_| acc.is_granted()) else {
                continue;
            };
            if user_folder_refused(p, host, key, this).is_some() {
                continue;
            }
            if let Some(real) =
                user_folder_place(dir, &host.home).filter(|r| !inside_sams_folders(r, sams))
            {
                grants.push((real, acc == Access::Rw));
            }
        }
        for c in &fs.custom_read {
            let named = crate::util::expand_home(c);
            if linked_place_left_out(p, host, &named, false, this).is_none() {
                grants.push((resolve(&named), false));
            }
        }
        let mut writes: Vec<(PathBuf, bool)> = Vec::new();
        for c in &fs.custom_write {
            let written = crate::util::expand_home(c);
            let bound = resolve(&written);
            if linked_place_left_out(p, host, &written, true, this).is_some() {
                continue;
            }
            let place = start_place_of_bound_write_grant(&written, &bound, &host.home);
            if write_grant_in_sams_folders(&bound, place.as_ref(), sams, &host.home) {
                continue;
            }
            writes.push((bound, place.is_none()));
        }
        // One below a folder the app can already change (shown writable
        // under any of its names, or in SAM's folders) is not bound: the
        // grant above shows it, as the sandbox decides it.
        let all = GrantsShown {
            grants: grants.iter().chain(&writes).cloned().collect(),
        };
        let can_change = |d: &Path| {
            all.names_of(d)
                .iter()
                .any(|c| all.deepest(c).is_some_and(|(_, w)| *w))
                || inside_sams_folders(d, sams)
        };
        grants.extend(
            writes
                .into_iter()
                .filter(|(bound, rw)| !*rw || !bound.parent().is_some_and(can_change)),
        );
        GrantsShown { grants }
    }

    /// The deepest grant that shows `p` by its own path.
    fn deepest(&self, p: &Path) -> Option<&(PathBuf, bool)> {
        self.grants
            .iter()
            .filter(|(g, _)| p.starts_with(g))
            .max_by_key(|(g, _)| g.components().count())
    }

    /// Every name under which a grant shows host path `at`: its own path,
    /// its resolved one and, for a grant kept behind a link, the resolved
    /// one under the grant's own name.
    fn names_of(&self, at: &Path) -> Vec<PathBuf> {
        let real = resolve(at);
        let mut out = vec![at.to_path_buf(), real.clone()];
        for (g, _) in &self.grants {
            let rg = resolve(g);
            if rg != *g {
                if let Ok(rest) = real.strip_prefix(&rg) {
                    out.push(g.join(rest));
                }
            }
        }
        out.retain(|c| self.deepest(c).is_some());
        out
    }

    /// Whether some grant shows host path `at`, under any of its names.
    pub fn shows(&self, at: &Path) -> bool {
        !self.names_of(at).is_empty()
    }

    /// Whether some grant shows host path `at` at that very name, where a
    /// bind of SAM's at that name only narrows it ([`own_place_decision`]).
    pub fn shows_at_name(&self, at: &Path) -> bool {
        self.deepest(at).is_some()
    }

    /// Whether SAM keeps the place `target` (links resolved), behind a
    /// link at a font or theme place, read-only where a grant shows it
    /// writable: strictly inside a writable grant, never the grant's own
    /// place, the home or a folder above it ([`own_place_links_note`]).
    /// Never where a name SAM would bind the target at is not valid text
    /// (always so for a target by such a name): the sandbox makes no such
    /// bind and only names the link, so the start is never stopped by a
    /// planted name.
    pub fn keeps_read_only(&self, home: &Path, target: &Path) -> bool {
        let real_home = resolve(home);
        let at: Vec<PathBuf> = self
            .names_of(target)
            .into_iter()
            .filter(|c| {
                !(home.starts_with(c) || real_home.starts_with(c))
                    && self.deepest(c).is_some_and(|(g, rw)| *rw && g != c)
            })
            .collect();
        !at.is_empty() && at.iter().all(|c| c.to_str().is_some())
    }
}

/// What SAM decides for each place of the home it shows on its own in a
/// start with the permissions `p` ([`own_home_places`],
/// [`own_place_decision`]), judged from the permissions alone
/// ([`GrantsShown`]), with SAM's folders `sams` ([`sams_folders`]). The
/// sandbox check and the app page take it; a start that opens a folder
/// may bind a little more, never show more.
pub fn own_places_from_settings(
    p: &PermissionSet,
    host: &HostInfo,
    sams: &[PathBuf],
    this: &ThisStart,
) -> Vec<(&'static str, OwnBind)> {
    let shown = GrantsShown::of(p, host, sams, this);
    let named = guarded_places_named(&host.home, sams);
    let everywhere = guarded_places_everywhere(&host.home, sams);
    own_home_places(p)
        .into_iter()
        .map(|rel| {
            let d = own_place_decision(
                host,
                rel,
                &|at| shown.shows_at_name(at),
                &named,
                &everywhere,
            );
            (rel, d)
        })
        .collect()
}

/// The note the start writes, and the app page shows, for the places of
/// the home SAM shows on its own that are links in a start with the
/// permissions `p`, judged from the permissions alone
/// ([`own_places_from_settings`], [`own_place_links_note`]).
pub fn own_place_links_note_from_settings(
    p: &PermissionSet,
    host: &HostInfo,
    sams: &[PathBuf],
    this: &ThisStart,
) -> Option<String> {
    let shown = GrantsShown::of(p, host, sams, this);
    let real_home = resolve(&host.home);
    let mut skipped = Vec::new();
    let mut kept: Vec<PathBuf> = Vec::new();
    for (rel, d) in own_places_from_settings(p, host, sams, this) {
        let OwnBind::Link(link) = d else {
            continue;
        };
        if link.exists {
            let target = resolve(&real_home.join(rel));
            if shown.keeps_read_only(&host.home, &target) && !kept.contains(&target) {
                kept.push(target);
            }
        }
        skipped.push(OwnLinkSkipped {
            rel,
            shown: shown.shows(&host.home.join(rel)),
            link,
        });
    }
    own_place_links_note(host, this, &skipped, &kept)
}

/// A place of the home SAM shows on its own that it does not bind for a
/// link ([`OwnBind::Link`]), for [`own_place_links_note`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnLinkSkipped {
    /// The place, relative to the home.
    pub rel: &'static str,
    /// The link.
    pub link: OwnPlaceLink,
    /// Whether a grant of this start shows the place anyway.
    pub shown: bool,
}

/// `p` with the home `home` written `~`, under its name and under its
/// real place.
fn tilde_in(home: &Path, p: &Path) -> String {
    for h in [home.to_path_buf(), resolve(home)] {
        match p.strip_prefix(&h) {
            Ok(rest) if rest.as_os_str().is_empty() => return "~".into(),
            Ok(rest) => return format!("~/{}", rest.display()),
            Err(_) => {}
        }
    }
    p.display().to_string()
}

/// The one note per start that names every place of the home SAM shows
/// on its own and does not bind for a link (`skipped`), in the order of
/// [`own_home_places`], the places behind one link together: each link
/// and where it leads, a link that leads nowhere now as the link says it,
/// and for a link to where programs outside the sandbox listen that
/// danger ([`leads_to_host_services`], [`passes_host_services`]). It
/// never says the place is hidden: a grant may still show it through the
/// link. It says how to show the files only where no grant shows the
/// place (with the whole home the advice would mislead), and which places
/// behind such links SAM keeps read-only (`kept`) where a writable grant
/// shows them. `None` when nothing was skipped.
pub fn own_place_links_note(
    host: &HostInfo,
    this: &ThisStart,
    skipped: &[OwnLinkSkipped],
    kept: &[PathBuf],
) -> Option<String> {
    if skipped.is_empty() {
        return None;
    }
    let home = &host.home;
    let t = |p: &Path| tilde_in(home, p);
    let mut groups: Vec<(&OwnPlaceLink, Vec<&str>)> = Vec::new();
    for s in skipped {
        match groups.iter_mut().find(|(l, _)| l.link == s.link.link) {
            Some((_, rels)) => rels.push(s.rel),
            None => groups.push((&s.link, vec![s.rel])),
        }
    }
    let items: Vec<String> = groups
        .iter()
        .map(|(l, rels)| {
            let places = rels
                .iter()
                .map(|r| format!("~/{r}"))
                .collect::<Vec<_>>()
                .join(", ");
            let itself = rels.len() == 1 && home.join(rels[0]) == l.link;
            let listen = leads_to_host_services(&l.leads, host, this)
                || follow(&l.link)
                    .links
                    .iter()
                    .any(|k| passes_host_services(k, host, this));
            let target = t(&l.leads);
            let args: &[(&str, &dyn std::fmt::Display)] = &[
                ("place", &places),
                ("places", &places),
                ("link", &t(&l.link)),
                ("target", &target),
            ];
            match (itself, listen) {
                (true, true) => crate::i18n::trf(
                    "{place} (a link to {target}, where programs outside the sandbox listen)",
                    args,
                ),
                (true, false) if !l.exists => crate::i18n::trf(
                    "{place} (a link to {target}, which leads nowhere now)",
                    &[("place", &places), ("target", &l.says.display())],
                ),
                (true, false) => crate::i18n::trf("{place} (a link to {target})", args),
                (false, true) => crate::i18n::trf(
                    "{places} (behind {link}, a link to {target}, where programs outside the sandbox listen)",
                    args,
                ),
                (false, false) => {
                    crate::i18n::trf("{places} (behind {link}, a link to {target})", args)
                }
            }
        })
        .collect();
    let mut note = crate::i18n::trf(
        "SAM does not bind {items} for this app on its own: each is a link, or lies behind a link, in your home, and SAM does not follow such a link for your fonts and theme files.",
        &[("items", &items.join("; "))],
    );
    note.push(' ');
    note.push_str(&crate::i18n::tr(
        "The app still sees what its other folders show there.",
    ));
    if skipped.iter().any(|s| !s.shown) {
        note.push(' ');
        note.push_str(&crate::i18n::tr(
            "If you made the link yourself, keeping the real files at that place lets SAM show them.",
        ));
    }
    if !kept.is_empty() {
        let targets = kept.iter().map(|k| t(k)).collect::<Vec<_>>().join(", ");
        note.push(' ');
        note.push_str(&crate::i18n::trf(
            "SAM keeps {targets} read-only where the app's other folders show them.",
            &[("targets", &targets)],
        ));
    }
    Some(note)
}

/// What the start says about the place `rel` of the home that SAM shows
/// on its own and leaves out for a guarded place ([`OwnBind::Holds`],
/// [`OwnBind::Inside`]); `None` for any other answer.
pub fn own_place_guarded_note(host: &HostInfo, rel: &str, why: &OwnBind) -> Option<String> {
    let path = format!("~/{rel}");
    let place = |g: &Path| tilde_in(&host.home, g);
    match why {
        OwnBind::Holds(g) => Some(crate::i18n::trf(
            "SAM does not bind {path} for this app on its own because it holds {place}, which is or leads to your keys or passwords, a place SAM protects or SAM's own files. The app still sees what its other folders show there.",
            &[("path", &path), ("place", &place(g))],
        )),
        OwnBind::Inside(g) => Some(crate::i18n::trf(
            "SAM does not bind {path} for this app on its own because it lies in {place}, a place SAM protects (your keys or passwords, files the desktop runs, or SAM's own files). The app still sees what its other folders show there.",
            &[("path", &path), ("place", &place(g))],
        )),
        _ => None,
    }
}

/// Which kind of place SAM leaves out ([`left_out_note`]): what to do
/// about a link the person made differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftOutPlace {
    /// An extra folder (`filesystem.custom_read`, `custom_write`).
    Extra,
    /// A user folder (Documents, Downloads, …).
    UserFolder,
}

/// What the start says about the place `shown` (as the person wrote it,
/// or `~/.fonts`), a place of the kind `kind`, that SAM leaves out
/// ([`LeftOut`]). For a link the person made, it says how to show its
/// place directly: an extra folder kept alongside the link stays left out
/// (and the sandbox check expects there what the place shows). `write`
/// says the bind was a writable one: for it a link is followed only into
/// what the home, the user folders and the extra read-only folders show
/// writable ([`shows_writable`]), so the place it
/// leads to may still be shown read-only (a read-only home), and the note
/// must not say it is hidden. No note, for a link the app may have planted
/// ([`LeftOut::Link`]) or one to where programs outside the sandbox listen
/// ([`LeftOut::HostServices`]), says the place is hidden, nor that SAM
/// does not show `shown`: SAM only leaves out this one bind, while the
/// folders around it may still show the link, and other extra folders, opened folders and the system's own
/// places the place it leads to (a read-only home shows `~/.fonts`, a link
/// to `/tmp/myfonts`, and `/tmp/myfonts` listed by its real place is shown
/// as written). For a planted link the rule weighs only what the home and
/// the user folders show, for a writable bind also the extra read-only
/// folders (for a user folder the home alone, and for a writable one the
/// other user folders and extra folders set read-only).
pub fn left_out_note(shown: &str, why: &LeftOut, kind: LeftOutPlace, write: bool) -> String {
    let t = crate::util::tildify;
    match why {
        LeftOut::Link(link) => {
            let args: &[(&str, &dyn std::fmt::Display)] = &[("path", &shown), ("link", &t(link))];
            match kind {
                LeftOutPlace::Extra if write => crate::i18n::trf(
                    "SAM leaves out the writable folder {path} for this app because the way there leads through the link {link}, which lies in a folder the app can change, to a place the home, the user folders and the extra read-only folders let the app read at most: the app may have made that link. The app still sees what its other folders show there. If you made the link yourself, list the place it leads to as an extra folder instead of this one.",
                    args,
                ),
                LeftOutPlace::UserFolder if write => crate::i18n::trf(
                    "SAM leaves out the writable user folder {path} for this app because the way there leads through the link {link}, which lies in a folder the app can change, to a place the home does not show writable or one inside another user folder or an extra folder set read-only: the app may have made that link. The app still sees what its other folders show there. If you made the link yourself, set this user folder to the place it leads to in ~/.config/user-dirs.dirs.",
                    args,
                ),
                LeftOutPlace::Extra => crate::i18n::trf(
                    "SAM leaves out the extra folder {path} for this app because the way there leads through the link {link}, which lies in a folder the app can change, to a place the home and the user folders do not show: the app may have made that link. The app still sees what its other folders show there. If you made the link yourself, list the place it leads to as an extra folder instead of this one.",
                    args,
                ),
                LeftOutPlace::UserFolder => crate::i18n::trf(
                    "SAM leaves out the user folder {path} for this app because the way there leads through the link {link}, which lies in a folder the app can change, to a place the home does not show: the app may have made that link. The app still sees what its other folders show there. If you made the link yourself, set this user folder to the place it leads to in ~/.config/user-dirs.dirs.",
                    args,
                ),
            }
        }
        LeftOut::HostServices(place) => {
            let args: &[(&str, &dyn std::fmt::Display)] = &[("path", &shown), ("place", &t(place))];
            match kind {
                LeftOutPlace::Extra if write => crate::i18n::trf(
                    "SAM leaves out the writable folder {path} for this app because it leads through a link to {place}, where programs outside the sandbox listen: through them the app could run commands outside the sandbox. The app still sees what its other folders show there.",
                    args,
                ),
                LeftOutPlace::UserFolder if write => crate::i18n::trf(
                    "SAM leaves out the writable user folder {path} for this app because it leads through a link to {place}, where programs outside the sandbox listen: through them the app could run commands outside the sandbox. The app still sees what its other folders show there.",
                    args,
                ),
                LeftOutPlace::Extra => crate::i18n::trf(
                    "SAM leaves out the extra folder {path} for this app because it leads through a link to {place}, where programs outside the sandbox listen: through them the app could run commands outside the sandbox. The app still sees what its other folders show there.",
                    args,
                ),
                LeftOutPlace::UserFolder => crate::i18n::trf(
                    "SAM leaves out the user folder {path} for this app because it leads through a link to {place}, where programs outside the sandbox listen: through them the app could run commands outside the sandbox. The app still sees what its other folders show there.",
                    args,
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slug a heading gets as a link target on the page: lower case,
    /// letters, digits, `-`, `_` and spaces kept, spaces made `-`.
    fn heading_slug(heading: &str) -> String {
        heading
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ' '))
            .map(|c| if c == ' ' { '-' } else { c })
            .collect()
    }

    /// The names in italics (`*X*`) inside every `(see …)` of `text`.
    fn pointers(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = text;
        while let Some(i) = rest.find("(see ") {
            let group = &rest[i + 1..];
            // To the closing parenthesis of this group; a link's `(#…)`
            // inside it opens and closes its own.
            let mut depth = 1;
            let mut end = group.len();
            for (j, c) in group.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let mut parts = group[..end].split('*');
            parts.next();
            // Every second part lies between two stars.
            while let Some(name) = parts.next() {
                out.push(name.to_string());
                parts.next();
            }
            rest = &group[end..];
        }
        out
    }

    /// Whether `text` holds an `R` and two or three digits with no letter
    /// or digit beside them (a private review number).
    fn has_review_number(text: &str) -> bool {
        let c: Vec<char> = text.chars().collect();
        (0..c.len()).any(|i| {
            if c[i] != 'R' || (i > 0 && c[i - 1].is_alphanumeric()) {
                return false;
            }
            let digits = c[i + 1..].iter().take_while(|d| d.is_ascii_digit()).count();
            let after = c.get(i + 1 + digits);
            (2..=3).contains(&digits) && !after.is_some_and(|a| a.is_alphanumeric())
        })
    }

    /// The security page's file rules are numbered once each (F1 to F5,
    /// C1 to C4), each points to where the page says it in full, every
    /// link and every pointer in the section names a heading or a bold
    /// paragraph of the page, and the section holds none of these private
    /// references: an `R` with two or three digits, the words "review
    /// finding" or "roadmap", "decision" with a number, or "chat".
    #[test]
    fn the_file_rules_are_numbered_once_each_and_cite_nothing_private() {
        use crate::file_rules_doc::{one_line, page, rule, section, HEADING};
        let page = page();
        assert_eq!(page.matches(HEADING).count(), 1, "the heading, once");
        let sec = section(&page);
        for id in ["F1", "F2", "F3", "F4", "F5", "C1", "C2", "C3", "C4"] {
            let mark = format!("- **{id},");
            assert_eq!(sec.matches(&mark).count(), 1, "rule {id}, once");
            let r = rule(&page, id);
            assert!(
                r.contains("](#") || one_line(r).contains("(see *"),
                "rule {id} points to nowhere: {r}"
            );
        }
        let headings: Vec<String> = page
            .lines()
            .filter(|l| l.starts_with('#'))
            .map(|l| l.trim_start_matches('#').trim().to_string())
            .collect();
        let slugs: Vec<String> = headings.iter().map(|h| heading_slug(h)).collect();
        let mut links = 0;
        let mut rest = sec;
        while let Some(i) = rest.find("](#") {
            let after = &rest[i + 3..];
            let end = after.find(')').expect("a link ends");
            let slug = &after[..end];
            assert!(
                slugs.iter().any(|s| s == slug),
                "the link #{slug} names no heading of the page"
            );
            links += 1;
            rest = &after[end..];
        }
        assert!(links > 0, "the section links to its homes");
        let flat_page = one_line(&page);
        let flat = one_line(sec);
        let names = pointers(&flat);
        assert!(
            names.len() > 9,
            "the section points to its homes: {names:?}"
        );
        for name in names {
            let bold = ['*', '.', ':']
                .iter()
                .any(|end| flat_page.contains(&format!("**{name}{end}")));
            assert!(
                bold || headings.iter().any(|h| *h == name),
                "the pointer *{name}* names no bold paragraph or heading of the page"
            );
        }
        assert!(!has_review_number(sec), "a review number");
        let lower = flat.to_lowercase();
        for word in ["review finding", "roadmap"] {
            assert!(!lower.contains(word), "{word:?} in the section");
        }
        let words: Vec<&str> = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        assert!(!words.contains(&"chat"), "a chat in the section");
        assert!(
            !words
                .windows(2)
                .any(|w| w[0] == "decision" && w[1].starts_with(|c: char| c.is_ascii_digit())),
            "a decision number in the section"
        );
    }

    /// The security page names the start places SAM does not lock in the
    /// gap paragraph of rule C3 exactly while `PROTECTED_RO` leaves them out
    /// (`~/.vim`, `~/.config/vim`, `~/.local/share/nvim`, `~/.config/hg`),
    /// and says that start places are not locked at the top of the home
    /// where `XDG_CONFIG_HOME` names the home exactly while
    /// `~/.config/autostart` does not follow there. It never
    /// requires a gap to stay: a change that closes one fails here until it
    /// also updates the rule.
    #[test]
    fn rule_c3_names_the_start_places_sam_does_not_lock() {
        use crate::file_rules_doc::{gap, page, rule};
        let page = page();
        let gaps = gap(rule(&page, "C3"));
        for place in [".vim", ".config/vim", ".local/share/nvim", ".config/hg"] {
            // Locked: the place itself or a folder above it is on the list
            // (an entry inside it, such as a file in `~/.vim`, locks only
            // that entry).
            let locked = PROTECTED_RO
                .iter()
                .any(|p| *p == place || place.starts_with(&format!("{p}/")));
            let marker = format!("`~/{place}`");
            assert_eq!(
                locked,
                !gaps.contains(&marker),
                "rule C3, marker {marker}: the code locks it: {locked}; gap paragraph: {gaps}"
            );
        }
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let at_top = protected_places_with(&home, Some(home.clone()), None)
            .iter()
            .any(|p| p == "autostart");
        let marker = "set to the home itself";
        assert_eq!(
            at_top,
            !gaps.contains(marker),
            "rule C3, marker {marker:?}: the code locks ~/autostart: {at_top}; gap paragraph: {gaps}"
        );
    }

    /// Nothing this start adds to its permissions.
    fn none() -> ThisStart {
        ThisStart::default()
    }

    /// A scratch folder outside `/tmp` and `/var/tmp`, beside the test
    /// program: there a link's target is an ordinary folder, while
    /// anything in `/tmp` counts as a place where programs outside the
    /// sandbox listen ([`leads_to_host_services`]).
    fn scratch() -> tempfile::TempDir {
        let exe = std::env::current_exe().unwrap();
        let t = tempfile::Builder::new()
            .prefix("places-")
            .tempdir_in(exe.parent().unwrap())
            .unwrap();
        let real = std::fs::canonicalize(t.path()).unwrap();
        assert!(
            !real.starts_with("/tmp") && !real.starts_with("/var/tmp"),
            "the test program lies in a temp folder: {}",
            real.display()
        );
        t
    }

    /// A writable folder counts as in a start place when it is one, lies
    /// inside one or is where one really is: as named, with `..`, through
    /// a link to the place, below a place kept in a dotfiles folder and
    /// below the places `XDG_CONFIG_HOME` names. An ordinary folder, a
    /// folder above a start place and a name that only begins like one do
    /// not count (owner decision 9 of 2026-11-23).
    #[test]
    fn a_write_grant_in_a_start_place_is_found_as_named_and_as_reached() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("u");
        for d in [
            ".config/fish/conf.d",
            "work",
            "dotfiles/nvim/lua",
            "cfg/fish",
        ] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(home.join(".config/fish"), home.join("fishlink")).unwrap();
        std::os::unix::fs::symlink(home.join("dotfiles/nvim"), home.join(".config/nvim")).unwrap();
        let places = protected_places_with(&home, Some(home.join("cfg")), None);
        let found = |g: &str| {
            let g = home.join(g);
            start_place_of_write_grant_in(&g, &resolve(&g), &home, &places)
        };
        let inside = |place: &str| {
            Some(StartPlaceGrant {
                place: place.into(),
                inside: true,
                home_or_above: false,
            })
        };
        assert_eq!(found(".config/fish/conf.d"), inside(".config/fish"));
        assert_eq!(found(".config/fish/missing/deeper"), inside(".config/fish"));
        assert_eq!(found("work/../.config/fish/conf.d"), inside(".config/fish"));
        assert_eq!(found("nowhere/../.config/fish/x"), inside(".config/fish"));
        assert_eq!(found("fishlink/conf.d"), inside(".config/fish"));
        assert_eq!(found("dotfiles/nvim/lua"), inside(".config/nvim"));
        assert_eq!(found("cfg/fish/conf.d"), inside("cfg/fish"));
        let itself = |place: &str| {
            Some(StartPlaceGrant {
                place: place.into(),
                inside: false,
                home_or_above: false,
            })
        };
        assert_eq!(found(".config/fish"), itself(".config/fish"));
        assert_eq!(found("fishlink"), itself(".config/fish"));
        assert_eq!(found("dotfiles/nvim"), itself(".config/nvim"));
        assert_eq!(found(".bashrc"), itself(".bashrc"));
        for plain in [
            "work",
            ".config",
            "dotfiles",
            ".config/fishy",
            ".bashrc.d/x",
        ] {
            assert_eq!(found(plain), None, "{plain}");
        }
        // Without the variable, `cfg/fish` is an ordinary folder.
        assert_eq!(
            start_place_of_write_grant_in(
                &home.join("cfg/fish"),
                &home.join("cfg/fish"),
                &home,
                &protected_places_with(&home, None, None)
            ),
            None
        );
        // The words name the grant as written and the place under `~`.
        let note = start_place_note("~/fishlink/conf.d", &inside(".config/fish").unwrap());
        assert!(
            note.contains("~/fishlink/conf.d") && note.contains("~/.config/fish"),
            "{note}"
        );
        assert!(note.contains("read-only"), "{note}");
        // The places named like SAM's own folders are told apart by name;
        // whether a start hides one is `sams_folder_by_name`. A grant in
        // SAM's own folders is not shown at all, and the words say so.
        for sams in [".config/sam", ".local/share/sam", "cfg/sam"] {
            assert!(is_sams_name(sams), "{sams}");
        }
        for other in [".config/fish", ".config/user-dirs.dirs", ".bashrc"] {
            assert!(!is_sams_name(other), "{other}");
        }
        let note = inside_sams_folders_note("~/x");
        assert!(note.contains("SAM's own folders"), "{note}");
        assert!(!note.contains("read-only"), "{note}");
        let note = start_place_note("~/.bashrc", &itself(".bashrc").unwrap());
        assert!(
            note.contains("~/.bashrc") && note.contains("read-only"),
            "{note}"
        );
    }

    /// A writable grant counts as in SAM's own folders when it lies in one
    /// of them wherever it is kept (`~/Games/sam`, also reached through a
    /// link), or in a start place that is one of them; a folder that only
    /// holds SAM's folder, or whose name only begins like it, does not
    /// (independent review of decision 9). A start place named `sam` that
    /// the start only keeps read-only is not in SAM's list, and a grant in
    /// it is shown read-only, never left out: the sandbox, its check and
    /// the app page decide by the list, not by the name.
    #[test]
    fn a_write_grant_in_sams_folders_is_found_wherever_they_are_kept() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("u");
        std::fs::create_dir_all(home.join("Games/sam/saves")).unwrap();
        std::os::unix::fs::symlink(home.join("Games"), home.join("g")).unwrap();
        let sam_dirs = [home.join("g/sam"), home.join(".config/sam")];
        let in_sam = |g: &str, place: Option<&StartPlaceGrant>| {
            write_grant_in_sams_folders(&resolve(&home.join(g)), place, &sam_dirs, &home)
        };
        for inside in ["Games/sam", "Games/sam/saves", "g/sam/saves/new"] {
            assert!(in_sam(inside, None), "{inside}");
        }
        for outside in ["Games", "Games/sam2", "work"] {
            assert!(!in_sam(outside, None), "{outside}");
        }
        let sams = StartPlaceGrant {
            place: ".config/sam".into(),
            inside: true,
            home_or_above: false,
        };
        assert!(in_sam("work", Some(&sams)), "a start place in SAM's list");
        let fish = StartPlaceGrant {
            place: ".config/fish".into(),
            inside: true,
            home_or_above: false,
        };
        assert!(!in_sam("work", Some(&fish)));
        let kept_read_only = StartPlaceGrant {
            place: ".local/share/sam".into(),
            inside: true,
            home_or_above: false,
        };
        assert!(
            !in_sam("work", Some(&kept_read_only)),
            "named like SAM's folders, not in the list"
        );
    }

    /// SAM's folders by name are every protected place named `sam`: the
    /// usual two, and the same under `XDG_CONFIG_HOME` and `XDG_DATA_HOME`
    /// (`~/cfg/sam`), which the sandbox now hides as SAM's own instead of
    /// only locking them read-only; a name that only begins like it, or
    /// another place in those folders, is none (independent re-review of
    /// decision 9).
    #[test]
    fn sams_folders_by_name_follow_other_config_and_data_folders() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("u");
        let places = protected_places_with(&home, Some(home.join("cfg")), Some(home.join("dat")));
        let mut found = sams_folders_in(&home, &[], &[], &places, &[]);
        found.sort();
        let mut want: Vec<PathBuf> = [".config/sam", ".local/share/sam", "cfg/sam", "dat/sam"]
            .iter()
            .map(|p| home.join(p))
            .collect();
        want.sort();
        assert_eq!(found, want);
        for other in [".config/samba", "cfg/fish", "dat/applications"] {
            assert!(!is_sams_name(other), "{other}");
        }
    }

    /// The credential stores follow `XDG_CONFIG_HOME` and `XDG_DATA_HOME`
    /// inside the home as the start places do: with `~/cfg`, Git's
    /// passwords are kept in `~/cfg/git/credentials`, which was only locked
    /// read-only, so an app with the whole home could read them. A
    /// variable that names the home itself puts them at the top of the
    /// home (`~/git/credentials`, `~/gh`, `~/keyrings`), which were not
    /// hidden at all. A folder outside the home or one written with `..`
    /// above it adds nothing, and the usual places always stay.
    #[test]
    fn credential_stores_follow_other_config_and_data_folders() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("u");
        let places = sensitive_places_with(&home, Some(home.join("cfg")), Some(home.join("dat")));
        for want in [
            ".config/git/credentials",
            ".git-credentials",
            "cfg/git/credentials",
            "cfg/keepassxc",
            "dat/keyrings",
        ] {
            assert!(places.iter().any(|p| p == want), "{want}: {places:?}");
        }
        for wrong in ["cfg/keyrings", "dat/git/credentials", "cfg/.aws"] {
            assert!(!places.iter().any(|p| p == wrong), "{wrong}: {places:?}");
        }
        // The home itself, as named and with a trailing `/`.
        for at_home in [home.clone(), PathBuf::from(format!("{}/", home.display()))] {
            let places = sensitive_places_with(&home, Some(at_home.clone()), Some(at_home));
            for want in [
                ".config/git/credentials",
                ".git-credentials",
                ".local/share/keyrings",
                "git/credentials",
                "keepassxc",
                "gh",
                "keyrings",
            ] {
                assert!(places.iter().any(|p| p == want), "{want}: {places:?}");
            }
            for wrong in ["", "/", ".aws/.aws", "git", "keyrings/keyrings"] {
                assert!(!places.iter().any(|p| p == wrong), "{wrong}: {places:?}");
            }
        }
        for outside in [home.join("../elsewhere"), PathBuf::from("/elsewhere")] {
            assert_eq!(
                sensitive_places_with(&home, Some(outside.clone()), Some(outside)),
                SENSITIVE_DOTFILES
            );
        }
        assert_eq!(sensitive_places_with(&home, None, None), SENSITIVE_DOTFILES);
    }

    /// The file SAM reads the user folders from (`user-dirs.dirs` in the
    /// config folder, as [`crate::host::xdg_user_dirs`] finds it) is a
    /// protected place wherever `XDG_CONFIG_HOME` puts it in the home: by
    /// default, in another folder inside the home, and at the top of the
    /// home when the variable names the home itself, as named, with a
    /// trailing `/` and by the home's real place. Not locked there, an app
    /// with the whole home writable rewrote `~/user-dirs.dirs`, and at its
    /// next start SAM showed other folders as its Documents or Downloads.
    #[test]
    fn the_user_folders_file_is_protected_wherever_sam_reads_it_in_the_home() {
        let t = scratch();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let real = root.join("data/u");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        let home = root.join("home/u");
        std::os::unix::fs::symlink(&real, &home).unwrap();
        for config in [
            None,
            Some(home.join(".config")),
            Some(home.join("cfg")),
            Some(home.clone()),
            Some(PathBuf::from(format!("{}/", home.display()))),
            Some(real.clone()),
        ] {
            let read = crate::host::config_home(config.clone().map(Into::into), &home)
                .join("user-dirs.dirs");
            let places = protected_places_with(&home, config.clone(), None);
            assert!(
                places
                    .iter()
                    .any(|p| resolve(&home.join(p)) == resolve(&read)),
                "{config:?}: {} is not protected: {:?}",
                read.display(),
                &places[PROTECTED_RO.len()..]
            );
        }
    }

    /// A place named like SAM's folders counts as SAM's, hidden wherever the
    /// app reaches it with links followed, unless hiding it would cover too
    /// much (independent reviews of decision 9):
    /// - a real folder counts, also with a grant inside it;
    /// - a link counts wherever it leads, inside or outside the home, also
    ///   through a link above it (`~/dat` leading out of the home): another
    ///   SAM may keep its settings in `~/Sync/sam` with `~/.local/share/sam`
    ///   a link there, and the whole home or a grant of `~/Sync` showed
    ///   them while every link counted as an ordinary start place;
    /// - a link to the home or a folder above it never counts, nor does a
    ///   real folder that is the home where it really is;
    /// - a link counts neither when the start shows only folders inside the
    ///   place it leads to (`~/.config/sam` planted as a link to `~/work`,
    ///   `~/work/proj` granted), but it does when the start shows that place
    ///   whole (exactly `~/work`, or the whole home), which SAM cannot tell
    ///   from another SAM's folder kept there: it stays hidden as before;
    /// - where this SAM keeps its own counts wherever it leads.
    #[test]
    fn a_folder_named_like_sams_is_hidden_unless_that_would_cover_too_much() {
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("u");
        for d in [
            ".config",
            ".local/share/sam/x",
            "Sync/sam/x",
            "work/proj",
            "cfg",
        ] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::create_dir_all(base.join("outside/sam/x")).unwrap();
        std::os::unix::fs::symlink(base.join("outside"), home.join("dat")).unwrap();
        let places = protected_places_with(&home, Some(home.join("cfg")), Some(home.join("dat")));
        assert!(places.iter().any(|p| p == "dat/sam"), "{places:?}");
        let at = |rel: &str| home.join(rel);
        // `rel` becomes a link to `target`, whatever was there.
        let link = |rel: &str, target: &Path| {
            let _ = std::fs::remove_file(at(rel));
            std::os::unix::fs::symlink(target, at(rel)).unwrap();
        };
        let counts = |rel: &str, own: &[PathBuf], shown: &[PathBuf]| {
            sams_folder_by_name(&home, rel, own, shown)
        };
        let none: Vec<PathBuf> = vec![];
        let whole = vec![home.clone()];

        // A real folder below the home.
        for shown in [&none, &whole, &vec![at(".local/share/sam/x")]] {
            assert!(counts(".local/share/sam", &[], shown), "real: {shown:?}");
        }
        // A link into the home (another SAM's folder in `~/Sync/sam`).
        std::fs::remove_dir_all(at(".local/share/sam")).unwrap();
        link(".local/share/sam", &at("Sync/sam"));
        for shown in [
            &none,
            &whole,
            &vec![at("Sync")],
            &vec![at("Sync/sam")],
            &vec![at("Sync/sam/x"), home.clone()],
        ] {
            assert!(counts(".local/share/sam", &[], shown), "Sync: {shown:?}");
        }
        assert!(!counts(".local/share/sam", &[], &[at("Sync/sam/x")]));
        // A real folder below a link out of the home (`~/dat`).
        for shown in [&none, &whole, &vec![base.join("outside")]] {
            assert!(counts("dat/sam", &[], shown), "outside: {shown:?}");
        }
        assert!(!counts("dat/sam", &[], &[base.join("outside/sam/x")]));
        // A link to the home or a folder above it.
        link(".config/sam", &home);
        link("cfg/sam", &base);
        for rel in [".config/sam", "cfg/sam"] {
            for shown in [&none, &whole, &vec![at("work")]] {
                assert!(!counts(rel, &[], shown), "{rel}: {shown:?}");
            }
        }
        // Unless this SAM keeps its own there.
        assert!(counts(".config/sam", &[at(".config/sam")], &whole));
        assert!(counts(
            ".local/share/sam",
            &[at("Sync/sam")],
            &[at("Sync/sam/x")]
        ));
        // A link to a folder that holds a grant.
        link(".config/sam", &at("work"));
        assert!(!counts(".config/sam", &[], &[at("work/proj")]));
        for shown in [
            &none,
            &vec![at("work")],
            &vec![at("work/proj"), home.clone()],
        ] {
            assert!(counts(".config/sam", &[], shown), "work: {shown:?}");
        }
        // No link itself, yet the home where it really is (a home named
        // `sam` whose `.config` leads to the folder above it).
        let sam_home = base.join("sam");
        std::fs::create_dir_all(&sam_home).unwrap();
        std::os::unix::fs::symlink(&base, sam_home.join(".config")).unwrap();
        assert!(!counts_in(&sam_home, ".config/sam"));
        // SAM's list: its own first, then each place that counts, once.
        let elsewhere = base.join("elsewhere");
        assert_eq!(
            sams_folders_in(
                &home,
                std::slice::from_ref(&elsewhere),
                &[at("work/proj")],
                &places,
                &[]
            ),
            vec![elsewhere, at(".local/share/sam"), at("dat/sam")]
        );
        // A writable grant below the link to the home is in a start place,
        // shown read-only, never left out as SAM's; the place is known to
        // lead to the home or above it, and the words say so.
        link(".config/sam", &home);
        let work = at("work");
        let found = start_place_of_write_grant_in(&work, &work, &home, &places);
        assert_eq!(
            found,
            Some(StartPlaceGrant {
                place: ".config/sam".into(),
                inside: true,
                home_or_above: true,
            })
        );
        let sams = sams_folders_in(&home, &[], std::slice::from_ref(&work), &places, &[]);
        assert!(!write_grant_in_sams_folders(
            &work,
            found.as_ref(),
            &sams,
            &home
        ));
        let note = start_place_note("~/work", found.as_ref().unwrap());
        assert!(note.contains("read-only"), "{note}");
        assert!(
            note.contains("~/.config/sam, a folder SAM protects, is not a real folder but a shortcut to your home folder or a folder above it")
                && note.contains("~/work"),
            "{note}"
        );
        assert!(!note.contains("is inside"), "{note}");
    }

    /// A protected place that really is the home (`~/.config/sam` planted
    /// as a link to it, or a start place such as `~/.config/fish` leading
    /// there) and that the start does not hide as SAM's is named: the
    /// sandbox's lock on it lands on the whole home, which the app then
    /// sees read-only, and its note, its check and the app page take this
    /// answer (independent review of decision 9: the check expected the
    /// home writable, and a grant in the home was said to be "inside
    /// ~/.config/sam"). A place the start hides as SAM's (where this SAM
    /// keeps its own), a link to a folder in the home and a link to a
    /// folder above the home, which no lock reaches with the whole home
    /// granted, are not named. A grant in the home counts as part of a
    /// place leading there, and the words say where that place leads.
    #[test]
    fn a_protected_place_that_really_is_the_home_is_named() {
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("u");
        for d in [".config/fish", "work"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let places = protected_places_with(&home, None, None);
        let at = |rel: &str| home.join(rel);
        let link = |rel: &str, target: &Path| {
            let _ = std::fs::remove_file(at(rel));
            std::os::unix::fs::symlink(target, at(rel)).unwrap();
        };
        let named = |sams: &[PathBuf]| protected_place_at_home_in(&home, sams, &places);
        // Nothing leads to the home.
        assert_eq!(named(&[]), None);
        // `~/.config/sam` planted as a link to the home.
        link(".config/sam", &home);
        let whole = std::slice::from_ref(&home);
        let own = [base.join("elsewhere")];
        let sams = sams_folders_in(&home, &own, whole, &places, &[]);
        assert_eq!(named(&sams), Some(".config/sam".to_string()));
        // Hidden as SAM's (where this SAM keeps its own): not named.
        let own_there = [at(".config/sam")];
        let sams = sams_folders_in(&home, &own_there, whole, &places, &[]);
        assert_eq!(named(&sams), None);
        // A link to a folder in the home or above it: not named.
        link(".config/sam", &at("work"));
        assert_eq!(named(&[]), None);
        link(".config/sam", &base);
        assert_eq!(named(&[]), None);
        // Any other start place leading to the home is named too.
        let _ = std::fs::remove_file(at(".config/sam"));
        std::fs::remove_dir_all(at(".config/fish")).unwrap();
        link(".config/fish", &home);
        assert_eq!(named(&[]), Some(".config/fish".to_string()));
        // A grant in the home lies in that place, which leads to the home.
        let work = at("work");
        let found = start_place_of_write_grant_in(&work, &work, &home, &places).unwrap();
        assert!(found.home_or_above, "{found:?}");
        let note = start_place_note("~/work", &found);
        assert!(
            note.contains("~/.config/fish, a folder SAM protects, is not a real folder but a shortcut to your home folder or a folder above it"),
            "{note}"
        );
        let note = home_read_only_note(".config/fish");
        assert!(
            note.contains("~/.config/fish, a folder SAM protects, is not a real folder but a shortcut to your whole home folder")
                && note.contains("delete the shortcut ~/.config/fish")
                && note.contains("read-only"),
            "{note}"
        );
    }

    /// A user folder is refused by each of the rules on its own, also when
    /// the home is kept behind a link (`~` at `home/ann`, a link to
    /// `data/ann`), where the home as named and the home where it really
    /// is answer differently:
    /// - the folder that holds the home's link (`home`) lies above the home
    ///   as named, not above the real home: shown, it handed the app the
    ///   link and every other home there;
    /// - the key folder by the home's linked name (`~/.ssh`) is a key store
    ///   of the real home only;
    /// - a folder in `/tmp` where programs outside the sandbox listen
    ///   (`/tmp`, `/tmp/tmux-1000`) is neither above the home nor a
    ///   sensitive place, yet hands over the host's terminal multiplexers.
    ///
    /// A folder in the real home and a plain folder in `/tmp` are shown.
    #[test]
    fn a_user_folder_above_a_linked_home_is_not_shown() {
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        for d in ["data/ann/.ssh", "data/ann/Docs", "home"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(base.join("data/ann"), base.join("home/ann")).unwrap();
        let home = base.join("home/ann");
        assert_eq!(
            user_folder_place(&base.join("home"), &home),
            None,
            "the folder holding the home's link"
        );
        assert_eq!(
            user_folder_place(&home.join(".ssh"), &home),
            None,
            "the key folder by the home's linked name"
        );
        assert_eq!(
            user_folder_place(&home.join("Docs"), &home),
            Some(base.join("data/ann/Docs")),
            "a folder in the home, where it really is"
        );
        let ann = Path::new("/home/ann");
        assert_eq!(user_folder_place(Path::new("/tmp/tmux-1000"), ann), None);
        assert_eq!(user_folder_place(Path::new("/tmp"), ann), None);
        assert_eq!(
            user_folder_place(Path::new("/tmp/exchange"), ann),
            Some(PathBuf::from("/tmp/exchange"))
        );
    }

    /// A folder that one of SAM's folder switches names (`SAM_DATA_DIR`,
    /// `SAM_CONFIG_DIR`) counts as SAM's by the rules for the folders named
    /// like SAM's, whatever its own name, so hiding it never covers too
    /// much (batch review of the change that made release builds ignore
    /// these switches):
    /// - a real folder counts, inside or outside the home, also with a
    ///   grant inside it or of the folder above it;
    /// - the home, a folder above it (`/` too) and a way there (`~/work/..`)
    ///   never count, nor does a link to the home: nothing then covers the
    ///   home, and SAM's folders by name stay as they are;
    /// - a link counts neither where the start shows only folders inside
    ///   the place it leads to (`~/work/proj` granted), but does where the
    ///   start shows that place whole;
    /// - one that is where this SAM keeps its own is listed once, its own
    ///   first, the folders by name next and the switches' folders last.
    #[test]
    fn a_folder_a_switch_names_is_hidden_unless_that_would_cover_too_much() {
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("u");
        for d in ["Games/sam/homes/x", "mydata", "work/proj", ".config"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::create_dir_all(base.join("outside/sam")).unwrap();
        let at = |rel: &str| home.join(rel);
        std::os::unix::fs::symlink(at("work"), at("Games/linked")).unwrap();
        std::os::unix::fs::symlink(&home, at("Games/home-link")).unwrap();
        let places = protected_places_with(&home, None, None);
        let own = [base.join("elsewhere")];
        let counts = |dir: &Path, shown: &[PathBuf]| {
            let switched = [dir.to_path_buf()];
            sams_folders_in(&home, &own, shown, &places, &switched).contains(&dir.to_path_buf())
        };
        let none: Vec<PathBuf> = vec![];
        let whole = vec![home.clone()];

        for dir in [at("Games/sam"), at("mydata"), base.join("outside/sam")] {
            for shown in [
                &none,
                &whole,
                &vec![at("Games")],
                &vec![at("Games/sam/homes/x")],
            ] {
                assert!(counts(&dir, shown), "{}: {shown:?}", dir.display());
            }
        }
        for dir in [
            home.clone(),
            at("work/.."),
            base.clone(),
            PathBuf::from("/"),
            at("Games/home-link"),
        ] {
            for shown in [&none, &whole, &vec![at("work")]] {
                let sams = sams_folders_in(&home, &own, shown, &places, std::slice::from_ref(&dir));
                assert!(
                    !sams.iter().any(|d| home.starts_with(resolve(d))),
                    "{}: {shown:?}: {sams:?}",
                    dir.display()
                );
                assert_eq!(
                    sams,
                    sams_folders_in(&home, &own, shown, &places, &[]),
                    "{}: {shown:?}",
                    dir.display()
                );
            }
        }
        let linked = at("Games/linked");
        assert!(!counts(&linked, &[at("work/proj")]));
        for shown in [
            &none,
            &vec![at("work")],
            &vec![at("work/proj"), home.clone()],
        ] {
            assert!(counts(&linked, shown), "linked: {shown:?}");
        }
        let games = at("Games/sam");
        let sams = sams_folders_in(
            &home,
            std::slice::from_ref(&games),
            &whole,
            &places,
            &[at("mydata"), games.clone()],
        );
        assert_eq!(
            sams,
            vec![
                games.clone(),
                at(".config/sam"),
                at(".local/share/sam"),
                at("mydata")
            ]
        );
    }

    /// [`sams_folder_by_name`] for a start that shows nothing.
    fn counts_in(home: &Path, rel: &str) -> bool {
        sams_folder_by_name(home, rel, &[], &[])
    }

    /// The way to a path follows every link as Linux does: each named in
    /// the folder that really holds it, `..` after a link going back from
    /// where the link leads, a link whose target does not exist yet
    /// followed to that target (a bind a moment later would show it if it
    /// appears), and a loop stuck at its 41st link.
    #[test]
    fn the_way_to_a_path_follows_every_link_also_one_that_leads_nowhere_yet() {
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let link = |to: &Path, at: &Path| std::os::unix::fs::symlink(to, at).unwrap();
        std::fs::create_dir_all(base.join("real/sub")).unwrap();
        link(&base.join("real"), &base.join("a"));
        link(Path::new("sub/../sub"), &base.join("real/s"));
        let way = follow(&base.join("a/s/x"));
        assert_eq!(way.leads, base.join("real/sub/x"));
        assert_eq!(way.links, vec![base.join("a"), base.join("real/s")]);
        assert!(!way.stuck);
        // Not there yet: followed where it would lead.
        link(
            Path::new("/tmp/tmux-sam-never-there"),
            &base.join("planted"),
        );
        let way = follow(&base.join("planted/default"));
        assert_eq!(way.leads, Path::new("/tmp/tmux-sam-never-there/default"));
        assert_eq!(way.links, vec![base.join("planted")]);
        // A plain path has no links.
        assert_eq!(follow(&base.join("real/sub")).links, Vec::<PathBuf>::new());
        // A loop.
        link(&base.join("loop2"), &base.join("loop1"));
        link(&base.join("loop1"), &base.join("loop2"));
        let way = follow(&base.join("loop1/x"));
        assert!(way.stuck);
        assert_eq!(way.links.len(), 41);
        // A planted link is the one in a folder the app can change; a
        // stuck way counts as one.
        let in_base = |d: &Path| d == base;
        let in_real = |d: &Path| d == base.join("real");
        let way = follow(&base.join("a/s/x"));
        assert_eq!(
            link_the_app_could_plant(&way, &in_base),
            Some(base.join("a"))
        );
        assert_eq!(
            link_the_app_could_plant(&way, &in_real),
            Some(base.join("real/s"))
        );
        assert_eq!(link_the_app_could_plant(&way, &|_| false), None);
        let way = follow(&base.join("loop1"));
        assert!(link_the_app_could_plant(&way, &|_| false).is_some());
    }

    /// The places where programs outside the sandbox listen: the whole
    /// computer; anything in `/tmp` and `/var/tmp` (a socket directly
    /// there, a socket folder by any name) and a folder holding one; the
    /// host's runtime folder and SAM's runtime folders wherever they are,
    /// and a folder holding one; `/run` but not drives under `/run/media`;
    /// `/proc` and `/dev`. Not an ordinary folder elsewhere, not a place in
    /// a home kept in `/tmp` (a guest session), and not a runtime folder
    /// that holds the home (a container's `XDG_RUNTIME_DIR=/tmp`).
    #[test]
    fn the_places_where_outside_programs_listen_are_known() {
        let host = HostInfo {
            home: "/home/u".into(),
            runtime_dir: Some("/mnt/wslg/runtime-dir".into()),
            ..Default::default()
        };
        let this = ThisStart {
            writable: Vec::new(),
            sam_runtime: vec!["/data/sam-run".into()],
        };
        let listens = |p: &str| leads_to_host_services(Path::new(p), &host, &this);
        for p in [
            "/",
            "/tmp",
            "/tmp/tmux-1000",
            "/tmp/ssh-XXXX/agent.1",
            "/tmp/.X11-unix",
            "/tmp/.s.PGSQL.5432",
            "/tmp/tmate-1000",
            "/tmp/exchange",
            "/var",
            "/var/tmp",
            "/var/tmp/sockets/s",
            "/mnt",
            "/mnt/wslg",
            "/mnt/wslg/runtime-dir",
            "/mnt/wslg/runtime-dir/bus",
            "/data",
            "/data/sam-run",
            "/data/sam-run/app/l1/bus",
            "/run",
            "/run/user/1000",
            "/run/user/1000/bus",
            "/run/dbus",
            "/run/docker.sock",
            "/proc/1/root",
            "/dev/shm",
        ] {
            assert!(listens(p), "{p}");
        }
        for p in [
            "/run/media/u/disk/fonts",
            "/home/u/.fonts",
            "/usr/share/fonts",
            "/runner",
            "/mnt/disk",
            "/data/other",
            "/var/lib/fonts",
        ] {
            assert!(!listens(p), "{p}");
        }
        // A guest session's home in `/tmp`, with the runtime folder `/tmp`
        // as in a container: its own places are judged by the other rules,
        // the rest of `/tmp` still counts.
        let guest = HostInfo {
            home: "/tmp/guest-u".into(),
            runtime_dir: Some("/tmp".into()),
            ..Default::default()
        };
        let none = ThisStart::default();
        assert!(!leads_to_host_services(
            Path::new("/tmp/guest-u/myfonts"),
            &guest,
            &none
        ));
        assert!(!leads_to_host_services(
            Path::new("/tmp/guest-u"),
            &guest,
            &none
        ));
        for p in ["/tmp", "/tmp/tmux-1000", "/tmp/.s.PGSQL.5432", "/tmp/other"] {
            assert!(leads_to_host_services(Path::new(p), &guest, &none), "{p}");
        }
        // A runtime folder in that home still counts.
        let inside = HostInfo {
            runtime_dir: Some("/tmp/guest-u/.run".into()),
            ..guest.clone()
        };
        assert!(leads_to_host_services(
            Path::new("/tmp/guest-u/.run/bus"),
            &inside,
            &none
        ));
        assert!(leads_to_host_services(
            Path::new("/tmp/guest-u"),
            &inside,
            &none
        ));
    }

    /// One rule for every extra folder and user folder reached through
    /// links (`~/x`): with the whole home writable, a link in it is not
    /// followed out of what the home shows (the app may have planted it),
    /// also when its target does not exist yet, and for one to where
    /// programs outside the sandbox listen that is the reason given; one
    /// that stays in the home is followed. Without a folder the app can
    /// change, a link is followed, unless it leads to where programs
    /// outside the sandbox listen. A place named by its real path (no
    /// link) is never left out: its name was rated as it is. A link in a
    /// writable user folder counts as well, one in a read-only home not.
    /// The fonts and theme files follow no link at all
    /// ([`own_place_decision`]).
    #[test]
    fn a_linked_place_is_left_out_where_a_planted_link_leads_out_or_to_host_services() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let outside = base.join("outside");
        for d in [home.join("mine"), home.join("Documents"), outside.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let sockets = tempfile::Builder::new()
            .prefix("tmux-")
            .tempdir_in("/tmp")
            .unwrap();
        let sockets = sockets.path().to_path_buf();
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let mut whole = PermissionSet::strict_gui();
        whole.filesystem.home = true;
        whole.filesystem.home_access = crate::permissions::Access::Rw;
        let private = PermissionSet::strict_gui();
        let x = home.join("x");
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&x);
            std::os::unix::fs::symlink(target, &x).unwrap();
        };
        // To the sockets: left out for them in both, also where the app
        // may have planted the link, so the note names the danger and no
        // way out.
        to(&sockets);
        assert_eq!(
            linked_place_left_out(&whole, &host, &x, false, &none()),
            Some(LeftOut::HostServices(sockets.clone()))
        );
        assert_eq!(
            linked_place_left_out(&private, &host, &x, false, &none()),
            Some(LeftOut::HostServices(sockets.clone()))
        );
        to(&outside);
        assert_eq!(
            linked_place_left_out(&whole, &host, &x, false, &none()),
            Some(LeftOut::Link(x.clone()))
        );
        assert_eq!(
            linked_place_left_out(&private, &host, &x, false, &none()),
            None
        );
        to(&base.join("not-there-yet"));
        assert_eq!(
            linked_place_left_out(&whole, &host, &x, false, &none()),
            Some(LeftOut::Link(x.clone()))
        );
        to(&home.join("mine"));
        assert_eq!(
            linked_place_left_out(&whole, &host, &x, false, &none()),
            None
        );
        // A read-only home: the app cannot have put the link there.
        let mut ro = whole.clone();
        ro.filesystem.home_access = crate::permissions::Access::Ro;
        to(&outside);
        assert_eq!(linked_place_left_out(&ro, &host, &x, false, &none()), None);
        // Named by its real place: shown as written (and warned about).
        assert_eq!(
            linked_place_left_out(&private, &host, &sockets, false, &none()),
            None
        );
        assert_eq!(
            linked_place_left_out(&whole, &host, &outside, false, &none()),
            None
        );
        // A link in a writable user folder, without the whole home.
        let mut host_docs = host.clone();
        host_docs
            .xdg_dirs
            .insert("documents".into(), home.join("Documents"));
        let mut docs = PermissionSet::strict_gui();
        docs.filesystem.documents = crate::permissions::Access::Rw;
        let planted = home.join("Documents/ro");
        std::os::unix::fs::symlink(&outside, &planted).unwrap();
        assert_eq!(
            linked_place_left_out(&docs, &host_docs, &planted, false, &none()),
            Some(LeftOut::Link(planted.clone()))
        );
        docs.filesystem.documents = crate::permissions::Access::Ro;
        assert_eq!(
            linked_place_left_out(&docs, &host_docs, &planted, false, &none()),
            None
        );
        // The note names the place and why.
        let note = left_out_note("~/x", &LeftOut::Link(x.clone()), LeftOutPlace::Extra, false);
        assert!(
            note.contains("~/x") && note.contains("may have made that link"),
            "{note}"
        );
        let note = left_out_note(
            "~/x",
            &LeftOut::HostServices(sockets.clone()),
            LeftOutPlace::Extra,
            false,
        );
        assert!(
            note.contains(&sockets.display().to_string())
                && note.contains("where programs outside the sandbox listen"),
            "{note}"
        );
    }

    /// A home kept behind a link (Fedora Silverblue's `/home` a link to
    /// `/var/home`, or `~` a link to `/data/u`) shows everything in its
    /// real place: with the whole home writable, an extra folder named by a
    /// link in the home to a folder in the real home is followed and bound,
    /// as in a plain home. Taken for a place outside the home, it was left
    /// out with a note on such a computer, although the home shows it
    /// anyway. A link out of the real home is still left out: the app may
    /// have planted it. A place SAM shows on its own follows no link below
    /// the home's real place at all, in such a home as in a plain one:
    /// `~/.fonts` a link to `~/myfonts` is skipped as a link, while the
    /// link that holds the home itself never counts, and a real `~/.fonts`
    /// there is bound.
    #[test]
    fn a_link_within_a_linked_home_is_followed_like_one_in_a_plain_home() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let real_home = base.join("data/u");
        let outside = base.join("outside");
        for d in [
            real_home.join("myfonts"),
            base.join("home"),
            outside.clone(),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::os::unix::fs::symlink(&real_home, base.join("home/u")).unwrap();
        let host = HostInfo {
            home: base.join("home/u"),
            ..Default::default()
        };
        assert_eq!(resolve(&host.home), real_home, "the home is behind a link");
        let mut whole = PermissionSet::strict_gui();
        whole.filesystem.home = true;
        whole.filesystem.home_access = crate::permissions::Access::Rw;
        let fonts = host.home.join(".fonts");
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
        };
        to(&real_home.join("myfonts"));
        assert_eq!(
            follow(&fonts).leads,
            real_home.join("myfonts"),
            "the way leads into the real home"
        );
        assert_eq!(
            linked_place_left_out(&whole, &host, &fonts, false, &none()),
            None
        );
        assert!(
            matches!(
                own_place_way(&host.home, ".fonts"),
                OwnPlaceWay::Link(l)
                    if l.link == fonts && l.exists && l.leads == real_home.join("myfonts")
            ),
            "{:?}",
            own_place_way(&host.home, ".fonts")
        );
        // Out of the real home: a link the app could have planted, left out.
        to(&outside);
        assert_eq!(
            linked_place_left_out(&whole, &host, &fonts, false, &none()),
            Some(LeftOut::Link(real_home.join(".fonts")))
        );
        // A real fonts folder in the home behind a link: no link below the
        // home's real place.
        std::fs::remove_file(&fonts).unwrap();
        std::fs::create_dir(real_home.join(".fonts")).unwrap();
        assert_eq!(own_place_way(&host.home, ".fonts"), OwnPlaceWay::Plain);
    }

    /// A left-out note, for a planted link or a link to where programs
    /// outside the sandbox listen, never says the place is hidden, since
    /// other grants may still show it, and for a planted link the rule
    /// weighs only what the home and the user folders show (for a user
    /// folder the home alone). With Documents writable in a private home,
    /// `~/Documents/Data3` a link to `data3` and `data3` listed too, the
    /// link is left out while `data3` is shown read-only; a read-only user
    /// folder behind a link in a writable folder is left out while its
    /// place may be listed. Each note opens with what SAM did with that one
    /// bind (it leaves out the extra or user folder, or does not bind the
    /// place on its own), never that SAM does not show it, and says what
    /// the rule weighs and that the app still sees what its other folders
    /// show. So does the note for the fonts and theme files SAM skips for
    /// a link: `~/.fonts` in a writable home a link to a folder listed as
    /// an extra folder too, and with the home read-only
    /// `~/.config/fontconfig` a link to a folder in `/tmp` that is listed
    /// by its real place too, and `~/.local/share/fonts` a link to the
    /// home: the home shows the links and the app reaches what they lead
    /// to.
    #[test]
    fn a_left_out_note_never_says_the_place_is_hidden() {
        use crate::permissions::Access;
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let data3 = base.join("data3");
        let fonts_dir = base.join("fonts");
        for d in [
            home.join("Documents"),
            home.join("Sync"),
            data3.clone(),
            fonts_dir.clone(),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let mut host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        host.xdg_dirs
            .insert("documents".into(), home.join("Documents"));
        let st = |p: &Path| p.display().to_string();
        // The note says what SAM did with this one bind, never that SAM
        // does not show the place: the folders around it may still show
        // the link, and other grants the place it leads to.
        let told = |note: &str, shown: &str, opens: &str, says: &str| {
            assert!(
                note.starts_with(opens)
                    && note.contains(says)
                    && note.contains("may have made that link")
                    && note.contains("The app still sees what its other folders show there.")
                    && !note.contains("not shown otherwise")
                    && !note.contains(&format!("does not show {shown}"))
                    && !note.contains("not show ~"),
                "{note}"
            );
        };
        // An extra folder whose place is listed as well.
        let link = home.join("Documents/Data3");
        std::os::unix::fs::symlink(&data3, &link).unwrap();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Rw;
        p.filesystem.custom_read = vec![st(&link), st(&data3)];
        let why = linked_place_left_out(&p, &host, &link, false, &none());
        assert_eq!(why, Some(LeftOut::Link(link.clone())));
        let note = left_out_note(
            "~/Documents/Data3",
            why.as_ref().unwrap(),
            LeftOutPlace::Extra,
            false,
        );
        told(
            &note,
            "~/Documents/Data3",
            "SAM leaves out the extra folder ~/Documents/Data3 for this app because",
            "to a place the home and the user folders do not show",
        );
        // A place SAM shows on its own, skipped for a link, its target
        // listed as an extra folder too: the note names the link and where
        // it leads, and that the app still sees what its other folders
        // show.
        let fonts = home.join(".fonts");
        std::os::unix::fs::symlink(&fonts_dir, &fonts).unwrap();
        let mut whole = PermissionSet::strict_gui();
        whole.filesystem.home = true;
        whole.filesystem.home_access = Access::Rw;
        whole.filesystem.custom_read = vec![st(&fonts_dir)];
        let skipped_note = |rel: &'static str| {
            let decided = own_places_from_settings(&whole, &host, &[], &none());
            assert!(
                decided
                    .iter()
                    .any(|(r, d)| *r == ".fonts" && matches!(d, OwnBind::Link(_))),
                "{decided:?}"
            );
            let OwnPlaceWay::Link(link) = own_place_way(&home, rel) else {
                panic!("~/{rel} is a link");
            };
            let skipped = [OwnLinkSkipped {
                rel,
                link,
                shown: true,
            }];
            own_place_links_note(&host, &none(), &skipped, &[]).unwrap()
        };
        let note = skipped_note(".fonts");
        assert!(
            note.starts_with(&format!(
                "SAM does not bind ~/.fonts (a link to {}) for this app on its own:",
                fonts_dir.display()
            )) && note.contains("The app still sees what its other folders show there.")
                && !note.contains("hidden")
                && !note.contains("does not show ~/.fonts")
                && !note.contains("not show ~"),
            "{note}"
        );
        // A read-only user folder behind a link in a writable folder.
        let docs = home.join("Sync/Documents");
        std::os::unix::fs::symlink(&data3, &docs).unwrap();
        let mut synced = host.clone();
        synced.xdg_dirs.insert("documents".into(), docs.clone());
        let mut q = PermissionSet::strict_gui();
        q.filesystem.documents = Access::Ro;
        q.filesystem.custom_write = vec![st(&home.join("Sync"))];
        let why = user_folder_left_out(&q, &synced, "documents", &none());
        assert_eq!(why, Some(LeftOut::Link(docs.clone())));
        let note = left_out_note(
            "~/Sync/Documents",
            why.as_ref().unwrap(),
            LeftOutPlace::UserFolder,
            false,
        );
        told(
            &note,
            "~/Sync/Documents",
            "SAM leaves out the user folder ~/Sync/Documents for this app because",
            "to a place the home does not show",
        );
        // Nor do the notes for a link to where programs outside the sandbox
        // listen, or to a guarded place: other grants may still show it.
        let plain = |note: &str, shown: &str, opens: &str, says: &str| {
            assert!(
                note.starts_with(opens)
                    && note.contains(says)
                    && note.contains("The app still sees what its other folders show there.")
                    && !note.contains(&format!("does not show {shown}"))
                    && !note.contains("not show ~"),
                "{note}"
            );
        };
        let listen = "where programs outside the sandbox listen";
        // A read-only home shows the link `~/.config/fontconfig` to a
        // folder in `/tmp`, and that folder listed by its real place is
        // shown as written: the app reaches it through the link.
        let in_tmp = tempfile::Builder::new()
            .prefix("myfonts-")
            .tempdir_in("/tmp")
            .unwrap();
        let myfonts = std::fs::canonicalize(in_tmp.path()).unwrap();
        std::fs::create_dir_all(home.join(".config")).unwrap();
        let fontconfig = home.join(".config/fontconfig");
        std::os::unix::fs::symlink(&myfonts, &fontconfig).unwrap();
        let mut ro_home = PermissionSet::strict_gui();
        ro_home.filesystem.home = true;
        ro_home.filesystem.home_access = Access::Ro;
        ro_home.filesystem.custom_read = vec![st(&myfonts)];
        assert_eq!(
            linked_place_left_out(&ro_home, &host, &myfonts, false, &none()),
            None
        );
        let note = skipped_note(".config/fontconfig");
        plain(
            &note,
            "~/.config/fontconfig",
            &format!(
                "SAM does not bind ~/.config/fontconfig (a link to {}, {listen}) for this app on its own:",
                myfonts.display()
            ),
            listen,
        );
        // An extra or user folder, read-only or writable, behind such a
        // link.
        let sockets = LeftOut::HostServices(myfonts.clone());
        for (kind, write, opens) in [
            (
                LeftOutPlace::Extra,
                false,
                "SAM leaves out the extra folder ~/x for this app because",
            ),
            (
                LeftOutPlace::Extra,
                true,
                "SAM leaves out the writable folder ~/x for this app because",
            ),
            (
                LeftOutPlace::UserFolder,
                false,
                "SAM leaves out the user folder ~/x for this app because",
            ),
            (
                LeftOutPlace::UserFolder,
                true,
                "SAM leaves out the writable user folder ~/x for this app because",
            ),
        ] {
            plain(
                &left_out_note("~/x", &sockets, kind, write),
                "~/x",
                opens,
                listen,
            );
        }
        // `~/.local/share/fonts` a link to the home while the whole home is
        // shown: the home shows that link and the home it leads to.
        std::fs::create_dir_all(home.join(".local/share")).unwrap();
        let local_fonts = home.join(".local/share/fonts");
        std::os::unix::fs::symlink(&home, &local_fonts).unwrap();
        let note = skipped_note(".local/share/fonts");
        plain(
            &note,
            "~/.local/share/fonts",
            "SAM does not bind ~/.local/share/fonts (a link to ~) for this app on its own:",
            "SAM does not follow such a link for your fonts and theme files.",
        );
    }

    /// Where the way ends is not all: a link in `/tmp` made outside the
    /// sandbox (on WSLg the host's `/tmp/.X11-unix`, a link to
    /// `/mnt/wslg/.X11-unix`) sends the way on to a place SAM does not
    /// know as one where programs listen. `~/.fonts` in a private or
    /// read-only home, a link to such a link, is left out for the link in
    /// `/tmp`; so is one whose way runs through `/proc`. A link through an
    /// ordinary folder, and one in a home kept in `/tmp` (a guest
    /// session) that stays in it, are followed. A link in `/run` other
    /// than the runtime folders is root's own (NixOS's
    /// `/run/current-system`) and does not count, nor `/` that every way
    /// starts at.
    #[test]
    fn a_link_in_tmp_that_sends_the_way_elsewhere_is_never_followed() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let outside = base.join("outside");
        for d in [home.clone(), outside.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let in_tmp = tempfile::Builder::new()
            .prefix("sam-hop-")
            .tempdir_in("/tmp")
            .unwrap();
        let hop = std::fs::canonicalize(in_tmp.path()).unwrap().join("x11");
        std::os::unix::fs::symlink(&outside, &hop).unwrap();
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let private = PermissionSet::strict_gui();
        let mut ro = PermissionSet::strict_gui();
        ro.filesystem.home = true;
        ro.filesystem.home_access = crate::permissions::Access::Ro;
        let fonts = home.join(".fonts");
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
        };
        to(&hop);
        assert_eq!(follow(&fonts).leads, outside);
        for p in [&private, &ro] {
            assert_eq!(
                linked_place_left_out(p, &host, &fonts, false, &none()),
                Some(LeftOut::HostServices(hop.clone()))
            );
        }
        // Through `/proc`: `/proc/self/root` leads back to `/`.
        let through_proc = Path::new("/proc/self/root").join(outside.strip_prefix("/").unwrap());
        to(&through_proc);
        assert_eq!(follow(&fonts).leads, outside);
        assert!(matches!(
            linked_place_left_out(&private, &host, &fonts, false, &none()),
            Some(LeftOut::HostServices(at)) if at.starts_with("/proc")
        ));
        // Through an ordinary folder: followed.
        let plain_hop = base.join("hop");
        std::os::unix::fs::symlink(&outside, &plain_hop).unwrap();
        to(&plain_hop);
        assert_eq!(
            linked_place_left_out(&private, &host, &fonts, false, &none()),
            None
        );
        // A guest session's home in `/tmp`: a link that stays in it is
        // followed.
        let guest_tmp = tempfile::Builder::new()
            .prefix("sam-guest-")
            .tempdir_in("/tmp")
            .unwrap();
        let guest_home = std::fs::canonicalize(guest_tmp.path()).unwrap().join("u");
        std::fs::create_dir_all(guest_home.join("myfonts")).unwrap();
        std::os::unix::fs::symlink(guest_home.join("myfonts"), guest_home.join(".fonts")).unwrap();
        let guest = HostInfo {
            home: guest_home.clone(),
            ..Default::default()
        };
        assert_eq!(
            linked_place_left_out(&private, &guest, &guest_home.join(".fonts"), false, &none()),
            None
        );
        // What counts on the way.
        let host = HostInfo {
            home: "/home/u".into(),
            runtime_dir: Some("/mnt/wslg/runtime-dir".into()),
            ..Default::default()
        };
        let passes = |p: &str| passes_host_services(Path::new(p), &host, &none());
        for p in [
            "/tmp",
            "/tmp/.X11-unix",
            "/tmp/anything",
            "/var/tmp/x",
            "/mnt/wslg/runtime-dir/x",
            "/proc/self",
            "/proc/1/root",
            "/dev/shm/x",
        ] {
            assert!(passes(p), "{p}");
        }
        for p in [
            "/",
            "/mnt",
            "/var",
            "/home",
            "/run/current-system",
            "/nix/store/fonts",
        ] {
            assert!(!passes(p), "{p}");
        }
    }

    /// A place SAM shows on its own (`~/.fonts`) that is a link is never
    /// bound, wherever it leads: to the home, a folder above it, a key
    /// folder (also where it is kept behind a link), a credential store, a
    /// folder holding a protected place (`~/.config`), SAM's own folders,
    /// and also to a fonts folder of your own. A real fonts folder that
    /// no grant shows is not bound either where it holds a key or
    /// credential store, also one under `XDG_CONFIG_HOME` and
    /// `XDG_DATA_HOME` in the home or outside it (`~/cfg/gh` with
    /// `XDG_CONFIG_HOME=~/cfg`, `/data/cfg/gh` with
    /// `XDG_CONFIG_HOME=/data/cfg`), kept there as a link into the fonts:
    /// in a private home nothing else hides what such a bind shows.
    #[test]
    fn an_own_place_never_leads_to_the_home_keys_or_sams_folders() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        for d in ["myfonts", "Sync/ssh", ".config", "Games/sam", ".aws"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(home.join("Sync/ssh"), home.join(".ssh")).unwrap();
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let sams = [home.join("Games/sam")];
        let guarded = guarded_places_everywhere(&home, &sams);
        let named = guarded_places_named(&home, &sams);
        let private = |_: &Path| false;
        let fonts = home.join(".fonts");
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
            own_place_decision(&host, ".fonts", &private, &named, &guarded)
        };
        for target in [
            home.clone(),
            base.clone(),
            home.join(".ssh"),
            home.join("Sync/ssh"),
            home.join(".aws"),
            home.join(".config"),
            home.join("Games"),
            home.join("Games/sam"),
            home.join("myfonts"),
        ] {
            assert!(
                matches!(to(&target), OwnBind::Link(l) if l.link == fonts && l.exists),
                "{}",
                target.display()
            );
        }
        std::fs::remove_file(&fonts).unwrap();
        assert_eq!(
            own_place_decision(&host, ".fonts", &private, &named, &guarded),
            OwnBind::Missing
        );
        assert_eq!(
            own_place_decision(&host, ".config/fontconfig", &private, &named, &guarded),
            OwnBind::Missing
        );
        // A real fonts folder holding a credential store kept as a link
        // into it, with `XDG_CONFIG_HOME=~/cfg` and `XDG_DATA_HOME=~/dat`.
        std::fs::create_dir_all(fonts.join("dots/gh")).unwrap();
        std::fs::create_dir_all(fonts.join("dots/keyrings")).unwrap();
        std::fs::create_dir_all(home.join("cfg")).unwrap();
        std::fs::create_dir_all(home.join("dat")).unwrap();
        assert_eq!(
            own_place_decision(&host, ".fonts", &private, &named, &guarded),
            OwnBind::Bind
        );
        let moved = |config: &Path, data: &Path| {
            (
                guarded_places_everywhere_with(
                    &home,
                    &sams,
                    Some(config.to_path_buf()),
                    Some(data.to_path_buf()),
                ),
                guarded_places_named_with(
                    &home,
                    &sams,
                    Some(config.to_path_buf()),
                    Some(data.to_path_buf()),
                ),
            )
        };
        let elsewhere = base.join("elsewhere");
        for d in ["cfg", "dat"] {
            std::fs::create_dir_all(elsewhere.join(d)).unwrap();
        }
        for (config, data) in [
            (home.join("cfg"), home.join("dat")),
            (elsewhere.join("cfg"), elsewhere.join("dat")),
        ] {
            for (link, target) in [
                (config.join("gh"), fonts.join("dots/gh")),
                (data.join("keyrings"), fonts.join("dots/keyrings")),
            ] {
                std::os::unix::fs::symlink(&target, &link).unwrap();
                // Taken at the start, as the sandbox takes them.
                let (everywhere, by_name) = moved(&config, &data);
                assert_eq!(
                    own_place_decision(&host, ".fonts", &private, &by_name, &everywhere),
                    OwnBind::Holds(target.clone()),
                    "{} a link into the fonts",
                    link.display()
                );
                // A grant that shows the fonts anyway: bound read-only.
                assert_eq!(
                    own_place_decision(&host, ".fonts", &|_| true, &by_name, &everywhere),
                    OwnBind::Bind
                );
                std::fs::remove_file(&link).unwrap();
            }
            let (everywhere, by_name) = moved(&config, &data);
            assert_eq!(
                own_place_decision(&host, ".fonts", &private, &by_name, &everywhere),
                OwnBind::Bind,
                "{}",
                config.display()
            );
        }
    }

    /// SAM's own folders are guarded also where they really lead, not only
    /// as configured: with the unpack folder set to `~/Apps/sam` and
    /// `~/Apps` a link into a real fonts folder (`~/.fonts/apps`), the
    /// fonts would show every unpacked app in a private home; and with the
    /// home kept behind a link (`/home/u` a link to `/data/u`) and SAM's
    /// data folder set to `~/Games/sam`, `~/Games` a link to
    /// `/data/u/.fonts/g` (the fonts under the home's real place) would
    /// show the other apps' private homes. So would a credential store
    /// kept as a link into the fonts under that real place
    /// (`~/.git-credentials` a link to `/data/u/.fonts/dots/gc`). The fonts
    /// are not bound there; a fonts folder of your own beside them is.
    #[test]
    fn sams_folders_are_guarded_where_they_really_lead() {
        // A SAM folder named through a link in the home, private home.
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        std::fs::create_dir_all(home.join(".fonts/apps/sam/app-1")).unwrap();
        std::fs::create_dir_all(home.join(".local/share/fonts")).unwrap();
        std::os::unix::fs::symlink(home.join(".fonts/apps"), home.join("Apps")).unwrap();
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let sams = [home.join("Apps/sam")];
        let everywhere = guarded_places_everywhere_with(&home, &sams, None, None);
        let named = guarded_places_named_with(&home, &sams, None, None);
        assert!(!named.contains(&home.join(".fonts/apps/sam")), "{named:?}");
        let private = |_: &Path| false;
        let decide = |rel: &str| own_place_decision(&host, rel, &private, &named, &everywhere);
        assert_eq!(
            decide(".fonts"),
            OwnBind::Holds(home.join(".fonts/apps/sam"))
        );
        assert_eq!(decide(".local/share/fonts"), OwnBind::Bind);

        // The home kept behind a link: SAM's data folder at a name no
        // protected place has, and a credential store, each kept as a link
        // into the fonts under the home's real place.
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named_home = base.join("home/u");
        for d in [
            ".fonts/g/sam/homes/other",
            ".fonts/dots",
            ".local/share/fonts",
        ] {
            std::fs::create_dir_all(real.join(d)).unwrap();
        }
        std::fs::write(real.join(".fonts/dots/gc"), "secret").unwrap();
        std::fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named_home).unwrap();
        let host = HostInfo {
            home: named_home.clone(),
            ..Default::default()
        };
        let decide = |sams: &[PathBuf], rel: &str| {
            let everywhere = guarded_places_everywhere_with(&named_home, sams, None, None);
            let named = guarded_places_named_with(&named_home, sams, None, None);
            own_place_decision(&host, rel, &private, &named, &everywhere)
        };
        std::os::unix::fs::symlink(real.join(".fonts/g"), real.join("Games")).unwrap();
        let sams = [named_home.join("Games/sam")];
        assert_eq!(
            decide(&sams, ".fonts"),
            OwnBind::Holds(real.join(".fonts/g/sam"))
        );
        assert_eq!(decide(&sams, ".local/share/fonts"), OwnBind::Bind);
        std::fs::remove_file(real.join("Games")).unwrap();
        assert_eq!(decide(&sams, ".fonts"), OwnBind::Bind);
        std::os::unix::fs::symlink(real.join(".fonts/dots/gc"), real.join(".git-credentials"))
            .unwrap();
        assert_eq!(
            decide(&[], ".fonts"),
            OwnBind::Holds(real.join(".fonts/dots/gc"))
        );
    }

    /// The font places stay bound read-only although a guarded name leads
    /// to the home: with hidden files on, the app made `~/.aws` (or
    /// `~/.ssh`, missing while the keys are granted) a link to the home in
    /// one start, so in the next every font place led into a guarded place
    /// and was left out, and the whole home writable showed the fonts and
    /// the fonts settings writable to the app. Where a grant shows a font
    /// place, the read-only bind only narrows; where none does (a private
    /// home), the place is checked against the guarded places by their
    /// names, which such a link does not change. A font place that is
    /// itself a link to the home is a link and never bound.
    #[test]
    fn with_the_whole_home_writable_the_font_places_stay_bound_read_only() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let places = [".fonts", ".local/share/fonts", ".config/fontconfig"];
        for d in places {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        for planted in [".aws", ".ssh"] {
            let link = home.join(planted);
            std::os::unix::fs::symlink(&home, &link).unwrap();
            let guarded = guarded_places_everywhere(&home, &[]);
            let named = guarded_places_named(&home, &[]);
            assert!(guarded.contains(&home), "{planted}: {guarded:?}");
            assert!(!named.contains(&home), "{planted}: {named:?}");
            for rel in places {
                for shown in [true, false] {
                    assert_eq!(
                        own_place_decision(&host, rel, &|_| shown, &named, &guarded),
                        OwnBind::Bind,
                        "{planted} a link to the home, shown {shown}: ~/{rel} is bound read-only"
                    );
                }
                // The mutant "at or inside, also where links lead": every
                // font place lay inside the home.
                assert_eq!(
                    own_place_decision(&host, rel, &|_| false, &guarded, &guarded),
                    OwnBind::Inside(home.clone()),
                    "{planted}: ~/{rel} judged where the guarded links lead"
                );
            }
            std::fs::remove_file(&link).unwrap();
        }
        // A font place that is itself a link to the home: never bound.
        let guarded = guarded_places_everywhere(&home, &[]);
        let named = guarded_places_named(&home, &[]);
        let fonts = home.join(".fonts");
        std::fs::remove_dir(&fonts).unwrap();
        std::os::unix::fs::symlink(&home, &fonts).unwrap();
        for shown in [true, false] {
            assert!(matches!(
                own_place_decision(&host, ".fonts", &|_| shown, &named, &guarded),
                OwnBind::Link(l) if l.leads == home
            ));
        }
    }

    /// Where another grant of this start shows a font place (an extra
    /// writable folder `~/.config` in a private home), the place stays
    /// bound read-only although a guarded name leads into it: with hidden
    /// files on, the app made `~/.config/vivaldi` a link to
    /// `~/.config/fontconfig` in one start, so in the next the fonts
    /// settings were left out and the extra folder showed them writable.
    /// Without such a grant, the place holds where a guarded link leads and
    /// stays left out, nothing exposed. A font place that is a link to the
    /// home is never bound.
    #[test]
    fn a_font_place_another_grant_shows_writable_stays_bound_read_only() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let fontconfig = home.join(".config/fontconfig");
        std::fs::create_dir_all(&fontconfig).unwrap();
        std::os::unix::fs::symlink(&fontconfig, home.join(".config/vivaldi")).unwrap();
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let mut p = PermissionSet::strict_gui();
        p.filesystem.hidden_files = true;
        p.filesystem.custom_write = vec![home.join(".config").display().to_string()];
        let guarded = guarded_places_everywhere(&home, &[]);
        let named = guarded_places_named(&home, &[]);
        assert!(guarded.contains(&fontconfig), "{guarded:?}");
        let grants = GrantsShown::of(&p, &host, &[], &none());
        assert!(grants.shows(&fontconfig), "{grants:?}");
        let why =
            |rel: &str, shown: bool| own_place_decision(&host, rel, &|_| shown, &named, &guarded);
        assert_eq!(why(".config/fontconfig", true), OwnBind::Bind);
        assert_eq!(
            why(".config/fontconfig", false),
            OwnBind::Holds(fontconfig.clone())
        );
        assert_eq!(
            own_places_from_settings(&p, &host, &[], &none())
                .into_iter()
                .find(|(r, _)| *r == ".config/fontconfig")
                .map(|(_, d)| d),
            Some(OwnBind::Bind)
        );
        // The home itself: a link, never bound, shown or not.
        std::os::unix::fs::symlink(&home, home.join(".fonts")).unwrap();
        assert!(matches!(why(".fonts", true), OwnBind::Link(_)));
    }

    /// With the home kept behind a link (`/home/u` a link to `/data/u`) and
    /// a private home, an extra `~/.config`, read-only or writable, is
    /// recorded at `/data/u/.config`: it shows the font settings, but not at
    /// their name `/home/u/.config/fontconfig`, where a bind of SAM's in the
    /// private home shows them anew. With `~/.git-credentials` kept as a
    /// link into them, they hold that credential and are not bound at
    /// their name (the app page and the sandbox check say so); without the
    /// link they are.
    #[test]
    fn a_grant_under_another_name_never_lets_a_font_place_hold_a_credential() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        std::fs::create_dir_all(real.join(".config/fontconfig")).unwrap();
        std::fs::write(real.join(".config/fontconfig/gc"), "secret").unwrap();
        std::fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        let host = HostInfo {
            home: named.clone(),
            ..Default::default()
        };
        let cred = real.join(".git-credentials");
        for writable in [false, true] {
            let mut p = PermissionSet::strict_gui();
            let config = vec![named.join(".config").display().to_string()];
            if writable {
                p.filesystem.custom_write = config;
            } else {
                p.filesystem.custom_read = config;
            }
            let grants = GrantsShown::of(&p, &host, &[], &none());
            let at = named.join(".config/fontconfig");
            assert!(grants.shows(&at), "writable {writable}: {grants:?}");
            assert!(
                !grants.shows_at_name(&at),
                "writable {writable}: {grants:?}"
            );
            let decided = || {
                own_places_from_settings(&p, &host, &[], &none())
                    .into_iter()
                    .find(|(r, _)| *r == ".config/fontconfig")
                    .map(|(_, d)| d)
            };
            std::os::unix::fs::symlink(named.join(".config/fontconfig/gc"), &cred).unwrap();
            assert!(
                matches!(decided(), Some(OwnBind::Holds(_))),
                "writable {writable}: {:?}",
                decided()
            );
            std::fs::remove_file(&cred).unwrap();
            assert_eq!(decided(), Some(OwnBind::Bind), "writable {writable}");
        }
    }

    /// With the whole home writable, a user folder set read-only is shown
    /// through the home, writable: a link the app made in it is not
    /// followed out of what the home and the user folders show, for a
    /// read-only bind or a writable one. With the home read-only, the
    /// folder's own switch decides: the app cannot have made the link.
    #[test]
    fn a_user_folder_in_a_writable_home_counts_as_one_the_app_can_change() {
        use crate::permissions::Access;
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let outside = base.join("outside");
        for d in [home.join("Downloads"), outside.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let mut host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        host.xdg_dirs
            .insert("downloads".into(), home.join("Downloads"));
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        p.filesystem.downloads = Access::Ro;
        let planted = home.join("Downloads/x");
        std::os::unix::fs::symlink(&outside, &planted).unwrap();
        for write in [false, true] {
            assert_eq!(
                linked_place_left_out(&p, &host, &planted, write, &none()),
                Some(LeftOut::Link(planted.clone())),
                "write: {write}"
            );
        }
        p.filesystem.home_access = Access::Ro;
        assert_eq!(
            linked_place_left_out(&p, &host, &planted, false, &none()),
            None
        );
    }

    /// A writable bind follows a link the app could have planted only into
    /// what the home and the user folders show writable: with the home
    /// read-only, a writable extra folder in a writable user folder that
    /// the app made a link to the home, or to a read-only user folder, is
    /// left out (bound there, it made the read-only home writable). A
    /// read-only extra folder there still leads into the home, which shows
    /// it anyway; a writable one into a writable user folder or a writable
    /// home is followed. The launch note for a writable extra or user
    /// folder left out so never says the app is not shown the place: the
    /// read-only home still shows it.
    #[test]
    fn a_writable_bind_follows_a_planted_link_only_into_what_is_shown_writable() {
        use crate::permissions::Access;
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        for d in ["Downloads", "Documents/sub", "Pictures"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let mut host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        for (key, d) in [
            ("downloads", "Downloads"),
            ("documents", "Documents"),
            ("pictures", "Pictures"),
        ] {
            host.xdg_dirs.insert(key.into(), home.join(d));
        }
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        p.filesystem.downloads = Access::Rw;
        p.filesystem.documents = Access::Rw;
        p.filesystem.pictures = Access::Ro;
        let out = home.join("Downloads/out");
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&out);
            std::os::unix::fs::symlink(target, &out).unwrap();
        };
        for target in [home.clone(), home.join("Pictures")] {
            to(&target);
            let why = linked_place_left_out(&p, &host, &out, true, &none());
            assert_eq!(
                why,
                Some(LeftOut::Link(out.clone())),
                "{}",
                target.display()
            );
            assert_eq!(linked_place_left_out(&p, &host, &out, false, &none()), None);
            let why = why.unwrap();
            for (kind, says) in [
                (LeftOutPlace::Extra, "leaves out the writable folder"),
                (
                    LeftOutPlace::UserFolder,
                    "leaves out the writable user folder",
                ),
            ] {
                let note = left_out_note("~/Downloads/out", &why, kind, true);
                assert!(
                    note.contains(says)
                        && note.contains("may have made that link")
                        && !note.contains("not shown otherwise"),
                    "{note}"
                );
            }
        }
        to(&home.join("Documents/sub"));
        assert_eq!(linked_place_left_out(&p, &host, &out, true, &none()), None);
        to(&home);
        p.filesystem.home_access = Access::Rw;
        assert_eq!(linked_place_left_out(&p, &host, &out, true, &none()), None);
    }

    /// A writable bind follows a link the app could have planted only into
    /// what the sandbox really shows writable, each folder at the access it
    /// is mounted at. With the whole home writable and Documents set
    /// read-only, the sandbox mounts Documents read-only over the home: a
    /// writable extra folder `~/x` the app made a link to `~/Documents/sub`
    /// is left out (bound there, it made a folder inside the read-only
    /// Documents writable), while a read-only one is followed and a link
    /// into a place the home shows writable still is. Music read and write
    /// and Pictures read-only, both set to `~/Media`, are both read-only
    /// there, so a writable extra folder made a link into `~/Media` is left
    /// out too; an extra read-only folder makes its place read-only the
    /// same way. A writable user folder set to a link in a folder only this
    /// start shows writable is left out when the link leads into the
    /// read-only Documents.
    #[test]
    fn a_writable_bind_never_follows_a_planted_link_into_a_read_only_folder() {
        use crate::permissions::Access;
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        for d in ["Documents/sub", "Media/sub", "ref/sub", "free", "Sync"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::create_dir_all(base.join("usb")).unwrap();
        let mut host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        host.xdg_dirs
            .insert("documents".into(), home.join("Documents"));
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        p.filesystem.documents = Access::Ro;
        let x = home.join("x");
        let to = |link: &Path, target: &Path| {
            let _ = std::fs::remove_file(link);
            std::os::unix::fs::symlink(target, link).unwrap();
        };
        // The writable home, Documents read-only.
        to(&x, &home.join("Documents/sub"));
        assert_eq!(
            linked_place_left_out(&p, &host, &x, true, &none()),
            Some(LeftOut::Link(x.clone()))
        );
        assert_eq!(linked_place_left_out(&p, &host, &x, false, &none()), None);
        to(&x, &home.join("free"));
        assert_eq!(linked_place_left_out(&p, &host, &x, true, &none()), None);
        p.filesystem.documents = Access::Rw;
        to(&x, &home.join("Documents/sub"));
        assert_eq!(linked_place_left_out(&p, &host, &x, true, &none()), None);
        p.filesystem.documents = Access::Ro;

        // An extra read-only folder in the writable home.
        p.filesystem.custom_read = vec![home.join("ref").to_string_lossy().into_owned()];
        to(&x, &home.join("ref/sub"));
        assert_eq!(
            linked_place_left_out(&p, &host, &x, true, &none()),
            Some(LeftOut::Link(x.clone()))
        );
        p.filesystem.custom_read.clear();
        assert_eq!(linked_place_left_out(&p, &host, &x, true, &none()), None);

        // A writable user folder whose link lies in a folder only this
        // start shows writable (`app /mnt/usb` with opened files writable).
        let dl = base.join("usb/dl");
        to(&dl, &home.join("Documents/sub"));
        host.xdg_dirs.insert("downloads".into(), dl.clone());
        p.filesystem.downloads = Access::Rw;
        let usb = ThisStart {
            writable: vec![base.join("usb")],
            ..Default::default()
        };
        assert_eq!(
            user_folder_left_out(&p, &host, "downloads", &usb),
            Some(LeftOut::Link(dl.clone()))
        );
        p.filesystem.documents = Access::Rw;
        assert_eq!(user_folder_left_out(&p, &host, "downloads", &usb), None);
        host.xdg_dirs.remove("downloads");
        p.filesystem.downloads = Access::None;

        // Music read and write and Pictures read-only, both set to
        // `~/Media`, in a private home; `~/Sync` and `~/Sync/x` writable
        // extra folders, the app made `~/Sync/x` a link to `~/Media/sub`.
        let mut p = PermissionSet::strict_gui();
        for key in ["music", "pictures"] {
            host.xdg_dirs.insert(key.into(), home.join("Media"));
        }
        p.filesystem.music = Access::Rw;
        p.filesystem.pictures = Access::Ro;
        let sync_x = home.join("Sync/x");
        p.filesystem.custom_write = [home.join("Sync"), sync_x.clone()]
            .iter()
            .map(|d| d.to_string_lossy().into_owned())
            .collect();
        to(&sync_x, &home.join("Media/sub"));
        assert_eq!(
            linked_place_left_out(&p, &host, &sync_x, true, &none()),
            Some(LeftOut::Link(sync_x.clone()))
        );
        p.filesystem.pictures = Access::None;
        assert_eq!(
            linked_place_left_out(&p, &host, &sync_x, true, &none()),
            None
        );
    }

    /// A user folder SAM binds on its own is left out where a link on its
    /// way lies in a folder the app can change and leads out of what the
    /// home shows, or where it leads to programs listening outside the
    /// sandbox, whoever made the link (with `~/Sync` writable,
    /// `~/Sync/Documents` made a link to `/tmp/tmux-…` showed the host's
    /// tmux sockets): where both hold, for the listening programs.
    /// Its own grant does not count, and a link you made in a home the app
    /// cannot change is followed.
    #[test]
    fn a_user_folder_behind_a_planted_link_is_left_out() {
        use crate::permissions::Access;
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let outside = base.join("outside");
        for d in [home.join("Sync"), home.join("Docs"), outside.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let sockets = tempfile::Builder::new()
            .prefix("tmux-")
            .tempdir_in("/tmp")
            .unwrap();
        let sockets = sockets.path().to_path_buf();
        let mut host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let docs = home.join("Sync/Documents");
        host.xdg_dirs.insert("documents".into(), docs.clone());
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&docs);
            std::os::unix::fs::symlink(target, &docs).unwrap();
        };
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Ro;
        p.filesystem.custom_write = vec![home.join("Sync").to_string_lossy().into_owned()];
        // The planted link to the sockets is left out for them: the note
        // names the danger and gives no way out, which for the planted link
        // would say to set the folder to the place it leads to.
        for (target, why) in [
            (&sockets, LeftOut::HostServices(sockets.clone())),
            (&outside, LeftOut::Link(docs.clone())),
        ] {
            to(target);
            assert_eq!(
                user_folder_left_out(&p, &host, "documents", &none()),
                Some(why),
                "{}",
                target.display()
            );
        }
        // Nothing the app can change on the way: only the sockets count.
        p.filesystem.custom_write.clear();
        to(&sockets);
        assert_eq!(
            user_folder_left_out(&p, &host, "documents", &none()),
            Some(LeftOut::HostServices(sockets.clone()))
        );
        to(&outside);
        assert_eq!(user_folder_left_out(&p, &host, "documents", &none()), None);
        // A link you made in the home, to a folder of its own: its own
        // writable grant does not make the link one the app could plant.
        p.filesystem.documents = Access::Rw;
        let mine = home.join("Docs/mine");
        std::os::unix::fs::symlink(home.join("Docs"), &mine).unwrap();
        host.xdg_dirs.insert("documents".into(), mine);
        assert_eq!(user_folder_left_out(&p, &host, "documents", &none()), None);
        // A planted user folder is no place that shows another link's
        // target either.
        host.xdg_dirs.insert("documents".into(), docs.clone());
        p.filesystem.custom_write = vec![home.join("Sync").to_string_lossy().into_owned()];
        let extra = home.join("Sync/extra");
        std::os::unix::fs::symlink(outside.join("x"), &extra).unwrap();
        std::fs::create_dir_all(outside.join("x")).unwrap();
        assert_eq!(
            linked_place_left_out(&p, &host, &extra, false, &none()),
            Some(LeftOut::Link(extra.clone()))
        );
    }

    /// A read-only grant never makes a folder one the app cannot change:
    /// with the whole home writable and `~/x` an extra read-only folder,
    /// the app made `~/x` a link to `~/.local/share` and
    /// `~/.local/share/fonts` a link to a folder it is not shown in one
    /// start, and the next start bound that folder as the fonts (counted
    /// read-only by `~/x`, `~/.local/share` hid the link). The extra folder
    /// itself leads into the home, which shows it anyway. With the home
    /// read-only the app changes nothing there, and an extra folder named
    /// by a link you made is followed. The fonts follow no link at all,
    /// whoever made it ([`own_place_way`]).
    #[test]
    fn a_read_only_grant_never_makes_a_folder_one_the_app_cannot_change() {
        use crate::permissions::Access;
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let secret = base.join("secret");
        for d in [home.join(".local/share"), secret.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let fonts = home.join(".local/share/fonts");
        std::os::unix::fs::symlink(&secret, &fonts).unwrap();
        std::os::unix::fs::symlink(home.join(".local/share"), home.join("x")).unwrap();
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let mut p = PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Rw;
        p.filesystem.custom_read = vec![home.join("x").to_string_lossy().into_owned()];
        let skipped = |p: &PermissionSet| {
            own_places_from_settings(p, &host, &[], &none())
                .into_iter()
                .any(|(r, d)| {
                    r == ".local/share/fonts" && matches!(d, OwnBind::Link(l) if l.link == fonts)
                })
        };
        assert!(skipped(&p));
        assert_eq!(
            linked_place_left_out(&p, &host, &fonts, false, &none()),
            Some(LeftOut::Link(fonts.clone()))
        );
        assert_eq!(
            linked_place_left_out(&p, &host, &home.join("x"), false, &none()),
            None
        );
        // Also with a writable extra folder above the read-only one.
        p.filesystem.home = false;
        p.filesystem.custom_write = vec![home.join(".local").to_string_lossy().into_owned()];
        assert_eq!(
            linked_place_left_out(&p, &host, &fonts, false, &none()),
            Some(LeftOut::Link(fonts.clone()))
        );
        assert!(skipped(&p));
        p.filesystem.custom_write.clear();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        assert_eq!(
            linked_place_left_out(&p, &host, &fonts, false, &none()),
            None
        );
        assert!(skipped(&p));
    }

    /// A folder this start shows writable besides the permissions (a
    /// folder opened with the app, writable; a writable bind of SAM's)
    /// holds links the app may have made, as a writable grant does: in a
    /// private home, an extra folder named by a link in such a folder is
    /// not followed out of what the app is shown.
    #[test]
    fn a_folder_this_start_shows_writable_counts_as_one_the_app_can_change() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let secret = base.join("secret");
        for d in [home.join("work"), secret.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let planted = home.join("work/fonts");
        std::os::unix::fs::symlink(&secret, &planted).unwrap();
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let p = PermissionSet::strict_gui();
        let opened = ThisStart {
            writable: vec![home.join("work")],
            sam_runtime: Vec::new(),
        };
        assert_eq!(
            linked_place_left_out(&p, &host, &planted, false, &none()),
            None
        );
        assert_eq!(
            linked_place_left_out(&p, &host, &planted, false, &opened),
            Some(LeftOut::Link(planted.clone()))
        );
    }

    /// A link nobody in the sandbox could have planted (an extra folder in
    /// a private home) to where programs outside the sandbox listen is left
    /// out, and the start says why: to a socket directly in `/tmp`, to a
    /// socket folder in `/tmp` by a name no list knows (`tmate-…`), to the
    /// host's runtime folder kept in `/tmp` or anywhere else, and to SAM's
    /// runtime folders wherever they are. A link to an ordinary folder is
    /// still followed. The fonts, which follow no link at all, name that
    /// danger for such a link in their note.
    #[test]
    fn a_link_to_any_place_where_outside_programs_listen_is_left_out() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let ordinary = base.join("ordinary");
        let runtime_elsewhere = base.join("runtime");
        let sam_runtime = base.join("sam-run");
        for d in [
            home.clone(),
            ordinary.clone(),
            runtime_elsewhere.clone(),
            sam_runtime.join("app"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        // A socket directly in `/tmp`, as PostgreSQL keeps its own.
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket = PathBuf::from(format!("/tmp/.s.SAMTEST.{}.{stamp}", std::process::id()));
        let _listening = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        struct Gone(PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _gone = Gone(socket.clone());
        let tmate = tempfile::Builder::new()
            .prefix("tmate-")
            .tempdir_in("/tmp")
            .unwrap();
        let tmate = tmate.path().to_path_buf();
        let runtime_in_tmp = tempfile::Builder::new()
            .prefix("runtime-dir-")
            .tempdir_in("/tmp")
            .unwrap();
        let runtime_in_tmp = runtime_in_tmp.path().to_path_buf();
        let p = PermissionSet::strict_gui();
        let fonts = home.join(".fonts");
        let note_of = |host: &HostInfo, this: &ThisStart| {
            let OwnPlaceWay::Link(link) = own_place_way(&host.home, ".fonts") else {
                panic!("~/.fonts is a link");
            };
            let skipped = [OwnLinkSkipped {
                rel: ".fonts",
                link,
                shown: false,
            }];
            own_place_links_note(host, this, &skipped, &[]).unwrap()
        };
        let check = |target: &Path, host: &HostInfo, this: &ThisStart| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
            let why = linked_place_left_out(&p, host, &fonts, false, this);
            assert_eq!(
                why,
                Some(LeftOut::HostServices(target.to_path_buf())),
                "{}",
                target.display()
            );
            let note = left_out_note(
                "~/.fonts",
                why.as_ref().unwrap(),
                LeftOutPlace::Extra,
                false,
            );
            assert!(
                note.contains("where programs outside the sandbox listen"),
                "{note}"
            );
            let note = note_of(host, this);
            assert!(
                note.contains(&format!(
                    "~/.fonts (a link to {}, where programs outside the sandbox listen)",
                    target.display()
                )),
                "{note}"
            );
        };
        let plain = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        check(&socket, &plain, &none());
        check(&tmate, &plain, &none());
        for runtime in [&runtime_in_tmp, &runtime_elsewhere] {
            let host = HostInfo {
                runtime_dir: Some(runtime.clone()),
                ..plain.clone()
            };
            check(runtime, &host, &none());
        }
        let sams = ThisStart {
            writable: Vec::new(),
            sam_runtime: vec![sam_runtime.clone()],
        };
        check(&sam_runtime.join("app"), &plain, &sams);
        // The control: an ordinary folder is followed, and its note names
        // no danger.
        let _ = std::fs::remove_file(&fonts);
        std::os::unix::fs::symlink(&ordinary, &fonts).unwrap();
        assert_eq!(
            linked_place_left_out(&p, &plain, &fonts, false, &sams),
            None
        );
        let note = note_of(&plain, &sams);
        assert!(
            note.contains(&format!("~/.fonts (a link to {})", ordinary.display()))
                && !note.contains("listen"),
            "{note}"
        );
    }

    /// The way to a place SAM shows on its own counts only the links below
    /// the home's real place ([`own_place_way`]): a relative or absolute
    /// link, one inside the home or out of it, one that leads nowhere, a
    /// loop, the place itself or a folder on its way. A link that holds the
    /// home itself (`/home/u` a link to `/data/u`) never counts, so such a
    /// home keeps its fonts. A missing part, a file on the way, a named
    /// pipe at the place, and a link on the way behind which the place does
    /// not exist leave nothing to bind. Every name SAM binds on its own is
    /// a plain path below the home, free of `..` and `.`, so no later entry
    /// slips past the walk.
    #[test]
    fn the_walk_to_an_own_place_counts_only_links_below_the_real_home() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        let outside = base.join("outside");
        for d in [
            real.join("dotfiles/config/fontconfig"),
            real.join("myfonts"),
            real.join(".local/share/fonts"),
            outside.clone(),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        let way = |rel: &str| own_place_way(&named, rel);
        let link = |rel: &str| match way(rel) {
            OwnPlaceWay::Link(l) => l,
            other => panic!("~/{rel}: {other:?}"),
        };
        // The home behind a link, no link below it.
        assert_eq!(way(".local/share/fonts"), OwnPlaceWay::Plain);
        // Missing.
        assert_eq!(way(".fonts"), OwnPlaceWay::Missing);
        assert_eq!(way(".config/fontconfig"), OwnPlaceWay::Missing);
        // The place itself, relative and absolute, inside the home (as
        // named and at its real place) and out of it.
        for target in [
            PathBuf::from("myfonts"),
            named.join("myfonts"),
            real.join("myfonts"),
            outside.clone(),
        ] {
            let _ = std::fs::remove_file(real.join(".fonts"));
            std::os::unix::fs::symlink(&target, real.join(".fonts")).unwrap();
            let l = link(".fonts");
            assert_eq!(l.link, named.join(".fonts"), "{}", target.display());
            assert!(l.exists, "{}", target.display());
            assert_eq!(l.says, target);
            assert_eq!(
                l.leads,
                if target == outside {
                    outside.clone()
                } else {
                    real.join("myfonts")
                }
            );
        }
        // Dangling, and a loop: named, leading nowhere.
        std::fs::remove_file(real.join(".fonts")).unwrap();
        std::os::unix::fs::symlink(base.join("gone"), real.join(".fonts")).unwrap();
        let l = link(".fonts");
        assert!(!l.exists && l.says == base.join("gone"), "{l:?}");
        std::fs::remove_file(real.join(".fonts")).unwrap();
        std::os::unix::fs::symlink(".fonts", real.join(".fonts")).unwrap();
        assert!(!link(".fonts").exists);
        std::fs::remove_file(real.join(".fonts")).unwrap();
        // A folder on the way (GNU Stow folds `~/.config`), relative.
        std::os::unix::fs::symlink("dotfiles/config", real.join(".config")).unwrap();
        let l = link(".config/fontconfig");
        assert_eq!(l.link, named.join(".config"));
        assert_eq!(l.leads, real.join("dotfiles/config"));
        assert!(l.exists);
        // Behind it, a place that is not there: nothing to name.
        assert_eq!(way(".config/gtk-3.0"), OwnPlaceWay::Missing);
        std::fs::remove_file(real.join(".config")).unwrap();
        // A dangling folder on the way: nothing to name.
        std::os::unix::fs::symlink(base.join("gone"), real.join(".config")).unwrap();
        assert_eq!(way(".config/fontconfig"), OwnPlaceWay::Missing);
        std::fs::remove_file(real.join(".config")).unwrap();
        // A file on the way, and a named pipe at the place.
        std::fs::write(real.join(".config"), "").unwrap();
        assert_eq!(way(".config/fontconfig"), OwnPlaceWay::Missing);
        std::fs::remove_file(real.join(".config")).unwrap();
        let fifo = real.join(".gtkrc-2.0");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        assert_eq!(way(".gtkrc-2.0"), OwnPlaceWay::Missing);
        std::fs::remove_file(&fifo).unwrap();
        std::fs::write(&fifo, "").unwrap();
        assert_eq!(way(".gtkrc-2.0"), OwnPlaceWay::Plain);
        // Every name is a plain path below the home.
        let mut all = PermissionSet::strict_gui();
        all.advanced.host_themes = true;
        let names = own_home_places(&all);
        assert_eq!(names.len(), 3 + THEME_FILES.len());
        for rel in names {
            assert!(
                !rel.is_empty()
                    && Path::new(rel)
                        .components()
                        .all(|c| matches!(c, Component::Normal(_))),
                "{rel}"
            );
        }
    }

    /// One note per start names every font and theme place SAM skips for
    /// a link and where each link leads ([`own_place_links_note`]): in the
    /// order of [`own_home_places`], the places behind one link together,
    /// each place in the home written `~` under both names of a home kept
    /// behind a link, a link that leads nowhere as it says, and for a link
    /// to where programs outside the sandbox listen that danger. It never
    /// says the place is hidden. It tells how to show the files only where
    /// no grant shows the place, and names the places it keeps read-only.
    #[test]
    fn one_note_names_every_font_and_theme_link_and_where_it_leads() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let real = base.join("data/u");
        let named = base.join("home/u");
        for d in [
            "dotfiles/config/fontconfig",
            "dotfiles/config/gtk-3.0",
            "myfonts",
        ] {
            std::fs::create_dir_all(real.join(d)).unwrap();
        }
        std::fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, &named).unwrap();
        std::os::unix::fs::symlink(real.join("dotfiles/config"), real.join(".config")).unwrap();
        std::os::unix::fs::symlink("myfonts", real.join(".fonts")).unwrap();
        std::fs::create_dir_all(real.join(".local/share")).unwrap();
        std::os::unix::fs::symlink(base.join("gone"), real.join(".local/share/fonts")).unwrap();
        let sockets = tempfile::Builder::new()
            .prefix("tmux-")
            .tempdir_in("/tmp")
            .unwrap();
        let sockets = std::fs::canonicalize(sockets.path()).unwrap();
        std::os::unix::fs::symlink(&sockets, real.join(".icons")).unwrap();
        let host = HostInfo {
            home: named.clone(),
            ..Default::default()
        };
        let mut p = PermissionSet::strict_gui();
        p.advanced.host_themes = true;
        let decided = own_places_from_settings(&p, &host, &[], &none());
        let links: Vec<&str> = decided
            .iter()
            .filter(|(_, d)| matches!(d, OwnBind::Link(_)))
            .map(|(r, _)| *r)
            .collect();
        assert_eq!(
            links,
            [
                ".local/share/fonts",
                ".fonts",
                ".config/fontconfig",
                ".config/gtk-3.0",
                ".icons"
            ]
        );
        let note = own_place_links_note_from_settings(&p, &host, &[], &none()).unwrap();
        let items = format!(
            "SAM does not bind ~/.local/share/fonts (a link to {gone}, which leads nowhere now); \
             ~/.fonts (a link to ~/myfonts); \
             ~/.config/fontconfig, ~/.config/gtk-3.0 (behind ~/.config, a link to ~/dotfiles/config); \
             ~/.icons (a link to {sockets}, where programs outside the sandbox listen) \
             for this app on its own: each is a link, or lies behind a link, in your home, \
             and SAM does not follow such a link for your fonts and theme files. \
             The app still sees what its other folders show there. \
             If you made the link yourself, keeping the real files at that place lets SAM show them.",
            gone = base.join("gone").display(),
            sockets = sockets.display(),
        );
        assert_eq!(note, items);
        assert!(
            !note.contains("hidden") && !note.contains("not shown"),
            "{note}"
        );
        // A grant that shows every place: no advice; and a place kept
        // read-only is named.
        let link = |rel: &'static str| {
            decided
                .iter()
                .find_map(|(r, d)| match d {
                    OwnBind::Link(l) if *r == rel => Some(OwnLinkSkipped {
                        rel,
                        link: l.clone(),
                        shown: true,
                    }),
                    _ => None,
                })
                .unwrap()
        };
        let note = own_place_links_note(&host, &none(), &[link(".fonts")], &[real.join("myfonts")])
            .unwrap();
        assert!(
            note.ends_with(
                "The app still sees what its other folders show there. \
                 SAM keeps ~/myfonts read-only where the app's other folders show them."
            ),
            "{note}"
        );
        assert_eq!(own_place_links_note(&host, &none(), &[], &[]), None);
    }

    /// In a private home, a font place that lies in a guarded place by its
    /// name (SAM's own folder set to `~/.local/share`), or holds one by its
    /// name (`XDG_DATA_HOME` set inside `~/.fonts`, which puts the keyrings
    /// folder there), is not bound, and the start says why
    /// ([`own_place_decision`]); where a grant shows the place anyway, it
    /// is bound read-only, which only narrows it.
    #[test]
    fn a_font_place_inside_a_guarded_place_by_name_is_not_bound_in_a_private_home() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        for d in [".local/share/fonts", ".fonts", "dat/fonts"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let host = HostInfo {
            home: home.clone(),
            ..Default::default()
        };
        let sams = [home.join(".local/share")];
        let named = guarded_places_named_with(&home, &sams, None, None);
        let everywhere = guarded_places_everywhere_with(&home, &sams, None, None);
        let decide = |rel: &str, shown: bool| {
            own_place_decision(&host, rel, &|_| shown, &named, &everywhere)
        };
        assert_eq!(
            decide(".local/share/fonts", false),
            OwnBind::Inside(home.join(".local/share"))
        );
        assert_eq!(decide(".local/share/fonts", true), OwnBind::Bind);
        assert_eq!(decide(".fonts", false), OwnBind::Bind);
        let note = own_place_guarded_note(
            &host,
            ".local/share/fonts",
            &decide(".local/share/fonts", false),
        )
        .unwrap();
        assert_eq!(
            note,
            "SAM does not bind ~/.local/share/fonts for this app on its own because it lies in \
             ~/.local/share, a place SAM protects (your keys or passwords, files the desktop \
             runs, or SAM's own files). The app still sees what its other folders show there."
        );
        // A guarded place by name under `XDG_DATA_HOME`, set inside the
        // fonts: the fonts hold the keyrings folder.
        let in_fonts = home.join(".fonts/data");
        std::fs::create_dir_all(&in_fonts).unwrap();
        let named = guarded_places_named_with(&home, &[], None, Some(in_fonts.clone()));
        let everywhere = guarded_places_everywhere_with(&home, &[], None, Some(in_fonts.clone()));
        assert!(
            matches!(
                own_place_decision(&host, ".fonts", &|_| false, &named, &everywhere),
                OwnBind::Holds(g) if g.starts_with(&in_fonts)
            ),
            "{named:?}"
        );
        assert_eq!(
            own_place_decision(&host, ".fonts", &|_| true, &named, &everywhere),
            OwnBind::Bind
        );
    }

    /// Makes the folders `dirs` under `base`.
    fn make_dirs(base: &Path, dirs: &[&str]) {
        for d in dirs {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
    }

    /// Makes `at` a link to `to`.
    fn link_to(to: &Path, at: &Path) {
        std::os::unix::fs::symlink(to, at).unwrap();
    }

    /// Whether `r` refuses the opened path `p`, on its one walk.
    fn refuses_opened(r: &RefusedForOpened, p: &Path) -> bool {
        r.refuses(p, &follow(p))
    }

    /// A file or folder named on the command line is also refused where a
    /// key folder, start place or credential store really leads
    /// (`~/.netrc` a link to `~/Sync/netrc`, `~/.bashrc` to
    /// `~/dotfiles/bashrc`), while a user folder set there is shown as
    /// before (user folders do not ask this list). Where `~/.config` really
    /// is kept (`~/dotfiles/config`), other files are shared and the start
    /// places and stores in it are refused (`autostart/x.desktop`,
    /// `git/credentials`). Where a start place, key folder or credential
    /// store leads to the home (`~/.config/fish`, `~/.ssh`, `~/.oci` or
    /// `~/.password-store` a link to `~`), every file in the home is
    /// refused (`~/conf.d`, `~/config.fish`), and where a store leads to a
    /// folder above the home (`~/.kube` a link to the scratch folder
    /// standing for `/`), every file in that folder is. A way that does not
    /// end (a loop of links, `a` to `b` and `b` to `a`) is refused on its
    /// own, though it leads neither to the home nor above it.
    #[test]
    fn opened_files_are_also_refused_where_a_listed_place_leads() {
        let t = scratch();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/ann");
        make_dirs(
            &home,
            &[
                "Sync",
                "dotfiles/config/helix",
                "dotfiles/config/autostart",
                "dotfiles/config/git",
                "work",
            ],
        );
        for f in [
            "Sync/netrc",
            "dotfiles/bashrc",
            "dotfiles/config/helix/config.toml",
            "dotfiles/config/autostart/x.desktop",
            "dotfiles/config/git/credentials",
            "work/a.txt",
        ] {
            std::fs::write(home.join(f), "x").unwrap();
        }
        link_to(&home.join("Sync/netrc"), &home.join(".netrc"));
        link_to(&home.join("dotfiles/bashrc"), &home.join(".bashrc"));
        link_to(&home.join("dotfiles/config"), &home.join(".config"));
        let opened = refused_for_opened_with(&home, None, None);
        for p in [home.join("Sync/netrc"), home.join("dotfiles/bashrc")] {
            assert!(refuses_opened(&opened, &p), "{p:?} is not shared");
            assert!(
                user_folder_place(&p, &home).is_some(),
                "{p:?} as a user folder is shown"
            );
        }
        for f in [
            "dotfiles/config/autostart/x.desktop",
            "dotfiles/config/git/credentials",
        ] {
            assert!(
                refuses_opened(&opened, &home.join(f)),
                "{f} where ~/.config really is"
            );
        }
        for p in [
            home.join("work/a.txt"),
            home.join("dotfiles/config/helix/config.toml"),
        ] {
            assert!(!refuses_opened(&opened, &p), "{p:?} is shared");
        }
        // A start place, key folder or credential store that leads to the
        // home: the programs outside the sandbox read its files from the
        // home itself (fish reads `~/config.fish`, the OCI tool
        // `~/config`).
        for (who, place) in [
            ("bo", ".config/fish"),
            ("cy", ".ssh"),
            ("dee", ".oci"),
            ("eve", ".password-store"),
        ] {
            let home = base.join("home").join(who);
            make_dirs(&home, &[".config", "conf.d"]);
            for f in ["conf.d/x.fish", "config.fish"] {
                std::fs::write(home.join(f), "x").unwrap();
            }
            link_to(&home, &home.join(place));
            let opened = refused_for_opened_with(&home, None, None);
            for f in ["conf.d", "conf.d/x.fish", "config.fish"] {
                assert!(
                    refuses_opened(&opened, &home.join(f)),
                    "{f} with {place} a link to the home"
                );
            }
        }
        // A credential store that leads to a folder above the home refuses
        // every file in that folder, in the home and outside it; the system
        // folders are judged below the scratch folder, so only the store
        // refuses `out/x.txt`.
        let home = base.join("home/fay");
        make_dirs(&home, &["work"]);
        make_dirs(&base, &["out"]);
        for f in [home.join("work/a.txt"), base.join("out/x.txt")] {
            std::fs::write(&f, "x").unwrap();
        }
        link_to(&base, &home.join(".kube"));
        let opened = refused_for_opened_with(&home, None, None).under_root(base.clone());
        for p in [home.join("work/a.txt"), base.join("out/x.txt")] {
            assert!(
                refuses_opened(&opened, &p),
                "{p:?} with .kube a link above the home"
            );
        }
        // A way SAM cannot follow to its end (a loop of links, `a` to `b`
        // and `b` to `a`) is refused on its own: it leads neither to the
        // home nor above it, into no system folder (judged below the
        // scratch folder) and into no listed place (a home without links).
        let home = base.join("home/gus");
        make_dirs(&home, &["work"]);
        make_dirs(&base, &["loop"]);
        link_to(Path::new("b"), &base.join("loop/a"));
        link_to(Path::new("a"), &base.join("loop/b"));
        let opened = refused_for_opened_with(&home, None, None).under_root(base.clone());
        for p in [base.join("loop/a"), base.join("loop/a/x")] {
            let way = follow(&p);
            assert!(way.stuck, "{p:?} is a way that does not end");
            assert!(
                !is_home_or_above(&home, &home, &way.leads),
                "{p:?} leads neither to the home nor above it"
            );
            assert!(
                refuses_opened(&opened, &p),
                "{p:?} in a loop of links is not shared"
            );
        }
    }

    /// For files named on the command line, system folders count only
    /// outside the home: a home kept behind a link in a system folder
    /// (`/home/ann` a link to `/var/home/ann`, or `/home` a link to
    /// `/var/home` that is a link itself) keeps its files; a file in a
    /// system folder, one leading into one (`/mnt` a link to `/var/mnt`)
    /// and one whose way passes a link in one are refused; with the home
    /// at `/` (no `HOME`), nothing counts as in the home. What a system
    /// folder is: `/etc`, `/usr` and `/run` and what lies in them, not
    /// `/opt`, `/srv`, a drive under `/run/media` or `/home` (by the text
    /// alone). The files are judged below a scratch folder standing for
    /// `/`, so the computer's own layout never matters.
    #[test]
    fn opened_files_count_system_folders_only_outside_the_home() {
        for system in ["/etc/x", "/usr/share/doc", "/run/user/1000"] {
            assert!(crate::risk::is_system_folder(Path::new(system)), "{system}");
        }
        for other in ["/opt/x", "/srv/x", "/run/media/u/disk/Docs", "/home/u"] {
            assert!(!crate::risk::is_system_folder(Path::new(other)), "{other}");
        }
        let t = scratch();
        let root = std::fs::canonicalize(t.path()).unwrap();
        make_dirs(
            &root,
            &[
                "var/home/ann/Documents",
                "var/lib/x",
                "var/mnt/disk",
                "sys",
                "b",
                "opt/x",
                "etc/x",
                "home",
            ],
        );
        link_to(&root.join("var/home/ann"), &root.join("home/ann"));
        link_to(&root.join("var/mnt"), &root.join("mnt"));
        link_to(&root.join("b"), &root.join("sys/lnk"));
        link_to(&root.join("sys/lnk"), &root.join("a"));
        let home = root.join("home/ann");
        let r = refused_for_opened_with(&home, None, None).under_root(root.clone());
        assert!(
            !refuses_opened(&r, &home.join("Documents")),
            "the home under /var"
        );
        assert!(
            !refuses_opened(&r, &root.join("opt/x")),
            "/opt is no system folder"
        );
        for p in [
            root.join("var/lib/x"),
            root.join("mnt/disk"),
            root.join("a"),
        ] {
            assert!(refuses_opened(&r, &p), "{p:?} is refused");
        }
        // The home's own way passes a link in a system folder.
        let t2 = scratch();
        let root2 = std::fs::canonicalize(t2.path()).unwrap();
        make_dirs(&root2, &["data/home/ann/Documents", "var"]);
        link_to(&root2.join("data/home"), &root2.join("var/home"));
        link_to(&root2.join("var/home"), &root2.join("home"));
        let home2 = root2.join("home/ann");
        let r = refused_for_opened_with(&home2, None, None).under_root(root2.clone());
        assert!(
            !refuses_opened(&r, &home2.join("Documents")),
            "the home's own way"
        );
        // The home at `/`.
        let r = refused_for_opened_with(Path::new("/"), None, None).under_root(root.clone());
        assert!(refuses_opened(&r, &root.join("etc/x")), "the home at /");
    }
}
