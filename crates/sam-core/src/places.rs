//! Places in the home folder that SAM treats specially, shared by the
//! sandbox (which hides or locks them) and the risk words (which call a
//! grant of them dangerous), so both always mean the same places.

use std::path::{Component, Path, PathBuf};

use crate::host::HostInfo;
use crate::permissions::{PermissionSet, XDG_DIR_KEYS};

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

/// The protected places relative to the home: `PROTECTED_RO`, and the same
/// places under `XDG_CONFIG_HOME` and `XDG_DATA_HOME` when those point to
/// other folders inside the home (desktops and programs follow them, so
/// `~/cfg/autostart` starts programs as `~/.config/autostart` does; audit
/// S-F6). Shared by the sandbox, which locks them, and the warnings, which
/// say when a grant inside one is shown read-only.
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
    let mut out: Vec<String> = PROTECTED_RO.iter().map(|p| p.to_string()).collect();
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

/// Where a user folder (Documents, Downloads, …) set to `dir` is shown:
/// where it really is (links resolved), unless that would show more than a
/// user folder: the home, a folder above it, a system folder, a key or
/// credential store or a start place (`user-dirs.dirs` is a plain text
/// file, audit S-F11). The sandbox also refuses one inside SAM's own
/// folders; that is left to the caller, since which folders count as
/// SAM's depends on what the start shows ([`shown_folders`]).
pub fn user_folder_place(dir: &Path, home: &Path) -> Option<PathBuf> {
    let real = resolve(dir);
    let text = real.to_string_lossy();
    let real_home = resolve(home);
    let refused = real_home.starts_with(&real)
        || crate::risk::is_sensitive_path_in(&text, home)
        || crate::risk::is_sensitive_path_in(&text, &real_home);
    (!refused).then_some(real)
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
                .and_then(|d| user_folder_place(d, &host.home))
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
    if !is_sams_name(rel) {
        return false;
    }
    let at = home.join(rel);
    let real = resolve(&at);
    if own.iter().any(|d| *d == at || real.starts_with(resolve(d))) {
        return true;
    }
    let real_home = resolve(home);
    if is_home_or_above(home, &real_home, &real) {
        return false;
    }
    let through_link = real != real_home.join(rel);
    let shown_whole = shown.iter().any(|s| real.starts_with(s));
    let shown_inside = shown.iter().any(|s| s.starts_with(&real));
    !(through_link && shown_inside && !shown_whole)
}

/// SAM's own folders in a start that shows the folders `shown`
/// ([`shown_folders`]): where this SAM keeps its own (`own`:
/// [`crate::Paths::sam_dirs`]) and the protected places named like them
/// that count as SAM's ([`sams_folder_by_name`]). The sandbox hides them,
/// its check expects them hidden, and the start line and the app page
/// leave them out, all from this one list.
pub fn sams_folders(home: &Path, own: &[PathBuf], shown: &[PathBuf]) -> Vec<PathBuf> {
    sams_folders_in(home, own, shown, &protected_places(home))
}

/// [`sams_folders`] among the protected places `places`.
pub fn sams_folders_in(
    home: &Path,
    own: &[PathBuf],
    shown: &[PathBuf],
    places: &[String],
) -> Vec<PathBuf> {
    let mut out = own.to_vec();
    for rel in places {
        let at = home.join(rel);
        if !out.contains(&at) && sams_folder_by_name(home, rel, own, shown) {
            out.push(at);
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

/// Whether a place holds what programs outside the sandbox listen on: the
/// whole computer, `/tmp` or a folder in it where they listen
/// ([`crate::risk::shows_host_sockets`]: tmux, SSH, the X server), anything
/// under `/run` (`/run/user/<uid>` with the session bus, systemd's and
/// GnuPG's sockets; the system bus; Docker's socket) except drives under
/// `/run/media`, and `/proc` and `/dev` (`/dev/log`, `/dev/shm`).
/// Connecting to a socket needs no write access, so a read-only bind of
/// such a place hands them over: through tmux's socket the app runs
/// commands outside the sandbox.
pub fn leads_to_host_services(real: &Path) -> bool {
    let under = |d: &str| real.starts_with(d);
    real == Path::new("/")
        || crate::risk::shows_host_sockets(&real.to_string_lossy())
        || (under("/run") && !under("/run/media"))
        || under("/proc")
        || under("/dev")
}

/// Why SAM leaves out a place it would bind where its links lead: an extra
/// folder (`filesystem.custom_read`, `custom_write`) or a place of the home
/// SAM shows on its own (the fonts, the fonts settings, the theme files).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeftOut {
    /// The way there holds this link, in a folder the app can change, and
    /// leads out of what the app is shown: the app may have made the link
    /// in an earlier start (`ln -s /tmp/tmux-1000 ~/.fonts`).
    Link(PathBuf),
    /// Through a link it leads to this place, where programs outside the
    /// sandbox listen ([`leads_to_host_services`]), whoever made the link.
    HostServices(PathBuf),
    /// It leads to this place, which is or holds the home, a key or
    /// credential store, a protected place or SAM's own folders (only for
    /// the places SAM shows on its own, [`own_place_left_out`]).
    Guarded(PathBuf),
}

/// The folders the permissions `p` show, each where it really is, and
/// whether the app can change it: the whole home (as named and as
/// reached), the user folders, the extra folders. Judged from the
/// permissions alone, so the sandbox, its check and the app page take one
/// answer: a writable extra folder counts writable also where the sandbox
/// shows it read-only (inside a start place), which leaves out more, never
/// less.
fn permission_grants(p: &PermissionSet, host: &HostInfo) -> Vec<(PathBuf, bool)> {
    use crate::permissions::Access;
    let fs = &p.filesystem;
    let mut grants: Vec<(PathBuf, bool)> = Vec::new();
    if fs.home {
        let rw = fs.home_access == Access::Rw;
        grants.push((host.home.clone(), rw));
        grants.push((resolve(&host.home), rw));
    }
    for key in XDG_DIR_KEYS {
        let acc = fs.xdg_access(key);
        if acc.is_granted() {
            if let Some(real) = host
                .xdg_dir(key)
                .and_then(|d| user_folder_place(d, &host.home))
            {
                grants.push((real, acc == Access::Rw));
            }
        }
    }
    for c in &fs.custom_read {
        grants.push((resolve(&crate::util::expand_home(c)), false));
    }
    for c in &fs.custom_write {
        grants.push((resolve(&crate::util::expand_home(c)), true));
    }
    grants
}

/// Whether SAM leaves out the place `named` (with `~` expanded) that it
/// binds where its links lead, in a start with the permissions `p`: an
/// extra folder, read-only or writable, or a place of the home it shows on
/// its own ([`own_place_left_out`]). One rule for every such bind, so no
/// bind follows a link the app could have planted to a place it must not
/// reach:
/// - a link on the way that lies in a folder the app can change is not
///   followed out of what the whole home and the user folders show
///   (with the whole home writable, `~/.fonts` missing and an extra folder
///   not made yet, the app made them links to `/tmp/tmux-1000` or any
///   folder on the computer, and the next start bound what they named);
/// - a link that leads to a place where programs outside the sandbox listen
///   is not followed, whoever made it: that place is bound over the
///   sandbox's own `/tmp` or runtime folder and hands their sockets over.
///
/// An extra folder named by its real place (no link on the way) is shown
/// as written: its name was rated, and warned about, as it is.
pub fn linked_place_left_out(p: &PermissionSet, host: &HostInfo, named: &Path) -> Option<LeftOut> {
    let way = follow(named);
    let grants = permission_grants(p, host);
    // The deepest grant that shows a folder decides, as the mounts do.
    let can_change = |d: &Path| {
        grants
            .iter()
            .filter(|(g, _)| d.starts_with(g))
            .max_by_key(|(g, rw)| (g.components().count(), *rw))
            .is_some_and(|(_, rw)| *rw)
    };
    if let Some(link) = link_the_app_could_plant(&way, &can_change) {
        let fs = &p.filesystem;
        let in_home = fs.home
            && (way.leads.starts_with(&host.home) || way.leads.starts_with(resolve(&host.home)));
        let in_user_folder = XDG_DIR_KEYS.iter().any(|key| {
            fs.xdg_access(key).is_granted()
                && host
                    .xdg_dir(key)
                    .and_then(|d| user_folder_place(d, &host.home))
                    .is_some_and(|real| way.leads.starts_with(real))
        });
        if way.stuck || !(in_home || in_user_folder) {
            return Some(LeftOut::Link(link));
        }
    }
    if !way.links.is_empty() && leads_to_host_services(&way.leads) {
        return Some(LeftOut::HostServices(way.leads));
    }
    None
}

/// Every place a bind SAM makes on its own must never show
/// ([`own_place_left_out`]): the protected places, the key folders and the
/// credential stores of the home `home`, each under the home as named,
/// under its real place and where it really leads, and SAM's own folders
/// (`sams`).
pub fn guarded_places_everywhere(home: &Path, sams: &[PathBuf]) -> Vec<PathBuf> {
    let homes = [home.to_path_buf(), resolve(home)];
    let rels = protected_places(home)
        .into_iter()
        .chain(SENSITIVE_DOTFILES.iter().map(|s| s.to_string()))
        .chain([".ssh".to_string(), ".gnupg".to_string()]);
    let mut out: Vec<PathBuf> = Vec::new();
    for rel in rels {
        for h in &homes {
            let at = h.join(&rel);
            for g in [resolve(&at), at] {
                if !out.contains(&g) {
                    out.push(g);
                }
            }
        }
    }
    out.extend(sams.iter().cloned());
    out
}

/// [`linked_place_left_out`] for a place of the home that SAM shows on its
/// own, read-only (`~/.fonts`, `~/.local/share/fonts`,
/// `~/.config/fontconfig`, the theme files): also never one that leads to
/// the home or a folder above it, or into or onto one of the places in
/// `guarded` ([`guarded_places_everywhere`]). In a private home nothing
/// else guards what such a bind shows: `~/.fonts` made a link to `~/.ssh`
/// showed the keys as fonts.
pub fn own_place_left_out(
    p: &PermissionSet,
    host: &HostInfo,
    named: &Path,
    guarded: &[PathBuf],
) -> Option<LeftOut> {
    if let Some(why) = linked_place_left_out(p, host, named) {
        return Some(why);
    }
    let leads = follow(named).leads;
    let home_or_above = is_home_or_above(&host.home, &resolve(&host.home), &leads);
    if home_or_above
        || guarded
            .iter()
            .any(|g| leads.starts_with(g) || g.starts_with(&leads))
    {
        return Some(LeftOut::Guarded(leads));
    }
    None
}

/// What the start says about the place `shown` (as the person wrote it,
/// or `~/.fonts`) that SAM leaves out ([`LeftOut`]).
pub fn left_out_note(shown: &str, why: &LeftOut) -> String {
    let t = crate::util::tildify;
    match why {
        LeftOut::Link(link) => crate::i18n::trf(
            "SAM does not show {path} to this app because the way there leads through the link {link}, which lies in a folder the app can change, to a place the app is not shown otherwise: the app may have made that link. If you made it yourself, add the place it leads to as an extra folder.",
            &[("path", &shown), ("link", &t(link))],
        ),
        LeftOut::HostServices(place) => crate::i18n::trf(
            "SAM does not show {path} to this app because it leads through a link to {place}, where programs outside the sandbox listen: through them the app could run commands outside the sandbox.",
            &[("path", &shown), ("place", &t(place))],
        ),
        LeftOut::Guarded(place) => crate::i18n::trf(
            "SAM does not show {path} to this app because it leads to {place}, which is or holds your home folder, your keys or passwords, a place SAM protects or SAM's own files.",
            &[("path", &shown), ("place", &t(place))],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut found = sams_folders_in(&home, &[], &[], &places);
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
                &places
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
        let sams = sams_folders_in(&home, &[], std::slice::from_ref(&work), &places);
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
        let sams = sams_folders_in(&home, &own, whole, &places);
        assert_eq!(named(&sams), Some(".config/sam".to_string()));
        // Hidden as SAM's (where this SAM keeps its own): not named.
        let own_there = [at(".config/sam")];
        let sams = sams_folders_in(&home, &own_there, whole, &places);
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
    /// computer, `/tmp` and its socket folders, `/run` (the runtime folder
    /// among it) but not drives under `/run/media`, `/proc` and `/dev`. An
    /// ordinary folder in `/tmp` or the home is none.
    #[test]
    fn the_places_where_outside_programs_listen_are_known() {
        for p in [
            "/",
            "/tmp",
            "/tmp/tmux-1000",
            "/tmp/ssh-XXXX/agent.1",
            "/tmp/.X11-unix",
            "/run",
            "/run/user/1000",
            "/run/user/1000/bus",
            "/run/dbus",
            "/run/docker.sock",
            "/proc/1/root",
            "/dev/shm",
        ] {
            assert!(leads_to_host_services(Path::new(p)), "{p}");
        }
        for p in [
            "/tmp/exchange",
            "/run/media/u/disk/fonts",
            "/home/u/.fonts",
            "/usr/share/fonts",
            "/runner",
        ] {
            assert!(!leads_to_host_services(Path::new(p)), "{p}");
        }
    }

    /// One rule for every bind through links (`~/.fonts`, an extra folder):
    /// with the whole home writable, a link in it is not followed out of
    /// what the home shows (the app may have planted it), also when its
    /// target does not exist yet; one that stays in the home is. Without a
    /// folder the app can change, a link is followed, unless it leads to
    /// where programs outside the sandbox listen. A place named by its real
    /// path (no link) is never left out: its name was rated as it is. A
    /// link in a writable user folder counts as well, one in a read-only
    /// home not.
    #[test]
    fn a_linked_place_is_left_out_where_a_planted_link_leads_out_or_to_host_services() {
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let home = base.join("home/u");
        let outside = base.join("outside");
        for d in [
            home.join("myfonts"),
            home.join("Documents"),
            outside.clone(),
        ] {
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
        let fonts = home.join(".fonts");
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
        };
        to(&sockets);
        assert_eq!(
            linked_place_left_out(&whole, &host, &fonts),
            Some(LeftOut::Link(fonts.clone()))
        );
        assert_eq!(
            linked_place_left_out(&private, &host, &fonts),
            Some(LeftOut::HostServices(sockets.clone()))
        );
        to(&outside);
        assert_eq!(
            linked_place_left_out(&whole, &host, &fonts),
            Some(LeftOut::Link(fonts.clone()))
        );
        assert_eq!(linked_place_left_out(&private, &host, &fonts), None);
        to(&base.join("not-there-yet"));
        assert_eq!(
            linked_place_left_out(&whole, &host, &fonts),
            Some(LeftOut::Link(fonts.clone()))
        );
        to(&home.join("myfonts"));
        assert_eq!(linked_place_left_out(&whole, &host, &fonts), None);
        // A read-only home: the app cannot have put the link there.
        let mut ro = whole.clone();
        ro.filesystem.home_access = crate::permissions::Access::Ro;
        to(&outside);
        assert_eq!(linked_place_left_out(&ro, &host, &fonts), None);
        // Named by its real place: shown as written (and warned about).
        assert_eq!(linked_place_left_out(&private, &host, &sockets), None);
        assert_eq!(linked_place_left_out(&whole, &host, &outside), None);
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
            linked_place_left_out(&docs, &host_docs, &planted),
            Some(LeftOut::Link(planted.clone()))
        );
        docs.filesystem.documents = crate::permissions::Access::Ro;
        assert_eq!(linked_place_left_out(&docs, &host_docs, &planted), None);
        // The note names the place and why.
        let note = left_out_note("~/.fonts", &LeftOut::Link(fonts.clone()));
        assert!(
            note.contains("~/.fonts") && note.contains("may have made that link"),
            "{note}"
        );
        let note = left_out_note("~/.fonts", &LeftOut::HostServices(sockets.clone()));
        assert!(
            note.contains(&sockets.display().to_string())
                && note.contains("where programs outside the sandbox listen"),
            "{note}"
        );
    }

    /// A place SAM shows on its own (`~/.fonts`) never leads to the home,
    /// a folder above it, a key folder (also where it is kept behind a
    /// link), a credential store, a folder holding a protected place
    /// (`~/.config`) or SAM's own folders, whoever made the link: in a
    /// private home nothing else hides what such a bind shows. A fonts
    /// folder of your own is shown.
    #[test]
    fn an_own_place_never_leads_to_the_home_keys_or_sams_folders() {
        let t = tempfile::tempdir().unwrap();
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
        let p = PermissionSet::strict_gui();
        let sams = [home.join("Games/sam")];
        let guarded = guarded_places_everywhere(&home, &sams);
        let fonts = home.join(".fonts");
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
            own_place_left_out(&p, &host, &fonts, &guarded)
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
        ] {
            assert!(
                matches!(to(&target), Some(LeftOut::Guarded(_))),
                "{}",
                target.display()
            );
        }
        assert_eq!(to(&home.join("myfonts")), None);
        std::fs::remove_file(&fonts).unwrap();
        assert_eq!(own_place_left_out(&p, &host, &fonts, &guarded), None);
        assert_eq!(
            own_place_left_out(&p, &host, &home.join(".config/fontconfig"), &guarded),
            None
        );
    }
}
