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
    places_following(PROTECTED_RO, home, config, data)
}

/// The credential stores relative to the home: `SENSITIVE_DOTFILES`, and
/// the same places under `XDG_CONFIG_HOME` and `XDG_DATA_HOME` when those
/// point to other folders inside the home, as [`protected_places`] finds
/// them. Programs keep their secrets where those variables say: with
/// `XDG_CONFIG_HOME=~/cfg`, git-credential-store keeps its passwords in
/// `~/cfg/git/credentials`, and only the fixed `~/.config/git/credentials`
/// was hidden, so an app with the whole home could read them (`~/cfg/git`
/// is only locked read-only). Shared by the sandbox, which hides them,
/// and the files opened for a start, which never share them.
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
    places_following(SENSITIVE_DOTFILES, home, config, data)
}

/// `list`, and each of its places under `.config/` or `.local/share/`
/// again under `config` and `data` where those are other folders inside
/// the home.
fn places_following(
    list: &[&str],
    home: &Path,
    config: Option<PathBuf>,
    data: Option<PathBuf>,
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
                if !r.is_empty() && format!("{r}/") != default && !rels.contains(&r) {
                    rels.push(r);
                }
            }
        }
        for rel in rels {
            for p in list {
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
/// folder (`filesystem.custom_read`, `custom_write`) or a place of the home
/// SAM shows on its own (the fonts, the fonts settings, the theme files).
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
    /// It leads to this place, which is or holds the home, a key or
    /// credential store, a protected place or SAM's own folders (only for
    /// the places SAM shows on its own, [`own_place_left_out`]).
    Guarded(PathBuf),
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
/// never less. A user folder in a writable home counts writable whatever
/// its own switch says: the sandbox shows it through the home, writable
/// (with the home writable and Downloads read-only, a link the app made
/// in `~/Downloads` was followed out of what it is shown).
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

/// Whether the whole home shows `leads` as a bind there needs it: at all
/// for a read-only bind, writable for a writable one (`write`). With the
/// home read-only, a writable extra folder planted as a link to the home
/// bound the whole home writable.
fn home_shows(p: &PermissionSet, host: &HostInfo, leads: &Path, write: bool) -> bool {
    let fs = &p.filesystem;
    fs.home && (!write || fs.home_access == crate::permissions::Access::Rw) && in_home(host, leads)
}

/// The rule for a bind where the links of `way` lead ([`linked_place_left_out`],
/// [`user_folder_left_out`]): `writable` names the folders the app can
/// change ([`writable_grants`]), `shown` whether the place the way leads to
/// is shown anyway; `host` and `this` say where programs outside the
/// sandbox listen ([`leads_to_host_services`]).
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
    if let Some(link) = link_the_app_could_plant(&way, &can_change) {
        if way.stuck || !shown(&way.leads) {
            return Some(LeftOut::Link(link));
        }
    }
    if !way.links.is_empty() && leads_to_host_services(&way.leads, host, this) {
        return Some(LeftOut::HostServices(way.leads));
    }
    // Where the way ends is not all: a link in `/tmp` the host made may
    // send it on to a socket folder SAM does not know by its place. A link
    // that only points into such a place either ends there (judged above)
    // or meets the next link there.
    way.links
        .iter()
        .find(|link| passes_host_services(link, host, this))
        .map(|link| LeftOut::HostServices(link.clone()))
}

/// Whether SAM leaves out the place `named` (with `~` expanded) that it
/// binds where its links lead, in a start with the permissions `p`: an
/// extra folder, read-only or writable (`write`), or a place of the home
/// it shows on its own ([`own_place_left_out`]). One rule for every such
/// bind, so no bind follows a link the app could have planted to a place
/// it must not reach:
/// - a link on the way that lies in a folder the app can change
///   ([`writable_grants`]: any writable grant shows it, also below a
///   read-only one, or `this` start shows it writable) is not followed
///   out of what the whole home and the user folders show, and
///   for a writable bind out of what they show writable (with the whole
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
    use crate::permissions::Access;
    let fs = &p.filesystem;
    let home_rw = fs.home && fs.home_access == Access::Rw;
    let shown = |leads: &Path| {
        home_shows(p, host, leads, write)
            || XDG_DIR_KEYS.iter().any(|key| {
                let acc = fs.xdg_access(key);
                acc.is_granted()
                    && user_folder_left_out(p, host, key, this).is_none()
                    && host
                        .xdg_dir(key)
                        .and_then(|d| user_folder_place(d, &host.home))
                        .is_some_and(|real| {
                            leads.starts_with(&real)
                                && (!write
                                    || acc == Access::Rw
                                    || (home_rw && in_home(host, &real)))
                        })
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
/// only into a home shown as the folder needs it, and a link to where
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
    let shown = |leads: &Path| home_shows(p, host, leads, write);
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
/// [`user_folder_left_out`], whose note names the danger or the link and
/// the way out, then [`user_folder_link_the_app_can_change`], then the
/// socket folders by name. One answer for the sandbox, which leaves the
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

/// Every place a bind SAM makes on its own must never show
/// ([`own_place_left_out`]): the protected places, the key folders and the
/// credential stores of the home `home`, each under the home as named,
/// under its real place and where it really leads, and SAM's own folders
/// (`sams`). The protected places and the credential stores follow
/// `XDG_CONFIG_HOME` and `XDG_DATA_HOME` ([`protected_places`],
/// [`sensitive_places`]): with `XDG_CONFIG_HOME=~/cfg`, `~/.fonts` made a
/// link to `~/cfg/gh` (where the GitHub tool keeps its token) in an
/// earlier start with the whole home writable was bound in a private home,
/// since only `~/.config/gh` was guarded.
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
    let homes = [home.to_path_buf(), resolve(home)];
    let rels = protected_places_with(home, config.clone(), data.clone())
        .into_iter()
        .chain(sensitive_places_with(home, config, data))
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
    this: &ThisStart,
) -> Option<LeftOut> {
    if let Some(why) = linked_place_left_out(p, host, named, false, this) {
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

/// Which kind of place SAM leaves out ([`left_out_note`]): what to do
/// about a link the person made differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftOutPlace {
    /// A place of the home SAM shows on its own (`~/.fonts`, the theme
    /// files).
    Own,
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
/// what the home and the user folders show writable, so the place it
/// leads to may still be shown read-only (a read-only home), and the note
/// must not say it is hidden. No note, for a link the app may have planted
/// ([`LeftOut::Link`]), one to where programs outside the sandbox listen
/// ([`LeftOut::HostServices`]) or a guarded place ([`LeftOut::Guarded`]),
/// says the place is hidden, nor that SAM does not show `shown`: SAM only
/// leaves out this one bind (for a place it shows on its own, it does not
/// bind it on its own), while the folders around it may still show the
/// link, and other extra folders, opened folders and the system's own
/// places the place it leads to (a read-only home shows `~/.fonts`, a link
/// to `/tmp/myfonts`, and `/tmp/myfonts` listed by its real place is shown
/// as written). For a planted link the rule weighs only what the home and
/// the user folders show (for a user folder the home alone). A place of
/// the home SAM shows on its own (`kind` [`LeftOutPlace::Own`]) stays left
/// out even once its target is listed as an extra folder; the app then
/// reaches that place through the link wherever its other folders show
/// the link.
pub fn left_out_note(shown: &str, why: &LeftOut, kind: LeftOutPlace, write: bool) -> String {
    let t = crate::util::tildify;
    match why {
        LeftOut::Link(link) => {
            let args: &[(&str, &dyn std::fmt::Display)] = &[("path", &shown), ("link", &t(link))];
            match kind {
                LeftOutPlace::Extra if write => crate::i18n::trf(
                    "SAM leaves out the writable folder {path} for this app because the way there leads through the link {link}, which lies in a folder the app can change, to a place the home and the user folders let the app read at most: the app may have made that link. The app still sees what its other folders show there. If you made the link yourself, list the place it leads to as an extra folder instead of this one.",
                    args,
                ),
                LeftOutPlace::UserFolder if write => crate::i18n::trf(
                    "SAM leaves out the writable user folder {path} for this app because the way there leads through the link {link}, which lies in a folder the app can change, to a place the home lets the app read at most: the app may have made that link. The app still sees what its other folders show there. If you made the link yourself, set this user folder to the place it leads to in ~/.config/user-dirs.dirs.",
                    args,
                ),
                LeftOutPlace::Own => crate::i18n::trf(
                    "SAM does not bind {path} for this app on its own because the way there leads through the link {link}, which lies in a folder the app can change, to a place the home and the user folders do not show: the app may have made that link. The app still sees what its other folders show there. If you made the link yourself, add the place it leads to as an extra folder: SAM still leaves out {path} then, but where the app's other folders show the link, the app reaches that place through it.",
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
                LeftOutPlace::Own => crate::i18n::trf(
                    "SAM does not bind {path} for this app on its own because it leads through a link to {place}, where programs outside the sandbox listen: through them the app could run commands outside the sandbox. The app still sees what its other folders show there.",
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
        // Only a place SAM shows on its own is guarded this way
        // ([`own_place_left_out`]); any other kind gets plain words too.
        LeftOut::Guarded(place) => {
            let args: &[(&str, &dyn std::fmt::Display)] = &[("path", &shown), ("place", &t(place))];
            match kind {
                LeftOutPlace::Own => crate::i18n::trf(
                    "SAM does not bind {path} for this app on its own because it leads to {place}, which is or holds your home folder, your keys or passwords, a place SAM protects or SAM's own files. The app still sees what its other folders show there.",
                    args,
                ),
                LeftOutPlace::Extra | LeftOutPlace::UserFolder => crate::i18n::trf(
                    "SAM leaves out {path} for this app because it leads to {place}, which is or holds your home folder, your keys or passwords, a place SAM protects or SAM's own files. The app still sees what its other folders show there.",
                    args,
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// read-only, so an app with the whole home could read them. A folder
    /// outside the home or one written with `..` above it adds nothing, and
    /// the usual places always stay.
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
        for outside in [home.join("../elsewhere"), PathBuf::from("/elsewhere")] {
            assert_eq!(
                sensitive_places_with(&home, Some(outside.clone()), Some(outside)),
                SENSITIVE_DOTFILES
            );
        }
        assert_eq!(sensitive_places_with(&home, None, None), SENSITIVE_DOTFILES);
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
        let t = scratch();
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
            linked_place_left_out(&whole, &host, &fonts, false, &none()),
            Some(LeftOut::Link(fonts.clone()))
        );
        assert_eq!(
            linked_place_left_out(&private, &host, &fonts, false, &none()),
            Some(LeftOut::HostServices(sockets.clone()))
        );
        to(&outside);
        assert_eq!(
            linked_place_left_out(&whole, &host, &fonts, false, &none()),
            Some(LeftOut::Link(fonts.clone()))
        );
        assert_eq!(
            linked_place_left_out(&private, &host, &fonts, false, &none()),
            None
        );
        to(&base.join("not-there-yet"));
        assert_eq!(
            linked_place_left_out(&whole, &host, &fonts, false, &none()),
            Some(LeftOut::Link(fonts.clone()))
        );
        to(&home.join("myfonts"));
        assert_eq!(
            linked_place_left_out(&whole, &host, &fonts, false, &none()),
            None
        );
        // A read-only home: the app cannot have put the link there.
        let mut ro = whole.clone();
        ro.filesystem.home_access = crate::permissions::Access::Ro;
        to(&outside);
        assert_eq!(
            linked_place_left_out(&ro, &host, &fonts, false, &none()),
            None
        );
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
        let note = left_out_note(
            "~/.fonts",
            &LeftOut::Link(fonts.clone()),
            LeftOutPlace::Own,
            false,
        );
        assert!(
            note.contains("~/.fonts") && note.contains("may have made that link"),
            "{note}"
        );
        let note = left_out_note(
            "~/.fonts",
            &LeftOut::HostServices(sockets.clone()),
            LeftOutPlace::Own,
            false,
        );
        assert!(
            note.contains(&sockets.display().to_string())
                && note.contains("where programs outside the sandbox listen"),
            "{note}"
        );
    }

    /// A left-out note, for a planted link, a link to where programs
    /// outside the sandbox listen or a guarded place, never says the place
    /// is hidden, since other grants may still show it, and for a planted
    /// link the rule weighs only what the home and the user folders show
    /// (for a user folder the home alone). With Documents writable in a
    /// private home,
    /// `~/Documents/Data3` a link to `data3` and `data3` listed too, the
    /// link is left out while `data3` is shown read-only; `~/.fonts` in a
    /// writable home stays left out after its target is listed as the note
    /// advises, and the app reaches that place through the home's link; a
    /// read-only user folder behind a link in a writable folder is left
    /// out while its place may be listed. Each note opens with what SAM
    /// did with that one bind (it leaves out the extra or user folder, or
    /// does not bind the place on its own), never that SAM does not show
    /// it, and says what the rule weighs and that the app still sees what
    /// its other folders show. So do the notes for a link to where programs
    /// outside the sandbox listen and for a guarded place: with the home
    /// read-only, `~/.config/fontconfig` a link to a folder in `/tmp` that
    /// is listed by its real place too, and `~/.local/share/fonts` a link
    /// to the home, the home shows both links and the app reaches what
    /// they lead to.
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
        // A place SAM shows on its own, its target listed as advised.
        let fonts = home.join(".fonts");
        std::os::unix::fs::symlink(&fonts_dir, &fonts).unwrap();
        let mut whole = PermissionSet::strict_gui();
        whole.filesystem.home = true;
        whole.filesystem.home_access = Access::Rw;
        whole.filesystem.custom_read = vec![st(&fonts_dir)];
        let guarded = guarded_places_everywhere(&home, &[]);
        let why = own_place_left_out(&whole, &host, &fonts, &guarded, &none());
        assert_eq!(why, Some(LeftOut::Link(fonts.clone())));
        let note = left_out_note("~/.fonts", why.as_ref().unwrap(), LeftOutPlace::Own, false);
        told(
            &note,
            "~/.fonts",
            "SAM does not bind ~/.fonts for this app on its own because",
            "to a place the home and the user folders do not show",
        );
        assert!(
            note.contains("SAM still leaves out ~/.fonts then")
                && note.contains("the app reaches that place through it"),
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
        let guards = "which is or holds your home folder";
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
        let why = own_place_left_out(&ro_home, &host, &fontconfig, &guarded, &none());
        assert_eq!(why, Some(LeftOut::HostServices(myfonts.clone())));
        let note = left_out_note(
            "~/.config/fontconfig",
            why.as_ref().unwrap(),
            LeftOutPlace::Own,
            false,
        );
        plain(
            &note,
            "~/.config/fontconfig",
            "SAM does not bind ~/.config/fontconfig for this app on its own because",
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
        let why = own_place_left_out(&ro_home, &host, &local_fonts, &guarded, &none());
        assert_eq!(why, Some(LeftOut::Guarded(home.clone())));
        let note = left_out_note(
            "~/.local/share/fonts",
            why.as_ref().unwrap(),
            LeftOutPlace::Own,
            false,
        );
        plain(
            &note,
            "~/.local/share/fonts",
            "SAM does not bind ~/.local/share/fonts for this app on its own because",
            guards,
        );
        let note = left_out_note("~/x", why.as_ref().unwrap(), LeftOutPlace::Extra, false);
        plain(
            &note,
            "~/x",
            "SAM leaves out ~/x for this app because",
            guards,
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

    /// A place SAM shows on its own (`~/.fonts`) never leads to the home,
    /// a folder above it, a key folder (also where it is kept behind a
    /// link), a credential store, a folder holding a protected place
    /// (`~/.config`) or SAM's own folders, whoever made the link: in a
    /// private home nothing else hides what such a bind shows. A fonts
    /// folder of your own is shown.
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
        let p = PermissionSet::strict_gui();
        let sams = [home.join("Games/sam")];
        let guarded = guarded_places_everywhere(&home, &sams);
        let fonts = home.join(".fonts");
        let to = |target: &Path| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
            own_place_left_out(&p, &host, &fonts, &guarded, &none())
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
        assert_eq!(
            own_place_left_out(&p, &host, &fonts, &guarded, &none()),
            None
        );
        assert_eq!(
            own_place_left_out(
                &p,
                &host,
                &home.join(".config/fontconfig"),
                &guarded,
                &none()
            ),
            None
        );
        // With `XDG_CONFIG_HOME=~/cfg` and `XDG_DATA_HOME=~/dat` the
        // credential stores under them are guarded too: `~/.fonts` made a
        // link to `~/cfg/gh` (the GitHub tool's token) was bound in a
        // private home, since only `~/.config/gh` was guarded.
        for d in ["cfg/gh", "cfg/git", "dat/keyrings", "cfg/myfonts"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let moved = guarded_places_everywhere_with(
            &home,
            &sams,
            Some(home.join("cfg")),
            Some(home.join("dat")),
        );
        let to_moved = |target: &Path| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
            own_place_left_out(&p, &host, &fonts, &moved, &none())
        };
        for target in [
            home.join("cfg/gh"),
            home.join("dat/keyrings"),
            home.join("cfg/git"),
            home.join(".ssh"),
        ] {
            assert!(
                matches!(to_moved(&target), Some(LeftOut::Guarded(_))),
                "{}",
                target.display()
            );
        }
        assert_eq!(to_moved(&home.join("cfg/myfonts")), None);
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

    /// A user folder SAM binds on its own is left out where a link on its
    /// way lies in a folder the app can change and leads out of what the
    /// home shows (with `~/Sync` writable, `~/Sync/Documents` made a link
    /// to `/tmp/tmux-…` showed the host's tmux sockets), or where it leads
    /// to programs listening outside the sandbox, whoever made the link.
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
        for target in [&sockets, &outside] {
            to(target);
            assert_eq!(
                user_folder_left_out(&p, &host, "documents", &none()),
                Some(LeftOut::Link(docs.clone())),
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
    /// start, and the next start with the same permissions bound that
    /// folder as the fonts (counted read-only by `~/x`, `~/.local/share`
    /// hid the link). The extra folder itself leads into the home, which
    /// shows it anyway. With the home read-only the app changes nothing
    /// there, and a link you made is followed.
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
        let guarded = guarded_places_everywhere(&home, &[]);
        assert_eq!(
            own_place_left_out(&p, &host, &fonts, &guarded, &none()),
            Some(LeftOut::Link(fonts.clone()))
        );
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
            own_place_left_out(&p, &host, &fonts, &guarded, &none()),
            Some(LeftOut::Link(fonts.clone()))
        );
        p.filesystem.custom_write.clear();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        assert_eq!(
            own_place_left_out(&p, &host, &fonts, &guarded, &none()),
            None
        );
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

    /// A link nobody in the sandbox could have planted (`~/.fonts` in a
    /// private home) to where programs outside the sandbox listen is left
    /// out, and the start says why: to a socket directly in `/tmp`, to a
    /// socket folder in `/tmp` by a name no list knows (`tmate-…`), to the
    /// host's runtime folder kept in `/tmp` or anywhere else, and to SAM's
    /// runtime folders wherever they are. A link to an ordinary folder is
    /// still followed.
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
        let guarded = guarded_places_everywhere(&home, &[]);
        let check = |target: &Path, host: &HostInfo, this: &ThisStart| {
            let _ = std::fs::remove_file(&fonts);
            std::os::unix::fs::symlink(target, &fonts).unwrap();
            let why = own_place_left_out(&p, host, &fonts, &guarded, this);
            assert_eq!(
                why,
                Some(LeftOut::HostServices(target.to_path_buf())),
                "{}",
                target.display()
            );
            let note = left_out_note("~/.fonts", why.as_ref().unwrap(), LeftOutPlace::Own, false);
            assert!(
                note.contains("where programs outside the sandbox listen"),
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
        // The control: an ordinary folder is followed.
        let _ = std::fs::remove_file(&fonts);
        std::os::unix::fs::symlink(&ordinary, &fonts).unwrap();
        assert_eq!(
            own_place_left_out(&p, &plain, &fonts, &guarded, &sams),
            None
        );
    }
}
