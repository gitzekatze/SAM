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
    /// is answer differently (audit S-F11):
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
}
