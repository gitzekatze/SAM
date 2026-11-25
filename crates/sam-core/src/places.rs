//! Places in the home folder that SAM treats specially, shared by the
//! sandbox (which hides or locks them) and the risk words (which call a
//! grant of them dangerous), so both always mean the same places.

use std::path::{Component, Path, PathBuf};

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
];

/// Paths kept read-only even with full home read/write: SAM's own state
/// and common persistence vectors.
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
    start_place_of_write_grant_in(grant, home, &protected_places(home))
}

/// [`start_place_of_write_grant`] for the protected places `places`.
pub fn start_place_of_write_grant_in(
    grant: &Path,
    home: &Path,
    places: &[String],
) -> Option<StartPlaceGrant> {
    let named = lexical(grant);
    let mut grants = vec![grant.to_path_buf(), resolve(grant), resolve(&named), named];
    grants.dedup();
    let real_home = resolve(home);
    let mut found: Option<StartPlaceGrant> = None;
    for rel in places {
        let at = home.join(rel);
        let spots = [resolve(&at), real_home.join(rel), at];
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
                    });
                }
            }
        }
    }
    found
}

/// What SAM says about an extra writable folder (`shown`, as the person
/// wrote it) that it shows read-only for lying in a start place: the
/// launch note and the warning on the app page and in `sam-jail info`.
pub fn read_only_grant_note(shown: &str, found: &StartPlaceGrant) -> String {
    if found.inside {
        crate::i18n::trf(
            "{path} is inside {place}, where files make your computer run programs at login or start; SAM shows it read-only.",
            &[("path", &shown), ("place", &format!("~/{}", found.place))],
        )
    } else {
        crate::i18n::trf(
            "{path} makes your computer run programs at login or start; SAM shows it read-only.",
            &[("path", &shown)],
        )
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
        let found = |g: &str| start_place_of_write_grant_in(&home.join(g), &home, &places);
        let inside = |place: &str| {
            Some(StartPlaceGrant {
                place: place.into(),
                inside: true,
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
                &home,
                &protected_places_with(&home, None, None)
            ),
            None
        );
        // The words name the grant as written and the place under `~`.
        let note = read_only_grant_note("~/fishlink/conf.d", &inside(".config/fish").unwrap());
        assert!(
            note.contains("~/fishlink/conf.d") && note.contains("~/.config/fish"),
            "{note}"
        );
        assert!(note.contains("read-only"), "{note}");
        let note = read_only_grant_note("~/.bashrc", &itself(".bashrc").unwrap());
        assert!(
            note.contains("~/.bashrc") && note.contains("read-only"),
            "{note}"
        );
    }
}
