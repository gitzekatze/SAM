//! Places in the home folder that SAM treats specially, shared by the
//! sandbox (which hides or locks them) and the risk words (which call a
//! grant of them dangerous), so both always mean the same places.

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
