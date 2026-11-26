//! Command line definitions (clap): every command and its arguments.

use super::*;

#[derive(Parser)]
#[command(
    name = "sam-jail",
    version,
    about = "SAM - Sandboxed AppImage Manager: Flatseal-style permission manager and sandbox launcher for AppImages"
)]
pub(crate) struct Cli {
    /// Print machine-readable JSON.
    #[arg(long, global = true)]
    pub(crate) json: bool,
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum MenuAction {
    /// List unsandboxed menu entries that start this app's AppImage.
    List,
    /// Hide them (SAM's sandboxed launcher stays).
    Hide,
    /// Put back the entries SAM hid.
    Restore,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Find AppImages in the scan directories.
    Scan {
        /// Register every new AppImage found.
        #[arg(long)]
        add: bool,
        /// Directories to scan (default: configured scan directories).
        dirs: Vec<PathBuf>,
    },
    /// List AppImages in the scan folders and menu, sandboxed or not.
    /// Reads names and icons without unpacking or running anything.
    Discover,
    /// Create a sandbox for an AppImage: extract, profile, add a menu entry.
    #[command(visible_alias = "sandbox")]
    Add {
        path: PathBuf,
        /// Allow the AppImage's own --appimage-extract (sandboxed) if static extraction fails.
        #[arg(long)]
        allow_fallback: bool,
        /// Do not create a desktop launcher.
        #[arg(long)]
        no_launcher: bool,
        /// Apply a preset instead of the recommended profile.
        #[arg(long)]
        preset: Option<String>,
        /// Accept the recommended profile (skip "Needs Review").
        #[arg(long)]
        accept: bool,
        /// Hide other menu entries that start this AppImage without a sandbox.
        #[arg(long)]
        hide_duplicates: bool,
        /// Use the permissions given as JSON on stdin instead of the recommendation.
        #[arg(long)]
        permissions_stdin: bool,
        /// Report progress on stderr, one JSON object per line:
        /// {"progress": {"step", "steps", "title", "detail", "fraction"}}.
        #[arg(long)]
        progress: bool,
    },
    /// Settings SAM would use for an AppImage without a sandbox (nothing is
    /// unpacked). With --permissions-stdin, evaluates adjusted settings.
    Preview {
        path: PathBuf,
        #[arg(long)]
        permissions_stdin: bool,
    },
    /// Things to check right after creating a sandbox, with one-click fixes.
    Hints {
        app: String,
        /// Apply the hint with this id.
        #[arg(long)]
        apply: Option<String>,
        /// Also apply a hint rated Think twice or Dangerous, or one that
        /// turns on compatibility mode; without it such a hint is refused.
        #[arg(long, requires = "apply")]
        yes: bool,
    },
    /// Repair an app that does not start or misbehaves: list steps, apply one, or undo.
    Repair {
        app: String,
        /// Apply the step with this id (see the list).
        #[arg(long)]
        apply: Option<String>,
        /// Apply the first step in the list.
        #[arg(long, conflicts_with = "apply")]
        next: bool,
        /// Restore the profile from before the first repair step.
        #[arg(long, conflicts_with_all = ["apply", "next"])]
        undo: bool,
        /// Switch off one applied repair step (by id), keeping the others.
        #[arg(long, conflicts_with_all = ["apply", "next", "undo"])]
        undo_step: Option<String>,
        /// Also apply a step rated Think twice or Dangerous, one that turns
        /// on compatibility mode, or one suggested by what the app printed
        /// (the app controls that text); without it such a step is refused.
        #[arg(long)]
        yes: bool,
    },
    /// Start sandboxed apps briefly and report which ones keep running.
    /// Opens their windows for a few seconds.
    Selftest {
        /// Apps to test (default: all sandboxed apps).
        apps: Vec<String>,
        /// Seconds to let each app run.
        #[arg(long, default_value_t = 8)]
        seconds: u64,
    },
    /// Show, hide or restore unsandboxed menu entries for a sandboxed app.
    Menu {
        #[arg(value_enum)]
        action: MenuAction,
        app: String,
    },
    /// List registered apps.
    List {
        #[arg(long)]
        search: Option<String>,
        /// Filter by badge (ready, needs-review, compatibility-mode,
        /// compatibility-risk, stale, broken, unsafe, missing, protection-missing).
        #[arg(long)]
        badge: Option<String>,
        /// Filter by risk: harmless, some-access, think-twice or dangerous (low, medium and high also work).
        #[arg(long)]
        risk: Option<String>,
        #[arg(long)]
        category: Option<String>,
        /// Sort by: name, recent, added.
        #[arg(long, default_value = "name")]
        sort: String,
    },
    /// Show details about an app.
    Info { app: String },
    /// Remove an app, its extraction, launcher and (unless --keep-data) its
    /// private home. Refuses while the app runs, unless --stop.
    Remove {
        app: String,
        #[arg(long)]
        keep_data: bool,
        /// Close the app first if it is running (instead of refusing).
        #[arg(long)]
        stop: bool,
    },
    /// Close a running app (it gets the chance to save and quit first).
    Stop { app: String },
    /// Write man pages (sam-jail.1 and one per command) into a folder.
    #[command(hide = true)]
    Man { dir: PathBuf },
    /// Remove SAM from this computer: every sandbox (menu entries SAM hid
    /// come back), SAM's menu entries, its settings and the apps' private
    /// data. AppImage files stay. Lists what it would remove without --yes.
    Uninstall {
        /// Keep SAM's settings and the apps' private data.
        #[arg(long)]
        keep_data: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Run an app in its sandbox.
    Run {
        /// Start it even when a protection its settings ask for cannot be
        /// set up this time (SAM's helper missing, the Wayland security
        /// context refused); without it, such a start is refused. Only for
        /// this start.
        #[arg(long)]
        start_anyway: bool,
        app: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show the generated sandbox command without running it.
    Command {
        app: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Check the system (or one app) for problems.
    Doctor {
        app: Option<String>,
        /// Check SAM's contracts with the outside world instead
        /// (docs/contracts.md): which hold on this computer, which are
        /// broken, with the versions of the components involved.
        #[arg(long, conflicts_with = "app")]
        contracts: bool,
    },
    /// Show the version and the level of the JSON interface.
    Version,
    /// Check whether newer versions are published (one app, or all).
    /// Contacts the update source each AppImage names (GitHub or its own
    /// server); nothing is downloaded or replaced.
    Updates {
        app: Option<String>,
        /// Only if `updates.check_on_start` is on, and only apps not checked
        /// for a day (used by the window at start).
        #[arg(long)]
        if_due: bool,
    },
    /// Download the newest published version of an app's AppImage and put it
    /// in place of the old one (kept, so `--undo` can go back). Settings and
    /// files stay.
    Update {
        app: String,
        /// Go back to the version the last update replaced.
        #[arg(long, conflicts_with = "accept_key_change")]
        undo: bool,
        /// Install the download the last run refused because its signing
        /// key changed, its signature could not be checked, or when it was
        /// signed could not be read: exactly that file, while it is still
        /// the published one (never a new download).
        #[arg(long)]
        accept_key_change: bool,
        /// Delete the download the last run kept for that answer, without
        /// installing it (one never answered is deleted after a week).
        #[arg(long, conflicts_with_all = ["accept_key_change", "undo"])]
        decline_key_change: bool,
    },
    /// Update SAM itself, when it runs from its AppImage ($APPIMAGE).
    SelfUpdate {
        /// Only check whether a newer SAM is published.
        #[arg(long)]
        check: bool,
    },
    /// Disk space of one app, or of every app.
    Space { app: Option<String> },
    /// Delete an app's unpacked copy; the next start unpacks it again.
    FreeSpace { app: String },
    /// Show logs for an app.
    Logs {
        app: String,
        /// launch, extract, detect or diagnose
        #[arg(long)]
        kind: Option<String>,
        /// List log files instead of printing the latest.
        #[arg(long)]
        list: bool,
        /// Print this log file (one of `--list`) instead of the latest.
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, default_value_t = 200)]
        tail: usize,
    },
    /// Change permissions of several sandboxed apps at once.
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Manage your own presets.
    Preset {
        #[command(subcommand)]
        cmd: PresetCmd,
    },
    /// Set one permission, e.g. `sam-jail set krita network.mode none`.
    Set {
        app: String,
        key: String,
        value: String,
        /// Confirm a change that adds something rated Think twice or
        /// Dangerous (it is refused without, and says what).
        #[arg(long)]
        yes: bool,
    },
    /// Read permissions (all, or one key).
    Get { app: String, key: Option<String> },
    /// Read or replace the full profile (JSON on stdin for `set`).
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Risk and warnings for a permission set given as JSON on stdin.
    Evaluate {
        /// Evaluate in the context of this app (category, backend).
        app: Option<String>,
    },
    /// Check that the app's sandbox gives it exactly what its settings say:
    /// starts the sandbox with a probe instead of the app. Also takes an
    /// AppImage without a sandbox: then the settings it would get are
    /// checked (nothing is unpacked or stored).
    Verify {
        app: String,
        /// Check these settings (a PermissionSet as JSON on stdin) for an
        /// AppImage without a sandbox, instead of SAM's recommendation.
        #[arg(long)]
        permissions_stdin: bool,
    },
    /// Turn compatibility mode on or off. Off restores the settings from
    /// before it was turned on.
    Compat {
        app: String,
        state: String,
        /// Confirm turning it on: the whole session bus in it is a way out
        /// of the sandbox.
        #[arg(long)]
        yes: bool,
    },
    /// Show the extra arguments always passed to the app, or replace them
    /// with a JSON list on stdin (`--stdin`).
    Args {
        app: String,
        #[arg(long)]
        stdin: bool,
    },
    /// Mark an app's profile as reviewed.
    Review {
        app: String,
        /// Confirm only the state shown: the `review_fingerprint` from
        /// `sam-jail info` when it was shown. Refused when the app changed
        /// since (a notice, a setting, or the AppImage).
        #[arg(long, value_name = "FINGERPRINT")]
        seen: Option<String>,
    },
    /// Re-extract the AppImage (after updates or failures).
    Reextract {
        app: String,
        #[arg(long)]
        allow_fallback: bool,
    },
    /// Re-run dependency detection and the recommendation.
    Redetect { app: String },
    /// Check AppImages for changes (stale/missing).
    Refresh {
        app: Option<String>,
        /// Always verify checksums.
        #[arg(long)]
        deep: bool,
    },
    /// Point an app at the new location of its AppImage.
    Relocate { app: String, path: PathBuf },
    /// Install or remove the desktop launcher. `sam-jail desktop all refresh`
    /// rewrites every launcher whose command is outdated (e.g. SAM's AppImage
    /// was moved).
    Desktop { app: String, action: String },
    /// Run the app once under strace to find missing resources.
    Diagnose {
        app: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        /// Apply low-risk fixes automatically.
        #[arg(long)]
        apply: bool,
    },
    /// Print a redacted bug report.
    Report { app: Option<String> },
    /// Read or change configuration.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// List all permissions with plain-language explanations.
    Permissions,
    /// Remove extraction leftovers not referenced by any app.
    Cleanup {
        /// Also (or with --list: only list) the private data of apps whose
        /// sandbox was removed with --keep-data.
        #[arg(long)]
        data: bool,
        /// Only list what would be removed.
        #[arg(long)]
        list: bool,
    },
    /// First-run onboarding status.
    Onboarding { action: Option<String> },
    /// Developer tools.
    #[command(hide = true)]
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
}

#[derive(Subcommand)]
pub(crate) enum GroupCmd {
    /// Every sandboxed app with its permissions and permission tags.
    List,
    /// Set one permission to the same value for several apps. Prints the
    /// settings from before as "previous", for `group restore`.
    Set {
        /// Permission key, e.g. network.mode or filesystem.documents.
        key: String,
        /// New value, e.g. none, ro, rw, true or false.
        value: String,
        #[arg(required = true)]
        apps: Vec<String>,
        /// Only report what each app would lose; change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Confirm a change that adds something rated Think twice or
        /// Dangerous to any of the apps.
        #[arg(long)]
        yes: bool,
    },
    /// Undo a `group set`: reads the "undo" object it printed (JSON on
    /// stdin) and takes back only that change.
    Restore {
        /// Confirm an undo that adds something rated Think twice or
        /// Dangerous back.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum PresetCmd {
    /// List your own presets.
    List,
    /// Print a preset (built-in or your own) as TOML.
    Show { name: String },
    /// Apply a preset to an app (asks for confirmation when it conflicts).
    Apply {
        name: String,
        app: String,
        #[arg(long, short)]
        yes: bool,
        /// Apply only if the preset is still the one checked: the
        /// `fingerprint` of an earlier `preset apply` reply.
        #[arg(long)]
        expect: Option<String>,
    },
    /// Print a starting point for a new preset (SAM's strictest settings).
    Template,
    /// Save an app's current permissions as a new preset.
    Save {
        app: String,
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Delete one of your own presets.
    Delete { name: String },
    /// Copy a preset under a new name, as a preset of your own.
    Duplicate { name: String, new_name: String },
    /// Add a preset from a TOML file.
    Import { file: PathBuf },
    /// Write a preset as TOML to a file, or print it.
    Export { name: String, file: Option<PathBuf> },
    /// Create or replace a user preset from JSON on stdin.
    Put,
}

#[derive(Subcommand)]
pub(crate) enum ProfileCmd {
    /// Print an app's permissions as JSON.
    Get { app: String },
    /// Replace permissions from JSON (a PermissionSet) on stdin.
    Set {
        app: String,
        /// Confirm a change that adds something rated Think twice or
        /// Dangerous.
        #[arg(long)]
        yes: bool,
    },
    /// Change permissions: reads {"from": …, "to": …} (two
    /// PermissionSets) on stdin and applies only what differs between
    /// them, so changes made elsewhere in the meantime stay. A setting
    /// changed elsewhere to another value is refused (code
    /// changed-meanwhile).
    Change {
        app: String,
        /// Confirm a change that adds something rated Think twice or
        /// Dangerous.
        #[arg(long)]
        yes: bool,
    },
    /// Reset to the recommended profile.
    Reset { app: String },
}

#[derive(Subcommand)]
pub(crate) enum ConfigCmd {
    /// Print the whole configuration.
    Show,
    /// Print one setting (for example extraction.max_files).
    Get { key: String },
    /// Change one setting.
    Set { key: String, value: String },
    /// Replace the whole configuration from JSON on stdin.
    Put,
    /// Print where SAM keeps its configuration, data and logs.
    Path,
}

#[derive(Subcommand)]
pub(crate) enum DevCmd {
    /// Build a synthetic test AppImage.
    MakeFixture {
        path: PathBuf,
        #[arg(long, default_value = "Hello")]
        name: String,
        #[arg(long, default_value = "Utility;")]
        categories: String,
        /// Use this file as the AppRun script.
        #[arg(long)]
        apprun: Option<PathBuf>,
        /// A terminal program (`Terminal=true` in its menu entry).
        #[arg(long)]
        terminal: bool,
    },
    /// Time the parts of SAM on a realistic test AppImage (for the version
    /// report). Uses a fresh folder under $TMPDIR and removes it.
    Bench {
        /// How many apps to create for the Permissions-page measurement.
        #[arg(long, default_value_t = 120)]
        apps: usize,
    },
    /// Write update information into an AppImage runtime (release builds).
    SetUpdateInfo { runtime: PathBuf, info: String },
    /// Write the .zsync update description of a file (release builds).
    MakeZsync {
        file: PathBuf,
        /// Address of the file, relative to the .zsync (usually its name).
        #[arg(long)]
        url: Option<String>,
        /// Output (default: FILE.zsync).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Sign an AppImage with a GnuPG key (release builds): the signature
    /// goes into the AppImage, and is checked afterwards.
    SignAppimage {
        file: PathBuf,
        /// The key's full fingerprint.
        #[arg(long)]
        key: String,
    },
    /// Reads an AppImage's name and icon into OUT; run by SAM inside a
    /// sandbox for the overview.
    Peek { file: PathBuf, out: PathBuf },
    /// Built-in SquashFS reader, run by SAM inside a sandbox during extraction.
    ExtractSquashfs {
        source: PathBuf,
        offset: u64,
        dest: PathBuf,
        #[arg(long)]
        max_files: u64,
        #[arg(long)]
        max_bytes: u64,
        #[arg(long)]
        max_seconds: u64,
    },
}
