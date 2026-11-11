//! `sam-jail`: the command line interface.
//!
//! Every command supports `--json`, which prints a single JSON envelope
//! (`{"ok": true, "data": ...}` or `{"ok": false, "error": "..."}`). The GUI
//! uses this mode as its API.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use sam_core::util::{format_ts, human_size, tildify};
use sam_core::*;
use sam_runner::launch::{prepare, run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};
use sam_storage::{parse_preset_toml, preset_to_toml, read_preset_file, LogKind, Logs, PresetStore};
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Parser)]
#[command(name = "sam-jail", version, about = "SAM - Sandboxed AppImage Manager: Flatseal-style permission manager and sandbox launcher for AppImages")]
struct Cli {
    /// Print machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum MenuAction {
    /// List unsandboxed menu entries that start this app's AppImage.
    List,
    /// Hide them (SAM's sandboxed launcher stays).
    Hide,
    /// Put back the entries SAM hid.
    Restore,
}

#[derive(Subcommand)]
enum Cmd {
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
        /// compatibility-risk, stale, broken, unsafe, missing).
        #[arg(long)]
        badge: Option<String>,
        /// Filter by risk level (low, medium, high, dangerous).
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
    Doctor { app: Option<String> },
    /// Show the version and the level of the JSON interface.
    Version,
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
    /// Manage presets.
    Preset {
        #[command(subcommand)]
        cmd: PresetCmd,
    },
    /// Set one permission, e.g. `sam-jail set krita network.mode none`.
    Set { app: String, key: String, value: String },
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
    Compat { app: String, state: String },
    /// Show the extra arguments always passed to the app, or replace them
    /// with a JSON list on stdin (`--stdin`).
    Args {
        app: String,
        #[arg(long)]
        stdin: bool,
    },
    /// Mark an app's profile as reviewed.
    Review { app: String },
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
enum PresetCmd {
    List,
    Show { name: String },
    /// Apply a preset to an app (asks for confirmation when it conflicts).
    Apply {
        name: String,
        app: String,
        #[arg(long, short)]
        yes: bool,
    },
    /// What applying a preset would change for an AppImage without a
    /// sandbox (the settings shown now as a PermissionSet on stdin with
    /// --current-stdin). Changes nothing.
    Check {
        name: String,
        appimage: PathBuf,
        #[arg(long)]
        current_stdin: bool,
    },
    /// Save an app's current permissions as a new preset.
    Save {
        app: String,
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    Delete { name: String },
    Duplicate { name: String, new_name: String },
    Import { file: PathBuf },
    Export { name: String, file: Option<PathBuf> },
    /// Create or replace a user preset from JSON on stdin.
    Put,
}

#[derive(Subcommand)]
enum ProfileCmd {
    Get { app: String },
    /// Replace permissions from JSON (a PermissionSet) on stdin.
    Set { app: String },
    /// Reset to the recommended profile.
    Reset { app: String },
}

#[derive(Subcommand)]
enum ConfigCmd {
    Show,
    Get { key: String },
    Set { key: String, value: String },
    /// Replace the whole configuration from JSON on stdin.
    Put,
    Path,
}

#[derive(Subcommand)]
enum DevCmd {
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
    },
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

/// Output: human text plus the JSON value.
struct Out {
    json: bool,
}

impl Out {
    fn emit<T: Serialize>(&self, data: &T, human: impl FnOnce()) {
        if self.json {
            println!("{}", json!({"ok": true, "data": data}));
        } else {
            human();
        }
    }
}

fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn paint(s: &str, code: &str) -> String {
    if color() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn badge_str(b: Badge) -> String {
    let code = match b {
        Badge::Ready => "32",
        Badge::NeedsReview => "36",
        Badge::CompatibilityMode | Badge::CompatibilityRisk | Badge::Stale => "33",
        Badge::Broken | Badge::Unsafe | Badge::Missing => "31",
    };
    paint(b.label(), code)
}

fn risk_str(r: RiskLevel) -> String {
    let code = match r {
        RiskLevel::Low => "32",
        RiskLevel::Medium => "33",
        RiskLevel::High => "31",
        RiskLevel::Dangerous => "1;31",
    };
    paint(r.label(), code)
}

fn sev_str(s: Severity) -> String {
    match s {
        Severity::Info => paint("info", "36"),
        Severity::Warning => paint("warning", "33"),
        Severity::Danger => paint("danger", "1;31"),
    }
}

fn print_warnings(ws: &[Warning]) {
    for w in ws {
        println!("  [{}] {}: {}", sev_str(w.severity), w.title, w.message);
    }
}

fn read_stdin() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

fn main() {
    let cli = Cli::parse();
    let json_mode = cli.json;
    if let Err(e) = real_main(cli) {
        if json_mode {
            println!("{}", json!({"ok": false, "error": format!("{e:#}")}));
        } else {
            eprintln!("{} {e:#}", paint("error:", "1;31"));
        }
        std::process::exit(1);
    }
}

fn real_main(cli: Cli) -> Result<()> {
    let out = Out { json: cli.json };
    // Before opening SAM's data, so it answers even when that fails.
    if let Cmd::Version = cli.cmd {
        let (version, interface) = (env!("CARGO_PKG_VERSION"), sam_core::JSON_INTERFACE);
        out.emit(&json!({"version": version, "interface": interface}), || println!("sam-jail {version} (JSON interface {interface})"));
        return Ok(());
    }
    let app = Sam::open()?;
    match cli.cmd {
        Cmd::Scan { add, dirs } => {
            let items = app.scan((!dirs.is_empty()).then_some(dirs))?;
            let mut added = Vec::new();
            if add {
                for it in items.iter().filter(|i| i.registered.is_none()) {
                    match app.add(&it.path, &AddOptions::default()) {
                        Ok(o) => added.push(json!({"path": it.path, "id": o.entry.id, "relocated": o.relocated})),
                        Err(e) => added.push(json!({"path": it.path, "error": format!("{e:#}")})),
                    }
                }
            }
            out.emit(&json!({"found": items, "added": added}), || {
                if items.is_empty() {
                    println!("No AppImages found in: {}", app.config.general.scan_directories.join(", "));
                }
                for it in &items {
                    let st = match (&it.registered, &it.moved_from) {
                        (Some(id), _) => format!("registered as {id}"),
                        (None, Some(id)) => paint(&format!("moved copy of {id}"), "33"),
                        _ => paint("new", "36"),
                    };
                    println!("{}  {}  ({})", tildify(&it.path), st, human_size(it.size));
                }
                for a in &added {
                    match a.get("error") {
                        Some(e) => println!("  failed {}: {}", a["path"], e),
                        None => println!("  added {}", a["id"].as_str().unwrap_or_default()),
                    }
                }
            });
        }
        Cmd::Discover => {
            let found = app.discover()?;
            out.emit(&json!({"apps": found}), || {
                if found.is_empty() {
                    println!("No AppImages found in: {}", app.default_scan_dirs().iter().map(|d| tildify(d)).collect::<Vec<_>>().join(", "));
                }
                for d in &found {
                    let st = match (&d.sandboxed, &d.moved_from) {
                        (Some(id), _) => paint(&format!("sandboxed ({id})"), "32"),
                        (None, Some(id)) => paint(&format!("moved copy of {id}"), "33"),
                        _ => paint("not sandboxed", "36"),
                    };
                    println!("{:<28} {:<14} {}  {}", d.name, d.category_label, st, tildify(&d.path));
                    for m in &d.menu_entries {
                        println!("    unsandboxed menu entry: {}", tildify(&m.file));
                    }
                }
            });
        }
        Cmd::Hints { app: query, apply } => {
            let e = app.resolve(&query)?;
            let e = match apply {
                Some(id) => {
                    let sug = sam_runner::repair::first_run_hints(&e).into_iter().find(|s| s.id == id).with_context(|| format!("no hint '{id}' for {}", e.display_name()))?;
                    app.apply_suggestion(&query, &sug, false)?
                }
                None => e,
            };
            let hints = sam_runner::repair::first_run_hints(&e);
            out.emit(&json!({"hints": hints}), || {
                if hints.is_empty() {
                    println!("Nothing to check for {}.", e.display_name());
                }
                for h in &hints {
                    println!("{}  {}\n    {}\n    fix: sam-jail hints {} --apply {}", paint(&h.id, "1"), h.title, h.explanation, e.id, h.id);
                }
            });
        }
        Cmd::Repair { app: query, apply, next, undo } => {
            let e = app.resolve(&query)?;
            let applied = if undo {
                app.undo_repairs(&query)?;
                Some("undo".to_string())
            } else if let Some(id) = apply.or_else(|| next.then(|| sam_runner::repair::ladder(&e, &app.config).first().map(|s| s.id.clone())).flatten()) {
                let sug = app.find_suggestion(&e, &id).with_context(|| format!("no repair step '{id}' for {}", e.display_name()))?;
                app.apply_suggestion(&query, &sug, true)?;
                Some(sug.title)
            } else {
                None
            };
            let e = app.resolve(&query)?;
            let steps = sam_runner::repair::ladder(&e, &app.config);
            let findings = e.last_launch.as_ref().map(|l| l.findings.clone()).unwrap_or_default();
            out.emit(&json!({"applied": applied, "findings": findings, "steps": steps, "applied_steps": e.repairs_applied, "can_undo": e.repair_backup.is_some()}), || {
                if let Some(a) = &applied {
                    println!("Applied: {a}. Start the app again to test it.");
                }
                for f in &findings {
                    println!("{} {}: {}", paint("found", "33"), f.title, f.explanation);
                }
                for (i, st) in steps.iter().enumerate() {
                    println!("{}. {} ({})\n   {}", i + 1, st.title, st.id, st.explanation);
                }
                if steps.is_empty() {
                    println!("No more repair steps. Check the logs (sam-jail logs {}).", e.id);
                }
                if e.repair_backup.is_some() {
                    println!("Undo all repairs: sam-jail repair {} --undo", e.id);
                }
            });
        }
        Cmd::Selftest { apps, seconds } => {
            let list: Vec<AppEntry> = if apps.is_empty() { app.registry().list()? } else { apps.iter().map(|q| app.resolve(q)).collect::<Result<_>>()? };
            let mut results = Vec::new();
            for mut e in list {
                if !out.json {
                    eprintln!("testing {} for {seconds}s…", e.display_name());
                }
                let opts = LaunchOptions { timeout_secs: Some(seconds), quiet: true, ..Default::default() };
                let (status, detail, findings) = match run(&mut e, &opts, &app.config, &app.paths, &app.host()) {
                    Ok(rec) => {
                        let ran = rec.finished_at - rec.started_at;
                        if rec.sandbox_failure {
                            ("fail", rec.summary.clone(), rec.findings.clone())
                        } else if rec.success || (rec.signal == Some(9) && ran + 1 >= seconds as i64) {
                            ("ok", if rec.signal.is_none() { "exited normally".into() } else { format!("kept running for {seconds}s") }, vec![])
                        } else {
                            ("fail", rec.summary.clone(), rec.findings.clone())
                        }
                    }
                    Err(err) => ("fail", format!("{err:#}"), vec![]),
                };
                results.push(json!({"id": e.id, "name": e.display_name(), "status": status, "detail": detail, "findings": findings}));
            }
            out.emit(&json!({"results": results}), || {
                for r in &results {
                    let ok = r["status"] == "ok";
                    println!("{} {:<28} {}", if ok { paint("✓", "32") } else { paint("✗", "31") }, r["name"].as_str().unwrap_or_default(), r["detail"].as_str().unwrap_or_default());
                    for f in r["findings"].as_array().into_iter().flatten() {
                        println!("    likely: {}", f["title"].as_str().unwrap_or_default());
                    }
                }
            });
        }
        Cmd::Menu { action, app: query } => {
            let e = match action {
                MenuAction::List => app.resolve(&query)?,
                MenuAction::Hide => app.hide_duplicates(&query)?,
                MenuAction::Restore => app.restore_menu_entries(&query)?,
            };
            let dups: Vec<_> = app.menu_duplicates(&e).into_iter().map(|f| json!({"file": f.file, "name": f.name})).collect();
            out.emit(&json!({"visible": dups, "hidden": e.hidden_entries}), || {
                for d in &dups {
                    println!("visible  {}", d["file"].as_str().unwrap_or_default());
                }
                for h in &e.hidden_entries {
                    println!("hidden   {}", tildify(&h.original));
                }
                if dups.is_empty() && e.hidden_entries.is_empty() {
                    println!("No other menu entries start {}.", e.display_name());
                }
            });
        }
        Cmd::Preview { path, permissions_stdin } => {
            let perms: Option<PermissionSet> = if permissions_stdin { Some(serde_json::from_str(&read_stdin()?).context("expected a PermissionSet as JSON on stdin")?) } else { None };
            let v = app.preview(&path, perms)?;
            out.emit(&v, || println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()));
        }
        Cmd::Add { path, allow_fallback, no_launcher, preset, accept, hide_duplicates, permissions_stdin } => {
            let permissions: Option<PermissionSet> = if permissions_stdin { Some(serde_json::from_str(&read_stdin()?).context("expected a PermissionSet as JSON on stdin")?) } else { None };
            let o = app.add(&path, &AddOptions { consent_fallback: allow_fallback, launcher: no_launcher.then_some(false), preset, accept, hide_duplicates, permissions })?;
            let summary = AppSummary::from_entry(&o.entry);
            out.emit(&json!({"app": summary, "entry": o.entry, "relocated": o.relocated, "needs_fallback_consent": o.needs_fallback_consent, "warnings": o.warnings}), || {
                if o.relocated {
                    println!("{} was already registered; updated its location.", o.entry.display_name());
                    return;
                }
                println!("Sandboxed {} as {} [{}]", o.entry.display_name(), o.entry.id, badge_str(summary.badge));
                for h in &o.entry.hidden_entries {
                    println!("  hid unsandboxed menu entry {}", tildify(&h.original));
                }
                if let Some(x) = &o.entry.extraction {
                    println!("  extracted {} files ({}) via {}", x.file_count, human_size(x.total_size), x.method);
                }
                println!("  category: {}   risk: {}", o.entry.category, risk_line(&summary.risk));
                for n in &o.entry.recommendation_notes {
                    println!("  - {n}");
                }
                if o.needs_fallback_consent {
                    println!("{}", paint("  Static extraction failed. Retry with --allow-fallback to let the AppImage extract itself inside a restricted sandbox.", "33"));
                }
                print_warnings(&o.warnings);
                if !o.entry.reviewed {
                    println!("Review the permissions with `sam-jail info {}` or in the SAM app, then `sam-jail review {}`.", o.entry.id, o.entry.id);
                }
            });
        }
        Cmd::List { search, badge, risk, category, sort } => {
            let mut apps: Vec<AppSummary> = app.registry().list()?.iter().map(AppSummary::from_entry).collect();
            if let Some(s) = search {
                let s = s.to_lowercase();
                apps.retain(|a| a.name.to_lowercase().contains(&s) || a.id.contains(&s) || a.comment.to_lowercase().contains(&s));
            }
            if let Some(b) = badge {
                apps.retain(|a| serde_json::to_value(a.badge).ok().and_then(|v| v.as_str().map(|s| s == b)).unwrap_or(false));
            }
            if let Some(r) = risk {
                apps.retain(|a| a.risk.level.label().eq_ignore_ascii_case(&r));
            }
            if let Some(c) = category {
                apps.retain(|a| a.category == c);
            }
            match sort.as_str() {
                "recent" => apps.sort_by_key(|a| std::cmp::Reverse(a.last_launched)),
                "added" => apps.sort_by_key(|a| std::cmp::Reverse(a.added_at)),
                _ => {}
            }
            out.emit(&apps, || {
                if apps.is_empty() {
                    println!("No apps registered. Add one with `sam-jail add <file.AppImage>` or `sam-jail scan --add`.");
                    return;
                }
                let w = apps.iter().map(|a| a.id.len()).max().unwrap_or(10);
                println!("{:<w$}  {:<24}  {:<12}  {:<10}  {:<12}  LAST RUN", "ID", "NAME", "CATEGORY", "RISK", "STATUS", w = w);
                for a in &apps {
                    let last = a.last_launched.map(format_ts).unwrap_or_else(|| "never".into());
                    let risk = format!("{:<10}", a.risk.level.label());
                    let badge = format!("{:<12}", a.badge.label());
                    println!(
                        "{:<w$}  {:<24}  {:<12}  {}  {}  {last}",
                        a.id,
                        truncate(&a.name, 24),
                        a.category,
                        risk.replace(a.risk.level.label(), &risk_str(a.risk.level)),
                        badge.replace(a.badge.label(), &badge_str(a.badge)),
                        w = w
                    );
                }
            });
        }
        Cmd::Info { app: q } => {
            let e = app.resolve(&q)?;
            let host = app.host();
            let warnings = app.app_warnings(&e, &host);
            let summary = AppSummary::from_entry(&e);
            let selection = sam_runner::select::select(&host).ok();
            let hints = sam_runner::repair::first_run_hints(&e);
            let steps = sam_runner::repair::ladder(&e, &app.config);
            out.emit(
                &json!({"app": summary, "entry": e, "warnings": warnings, "selection": selection, "hints": hints, "repair_steps": steps, "private_home": app.paths.app_home(&e.id), "running": app.running(&e.id).len(),
                    "check_current": e.last_check.as_ref().is_some_and(|c| c.key == sam_runner::verify::check_key(&e, &app.config, &host))}),
                || print_info(&e, &summary, &warnings, selection.as_ref()),
            );
        }
        Cmd::Remove { app: q, keep_data, stop } => {
            if stop {
                app.stop(&q)?;
            }
            let (e, problems) = app.remove(&q, keep_data)?;
            out.emit(&json!({"removed": e.id, "warnings": problems}), || {
                println!("Removed {} ({}){}", e.display_name(), e.id, if keep_data { "; private data kept" } else { "" });
                for p in &problems {
                    eprintln!("{} {p}", paint("warning:", "33"));
                }
            });
        }
        Cmd::Version => {} // answered above
        Cmd::Space { app: q } => {
            let entries = match &q {
                Some(q) => vec![app.resolve(q)?],
                None => app.registry().list()?,
            };
            let usage: Vec<_> = entries.iter().map(|e| app.disk_usage(e)).collect();
            let total: u64 = usage.iter().map(|u| u.total).sum();
            out.emit(&json!({"apps": usage, "total": total}), || {
                let mb = |b: u64| format!("{:.1} MB", b as f64 / 1e6);
                for u in &usage {
                    println!("{:<28} {:>10}  (unpacked {}, home {}, app folder {}, logs {})", u.name, mb(u.total), mb(u.unpacked), mb(u.home), mb(u.overlay), mb(u.logs));
                }
                println!("{:<28} {:>10}", "total", mb(total));
            });
        }
        Cmd::FreeSpace { app: q } => {
            let freed = app.free_space(&q)?;
            out.emit(&json!({"freed": freed}), || println!("Freed {:.1} MB; the next start unpacks the AppImage again", freed as f64 / 1e6));
        }
        Cmd::Man { dir } => {
            write_man_pages(&dir)?;
            out.emit(&json!({"dir": dir}), || println!("Man pages written to {}", dir.display()));
        }
        Cmd::Uninstall { keep_data, yes } => {
            let u = app.uninstall(keep_data, !yes)?;
            out.emit(&json!({"done": yes, "apps": u.apps, "files": u.files, "dirs": u.dirs, "problems": u.problems}), || {
                println!("{} SAM{}:", if yes { "Removed" } else { "This would remove" }, if keep_data { " (keeping settings and app data)" } else { "" });
                println!("  sandboxes: {}", if u.apps.is_empty() { "none".into() } else { u.apps.join(", ") });
                for f in &u.files {
                    println!("  {}", tildify(f));
                }
                for d in &u.dirs {
                    println!("  {}/", tildify(d));
                }
                for p in &u.problems {
                    eprintln!("{} {p}", paint("warning:", "33"));
                }
                if !yes {
                    println!("Your AppImage files stay. Run again with --yes to remove.");
                } else {
                    println!("Your AppImage files were not touched. Remove the SAM package or AppImage to finish.");
                }
            });
        }
        Cmd::Stop { app: q } => {
            let n = app.stop(&q)?;
            out.emit(&json!({"stopped": n}), || {
                if n == 0 {
                    println!("Not running");
                } else {
                    println!("Closed {n} running launch(es)");
                }
            });
        }
        Cmd::Run { app: q, args } => {
            let mut e = app.resolve(&q)?;
            app.ensure_unpacked(&mut e)?;
            let rec = run(&mut e, &LaunchOptions { args, ..Default::default() }, &app.config, &app.paths, &app.host())?;
            out.emit(&rec, || {
                if rec.sandbox_failure {
                    eprintln!("{} {}", paint("sam-jail:", "1;31"), rec.summary);
                    eprintln!("  log: {}", rec.log_file.as_ref().map(|p| tildify(p)).unwrap_or_default());
                    eprintln!("  try: sam-jail doctor {} / sam-jail diagnose {} / sam-jail compat {} on", e.id, e.id, e.id);
                }
            });
            if !out.json && !rec.success {
                std::process::exit(rec.exit_code.unwrap_or(1).max(1));
            }
        }
        Cmd::Command { app: q, args } => {
            let e = app.resolve(&q)?;
            let p = prepare(&e, &LaunchOptions { args, ..Default::default() }, &app.config, &app.paths, &app.host())?;
            let pv = p.preview();
            out.emit(&pv, || {
                println!("# sandbox: {} ({})", pv.backend, pv.reason);
                println!("# landlock: {}  seccomp: {}", pv.landlock, pv.seccomp);
                if let Some(d) = &pv.dbus_proxy {
                    println!("# dbus proxy: xdg-dbus-proxy {}", sam_core::util::shell_join(d));
                }
                for n in &pv.notes {
                    println!("# note: {n}");
                }
                println!("{}", pretty_command(&pv.argv));
            });
        }
        Cmd::Doctor { app: q } => {
            let host = HostInfo::probe_full();
            let report = match &q {
                Some(q) => sam_runner::doctor::app_report(&app, &app.resolve(q)?, &host),
                None => sam_runner::doctor::system_report(&app, &host),
            };
            out.emit(&report, || {
                for c in &report.checks {
                    let st = match c.status {
                        CheckStatus::Ok => paint("  ok ", "32"),
                        CheckStatus::Info => paint(" info", "36"),
                        CheckStatus::Warn => paint(" warn", "33"),
                        CheckStatus::Fail => paint(" FAIL", "1;31"),
                    };
                    println!("{st}  {:<26} {}", c.label, c.detail);
                    if let Some(h) = &c.hint {
                        println!("       {:<26} → {h}", "");
                    }
                }
            });
        }
        Cmd::Logs { app: q, kind, list, file, tail } => {
            let e = app.resolve(&q)?;
            let kind = kind.as_deref().map(|k| LogKind::parse(k).with_context(|| format!("unknown log kind '{k}'"))).transpose()?;
            let logs = Logs::new(&app.paths);
            if list {
                let files = logs.list(&e.id, kind)?;
                out.emit(&files, || {
                    for f in &files {
                        println!("{}  {:<8}  {:>9}  {}", format_ts(f.modified), f.kind.prefix(), human_size(f.size), tildify(&f.path));
                    }
                });
            } else if let Some(f) = file {
                // Only files of this app's own log list.
                let known = logs.list(&e.id, None)?.into_iter().find(|l| l.path == f).context("not a log file of this app")?;
                let text = sam_runner::launch::tail(&known.path, tail);
                out.emit(&json!({"file": known.path, "kind": known.kind, "text": text}), || {
                    println!("==> {} <==", tildify(&known.path));
                    println!("{text}");
                });
            } else {
                let latest = logs.latest(&e.id, kind)?.context("no logs yet for this app")?;
                let text = sam_runner::launch::tail(&latest.path, tail);
                out.emit(&json!({"file": latest.path, "kind": latest.kind, "text": text}), || {
                    println!("==> {} <==", tildify(&latest.path));
                    println!("{text}");
                });
            }
        }
        Cmd::Preset { cmd } => preset_cmd(&app, &out, cmd)?,
        Cmd::Set { app: q, key, value } => {
            let e = app.set_permission(&q, &key, &value)?;
            let v = e.profile.permissions.get_key(&key)?;
            let eval = app.evaluate(&e.profile.permissions, Some(&e), &app.host());
            out.emit(&json!({"key": key, "value": v, "risk": eval.risk, "warnings": eval.warnings}), || {
                println!("{key} = {v}   (risk now {})", risk_line(&eval.risk));
                print_warnings(&eval.warnings.iter().filter(|w| w.key.as_deref() == Some(&key)).cloned().collect::<Vec<_>>());
            });
        }
        Cmd::Get { app: q, key } => {
            let e = app.resolve(&q)?;
            let v = match &key {
                Some(k) => e.profile.permissions.get_key(k)?,
                None => serde_json::to_value(&e.profile.permissions)?,
            };
            out.emit(&v, || match &key {
                Some(_) => println!("{v}"),
                None => print!("{}", toml::to_string_pretty(&e.profile.permissions).unwrap_or_default()),
            });
        }
        Cmd::Profile { cmd } => match cmd {
            ProfileCmd::Get { app: q } => {
                let e = app.resolve(&q)?;
                out.emit(&e.profile, || println!("{}", serde_json::to_string_pretty(&e.profile).unwrap_or_default()));
            }
            ProfileCmd::Set { app: q } => {
                let perms: PermissionSet = serde_json::from_str(&read_stdin()?).context("expected a PermissionSet as JSON on stdin")?;
                let e = app.set_permissions(&q, perms)?;
                out.emit(&AppSummary::from_entry(&e), || println!("Updated permissions for {}", e.display_name()));
            }
            ProfileCmd::Reset { app: q } => {
                let e = app.reset_profile(&q)?;
                out.emit(&AppSummary::from_entry(&e), || println!("Reset {} to the recommended profile", e.display_name()));
            }
        },
        Cmd::Evaluate { app: q } => {
            let perms: PermissionSet = serde_json::from_str(&read_stdin()?).context("expected a PermissionSet as JSON on stdin")?;
            let e = q.map(|q| app.resolve(&q)).transpose()?;
            let host = app.host();
            let ev = app.evaluate(&perms, e.as_ref(), &host);
            out.emit(&ev, || {
                println!("risk: {}", risk_line(&ev.risk));
                print_warnings(&ev.warnings);
            });
        }
        Cmd::Compat { app: q, state } => {
            let on = matches!(state.as_str(), "on" | "true" | "1" | "yes");
            let e = app.set_compat(&q, on)?;
            out.emit(&AppSummary::from_entry(&e), || {
                println!("Compatibility mode {} for {}", if on { "enabled" } else { "disabled" }, e.display_name());
                if on {
                    println!("{}", paint(sam_profile::COMPAT_WARNING, "33"));
                }
            });
        }
        Cmd::Verify { app: q, permissions_stdin } => {
            let perms: Option<PermissionSet> = if permissions_stdin { Some(serde_json::from_str(&read_stdin()?).context("expected a PermissionSet as JSON on stdin")?) } else { None };
            let out_v = match app.resolve(&q) {
                Ok(_) if perms.is_some() => bail!("{q} already has a sandbox; --permissions-stdin is only for AppImages without one"),
                Ok(_) => app.verify(&q)?,
                Err(e) if std::path::Path::new(&q).is_file() => {
                    let _ = e;
                    app.verify_preview(std::path::Path::new(&q), perms)?
                }
                Err(e) => return Err(e),
            };
            let r = &out_v.report;
            out.emit(&json!({"report": r, "record": out_v.record}), || {
                let mut group = String::new();
                for res in &r.results {
                    if res.group != group {
                        group = res.group.clone();
                        println!("\n{group}");
                    }
                    let mark = match res.ok {
                        Some(true) => paint("✓", "32"),
                        Some(false) => paint("✗", "31"),
                        None => paint("–", "90"),
                    };
                    println!("  {mark} {:<46} {}", res.title, res.observed);
                }
                println!("\n{} passed, {} failed, {} not applicable", out_v.record.passed, out_v.record.failed.len(), out_v.record.skipped);
            });
        }
        Cmd::Args { app: q, stdin } => {
            let e = if stdin {
                let list: Vec<String> = serde_json::from_str(&read_stdin()?).context("expected a JSON list of strings on stdin")?;
                app.set_args(&q, list)?
            } else {
                app.resolve(&q)?
            };
            out.emit(&e.profile.args, || {
                if e.profile.args.is_empty() {
                    println!("No extra arguments for {}", e.display_name());
                } else {
                    println!("{}", e.profile.args.join(" "));
                }
            });
        }
        Cmd::Review { app: q } => {
            let e = app.mark_reviewed(&q)?;
            out.emit(&AppSummary::from_entry(&e), || println!("{} marked as reviewed [{}]", e.display_name(), badge_str(e.badge())));
        }
        Cmd::Reextract { app: q, allow_fallback } => {
            let e = app.reextract(&q, allow_fallback)?;
            out.emit(&json!({"app": AppSummary::from_entry(&e), "pending_changes": e.pending_changes}), || {
                println!("Re-extracted {} [{}]", e.display_name(), badge_str(e.badge()));
                if !e.pending_changes.is_empty() {
                    println!("{}", paint(&format!("  The update likely needs new permissions: {}. Your customized profile was kept.", e.pending_changes.join(", ")), "33"));
                }
            });
        }
        Cmd::Redetect { app: q } => {
            let e = app.redetect(&q)?;
            out.emit(&json!({"app": AppSummary::from_entry(&e), "detection": e.detection}), || {
                println!("Dependency detection finished for {}", e.display_name());
                if let Some(d) = &e.detection {
                    print_detection(d);
                }
            });
        }
        Cmd::Refresh { app: q, deep } => {
            let items = app.refresh(q.as_deref(), deep)?;
            out.emit(&items, || {
                for i in &items {
                    let st = match i.status.as_str() {
                        "unchanged" => paint("unchanged", "32"),
                        "touched" => paint("unchanged (metadata updated)", "32"),
                        "stale" => paint("STALE", "33"),
                        _ => paint("MISSING", "31"),
                    };
                    println!("{:<32} {st} {}", i.name, i.reasons.join("; "));
                }
            });
        }
        Cmd::Relocate { app: q, path } => {
            let e = app.relocate(&q, &path)?;
            out.emit(&AppSummary::from_entry(&e), || println!("{} now points to {} [{}]", e.display_name(), tildify(&e.source_path), badge_str(e.badge())));
        }
        Cmd::Desktop { app: q, action } if q == "all" && action == "refresh" => {
            let n = sam_intake::desktop::refresh_launchers(&app.paths, &app.registry().list()?);
            out.emit(&json!({"refreshed": n}), || println!("{n} launcher(s) updated"));
        }
        Cmd::Desktop { app: q, action } => {
            let mut e = app.resolve(&q)?;
            match action.as_str() {
                "install" => e.desktop_entry = Some(sam_intake::desktop::install_launcher(&app.paths, &e)?),
                "remove" | "uninstall" => {
                    sam_intake::desktop::remove_launcher(&app.paths, &e.id)?;
                    e.desktop_entry = None;
                }
                other => bail!("unknown action '{other}' (install, remove)"),
            }
            app.registry().save(&mut e)?;
            out.emit(&json!({"desktop_entry": e.desktop_entry}), || match &e.desktop_entry {
                Some(p) => println!("Launcher installed: {}", tildify(p)),
                None => println!("Launcher removed"),
            });
        }
        Cmd::Diagnose { app: q, timeout, apply } => {
            let mut e = app.resolve(&q)?;
            if !out.json {
                eprintln!("Starting {} in diagnostic mode for up to {timeout}s. Use the app normally, then close it.", e.display_name());
            }
            let r = sam_runner::diagnose::diagnose(&app, &mut e, timeout, apply)?;
            out.emit(&r, || {
                println!("Diagnostic run: {}", r.launch_summary);
                if r.findings.is_empty() {
                    println!("No missing resources were detected.");
                }
                for f in &r.findings {
                    let fix = f.fix.as_ref().map(|(k, v)| format!("  fix: sam-jail set {} {k} {v}", e.id)).unwrap_or_default();
                    println!("  [{}] {} ({}){}{}", risk_str(f.risk), f.suggestion, f.error, if f.applied { paint("  applied", "32") } else { String::new() }, if f.applied { String::new() } else { fix });
                }
                if r.applied > 0 {
                    println!("{} low-risk fix(es) applied automatically.", r.applied);
                }
            });
        }
        Cmd::Report { app: q } => {
            let host = HostInfo::probe_full();
            let e = q.map(|q| app.resolve(&q)).transpose()?;
            let text = sam_runner::doctor::bug_report(&app, e.as_ref(), &host);
            out.emit(&json!({"report": text}), || println!("{text}"));
        }
        Cmd::Config { cmd } => config_cmd(&app, &out, cmd)?,
        Cmd::Permissions => {
            let cat = permission_catalog();
            out.emit(&cat, || {
                let mut last = "";
                for p in &cat {
                    if p.category != last {
                        println!("\n{}", paint(p.category, "1"));
                        last = p.category;
                    }
                    println!("  {:<30} {:<10} {}", p.key, risk_str(p.risk), p.title);
                    println!("  {:<30} {:<10} {}", "", "", p.description);
                }
            });
        }
        Cmd::Cleanup { data, list } => {
            if data {
                let items = if list { app.leftover_data()? } else { app.remove_leftover_data()? };
                let total: u64 = items.iter().map(|d| d.size).sum();
                out.emit(&json!({"apps": items, "total": total, "removed": !list}), || {
                    for d in &items {
                        println!("{:<40} {:>10}", d.id, human_size(d.size));
                    }
                    println!("{} {} app(s), {}", if list { "Left behind by" } else { "Removed data of" }, items.len(), human_size(total));
                });
            } else {
                let removed = if list { vec![] } else { app.cleanup()? };
                out.emit(&removed, || {
                    println!("Removed {} unreferenced extraction(s)", removed.len());
                });
            }
        }
        Cmd::Onboarding { action } => {
            let marker = app.paths.onboarding_marker();
            if action.as_deref() == Some("done") {
                sam_core::util::atomic_write(&marker, b"1")?;
            } else if action.as_deref() == Some("reset") {
                let _ = std::fs::remove_file(&marker);
            }
            let done = marker.exists();
            out.emit(&json!({"done": done}), || println!("onboarding {}", if done { "completed" } else { "pending" }));
        }
        Cmd::Dev { cmd: DevCmd::ExtractSquashfs { source, offset, dest, max_files, max_bytes, max_seconds } } => {
            let limits = sam_intake::normalize::Limits { max_files, max_bytes, max_seconds };
            sam_intake::extract::builtin_squashfs_entry(&source, offset, &dest, &limits)?;
        }
        Cmd::Dev { cmd: DevCmd::MakeFixture { path, name, categories, apprun } } => {
            let mut spec = sam_intake::testkit::FixtureSpec::hello(&name);
            spec.categories = categories;
            if let Some(a) = apprun {
                spec.apprun = std::fs::read_to_string(a)?;
            }
            sam_intake::testkit::build(&path, &spec)?;
            out.emit(&json!({"path": path}), || println!("Wrote {}", path.display()));
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

/// Break a long bwrap command into readable lines.
fn pretty_command(argv: &[String]) -> String {
    let mut out = String::new();
    let mut i = 0;
    let q = |s: &String| sam_core::util::shell_quote(s);
    if let Some(first) = argv.first() {
        out += &q(first);
        i = 1;
    }
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            out += " \\\n  -- ";
            out += &argv[i + 1..].iter().map(q).collect::<Vec<_>>().join(" ");
            break;
        }
        let n = match a.as_str() {
            "--bind" | "--bind-try" | "--ro-bind" | "--ro-bind-try" | "--dev-bind" | "--dev-bind-try" | "--symlink" | "--setenv" => 2,
            "--proc" | "--dev" | "--tmpfs" | "--dir" | "--perms" | "--hostname" | "--chdir" | "--cap-drop" | "--seccomp" => 1,
            _ => 0,
        };
        out += " \\\n  ";
        out += &argv[i..(i + 1 + n).min(argv.len())].iter().map(q).collect::<Vec<_>>().join(" ");
        i += 1 + n;
    }
    out
}

fn print_info(e: &AppEntry, s: &AppSummary, warnings: &[Warning], sel: Option<&sam_runner::select::Selection>) {
    println!("{}  [{}]", paint(e.display_name(), "1"), badge_str(s.badge));
    if !e.metadata.comment.is_empty() {
        println!("  {}", e.metadata.comment);
    }
    println!("  id:          {}", e.id);
    println!("  source:      {}{}", tildify(&e.source_path), if e.source_path.exists() { "" } else { "  (missing)" });
    println!("  sha256:      {}", e.source.sha256);
    println!("  type:        {}", e.appimage_type.label());
    if let Some(sig) = &e.signature {
        println!("  signature:   {}", sig.detail);
    }
    println!("  category:    {}", e.category);
    println!("  state:       {:?}", e.state);
    match sel {
        Some(sel) => println!("  sandbox:     Bubblewrap ({})", sel.reason),
        None => println!("  sandbox:     not available (see sam-jail doctor)"),
    }
    println!("  risk:        {}", risk_line(&s.risk));
    if let Some(p) = &e.profile.preset {
        println!("  preset:      {p}");
    }
    if let Some(x) = &e.extraction {
        println!("  extraction:  {} files, {} via {} ({})", x.file_count, human_size(x.total_size), x.method, x.compression);
    } else {
        println!("  extraction:  {}", paint("not extracted", "31"));
    }
    println!("  launcher:    {}", e.desktop_entry.as_ref().map(|p| tildify(p)).unwrap_or_else(|| "none".into()));
    println!("  last run:    {}", e.last_launch.as_ref().map(|l| format!("{} — {}", format_ts(l.started_at), l.summary)).unwrap_or_else(|| "never".into()));

    let p = &e.profile.permissions;
    println!("\n{}", paint("Permissions", "1"));
    let fs = &p.filesystem;
    let mut dirs: Vec<String> = XDG_DIR_KEYS.iter().filter(|k| fs.xdg_access(k).is_granted()).map(|k| format!("{k} ({})", fs.xdg_access(k).as_str())).collect();
    dirs.extend(fs.custom_read.iter().map(|c| format!("{c} (ro)")));
    dirs.extend(fs.custom_write.iter().map(|c| format!("{c} (rw)")));
    println!("  filesystem:  {}", if fs.home { format!("FULL HOME ({})", fs.home_access.as_str()) } else if dirs.is_empty() { "private home only".into() } else { dirs.join(", ") });
    println!("  network:     {}", p.network.mode.as_str());
    println!("  display:     wayland={} x11={}", p.display.wayland, p.display.x11);
    println!("  audio:       {}{}{}", p.audio.enabled, if p.audio.pipewire { " + direct PipeWire" } else { "" }, if p.audio.alsa_raw { " + raw ALSA" } else { "" });
    println!("  devices:     gpu={} webcam={} gamepads={} input={} usb={}", p.devices.gpu, p.devices.webcam, p.devices.gamepads, p.devices.input, p.devices.usb);
    println!(
        "  desktop:     input_method={} keyring={} media_controls={} screen_sharing={} file_manager={}",
        p.integrations.input_method, p.integrations.keyring, p.integrations.media_controls, p.integrations.screen_sharing, p.integrations.file_manager
    );
    println!("  d-bus:       session={} system={}", p.dbus.session.mode.as_str(), p.dbus.system.mode.as_str());
    if let Some(d) = &e.detection {
        println!("\n{}", paint("Dependencies", "1"));
        print_detection(d);
    }
    if !e.recommendation_notes.is_empty() {
        println!("\n{}", paint("Why this profile", "1"));
        for n in &e.recommendation_notes {
            println!("  - {n}");
        }
    }
    if !warnings.is_empty() {
        println!("\n{}", paint("Warnings", "1"));
        print_warnings(warnings);
    }
}

fn print_detection(d: &DependencyReport) {
    println!("  toolkit: {}   arch: {}   ELF files: {}   bundled libs: {}", d.requirements.toolkit, d.arch, d.elf_count, d.bundled_libraries);
    println!("  compatibility: {:?}{}", d.compatibility, d.verdict.map(|v| format!("   ({})", v.message())).unwrap_or_default());
    let host_libs: Vec<&str> = d.missing.iter().filter(|m| m.class == ResourceClass::System).map(|m| m.name.as_str()).collect();
    if !host_libs.is_empty() {
        println!("  host system libraries: {}", host_libs.join(", "));
    }
    for m in d.missing.iter().filter(|m| m.class != ResourceClass::System) {
        println!("  host library {} [{:?}]{}", m.name, m.class, if m.host_available { "" } else { "  NOT FOUND" });
    }
    for r in d.resources.iter().filter(|r| !r.auto) {
        println!("  needs {} ({})", r.resource, r.reason);
    }
    for n in &d.notes {
        println!("  note: {n}");
    }
}

fn preset_cmd(app: &Sam, out: &Out, cmd: PresetCmd) -> Result<()> {
    let store = PresetStore::new(&app.paths);
    match cmd {
        PresetCmd::List => {
            let all = sam_profile::all_presets(&app.paths)?;
            out.emit(&all, || {
                for p in &all {
                    println!("{:<26} {:<10} {}{}", p.name, risk_str(p.risk), p.description, if p.builtin { "  (built-in)" } else { "" });
                }
            });
        }
        PresetCmd::Show { name } => {
            let p = sam_profile::find_preset(&app.paths, &name)?.with_context(|| format!("unknown preset '{name}'"))?;
            out.emit(&p, || print!("{}", preset_to_toml(&p).unwrap_or_default()));
        }
        PresetCmd::Apply { name, app: q, yes } => {
            let r = app.apply_preset(&q, &name, yes)?;
            out.emit(&r, || {
                let c = &r.check;
                for s in &c.removes_needed {
                    println!("  {} removes {s}, which the app likely needs", paint("warning:", "33"));
                }
                for s in &c.adds_dangerous {
                    println!("  {} adds high-risk permission: {s}", paint("warning:", "31"));
                }
                if r.applied {
                    println!("Applied '{}' (risk {} → {})", r.preset, c.risk_before, c.risk_after);
                } else {
                    println!("Not applied. Re-run with --yes to confirm.");
                }
            });
        }
        PresetCmd::Check { name, appimage, current_stdin } => {
            let current: Option<PermissionSet> = if current_stdin { Some(serde_json::from_str(&read_stdin()?).context("expected a PermissionSet as JSON on stdin")?) } else { None };
            let (p, c) = app.check_preset_preview(&appimage, &name, current)?;
            out.emit(&json!({"preset": p.name, "permissions": p.permissions, "check": c, "needs_confirmation": c.needs_confirmation()}), || {
                for s in &c.removes_needed {
                    println!("  {} removes {s}, which the app likely needs", paint("warning:", "33"));
                }
                for s in &c.adds_dangerous {
                    println!("  {} adds high-risk permission: {s}", paint("warning:", "31"));
                }
                println!("'{}': risk {} → {}", p.name, c.risk_before, c.risk_after);
            });
        }
        PresetCmd::Save { app: q, name, description } => {
            let p = app.save_preset_from_app(&q, &name, &description)?;
            out.emit(&p, || println!("Saved preset '{}' ({})", p.name, p.risk));
        }
        PresetCmd::Delete { name } => {
            if sam_profile::builtin_presets().iter().any(|b| b.name.eq_ignore_ascii_case(&name)) && store.get(&name)?.is_none() {
                bail!("built-in presets cannot be deleted");
            }
            let ok = store.delete(&name)?;
            if !ok {
                bail!("no user preset named '{name}'");
            }
            out.emit(&json!({"deleted": name}), || println!("Deleted preset '{name}'"));
        }
        PresetCmd::Duplicate { name, new_name } => {
            let mut p = sam_profile::find_preset(&app.paths, &name)?.with_context(|| format!("unknown preset '{name}'"))?;
            if sam_profile::find_preset(&app.paths, &new_name)?.is_some() {
                bail!("a preset named '{new_name}' already exists");
            }
            p.name = new_name;
            p.builtin = false;
            p.created_at = 0;
            store.save(&mut p)?;
            out.emit(&p, || println!("Created preset '{}'", p.name));
        }
        PresetCmd::Import { file } => {
            let mut p = read_preset_file(&file)?;
            if sam_profile::builtin_presets().iter().any(|b| b.name.eq_ignore_ascii_case(&p.name)) {
                p.name = format!("{} (imported)", p.name);
            }
            let path = store.save(&mut p)?;
            out.emit(&p, || println!("Imported '{}' → {}", p.name, tildify(&path)));
        }
        PresetCmd::Export { name, file } => {
            let p = sam_profile::find_preset(&app.paths, &name)?.with_context(|| format!("unknown preset '{name}'"))?;
            let text = preset_to_toml(&p)?;
            match &file {
                Some(f) => std::fs::write(f, &text)?,
                None if !out.json => print!("{text}"),
                None => {}
            }
            out.emit(&json!({"toml": text, "file": file}), || {
                if let Some(f) = &file {
                    println!("Exported '{}' → {}", p.name, f.display());
                }
            });
        }
        PresetCmd::Put => {
            let input = read_stdin()?;
            let mut p: Preset = match serde_json::from_str::<Preset>(&input) {
                Ok(p) => p,
                Err(_) => parse_preset_toml(&input).context("expected a preset as JSON or TOML on stdin")?,
            };
            if sam_profile::builtin_presets().iter().any(|b| b.name.eq_ignore_ascii_case(&p.name)) {
                bail!("'{}' is a built-in preset; duplicate it to make changes", p.name);
            }
            if let Some(existing) = store.get(&p.name)? {
                p.created_at = existing.created_at;
            }
            store.save(&mut p)?;
            out.emit(&p, || println!("Saved preset '{}'", p.name));
        }
    }
    Ok(())
}

fn config_cmd(app: &Sam, out: &Out, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Show => {
            let c = &app.config;
            out.emit(c, || print!("{}", toml::to_string_pretty(c).unwrap_or_default()));
        }
        ConfigCmd::Get { key } => {
            let v = app.config.get_key(&key)?;
            out.emit(&v, || println!("{v}"));
        }
        ConfigCmd::Set { key, value } => {
            let mut c = app.config.clone();
            c.set_key(&key, &value)?;
            c.save(&app.paths)?;
            let v = c.get_key(&key)?;
            out.emit(&json!({"key": key, "value": v}), || println!("{key} = {v}"));
        }
        ConfigCmd::Put => {
            let c: Config = serde_json::from_str(&read_stdin()?).context("expected the configuration as JSON on stdin")?;
            c.validate()?;
            c.save(&app.paths)?;
            out.emit(&c, || println!("Configuration saved"));
        }
        ConfigCmd::Path => {
            let v: Value = json!({
                "config_file": app.paths.config_file(),
                "data_dir": app.paths.data_dir,
                "extracted": app.extracted_root(),
                "presets": app.paths.presets_dir(),
                "logs": app.paths.logs_dir(),
                "applications": app.paths.applications_dir,
            });
            out.emit(&v, || {
                for (k, val) in v.as_object().unwrap() {
                    println!("{k:<14} {}", val.as_str().unwrap_or_default());
                }
            });
        }
    }
    Ok(())
}

/// "High (Network, Webcam)": the level and the permissions that set it.
fn risk_line(r: &sam_core::risk::RiskAssessment) -> String {
    let names: Vec<&str> = r.deciding().iter().map(|i| i.title.as_str()).collect();
    if names.is_empty() {
        risk_str(r.level)
    } else {
        format!("{} ({})", risk_str(r.level), names.join(", "))
    }
}

/// `sam-jail.1` plus `sam-jail-<command>.1` for every visible command,
/// generated from the same definitions as `--help`.
fn write_man_pages(dir: &std::path::Path) -> Result<()> {
    use clap::CommandFactory;
    std::fs::create_dir_all(dir)?;
    // The release script sets the release date; otherwise today.
    let date = std::env::var("SAM_MAN_DATE").unwrap_or_else(|_| sam_core::util::format_ts(sam_core::util::now()).chars().take(10).collect());
    let render = |cmd: clap::Command, file: &str| -> Result<()> {
        let mut buf = Vec::new();
        clap_mangen::Man::new(cmd).date(date.clone()).source(format!("SAM {}", env!("CARGO_PKG_VERSION"))).manual("SAM - Sandboxed AppImage Manager").render(&mut buf)?;
        std::fs::write(dir.join(file), buf)?;
        Ok(())
    };
    let root = Cli::command();
    for sub in root.get_subcommands().filter(|s| !s.is_hide_set()) {
        // A one-off command: the names may live until it exits.
        let name: &'static str = Box::leak(format!("sam-jail-{}", sub.get_name()).into_boxed_str());
        let typed: &'static str = Box::leak(format!("sam-jail {}", sub.get_name()).into_boxed_str());
        render(sub.clone().name(name).display_name(name).bin_name(typed), &format!("{name}.1"))?;
    }
    render(root, "sam-jail.1")
}

