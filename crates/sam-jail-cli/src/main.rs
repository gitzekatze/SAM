//! `sam-jail`: the command line interface.
//!
//! Every command supports `--json`, which prints a single JSON envelope
//! (`{"ok": true, "data": ...}` or `{"ok": false, "error": "..."}`). The GUI
//! uses this mode as its API.

use sam_core::i18n::{tr, trf, trn};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sam_core::error::InFunctionExt;
use sam_core::util::{format_ts, human_size, tildify};
use sam_core::*;
use sam_runner::launch::{prepare, run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};
use sam_storage::{
    parse_preset_toml, preset_to_toml, read_preset_file, LogKind, Logs, PresetStore,
};
use serde::Serialize;
use serde_json::{json, Value};

mod bench;
mod cli;
mod config_cmd;
mod man;
mod output;
mod presets;

use cli::*;
use config_cmd::config_cmd;
use man::write_man_pages;
use output::*;
use presets::{group_cmd, preset_cmd};

/// Progress as JSON lines on stderr, at most about ten per second (the
/// first report of each step and the last one always pass).
fn progress_lines() -> sam_runner::progress::ProgressSink {
    let last = std::sync::Mutex::new((0usize, std::time::Instant::now()));
    sam_runner::progress::ProgressSink::new(move |p| {
        let Ok(mut l) = last.lock() else { return };
        let now = std::time::Instant::now();
        if !progress_passes(*l, p, now) {
            return;
        }
        *l = (p.step, now);
        errln!("{}", json!({ "progress": p }));
    })
}

/// Whether a progress report is printed at `now`, after the last printed
/// one (`last`: its step and time): the first report of each step and the
/// last one (all done) always, others of the same step at most every
/// 100 ms.
fn progress_passes(
    last: (usize, std::time::Instant),
    p: &sam_runner::progress::Progress,
    now: std::time::Instant,
) -> bool {
    !(last.0 == p.step
        && now.saturating_duration_since(last.1) < std::time::Duration::from_millis(100)
        && p.fraction < 1.0)
}

fn main() {
    // Like other command-line tools, end quietly when the reader of the
    // output goes away (`sam-jail list | head`) instead of panicking.
    // Rust ignores SIGPIPE by default; started apps get the default back
    // from std::process::Command either way.
    // SAFETY: called first in main, before any other thread exists.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    // What this program inherited never reaches an app (review F6).
    sam_core::util::close_inherited_on_exec();
    // Messages in the user's language (before any other thread starts).
    sam_core::i18n::init(true);
    let cli = Cli::parse();
    let json_mode = cli.json;
    // The app a refused `run` names, for the hint how to start it anyway.
    let run_app = match &cli.cmd {
        Cmd::Run { app, .. } => Some(app.clone()),
        _ => None,
    };
    let function = function_for(&cli.cmd);
    let result = match function {
        Some(id) => real_main(cli).in_function(id),
        None => real_main(cli),
    };
    if let Err(e) = result {
        let message = sam_core::error::message_of(&e);
        let function = sam_core::error::function_of(&e);
        if json_mode {
            // A code lets callers react without reading the (translated)
            // message; the function names the part of SAM it happened in.
            let mut v = json!({"ok": false, "error": message});
            if let Some(code) = sam_core::error::code_of(&e) {
                v["code"] = json!(code);
            }
            if let Some(id) = function {
                v["function"] = json!(id);
            }
            sam_core::terminal::print_json(&v.to_string());
        } else {
            match function {
                Some(id) => errln!(
                    "{} {message} ({})",
                    paint("error:", "1;31"),
                    sam_core::i18n::trf("SAM function {id}", &[("id", &id)])
                ),
                None => errln!("{} {message}", paint("error:", "1;31")),
            }
            // How to choose "Start anyway" here (B2 R75, R77): only after
            // `run`, the one command that takes it.
            if let Some(q) = run_app.as_ref().filter(|_| {
                sam_core::error::code_of(&e) == Some(sam_runner::launch::PROTECTION_MISSING)
            }) {
                errln!(
                    "{}",
                    sam_core::i18n::trf(
                        "To start it anyway this one time: {command}",
                        &[(
                            "command",
                            &format!(
                                "sam-jail run --start-anyway {}",
                                sam_core::util::shell_quote(q)
                            ),
                        )],
                    )
                );
            }
        }
        std::process::exit(1);
    }
    let code = EXIT.load(std::sync::atomic::Ordering::Relaxed);
    if code != 0 {
        use std::io::Write;
        std::io::stdout().flush().ok();
        std::process::exit(code);
    }
}

/// Exit code of a command that ran but whose check did not pass, or that
/// did not do what was asked: `verify` with a failed check, `selftest`
/// with a failed app, `doctor` with a failed check or a broken contract,
/// `preset apply` not applied. 1 is an error, 2 a wrong command line
/// (clap's). So `sam-jail verify APP && sam-jail run APP` gates (audit
/// G-F9: these ended with 0).
pub(crate) const EXIT_NOT_PASSED: i32 = 3;

static EXIT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// The exit code once the output is written (the output comes first, so a
/// script still reads what failed).
pub(crate) fn exit_with(code: i32) {
    EXIT.store(code, std::sync::atomic::Ordering::Relaxed);
}

/// `on` or `off` for a switch given in words; anything else is refused
/// (audit G-F9: `ON` meant off).
fn on_off(state: &str) -> Result<bool> {
    match state.to_ascii_lowercase().as_str() {
        "on" | "true" | "1" | "yes" => Ok(true),
        "off" | "false" | "0" | "no" => Ok(false),
        _ => bail!(trf(
            "“{state}” is neither on nor off.",
            &[("state", &state)]
        )),
    }
}

/// The SAM function (docs/functions.md) each command carries out, so an
/// error names the part of SAM it happened in. Steps inside a command that
/// belong to another function mark their errors themselves (the innermost
/// mark wins). `scripts/function-map.py --check` makes sure each number
/// exists.
fn function_for(cmd: &Cmd) -> Option<u16> {
    Some(match cmd {
        Cmd::Scan { .. } | Cmd::Discover | Cmd::Onboarding { .. } => 1,
        Cmd::Add { .. } | Cmd::Reextract { .. } => 3,
        Cmd::Preview { .. } | Cmd::Redetect { .. } => 6,
        Cmd::Info { .. } | Cmd::Get { .. } | Cmd::Evaluate { .. } => 7,
        Cmd::Set { .. } | Cmd::Profile { .. } | Cmd::Group { .. } | Cmd::Preset { .. } => 8,
        Cmd::Run { .. }
        | Cmd::Menu { .. }
        | Cmd::Args { .. }
        | Cmd::Command { .. }
        | Cmd::Desktop { .. } => 19,
        Cmd::Verify { .. } | Cmd::Selftest { .. } => 20,
        Cmd::Stop { .. } => 21,
        Cmd::Logs { .. } => 22,
        Cmd::Hints { .. } => 23,
        Cmd::Repair { .. } => 24,
        Cmd::Diagnose { .. } => 25,
        Cmd::Compat { .. } => 26,
        Cmd::Review { .. } => 27,
        Cmd::Updates { .. } | Cmd::Update { .. } | Cmd::SelfUpdate { .. } => 28,
        Cmd::Refresh { .. } | Cmd::Relocate { .. } => 29,
        Cmd::Remove { .. } => 30,
        Cmd::Space { .. } | Cmd::FreeSpace { .. } | Cmd::Cleanup { .. } => 31,
        Cmd::Uninstall { .. } => 32,
        Cmd::Doctor { .. } => 33,
        Cmd::Report { .. } => 34,
        Cmd::List { .. } => 35,
        Cmd::Permissions => 36,
        Cmd::Man { .. } | Cmd::Version | Cmd::Config { .. } | Cmd::Dev { .. } => return None,
    })
}

fn real_main(cli: Cli) -> Result<()> {
    let out = Out { json: cli.json };
    // Before opening SAM's data, so it answers even when that fails.
    if let Cmd::Version = cli.cmd {
        let (version, interface) = (env!("CARGO_PKG_VERSION"), sam_core::JSON_INTERFACE);
        out.emit(&json!({"version": version, "interface": interface}), || {
            outln!("sam-jail {version} (JSON interface {interface})")
        });
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
                        Ok(o) => added.push(
                            json!({"path": it.path, "id": o.entry.id, "relocated": o.relocated}),
                        ),
                        Err(e) => added.push(json!({"path": it.path, "error": format!("{e:#}")})),
                    }
                }
            }
            out.emit(&json!({"found": items, "added": added}), || {
                if items.is_empty() {
                    outln!(
                        "{}",
                        trf(
                            "No AppImages found in: {folders}",
                            &[("folders", &app.config.general.scan_directories.join(", "))]
                        )
                    );
                }
                for it in &items {
                    let st = match (&it.registered, &it.moved_from) {
                        (Some(id), _) => format!("registered as {id}"),
                        (None, Some(id)) => paint(
                            &sam_core::i18n::trf("moved copy of {id}", &[("id", &id)]),
                            "33",
                        ),
                        _ => paint("new", "36"),
                    };
                    outln!("{}  {}  ({})", tildify(&it.path), st, human_size(it.size));
                }
                for a in &added {
                    match a.get("error") {
                        Some(e) => outln!("  failed {}: {}", a["path"], e),
                        None => outln!("  added {}", a["id"].as_str().unwrap_or_default()),
                    }
                }
            });
        }
        Cmd::Discover => {
            let found = app.discover()?;
            out.emit(&json!({"apps": found}), || {
                if found.is_empty() {
                    outln!(
                        "{}",
                        trf(
                            "No AppImages found in: {folders}",
                            &[(
                                "folders",
                                &app.default_scan_dirs()
                                    .iter()
                                    .map(|d| tildify(d))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )]
                        )
                    );
                }
                for d in &found {
                    let st = match (&d.sandboxed, &d.moved_from) {
                        (Some(id), _) => paint(&format!("sandboxed ({id})"), "32"),
                        (None, Some(id)) => paint(
                            &sam_core::i18n::trf("moved copy of {id}", &[("id", &id)]),
                            "33",
                        ),
                        _ => paint("not sandboxed", "36"),
                    };
                    outln!(
                        "{:<28} {:<14} {}  {}",
                        d.name,
                        d.category_label,
                        st,
                        tildify(&d.path)
                    );
                    for m in &d.menu_entries {
                        outln!("    unsandboxed menu entry: {}", tildify(&m.file));
                    }
                }
            });
        }
        Cmd::Hints {
            app: query,
            apply,
            yes,
        } => {
            let e = app.resolve(&query)?;
            let e = match apply {
                Some(id) => {
                    let sug = sam_runner::repair::first_run_hints(&e)
                        .into_iter()
                        .find(|s| s.id == id)
                        .with_context(|| format!("no hint '{id}' for {}", e.display_name()))?;
                    app.apply_suggestion(&query, &sug, false, yes)?
                }
                None => e,
            };
            let hints = sam_runner::repair::first_run_hints(&e);
            out.emit(&json!({"hints": hints}), || {
                if hints.is_empty() {
                    outln!(
                        "{}",
                        trf("Nothing to check for {app}.", &[("app", &e.display_name())])
                    );
                }
                for h in &hints {
                    outln!(
                        "{}  {}\n    {}\n    fix: sam-jail hints {} --apply {}",
                        paint(&h.id, "1"),
                        h.title,
                        h.explanation,
                        e.id,
                        h.id
                    );
                }
            });
        }
        Cmd::Repair {
            app: query,
            apply,
            next,
            undo,
            undo_step,
            yes,
        } => {
            let e = app.resolve(&query)?;
            let applied = if undo {
                app.undo_repairs(&query)?;
                Some("undo".to_string())
            } else if let Some(id) = undo_step {
                app.undo_repair_step(&query, &id)?;
                Some(format!("undo {id}"))
            } else if let Some(id) = apply.or_else(|| {
                next.then(|| {
                    sam_runner::repair::ladder(&e, &app.config, &app.paths)
                        .first()
                        .map(|s| s.id.clone())
                })
                .flatten()
            }) {
                let sug = app.find_suggestion(&e, &id).with_context(|| {
                    trf(
                        "no repair step '{id}' for {app}",
                        &[("id", &id), ("app", &e.display_name())],
                    )
                })?;
                may_apply(&sug, yes)?;
                app.apply_suggestion(&query, &sug, true, yes)?;
                Some(sug.title)
            } else {
                None
            };
            let e = app.resolve(&query)?;
            let steps = sam_runner::repair::ladder(&e, &app.config, &app.paths);
            let findings = e
                .last_launch
                .as_ref()
                .map(|l| l.findings.clone())
                .unwrap_or_default();
            out.emit(
                &json!({"applied": applied, "findings": findings, "steps": steps, "applied_steps": e.repairs_applied, "can_undo": e.repair_backup.is_some()}),
                || {
                    if let Some(a) = &applied {
                        outln!("{}", trf("Applied: {step}. Start the app again to test it.", &[("step", &a)]));
                    }
                    for f in &findings {
                        outln!("{} {}: {}", paint("found", "33"), f.title, f.explanation);
                    }
                    for (i, st) in steps.iter().enumerate() {
                        outln!("{}. {} ({})\n   {}", i + 1, st.title, st.id, st.explanation);
                    }
                    if steps.is_empty() {
                        outln!("{}", trf("No more repair steps. Check the logs (sam-jail logs {id}).", &[("id", &e.id)]));
                    }
                    if e.repair_backup.is_some() {
                        outln!("{}", sam_core::i18n::trf("Undo all repairs: sam-jail repair {id} --undo", &[("id", &e.id)]));
                    }
                },
            );
        }
        Cmd::Selftest { apps, seconds } => {
            let list: Vec<AppEntry> = if apps.is_empty() {
                app.registry().list()?
            } else {
                apps.iter().map(|q| app.resolve(q)).collect::<Result<_>>()?
            };
            let mut results = Vec::new();
            for mut e in list {
                if !out.json {
                    errln!(
                        "{}",
                        sam_core::i18n::trf(
                            "Testing {name} for {seconds} s…",
                            &[("name", &e.display_name()), ("seconds", &seconds)]
                        )
                    );
                }
                let opts = LaunchOptions {
                    timeout_secs: Some(seconds),
                    quiet: true,
                    ..Default::default()
                };
                let start = app.start_lock(&mut e);
                let (status, detail, findings) = match start
                    .and_then(|_start| run(&mut e, &opts, &app.config, &app.paths, &app.host()))
                {
                    Ok(rec) => selftest_verdict(&rec, seconds, e.metadata.terminal),
                    Err(err) => ("fail", format!("{err:#}"), vec![]),
                };
                results.push(json!({"id": e.id, "name": e.display_name(), "status": status, "detail": detail, "findings": findings}));
            }
            if results.iter().any(|r| r["status"] != "ok") {
                exit_with(EXIT_NOT_PASSED);
            }
            out.emit(&json!({"results": results}), || {
                for r in &results {
                    let ok = r["status"] == "ok";
                    outln!(
                        "{} {:<28} {}",
                        if ok {
                            paint("✓", "32")
                        } else {
                            paint("✗", "31")
                        },
                        r["name"].as_str().unwrap_or_default(),
                        r["detail"].as_str().unwrap_or_default()
                    );
                    for f in r["findings"].as_array().into_iter().flatten() {
                        outln!("    likely: {}", f["title"].as_str().unwrap_or_default());
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
            let dups: Vec<_> = app
                .menu_duplicates(&e)
                .into_iter()
                .map(|f| json!({"file": f.file, "name": f.name}))
                .collect();
            out.emit(
                &json!({"visible": dups, "hidden": e.hidden_entries}),
                || {
                    for d in &dups {
                        outln!("visible  {}", d["file"].as_str().unwrap_or_default());
                    }
                    for h in &e.hidden_entries {
                        outln!("hidden   {}", tildify(&h.original));
                    }
                    if dups.is_empty() && e.hidden_entries.is_empty() {
                        outln!(
                            "{}",
                            trf(
                                "No other menu entries start {app}.",
                                &[("app", &e.display_name())]
                            )
                        );
                    }
                },
            );
        }
        Cmd::Preview {
            path,
            permissions_stdin,
        } => {
            let perms: Option<PermissionSet> = if permissions_stdin {
                Some(
                    serde_json::from_str(&read_stdin()?)
                        .context(tr("expected a PermissionSet as JSON on stdin"))?,
                )
            } else {
                None
            };
            let v = app.preview(&path, perms)?;
            out.emit(&v, || {
                outln!("{}", serde_json::to_string_pretty(&v).unwrap_or_default())
            });
        }
        Cmd::Add {
            path,
            allow_fallback,
            no_launcher,
            preset,
            accept,
            hide_duplicates,
            permissions_stdin,
            progress,
        } => {
            let permissions: Option<PermissionSet> = if permissions_stdin {
                Some(
                    serde_json::from_str(&read_stdin()?)
                        .context(tr("expected a PermissionSet as JSON on stdin"))?,
                )
            } else {
                None
            };
            let progress = if progress {
                progress_lines()
            } else {
                Default::default()
            };
            let o = app.add(
                &path,
                &AddOptions {
                    consent_fallback: allow_fallback,
                    launcher: no_launcher.then_some(false),
                    preset,
                    accept,
                    hide_duplicates,
                    permissions,
                    progress,
                },
            )?;
            let summary = AppSummary::from_entry(&o.entry);
            out.emit(&json!({"app": summary, "entry": o.entry, "relocated": o.relocated, "needs_fallback_consent": o.needs_fallback_consent, "warnings": o.warnings}), || {
                if o.relocated {
                    outln!("{}", trf("{app} was already registered; its location was updated.", &[("app", &o.entry.display_name())]));
                    return;
                }
                outln!("Sandboxed {} as {} [{}]", o.entry.display_name(), o.entry.id, badge_str(summary.badge));
                for h in &o.entry.hidden_entries {
                    outln!("  hid unsandboxed menu entry {}", tildify(&h.original));
                }
                if let Some(x) = &o.entry.extraction {
                    outln!("  extracted {} files ({}) via {}", x.file_count, human_size(x.total_size), x.method);
                }
                outln!("  category: {}   risk: {}", o.entry.category, risk_line(&summary.risk));
                for n in &o.entry.recommendation_notes {
                    outln!("  - {n}");
                }
                if o.needs_fallback_consent {
                    outln!("{}", paint("  Static extraction failed. Retry with --allow-fallback to let the AppImage extract itself inside a restricted sandbox.", "33"));
                }
                print_warnings(&o.warnings);
                if !o.entry.reviewed {
                    outln!("{}", trf("Review the permissions with `sam-jail info {id}` or in the SAM app, then `sam-jail review {id}`.", &[("id", &o.entry.id)]));
                }
            });
        }
        Cmd::List {
            search,
            badge,
            risk,
            category,
            sort,
        } => {
            let mut apps: Vec<AppSummary> = app
                .registry()
                .list()?
                .iter()
                .map(AppSummary::from_entry)
                .collect();
            if let Some(s) = search {
                let s = s.to_lowercase();
                apps.retain(|a| {
                    a.name.to_lowercase().contains(&s)
                        || a.id.contains(&s)
                        || a.comment.to_lowercase().contains(&s)
                });
            }
            if let Some(b) = badge {
                apps.retain(|a| {
                    serde_json::to_value(a.badge)
                        .ok()
                        .and_then(|v| v.as_str().map(|s| s == b))
                        .unwrap_or(false)
                });
            }
            if let Some(r) = risk {
                apps.retain(|a| a.risk.level.is_named(&r));
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
                    outln!("{}", sam_core::i18n::tr("No apps are registered. Add one with `sam-jail add <file.AppImage>` or `sam-jail scan --add`."));
                    return;
                }
                let w = apps.iter().map(|a| a.id.len()).max().unwrap_or(10);
                outln!("{:<w$}  {:<24}  {:<12}  {:<11}  {:<12}  LAST RUN", "ID", "NAME", "CATEGORY", "RISK", "STATUS", w = w);
                for a in &apps {
                    let last = a.last_launched.map(format_ts).unwrap_or_else(|| "never".into());
                    let risk = format!("{:<11}", a.risk.level.words());
                    let badge = format!("{:<12}", a.badge.label());
                    outln!(
                        "{:<w$}  {:<24}  {:<12}  {}  {}  {last}",
                        a.id,
                        truncate(&a.name, 24),
                        a.category,
                        risk.replace(&a.risk.level.words(), &risk_str(a.risk.level)),
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
            let selection = sam_runner::bwrap::check(&host).ok();
            let hints = sam_runner::repair::first_run_hints(&e);
            let steps = sam_runner::repair::ladder(&e, &app.config, &app.paths);
            // What each repair step changes and costs, for the step switches;
            // what compatibility mode turns on (or turned on).
            let p = &e.profile.permissions;
            let mut effects = serde_json::Map::new();
            for s in steps
                .iter()
                .chain(e.applied_repairs.iter().filter_map(|r| r.step.as_ref()))
            {
                effects.insert(s.id.clone(), json!(sam_runner::repair::effect(s, p)));
            }
            let compat_changes = match (&e.profile.compatibility_mode, &e.profile.before_compat) {
                (true, Some(before)) => sam_runner::repair::compat_changes(before),
                _ => sam_runner::repair::compat_changes(p),
            };
            out.emit(
                &json!({"app": summary, "entry": e, "warnings": warnings, "selection": selection, "hints": hints, "repair_steps": steps, "repair_effects": effects, "compat_changes": compat_changes, "private_home": app.paths.app_home(&e.id), "running": app.running(&e.id).len(),
                    "check_current": e.last_check.as_ref().is_some_and(|c| c.key == sam_runner::verify::check_key(&e, &app.config, &host)),
                    "review_fingerprint": sam_storage::review_fingerprint(&e)?}),
                || print_info(&e, &summary, &warnings, selection.as_ref()),
            );
        }
        Cmd::Remove {
            app: q,
            keep_data,
            stop,
        } => {
            if stop {
                app.stop(&q)?;
            }
            let (e, problems) = app.remove(&q, keep_data)?;
            out.emit(&json!({"removed": e.id, "warnings": problems}), || {
                if keep_data {
                    outln!(
                        "{}",
                        sam_core::i18n::trf(
                            "Removed {name} ({id}); its private data was kept",
                            &[("name", &e.display_name()), ("id", &e.id)]
                        )
                    );
                } else {
                    outln!(
                        "{}",
                        sam_core::i18n::trf(
                            "Removed {name} ({id})",
                            &[("name", &e.display_name()), ("id", &e.id)]
                        )
                    );
                };
                for p in &problems {
                    errln!("{} {p}", paint("warning:", "33"));
                }
            });
        }
        Cmd::Version => {} // answered above
        Cmd::Updates { app: q, if_due } => {
            let results = app.check_updates(q.as_deref(), if_due)?;
            let list: Vec<_> = results
                .iter()
                .map(|(id, s)| json!({"id": id, "update": s}))
                .collect();
            out.emit(&json!({"apps": list}), || {
                if results.is_empty() && if_due {
                    outln!("{}", tr("Nothing is due: updates.check_on_start is off, or every app was checked today."));
                }
                for (id, s) in &results {
                    let state = match s.state {
                        sam_core::model::UpdateState::Available => paint("update available", "33"),
                        sam_core::model::UpdateState::Current => paint("up to date", "32"),
                        sam_core::model::UpdateState::Failed => paint("check failed", "31"),
                        sam_core::model::UpdateState::Unsupported => tr("no update source"),
                    };
                    outln!("{id:<32} {state}  {}", s.detail);
                    if let Some(p) = s.download_page.as_deref().filter(|_| s.state == sam_core::model::UpdateState::Available) {
                        outln!("{:<32} {p}", "");
                    }
                }
            });
        }
        Cmd::Update {
            app: q,
            decline_key_change: true,
            ..
        } => {
            let (e, was) = app.decline_update(&q)?;
            #[derive(Serialize)]
            struct Declined {
                deleted: bool,
                #[serde(flatten)]
                app: AppSummary,
            }
            let answer = Declined {
                deleted: was,
                app: AppSummary::from_entry(&e),
            };
            out.emit(&answer, || {
                let name = sam_core::util::display_safe(e.display_name(), 80);
                if was {
                    outln!(
                        "{}",
                        trf(
                            "The update of {app} that waited for your answer was deleted.",
                            &[("app", &name)]
                        )
                    );
                } else {
                    outln!(
                        "{}",
                        trf(
                            "No update of {app} waits for your answer.",
                            &[("app", &name)]
                        )
                    );
                }
            });
        }
        Cmd::Update {
            app: q,
            undo,
            accept_key_change,
            ..
        } => {
            let e = if undo {
                app.undo_update(&q)?
            } else {
                app.update(&q, accept_key_change)?
            };
            out.emit(&AppSummary::from_entry(&e), || {
                if undo {
                    outln!(
                        "{}",
                        trf(
                            "{app} is back to {file}.",
                            &[
                                ("app", &e.display_name()),
                                ("file", &tildify(&e.source_path))
                            ]
                        )
                    );
                } else {
                    outln!("{} updated: {}", e.display_name(), tildify(&e.source_path));
                    if let Some(b) = &e.update_backup {
                        outln!(
                            "  previous version kept: {} (sam-jail update {} --undo)",
                            tildify(&b.file),
                            e.id
                        );
                    }
                }
            });
        }
        Cmd::SelfUpdate { check } => {
            let appimage = std::env::var_os("APPIMAGE")
                .map(std::path::PathBuf::from)
                .unwrap_or_default();
            let r = app.self_update(&appimage, check)?;
            out.emit(&r, || {
                outln!("{}", r.detail);
                if r.state == "updated" {
                    outln!("  new file: {}", tildify(&r.path));
                }
            });
        }
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
                    outln!(
                        "{:<28} {:>10}  (unpacked {}, home {}, app folder {}, logs {})",
                        u.name,
                        mb(u.total),
                        mb(u.unpacked),
                        mb(u.home),
                        mb(u.overlay),
                        mb(u.logs)
                    );
                }
                outln!("{:<28} {:>10}", "total", mb(total));
            });
        }
        Cmd::FreeSpace { app: q } => {
            let freed = app.free_space(&q)?;
            out.emit(&json!({"freed": freed}), || {
                outln!(
                    "{}",
                    trf(
                        "Freed {size}; the next start unpacks the AppImage again.",
                        &[("size", &format!("{:.1} MB", freed as f64 / 1e6))]
                    )
                )
            });
        }
        Cmd::Man { dir } => {
            write_man_pages(&dir)?;
            out.emit(&json!({"dir": dir}), || {
                outln!(
                    "{}",
                    trf(
                        "Man pages written to {folder}.",
                        &[("folder", &dir.display())]
                    )
                )
            });
        }
        Cmd::Uninstall { keep_data, yes } => {
            let u = app.uninstall(keep_data, !yes)?;
            out.emit(&json!({"done": yes, "apps": u.apps, "files": u.files, "dirs": u.dirs, "problems": u.problems}), || {
                outln!(
                    "{}",
                    match (yes, keep_data) {
                        (true, false) => tr("Removed from SAM:"),
                        (true, true) => tr("Removed from SAM (settings and app data kept):"),
                        (false, false) => tr("This would remove from SAM:"),
                        (false, true) => tr("This would remove from SAM (keeping settings and app data):"),
                    }
                );
                outln!("  sandboxes: {}", if u.apps.is_empty() { "none".into() } else { u.apps.join(", ") });
                for f in &u.files {
                    outln!("  {}", tildify(f));
                }
                for d in &u.dirs {
                    outln!("  {}/", tildify(d));
                }
                for p in &u.problems {
                    errln!("{} {p}", paint("warning:", "33"));
                }
                if !yes {
                    outln!("{}", sam_core::i18n::tr("Your AppImage files stay. Run again with --yes to remove SAM."));
                } else {
                    outln!("{}", tr("Your AppImage files were not touched. Remove the SAM package or AppImage to finish."));
                }
            });
        }
        Cmd::Stop { app: q } => {
            let n = app.stop(&q)?;
            out.emit(&json!({"stopped": n}), || {
                if n == 0 {
                    outln!("{}", sam_core::i18n::tr("Not running"));
                } else {
                    outln!(
                        "{}",
                        sam_core::i18n::trn(
                            "Closed {n} running launch",
                            "Closed {n} running launches",
                            n as u64,
                            &[]
                        )
                    );
                }
            });
        }
        Cmd::Run {
            app: q,
            args,
            start_anyway,
        } => {
            let mut e = app.resolve(&q)?;
            app.ensure_unpacked(&mut e)?;
            let _start = app.start_lock(&mut e)?;
            app.check_before_start(&mut e, &app.host())?;
            let rec = run(
                &mut e,
                &LaunchOptions {
                    args,
                    // With --json, standard output is SAM's reply alone.
                    app_output_to_stderr: cli.json,
                    start_anyway,
                    ..Default::default()
                },
                &app.config,
                &app.paths,
                &app.host(),
            )?;
            out.emit(&rec, || {
                if rec.sandbox_failure {
                    errln!("{} {}", paint("sam-jail:", "1;31"), rec.summary);
                    errln!(
                        "  log: {}",
                        rec.log_file
                            .as_ref()
                            .map(|p| tildify(p))
                            .unwrap_or_default()
                    );
                    errln!(
                        "  try: sam-jail doctor {} / sam-jail diagnose {} / sam-jail repair {}",
                        e.id,
                        e.id,
                        e.id
                    );
                }
            });
            // The app's own exit code (a terminal program's error code counts
            // as a successful start, but scripts still see it), with --json
            // too (audit G-F9: a sandbox failure ended with 0 there).
            if !rec.success || rec.exit_code.is_some_and(|c| c != 0) {
                exit_with(rec.exit_code.unwrap_or(1).max(1));
            }
        }
        Cmd::Command { app: q, args } => {
            let e = app.resolve(&q)?;
            let p = prepare(
                &e,
                &LaunchOptions {
                    args,
                    // Shown, not started: a missing protection is part of
                    // what the command shows (B2 R75).
                    preview: true,
                    ..Default::default()
                },
                &app.config,
                &app.paths,
                &app.host(),
            )?;
            let pv = p.preview();
            out.emit(&pv, || {
                outln!("# sandbox: {} ({})", pv.backend, pv.reason);
                outln!("# landlock: {}  seccomp: {}", pv.landlock, pv.seccomp);
                if let Some(d) = &pv.dbus_proxy {
                    outln!(
                        "# dbus proxy: xdg-dbus-proxy {}",
                        sam_core::util::shell_join(d)
                    );
                }
                for n in &pv.notes {
                    outln!("# note: {n}");
                }
                if !pv.app_variables.is_empty() {
                    outln!(
                        "# {}",
                        trf(
                            "set by SAM's helper for the app, after its layers: {variables}",
                            &[(
                                "variables",
                                &sam_core::util::shell_join(
                                    pv.app_variables.iter().map(|(k, v)| format!("{k}={v}"))
                                )
                            )]
                        )
                    );
                }
                outln!("{}", pretty_command(&pv.argv));
            });
        }
        Cmd::Doctor {
            contracts: true, ..
        } => {
            let host = HostInfo::probe_full();
            let report = sam_runner::contracts::check_all(&host);
            if report
                .contracts
                .iter()
                .any(|c| c.state == sam_runner::contracts::State::Broken)
            {
                exit_with(EXIT_NOT_PASSED);
            }
            out.emit(&report, || {
                use sam_runner::contracts::State;
                for c in &report.contracts {
                    let st = match c.state {
                        State::Holds => paint(" holds ", "32"),
                        State::Broken => paint(" BROKEN", "1;31"),
                        State::Absent => paint(" absent", "33"),
                        State::NotHere => paint("   -   ", "2"),
                    };
                    outln!("{st}  {:<26} {}", c.id, c.detail);
                    if c.state == State::Broken {
                        outln!("         {:<26} → {}", "", c.playbook);
                    }
                }
                outln!();
                for v in &report.components {
                    if let Some(ver) = &v.version {
                        outln!("  {:<40} {ver}", v.name);
                    }
                }
            });
        }
        Cmd::Doctor { app: q, .. } => {
            let host = HostInfo::probe_full();
            let report = match &q {
                Some(q) => sam_runner::doctor::app_report(&app, &app.resolve(q)?, &host),
                None => sam_runner::doctor::system_report(&app, &host),
            };
            if report.checks.iter().any(|c| c.status == CheckStatus::Fail) {
                exit_with(EXIT_NOT_PASSED);
            }
            out.emit(&report, || {
                for c in &report.checks {
                    let st = match c.status {
                        CheckStatus::Ok => paint("  ok ", "32"),
                        CheckStatus::Info => paint(" info", "36"),
                        CheckStatus::Warn => paint(" warn", "33"),
                        CheckStatus::Fail => paint(" FAIL", "1;31"),
                    };
                    outln!("{st}  {:<26} {}", c.label, c.detail);
                    if let Some(h) = &c.hint {
                        outln!("       {:<26} → {h}", "");
                    }
                }
            });
        }
        Cmd::Logs {
            app: q,
            kind,
            list,
            file,
            tail,
        } => {
            let e = app.resolve(&q)?;
            let kind = kind
                .as_deref()
                .map(|k| {
                    LogKind::parse(k)
                        .with_context(|| trf("unknown log kind '{kind}'", &[("kind", &k)]))
                })
                .transpose()?;
            let logs = Logs::new(&app.paths);
            if list {
                let files = logs.list(&e.id, kind)?;
                out.emit(&files, || {
                    for f in &files {
                        outln!(
                            "{}  {:<8}  {:>9}  {}",
                            format_ts(f.modified),
                            f.kind.prefix(),
                            human_size(f.size),
                            tildify(&f.path)
                        );
                    }
                });
            } else if let Some(f) = file {
                // Only files of this app's own log list.
                let known = logs
                    .list(&e.id, None)?
                    .into_iter()
                    .find(|l| l.path == f)
                    .context(tr("not a log file of this app"))?;
                let text = sam_runner::launch::tail(&known.path, tail);
                out.emit(
                    &json!({"file": known.path, "kind": known.kind, "text": text}),
                    || {
                        outln!("==> {} <==", tildify(&known.path));
                        outln!("{text}");
                    },
                );
            } else {
                let latest = logs
                    .latest(&e.id, kind)?
                    .context(tr("no logs yet for this app"))?;
                let text = sam_runner::launch::tail(&latest.path, tail);
                out.emit(
                    &json!({"file": latest.path, "kind": latest.kind, "text": text}),
                    || {
                        outln!("==> {} <==", tildify(&latest.path));
                        outln!("{text}");
                    },
                );
            }
        }
        Cmd::Preset { cmd } => preset_cmd(&app, &out, cmd)?,
        Cmd::Group { cmd } => group_cmd(&app, &out, cmd)?,
        Cmd::Set {
            app: q,
            key,
            value,
            yes,
        } => {
            let cur = app.resolve(&q)?.profile.permissions;
            let mut new = cur.clone();
            new.set_key(&key, &value)?;
            confirm_risks(&sam_core::risk::new_risks(&cur, &new), yes)?;
            let e = app.set_permission(&q, &key, &value)?;
            let v = e.profile.permissions.get_key(&key)?;
            let eval = app.evaluate(&e.profile.permissions, Some(&e), &app.host());
            out.emit(
                &json!({"key": key, "value": v, "risk": eval.risk, "warnings": eval.warnings}),
                || {
                    outln!("{key} = {v}   (risk now {})", risk_line(&eval.risk));
                    print_warnings(
                        &eval
                            .warnings
                            .iter()
                            .filter(|w| w.key.as_deref() == Some(&key))
                            .cloned()
                            .collect::<Vec<_>>(),
                    );
                },
            );
        }
        Cmd::Get { app: q, key } => {
            let e = app.resolve(&q)?;
            let v = match &key {
                Some(k) => e.profile.permissions.get_key(k)?,
                None => serde_json::to_value(&e.profile.permissions)?,
            };
            out.emit(&v, || match &key {
                Some(_) => outln!("{v}"),
                None => out!(
                    "{}",
                    toml::to_string_pretty(&e.profile.permissions).unwrap_or_default()
                ),
            });
        }
        Cmd::Profile { cmd } => match cmd {
            ProfileCmd::Get { app: q } => {
                let e = app.resolve(&q)?;
                out.emit(&e.profile, || {
                    outln!(
                        "{}",
                        serde_json::to_string_pretty(&e.profile).unwrap_or_default()
                    )
                });
            }
            ProfileCmd::Set { app: q, yes } => {
                let perms: PermissionSet = serde_json::from_str(&read_stdin()?)
                    .context(tr("expected a PermissionSet as JSON on stdin"))?;
                let cur = app.resolve(&q)?.profile.permissions;
                confirm_risks(&sam_core::risk::new_risks(&cur, &perms), yes)?;
                let e = app.set_permissions(&q, perms)?;
                out.emit(&AppSummary::from_entry(&e), || {
                    outln!(
                        "{}",
                        trf(
                            "Updated permissions for {app}.",
                            &[("app", &e.display_name())]
                        )
                    )
                });
            }
            ProfileCmd::Change { app: q, yes } => {
                let change: sam_runner::ops::PermissionChange =
                    serde_json::from_str(&read_stdin()?).context(tr(
                        "expected {\"from\": …, \"to\": …} with two PermissionSets as JSON on stdin",
                    ))?;
                let (cur, merged) = app.plan_change(&q, &change)?;
                confirm_risks(
                    &sam_core::risk::new_risks(&cur.profile.permissions, &merged),
                    yes,
                )?;
                let e = app.change_permissions(&cur.id, merged)?;
                out.emit(&AppSummary::from_entry(&e), || {
                    outln!(
                        "{}",
                        trf(
                            "Updated permissions for {app}.",
                            &[("app", &e.display_name())]
                        )
                    )
                });
            }
            ProfileCmd::Reset { app: q } => {
                let e = app.reset_profile(&q)?;
                out.emit(&AppSummary::from_entry(&e), || {
                    outln!(
                        "{}",
                        trf(
                            "{app} is back to the recommended settings.",
                            &[("app", &e.display_name())]
                        )
                    )
                });
            }
        },
        Cmd::Evaluate { app: q } => {
            let perms: PermissionSet = serde_json::from_str(&read_stdin()?)
                .context(tr("expected a PermissionSet as JSON on stdin"))?;
            let e = q.map(|q| app.resolve(&q)).transpose()?;
            let host = app.host();
            let ev = app.evaluate(&perms, e.as_ref(), &host);
            out.emit(&ev, || {
                outln!("risk: {}", risk_line(&ev.risk));
                print_warnings(&ev.warnings);
            });
        }
        Cmd::Compat { app: q, state, yes } => {
            let on = on_off(&state)?;
            // The full session bus in it is a way out (audit D-H5): turning
            // it on is said and confirmed, as in the window.
            compat_allowed(on, yes)?;
            let e = app.set_compat(&q, on)?;
            out.emit(&AppSummary::from_entry(&e), || {
                if on {
                    outln!(
                        "{}",
                        sam_core::i18n::trf(
                            "Compatibility mode turned on for {name}",
                            &[("name", &e.display_name())]
                        )
                    );
                } else {
                    outln!(
                        "{}",
                        sam_core::i18n::trf(
                            "Compatibility mode turned off for {name}",
                            &[("name", &e.display_name())]
                        )
                    );
                };
                if on {
                    outln!("{}", paint(&tr(sam_profile::COMPAT_WARNING), "33"));
                }
            });
        }
        Cmd::Verify {
            app: q,
            permissions_stdin,
        } => {
            let perms: Option<PermissionSet> = if permissions_stdin {
                Some(
                    serde_json::from_str(&read_stdin()?)
                        .context(tr("expected a PermissionSet as JSON on stdin"))?,
                )
            } else {
                None
            };
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
            if !out_v.record.failed.is_empty() {
                exit_with(EXIT_NOT_PASSED);
            }
            out.emit(&json!({"report": r, "record": out_v.record}), || {
                let mut group = String::new();
                for res in &r.results {
                    if res.group != group {
                        group = res.group.clone();
                        outln!("\n{group}");
                    }
                    let mark = match res.ok {
                        Some(true) => paint("✓", "32"),
                        Some(false) => paint("✗", "31"),
                        None => paint("–", "90"),
                    };
                    outln!("  {mark} {:<46} {}", res.title, res.observed);
                }
                outln!(
                    "\n{} passed, {} failed, {} not applicable",
                    out_v.record.passed,
                    out_v.record.failed.len(),
                    out_v.record.skipped
                );
            });
        }
        Cmd::Args { app: q, stdin } => {
            let e = if stdin {
                let list: Vec<String> = serde_json::from_str(&read_stdin()?)
                    .context(tr("expected a JSON list of strings on stdin"))?;
                app.set_args(&q, list)?
            } else {
                app.resolve(&q)?
            };
            out.emit(&e.profile.args, || {
                if e.profile.args.is_empty() {
                    outln!(
                        "{}",
                        trf(
                            "No extra arguments for {app}.",
                            &[("app", &e.display_name())]
                        )
                    );
                } else {
                    outln!("{}", e.profile.args.join(" "));
                }
            });
        }
        Cmd::Review { app: q, seen } => {
            let e = app.mark_reviewed_as_shown(&q, seen.as_deref())?;
            out.emit(&AppSummary::from_entry(&e), || {
                outln!(
                    "{}",
                    trf(
                        "{app} marked as reviewed [{state}]",
                        &[("app", &e.display_name()), ("state", &badge_str(e.badge()))]
                    )
                )
            });
        }
        Cmd::Reextract {
            app: q,
            allow_fallback,
        } => {
            let e = app.reextract(&q, allow_fallback)?;
            out.emit(&json!({"app": AppSummary::from_entry(&e), "pending_changes": e.pending_changes}), || {
                outln!("Re-extracted {} [{}]", e.display_name(), badge_str(e.badge()));
                if !e.pending_changes.is_empty() {
                    outln!(
                        "{}",
                        paint(&format!("  The update likely needs new permissions: {}. Your customized profile was kept.", e.pending_changes.join(", ")), "33")
                    );
                }
            });
        }
        Cmd::Redetect { app: q } => {
            let e = app.redetect(&q)?;
            out.emit(
                &json!({"app": AppSummary::from_entry(&e), "detection": e.detection}),
                || {
                    outln!(
                        "{}",
                        trf(
                            "Dependency detection finished for {app}.",
                            &[("app", &e.display_name())]
                        )
                    );
                    if let Some(d) = &e.detection {
                        print_detection(d);
                    }
                },
            );
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
                    outln!("{:<32} {st} {}", i.name, i.reasons.join("; "));
                }
            });
        }
        Cmd::Relocate { app: q, path } => {
            let e = app.relocate(&q, &path)?;
            out.emit(&AppSummary::from_entry(&e), || {
                outln!(
                    "{}",
                    trf(
                        "{app} now points to {file} [{state}]",
                        &[
                            ("app", &e.display_name()),
                            ("file", &tildify(&e.source_path)),
                            ("state", &badge_str(e.badge()))
                        ]
                    )
                )
            });
        }
        Cmd::Desktop { app: q, action } if q == "all" && action == "refresh" => {
            let n = sam_intake::desktop::refresh_launchers(&app.paths, &app.registry().list()?);
            out.emit(&json!({"refreshed": n}), || {
                outln!("{n} launcher(s) updated")
            });
        }
        Cmd::Desktop { app: q, action } => {
            let mut e = app.resolve(&q)?;
            match action.as_str() {
                "install" => {
                    e.desktop_entry = Some(sam_intake::desktop::install_launcher(&app.paths, &e)?)
                }
                "remove" | "uninstall" => {
                    sam_intake::desktop::remove_launcher(&app.paths, &e.id)?;
                    e.desktop_entry = None;
                }
                other => bail!("unknown action '{other}' (install, remove)"),
            }
            app.registry().save(&mut e)?;
            out.emit(&json!({"desktop_entry": e.desktop_entry}), || {
                match &e.desktop_entry {
                    Some(p) => outln!(
                        "{}",
                        sam_core::i18n::trf("Launcher installed: {path}", &[("path", &tildify(p))])
                    ),
                    None => outln!("{}", sam_core::i18n::tr("Launcher removed")),
                }
            });
        }
        Cmd::Diagnose {
            app: q,
            timeout,
            apply,
        } => {
            let mut e = app.resolve(&q)?;
            if !out.json {
                errln!(
                    "{}",
                    trf(
                        "Starting {app} in diagnostic mode for up to {seconds} s. Use the app normally, then close it.",
                        &[("app", &e.display_name()), ("seconds", &timeout)]
                    )
                );
            }
            let r = sam_runner::diagnose::diagnose(&app, &mut e, timeout, apply)?;
            out.emit(&r, || {
                outln!(
                    "{}",
                    sam_core::i18n::trf(
                        "Diagnostic run: {summary}",
                        &[("summary", &r.launch_summary)]
                    )
                );
                if r.findings.is_empty() {
                    outln!("{}", tr("No missing resources were detected."));
                }
                for f in &r.findings {
                    let fix = f
                        .fix
                        .as_ref()
                        .map(|(k, v)| format!("  fix: sam-jail set {} {k} {v}", e.id))
                        .unwrap_or_default();
                    let fix = if f.already_granted {
                        String::new()
                    } else {
                        fix
                    };
                    outln!(
                        "  [{}] {} ({}){}{}",
                        risk_str(f.risk),
                        f.suggestion,
                        f.error,
                        if f.applied {
                            paint("  applied", "32")
                        } else {
                            String::new()
                        },
                        if f.applied { String::new() } else { fix }
                    );
                    if f.already_granted {
                        outln!("      {}", f.trace_line);
                    }
                }
                if let Some(t) = &r.trace_file {
                    outln!(
                        "{}",
                        trf("The full trace is in {file}.", &[("file", &tildify(t))])
                    );
                }
                if r.applied > 0 {
                    outln!("{} low-risk fix(es) applied automatically.", r.applied);
                }
            });
        }
        Cmd::Report { app: q } => {
            let host = HostInfo::probe_full();
            let e = q.map(|q| app.resolve(&q)).transpose()?;
            let text = sam_runner::doctor::bug_report(&app, e.as_ref(), &host);
            out.emit(&json!({"report": text}), || outln!("{text}"));
        }
        Cmd::Config { cmd } => config_cmd(&app, &out, cmd)?,
        Cmd::Permissions => {
            let cat = permission_catalog();
            out.emit(&cat, || {
                let mut last = "";
                for p in &cat {
                    if p.category != last {
                        outln!("\n{}", paint(p.category, "1"));
                        last = p.category;
                    }
                    outln!("  {:<30} {:<10} {}", p.key, risk_str(p.risk), p.title);
                    outln!("  {:<30} {:<10} {}", "", "", p.description);
                }
            });
        }
        Cmd::Cleanup { data, list } => {
            if data {
                let items = if list {
                    app.leftover_data()?
                } else {
                    app.remove_leftover_data()?
                };
                let total: u64 = items.iter().map(|d| d.size).sum();
                out.emit(
                    &json!({"apps": items, "total": total, "removed": !list}),
                    || {
                        for d in &items {
                            outln!("{:<40} {:>10}", d.id, human_size(d.size));
                        }
                        outln!(
                            "{}",
                            if list {
                                trn(
                                    "Left behind by {n} app: {size}",
                                    "Left behind by {n} apps: {size}",
                                    items.len() as u64,
                                    &[("size", &human_size(total))],
                                )
                            } else {
                                trn(
                                    "Removed the data of {n} app: {size}",
                                    "Removed the data of {n} apps: {size}",
                                    items.len() as u64,
                                    &[("size", &human_size(total))],
                                )
                            }
                        );
                    },
                );
            } else {
                let removed = if list { vec![] } else { app.cleanup()? };
                out.emit(&removed, || {
                    outln!(
                        "{}",
                        sam_core::i18n::trn(
                            "Removed {n} unused unpacked copy",
                            "Removed {n} unused unpacked copies",
                            removed.len() as u64,
                            &[]
                        )
                    );
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
            out.emit(&json!({"done": done}), || {
                outln!("onboarding {}", if done { "completed" } else { "pending" })
            });
        }
        Cmd::Dev {
            cmd: DevCmd::Peek { file, out: dir },
        } => {
            // Runs inside the preview sandbox; the parent reads `dir`.
            if sam_intake::peek::peek_entry(&file, &dir).is_err() {
                std::process::exit(1);
            }
        }
        Cmd::Dev {
            cmd:
                DevCmd::ExtractSquashfs {
                    source,
                    offset,
                    dest,
                    max_files,
                    max_bytes,
                    max_seconds,
                },
        } => {
            // The memory limit was set by SAM before the sandbox started.
            let limits = sam_intake::normalize::Limits {
                max_files,
                max_bytes,
                max_seconds,
                max_memory: 0,
            };
            // Runs inside the unpack sandbox: an exceeded limit gets its own
            // exit code, so the parent stops instead of trying other ways.
            if let Err(e) =
                sam_intake::extract::builtin_squashfs_entry(&source, offset, &dest, &limits)
            {
                if sam_core::error::code_of(&e) == Some("extraction-limit") {
                    errln!("error: {}", sam_core::error::message_of(&e));
                    std::process::exit(sam_intake::extract::EXIT_LIMIT);
                }
                // A full disk too: the parent stops instead of filling it
                // again with the next tool (review F2).
                if sam_intake::extract::is_disk_full(&e) {
                    errln!("error: {e:#}");
                    std::process::exit(sam_intake::extract::EXIT_DISK_FULL);
                }
                return Err(e);
            }
        }
        Cmd::Dev {
            cmd: DevCmd::Bench { apps },
        } => {
            let r = bench::bench(apps)?;
            out.emit(&r, || {
                for m in &r {
                    let ms = serde_json::to_value(m)
                        .ok()
                        .and_then(|v| v["best_ms"].as_f64());
                    let v = serde_json::to_value(m).unwrap_or_default();
                    match ms {
                        Some(ms) => outln!(
                            "{:<16} {:>10.3} ms  {}",
                            v["key"].as_str().unwrap_or(""),
                            ms,
                            v["what"].as_str().unwrap_or("")
                        ),
                        None => outln!(
                            "{:<16} {:>13}  {}",
                            v["key"].as_str().unwrap_or(""),
                            "not here",
                            v["what"].as_str().unwrap_or("")
                        ),
                    }
                }
            });
        }
        Cmd::Dev {
            cmd: DevCmd::SetUpdateInfo { runtime, info },
        } => {
            sam_detect::update_info::write(&runtime, &info)?;
            out.emit(&json!({"runtime": runtime, "info": info}), || {
                outln!(
                    "{}",
                    trf(
                        "Update information written to {file}.",
                        &[("file", &runtime.display())]
                    )
                )
            });
        }
        Cmd::Dev {
            cmd:
                DevCmd::MakeZsync {
                    file,
                    url,
                    out: dest,
                },
        } => {
            let name = file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .context(sam_core::i18n::tr("no file name"))?;
            let modified = std::fs::metadata(&file)?
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let mtime = sam_core::util::format_utc_date(modified);
            let data =
                sam_runner::zsync::make(&file, &name, url.as_deref().unwrap_or(&name), &mtime)?;
            let dest = dest.unwrap_or_else(|| file.with_file_name(format!("{name}.zsync")));
            std::fs::write(&dest, data)?;
            out.emit(&json!({"zsync": dest}), || {
                outln!(
                    "{}",
                    sam_core::i18n::trf("Wrote {path}", &[("path", &dest.display())])
                )
            });
        }
        Cmd::Dev {
            cmd: DevCmd::SignAppimage { file, key },
        } => {
            sam_detect::signature::sign_embedded(&file, None, &key)?;
            // SAM's own file, just signed here: GnuPG reads only our key.
            let sig = sam_detect::signature::check(&file, &sam_detect::signature::GnuPg::Direct);
            let fp = sig.fingerprint.clone().unwrap_or_default();
            if sig.state != sam_core::model::SignatureState::Valid || !fp.eq_ignore_ascii_case(&key)
            {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "the signature in {file} does not check out: {detail}",
                        &[("file", &file.display()), ("detail", &sig.detail)]
                    )
                );
            }
            out.emit(&json!({"path": file, "fingerprint": fp}), || {
                outln!(
                    "{}",
                    sam_core::i18n::trf(
                        "Signed {path} with {key}",
                        &[("path", &file.display()), ("key", &fp)]
                    )
                )
            });
        }
        Cmd::Dev {
            cmd:
                DevCmd::MakeFixture {
                    path,
                    name,
                    categories,
                    apprun,
                    terminal,
                },
        } => {
            let mut spec = sam_intake::testkit::FixtureSpec::hello(&name);
            spec.categories = categories;
            spec.terminal = terminal;
            if let Some(a) = apprun {
                spec.apprun = std::fs::read_to_string(a)?;
            }
            sam_intake::testkit::build(&path, &spec)?;
            out.emit(&json!({"path": path}), || {
                outln!(
                    "{}",
                    sam_core::i18n::trf("Wrote {path}", &[("path", &path.display())])
                )
            });
        }
    }
    Ok(())
}

/// A change that adds something rated Think twice or Dangerous is made
/// only with `--yes`, as the window asks before it (audit D-M9, G-F2,
/// G-F11: `set` applied raw Bubblewrap arguments silently).
pub(crate) fn confirm_risks(added: &[sam_core::risk::RiskItem], yes: bool) -> anyhow::Result<()> {
    if added.is_empty() || yes {
        return Ok(());
    }
    let list: Vec<String> = added
        .iter()
        .map(|i| format!("{} ({})", i.title, i.level.words()))
        .collect();
    Err(sam_core::error::CodedError::new(
        "change-needs-yes",
        sam_core::i18n::trf(
            "This change adds {items}. Look at it, then repeat it with --yes, or make it in SAM's window, which asks.",
            &[("items", &list.join(", "))],
        ),
    )
    .into())
}

/// Compatibility mode is turned on only with `--yes`: the whole session bus
/// in it is a way out (audit D-H5), as the window says before it asks.
fn compat_allowed(on: bool, yes: bool) -> anyhow::Result<()> {
    if on && !yes {
        return Err(sam_core::error::CodedError::new(
            "compat-needs-yes",
            sam_core::i18n::tr("Compatibility mode gives the app the network, all of /usr, X11, the GPU, sound and the whole session bus. Through the whole session bus it can ask desktop services to run programs outside its sandbox, so this is a way out. Turn it on only for apps you trust: add --yes."),
        )
        .into());
    }
    Ok(())
}

/// A repair step suggested by what the app printed is applied only with
/// `--yes`: the app controls that text, and could ask for the keyring or a
/// service this way (audit U-M2; the window asks, and so must this).
fn may_apply(sug: &sam_core::model::Suggestion, yes: bool) -> anyhow::Result<()> {
    if sug.from_app_output && !yes {
        return Err(sam_core::error::CodedError::new(
            "repair-needs-yes",
            sam_core::i18n::trf(
                "\"{title}\" comes from what the app printed, which the app controls: {explanation} Look at it, then apply it with --yes, or in SAM's window.",
                &[("title", &sug.title), ("explanation", &sug.explanation)],
            ),
        )
        .into());
    }
    Ok(())
}

/// What `selftest` says about one start that `seconds` long: status, the
/// detail shown and, for a failure, what the app's output suggests. "ok"
/// when the app started in its sandbox and ended well or kept running
/// until SAM ended it; a kill from outside counts as kept running when it
/// came at most a second before the time was up.
fn selftest_verdict(
    rec: &LaunchRecord,
    seconds: u64,
    terminal: bool,
) -> (&'static str, String, Vec<Suggestion>) {
    let ran = rec.finished_at - rec.started_at;
    if rec.sandbox_failure {
        ("fail", rec.summary.clone(), rec.findings.clone())
    } else if rec.success || (rec.signal == Some(9) && ran + 1 >= seconds as i64) {
        let detail = match (rec.signal, terminal) {
            (Some(_), _) => {
                sam_core::i18n::trf("kept running for {seconds}s", &[("seconds", &seconds)])
            }
            (None, true) => trf(
                "ran in its sandbox and ended by itself ({summary})",
                &[("summary", &rec.summary)],
            ),
            (None, false) => rec.summary.clone(),
        };
        ("ok", detail, vec![])
    } else {
        ("fail", rec.summary.clone(), rec.findings.clone())
    }
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Each command's errors name the SAM function it carries out
    /// (docs/functions.md), and the commands outside SAM's functions name
    /// none (mutation run: every answer could be dropped or be any number).
    #[test]
    fn each_command_names_its_sam_function() {
        for (args, want) in [
            (&["info", "x"][..], Some(7)),
            (&["run", "x"][..], Some(19)),
            (&["verify", "x"][..], Some(20)),
            (&["scan"][..], Some(1)),
            (&["list"][..], Some(35)),
            (&["uninstall"][..], Some(32)),
            (&["version"][..], None),
            (&["dev", "make-fixture", "f.AppImage"][..], None),
        ] {
            let cli = Cli::try_parse_from(std::iter::once("sam-jail").chain(args.iter().copied()))
                .unwrap_or_else(|e| panic!("{args:?}: {e}"));
            assert_eq!(function_for(&cli.cmd), want, "{args:?}");
        }
    }

    fn report(step: usize, fraction: f64) -> sam_runner::progress::Progress {
        sam_runner::progress::Progress {
            step,
            steps: 5,
            title: "Unpacking".into(),
            detail: String::new(),
            fraction,
        }
    }

    /// The progress lines: the first report of each step and the last one
    /// always pass, more reports of the same step only every 100 ms (the
    /// window's bar moves, and the per-file reports do not flood it).
    #[test]
    fn progress_lines_pass_new_steps_and_the_end_and_thin_out_the_rest() {
        let t = Instant::now();
        let ms = |n| t + Duration::from_millis(n);
        assert!(
            progress_passes((0, t), &report(1, 0.0), t),
            "the very first report"
        );
        assert!(
            progress_passes((1, t), &report(2, 0.3), ms(10)),
            "the first report of a new step, however soon"
        );
        assert!(
            !progress_passes((1, t), &report(1, 0.5), ms(10)),
            "the same step again within 100 ms"
        );
        assert!(
            progress_passes((1, t), &report(1, 0.5), ms(150)),
            "the same step after 100 ms"
        );
        assert!(
            progress_passes((5, t), &report(5, 1.0), ms(10)),
            "the last report, however soon"
        );
    }

    fn start(success: bool, signal: Option<i32>, ran: i64) -> LaunchRecord {
        LaunchRecord {
            started_at: 1000,
            finished_at: 1000 + ran,
            success,
            signal,
            exit_code: if success || signal.is_some() {
                None
            } else {
                Some(7)
            },
            summary: "the summary".into(),
            ..Default::default()
        }
    }

    /// `selftest` passes a start that ended well or kept running until the
    /// time was up, and fails one that ended badly or was killed early,
    /// with a second's grace for a kill from outside SAM (mutation run:
    /// every comparison here could be turned around unnoticed).
    #[test]
    fn selftest_passes_starts_that_ended_well_or_kept_running() {
        for (rec, seconds, terminal, want, detail) in [
            (start(true, None, 0), 5, false, "ok", "the summary"),
            (start(true, None, 0), 5, true, "ok", "ended by itself"),
            (
                start(true, Some(9), 5),
                5,
                false,
                "ok",
                "kept running for 5s",
            ),
            // An error code after a while is still an error.
            (start(false, None, 5), 1, false, "fail", "the summary"),
            (start(false, None, 0), 5, false, "fail", "the summary"),
            // Killed from outside (the out-of-memory killer): early is a
            // failure, at the end (with a second's grace) it kept running.
            (start(false, Some(9), 1), 10, false, "fail", "the summary"),
            (
                start(false, Some(9), 9),
                10,
                false,
                "ok",
                "kept running for 10s",
            ),
            (start(false, Some(9), 30), 30, false, "ok", "kept running"),
        ] {
            let (status, text, _) = selftest_verdict(&rec, seconds, terminal);
            assert_eq!(status, want, "{rec:?} for {seconds} s");
            assert!(text.contains(detail), "{text:?} for {rec:?}");
        }
        let mut broken = start(true, None, 5);
        broken.sandbox_failure = true;
        assert_eq!(selftest_verdict(&broken, 5, false).0, "fail");
    }
}

#[cfg(test)]
mod repair_tests {
    use super::{compat_allowed, may_apply};

    /// Compatibility mode goes on only with --yes, and the refusal says why
    /// (audit D-H5); turning it off needs nothing.
    #[test]
    fn compatibility_mode_needs_yes_and_says_why() {
        let err = compat_allowed(true, false).unwrap_err();
        assert_eq!(sam_core::error::code_of(&err), Some("compat-needs-yes"));
        assert!(format!("{err:#}").contains("way out"));
        assert!(compat_allowed(true, true).is_ok());
        assert!(compat_allowed(false, false).is_ok());
    }
    use sam_core::model::{FixAction, Suggestion};

    /// A step from the app's own output needs --yes; SAM's own steps do
    /// not (audit U-M2).
    #[test]
    fn a_step_from_the_apps_output_needs_yes() {
        let mut sug = Suggestion {
            id: "keyring".into(),
            title: "The app wants the keyring".into(),
            explanation: "It printed that the keyring is missing.".into(),
            action: FixAction::Add {
                key: "integrations.keyring".into(),
                value: "true".into(),
            },
            risk: sam_core::risk::RiskLevel::High,
            from_app_output: true,
        };
        let err = may_apply(&sug, false).unwrap_err();
        assert_eq!(sam_core::error::code_of(&err), Some("repair-needs-yes"));
        assert!(format!("{err:#}").contains("--yes"));
        assert!(may_apply(&sug, true).is_ok());
        sug.from_app_output = false;
        assert!(may_apply(&sug, false).is_ok());
    }
}
