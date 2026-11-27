//! SAM's one gate for changes that wait for a yes. A change rated Think
//! twice or Dangerous, one that turns on compatibility mode, one suggested
//! by what the app printed, and one that turns off a protection for every
//! app is made only after the person said yes; every front end hands its
//! change in here, and the window confirms for the command line exactly
//! when it asked (by the same rule, [`sam_core::risk::waits_for_yes`]).
//!
//! The refusals keep their own codes, part of the JSON interface:
//! `change-needs-yes`, `compat-needs-yes`, `config-needs-yes`,
//! `repair-needs-yes`, `hint-needs-yes` and `step-needs-yes`.

use anyhow::Result;
use sam_core::error::CodedError;
use sam_core::i18n::{tr, trf};
use sam_core::permissions::PermissionSet;
use sam_core::risk::{new_risks, waits_for_yes, RiskItem, RiskLevel};
use sam_core::{AppEntry, Config, FixAction, Paths, Suggestion};

use crate::repair::{apply_step, effect, first_run_hints, ladder, level_added};

/// A change, as a front end hands it to [`confirm`].
pub enum Change<'a> {
    /// One app's settings, before and after (`set`, `profile set`,
    /// `profile change`).
    Settings {
        before: &'a PermissionSet,
        after: &'a PermissionSet,
    },
    /// Several apps' settings at once, each before and after (`group set`,
    /// `group restore`): one question, each item named once.
    Group(&'a [(PermissionSet, PermissionSet)]),
    /// Compatibility mode of an app turned on (`true`) or off.
    Compat { on: bool },
    /// SAM's configuration for every app, before and after.
    Config { old: &'a Config, new: &'a Config },
    /// A hint, finding or repair step as it was found, before the app's
    /// record is looked at: whether it comes from what the app printed.
    Found(&'a Suggestion),
    /// A hint, finding or repair step applied to the app's record `e`:
    /// judged on that record, so a page drawn before a change cannot apply
    /// it with an older, lower label.
    Apply {
        e: &'a AppEntry,
        cfg: &'a Config,
        paths: &'a Paths,
        sug: &'a Suggestion,
    },
}

/// Lets `change` through when the person confirmed it (`confirmed`) or it
/// does not wait for a yes; refuses it otherwise with its coded refusal,
/// which names what it adds or turns off and the two ways to say yes.
pub fn confirm(change: &Change<'_>, confirmed: bool) -> Result<()> {
    if confirmed {
        return Ok(());
    }
    match *change {
        Change::Settings { before, after } => settings(&new_risks(before, after)),
        Change::Group(pairs) => {
            let mut added: Vec<RiskItem> = Vec::new();
            for (before, after) in pairs {
                for i in new_risks(before, after) {
                    if !added.iter().any(|x| x.title == i.title) {
                        added.push(i);
                    }
                }
            }
            settings(&added)
        }
        Change::Compat { on } => compat(on),
        Change::Config { old, new } => config(&old.protections_turned_off(new)),
        Change::Found(sug) => app_output(sug),
        Change::Apply { e, cfg, paths, sug } => {
            app_output(sug)?;
            confirm_hint(e, sug, false)?;
            confirm_step(e, cfg, paths, sug, false)
        }
    }
}

/// A change that adds something rated Think twice or Dangerous (`added`,
/// from [`new_risks`]) is made only with `--yes`, as the window asks
/// before it (audit D-M9, G-F2, G-F11: `set` applied raw Bubblewrap
/// arguments silently).
fn settings(added: &[RiskItem]) -> Result<()> {
    if added.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = added
        .iter()
        .map(|i| format!("{} ({})", i.title, i.level.words()))
        .collect();
    Err(CodedError::new(
        "change-needs-yes",
        trf(
            "This change adds {items}. Look at it, then repeat it with --yes, or make it in SAM's window, which asks.",
            &[("items", &list.join(", "))],
        ),
    )
    .into())
}

/// Compatibility mode is turned on only with `--yes`: the whole session bus
/// in it is a way out (audit D-H5), as the window says before it asks.
fn compat(on: bool) -> Result<()> {
    if !waits_for_yes(RiskLevel::Low, on, false) {
        return Ok(());
    }
    Err(CodedError::new(
        "compat-needs-yes",
        tr("Compatibility mode gives the app the network, all of /usr, X11, the GPU, sound and the whole session bus. Through the whole session bus it can ask desktop services to run programs outside its sandbox, so this is a way out. Turn it on only for apps you trust: add --yes."),
    )
    .into())
}

/// A change that turns off a protection for every app (`off`: Landlock,
/// the syscall filter) is saved only with `--yes`, as the window asks
/// before it (audit G-F11): one pasted line or a script turned it off
/// unasked.
fn config(off: &[&str]) -> Result<()> {
    if off.is_empty() {
        return Ok(());
    }
    let exposed: Vec<String> = off
        .iter()
        .map(|key| match *key {
            "security.experimental_landlock" => tr("Landlock: apps lose its write protection and the block on abstract sockets outside the sandbox (such as XWayland's), so they can reach more of this computer than their settings say."),
            "security.baseline_seccomp" => tr("The syscall filter: apps can use kernel interfaces no desktop app needs (modules, BPF, perf, keyrings, io_uring, terminal injection), which attacks on the kernel use."),
            other => other.to_string(),
        })
        .collect();
    Err(CodedError::new(
        "config-needs-yes",
        trf(
            "This change turns off a protection for every sandboxed app. {protections} Nothing was saved. Look at it, then repeat it with --yes, or make it in SAM's window, which asks.",
            &[("protections", &exposed.join(" "))],
        ),
    )
    .into())
}

/// A hint or repair step suggested by what the app printed is applied
/// only with `--yes`: the app controls that text, and could ask for the
/// keyring or a service this way (audit U-M2; the window asks, and so must
/// the command line).
fn app_output(sug: &Suggestion) -> Result<()> {
    if !waits_for_yes(RiskLevel::Low, false, sug.from_app_output) {
        return Ok(());
    }
    Err(CodedError::new(
        "repair-needs-yes",
        trf(
            "\"{title}\" comes from what the app printed, which the app controls: {explanation} Look at it, then apply it with --yes, or in SAM's window.",
            &[("title", &sug.title), ("explanation", &sug.explanation)],
        ),
    )
    .into())
}

/// Applying a first-run hint rated Think twice or Dangerous, or one that
/// turns on compatibility mode, waits for a yes (`confirmed`): `hints
/// --apply` and `repair --apply` alike, however the hint was found, and
/// judged on the settings `e` it is applied to. Refused with
/// `hint-needs-yes`, naming the hint, what it turns on and what it adds
/// (owner decision 13 of 2026-11-23). Other repair steps are judged by
/// [`confirm_step`].
pub(crate) fn confirm_hint(e: &AppEntry, sug: &Suggestion, confirmed: bool) -> Result<()> {
    if confirmed {
        return Ok(());
    }
    let Some(hint) = first_run_hints(e).into_iter().find(|h| h.id == sug.id) else {
        return Ok(());
    };
    let compat = matches!(hint.action, FixAction::Compat);
    judge(e, sug, hint.risk, compat, "hint-needs-yes")
}

/// Applying any other repair step rated Think twice or Dangerous, or one
/// that turns on compatibility mode, waits for a yes (`confirmed`) as
/// well: a step of the ladder, also one reached with `repair --next`, and
/// a finding of the last start (owner decision A of 2026-11-25: `repair
/// --apply seccomp-baseline` turned off the syscall filter unasked).
/// Judged like a hint, by its label in the ladder SAM offers now, so a
/// lower label handed in for a step SAM lists cannot skip the yes (the
/// command line and the window hand in SAM's own copy, found by id).
/// Refused with `step-needs-yes`. First-run hints are left to
/// [`confirm_hint`].
pub(crate) fn confirm_step(
    e: &AppEntry,
    cfg: &Config,
    paths: &Paths,
    sug: &Suggestion,
    confirmed: bool,
) -> Result<()> {
    if confirmed || first_run_hints(e).iter().any(|h| h.id == sug.id) {
        return Ok(());
    }
    let listed = ladder(e, cfg, paths)
        .into_iter()
        .find(|s| s.id == sug.id)
        .map_or(RiskLevel::Low, |s| s.risk);
    judge(e, sug, listed, false, "step-needs-yes")
}

/// The one judgement of a hint or repair step: the highest of the label
/// SAM gives it now (`listed`), the label handed in and what applying it
/// to `e` adds; compatibility mode asks whatever that level, also where it
/// adds nothing rated Think twice to settings that are wide already.
fn judge(
    e: &AppEntry,
    sug: &Suggestion,
    listed: RiskLevel,
    listed_compat: bool,
    code: &'static str,
) -> Result<()> {
    let level = listed.max(sug.risk).max(level_added(e, sug));
    let compat = listed_compat || matches!(sug.action, FixAction::Compat);
    if !waits_for_yes(level, compat, false) {
        return Ok(());
    }
    Err(needs_yes(e, sug, level, code))
}

/// The refusal for a hint or repair step that waits for a yes: names it,
/// its level, what it turns on or off and what it adds, and the two ways
/// to say yes.
fn needs_yes(
    e: &AppEntry,
    sug: &Suggestion,
    level: RiskLevel,
    code: &'static str,
) -> anyhow::Error {
    let mut after = e.clone();
    let added = match apply_step(&mut after, sug, &mut Default::default()) {
        Ok(()) => new_risks(&e.profile.permissions, &after.profile.permissions),
        Err(_) => Vec::new(),
    };
    let level_words = level.words();
    let effect = effect(sug, &e.profile.permissions);
    let text = if added.is_empty() {
        trf(
            "SAM applies \"{title}\" ({level}) only after a yes. {effect} Look at it, then apply it with --yes, or in SAM's window, which asks.",
            &[("title", &sug.title), ("level", &level_words), ("effect", &effect)],
        )
    } else {
        let items: Vec<String> = added
            .iter()
            .map(|i| format!("{} ({})", i.title, i.level.words()))
            .collect();
        trf(
            "SAM applies \"{title}\" ({level}) only after a yes. {effect} It adds {items}. Look at it, then apply it with --yes, or in SAM's window, which asks.",
            &[
                ("title", &sug.title),
                ("level", &level_words),
                ("effect", &effect),
                ("items", &items.join(", ")),
            ],
        )
    };
    CodedError::new(code, text).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::error::code_of;

    fn code(r: Result<()>) -> Option<&'static str> {
        r.err().and_then(|e| code_of(&e))
    }

    /// One gate for every change: a change of settings that adds Think
    /// twice or Dangerous, also for several apps at once (each item named
    /// once), compatibility mode turned on, a protection turned off for
    /// every app and a step from what the app printed are each refused
    /// with their own code until the person says yes; a Some access
    /// change, turning compatibility mode off and turning a protection on
    /// go through unasked.
    #[test]
    fn one_gate_refuses_each_change_that_waits_with_its_own_code() {
        let before = PermissionSet::strict_gui();
        let mut x11 = before.clone();
        x11.display.x11 = true;
        let mut gpu = before.clone();
        gpu.devices.gpu = true;
        let settings = Change::Settings {
            before: &before,
            after: &x11,
        };
        assert_eq!(code(confirm(&settings, false)), Some("change-needs-yes"));
        assert!(confirm(&settings, true).is_ok());
        let harmless = Change::Settings {
            before: &before,
            after: &gpu,
        };
        assert!(confirm(&harmless, false).is_ok(), "Some access");

        let pairs = [(before.clone(), x11.clone()), (before.clone(), x11.clone())];
        let err = confirm(&Change::Group(&pairs), false).unwrap_err();
        assert_eq!(code_of(&err), Some("change-needs-yes"));
        assert_eq!(format!("{err:#}").matches("X11").count(), 1, "{err:#}");
        assert!(confirm(&Change::Group(&[(before.clone(), gpu)]), false).is_ok());

        assert_eq!(
            code(confirm(&Change::Compat { on: true }, false)),
            Some("compat-needs-yes")
        );
        assert!(confirm(&Change::Compat { on: true }, true).is_ok());
        assert!(confirm(&Change::Compat { on: false }, false).is_ok());

        let old = Config::default();
        let mut off = old.clone();
        off.set_key("security.baseline_seccomp", "false").unwrap();
        let err = confirm(
            &Change::Config {
                old: &old,
                new: &off,
            },
            false,
        )
        .unwrap_err();
        assert_eq!(code_of(&err), Some("config-needs-yes"));
        assert!(format!("{err:#}").contains("syscall filter"), "{err:#}");
        assert!(confirm(
            &Change::Config {
                old: &old,
                new: &off
            },
            true
        )
        .is_ok());
        assert!(confirm(
            &Change::Config {
                old: &off,
                new: &old
            },
            false
        )
        .is_ok());

        let mut found = crate::repair::compat_step();
        found.action = FixAction::Set {
            key: "devices.gpu".into(),
            value: "true".into(),
        };
        found.risk = RiskLevel::Low;
        assert!(confirm(&Change::Found(&found), false).is_ok(), "SAM's own");
        found.from_app_output = true;
        assert_eq!(
            code(confirm(&Change::Found(&found), false)),
            Some("repair-needs-yes")
        );
        assert!(confirm(&Change::Found(&found), true).is_ok());
    }

    /// A hint or repair step applied to an app's record goes through the
    /// same gate, in a fixed order: what the app printed first (also under
    /// the name of a risky hint of SAM's own), then a first-run hint by its
    /// rating, then any other step by its rating in the ladder; a lower
    /// label handed in skips nothing, and a Some access step applies.
    #[test]
    fn one_gate_judges_an_applied_step_in_one_order() {
        let mut game = AppEntry {
            category: "game".into(),
            ..Default::default()
        };
        game.profile.permissions = PermissionSet::strict_gui();
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, paths) = (Config::default(), Paths::rooted(tmp.path()));
        let apply = |sug: &Suggestion, yes: bool| {
            let change = Change::Apply {
                e: &game,
                cfg: &cfg,
                paths: &paths,
                sug,
            };
            confirm(&change, yes)
        };
        let mut network = first_run_hints(&game)
            .into_iter()
            .find(|h| h.id == "network")
            .expect("offered");
        network.risk = RiskLevel::Low;
        assert_eq!(code(apply(&network, false)), Some("hint-needs-yes"));
        network.from_app_output = true;
        assert_eq!(code(apply(&network, false)), Some("repair-needs-yes"));
        assert!(apply(&network, true).is_ok());

        let step = |id: &str| {
            ladder(&game, &cfg, &paths)
                .into_iter()
                .find(|s| s.id == id)
                .unwrap_or_else(|| panic!("{id} offered"))
        };
        let mut seccomp = step("seccomp-baseline");
        seccomp.risk = RiskLevel::Low;
        assert_eq!(code(apply(&seccomp, false)), Some("step-needs-yes"));
        assert!(apply(&seccomp, true).is_ok());
        assert!(apply(&step("full-usr"), false).is_ok(), "Some access");
        assert_eq!(code(apply(&step("compat"), false)), Some("step-needs-yes"));
    }
}
