//! What the commands of the real `sam-jail` binary answer, on the terminal
//! and in JSON, about the apps they work on: whether an AppImage has a
//! sandbox, which menu entries start it outside it, which apps a filter
//! finds, what a change or a hint turns on. Each test here was missing
//! (mutation run 2026-11-23: these answers could be turned around without
//! any test noticing). Nothing here starts an app; adding one unpacks it
//! in a sandbox, as in the other command-line tests.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// SAM's folders, the home and the menu folders of one test, all in a
/// temporary folder: nothing of the computer's own (the menu entries in
/// /usr/share, the person's desktop session) gets in.
struct Env {
    tmp: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let e = Env {
            tmp: tempfile::tempdir().unwrap(),
        };
        for d in ["config", "home", "apps"] {
            fs::create_dir_all(e.root().join(d)).unwrap();
        }
        e
    }

    fn root(&self) -> &Path {
        self.tmp.path()
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let r = self.root();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
        cmd.args(args)
            .env("SAM_CONFIG_DIR", r.join("config"))
            .env("SAM_DATA_DIR", r.join("data"))
            .env("SAM_APPLICATIONS_DIR", r.join("applications"))
            .env("HOME", r.join("home"))
            .env("XDG_CONFIG_HOME", r.join("home/.config"))
            .env("XDG_DATA_HOME", r.join("home/.local/share"))
            .env("XDG_DATA_DIRS", r.join("system"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // No desktop session of the person, English messages.
        sam_runner::testenv::isolate_command(&mut cmd, &r.join("sam"));
        let mut c = cmd.spawn().unwrap();
        {
            use std::io::Write;
            let mut input = c.stdin.take().unwrap();
            if let Some(s) = stdin {
                input.write_all(s.as_bytes()).unwrap();
            }
        }
        c.wait_with_output().unwrap()
    }

    /// The `data` of a `--json` answer that must succeed.
    fn json(&self, args: &[&str], stdin: Option<&str>) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        let o = self.run(&a, stdin);
        assert!(
            o.status.success(),
            "{args:?}: {}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["ok"], true, "{v}");
        v["data"].clone()
    }

    /// What a command that must succeed prints on the terminal.
    fn text(&self, args: &[&str]) -> String {
        let o = self.run(args, None);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap()
    }

    /// The error of a `--json` command that must fail.
    fn refused(&self, args: &[&str], stdin: Option<&str>) -> String {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        let o = self.run(&a, stdin);
        assert!(!o.status.success(), "{args:?} must fail");
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["ok"], false, "{v}");
        v["error"].as_str().unwrap().to_string()
    }

    /// A test AppImage named `name` in `dir`, with these menu categories.
    fn fixture(&self, dir: &str, name: &str, categories: &str) -> PathBuf {
        let d = self.root().join(dir);
        fs::create_dir_all(&d).unwrap();
        let img = d.join(format!("{name}.AppImage"));
        self.json(
            &[
                "dev",
                "make-fixture",
                "--name",
                name,
                "--categories",
                categories,
                img.to_str().unwrap(),
            ],
            None,
        );
        img
    }

    /// Adds an AppImage (confirmed with `accept`); its id.
    fn add(&self, img: &Path, accept: bool) -> String {
        let mut args = vec!["add", img.to_str().unwrap(), "--no-launcher"];
        if accept {
            args.push("--accept");
        }
        self.json(&args, None)["entry"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Changes an app's record as SAM would save it (with its checksum),
    /// for what a test cannot otherwise arrange quickly: the time it was
    /// added or last started, its description.
    fn edit_record(&self, id: &str, change: impl FnOnce(&mut sam_core::AppEntry)) {
        let file = self.root().join(format!("data/apps/{id}.json"));
        let mut e: sam_core::AppEntry =
            serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        change(&mut e);
        e.integrity = Some(sam_storage::integrity_of(&e).unwrap());
        fs::write(&file, serde_json::to_string_pretty(&e).unwrap()).unwrap();
    }

    /// The ids of `list` with these filters, in order.
    fn list(&self, filters: &[&str]) -> Vec<String> {
        let mut args = vec!["list"];
        args.extend_from_slice(filters);
        self.json(&args, None)
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap().to_string())
            .collect()
    }
}

/// The line of `text` about the file `name`.
fn line_of<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find(|l| l.contains(name))
        .unwrap_or_else(|| panic!("no line about {name} in\n{text}"))
}

/// `scan` and `discover` on the terminal say of each AppImage whether it
/// has a sandbox (and which), is a moved copy of a sandboxed one, or has
/// none: a sandboxed app is never shown as new or unprotected, a new one
/// never as sandboxed.
#[test]
fn scan_and_discover_say_which_appimages_have_a_sandbox() {
    let e = Env::new();
    let kept = e.fixture("apps", "Kept", "Utility;");
    let kept_id = e.add(&kept, true);
    let moved = e.fixture("apps", "Moved", "Utility;");
    let moved_id = e.add(&moved, true);
    let fresh = e.fixture("apps", "Fresh", "Utility;");
    // The sandboxed file moves elsewhere: the same content in another place.
    fs::create_dir_all(e.root().join("elsewhere")).unwrap();
    fs::rename(&moved, e.root().join("elsewhere/Moved.AppImage")).unwrap();
    let (apps, elsewhere) = (e.root().join("apps"), e.root().join("elsewhere"));

    let scan = e.text(&["scan", apps.to_str().unwrap(), elsewhere.to_str().unwrap()]);
    let l = line_of(&scan, "Kept.AppImage");
    assert!(l.contains(&format!("registered as {kept_id}")), "{l}");
    let l = line_of(&scan, "Moved.AppImage");
    assert!(l.contains(&format!("moved copy of {moved_id}")), "{l}");
    let l = line_of(&scan, "Fresh.AppImage");
    assert!(l.contains("new") && !l.contains("registered"), "{l}");
    assert!(fresh.exists());

    fs::write(
        e.root().join("config/config.toml"),
        format!(
            "[general]\nscan_directories = [\"{}\", \"{}\"]\n",
            apps.display(),
            elsewhere.display()
        ),
    )
    .unwrap();
    let found = e.text(&["discover"]);
    let l = line_of(&found, "Kept.AppImage");
    assert!(l.contains(&format!("sandboxed ({kept_id})")), "{l}");
    assert!(!l.contains("not sandboxed"), "{l}");
    let l = line_of(&found, "Moved.AppImage");
    assert!(l.contains(&format!("moved copy of {moved_id}")), "{l}");
    let l = line_of(&found, "Fresh.AppImage");
    assert!(l.contains("not sandboxed"), "{l}");
}

/// `hints APP --apply ID` applies exactly the hint asked for: "files"
/// grants Downloads and leaves the network off, although the game is also
/// offered the network; an id that is not offered changes nothing.
#[test]
fn a_hint_applies_only_what_was_asked_for() {
    let e = Env::new();
    let game = e.fixture("apps", "Game", "Game;");
    let id = e.add(&game, true);
    let offered: Vec<String> = e.json(&["hints", &id], None)["hints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        offered.contains(&"network".to_string()) && offered.contains(&"files".to_string()),
        "a game without network or folders is offered both: {offered:?}"
    );
    let before = e.json(&["get", &id], None);
    let err = e.refused(&["hints", &id, "--apply", "nothing-like-it"], None);
    assert!(err.contains("no hint"), "{err}");
    assert_eq!(e.json(&["get", &id], None), before, "nothing changed");

    e.json(&["hints", &id, "--apply", "files"], None);
    assert_eq!(e.json(&["get", &id, "filesystem.downloads"], None), "rw");
    assert_eq!(
        e.json(&["get", &id, "network.mode"], None),
        "none",
        "the network stays off"
    );
}

/// `hints APP --apply ID` applies a hint rated Think twice or Dangerous
/// only with --yes, as `set` does: without it the network hint is refused
/// with `hint-needs-yes`, names the hint and changes nothing; with it the
/// network is on. A Medium hint ("files") needs no --yes (owner decision
/// 13 of 2026-11-23: one command gave the app the network unasked).
#[test]
fn a_risky_hint_is_applied_only_with_yes() {
    let e = Env::new();
    let game = e.fixture("apps", "Racer", "Game;");
    let id = e.add(&game, true);
    let network = e.json(&["hints", &id], None)["hints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == "network")
        .cloned()
        .expect("a game without network is offered it");
    assert!(
        network["risk"] == "high" || network["risk"] == "dangerous",
        "{network}"
    );
    let before = e.json(&["get", &id], None);
    let o = e.run(&["--json", "hints", &id, "--apply", "network"], None);
    assert!(!o.status.success(), "refused without --yes");
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["code"], "hint-needs-yes", "{v}");
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains(network["title"].as_str().unwrap()) && msg.contains("--yes"),
        "{msg}"
    );
    assert_eq!(e.json(&["get", &id], None), before, "nothing changed");

    e.json(&["hints", &id, "--apply", "files"], None);
    assert_eq!(e.json(&["get", &id, "filesystem.downloads"], None), "rw");
    assert_eq!(e.json(&["get", &id, "network.mode"], None), "none");

    e.json(&["hints", &id, "--apply", "network", "--yes"], None);
    assert_eq!(e.json(&["get", &id, "network.mode"], None), "full");
}

/// A risky first-run hint needs --yes through `repair --apply` as well:
/// `repair APP --apply network` found the hint and applied it unasked
/// (review of owner decision 13 of 2026-11-23). Without --yes it is
/// refused with `hint-needs-yes` and nothing changes; with it the network
/// is on.
#[test]
fn a_risky_hint_needs_yes_through_repair_too() {
    let e = Env::new();
    let game = e.fixture("apps", "Kart", "Game;");
    let id = e.add(&game, true);
    let before = e.json(&["get", &id], None);
    let o = e.run(&["--json", "repair", &id, "--apply", "network"], None);
    assert!(!o.status.success(), "refused without --yes");
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["code"], "hint-needs-yes", "{v}");
    assert_eq!(e.json(&["get", &id], None), before, "nothing changed");

    e.json(&["repair", &id, "--apply", "network", "--yes"], None);
    assert_eq!(e.json(&["get", &id, "network.mode"], None), "full");
}

/// A step the app's own output raised stays the app's request when SAM
/// has a first-run hint of the same name. The hint was found first,
/// without the mark (independent review of 2026-11-27):
/// - `gpu` (Some access): the app printed a graphics error, and `repair
///   --next` turned on the GPU with no --yes at all;
/// - `network` (Think twice): `repair --next` asked for SAM's hint
///   (`hint-needs-yes`) instead, and a script that confirms SAM's own
///   hints granted the network on the app's word.
///
/// Now `repair --next` and `repair --apply ID` refuse both with
/// `repair-needs-yes`, as any step from the app's output, and nothing
/// changes; with --yes they apply.
#[test]
fn a_step_the_apps_output_raised_stays_its_request_under_a_hints_name() {
    use sam_core::model::{FixAction, LaunchRecord, Suggestion};
    use sam_core::risk::RiskLevel;
    let e = Env::new();
    for (name, step, key, value, risk) in [
        ("Glider", "gpu", "devices.gpu", "true", RiskLevel::Medium),
        ("Rover", "network", "network.mode", "full", RiskLevel::High),
    ] {
        let id = e.add(&e.fixture("apps", name, "Game;"), true);
        e.edit_record(&id, |a| {
            // What makes SAM offer its own `gpu` hint: a windowed app with
            // programs and no toolkit or display found.
            let d = a.detection.get_or_insert_with(Default::default);
            d.elf_count = d.elf_count.max(1);
            d.requirements.toolkit.clear();
            d.requirements.wayland = false;
            d.requirements.x11 = false;
            a.metadata.terminal = false;
            a.profile.permissions.devices.gpu = false;
            a.last_launch = Some(LaunchRecord {
                findings: vec![Suggestion {
                    id: step.into(),
                    title: "The app printed an error".into(),
                    explanation: "From the app's output.".into(),
                    action: FixAction::Set {
                        key: key.into(),
                        value: value.into(),
                    },
                    risk,
                    from_app_output: true,
                }],
                ..Default::default()
            });
        });
        let hints = e.json(&["hints", &id], None)["hints"].clone();
        assert!(
            hints.as_array().unwrap().iter().any(|h| h["id"] == step),
            "{step}: SAM offers its own hint of that name: {hints}"
        );
        let steps = e.json(&["repair", &id], None)["steps"].clone();
        assert_eq!(steps[0]["id"], step, "the finding comes first: {steps}");
        let before = e.json(&["get", &id], None);
        for args in [
            &["--json", "repair", &id, "--next"][..],
            &["--json", "repair", &id, "--apply", step][..],
        ] {
            let o = e.run(args, None);
            assert!(!o.status.success(), "{args:?} refused without --yes");
            let v: Value = serde_json::from_slice(&o.stdout).unwrap();
            assert_eq!(v["code"], "repair-needs-yes", "{args:?}: {v}");
            assert_eq!(e.json(&["get", &id], None), before, "{step}: unchanged");
        }

        e.json(&["repair", &id, "--next", "--yes"], None);
        assert_ne!(e.json(&["get", &id], None), before, "{step}: applied");
    }
}

/// `repair APP --apply ID` applies a repair step rated Think twice or
/// Dangerous only with --yes, as `set` and risky hints do: without it
/// turning off the syscall filter is refused with `step-needs-yes`, names
/// the step and changes nothing; with it the filter is off. A step rated
/// Some access ("full-usr") needs no --yes (owner decision A of
/// 2026-11-25: one command turned off the filter unasked).
#[test]
fn a_risky_repair_step_is_applied_only_with_yes() {
    let e = Env::new();
    let game = e.fixture("apps", "Rally", "Game;");
    let id = e.add(&game, true);
    let steps = e.json(&["repair", &id], None)["steps"]
        .as_array()
        .unwrap()
        .clone();
    let step = |sid: &str| {
        steps
            .iter()
            .find(|s| s["id"] == sid)
            .cloned()
            .unwrap_or_else(|| panic!("{sid} offered: {steps:?}"))
    };
    let seccomp = step("seccomp-baseline");
    assert_eq!(seccomp["risk"], "high", "{seccomp}");
    assert_eq!(step("full-usr")["risk"], "medium");

    let before = e.json(&["get", &id], None);
    let o = e.run(
        &["--json", "repair", &id, "--apply", "seccomp-baseline"],
        None,
    );
    assert!(!o.status.success(), "refused without --yes");
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["code"], "step-needs-yes", "{v}");
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains(seccomp["title"].as_str().unwrap()) && msg.contains("--yes"),
        "{msg}"
    );
    assert_eq!(e.json(&["get", &id], None), before, "nothing changed");

    e.json(&["repair", &id, "--apply", "full-usr"], None);
    assert_eq!(e.json(&["get", &id, "advanced.host_runtime"], None), "full");
    assert_eq!(
        e.json(&["get", &id, "advanced.seccomp_baseline"], None),
        true
    );

    e.json(
        &["repair", &id, "--apply", "seccomp-baseline", "--yes"],
        None,
    );
    assert_eq!(
        e.json(&["get", &id, "advanced.seccomp_baseline"], None),
        false
    );
}

/// `menu list` on the terminal names an unsandboxed menu entry that starts
/// the app, and after `menu hide` the hidden one; it says that no other
/// entry starts the app only when there is none.
#[test]
fn the_menu_command_names_every_entry_that_starts_the_app_outside() {
    let e = Env::new();
    let img = e.fixture("apps", "Kept", "Utility;");
    let id = e.add(&img, true);
    let none = "No other menu entries";
    assert!(e.text(&["menu", "list", &id]).contains(none));
    let apps_dir = e.root().join("applications");
    fs::create_dir_all(&apps_dir).unwrap();
    let dup = apps_dir.join("kept-unsandboxed.desktop");
    fs::write(
        &dup,
        format!(
            "[Desktop Entry]\nType=Application\nName=Kept\nExec={} %U\n",
            img.display()
        ),
    )
    .unwrap();

    let listed = e.text(&["menu", "list", &id]);
    assert!(
        listed.contains("visible") && listed.contains("kept-unsandboxed.desktop"),
        "{listed}"
    );
    assert!(!listed.contains(none), "{listed}");
    let hidden = e.text(&["menu", "hide", &id]);
    assert!(
        hidden.contains("hidden") && hidden.contains("kept-unsandboxed.desktop"),
        "{hidden}"
    );
    assert!(!hidden.contains(none), "{hidden}");
    let restored = e.text(&["menu", "restore", &id]);
    assert!(restored.contains("visible"), "back in the menu: {restored}");
}

/// `list` finds apps by name or by id alone, by badge and by category, and
/// sorts by the last start or by when they were added.
#[test]
fn list_filters_and_sorts_the_apps() {
    let e = Env::new();
    let tool = e.add(&e.fixture("apps", "My Tool", "Utility;"), true);
    let game = e.add(&e.fixture("apps", "Other", "Game;"), false);
    // Only the name and the id are searched here, not the description.
    e.edit_record(&tool, |a| a.metadata.comment = "Edits pictures".into());
    assert!(tool.contains("my-tool"), "{tool}");

    assert_eq!(e.list(&["--search", "my t"]), vec![tool.clone()], "by name");
    assert_eq!(
        e.list(&["--search", "my-tool"]),
        vec![tool.clone()],
        "by id"
    );
    assert_eq!(e.list(&["--search", "pictures"]), vec![tool.clone()]);

    let all = e.json(&["list"], None);
    let badge = |id: &str| {
        all.as_array()
            .unwrap()
            .iter()
            .find(|a| a["id"] == id)
            .unwrap()["badge"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(badge(&game), "needs-review");
    assert_ne!(badge(&tool), "needs-review");
    assert_eq!(e.list(&["--badge", "needs-review"]), vec![game.clone()]);
    assert_eq!(e.list(&["--badge", &badge(&tool)]), vec![tool.clone()]);
    assert_eq!(e.list(&["--category", "game"]), vec![game.clone()]);
    assert_eq!(e.list(&["--category", "utility"]), vec![tool.clone()]);
    assert!(e.list(&["--category", "office"]).is_empty());

    // The second in name order was added and started last: first in both.
    let names = e.list(&[]);
    assert_eq!(names, [tool.clone(), game.clone()], "by name");
    e.edit_record(&tool, |a| {
        a.added_at = 1_000;
        a.last_launched = Some(4_000);
    });
    e.edit_record(&game, |a| {
        a.added_at = 2_000;
        a.last_launched = Some(5_000);
    });
    assert_eq!(e.list(&["--sort", "recent"]), [game.clone(), tool.clone()]);
    assert_eq!(e.list(&["--sort", "added"]), [game.clone(), tool.clone()]);
}

/// `info` names what compatibility mode turns on, and still names it
/// while the mode is on (computed from the settings before it).
#[test]
fn info_names_what_compatibility_mode_turns_on_while_it_is_on() {
    let e = Env::new();
    let id = e.add(&e.fixture("apps", "Kept", "Utility;"), true);
    let off = e.json(&["info", &id], None)["compat_changes"].clone();
    assert!(!off.as_array().unwrap().is_empty(), "{off}");
    e.json(&["compat", &id, "on", "--yes"], None);
    let on = e.json(&["info", &id], None)["compat_changes"].clone();
    assert_eq!(on, off);
}

/// `set` on the terminal shows the warnings about the setting just
/// changed, and only those.
#[test]
fn set_shows_the_warnings_about_the_changed_setting() {
    let e = Env::new();
    let id = e.add(&e.fixture("apps", "Kept", "Utility;"), true);
    // Something else to warn about: X11.
    e.json(&["set", &id, "display.x11", "true", "--yes"], None);
    let all = e.json(&["set", &id, "filesystem.home", "true", "--yes"], None)["warnings"].clone();
    let (own, other): (Vec<&Value>, Vec<&Value>) = all
        .as_array()
        .unwrap()
        .iter()
        .partition(|w| w["key"] == "filesystem.home");
    assert!(!own.is_empty(), "the full home is warned about: {all}");
    assert!(
        other.iter().any(|w| w["key"] == "display.x11"),
        "and X11: {all}"
    );
    let shown = e.text(&["set", &id, "filesystem.home", "true", "--yes"]);
    for w in own {
        assert!(shown.contains(w["message"].as_str().unwrap()), "{shown}");
    }
    for w in other {
        assert!(!shown.contains(w["message"].as_str().unwrap()), "{shown}");
    }
}

/// `add` on the terminal reminds to confirm the settings of an app that
/// is not confirmed yet (it does not start before), and not of one added
/// with --accept.
#[test]
fn add_reminds_to_confirm_unconfirmed_settings() {
    let e = Env::new();
    let img = e.fixture("apps", "Kept", "Utility;");
    let said = e.text(&["add", img.to_str().unwrap(), "--no-launcher"]);
    let id = e.list(&[])[0].clone();
    assert!(said.contains(&format!("sam-jail review {id}")), "{said}");
    let other = e.fixture("apps", "Other", "Utility;");
    let said = e.text(&["add", other.to_str().unwrap(), "--no-launcher", "--accept"]);
    assert!(!said.contains("sam-jail review"), "{said}");
}

/// `add --progress` prints the progress for the window as JSON lines on
/// standard error: the first step and the end always.
#[test]
fn add_with_progress_reports_from_the_first_step_to_the_end() {
    let e = Env::new();
    let img = e.fixture("apps", "Kept", "Utility;");
    let o = e.run(
        &[
            "--json",
            "add",
            img.to_str().unwrap(),
            "--no-launcher",
            "--accept",
            "--progress",
        ],
        None,
    );
    assert!(o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    let lines: Vec<Value> = err
        .lines()
        .filter(|l| l.starts_with("{\"progress\""))
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["progress"].clone())
        .collect();
    assert!(lines.len() >= 2, "{err}");
    assert_eq!(lines[0]["step"], 1, "{err}");
    assert_eq!(lines[0]["steps"], 5, "{err}");
    let last = lines.last().unwrap();
    assert_eq!(last["step"], 5, "{err}");
    assert_eq!(last["fraction"], 1.0, "{err}");
    let fractions: Vec<f64> = lines
        .iter()
        .map(|p| p["fraction"].as_f64().unwrap())
        .collect();
    assert!(fractions.windows(2).all(|w| w[0] <= w[1]), "{fractions:?}");
}

/// `uninstall` without --yes only says what it would remove; with --yes it
/// removes the sandboxes, and the AppImage stays.
#[test]
fn uninstall_removes_only_with_yes() {
    let e = Env::new();
    let img = e.fixture("apps", "Kept", "Utility;");
    let id = e.add(&img, true);
    let record = e.root().join(format!("data/apps/{id}.json"));
    let preview = e.json(&["uninstall"], None);
    assert_eq!(preview["done"], false);
    assert_eq!(preview["apps"][0], "Kept", "{preview}");
    assert_eq!(e.list(&[]), vec![id.clone()], "still there");
    assert!(record.exists());
    let done = e.json(&["uninstall", "--yes"], None);
    assert_eq!(done["done"], true);
    assert!(e.list(&[]).is_empty());
    assert!(!record.exists());
    assert!(img.exists(), "the AppImage stays");
}

/// `command APP -- ARGS` shows the command that `run` would start, with
/// the arguments given at its end.
#[test]
fn the_command_preview_ends_with_the_arguments_given() {
    let e = Env::new();
    let id = e.add(&e.fixture("apps", "Kept", "Utility;"), true);
    let pv = e.json(&["command", &id, "--", "--hello", "world"], None);
    let argv: Vec<&str> = pv["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    assert_eq!(argv[argv.len() - 2..], ["--hello", "world"], "{argv:?}");
}

/// `logs APP --file F` shows exactly that log of the app, and refuses a
/// file that is not one of its logs.
#[test]
fn logs_shows_the_log_asked_for_and_nothing_else() {
    let e = Env::new();
    let id = e.add(&e.fixture("apps", "Kept", "Utility;"), true);
    let dir = e.root().join(format!("config/logs/{id}"));
    fs::create_dir_all(&dir).unwrap();
    let (first, second) = (
        dir.join("launch-20260101-000000.log"),
        dir.join("launch-20260102-000000.log"),
    );
    fs::write(&first, "first start\n").unwrap();
    fs::write(&second, "second start\n").unwrap();
    for (f, text) in [(&first, "first start"), (&second, "second start")] {
        let v = e.json(&["logs", &id, "--file", f.to_str().unwrap()], None);
        assert_eq!(v["file"], f.to_str().unwrap());
        assert!(v["text"].as_str().unwrap().contains(text), "{v}");
    }
    let foreign = e.root().join("launch-20260103-000000.log");
    fs::write(&foreign, "not this app's\n").unwrap();
    let err = e.refused(&["logs", &id, "--file", foreign.to_str().unwrap()], None);
    assert!(err.contains("not a log file of this app"), "{err}");
}

/// `verify --permissions-stdin` is for AppImages without a sandbox: for a
/// sandboxed app it is refused instead of checking other settings than
/// the ones given.
#[test]
fn verify_with_given_settings_is_refused_for_a_sandboxed_app() {
    let e = Env::new();
    let id = e.add(&e.fixture("apps", "Kept", "Utility;"), true);
    let perms = e.json(&["get", &id], None).to_string();
    let err = e.refused(&["verify", &id, "--permissions-stdin"], Some(&perms));
    assert!(err.contains("already has a sandbox"), "{err}");
}

/// `desktop APP install` and `remove` put the app's launcher in the menu
/// and take it out; `desktop all refresh` renews every launcher; other
/// actions are refused.
#[test]
fn desktop_installs_removes_and_refreshes_launchers() {
    let e = Env::new();
    let id = e.add(&e.fixture("apps", "Kept", "Utility;"), true);
    let installed = e.json(&["desktop", &id, "install"], None);
    let launcher = PathBuf::from(installed["desktop_entry"].as_str().unwrap());
    assert!(launcher.exists(), "{installed}");
    assert!(launcher.starts_with(e.root().join("applications")));
    let refreshed = e.json(&["desktop", "all", "refresh"], None);
    assert!(refreshed["refreshed"].as_u64().is_some(), "{refreshed}");
    let err = e.refused(&["desktop", &id, "refresh"], None);
    assert!(err.contains("unknown action"), "{err}");
    let removed = e.json(&["desktop", &id, "remove"], None);
    assert!(removed["desktop_entry"].is_null(), "{removed}");
    assert!(!launcher.exists());
}

/// `onboarding` answers whether the first-start tour is done without
/// changing it; `done` and `reset` change it.
#[test]
fn onboarding_is_changed_only_by_done_and_reset() {
    let e = Env::new();
    let done = |args: &[&str]| e.json(args, None)["done"].as_bool().unwrap();
    assert!(!done(&["onboarding"]));
    assert!(!done(&["onboarding"]), "asking changes nothing");
    assert!(done(&["onboarding", "done"]));
    assert!(done(&["onboarding"]), "asking changes nothing");
    assert!(!done(&["onboarding", "reset"]));
    assert!(!done(&["onboarding"]));
}

/// `update APP --decline-key-change` (the window's answer "no" to an
/// update signed differently) deletes the download that waited for that
/// answer, and only that one; the app stays as it was. Before, it stayed
/// in SAM's folder until the app's next update.
#[test]
fn declining_an_update_deletes_the_download_that_waited() {
    let e = Env::new();
    let img = e.fixture("apps", "Kept", "Utility;");
    let id = e.add(&img, true);
    let before = fs::read(&img).unwrap();
    let consent = e.root().join("data/update-consent");
    for app in [id.as_str(), "appimage-other-1234"] {
        fs::create_dir_all(consent.join(app)).unwrap();
        fs::write(consent.join(app).join("download"), "the update").unwrap();
        fs::write(consent.join(app).join("waiting.json"), "{}").unwrap();
    }
    let answer = e.text(&["update", &id, "--decline-key-change"]);
    assert!(answer.contains("was deleted"), "{answer}");
    assert!(!consent.join(&id).exists(), "the waiting download is gone");
    assert!(
        consent.join("appimage-other-1234/download").exists(),
        "another app's waiting download stays"
    );
    assert_eq!(fs::read(&img).unwrap(), before, "the AppImage is unchanged");
    assert_eq!(e.list(&[]), vec![id.clone()]);
    // Nothing waits any more: it says so.
    let again = e.json(&["update", &id, "--decline-key-change"], None);
    assert_eq!(again["id"], id.as_str(), "{again}");
    assert_eq!(again["deleted"], false, "{again}");
    assert!(e
        .text(&["update", &id, "--decline-key-change"])
        .contains("No update of"));
}

/// `config set` turns Landlock or the syscall filter off for every app
/// only with --yes, as the window asks first: without it the change is
/// refused with `config-needs-yes`, names what goes off and nothing is
/// saved. Turning them on, and other settings, need no --yes (one pasted
/// line turned a protection off for all apps unasked).
#[test]
fn turning_a_protection_off_for_every_app_needs_yes() {
    let e = Env::new();
    let file = e.root().join("config/config.toml");
    for (key, name) in [
        ("security.experimental_landlock", "Landlock"),
        ("security.baseline_seccomp", "syscall filter"),
    ] {
        let before = e.json(&["config", "show"], None);
        let saved = fs::read(&file).ok();
        let o = e.run(&["--json", "config", "set", key, "false"], None);
        assert!(!o.status.success(), "{key}: refused without --yes");
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["code"], "config-needs-yes", "{v}");
        let msg = v["error"].as_str().unwrap();
        assert!(msg.contains(name) && msg.contains("--yes"), "{msg}");
        assert_eq!(e.json(&["config", "show"], None), before, "{key}");
        assert_eq!(fs::read(&file).ok(), saved, "{key}: nothing saved");

        e.json(&["config", "set", key, "false", "--yes"], None);
        assert_eq!(e.json(&["config", "get", key], None), false, "{key}");
        // Already off: setting it off again turns nothing off.
        e.json(&["config", "set", key, "false"], None);
        e.json(&["config", "set", key, "true"], None);
        assert_eq!(e.json(&["config", "get", key], None), true, "{key}");
    }
    e.json(&["config", "set", "security.warn_x11", "false"], None);
    assert_eq!(e.json(&["config", "get", "security.warn_x11"], None), false);
}

/// `config put` saves a configuration that turns the syscall filter off
/// for every app only with --yes (code `config-needs-yes`, nothing
/// saved); one that changes something else needs none.
#[test]
fn putting_a_configuration_that_turns_a_protection_off_needs_yes() {
    let e = Env::new();
    let before = e.json(&["config", "show"], None);
    let mut other = before.clone();
    other["security"]["warn_x11"] = Value::Bool(false);
    e.json(&["config", "put"], Some(&other.to_string()));
    let before = e.json(&["config", "show"], None);
    assert_eq!(before["security"]["warn_x11"], false);

    let mut off = before.clone();
    off["security"]["baseline_seccomp"] = Value::Bool(false);
    let o = e.run(&["--json", "config", "put"], Some(&off.to_string()));
    assert!(!o.status.success(), "refused without --yes");
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["code"], "config-needs-yes", "{v}");
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains("syscall filter") && msg.contains("--yes"),
        "{msg}"
    );
    assert_eq!(e.json(&["config", "show"], None), before, "nothing saved");

    e.json(&["config", "put", "--yes"], Some(&off.to_string()));
    assert_eq!(
        e.json(&["config", "get", "security.baseline_seccomp"], None),
        false
    );
}
