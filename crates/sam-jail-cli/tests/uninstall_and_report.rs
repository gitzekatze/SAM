//! End to end through the real `sam-jail` in a fixture home, with SAM's
//! folders in their standard places: what uninstalling SAM removes and
//! keeps, and what a bug report hides.
//!
//! The uninstall test uses SAM through its own commands (`config set`,
//! `onboarding done`, `add`, `run`, `discover`, `preset save`,
//! `remove --keep-data`) and writes the window's own files by hand, as the
//! window writes them. It compares the whole fixture before SAM and after
//! `uninstall --yes`, with and without `--keep-data`, for an unpack folder
//! SAM made, the default one, a linked unpack location and a moved
//! (earlier) unpack location. Skipped where Bubblewrap cannot run.
//!
//! With `--keep-data` the settings and the apps' data also stay. Places
//! allowed to stay by name, pinned as SAM does them today:
//! - with `--keep-data`: the unpack folder, holding only SAM's marker file
//!   `.sam-unpack-folder`; the window's icon copy (`theme/`); the
//!   overview's previews (`previews/`); the `apps/` folder and the record
//!   lock file `apps/.records.lock`, when SAM made it;
//! - a linked unpack location (`~/Apps`): without `--keep-data` the link
//!   goes and the folder behind it stays, holding only the marker file;
//! - an earlier unpack location (`~/Unpacked`, then `~/Moved`): the earlier
//!   folder stays with its marker file and the copy in it, and `~/Moved`
//!   stays empty.
//!
//! The unpack folder's leftovers are checked exactly.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// How long one command may take before the test fails.
const LIMIT: Duration = Duration::from_secs(180);

fn bwrap_works() -> bool {
    Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-user",
            "--unshare-pid",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The test's setup, or a recorded skip where Bubblewrap cannot run.
fn usable() -> bool {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return false;
    }
    true
}

/// A person's computer in a temporary folder: a home with SAM's folders
/// in their standard places, a runtime folder, a system menu folder.
struct Computer {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    run: PathBuf,
}

const USER: &str = "erika";

impl Computer {
    fn new() -> Computer {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let home = root.join("home").join(USER);
        // The runtime folder of this test (short enough for SAM's sockets).
        let run = sam_core::Paths::rooted(&root).runtime_root.unwrap();
        fs::create_dir_all(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        // What a desktop has before SAM: its settings and menu folders, a
        // file of the person's, the system's menu folder.
        for d in [".config", ".local/share/applications", "Documents"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        fs::write(home.join("Documents/notes.txt"), "the person's notes").unwrap();
        fs::create_dir_all(root.join("system/applications")).unwrap();
        Computer {
            _tmp: tmp,
            root,
            home,
            run,
        }
    }

    /// `sam-jail` as the person runs it: SAM finds its folders below the
    /// home and the runtime folder, as an installed SAM does.
    fn sam(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
        c.args(args).stdin(Stdio::null());
        // No desktop session of the person, English messages.
        sam_runner::testenv::isolate_command(&mut c, &self.root);
        for v in [
            "SAM_CONFIG_DIR",
            "SAM_DATA_DIR",
            "SAM_APPLICATIONS_DIR",
            "SAM_RUNTIME_DIR",
        ] {
            c.env_remove(v);
        }
        c.env("HOME", &self.home)
            .env("USER", USER)
            .env("LOGNAME", USER)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env("XDG_DATA_DIRS", self.root.join("system"))
            .env("XDG_RUNTIME_DIR", &self.run);
        c
    }

    /// Runs a command that must succeed, within [`LIMIT`]; its output.
    fn ok(&self, args: &[&str]) -> String {
        let o = finish(self.sam(args), &args.join(" "));
        assert!(
            o.status.success(),
            "`sam-jail {}` failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    /// The `data` of a `--json` answer that must succeed.
    fn json(&self, args: &[&str]) -> serde_json::Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        let text = self.ok(&a);
        let v: serde_json::Value = serde_json::from_str(
            text.lines()
                .rfind(|l| !l.trim().is_empty())
                .unwrap_or("null"),
        )
        .unwrap_or_else(|e| panic!("{e}: {text}"));
        v["data"].clone()
    }

    /// A terminal program in `~/Downloads` with this start script.
    fn appimage(&self, name: &str, script: &str) -> PathBuf {
        let dir = self.home.join("Downloads");
        fs::create_dir_all(&dir).unwrap();
        let s = self.root.join(format!("{name}.apprun"));
        fs::write(&s, script).unwrap();
        fs::set_permissions(&s, fs::Permissions::from_mode(0o755)).unwrap();
        let img = dir.join(format!("{name}-1.0-x86_64.AppImage"));
        self.ok(&[
            "dev",
            "make-fixture",
            "--name",
            name,
            "--terminal",
            "--apprun",
            s.to_str().unwrap(),
            img.to_str().unwrap(),
        ]);
        img
    }
}

/// `cmd` with its output, or a failed test naming it after [`LIMIT`].
fn finish(mut cmd: Command, what: &str) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn().unwrap();
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(LIMIT) {
        Ok(o) => o.unwrap(),
        Err(_) => {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            panic!("`sam-jail {what}` did not finish within {LIMIT:?}");
        }
    }
}

/// What a place holds: a folder, a file's bytes or a link's target.
#[derive(Debug, PartialEq)]
enum Held {
    Folder,
    File(Vec<u8>),
    Link(PathBuf),
}

/// Everything below `top`, by path.
fn snapshot(top: &Path) -> BTreeMap<PathBuf, Held> {
    fn walk(p: &Path, out: &mut BTreeMap<PathBuf, Held>) {
        let Ok(m) = fs::symlink_metadata(p) else {
            return;
        };
        if m.file_type().is_symlink() {
            out.insert(p.to_path_buf(), Held::Link(fs::read_link(p).unwrap()));
        } else if m.is_dir() {
            out.insert(p.to_path_buf(), Held::Folder);
            let mut names: Vec<_> = fs::read_dir(p)
                .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
                .flatten()
                .map(|e| e.path())
                .collect();
            names.sort();
            for n in names {
                walk(&n, out);
            }
        } else {
            out.insert(p.to_path_buf(), Held::File(fs::read(p).unwrap_or_default()));
        }
    }
    let mut out = BTreeMap::new();
    walk(top, &mut out);
    out
}

/// The computer as a whole: its folder and the runtime folder (which lies
/// elsewhere when the test's folder has a long name).
fn whole(c: &Computer) -> BTreeMap<PathBuf, Held> {
    let mut all = snapshot(&c.root);
    if !c.run.starts_with(&c.root) {
        all.extend(snapshot(&c.run));
    }
    all
}

/// The name of the place a path belongs to, for the failure message.
fn place(c: &Computer, p: &Path) -> &'static str {
    let apps = c.home.join(".local/share/applications");
    let named = |prefix: &str| {
        p.strip_prefix(&apps)
            .ok()
            .and_then(|r| r.to_str())
            .is_some_and(|r| r.starts_with(prefix))
    };
    if p.starts_with(c.home.join(".config/sam")) {
        "SAM's settings folder (~/.config/sam: settings, presets, launch logs)"
    } else if p.starts_with(c.home.join(".local/share/sam/extracted")) {
        "SAM's default unpack folder (~/.local/share/sam/extracted: unpacked apps, marker file)"
    } else if p.starts_with(c.home.join(".local/share/sam/theme")) {
        "the copy of SAM's icon in its data folder (~/.local/share/sam/theme, written by the window)"
    } else if p.starts_with(c.home.join(".local/share/sam/previews")) {
        "the overview's previews of the AppImages it found (~/.local/share/sam/previews)"
    } else if p.starts_with(c.home.join(".local/share/sam")) {
        "SAM's data folder (~/.local/share/sam: app records, unpacked apps, private homes, icons)"
    } else if p.starts_with(c.home.join("Unpacked")) {
        "the unpack folder SAM made (extraction.location)"
    } else if p == c.home.join("Apps") {
        "the person's link used as the unpack location (~/Apps)"
    } else if p.starts_with(c.root.join("disk")) {
        "the folder behind the linked unpack location (~/Apps)"
    } else if p.starts_with(c.home.join("Moved")) {
        "the unpack location set after the apps were unpacked (~/Moved)"
    } else if p.starts_with(c.run.join("sam")) {
        "SAM's runtime folder ($XDG_RUNTIME_DIR/sam)"
    } else if named("sam-") {
        "a menu entry SAM made for an app"
    } else if named("io.github.gitzekatze.SAM") {
        "SAM's own menu entry (written by the window)"
    } else if p.starts_with(c.home.join(".local/share/icons")) {
        "SAM's own icon (written by the window)"
    } else if named("") {
        "another tool's menu entry that SAM hid, or SAM's override of a system entry"
    } else if p.starts_with(c.home.join("Downloads")) {
        "the person's AppImages"
    } else {
        "a place outside SAM's known places"
    }
}

/// What changed between `before` and `after`, each with the name of its
/// place; `allowed` lets a change through, `gone` a deletion (by name).
fn changes(
    c: &Computer,
    before: &BTreeMap<PathBuf, Held>,
    after: &BTreeMap<PathBuf, Held>,
    gone: &[PathBuf],
    allowed: impl Fn(&Path, &Held) -> bool,
) -> Vec<String> {
    let mut out = Vec::new();
    for (p, h) in after {
        let what = match before.get(p) {
            None => "left behind",
            Some(b) if b != h => "changed",
            Some(_) => continue,
        };
        if !allowed(p, h) {
            out.push(format!("- {}: {} ({what})", place(c, p), p.display()));
        }
    }
    for p in before
        .keys()
        .filter(|p| !after.contains_key(*p) && !gone.contains(*p))
    {
        out.push(format!("- {}: {} (deleted)", place(c, p), p.display()));
    }
    out
}

/// The folders of the icon theme the window puts its icon in: shared
/// with every other program, they stay when they hold no file.
fn shared_icon_folder(c: &Computer, p: &Path, h: &Held) -> bool {
    *h == Held::Folder
        && p.starts_with(c.home.join(".local/share/icons"))
        && snapshot(p).values().all(|h| *h == Held::Folder)
}

/// The desktop's menu database (`update-desktop-database`, when it is
/// installed): SAM brings it up to date after its changes; it may stay,
/// without any entry of SAM's.
fn menu_database(c: &Computer, p: &Path, h: &Held) -> bool {
    p == c.home.join(".local/share/applications/mimeinfo.cache")
        && matches!(h, Held::File(t) if !String::from_utf8_lossy(t).contains("sam-"))
}

/// The person's AppImages, and other tools' menu entries for one of them,
/// from before SAM.
fn before_sam(c: &Computer) -> (PathBuf, PathBuf) {
    let plain = c.appimage("Plain", "#!/bin/sh\necho plain started\n");
    let other = c.appimage("Other", "#!/bin/sh\necho other started\n");
    // Two other tools' menu entries that start Plain without a sandbox: a
    // user-level one SAM edits, a system one SAM overrides.
    let entry = |n: &str| {
        format!(
            "[Desktop Entry]\nType=Application\nName={n}\nExec=\"{}\" %U\n",
            plain.display()
        )
    };
    fs::write(
        c.home
            .join(".local/share/applications/appimagekit-plain.desktop"),
        entry("Plain"),
    )
    .unwrap();
    fs::write(
        c.root.join("system/applications/gearlever-plain.desktop"),
        entry("Plain (system)"),
    )
    .unwrap();
    (plain, other)
}

/// Where SAM unpacks in a run of the test.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Unpack {
    /// A folder SAM makes outside its data folder (`~/Unpacked`, set with
    /// `config set extraction.location`).
    Made,
    /// The default unpack folder inside SAM's data folder.
    Default,
    /// A link the person made (`~/Apps`) to an empty folder elsewhere (as
    /// on another disk), set as the unpack location.
    Linked,
    /// `~/Unpacked` as in `Made`, then the location is changed to the
    /// person's empty folder `~/Moved` (a folder chooser returns a folder
    /// that exists) and nothing is unpacked again before uninstalling.
    Moved,
}

impl Unpack {
    /// The unpack location while the apps are added and unpacked.
    fn root(self, c: &Computer) -> PathBuf {
        match self {
            Unpack::Made | Unpack::Moved => c.home.join("Unpacked"),
            Unpack::Default => c.home.join(".local/share/sam/extracted"),
            Unpack::Linked => c.home.join("Apps"),
        }
    }

    /// The real folder that holds SAM's marker file: the one behind the
    /// link for `Linked`, the unpack location itself otherwise.
    fn folder(self, c: &Computer) -> PathBuf {
        match self {
            Unpack::Linked => c.root.join("disk/Apps"),
            _ => self.root(c),
        }
    }

    /// The person's own places for this run, there before SAM.
    fn before_sam(self, c: &Computer) {
        match self {
            Unpack::Linked => {
                fs::create_dir_all(self.folder(c)).unwrap();
                std::os::unix::fs::symlink(self.folder(c), self.root(c)).unwrap();
            }
            // The folder the person later picks in Preferences: it exists,
            // so SAM's check that a copy lies in the current location runs
            // against a real folder.
            Unpack::Moved => fs::create_dir_all(c.home.join("Moved")).unwrap(),
            Unpack::Made | Unpack::Default => {}
        }
    }
}

/// The marker file SAM writes into an unpack folder it makes.
const UNPACK_MARKER: &str = ".sam-unpack-folder";

/// The copy of SAM's icon the window writes into SAM's data folder at
/// every start (`own_icon_dir` in sam-gtk), below `data`.
const THEME_ICON: &str = "theme/hicolor/scalable/apps/io.github.gitzekatze.SAM.svg";

/// Puts SAM onto `c` the way a person uses it: every kind of place SAM
/// writes, unpacking in `unpack`. Returns the started app's id and the one
/// removed with `--keep-data`.
fn use_sam(c: &Computer, (plain, other): &(PathBuf, PathBuf), unpack: Unpack) -> (String, String) {
    let unpacked = unpack.root(c);
    match unpack {
        Unpack::Made | Unpack::Linked | Unpack::Moved => c.ok(&[
            "config",
            "set",
            "extraction.location",
            unpacked.to_str().unwrap(),
        ]),
        // A setting that leaves the unpack folder where it is, so that
        // SAM writes its settings file here too.
        Unpack::Default => c.ok(&["config", "set", "general.scan_downloads", "false"]),
    };
    c.ok(&["onboarding", "done"]);
    let id = c.json(&[
        "add",
        plain.to_str().unwrap(),
        "--accept",
        "--hide-duplicates",
    ])["entry"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let other_id = c.json(&["add", other.to_str().unwrap(), "--accept"])["entry"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let hidden = fs::read_to_string(
        c.home
            .join(".local/share/applications/appimagekit-plain.desktop"),
    )
    .unwrap();
    assert!(
        hidden.contains("Hidden=true"),
        "SAM hid the entry: {hidden}"
    );
    assert!(
        c.home
            .join(".local/share/applications/gearlever-plain.desktop")
            .is_file(),
        "SAM overrode the system entry"
    );
    c.ok(&["run", &id]);
    c.ok(&["run", &other_id]);
    // The overview's list, as the window shows it at every start.
    c.ok(&["discover"]);
    c.ok(&["preset", "save", &id, "Mine"]);
    c.ok(&["remove", &other_id, "--keep-data"]);
    // SAM's own menu entry and icon, as the window writes them when SAM
    // runs from a folder without a system-wide desktop file.
    let apps = c.home.join(".local/share/applications");
    fs::write(
        apps.join("io.github.gitzekatze.SAM.desktop"),
        "[Desktop Entry]\nType=Application\nName=SAM\nNoDisplay=true\nX-SAM-Self=true\n",
    )
    .unwrap();
    let icons = c.home.join(".local/share/icons/hicolor/scalable/apps");
    fs::create_dir_all(&icons).unwrap();
    fs::write(icons.join("io.github.gitzekatze.SAM.svg"), "<svg/>").unwrap();
    // The copy of its icon the window writes into SAM's data folder at
    // every start, wherever SAM is installed.
    let data = c.home.join(".local/share/sam");
    let theme_icon = data.join(THEME_ICON);
    fs::create_dir_all(theme_icon.parent().unwrap()).unwrap();
    fs::write(&theme_icon, "<svg/>").unwrap();
    // Every kind of place is there before uninstalling.
    for (what, p) in [
        ("settings", c.home.join(".config/sam/config.toml")),
        ("a preset", c.home.join(".config/sam/presets")),
        ("launch logs", c.home.join(format!(".config/sam/logs/{id}"))),
        ("app records", data.join("apps")),
        ("a private home", data.join(format!("homes/{id}"))),
        ("kept data", data.join(format!("kept/{other_id}"))),
        ("the overview's previews", data.join("previews")),
        ("the window's icon copy", theme_icon),
        ("the unpacked app", unpacked.join(&id)),
        (
            "the unpack folder's marker",
            unpack.folder(c).join(UNPACK_MARKER),
        ),
        ("a menu entry", apps.join(format!("sam-{id}.desktop"))),
        ("the runtime folder", c.run.join("sam")),
    ] {
        assert!(p.exists(), "SAM did not make {what} ({})", p.display());
    }
    assert!(
        fs::read_dir(data.join("previews"))
            .unwrap()
            .flatten()
            .any(|e| e.path().extension().is_some_and(|x| x == "json")),
        "the overview cached no preview in {}",
        data.join("previews").display()
    );
    if unpack == Unpack::Moved {
        // The person picks another unpack location; the copies stay where
        // they are until the apps are unpacked again.
        let moved = c.home.join("Moved");
        c.ok(&[
            "config",
            "set",
            "extraction.location",
            moved.to_str().unwrap(),
        ]);
    }
    (id, other_id)
}

/// The leftovers of the unpack folder, as SAM does them today: checks
/// exactly what of it stays after uninstalling, and returns the deletions
/// that belong to them. Each is pinned: should SAM come to remove more,
/// this test changes with it.
fn unpack_leftover(c: &Computer, unpack: Unpack, id: &str, keep_data: bool) -> Vec<PathBuf> {
    let folder = unpack.folder(c);
    let marker = folder.join(UNPACK_MARKER);
    let held: Vec<PathBuf> = snapshot(&folder).into_keys().collect();
    match (unpack, keep_data) {
        // Nothing stays; the strict comparison checks it.
        (Unpack::Made | Unpack::Default, false) => Vec::new(),
        // The unpack folder stays holding only its marker file.
        (Unpack::Made | Unpack::Default | Unpack::Linked, true) => {
            assert_eq!(
                held,
                vec![folder.clone(), marker],
                "known limit ({unpack:?} unpack folder): with --keep-data SAM leaves the unpack \
                 folder {} holding only its marker file {UNPACK_MARKER}, as SAM does today",
                folder.display()
            );
            Vec::new()
        }
        // Only the link goes; the folder behind it stays with the marker.
        (Unpack::Linked, false) => {
            let link = unpack.root(c);
            assert!(
                fs::symlink_metadata(&link).is_err(),
                "known limit (linked unpack location): uninstalling without --keep-data \
                 removes the link {}, as SAM does today",
                link.display()
            );
            assert_eq!(
                held,
                vec![folder.clone(), marker],
                "known limit (linked unpack location): the folder {} behind the link stays \
                 holding only SAM's marker file {UNPACK_MARKER}, as SAM does today",
                folder.display()
            );
            vec![link]
        }
        // The earlier location stays with its marker and the copy of the
        // app that was still unpacked there.
        (Unpack::Moved, _) => {
            let copy = folder.join(id);
            assert!(
                copy.is_dir(),
                "earlier unpack location (keep data: {keep_data}): SAM removes unpacked \
                 copies only inside the current unpack location ~/Moved, so the copy {} in \
                 the earlier folder stays, as SAM does today",
                copy.display()
            );
            let other: Vec<&PathBuf> = held
                .iter()
                .filter(|p| **p != folder && **p != marker && !p.starts_with(&copy))
                .collect();
            assert!(
                held.contains(&marker) && other.is_empty(),
                "known limit (earlier unpack location, keep data: {keep_data}): the folder {} \
                 stays holding only SAM's marker file and the app's unpacked copy; also there: \
                 {other:?}",
                folder.display()
            );
            let moved = c.home.join("Moved");
            assert_eq!(
                snapshot(&moved).into_keys().collect::<Vec<_>>(),
                vec![moved.clone()],
                "the new unpack location {} stays as the person had it (empty, without SAM's \
                 marker file): nothing was unpacked there",
                moved.display()
            );
            Vec::new()
        }
    }
}

/// What uninstalling SAM removes and keeps, with and without `--keep-data`,
/// for a made, default, linked and moved unpack folder. A failure names
/// each place left behind, changed or deleted.
#[test]
fn uninstalling_leaves_only_what_the_person_keeps() {
    if !usable() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));

    for unpack in [Unpack::Made, Unpack::Default, Unpack::Linked, Unpack::Moved] {
        // Everything goes, apart from the known limits.
        let c = Computer::new();
        let images = before_sam(&c);
        unpack.before_sam(&c);
        let before = whole(&c);
        let (id, _) = use_sam(&c, &images, unpack);
        let done = c.json(&["uninstall", "--yes"]);
        assert_eq!(
            done["problems"],
            serde_json::json!([]),
            "{unpack:?}: {done}"
        );
        let gone = unpack_leftover(&c, unpack, &id, false);
        let leftover = |p: &Path| {
            matches!(unpack, Unpack::Linked | Unpack::Moved) && p.starts_with(unpack.folder(&c))
        };
        let left = changes(&c, &before, &whole(&c), &gone, |p, h| {
            leftover(p) || shared_icon_folder(&c, p, h) || menu_database(&c, p, h)
        });
        assert!(
            left.is_empty(),
            "uninstalling ({unpack:?} unpack folder) left the computer different from before SAM:\n{}",
            left.join("\n")
        );

        // The settings and the data folder stay; nothing else does, except
        // the known limits.
        let c = Computer::new();
        let images = before_sam(&c);
        unpack.before_sam(&c);
        let before = whole(&c);
        let (id, other_id) = use_sam(&c, &images, unpack);
        let done = c.json(&["uninstall", "--yes", "--keep-data"]);
        assert_eq!(
            done["problems"],
            serde_json::json!([]),
            "{unpack:?}: {done}"
        );
        let config = c.home.join(".config/sam");
        let data = c.home.join(".local/share/sam");
        let folder = unpack.folder(&c);
        let gone = unpack_leftover(&c, unpack, &id, true);
        // Of the data folder only the apps' data stays (their private homes,
        // the data kept earlier, writable app folders, the versions updates
        // replaced), folders without any file in them, and by name the
        // window's icon copy and the overview's previews: never an app
        // record, an icon of an app or an unpacked copy.
        let apps_data = ["homes", "kept", "overlays", "update-backups"].map(|k| data.join(k));
        let theme = data.join("theme");
        let theme_icon = data.join(THEME_ICON);
        let previews = data.join("previews");
        let records = data.join("apps");
        let left = changes(&c, &before, &whole(&c), &gone, |p, h| {
            p.starts_with(&config)
                || p == data
                || apps_data.iter().any(|k| p.starts_with(k))
                || (p.starts_with(&data)
                    && *h == Held::Folder
                    && snapshot(p).values().all(|h| *h == Held::Folder))
                // Named: the window's icon copy, and the overview's
                // previews (its cache of every AppImage it found).
                || (p.starts_with(&theme) && (*h == Held::Folder || p == theme_icon))
                || p.starts_with(&previews)
                // By name: the lock file SAM takes to save app records
                // stays in `apps/` after saving, and `--keep-data` keeps
                // it. A SAM without the record lock makes no such file.
                || p == records
                || p == records.join(".records.lock")
                // The known limits for the unpack folder, whose exact
                // contents `unpack_leftover` checked.
                || p.starts_with(&folder)
                || shared_icon_folder(&c, p, h)
                || menu_database(&c, p, h)
        });
        assert!(
            left.is_empty(),
            "uninstalling with --keep-data ({unpack:?} unpack folder) left more than the \
             settings, the apps' data, the window's icon copy, the overview's previews, the record \
             lock file and the known leftover of the unpack folder {}:\n{}",
            folder.display(),
            left.join("\n")
        );
        for (what, p) in [
            ("the settings", config.join("config.toml")),
            ("the preset", config.join("presets")),
            ("the launch logs", config.join(format!("logs/{id}"))),
            ("the private home", data.join(format!("homes/{id}"))),
            (
                "the data kept earlier",
                data.join(format!("kept/{other_id}")),
            ),
            // Known limits of the kept data folder.
            ("the window's icon copy", theme_icon.clone()),
            ("the overview's previews", previews.clone()),
        ] {
            assert!(
                p.exists(),
                "--keep-data ({unpack:?} unpack folder) deleted {what} ({})",
                p.display()
            );
        }
    }
}

/// `sam-jail report APP` holds the app's launch log without the home
/// folder, another user's name, the user name, an email address, an IP
/// address or a given variable's value, and without the computer's name
/// when it is longer than one letter.
#[test]
fn a_bug_report_removes_the_personal_details_it_promises_to() {
    if !usable() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let c = Computer::new();
    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    let home = c.home.display().to_string();
    // What apps print into their logs.
    let img = c.appimage(
        "Talker",
        &format!(
            "#!/bin/sh\n\
             echo 'opened {home}/Documents/plan.txt'\n\
             echo 'signed in as {USER} on {host} now'\n\
             echo 'mail jo.muster@example.org from 192.168.40.7'\n\
             echo 'seen /home/someone/Private/list.txt'\n"
        ),
    );
    let id = c.json(&["add", img.to_str().unwrap(), "--no-launcher", "--accept"])["entry"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    c.ok(&[
        "set",
        &id,
        "environment.set",
        r#"{"GREETING": "pink-elephant-42"}"#,
        "--yes",
    ]);
    c.ok(&["run", &id]);
    let report = c.json(&["report", &id])["report"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        report.contains("#### Last launch log"),
        "the report holds the app's launch log: {report}"
    );
    assert!(
        report.contains("opened ~/Documents/plan.txt"),
        "the home folder is shown as ~ and the path stays readable: {report}"
    );
    assert!(
        report.contains("/home/<user>/Private/list.txt"),
        "another user's folder is hidden: {report}"
    );
    assert!(
        report.contains("GREETING"),
        "the variable's name stays: {report}"
    );
    let mut hidden = vec![
        ("the home folder", home.as_str()),
        ("the user name", USER),
        ("an email address", "jo.muster@example.org"),
        ("an IP address", "192.168.40.7"),
        ("another user's name", "someone"),
        (
            "the value of a variable given to the app",
            "pink-elephant-42",
        ),
    ];
    // SAM hides a computer name longer than one letter.
    if host.len() > 1 {
        hidden.push(("the computer's name", host.as_str()));
    }
    let shown: Vec<String> = hidden
        .iter()
        .filter(|(_, v)| report.contains(v))
        .map(|(what, v)| format!("{what} ({v})"))
        .collect();
    assert!(
        shown.is_empty(),
        "the bug report shows {}:\n{report}",
        shown.join(", ")
    );
}
