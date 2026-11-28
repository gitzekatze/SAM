//! The places SAM shows an app from your home on its own (your fonts, the
//! fonts settings, the theme files) follow no link at all, and the extra
//! read-only folders are never followed through a link to a place the app
//! must not reach, attacked from inside a real sandbox.
//!
//! With the whole home writable and `~/.fonts` missing (common), an app
//! makes `~/.fonts` a link to `/tmp/tmux-1000` in one start. At the next
//! start SAM followed the link and bound the host's folder over the
//! sandbox's own `/tmp`. Connecting to a socket needs no write access, so
//! the app reached the host's tmux server through the read-only bind and
//! could run commands outside the sandbox (the same with `/run/user/1000`,
//! which holds the session bus, systemd's and GnuPG's sockets). Here the
//! socket folder is a stand-in named like tmux's, in the test machine's
//! `/tmp`, with a listening socket the app must not reach.
//!
//! Each protection has its own case:
//! - a font place that is a link, or lies behind one, in the home is not
//!   followed, whoever made the link and wherever it leads: to an
//!   ordinary folder in the home or out of it, to your keys, to where
//!   programs outside the sandbox listen, also a link made in an earlier
//!   start with the whole home writable; the start names each such link;
//! - a link at a protected name never knocks out the read-only bind of
//!   the fonts settings, also with the home kept behind a link;
//! - a credential kept as a link into a fonts folder stays hidden, in a
//!   private home and with the home read-only, also with the home kept
//!   behind a link and an extra folder that shows the fonts settings;
//! - a link you made, in a folder the app cannot change, to fonts
//!   settings that a writable folder shows keeps them read-only there;
//! - an extra folder's link in a folder the app can change that leads out
//!   of what the app is shown is not followed (the app may have made it);
//! - an extra folder's link that leads to a place where programs outside
//!   the sandbox listen is not followed, whoever made it: also a socket
//!   directly in `/tmp`, a socket folder there by any name, and the host's
//!   runtime folder kept outside `/run` and `/tmp`;
//! - a read-only grant the app made lead into a folder it can change
//!   does not hide a link it planted there;
//! - a user folder reached through a link the app planted is not bound;
//! - a writable extra folder the app made a link to a read-only home does
//!   not make the home writable, nor one made a link into a user folder
//!   set read-only under a writable home.
//!
//! Controls: ordinary fonts folders still work, also in a home kept
//! behind a link and through a read-only home that shows a linked one,
//! and an extra folder you list by its real place in `/tmp` is still
//! passed in, so a connection would have been seen.
//!
//! In its own file because it sets `HOME` for the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// The tests share `HOME` and the runtime folder of the test process.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// `plant`: put a link at each place in `SAM_TEST_LINK` to the place at
/// the same position in `SAM_TEST_TARGET`, as an app with the folder
/// writable can. Then connect to every socket in
/// `SAM_TEST_SOCKETS`, read every file in `SAM_TEST_FILES`, rename each
/// `from>to` pair in `SAM_TEST_MOVES` and create every file in
/// `SAM_TEST_WRITES` (each list split by `|`), saying for each what
/// happened.
const PROBE_PY: &str = r#"
import os, socket
if os.environ.get("SAM_TEST_STEP") == "plant":
    try:
        for link, target in zip(os.environ["SAM_TEST_LINK"].split("|"),
                                os.environ["SAM_TEST_TARGET"].split("|")):
            os.makedirs(os.path.dirname(link), exist_ok=True)
            os.symlink(target, link)
        print("PLANTED=yes")
    except OSError as e:
        print("PLANTED=" + str(e.errno))
for i, path in enumerate(p for p in os.environ.get("SAM_TEST_SOCKETS", "").split("|") if p):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(path); s.sendall(b"pwned"); print("CONNECT%d=ok" % i)
    except OSError as e:
        print("CONNECT%d=%d" % (i, e.errno))
for i, path in enumerate(p for p in os.environ.get("SAM_TEST_FILES", "").split("|") if p):
    try:
        with open(path) as f:
            print("READ%d=%s" % (i, f.read().strip()))
    except OSError as e:
        print("READ%d=%d" % (i, e.errno))
for i, pair in enumerate(p for p in os.environ.get("SAM_TEST_MOVES", "").split("|") if p):
    src, dst = pair.split(">")
    try:
        os.rename(src, dst); print("MOVE%d=ok" % i)
    except OSError as e:
        print("MOVE%d=%d" % (i, e.errno))
for i, path in enumerate(p for p in os.environ.get("SAM_TEST_WRITES", "").split("|") if p):
    try:
        with open(path, "x") as f:
            f.write("ESCAPED")
        print("WRITE%d=ok" % i)
    except OSError as e:
        print("WRITE%d=%d" % (i, e.errno))
print("END=1")
"#;

const APPRUN: &str = "#!/bin/sh\nexec python3 \"$APPDIR/usr/bin/probe.py\"\n";

fn parse(log: &Path) -> HashMap<String, String> {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// A stand-in for a folder in `/tmp` where a program outside the sandbox
/// listens (`/tmp/tmux-1000`), with its socket.
struct SocketFolder {
    dir: tempfile::TempDir,
    listener: UnixListener,
}

impl SocketFolder {
    fn new() -> SocketFolder {
        // Named like tmux's own, in the machine's real `/tmp`.
        SocketFolder::at(Path::new("/tmp"), "tmux-")
    }

    /// One named `prefix…` in `parent`.
    fn at(parent: &Path, prefix: &str) -> SocketFolder {
        let dir = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(parent)
            .unwrap();
        let listener = UnixListener::bind(dir.path().join("default")).unwrap();
        listener.set_nonblocking(true).unwrap();
        SocketFolder { dir, listener }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    fn socket(&self) -> String {
        self.dir.path().join("default").display().to_string()
    }

    /// Whether anyone connected since the last look (it does not wait).
    fn was_reached(&self) -> bool {
        let mut any = false;
        while self.listener.accept().is_ok() {
            any = true;
        }
        any
    }
}

/// A fake home with the probe app added, and starts of it.
struct Rig {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    app: Sam,
    id: String,
    host: HostInfo,
}

impl Rig {
    /// `None` (recorded as a skip) where Bubblewrap or python3 is missing.
    fn new(name: &str) -> Option<Rig> {
        let host = HostInfo::probe();
        if host.tools.bwrap.is_none()
            || sam_runner::doctor::bwrap_functional(&host).is_err()
            || sam_core::util::which("python3").is_none()
        {
            sam_runner::contracts::skip("bubblewrap is not functional here, or python3 is missing")
                .unwrap_or_else(|e| panic!("{e}"));
            return None;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        sam_runner::testenv::isolate_this_process(&root);
        let home = root.join("home/tester");
        fs::create_dir_all(home.join(".config")).unwrap();
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
        std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
        let img = root.join(format!("{name}-1.0-x86_64.AppImage"));
        let mut spec = FixtureSpec::hello(name);
        spec.apprun = APPRUN.into();
        spec.host_binary = None;
        spec.files.push(FixtureFile {
            path: "usr/bin/probe.py".into(),
            data: PROBE_PY.as_bytes().to_vec(),
            mode: 0o644,
        });
        build(&img, &spec).unwrap();
        let app = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
        let id = app
            .add(
                &img,
                &AddOptions {
                    accept: true,
                    launcher: Some(false),
                    ..Default::default()
                },
            )
            .unwrap()
            .entry
            .id;
        let mut host = sam_runner::testenv::test_host(HostInfo::probe());
        host.xdg_dirs.clear();
        Some(Rig {
            _tmp: tmp,
            home,
            app,
            id,
            host,
        })
    }

    /// Starts the app with `p` and the probe's variables `env`; what the
    /// probe said, and the start's notes.
    fn start(
        &self,
        p: &PermissionSet,
        env: &[(&str, String)],
    ) -> (HashMap<String, String>, String) {
        let mut p = p.clone();
        for (k, v) in env {
            p.environment.set.insert(k.to_string(), v.clone());
        }
        let mut e = self.app.set_permissions(&self.id, p).unwrap();
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                owd: Some(self.home.clone()),
                ..Default::default()
            },
            &self.app.config,
            &self.app.paths,
            &self.host,
        )
        .unwrap_or_else(|e| panic!("the app did not start: {e:#}"));
        let log = rec.log_file.clone().unwrap();
        let text = fs::read_to_string(&log).unwrap_or_default();
        let r = parse(&log);
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "the probe did not finish: {}\n{text}",
            rec.summary
        );
        (r, text)
    }
}

fn whole_home_writable() -> PermissionSet {
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

/// With the whole home writable, the app makes `place` (missing so far) a
/// link to a stand-in for tmux's socket folder in one start; in the next
/// start it reaches the socket neither where the link leads nor through
/// the link, and the start names that danger, not the planted link.
fn planted_link_never_reaches_host_sockets(rig: &Rig, place: &Path, p: &PermissionSet) {
    let sockets = SocketFolder::new();
    let (r, text) = rig.start(
        p,
        &[
            ("SAM_TEST_STEP", "plant".into()),
            ("SAM_TEST_LINK", s(place)),
            ("SAM_TEST_TARGET", s(&sockets.path())),
        ],
    );
    assert_eq!(r["PLANTED"], "yes", "the writable home lets it: {text}");
    assert!(fs::symlink_metadata(place)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!sockets.was_reached());
    let through_link = place.join("default");
    let (r, text) = rig.start(
        p,
        &[(
            "SAM_TEST_SOCKETS",
            format!("{}|{}", sockets.socket(), s(&through_link)),
        )],
    );
    assert_ne!(
        r["CONNECT0"], "ok",
        "the app reached the host's socket folder at its own place: {text}"
    );
    assert_ne!(
        r["CONNECT1"], "ok",
        "the app reached the host's socket through its link: {text}"
    );
    assert!(
        !sockets.was_reached(),
        "a program outside the sandbox was reached through {}",
        place.display()
    );
    // The start names the danger and gives no way out: the note for a link
    // the app may have made says to show the place it leads to.
    assert!(
        text.contains("where programs outside the sandbox listen")
            && !text.contains("may have made that link"),
        "the start names the danger: {text}"
    );
}

/// `~/.fonts`, planted as a link to a socket folder in `/tmp`.
#[test]
fn a_font_folder_link_the_app_planted_never_reaches_host_sockets() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("Fonts") else {
        return;
    };
    planted_link_never_reaches_host_sockets(&rig, &rig.home.join(".fonts"), &whole_home_writable());
}

/// `~/.config/fontconfig`, planted as a link to a socket folder in `/tmp`.
#[test]
fn a_fontconfig_link_the_app_planted_never_reaches_host_sockets() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("Fontconfig") else {
        return;
    };
    planted_link_never_reaches_host_sockets(
        &rig,
        &rig.home.join(".config/fontconfig"),
        &whole_home_writable(),
    );
}

/// An extra read-only folder that did not exist yet, planted as a link to
/// a socket folder in `/tmp`; also one planted as a link to a folder
/// outside the home and outside `/tmp` that the app is not shown (not a
/// place of sockets: the link rule alone, and the start names it). The
/// control: listed by its real place in `/tmp`, a socket folder is still
/// passed in (you were warned), and the probe reaches its socket.
#[test]
fn an_extra_folder_link_the_app_planted_never_reaches_host_sockets() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("Extra") else {
        return;
    };
    // The control.
    let listed = SocketFolder::new();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_read = vec![s(&listed.path())];
    let (r, text) = rig.start(&p, &[("SAM_TEST_SOCKETS", listed.socket())]);
    assert_eq!(r["CONNECT0"], "ok", "listed by its real place: {text}");
    assert!(listed.was_reached());

    fs::create_dir_all(rig.home.join("shared")).unwrap();
    let place = rig.home.join("shared/ro");
    let mut p = whole_home_writable();
    p.filesystem.custom_read = vec![s(&place)];
    planted_link_never_reaches_host_sockets(&rig, &place, &p);

    // A folder outside the home and outside `/tmp` the app is never
    // shown: only the link rule keeps it out.
    let scratch = outside_tmp();
    let outside = fs::canonicalize(scratch.path()).unwrap().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), "SECRET").unwrap();
    let place = rig.home.join("shared/ro2");
    p.filesystem.custom_read = vec![s(&place)];
    let (r, _) = rig.start(
        &p,
        &[
            ("SAM_TEST_STEP", "plant".into()),
            ("SAM_TEST_LINK", s(&place)),
            ("SAM_TEST_TARGET", s(&outside)),
        ],
    );
    assert_eq!(r["PLANTED"], "yes");
    let (r, text) = rig.start(
        &p,
        &[(
            "SAM_TEST_FILES",
            format!(
                "{}|{}",
                s(&outside.join("secret.txt")),
                s(&place.join("secret.txt"))
            ),
        )],
    );
    assert_ne!(r["READ0"], "SECRET", "{text}");
    assert_ne!(r["READ1"], "SECRET", "{text}");
    assert!(
        text.contains("may have made that link"),
        "the start says why: {text}"
    );
}

/// For `~/.fonts`, a link is never followed:
/// - with the whole home writable, a link to a folder outside the home
///   that the app is not shown (the app may have made it);
/// - in a private home, a link to a socket folder in `/tmp` (another
///   program made it; the app cannot change the home);
/// - in a private home, a link to your SSH keys.
#[test]
fn a_font_folder_link_never_leads_out_of_what_the_app_is_shown() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("Leads") else {
        return;
    };
    let fonts = rig.home.join(".fonts");
    let scratch = outside_tmp();
    let outside = fs::canonicalize(scratch.path()).unwrap().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), "SECRET").unwrap();
    symlink(&outside, &fonts).unwrap();
    let files = format!(
        "{}|{}",
        s(&outside.join("secret.txt")),
        s(&fonts.join("secret.txt"))
    );
    let (r, text) = rig.start(&whole_home_writable(), &[("SAM_TEST_FILES", files.clone())]);
    assert_ne!(r["READ0"], "SECRET", "{text}");
    assert_ne!(r["READ1"], "SECRET", "{text}");
    assert!(
        text.contains(&format!("~/.fonts (a link to {})", s(&outside))),
        "the start says why: {text}"
    );

    fs::remove_file(&fonts).unwrap();
    let sockets = SocketFolder::new();
    symlink(sockets.path(), &fonts).unwrap();
    let private = PermissionSet::strict_gui();
    let (r, text) = rig.start(
        &private,
        &[(
            "SAM_TEST_SOCKETS",
            format!("{}|{}", s(&fonts.join("default")), sockets.socket()),
        )],
    );
    assert_ne!(r["CONNECT0"], "ok", "{text}");
    assert_ne!(r["CONNECT1"], "ok", "{text}");
    assert!(!sockets.was_reached(), "{text}");

    fs::remove_file(&fonts).unwrap();
    fs::create_dir_all(rig.home.join(".ssh")).unwrap();
    fs::write(rig.home.join(".ssh/id_ed25519"), "PRIVATE KEY").unwrap();
    symlink(rig.home.join(".ssh"), &fonts).unwrap();
    let (r, text) = rig.start(
        &private,
        &[("SAM_TEST_FILES", s(&fonts.join("id_ed25519")))],
    );
    assert_ne!(r["READ0"], "PRIVATE KEY", "{text}");
}

/// The controls: fonts folders and links that stay inside what the app
/// is shown still work. In a private home: `~/.local/share/fonts` as it
/// is, and an extra read-only folder. With the whole home writable:
/// `~/.fonts` a link to `~/.local/share/fonts`, read through the home,
/// which shows it anyway. (`~/.fonts` a link you made to `~/myfonts` in a
/// private home is no longer followed:
/// [`a_font_link_to_an_ordinary_folder_is_not_followed_in_a_private_home`].)
#[test]
fn ordinary_font_folders_and_links_inside_the_home_still_work() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("Ordinary") else {
        return;
    };
    let h = &rig.home;
    for d in [".local/share/fonts", "notes"] {
        fs::create_dir_all(h.join(d)).unwrap();
    }
    fs::write(h.join(".local/share/fonts/a.txt"), "FONT A").unwrap();
    fs::write(h.join("notes/n.txt"), "NOTE").unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_read = vec![s(&h.join("notes"))];
    let files = format!(
        "{}|{}",
        s(&h.join(".local/share/fonts/a.txt")),
        s(&h.join("notes/n.txt"))
    );
    let (r, text) = rig.start(&p, &[("SAM_TEST_FILES", files)]);
    assert_eq!(r["READ0"], "FONT A", "{text}");
    assert_eq!(r["READ1"], "NOTE", "{text}");

    symlink(h.join(".local/share/fonts"), h.join(".fonts")).unwrap();
    let (r, text) = rig.start(
        &whole_home_writable(),
        &[("SAM_TEST_FILES", s(&h.join(".fonts/a.txt")))],
    );
    assert_eq!(r["READ0"], "FONT A", "{text}");
}

/// A user folder SAM binds on its own: in a private home with `~/Sync`
/// writable and Documents set to `~/Sync/Documents` (not made yet), the
/// app makes it a link to a stand-in for tmux's socket folder in one
/// start; in the next start SAM leaves Documents out, and the app reaches
/// the socket neither where the link leads nor through the link.
#[test]
fn a_user_folder_link_the_app_planted_never_reaches_host_sockets() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut rig) = Rig::new("UserFolder") else {
        return;
    };
    fs::create_dir_all(rig.home.join("Sync")).unwrap();
    let docs = rig.home.join("Sync/Documents");
    rig.host.xdg_dirs.insert("documents".into(), docs.clone());
    let mut p = PermissionSet::strict_gui();
    p.filesystem.documents = Access::Ro;
    p.filesystem.custom_write = vec![s(&rig.home.join("Sync"))];
    planted_link_never_reaches_host_sockets(&rig, &docs, &p);
}

/// With the home read-only and Downloads writable, the app makes an
/// extra writable folder in Downloads, not made yet, a link to the home
/// in one start; in the next start it can write neither in the home nor
/// through the link: the read-only home stays read-only. The start says
/// it leaves out the writable folder, never that the app is not shown the
/// place the read-only home still shows.
#[test]
fn a_link_the_app_planted_never_makes_a_read_only_home_writable() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut rig) = Rig::new("ReadOnlyHome") else {
        return;
    };
    fs::create_dir_all(rig.home.join("Downloads")).unwrap();
    rig.host
        .xdg_dirs
        .insert("downloads".into(), rig.home.join("Downloads"));
    let out = rig.home.join("Downloads/out");
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Ro;
    p.filesystem.downloads = Access::Rw;
    p.filesystem.custom_write = vec![s(&out)];
    let (r, text) = rig.start(
        &p,
        &[
            ("SAM_TEST_STEP", "plant".into()),
            ("SAM_TEST_LINK", s(&out)),
            ("SAM_TEST_TARGET", s(&rig.home)),
        ],
    );
    assert_eq!(r["PLANTED"], "yes", "Downloads is writable: {text}");
    let (in_home, through_link) = (rig.home.join("escaped.txt"), out.join("escaped2.txt"));
    let (r, text) = rig.start(
        &p,
        &[(
            "SAM_TEST_WRITES",
            format!("{}|{}", s(&in_home), s(&through_link)),
        )],
    );
    assert_ne!(
        r["WRITE0"], "ok",
        "the app wrote in the read-only home: {text}"
    );
    assert_ne!(r["WRITE1"], "ok", "the app wrote through its link: {text}");
    assert!(!in_home.exists() && !rig.home.join("escaped2.txt").exists());
    assert!(
        text.contains("may have made that link"),
        "the start says why: {text}"
    );
    // The home still shows the place read-only, so the note never says the
    // app is not shown it.
    assert!(
        text.contains("leaves out the writable folder") && !text.contains("not shown otherwise"),
        "the start says the folder is left out as a writable one: {text}"
    );
}

/// With the whole home writable and Downloads set read-only, the app
/// cannot plant anything in Downloads: SAM mounts it read-only at its own
/// access over the writable home. But in an earlier start, while Downloads
/// was still set to read and write, the app made an extra read-only folder
/// in it, not made yet, a link to a folder outside the home. In the next
/// start with Downloads read-only it reads nothing there, neither where the
/// link leads nor through the link: the folder Downloads lies in counts as
/// one the app can change, whatever its own switch says now.
#[test]
fn a_link_planted_in_a_user_folder_of_a_writable_home_is_not_followed() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut rig) = Rig::new("UserFolderInHome") else {
        return;
    };
    fs::create_dir_all(rig.home.join("Downloads")).unwrap();
    rig.host
        .xdg_dirs
        .insert("downloads".into(), rig.home.join("Downloads"));
    let scratch = outside_tmp();
    let outside = fs::canonicalize(scratch.path()).unwrap().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), "SECRET").unwrap();
    let place = rig.home.join("Downloads/x");
    let mut p = whole_home_writable();
    p.filesystem.downloads = Access::Ro;
    p.filesystem.custom_read = vec![s(&place)];
    let plant = [
        ("SAM_TEST_STEP", "plant".to_string()),
        ("SAM_TEST_LINK", s(&place)),
        ("SAM_TEST_TARGET", s(&outside)),
    ];
    let (r, text) = rig.start(&p, &plant);
    assert_ne!(
        r["PLANTED"], "yes",
        "Downloads is mounted read-only over the writable home: {text}"
    );
    assert!(fs::symlink_metadata(&place).is_err(), "{text}");
    let mut earlier = p.clone();
    earlier.filesystem.downloads = Access::Rw;
    let (r, text) = rig.start(&earlier, &plant);
    assert_eq!(
        r["PLANTED"], "yes",
        "the home shows Downloads writable: {text}"
    );
    let (r, text) = rig.start(
        &p,
        &[(
            "SAM_TEST_FILES",
            format!(
                "{}|{}",
                s(&outside.join("secret.txt")),
                s(&place.join("secret.txt"))
            ),
        )],
    );
    assert_ne!(r["READ0"], "SECRET", "{text}");
    assert_ne!(r["READ1"], "SECRET", "{text}");
    assert!(
        text.contains("may have made that link"),
        "the start says why: {text}"
    );
}

/// With the whole home writable and Documents set read-only, SAM mounts
/// Documents read-only over the home. With an extra writable folder `~/x`
/// that does not exist yet, the app makes `~/x` a link to
/// `~/Documents/Taxes` in one start. In the next start with the same
/// permissions it can write neither in `~/Documents/Taxes` nor through the
/// link, and the start says why: SAM counted the writable home as showing
/// the whole home writable, followed the link and bound
/// `~/Documents/Taxes` writable inside the read-only Documents. A write
/// elsewhere in the writable home still works, so a refused write would
/// have been seen.
#[test]
fn a_planted_link_never_makes_a_read_only_user_folder_writable() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut rig) = Rig::new("ReadOnlyDocuments") else {
        return;
    };
    let taxes = rig.home.join("Documents/Taxes");
    fs::create_dir_all(&taxes).unwrap();
    rig.host
        .xdg_dirs
        .insert("documents".into(), rig.home.join("Documents"));
    let x = rig.home.join("x");
    let mut p = whole_home_writable();
    p.filesystem.documents = Access::Ro;
    p.filesystem.custom_write = vec![s(&x)];
    let (r, text) = rig.start(
        &p,
        &[
            ("SAM_TEST_STEP", "plant".into()),
            ("SAM_TEST_LINK", s(&x)),
            ("SAM_TEST_TARGET", s(&taxes)),
        ],
    );
    assert_eq!(r["PLANTED"], "yes", "the writable home lets it: {text}");
    let (in_taxes, through_link, control) = (
        taxes.join("new.txt"),
        x.join("new2.txt"),
        rig.home.join("control.txt"),
    );
    let (r, text) = rig.start(
        &p,
        &[(
            "SAM_TEST_WRITES",
            format!("{}|{}|{}", s(&in_taxes), s(&through_link), s(&control)),
        )],
    );
    assert_eq!(r["WRITE2"], "ok", "control, the writable home: {text}");
    assert_ne!(
        r["WRITE0"], "ok",
        "the app wrote inside the read-only Documents: {text}"
    );
    assert_ne!(r["WRITE1"], "ok", "the app wrote through its link: {text}");
    assert!(!in_taxes.exists() && !taxes.join("new2.txt").exists());
    assert!(
        text.contains("leaves out the writable folder") && text.contains("may have made that link"),
        "the start says why: {text}"
    );
}

/// A folder outside `/tmp` and `/var/tmp` (in the build's own scratch
/// folder), so only the rule for links the app could have planted, or
/// for runtime folders, keeps it out: anything in `/tmp` counts as a
/// place where programs outside the sandbox listen anyway.
fn outside_tmp() -> tempfile::TempDir {
    let t = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let real = fs::canonicalize(t.path()).unwrap();
    assert!(
        !real.starts_with("/tmp") && !real.starts_with("/var/tmp"),
        "the build's scratch folder lies in a temp folder: {}",
        real.display()
    );
    t
}

/// A read-only grant never hides a link the app planted: with the whole
/// home writable and `~/x` an extra read-only folder, the app makes `~/x`
/// a link to `~/.local/share`, and `~/.local/share/fonts` and the extra
/// read-only folder `~/.local/share/data` links to a folder it is not
/// shown, in one start. In the next start with the same permissions it
/// reads nothing there, neither where the links lead nor through them,
/// and the start says why (before, `~/x` counted `~/.local/share` as a
/// folder the app cannot change, and SAM bound the folder as the fonts).
/// The fonts follow no link at all; the extra folder is the one that
/// needs this rule.
#[test]
fn a_read_only_grant_never_hides_a_link_the_app_planted() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("ReadOnlyGrant") else {
        return;
    };
    let scratch = outside_tmp();
    let secret = fs::canonicalize(scratch.path()).unwrap().join("secret");
    fs::create_dir_all(&secret).unwrap();
    fs::write(secret.join("secret.txt"), "SECRET").unwrap();
    let (x, share) = (rig.home.join("x"), rig.home.join(".local/share"));
    let (fonts, data) = (share.join("fonts"), share.join("data"));
    let mut p = whole_home_writable();
    p.filesystem.custom_read = vec![s(&x), "~/.local/share/data".into()];
    let (r, text) = rig.start(
        &p,
        &[
            ("SAM_TEST_STEP", "plant".into()),
            (
                "SAM_TEST_LINK",
                format!("{}|{}|{}", s(&fonts), s(&data), s(&x)),
            ),
            (
                "SAM_TEST_TARGET",
                format!("{}|{}|{}", s(&secret), s(&secret), s(&share)),
            ),
        ],
    );
    assert_eq!(r["PLANTED"], "yes", "the writable home lets it: {text}");
    assert!(fs::symlink_metadata(&x).unwrap().file_type().is_symlink());
    assert!(fs::symlink_metadata(&fonts)
        .unwrap()
        .file_type()
        .is_symlink());
    let (r, text) = rig.start(
        &p,
        &[(
            "SAM_TEST_FILES",
            format!(
                "{}|{}|{}|{}|{}",
                s(&secret.join("secret.txt")),
                s(&fonts.join("secret.txt")),
                s(&x.join("fonts/secret.txt")),
                s(&data.join("secret.txt")),
                s(&x.join("data/secret.txt"))
            ),
        )],
    );
    assert_ne!(r["READ0"], "SECRET", "{text}");
    assert_ne!(r["READ1"], "SECRET", "{text}");
    assert_ne!(r["READ2"], "SECRET", "{text}");
    assert_ne!(r["READ3"], "SECRET", "the extra folder: {text}");
    assert_ne!(r["READ4"], "SECRET", "the extra folder through ~/x: {text}");
    assert!(
        text.contains(&format!("~/.local/share/fonts (a link to {})", s(&secret)))
            && text.contains("SAM does not follow such a link for your fonts and theme files"),
        "the start says why: {text}"
    );
    assert!(
        text.contains("SAM leaves out the extra folder ~/.local/share/data for this app because")
            && text.contains("may have made that link"),
        "the start says why for the extra folder: {text}"
    );
}

/// A link nobody in the sandbox could have planted (`~/.fonts` and the
/// extra read-only folder `~/y` in a private home) never reaches a place
/// where programs outside the sandbox listen, by any name: a socket
/// directly in `/tmp` (as PostgreSQL keeps its own), a socket folder in
/// `/tmp` by a name no list knows (`tmate-…`), and the host's runtime
/// folder kept outside `/run` and `/tmp` (as `/mnt/wslg/runtime-dir`).
/// The app reaches the socket neither through either link nor at its own
/// place, and the start says why, for the extra folder too: the fonts
/// follow no link at all, the extra folder needs this rule.
#[test]
fn a_font_folder_link_never_reaches_sockets_by_any_name() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut rig) = Rig::new("AnyName") else {
        return;
    };
    let fonts = rig.home.join(".fonts");
    let y = rig.home.join("y");
    let mut private = PermissionSet::strict_gui();
    private.filesystem.custom_read = vec!["~/y".into()];
    // `~/.fonts` and `~/y` both a link to `target`.
    let link_to = |target: &Path| {
        for l in [&fonts, &y] {
            let _ = fs::remove_file(l);
            symlink(target, l).unwrap();
        }
    };
    // `inside`: the socket's name inside the place the links lead to
    // (empty for the socket itself).
    let attempt = |rig: &Rig, socket: &Path, inside: &str, reached: &dyn Fn() -> bool| {
        let through = |l: &Path| {
            if inside.is_empty() {
                s(l)
            } else {
                s(&l.join(inside))
            }
        };
        let (r, text) = rig.start(
            &private,
            &[(
                "SAM_TEST_SOCKETS",
                format!("{}|{}|{}", through(&fonts), s(socket), through(&y)),
            )],
        );
        assert_ne!(r["CONNECT0"], "ok", "through the fonts link: {text}");
        assert_ne!(r["CONNECT1"], "ok", "at its own place: {text}");
        assert_ne!(r["CONNECT2"], "ok", "through the extra folder: {text}");
        assert!(
            !reached(),
            "a program outside the sandbox was reached: {text}"
        );
        assert!(
            text.contains("where programs outside the sandbox listen")
                && text.contains(
                    "SAM leaves out the extra folder ~/y for this app because it leads through a link to"
                ),
            "the start says why: {text}"
        );
    };

    // A socket directly in `/tmp`.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let socket = PathBuf::from(format!("/tmp/.s.SAMTEST.{}.{stamp}", std::process::id()));
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    link_to(&socket);
    let reached = || {
        let mut any = false;
        while listener.accept().is_ok() {
            any = true;
        }
        any
    };
    attempt(&rig, &socket, "", &reached);
    drop(listener);
    let _ = fs::remove_file(&socket);

    // A socket folder in `/tmp` by a name no list knows.
    let tmate = SocketFolder::at(Path::new("/tmp"), "tmate-");
    link_to(&tmate.path());
    attempt(&rig, Path::new(&tmate.socket()), "default", &|| {
        tmate.was_reached()
    });

    // The host's runtime folder, kept outside `/run` and `/tmp`.
    let scratch = outside_tmp();
    let runtime = SocketFolder::at(scratch.path(), "runtime-dir-");
    rig.host.runtime_dir = Some(runtime.path());
    link_to(&runtime.path());
    attempt(&rig, Path::new(&runtime.socket()), "default", &|| {
        runtime.was_reached()
    });
}

/// Where the way ends is not all: a link in `/tmp` made outside the
/// sandbox may send it on to a socket folder SAM does not know by its
/// place (on WSLg the host's `/tmp/.X11-unix` is a link to
/// `/mnt/wslg/.X11-unix`). `~/.fonts` in a private home, a link to such a
/// link in `/tmp` whose socket folder lies outside `/tmp`, `/run` and the
/// runtime folders, and the extra read-only folder `~/y` a link to the
/// same: the app reaches the socket neither through either link nor at
/// its own place, and the start says why, for the extra folder too
/// (before, SAM judged only the folder at the end and bound it as the
/// fonts). The fonts follow no link at all; the extra folder needs this
/// rule.
#[test]
fn a_font_folder_link_through_a_link_in_tmp_never_reaches_sockets() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("ThroughTmp") else {
        return;
    };
    let scratch = outside_tmp();
    let x11 = SocketFolder::at(&fs::canonicalize(scratch.path()).unwrap(), "x11-");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let hop = PathBuf::from(format!("/tmp/.SAMTEST-unix.{}.{stamp}", std::process::id()));
    symlink(x11.path(), &hop).unwrap();
    let (fonts, y) = (rig.home.join(".fonts"), rig.home.join("y"));
    symlink(&hop, &fonts).unwrap();
    symlink(&hop, &y).unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_read = vec!["~/y".into()];
    let (r, text) = rig.start(
        &p,
        &[(
            "SAM_TEST_SOCKETS",
            format!(
                "{}|{}|{}",
                s(&fonts.join("default")),
                x11.socket(),
                s(&y.join("default"))
            ),
        )],
    );
    let _ = fs::remove_file(&hop);
    assert_ne!(r["CONNECT0"], "ok", "through the fonts link: {text}");
    assert_ne!(r["CONNECT1"], "ok", "at its own place: {text}");
    assert_ne!(r["CONNECT2"], "ok", "through the extra folder: {text}");
    assert!(
        !x11.was_reached(),
        "a program outside the sandbox was reached: {text}"
    );
    assert!(
        text.contains("where programs outside the sandbox listen")
            && text.contains(
                "SAM leaves out the extra folder ~/y for this app because it leads through a link to"
            ),
        "the start says why: {text}"
    );
}

/// With the home kept behind a link (`~` a link to its real folder, as
/// `/home` to `/var/home` on some systems) and the whole home writable,
/// the app makes a missing `~/.fonts` a link to the real place of
/// `~/.ssh` (or of SAM's own folder `~/.local/share/sam`) in one start.
/// In the next start it reads the key neither at that real place nor
/// through the fonts folder, and the start says why: before, SAM counted
/// the real place as one the home shows and bound it read-only at that
/// name, beside the home, where the keys were not hidden. In a private
/// home, with SAM's own folders named through a link, `~/.fonts` made a
/// link to their real place shows nothing of them either.
#[test]
fn a_font_link_to_the_real_place_of_a_home_behind_a_link_shows_no_keys() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("HomeBehindLink") else {
        return;
    };
    let real = rig.home.parent().unwrap().join("tester-real");
    fs::rename(&rig.home, &real).unwrap();
    symlink(&real, &rig.home).unwrap();
    let fonts = rig.home.join(".fonts");
    for guarded in [".ssh", ".local/share/sam"] {
        let target = real.join(guarded);
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("id_ed25519"), "PRIVATE KEY").unwrap();
        let _ = fs::remove_file(real.join(".fonts"));
        symlink(&target, real.join(".fonts")).unwrap();
        let files = format!(
            "{}|{}",
            s(&target.join("id_ed25519")),
            s(&fonts.join("id_ed25519"))
        );
        let (r, text) = rig.start(&whole_home_writable(), &[("SAM_TEST_FILES", files)]);
        assert_ne!(
            r["READ0"], "PRIVATE KEY",
            "{guarded} at its real place: {text}"
        );
        assert_ne!(
            r["READ1"], "PRIVATE KEY",
            "{guarded} through ~/.fonts: {text}"
        );
        assert!(
            text.contains(&format!("~/.fonts (a link to ~/{guarded})"))
                && text.contains("SAM does not follow such a link for your fonts and theme files"),
            "{guarded}: the start says why: {text}"
        );
    }
    // SAM's own folders named through a link (here SAM's whole folder is a
    // link to `~/Apps/sam` at the home's real place, as with the unpack
    // folder set to `~/Apps/sam` and `~/Apps` a link to another disk):
    // `~/.fonts` made a link to their real place in an earlier start with
    // the whole home writable was bound in the next start with a private
    // home, since SAM's folders were guarded only as named, and the app
    // read SAM's app records through it. In the home, since the test's
    // folders lie in `/tmp`, where a link out of the home is refused for
    // that reason alone.
    let root = rig.home.parent().unwrap().parent().unwrap().to_path_buf();
    let sam_real = real.join("Apps/sam");
    fs::create_dir_all(real.join("Apps")).unwrap();
    fs::rename(root.join("sam"), &sam_real).unwrap();
    symlink(&sam_real, root.join("sam")).unwrap();
    let target = sam_real.join("data");
    fs::write(target.join("id_ed25519"), "PRIVATE KEY").unwrap();
    let _ = fs::remove_file(real.join(".fonts"));
    symlink(&target, real.join(".fonts")).unwrap();
    let files = format!(
        "{}|{}",
        s(&target.join("id_ed25519")),
        s(&fonts.join("id_ed25519"))
    );
    let (r, text) = rig.start(&PermissionSet::strict_gui(), &[("SAM_TEST_FILES", files)]);
    assert_ne!(
        r["READ0"], "PRIVATE KEY",
        "SAM's folder at its real place: {text}"
    );
    assert_ne!(
        r["READ1"], "PRIVATE KEY",
        "SAM's folder through ~/.fonts: {text}"
    );
    assert!(
        text.contains("~/.fonts (a link to ~/Apps/sam/data)")
            && text.contains("SAM does not follow such a link for your fonts and theme files"),
        "SAM's folder: the start says why: {text}"
    );
}

/// How many of the start's notes name the font or theme places SAM skips
/// for a link ([`sam_core::places::own_place_links_note`]). The log also
/// holds the app page's entries (`# warning [own-place-links]`), with the
/// same words; those are not counted.
fn link_notes(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            l.starts_with("# note: ")
                && l.contains("SAM does not follow such a link for your fonts and theme files")
        })
        .count()
}

/// In a private home, `~/.fonts` that is a link is not followed, wherever
/// it leads and whoever made it: your own link to `~/myfonts`, a link
/// another app made to `~/Documents`, and one to a folder outside the
/// home and outside `/tmp`. The app reads nothing through the link nor at
/// the place it leads to, and the start names the link and where it
/// leads, once. Before, SAM bound where the link led, so anyone who could
/// write in the home chose what a private home showed as the fonts.
#[test]
fn a_font_link_to_an_ordinary_folder_is_not_followed_in_a_private_home() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("FontLink") else {
        return;
    };
    let h = &rig.home;
    let scratch = outside_tmp();
    let outside = fs::canonicalize(scratch.path()).unwrap().join("outside");
    for d in [h.join("myfonts"), h.join("Documents"), outside.clone()] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(h.join("myfonts/b.txt"), "FONT B").unwrap();
    fs::write(h.join("Documents/secret.txt"), "SECRET").unwrap();
    fs::write(outside.join("secret.txt"), "SECRET").unwrap();
    let fonts = h.join(".fonts");
    for (target, file, content, named) in [
        (
            PathBuf::from("myfonts"),
            "b.txt",
            "FONT B",
            "~/myfonts".to_string(),
        ),
        (
            h.join("Documents"),
            "secret.txt",
            "SECRET",
            "~/Documents".to_string(),
        ),
        (outside.clone(), "secret.txt", "SECRET", s(&outside)),
    ] {
        let _ = fs::remove_file(&fonts);
        symlink(&target, &fonts).unwrap();
        let real = fs::canonicalize(&fonts).unwrap();
        let files = format!("{}|{}", s(&fonts.join(file)), s(&real.join(file)));
        let (r, text) = rig.start(&PermissionSet::strict_gui(), &[("SAM_TEST_FILES", files)]);
        assert_ne!(r["READ0"], content, "{named}, through ~/.fonts: {text}");
        assert_ne!(r["READ1"], content, "{named}, where it leads: {text}");
        assert!(
            text.contains(&format!("~/.fonts (a link to {named})")),
            "{named}: the start names the link: {text}"
        );
        assert_eq!(link_notes(&text), 1, "{named}: one note: {text}");
    }
}

/// An app with the whole home writable makes `~/.fonts` (missing so far)
/// a link to a folder outside the home and outside `/tmp` in one start.
/// In a later start with a private home, the app reads nothing there,
/// neither through the link nor where it leads, and the start names the
/// link and where it leads. Before, a link from an earlier start with
/// more rights decided what a private home showed as the fonts.
#[test]
fn a_font_link_made_in_a_start_with_the_home_writable_is_not_followed_later() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("EarlierStart") else {
        return;
    };
    let scratch = outside_tmp();
    let private = fs::canonicalize(scratch.path()).unwrap().join("private");
    fs::create_dir_all(&private).unwrap();
    fs::write(private.join("secret.txt"), "SECRET").unwrap();
    let fonts = rig.home.join(".fonts");
    let (r, text) = rig.start(
        &whole_home_writable(),
        &[
            ("SAM_TEST_STEP", "plant".into()),
            ("SAM_TEST_LINK", s(&fonts)),
            ("SAM_TEST_TARGET", s(&private)),
        ],
    );
    assert_eq!(r["PLANTED"], "yes", "the writable home lets it: {text}");
    let files = format!(
        "{}|{}",
        s(&fonts.join("secret.txt")),
        s(&private.join("secret.txt"))
    );
    let (r, text) = rig.start(&PermissionSet::strict_gui(), &[("SAM_TEST_FILES", files)]);
    assert_ne!(r["READ0"], "SECRET", "through ~/.fonts: {text}");
    assert_ne!(r["READ1"], "SECRET", "where it leads: {text}");
    assert!(
        text.contains(&format!("~/.fonts (a link to {})", s(&private))),
        "the start names the link: {text}"
    );
}

/// The control for a home kept behind a link (`~` a link to its real
/// folder, as `/home` to `/var/home` on some systems): the link that holds
/// the home is not one below it, so a real `~/.fonts` there is shown in a
/// private home, and the start names no link.
#[test]
fn a_home_kept_behind_a_link_keeps_its_fonts_in_a_real_sandbox() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("HomeLinkFonts") else {
        return;
    };
    let real = rig.home.parent().unwrap().join("tester-real");
    fs::rename(&rig.home, &real).unwrap();
    symlink(&real, &rig.home).unwrap();
    fs::create_dir_all(real.join(".fonts")).unwrap();
    fs::write(real.join(".fonts/f.txt"), "FONT").unwrap();
    let (r, text) = rig.start(
        &PermissionSet::strict_gui(),
        &[("SAM_TEST_FILES", s(&rig.home.join(".fonts/f.txt")))],
    );
    assert_eq!(r["READ0"], "FONT", "{text}");
    assert_eq!(link_notes(&text), 0, "{text}");
}

/// A link at a protected name never knocks out the read-only bind of the
/// fonts settings: with the home read-only, hidden files on and an extra
/// writable `~/.config`, `~/.config/vivaldi` made a link to
/// `~/.config/fontconfig` (an app with that folder writable can make it)
/// left the fonts settings writable through the extra folder, so the app
/// could plant rules that programs outside the sandbox load. With the
/// home kept behind a link, that extra folder is shown at its real place,
/// and the fonts settings were writable there even without the planted
/// link. The app cannot write there; elsewhere in the extra folder it
/// can, so a refused write would have been seen. In a private home the
/// hidden-files switch does not count, so SAM hides `~/.config/vivaldi`
/// where its link leads: whatever the app writes there never reaches the
/// fonts settings.
#[test]
fn a_protected_link_never_knocks_out_the_read_only_font_settings_in_a_real_sandbox() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("FontSettings") else {
        return;
    };
    let config = rig.home.join(".config");
    fs::create_dir_all(config.join("fontconfig")).unwrap();
    symlink(config.join("fontconfig"), config.join("vivaldi")).unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Ro;
    p.filesystem.hidden_files = true;
    p.filesystem.custom_write = vec![s(&config)];
    let writes = format!(
        "{}|{}",
        s(&config.join("fontconfig/x.conf")),
        s(&config.join("other.txt"))
    );
    let (r, text) = rig.start(&p, &[("SAM_TEST_WRITES", writes.clone())]);
    assert_eq!(
        r["WRITE0"], "30",
        "the fonts settings stay read-only: {text}"
    );
    assert_eq!(r["WRITE1"], "ok", "control, the extra folder: {text}");
    fs::remove_file(config.join("other.txt")).unwrap();

    // A private home: the planted link is hidden where it leads.
    let mut private = p.clone();
    private.filesystem.home = false;
    let (r, text) = rig.start(&private, &[("SAM_TEST_WRITES", writes)]);
    assert_eq!(r["WRITE1"], "ok", "private home, control: {text}");
    assert!(
        !config.join("fontconfig/x.conf").exists(),
        "private home, nothing reaches the fonts settings: {text}"
    );
    fs::remove_file(config.join("other.txt")).unwrap();
    fs::remove_file(config.join("vivaldi")).unwrap();

    // The home kept behind a link: the extra folder is shown at its real
    // place, and the fonts settings stay read-only there, with and
    // without the planted link. In a private home without the planted
    // link they are read-only under the home's name too; with it, the
    // planted link is hidden where it leads, and nothing reaches the
    // fonts settings (checked last).
    let real = rig.home.parent().unwrap().join("tester-real");
    fs::rename(&rig.home, &real).unwrap();
    symlink(&real, &rig.home).unwrap();
    for (name, perms) in [("read-only home", &p), ("private home", &private)] {
        for planted in [false, true] {
            if planted {
                symlink(config.join("fontconfig"), real.join(".config/vivaldi")).unwrap();
            }
            let writes = format!(
                "{}|{}|{}",
                s(&real.join(".config/fontconfig/x.conf")),
                s(&config.join("fontconfig/y.conf")),
                s(&real.join(".config/other.txt"))
            );
            let (r, text) = rig.start(perms, &[("SAM_TEST_WRITES", writes)]);
            let what = format!("{name}, planted {planted}");
            if name == "read-only home" || !planted {
                assert_eq!(r["WRITE0"], "30", "{what}, real place: {text}");
            }
            if name == "private home" && !planted {
                assert_ne!(r["WRITE1"], "ok", "{what}, home's name: {text}");
            }
            assert_eq!(r["WRITE2"], "ok", "{what}, control: {text}");
            fs::remove_file(real.join(".config/other.txt")).unwrap();
            if planted {
                fs::remove_file(real.join(".config/vivaldi")).unwrap();
            }
        }
    }
    assert!(!real.join(".config/fontconfig/x.conf").exists());
    assert!(!real.join(".config/fontconfig/y.conf").exists());
}

/// In a private home, a credential the person keeps as a link into a
/// fonts folder (`~/.git-credentials` a link to
/// `~/.fonts/dots/git-credentials`) stays hidden: SAM does not bind
/// `~/.fonts` on its own, since it holds where that protected link really
/// leads, and the private home shows no name of the link to mask. The
/// control: without the link, the same file is shown as part of the
/// fonts, so a read would have been seen.
#[test]
fn a_credential_kept_as_a_link_into_a_font_folder_stays_hidden_in_a_private_home() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("CredInFonts") else {
        return;
    };
    let dots = rig.home.join(".fonts/dots");
    fs::create_dir_all(&dots).unwrap();
    fs::write(dots.join("git-credentials"), "SECRET").unwrap();
    symlink(
        dots.join("git-credentials"),
        rig.home.join(".git-credentials"),
    )
    .unwrap();
    let files = || {
        (
            "SAM_TEST_FILES",
            format!(
                "{}|{}",
                s(&dots.join("git-credentials")),
                s(&rig.home.join(".git-credentials"))
            ),
        )
    };
    let (r, text) = rig.start(&PermissionSet::strict_gui(), &[files()]);
    assert_ne!(r["READ0"], "SECRET", "through the fonts: {text}");
    assert_ne!(r["READ1"], "SECRET", "through the link: {text}");
    assert!(
        text.contains("SAM does not bind ~/.fonts for this app on its own because it holds"),
        "the start says why: {text}"
    );
    fs::remove_file(rig.home.join(".git-credentials")).unwrap();
    let (r, text) = rig.start(&PermissionSet::strict_gui(), &[files()]);
    assert_eq!(
        r["READ0"], "SECRET",
        "control, a plain file in the fonts: {text}"
    );
}

/// With the home kept behind a link (`~` a link to its real folder, as
/// `/home` to `/var/home` on some systems), a private home and an extra
/// read-only `~/.config`, a credential kept as a link into the font
/// settings (`~/.git-credentials` a link to `~/.config/fontconfig/gc`)
/// stays hidden: SAM bound the settings a second time at the home's name
/// in the private home, a mount that the mask at their real place did not
/// reach, and the app read the credential at `~/.config/fontconfig/gc`.
/// The control: without the link the same file is read there.
#[test]
fn a_credential_linked_into_the_font_settings_stays_hidden_behind_a_linked_home() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("CredLinkedHome") else {
        return;
    };
    let real = rig.home.parent().unwrap().join("tester-real");
    fs::rename(&rig.home, &real).unwrap();
    symlink(&real, &rig.home).unwrap();
    let settings = rig.home.join(".config/fontconfig");
    fs::create_dir_all(real.join(".config/fontconfig")).unwrap();
    fs::write(real.join(".config/fontconfig/gc"), "SECRET").unwrap();
    let cred = real.join(".git-credentials");
    symlink(settings.join("gc"), &cred).unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_read = vec!["~/.config".into()];
    let files = || {
        (
            "SAM_TEST_FILES",
            format!(
                "{}|{}|{}",
                s(&settings.join("gc")),
                s(&rig.home.join(".git-credentials")),
                s(&real.join(".config/fontconfig/gc"))
            ),
        )
    };
    let (r, text) = rig.start(&p, &[files()]);
    assert_ne!(r["READ0"], "SECRET", "at the home's name: {text}");
    assert_ne!(r["READ1"], "SECRET", "through the link: {text}");
    assert_ne!(r["READ2"], "SECRET", "at the real place: {text}");
    assert!(
        text.contains(
            "SAM does not bind ~/.config/fontconfig for this app on its own because it holds"
        ),
        "the start says why: {text}"
    );
    fs::remove_file(&cred).unwrap();
    let (r, text) = rig.start(&p, &[files()]);
    assert_eq!(
        r["READ0"], "SECRET",
        "control, a plain file in the font settings: {text}"
    );
}

/// A link you made, in a folder the app cannot change, to fonts settings
/// that a writable folder shows: with the home read-only, `~/dotfiles` an
/// extra writable folder and `~/.config/fontconfig` a relative link to
/// `../dotfiles/fontconfig`, directly below that folder, SAM keeps that target read-only
/// where the writable folder shows it, and says so. The bind only takes
/// write access away. Without it, the app could write font rules that
/// programs outside the sandbox load. Elsewhere in `~/dotfiles` the app
/// can write, so a refused write would have been seen.
#[test]
fn a_link_you_made_into_a_writable_folder_keeps_the_font_settings_read_only() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("StowFonts") else {
        return;
    };
    let h = &rig.home;
    fs::create_dir_all(h.join("dotfiles/fontconfig")).unwrap();
    symlink("../dotfiles/fontconfig", h.join(".config/fontconfig")).unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Ro;
    p.filesystem.custom_write = vec![s(&h.join("dotfiles"))];
    let writes = format!(
        "{}|{}|{}",
        s(&h.join("dotfiles/fontconfig/x.conf")),
        s(&h.join(".config/fontconfig/y.conf")),
        s(&h.join("dotfiles/other.txt"))
    );
    let (r, text) = rig.start(&p, &[("SAM_TEST_WRITES", writes)]);
    assert_eq!(
        r["WRITE0"], "30",
        "where the writable folder shows it: {text}"
    );
    assert_ne!(r["WRITE1"], "ok", "through the link: {text}");
    assert_eq!(r["WRITE2"], "ok", "control, the writable folder: {text}");
    assert!(!h.join("dotfiles/fontconfig/x.conf").exists());
    assert!(
        text.contains("~/.config/fontconfig (a link to ~/dotfiles/fontconfig)")
            && text.contains("SAM keeps ~/dotfiles/fontconfig read-only"),
        "the start says so: {text}"
    );
}

/// GNU Stow's own layout puts the target deeper: with the home read-only,
/// `~/dotfiles` an extra writable folder and `~/.config/fontconfig` a
/// link to `../dotfiles/fontconfig/.config/fontconfig`, SAM keeps that
/// target read-only and pins the folders between it and `~/dotfiles`, so
/// the app cannot rename `~/dotfiles/fontconfig` away with the read-only
/// bind inside and write new font rules at the old place, which programs
/// outside the sandbox would load through the link. The control: a
/// folder beside it in `~/dotfiles` can be renamed. With the whole home
/// writable the app can replace the link itself, so SAM pins nothing
/// there and `~/dotfiles/fontconfig` can be renamed as before.
#[test]
fn a_folder_above_a_font_place_kept_read_only_cannot_be_renamed_away() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("StowDeep") else {
        return;
    };
    let h = &rig.home;
    fs::create_dir_all(h.join("dotfiles/fontconfig/.config/fontconfig")).unwrap();
    fs::create_dir_all(h.join("dotfiles/other")).unwrap();
    symlink(
        "../dotfiles/fontconfig/.config/fontconfig",
        h.join(".config/fontconfig"),
    )
    .unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Ro;
    p.filesystem.custom_write = vec![s(&h.join("dotfiles"))];
    let moves = format!(
        "{}>{}|{}>{}|{}>{}",
        s(&h.join("dotfiles/fontconfig")),
        s(&h.join("dotfiles/moved")),
        s(&h.join("dotfiles/fontconfig/.config")),
        s(&h.join("dotfiles/fontconfig/moved")),
        s(&h.join("dotfiles/other")),
        s(&h.join("dotfiles/other2")),
    );
    let writes = s(&h.join("dotfiles/fontconfig/.config/fontconfig/fonts.conf"));
    let (r, text) = rig.start(
        &p,
        &[("SAM_TEST_MOVES", moves), ("SAM_TEST_WRITES", writes)],
    );
    assert_eq!(r["MOVE0"], "16", "the top folder stays: {text}");
    assert_eq!(r["MOVE1"], "16", "the folder between stays: {text}");
    assert_eq!(r["MOVE2"], "ok", "control, a folder beside it: {text}");
    assert_ne!(r["WRITE0"], "ok", "no new font rules: {text}");
    assert!(h.join("dotfiles/fontconfig/.config/fontconfig").is_dir());
    assert!(!h.join("dotfiles/moved").exists());
    assert!(!h
        .join("dotfiles/fontconfig/.config/fontconfig/fonts.conf")
        .exists());

    // The whole home writable: the link itself can be replaced, no pins.
    fs::rename(h.join("dotfiles/other2"), h.join("dotfiles/other")).unwrap();
    let mut whole = p.clone();
    whole.filesystem.home_access = Access::Rw;
    whole.filesystem.custom_write.clear();
    let moves = format!(
        "{}>{}",
        s(&h.join("dotfiles/fontconfig")),
        s(&h.join("dotfiles/moved"))
    );
    let (r, text) = rig.start(&whole, &[("SAM_TEST_MOVES", moves)]);
    assert_eq!(r["MOVE0"], "ok", "whole home writable, no pins: {text}");
    assert!(h.join("dotfiles/moved/.config/fontconfig").is_dir());
}

/// With the home read-only, a credential kept as a link into a fonts
/// folder (`~/.git-credentials` a link to `~/.fonts/dots/gc`) stays
/// hidden: the read-only home shows the fonts, SAM binds them read-only,
/// and the credential is hidden where its link leads after that bind.
/// The control: the font beside it is read.
#[test]
fn a_credential_linked_into_the_fonts_stays_hidden_with_a_read_only_home() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("CredRoHome") else {
        return;
    };
    let dots = rig.home.join(".fonts/dots");
    fs::create_dir_all(&dots).unwrap();
    fs::write(dots.join("gc"), "SECRET").unwrap();
    fs::write(rig.home.join(".fonts/f.txt"), "FONT").unwrap();
    symlink(dots.join("gc"), rig.home.join(".git-credentials")).unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Ro;
    let files = format!(
        "{}|{}",
        s(&dots.join("gc")),
        s(&rig.home.join(".fonts/f.txt"))
    );
    let (r, text) = rig.start(&p, &[("SAM_TEST_FILES", files)]);
    assert_ne!(r["READ0"], "SECRET", "{text}");
    assert_eq!(r["READ1"], "FONT", "control: {text}");
}

/// With the whole home read-only and `~/.fonts` a link to
/// `~/.local/share/fonts`, the app reads the fonts through the home,
/// which shows the link and where it leads. SAM does not bind `~/.fonts`
/// on its own and says so, without the advice to keep the real files
/// there: the home shows them anyway.
#[test]
fn a_linked_font_folder_is_read_through_a_read_only_home() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("RoHomeFonts") else {
        return;
    };
    let h = &rig.home;
    fs::create_dir_all(h.join(".local/share/fonts")).unwrap();
    fs::write(h.join(".local/share/fonts/a.txt"), "FONT A").unwrap();
    symlink(h.join(".local/share/fonts"), h.join(".fonts")).unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Ro;
    let (r, text) = rig.start(&p, &[("SAM_TEST_FILES", s(&h.join(".fonts/a.txt")))]);
    assert_eq!(r["READ0"], "FONT A", "{text}");
    assert!(
        text.contains("~/.fonts (a link to ~/.local/share/fonts)")
            && !text.contains("If you made the link yourself"),
        "{text}"
    );
}
