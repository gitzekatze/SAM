//! The places SAM shows an app from your home on its own (your fonts, the
//! fonts settings) and the extra read-only folders are never followed
//! through a link to a place the app must not reach, attacked from inside
//! a real sandbox.
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
//! - a link in a folder the app can change that leads out of what the app
//!   is shown is not followed (the app may have made it);
//! - a link that leads to a place where programs outside the sandbox
//!   listen is not followed, whoever made it: also a socket directly in
//!   `/tmp`, a socket folder there by any name, and the host's runtime
//!   folder kept outside `/run` and `/tmp`;
//! - a read-only grant the app made lead into a folder it can change
//!   does not hide a link it planted there;
//! - a link that leads from a fonts place to your keys is not followed;
//! - a user folder reached through a link the app planted is not bound;
//! - a writable extra folder the app made a link to a read-only home does
//!   not make the home writable.
//!
//! Controls: ordinary fonts folders and links that stay inside what the
//! app is shown still work, and an extra folder you list by its real
//! place in `/tmp` is still passed in, so a connection would have been
//! seen.
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
/// `SAM_TEST_SOCKETS`, read every file in `SAM_TEST_FILES` and create
/// every file in `SAM_TEST_WRITES` (each list split by `|`), saying for
/// each what happened.
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
/// the link.
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

/// Each rule on its own, for `~/.fonts`:
/// - with the whole home writable, a link to a folder outside the home
///   that the app is not shown (the app may have made it) is not
///   followed;
/// - in a private home, a link to a socket folder in `/tmp` (another
///   program made it; the app cannot change the home) is not followed;
/// - in a private home, a link to your SSH keys is not followed.
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
        text.contains("may have made that link"),
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
/// is, `~/.fonts` a link you made to `~/myfonts`, and an extra read-only
/// folder. With the whole home writable: `~/.fonts` a link to
/// `~/.local/share/fonts`, which the home shows anyway.
#[test]
fn ordinary_font_folders_and_links_inside_the_home_still_work() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rig) = Rig::new("Ordinary") else {
        return;
    };
    let h = &rig.home;
    for d in [".local/share/fonts", "myfonts", "notes"] {
        fs::create_dir_all(h.join(d)).unwrap();
    }
    fs::write(h.join(".local/share/fonts/a.txt"), "FONT A").unwrap();
    fs::write(h.join("myfonts/b.txt"), "FONT B").unwrap();
    fs::write(h.join("notes/n.txt"), "NOTE").unwrap();
    symlink(h.join("myfonts"), h.join(".fonts")).unwrap();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.custom_read = vec![s(&h.join("notes"))];
    let files = format!(
        "{}|{}|{}",
        s(&h.join(".local/share/fonts/a.txt")),
        s(&h.join(".fonts/b.txt")),
        s(&h.join("notes/n.txt"))
    );
    let (r, text) = rig.start(&p, &[("SAM_TEST_FILES", files)]);
    assert_eq!(r["READ0"], "FONT A", "{text}");
    assert_eq!(r["READ1"], "FONT B", "{text}");
    assert_eq!(r["READ2"], "NOTE", "{text}");

    fs::remove_file(h.join(".fonts")).unwrap();
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
/// through the link: the read-only home stays read-only.
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
}

/// With the whole home writable and Downloads set read-only, the sandbox
/// shows Downloads through the home, writable: the app makes an extra
/// read-only folder in it, not made yet, a link to a folder outside the
/// home in one start, and in the next start it reads nothing there,
/// neither where the link leads nor through the link.
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
    let (r, text) = rig.start(
        &p,
        &[
            ("SAM_TEST_STEP", "plant".into()),
            ("SAM_TEST_LINK", s(&place)),
            ("SAM_TEST_TARGET", s(&outside)),
        ],
    );
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
/// a link to `~/.local/share` and `~/.local/share/fonts` a link to a
/// folder it is not shown, in one start. In the next start with the same
/// permissions it reads nothing there, neither where the link leads nor
/// through the fonts folder, and the start says why (before, `~/x`
/// counted `~/.local/share` as a folder the app cannot change, and SAM
/// bound the folder as the fonts).
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
    let fonts = share.join("fonts");
    let mut p = whole_home_writable();
    p.filesystem.custom_read = vec![s(&x)];
    let (r, text) = rig.start(
        &p,
        &[
            ("SAM_TEST_STEP", "plant".into()),
            ("SAM_TEST_LINK", format!("{}|{}", s(&fonts), s(&x))),
            ("SAM_TEST_TARGET", format!("{}|{}", s(&secret), s(&share))),
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
                "{}|{}|{}",
                s(&secret.join("secret.txt")),
                s(&fonts.join("secret.txt")),
                s(&x.join("fonts/secret.txt"))
            ),
        )],
    );
    assert_ne!(r["READ0"], "SECRET", "{text}");
    assert_ne!(r["READ1"], "SECRET", "{text}");
    assert_ne!(r["READ2"], "SECRET", "{text}");
    assert!(
        text.contains("may have made that link"),
        "the start says why: {text}"
    );
}

/// A link nobody in the sandbox could have planted (`~/.fonts` in a
/// private home) never reaches a place where programs outside the
/// sandbox listen, by any name: a socket directly in `/tmp` (as
/// PostgreSQL keeps its own), a socket folder in `/tmp` by a name no list
/// knows (`tmate-…`), and the host's runtime folder kept outside `/run`
/// and `/tmp` (as `/mnt/wslg/runtime-dir`). The app reaches the socket
/// neither through the link nor at its own place, and the start says why.
#[test]
fn a_font_folder_link_never_reaches_sockets_by_any_name() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut rig) = Rig::new("AnyName") else {
        return;
    };
    let fonts = rig.home.join(".fonts");
    let private = PermissionSet::strict_gui();
    let attempt = |rig: &Rig, socket: &Path, through_link: &Path, reached: &dyn Fn() -> bool| {
        let (r, text) = rig.start(
            &private,
            &[(
                "SAM_TEST_SOCKETS",
                format!("{}|{}", s(through_link), s(socket)),
            )],
        );
        assert_ne!(r["CONNECT0"], "ok", "through the link: {text}");
        assert_ne!(r["CONNECT1"], "ok", "at its own place: {text}");
        assert!(
            !reached(),
            "a program outside the sandbox was reached: {text}"
        );
        assert!(
            text.contains("where programs outside the sandbox listen"),
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
    symlink(&socket, &fonts).unwrap();
    let reached = || {
        let mut any = false;
        while listener.accept().is_ok() {
            any = true;
        }
        any
    };
    attempt(&rig, &socket, &fonts, &reached);
    drop(listener);
    let _ = fs::remove_file(&socket);

    // A socket folder in `/tmp` by a name no list knows.
    let tmate = SocketFolder::at(Path::new("/tmp"), "tmate-");
    fs::remove_file(&fonts).unwrap();
    symlink(tmate.path(), &fonts).unwrap();
    attempt(
        &rig,
        Path::new(&tmate.socket()),
        &fonts.join("default"),
        &|| tmate.was_reached(),
    );

    // The host's runtime folder, kept outside `/run` and `/tmp`.
    let scratch = outside_tmp();
    let runtime = SocketFolder::at(scratch.path(), "runtime-dir-");
    rig.host.runtime_dir = Some(runtime.path());
    fs::remove_file(&fonts).unwrap();
    symlink(runtime.path(), &fonts).unwrap();
    attempt(
        &rig,
        Path::new(&runtime.socket()),
        &fonts.join("default"),
        &|| runtime.was_reached(),
    );
}

/// Where the way ends is not all: a link in `/tmp` made outside the
/// sandbox may send it on to a socket folder SAM does not know by its
/// place (on WSLg the host's `/tmp/.X11-unix` is a link to
/// `/mnt/wslg/.X11-unix`). `~/.fonts` in a private home, a link to such a
/// link in `/tmp` whose socket folder lies outside `/tmp`, `/run` and the
/// runtime folders: the app reaches the socket neither through the link
/// nor at its own place, and the start says why (before, SAM judged only
/// the folder at the end and bound it as the fonts).
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
    let fonts = rig.home.join(".fonts");
    symlink(&hop, &fonts).unwrap();
    let (r, text) = rig.start(
        &PermissionSet::strict_gui(),
        &[(
            "SAM_TEST_SOCKETS",
            format!("{}|{}", s(&fonts.join("default")), x11.socket()),
        )],
    );
    let _ = fs::remove_file(&hop);
    assert_ne!(r["CONNECT0"], "ok", "through the link: {text}");
    assert_ne!(r["CONNECT1"], "ok", "at its own place: {text}");
    assert!(
        !x11.was_reached(),
        "a program outside the sandbox was reached: {text}"
    );
    assert!(
        text.contains("where programs outside the sandbox listen"),
        "the start says why: {text}"
    );
}
