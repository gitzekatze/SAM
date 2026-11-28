//! End-to-end sandbox tests.
//!
//! Builds a probe AppImage, registers it through the full intake pipeline and
//! launches it with Bubblewrap under several profiles. The probe prints what
//! it can see from inside the sandbox. Uses a fake `$HOME`, so the real home
//! directory is never touched. Skipped when bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sam_core::permissions::*;
use sam_core::{AppState, Badge, HostInfo, Paths};
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

const PROBE: &str = r#"#!/bin/sh
echo "APPDIR=$APPDIR"
echo "APPIMAGE=$APPIMAGE"
echo "OWD=$OWD"
[ -e "$HOME/.ssh/id_ed25519" ] && echo "SECRET=visible" || echo "SECRET=hidden"
[ -e "$HOME/Documents/report.txt" ] && echo "DOCS=visible" || echo "DOCS=hidden"
( echo x > "$HOME/Documents/new.txt" ) 2>/dev/null && echo "DOCS_WRITE=yes" || echo "DOCS_WRITE=no"
touch /opt/app/x 2>/dev/null && echo "APPDIR_WRITE=yes" || echo "APPDIR_WRITE=no"
touch /usr/x 2>/dev/null && echo "USR_WRITE=yes" || echo "USR_WRITE=no"
echo "NET=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | sort | tr '\n' ',')"
echo "PASSWD=$(wc -l < /etc/passwd)"
echo "HOSTS=$(cat /etc/hosts 2>/dev/null | tr '\n' ',')"
getent hosts localhost >/dev/null 2>&1 && echo "LOCALHOST=resolves" || echo "LOCALHOST=fails"
echo "PIDS=$(ls /proc | grep -c '^[0-9]')"
echo "SUID=$(stat -c %a "$APPDIR/usr/bin/suid-tool")"
[ -S /run/dbus/system_bus_socket ] && echo "SYSBUS=yes" || echo "SYSBUS=no"
[ -r /etc/shadow ] && echo "SHADOW=readable" || echo "SHADOW=no"
echo "ETC_ADMIN=$(for f in shadow gshadow sudoers sudoers.d pam.d polkit-1 security ssh; do [ -e /etc/$f ] && printf '%s,' $f; done)"
( touch "$HOME/persist" ) 2>/dev/null && echo "HOME_WRITE=yes" || echo "HOME_WRITE=no"
[ -e /dev/dri ] && echo "GPU=yes" || echo "GPU=no"
[ -d /tmp/.X11-unix ] && [ -n "$(ls /tmp/.X11-unix 2>/dev/null)" ] && echo "X11=yes" || echo "X11=no"
echo "ESCAPE=$( [ -e "$APPDIR/usr/lib/escape" ] && echo present || echo removed)"
echo "ARGS=$*"
"#;

fn bwrap_works() -> bool {
    let host = HostInfo::probe();
    host.tools.bwrap.is_some() && sam_runner::doctor::bwrap_functional(&host).is_ok()
}

fn parse(log: &Path) -> HashMap<String, String> {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| {
            !k.is_empty()
                && k.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        })
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The tests here that set `HOME` for the whole test process take turns.
static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Inside a real sandbox, each profile shows exactly the files and services it allows.
#[test]
fn a_real_sandbox_shows_exactly_what_each_profile_allows() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts = sam_runner::contracts::guard(&[
        "bwrap-core",
        "fs-layout",
        "etc-identity-and-names",
        "sensitive-system-files",
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/id_ed25519"), "PRIVATE KEY").unwrap();
    fs::create_dir_all(home.join("Documents")).unwrap();
    fs::write(home.join("Documents/report.txt"), "hello").unwrap();
    // A fake home keeps the test away from the real one.
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Probe-2.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Probe");
    spec.apprun = PROBE.into();
    spec.categories = "Utility;".into();
    spec.files.push(FixtureFile {
        path: "usr/bin/suid-tool".into(),
        data: b"#!/bin/sh\n".to_vec(),
        mode: 0o4755,
    });
    spec.symlinks.push((
        "usr/lib/escape".into(),
        "../../../../../../etc/shadow".into(),
    ));
    build(&img, &spec).unwrap();

    let paths = Paths::rooted(&root.join("sam"));
    let app = Sam::with_paths(paths.clone()).unwrap();
    let added = app
        .add(
            &img,
            &AddOptions {
                launcher: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    let id = added.entry.id.clone();
    assert!(id.starts_with("appimage-probe-"), "{id}");
    assert_eq!(added.entry.badge(), Badge::NeedsReview);
    let launcher = added
        .entry
        .desktop_entry
        .clone()
        .expect("launcher installed");
    let launcher_text = fs::read_to_string(&launcher).unwrap();
    assert!(
        launcher_text.contains(&format!("--app-id {id} %F")),
        "desktop launcher uses the runner"
    );

    let host = HostInfo::probe();
    // The same run on every computer: not the person's display or session bus.
    let host = sam_runner::testenv::test_host(host);
    let launch = |perms: PermissionSet, args: Vec<String>| {
        let mut e = app.set_permissions(&id, perms).unwrap();
        let opts = LaunchOptions {
            args,
            quiet: true,
            owd: Some(home.clone()),
            ..Default::default()
        };
        let rec = run(&mut e, &opts, &app.config, &app.paths, &host).unwrap();
        assert!(
            rec.success,
            "launch failed: {} (log {:?})",
            rec.summary, rec.log_file
        );
        parse(rec.log_file.as_ref().unwrap())
    };

    // 1. Strict profile.
    let r = launch(PermissionSet::strict_gui(), vec![]);
    assert_eq!(r["APPDIR"], "/opt/app");
    assert_eq!(r["APPIMAGE"], "/run/sam/Probe-2.0-x86_64.AppImage");
    assert_eq!(r["SECRET"], "hidden", "private home hides ~/.ssh");
    assert_eq!(r["DOCS"], "hidden", "Documents not granted");
    assert_eq!(r["APPDIR_WRITE"], "no", "payload is read-only");
    assert_eq!(r["USR_WRITE"], "no");
    assert_eq!(r["NET"], "lo,", "network none = loopback only");
    assert_eq!(r["PASSWD"], "2", "synthetic passwd");
    // Without the network, /etc/hosts holds only the loopback names, so
    // "localhost" resolves on every distribution and nothing else leaks
    // (regression: Ubuntu resolves localhost only through /etc/hosts).
    assert_eq!(
        r["HOSTS"],
        "127.0.0.1 localhost,::1 localhost ip6-localhost ip6-loopback,"
    );
    assert_eq!(r["LOCALHOST"], "resolves");
    assert!(
        r["PIDS"].parse::<u32>().unwrap() <= 8,
        "pid namespace: {}",
        r["PIDS"]
    );
    assert_eq!(r["SUID"], "755", "setuid stripped");
    assert_eq!(r["SYSBUS"], "no", "system D-Bus denied by default");
    assert_eq!(r["SHADOW"], "no");
    // /etc/shadow is unreadable for any user, sandbox or not, so the line
    // above proves little (verification audit 2026-11-19). The system's
    // secrets and login rules are not even there inside the sandbox, while
    // on this computer they are, and some of them are readable by anyone.
    let on_host: Vec<&str> = sam_runner::contracts::LOGIN_AND_ADMIN_FILES
        .iter()
        .copied()
        .filter(|f| Path::new("/etc").join(f).exists())
        .collect();
    assert!(on_host.contains(&"shadow"), "this computer has /etc/shadow");
    assert!(
        on_host
            .iter()
            .any(|f| fs::read_dir(Path::new("/etc").join(f)).is_ok()
                || fs::File::open(Path::new("/etc").join(f)).is_ok()),
        "one of {on_host:?} is readable here, so hiding it is something the sandbox does"
    );
    assert_eq!(
        r["ETC_ADMIN"], "",
        "inside the sandbox none of {on_host:?} exists"
    );
    assert_eq!(r["HOME_WRITE"], "yes", "private home is writable");
    assert_eq!(r["GPU"], "no");
    assert_eq!(r["X11"], "no");
    assert_eq!(
        r["ESCAPE"], "removed",
        "escaping symlink removed at extraction"
    );
    assert!(
        paths.app_home(&id).join("persist").exists(),
        "private home persisted on the host"
    );
    assert!(!home.join("persist").exists(), "real home untouched");

    // 2. Documents read-only: visible but not writable.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.documents = Access::Ro;
    let r = launch(p.clone(), vec![]);
    assert_eq!(r["DOCS"], "visible");
    assert_eq!(r["DOCS_WRITE"], "no");
    assert_eq!(r["SECRET"], "hidden");

    // 3. Documents read/write.
    p.filesystem.documents = Access::Rw;
    let r = launch(p, vec![]);
    assert_eq!(r["DOCS_WRITE"], "yes");
    assert!(home.join("Documents/new.txt").exists());

    // 4. Full home read-only still masks ~/.ssh and denies writes.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Ro;
    let r = launch(p, vec![]);
    assert_eq!(r["DOCS"], "visible");
    assert_eq!(r["SECRET"], "hidden", "~/.ssh masked under full home");
    assert_eq!(r["HOME_WRITE"], "no");
    assert_eq!(r["DOCS_WRITE"], "no");

    // 5. A file opened via the launcher is granted individually.
    let opened = home.join("Documents/report.txt");
    let r = launch(
        PermissionSet::strict_gui(),
        vec![opened.display().to_string()],
    );
    assert_eq!(r["ARGS"], opened.display().to_string());

    // Preview shows the generated command.
    let e = app.resolve(&id).unwrap();
    let prep = sam_runner::launch::prepare(
        &e,
        &LaunchOptions::default(),
        &app.config,
        &app.paths,
        &host,
    )
    .unwrap();
    assert!(prep.preview().command.contains("--unshare-net"));
    drop(prep);

    // Review K-1: a start that shares the computer's network, on a kernel
    // whose Landlock fences abstract sockets (Linux 6.12, Landlock 6),
    // relies on that fence: it then counts as missing unless the helper
    // reports it in place. The kernel's Landlock version is set here, so
    // every computer checks both sides; nothing is started.
    let fence = |mode: &str, abi: u32| {
        let e = app.set_permission(&id, "network.mode", mode).unwrap();
        let mut h = host.clone();
        h.landlock_abi = Some(abi);
        let p =
            sam_runner::launch::prepare(&e, &LaunchOptions::default(), &app.config, &app.paths, &h)
                .unwrap();
        (p.wanted_landlock, p.wanted_fence)
    };
    assert_eq!(fence("full", 6), (true, true), "full network");
    assert_eq!(fence("full", 5), (true, false), "a kernel without it");
    assert_eq!(fence("none", 6), (true, false), "no network");
    assert_eq!(fence("localhost", 6), (true, false), "a network of its own");

    // Staleness: customize the profile, then modify the source.
    app.set_permission(&id, "filesystem.music", "ro").unwrap();
    let mut data = fs::read(&img).unwrap();
    data.extend_from_slice(b"update");
    fs::write(&img, &data).unwrap();
    let items = app.refresh(Some(&id), false).unwrap();
    assert_eq!(items[0].status, "stale");
    assert_eq!(app.resolve(&id).unwrap().state, AppState::Stale);
    // Re-extract keeps the user-modified profile.
    let e = app.reextract(&id, false).unwrap();
    assert!(e.profile.user_modified);
    assert_eq!(e.state, AppState::Ready);
    // The file was changed outside SAM: marked until confirmed, also after
    // the change check (audit U-H2).
    assert!(e.content_changed_outside);
    app.mark_reviewed(&id).unwrap();

    // Missing source.
    fs::remove_file(&img).unwrap();
    app.refresh(None, false).unwrap();
    assert_eq!(app.resolve(&id).unwrap().badge(), Badge::Missing);

    // Removal cleans everything up.
    app.remove(&id, false).unwrap();
    assert!(!launcher.exists(), "launcher removed");
    assert!(!paths.app_home(&id).exists());
    assert!(app.registry().list().unwrap().is_empty());
}

/// Inside a real sandbox, the host tools that ask a service outside it to
/// start a program (`systemd-run`, `flatpak-spawn`) are SAM's stand-ins:
/// `flatpak-spawn` refuses, `systemd-run` runs the command right there,
/// also where the tool is a link (contract host-escape-tools; audit D-M10:
/// nothing ran `flatpak-spawn` inside a sandbox). CI machines have no
/// `flatpak-spawn`, so the "host tools" here are programs of the test, in
/// a folder of its own, that print ESCAPED when they run; SAM covers them
/// with the same arguments it gives every sandbox for the real ones.
#[test]
fn host_tools_that_start_programs_outside_meet_their_stand_ins() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "host-escape-tools"])
        .unwrap_or_else(|e| panic!("{e}"));
    use std::os::unix::fs::PermissionsExt;
    // Every tool SAM covers in its sandboxes gets a stand-in here.
    let names: Vec<&str> = sam_sandbox::HIDDEN_HOST_TOOLS
        .iter()
        .map(|t| t.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(names, ["systemd-run", "flatpak-spawn"]);
    let tmp = tempfile::tempdir().unwrap();
    let (bin, lib) = (
        tmp.path().join("usr/bin"),
        tmp.path().join("usr/lib/systemd"),
    );
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&lib).unwrap();
    let real = "#!/bin/sh\necho ESCAPED\n";
    // systemd-run as a link, as some distributions install it.
    fs::write(lib.join("systemd-run"), real).unwrap();
    std::os::unix::fs::symlink("../lib/systemd/systemd-run", bin.join("systemd-run")).unwrap();
    fs::write(bin.join("flatpak-spawn"), real).unwrap();
    for f in [lib.join("systemd-run"), bin.join("flatpak-spawn")] {
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let tools: Vec<String> = names
        .iter()
        .map(|n| bin.join(n).display().to_string())
        .collect();
    let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
    // The control: outside a sandbox the "host tools" run.
    for t in &tools {
        let out = Command::new(t).output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "ESCAPED",
            "{t}"
        );
    }

    // SAM's stand-ins, as every start writes them, and its arguments.
    let mut ctx = sam_core::sandbox::sample_context();
    ctx.runtime_dir = tmp.path().join("run");
    sam_sandbox::write_identity_files(&ctx).unwrap();
    let cover = sam_sandbox::host_tool_stand_in_args(&ctx.runtime_dir, &tools);
    let inside = |cmd: &[&str]| {
        Command::new("bwrap")
            .args(["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"])
            .args(["--unshare-all", "--die-with-parent"])
            .args(&cover)
            .arg("--")
            .args(cmd)
            .output()
            .unwrap()
    };
    let spawn = inside(&[tools[1], "--host", "sh", "-c", "echo ESCAPED"]);
    let (stdout, stderr) = (
        String::from_utf8_lossy(&spawn.stdout),
        String::from_utf8_lossy(&spawn.stderr),
    );
    assert!(
        !spawn.status.success(),
        "flatpak-spawn refuses: {stdout} {stderr}"
    );
    assert!(
        stderr.contains("flatpak-spawn: not available in SAM's sandbox") && stdout.is_empty(),
        "the stand-in answered: {stdout} {stderr}"
    );
    let run = inside(&[
        tools[0],
        "--user",
        "--scope",
        "--unit=x.scope",
        "sh",
        "-c",
        "echo ran",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&run.stdout).trim(),
        "ran",
        "systemd-run runs the command in the sandbox: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// The probe of [`a_read_only_user_folder_outside_the_home_is_shown_with_the_whole_home`]:
/// it finds Documents as apps do, in `user-dirs.dirs`, reads a file there
/// and adds one.
const OUTSIDE_PROBE: &str = r#"#!/bin/sh
. "$HOME/.config/user-dirs.dirs"
D="$XDG_DOCUMENTS_DIR"
echo "DOCS_AT=$D"
grep -q hello "$D/report.txt" 2>/dev/null && echo DOCS_READ=yes || echo DOCS_READ=no
( echo x > "$D/new.txt" ) 2>/dev/null && echo DOCS_WRITE=yes || echo DOCS_WRITE=no
echo END=1
"#;

/// A user folder outside the home (`XDG_DOCUMENTS_DIR=/data/Documents`) is
/// shown at its own access with the whole home granted, read-only or
/// writable, the home read-only or writable: inside a real sandbox the app
/// reads it, writes there only when it is set to read and write, and a
/// read-only one stays as it was on the host. Before, with the whole home
/// granted no user folder outside it was bound, so the app saw nothing of
/// what the person had granted.
#[test]
fn a_read_only_user_folder_outside_the_home_is_shown_with_the_whole_home() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    let docs = root.join("data/Documents");
    fs::create_dir_all(&docs).unwrap();
    fs::create_dir_all(home.join(".config")).unwrap();
    fs::write(docs.join("report.txt"), "hello\n").unwrap();
    fs::write(
        home.join(".config/user-dirs.dirs"),
        format!("XDG_DOCUMENTS_DIR=\"{}\"\n", docs.display()),
    )
    .unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Outside-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Outside");
    spec.apprun = OUTSIDE_PROBE.into();
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
    let host = sam_runner::testenv::test_host(HostInfo::probe());
    assert_eq!(
        host.xdg_dir("documents"),
        Some(docs.as_path()),
        "the test's own"
    );
    for home_access in [Access::Rw, Access::Ro] {
        for documents in [Access::Ro, Access::Rw] {
            let mut p = PermissionSet::strict_gui();
            p.filesystem.home = true;
            p.filesystem.home_access = home_access;
            p.filesystem.documents = documents;
            let mut e = app.set_permissions(&id, p).unwrap();
            let opts = LaunchOptions {
                quiet: true,
                owd: Some(home.clone()),
                ..Default::default()
            };
            let rec = run(&mut e, &opts, &app.config, &app.paths, &host).unwrap();
            assert!(rec.success, "launch failed: {}", rec.summary);
            let r = parse(rec.log_file.as_ref().unwrap());
            let case = format!("{home_access:?} home, {documents:?} Documents: {r:?}");
            assert_eq!(r.get("END").map(String::as_str), Some("1"), "{case}");
            assert_eq!(r["DOCS_AT"], docs.display().to_string(), "{case}");
            assert_eq!(r["DOCS_READ"], "yes", "{case}");
            let rw = documents == Access::Rw;
            assert_eq!(r["DOCS_WRITE"], if rw { "yes" } else { "no" }, "{case}");
            assert_eq!(docs.join("new.txt").is_file(), rw, "{case}");
            let _ = fs::remove_file(docs.join("new.txt"));
            assert_eq!(
                fs::read_to_string(docs.join("report.txt")).unwrap(),
                "hello\n",
                "{case}"
            );
        }
    }
}

/// The probe of [`a_user_folder_link_the_app_planted_never_shows_where_it_leads`]:
/// told to (`plant PLACE`), it turns Downloads into a link to `PLACE`, as
/// an app with the whole home writable can; otherwise it reads and writes
/// through Downloads.
const PLANT_PROBE: &str = r#"#!/bin/sh
H="$HOME"
if [ "$1" = plant ]; then
  mv "$H/Downloads" "$H/D" 2>/dev/null && ln -s "$2" "$H/Downloads" 2>/dev/null && echo PLANTED=yes || echo PLANTED=no
fi
grep -q secret "$H/Downloads/secret.txt" 2>/dev/null && echo READ=yes || echo READ=no
( echo x > "$H/Downloads/new.txt" ) 2>/dev/null && echo WRITE=yes || echo WRITE=no
echo END=1
"#;

/// An app with the whole home writable and Downloads granted turns
/// `~/Downloads` into a link to a folder outside the home that it was never
/// shown (in one start). In the next start, SAM does not show where the
/// link leads: the app can neither read nor write there. Before, SAM followed the link and bound the place,
/// any place on the computer the app chose (also the host's `/tmp`, with
/// the sockets of programs outside the sandbox).
#[test]
fn a_user_folder_link_the_app_planted_never_shows_where_it_leads() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    let secret = root.join("data/secret");
    fs::create_dir_all(home.join("Downloads")).unwrap();
    fs::create_dir_all(&secret).unwrap();
    fs::create_dir_all(home.join(".config")).unwrap();
    fs::write(secret.join("secret.txt"), "secret\n").unwrap();
    fs::write(
        home.join(".config/user-dirs.dirs"),
        "XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n",
    )
    .unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Plant-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Plant");
    spec.apprun = PLANT_PROBE.into();
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
    let host = sam_runner::testenv::test_host(HostInfo::probe());
    assert_eq!(
        host.xdg_dir("downloads"),
        Some(home.join("Downloads").as_path()),
        "the test's own"
    );
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.downloads = Access::Rw;
    let start = |args: &[&str]| {
        let mut e = app.set_permissions(&id, p.clone()).unwrap();
        let opts = LaunchOptions {
            args: args.iter().map(|a| a.to_string()).collect(),
            quiet: true,
            owd: Some(home.clone()),
            ..Default::default()
        };
        let rec = run(&mut e, &opts, &app.config, &app.paths, &host).unwrap();
        assert!(rec.success, "launch failed: {}", rec.summary);
        let r = parse(rec.log_file.as_ref().unwrap());
        assert_eq!(r.get("END").map(String::as_str), Some("1"), "{r:?}");
        r
    };
    let secret_text = secret.to_string_lossy().into_owned();
    let r = start(&["plant", &secret_text]);
    assert_eq!(r["PLANTED"], "yes", "the writable home lets it: {r:?}");
    assert_eq!(r["READ"], "no", "not shown in the same start: {r:?}");
    assert!(fs::symlink_metadata(home.join("Downloads"))
        .unwrap()
        .file_type()
        .is_symlink());

    let r = start(&[]);
    assert_eq!(r["READ"], "no", "{r:?}");
    assert_eq!(r["WRITE"], "no", "{r:?}");
    assert!(!secret.join("new.txt").exists());
}

/// The probe of [`a_link_planted_inside_a_refused_read_only_folder_is_never_followed`],
/// [`the_folders_above_a_read_only_user_folder_cannot_be_renamed`],
/// [`the_font_folders_stay_read_only_around_an_extra_folder_inside`] and
/// [`a_linked_start_file_inside_a_writable_folder_in_the_fonts_stays_pinned`]:
/// told to (`plant PLACE`), it turns Downloads, found as apps find it, into
/// a link to `PLACE`; told to (`rename`), it tries to rename the folders
/// above the read-only ones and writes inside them; told to (`fonts`), it
/// writes into the font folders; told to (`fontwork`), it tries to rename
/// the folder in `~/.fonts/work` where a start file is kept and writes
/// there and into `~/.fonts`; otherwise it reads and writes through
/// Downloads.
const FOLDER_PROBE: &str = r#"#!/bin/sh
. "$HOME/.config/user-dirs.dirs"
D="$XDG_DOWNLOAD_DIR"
if [ "$1" = plant ]; then
  mv "$D" "$HOME/x" 2>/dev/null && ln -s "$2" "$D" 2>/dev/null && echo PLANTED=yes || echo PLANTED=no
fi
if [ "$1" = rename ]; then
  mv "$HOME/Sync" "$HOME/S2" 2>/dev/null && echo SYNC_MOVED=yes || echo SYNC_MOVED=no
  mv "$HOME/work" "$HOME/w2" 2>/dev/null && echo WORK_MOVED=yes || echo WORK_MOVED=no
  ( echo x > "$HOME/Sync/Documents/proj/new.txt" ) 2>/dev/null && echo PROJ_WRITE=yes || echo PROJ_WRITE=no
  ( echo x > "$HOME/Sync/Documents/new.txt" ) 2>/dev/null && echo DOCS_WRITE=yes || echo DOCS_WRITE=no
fi
if [ "$1" = fonts ]; then
  ( echo x > "$HOME/.fonts/new.txt" ) 2>/dev/null && echo FONTS_WRITE=yes || echo FONTS_WRITE=no
  ( echo x > "$HOME/.local/share/fonts/a/new.txt" ) 2>/dev/null && echo SHARE_FONTS_WRITE=yes || echo SHARE_FONTS_WRITE=no
  ( echo x > "$HOME/new.txt" ) 2>/dev/null && echo HOME_WRITE=yes || echo HOME_WRITE=no
fi
if [ "$1" = fontwork ]; then
  mv "$HOME/.fonts/work/dots" "$HOME/.fonts/work/d2" 2>/dev/null && echo DOTS_MOVED=yes || echo DOTS_MOVED=no
  ( echo x > "$HOME/.fonts/work/new.txt" ) 2>/dev/null && echo WORK_WRITE=yes || echo WORK_WRITE=no
  ( echo x > "$HOME/.fonts/new.txt" ) 2>/dev/null && echo FONTS_WRITE=yes || echo FONTS_WRITE=no
fi
grep -q secret "$D/secret.txt" 2>/dev/null && echo READ=yes || echo READ=no
( echo x > "$D/new.txt" ) 2>/dev/null && echo WRITE=yes || echo WRITE=no
echo END=1
"#;

/// Starts the app `id` of `app` with the permissions `p` and the arguments
/// `args`, and returns what its probe printed.
fn start_probe(
    app: &Sam,
    id: &str,
    p: &PermissionSet,
    home: &Path,
    host: &HostInfo,
    args: &[&str],
) -> HashMap<String, String> {
    let mut e = app.set_permissions(id, p.clone()).unwrap();
    let opts = LaunchOptions {
        args: args.iter().map(|a| a.to_string()).collect(),
        quiet: true,
        owd: Some(home.to_path_buf()),
        ..Default::default()
    };
    let rec = run(&mut e, &opts, &app.config, &app.paths, host).unwrap();
    assert!(rec.success, "launch failed: {}", rec.summary);
    let r = parse(rec.log_file.as_ref().unwrap());
    assert_eq!(r.get("END").map(String::as_str), Some("1"), "{r:?}");
    r
}

/// Sets up a test home at `root/home/tester` with `user-dirs.dirs` holding
/// `dirs`, and adds the folder probe as an app; returns SAM, the app's id,
/// the home and the host.
fn folder_probe_app(root: &Path, name: &str, dirs: &str) -> (Sam, String, PathBuf, HostInfo) {
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    fs::create_dir_all(home.join(".config")).unwrap();
    fs::write(home.join(".config/user-dirs.dirs"), dirs).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    let img = root.join(format!("{name}-1.0-x86_64.AppImage"));
    let mut spec = FixtureSpec::hello(name);
    spec.apprun = FOLDER_PROBE.into();
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
    let host = sam_runner::testenv::test_host(HostInfo::probe());
    (app, id, home, host)
}

/// With the whole home writable, Documents read-only but itself a link in
/// the home (`~/Documents` to `~/Dropbox/Documents`, so SAM does not mount
/// it) and Downloads read and write inside it, an app turns Downloads into
/// a link to a folder outside the home that it was never shown. In the
/// next start, SAM does not show where the link leads: the app can neither
/// read nor write there. Before, SAM took the link's folder for read-only
/// and bound the place writable (review of finding R63).
#[test]
fn a_link_planted_inside_a_refused_read_only_folder_is_never_followed() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let secret = root.join("data/secret");
    fs::create_dir_all(&secret).unwrap();
    fs::write(secret.join("secret.txt"), "secret\n").unwrap();
    let (app, id, home, host) = folder_probe_app(
        root,
        "PlantIn",
        "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\nXDG_DOWNLOAD_DIR=\"$HOME/Dropbox/Documents/Downloads\"\n",
    );
    let downloads = home.join("Dropbox/Documents/Downloads");
    fs::create_dir_all(&downloads).unwrap();
    std::os::unix::fs::symlink(home.join("Dropbox/Documents"), home.join("Documents")).unwrap();
    assert_eq!(
        host.xdg_dir("downloads"),
        Some(downloads.as_path()),
        "the test's own"
    );
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.documents = Access::Ro;
    p.filesystem.downloads = Access::Rw;
    let secret_text = secret.to_string_lossy().into_owned();
    let r = start_probe(&app, &id, &p, &home, &host, &["plant", &secret_text]);
    assert_eq!(r["PLANTED"], "yes", "the writable home lets it: {r:?}");
    assert!(fs::symlink_metadata(&downloads)
        .unwrap()
        .file_type()
        .is_symlink());
    let r = start_probe(&app, &id, &p, &home, &host, &[]);
    assert_eq!(r["READ"], "no", "{r:?}");
    assert_eq!(r["WRITE"], "no", "{r:?}");
    assert!(!secret.join("new.txt").exists());
}

/// [`start_probe`], with the start's launch log as well, which holds its
/// notes.
fn start_probe_log(
    app: &Sam,
    id: &str,
    p: &PermissionSet,
    home: &Path,
    host: &HostInfo,
    args: &[&str],
) -> (HashMap<String, String>, String) {
    let mut e = app.set_permissions(id, p.clone()).unwrap();
    let opts = LaunchOptions {
        args: args.iter().map(|a| a.to_string()).collect(),
        quiet: true,
        owd: Some(home.to_path_buf()),
        ..Default::default()
    };
    let rec = run(&mut e, &opts, &app.config, &app.paths, host).unwrap();
    assert!(rec.success, "launch failed: {}", rec.summary);
    let log = rec.log_file.clone().unwrap();
    let text = fs::read_to_string(&log).unwrap_or_default();
    let r = parse(&log);
    assert_eq!(r.get("END").map(String::as_str), Some("1"), "{r:?}\n{text}");
    (r, text)
}

/// A folder outside `/tmp` and `/var/tmp` (in the build's own scratch
/// folder) for the place a planted link leads to: anything in `/tmp`
/// counts as a place where programs outside the sandbox listen, which
/// leaves it out whoever made the link, so only there the rule for links
/// the app could have planted is what keeps it out.
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

/// [`a_user_folder_link_the_app_planted_never_shows_where_it_leads`] with
/// the place the link leads to outside `/tmp`, so the rule for links the
/// app could have planted keeps it out, not the rule for places where
/// programs outside the sandbox listen: the app can neither read nor
/// write there, and the start says the app may have made that link.
#[test]
fn a_user_folder_link_the_app_planted_outside_tmp_never_shows_where_it_leads() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let scratch = outside_tmp();
    let secret = fs::canonicalize(scratch.path()).unwrap().join("secret");
    fs::create_dir_all(&secret).unwrap();
    fs::write(secret.join("secret.txt"), "secret\n").unwrap();
    let (app, id, home, host) =
        folder_probe_app(root, "PlantOut", "XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n");
    let downloads = home.join("Downloads");
    fs::create_dir_all(&downloads).unwrap();
    assert_eq!(
        host.xdg_dir("downloads"),
        Some(downloads.as_path()),
        "the test's own"
    );
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.downloads = Access::Rw;
    let secret_text = secret.to_string_lossy().into_owned();
    let (r, text) = start_probe_log(&app, &id, &p, &home, &host, &["plant", &secret_text]);
    assert_eq!(r["PLANTED"], "yes", "the writable home lets it: {text}");
    assert!(fs::symlink_metadata(&downloads)
        .unwrap()
        .file_type()
        .is_symlink());
    let (r, text) = start_probe_log(&app, &id, &p, &home, &host, &[]);
    assert_eq!(r["READ"], "no", "{text}");
    assert_eq!(r["WRITE"], "no", "{text}");
    assert!(!secret.join("new.txt").exists());
    assert!(
        text.contains(
            "# note: SAM leaves out the writable user folder ~/Downloads for this app because the way there leads through the link ~/Downloads"
        ) && text.contains("may have made that link"),
        "the start gives the planted-link reason: {text}"
    );
}

/// [`a_link_planted_inside_a_refused_read_only_folder_is_never_followed`]
/// with the place the link leads to outside `/tmp`, so the rule for links
/// the app could have planted keeps it out, not the rule for places where
/// programs outside the sandbox listen: the app can neither read nor
/// write there, and the start says the app may have made that link.
#[test]
fn a_link_planted_inside_a_refused_read_only_folder_outside_tmp_is_never_followed() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let scratch = outside_tmp();
    let secret = fs::canonicalize(scratch.path()).unwrap().join("secret");
    fs::create_dir_all(&secret).unwrap();
    fs::write(secret.join("secret.txt"), "secret\n").unwrap();
    let (app, id, home, host) = folder_probe_app(
        root,
        "PlantInOut",
        "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\nXDG_DOWNLOAD_DIR=\"$HOME/Dropbox/Documents/Downloads\"\n",
    );
    let downloads = home.join("Dropbox/Documents/Downloads");
    fs::create_dir_all(&downloads).unwrap();
    std::os::unix::fs::symlink(home.join("Dropbox/Documents"), home.join("Documents")).unwrap();
    assert_eq!(
        host.xdg_dir("downloads"),
        Some(downloads.as_path()),
        "the test's own"
    );
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.documents = Access::Ro;
    p.filesystem.downloads = Access::Rw;
    let secret_text = secret.to_string_lossy().into_owned();
    let (r, text) = start_probe_log(&app, &id, &p, &home, &host, &["plant", &secret_text]);
    assert_eq!(r["PLANTED"], "yes", "the writable home lets it: {text}");
    assert!(fs::symlink_metadata(&downloads)
        .unwrap()
        .file_type()
        .is_symlink());
    let (r, text) = start_probe_log(&app, &id, &p, &home, &host, &[]);
    assert_eq!(r["READ"], "no", "{text}");
    assert_eq!(r["WRITE"], "no", "{text}");
    assert!(!secret.join("new.txt").exists());
    assert!(
        text.contains(
            "# note: SAM leaves out the writable user folder ~/Dropbox/Documents/Downloads for this app because the way there leads through the link ~/Dropbox/Documents/Downloads"
        ) && text.contains("may have made that link"),
        "the start gives the planted-link reason: {text}"
    );
}

/// With the whole home writable, Documents read-only in `~/Sync`, an extra
/// writable folder inside it and an extra read-only folder in `~/work`,
/// the app can rename neither `~/Sync` nor `~/work`: each is a mount point
/// of its own. A second start of the app with these permissions could
/// otherwise rename one, which carries the read-only mount along, and put
/// a link in its place while SAM starts the app again, so that start bound
/// where the link led (review of finding R63). The extra writable folder
/// stays writable, Documents read-only.
#[test]
fn the_folders_above_a_read_only_user_folder_cannot_be_renamed() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (app, id, home, host) = folder_probe_app(
        root,
        "Rename",
        "XDG_DOCUMENTS_DIR=\"$HOME/Sync/Documents\"\n",
    );
    for d in ["Sync/Documents/proj", "work/ref"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    let st = |p: &Path| p.to_string_lossy().into_owned();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.documents = Access::Ro;
    p.filesystem.custom_read = vec![st(&home.join("work/ref"))];
    p.filesystem.custom_write = vec![st(&home.join("Sync/Documents/proj"))];
    let r = start_probe(&app, &id, &p, &home, &host, &["rename"]);
    assert_eq!(r["SYNC_MOVED"], "no", "{r:?}");
    assert_eq!(r["WORK_MOVED"], "no", "{r:?}");
    assert_eq!(r["PROJ_WRITE"], "yes", "{r:?}");
    assert_eq!(r["DOCS_WRITE"], "no", "{r:?}");
    assert!(home.join("Sync/Documents/proj/new.txt").is_file());
    assert!(!home.join("Sync/Documents/new.txt").exists());
    assert!(home.join("work/ref").is_dir() && !home.join("w2").exists());
}

/// With the whole home writable and an extra read-only folder inside each
/// font folder (`~/.fonts/licensed`, `~/.local/share/fonts/a/licensed`),
/// the font folders stay read-only, as SAM always binds them: the pins of
/// the folders above a read-only extra folder (review of finding R63) once
/// bound `~/.fonts` writable after its read-only bind. The home stays
/// writable.
/// Here both font folders are real folders: SAM binds a font place only
/// where neither it nor a folder on its way in the home is a link.
#[test]
fn the_font_folders_stay_read_only_around_an_extra_folder_inside() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (app, id, home, host) = folder_probe_app(root, "Fonts", "");
    for d in [".fonts/licensed", ".local/share/fonts/a/licensed"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    let st = |p: &Path| p.to_string_lossy().into_owned();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.custom_read = vec![
        st(&home.join(".fonts/licensed")),
        st(&home.join(".local/share/fonts/a/licensed")),
    ];
    let r = start_probe(&app, &id, &p, &home, &host, &["fonts"]);
    assert_eq!(r["FONTS_WRITE"], "no", "{r:?}");
    assert_eq!(r["SHARE_FONTS_WRITE"], "no", "{r:?}");
    assert_eq!(r["HOME_WRITE"], "yes", "{r:?}");
    assert!(!home.join(".fonts/new.txt").exists());
    assert!(!home.join(".local/share/fonts/a/new.txt").exists());
}

/// With the whole home writable, `~/.fonts` an extra read-only folder, an
/// extra writable folder inside it (`~/.fonts/work`) and `~/.bashrc` kept
/// as a link to `~/.fonts/work/dots/bashrc`, the app cannot rename `dots`:
/// it is a mount point of its own, so the guard of the start file stays
/// where the link leads (review B2 S3, R50). Skipped on or inside the
/// whole font folder, that pin was lost, and the app could rename `dots`
/// away with the guard and put a start file of its own where the link
/// leads. The writable folder stays writable, the font folder read-only.
#[test]
fn a_linked_start_file_inside_a_writable_folder_in_the_fonts_stays_pinned() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (app, id, home, host) = folder_probe_app(root, "FontWork", "");
    let dots = home.join(".fonts/work/dots");
    fs::create_dir_all(&dots).unwrap();
    fs::write(dots.join("bashrc"), "").unwrap();
    std::os::unix::fs::symlink(".fonts/work/dots/bashrc", home.join(".bashrc")).unwrap();
    let st = |p: &Path| p.to_string_lossy().into_owned();
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    p.filesystem.custom_read = vec![st(&home.join(".fonts"))];
    p.filesystem.custom_write = vec![st(&home.join(".fonts/work"))];
    let r = start_probe(&app, &id, &p, &home, &host, &["fontwork"]);
    assert_eq!(r["DOTS_MOVED"], "no", "{r:?}");
    assert_eq!(r["WORK_WRITE"], "yes", "{r:?}");
    assert_eq!(r["FONTS_WRITE"], "no", "{r:?}");
    assert!(dots.join("bashrc").is_file() && !home.join(".fonts/work/d2").exists());
    assert!(home.join(".fonts/work/new.txt").is_file());
    assert!(!home.join(".fonts/new.txt").exists());
}
