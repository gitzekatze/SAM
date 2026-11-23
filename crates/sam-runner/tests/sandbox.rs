//! End-to-end sandbox tests.
//!
//! Builds a probe AppImage, registers it through the full intake pipeline and
//! launches it with Bubblewrap under several profiles. The probe prints what
//! it can see from inside the sandbox. Uses a fake `$HOME`, so the real home
//! directory is never touched. Skipped when bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::path::Path;
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

/// Inside a real sandbox, each profile shows exactly the files and services it allows.
#[test]
fn a_real_sandbox_shows_exactly_what_each_profile_allows() {
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
