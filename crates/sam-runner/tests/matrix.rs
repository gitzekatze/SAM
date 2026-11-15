//! Permission matrix: every permission, switched on one at a time, checked
//! from inside a real Bubblewrap sandbox by a probe AppImage. Checks that
//! depend on host hardware or services (GPU, gamepads, PipeWire, Wayland, …)
//! only assert when the host has them. Uses a fake `$HOME`. Skipped when
//! bubblewrap cannot run here.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use sam_core::permissions::*;
use sam_core::HostInfo;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

const PROBE: &str = r#"#!/bin/sh
yn() { if eval "$1" 2>/dev/null; then echo "$2=yes"; else echo "$2=no"; fi; }
yn '[ -e /dev/dri ]' GPU
yn '[ -e /sys/module/nvidia/version ]' NVMOD
echo "JS=$(ls /dev/input 2>/dev/null | grep -c '^js')"
echo "EVENTS=$(ls /dev/input 2>/dev/null | grep -c '^event')"
echo "MICE=$(ls /dev/input 2>/dev/null | grep -c '^mice')"
yn '[ -e /dev/uinput ]' UINPUT
yn '[ -e /dev/bus/usb ]' USB
yn '[ -e /dev/snd ]' ALSA
yn 'ls /dev | grep -q "^video"' VIDEO
yn '[ -S "$XDG_RUNTIME_DIR/pulse/native" ]' AUDIO
yn '[ -S "$XDG_RUNTIME_DIR/pipewire-0" ]' PIPEWIRE
yn '[ -n "$WAYLAND_DISPLAY" ] && [ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]' WAYLAND
yn '[ -n "$(ls /tmp/.X11-unix 2>/dev/null)" ]' X11
echo "NET=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | sort | tr '\n' ',')"
yn '[ -n "$DBUS_SESSION_BUS_ADDRESS" ]' SESSBUS
yn '[ -S /run/dbus/system_bus_socket ]' SYSBUS
yn '[ -n "$SSH_AUTH_SOCK" ] && [ -S "$SSH_AUTH_SOCK" ]' SSHAGENT
yn '[ -S /run/cups/cups.sock ]' CUPS
echo "PASSVAR=${SAM_MATRIX_VAR:-unset}"
echo "IBUS_USE_PORTAL=${IBUS_USE_PORTAL:-unset}"
yn '[ -e "$HOME/.ssh/id_ed25519" ]' SSHKEY
yn '[ -e "$HOME/.gnupg/pubring.kbx" ]' GNUPG
yn '[ -e "$HOME/.hidden-note" ]' HIDDEN
yn '[ -e "$HOME/Documents/report.txt" ]' DOCS
yn '( echo x > "$HOME/Pictures/new.png" )' PICS_WRITE
yn '[ -e "$SAM_MATRIX_EXTRA/data.txt" ]' EXTRA_READ
yn '( echo x > "$SAM_MATRIX_EXTRA/new.txt" )' EXTRA_WRITE
yn '( echo x > "$APPDIR/portable.ini" )' APPDIR_WRITE
yn '[ -e "$HOME/marker" ]' MARKER
touch "$HOME/marker" 2>/dev/null
yn '[ -e /usr/share/sam-matrix-never ] || [ -d /usr/include ]' FULL_USR
yn 'unshare -U true' USERNS
yn '[ -d /sys/class ]' SYSFS
echo "END=1"
[ "$1" = sleep ] && sleep 3
exit 0
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
        .filter(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn count_host(prefix: &str) -> usize {
    fs::read_dir("/dev/input").map(|rd| rd.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(prefix)).count()).unwrap_or(0)
}

fn runtime_has(name: &str) -> bool {
    std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|d| PathBuf::from(d).join(name).exists())
}

/// Inside a real sandbox, each permission grants exactly its access and nothing more.
#[test]
fn each_permission_grants_exactly_its_access_in_a_real_sandbox() {
    if !bwrap_works() {
        eprintln!("skipping: bubblewrap is not functional here");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    for d in [".ssh", ".gnupg", "Documents", "Pictures"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    fs::write(home.join(".ssh/id_ed25519"), "PRIVATE KEY").unwrap();
    fs::write(home.join(".gnupg/pubring.kbx"), "keys").unwrap();
    fs::write(home.join(".hidden-note"), "note").unwrap();
    fs::write(home.join("Documents/report.txt"), "hello").unwrap();
    let extra = root.join("extra");
    fs::create_dir_all(&extra).unwrap();
    fs::write(extra.join("data.txt"), "data").unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    std::env::set_var("SAM_MATRIX_VAR", "hello");

    let img = root.join("Matrix-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Matrix");
    spec.apprun = PROBE.into();
    spec.categories = "Utility;".into();
    build(&img, &spec).unwrap();

    let paths = Paths::rooted(&root.join("sam"));
    let app = Sam::with_paths(paths.clone()).unwrap();
    let id = app.add(&img, &AddOptions { launcher: Some(false), ..Default::default() }).unwrap().entry.id;
    let host = HostInfo::probe();

    let base = || {
        let mut p = PermissionSet::strict_gui();
        // The probe passes the extra folder's path through the environment.
        p.environment.passthrough.push("SAM_MATRIX_EXTRA".into());
        p.integrations.input_method = false;
        p.advanced.allow_userns = false;
        p
    };
    std::env::set_var("SAM_MATRIX_EXTRA", &extra);
    let last = std::cell::RefCell::new(None::<sam_core::LaunchRecord>);
    let launch = |name: &str, perms: PermissionSet| {
        let mut e = app.set_permissions(&id, perms).unwrap();
        let opts = LaunchOptions { quiet: true, owd: Some(home.clone()), ..Default::default() };
        let rec = run(&mut e, &opts, &app.config, &app.paths, &host).unwrap();
        if !rec.success {
            // The log is gone after the test (and on CI out of reach): show
            // what matters from it right here.
            let log = rec.log_file.as_ref().and_then(|f| fs::read_to_string(f).ok()).unwrap_or_default();
            let important: Vec<&str> = log
                .lines()
                .filter(|l| l.starts_with("[err]") || l.starts_with("# note") || l.starts_with("# warning") || l.contains("bwrap:") || l.contains("pasta"))
                .take(40)
                .collect();
            panic!("[{name}] launch failed: {}\n{}", rec.summary, important.join("\n"));
        }
        if std::env::var_os("SAM_MATRIX_DEBUG").is_some() {
            eprintln!("=== {name}\n{}", fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap());
        }
        let log = rec.log_file.clone().unwrap_or_else(|| panic!("[{name}] the launch kept no log: {}", rec.summary));
        if !log.exists() {
            let dir =
                log.parent().map(|d| fs::read_dir(d).map(|r| r.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect::<Vec<_>>().join(", ")));
            panic!("[{name}] the log {} is missing ({}); the folder holds: {dir:?}", log.display(), rec.summary);
        }
        let r = parse(&log);
        *last.borrow_mut() = Some(rec.clone());
        assert_eq!(r.get("END").map(String::as_str), Some("1"), "[{name}] probe did not finish: {r:?}");
        r
    };

    // Baseline: everything off.
    let r = launch("strict", base());
    for (k, v) in [
        ("GPU", "no"),
        ("UINPUT", "no"),
        ("USB", "no"),
        ("ALSA", "no"),
        ("VIDEO", "no"),
        ("AUDIO", "no"),
        ("X11", "no"),
        ("SYSBUS", "no"),
        ("SSHAGENT", "no"),
        ("CUPS", "no"),
        ("SSHKEY", "no"),
        ("DOCS", "no"),
        ("PICS_WRITE", "no"),
        ("EXTRA_READ", "no"),
        ("APPDIR_WRITE", "no"),
        ("USERNS", "no"),
        ("SYSFS", "no"),
        ("PASSVAR", "unset"),
        ("IBUS_USE_PORTAL", "unset"),
        ("JS", "0"),
        ("EVENTS", "0"),
    ] {
        assert_eq!(r[k], v, "[strict] {k}");
    }
    assert_eq!(r["NET"], "lo,", "[strict] network");

    // Devices.
    let mut p = base();
    p.devices.gpu = true;
    let r = launch("gpu", p);
    if Path::new("/dev/dri").exists() {
        assert_eq!(r["GPU"], "yes");
        assert_eq!(r["SYSFS"], "yes", "GPU drivers need /sys");
    }
    if Path::new("/sys/module/nvidia/version").exists() {
        assert_eq!(r["NVMOD"], "yes", "NVIDIA's driver needs /sys/module/nvidia");
    }

    let mut p = base();
    p.devices.gamepads = true;
    let r = launch("gamepads", p);
    assert_eq!(r["JS"], count_host("js").to_string(), "every joystick node");
    assert_eq!(r["MICE"], "0", "no mice with gamepads only");
    assert_eq!(r["UINPUT"], "no");
    let host_events = count_host("event");
    let got: usize = r["EVENTS"].parse().unwrap();
    assert!(host_events == 0 || got < host_events, "keyboards and mice stay hidden ({got} of {host_events})");

    let mut p = base();
    p.devices.input = true;
    let r = launch("input", p);
    assert_eq!(r["EVENTS"], count_host("event").to_string());

    let mut p = base();
    p.devices.usb = true;
    let r = launch("usb", p);
    assert_eq!(r["USB"], if Path::new("/dev/bus/usb").exists() { "yes" } else { "no" });

    let mut p = base();
    p.devices.webcam = true;
    let r = launch("webcam", p);
    let cams = fs::read_dir("/dev").unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("video"));
    assert_eq!(r["VIDEO"], if cams { "yes" } else { "no" });

    let mut p = base();
    p.audio.enabled = true;
    let r = launch("audio", p);
    if runtime_has("pulse/native") {
        assert_eq!(r["AUDIO"], "yes");
    }
    assert_eq!(r["PIPEWIRE"], "no", "sound never brings the raw PipeWire socket (cameras, screen streams)");
    assert_eq!(r["ALSA"], "no", "audio does not expose raw ALSA");

    let mut p = base();
    p.audio.pipewire = true;
    let r = launch("pipewire", p);
    assert_eq!(r["PIPEWIRE"], if runtime_has("pipewire-0") { "yes" } else { "no" });

    let mut p = base();
    p.audio.alsa_raw = true;
    let r = launch("alsa", p);
    assert_eq!(r["ALSA"], if Path::new("/dev/snd").exists() { "yes" } else { "no" });

    // Display.
    let mut p = base();
    p.display.wayland = true;
    let r = launch("wayland", p);
    if std::env::var("WAYLAND_DISPLAY").is_ok_and(|d| runtime_has(&d)) {
        assert_eq!(r["WAYLAND"], "yes");
    }
    let mut p = base();
    p.display.wayland = false;
    let r = launch("no-wayland", p);
    assert_eq!(r["WAYLAND"], "no");

    let mut p = base();
    p.display.x11 = true;
    let r = launch("x11", p);
    if fs::read_dir("/tmp/.X11-unix").is_ok_and(|mut d| d.next().is_some()) && host.sockets.x11_display.is_some() {
        assert_eq!(r["X11"], "yes");
    }

    // Network.
    let mut p = base();
    p.network.mode = NetworkMode::Full;
    let r = launch("network", p);
    assert_ne!(r["NET"], "lo,", "full network shares host interfaces");
    if host.tools_extra_pasta() && sam_runner::netns::pasta_usable().is_err() {
        // A pasta without --splice-only (Ubuntu 24.04) would give the app
        // internet access: SAM starts it with no network at all instead.
        let mut p = base();
        p.network.mode = NetworkMode::Localhost;
        let r = launch("localhost-old-pasta", p);
        assert_eq!(r["NET"], "lo,", "no network at all with an old pasta");
    } else if host.tools_extra_pasta() {
        let mut p = base();
        p.network.mode = NetworkMode::Localhost;
        let r = launch("localhost", p);
        assert!(r["NET"].contains("lo"), "this computer only: {}", r["NET"]);
        let rec = last.borrow().clone().unwrap();
        assert!(!rec.setup_failed, "bwrap status reached SAM through pasta");
        if sam_runner::find_helper().is_some() {
            let e = rec.enforcement.unwrap_or_default();
            assert!(e.contains("landlock"), "helper status reached SAM through pasta: {e:?}");
        }
    }

    // D-Bus.
    let mut p = base();
    p.dbus.session.mode = DbusMode::None;
    let r = launch("dbus-none", p);
    assert_eq!(r["SESSBUS"], "no");
    if host.tools.xdg_dbus_proxy.is_some() && host.sockets.dbus_session.is_some() {
        let mut p = base();
        p.dbus.session.mode = DbusMode::Filtered;
        p.integrations.input_method = true;
        let r = launch("dbus-filtered", p);
        assert_eq!(r["SESSBUS"], "yes");
        assert_eq!(r["IBUS_USE_PORTAL"], "1", "input method uses the IBus portal");
    }
    let mut p = base();
    p.dbus.system.mode = DbusMode::Full;
    let r = launch("system-bus", p);
    assert_eq!(r["SYSBUS"], if Path::new("/run/dbus/system_bus_socket").exists() { "yes" } else { "no" });

    // Sockets and environment.
    let mut p = base();
    p.sockets.ssh_agent = true;
    let r = launch("ssh-agent", p);
    if std::env::var_os("SSH_AUTH_SOCK").is_some_and(|s| Path::new(&s).exists()) {
        assert_eq!(r["SSHAGENT"], "yes");
    }
    let mut p = base();
    p.sockets.cups = true;
    let r = launch("cups", p);
    assert_eq!(r["CUPS"], if Path::new("/run/cups/cups.sock").exists() { "yes" } else { "no" });
    let mut p = base();
    p.environment.passthrough.push("SAM_MATRIX_VAR".into());
    let r = launch("env", p);
    assert_eq!(r["PASSVAR"], "hello");

    // Files.
    let mut p = base();
    p.filesystem.pictures = Access::Rw;
    let r = launch("pictures-rw", p);
    assert_eq!(r["PICS_WRITE"], "yes");
    assert!(home.join("Pictures/new.png").exists());
    let mut p = base();
    p.filesystem.custom_read.push(extra.display().to_string());
    let r = launch("custom-read", p);
    assert_eq!((r["EXTRA_READ"].as_str(), r["EXTRA_WRITE"].as_str()), ("yes", "no"));
    let mut p = base();
    p.filesystem.custom_write.push(extra.display().to_string());
    let r = launch("custom-write", p);
    assert_eq!((r["EXTRA_READ"].as_str(), r["EXTRA_WRITE"].as_str()), ("yes", "yes"));

    let mut p = base();
    p.filesystem.home = true;
    let r = launch("full-home", p.clone());
    assert_eq!(r["DOCS"], "yes");
    assert_eq!((r["SSHKEY"].as_str(), r["GNUPG"].as_str()), ("no", "no"), "keys masked");
    p.filesystem.ssh = true;
    p.filesystem.gnupg = true;
    p.filesystem.hidden_files = true;
    let r = launch("full-home-keys", p);
    assert_eq!((r["SSHKEY"].as_str(), r["GNUPG"].as_str(), r["HIDDEN"].as_str()), ("yes", "yes", "yes"));

    // Advanced.
    let mut p = base();
    p.advanced.writable_appdir = true;
    let r = launch("writable-appdir", p);
    // Without overlays (Bubblewrap before 0.10, as on Ubuntu 24.04, or a
    // filesystem that cannot hold one, as in a container) the app folder
    // stays read-only, and the app still starts.
    let overlays_work = sam_core::host::overlay_works_in(&paths.data_dir.join("overlays"));
    assert_eq!(r["APPDIR_WRITE"], if overlays_work { "yes" } else { "no" });
    let extracted = app.resolve(&id).unwrap().extraction.unwrap().appdir;
    assert!(!Path::new(&extracted).join("portable.ini").exists(), "extracted copy unchanged");

    let mut p = base();
    p.advanced.persistent_home = false;
    launch("ephemeral-1", p.clone());
    let r = launch("ephemeral-2", p);
    assert_eq!(r["MARKER"], "no", "home is fresh every start");

    let mut p = base();
    p.advanced.host_runtime = HostRuntime::Full;
    let r = launch("full-usr", p);
    if Path::new("/usr/include").is_dir() {
        assert_eq!(r["FULL_USR"], "yes");
    }

    let mut p = base();
    p.advanced.allow_userns = true;
    p.advanced.seccomp_baseline = false;
    let r = launch("userns", p);
    assert_eq!(r["USERNS"], "yes", "nested namespaces allowed");

    let mut p = base();
    p.advanced.seccomp_strict = true;
    p.advanced.landlock = Some(true);
    launch("strict-filters", p);

    for flag in [false, true] {
        let mut p = base();
        p.advanced.host_themes = flag;
        launch("themes", p);
    }

    // A running app cannot lose its sandbox or be unpacked again.
    let e = app.set_permissions(&id, base()).unwrap();
    std::thread::scope(|sc| {
        let h = sc.spawn(|| {
            let mut e = e;
            let opts = LaunchOptions { quiet: true, args: vec!["sleep".into()], owd: Some(home.clone()), ..Default::default() };
            run(&mut e, &opts, &app.config, &app.paths, &host).unwrap()
        });
        let t0 = std::time::Instant::now();
        while app.running(&id).is_empty() && t0.elapsed().as_secs() < 5 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!app.running(&id).is_empty(), "the launch is seen as running");
        let err = app.remove(&id, false).unwrap_err().to_string();
        assert!(err.contains("is running"), "{err}");
        assert!(app.reextract(&id, false).unwrap_err().to_string().contains("is running"));
        assert!(h.join().unwrap().success);
    });
    assert!(app.running(&id).is_empty());
    let overlay = paths.data_dir.join("overlays").join(&id);
    // The layer exists only where overlays work.
    assert_eq!(overlay.exists(), overlays_work, "writable app folder layer");
    app.remove(&id, false).unwrap();
    assert!(!overlay.exists(), "remove deletes the writable app folder layer");
    assert!(!paths.runtime_dir(&id).exists(), "no runtime folder left behind");
}

use sam_core::Paths;

trait PastaProbe {
    fn tools_extra_pasta(&self) -> bool;
}
impl PastaProbe for HostInfo {
    fn tools_extra_pasta(&self) -> bool {
        std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("pasta").is_file()))
    }
}
