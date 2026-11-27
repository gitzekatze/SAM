//! Permission matrix: every permission, switched on one at a time, checked
//! from inside a real Bubblewrap sandbox by a probe AppImage. Checks that
//! depend on host hardware or services (GPU, gamepads, PipeWire, Wayland, …)
//! only assert when the host has them. Uses a fake `$HOME`. Skipped when
//! bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

// Isolated by variables only a developer build reads (developer_build_tests.rs).
#[cfg(not(debug_assertions))]
compile_error!("This test keeps SAM away from your real folders with variables only a developer build reads: run it without --release.");

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
yn 'grep -q matrix-theme "$HOME/.config/gtk-3.0/settings.ini"' THEME
yn 'grep -q file:// "$HOME/.config/gtk-3.0/bookmarks"' BOOKMARKS
yn 'grep -q sftp:// "$HOME/.config/gtk-3.0/servers"' SERVERS
touch "$HOME/marker" 2>/dev/null
yn '[ -e /usr/share/sam-matrix-never ] || [ -d /usr/include ]' FULL_USR
yn 'unshare -U true' USERNS
yn '[ -d /sys/class ]' SYSFS
yn '[ -n "$(ls /usr/share/fonts 2>/dev/null)" ]' FONTS
yn '[ -n "$(ls /etc/ssl/certs 2>/dev/null)" ]' CERTS
# Services on the host's loopback: one port listed in network.host_ports, one not.
tcp() { bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }
yn 'command -v bash' HAVE_BASH
if [ -n "${SAM_MATRIX_PORT_LISTED:-}" ]; then
  yn 'tcp "$SAM_MATRIX_PORT_LISTED"' PORT_LISTED
  yn 'tcp "$SAM_MATRIX_PORT_UNLISTED"' PORT_UNLISTED
fi
# The Wayland protocols the compositor offers the app (WL_GLOBALS).
if [ -n "${WAYLAND_DISPLAY:-}" ] && command -v python3 >/dev/null; then
  python3 "$APPDIR/usr/bin/wl-globals"
fi
echo "END=1"
[ "$1" = sleep ] && sleep 3
exit 0
"#;

/// Prints `WL_GLOBALS=` and the names of the protocols the Wayland
/// display offers (`$WAYLAND_DISPLAY`, below `$XDG_RUNTIME_DIR` unless a
/// whole path), sorted: a client of the Wayland wire protocol in a few
/// lines, so neither side needs a Wayland library.
const WL_GLOBALS: &str = r#"import os, socket, struct, sys
d = os.environ["WAYLAND_DISPLAY"]
s = socket.socket(socket.AF_UNIX)
s.connect(d if d.startswith("/") else os.path.join(os.environ["XDG_RUNTIME_DIR"], d))
# wl_display.get_registry(new id 2), then wl_display.sync(new id 3).
s.sendall(struct.pack("<IHHI", 1, 1, 12, 2) + struct.pack("<IHHI", 1, 0, 12, 3))
buf, names = b"", set()
while True:
    chunk = s.recv(65536)
    if not chunk:
        sys.exit("WL_GLOBALS=closed")
    buf += chunk
    while len(buf) >= 8:
        obj, op, size = struct.unpack("<IHH", buf[:8])
        if len(buf) < size:
            break
        body, buf = buf[8:size], buf[size:]
        if obj == 2 and op == 0:  # wl_registry.global(name, interface, version)
            n = struct.unpack("<I", body[4:8])[0]
            names.add(body[8:8 + n - 1].decode())
        elif obj == 1 and op == 0:  # wl_display.error
            sys.exit("WL_GLOBALS=error")
        elif obj == 3:  # the sync's callback: every global was sent
            print("WL_GLOBALS=" + ",".join(sorted(names)))
            sys.exit(0)
"#;

/// Protocols that let a client watch or steer the rest of the desktop:
/// read the clipboard in the background, capture the screen, type or move
/// the mouse for the person, list and steer other windows, read keystrokes
/// as an input method, make security contexts of its own. A client of a
/// security context must get none of them (threat model: "an app watches
/// your other windows or keystrokes"). Each compositor offers some.
const PRIVILEGED_WAYLAND: &[&str] = &[
    "wp_security_context_manager_v1",
    "zwlr_data_control_manager_v1",
    "ext_data_control_manager_v1",
    "zwlr_screencopy_manager_v1",
    "zwlr_export_dmabuf_manager_v1",
    "ext_image_copy_capture_manager_v1",
    "ext_output_image_capture_source_manager_v1",
    "ext_foreign_toplevel_image_capture_source_manager_v1",
    "zkde_screencast_unstable_v1",
    "zwp_virtual_keyboard_manager_v1",
    "zwlr_virtual_pointer_manager_v1",
    "org_kde_kwin_fake_input",
    "zwp_input_method_manager_v2",
    "zwlr_foreign_toplevel_manager_v1",
    "ext_foreign_toplevel_list_v1",
    "org_kde_plasma_window_management",
];

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

fn count_host(prefix: &str) -> usize {
    fs::read_dir("/dev/input")
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
                .count()
        })
        .unwrap_or(0)
}

fn runtime_has(name: &str) -> bool {
    std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|d| PathBuf::from(d).join(name).exists())
}

/// Inside a real sandbox, each permission grants exactly its access and nothing more.
#[test]
fn each_permission_grants_exactly_its_access_in_a_real_sandbox() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts = sam_runner::contracts::guard(&[
        "bwrap-core",
        "pasta-splice-only",
        "dbus-proxy-filter",
        "fs-layout",
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // The environment agrees with the host the sandboxes see (testenv): the
    // sound and display checks below read it, so on a desktop they would
    // otherwise expect the person's own sockets.
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    for d in [".ssh", ".gnupg", "Documents", "Pictures"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    fs::write(home.join(".ssh/id_ed25519"), "PRIVATE KEY").unwrap();
    fs::write(home.join(".gnupg/pubring.kbx"), "keys").unwrap();
    fs::write(home.join(".hidden-note"), "note").unwrap();
    fs::write(home.join("Documents/report.txt"), "hello").unwrap();
    // Theme settings, and next to them the file chooser's bookmarks and
    // server list, which name the person's folders and servers.
    let gtk3 = home.join(".config/gtk-3.0");
    fs::create_dir_all(&gtk3).unwrap();
    fs::write(
        gtk3.join("settings.ini"),
        "[Settings]\ngtk-theme-name=matrix-theme\n",
    )
    .unwrap();
    fs::write(
        gtk3.join("bookmarks"),
        "file:///home/tester/Secret%20project\n",
    )
    .unwrap();
    fs::write(
        gtk3.join("servers"),
        "<bookmark href=\"sftp://me@work.example\"/>\n",
    )
    .unwrap();
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
    spec.files.push(sam_intake::testkit::FixtureFile {
        path: "usr/bin/wl-globals".into(),
        data: WL_GLOBALS.as_bytes().to_vec(),
        mode: 0o644,
    });
    build(&img, &spec).unwrap();

    let paths = Paths::rooted(&root.join("sam"));
    let app = Sam::with_paths(paths.clone()).unwrap();
    let id = app
        .add(
            &img,
            &AddOptions {
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    let host = HostInfo::probe();
    // The same run on every computer: not the person's display or session bus.
    let host = sam_runner::testenv::test_host(host);
    // Its own session bus (no services) and SSH agent: the D-Bus and SSH
    // sections run on every computer, never against the person's own.
    let services = sam_runner::testenv::PrivateServices::start(root);
    let host = services.apply_to_this_process(host);

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
        let opts = LaunchOptions {
            quiet: true,
            owd: Some(home.clone()),
            ..Default::default()
        };
        let rec = run(&mut e, &opts, &app.config, &app.paths, &host).unwrap();
        if !rec.success {
            // The log is gone after the test (and on CI out of reach): show
            // what matters from it right here.
            let log = rec
                .log_file
                .as_ref()
                .and_then(|f| fs::read_to_string(f).ok())
                .unwrap_or_default();
            let important: Vec<&str> = log
                .lines()
                .filter(|l| {
                    l.starts_with("[err]")
                        || l.starts_with("# note")
                        || l.starts_with("# warning")
                        || l.contains("bwrap:")
                        || l.contains("pasta")
                })
                .take(40)
                .collect();
            panic!(
                "[{name}] launch failed: {}\n{}",
                rec.summary,
                important.join("\n")
            );
        }
        if std::env::var_os("SAM_MATRIX_DEBUG").is_some() {
            eprintln!(
                "=== {name}\n{}",
                fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap()
            );
        }
        let log = rec
            .log_file
            .clone()
            .unwrap_or_else(|| panic!("[{name}] the launch kept no log: {}", rec.summary));
        if !log.exists() {
            let dir = log.parent().map(|d| {
                fs::read_dir(d).map(|r| {
                    r.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
            });
            panic!(
                "[{name}] the log {} is missing ({}); the folder holds: {dir:?}",
                log.display(),
                rec.summary
            );
        }
        let r = parse(&log);
        *last.borrow_mut() = Some(rec.clone());
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "[{name}] probe did not finish: {r:?}"
        );
        r
    };

    // Every section is checked on its own; a failure names it
    // (CHECK FAIL matrix/<section>) and the next sections still run.
    let overlays_work = sam_core::host::overlay_works_in(&paths.data_dir.join("overlays"));
    let mut c = sam_runner::contracts::Checks::new("matrix");
    c.section("baseline", || {
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
    });
    c.section("devices", || {
        // Devices.
        let mut p = base();
        p.devices.gpu = true;
        let r = launch("gpu", p);
        if Path::new("/dev/dri").exists() {
            assert_eq!(r["GPU"], "yes");
            assert_eq!(r["SYSFS"], "yes", "GPU drivers need /sys");
        }
        if Path::new("/sys/module/nvidia/version").exists() {
            assert_eq!(
                r["NVMOD"], "yes",
                "NVIDIA's driver needs /sys/module/nvidia"
            );
        }

        let mut p = base();
        p.devices.gamepads = true;
        let r = launch("gamepads", p);
        // Exactly the joysticks SAM shows: never one udev also calls a
        // keyboard or pointer, nor one udev has no record of (review R56).
        let pads =
            sam_sandbox::sort_gamepad_nodes(Path::new("/dev/input"), Path::new("/run/udev/data"));
        assert_eq!(
            r["JS"],
            pads.shown.len().to_string(),
            "every game controller SAM shows, no other (left out: {:?}, {:?})",
            pads.refused,
            pads.unknown
        );
        assert_eq!(r["MICE"], "0", "no mice with gamepads only");
        assert_eq!(r["UINPUT"], "no");
        let host_events = count_host("event");
        let got: usize = r["EVENTS"].parse().unwrap();
        assert!(
            host_events == 0 || got < host_events,
            "keyboards and mice stay hidden ({got} of {host_events})"
        );

        let mut p = base();
        p.devices.input = true;
        let r = launch("input", p);
        assert_eq!(r["EVENTS"], count_host("event").to_string());

        let mut p = base();
        p.devices.usb = true;
        let r = launch("usb", p);
        assert_eq!(
            r["USB"],
            if Path::new("/dev/bus/usb").exists() {
                "yes"
            } else {
                "no"
            }
        );

        let mut p = base();
        p.devices.webcam = true;
        let r = launch("webcam", p);
        let cams = fs::read_dir("/dev")
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("video"));
        assert_eq!(r["VIDEO"], if cams { "yes" } else { "no" });

        let mut p = base();
        p.audio.enabled = true;
        let r = launch("audio", p);
        // In the desktop session of CI (tests/gui/desktop-sandbox.sh) sound
        // must be there: the checks below would otherwise pass unseen.
        if std::env::var("SAM_REQUIRE_SOUND").as_deref() == Ok("1") {
            assert!(
                runtime_has("pulse/native"),
                "SAM_REQUIRE_SOUND=1, but there is no PulseAudio socket"
            );
            assert!(
                runtime_has("pipewire-0"),
                "SAM_REQUIRE_SOUND=1, but there is no PipeWire socket"
            );
        }
        if runtime_has("pulse/native") {
            assert_eq!(r["AUDIO"], "yes");
        }
        assert_eq!(
            r["PIPEWIRE"], "no",
            "sound never brings the raw PipeWire socket (cameras, screen streams)"
        );
        assert_eq!(r["ALSA"], "no", "audio does not expose raw ALSA");

        let mut p = base();
        p.audio.pipewire = true;
        let r = launch("pipewire", p);
        assert_eq!(
            r["PIPEWIRE"],
            if runtime_has("pipewire-0") {
                "yes"
            } else {
                "no"
            }
        );

        let mut p = base();
        p.audio.alsa_raw = true;
        let r = launch("alsa", p);
        assert_eq!(
            r["ALSA"],
            if Path::new("/dev/snd").exists() {
                "yes"
            } else {
                "no"
            }
        );
    });
    c.section("display", || {
        // Display.
        let mut p = base();
        p.display.wayland = true;
        let r = launch("wayland", p);
        // In the desktop session of CI the display must be there (see above).
        if std::env::var("SAM_REQUIRE_DESKTOP").as_deref() == Ok("1") {
            assert!(
                std::env::var("WAYLAND_DISPLAY").is_ok_and(|d| runtime_has(&d)),
                "SAM_REQUIRE_DESKTOP=1, but there is no Wayland display"
            );
            // Where the compositor offers Wayland security contexts, the app's
            // connection must carry one (the contract wayland-security-context);
            // an older KWin may not offer them, which the skip list then says.
            let offered = host
                .sockets
                .wayland
                .as_ref()
                .is_some_and(|w| sam_runner::wayland_ctx::supported(w));
            if offered {
                let rec = last.borrow().clone().unwrap();
                let log = fs::read_to_string(rec.log_file.as_ref().unwrap()).unwrap();
                assert!(
                    log.contains("wayland security context: true"),
                    "the compositor offers security contexts, but the app's Wayland connection carries none: {}",
                    log.lines().take(3).collect::<Vec<_>>().join(" | ")
                );
                // What the security context is for: the compositor withholds
                // its privileged protocols from the app, which a client of
                // the compositor's own socket gets (audit D-M10: only the
                // log line above was checked).
                let script = root.join("wl-globals.py");
                fs::write(&script, WL_GLOBALS).unwrap();
                let socket = host.sockets.wayland.clone().unwrap();
                let out = std::process::Command::new("python3")
                    .arg(&script)
                    .env("WAYLAND_DISPLAY", &socket)
                    .output()
                    .unwrap();
                let list = |v: &str| -> std::collections::BTreeSet<String> {
                    v.split(',').filter(|g| !g.is_empty()).map(str::to_string).collect()
                };
                let printed = String::from_utf8_lossy(&out.stdout).into_owned();
                let outside = list(
                    printed
                        .trim()
                        .strip_prefix("WL_GLOBALS=")
                        .unwrap_or_else(|| panic!("no list of protocols outside: {printed:?} {}", String::from_utf8_lossy(&out.stderr))),
                );
                let inside = list(
                    r.get("WL_GLOBALS")
                        .unwrap_or_else(|| panic!("no list of protocols from the app: {r:?}")),
                );
                let withheld: Vec<&&str> = PRIVILEGED_WAYLAND
                    .iter()
                    .filter(|g| outside.contains(**g))
                    .collect();
                assert!(
                    !withheld.is_empty(),
                    "the compositor's own socket offers none of the privileged protocols, so nothing shows the security context at work: {outside:?}"
                );
                for g in &withheld {
                    assert!(
                        !inside.contains(**g),
                        "the app gets the privileged protocol {g} through its security context: {inside:?}"
                    );
                }
                assert!(
                    inside.contains("wl_compositor") && inside.is_subset(&outside),
                    "the app gets the ordinary protocols and nothing more: {inside:?} of {outside:?}"
                );
            } else {
                sam_runner::contracts::not_here("this compositor offers no Wayland security contexts");
            }
        }
        if std::env::var("WAYLAND_DISPLAY").is_ok_and(|d| runtime_has(&d)) {
            assert_eq!(r["WAYLAND"], "yes");
        }
        let mut p = base();
        p.display.wayland = false;
        let r = launch("no-wayland", p);
        assert_eq!(r["WAYLAND"], "no");
        // Shared system data (contract system-data): fonts and certificates are
        // visible wherever the computer has them.
        let has = |d: &str| fs::read_dir(d).is_ok_and(|mut e| e.next().is_some());
        if has("/usr/share/fonts") {
            assert_eq!(r["FONTS"], "yes", "fonts are visible in the sandbox");
        }
        if has("/etc/ssl/certs") {
            assert_eq!(r["CERTS"], "yes", "certificates are visible in the sandbox");
        }

        let mut p = base();
        p.display.x11 = true;
        let r = launch("x11", p);
        if fs::read_dir("/tmp/.X11-unix").is_ok_and(|mut d| d.next().is_some())
            && host.sockets.x11_display.is_some()
        {
            assert_eq!(r["X11"], "yes");
        }
    });
    c.section("network", || {
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
            // Two services on the host's loopback: the app reaches the one whose
            // port is listed, and not the other ("Other local services stay
            // unreachable").
            let listed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let unlisted = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let listed_port = listed.local_addr().unwrap().port();
            std::env::set_var("SAM_MATRIX_PORT_LISTED", listed_port.to_string());
            std::env::set_var(
                "SAM_MATRIX_PORT_UNLISTED",
                unlisted.local_addr().unwrap().port().to_string(),
            );
            let mut p = base();
            p.network.mode = NetworkMode::Localhost;
            p.network.host_ports = vec![listed_port.to_string()];
            p.environment.passthrough.extend([
                "SAM_MATRIX_PORT_LISTED".into(),
                "SAM_MATRIX_PORT_UNLISTED".into(),
            ]);
            let r = launch("localhost", p);
            assert!(r["NET"].contains("lo"), "this computer only: {}", r["NET"]);
            if r["HAVE_BASH"] == "yes" {
                assert_eq!(r["PORT_LISTED"], "yes", "a listed host port is reachable");
                assert_eq!(r["PORT_UNLISTED"], "no", "an unlisted host port is not");
            }
            drop((listed, unlisted));
            let rec = last.borrow().clone().unwrap();
            assert!(!rec.setup_failed, "bwrap status reached SAM through pasta");
            if sam_runner::find_helper().is_some() {
                let e = rec.enforcement.unwrap_or_default();
                assert!(
                    e.contains("landlock"),
                    "helper status reached SAM through pasta: {e:?}"
                );
            }
        }
    });
    c.section("dbus", || {
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
            assert_eq!(
                r["IBUS_USE_PORTAL"], "1",
                "input method uses the IBus portal"
            );
        }
        let mut p = base();
        p.dbus.system.mode = DbusMode::Full;
        let r = launch("system-bus", p);
        assert_eq!(
            r["SYSBUS"],
            if Path::new("/run/dbus/system_bus_socket").exists() {
                "yes"
            } else {
                "no"
            }
        );
    });
    c.section("sockets-and-environment", || {
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
        assert_eq!(
            r["CUPS"],
            if Path::new("/run/cups/cups.sock").exists() {
                "yes"
            } else {
                "no"
            }
        );
        let mut p = base();
        p.environment.passthrough.push("SAM_MATRIX_VAR".into());
        let r = launch("env", p);
        assert_eq!(r["PASSVAR"], "hello");
    });
    c.section("files", || {
        // Files.
        let mut p = base();
        p.filesystem.pictures = Access::Rw;
        let r = launch("pictures-rw", p);
        assert_eq!(r["PICS_WRITE"], "yes");
        assert!(home.join("Pictures/new.png").exists());
        // In a read-only home, a folder set to read/write stays writable.
        let _ = fs::remove_file(home.join("Pictures/new.png"));
        let mut p = base();
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        p.filesystem.pictures = Access::Rw;
        let r = launch("home-ro-pictures-rw", p);
        assert_eq!(
            r["PICS_WRITE"], "yes",
            "a writable folder in a read-only home"
        );
        assert!(home.join("Pictures/new.png").exists());
        let mut p = base();
        p.filesystem.custom_read.push(extra.display().to_string());
        let r = launch("custom-read", p);
        assert_eq!(
            (r["EXTRA_READ"].as_str(), r["EXTRA_WRITE"].as_str()),
            ("yes", "no")
        );
        let mut p = base();
        p.filesystem.custom_write.push(extra.display().to_string());
        let r = launch("custom-write", p);
        assert_eq!(
            (r["EXTRA_READ"].as_str(), r["EXTRA_WRITE"].as_str()),
            ("yes", "yes")
        );

        let mut p = base();
        p.filesystem.home = true;
        let r = launch("full-home", p.clone());
        assert_eq!(r["DOCS"], "yes");
        assert_eq!(
            (r["SSHKEY"].as_str(), r["GNUPG"].as_str()),
            ("no", "no"),
            "keys masked"
        );
        p.filesystem.ssh = true;
        p.filesystem.gnupg = true;
        p.filesystem.hidden_files = true;
        let r = launch("full-home-keys", p);
        assert_eq!(
            (
                r["SSHKEY"].as_str(),
                r["GNUPG"].as_str(),
                r["HIDDEN"].as_str()
            ),
            ("yes", "yes", "yes")
        );
    });
    c.section("advanced", || {
        // Advanced.
        let mut p = base();
        p.advanced.writable_appdir = true;
        let r = launch("writable-appdir", p);
        // Without overlays (Bubblewrap before 0.10, as on Ubuntu 24.04, or a
        // filesystem that cannot hold one, as in a container) the app folder
        // stays read-only, and the app still starts.
        assert_eq!(r["APPDIR_WRITE"], if overlays_work { "yes" } else { "no" });
        let extracted = app.resolve(&id).unwrap().extraction.unwrap().appdir;
        assert!(
            !Path::new(&extracted).join("portable.ini").exists(),
            "extracted copy unchanged"
        );

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

        // Without nested sandboxes, Bubblewrap itself refuses them
        // (--disable-userns), not only the syscall filter: with the filter
        // off, nesting stays refused (verification audit 2026-11-19: the
        // filter blocked unshare first, so no real test saw this layer).
        let mut p = base();
        p.advanced.allow_userns = false;
        p.advanced.seccomp_baseline = false;
        let r = launch("no-userns-without-filter", p);
        assert_eq!(
            r["USERNS"], "no",
            "nested namespaces refused without the filter too"
        );

        let mut p = base();
        p.advanced.seccomp_strict = true;
        p.advanced.landlock = Some(true);
        launch("strict-filters", p);

        // Theme settings: shown read-only with the switch, but not the
        // file chooser's bookmarks and server list next to them, unless a
        // grant shows the folder itself.
        let mut p = base();
        p.advanced.host_themes = false;
        let r = launch("no-themes", p);
        assert_eq!((r["THEME"].as_str(), r["BOOKMARKS"].as_str()), ("no", "no"));
        let mut p = base();
        p.advanced.host_themes = true;
        let r = launch("themes", p);
        assert_eq!(r["THEME"], "yes", "the theme settings are shown");
        assert_eq!(r["BOOKMARKS"], "no", "the bookmarks stay out");
        assert_eq!(r["SERVERS"], "no", "the server list stays out");
        let mut p = base();
        p.advanced.host_themes = true;
        p.filesystem.custom_read = vec![gtk3.display().to_string()];
        let r = launch("themes-folder-granted", p);
        assert_eq!(
            (r["THEME"].as_str(), r["BOOKMARKS"].as_str()),
            ("yes", "yes"),
            "a grant of the folder itself shows the bookmarks"
        );
    });
    c.section("running-app-and-its-layer", || {
        // A running app cannot lose its sandbox or be unpacked again.
        let e = app.set_permissions(&id, base()).unwrap();
        std::thread::scope(|sc| {
            let h = sc.spawn(|| {
                let mut e = e;
                let opts = LaunchOptions {
                    quiet: true,
                    args: vec!["sleep".into()],
                    owd: Some(home.clone()),
                    ..Default::default()
                };
                run(&mut e, &opts, &app.config, &app.paths, &host).unwrap()
            });
            let t0 = std::time::Instant::now();
            while app.running(&id).is_empty() && t0.elapsed().as_secs() < 5 {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            assert!(
                !app.running(&id).is_empty(),
                "the launch is seen as running"
            );
            let err = app.remove(&id, false).unwrap_err().to_string();
            assert!(err.contains("is running"), "{err}");
            assert!(app
                .reextract(&id, false)
                .unwrap_err()
                .to_string()
                .contains("is running"));
            assert!(h.join().unwrap().success);
        });
        assert!(app.running(&id).is_empty());
        let overlay = paths.data_dir.join("overlays").join(&id);
        // The layer exists only where overlays work.
        assert_eq!(overlay.exists(), overlays_work, "writable app folder layer");
        app.remove(&id, false).unwrap();
        assert!(
            !overlay.exists(),
            "remove deletes the writable app folder layer"
        );
        assert!(
            !paths.runtime_dir(&id).exists(),
            "no runtime folder left behind"
        );
    });
    c.finish().unwrap_or_else(|e| panic!("{e}"));
}

use sam_core::Paths;

trait PastaProbe {
    fn tools_extra_pasta(&self) -> bool;
}
impl PastaProbe for HostInfo {
    fn tools_extra_pasta(&self) -> bool {
        std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("pasta").is_file()))
    }
}
