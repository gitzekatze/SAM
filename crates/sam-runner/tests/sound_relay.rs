//! Sound never lets an app load code into the sound server outside the
//! sandbox (audit S-F1, proven on 2026-11-18: with only sound on, an app
//! made the person's sound server load a module). Attacked from inside a
//! real sandbox against a private PipeWire with its PulseAudio server:
//! - through SAM's relay the app has sound, and loading a module is refused;
//! - where the relay cannot run, the app has no sound and the start says
//!   why;
//! - only when the person allowed sound without the relay does the app get
//!   the sound server's own connection, with a warning: the control that
//!   shows the attack would have been seen.
//!
//! In its own file because it sets `HOME` and starts a sound server for the
//! test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

const ATTACK: &str = r#"#!/bin/sh
pactl info >/dev/null 2>&1 && echo SOUND=yes || echo SOUND=no
if pactl load-module module-null-sink sink_name=sam_attack >/dev/null 2>&1; then echo LOAD=done; else echo LOAD=refused; fi
echo END=1
"#;

fn parse(log: &Path) -> HashMap<String, String> {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The private sound servers, ended with the test.
struct Servers(Vec<Child>);
impl Drop for Servers {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn wait_for(path: &Path) -> bool {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Modules named `sam_attack` loaded into the private sound server.
fn attack_modules(run: &Path) -> usize {
    let out = Command::new("pactl")
        .args([
            "-s",
            &format!("unix:{}", run.join("pulse/native").display()),
        ])
        .args(["list", "short", "modules"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("sam_attack"))
        .count()
}

#[test]
fn sound_never_loads_code_into_the_sound_server() {
    let host = HostInfo::probe();
    if host.tools.bwrap.is_none() || sam_runner::doctor::bwrap_functional(&host).is_err() {
        sam_runner::contracts::skip("bubblewrap is not functional here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let have = |p: &str| {
        Command::new(p)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    };
    if !(have("pipewire") && have("pipewire-pulse") && have("pactl")) {
        sam_runner::contracts::skip("PipeWire, its PulseAudio server or pactl is not installed")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    sam_runner::testenv::isolate_this_process(root);
    let home = root.join("home/tester");
    fs::create_dir_all(home.join(".config")).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    std::env::set_var("XDG_STATE_HOME", home.join(".local/state"));
    std::env::remove_var("PIPEWIRE_REMOTE");
    std::env::remove_var("PULSE_SERVER");
    let run_dir = std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").unwrap());

    // A private PipeWire and its PulseAudio server, in the test's own
    // runtime folder (never the person's).
    let quiet = |p: &str| {
        Command::new(p)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let mut servers = Servers(vec![quiet("pipewire")]);
    assert!(
        wait_for(&run_dir.join("pipewire-0")),
        "private PipeWire runs"
    );
    servers.0.push(quiet("pipewire-pulse"));
    assert!(
        wait_for(&run_dir.join("pulse/native")),
        "private PulseAudio server runs"
    );

    let img = root.join("Sound-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Sound");
    spec.apprun = ATTACK.into();
    build(&img, &spec).unwrap();
    let app = Sam::with_paths(Paths::rooted(&root.join("samroot"))).unwrap();
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
    let start = |direct: bool, relay: bool| {
        let mut p = PermissionSet::strict_gui();
        p.audio.enabled = true;
        p.audio.direct = direct;
        let mut e = app.set_permissions(&id, p).unwrap();
        // The desktop stays out; the sound sockets are the test's own.
        let probed = HostInfo::probe();
        let mut h = sam_runner::testenv::test_host(probed.clone());
        h.sockets.pipewire = probed.sockets.pipewire.clone();
        h.sockets.pulse = probed.sockets.pulse.clone();
        for s in [&h.sockets.pipewire, &h.sockets.pulse] {
            assert!(
                s.as_ref().is_some_and(|s| s.starts_with(&run_dir)),
                "the private sound server: {s:?}"
            );
        }
        if !relay {
            // A computer where the relay cannot run.
            h.tools.pipewire = None;
        }
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                owd: Some(home.clone()),
                ..Default::default()
            },
            &app.config,
            &app.paths,
            &h,
        )
        .unwrap();
        let log = rec.log_file.clone().unwrap();
        let r = parse(&log);
        assert_eq!(
            r.get("END").map(String::as_str),
            Some("1"),
            "the attack ran: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        (r, fs::read_to_string(&log).unwrap())
    };

    // Through SAM's relay: sound, and no module.
    let (r, log) = start(false, true);
    assert_eq!(r["SOUND"], "yes", "{log}");
    assert_eq!(r["LOAD"], "refused", "{log}");
    assert_eq!(attack_modules(&run_dir), 0, "nothing loaded");
    assert!(log.contains("# sound: through SAM's relay"), "{log}");

    // The relay allowed, but not running: no sound, and the start says why.
    let (r, log) = start(false, false);
    assert_eq!(r["SOUND"], "no", "{log}");
    assert_eq!(attack_modules(&run_dir), 0);
    assert!(log.contains("sound-off"), "{log}");

    // The control: sound without the relay, allowed by the person, reaches
    // the sound server itself, so the module loads, and the start warns.
    let (r, log) = start(true, false);
    assert_eq!(r["SOUND"], "yes", "{log}");
    assert_eq!(r["LOAD"], "done", "{log}");
    assert_eq!(
        attack_modules(&run_dir),
        1,
        "the attack works without the relay"
    );
    assert!(log.contains("sound-without-relay"), "{log}");
    drop(servers);
}
