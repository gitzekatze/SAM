//! Room service's first promise, checked broadly: for many generated
//! requests, no room reads, writes, reaches or shows anything its app
//! cannot. The app and every room run the same probe:
//! - reads and connections are judged by the probe;
//! - writes are judged on the computer afterwards (a marker file per writer
//!   in every folder it reached);
//! - what a room shows is judged by its mounts: every folder of the
//!   computer mounted in a room must be one its app has mounted, or lie
//!   within one. This holds whatever Landlock or the syscall filter would
//!   stop later, so it checks the room service itself.
//!
//! The requests come from a fixed seed, so a failure can be repeated
//! (`SAM_ROOMS_SEED` picks another one).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod rooms_common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rooms_common::{
    host_mount_devices, markers, mounts_beyond_app, mounts_of, writable_beyond_app, World, SECRET,
};
use sam_core::permissions::{NetworkMode, PermissionSet};

/// Places a request may name (shell words, expanded in the app).
const PLACES: &[&str] = &[
    "/",
    "/usr",
    "/etc",
    "/tmp",
    "/var",
    "/var/tmp",
    "/run",
    "/run/user",
    "/run/sam",
    "/dev",
    "/opt",
    "/home",
    "/root",
    "/sys",
    "/proc",
    "\"$HOME\"",
    "\"$HOME/sub\"",
    "\"$HOME/.config\"",
    "\"$APPDIR\"",
    "\"$SECRET_DIR\"",
    "\"$(dirname \"$OTHER_APP\")\"",
    "\"$(dirname \"$SAM_SETTINGS\")\"",
    "\"$(dirname \"$HOST_KEY\")\"",
];

const BINDS: &[&str] = &[
    "--ro-bind",
    "--bind",
    "--ro-bind-try",
    "--bind-try",
    "--bind-try",
    "--ro-bind-try",
    "--dev-bind-try",
];

const EXTRAS: &[&str] = &[
    "--share-net",
    "--unshare-net",
    "--tmpfs /tmp",
    "--dev /dev",
    "--die-with-parent",
    "--new-session",
    "--unshare-pid",
];

/// A change to an app's settings for one run.
type Tweak = dyn Fn(&mut PermissionSet);

/// A small, fixed random source (xorshift): the same requests every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a>(&mut self, from: &[&'a str]) -> &'a str {
        from[(self.next() % from.len() as u64) as usize]
    }
}

/// The probe line: read these files, reach the listeners, write a marker
/// named after the writer into each of these folders.
const FILES: &str = "\"$SECRET_FILE\" \"$OTHER_APP\" \"$SAM_SETTINGS\" \"$HOST_KEY\" \"$HOME/own\"";
const DIRS: &str = "\"$HOME\" \"$HOME/sub\" \"$HOME/.config/autostart\" \"$APPDIR/usr/bin\" \"$SECRET_DIR\" \"$(dirname \"$OTHER_APP\")\" \"$(dirname \"$SAM_SETTINGS\")\" /tmp /var/tmp";

/// The app's own probe, then `rooms` generated requests. Every request has
/// a /proc of its own (`--proc /proc`) so the room can list its mounts; the
/// first one asks for everything (`--bind / /`).
fn script(rng: &mut Rng, rooms: usize, tag: &str) -> String {
    let mut s = format!(
        "mkdir -p \"$HOME/sub\" \"$HOME/.config/autostart\"\n\
         echo {SECRET} > \"$HOME/own\"\n\
         echo \"PROBE app $($P all \"$PORT\" \"$ABSTRACT\" {tag}-app {FILES} -- {DIRS})\"\n"
    );
    for i in 0..rooms {
        let mut req: Vec<String> = Vec::new();
        if i == 0 {
            req.push("--bind / / --dev-bind /dev /dev --share-net".into());
        } else {
            for _ in 0..1 + rng.next() % 4 {
                let place = rng.pick(PLACES);
                req.push(format!("{} {place} {place}", rng.pick(BINDS)));
            }
            for _ in 0..rng.next() % 3 {
                req.push(rng.pick(EXTRAS).to_string());
            }
        }
        req.push("--proc /proc".into());
        let req = req.join(" ");
        s.push_str(&format!(
            "r=$(room {req} -- $P all \"$PORT\" \"$ABSTRACT\" {tag}-room-{i} {FILES} -- {DIRS} 2>/dev/null)\n\
             echo \"PROBE room-{i} ${{r:-refused}}\"\n\
             echo 'REQUEST room-{i} {}'\n",
            req.replace('\'', "")
        ));
    }
    s
}

/// `PROBE name {json}` lines: what each writer could read, reach and show.
fn probes(log: &str) -> BTreeMap<String, Option<serde_json::Value>> {
    log.lines()
        .filter_map(|l| l.trim().strip_prefix("PROBE "))
        .filter_map(|l| l.split_once(' '))
        .map(|(name, rest)| (name.to_string(), serde_json::from_str(rest).ok()))
        .collect()
}

fn requests(log: &str) -> BTreeMap<String, String> {
    log.lines()
        .filter_map(|l| l.trim().strip_prefix("REQUEST "))
        .filter_map(|l| l.split_once(' '))
        .map(|(n, r)| (n.to_string(), r.to_string()))
        .collect()
}

fn abilities(probe: &serde_json::Value) -> BTreeMap<String, bool> {
    probe["can"]
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_bool().unwrap_or(false)))
                .collect()
        })
        .unwrap_or_default()
}

/// Every room is within its app, for generated requests under no network,
/// the full network, and in an app with Landlock and its syscall filter off:
/// no room reads, writes or reaches anything its app cannot, and no room
/// shows a folder of the computer its app is not shown.
#[test]
fn every_room_is_a_subset_of_its_app() {
    if !rooms_common::require() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "bwrap-rooms", "kernel-seccomp"])
        .unwrap_or_else(|e| panic!("{e}"));
    let seed: u64 = std::env::var("SAM_ROOMS_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5341_4d52_4f4f_4d53);
    eprintln!("compare: seed {seed}");
    let w = World::new();
    let host_devices = host_mount_devices();
    let pid = std::process::id();
    let mut failures: Vec<String> = Vec::new();
    let full = |p: &mut PermissionSet| p.network.mode = NetworkMode::Full;
    let exceptions = |p: &mut PermissionSet| {
        p.network.mode = NetworkMode::Full;
        p.advanced.landlock = Some(false);
        p.advanced.seccomp_baseline = false;
        p.advanced.allow_userns = true;
    };
    let modes: [(&str, &Tweak); 3] = [
        ("none", &|_| {}),
        ("full", &full),
        ("exceptions", &exceptions),
    ];
    let mut rng = Rng(seed);
    for (mode, tweak) in modes {
        let tag = format!("sam-probe-{pid}-{mode}");
        for tmp in ["/tmp", "/var/tmp"] {
            for who in
                std::iter::once("app".to_string()).chain((0..60).map(|i| format!("room-{i}")))
            {
                w.leftovers
                    .borrow_mut()
                    .push(PathBuf::from(tmp).join(format!("{tag}-{who}")));
            }
        }
        let id = w.add(&format!("RoomCompare{mode}"), &script(&mut rng, 60, &tag));
        let log = w.start(&id, |p| tweak(p), 300);
        let got = probes(&log);
        let reqs = requests(&log);
        let request_of = |name: &str| reqs.get(name).map_or("?", String::as_str).to_string();
        let Some(Some(app)) = got.get("app") else {
            failures.push(format!(
                "{mode}: the app's own probe gave no result; log:\n{log}"
            ));
            continue;
        };
        let app_can = abilities(app);
        let app_mounts = mounts_of(app);
        if app_mounts.is_empty() {
            failures.push(format!("{mode}: the app's mounts could not be read"));
            continue;
        }
        let built: Vec<(&String, &serde_json::Value)> = got
            .iter()
            .filter(|(n, _)| n.starts_with("room-"))
            .filter_map(|(n, r)| r.as_ref().map(|r| (n, r)))
            .collect();
        eprintln!("compare: {mode}: {} of 60 rooms built", built.len());
        // The controls: the request for everything was built, and enough
        // others for the comparison to mean something.
        if !got.get("room-0").is_some_and(Option::is_some) {
            failures.push(format!(
                "{mode}: the room asking for everything (--bind / /) was not built, so nothing was compared"
            ));
        }
        if built.len() < 20 {
            failures.push(format!(
                "{mode}: only {} of 60 rooms were built, so Room service is missing or refuses too much",
                built.len()
            ));
        }
        for (name, room) in &built {
            for (k, v) in abilities(room) {
                if v && !app_can.get(&k).copied().unwrap_or(false) {
                    failures.push(format!(
                        "{mode}: {name} got {k}, its app has not (request: {})",
                        request_of(name)
                    ));
                }
            }
            let room_mounts = mounts_of(room);
            if room_mounts.is_empty() {
                failures.push(format!("{mode}: {name}: its mounts could not be read"));
            }
            for (dev, root, at, _) in writable_beyond_app(&room_mounts, &app_mounts, &host_devices)
            {
                failures.push(format!(
                    "{mode}: {name} has {root} of device {dev} writable at {at}, which its app has read-only (request: {})",
                    request_of(name)
                ));
            }
            for (dev, root, at, _) in mounts_beyond_app(&room_mounts, &app_mounts, &host_devices) {
                failures.push(format!(
                    "{mode}: {name} shows {root} of device {dev} at {at}, which its app is not shown (request: {})",
                    request_of(name)
                ));
            }
        }
        // Writes, judged on the computer: a room's marker only where the
        // app's marker is too.
        let mut places: Vec<PathBuf> = vec![
            w.app_home(&id),
            w.app_home(&id).join("sub"),
            w.app_home(&id).join(".config/autostart"),
            w.home.clone(),
            w.home.join("sub"),
            w.home.join(".config/autostart"),
            w.secret_dir.clone(),
            w.other_app.clone(),
            w.sam.paths.config_dir.clone(),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ];
        places.extend(w.app_dirs().iter().map(|d| d.join("usr/bin")));
        for place in &places {
            let found: BTreeSet<String> = markers(place, &tag).into_iter().collect();
            let app_there = found.contains(&format!("{tag}-app"));
            for m in &found {
                if let Some((_, i)) = m.rsplit_once("-room-") {
                    if !app_there {
                        failures.push(format!(
                            "{mode}: room-{i} wrote to {} where its app cannot (request: {})",
                            place.display(),
                            request_of(&format!("room-{i}"))
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "rooms got more than their app (seed {seed}):\n{}",
        failures.join("\n")
    );
}
