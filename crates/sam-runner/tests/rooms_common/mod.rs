//! Shared by the Room service tests: a fake home with secrets outside the
//! app's view, a private session bus, listeners on the computer a room must
//! not reach unless its app can, test AppImages started through SAM's
//! normal path, and the probe that runs inside apps and rooms.
//!
//! Every test file using this has a single test: `World::new` changes the
//! process's environment (HOME, the test's runtime folder, the session bus).
#![allow(clippy::unwrap_used, clippy::panic, dead_code)] // a test helper: a panic is a failed test

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::TcpListener;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sam_core::permissions::PermissionSet;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// The token in every secret file: a room that prints it read a secret.
pub const SECRET: &str = "ROOM-SERVICE-SECRET";

/// A variable of the test process (where SAM's launcher, and so the room
/// service, runs): no app or room may ever see it.
pub const HOST_MARKER: (&str, &str) = ("SAM_ROOMS_HOST_MARKER", "host-environment-leaked");

/// Whether this computer can run the Room service tests: a working
/// Bubblewrap, SAM's helper of this build, and python3 (the probe).
pub fn usable() -> Result<(), String> {
    let host = HostInfo::probe();
    sam_runner::bwrap::check(&host).map_err(|e| format!("Bubblewrap cannot run here: {e}"))?;
    if sam_runner::find_helper().is_none() {
        return Err("SAM's helper sam-jail-run of this build is missing".into());
    }
    if sam_core::util::which("python3").is_none() {
        return Err("python3 is missing (the probe runs in apps and rooms)".into());
    }
    Ok(())
}

/// Skips the test where this computer cannot run it (an error where a run
/// must prove everything, as on CI).
pub fn require() -> bool {
    match usable() {
        Ok(()) => true,
        Err(reason) => {
            sam_runner::contracts::skip(&reason).unwrap_or_else(|e| panic!("{e}"));
            false
        }
    }
}

/// The kernel's Landlock version (0: none). From version 6 on, Landlock
/// also keeps a sandbox off abstract sockets outside it (the kind X11 uses).
pub fn landlock_abi() -> i64 {
    // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
    // SAFETY: the documented way to ask for the version; no memory is passed.
    let v = unsafe { libc::syscall(444, std::ptr::null::<u8>(), 0usize, 1u32) };
    v.max(0)
}

/// The world a test runs in.
pub struct World {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
    /// The fake home of the person (outside every app's view unless the app
    /// is given the home: apps get a private home at the same path).
    pub home: PathBuf,
    pub sam: Sam,
    pub host: HostInfo,
    /// A folder on the computer that no app is shown, holding `f` with the
    /// secret token.
    pub secret_dir: PathBuf,
    /// Another app's private home, with `secret` in it.
    pub other_app: PathBuf,
    /// A port on the computer no app was given.
    pub port: u16,
    _tcp: TcpListener,
    /// An abstract socket outside every sandbox (the kind X11 uses).
    pub abstract_name: String,
    _abstract: UnixListener,
    _services: sam_runner::testenv::PrivateServices,
    /// Files this test leaves outside its temporary folder (markers in /tmp
    /// and /var/tmp), removed when the test ends, whatever its result.
    pub leftovers: std::cell::RefCell<Vec<PathBuf>>,
}

impl World {
    pub fn new() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let sam_root = root.join("sam");
        // The runtime folder of SAM's paths, so that the starts and the
        // process agree where launches live.
        sam_runner::testenv::isolate_this_process(&sam_root);
        let home = root.join("home/tester");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(home.join(".config/autostart")).unwrap();
        fs::write(home.join(".ssh/id_ed25519"), SECRET).unwrap();
        fs::write(home.join(".bashrc"), "# bashrc\n").unwrap();
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
        std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
        std::env::set_var(HOST_MARKER.0, HOST_MARKER.1);
        let secret_dir = root.join("secret");
        fs::create_dir_all(&secret_dir).unwrap();
        fs::write(secret_dir.join("f"), SECRET).unwrap();
        let sam = Sam::with_paths(Paths::rooted(&sam_root)).unwrap();
        fs::create_dir_all(&sam.paths.config_dir).unwrap();
        fs::write(sam.paths.config_file(), format!("# {SECRET}\n")).unwrap();
        let other_app = sam.paths.app_home("appimage-other-1");
        fs::create_dir_all(&other_app).unwrap();
        fs::write(other_app.join("secret"), SECRET).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let abstract_name = format!("sam-rooms-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(abstract_name.as_bytes()).unwrap();
        let abs = UnixListener::bind_addr(&addr).unwrap();
        // A session bus of the test's own: apps get it through SAM's
        // filtered proxy, and a room must get that proxy too, never the bus.
        let services = sam_runner::testenv::PrivateServices::start(&sam_root);
        let host =
            services.apply_to_this_process(sam_runner::testenv::test_host(HostInfo::probe()));
        World {
            _tmp: tmp,
            root,
            home,
            sam,
            host,
            secret_dir,
            other_app,
            port,
            _tcp: tcp,
            abstract_name,
            _abstract: abs,
            _services: services,
            leftovers: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Adds a test AppImage whose start script is the prelude plus `script`,
    /// the way any AppImage is added (SAM's recommended settings).
    pub fn add(&self, name: &str, script: &str) -> String {
        let img = self.root.join(format!("{name}.AppImage"));
        let mut spec = FixtureSpec::hello(name);
        spec.apprun = format!("#!/bin/sh\n{}\n{script}\n", self.prelude());
        spec.host_binary = None;
        spec.files.push(FixtureFile {
            path: "usr/bin/probe.py".into(),
            data: PROBE_PY.as_bytes().to_vec(),
            mode: 0o755,
        });
        build(&img, &spec).unwrap();
        self.sam
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
            .id
    }

    /// Starts the app with its settings changed by `tweak`; returns the
    /// start's log (stdout and stderr of the app, and SAM's start record).
    pub fn start(
        &self,
        id: &str,
        tweak: impl FnOnce(&mut PermissionSet),
        timeout_secs: u64,
    ) -> String {
        let mut e = self.sam.resolve(id).unwrap();
        tweak(&mut e.profile.permissions);
        let rec = run(
            &mut e,
            &LaunchOptions {
                quiet: true,
                timeout_secs: Some(timeout_secs),
                ..Default::default()
            },
            &self.sam.config,
            &self.sam.paths,
            &self.host,
        )
        .unwrap_or_else(|e| panic!("the start of {id} failed: {e:#}"));
        fs::read_to_string(rec.log_file.unwrap()).unwrap()
    }

    /// The app's private home on the computer.
    pub fn app_home(&self, id: &str) -> PathBuf {
        self.sam.paths.app_home(id)
    }

    /// The app folders SAM unpacked, on the computer.
    pub fn app_dirs(&self) -> Vec<PathBuf> {
        fs::read_dir(self.sam.paths.default_extracted_dir())
            .unwrap()
            .flatten()
            .map(|d| d.path().join("AppDir"))
            .collect()
    }

    /// Shell helpers for every test app:
    /// - `room ARGS…` asks for a Bubblewrap sandbox the way glycin does
    ///   (`/usr`, the system's top-level folders as this system has them,
    ///   and the app's own folder for the probe), plus ARGS;
    /// - `rv CMD…` prints what CMD printed, or `refused` when it printed
    ///   nothing (no room was built);
    /// - `say NAME VALUE` reports one result as `CASE NAME=VALUE`;
    /// - `$P` runs the probe.
    pub fn prelude(&self) -> String {
        format!(
            r#"SYS=""
for d in /bin /sbin /lib /lib32 /lib64; do
  if [ -L "$d" ]; then SYS="$SYS --symlink $(readlink "$d") $d"
  elif [ -d "$d" ]; then SYS="$SYS --ro-bind $d $d"; fi
done
P="/usr/bin/python3 -I -S $APPDIR/usr/bin/probe.py"
room() {{ bwrap --ro-bind /usr /usr $SYS --ro-bind "$APPDIR" "$APPDIR" "$@"; }}
rv() {{ out=$("$@" 2>/dev/null); [ -n "$out" ] && echo "$out" || echo refused; }}
say() {{ echo "CASE $1=$2"; }}
SECRET_FILE={secret}/f
SECRET_DIR={secret}
OTHER_APP={other}/secret
SAM_SETTINGS={settings}
HOST_KEY={home}/.ssh/id_ed25519
PORT={port}
ABSTRACT={abs}
TEST_PID={pid}
export SECRET_FILE SECRET_DIR OTHER_APP SAM_SETTINGS HOST_KEY PORT ABSTRACT TEST_PID"#,
            secret = self.secret_dir.display(),
            other = self.other_app.display(),
            settings = self.sam.paths.config_file().display(),
            home = self.home.display(),
            port = self.port,
            abs = self.abstract_name,
            pid = std::process::id(),
        )
    }
}

impl Drop for World {
    fn drop(&mut self) {
        for p in self.leftovers.borrow().iter() {
            let _ = fs::remove_file(p);
        }
    }
}

/// The `CASE NAME=VALUE` lines of a log (the last value of each name wins).
pub fn cases(log: &str) -> BTreeMap<String, String> {
    log.lines()
        .filter_map(|l| l.trim().strip_prefix("CASE "))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.trim().to_string()))
        .collect()
}

/// Checks `want` for every named case (a value may list choices as
/// `a|b`), collecting all mismatches.
pub fn check(log: &str, want: &[(&str, &str)]) -> Vec<String> {
    let got = cases(log);
    want.iter()
        .filter_map(|(k, v)| match got.get(*k) {
            Some(g) if v.split('|').any(|c| c == g) => None,
            Some(g) => Some(format!("{k}: wanted {v}, got {g}")),
            None => Some(format!("{k}: no result")),
        })
        .collect()
}

/// The processes on the computer running exactly these arguments.
pub fn processes(args: &[&str]) -> Vec<i32> {
    let want: Vec<u8> = args
        .iter()
        .flat_map(|a| [a.as_bytes(), b"\0"].concat())
        .collect();
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|d| {
            let pid = d.file_name().to_str()?.parse::<i32>().ok()?;
            Some((pid, d.path()))
        })
        .filter(|(_, p)| fs::read(p.join("cmdline")).is_ok_and(|c| c == want))
        .map(|(p, _)| p)
        .collect()
}

/// Ends processes a failed test left running.
pub fn kill_all(args: &[&str]) {
    for p in processes(args) {
        // SAFETY: a plain signal to a process of this user.
        unsafe { libc::kill(p, libc::SIGKILL) };
    }
}

/// The open file descriptors of this process.
pub fn open_fds() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

/// The version line of the Bubblewrap SAM uses on this computer.
pub fn host_bwrap_version(host: &HostInfo) -> String {
    let bwrap = host
        .tools
        .bwrap
        .as_ref()
        .map_or_else(|| PathBuf::from("bwrap"), |t| t.path.clone());
    let out = Command::new(bwrap)
        .arg("--version")
        .stderr(Stdio::null())
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Files in `dir` whose name starts with `prefix`.
pub fn markers(dir: &Path, prefix: &str) -> Vec<String> {
    fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .filter_map(|d| d.file_name().into_string().ok())
                .filter(|n| n.starts_with(prefix))
                .collect()
        })
        .unwrap_or_default()
}

/// The devices (`major:minor`) of the computer's own mounts: a mount in a
/// sandbox on one of them shows a folder of the computer; any other device
/// is a filesystem made fresh for the sandbox (Bubblewrap's tmpfs, /proc).
pub fn host_mount_devices() -> BTreeSet<String> {
    fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2).map(str::to_string))
        .collect()
}

/// One mount as the probe reports it: device, folder within that device's
/// filesystem, where it is mounted.
pub type Mount = (String, String, String);

pub fn mounts_of(probe: &serde_json::Value) -> Vec<Mount> {
    probe["mounts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let m = m.as_array()?;
                    Some((
                        m.first()?.as_str()?.to_string(),
                        m.get(1)?.as_str()?.to_string(),
                        m.get(2)?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `inner` is `outer` or a path below it.
pub fn path_within(inner: &str, outer: &str) -> bool {
    let outer = outer.trim_end_matches('/');
    outer.is_empty() || inner == outer || inner.starts_with(&format!("{outer}/"))
}

/// The room's mounts that show a folder of the computer the app is not
/// shown: on a device of the computer, and not at or below a folder that
/// one of the app's mounts of that device shows.
pub fn mounts_beyond_app(
    room: &[Mount],
    app: &[Mount],
    host_devices: &BTreeSet<String>,
) -> Vec<Mount> {
    room.iter()
        .filter(|(dev, _, _)| host_devices.contains(dev))
        .filter(|(dev, root, _)| !app.iter().any(|(d, r, _)| d == dev && path_within(root, r)))
        .cloned()
        .collect()
}

/// The probe, run inside apps and rooms. One word per check: `allowed` or
/// `blocked`; `read` is `allowed` only when the file held the secret token.
///   probe.py read FILE | write DIR NAME | tcp PORT | abstract NAME |
///            keyctl | uname | userns | pids | fds | devices | env NAME |
///            ids PATH… | all PORT ABSTRACT WRITER FILE… -- DIR…
pub const PROBE_PY: &str = r#"#!/usr/bin/python3
import ctypes, json, os, socket, sys

SECRET = "ROOM-SERVICE-SECRET"
libc = ctypes.CDLL(None, use_errno=True)
# The machine from the ELF loader's name, not uname (a room's filter may
# refuse uname).
MACHINE = "aarch64" if os.path.exists("/lib/ld-linux-aarch64.so.1") else "x86_64"
KEYCTL = {"x86_64": 250, "aarch64": 219}[MACHINE]

def read(path):
    try:
        with open(path, errors="replace") as f:
            return SECRET in f.read(4096)
    except OSError:
        return False

def write(d, name):
    try:
        with open(os.path.join(d, name), "w") as f:
            f.write("x")
        return True
    except OSError:
        return False

def tcp(port):
    try:
        socket.create_connection(("127.0.0.1", int(port)), timeout=3).close()
        return True
    except OSError:
        return False

def abstract(name):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    try:
        s.connect("\0" + name)
        return True
    except OSError:
        return False
    finally:
        s.close()

def keyctl():
    r = libc.syscall(KEYCTL, 0, -3, 0)  # KEYCTL_GET_KEYRING_ID, session keyring
    return r >= 0 or ctypes.get_errno() not in (1, 38)  # EPERM, ENOSYS: blocked

def userns():
    return libc.unshare(0x10000000) == 0  # CLONE_NEWUSER

def mounts():
    out = []
    try:
        for line in open("/proc/self/mountinfo"):
            f = line.split()
            out.append([f[2], f[3], f[4]])
    except OSError:
        return None
    return out

def word(ok):
    return "allowed" if ok else "blocked"

a = sys.argv[1:]
k = a[0]
if k == "read":
    print(word(read(a[1])))
elif k == "write":
    print(word(write(a[1], a[2])))
elif k == "tcp":
    print(word(tcp(a[1])))
elif k == "abstract":
    print(word(abstract(a[1])))
elif k == "keyctl":
    print(word(keyctl()))
elif k == "uname":
    try:
        os.uname()
        print("allowed")
    except OSError:
        print("blocked")
elif k == "userns":
    print(word(userns()))
elif k == "pids":
    print(sum(1 for n in os.listdir("/proc") if n.isdigit()))
elif k == "fds":
    fds = []
    for n in os.listdir("/proc/self/fd"):
        try:
            os.fstat(int(n))
            fds.append(int(n))
        except OSError:
            pass  # the folder listing's own, closed again
    print(",".join(str(f) for f in sorted(fds)))
elif k == "devices":
    try:
        print(" ".join(sorted(os.listdir("/dev"))) or "none")
    except OSError:
        print("none")
elif k == "env":
    print(os.environ.get(a[1], "none"))
elif k == "ids":
    r = {}
    for p in a[1:]:
        try:
            st = os.stat(p)
            r[p] = f"{st.st_dev}:{st.st_ino}"
        except OSError:
            r[p] = None
    print(json.dumps(r, sort_keys=True))
elif k == "all":
    port, name, writer = a[1], a[2], a[3]
    i = a.index("--")
    files, dirs = a[4:i], a[i + 1:]
    r = {"tcp": tcp(port), "abstract": abstract(name), "keyctl": keyctl()}
    for f in files:
        r["read:" + f] = read(f)
    for d in dirs:
        write(d, writer)  # judged on the computer afterwards
    print(json.dumps({"can": r, "mounts": mounts()}, sort_keys=True))
"#;
