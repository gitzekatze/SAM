//! Breakout attempts: a probe app tries to get out of its sandbox in ways
//! `docs/security.md` says are blocked, and every attempt must fail.
//!
//! Covers what the other end-to-end tests do not: the syscall filter
//! (keyrings, userfaultfd, namespaces, perf, terminal injection), Landlock
//! behind a wrongly writable mount, abstract sockets of the host, a
//! read-only `/`, a private `/dev/shm`, the cleared environment, the
//! systemd-run stand-in, and full home access (persistence paths stay
//! read-only, also when they do not exist yet; credential stores and SAM's
//! own data stay hidden).
//!
//! Syscall numbers follow the architecture (x86_64 or aarch64).
//!
//! Uses a fake `$HOME`. Skipped when Bubblewrap cannot run, or when
//! sam-jail-run (which applies Landlock and seccomp) or python3 is missing.

use std::collections::HashMap;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::Path;

use sam_core::permissions::*;
use sam_core::{HostInfo, Paths};
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use sam_runner::launch::{run, LaunchOptions};
use sam_runner::ops::{AddOptions, Sam};

/// Prints KEY=VALUE lines. Syscalls are made directly (x86_64 numbers), so
/// each result is the kernel's answer, not a library's.
const PROBE_PY: &str = r#"
import ctypes, errno, os, socket, subprocess, sys
print("ENVKEYS=" + ",".join(sorted(k for k in os.environ if k.startswith("SAM"))))
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def sc(nr, *a):
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(x) for x in a])
    return r, ctypes.get_errno()
def show(key, r):
    print(f"{key}=" + ("ok" if r[0] >= 0 else errno.errorcode.get(r[1], str(r[1]))))
# Syscall numbers differ per architecture (x86_64, and the generic table
# that aarch64 uses).
import platform
ARM = platform.machine() in ("aarch64", "arm64")
NR = dict(keyctl=219, userfaultfd=282, unshare=97, perf=241, bpf=280, init_module=105,
          open_by_handle=265, syslog=116, ioctl=29, io_uring_setup=425) if ARM else \
     dict(keyctl=250, userfaultfd=323, unshare=272, perf=298, bpf=321, init_module=175,
          open_by_handle=304, syslog=103, ioctl=16, io_uring_setup=425)
# Calls that work for an ordinary user without the filter.
show("SC_KEYCTL", sc(NR["keyctl"], 0, -3, 0))            # keyctl(GET_KEYRING_ID, SESSION)
show("SC_USERFAULTFD", sc(NR["userfaultfd"], 1))         # userfaultfd(UFFD_USER_MODE_ONLY)
show("SC_UNSHARE", sc(NR["unshare"], 0))                 # unshare(0)
show("SC_PERF", sc(NR["perf"], 0, 0, -1, -1, 0))         # perf_event_open(NULL, ...)
show("SC_BPF", sc(NR["bpf"], 9999, 0, 0))                # bpf(invalid cmd)
show("SC_INIT_MODULE", sc(NR["init_module"], 0, 0, 0))
show("SC_OPEN_BY_HANDLE", sc(NR["open_by_handle"], -1, 0, 0))
show("SC_SYSLOG", sc(NR["syslog"], 10, 0, 0))            # SYSLOG_ACTION_SIZE_BUFFER
show("SC_IO_URING", sc(NR["io_uring_setup"], 1, 0))      # io_uring_setup(1, NULL): EFAULT unfiltered
show("SC_TIOCSTI", sc(NR["ioctl"], 0, 0x5412, 0))        # ioctl(0, TIOCSTI): ENOTTY unfiltered
show("SC_TIOCLINUX", sc(NR["ioctl"], 0, 0x541C, 0))
# The same calls through the x32 ABI (bit 30, x86_64 only): the filter
# answers before the kernel would say ENOSYS, so EPERM proves x32 is covered.
if ARM:
    print("SC_X32_KEYCTL=n/a"); print("SC_X32_UNSHARE=n/a")
else:
    show("SC_X32_KEYCTL", sc(250 | 0x40000000, 0, -3, 0))
    show("SC_X32_UNSHARE", sc(272 | 0x40000000, 0))
# Abstract socket created by the test on the host.
name = os.environ.get("SAM_TEST_ABSTRACT", "")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("\0" + name); print("ABSTRACT=connected")
except OSError as e:
    print("ABSTRACT=" + errno.errorcode.get(e.errno, str(e.errno)))
# Writes that must fail.
def try_write(key, path):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f: f.write("x")
        print(f"{key}=written")
    except OSError as e:
        print(f"{key}=" + errno.errorcode.get(e.errno, str(e.errno)))
home = os.environ["HOME"]
try_write("ROOT_WRITE", "/sam-breakout-probe")
try_write("LANDLOCK_EXTRA", os.environ.get("SAM_TEST_EXTRA", "/nonexistent") + "/landlock.txt")
for key, rel in [("P_AUTOSTART", ".config/autostart/evil.desktop"), ("P_AUTOSTART_NEW", ".config/autostart-new-test/evil"),
                 ("P_SYSTEMD", ".config/systemd/user/evil.service"), ("P_BASHRC", ".bashrc"),
                 ("P_LOCALBIN", ".local/bin/ls"), ("P_DBUS_SERVICES", ".local/share/dbus-1/services/evil.service"),
                 ("P_MIMEAPPS", ".config/mimeapps.list"), ("P_APPLICATIONS", ".local/share/applications/evil.desktop"),
                 ("P_KWIN_SCRIPTS", ".local/share/kwin/scripts/evil/metadata.json"), ("P_GITCONFIG", ".gitconfig"),
                 ("P_SAM_CONFIG", ".config/sam/config.toml")]:
    try_write(key, home + "/" + rel)
for key, rel in [("H_KEYRINGS", ".local/share/keyrings/login.keyring"), ("H_PASS", ".password-store/bank.gpg"),
                 ("H_AWS", ".aws/credentials"), ("H_SSH", ".ssh/id_ed25519"), ("H_SAM", ".config/sam/config.toml")]:
    try:
        data = open(home + "/" + rel).read(); print(f"{key}=readable:{data[:8]}")
    except OSError as e:
        print(f"{key}=" + errno.errorcode.get(e.errno, str(e.errno)))
# SAM's own registry, inside a folder the app may read.
samdir = os.environ.get("SAM_TEST_SAMDIR", "/nonexistent")
def has_files(d):
    try: return len(os.listdir(d)) > 0
    except OSError: return False
print("SAM_REGISTRY=" + ("visible" if has_files(samdir + "/data") or has_files(samdir + "/config") else "hidden"))
# Private /dev/shm and the environment.
token = os.environ.get("SAM_TEST_TOKEN", "none")
try:
    open("/dev/shm/sam-breakout-" + token, "w").write("x"); print("SHM=written")
except OSError as e:
    print("SHM=" + str(e.errno))
print("ENV_SECRET=" + ("leaked" if "SAM_TEST_HOST_SECRET" in os.environ else "absent"))
# systemd-run runs the command inside the sandbox.
out = subprocess.run(["systemd-run", "--user", "--scope", "--unit=x.scope", "sh", "-c", "echo ${SAM_SANDBOX:-outside}"], capture_output=True, text=True)
print("SYSTEMD_RUN=" + (out.stdout.strip() or "error:" + out.stderr.strip()[:60]))
st = open("/proc/self/status").read()
for line in st.splitlines():
    k, _, v = line.partition(":")
    if k in ("CapEff", "NoNewPrivs", "Seccomp"):
        print(f"{k.upper()}={v.strip()}")
print("END=1")
"#;

const APPRUN: &str = "#!/bin/sh\nexec python3 \"$APPDIR/usr/bin/breakout.py\"\n";

fn usable() -> bool {
    let host = HostInfo::probe();
    host.tools.bwrap.is_some() && sam_runner::doctor::bwrap_functional(&host).is_ok() && sam_runner::find_helper().is_some() && sam_core::util::which("python3").is_some()
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

#[test]
fn breakout_attempts_fail() {
    if !usable() {
        eprintln!("skipping: bubblewrap, sam-jail-run or python3 not available");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    for d in ["Documents", ".ssh", ".aws", ".password-store", ".local/share/keyrings", ".config/autostart", ".config/systemd/user", ".config/sam", ".local/share/applications"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    for (f, data) in [(".ssh/id_ed25519", "KEY"), (".aws/credentials", "AWS"), (".password-store/bank.gpg", "PASS"), (".local/share/keyrings/login.keyring", "RING"), (".bashrc", "# bashrc"), (".config/sam/config.toml", "# sam")] {
        fs::write(home.join(f), data).unwrap();
    }
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));

    let img = root.join("Breakout-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Breakout");
    spec.apprun = APPRUN.into();
    spec.host_binary = None;
    spec.files.push(FixtureFile { path: "usr/bin/breakout.py".into(), data: PROBE_PY.as_bytes().to_vec(), mode: 0o644 });
    build(&img, &spec).unwrap();
    let app = Sam::with_paths(Paths::rooted(&root.join("sam"))).unwrap();
    let id = app.add(&img, &AddOptions { launcher: Some(false), ..Default::default() }).unwrap().entry.id;
    let host = HostInfo::probe();

    // A host abstract socket, a secret in the environment, a /dev/shm token.
    let abstract_name = format!("sam-breakout-{}", std::process::id());
    let listener = {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes()).unwrap();
        UnixListener::bind_addr(&addr).unwrap()
    };
    let token = format!("{}", std::process::id());
    std::env::set_var("SAM_TEST_HOST_SECRET", "topsecret");

    let launch = |p: PermissionSet| {
        let mut p = p;
        p.environment.set.insert("SAM_TEST_ABSTRACT".into(), abstract_name.clone());
        p.environment.set.insert("SAM_TEST_TOKEN".into(), token.clone());
        let mut e = app.set_permissions(&id, p).unwrap();
        let rec = run(&mut e, &LaunchOptions { quiet: true, ..Default::default() }, &app.config, &app.paths, &host).unwrap();
        let log = rec.log_file.clone().unwrap();
        let r = parse(&log);
        let errors: String = fs::read_to_string(&log).unwrap().lines().filter(|l| l.starts_with("[err]")).collect::<Vec<_>>().join("\n");
        assert_eq!(r.get("END").map(String::as_str), Some("1"), "probe did not finish: {}\n{errors}\n{r:?}", rec.summary);
        r
    };

    // 1. Full network (shares the host's network namespace, so abstract
    //    sockets would be reachable without Landlock), an extra folder
    //    outside the home granted read-only but mounted writable by a raw
    //    Bubblewrap argument.
    // Outside every place Landlock lets the app write (its home, /tmp,
    // /var/tmp, /dev, /proc, the runtime folder): the test's temporary
    // folder may itself be under /tmp (CI), so use Cargo's folder for tests.
    let extra_dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let extra = extra_dir.path().join("shared-readonly");
    fs::create_dir_all(&extra).unwrap();
    assert!(!extra.starts_with("/tmp") && !extra.starts_with("/var/tmp"), "{}", extra.display());
    let mut p = PermissionSet::strict_gui();
    p.network.mode = NetworkMode::Full;
    let ex = extra.display().to_string();
    // The whole test folder, which holds SAM's config and data (sam/).
    p.filesystem.custom_read = vec![ex.clone(), root.display().to_string()];
    p.environment.set.insert("SAM_TEST_SAMDIR".into(), root.join("sam").display().to_string());
    p.advanced.extra_bwrap_args = vec!["--bind".into(), ex.clone(), ex.clone()];
    p.environment.set.insert("SAM_TEST_EXTRA".into(), ex);
    let r = launch(p);

    // The syscall filter: calls an ordinary user may make are refused.
    for k in ["SC_KEYCTL", "SC_USERFAULTFD", "SC_UNSHARE", "SC_IO_URING", "SC_TIOCSTI", "SC_TIOCLINUX", "SC_X32_KEYCTL", "SC_X32_UNSHARE"] {
        if r[k] == "n/a" {
            continue; // x32 exists only on x86_64
        }
        assert_eq!(r[k], "EPERM", "{k} is blocked by the syscall filter");
    }
    for k in ["SC_PERF", "SC_BPF", "SC_INIT_MODULE", "SC_OPEN_BY_HANDLE", "SC_SYSLOG"] {
        assert_ne!(r[k], "ok", "{k} must not succeed");
    }
    assert_eq!(r["SECCOMP"], "2", "seccomp filter mode");
    assert_eq!(r["NONEWPRIVS"], "1");
    assert_eq!(r["CAPEFF"], "0000000000000000");
    // Landlock: the raw --bind made the folder writable as a mount, but the
    // profile says read-only, so the kernel refuses the write.
    assert_eq!(r["LANDLOCK_EXTRA"], "EACCES", "Landlock blocks writes the profile does not allow");
    assert!(!extra.join("landlock.txt").exists());
    // Abstract sockets of the host (Landlock ABI 6, kernel 6.12+).
    if host.landlock_abi.is_some_and(|v| v >= 6) {
        assert_ne!(r["ABSTRACT"], "connected", "host abstract sockets are blocked");
    }
    assert_ne!(r["ROOT_WRITE"], "written", "/ is read-only");
    assert_eq!(r["SAM_REGISTRY"], "hidden", "SAM's own folders stay hidden inside granted folders");
    assert_eq!(r["SHM"], "written", "the app has a /dev/shm of its own");
    assert!(!Path::new(&format!("/dev/shm/sam-breakout-{token}")).exists(), "/dev/shm is private");
    assert_eq!(r["ENV_SECRET"], "absent", "host environment is not passed in");
    assert_eq!(r["SYSTEMD_RUN"], "bubblewrap", "systemd-run runs the command inside the sandbox");
    // Strict profile: credential stores live in the real home, which is not there.
    assert!(!r["H_SSH"].starts_with("readable"));

    // 2. Full home read/write: persistence paths read-only (also missing
    //    ones), credential stores and SAM's own data hidden.
    let mut p = PermissionSet::strict_gui();
    p.filesystem.home = true;
    p.filesystem.home_access = Access::Rw;
    let r = launch(p);
    let protected = ["P_AUTOSTART", "P_SYSTEMD", "P_BASHRC", "P_LOCALBIN", "P_DBUS_SERVICES", "P_MIMEAPPS", "P_APPLICATIONS", "P_KWIN_SCRIPTS", "P_GITCONFIG"];
    let written: Vec<&str> = protected.iter().copied().filter(|k| r[*k] == "written").collect();
    assert!(written.is_empty(), "persistence paths writable under full home: {written:?}");
    assert_eq!(r["P_AUTOSTART_NEW"], "written", "ordinary folders stay writable with full home");
    for k in ["H_KEYRINGS", "H_PASS", "H_AWS", "H_SSH"] {
        assert!(!r[k].starts_with("readable"), "{k} stays hidden under full home: {}", r[k]);
    }
    assert_ne!(r["H_SAM"], "readable:# sam", "SAM's real configuration is hidden");
    assert_eq!(fs::read_to_string(home.join(".bashrc")).unwrap(), "# bashrc", "startup file unchanged");
    // SAM's own folder is replaced by an empty, throwaway one: writes land
    // there, never in the real configuration.
    assert_eq!(fs::read_to_string(home.join(".config/sam/config.toml")).unwrap(), "# sam", "SAM's configuration unchanged");
    for rel in [".config/autostart/evil.desktop", ".local/bin/ls", ".local/share/dbus-1/services/evil.service", ".local/share/kwin/scripts/evil/metadata.json"] {
        assert!(!home.join(rel).exists(), "{rel} was not created on the host");
    }
    // Created empty by SAM so they could be mounted read-only; still empty.
    for rel in [".config/mimeapps.list", ".gitconfig"] {
        assert_eq!(fs::read_to_string(home.join(rel)).unwrap(), "", "{rel} stays empty");
    }
    drop(listener);
}
