//! What SAM reads about this computer matches the real kernel and tools:
//! the Landlock version, Bubblewrap's overlays, the loader's library
//! folders and the graphics devices. The logic behind each is tested with
//! stand-ins in sam-core (host.rs); these tests tie it to the real thing.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sam_core::host;
use sam_runner::contracts::{not_here, skip};

fn skip_or_fail(reason: &str) {
    skip(reason).unwrap_or_else(|e| panic!("{e}"));
}

/// The lowest Landlock version a kernel of this release offers (each
/// version came with the kernel named here).
fn least_landlock_abi(release: &str) -> u32 {
    let mut it = release
        .split(|c: char| !c.is_ascii_digit())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let v = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    [
        ((6, 12), 6),
        ((6, 10), 5),
        ((6, 7), 4),
        ((6, 2), 3),
        ((5, 19), 2),
        ((5, 13), 1),
    ]
    .iter()
    .find(|(since, _)| v >= *since)
    .map_or(1, |(_, abi)| *abi)
}

/// The Landlock version SAM reads is the kernel's: none where Landlock is
/// not active, and at least the version this kernel brings where it is
/// (a wrong one turns layers on that do not exist, or switches off the
/// check that Landlock fences abstract sockets).
#[test]
fn the_landlock_version_is_the_kernels() {
    let Ok(lsm) = fs::read_to_string("/sys/kernel/security/lsm") else {
        return skip_or_fail("the list of active security modules cannot be read");
    };
    let abi = host::landlock_abi();
    if !lsm.trim().split(',').any(|m| m == "landlock") {
        assert_eq!(abi, None, "Landlock is not active: {lsm}");
        return;
    }
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let least = least_landlock_abi(release.trim());
    assert!(
        abi.is_some_and(|v| v >= least),
        "kernel {} offers Landlock {least} or newer, SAM read {abi:?}",
        release.trim()
    );
}

#[test]
fn the_kernel_release_gives_the_least_landlock_version() {
    assert_eq!(least_landlock_abi("7.3.4-1-cachyos"), 6);
    assert_eq!(least_landlock_abi("6.8.0-1017-azure"), 4);
    assert_eq!(least_landlock_abi("6.12.0"), 6);
    assert_eq!(least_landlock_abi("5.15.0-91-generic"), 1);
    assert_eq!(least_landlock_abi("5.19.1"), 2);
}

/// A syscall filter of the test's own: Landlock's call (444 on every
/// processor SAM asks it on) "succeeds" with 0 without reaching the kernel,
/// as a container's or another sandbox's filter may answer calls it does
/// not know; everything else is allowed.
fn landlock_answers_zero() -> Vec<libc::sock_filter> {
    let op = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    const LD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RET: u16 = 0x06; // BPF_RET | BPF_K
    vec![
        op(LD, 0, 0, 0),                        // the call's number
        op(JEQ, 0, 1, 444),                     // landlock_create_ruleset
        op(RET, 0, 0, libc::SECCOMP_RET_ERRNO), // "error" 0: success
        op(RET, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

/// Where Landlock's version query answers 0 (no version at all; a filter
/// SAM runs under that fakes success), SAM counts no Landlock: it must
/// never report or plan on a protection layer that is not there.
#[test]
fn a_landlock_answer_of_zero_is_no_landlock() {
    let filter = landlock_answers_zero();
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: the child only makes system calls and ends with _exit; the
    // filter was built before the fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // SAFETY: plain system calls on memory that lives until _exit.
        let code = unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &prog as *const libc::sock_fprog,
                ) != 0
            {
                2
            } else if libc::syscall(444, std::ptr::null::<u8>(), 0usize, 1u32) != 0 {
                3 // the filter did not answer the call
            } else if host::landlock_abi().is_some() {
                1
            } else {
                0
            }
        };
        // SAFETY: ends the child without running the parent's cleanup.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY: waits for the child started above.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "status {status}");
    match libc::WEXITSTATUS(status) {
        0 => {}
        1 => panic!("an answer of 0 was taken for a Landlock version"),
        3 => panic!("the test's filter did not answer Landlock's call"),
        _ => skip_or_fail("a syscall filter cannot be loaded here"),
    }
}

/// Bubblewrap's overlay, tried the way the writable app folder needs it,
/// with its changes in `dir`: the real tool's answer.
fn real_overlay_works(bwrap: &Path, dir: &Path) -> bool {
    for d in ["lower", "upper", "work"] {
        fs::create_dir_all(dir.join(d)).unwrap();
    }
    Command::new(bwrap)
        .args(["--unshare-user", "--ro-bind", "/", "/", "--tmpfs", "/tmp"])
        .arg("--overlay-src")
        .arg(dir.join("lower"))
        .arg("--overlay")
        .arg(dir.join("upper"))
        .arg(dir.join("work"))
        .args(["/tmp/o", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// SAM offers the writable app folder exactly where the real Bubblewrap
/// can give it: overlays only from a Bubblewrap that has them (it lists
/// `--overlay-src`), and only on a folder where a real overlay works. The
/// check leaves nothing behind.
#[test]
fn the_overlay_checks_match_the_real_bubblewrap() {
    let tmp = tempfile::tempdir().unwrap();
    let sams = tmp.path().join("sam");
    let Some(bwrap) = sam_core::util::which("bwrap") else {
        assert!(!host::bwrap_supports_overlay());
        assert!(!host::overlay_works_in(&sams));
        return skip_or_fail("bubblewrap is not installed");
    };
    let help = Command::new(&bwrap).arg("--help").output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    let has_overlays = text.contains("--overlay-src");
    assert_eq!(host::bwrap_supports_overlay(), has_overlays, "{text}");
    let real = has_overlays && real_overlay_works(&bwrap, &tmp.path().join("own"));
    assert_eq!(host::overlay_works_in(&sams), real);
    let left: Vec<PathBuf> = fs::read_dir(&sams)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert!(left.is_empty(), "the check left {left:?}");
    if !has_overlays {
        not_here("this Bubblewrap has no overlays (older than 0.10)");
    } else if !real {
        skip_or_fail("a real overlay does not work in the test's folder");
    }
}

/// The loader's library folders SAM shows are this computer's: every
/// existing folder its ld.so.conf.d files list, and /usr/local/lib, which
/// is outside the folders a sandbox shows anyway.
#[test]
fn the_loaders_folders_on_this_computer_are_found() {
    let local = Path::new("/usr/local/lib");
    if !local.is_dir() {
        return skip_or_fail("this computer has no /usr/local/lib");
    }
    let dirs = host::loader_lib_dirs();
    assert!(dirs.iter().any(|d| d == local), "{dirs:?}");
    for f in fs::read_dir("/etc/ld.so.conf.d")
        .into_iter()
        .flatten()
        .flatten()
    {
        for l in fs::read_to_string(f.path()).unwrap_or_default().lines() {
            let d = Path::new(l.trim());
            if d.is_absolute() && d.is_dir() {
                assert!(
                    dirs.iter().any(|x| x == d),
                    "{} is missing: {dirs:?}",
                    d.display()
                );
            }
        }
    }
    let extra = host::extra_lib_dirs(Path::new("/nonexistent-home"));
    assert!(extra.iter().any(|d| d == local), "{extra:?}");
}

/// The graphics devices SAM can give an app are this computer's: every
/// entry of /dev/dri and every /dev/nvidia* entry, and nothing else.
#[test]
fn the_graphics_devices_on_this_computer_are_found() {
    let entries = |dir: &str| -> Vec<PathBuf> {
        fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect()
    };
    let mut want = entries("/dev/dri");
    want.extend(entries("/dev").into_iter().filter(|p| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("nvidia"))
    }));
    if want.is_empty() {
        return not_here("this computer has no graphics devices");
    }
    want.sort();
    assert_eq!(sam_core::HostInfo::probe().gpu_devices, want);
}
