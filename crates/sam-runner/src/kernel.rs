//! Kernel security features: Landlock and seccomp.
//!
//! * Landlock is applied *inside* the sandbox by `sam-jail-run --sandbox-exec`
//!   (a Landlock domain cannot set up mounts, so it must come after bwrap).
//!   Reads stay allowed everywhere the mounts allow; writes are limited to the
//!   locations the profile grants read/write. This is defense in depth for the
//!   bind-mount layout, not a complete sandbox.
//!   It also scopes abstract UNIX sockets (Landlock ABI 6): the app cannot
//!   connect to abstract sockets created outside the sandbox, e.g. XWayland's
//!   `@/tmp/.X11-unix/X0`, which is reachable whenever the app shares the
//!   host network namespace.
//! * Seccomp filters are compiled with seccompiler and loaded by the same
//!   helper right before exec: a baseline filter (on by default, similar to
//!   Flatpak's) and an optional strict one. Loading them in the helper rather
//!   than via `bwrap --seccomp <fd>` also works when bwrap runs under pasta,
//!   which does not pass extra file descriptors on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use sam_core::permissions::*;
use sam_core::util::expand_home;
use sam_core::HostInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxSpec {
    pub landlock: Option<LandlockSpec>,
    #[serde(default)]
    pub seccomp: Option<SeccompSpec>,
    /// Sandbox check: run these checks instead of the app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<crate::probe::ProbePlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeccompSpec {
    /// Also apply the strict filter on top of the baseline.
    pub strict: bool,
    /// Nested sandboxes allowed (Chromium, Electron, WebKit's bwrap):
    /// keep unshare/setns and the mount family.
    pub allow_userns: bool,
    /// Bluetooth sockets allowed (the Bluetooth switch).
    #[serde(default)]
    pub bluetooth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LandlockSpec {
    /// Paths that are readable and executable.
    pub read: Vec<PathBuf>,
    /// Paths that are fully writable.
    pub write: Vec<PathBuf>,
}

/// Writable locations implied by a permission set (sandbox paths).
/// `extra_write`: paths mounted writable for this launch only, e.g. files
/// passed with "Open with" (else the app could open but not save them).
pub fn landlock_spec(
    p: &PermissionSet,
    host: &HostInfo,
    runtime_dir_in_sandbox: &str,
    extra_write: &[PathBuf],
) -> LandlockSpec {
    let mut write: Vec<PathBuf> = ["/tmp", "/var/tmp", "/dev", "/proc", runtime_dir_in_sandbox]
        .iter()
        .map(PathBuf::from)
        .collect();
    let fs = &p.filesystem;
    if !fs.home || fs.home_access == Access::Rw {
        // Private home (or full home read/write).
        write.push(host.home.clone());
    }
    for key in XDG_DIR_KEYS {
        if fs.xdg_access(key) == Access::Rw {
            if let Some(d) = host.xdg_dir(key) {
                write.push(d.to_path_buf());
            }
        }
    }
    for c in &fs.custom_write {
        write.push(expand_home(c));
    }
    for s in &p.sockets.custom {
        let sp = expand_home(s);
        if sam_sandbox::is_socket(&sp) {
            write.push(sp);
        }
    }
    write.extend(extra_write.iter().cloned());
    LandlockSpec {
        read: vec![PathBuf::from("/")],
        write,
    }
}

/// Entry point for `sam-jail-run --sandbox-exec <spec> -- <cmd...>`:
/// apply restrictions and exec. Never returns on success.
pub fn sandbox_exec(spec_path: &Path, argv: &[String]) -> Result<()> {
    let spec: SandboxSpec = serde_json::from_slice(
        &std::fs::read(spec_path).context(sam_core::i18n::tr("reading sandbox spec"))?,
    )?;
    let (prog, rest) = argv
        .split_first()
        .context(sam_core::i18n::tr("no command given"))?;
    let mut report: Vec<String> = Vec::new();
    if let Some(ll) = &spec.landlock {
        match apply_landlock(ll) {
            Ok(status) => report.push(format!("landlock: {status}")),
            Err(e) => {
                eprintln!("sam-jail: landlock not applied: {e:#}");
                report.push(format!("landlock: NOT applied ({e})"));
            }
        }
    }
    if let Some(sc) = &spec.seccomp {
        // A filter that fails to load must stop the launch: running without
        // it while the UI says it is on would be false confidence.
        apply_seccomp(sc).context(sam_core::i18n::tr("loading the seccomp filter"))?;
        report.push(format!(
            "seccomp: {} loaded",
            if sc.strict { "strict" } else { "baseline" }
        ));
    }
    // Report to SAM on a private fd, then close it before the app runs, so
    // the app cannot forge or read the report.
    if let Some(plan) = &spec.probe {
        // Every layer is in place: check what the app would get, report, stop.
        let r = crate::probe::run(plan, &report.join("; "));
        println!(
            "{}{}",
            crate::probe::REPORT_MARKER,
            serde_json::to_string(&r)?
        );
        std::process::exit(0);
    }
    if let Some(fd) = std::env::var("SAM_STATUS_FD")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
    {
        let line = format!("{}\n", report.join("; "));
        // SAFETY: `line` is a valid buffer of line.len() bytes; `fd` was handed to this process for this one report and is not used afterwards.
        unsafe {
            libc::write(fd, line.as_ptr().cast(), line.len());
            libc::close(fd);
        }
    }
    run_and_reap(prog, rest)
}

/// Starts the app and stays until its last process has ended, not only the
/// first: many start scripts (Pulsar, WezTerm) launch the real program in
/// the background and exit at once, and when the first process of a
/// Bubblewrap sandbox ends, the whole sandbox ends with it. As subreaper the
/// helper inherits such background processes and waits for them too.
/// Returns the exit status of the program it started.
fn run_and_reap(prog: &str, args: &[String]) -> Result<()> {
    // SAFETY: plain prctl; only changes who reaps orphaned descendants.
    unsafe {
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
    let child = Command::new(prog)
        .args(args)
        .env_remove("SAM_STATUS_FD")
        .spawn()
        .with_context(|| format!("starting {prog}"))?;
    let main = child.id() as libc::pid_t;
    // Closing the app (sam-jail stop) signals every process in the sandbox;
    // the helper outlives them so they can quit cleanly. Set only here, in
    // the helper: an ignored signal would be inherited by the app.
    // SAFETY: setting signal dispositions to SIG_IGN.
    unsafe {
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::signal(sig, libc::SIG_IGN);
        }
    }
    let mut code = 0;
    loop {
        let mut status = 0;
        // SAFETY: waitpid on any child, status points to a local.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break; // ECHILD: nothing of the app is left
        }
        if pid == main {
            code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            };
        }
    }
    std::process::exit(code)
}

fn apply_landlock(spec: &LandlockSpec) -> Result<String> {
    use landlock::{
        path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, Scope, ABI,
    };
    let abi = ABI::V3;
    let read = AccessFs::from_read(abi);
    let all = AccessFs::from_all(abi);
    let write_existing: Vec<&PathBuf> = spec.write.iter().filter(|p| p.exists()).collect();
    // Best effort: kernels before 6.12 (ABI 6) ignore the scope.
    let status = Ruleset::default()
        .handle_access(all)
        .map_err(|e| anyhow!("{e}"))?
        .scope(Scope::AbstractUnixSocket)
        .map_err(|e| anyhow!("{e}"))?
        .create()
        .map_err(|e| anyhow!("{e}"))?
        .add_rules(path_beneath_rules(&spec.read, read))
        .map_err(|e| anyhow!("{e}"))?
        .add_rules(path_beneath_rules(&write_existing, all))
        .map_err(|e| anyhow!("{e}"))?
        .restrict_self()
        .map_err(|e| anyhow!("{e}"))?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => "fully enforced",
        RulesetStatus::PartiallyEnforced => "partially enforced",
        RulesetStatus::NotEnforced => "not enforced (kernel too old)",
    }
    .into())
}

/// Calls with their names: `calls![libc::SYS_mount, …]` gives
/// `("mount", number)` on this architecture. The review list
/// (docs/syscalls-reviewed.txt) is compared with these names.
macro_rules! calls {
    ($($p:path),* $(,)?) => {
        vec![$((
            {
                let s = stringify!($p);
                &s[s.rfind("SYS_").map_or(0, |i| i + 4)..]
            },
            $p as i64,
        )),*]
    };
}

/// Syscalls blocked (EPERM) by the baseline filter, on by default. Kernel
/// interfaces no desktop app needs and that have a history of exploits:
/// modules, kexec, BPF, perf, keyrings, userfaultfd, handle-based opens, io_uring.
fn baseline_syscalls(allow_userns: bool) -> Vec<(&'static str, i64)> {
    let mut v = calls![
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_adjtimex,
        // The same as adjtimex and quotactl through another door (audit
        // S-F10: the siblings were blocked, these were not).
        libc::SYS_clock_adjtime,
        libc::SYS_quotactl,
        libc::SYS_quotactl_fd,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_vhangup,
        libc::SYS_syslog,
        // io_uring: a frequent source of kernel privilege escalations,
        // blocked by Docker, ChromeOS and Android too. Programs that use it
        // fall back to ordinary I/O when it is refused.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ];
    // On every processor (it sat with the x86-only calls, so ARM did not
    // block it; found by the review list test on ARM).
    v.extend(calls![libc::SYS_kexec_file_load]);
    // Calls only x86-64 has.
    #[cfg(target_arch = "x86_64")]
    v.extend(calls![libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_uselib]);
    if !allow_userns {
        // Without nested sandboxes nothing inside needs namespaces or mounts.
        v.extend(calls![
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsmount,
            libc::SYS_fsconfig,
            libc::SYS_fspick,
            libc::SYS_mount_setattr,
        ]);
    }
    v
}

/// Additionally blocked by the strict filter.
fn strict_extra_syscalls() -> Vec<(&'static str, i64)> {
    calls![
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_process_vm_readv,
        libc::SYS_personality,
        libc::SYS_mbind,
        libc::SYS_move_pages,
        libc::SYS_migrate_pages,
    ]
}

/// What the filter does with each call it names, as the review list says
/// it: "blocked" (always), "blocked unless nested sandboxes" (nested
/// sandboxes need namespaces and mounts), "blocked by the strict filter"
/// (only with the strict filter on) or "limited" (only some uses refused:
/// `ioctl` typing into the terminal, `socket` the families outside
/// [`SOCKET_FAMILIES`]). Every other call is allowed (audit S-F10: the list
/// said "blocked" for calls the default filter allows).
pub fn review_statuses() -> BTreeMap<&'static str, &'static str> {
    let always: Vec<&str> = baseline_syscalls(true)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let mut out = BTreeMap::new();
    for (n, _) in baseline_syscalls(false) {
        out.insert(
            n,
            if always.contains(&n) {
                "blocked"
            } else {
                "blocked unless nested sandboxes"
            },
        );
    }
    for (n, _) in strict_extra_syscalls() {
        out.insert(n, "blocked by the strict filter");
    }
    out.insert("ioctl", "limited");
    out.insert("socket", "limited");
    // Calls only x86-64 has: blocked there; elsewhere there is no such
    // call. The review list, shared by every processor, says "blocked".
    for n in X86_ONLY {
        out.entry(n).or_insert("blocked");
    }
    out
}

/// Calls only x86-64 has; the filter blocks them there.
const X86_ONLY: [&str; 3] = ["iopl", "ioperm", "uselib"];

/// Socket families every app may open: local sockets, the internet (the
/// network namespace decides whether it leads anywhere) and netlink (the
/// kernel's status channel: network interfaces, device events; glib, udev
/// and Chromium need it). Everything else answers "family not supported",
/// as in Flatpak: virtual-machine sockets (`AF_VSOCK`, not tied to the
/// network namespace), raw packets, kernel crypto (`AF_ALG`) and the other
/// rarely used families with a history of kernel bugs (audit S-F7).
/// Bluetooth only with the Bluetooth switch.
pub const SOCKET_FAMILIES: &[i32] = &[
    libc::AF_UNIX,
    libc::AF_INET,
    libc::AF_INET6,
    libc::AF_NETLINK,
];

/// The part of the filter seccompiler cannot say, put in front of it:
/// - every call through the x32 ABI is refused. x32 programs share the
///   architecture of x86-64 programs but number some calls on their own
///   (x32 `ptrace` is 521, not 101), so blocking each call by its number
///   missed those (audit S-F9). No AppImage is an x32 program.
/// - `socket` opens only the families in [`SOCKET_FAMILIES`].
///
/// These only refuse; whatever passes goes on to seccompiler's filter,
/// which checks the architecture first and ends 32-bit callers.
fn front_filter(spec: &SeccompSpec) -> seccompiler::BpfProgram {
    use seccompiler::sock_filter;
    const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K
    const RET_ERRNO: u32 = 0x0005_0000; // SECCOMP_RET_ERRNO
    const NR: u32 = 0; // seccomp_data.nr
    const ARG0: u32 = 16; // seccomp_data.args[0], low half (little endian)
    const X32: u32 = 0x4000_0000;
    let op = |code, k, jt, jf| sock_filter { code, jt, jf, k };
    let mut families: Vec<u32> = SOCKET_FAMILIES.iter().map(|f| *f as u32).collect();
    if spec.bluetooth {
        families.push(libc::AF_BLUETOOTH as u32);
    }
    let n = families.len() as u8;
    let mut f = vec![
        op(LD_W_ABS, NR, 0, 0),
        op(JSET_K, X32, 0, 1),
        op(RET_K, RET_ERRNO | libc::EPERM as u32, 0, 0),
        // Not `socket`: skip the family check (n compares, 1 load, 1 return).
        op(JEQ_K, libc::SYS_socket as u32, 0, n + 2),
        op(LD_W_ABS, ARG0, 0, 0),
    ];
    for (i, fam) in families.iter().enumerate() {
        // A listed family jumps past the remaining compares and the return.
        f.push(op(JEQ_K, *fam, n - i as u8, 0));
    }
    f.push(op(RET_K, RET_ERRNO | libc::EAFNOSUPPORT as u32, 0, 0));
    f
}

/// The compiled BPF program for a filter spec: [`front_filter`], then the
/// list of blocked calls.
pub fn seccomp_program(spec: &SeccompSpec) -> Result<seccompiler::BpfProgram> {
    let mut program = front_filter(spec);
    program.extend(listed_calls(spec)?);
    Ok(program)
}

/// The filter as `bwrap --seccomp` reads it: the program's instructions,
/// eight bytes each in the machine's byte order.
pub fn filter_bytes(spec: &SeccompSpec) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for i in seccomp_program(spec)? {
        out.extend(i.code.to_ne_bytes());
        out.push(i.jt);
        out.push(i.jf);
        out.extend(i.k.to_ne_bytes());
    }
    Ok(out)
}

/// The calls the filter blocks by number, compiled by seccompiler.
fn listed_calls(spec: &SeccompSpec) -> Result<seccompiler::BpfProgram> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    let arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        bail!(
            "{}",
            sam_core::i18n::tr("seccomp filters are not supported on this architecture")
        );
    };
    let mut list: Vec<i64> = baseline_syscalls(spec.allow_userns)
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    if spec.strict {
        list.extend(strict_extra_syscalls().into_iter().map(|(_, n)| n));
    }
    // x32 calls never get here (`front_filter`); 32-bit calls through
    // int 0x80 fail the architecture check and end the process.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        list.into_iter().map(|s| (s, vec![])).collect();
    // Terminal input injection into the parent's tty (TIOCSTI, TIOCLINUX).
    let ioctl_rule = |req: u64| -> Result<SeccompRule> {
        let c = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, req)
            .map_err(|e| anyhow!("{e}"))?;
        SeccompRule::new(vec![c]).map_err(|e| anyhow!("{e}"))
    };
    rules.insert(
        libc::SYS_ioctl,
        vec![ioctl_rule(libc::TIOCSTI)?, ioctl_rule(0x541C)?],
    );
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| anyhow!("{e}"))?;
    filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| anyhow!("{e}"))
}

fn apply_seccomp(spec: &SeccompSpec) -> Result<()> {
    let prog = seccomp_program(spec)?;
    // Required for unprivileged filters (bwrap sets it too).
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS) takes plain integers and has no memory preconditions.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!("PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error());
    }
    seccompiler::apply_filter(&prog).map_err(|e| anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::sandbox::sample_context;

    /// The Landlock rules allow writing exactly in the folders the permissions grant.
    #[test]
    fn landlock_allows_writing_exactly_in_granted_folders() {
        let ctx = sample_context();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Rw;
        p.filesystem.music = Access::Ro;
        let s = landlock_spec(&p, &ctx.host, "/run/user/1000", &[]);
        assert!(s.write.contains(&PathBuf::from("/home/tester/Documents")));
        assert!(!s.write.contains(&PathBuf::from("/home/tester/Music")));
        assert!(
            s.write.contains(&PathBuf::from("/home/tester")),
            "private home is writable"
        );
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        let s = landlock_spec(&p, &ctx.host, "/run/user/1000", &[]);
        assert!(
            !s.write.contains(&PathBuf::from("/home/tester")),
            "read-only full home"
        );
    }

    /// What each of `calls` answers in a child process: 0 for success,
    /// else its errno. Under the filter of `spec`, or without one (the
    /// control) when `spec` is `None`.
    fn errnos(spec: Option<&SeccompSpec>, calls: &[fn() -> libc::c_long]) -> Vec<i32> {
        let prog = spec.map(|s| seccomp_program(s).unwrap());
        let fprog = prog.as_ref().map(|p| libc::sock_fprog {
            len: p.len() as u16,
            filter: p.as_ptr() as *mut libc::sock_filter,
        });
        let mut fds = [0; 2];
        // SAFETY: pipe fills the two descriptors of a valid array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the child calls only async-signal-safe functions (prctl,
        // the probed syscalls, write, _exit) and touches no allocation.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: as above; `fprog` points to a program that outlives the child.
            unsafe {
                if let Some(f) = &fprog {
                    libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, f) != 0 {
                        libc::_exit(2);
                    }
                }
                for c in calls {
                    let e: i32 = if c() < 0 {
                        *libc::__errno_location()
                    } else {
                        0
                    };
                    libc::write(fds[1], (&raw const e).cast(), 4);
                }
                libc::_exit(0);
            }
        }
        // SAFETY: closing the write end the parent no longer needs.
        unsafe { libc::close(fds[1]) };
        let mut buf = vec![0u8; calls.len() * 4];
        let mut got = 0;
        while got < buf.len() {
            // SAFETY: reads into the unread rest of `buf`.
            let n = unsafe { libc::read(fds[0], buf[got..].as_mut_ptr().cast(), buf.len() - got) };
            if n <= 0 {
                break;
            }
            got += n as usize;
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        unsafe {
            libc::close(fds[0]);
            libc::waitpid(pid, &mut status, 0);
        }
        assert_eq!(status, 0, "the child ran every call");
        buf.chunks(4)
            .map(|c| i32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    /// A raw call with plain integer arguments.
    fn raw(nr: libc::c_long, a: libc::c_long, b: libc::c_long) -> libc::c_long {
        // SAFETY: the probed calls take plain integers or a null pointer.
        unsafe { libc::syscall(nr, a, b, 0, 0, 0) }
    }

    /// `clock_adjtime` reading the clock (no change requested).
    fn read_clock() -> libc::c_long {
        // SAFETY: `t` is a zeroed `timex` the call may fill.
        unsafe {
            let mut t: libc::timex = std::mem::zeroed();
            libc::syscall(libc::SYS_clock_adjtime, libc::CLOCK_REALTIME, &mut t)
        }
    }

    fn sock(family: i32, kind: i32, proto: i32) -> libc::c_long {
        // SAFETY: socket takes plain integers.
        unsafe { libc::socket(family, kind, proto) as libc::c_long }
    }

    /// The filter, applied by the real kernel in a child process: every
    /// call through the x32 ABI is refused (audit S-F9; x32 `ptrace` has its
    /// own number), the siblings of blocked calls are blocked too (S-F10),
    /// and a socket opens only as local, internet or netlink, Bluetooth
    /// only with its switch (S-F7). The control without the filter shows
    /// each refusal is the filter's.
    #[test]
    fn the_filter_refuses_x32_odd_sockets_and_the_siblings() {
        const X32: libc::c_long = 0x4000_0000;
        let calls: Vec<fn() -> libc::c_long> = vec![
            || sock(libc::AF_UNIX, libc::SOCK_STREAM, 0),
            || sock(libc::AF_INET, libc::SOCK_DGRAM, 0),
            || sock(libc::AF_INET6, libc::SOCK_DGRAM, 0),
            || sock(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE),
            || sock(libc::AF_ALG, libc::SOCK_SEQPACKET, 0),
            || sock(libc::AF_VSOCK, libc::SOCK_STREAM, 0),
            || sock(libc::AF_PACKET, libc::SOCK_RAW, 0),
            || sock(libc::AF_BLUETOOTH, libc::SOCK_STREAM, 0),
            || raw(libc::SYS_getpid | X32, 0, 0),
            || raw(521 | X32, 0, 0), // x32 ptrace
            read_clock,
            || raw(libc::SYS_quotactl_fd, -1, 0),
            || raw(libc::SYS_fspick, -1, 0),
            || raw(libc::SYS_mount_setattr, -1, 0),
        ];
        let spec = SeccompSpec::default();
        let filtered = errnos(Some(&spec), &calls);
        let control = errnos(None, &calls);
        let (eperm, eaf) = (libc::EPERM, libc::EAFNOSUPPORT);
        assert_eq!(
            &filtered[..4],
            &control[..4],
            "local, internet, netlink as without the filter"
        );
        assert_eq!(
            &filtered[4..8],
            &[eaf; 4],
            "crypto, VM, packet, Bluetooth sockets"
        );
        assert_eq!(&filtered[8..], &[eperm; 6], "x32 calls and the siblings");
        assert!(
            control[8] != eperm && control[9] != eperm,
            "x32: the kernel's answer, not the filter's"
        );
        assert_eq!(
            control[10], 0,
            "clock_adjtime reads the clock without the filter"
        );
        // quotactl_fd and mount_setattr answer "bad descriptor" or
        // "invalid" without the filter; fspick needs administrator rights,
        // so the kernel refuses it either way.
        assert!(control[11] != eperm && control[13] != eperm, "{control:?}");
        // With the Bluetooth switch, Bluetooth sockets as without the filter.
        let bt = SeccompSpec {
            bluetooth: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&bt), &calls[7..8]), control[7..8]);
        // Nested sandboxes keep fspick and mount_setattr.
        let nested = SeccompSpec {
            allow_userns: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&nested), &calls[12..]), control[12..]);
    }

    /// Bubblewrap reads the filter as eight bytes per instruction.
    #[test]
    fn the_filter_reaches_bubblewrap_as_whole_instructions() {
        let spec = SeccompSpec::default();
        let p = seccomp_program(&spec).unwrap();
        let b = filter_bytes(&spec).unwrap();
        assert_eq!(b.len(), p.len() * 8);
        assert_eq!(&b[..2], &p[0].code.to_ne_bytes());
        assert_eq!(&b[4..8], &p[0].k.to_ne_bytes());
    }

    /// The syscall filter compiles in every variant and always blocks mount and io_uring.
    #[test]
    fn the_syscall_filter_compiles_and_blocks_mount_and_io_uring() {
        for (strict, allow_userns) in [(false, true), (false, false), (true, true)] {
            assert!(!seccomp_program(&SeccompSpec {
                strict,
                allow_userns,
                bluetooth: false,
            })
            .unwrap()
            .is_empty());
        }
        assert!(baseline_syscalls(false).contains(&("mount", libc::SYS_mount)));
        assert!(
            baseline_syscalls(true).contains(&("io_uring_setup", libc::SYS_io_uring_setup)),
            "io_uring is blocked even with nested sandboxes"
        );
        assert!(
            !baseline_syscalls(true).contains(&("mount", libc::SYS_mount)),
            "nested sandboxes need mount"
        );
    }
}
