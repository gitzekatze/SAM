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
use sam_core::{errln, outln};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxSpec {
    pub landlock: Option<LandlockSpec>,
    #[serde(default)]
    pub seccomp: Option<SeccompSpec>,
    /// Sandbox check: run these checks instead of the app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<crate::probe::ProbePlan>,
    /// The app's own variables ([`sam_core::SandboxCommand::exec_env`]):
    /// set once every layer is in place, for the app alone (review SB-5).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<(String, String)>,
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
    /// The program the app starts is a 32-bit x86 program: its 32-bit
    /// calls go through the same list (see [`i386_branch`]) instead of
    /// ending it. Off for every other app, whose 32-bit calls still end
    /// the process. No effect on other processors.
    #[serde(default)]
    pub i386: bool,
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
    // SAM's private channel, read before the app's variables are set: one
    // of them cannot redirect the report.
    let status_fd = std::env::var("SAM_STATUS_FD")
        .ok()
        .and_then(|v| v.parse::<i32>().ok());
    let mut report: Vec<String> = Vec::new();
    if let Some(ll) = &spec.landlock {
        match apply_landlock(ll) {
            Ok((status, enforced)) => {
                report.push(format!("landlock: {status}"));
                if let Some(fully) = enforced {
                    report.push(scope_report(fully, sam_core::host::landlock_abi()).into());
                }
            }
            Err(e) => {
                errln!("sam-jail: landlock not applied: {e:#}");
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
    // Only now, with every layer in place, the app's own variables: this
    // helper's loader has long finished, so LD_PRELOAD, LD_LIBRARY_PATH,
    // LD_AUDIT and the like act on the app alone, inside its layers
    // (review SB-5). The sandbox check below sees them as the app will.
    set_app_variables(&spec.env);
    // Report to SAM on a private fd, then close it before the app runs, so
    // the app cannot forge or read the report.
    if let Some(plan) = &spec.probe {
        // Every layer is in place: check what the app would get, report, stop.
        let r = crate::probe::run(plan, &report.join("; "));
        outln!(
            "{}{}",
            crate::probe::REPORT_MARKER,
            serde_json::to_string(&r)?
        );
        std::process::exit(0);
    }
    if let Some(fd) = status_fd {
        let line = format!("{}\n", report.join("; "));
        // SAFETY: `line` is a valid buffer of line.len() bytes; `fd` was handed to this process for this one report and is not used afterwards.
        unsafe {
            libc::write(fd, line.as_ptr().cast(), line.len());
            libc::close(fd);
        }
    }
    run_and_reap(prog, rest)
}

/// Sets the app's own variables in this process, whose children inherit
/// them. A name the environment cannot hold (empty, with `=` or NUL) or a
/// value with NUL is left out, and so is SAM's status channel.
fn set_app_variables(env: &[(String, String)]) {
    for (k, v) in env {
        let holds = !k.is_empty() && !k.contains(['=', '\0']) && !v.contains('\0');
        if holds && k != "SAM_STATUS_FD" {
            std::env::set_var(k, v);
        }
    }
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

/// The helper's report item when Landlock fences abstract UNIX sockets.
pub const ABSTRACT_SCOPED: &str = "abstract sockets: scoped";

/// What the helper reports about the abstract-socket fence (Landlock ABI 6,
/// Linux 6.12), once Landlock itself is in place: its own item, because an
/// older kernel drops the fence without a word and Landlock then only reads
/// "partially enforced" (review K-1). `fully`: every part of the ruleset
/// was applied; `abi`: the kernel's Landlock version.
fn scope_report(fully: bool, abi: Option<u32>) -> &'static str {
    if fully || abi.is_some_and(|v| v >= 6) {
        ABSTRACT_SCOPED
    } else {
        "abstract sockets: NOT scoped (needs Linux 6.12)"
    }
}

/// Applies the ruleset: how it was enforced, and whether every part of it
/// (the abstract-socket fence too) was; `None` when nothing was.
fn apply_landlock(spec: &LandlockSpec) -> Result<(String, Option<bool>)> {
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
        RulesetStatus::FullyEnforced => ("fully enforced".into(), Some(true)),
        RulesetStatus::PartiallyEnforced => ("partially enforced".into(), Some(false)),
        RulesetStatus::NotEnforced => ("not enforced (kernel too old)".into(), None),
    })
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
        // clone and clone3 can make namespaces too: see `listed_calls` and
        // `front_filter`.
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
/// [`SOCKET_FAMILIES`], `clone` a new user namespace without nested
/// sandboxes). Every other call is allowed (audit S-F10: the list
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
    // A clone into a new user namespace is refused without nested
    // sandboxes; clone3 then answers "not implemented" (review K-2).
    out.insert("clone", "limited");
    out.insert("clone3", "blocked unless nested sandboxes");
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
/// - without nested sandboxes, `clone3` answers "not implemented".
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
    ];
    if !spec.allow_userns {
        // clone3 keeps its flags in memory, where no filter can read them,
        // so it is refused as a whole (review K-2). "Not implemented"
        // makes the C library fall back to clone(), whose flags the
        // listed calls check, as in Flatpak.
        f.push(op(JEQ_K, libc::SYS_clone3 as u32, 0, 1));
        f.push(op(RET_K, RET_ERRNO | libc::ENOSYS as u32, 0, 0));
    }
    f.extend([
        // Not `socket`: skip the family check (n compares, 1 load, 1 return).
        op(JEQ_K, libc::SYS_socket as u32, 0, n + 2),
        op(LD_W_ABS, ARG0, 0, 0),
    ]);
    for (i, fam) in families.iter().enumerate() {
        // A listed family jumps past the remaining compares and the return.
        f.push(op(JEQ_K, *fam, n - i as u8, 0));
    }
    f.push(op(RET_K, RET_ERRNO | libc::EAFNOSUPPORT as u32, 0, 0));
    f
}

/// The compiled BPF program for a filter spec: for a 32-bit app the
/// [`i386_branch`], then [`front_filter`], then the list of blocked calls.
pub fn seccomp_program(spec: &SeccompSpec) -> Result<seccompiler::BpfProgram> {
    let mut program = i386_branch(spec)?;
    program.extend(front_filter(spec));
    program.extend(listed_calls(spec)?);
    Ok(program)
}

/// The 32-bit x86 numbers of the calls the filter blocks, under the name
/// of the 64-bit call they stand for. A few have more than one number:
/// the older and the 64-bit-time forms of the same call. kexec_file_load
/// has no 32-bit x86 number.
const I386_CALLS: &[(&str, u32)] = &[
    ("kexec_load", 283),
    ("init_module", 128),
    ("finit_module", 350),
    ("delete_module", 129),
    ("reboot", 88),
    ("swapon", 87),
    ("swapoff", 115),
    ("acct", 51),
    ("settimeofday", 79),
    ("settimeofday", 25), // stime
    ("clock_settime", 264),
    ("clock_settime", 404), // clock_settime64
    ("adjtimex", 124),
    ("clock_adjtime", 343),
    ("clock_adjtime", 405), // clock_adjtime64
    ("quotactl", 131),
    ("quotactl_fd", 443),
    ("bpf", 357),
    ("perf_event_open", 336),
    ("userfaultfd", 374),
    ("keyctl", 288),
    ("add_key", 286),
    ("request_key", 287),
    ("open_by_handle_at", 342),
    ("name_to_handle_at", 341),
    ("vhangup", 111),
    ("syslog", 103),
    ("io_uring_setup", 425),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("iopl", 110),
    ("ioperm", 101),
    ("uselib", 86),
    ("unshare", 310),
    ("setns", 346),
    ("mount", 21),
    ("umount2", 52),
    ("umount2", 22), // umount
    ("pivot_root", 217),
    ("open_tree", 428),
    ("move_mount", 429),
    ("fsopen", 430),
    ("fsconfig", 431),
    ("fsmount", 432),
    ("fspick", 433),
    ("mount_setattr", 442),
    ("ptrace", 26),
    ("process_vm_readv", 347),
    ("process_vm_writev", 348),
    ("personality", 136),
    ("mbind", 274),
    ("move_pages", 317),
    ("migrate_pages", 294),
];

/// 32-bit x86 numbers of the calls with a closer look.
const I386_IOCTL: u32 = 54;
const I386_SOCKET: u32 = 359;
const I386_CLONE: u32 = 120;
const I386_CLONE3: u32 = 435;

/// The filter for 32-bit calls, put in front of everything else when the
/// app's start program is 32-bit ([`SeccompSpec::i386`]; review K-3: such
/// apps ran with no filter at all, and an app could choose that by making
/// its start program 32-bit). A 32-bit call gets the same answers as its
/// 64-bit twin: the listed calls are refused, so are typing into the
/// terminal, socket families outside [`SOCKET_FAMILIES`] and, without
/// nested sandboxes, a clone into a new user namespace and clone3. Every
/// other 32-bit call is allowed; 64-bit calls jump past this part.
///
/// One gap is left, as in Flatpak: socketcall(), through which older C
/// libraries open sockets, passes the family in memory the filter cannot
/// read, so a 32-bit socket opened that way is not limited to the listed
/// families. Without this branch such an app had no filter at all.
fn i386_branch(spec: &SeccompSpec) -> Result<seccompiler::BpfProgram> {
    use seccompiler::sock_filter;
    if !(spec.i386 && cfg!(target_arch = "x86_64")) {
        return Ok(Vec::new());
    }
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const JSET_K: u16 = 0x45;
    const RET_K: u16 = 0x06;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const AUDIT_ARCH_I386: u32 = 0x4000_0003;
    const NR: u32 = 0;
    const ARCH: u32 = 4;
    const ARG0: u32 = 16;
    const ARG1: u32 = 24;
    let op = |code, k, jt, jf| sock_filter { code, jt, jf, k };
    let errno = |e: i32| op(RET_K, RET_ERRNO | e as u32, 0, 0);
    let mut names: Vec<&str> = baseline_syscalls(spec.allow_userns)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    if spec.strict {
        names.extend(strict_extra_syscalls().into_iter().map(|(n, _)| n));
    }
    let mut b = vec![op(LD_W_ABS, NR, 0, 0)];
    for (_, nr) in I386_CALLS.iter().filter(|(n, _)| names.contains(n)) {
        b.push(op(JEQ_K, *nr, 0, 1));
        b.push(errno(libc::EPERM));
    }
    if !spec.allow_userns {
        b.push(op(JEQ_K, I386_CLONE3, 0, 1));
        b.push(errno(libc::ENOSYS));
        // clone(flags, …): refused when the flags ask for a user namespace.
        b.push(op(JEQ_K, I386_CLONE, 0, 3));
        b.push(op(LD_W_ABS, ARG0, 0, 0));
        b.push(op(JSET_K, libc::CLONE_NEWUSER as u32, 0, 1));
        b.push(errno(libc::EPERM));
        b.push(op(LD_W_ABS, NR, 0, 0));
    }
    // ioctl(fd, request, …): typing into the terminal is refused.
    b.push(op(JEQ_K, I386_IOCTL, 0, 4));
    b.push(op(LD_W_ABS, ARG1, 0, 0));
    b.push(op(JEQ_K, libc::TIOCSTI as u32, 1, 0));
    b.push(op(JEQ_K, 0x541C, 0, 1)); // TIOCLINUX
    b.push(errno(libc::EPERM));
    b.push(op(LD_W_ABS, NR, 0, 0));
    // socket(family, …): only the listed families.
    let mut families: Vec<u32> = SOCKET_FAMILIES.iter().map(|f| *f as u32).collect();
    if spec.bluetooth {
        families.push(libc::AF_BLUETOOTH as u32);
    }
    let n = families.len() as u8;
    b.push(op(JEQ_K, I386_SOCKET, 0, n + 2));
    b.push(op(LD_W_ABS, ARG0, 0, 0));
    for (i, fam) in families.iter().enumerate() {
        b.push(op(JEQ_K, *fam, n - i as u8, 0));
    }
    b.push(errno(libc::EAFNOSUPPORT));
    b.push(op(RET_K, RET_ALLOW, 0, 0));
    // In front: a 32-bit call enters the branch, any other jumps past it.
    let skip = u8::try_from(b.len()).context("the 32-bit filter is too long for one jump")?;
    let mut f = vec![
        op(LD_W_ABS, ARCH, 0, 0),
        op(JEQ_K, AUDIT_ARCH_I386, 0, skip),
    ];
    f.extend(b);
    Ok(f)
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
    // int 0x80 fail the architecture check and end the process, unless
    // the app is a 32-bit one (`i386_branch` answered them already).
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
    if !spec.allow_userns {
        // clone() can make a user namespace as well as unshare() can
        // (review K-2). Its flags are the first argument on x86_64 and
        // aarch64. A thread or a plain child process stays allowed.
        let newuser = libc::CLONE_NEWUSER as u64;
        let c = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(newuser),
            newuser,
        )
        .map_err(|e| anyhow!("{e}"))?;
        rules.insert(
            libc::SYS_clone,
            vec![SeccompRule::new(vec![c]).map_err(|e| anyhow!("{e}"))?],
        );
    }
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
        let (out, status) = errnos_and_status(spec, calls);
        assert_eq!(status, 0, "the child ran every call");
        out
    }

    /// [`errnos`], also when the filter ends the child: the answers it
    /// gave before that, and the child's wait status (0: it ran every call).
    fn errnos_and_status(
        spec: Option<&SeccompSpec>,
        calls: &[fn() -> libc::c_long],
    ) -> (Vec<i32>, i32) {
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
        buf.truncate(got - got % 4);
        let out = buf
            .chunks(4)
            .map(|c| i32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        (out, status)
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
                i386: strict,
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
    /// A raw clone with these flags. CLONE_THREAD without CLONE_SIGHAND
    /// is invalid, so without a filter the kernel answers EINVAL and no
    /// process is ever made; a filter answers before the kernel looks.
    fn bad_clone(flags: libc::c_long) -> libc::c_long {
        raw(
            libc::SYS_clone,
            flags | libc::CLONE_THREAD as libc::c_long,
            0,
        )
    }

    /// Review K-2: without nested sandboxes the filter refused unshare()
    /// but let clone() and clone3() make a new user namespace, which the
    /// unpack sandbox did not stop otherwise. Now clone with a new user
    /// namespace is refused and clone3 answers "not implemented" (so the C
    /// library falls back to clone); a clone without one is untouched, and
    /// an app that may run nested sandboxes keeps both.
    #[test]
    fn without_nested_sandboxes_clone_cannot_make_a_user_namespace() {
        let calls: Vec<fn() -> libc::c_long> = vec![
            || bad_clone(libc::CLONE_NEWUSER as libc::c_long),
            || bad_clone(0),
            // clone3 with no arguments: EINVAL from the kernel.
            || raw(libc::SYS_clone3, 0, 0),
        ];
        let control = errnos(None, &calls);
        assert_eq!(control, [libc::EINVAL; 3], "the kernel's own answers");
        let filtered = errnos(Some(&SeccompSpec::default()), &calls);
        assert_eq!(
            filtered,
            [libc::EPERM, libc::EINVAL, libc::ENOSYS],
            "new user namespace refused, plain clone untouched, clone3 not implemented"
        );
        let nested = SeccompSpec {
            allow_userns: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&nested), &calls), control, "nested sandboxes");
    }

    /// A 32-bit x86 call (`int 0x80`) with up to three integer arguments,
    /// made from this 64-bit test: the kernel and the filter see it exactly
    /// as a call from a 32-bit program. Sets errno like the C library.
    #[cfg(target_arch = "x86_64")]
    fn call32(nr: u32, a: u32, b: u32, c: u32) -> libc::c_long {
        let r: u64;
        // SAFETY: a system call with integer arguments only; rbx is
        // reserved by the compiler, so it is swapped in and back.
        unsafe {
            std::arch::asm!(
                "xchg {a:r}, rbx",
                "int 0x80",
                "xchg {a:r}, rbx",
                a = inout(reg) u64::from(a) => _,
                inlateout("rax") u64::from(nr) => r,
                in("rcx") u64::from(b),
                in("rdx") u64::from(c),
            );
        }
        let r = r as u32 as i32;
        if r < 0 {
            // SAFETY: errno is this thread's own variable.
            unsafe { *libc::__errno_location() = -r };
            -1
        } else {
            libc::c_long::from(r)
        }
    }

    /// Review K-3: a 32-bit start program switched the whole filter off,
    /// and a 64-bit program it started then ran with no filter at all.
    /// Now a 32-bit app's filter answers 32-bit calls like their 64-bit
    /// twins: allowed calls work, blocked ones are refused, the terminal,
    /// socket families and user namespaces are limited, and its 64-bit
    /// calls are filtered as before. Every other app's 32-bit calls still
    /// end the process (they would open the 32-bit kernel interface to a
    /// 64-bit app).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_32_bit_app_gets_its_calls_filtered_not_switched_off() {
        let calls: Vec<fn() -> libc::c_long> = vec![
            || call32(20, 0, 0, 0),             // getpid
            || call32(288, 0, -3i32 as u32, 0), // keyctl(GET_KEYRING_ID, SESSION)
            || call32(425, 1, 0, 0),            // io_uring_setup(1, NULL)
            || call32(357, 9999, 0, 0),         // bpf(invalid command)
            || call32(310, 0, 0, 0),            // unshare(0)
            || call32(120, (libc::CLONE_NEWUSER | libc::CLONE_THREAD) as u32, 0, 0),
            || call32(120, libc::CLONE_THREAD as u32, 0, 0), // clone without a namespace
            || call32(435, 0, 0, 0),                         // clone3(NULL, 0)
            || call32(54, 0, libc::TIOCSTI as u32, 0),       // ioctl(0, TIOCSTI)
            || call32(359, libc::AF_ALG as u32, libc::SOCK_SEQPACKET as u32, 0),
            || call32(359, libc::AF_UNIX as u32, libc::SOCK_STREAM as u32, 0),
            || raw(libc::SYS_keyctl, 0, -3), // the 64-bit twin
            || call32(54, 0, 0x541C, 0),     // ioctl(0, TIOCLINUX)
            || call32(26, 1, 0, 0),          // ptrace(PEEKTEXT, pid 0): ESRCH
        ];
        let (control, status) = errnos_and_status(None, &calls);
        if status != 0 {
            // A kernel without 32-bit support (ia32_emulation=0) ends a
            // 32-bit call with SIGSEGV; there is nothing to filter then.
            crate::contracts::skip("this kernel runs no 32-bit x86 programs")
                .unwrap_or_else(|e| panic!("{e}"));
            return;
        }
        let (eperm, einval) = (libc::EPERM, libc::EINVAL);
        assert_eq!(control[0], 0, "getpid works without the filter");
        assert_eq!(control[4], 0, "unshare(0) works without the filter");
        assert_eq!(control[5], einval, "invalid clone flags");
        assert_eq!(control[7], einval, "clone3 without arguments");
        assert_eq!(control[10], 0, "a local socket opens");
        // Any other app: its first 32-bit call ends it, as before.
        let (_, ended) = errnos_and_status(Some(&SeccompSpec::default()), &calls[..1]);
        assert!(
            libc::WIFSIGNALED(ended) && libc::WTERMSIG(ended) == libc::SIGSYS,
            "a 64-bit app's 32-bit call ends it: {ended:#x}"
        );
        let spec = SeccompSpec {
            i386: true,
            ..SeccompSpec::default()
        };
        let filtered = errnos(Some(&spec), &calls);
        assert_eq!(
            filtered,
            [
                0,
                eperm,
                eperm,
                eperm,
                eperm,
                eperm,
                einval,
                libc::ENOSYS,
                eperm,
                libc::EAFNOSUPPORT,
                0,
                eperm,
                eperm,
                libc::ESRCH
            ],
            "control: {control:?}"
        );
        assert_ne!(control[12], eperm, "TIOCLINUX is refused by the filter");
        assert_eq!(control[13], libc::ESRCH, "no process 0 to trace");
        // Every allowed socket family answers as without the filter, not
        // only the first one it checks (mutation run 2026-11-24: a jump
        // past the allowing answer for all but AF_UNIX went unnoticed).
        let families: Vec<fn() -> libc::c_long> = vec![
            || call32(359, libc::AF_INET as u32, libc::SOCK_DGRAM as u32, 0),
            || call32(359, libc::AF_INET6 as u32, libc::SOCK_DGRAM as u32, 0),
            || call32(359, libc::AF_NETLINK as u32, libc::SOCK_DGRAM as u32, 0),
        ];
        let open = errnos(None, &families);
        assert_eq!(open[0], 0, "an internet socket opens without the filter");
        for (name, errno) in [("IPv6", open[1]), ("netlink", open[2])] {
            if errno != 0 {
                // Off on this computer: the filter's own refusal could not
                // be told apart from the kernel's.
                crate::contracts::skip(&format!("{name} sockets are off here"))
                    .unwrap_or_else(|e| panic!("{e}"));
            }
        }
        assert_eq!(errnos(Some(&spec), &families), open, "allowed families");
        // The strict filter's calls are refused through their 32-bit
        // numbers too.
        let strict = SeccompSpec {
            i386: true,
            strict: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&strict), &calls[13..]), [eperm], "strict");
        // Nested sandboxes: the namespace calls as without the filter.
        let nested = SeccompSpec {
            i386: true,
            allow_userns: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&nested), &calls[4..8]), control[4..8]);
    }

    /// Review K-1: the abstract-socket fence is its own item in the
    /// helper's report. A kernel before 6.12 drops it without a word, and
    /// Landlock then reads only "partially enforced".
    #[test]
    fn the_helper_reports_the_socket_fence_on_its_own() {
        assert_eq!(scope_report(true, Some(6)), ABSTRACT_SCOPED);
        assert_eq!(scope_report(false, Some(7)), ABSTRACT_SCOPED);
        for abi in [Some(4), Some(5), None] {
            let r = scope_report(false, abi);
            assert!(r.contains("NOT scoped"), "{abi:?}: {r}");
            assert!(!r.contains(ABSTRACT_SCOPED), "{abi:?}: {r}");
        }
    }

    /// Every call the filter blocks by name has its 32-bit numbers in
    /// [`I386_CALLS`] (kexec_file_load has none), and every name there is
    /// one the filter blocks: a call added to the list is not forgotten
    /// for 32-bit apps.
    #[test]
    fn every_blocked_call_is_blocked_for_32_bit_apps_too() {
        let mut blocked: Vec<&str> = baseline_syscalls(false)
            .into_iter()
            .chain(strict_extra_syscalls())
            .map(|(n, _)| n)
            .collect();
        blocked.extend(X86_ONLY);
        for n in &blocked {
            assert!(
                *n == "kexec_file_load" || I386_CALLS.iter().any(|(m, _)| m == n),
                "{n} has no 32-bit number in I386_CALLS"
            );
        }
        for (n, _) in I386_CALLS {
            assert!(blocked.contains(n), "{n} is not blocked by the filter");
        }
    }
}
