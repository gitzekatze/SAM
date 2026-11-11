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
pub fn landlock_spec(p: &PermissionSet, host: &HostInfo, runtime_dir_in_sandbox: &str, extra_write: &[PathBuf]) -> LandlockSpec {
    let mut write: Vec<PathBuf> = ["/tmp", "/var/tmp", "/dev", "/proc", runtime_dir_in_sandbox].iter().map(PathBuf::from).collect();
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
    LandlockSpec { read: vec![PathBuf::from("/")], write }
}

/// Entry point for `sam-jail-run --sandbox-exec <spec> -- <cmd...>`:
/// apply restrictions and exec. Never returns on success.
pub fn sandbox_exec(spec_path: &Path, argv: &[String]) -> Result<()> {
    let spec: SandboxSpec = serde_json::from_slice(&std::fs::read(spec_path).context("reading sandbox spec")?)?;
    let (prog, rest) = argv.split_first().context("no command given")?;
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
        apply_seccomp(sc).context("loading the seccomp filter")?;
        report.push(format!("seccomp: {} loaded", if sc.strict { "strict" } else { "baseline" }));
    }
    // Report to SAM on a private fd, then close it before the app runs, so
    // the app cannot forge or read the report.
    if let Some(plan) = &spec.probe {
        // Every layer is in place: check what the app would get, report, stop.
        let r = crate::probe::run(plan, &report.join("; "));
        println!("{}{}", crate::probe::REPORT_MARKER, serde_json::to_string(&r)?);
        std::process::exit(0);
    }
    if let Some(fd) = std::env::var("SAM_STATUS_FD").ok().and_then(|v| v.parse::<i32>().ok()) {
        let line = format!("{}\n", report.join("; "));
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
    let child = Command::new(prog).args(args).env_remove("SAM_STATUS_FD").spawn().with_context(|| format!("starting {prog}"))?;
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
            code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 128 + libc::WTERMSIG(status) };
        }
    }
    std::process::exit(code)
}

fn apply_landlock(spec: &LandlockSpec) -> Result<String> {
    use landlock::{path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI};
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

/// Syscalls blocked (EPERM) by the baseline filter, on by default. Kernel
/// interfaces no desktop app needs and that have a history of exploits:
/// modules, kexec, BPF, perf, keyrings, userfaultfd, handle-based opens, io_uring.
fn baseline_syscalls(allow_userns: bool) -> Vec<i64> {
    let mut v: Vec<i64> = vec![
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
        libc::SYS_quotactl,
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
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_kexec_file_load, libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_uselib]);
    if !allow_userns {
        // Without nested sandboxes nothing inside needs namespaces or mounts.
        v.extend([
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
        ]);
    }
    v
}

/// Additionally blocked by the strict filter.
fn strict_extra_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_process_vm_readv,
        libc::SYS_personality,
        libc::SYS_mbind,
        libc::SYS_move_pages,
        libc::SYS_migrate_pages,
    ]
}

/// The compiled BPF program for a filter spec.
pub fn seccomp_program(spec: &SeccompSpec) -> Result<seccompiler::BpfProgram> {
    use seccompiler::{SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch};
    let arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        bail!("seccomp filters are not supported on this architecture");
    };
    let mut list = baseline_syscalls(spec.allow_userns);
    if spec.strict {
        list.extend(strict_extra_syscalls());
    }
    // x86-64 kernels may accept the x32 ABI: the same architecture, syscall
    // numbers with bit 30 set. Block those numbers too, or a blocked call
    // could be made through x32 where the kernel allows it. (32-bit calls
    // through int 0x80 fail the architecture check and end the process.)
    const X32: i64 = 0x4000_0000;
    let x86 = matches!(arch, TargetArch::x86_64);
    if x86 {
        let x32: Vec<i64> = list.iter().map(|n| n | X32).collect();
        list.extend(x32);
    }
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = list.into_iter().map(|s| (s, vec![])).collect();
    // Terminal input injection into the parent's tty (TIOCSTI, TIOCLINUX).
    let ioctl_rule = |req: u64| -> Result<SeccompRule> {
        let c = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, req).map_err(|e| anyhow!("{e}"))?;
        SeccompRule::new(vec![c]).map_err(|e| anyhow!("{e}"))
    };
    rules.insert(libc::SYS_ioctl, vec![ioctl_rule(libc::TIOCSTI)?, ioctl_rule(0x541C)?]);
    if x86 {
        // x32's ioctl is the compat entry 514.
        rules.insert(514 | X32, vec![ioctl_rule(libc::TIOCSTI)?, ioctl_rule(0x541C)?]);
    }
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch).map_err(|e| anyhow!("{e}"))?;
    filter.try_into().map_err(|e: seccompiler::BackendError| anyhow!("{e}"))
}

fn apply_seccomp(spec: &SeccompSpec) -> Result<()> {
    let prog = seccomp_program(spec)?;
    // Required for unprivileged filters (bwrap sets it too).
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!("PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error());
    }
    seccompiler::apply_filter(&prog).map_err(|e| anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::sandbox::sample_context;

    #[test]
    fn spec_follows_permissions() {
        let ctx = sample_context();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Rw;
        p.filesystem.music = Access::Ro;
        let s = landlock_spec(&p, &ctx.host, "/run/user/1000", &[]);
        assert!(s.write.contains(&PathBuf::from("/home/tester/Documents")));
        assert!(!s.write.contains(&PathBuf::from("/home/tester/Music")));
        assert!(s.write.contains(&PathBuf::from("/home/tester")), "private home is writable");
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        let s = landlock_spec(&p, &ctx.host, "/run/user/1000", &[]);
        assert!(!s.write.contains(&PathBuf::from("/home/tester")), "read-only full home");
    }

    #[test]
    fn seccomp_compiles() {
        for (strict, allow_userns) in [(false, true), (false, false), (true, true)] {
            assert!(!seccomp_program(&SeccompSpec { strict, allow_userns }).unwrap().is_empty());
        }
        assert!(baseline_syscalls(false).contains(&libc::SYS_mount));
        assert!(baseline_syscalls(true).contains(&libc::SYS_io_uring_setup), "io_uring is blocked even with nested sandboxes");
        assert!(!baseline_syscalls(true).contains(&libc::SYS_mount), "nested sandboxes need mount");
    }
}
