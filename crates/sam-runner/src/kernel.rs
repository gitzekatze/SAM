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
//! * Seccomp filters are built from one table of rules (`RULES`) and loaded
//!   by the same helper right before exec: a baseline filter (on by default; without
//!   nested sandboxes it blocks what Flatpak's default filter blocks except
//!   `ptrace`, some `personality` values and `modify_ldt`, and more: see
//!   docs/security.md) and an optional strict one. Loading them in the helper rather
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
    /// calls go through the same rules (see [`seccomp_program`]) instead
    /// of ending it. Off for every other app, whose 32-bit calls still end
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
    // At the access the sandbox shows each at: two set to one place at
    // different access are both read-only (stricter wins).
    for key in XDG_DIR_KEYS {
        if sam_core::places::user_folder_access(p, host, key) == Access::Rw {
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

/// Who a row of the filter applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    /// Every app: the baseline filter, on by default.
    Baseline,
    /// Apps without nested sandboxes. Nested sandboxes (Chromium,
    /// Electron, WebKit's bwrap) need namespaces and mounts; without them
    /// nothing inside does.
    WithoutNested,
    /// Apps with the strict filter on, on top of the baseline.
    Strict,
}

/// Which uses of a call a row refuses. An argument is compared by its
/// lower 32 bits only: the kernel reads `ioctl`'s request, `socket`'s
/// family and `clone`'s flags no wider, so a value with something in the
/// upper half is the same request to it (review R74).
#[derive(Clone, Copy, Debug)]
enum Uses {
    /// Every use.
    All,
    /// When argument number `.0` is one of these values.
    ArgIs(u32, &'static [u32]),
    /// When argument number `.0` has this bit set.
    ArgHasBit(u32, u32),
    /// When argument number `.0` is a socket family the app may not open:
    /// one outside [`SOCKET_FAMILIES`], or Bluetooth without its switch.
    FamilyNotAllowed(u32),
}

/// One row of the filter: a call, whom the row applies to, which uses it
/// refuses, and the error a refused call answers.
#[derive(Debug)]
struct Rule {
    /// The call's name, as docs/syscalls-reviewed.txt says it.
    name: &'static str,
    /// Its number on this processor; none where this processor has no
    /// such call.
    nr: Option<u32>,
    /// Its 32-bit x86 numbers, older forms of the same call included.
    i386: &'static [u32],
    scope: Scope,
    uses: Uses,
    errno: i32,
}

impl Rule {
    /// Whether the row is part of the filter for `spec`.
    fn applies(&self, spec: &SeccompSpec) -> bool {
        match self.scope {
            Scope::Baseline => true,
            Scope::WithoutNested => !spec.allow_userns,
            Scope::Strict => spec.strict,
        }
    }
}

/// A call's name from its libc constant: `SYS_mount` is "mount".
const fn call_name(constant: &'static str) -> &'static str {
    constant.split_at("SYS_".len()).1
}

/// This processor's number of a call only x86-64 has; none elsewhere.
#[cfg(target_arch = "x86_64")]
macro_rules! x86_only {
    ($sys:ident) => {
        Some(libc::$sys as u32)
    };
}
#[cfg(not(target_arch = "x86_64"))]
macro_rules! x86_only {
    ($sys:ident) => {
        None
    };
}

/// A row of [`RULES`], named after its libc constant, with this
/// processor's number from libc: `row!(SYS_mount, [21], WithoutNested)`
/// refuses every use of `mount` with "not permitted"; the 32-bit x86
/// number of `mount` is 21. A fourth and fifth part name the uses refused
/// and the error; `x86_only` marks a call only x86-64 has.
macro_rules! row {
    (x86_only $sys:ident, $i386:expr, $scope:ident) => {
        row!(@ $sys, x86_only!($sys), $i386, $scope, Uses::All, libc::EPERM)
    };
    ($sys:ident, $i386:expr, $scope:ident) => {
        row!($sys, $i386, $scope, Uses::All, libc::EPERM)
    };
    ($sys:ident, $i386:expr, $scope:ident, $uses:expr, $errno:expr) => {
        row!(@ $sys, Some(libc::$sys as u32), $i386, $scope, $uses, $errno)
    };
    (@ $sys:ident, $nr:expr, $i386:expr, $scope:ident, $uses:expr, $errno:expr) => {
        Rule {
            name: call_name(stringify!($sys)),
            nr: $nr,
            i386: &$i386,
            scope: Scope::$scope,
            uses: $uses,
            errno: $errno,
        }
    };
}

/// What the syscall filter refuses: one row per call, with this
/// processor's number and the 32-bit x86 numbers side by side, so a call
/// added for one is added for the other. Every call not named here is
/// allowed: the filter is a deny list (contract `kernel-seccomp`), and
/// docs/syscalls-reviewed.txt says what it does with every call
/// ([`review_statuses`]). [`seccomp_program`] turns the rows into the
/// filter program.
const RULES: &[Rule] = &[
    // The baseline: kernel interfaces no desktop app needs and that have
    // a history of exploits: modules, kexec, BPF, perf, keyrings,
    // userfaultfd, handle-based opens, io_uring.
    row!(SYS_kexec_load, [283], Baseline),
    // On every processor (it sat with the x86-only calls, so ARM did not
    // block it; found by the review list test on ARM). 32-bit x86 has no
    // such call.
    row!(SYS_kexec_file_load, [], Baseline),
    row!(SYS_init_module, [128], Baseline),
    row!(SYS_finit_module, [350], Baseline),
    row!(SYS_delete_module, [129], Baseline),
    row!(SYS_reboot, [88], Baseline),
    row!(SYS_swapon, [87], Baseline),
    row!(SYS_swapoff, [115], Baseline),
    row!(SYS_acct, [51], Baseline),
    row!(SYS_settimeofday, [79, 25 /* stime */], Baseline),
    row!(
        SYS_clock_settime,
        [264, 404 /* clock_settime64 */],
        Baseline
    ),
    row!(SYS_adjtimex, [124], Baseline),
    // The same as adjtimex and quotactl through another door (audit
    // S-F10: the siblings were blocked, these were not).
    row!(
        SYS_clock_adjtime,
        [343, 405 /* clock_adjtime64 */],
        Baseline
    ),
    row!(SYS_quotactl, [131], Baseline),
    row!(SYS_quotactl_fd, [443], Baseline),
    row!(SYS_bpf, [357], Baseline),
    row!(SYS_perf_event_open, [336], Baseline),
    row!(SYS_userfaultfd, [374], Baseline),
    row!(SYS_keyctl, [288], Baseline),
    row!(SYS_add_key, [286], Baseline),
    row!(SYS_request_key, [287], Baseline),
    row!(SYS_open_by_handle_at, [342], Baseline),
    row!(SYS_name_to_handle_at, [341], Baseline),
    row!(SYS_vhangup, [111], Baseline),
    row!(SYS_syslog, [103], Baseline),
    // io_uring: a frequent source of kernel privilege escalations,
    // blocked by Docker, ChromeOS and Android too. Programs that use it
    // fall back to ordinary I/O when it is refused.
    row!(SYS_io_uring_setup, [425], Baseline),
    row!(SYS_io_uring_enter, [426], Baseline),
    row!(SYS_io_uring_register, [427], Baseline),
    // Blocked by Flatpak's default filter too, and needed by no desktop
    // app (review R69; owner, 2026-11-25): the NUMA memory calls (which
    // memory banks of a many-processor server a program uses; reading
    // them tells another process's placement, changing them moves pages
    // of the machine). `chroot` is with the namespace calls below:
    // Chromium's own sandbox needs it.
    row!(SYS_mbind, [274], Baseline),
    row!(SYS_move_pages, [317], Baseline),
    row!(SYS_migrate_pages, [294], Baseline),
    row!(SYS_get_mempolicy, [275], Baseline),
    row!(SYS_set_mempolicy, [276], Baseline),
    row!(SYS_set_mempolicy_home_node, [450], Baseline),
    // Calls only x86-64 has (and 32-bit x86).
    row!(x86_only SYS_iopl, [110], Baseline),
    row!(x86_only SYS_ioperm, [101], Baseline),
    row!(x86_only SYS_uselib, [86], Baseline),
    // Typing into the terminal of the app's parent: TIOCSTI and
    // TIOCLINUX (0x541C; libc has no name for it).
    row!(
        SYS_ioctl,
        [54],
        Baseline,
        Uses::ArgIs(1, &[libc::TIOCSTI as u32, 0x541C]),
        libc::EPERM
    ),
    // Only the families in SOCKET_FAMILIES, as in Flatpak (audit S-F7).
    // `socketpair` makes its sockets as `socket` does, so it would load
    // and open any other family as well (a usable pair of TIPC sockets,
    // for one; review R66).
    row!(
        SYS_socket,
        [359],
        Baseline,
        Uses::FamilyNotAllowed(0),
        libc::EAFNOSUPPORT
    ),
    row!(
        SYS_socketpair,
        [360],
        Baseline,
        Uses::FamilyNotAllowed(0),
        libc::EAFNOSUPPORT
    ),
    // Without nested sandboxes nothing inside needs namespaces or mounts.
    row!(SYS_unshare, [310], WithoutNested),
    row!(SYS_setns, [346], WithoutNested),
    row!(SYS_mount, [21], WithoutNested),
    row!(SYS_umount2, [52, 22 /* umount */], WithoutNested),
    row!(SYS_pivot_root, [217], WithoutNested),
    row!(SYS_open_tree, [428], WithoutNested),
    row!(SYS_move_mount, [429], WithoutNested),
    row!(SYS_fsopen, [430], WithoutNested),
    row!(SYS_fsmount, [432], WithoutNested),
    row!(SYS_fsconfig, [431], WithoutNested),
    row!(SYS_fspick, [433], WithoutNested),
    row!(SYS_mount_setattr, [442], WithoutNested),
    // open_tree and mount_setattr in one call (Linux 6.15): blocked like
    // the two it combines (review R67). The libc crate has no name for it
    // yet; its number is 467 on x86_64, i386 and aarch64, the only
    // processors the filter supports.
    Rule {
        name: "open_tree_attr",
        nr: Some(467),
        i386: &[467],
        scope: Scope::WithoutNested,
        uses: Uses::All,
        errno: libc::EPERM,
    },
    // Changing the root folder (review R69, as in Flatpak). It needs a
    // right the app has only in a namespace of its own, so the kernel
    // refuses it there anyway; with nested sandboxes Chromium's sandbox
    // (Electron, CEF) uses it to drop the file system, and refusing it
    // would push apps to `--no-sandbox`.
    row!(SYS_chroot, [61], WithoutNested),
    // clone() can make a user namespace as well as unshare() can (review
    // K-2): refused when its flags ask for one. A thread or a plain child
    // process stays allowed.
    row!(
        SYS_clone,
        [120],
        WithoutNested,
        Uses::ArgHasBit(0, libc::CLONE_NEWUSER as u32),
        libc::EPERM
    ),
    // clone3 keeps its flags in memory, where no filter can read them, so
    // it is refused as a whole (review K-2). "Not implemented" makes the C
    // library fall back to clone(), whose flags the row above checks, as
    // in Flatpak.
    row!(SYS_clone3, [435], WithoutNested, Uses::All, libc::ENOSYS),
    // The strict filter: `ptrace` and every call that reaches into
    // another process as far (its memory, its descriptors, its kernel
    // objects), and `personality` (review R68: the help text promised
    // these, three were missing). The NUMA memory calls the strict filter
    // used to add are in the baseline since review R69. `ptrace` and
    // `personality` stay here: crash reporters and Wine use them, and
    // programs ask `personality` for their mode. The full promise is
    // written in `docs/security.md`, section "strict filter".
    row!(SYS_ptrace, [26], Strict),
    row!(SYS_process_vm_writev, [348], Strict),
    row!(SYS_process_vm_readv, [347], Strict),
    row!(SYS_process_madvise, [440], Strict),
    row!(SYS_pidfd_getfd, [438], Strict),
    row!(SYS_kcmp, [349], Strict),
    row!(SYS_personality, [136], Strict),
];

/// What the filter does with each call it names, as the review list says
/// it: "blocked" (always), "blocked unless nested sandboxes" (nested
/// sandboxes need namespaces and mounts), "blocked by the strict filter"
/// (only with the strict filter on) or "limited" (only some uses refused:
/// `ioctl` typing into the terminal, `socket` and `socketpair` the
/// families outside [`SOCKET_FAMILIES`], `clone` a new user namespace
/// without nested sandboxes). Every other call is allowed (audit S-F10:
/// the list said "blocked" for calls the default filter allows). The
/// calls only x86-64 has are "blocked" on every processor: elsewhere
/// there is no such call, and the list is shared.
pub fn review_statuses() -> BTreeMap<&'static str, &'static str> {
    RULES
        .iter()
        .map(|r| {
            let status = match (r.uses, r.scope) {
                (Uses::All, Scope::Baseline) => "blocked",
                (Uses::All, Scope::WithoutNested) => "blocked unless nested sandboxes",
                (Uses::All, Scope::Strict) => "blocked by the strict filter",
                _ => "limited",
            };
            (r.name, status)
        })
        .collect()
}

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

/// socketcall's 32-bit x86 number: the call through which older C
/// libraries open sockets, passing the family in memory.
const SOCKETCALL_I386: u32 = 102;

impl SeccompSpec {
    /// The filter has its 32-bit part ([`seccomp_program`], step 1).
    pub fn filters_32_bit_calls(&self) -> bool {
        self.i386 && cfg!(target_arch = "x86_64")
    }

    /// The filter has its 32-bit part and no row of it names socketcall,
    /// so a 32-bit socket made through socketcall is not limited to the
    /// families (the gap in [`seccomp_program`], step 1). The app page and
    /// the sandbox check say so. Read from the rows, so a row that closes
    /// the gap later removes the note with it; `tests/seccomp_decisions.rs`
    /// ties this to what the built program answers.
    pub fn socketcall_unlimited(&self) -> bool {
        self.filters_32_bit_calls()
            && !RULES
                .iter()
                .any(|r| r.applies(self) && r.i386.contains(&SOCKETCALL_I386))
    }
}

// The filter language (classic BPF) as the kernel's seccomp runs it, and
// the call it looks at (`struct seccomp_data`; linux/filter.h,
// linux/seccomp.h, linux/audit.h).
const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS: load a 32-bit word of the call
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K: jump on equal
const JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K: jump when a bit is set
const RET_K: u16 = 0x06; // BPF_RET | BPF_K: answer
const RET_ALLOW: u32 = 0x7fff_0000; // SECCOMP_RET_ALLOW
const RET_ERRNO: u32 = 0x0005_0000; // SECCOMP_RET_ERRNO, the error in the low 16 bits
const RET_KILL_PROCESS: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS
const NR: u32 = 0; // seccomp_data.nr: the call number
const ARCH: u32 = 4; // seccomp_data.arch: the architecture the call came from
const ARGS: u32 = 16; // seccomp_data.args[0]; 8 bytes per argument, low half first (little endian)
const X32: u32 = 0x4000_0000; // __X32_SYSCALL_BIT of a call number
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

fn stmt(code: u16, k: u32) -> seccompiler::sock_filter {
    jump(code, k, 0, 0)
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> seccompiler::sock_filter {
    seccompiler::sock_filter { code, jt, jf, k }
}

/// The answer "refused with `errno`".
fn refusal(errno: i32) -> seccompiler::sock_filter {
    stmt(RET_K, RET_ERRNO | errno as u32)
}

/// The architecture of this processor's own calls. The filter supports
/// x86-64 and aarch64 (both little endian, as [`ARGS`] assumes).
fn native_arch() -> Result<u32> {
    if cfg!(target_arch = "x86_64") {
        Ok(AUDIT_ARCH_X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(AUDIT_ARCH_AARCH64)
    } else {
        bail!(
            "{}",
            sam_core::i18n::tr("seccomp filters are not supported on this architecture")
        );
    }
}

/// The instructions of one row for one call number. They expect the call
/// number loaded and leave it loaded: a call with another number, or a use
/// the row does not refuse, goes on to the next row.
fn check(nr: u32, rule: &Rule, families: &[u32]) -> Result<Vec<seccompiler::sock_filter>> {
    // Compares of the argument: each either jumps to the refusal right
    // after them or past it, to where the call number is loaded again.
    let (arg, compares) = match rule.uses {
        Uses::All => return Ok(vec![jump(JEQ_K, nr, 0, 1), refusal(rule.errno)]),
        Uses::ArgIs(arg, values) => (arg, one_of(values, true)?),
        Uses::FamilyNotAllowed(arg) => (arg, one_of(families, false)?),
        Uses::ArgHasBit(arg, bit) => (arg, vec![jump(JSET_K, bit, 0, 1)]),
    };
    // Another call number skips the argument's load, the compares and the
    // refusal.
    let skip = u8::try_from(compares.len() + 2).context("too many values for one row")?;
    let mut out = vec![jump(JEQ_K, nr, 0, skip), stmt(LD_W_ABS, ARGS + 8 * arg)];
    out.extend(compares);
    out.extend([refusal(rule.errno), stmt(LD_W_ABS, NR)]);
    Ok(out)
}

/// Compares the loaded argument with each value. With `refuse`, a value
/// that matches goes to the refusal after the compares and none matching
/// goes past it; without, the other way round.
fn one_of(values: &[u32], refuse: bool) -> Result<Vec<seccompiler::sock_filter>> {
    let n = u8::try_from(values.len()).context("too many values for one row")?;
    Ok((0..n)
        .zip(values)
        .map(|(i, v)| {
            // From compare i: the refusal is n - 1 - i instructions ahead.
            let (to_refusal, past_it) = (n - 1 - i, n - i);
            let last = i + 1 == n;
            if refuse {
                jump(JEQ_K, *v, to_refusal, u8::from(last))
            } else {
                jump(JEQ_K, *v, past_it, 0)
            }
        })
        .collect())
}

/// The filter program for `spec`, made from the rows of [`RULES`] that
/// apply to it:
/// 1. For a 32-bit app on x86-64 ([`SeccompSpec::i386`]; review K-3: such
///    apps once ran with no filter at all, and an app could choose that
///    by making its start program 32-bit), a 32-bit x86 call goes through
///    the rows by its 32-bit numbers and is allowed when none refuses it.
///    A call of another architecture jumps past this part. One gap is
///    left, as in Flatpak: socketcall(), through which older C libraries
///    open sockets, passes the family in memory the filter cannot read,
///    so a 32-bit socket made that way is not limited to the families.
/// 2. A call of any architecture other than this processor's ends the
///    process before any number is compared, since a 32-bit number can be
///    a different call here (41 is `dup` there, `socket` here; review
///    R71).
/// 3. Every call through the x32 ABI is refused. x32 programs share the
///    architecture of x86-64 programs but number some calls on their own
///    (x32 `ptrace` is 521, not 101), so refusing each call by its number
///    missed those (audit S-F9). No AppImage is an x32 program.
/// 4. The call goes through the rows by this processor's numbers and is
///    allowed when none refuses it.
///
/// No call number is in two rows (`each_call_number_is_in_one_row`), so
/// the order of the rows changes no answer.
pub fn seccomp_program(spec: &SeccompSpec) -> Result<seccompiler::BpfProgram> {
    let native = native_arch()?;
    let rules: Vec<&Rule> = RULES.iter().filter(|r| r.applies(spec)).collect();
    let mut families: Vec<u32> = SOCKET_FAMILIES.iter().map(|f| *f as u32).collect();
    if spec.bluetooth {
        families.push(libc::AF_BLUETOOTH as u32);
    }
    let mut program = Vec::new();
    if spec.filters_32_bit_calls() {
        let mut part = vec![stmt(LD_W_ABS, NR)];
        for rule in &rules {
            for nr in rule.i386 {
                part.extend(check(*nr, rule, &families)?);
            }
        }
        part.push(stmt(RET_K, RET_ALLOW));
        let skip =
            u8::try_from(part.len()).context("the 32-bit filter is too long for one jump")?;
        program.extend([stmt(LD_W_ABS, ARCH), jump(JEQ_K, AUDIT_ARCH_I386, 0, skip)]);
        program.extend(part);
    }
    program.extend([
        stmt(LD_W_ABS, ARCH),
        jump(JEQ_K, native, 1, 0),
        stmt(RET_K, RET_KILL_PROCESS),
        stmt(LD_W_ABS, NR),
        jump(JSET_K, X32, 0, 1),
        refusal(libc::EPERM),
    ]);
    for rule in &rules {
        if let Some(nr) = rule.nr {
            program.extend(check(nr, rule, &families)?);
        }
    }
    program.push(stmt(RET_K, RET_ALLOW));
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

    /// The Landlock rules allow writing exactly in the folders the
    /// permissions grant, a user folder at the access the sandbox shows it
    /// at: Documents read and write set to the same place as Pictures
    /// read-only is not writable (the stricter setting wins).
    #[test]
    fn landlock_allows_writing_exactly_in_granted_folders() {
        let mut ctx = sample_context();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Rw;
        p.filesystem.music = Access::Ro;
        let s = landlock_spec(&p, &ctx.host, "/run/user/1000", &[]);
        assert!(s.write.contains(&PathBuf::from("/home/tester/Documents")));
        assert!(!s.write.contains(&PathBuf::from("/home/tester/Music")));
        let mut same = p.clone();
        same.filesystem.pictures = Access::Ro;
        let docs = ctx.host.xdg_dir("documents").unwrap().to_path_buf();
        ctx.host.xdg_dirs.insert("pictures".into(), docs.clone());
        let s = landlock_spec(&same, &ctx.host, "/run/user/1000", &[]);
        assert!(!s.write.contains(&docs), "{:?}", s.write);
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

    /// Review R71: the architecture check that opens [`seccomp_program`]
    /// (for an app that is not a 32-bit app) is the one seccompiler builds
    /// for this processor (same field, same number, same end), for the
    /// processor the test runs on. A wrong number would end every call of
    /// every app there. CI runs it on x86_64; the aarch64 number is checked
    /// wherever the tests run on an aarch64 machine.
    #[test]
    fn the_filter_checks_the_architecture_seccompiler_checks() {
        use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
        let arch = TargetArch::try_from(std::env::consts::ARCH).unwrap();
        let reference: seccompiler::BpfProgram = SeccompFilter::new(
            BTreeMap::new(),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            arch,
        )
        .unwrap()
        .try_into()
        .unwrap();
        for spec in [
            SeccompSpec::default(),
            SeccompSpec {
                strict: true,
                bluetooth: true,
                ..SeccompSpec::default()
            },
        ] {
            let program = seccomp_program(&spec).unwrap();
            assert_eq!(program[..3], reference[..3], "the architecture check");
        }
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
            || raw(467, -1, 0), // open_tree_attr (review R67)
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
        assert_eq!(&filtered[8..], &[eperm; 7], "x32 calls and the siblings");
        assert!(
            control[8] != eperm && control[9] != eperm,
            "x32: the kernel's answer, not the filter's"
        );
        assert_eq!(
            control[10], 0,
            "clock_adjtime reads the clock without the filter"
        );
        // quotactl_fd, mount_setattr and open_tree_attr answer "bad
        // descriptor", "invalid" or (before Linux 6.15) "no such call"
        // without the filter; fspick needs administrator rights, so the
        // kernel refuses it either way.
        assert!(
            control[11] != eperm && control[13] != eperm && control[14] != eperm,
            "{control:?}"
        );
        // With the Bluetooth switch, Bluetooth sockets as without the filter.
        let bt = SeccompSpec {
            bluetooth: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&bt), &calls[7..8]), control[7..8]);
        // Nested sandboxes keep fspick, mount_setattr and open_tree_attr.
        let nested = SeccompSpec {
            allow_userns: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&nested), &calls[12..]), control[12..]);
    }

    /// Review R68: the strict filter promised to block access to other
    /// processes and the NUMA memory calls, but let through
    /// `process_madvise`, `pidfd_getfd` (another process's descriptors,
    /// the same right as `ptrace`), `kcmp` and three NUMA calls. Each
    /// answers as without the filter under the baseline, and "not
    /// permitted" under the strict filter; the control shows the kernel
    /// never says that itself here.
    #[test]
    fn the_strict_filter_blocks_every_call_its_text_names() {
        let calls: Vec<fn() -> libc::c_long> = vec![
            || raw(libc::SYS_process_madvise, -1, 0),
            || raw(libc::SYS_pidfd_getfd, -1, 0),
            || raw(libc::SYS_kcmp, 0, 0),
            || raw(libc::SYS_get_mempolicy, 0, 0),
            || raw(libc::SYS_set_mempolicy, 0, 0), // MPOL_DEFAULT: no change
            || raw(libc::SYS_set_mempolicy_home_node, 0, 0),
        ];
        let control = errnos(None, &calls);
        assert!(!control.contains(&libc::EPERM), "{control:?}");
        let baseline = errnos(Some(&SeccompSpec::default()), &calls);
        assert_eq!(
            baseline[..3],
            control[..3],
            "the baseline leaves the process calls"
        );
        // The NUMA calls are in the baseline since review R69.
        assert_eq!(
            baseline[3..],
            [libc::EPERM; 3],
            "the baseline blocks NUMA calls"
        );
        let strict = SeccompSpec {
            strict: true,
            ..SeccompSpec::default()
        };
        assert_eq!(
            errnos(Some(&strict), &calls),
            [libc::EPERM; 6],
            "control {control:?}"
        );
    }

    /// Review R69: the baseline blocks what Flatpak's default filter blocks
    /// and no desktop app needs: `chroot` and the NUMA memory calls. Each
    /// gets arguments that change nothing (a null folder, no pages, the
    /// default policy); the control shows the kernel never answers "not
    /// permitted" itself here. With nested sandboxes `chroot` stays open
    /// (Chromium's own sandbox uses it), the NUMA calls stay blocked.
    #[test]
    fn the_baseline_blocks_what_no_desktop_app_needs() {
        let calls: Vec<fn() -> libc::c_long> = vec![
            || raw(libc::SYS_chroot, 0, 0),
            || raw(libc::SYS_mbind, 0, 0),
            || raw(libc::SYS_move_pages, 0, 0),
            || raw(libc::SYS_migrate_pages, 0, 0),
            || raw(libc::SYS_get_mempolicy, 0, 0),
            || raw(libc::SYS_set_mempolicy, 0, 0),
            || raw(libc::SYS_set_mempolicy_home_node, 0, 0),
        ];
        let control = errnos(None, &calls);
        assert!(!control.contains(&libc::EPERM), "{control:?}");
        let n = calls.len();
        assert_eq!(
            errnos(Some(&SeccompSpec::default()), &calls),
            vec![libc::EPERM; n],
            "control {control:?}"
        );
        let nested = SeccompSpec {
            allow_userns: true,
            ..SeccompSpec::default()
        };
        let mut nested_want = vec![libc::EPERM; n];
        nested_want[0] = control[0];
        assert_eq!(errnos(Some(&nested), &calls), nested_want, "nested");
    }

    /// `socketpair(family, type, protocol, NULL)`: no place for the pair,
    /// so the kernel never hands one out.
    fn pair(family: i32, kind: i32) -> libc::c_long {
        raw(libc::SYS_socketpair, family.into(), kind.into())
    }

    /// Review R66: `socketpair` makes its sockets as `socket` does, but
    /// only `socket` had the family limit, so a pair of crypto, packet or
    /// virtual-machine sockets reached the kernel (and loaded its module;
    /// TIPC even works as a pair). Now a pair answers "family not
    /// supported" for the same families, a local or internet pair passes
    /// as before, and Bluetooth pairs follow the Bluetooth switch. The
    /// pair has no place (a null pointer), so nothing is left open; the
    /// control shows each refusal is the filter's.
    #[test]
    fn a_socket_pair_opens_only_the_listed_families_too() {
        let calls: Vec<fn() -> libc::c_long> = vec![
            || pair(libc::AF_UNIX, libc::SOCK_STREAM),
            || pair(libc::AF_INET, libc::SOCK_STREAM),
            || pair(libc::AF_ALG, libc::SOCK_SEQPACKET),
            || pair(libc::AF_PACKET, libc::SOCK_DGRAM),
            || pair(libc::AF_VSOCK, libc::SOCK_STREAM),
            || pair(libc::AF_BLUETOOTH, libc::SOCK_STREAM),
        ];
        let control = errnos(None, &calls);
        let filtered = errnos(Some(&SeccompSpec::default()), &calls);
        assert_eq!(
            &filtered[..2],
            &control[..2],
            "local and internet pairs as without the filter"
        );
        assert_eq!(
            &filtered[2..],
            &[libc::EAFNOSUPPORT; 4],
            "crypto, packet, VM and Bluetooth pairs (control {control:?})"
        );
        // Without the filter the kernel writes the pair's place before it
        // looks at the family (Linux 4.17 and later), so it answers "bad
        // address" for every family and makes no socket; never "family
        // not supported".
        assert!(!control[2..].contains(&libc::EAFNOSUPPORT), "{control:?}");
        let bt = SeccompSpec {
            bluetooth: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&bt), &calls[5..]), control[5..], "Bluetooth");
        let nested = SeccompSpec {
            allow_userns: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&nested), &calls), filtered, "nested sandboxes");
    }

    /// Review R74: the kernel reads `ioctl`'s request and `socket`'s family
    /// as 32-bit numbers and drops the upper half of the register. The
    /// filter must compare the same half. A request of 0x1_0000_5412 is
    /// TIOCSTI to the kernel: a terminal rule that compared all 64 bits
    /// would let it through (Flatpak's CVE-2019-10063). A family of
    /// (1 << 32) | AF_PACKET is AF_PACKET: a family check that read the
    /// upper half would let it through. The controls show the kernel takes
    /// both as their lower half (FIONREAD with bit 32 set still reads a
    /// pipe; a local family with bit 32 set still opens).
    #[test]
    fn the_filter_reads_arguments_as_wide_as_the_kernel_does() {
        const HIGH: libc::c_long = 1 << 32;
        let calls: Vec<fn() -> libc::c_long> = vec![
            || raw(libc::SYS_ioctl, -1, HIGH | libc::TIOCSTI as libc::c_long),
            || raw(libc::SYS_ioctl, -1, HIGH | 0x541C), // TIOCLINUX
            || {
                raw(
                    libc::SYS_socket,
                    HIGH | libc::c_long::from(libc::AF_PACKET),
                    libc::c_long::from(libc::SOCK_DGRAM),
                )
            },
            || {
                raw(
                    libc::SYS_socket,
                    HIGH | libc::c_long::from(libc::AF_UNIX),
                    libc::c_long::from(libc::SOCK_STREAM),
                )
            },
            // FIONREAD with bit 32 set on a pipe: answered only by a
            // kernel that drops the upper half (else "not a terminal").
            || {
                let mut p = [0; 2];
                let mut n: libc::c_int = 0;
                // SAFETY: pipe fills a valid array; FIONREAD writes one int to `n`.
                unsafe {
                    if libc::pipe(p.as_mut_ptr()) != 0 {
                        return -1;
                    }
                    libc::syscall(
                        libc::SYS_ioctl,
                        libc::c_long::from(p[0]),
                        HIGH | libc::FIONREAD as libc::c_long,
                        &raw mut n,
                    )
                }
            },
        ];
        let control = errnos(None, &calls);
        assert_eq!(control[..2], [libc::EBADF; 2], "no descriptor -1");
        assert_ne!(
            control[2],
            libc::EAFNOSUPPORT,
            "this kernel has no packet sockets (CONFIG_PACKET), which the control needs: {control:?}"
        );
        assert_eq!(control[3], 0, "a local socket opens");
        assert_eq!(control[4], 0, "the kernel reads FIONREAD's lower half");
        assert_eq!(
            errnos(Some(&SeccompSpec::default()), &calls),
            [libc::EPERM, libc::EPERM, libc::EAFNOSUPPORT, 0, 0],
            "control {control:?}"
        );
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
        // The calls a filter refuses in every use, with this processor's numbers.
        let refused = |allow_userns| -> Vec<(&str, Option<u32>)> {
            let spec = SeccompSpec {
                allow_userns,
                ..SeccompSpec::default()
            };
            RULES
                .iter()
                .filter(|r| r.applies(&spec) && matches!(r.uses, Uses::All))
                .map(|r| (r.name, r.nr))
                .collect()
        };
        let mount = ("mount", Some(libc::SYS_mount as u32));
        assert!(refused(false).contains(&mount));
        assert!(
            refused(true).contains(&("io_uring_setup", Some(libc::SYS_io_uring_setup as u32))),
            "io_uring is blocked even with nested sandboxes"
        );
        assert!(
            !refused(true).contains(&mount),
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
                // A fourth argument, null (socketpair's place for the pair).
                in("rsi") 0u64,
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
        // Also the 32-bit numbers that are socket (41, `dup` there) and
        // clone3 (435) here: no answer, the end (review R71).
        let twins: [fn() -> libc::c_long; 2] = [|| call32(41, 5, 0, 0), || call32(435, 0, 0, 0)];
        for (n, call) in twins.into_iter().enumerate() {
            let (_, ended) = errnos_and_status(Some(&SeccompSpec::default()), &[call]);
            assert!(
                libc::WIFSIGNALED(ended) && libc::WTERMSIG(ended) == libc::SIGSYS,
                "32-bit twin {n} ends a 64-bit app: {ended:#x}"
            );
        }
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
        // socketpair (32-bit number 360) is limited like socket (review
        // R66); the pair has no place, so nothing is left open.
        let pairs: Vec<fn() -> libc::c_long> = vec![
            || call32(360, libc::AF_PACKET as u32, libc::SOCK_DGRAM as u32, 0),
            || call32(360, libc::AF_UNIX as u32, libc::SOCK_STREAM as u32, 0),
        ];
        let open_pairs = errnos(None, &pairs);
        assert_ne!(open_pairs[0], libc::EAFNOSUPPORT, "{open_pairs:?}");
        assert_eq!(
            errnos(Some(&spec), &pairs),
            [libc::EAFNOSUPPORT, open_pairs[1]],
            "32-bit pairs"
        );
        // The strict filter's calls are refused through their 32-bit
        // numbers too.
        let strict = SeccompSpec {
            i386: true,
            strict: true,
            ..SeccompSpec::default()
        };
        assert_eq!(errnos(Some(&strict), &calls[13..]), [eperm], "strict");
        // The six calls the strict filter gained (review R68; the three
        // NUMA ones are in the baseline since R69), each through its own
        // 32-bit number, with arguments that change nothing.
        let reach: Vec<fn() -> libc::c_long> = vec![
            || call32(440, -1i32 as u32, 0, 0), // process_madvise(-1)
            || call32(438, -1i32 as u32, 0, 0), // pidfd_getfd(-1)
            || call32(349, 0, 0, 0),            // kcmp: no process 0
            || call32(275, 0, 0, 0),            // get_mempolicy(NULL)
            || call32(276, 0, 0, 0),            // set_mempolicy(MPOL_DEFAULT)
            || call32(450, 0, 0, 0),            // set_mempolicy_home_node, no pages
        ];
        let open_reach = errnos(None, &reach);
        assert!(!open_reach.contains(&eperm), "{open_reach:?}");
        assert_eq!(errnos(Some(&strict), &reach), [eperm; 6], "strict, 32-bit");
        // open_tree_attr through its 32-bit number (review R67).
        let tree: Vec<fn() -> libc::c_long> = vec![|| call32(467, -1i32 as u32, 0, 0)];
        let open_tree = errnos(None, &tree);
        assert_ne!(open_tree, [eperm], "the kernel's own answer");
        assert_eq!(errnos(Some(&spec), &tree), [eperm], "32-bit open_tree_attr");
        // Review R69: `chroot` and the NUMA calls the baseline gained,
        // through their 32-bit numbers.
        let gained: Vec<fn() -> libc::c_long> = vec![
            || call32(61, 0, 0, 0),  // chroot(NULL)
            || call32(274, 0, 0, 0), // mbind, no pages
            || call32(317, 0, 0, 0), // move_pages, no pages
            || call32(294, 0, 0, 0), // migrate_pages, no nodes
            || call32(275, 0, 0, 0), // get_mempolicy(NULL)
            || call32(276, 0, 0, 0), // set_mempolicy(MPOL_DEFAULT)
            || call32(450, 0, 0, 0), // set_mempolicy_home_node, no pages
        ];
        let open_gained = errnos(None, &gained);
        assert!(!open_gained.contains(&eperm), "{open_gained:?}");
        assert_eq!(errnos(Some(&spec), &gained), [eperm; 7], "32-bit baseline");
        let nested_tree = SeccompSpec {
            i386: true,
            allow_userns: true,
            ..SeccompSpec::default()
        };
        assert_eq!(
            errnos(Some(&nested_tree), &tree),
            open_tree,
            "nested, 32-bit"
        );
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

    /// Every row of the filter has its 32-bit x86 numbers (kexec_file_load
    /// has none): a call added to the filter is not forgotten for 32-bit
    /// apps.
    #[test]
    fn every_blocked_call_is_blocked_for_32_bit_apps_too() {
        for r in RULES {
            assert!(
                r.name == "kexec_file_load" || !r.i386.is_empty(),
                "{} has no 32-bit number in its row",
                r.name
            );
        }
    }

    /// No call is named twice and no call number is in two rows, neither
    /// this processor's nor a 32-bit one, so one row says everything a call
    /// gets. With two rows for one number the order of the rows would
    /// matter: a row that refuses every use answers the call, and a later
    /// row for it is never read; a row that refuses only some uses lets the
    /// others go on, and a later row for the same number then answers them.
    #[test]
    fn each_call_number_is_in_one_row() {
        let mut names = std::collections::BTreeSet::new();
        let mut native = std::collections::BTreeSet::new();
        let mut i386 = std::collections::BTreeSet::new();
        for r in RULES {
            assert!(names.insert(r.name), "{} has two rows", r.name);
            if let Some(nr) = r.nr {
                assert!(native.insert(nr), "{}: number {nr} has two rows", r.name);
            }
            for nr in r.i386 {
                assert!(
                    i386.insert(*nr),
                    "{}: 32-bit number {nr} has two rows",
                    r.name
                );
            }
        }
    }
}
