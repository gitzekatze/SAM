//! Kernel security features (§2.22.2): Landlock and seccomp.
//!
//! * Landlock is applied *inside* the sandbox by `sam-jail-run --sandbox-exec`
//!   (a Landlock domain cannot set up mounts, so it must come after bwrap).
//!   Reads stay allowed everywhere the mounts allow; writes are limited to the
//!   locations the profile grants read/write. This is defense in depth for the
//!   bind-mount layout, not a complete sandbox.
//! * The strict seccomp filter is compiled with seccompiler and handed to
//!   bwrap through `--seccomp <fd>`.

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LandlockSpec {
    /// Paths that are readable and executable.
    pub read: Vec<PathBuf>,
    /// Paths that are fully writable.
    pub write: Vec<PathBuf>,
}

/// Writable locations implied by a permission set (sandbox paths).
pub fn landlock_spec(p: &PermissionSet, host: &HostInfo, runtime_dir_in_sandbox: &str) -> LandlockSpec {
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
        write.push(expand_home(s));
    }
    LandlockSpec { read: vec![PathBuf::from("/")], write }
}

/// Entry point for `sam-jail-run --sandbox-exec <spec> -- <cmd...>`:
/// apply restrictions and exec. Never returns on success.
pub fn sandbox_exec(spec_path: &Path, argv: &[String]) -> Result<()> {
    let spec: SandboxSpec = serde_json::from_slice(&std::fs::read(spec_path).context("reading sandbox spec")?)?;
    let (prog, rest) = argv.split_first().context("no command given")?;
    if let Some(ll) = &spec.landlock {
        match apply_landlock(ll) {
            Ok(status) => {
                if std::env::var_os("SAM_DEBUG").is_some() {
                    eprintln!("sam-jail: landlock {status}");
                }
            }
            Err(e) => eprintln!("sam-jail: landlock not applied: {e:#}"),
        }
    }
    let err = Command::new(prog).args(rest).exec();
    bail!("exec {prog}: {err}")
}

fn apply_landlock(spec: &LandlockSpec) -> Result<String> {
    use landlock::{
        path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };
    let abi = ABI::V3;
    let read = AccessFs::from_read(abi);
    let all = AccessFs::from_all(abi);
    let write_existing: Vec<&PathBuf> = spec.write.iter().filter(|p| p.exists()).collect();
    let status = Ruleset::default()
        .handle_access(all)
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

/// Syscalls blocked (EPERM) by the strict filter.
fn strict_syscalls(allow_userns: bool) -> Vec<i64> {
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
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_vhangup,
        libc::SYS_syslog,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fsconfig,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_kexec_file_load, libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_uselib]);
    if !allow_userns {
        v.extend([libc::SYS_unshare, libc::SYS_setns]);
    }
    v
}

/// Compile the strict filter and store it in an inheritable memfd.
/// Returns the raw fd to pass to `bwrap --seccomp`.
pub fn seccomp_fd(allow_userns: bool) -> Result<i32> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    let arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        bail!("seccomp strict mode is not supported on this architecture");
    };
    let rules: BTreeMap<i64, Vec<SeccompRule>> = strict_syscalls(allow_userns).into_iter().map(|s| (s, vec![])).collect();
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch)
        .map_err(|e| anyhow!("{e}"))?;
    let prog: BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| anyhow!("{e}"))?;
    let mut bytes = Vec::with_capacity(prog.len() * 8);
    for ins in &prog {
        bytes.extend_from_slice(&ins.code.to_ne_bytes());
        bytes.push(ins.jt);
        bytes.push(ins.jf);
        bytes.extend_from_slice(&ins.k.to_ne_bytes());
    }
    // memfd without MFD_CLOEXEC so bwrap inherits it.
    let name = std::ffi::CString::new("sam-seccomp").unwrap();
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        bail!("memfd_create failed: {}", std::io::Error::last_os_error());
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    f.write_all(&bytes)?;
    f.seek(SeekFrom::Start(0))?;
    Ok(f.into_raw_fd())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::backend::sample_context;

    #[test]
    fn spec_follows_permissions() {
        let ctx = sample_context();
        let mut p = PermissionSet::strict_gui();
        p.filesystem.documents = Access::Rw;
        p.filesystem.music = Access::Ro;
        let s = landlock_spec(&p, &ctx.host, "/run/user/1000");
        assert!(s.write.contains(&PathBuf::from("/home/tester/Documents")));
        assert!(!s.write.contains(&PathBuf::from("/home/tester/Music")));
        assert!(s.write.contains(&PathBuf::from("/home/tester")), "private home is writable");
        p.filesystem.home = true;
        p.filesystem.home_access = Access::Ro;
        let s = landlock_spec(&p, &ctx.host, "/run/user/1000");
        assert!(!s.write.contains(&PathBuf::from("/home/tester")), "read-only full home");
    }

    #[test]
    fn seccomp_compiles() {
        let fd = seccomp_fd(true).unwrap();
        assert!(fd >= 0);
        unsafe { libc::close(fd) };
    }
}
