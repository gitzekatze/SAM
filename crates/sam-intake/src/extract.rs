//! Payload extraction.
//!
//! Preferred order:
//! 1. Static extraction without executing the AppImage:
//!    * Type 2: built-in SquashFS reader (gzip/xz/zstd/lz4), then `unsquashfs`
//!    * Type 2 with a DwarFS image (uruntime): `dwarfsextract`
//!    * Type 1: `bsdtar` (libarchive)
//! 2. Optional fallback: the AppImage's own `--appimage-extract`, run inside a
//!    network-less bubblewrap sandbox, only with explicit user consent.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use sam_core::util::which;
use sam_core::AppImageType;
use sam_detect::AppImageInfo;

use crate::normalize::{normalize, sanitize_archive_path, Limits, NormalizeReport};

pub struct ExtractRequest<'a> {
    pub source: &'a Path,
    pub info: &'a AppImageInfo,
    /// `extracted/<app-id>/`; the payload ends up in `<root>/AppDir`.
    pub root: &'a Path,
    pub limits: Limits,
    /// The user consented to running the AppImage's own extractor.
    pub allow_fallback: bool,
    /// Run the extractors inside a minimal Bubblewrap sandbox (source
    /// read-only, only the target writable, no network, no capabilities).
    /// `None` extracts in-process (tests, or Bubblewrap unavailable).
    pub isolation: Option<Isolation>,
}

/// How to isolate extraction: the bwrap binary and SAM's own CLI binary,
/// which provides the built-in SquashFS reader as `sam-jail dev extract-squashfs`.
#[derive(Debug, Clone)]
pub struct Isolation {
    pub bwrap: PathBuf,
    pub self_exe: PathBuf,
    /// The system the sandbox shows, as Bubblewrap arguments: the view
    /// every sandbox SAM builds rests on (`sam_sandbox::helper_system_args`),
    /// so unpacking sees the same system as the apps on every distribution.
    pub system: Vec<String>,
    /// SAM's baseline syscall filter as raw BPF (what `bwrap --seccomp`
    /// reads): unpacking untrusted input, by SAM's reader or by the
    /// AppImage's own extractor, meets the same kernel limits as an app
    /// (audit I-F17: the self-unpack sandbox had no filter).
    pub filter: Option<Vec<u8>>,
}

/// Hands `filter` to Bubblewrap as `--seccomp N`: a memory file holding the
/// program, kept open across `exec` in the child only (N is its number).
fn with_filter(c: &mut Command, filter: &[u8]) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    // SAFETY: memfd_create takes a NUL-terminated name and flags; it returns a new descriptor or -1.
    let raw = unsafe { libc::memfd_create(c"sam-filter".as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        bail!("memfd_create: {}", io::Error::last_os_error());
    }
    // SAFETY: `raw` is a descriptor memfd_create just returned and nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut file = fs::File::from(fd);
    file.write_all(filter)?;
    use std::io::Seek;
    file.seek(io::SeekFrom::Start(0))?;
    let n = file.as_raw_fd();
    c.arg("--seccomp").arg(n.to_string());
    // SAFETY: the closure runs between fork and exec and calls only fcntl, which is async-signal-safe.
    unsafe {
        c.pre_exec(move || {
            // Owned here, so the file lives as long as the command.
            let n = file.as_raw_fd();
            let flags = libc::fcntl(n, libc::F_GETFD);
            if flags < 0 || libc::fcntl(n, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

/// Nothing inside an unpack sandbox may make a user namespace of its own:
/// one gives the program inside full rights over a fresh network namespace
/// and with it the kernel's netfilter, the usual way into kernel bugs
/// (review K-2). The syscall filter refuses it too; this holds even where
/// a call slips past the filter. App sandboxes do the same
/// (sam-sandbox, `--disable-userns`).
const NO_NESTED_USERNS: [&str; 2] = ["--unshare-user", "--disable-userns"];

/// `bwrap … --` prefix for running an extractor on untrusted input.
/// `tool` is the program that will run; one installed outside `/usr` (for
/// example in `~/.local/bin`) is added read-only so it exists inside.
pub(crate) fn isolated(
    iso: &Isolation,
    source: &Path,
    writable: &Path,
    tool: &Path,
) -> Result<Command> {
    let mut c = Command::new(&iso.bwrap);
    c.args(["--die-with-parent", "--new-session", "--unshare-all"]);
    c.args(NO_NESTED_USERNS);
    c.args(["--cap-drop", "ALL", "--clearenv", "--tmpfs", "/"]);
    c.args(&iso.system);
    if let Some(f) = &iso.filter {
        with_filter(&mut c, f)?;
    }
    c.args(["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]);
    c.arg("--ro-bind").arg(source).arg(source);
    c.arg("--bind").arg(writable).arg(writable);
    c.arg("--ro-bind").arg(&iso.self_exe).arg(&iso.self_exe);
    if !tool.starts_with("/usr") && tool != iso.self_exe {
        c.arg("--ro-bind").arg(tool).arg(tool);
    }
    c.args(["--setenv", "PATH", "/usr/bin:/bin"]);
    c.args(FEW_MALLOC_ARENAS);
    c.args(["--remount-ro", "/", "--"]);
    Ok(c)
}

/// Unpacking programs run with a memory limit ([`Limits::max_memory`],
/// counted as address space). The C library reserves address space for
/// each thread's own memory pool, so a tool with a thread per processor
/// could reach the limit on a computer with many processors without using
/// the memory; two pools are plenty for unpacking.
const FEW_MALLOC_ARENAS: [&str; 3] = ["--setenv", "MALLOC_ARENA_MAX", "2"];

/// `program` inside the same sandbox as the unpacking tools, with `home`
/// as the only folder it sees of the computer's own files, writable: for
/// GnuPG, which reads the key and the signature an AppImage carries (review
/// 2026-11-23, F6; audit I-F18). No network, nothing of the home, the
/// baseline syscall filter; a program it leaves behind (a gpg-agent) ends
/// with the sandbox.
pub fn isolated_program(iso: &Isolation, home: &Path, program: &Path) -> Result<Command> {
    let mut c = isolated(iso, home, home, program)?;
    c.arg(program);
    Ok(c)
}

/// Exit code of `sam-jail dev extract-squashfs` when an unpacking limit was
/// exceeded inside the sandbox. Without it the parent saw only "failed",
/// tried the next tool (which has only a time limit) and then offered to let
/// the AppImage unpack itself: a crafted image escaped the limits (audit
/// I-F3).
pub const EXIT_LIMIT: i32 = 87;

/// Exit code of `sam-jail dev extract-squashfs` when the disk became full
/// inside the sandbox. Without it the parent saw only "exited with 1", so
/// SAM filled the disk again with the next tool and then offered to let
/// the AppImage unpack itself (review F2).
pub const EXIT_DISK_FULL: i32 = 88;

/// Entry point of `sam-jail dev extract-squashfs` (runs inside the sandbox).
pub fn builtin_squashfs_entry(src: &Path, offset: u64, dst: &Path, limits: &Limits) -> Result<()> {
    builtin_squashfs(src, offset, dst, limits, Instant::now(), &mut io::stderr())
}

#[derive(Debug)]
pub struct ExtractOutcome {
    pub appdir: PathBuf,
    pub method: String,
    pub report: NormalizeReport,
    pub attempts: Vec<String>,
}

/// Error type signalling that only the consent-gated fallback is left.
#[derive(Debug)]
pub struct NeedsFallbackConsent {
    pub attempts: Vec<String>,
}

impl std::fmt::Display for NeedsFallbackConsent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SAM could not unpack it by itself ({}). The AppImage can unpack itself instead, which runs code from it inside a sandbox with no network, no access to your files and the same limits on kernel calls as an app: allow that in SAM's window, or with `sam-jail reextract APP --allow-fallback`.",
            self.attempts.join("; ")
        )
    }
}
impl std::error::Error for NeedsFallbackConsent {}

/// Free bytes for an unprivileged user in the file system that holds `dir`.
pub fn free_bytes(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs is a plain C struct; all zeros is a valid value.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a NUL-terminated path and `st` a valid, writable statvfs.
    (unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0)
        .then(|| st.f_bavail as u64 * st.f_frsize as u64)
}

/// About how much space unpacking an AppImage of `source_size` bytes takes:
/// SquashFS and DwarFS images usually unpack to two or three times their
/// size; never more than the unpack limit allows.
pub fn space_needed(source_size: u64, limits: &Limits) -> u64 {
    source_size
        .saturating_mul(3)
        .saturating_add(64 * 1024 * 1024)
        .min(limits.max_bytes.saturating_add(64 * 1024 * 1024))
}

/// Refuses to start unpacking when the folder clearly has too little room,
/// with what to do about it, instead of failing halfway with a full disk.
pub fn check_space(
    root: &Path,
    source_size: u64,
    limits: &Limits,
    free: Option<u64>,
) -> Result<()> {
    let needed = space_needed(source_size, limits);
    match free {
        Some(free) if free < needed => bail!(
            "{}",
            sam_core::i18n::trf(
                "There is not enough free space to unpack this AppImage: it needs about {needed}, but the folder {folder} has only {free} free. Free some space, or choose another folder for unpacked apps under Preferences → Unpacking → Location.",
                &[("needed", &sam_core::util::human_size(needed)), ("folder", &root.display()), ("free", &sam_core::util::human_size(free))],
            )
        ),
        _ => Ok(()),
    }
}

/// A limit error with why the limit exists and how to raise it.
fn explain_limit(e: anyhow::Error) -> anyhow::Error {
    anyhow!(
        "{}",
        sam_core::i18n::trf(
            "SAM stopped unpacking this AppImage: {reason}. The limits protect your computer from AppImages built to fill the disk or keep SAM busy. If you trust this AppImage, raise the limit, for example with `sam-jail config set extraction.max_files 400000` (also extraction.max_size_mb, extraction.max_seconds and extraction.max_memory_mb), then create the sandbox again.",
            &[("reason", &format!("{e:#}"))],
        )
    )
}

/// What SAM says when the disk became full while unpacking into `root`.
fn disk_full(root: &Path) -> anyhow::Error {
    anyhow!(
        "{}",
        sam_core::i18n::trf(
            "The disk became full while unpacking this AppImage into {folder}. SAM removed the part that was already unpacked. Free some space, or choose another folder for unpacked apps under Preferences → Unpacking → Location.",
            &[("folder", &root.display())],
        )
    )
}

/// Whether an unpacking error came from a full disk.
pub fn is_disk_full(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.raw_os_error() == Some(libc::ENOSPC))
            || c.to_string().contains("No space left on device")
    })
}

pub fn extract(req: &ExtractRequest, log: &mut dyn Write) -> Result<ExtractOutcome> {
    fs::create_dir_all(req.root)?;
    let source_size = fs::metadata(req.source).map(|m| m.len()).unwrap_or(0);
    check_space(req.root, source_size, &req.limits, free_bytes(req.root))?;
    // Each attempt unpacks into `staging` inside a fresh, empty box; only the
    // box is writable for the unpacking tool. The rest of the app's folder
    // (where SAM writes its records, the menu entry and the icon afterwards)
    // stays out of its reach: a tool tricked by a crafted image could
    // otherwise plant links there that SAM would then write through,
    // outside any sandbox (regression, audit I-F2).
    let unpack_box = req.root.join(format!(".unpack-{}", std::process::id()));
    let staging = unpack_box.join("out");
    let fresh_box = || -> Result<()> {
        if fs::symlink_metadata(&unpack_box).is_ok() {
            fs::remove_dir_all(&unpack_box)?;
        }
        fs::create_dir(&unpack_box)?;
        Ok(())
    };
    let started = Instant::now();
    let mut attempts = Vec::new();

    type Method<'m> = (
        &'static str,
        Box<dyn Fn(&Path, &mut dyn Write) -> Result<()> + 'm>,
    );
    let mut methods: Vec<Method> = Vec::new();
    match req.info.kind {
        AppImageType::Type2 if req.info.payload == sam_detect::appimage::PayloadFormat::Dwarfs => {
            // DwarFS (uruntime): unpacked by the dwarfs tools, inside the
            // same minimal sandbox as the other extractors.
            let off = req.info.payload_offset.context(sam_core::i18n::tr(
                "the app image inside the AppImage was not found",
            ))?;
            if let Some(d) = which("dwarfsextract") {
                methods.push((
                    "dwarfsextract",
                    Box::new(move |dst: &Path, log: &mut dyn Write| {
                        fs::create_dir_all(dst)?;
                        let mut c = match &req.isolation {
                            Some(iso) => {
                                let mut c =
                                    isolated(iso, req.source, dst.parent().unwrap_or(dst), &d)?;
                                c.arg(&d);
                                c
                            }
                            None => Command::new(&d),
                        };
                        run_tool(
                            c.arg("-i")
                                .arg(req.source)
                                .arg("-O")
                                .arg(off.to_string())
                                .arg("-o")
                                .arg(dst),
                            &req.limits,
                            started,
                            log,
                            dst.parent().unwrap_or(dst),
                        )
                    }),
                ));
            } else {
                attempts
                    .push(sam_core::i18n::tr("this AppImage uses a DwarFS image; install the dwarfs tools (dwarfsextract) to unpack it without running it"));
            }
        }
        AppImageType::Type2 => {
            let off = req.info.payload_offset.context(sam_core::i18n::tr(
                "the app image inside the AppImage was not found",
            ))?;
            methods.push((
                "builtin-squashfs",
                Box::new(
                    move |dst: &Path, log: &mut dyn Write| match &req.isolation {
                        Some(iso) => {
                            let mut c = isolated(
                                iso,
                                req.source,
                                dst.parent().unwrap_or(dst),
                                &iso.self_exe,
                            )?;
                            c.arg(&iso.self_exe)
                                .args(["dev", "extract-squashfs"])
                                .arg(req.source)
                                .arg(off.to_string())
                                .arg(dst);
                            c.args([
                                "--max-files",
                                &req.limits.max_files.to_string(),
                                "--max-bytes",
                                &req.limits.max_bytes.to_string(),
                                "--max-seconds",
                                &req.limits.max_seconds.to_string(),
                            ]);
                            run_tool(
                                &mut c,
                                &req.limits,
                                started,
                                log,
                                dst.parent().unwrap_or(dst),
                            )
                        }
                        // In SAM's own process (no sandbox for the reader): a
                        // panic of the SquashFS reader on a damaged image becomes
                        // an error, like in the sandboxed reader process.
                        None => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            builtin_squashfs(req.source, off, dst, &req.limits, started, log)
                        }))
                        .unwrap_or_else(|_| {
                            Err(anyhow!(
                                "{}",
                                sam_core::i18n::tr(
                                    "the AppImage's SquashFS image is damaged (the reader stopped)"
                                )
                            ))
                        }),
                    },
                ),
            ));
            if let Some(u) = which("unsquashfs") {
                methods.push((
                    "unsquashfs",
                    Box::new(move |dst: &Path, log: &mut dyn Write| {
                        let mut c = match &req.isolation {
                            Some(iso) => {
                                let mut c =
                                    isolated(iso, req.source, dst.parent().unwrap_or(dst), &u)?;
                                c.arg(&u);
                                c
                            }
                            None => Command::new(&u),
                        };
                        run_tool(
                            c.arg("-o")
                                .arg(off.to_string())
                                .arg("-d")
                                .arg(dst)
                                .args(["-f", "-no-xattrs", "-no-progress", "-quiet"])
                                .arg(req.source),
                            &req.limits,
                            started,
                            log,
                            dst.parent().unwrap_or(dst),
                        )
                    }),
                ));
            }
        }
        AppImageType::Type1 => {
            if let Some(b) = which("bsdtar") {
                methods.push((
                    "bsdtar",
                    Box::new(move |dst: &Path, log: &mut dyn Write| {
                        fs::create_dir_all(dst)?;
                        let mut c = match &req.isolation {
                            Some(iso) => {
                                let mut c =
                                    isolated(iso, req.source, dst.parent().unwrap_or(dst), &b)?;
                                c.arg(&b);
                                c
                            }
                            None => Command::new(&b),
                        };
                        run_tool(
                            c.arg("-xf").arg(req.source).arg("-C").arg(dst).args([
                                "--no-same-owner",
                                "--no-xattrs",
                                "--no-acls",
                            ]),
                            &req.limits,
                            started,
                            log,
                            dst.parent().unwrap_or(dst),
                        )
                    }),
                ));
            } else {
                attempts.push(sam_core::i18n::tr("bsdtar (libarchive) is not installed"));
            }
        }
        AppImageType::Unknown => bail!(
            "{}",
            sam_core::i18n::trf(
                "{file} is not a recognized AppImage",
                &[("file", &req.source.display())]
            )
        ),
    }

    match &req.isolation {
        Some(iso) => writeln!(
            log,
            "[extract] isolated: extractors run inside {} (no network, read-only source)",
            iso.bwrap.display()
        )?,
        None => writeln!(
            log,
            "[extract] not isolated: extracting in-process (Bubblewrap unavailable)"
        )?,
    }
    let mut method_used = None;
    for (name, f) in &methods {
        writeln!(log, "[extract] trying {name}")?;
        fresh_box()?;
        match f(&staging, log) {
            Ok(()) => {
                method_used = Some(name.to_string());
                break;
            }
            Err(e) => {
                writeln!(log, "[extract] {name} failed: {e:#}")?;
                if is_limit_error(&e) {
                    let _ = fs::remove_dir_all(&unpack_box);
                    return Err(explain_limit(e));
                }
                // A full disk: remove what was unpacked so far and say so;
                // the next method would fail the same way.
                if is_disk_full(&e) {
                    let _ = fs::remove_dir_all(&unpack_box);
                    return Err(disk_full(req.root));
                }
                attempts.push(format!("{name}: {e:#}"));
            }
        }
    }

    if method_used.is_none() {
        if !req.allow_fallback {
            let _ = fs::remove_dir_all(&unpack_box);
            return Err(anyhow!(NeedsFallbackConsent { attempts }));
        }
        writeln!(
            log,
            "[extract] trying sandboxed --appimage-extract (user consented)"
        )?;
        fresh_box()?;
        match self_extract_sandboxed(
            req.isolation.as_ref(),
            req.source,
            &staging,
            &req.limits,
            started,
            log,
        ) {
            Ok(()) => method_used = Some("appimage-extract (sandboxed)".into()),
            Err(e) => {
                let _ = fs::remove_dir_all(&unpack_box);
                if is_limit_error(&e) {
                    return Err(explain_limit(e));
                }
                if is_disk_full(&e) {
                    return Err(disk_full(req.root));
                }
                attempts.push(format!("appimage-extract: {e:#}"));
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "all ways of unpacking failed:\n  {attempts}",
                        &[("attempts", &attempts.join("\n  "))]
                    )
                );
            }
        }
    }

    // What the tool left must be a real folder, not a link to elsewhere.
    if !fs::symlink_metadata(&staging).is_ok_and(|m| m.is_dir()) {
        let _ = fs::remove_dir_all(&unpack_box);
        bail!(
            "{}",
            sam_core::i18n::tr("the unpacked app is not a plain folder; it was removed")
        );
    }
    let report = match normalize(&staging, &req.limits, started) {
        Ok(r) => r,
        Err(e) => {
            let _ = fs::remove_dir_all(&unpack_box);
            return Err(if is_limit_error(&e) {
                explain_limit(e)
            } else {
                e
            });
        }
    };
    writeln!(
        log,
        "[extract] normalized {} entries, {} bytes; {} setid bits removed, {} escaping symlinks removed, {} special files removed",
        report.file_count,
        report.total_size,
        report.setid_removed.len(),
        report.removed_symlinks.len(),
        report.removed_special.len()
    )?;

    let appdir = req.root.join("AppDir");
    let old = req.root.join(format!(".old-{}", std::process::id()));
    let swapped = swap_into_place(&staging, &appdir, &old, true);
    let _ = fs::remove_dir_all(&unpack_box);
    swapped?;
    if fs::symlink_metadata(&old).is_ok() {
        let _ = fs::remove_dir_all(&old);
    }
    Ok(ExtractOutcome {
        appdir,
        method: method_used.unwrap_or_default(),
        report,
        attempts,
    })
}

/// Puts the unpacked app `new` at `appdir`, in one step where the file
/// system can: the old app and the new one change places at once, so there
/// is never a moment without an app (`old` then holds the old one). Where
/// it cannot (`exchange` false, or a file system without that), the old app
/// is moved to `old` first and put back if the new one cannot follow: a
/// failed second step left the app with no unpacked files at all (audit
/// I-F16).
fn swap_into_place(new: &Path, appdir: &Path, old: &Path, exchange: bool) -> Result<()> {
    if fs::symlink_metadata(appdir).is_err() {
        fs::rename(new, appdir).with_context(|| format!("moving into {}", appdir.display()))?;
        return Ok(());
    }
    if exchange {
        match exchange_paths(new, appdir) {
            Ok(()) => {
                // The old app now sits where the new one was; the new one is
                // in place whatever happens to the old one now.
                if fs::rename(new, old).is_err() {
                    let _ = fs::remove_dir_all(new);
                }
                return Ok(());
            }
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
                ) => {}
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context(format!("moving into {}", appdir.display()))
                )
            }
        }
    }
    fs::rename(appdir, old)?;
    if let Err(e) = fs::rename(new, appdir) {
        fs::rename(old, appdir)
            .with_context(|| format!("putting the old app back at {} ({e})", appdir.display()))?;
        return Err(anyhow::Error::new(e).context(format!("moving into {}", appdir.display())));
    }
    Ok(())
}

/// Swaps two paths in one step (`renameat2` with `RENAME_EXCHANGE`).
fn exchange_paths(a: &Path, b: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let ca = std::ffi::CString::new(a.as_os_str().as_bytes())?;
    let cb = std::ffi::CString::new(b.as_os_str().as_bytes())?;
    // SAFETY: both are NUL-terminated paths; renameat2 only renames.
    let r = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            ca.as_ptr(),
            libc::AT_FDCWD,
            cb.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// An error for an exceeded unpacking limit. It carries a code, so it is
/// recognized whatever language its message is in.
pub(crate) fn limit_error(message: String) -> anyhow::Error {
    sam_core::error::CodedError::new("extraction-limit", message).into()
}

fn is_limit_error(e: &anyhow::Error) -> bool {
    sam_core::error::code_of(e) == Some("extraction-limit")
}

/// Make sure every existing ancestor of `rel` inside `root` is a real
/// directory (not a symlink), creating missing ones.
fn safe_mkdirs(root: &Path, rel: &Path) -> Result<PathBuf> {
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => bail!(
                "{}",
                sam_core::i18n::trf(
                    "a link at {path} points outside the app",
                    &[("path", &cur.display())]
                )
            ),
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!(
                "{}",
                sam_core::i18n::trf("{path} is not a folder", &[("path", &cur.display())])
            ),
            Err(_) => fs::create_dir(&cur)?,
        }
    }
    Ok(cur)
}

struct LimitedReader<'a, R> {
    inner: R,
    total: &'a mut u64,
    max: u64,
}
impl<R: Read> Read for LimitedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        *self.total += n as u64;
        if *self.total > self.max {
            return Err(io::Error::other(sam_core::error::CodedError::new(
                "extraction-limit",
                sam_core::i18n::tr("unpacking limit exceeded: the app is too large"),
            )));
        }
        Ok(n)
    }
}

fn builtin_squashfs(
    src: &Path,
    offset: u64,
    dst: &Path,
    limits: &Limits,
    started: Instant,
    log: &mut dyn Write,
) -> Result<()> {
    use backhand::{FilesystemReader, InnerNode};
    let reader = BufReader::new(File::open(src)?);
    let sqfs =
        FilesystemReader::from_reader_with_offset(reader, offset).map_err(|e| anyhow!("{e}"))?;
    fs::create_dir_all(dst)?;
    let mut count = 0u64;
    let mut total = 0u64;
    let mut skipped = 0u64;
    for node in sqfs.files() {
        count += 1;
        if count > limits.max_files {
            return Err(limit_error(sam_core::i18n::trf(
                "unpacking limit exceeded: more than {count} files",
                &[("count", &limits.max_files)],
            )));
        }
        if started.elapsed() > Duration::from_secs(limits.max_seconds) {
            return Err(limit_error(sam_core::i18n::trf(
                "unpacking limit exceeded: it took longer than {seconds} seconds",
                &[("seconds", &limits.max_seconds)],
            )));
        }
        let Some(rel) = sanitize_archive_path(&node.fullpath) else {
            if node
                .fullpath
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                writeln!(
                    log,
                    "[extract] refusing path traversal entry {}",
                    node.fullpath.display()
                )?;
                skipped += 1;
            }
            continue;
        };
        let parent_rel = rel.parent().unwrap_or(Path::new(""));
        let parent = safe_mkdirs(dst, parent_rel)?;
        let target = parent.join(
            rel.file_name()
                .context(sam_core::i18n::tr("entry without name"))?,
        );
        match &node.inner {
            InnerNode::Dir(_) => {
                safe_mkdirs(dst, &rel)?;
            }
            InnerNode::File(f) => {
                if fs::symlink_metadata(&target).is_ok() {
                    bail!("duplicate entry {}", rel.display());
                }
                let mut out = File::create(&target)?;
                let mut r = LimitedReader {
                    inner: sqfs.file(f).reader(),
                    total: &mut total,
                    max: limits.max_bytes,
                };
                io::copy(&mut r, &mut out)
                    .map_err(|e| anyhow::Error::new(e).context(rel.display().to_string()))?;
                let mode = if node.header.permissions & 0o111 != 0 {
                    0o755
                } else {
                    0o644
                };
                fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
            }
            InnerNode::Symlink(s) => {
                symlink(&s.link, &target)?;
            }
            InnerNode::CharacterDevice(_)
            | InnerNode::BlockDevice(_)
            | InnerNode::NamedPipe
            | InnerNode::Socket => {
                writeln!(log, "[extract] skipping special file {}", rel.display())?;
                skipped += 1;
            }
        }
    }
    writeln!(
        log,
        "[extract] builtin reader: {count} entries, {total} bytes, {skipped} skipped"
    )?;
    Ok(())
}

pub(crate) fn wait_with_timeout(
    child: std::process::Child,
    limits: &Limits,
    started: Instant,
) -> Result<std::process::ExitStatus> {
    wait_within_limits(child, limits, started, None)
}

/// Waits for an unpacking program, stopping it at the time limit and, with
/// `watch`, as soon as the folder it writes holds more files or bytes than
/// the limits allow. Only SAM's own reader counted while it unpacked; every
/// other tool (`unsquashfs`, `bsdtar`, `dwarfsextract`, the AppImage's own
/// extractor) was checked only after it had finished, so a crafted image
/// that SAM's reader cannot read could fill the disk first (review F1).
/// The folder is measured again after a pause several times as long as
/// the last measuring took, so a large unpack is not slowed down by it.
fn wait_within_limits(
    mut child: std::process::Child,
    limits: &Limits,
    started: Instant,
    watch: Option<&Path>,
) -> Result<std::process::ExitStatus> {
    let mut next_count = Instant::now();
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(st);
        }
        let over = if started.elapsed() > Duration::from_secs(limits.max_seconds) {
            Some(limit_error(sam_core::i18n::trf(
                "unpacking limit exceeded: it took longer than {seconds} seconds",
                &[("seconds", &limits.max_seconds)],
            )))
        } else {
            match watch.filter(|_| Instant::now() >= next_count) {
                Some(dir) => {
                    let t = Instant::now();
                    let over = over_limits(dir, limits);
                    next_count = Instant::now()
                        + (t.elapsed() * 4)
                            .clamp(Duration::from_millis(200), Duration::from_secs(5));
                    over
                }
                None => None,
            }
        };
        if let Some(e) = over {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The limit `dir` is past, if any: more entries than `max_files`, or more
/// bytes in its files than `max_bytes`. Counted as `normalize` counts them
/// afterwards (which holds the exact limit); links are not followed.
fn over_limits(dir: &Path, limits: &Limits) -> Option<anyhow::Error> {
    let (mut entries, mut bytes) = (0u64, 0u64);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            entries += 1;
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else if m.is_file() {
                bytes = bytes.saturating_add(m.len());
            }
            // The box's own folders (the tool's top folder) do not count:
            // `normalize` counts only what is inside the app.
            if entries > limits.max_files.saturating_add(2) {
                return Some(limit_error(sam_core::i18n::trf(
                    "unpacking limit exceeded: more than {count} files",
                    &[("count", &limits.max_files)],
                )));
            }
            if bytes > limits.max_bytes {
                return Some(limit_error(sam_core::i18n::trf(
                    "unpacking limit exceeded: more than {size} unpacked",
                    &[("size", &sam_core::util::human_size(limits.max_bytes))],
                )));
            }
        }
    }
    None
}

/// Limits the kernel holds for an unpacking program and everything it
/// starts: no file larger than the size limit (the write fails, or the
/// program is stopped with SIGXFSZ), and no more memory than
/// [`Limits::max_memory`]. A crafted image could otherwise make a tool
/// use up the memory and freeze the session (review F5).
fn with_kernel_limits(c: &mut Command, limits: &Limits) {
    use std::os::unix::process::CommandExt;
    let (fsize, memory) = (limits.max_bytes, limits.max_memory);
    // SAFETY: runs between fork and exec and calls only setrlimit, which
    // is async-signal-safe.
    unsafe {
        c.pre_exec(move || {
            let set = |what, n: u64| {
                let lim = libc::rlimit {
                    rlim_cur: n,
                    rlim_max: n,
                };
                if libc::setrlimit(what, &lim) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            };
            set(libc::RLIMIT_FSIZE, fsize.max(1))?;
            if memory > 0 {
                set(libc::RLIMIT_AS, memory)?;
            }
            Ok(())
        });
    }
}

/// Runs one unpacking program within every limit. `watch` is the folder
/// it writes in (the unpack box).
fn run_tool(
    cmd: &mut Command,
    limits: &Limits,
    started: Instant,
    log: &mut dyn Write,
    watch: &Path,
) -> Result<()> {
    let errf = tempfile_in_tmp()?;
    with_kernel_limits(cmd, limits);
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(errf.try_clone()?))
        .spawn()
        .context(sam_core::i18n::tr("starting the unpacking tool"))?;
    let st = wait_within_limits(child, limits, started, Some(watch))?;
    let mut err = String::new();
    let mut f = errf;
    use std::io::Seek;
    f.seek(io::SeekFrom::Start(0))?;
    f.take(16 * 1024).read_to_string(&mut err).ok();
    if !err.trim().is_empty() {
        writeln!(log, "{}", err.trim_end())?;
    }
    if st.code() == Some(EXIT_LIMIT) {
        let why = err
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("an unpacking limit was exceeded")
            .trim_start_matches("error: ");
        return Err(limit_error(why.to_string()));
    }
    if died_of(&st, libc::SIGXFSZ) {
        return Err(limit_error(sam_core::i18n::trf(
            "unpacking limit exceeded: more than {size} unpacked",
            &[("size", &sam_core::util::human_size(limits.max_bytes))],
        )));
    }
    // SAM's own reader ran out of the memory it may use: a limit too, so
    // SAM stops instead of trying a tool without SAM's checks.
    if died_of(&st, libc::SIGABRT) && err.contains("memory allocation of") {
        return Err(limit_error(sam_core::i18n::trf(
            "unpacking limit exceeded: it needed more than {size} of memory",
            &[("size", &sam_core::util::human_size(limits.max_memory))],
        )));
    }
    if !st.success() {
        // A full disk, said by SAM's reader, by the tool in its own words
        // (the sandbox runs it in the C locale), or seen on the disk itself.
        let full = st.code() == Some(EXIT_DISK_FULL)
            || err.contains("No space left on device")
            || free_bytes(watch).is_some_and(|f| f < 1024 * 1024);
        if full {
            return Err(
                anyhow::Error::new(io::Error::from_raw_os_error(libc::ENOSPC))
                    .context(format!("exited with {st}")),
            );
        }
        bail!("exited with {st}");
    }
    Ok(())
}

/// Whether a program ended through `signal`, also as Bubblewrap reports it
/// for the program inside (exit code 128 + the signal's number).
fn died_of(st: &std::process::ExitStatus, signal: i32) -> bool {
    use std::os::unix::process::ExitStatusExt;
    st.signal() == Some(signal) || st.code() == Some(128 + signal)
}

/// A fresh, already deleted file for a tool's error output. Its name holds
/// a counter: two unpacks in one process within the same second (the
/// window adding several apps, tests running side by side) got the same
/// name, and the second failed with "File exists".
fn tempfile_in_tmp() -> Result<File> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "sam-extract-{}-{}-{}",
        std::process::id(),
        sam_core::util::now(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&p)?;
    fs::remove_file(&p).ok();
    Ok(f)
}

/// Run `<appimage> --appimage-extract` inside a minimal Bubblewrap sandbox:
/// no network, no home, the shared read-only system view, only the work
/// folder writable, and SAM's baseline syscall filter.
fn self_extract_sandboxed(
    iso: Option<&Isolation>,
    src: &Path,
    staging: &Path,
    limits: &Limits,
    started: Instant,
    log: &mut dyn Write,
) -> Result<()> {
    let iso = iso.context(sam_core::i18n::tr(
        "Bubblewrap is needed to let the AppImage unpack itself in a sandbox",
    ))?;
    let work = staging.with_extension("work");
    if work.exists() {
        fs::remove_dir_all(&work)?;
    }
    fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    // The AppImage's own extractor runs from the file, which must be
    // executable; browsers save downloads without that bit. Then it runs
    // from an executable copy (outside the folder it extracts to).
    let exe_copy = work.with_extension("appimage");
    let src = {
        use std::os::unix::fs::PermissionsExt;
        let executable = fs::metadata(src)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
        if executable {
            src.to_path_buf()
        } else {
            fs::copy(src, &exe_copy).context(sam_core::i18n::tr(
                "copying the AppImage so it can unpack itself",
            ))?;
            fs::set_permissions(&exe_copy, fs::Permissions::from_mode(0o755))
                .context(sam_core::i18n::tr("making the copy executable"))?;
            exe_copy.clone()
        }
    };
    let src = src.as_path();
    let mut cmd = Command::new(&iso.bwrap);
    cmd.args(["--unshare-all", "--die-with-parent", "--new-session"])
        .args(NO_NESTED_USERNS)
        .args(["--cap-drop", "ALL"])
        .args(&iso.system);
    if let Some(f) = &iso.filter {
        with_filter(&mut cmd, f)?;
    }
    cmd.args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
        .arg("--ro-bind")
        .arg(src)
        .arg("/in/app.AppImage")
        .arg("--bind")
        .arg(&work)
        .arg("/out")
        .args([
            "--chdir",
            "/out",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "HOME",
            "/out",
        ])
        .args(FEW_MALLOC_ARENAS)
        .args(["--", "/in/app.AppImage", "--appimage-extract"]);
    let ran = run_tool(&mut cmd, limits, started, log, &work);
    let _ = fs::remove_file(&exe_copy);
    ran?;
    // Classic runtimes write squashfs-root; uruntime writes AppDir and makes
    // squashfs-root a link to it. Follow the link, but only inside the work
    // folder (moving the link itself would leave it pointing nowhere).
    let out = ["squashfs-root", "AppDir"]
        .iter()
        .filter_map(|n| fs::canonicalize(work.join(n)).ok())
        .find(|p| {
            p.starts_with(fs::canonicalize(&work).unwrap_or_else(|_| work.clone())) && p.is_dir()
        });
    let Some(out) = out else {
        let _ = fs::remove_dir_all(&work);
        bail!(
            "{}",
            sam_core::i18n::tr("--appimage-extract produced no squashfs-root")
        );
    };
    fs::rename(&out, staging).with_context(|| {
        sam_core::i18n::trf(
            "moving the unpacked app to {folder}",
            &[("folder", &staging.display())],
        )
    })?;
    let _ = fs::remove_dir_all(&work);
    Ok(())
}

#[cfg(test)]
mod space_tests {
    /// The question before the AppImage unpacks itself says what the
    /// sandbox holds back, including the kernel limits (audit I-F17: it
    /// named only the network and the files), and why SAM could not.
    #[test]
    fn the_self_unpack_question_names_the_sandbox_and_the_reason() {
        let text = NeedsFallbackConsent {
            attempts: vec!["builtin-squashfs: damaged image".into()],
        }
        .to_string();
        for part in [
            "builtin-squashfs: damaged image",
            "no network",
            "no access to your files",
            "limits on kernel calls",
            "--allow-fallback",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
    }

    use super::*;

    /// Error files opened at the same moment in one process are separate
    /// files: an unpack running beside another no longer fails with "File
    /// exists" (it did on CI when two tests unpacked at once).
    #[test]
    fn two_unpacks_at_once_get_their_own_error_files() {
        let threads = 8;
        let start = std::sync::Arc::new(std::sync::Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    (0..300).filter(|_| tempfile_in_tmp().is_err()).count()
                })
            })
            .collect();
        let failed: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(failed, 0, "error files that could not be created");
    }

    /// Unpacking does not start when the folder clearly has too little room;
    /// the message names the folder, both sizes, and where to choose another
    /// folder. With enough room, or when the free space is unknown, it starts.
    #[test]
    fn unpacking_refuses_to_start_without_enough_free_space() {
        let lim = Limits::default();
        let size = 500 * 1024 * 1024;
        let err = check_space(
            Path::new("/data/unpacked"),
            size,
            &lim,
            Some(100 * 1024 * 1024),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("/data/unpacked")
                && err.contains("100.0 MiB")
                && err.contains("Preferences → Unpacking → Location"),
            "{err}"
        );
        assert!(check_space(Path::new("/x"), size, &lim, Some(10 * 1024 * 1024 * 1024)).is_ok());
        assert!(
            check_space(Path::new("/x"), size, &lim, None).is_ok(),
            "unknown free space does not block"
        );
        assert!(
            space_needed(u64::MAX / 2, &lim) <= lim.max_bytes + 64 * 1024 * 1024,
            "never more than the unpack limit"
        );
    }

    /// A full disk during unpacking is recognized, also inside an error
    /// chain, so SAM can clean up and say what happened.
    #[test]
    fn a_full_disk_during_unpacking_is_recognized() {
        let e = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::ENOSPC))
            .context("writing usr/lib/libbig.so");
        assert!(is_disk_full(&e));
        assert!(!is_disk_full(&anyhow!("some other problem")));
    }

    /// Regression (audit I-F16): putting a new unpack in place was two
    /// renames, and when the second failed the app had no unpacked files
    /// left. Now the old app stays (or comes back) when the new one cannot
    /// be moved in, both with the one-step swap and without it; and a
    /// working swap leaves the new app in place and the old one aside.
    #[test]
    fn a_failed_swap_keeps_the_old_app() {
        for exchange in [true, false] {
            let d = tempfile::tempdir().unwrap();
            let appdir = d.path().join("AppDir");
            let old = d.path().join(".old-1");
            fs::create_dir(&appdir).unwrap();
            fs::write(appdir.join("AppRun"), "old").unwrap();
            // The new unpack cannot be moved in: it is not there.
            let gone = d.path().join("gone");
            assert!(swap_into_place(&gone, &appdir, &old, exchange).is_err());
            assert_eq!(
                fs::read_to_string(appdir.join("AppRun")).ok().as_deref(),
                Some("old"),
                "exchange {exchange}: the old app is gone"
            );
            assert!(fs::symlink_metadata(&old).is_err());

            let new = d.path().join("new");
            fs::create_dir(&new).unwrap();
            fs::write(new.join("AppRun"), "new").unwrap();
            swap_into_place(&new, &appdir, &old, exchange).unwrap();
            assert_eq!(fs::read_to_string(appdir.join("AppRun")).unwrap(), "new");
            assert_eq!(fs::read_to_string(old.join("AppRun")).unwrap(), "old");
            assert!(fs::symlink_metadata(&new).is_err());
        }
    }

    /// Only an exceeded limit counts as one: other errors are not explained
    /// as a limit the user could raise.
    #[test]
    fn only_an_exceeded_limit_counts_as_one() {
        assert!(is_limit_error(
            &limit_error("more than 10 files".into()).context("unpacking")
        ));
        assert!(!is_limit_error(&anyhow!("the image is damaged")));
    }
}
