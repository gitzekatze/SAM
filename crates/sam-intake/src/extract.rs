//! Payload extraction (§2.11.2).
//!
//! Preferred order:
//! 1. Static extraction without executing the AppImage:
//!    * Type 2: built-in SquashFS reader (gzip/xz/zstd), then `unsquashfs`
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
            "static extraction failed ({}). The AppImage's own extractor can be tried, but that runs code from the AppImage (inside a restricted sandbox). Re-run with consent to allow it.",
            self.attempts.join("; ")
        )
    }
}
impl std::error::Error for NeedsFallbackConsent {}

pub fn extract(req: &ExtractRequest, log: &mut dyn Write) -> Result<ExtractOutcome> {
    fs::create_dir_all(req.root)?;
    let staging = req.root.join(format!(".staging-{}", std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    let started = Instant::now();
    let mut attempts = Vec::new();

    type Method<'m> = (&'static str, Box<dyn Fn(&Path, &mut dyn Write) -> Result<()> + 'm>);
    let mut methods: Vec<Method> = Vec::new();
    match req.info.kind {
        AppImageType::Type2 => {
            let off = req.info.payload_offset.context("no payload offset")?;
            methods.push(("builtin-squashfs", Box::new(move |dst: &Path, log: &mut dyn Write| {
                builtin_squashfs(req.source, off, dst, &req.limits, started, log)
            })));
            if let Some(u) = which("unsquashfs") {
                methods.push(("unsquashfs", Box::new(move |dst: &Path, log: &mut dyn Write| {
                    run_tool(
                        Command::new(&u)
                            .arg("-o").arg(off.to_string())
                            .arg("-d").arg(dst)
                            .args(["-f", "-no-xattrs", "-no-progress", "-quiet"])
                            .arg(req.source),
                        &req.limits, started, log,
                    )
                })));
            }
        }
        AppImageType::Type1 => {
            if let Some(b) = which("bsdtar") {
                methods.push(("bsdtar", Box::new(move |dst: &Path, log: &mut dyn Write| {
                    fs::create_dir_all(dst)?;
                    run_tool(
                        Command::new(&b).arg("-xf").arg(req.source).arg("-C").arg(dst).args(["--no-same-owner", "--no-xattrs", "--no-acls"]),
                        &req.limits, started, log,
                    )
                })));
            } else {
                attempts.push("bsdtar (libarchive) is not installed".into());
            }
        }
        AppImageType::Unknown => bail!("{} is not a recognized AppImage", req.source.display()),
    }

    let mut method_used = None;
    for (name, f) in &methods {
        writeln!(log, "[extract] trying {name}")?;
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        match f(&staging, log) {
            Ok(()) => {
                method_used = Some(name.to_string());
                break;
            }
            Err(e) => {
                writeln!(log, "[extract] {name} failed: {e:#}")?;
                if is_limit_error(&e) {
                    let _ = fs::remove_dir_all(&staging);
                    return Err(e);
                }
                attempts.push(format!("{name}: {e:#}"));
            }
        }
    }

    if method_used.is_none() {
        if !req.allow_fallback {
            let _ = fs::remove_dir_all(&staging);
            return Err(anyhow!(NeedsFallbackConsent { attempts }));
        }
        writeln!(log, "[extract] trying sandboxed --appimage-extract (user consented)")?;
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        match self_extract_sandboxed(req.source, &staging, &req.limits, started, log) {
            Ok(()) => method_used = Some("appimage-extract (sandboxed)".into()),
            Err(e) => {
                let _ = fs::remove_dir_all(&staging);
                attempts.push(format!("appimage-extract: {e:#}"));
                bail!("all extraction methods failed:\n  {}", attempts.join("\n  "));
            }
        }
    }

    let report = match normalize(&staging, &req.limits, started) {
        Ok(r) => r,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    writeln!(
        log,
        "[extract] normalized {} entries, {} bytes; {} setid bits removed, {} escaping symlinks removed, {} special files removed",
        report.file_count, report.total_size, report.setid_removed.len(), report.removed_symlinks.len(), report.removed_special.len()
    )?;

    // Atomically swap the new payload into place.
    let appdir = req.root.join("AppDir");
    let old = req.root.join(format!(".old-{}", std::process::id()));
    if appdir.exists() {
        fs::rename(&appdir, &old)?;
    }
    fs::rename(&staging, &appdir)?;
    if old.exists() {
        let _ = fs::remove_dir_all(&old);
    }
    Ok(ExtractOutcome {
        appdir,
        method: method_used.unwrap_or_default(),
        report,
        attempts,
    })
}

fn is_limit_error(e: &anyhow::Error) -> bool {
    e.to_string().contains("extraction limit exceeded")
}

/// Make sure every existing ancestor of `rel` inside `root` is a real
/// directory (not a symlink), creating missing ones.
fn safe_mkdirs(root: &Path, rel: &Path) -> Result<PathBuf> {
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => bail!("path traversal via symlink at {}", cur.display()),
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("{} is not a directory", cur.display()),
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
            return Err(io::Error::other("extraction limit exceeded: payload too large"));
        }
        Ok(n)
    }
}

fn builtin_squashfs(src: &Path, offset: u64, dst: &Path, limits: &Limits, started: Instant, log: &mut dyn Write) -> Result<()> {
    use backhand::{FilesystemReader, InnerNode};
    let reader = BufReader::new(File::open(src)?);
    let sqfs = FilesystemReader::from_reader_with_offset(reader, offset).map_err(|e| anyhow!("{e}"))?;
    fs::create_dir_all(dst)?;
    let mut count = 0u64;
    let mut total = 0u64;
    let mut skipped = 0u64;
    for node in sqfs.files() {
        count += 1;
        if count > limits.max_files {
            bail!("extraction limit exceeded: more than {} files", limits.max_files);
        }
        if started.elapsed() > Duration::from_secs(limits.max_seconds) {
            bail!("extraction limit exceeded: took longer than {} seconds", limits.max_seconds);
        }
        let Some(rel) = sanitize_archive_path(&node.fullpath) else {
            if node.fullpath.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                writeln!(log, "[extract] refusing path traversal entry {}", node.fullpath.display())?;
                skipped += 1;
            }
            continue;
        };
        let parent_rel = rel.parent().unwrap_or(Path::new(""));
        let parent = safe_mkdirs(dst, parent_rel)?;
        let target = parent.join(rel.file_name().context("entry without name")?);
        match &node.inner {
            InnerNode::Dir(_) => {
                safe_mkdirs(dst, &rel)?;
            }
            InnerNode::File(f) => {
                if fs::symlink_metadata(&target).is_ok() {
                    bail!("duplicate entry {}", rel.display());
                }
                let mut out = File::create(&target)?;
                let mut r = LimitedReader { inner: sqfs.file(f).reader(), total: &mut total, max: limits.max_bytes };
                io::copy(&mut r, &mut out).map_err(|e| anyhow!("{}: {e}", rel.display()))?;
                let mode = if node.header.permissions & 0o111 != 0 { 0o755 } else { 0o644 };
                fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
            }
            InnerNode::Symlink(s) => {
                symlink(&s.link, &target)?;
            }
            InnerNode::CharacterDevice(_) | InnerNode::BlockDevice(_) | InnerNode::NamedPipe | InnerNode::Socket => {
                writeln!(log, "[extract] skipping special file {}", rel.display())?;
                skipped += 1;
            }
        }
    }
    writeln!(log, "[extract] builtin reader: {count} entries, {total} bytes, {skipped} skipped")?;
    Ok(())
}

fn wait_with_timeout(mut child: std::process::Child, limits: &Limits, started: Instant) -> Result<std::process::ExitStatus> {
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(st);
        }
        if started.elapsed() > Duration::from_secs(limits.max_seconds) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("extraction limit exceeded: took longer than {} seconds", limits.max_seconds);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run_tool(cmd: &mut Command, limits: &Limits, started: Instant, log: &mut dyn Write) -> Result<()> {
    let errf = tempfile_in_tmp()?;
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(errf.try_clone()?))
        .spawn()
        .context("spawning extraction tool")?;
    let st = wait_with_timeout(child, limits, started)?;
    let mut err = String::new();
    let mut f = errf;
    use std::io::Seek;
    f.seek(io::SeekFrom::Start(0))?;
    f.take(16 * 1024).read_to_string(&mut err).ok();
    if !err.trim().is_empty() {
        writeln!(log, "{}", err.trim_end())?;
    }
    if !st.success() {
        bail!("exited with {st}");
    }
    Ok(())
}

fn tempfile_in_tmp() -> Result<File> {
    let p = std::env::temp_dir().join(format!("sam-extract-{}-{}", std::process::id(), sam_core::util::now()));
    let f = fs::OpenOptions::new().read(true).write(true).create_new(true).open(&p)?;
    fs::remove_file(&p).ok();
    Ok(f)
}

/// Run `<appimage> --appimage-extract` inside a minimal bubblewrap sandbox:
/// no network, no home, read-only system, only the staging dir writable.
fn self_extract_sandboxed(src: &Path, staging: &Path, limits: &Limits, started: Instant, log: &mut dyn Write) -> Result<()> {
    let bwrap = which("bwrap").context("bubblewrap is required for sandboxed fallback extraction")?;
    let work = staging.with_extension("work");
    if work.exists() {
        fs::remove_dir_all(&work)?;
    }
    fs::create_dir_all(&work)?;
    let mut cmd = Command::new(bwrap);
    cmd.args(["--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL"])
        .args(["--ro-bind", "/usr", "/usr"])
        .args(["--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin"])
        .args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
        .args(["--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache"])
        .arg("--ro-bind").arg(src).arg("/in/app.AppImage")
        .arg("--bind").arg(&work).arg("/out")
        .args(["--chdir", "/out", "--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "HOME", "/out"])
        .args(["--", "/in/app.AppImage", "--appimage-extract"]);
    run_tool(&mut cmd, limits, started, log)?;
    let out = work.join("squashfs-root");
    if !out.is_dir() {
        let _ = fs::remove_dir_all(&work);
        bail!("--appimage-extract produced no squashfs-root");
    }
    fs::rename(&out, staging)?;
    let _ = fs::remove_dir_all(&work);
    Ok(())
}
