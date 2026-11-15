//! Payload normalization.
//!
//! * directories become 0755, files 0755 (if any exec bit) or 0644
//! * setuid/setgid/sticky and world-writable bits are dropped
//! * relative symlinks that resolve outside the AppDir are removed
//! * device nodes, FIFOs and sockets are removed
//! * file count / total size limits are enforced

use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_files: u64,
    pub max_bytes: u64,
    pub max_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_files: 200_000, max_bytes: 8 * 1024 * 1024 * 1024, max_seconds: 600 }
    }
}

#[derive(Debug, Default, Clone)]
pub struct NormalizeReport {
    pub file_count: u64,
    pub total_size: u64,
    pub setid_removed: Vec<String>,
    pub removed_symlinks: Vec<String>,
    pub removed_special: Vec<String>,
    pub absolute_symlinks: u64,
    pub suspicious: Vec<String>,
}

impl NormalizeReport {
    pub fn all_suspicious(&self) -> Vec<String> {
        let mut v = Vec::new();
        v.extend(self.setid_removed.iter().map(|p| sam_core::i18n::trf("setuid/setgid bit removed: {path}", &[("path", &p)])));
        v.extend(self.removed_symlinks.iter().map(|p| sam_core::i18n::trf("link pointing outside the app removed: {path}", &[("path", &p)])));
        v.extend(self.removed_special.iter().map(|p| sam_core::i18n::trf("special file removed: {path}", &[("path", &p)])));
        v.extend(self.suspicious.iter().cloned());
        v
    }
}

pub fn normalize(root: &Path, limits: &Limits, started: Instant) -> Result<NormalizeReport> {
    let mut r = NormalizeReport::default();
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).with_context(|| format!("permissions of {}", root.display()))?;
    walk(root, Path::new(""), limits, started, &mut r)?;
    Ok(r)
}

fn walk(root: &Path, rel: &Path, limits: &Limits, started: Instant, r: &mut NormalizeReport) -> Result<()> {
    let dir = root.join(rel);
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let rel_path = rel.join(&name);
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).with_context(|| format!("inspecting {}", path.display()))?;
        let ft = meta.file_type();

        r.file_count += 1;
        if r.file_count > limits.max_files {
            return Err(crate::extract::limit_error(sam_core::i18n::trf("unpacking limit exceeded: more than {count} files", &[("count", &limits.max_files)])));
        }
        if started.elapsed().as_secs() > limits.max_seconds {
            return Err(crate::extract::limit_error(sam_core::i18n::trf(
                "unpacking limit exceeded: it took longer than {seconds} seconds",
                &[("seconds", &limits.max_seconds)],
            )));
        }

        let display = rel_path.display().to_string();
        if ft.is_symlink() {
            let target = fs::read_link(&path)?;
            if target.is_absolute() {
                // Only meaningful inside the sandbox; SAM never follows it host-side.
                r.absolute_symlinks += 1;
            } else if escapes(rel, &target) {
                fs::remove_file(&path)?;
                r.removed_symlinks.push(format!("{display} -> {}", target.display()));
            }
        } else if ft.is_dir() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).with_context(|| format!("permissions of {}", path.display()))?;
            walk(root, &rel_path, limits, started, r)?;
        } else if ft.is_file() {
            let mode = meta.permissions().mode();
            if mode & 0o6000 != 0 {
                r.setid_removed.push(display.clone());
            }
            let new_mode = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
            if mode & 0o7777 != new_mode {
                fs::set_permissions(&path, fs::Permissions::from_mode(new_mode)).with_context(|| format!("permissions of {}", path.display()))?;
            }
            r.total_size += meta.len();
            if r.total_size > limits.max_bytes {
                return Err(crate::extract::limit_error(sam_core::i18n::trf(
                    "unpacking limit exceeded: more than {size} unpacked",
                    &[("size", &sam_core::util::human_size(limits.max_bytes))],
                )));
            }
            let lname = name.to_string_lossy().to_lowercase();
            if lname.ends_with(".ko") || lname.ends_with(".ko.xz") || lname.ends_with(".ko.zst") {
                r.suspicious.push(format!("kernel module: {display}"));
            }
        } else {
            let kind = if ft.is_fifo() {
                "fifo"
            } else if ft.is_socket() {
                "socket"
            } else if ft.is_char_device() {
                "character device"
            } else if ft.is_block_device() {
                "block device"
            } else {
                "unknown"
            };
            fs::remove_file(&path)?;
            r.removed_special.push(format!("{display} ({kind})"));
        }
    }
    Ok(())
}

/// Does a relative symlink located in directory `link_dir` (relative to the
/// AppDir root) point outside the root?
pub fn escapes(link_dir: &Path, target: &Path) -> bool {
    let mut depth: i64 = link_dir.components().filter(|c| matches!(c, Component::Normal(_))).count() as i64;
    for c in target.components() {
        match c {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

/// Resolve `rel` inside `root`, refusing anything that ends up outside it
/// (absolute symlinks to host paths, `..` tricks). Used for every host-side
/// read of payload files (icons, desktop entries).
pub fn safe_resolve(root: &Path, rel: &Path) -> Option<PathBuf> {
    let root = fs::canonicalize(root).ok()?;
    let p = fs::canonicalize(root.join(rel)).ok()?;
    p.starts_with(&root).then_some(p)
}

/// Turn an archive path into a safe relative path, or `None` if it is the
/// root or tries to traverse upwards.
pub fn sanitize_archive_path(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(n) => out.push(n),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Unpacking stops with a clear error when it takes longer than the time
    /// limit, so a huge or hostile AppImage cannot keep SAM busy forever.
    #[test]
    fn unpacking_stops_at_the_time_limit() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("f"), b"").unwrap();
        let lim = Limits { max_seconds: 0, ..Default::default() };
        let started = Instant::now() - std::time::Duration::from_secs(2);
        let err = normalize(d.path(), &lim, started).unwrap_err().to_string();
        assert!(err.contains("took longer than 0 seconds"), "{err}");
    }

    /// A symlink that points outside the unpacked app is recognized.
    #[test]
    fn symlinks_pointing_outside_the_app_are_recognized() {
        assert!(!escapes(Path::new("usr/lib"), Path::new("libfoo.so.1")));
        assert!(!escapes(Path::new("usr/lib"), Path::new("../../AppRun")));
        assert!(escapes(Path::new("usr/lib"), Path::new("../../../etc/passwd")));
        assert!(escapes(Path::new(""), Path::new("../x")));
        assert!(!escapes(Path::new("a"), Path::new("./b/../c")));
    }

    /// Paths from the AppImage image are made relative, and paths that climb out with .. are refused.
    #[test]
    fn paths_climbing_out_of_the_image_are_refused() {
        assert_eq!(sanitize_archive_path(Path::new("/usr/bin/x")), Some(PathBuf::from("usr/bin/x")));
        assert_eq!(sanitize_archive_path(Path::new("/")), None);
        assert_eq!(sanitize_archive_path(Path::new("a/../../b")), None);
    }

    /// Unpacking removes setuid bits and makes files read-only for others.
    #[test]
    fn unpacking_removes_setuid_bits() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        fs::write(root.join("AppRun"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(root.join("AppRun"), fs::Permissions::from_mode(0o4777)).unwrap();
        fs::write(root.join("data.txt"), b"x").unwrap();
        fs::set_permissions(root.join("data.txt"), fs::Permissions::from_mode(0o666)).unwrap();
        symlink("../../../../etc/shadow", root.join("usr/lib/evil")).unwrap();
        symlink("../../AppRun", root.join("usr/lib/ok")).unwrap();
        symlink("/usr/share/icons/x.png", root.join(".DirIcon")).unwrap();
        // Special files: a FIFO and a socket (device nodes need root).
        assert!(std::process::Command::new("mkfifo").arg(root.join("usr/lib/pipe")).status().unwrap().success());
        let _sock = std::os::unix::net::UnixListener::bind(root.join("usr/lib/sock")).unwrap();
        let r = normalize(root, &Limits::default(), Instant::now()).unwrap();
        assert!(fs::symlink_metadata(root.join("usr/lib/pipe")).is_err(), "FIFO removed");
        assert!(fs::symlink_metadata(root.join("usr/lib/sock")).is_err(), "socket removed");
        assert_eq!(fs::metadata(root.join("AppRun")).unwrap().permissions().mode() & 0o7777, 0o755);
        assert_eq!(fs::metadata(root.join("data.txt")).unwrap().permissions().mode() & 0o7777, 0o644);
        assert_eq!(r.setid_removed, vec!["AppRun"]);
        assert!(!root.join("usr/lib/evil").exists() && fs::symlink_metadata(root.join("usr/lib/evil")).is_err());
        assert!(fs::symlink_metadata(root.join("usr/lib/ok")).is_ok());
        assert_eq!(r.absolute_symlinks, 1);
        // Host-side reads refuse the absolute link.
        assert!(safe_resolve(root, Path::new(".DirIcon")).is_none());
        assert!(safe_resolve(root, Path::new("usr/lib/ok")).is_some());
    }

    /// Unpacking stops when the AppImage contains more files than the limit.
    #[test]
    fn unpacking_stops_at_the_file_limit() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..5 {
            fs::write(d.path().join(format!("f{i}")), b"").unwrap();
        }
        let lim = Limits { max_files: 3, ..Default::default() };
        assert!(normalize(d.path(), &lim, Instant::now()).is_err());
    }
}
