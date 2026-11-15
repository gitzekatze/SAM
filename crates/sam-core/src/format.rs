//! Versions of SAM's files (configuration, app records, presets), and what
//! happens with old, newer and damaged ones.
//!
//! - Every file carries `format`. A missing one means 0 (before versioning).
//! - Older formats are migrated step by step when read; the original is
//!   kept once as `<file>.format<N>.bak`.
//! - A file from a newer SAM is never changed: reading it is an error that
//!   says to update SAM (an older SAM would otherwise drop what it does not
//!   know when saving).
//! - A damaged file (not readable as its format) is moved aside as
//!   `<file>.damaged-<time>`, so nothing is lost, and SAM carries on.
//!   `damaged_files` lists them for `sam-jail doctor`.

use std::fs;
use std::path::{Path, PathBuf};

/// The format this SAM writes.
pub const CURRENT: u32 = 1;

/// The `format` of a file read as a JSON or TOML value (0 when missing).
pub fn of_json(v: &serde_json::Value) -> u32 {
    v.get("format")
        .and_then(serde_json::Value::as_u64)
        .map(|n| n.min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

/// Error for a file written by a newer SAM.
#[derive(Debug)]
pub struct NewerFormat {
    pub path: PathBuf,
    pub found: u32,
}

impl std::fmt::Display for NewerFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::i18n::trf(
            "{file} was written by a newer SAM (format {found}, this SAM knows up to {known}); update SAM. The file was left unchanged.",
            &[("file", &self.path.display()), ("found", &self.found), ("known", &CURRENT)],
        ))
    }
}

impl std::error::Error for NewerFormat {}

/// Refuses files from a newer SAM.
pub fn check_not_newer(path: &Path, found: u32) -> anyhow::Result<()> {
    if found > CURRENT {
        return Err(NewerFormat {
            path: path.to_path_buf(),
            found,
        }
        .into());
    }
    Ok(())
}

/// Keeps the original of a file before its first migration.
pub fn backup_before_migration(path: &Path, found: u32) {
    if found >= CURRENT {
        return;
    }
    let bak = with_suffix(path, &format!(".format{found}.bak"));
    if !bak.exists() {
        let _ = fs::copy(path, &bak);
    }
}

/// Moves a damaged file aside; returns where it went.
pub fn quarantine(path: &Path) -> Option<PathBuf> {
    let to = with_suffix(path, &format!(".damaged-{}", crate::util::now()));
    fs::rename(path, &to).ok().map(|_| to)
}

/// Damaged files moved aside in these folders (non-recursive).
pub fn damaged_files(dirs: &[&Path]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for d in dirs {
        if let Ok(rd) = fs::read_dir(d) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().contains(".damaged-") {
                    out.push(e.path());
                }
            }
        }
    }
    out.sort();
    out
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SAM refuses to overwrite a file written by a newer SAM and reads files without a format number as format 0.
    #[test]
    fn files_from_a_newer_sam_are_never_overwritten() {
        assert_eq!(of_json(&serde_json::json!({})), 0);
        assert_eq!(of_json(&serde_json::json!({"format": 1})), 1);
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("x.json");
        fs::write(&f, "{}").unwrap();
        assert!(check_not_newer(&f, CURRENT).is_ok());
        let e = check_not_newer(&f, CURRENT + 1).unwrap_err();
        assert!(e.downcast_ref::<NewerFormat>().is_some() && e.to_string().contains("newer SAM"));
        backup_before_migration(&f, 0);
        assert!(d.path().join("x.json.format0.bak").exists());
        let moved = quarantine(&f).unwrap();
        assert!(!f.exists() && moved.exists());
        assert_eq!(damaged_files(&[d.path()]), vec![moved]);
    }
}
