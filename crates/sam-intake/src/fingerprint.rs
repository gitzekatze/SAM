//! Source file fingerprints and staleness detection (§2.11.7).

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result};
use sam_core::util::hex;
use sam_core::Fingerprint;
use sha2::{Digest, Sha256};

pub fn quick(path: &Path) -> Result<Fingerprint> {
    let m = fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Fingerprint {
        size: m.len(),
        mtime: m.mtime(),
        inode: m.ino(),
        device: m.dev(),
        sha256: String::new(),
    })
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut r = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

pub fn compute(path: &Path) -> Result<Fingerprint> {
    let mut fp = quick(path)?;
    fp.sha256 = sha256_file(path)?;
    Ok(fp)
}

#[derive(Debug, Clone, PartialEq)]
pub enum SourceStatus {
    Unchanged,
    /// Metadata changed but the content is identical (e.g. copied, touched).
    Touched(Fingerprint),
    /// Content changed (AppImage updated).
    Changed { new: Fingerprint, reasons: Vec<String> },
    Missing,
}

/// Compare the file on disk with a known fingerprint. With `deep`, the
/// checksum is always recomputed.
pub fn check(path: &Path, known: &Fingerprint, deep: bool) -> Result<SourceStatus> {
    if !path.exists() {
        return Ok(SourceStatus::Missing);
    }
    let q = quick(path)?;
    let mut reasons = Vec::new();
    if q.size != known.size {
        reasons.push(format!("size changed ({} -> {})", known.size, q.size));
    }
    if q.mtime != known.mtime {
        reasons.push("modification time changed".to_string());
    }
    if q.inode != known.inode || q.device != known.device {
        reasons.push("file was replaced (inode changed)".to_string());
    }
    if reasons.is_empty() && !deep {
        return Ok(SourceStatus::Unchanged);
    }
    let full = Fingerprint { sha256: sha256_file(path)?, ..q };
    if full.sha256 == known.sha256 {
        if reasons.is_empty() {
            Ok(SourceStatus::Unchanged)
        } else {
            Ok(SourceStatus::Touched(full))
        }
    } else {
        reasons.push("SHA-256 checksum changed".into());
        Ok(SourceStatus::Changed { new: full, reasons })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_changes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.AppImage");
        fs::write(&p, b"one").unwrap();
        let fp = compute(&p).unwrap();
        assert_eq!(check(&p, &fp, false).unwrap(), SourceStatus::Unchanged);
        assert_eq!(check(&p, &fp, true).unwrap(), SourceStatus::Unchanged);
        fs::write(&p, b"two!").unwrap();
        assert!(matches!(check(&p, &fp, false).unwrap(), SourceStatus::Changed { .. }));
        fs::remove_file(&p).unwrap();
        assert_eq!(check(&p, &fp, false).unwrap(), SourceStatus::Missing);
    }
}
