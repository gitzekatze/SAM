//! Source file fingerprints and staleness detection.

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

/// Short stable hex id for file names (first 16 hex digits of SHA-256).
pub fn short_hash(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
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

/// Copies `from` into the new file `to` (which must not exist and is never
/// opened through a link) and returns the fingerprint of what was copied:
/// the checksum of the bytes written, with the size, time and inode the
/// file had when SAM opened it. The file is read once, so what is
/// unpacked, checked and recorded afterwards from the copy are the same
/// bytes, whatever another program does to `from` meanwhile (audit I-F6);
/// a change to `from` during the copy shows later as a changed file.
pub fn copy_with_fingerprint(from: &Path, to: &Path, mode: u32) -> Result<Fingerprint> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let src = sam_core::util::open_regular(from)
        .with_context(|| format!("reading {}", from.display()))?;
    let m = src.metadata()?;
    let mut dst = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(to)
        .with_context(|| format!("creating {}", to.display()))?;
    let copied = (|| -> Result<String> {
        let mut r = BufReader::with_capacity(1 << 20, src);
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            dst.write_all(&buf[..n])?;
        }
        dst.flush()?;
        Ok(hex(&h.finalize()))
    })();
    let sha256 = match copied {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_file(to);
            return Err(e.context(format!("copying {}", from.display())));
        }
    };
    Ok(Fingerprint {
        size: m.len(),
        mtime: m.mtime(),
        inode: m.ino(),
        device: m.dev(),
        sha256,
    })
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
    Changed {
        new: Fingerprint,
        reasons: Vec<String>,
    },
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
        reasons.push(sam_core::i18n::tr("modification time changed"));
    }
    if q.inode != known.inode || q.device != known.device {
        reasons.push(sam_core::i18n::tr("file was replaced (inode changed)"));
    }
    if reasons.is_empty() && !deep {
        return Ok(SourceStatus::Unchanged);
    }
    let full = Fingerprint {
        sha256: sha256_file(path)?,
        ..q
    };
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

    /// A changed AppImage file is noticed by its fingerprint.
    #[test]
    fn a_changed_appimage_file_is_noticed() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.AppImage");
        fs::write(&p, b"one").unwrap();
        let fp = compute(&p).unwrap();
        assert_eq!(check(&p, &fp, false).unwrap(), SourceStatus::Unchanged);
        assert_eq!(check(&p, &fp, true).unwrap(), SourceStatus::Unchanged);
        fs::write(&p, b"two!").unwrap();
        assert!(matches!(
            check(&p, &fp, false).unwrap(),
            SourceStatus::Changed { .. }
        ));
        fs::remove_file(&p).unwrap();
        assert_eq!(check(&p, &fp, false).unwrap(), SourceStatus::Missing);
    }
}
