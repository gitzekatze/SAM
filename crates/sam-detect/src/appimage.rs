//! AppImage magic, type and payload detection, without executing anything.
//!
//! * Type 1: ISO 9660 image that is also an ELF (`AI\x01` at offset 8).
//! * Type 2: ELF runtime followed by a SquashFS payload (`AI\x02` at offset 8).
//!   The payload starts where the ELF ends: `e_shoff + e_shentsize * e_shnum`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sam_core::AppImageType;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadFormat {
    Squashfs,
    /// DwarFS image (newer runtimes such as uruntime).
    Dwarfs,
    Iso9660,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppImageInfo {
    pub path: PathBuf,
    pub size: u64,
    pub is_elf: bool,
    /// `AI\x01` / `AI\x02` magic present at offset 8.
    pub magic: bool,
    pub kind: AppImageType,
    pub payload: PayloadFormat,
    pub payload_offset: Option<u64>,
    /// The SquashFS image's own size (`bytes_used` in its superblock).
    pub payload_size: Option<u64>,
    pub compression: Option<String>,
    pub arch: Option<String>,
    pub notes: Vec<String>,
}

impl AppImageInfo {
    /// `(bytes the file has, bytes its image needs)` when the file is
    /// shorter than its SquashFS image says: a download that broke off.
    pub fn incomplete(&self) -> Option<(u64, u64)> {
        let need = self.payload_offset?.checked_add(self.payload_size?)?;
        (self.size < need).then_some((self.size, need))
    }

    pub fn is_appimage(&self) -> bool {
        self.kind != AppImageType::Unknown
    }
}

const SQUASHFS_MAGIC: &[u8; 4] = b"hsqs";
/// Start of a DwarFS image (followed by its major and minor version).
const DWARFS_MAGIC: &[u8; 6] = b"DWARFS";

/// Cheap check used by directory scans: extension or magic.
pub fn looks_like_appimage(path: &Path) -> bool {
    let ext_match = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("appimage"));
    if ext_match {
        return true;
    }
    let mut buf = [0u8; 11];
    match File::open(path).and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => {
            &buf[0..4] == b"\x7fELF" && &buf[8..10] == b"AI" && (buf[10] == 1 || buf[10] == 2)
        }
        Err(_) => false,
    }
}

pub fn inspect(path: &Path) -> Result<AppImageInfo> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let size = f.metadata()?.len();
    let mut head = vec![0u8; 64.min(size as usize)];
    f.read_exact(&mut head)?;

    let mut info = AppImageInfo {
        path: path.to_path_buf(),
        size,
        is_elf: head.len() >= 52 && &head[0..4] == b"\x7fELF",
        magic: false,
        kind: AppImageType::Unknown,
        payload: PayloadFormat::Unknown,
        payload_offset: None,
        payload_size: None,
        compression: None,
        arch: None,
        notes: vec![],
    };
    if !info.is_elf {
        info.notes.push("not an ELF file".into());
        return Ok(info);
    }
    let elf_type_byte = head.get(10).copied().unwrap_or(0);
    info.magic = &head[8..10] == b"AI" && (elf_type_byte == 1 || elf_type_byte == 2);
    info.arch = elf_machine(&head).map(str::to_string);

    // Type 1: ISO 9660 primary volume descriptor at sector 16.
    if (info.magic && elf_type_byte == 1) || has_iso_signature(&mut f)? {
        if has_iso_signature(&mut f)? {
            info.kind = AppImageType::Type1;
            info.payload = PayloadFormat::Iso9660;
            info.payload_offset = Some(0);
            return Ok(info);
        }
        info.notes.push(sam_core::i18n::tr(
            "type 1 magic present but no ISO 9660 signature found",
        ));
    }

    // Type 2: SquashFS appended after the ELF.
    if let Some(off) = elf_end_offset(&head) {
        if off + 96 <= size && read_at(&mut f, off, 4)? == SQUASHFS_MAGIC {
            info.payload_offset = Some(off);
        }
    }
    // Type 2 with a DwarFS image (uruntime): appended after the ELF too.
    if info.payload_offset.is_none() {
        if let Some(off) = elf_end_offset(&head) {
            if off + 8 <= size && read_at(&mut f, off, 6)? == DWARFS_MAGIC {
                info.payload = PayloadFormat::Dwarfs;
                info.payload_offset = Some(off);
                info.compression = Some("dwarfs".into());
                info.kind = AppImageType::Type2;
                return Ok(info);
            }
        }
    }
    if info.payload_offset.is_none() {
        // Fall back to scanning the first 16 MiB for a plausible superblock.
        if let Some(off) = scan_for_squashfs(&mut f, size)? {
            info.notes.push(sam_core::i18n::trf(
                "SquashFS found by scanning at offset {off}",
                &[("off", &off)],
            ));
            info.payload_offset = Some(off);
        }
    }
    if let Some(off) = info.payload_offset {
        info.payload = PayloadFormat::Squashfs;
        info.compression = Some(squashfs_compression(&mut f, off)?);
        info.payload_size = squashfs_bytes_used(&mut f, off);
        info.kind = AppImageType::Type2;
        if !info.magic {
            info.notes.push(sam_core::i18n::tr("The AppImage marker is missing; it is treated as Type 2 because it contains a SquashFS image"));
        }
    } else if info.magic {
        info.notes.push(sam_core::i18n::tr(
            "The AppImage marker is present, but the file contains no app image",
        ));
    }
    Ok(info)
}

fn read_at(f: &mut File, off: u64, len: usize) -> Result<Vec<u8>> {
    f.seek(SeekFrom::Start(off))?;
    let mut b = vec![0u8; len];
    f.read_exact(&mut b)?;
    Ok(b)
}

fn has_iso_signature(f: &mut File) -> Result<bool> {
    match read_at(f, 0x8001, 5) {
        Ok(b) => Ok(&b == b"CD001"),
        Err(_) => Ok(false),
    }
}

fn le_or_be(head: &[u8]) -> bool {
    head[5] != 2
}

fn u16_at(head: &[u8], off: usize, le: bool) -> Option<u64> {
    let b: [u8; 2] = head.get(off..off + 2)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    } as u64)
}
fn u32_at(head: &[u8], off: usize, le: bool) -> Option<u64> {
    let b: [u8; 4] = head.get(off..off + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    } as u64)
}
fn u64_at(head: &[u8], off: usize, le: bool) -> Option<u64> {
    let b: [u8; 8] = head.get(off..off + 8)?.try_into().ok()?;
    Some(if le {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    })
}

/// End of the ELF image = end of the section header table.
pub fn elf_end_offset(head: &[u8]) -> Option<u64> {
    let le = le_or_be(head);
    match head.get(4)? {
        2 => {
            let shoff = u64_at(head, 0x28, le)?;
            let shentsize = u16_at(head, 0x3A, le)?;
            let shnum = u16_at(head, 0x3C, le)?;
            Some(shoff + shentsize * shnum)
        }
        1 => {
            let shoff = u32_at(head, 0x20, le)?;
            let shentsize = u16_at(head, 0x2E, le)?;
            let shnum = u16_at(head, 0x30, le)?;
            Some(shoff + shentsize * shnum)
        }
        _ => None,
    }
}

/// This computer's processor, in the names `elf_machine` uses.
pub fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86" => "i686",
        "arm" => "armhf",
        other => other,
    }
}

/// Whether a program built for `app` runs on a `host` processor: the same
/// one, or 32-bit x86 on 64-bit x86 (the kernel runs both).
pub fn runs_on(app: &str, host: &str) -> bool {
    app == host || (app == "i686" && host == "x86_64") || (app == "armhf" && host == "aarch64")
}

/// Why this AppImage cannot run on this computer, if its processor is a
/// different one; None when it fits or the processor is unknown.
pub fn wrong_processor(info: &AppImageInfo) -> Option<String> {
    let app = info.arch.as_deref()?;
    let host = host_arch();
    if runs_on(app, host) {
        return None;
    }
    let name = |a: &str| {
        match a {
            "x86_64" => "x86-64 (Intel and AMD)",
            "i686" => "32-bit x86",
            "aarch64" => "ARM (aarch64)",
            "armhf" => "32-bit ARM",
            "riscv64" => "RISC-V",
            other => other,
        }
        .to_string()
    };
    // No article ("a"/"an"): the sentence must work in every language.
    Some(sam_core::i18n::trf(
        "it is built for {app} processors, but this computer's processor is {host}, so it cannot run here. Download the {version} version of the app instead",
        &[("app", &name(app)), ("host", &name(host)), ("version", &host)],
    ))
}

fn elf_machine(head: &[u8]) -> Option<&'static str> {
    Some(match u16_at(head, 18, le_or_be(head))? {
        0x3E => "x86_64",
        0xB7 => "aarch64",
        0x03 => "i686",
        0x28 => "armhf",
        0xF3 => "riscv64",
        _ => return None,
    })
}

fn plausible_superblock(sb: &[u8]) -> bool {
    if sb.len() < 30 || &sb[0..4] != SQUASHFS_MAGIC {
        return false;
    }
    let compression = u16::from_le_bytes([sb[20], sb[21]]);
    let block_log = u16::from_le_bytes([sb[22], sb[23]]);
    let major = u16::from_le_bytes([sb[28], sb[29]]);
    (1..=6).contains(&compression) && (12..=20).contains(&block_log) && major == 4
}

fn scan_for_squashfs(f: &mut File, size: u64) -> Result<Option<u64>> {
    let limit = size.min(16 * 1024 * 1024);
    f.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; limit as usize];
    f.read_exact(&mut buf)?;
    let mut i = 0;
    while i + 96 <= buf.len() {
        if &buf[i..i + 4] == SQUASHFS_MAGIC && plausible_superblock(&buf[i..i + 32]) {
            return Ok(Some(i as u64));
        }
        i += 1;
    }
    Ok(None)
}

/// `bytes_used` from the superblock: how long the image is. `None` when the
/// file ends before the superblock does.
fn squashfs_bytes_used(f: &mut File, off: u64) -> Option<u64> {
    let sb = read_at(f, off, 48).ok()?;
    Some(u64::from_le_bytes(sb.get(40..48)?.try_into().ok()?))
}

fn squashfs_compression(f: &mut File, off: u64) -> Result<String> {
    let sb = read_at(f, off, 32)?;
    Ok(match u16::from_le_bytes([sb[20], sb[21]]) {
        1 => "gzip",
        2 => "lzma",
        3 => "lzo",
        4 => "xz",
        5 => "lz4",
        6 => "zstd",
        _ => "unknown",
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// An ordinary program file is not taken for an AppImage.
    #[test]
    fn plain_elf_is_not_appimage() {
        let info = inspect(Path::new("/bin/sh")).unwrap();
        assert!(info.is_elf);
        assert!(!info.is_appimage());
    }

    /// A type 2 AppImage (ELF with the AppImage magic and a squashfs image) is recognized.
    #[test]
    fn a_type_2_appimage_is_recognized() {
        // Take a real ELF, set the magic and append a fake superblock.
        let elf = std::fs::read("/bin/true").unwrap();
        let end = elf_end_offset(&elf).unwrap() as usize;
        let mut data = elf[..end.min(elf.len())].to_vec();
        data.resize(end, 0);
        data[8] = b'A';
        data[9] = b'I';
        data[10] = 2;
        let mut sb = vec![0u8; 96];
        sb[0..4].copy_from_slice(b"hsqs");
        sb[20] = 6; // zstd
        sb[22] = 17;
        sb[28] = 4;
        data.extend_from_slice(&sb);
        let mut t = tempfile::NamedTempFile::new().unwrap();
        t.write_all(&data).unwrap();
        let info = inspect(t.path()).unwrap();
        assert!(info.magic);
        assert_eq!(info.kind, AppImageType::Type2);
        assert_eq!(info.payload_offset, Some(end as u64));
        assert_eq!(info.compression.as_deref(), Some("zstd"));
        assert!(looks_like_appimage(t.path()));
    }

    /// A download that broke off is recognized: the file is shorter than
    /// its SquashFS image says, and a complete one is not.
    #[test]
    fn an_appimage_shorter_than_its_image_is_incomplete() {
        let elf = std::fs::read("/bin/true").unwrap();
        let end = elf_end_offset(&elf).unwrap() as usize;
        let mut data = elf[..end.min(elf.len())].to_vec();
        data.resize(end, 0);
        data[8] = b'A';
        data[9] = b'I';
        data[10] = 2;
        let mut sb = vec![0u8; 96];
        sb[0..4].copy_from_slice(b"hsqs");
        sb[20] = 6;
        sb[22] = 17;
        sb[28] = 4;
        // The image says it is 4096 bytes long; the header is its start.
        sb[40..48].copy_from_slice(&4096u64.to_le_bytes());
        data.extend_from_slice(&sb);
        data.resize(end + 4096, 0);
        let mut whole = tempfile::NamedTempFile::new().unwrap();
        whole.write_all(&data).unwrap();
        assert_eq!(
            inspect(whole.path()).unwrap().incomplete(),
            None,
            "complete"
        );
        // The download broke off after 1000 bytes of the image.
        let mut cut = tempfile::NamedTempFile::new().unwrap();
        cut.write_all(&data[..end + 1000]).unwrap();
        let info = inspect(cut.path()).unwrap();
        assert_eq!(
            info.incomplete(),
            Some(((end + 1000) as u64, (end + 4096) as u64)),
            "broken off"
        );
    }

    /// An AppImage with a DwarFS image instead of squashfs is recognized.
    #[test]
    fn an_appimage_with_a_dwarfs_image_is_recognized() {
        let elf = std::fs::read("/bin/true").unwrap();
        let end = elf_end_offset(&elf).unwrap() as usize;
        let mut data = elf[..end.min(elf.len())].to_vec();
        data.resize(end, 0);
        data[8] = b'A';
        data[9] = b'I';
        data[10] = 2;
        data.extend_from_slice(b"DWARFS\x02\x05");
        data.resize(data.len() + 64, 0);
        let mut t = tempfile::NamedTempFile::new().unwrap();
        t.write_all(&data).unwrap();
        let info = inspect(t.path()).unwrap();
        assert_eq!(info.kind, AppImageType::Type2);
        assert_eq!(info.payload, PayloadFormat::Dwarfs);
        assert_eq!(info.payload_offset, Some(end as u64));
        assert_eq!(info.compression.as_deref(), Some("dwarfs"));
    }

    /// A file that is not an ELF program is not taken for an AppImage.
    #[test]
    fn a_file_that_is_no_program_is_not_an_appimage() {
        let mut t = tempfile::NamedTempFile::new().unwrap();
        t.write_all(&[0u8; 128]).unwrap();
        let info = inspect(t.path()).unwrap();
        assert!(!info.is_elf && !info.is_appimage());
    }
}

#[cfg(test)]
mod processor_tests {
    use super::*;

    /// An AppImage runs on the same processor and 32-bit builds on their
    /// 64-bit relatives; ARM builds never run on x86-64 or the other way.
    #[test]
    fn appimages_run_only_on_a_matching_processor() {
        assert!(runs_on("x86_64", "x86_64"));
        assert!(runs_on("i686", "x86_64"));
        assert!(runs_on("armhf", "aarch64"));
        assert!(!runs_on("aarch64", "x86_64"));
        assert!(!runs_on("x86_64", "aarch64"));
        assert!(!runs_on("riscv64", "x86_64"));
    }
}
