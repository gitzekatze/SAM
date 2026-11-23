//! zsync control files: write them (for SAM's own releases) and use them to
//! update a file by downloading only the blocks that changed.
//!
//! A control file is a text header (`zsync`, `Filename`, `Blocksize`,
//! `Length`, `Hash-Lengths`, `URL`, `SHA-1`, …), an empty line, then for
//! every block of the published file a weak rolling checksum (`rsum`) and
//! the start of its MD4. Blocks of the old file whose checksums match are
//! reused; the rest is fetched with HTTP range requests. The result must
//! match the published SHA-1, or it is thrown away.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
// MD4 only because the zsync format checks blocks with it; the whole file is
// then checked (SHA-1) and its signature compared.
use md4::{Digest as _, Md4};
use sha1::Sha1;

/// A parsed control file.
#[derive(Debug, Clone)]
pub struct Control {
    pub filename: Option<String>,
    pub url: Option<String>,
    pub sha1: String,
    pub length: u64,
    pub blocksize: usize,
    /// How many consecutive blocks must match (1 or 2).
    pub seq_matches: usize,
    pub rsum_bytes: usize,
    pub checksum_bytes: usize,
    /// Per block: the stored part of the rolling checksum.
    pub rsums: Vec<u32>,
    /// Per block, one after another: the stored `checksum_bytes` of the MD4.
    /// One buffer, not one per block: a description with millions of
    /// blocks took a heap allocation for each (review 2026-11-23, U-6).
    pub checksums: Vec<u8>,
}

impl Control {
    pub fn block_count(&self) -> usize {
        self.length.div_ceil(self.blocksize as u64) as usize
    }

    /// The stored part of block `i`'s MD4.
    fn checksum(&self, i: usize) -> &[u8] {
        &self.checksums[i * self.checksum_bytes..(i + 1) * self.checksum_bytes]
    }
}

/// The smallest block size SAM uses for a delta (zsyncmake uses 2048 or
/// 4096): with `Blocksize: 1` a 64 MiB description lists millions of blocks.
pub const MIN_BLOCKSIZE: usize = 512;
/// The most blocks SAM plans with: 8 GiB (its largest download) in blocks
/// of 2048 bytes. More, and the update is downloaded whole.
pub const MAX_BLOCKS: usize = 1 << 22;

/// How many blocks with the same quick checksum are tried at one offset.
const MAX_SAME_CHECKSUM: usize = 16;

/// The 16+16-bit rolling checksum zsync uses (`a` = byte sum, `b` = sum of `a`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rsum {
    a: u16,
    b: u16,
}

fn rsum(block: &[u8]) -> Rsum {
    let (mut a, mut b) = (0u16, 0u16);
    for &c in block {
        a = a.wrapping_add(c as u16);
        b = b.wrapping_add(a);
    }
    Rsum { a, b }
}

/// The last `n` bytes of `a` (big-endian) then `b` (big-endian), as zsync stores them.
fn rsum_key(r: Rsum, n: usize) -> u32 {
    let full = ((r.a as u32) << 16) | r.b as u32;
    if n >= 4 {
        full
    } else {
        full & ((1u32 << (8 * n)) - 1)
    }
}

fn md4_of(block: &[u8], blocksize: usize) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(block);
    if block.len() < blocksize {
        h.update(vec![0u8; blocksize - block.len()]);
    }
    h.finalize().into()
}

/// Parses a whole control file.
pub fn parse(data: &[u8]) -> Result<Control> {
    let split = data
        .windows(2)
        .position(|w| w == b"\n\n")
        .context(sam_core::i18n::tr(
            "the update description (.zsync) has no end of header",
        ))?;
    let header = String::from_utf8_lossy(&data[..split]);
    let body = &data[split + 2..];
    let mut c = Control {
        filename: None,
        url: None,
        sha1: String::new(),
        length: 0,
        blocksize: 0,
        seq_matches: 1,
        rsum_bytes: 4,
        checksum_bytes: 16,
        rsums: vec![],
        checksums: vec![],
    };
    for line in header.lines() {
        let Some((k, v)) = line.split_once(": ") else {
            continue;
        };
        let v = v.trim();
        match k {
            "Filename" => c.filename = Some(v.to_string()),
            "URL" if c.url.is_none() => c.url = Some(v.to_string()),
            "SHA-1" => c.sha1 = v.to_ascii_lowercase(),
            "Length" => c.length = v.parse().context("Length")?,
            "Blocksize" => c.blocksize = v.parse().context("Blocksize")?,
            "Hash-Lengths" => {
                let n: Vec<usize> = v.split(',').filter_map(|x| x.trim().parse().ok()).collect();
                if n.len() != 3 {
                    bail!("{}", sam_core::i18n::tr("bad Hash-Lengths"));
                }
                (c.seq_matches, c.rsum_bytes, c.checksum_bytes) = (n[0], n[1], n[2]);
            }
            "Z-URL" | "Z-Filename" => bail!(
                "{}",
                sam_core::i18n::tr("compressed zsync downloads are not supported")
            ),
            _ => {}
        }
    }
    if c.sha1.len() != 40
        || c.blocksize == 0
        || c.blocksize > 1 << 20
        || !(1..=2).contains(&c.seq_matches)
        || !(1..=4).contains(&c.rsum_bytes)
        || !(3..=16).contains(&c.checksum_bytes)
    {
        bail!(
            "{}",
            sam_core::i18n::tr("the update description (.zsync) is incomplete")
        );
    }
    // The length comes from the server: no larger than SAM downloads at
    // all, and every size computed from it is checked, because an overflow
    // wraps silently in a release build (audit U-M7).
    if c.length > crate::updates::MAX_DOWNLOAD {
        bail!(
            "{}",
            sam_core::i18n::tr("the update description (.zsync) names an impossible length")
        );
    }
    // Checked before anything is allocated for the blocks: tiny blocks
    // make a small description list millions of them (review 2026-11-23,
    // U-6). Such an update is downloaded whole instead.
    let n = c.block_count();
    if c.blocksize < MIN_BLOCKSIZE || n > MAX_BLOCKS {
        bail!(
            "{}",
            sam_core::i18n::tr(
                "the update description (.zsync) lists too many small blocks for a partial download"
            )
        );
    }
    let per = c.rsum_bytes + c.checksum_bytes;
    if n.checked_mul(per).is_none_or(|need| body.len() < need) {
        bail!(
            "{}",
            sam_core::i18n::tr("the update description (.zsync) is cut short")
        );
    }
    c.rsums = Vec::with_capacity(n);
    c.checksums = Vec::with_capacity(n * c.checksum_bytes);
    for e in body[..n * per].chunks_exact(per) {
        c.rsums.push(
            e[..c.rsum_bytes]
                .iter()
                .fold(0u32, |acc, &b| (acc << 8) | b as u32),
        );
        c.checksums.extend_from_slice(&e[c.rsum_bytes..]);
    }
    Ok(c)
}

/// Writes a control file for `path` (full-length checksums, one block per
/// match, so a reader needs no sequence logic).
pub fn make(path: &Path, filename: &str, url: &str, mtime: &str) -> Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    let blocksize = if data.len() < 100 << 20 { 2048 } else { 4096 };
    let mut out = Vec::new();
    write!(
        out,
        "zsync: 0.6.2\nFilename: {filename}\nMTime: {mtime}\nBlocksize: {blocksize}\nLength: {}\nHash-Lengths: 1,4,16\nURL: {url}\nSHA-1: {}\n\n",
        data.len(),
        sam_core::util::hex(&Sha1::digest(&data))
    )?;
    for block in data.chunks(blocksize) {
        let r = rsum(&pad(block, blocksize));
        out.extend_from_slice(&r.a.to_be_bytes());
        out.extend_from_slice(&r.b.to_be_bytes());
        out.extend_from_slice(&md4_of(block, blocksize));
    }
    Ok(out)
}

fn pad(block: &[u8], blocksize: usize) -> std::borrow::Cow<'_, [u8]> {
    if block.len() == blocksize {
        std::borrow::Cow::Borrowed(block)
    } else {
        let mut v = block.to_vec();
        v.resize(blocksize, 0);
        std::borrow::Cow::Owned(v)
    }
}

/// Where each block of the new file can be found in `old` (`None` = must be
/// downloaded). Gives up after a minute: what is not found by then is
/// downloaded (see `plan_within`).
pub fn plan(c: &Control, old: &[u8]) -> Vec<Option<u64>> {
    plan_within(c, old, std::time::Duration::from_secs(60))
}

/// `plan` with a time limit. The description comes from the server: one
/// whose quick checksums match a stretch of identical bytes in the old file
/// makes every offset need a full comparison, which on a large file takes
/// practically forever (audit U-M7). After `limit`, the blocks not found
/// yet are simply downloaded.
pub fn plan_within(c: &Control, old: &[u8], limit: std::time::Duration) -> Vec<Option<u64>> {
    let started = std::time::Instant::now();
    let bs = c.blocksize;
    let n = c.block_count();
    let mut found: Vec<Option<u64>> = vec![None; n];
    if old.len() < bs {
        return found;
    }
    // Blocks by quick checksum, in block order within one checksum: one
    // flat sorted list, not a list per checksum (review 2026-11-23, U-6).
    let mut by_rsum: Vec<(u32, u32)> = c
        .rsums
        .iter()
        .enumerate()
        .map(|(i, r)| (*r, i as u32))
        .collect();
    by_rsum.sort_unstable();
    let candidates = |key: u32| -> &[(u32, u32)] {
        let from = by_rsum.partition_point(|(r, _)| *r < key);
        let to = by_rsum.partition_point(|(r, _)| *r <= key);
        &by_rsum[from..to]
    };
    let strong = |i: usize, off: usize| -> bool {
        if off + bs > old.len() {
            return false;
        }
        md4_of(&old[off..off + bs], bs)[..c.checksum_bytes] == *c.checksum(i)
    };
    let weak = |i: usize, off: usize| -> bool {
        off + bs <= old.len() && rsum_key(rsum(&old[off..off + bs]), c.rsum_bytes) == c.rsums[i]
    };
    let mut off = 0usize;
    let mut r = rsum(&old[..bs]);
    loop {
        let mut matched = false;
        {
            let cands = candidates(rsum_key(r, c.rsum_bytes));
            // A description can give thousands of blocks the same quick
            // checksum, which would make SAM compare each one at every byte
            // of the old file (practically endless). Beyond a few, the
            // blocks are simply downloaded (audit U-M7).
            for i in cands
                .iter()
                .take(MAX_SAME_CHECKSUM)
                .map(|(_, i)| *i as usize)
            {
                if found[i].is_some() {
                    continue;
                }
                // With seq_matches 2 the stored checksums are short: the next
                // block must match too (the last block of the file stands
                // alone). Its cheap checksum goes first, so MD4 runs only
                // on real candidates.
                let pair = c.seq_matches == 2 && i + 1 < n;
                if pair && !weak(i + 1, off + bs) {
                    continue;
                }
                if !strong(i, off) || (pair && !strong(i + 1, off + bs)) {
                    continue;
                }
                found[i] = Some(off as u64);
                matched = true;
            }
        }
        let step = if matched { bs } else { 1 };
        if off + step + bs > old.len() {
            break;
        }
        // Looking at the clock every 64 KiB of offsets is enough.
        if off.is_multiple_of(64 << 10) && started.elapsed() > limit {
            break;
        }
        if step == 1 {
            // Roll the checksum one byte forward.
            let out = old[off] as u16;
            let inn = old[off + bs] as u16;
            r.a = r.a.wrapping_sub(out).wrapping_add(inn);
            r.b =
                r.b.wrapping_sub((bs as u16).wrapping_mul(out))
                    .wrapping_add(r.a);
        } else {
            r = rsum(&old[off + bs..off + 2 * bs]);
        }
        off += step;
    }
    // The last block may be shorter than a block of the old file: try it
    // at the very end of the old file, padded.
    if n > 0 && found[n - 1].is_none() {
        let tail = (c.length as usize) - (n - 1) * bs;
        if tail < bs && old.len() >= tail {
            let start = old.len() - tail;
            let blk = &old[start..];
            if md4_of(blk, bs)[..c.checksum_bytes] == *c.checksum(n - 1)
                && rsum_key(rsum(&pad(blk, bs)), c.rsum_bytes) == c.rsums[n - 1]
            {
                found[n - 1] = Some(start as u64);
            }
        }
    }
    found
}

/// Byte ranges of the new file that have to be downloaded, merged so that
/// close ranges become one request.
pub fn missing_ranges(c: &Control, plan: &[Option<u64>], merge_gap: u64) -> Vec<(u64, u64)> {
    let bs = c.blocksize as u64;
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (i, p) in plan.iter().enumerate() {
        if p.is_some() {
            continue;
        }
        let (s, e) = (i as u64 * bs, ((i as u64 + 1) * bs).min(c.length));
        match out.last_mut() {
            Some(last) if s <= last.1 + merge_gap => last.1 = e,
            _ => out.push((s, e)),
        }
    }
    out
}

/// Builds the new file at `dest` from `old` (by `plan`) and the downloaded
/// `ranges` (`fetch(start, end)` returns those bytes), then checks its SHA-1.
pub fn assemble(
    c: &Control,
    old: &[u8],
    plan: &[Option<u64>],
    ranges: &[(u64, u64)],
    dest: &Path,
    mut fetch: impl FnMut(u64, u64) -> Result<Vec<u8>>,
) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(dest)?;
    f.set_len(c.length)?;
    let bs = c.blocksize as u64;
    for (i, p) in plan.iter().enumerate() {
        if let Some(off) = p {
            let start = i as u64 * bs;
            let len = (bs.min(c.length - start)) as usize;
            f.seek(SeekFrom::Start(start))?;
            f.write_all(&old[*off as usize..*off as usize + len])?;
        }
    }
    for &(s, e) in ranges {
        let data = fetch(s, e)?;
        if data.len() as u64 != e - s {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the server sent {got} bytes instead of {expected}",
                    &[("got", &data.len()), ("expected", &(e - s))]
                )
            );
        }
        f.seek(SeekFrom::Start(s))?;
        f.write_all(&data)?;
    }
    f.flush()?;
    f.seek(SeekFrom::Start(0))?;
    let mut h = Sha1::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    if sam_core::util::hex(&h.finalize()) != c.sha1 {
        bail!(
            "{}",
            sam_core::i18n::tr("the assembled file does not match the published checksum")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The block checksums are the ones zsync defines: MD4 of a block padded
    /// with zeros to the block size, and the weak sum cut to its last bytes.
    /// A wrong one would make every downloaded block look changed or, worse,
    /// a changed block look unchanged.
    #[test]
    fn block_checksums_match_the_zsync_definition() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&md4_of(b"abc", 3)),
            "a448017aaf21d8525fc10ae87aa6729d",
            "MD4 test vector"
        );
        assert_eq!(
            md4_of(b"abc", 8),
            md4_of(b"abc\0\0\0\0\0", 8),
            "short blocks are padded with zeros"
        );
        assert_ne!(md4_of(b"abc", 8), md4_of(b"abc", 3));
        let r = Rsum {
            a: 0x1234,
            b: 0x5678,
        };
        assert_eq!(rsum_key(r, 4), 0x1234_5678);
        assert_eq!(
            rsum_key(
                Rsum {
                    a: 0x1234,
                    b: 0x5678
                },
                2
            ),
            0x5678
        );
        assert_eq!(
            rsum_key(
                Rsum {
                    a: 0x1234,
                    b: 0x5678
                },
                3
            ),
            0x34_5678
        );
    }

    fn sample(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1103515245).wrapping_add(12345);
                (x >> 16) as u8
            })
            .collect()
    }

    /// An update is rebuilt from the old version plus the changed blocks.
    #[test]
    fn an_update_is_rebuilt_from_the_old_version_and_changed_blocks() {
        let d = tempfile::tempdir().unwrap();
        // New = old with a changed stretch in the middle, bytes inserted
        // near the start (so the rest shifts) and a different tail.
        let old = sample(300_000, 7);
        let mut new = old.clone();
        new.splice(1000..1000, sample(37, 9));
        for b in &mut new[150_000..151_000] {
            *b ^= 0x5a;
        }
        new.truncate(new.len() - 500);
        new.extend(sample(1234, 11));
        let newp = d.path().join("new.AppImage");
        std::fs::write(&newp, &new).unwrap();
        let ctl = make(
            &newp,
            "new.AppImage",
            "new.AppImage",
            "Wed, 11 Nov 2026 12:00:00 +0000",
        )
        .unwrap();
        let c = parse(&ctl).unwrap();
        assert_eq!(c.length, new.len() as u64);
        assert_eq!(c.block_count(), c.rsums.len());
        assert_eq!(c.block_count() * c.checksum_bytes, c.checksums.len());

        let p = plan(&c, &old);
        let reused = p.iter().filter(|x| x.is_some()).count();
        assert!(
            reused * 10 > p.len() * 9,
            "most blocks come from the old file: {reused}/{}",
            p.len()
        );
        let ranges = missing_ranges(&c, &p, 0);
        let fetched: u64 = ranges.iter().map(|(s, e)| e - s).sum();
        assert!(
            fetched < 20_000,
            "only the changed parts are fetched: {fetched} bytes"
        );
        let out = d.path().join("out");
        assemble(&c, &old, &p, &ranges, &out, |s, e| {
            Ok(new[s as usize..e as usize].to_vec())
        })
        .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), new);

        // A wrong download is caught by the SHA-1.
        let bad = assemble(&c, &old, &p, &ranges, &out, |s, e| {
            Ok(vec![0u8; (e - s) as usize])
        });
        assert!(bad.is_err());
    }

    /// The rolling checksum of the update transfer matches a direct computation at every offset.
    #[test]
    fn the_rolling_checksum_matches_a_direct_computation() {
        let data = sample(10_000, 3);
        let bs = 2048;
        let mut r = rsum(&data[..bs]);
        for off in 0..(data.len() - bs) {
            assert_eq!(r, rsum(&data[off..off + bs]), "offset {off}");
            let (out, inn) = (data[off] as u16, data[off + bs] as u16);
            r.a = r.a.wrapping_sub(out).wrapping_add(inn);
            r.b =
                r.b.wrapping_sub((bs as u16).wrapping_mul(out))
                    .wrapping_add(r.a);
        }
    }

    /// Compressed or incomplete zsync files are refused.
    #[test]
    fn refuses_compressed_and_broken_files() {
        assert!(parse(
            b"zsync: 0.6.2\nZ-URL: x.gz\nSHA-1: 0123456789abcdef0123456789abcdef01234567\n\n"
        )
        .is_err());
        assert!(parse(b"zsync: 0.6.2\nBlocksize: 2048\n\n").is_err());
    }

    /// Regression (review 2026-11-23, U-6): `Blocksize: 1` and the
    /// shortest checksums made a description of 64 MiB (the most SAM
    /// fetches) list about 16 million blocks, and SAM allocated some 2 GB
    /// for them before giving up on the delta. Blocks smaller than 512
    /// bytes, or more than SAM plans with, are refused before anything is
    /// allocated; the update is then downloaded whole.
    #[test]
    fn a_description_with_tiny_or_countless_blocks_is_refused_before_allocating() {
        let make = |bs: usize, len: usize| {
            let mut z = format!(
                "zsync: 0.6.2\nBlocksize: {bs}\nLength: {len}\nHash-Lengths: 1,1,3\nSHA-1: {}\n\n",
                "0".repeat(40)
            )
            .into_bytes();
            z.resize(z.len() + len.div_ceil(bs) * 4, 0);
            z
        };
        for (bs, len) in [
            (1, 100_000),
            (256, 100_000),
            (MIN_BLOCKSIZE, (MAX_BLOCKS + 1) * MIN_BLOCKSIZE),
        ] {
            let e = parse(&make(bs, len)).unwrap_err().to_string();
            assert!(e.contains("too many small blocks"), "{bs} {len}: {e}");
        }
        let c = parse(&make(MIN_BLOCKSIZE, 100_000)).unwrap();
        assert_eq!(c.rsums.len(), 100_000usize.div_ceil(MIN_BLOCKSIZE));
    }

    /// A description from a hostile server cannot crash SAM or keep it busy
    /// (audit U-M7): an absurd length is refused, a block count that would
    /// overflow the size computation is refused instead of wrapping, and
    /// thousands of blocks whose quick checksum matches a stretch of
    /// identical bytes end at the time limit, with those blocks left for
    /// downloading.
    #[test]
    fn a_hostile_update_description_cannot_crash_or_stall_sam() {
        let head = |len: u64, bs: usize| {
            format!(
                "zsync: 0.6.2\nFilename: x\nBlocksize: {bs}\nLength: {len}\nHash-Lengths: 1,4,16\nURL: x\nSHA-1: {}\n\n",
                "0".repeat(40)
            )
            .into_bytes()
        };
        let e = parse(&head(u64::MAX, 2048)).unwrap_err().to_string();
        assert!(e.contains("impossible length"), "{e}");
        let e = parse(&head(crate::updates::MAX_DOWNLOAD + 1, 2048))
            .unwrap_err()
            .to_string();
        assert!(e.contains("impossible length"), "{e}");
        // Within the limit, but without the block list: refused, no panic.
        assert!(parse(&head(crate::updates::MAX_DOWNLOAD, 2048)).is_err());

        // 4 MiB of zeros in the old file; 3,000 blocks claim the zero
        // block's quick checksum but never match fully.
        let bs = 2048;
        let old = vec![0u8; 4 << 20];
        let zero = rsum_key(rsum(&old[..bs]), 4);
        let n = 3000;
        let c = Control {
            filename: None,
            url: None,
            sha1: String::new(),
            length: (n * bs) as u64,
            blocksize: bs,
            seq_matches: 1,
            rsum_bytes: 4,
            checksum_bytes: 16,
            rsums: vec![zero; n],
            checksums: (0..n).flat_map(|i| [(i % 251) as u8 + 1; 16]).collect(),
        };
        let t = std::time::Instant::now();
        let p = plan_within(&c, &old, std::time::Duration::from_millis(500));
        assert!(
            t.elapsed() < std::time::Duration::from_secs(20),
            "{:?}",
            t.elapsed()
        );
        assert!(
            p.iter().all(Option::is_none),
            "nothing false is taken from the old file"
        );
    }
}
