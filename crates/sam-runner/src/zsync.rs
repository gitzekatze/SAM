//! zsync control files: write them (for SAM's own releases) and use them to
//! update a file by downloading only the blocks that changed.
//!
//! A control file is a text header (`zsync`, `Filename`, `Blocksize`,
//! `Length`, `Hash-Lengths`, `URL`, `SHA-1`, …), an empty line, then for
//! every block of the published file a weak rolling checksum (`rsum`) and
//! the start of its MD4. Blocks of the old file whose checksums match are
//! reused; the rest is fetched with HTTP range requests. The result must
//! match the published SHA-1, or it is thrown away.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
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
    /// Per block: the stored part of the rolling checksum, and of the MD4.
    pub blocks: Vec<(u32, Vec<u8>)>,
}

impl Control {
    pub fn block_count(&self) -> usize {
        self.length.div_ceil(self.blocksize as u64) as usize
    }
}

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
    let split = data.windows(2).position(|w| w == b"\n\n").context(sam_core::i18n::tr("the update description (.zsync) has no end of header"))?;
    let header = String::from_utf8_lossy(&data[..split]);
    let body = &data[split + 2..];
    let mut c =
        Control { filename: None, url: None, sha1: String::new(), length: 0, blocksize: 0, seq_matches: 1, rsum_bytes: 4, checksum_bytes: 16, blocks: vec![] };
    for line in header.lines() {
        let Some((k, v)) = line.split_once(": ") else { continue };
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
            "Z-URL" | "Z-Filename" => bail!("{}", sam_core::i18n::tr("compressed zsync downloads are not supported")),
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
        bail!("{}", sam_core::i18n::tr("the update description (.zsync) is incomplete"));
    }
    let per = c.rsum_bytes + c.checksum_bytes;
    let n = c.block_count();
    if body.len() < n * per {
        bail!("{}", sam_core::i18n::tr("the update description (.zsync) is cut short"));
    }
    c.blocks = (0..n)
        .map(|i| {
            let e = &body[i * per..(i + 1) * per];
            let r = e[..c.rsum_bytes].iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);
            (r, e[c.rsum_bytes..].to_vec())
        })
        .collect();
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
/// downloaded).
pub fn plan(c: &Control, old: &[u8]) -> Vec<Option<u64>> {
    let bs = c.blocksize;
    let n = c.block_count();
    let mut found: Vec<Option<u64>> = vec![None; n];
    if old.len() < bs {
        return found;
    }
    let mut by_rsum: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, (r, _)) in c.blocks.iter().enumerate() {
        by_rsum.entry(*r).or_default().push(i);
    }
    let strong = |i: usize, off: usize| -> bool {
        if off + bs > old.len() {
            return false;
        }
        md4_of(&old[off..off + bs], bs)[..c.checksum_bytes] == c.blocks[i].1[..]
    };
    let weak = |i: usize, off: usize| -> bool { off + bs <= old.len() && rsum_key(rsum(&old[off..off + bs]), c.rsum_bytes) == c.blocks[i].0 };
    let mut off = 0usize;
    let mut r = rsum(&old[..bs]);
    loop {
        let mut matched = false;
        if let Some(cands) = by_rsum.get(&rsum_key(r, c.rsum_bytes)) {
            for &i in cands {
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
        if step == 1 {
            // Roll the checksum one byte forward.
            let out = old[off] as u16;
            let inn = old[off + bs] as u16;
            r.a = r.a.wrapping_sub(out).wrapping_add(inn);
            r.b = r.b.wrapping_sub((bs as u16).wrapping_mul(out)).wrapping_add(r.a);
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
            if md4_of(blk, bs)[..c.checksum_bytes] == c.blocks[n - 1].1[..] && rsum_key(rsum(&pad(blk, bs)), c.rsum_bytes) == c.blocks[n - 1].0 {
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
    let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).read(true).open(dest)?;
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
            bail!("the server sent {} bytes instead of {}", data.len(), e - s);
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
        bail!("{}", sam_core::i18n::tr("the assembled file does not match the published checksum"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let ctl = make(&newp, "new.AppImage", "new.AppImage", "Wed, 11 Nov 2026 12:00:00 +0000").unwrap();
        let c = parse(&ctl).unwrap();
        assert_eq!(c.length, new.len() as u64);
        assert_eq!(c.block_count(), c.blocks.len());

        let p = plan(&c, &old);
        let reused = p.iter().filter(|x| x.is_some()).count();
        assert!(reused * 10 > p.len() * 9, "most blocks come from the old file: {reused}/{}", p.len());
        let ranges = missing_ranges(&c, &p, 0);
        let fetched: u64 = ranges.iter().map(|(s, e)| e - s).sum();
        assert!(fetched < 20_000, "only the changed parts are fetched: {fetched} bytes");
        let out = d.path().join("out");
        assemble(&c, &old, &p, &ranges, &out, |s, e| Ok(new[s as usize..e as usize].to_vec())).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), new);

        // A wrong download is caught by the SHA-1.
        let bad = assemble(&c, &old, &p, &ranges, &out, |s, e| Ok(vec![0u8; (e - s) as usize]));
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
            r.b = r.b.wrapping_sub((bs as u16).wrapping_mul(out)).wrapping_add(r.a);
        }
    }

    /// Compressed or incomplete zsync files are refused.
    #[test]
    fn refuses_compressed_and_broken_files() {
        assert!(parse(b"zsync: 0.6.2\nZ-URL: x.gz\nSHA-1: 0123456789abcdef0123456789abcdef01234567\n\n").is_err());
        assert!(parse(b"zsync: 0.6.2\nBlocksize: 2048\n\n").is_err());
    }
}
