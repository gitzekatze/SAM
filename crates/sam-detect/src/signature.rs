//! Embedded AppImage signatures.
//!
//! A signed Type 2 AppImage carries two ELF sections in its runtime:
//! `.sha256_sig` (an ASCII-armoured GPG signature) and `.sig_key` (the
//! signer's public key). The signature covers the SHA-256 digest, written as
//! lowercase hex, of the whole file with both sections filled with zeros
//! (what appimagetool signs and the AppImage `validate` tool checks).
//!
//! The key travels inside the file, so a valid signature says only that the
//! file was not changed since someone with that key signed it, not who that
//! someone is. Its value is continuity: SAM remembers the key and warns
//! when an update comes signed with another key, or unsigned.
//!
//! Checking uses `gpgv` with a throwaway keyring in a temporary folder; the
//! user's own GnuPG folder is never touched.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use sam_core::model::{SignatureInfo, SignatureState};
use sha2::{Digest, Sha256};

/// Signatures and keys larger than this are not believed.
const MAX_SECTION: u64 = 64 * 1024;
/// How much of the file is read to find the sections.
const HEAD: u64 = 8 * 1024 * 1024;

/// Checks the embedded signature of `path`. Never fails: problems are
/// reported in the result.
pub fn check(path: &Path) -> SignatureInfo {
    match check_inner(path) {
        Ok(i) => i,
        Err(e) => SignatureInfo { state: SignatureState::Unchecked, fingerprint: None, detail: format!("{e:#}") },
    }
}

fn check_inner(path: &Path) -> Result<SignatureInfo> {
    // The sections live in the runtime (the ELF in front of the payload),
    // which is well under this size.
    let mut head = Vec::new();
    File::open(path).with_context(|| sam_core::i18n::trf("reading {file}", &[("file", &path.display())]))?.take(HEAD).read_to_end(&mut head)?;
    let Some((sig_range, key_range)) = sections(&head) else {
        return Ok(unsigned("the runtime has no signature sections"));
    };
    let sig = trim_zeros(&head[sig_range.clone()]).to_vec();
    let key = trim_zeros(&head[key_range.clone()]).to_vec();
    drop(head);
    if sig.is_empty() {
        return Ok(unsigned("not signed"));
    }
    if key.is_empty() {
        return Ok(SignatureInfo { state: SignatureState::Invalid, fingerprint: None, detail: sam_core::i18n::tr("signed, but the signer's key is missing") });
    }
    let Some(gpgv) = sam_core::util::which("gpgv") else {
        return Ok(SignatureInfo {
            state: SignatureState::Unchecked,
            fingerprint: None,
            detail: sam_core::i18n::tr("signed; install GnuPG (gpgv) to check the signature"),
        });
    };
    let digest = digest_without(path, &[sig_range, key_range])?;

    let tmp = tempfile::tempdir().context(sam_core::i18n::tr("temporary folder"))?;
    let home = tmp.path();
    std::fs::write(home.join("key.asc"), &key)?;
    std::fs::write(home.join("digest"), digest.as_bytes())?;
    std::fs::write(home.join("digest.sig"), &sig)?;
    let gpg = sam_core::util::which("gpg").context(sam_core::i18n::tr("GnuPG (gpg) is needed to read the signer's key"))?;
    // Keyring for gpgv, plus the key's fingerprint.
    let keyring = home.join("keyring.gpg");
    let st = Command::new(&gpg)
        .args(["--batch", "--quiet", "--no-options", "--homedir"])
        .arg(home)
        .args(["--no-default-keyring", "--keyring"])
        .arg(&keyring)
        .arg("--import")
        .arg(home.join("key.asc"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !st.success() {
        return Ok(SignatureInfo {
            state: SignatureState::Invalid,
            fingerprint: None,
            detail: sam_core::i18n::tr("signed, but the signer's key cannot be read"),
        });
    }
    let out = Command::new(&gpg)
        .args(["--batch", "--no-options", "--with-colons", "--homedir"])
        .arg(home)
        .args(["--no-default-keyring", "--keyring"])
        .arg(&keyring)
        .args(["--list-keys", "--fingerprint"])
        .stderr(Stdio::null())
        .output()?;
    let listing = String::from_utf8_lossy(&out.stdout);
    let fingerprint = listing.lines().find(|l| l.starts_with("fpr:")).and_then(|l| l.split(':').nth(9)).map(str::to_string);
    let uid = listing.lines().find(|l| l.starts_with("uid:")).and_then(|l| l.split(':').nth(9)).map(|u| sam_core::util::display_safe(u, 80));
    let ok = Command::new(&gpgv)
        .arg("--homedir")
        .arg(home)
        .arg("--keyring")
        .arg(&keyring)
        .arg(home.join("digest.sig"))
        .arg(home.join("digest"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    // Whole sentences with and without the signer's name: a name glued on
    // with an English " by" would not translate.
    let detail = match (ok, &uid) {
        (true, Some(u)) => {
            sam_core::i18n::trf("signed by {signer}; the key comes with the file, so this shows it is unchanged, not who made it", &[("signer", u)])
        }
        (true, None) => sam_core::i18n::tr("signed; the key comes with the file, so this shows it is unchanged, not who made it"),
        (false, Some(u)) => sam_core::i18n::trf("the signature by {signer} does not match the file: it was changed after signing", &[("signer", u)]),
        (false, None) => sam_core::i18n::tr("the signature does not match the file: it was changed after signing"),
    };
    Ok(SignatureInfo { state: if ok { SignatureState::Valid } else { SignatureState::Invalid }, fingerprint, detail })
}

/// SHA-256 (lowercase hex) of the file with `zero` ranges read as zeros,
/// streamed so large AppImages are not loaded into memory.
fn digest_without(path: &Path, zero: &[std::ops::Range<usize>]) -> Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut pos = 0usize;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        for r in zero {
            let (s, e) = (r.start.max(pos), r.end.min(pos + n));
            if s < e {
                chunk[s - pos..e - pos].fill(0);
            }
        }
        h.update(&chunk[..]);
        pos += n;
    }
    Ok(sam_core::util::hex(&h.finalize()))
}

/// An unsigned result; `detail` is translated here.
fn unsigned(detail: &str) -> SignatureInfo {
    SignatureInfo { state: SignatureState::Unsigned, fingerprint: None, detail: sam_core::i18n::tr(detail) }
}

/// File ranges of `.sha256_sig` and `.sig_key`.
fn sections(data: &[u8]) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    let elf = goblin::elf::Elf::parse(data).ok()?;
    let mut sig = None;
    let mut key = None;
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name)?;
        let (off, size) = (sh.sh_offset, sh.sh_size);
        if size == 0 || size > MAX_SECTION || off.checked_add(size)? > data.len() as u64 {
            continue;
        }
        let r = off as usize..(off + size) as usize;
        match name {
            ".sha256_sig" => sig = Some(r),
            ".sig_key" => key = Some(r),
            _ => {}
        }
    }
    Some((sig?, key?))
}

fn trim_zeros(b: &[u8]) -> &[u8] {
    let end = b.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
    &b[..end]
}

/// Writes a signature into an AppImage whose runtime has empty signature
/// sections; for tests.
#[doc(hidden)]
pub fn sign_for_test(path: &Path, gpg_home: &Path, key_id: &str) -> Result<()> {
    sign_embedded(path, Some(gpg_home), key_id)
}

/// Signs an AppImage the way AppImage tools check it: the SHA-256 of the
/// file with both signature sections empty is signed with `key_id`, and the
/// signature and the public key are written into those sections. GnuPG
/// asks for the passphrase itself. `gpg_home` is GnuPG's own folder when
/// not given.
pub fn sign_embedded(path: &Path, gpg_home: Option<&Path>, key_id: &str) -> Result<()> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;
    let (sig_range, key_range) = sections(&data).context(sam_core::i18n::tr("no signature sections"))?;
    let gpg = sam_core::util::which("gpg").context(sam_core::i18n::tr("gpg missing"))?;
    let gpg_cmd = || {
        let mut c = Command::new(&gpg);
        if let Some(h) = gpg_home {
            c.arg("--homedir").arg(h);
        }
        c
    };
    let key = gpg_cmd().args(["--batch", "--armor", "--export", key_id]).output()?.stdout;
    anyhow::ensure!(!key.is_empty(), "{}", sam_core::i18n::trf("GnuPG has no key {key}", &[("key", &key_id)]));
    anyhow::ensure!(key.len() <= key_range.len(), "key too large");
    let mut zeroed = data.clone();
    zeroed[sig_range.clone()].fill(0);
    zeroed[key_range.clone()].fill(0);
    let digest = sam_core::util::hex(&Sha256::digest(&zeroed));
    let mut child = gpg_cmd()
        .args(["--batch", "--yes", "--armor", "--detach-sign", "--local-user", key_id, "--output", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.take().context("stdin")?.write_all(digest.as_bytes())?;
    let sig = child.wait_with_output()?.stdout;
    anyhow::ensure!(!sig.is_empty() && sig.len() <= sig_range.len(), "{}", sam_core::i18n::tr("signature missing or too large"));
    data[key_range.start..key_range.start + key.len()].copy_from_slice(&key);
    data[sig_range.start..sig_range.start + sig.len()].copy_from_slice(&sig);
    std::fs::write(path, data)?;
    Ok(())
}
