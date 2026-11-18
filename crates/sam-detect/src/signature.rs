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
        Err(e) => SignatureInfo {
            state: SignatureState::Unchecked,
            fingerprint: None,
            detail: format!("{e:#}"),
        },
    }
}

fn check_inner(path: &Path) -> Result<SignatureInfo> {
    // The sections live in the runtime (the ELF in front of the payload),
    // which is well under this size.
    let mut head = Vec::new();
    File::open(path)
        .with_context(|| sam_core::i18n::trf("reading {file}", &[("file", &path.display())]))?
        .take(HEAD)
        .read_to_end(&mut head)?;
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
        return Ok(SignatureInfo {
            state: SignatureState::Invalid,
            fingerprint: None,
            detail: sam_core::i18n::tr("signed, but the signer's key is missing"),
        });
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
    let gpg = sam_core::util::which("gpg").context(sam_core::i18n::tr(
        "GnuPG (gpg) is needed to read the signer's key",
    ))?;
    let keyring = home.join("keyring.gpg");
    let Some(listing) = import_keys(&gpg, home, &keyring, &home.join("key.asc"))? else {
        return Ok(SignatureInfo {
            state: SignatureState::Invalid,
            fingerprint: None,
            detail: sam_core::i18n::tr("signed, but the signer's key cannot be read"),
        });
    };
    // gpgv accepts a signature by ANY key in its keyring, so a file that
    // carries a trusted key next to its own could borrow the trusted key's
    // name (regression: SAM took the first key's fingerprint as the
    // signer). An AppImage carries the key of its one signer: anything else
    // is refused.
    let primaries = primary_fingerprints(&listing);
    if primaries.len() != 1 {
        return Ok(SignatureInfo {
            state: SignatureState::Invalid,
            fingerprint: None,
            detail: sam_core::i18n::trf(
                "the file carries {count} keys instead of its signer's one; SAM does not accept its signature",
                &[("count", &primaries.len())],
            ),
        });
    }
    let uid = listing
        .lines()
        .find(|l| l.starts_with("uid:"))
        .and_then(|l| l.split(':').nth(9))
        .map(|u| sam_core::util::display_safe(u, 80));
    // The signer is what gpgv itself reports for the signature it checked.
    let signer = verify(
        &gpgv,
        home,
        &keyring,
        &home.join("digest.sig"),
        &home.join("digest"),
    )?;
    let ok = signer
        .as_deref()
        .is_some_and(|s| primaries.iter().any(|p| p == s));
    let fingerprint = if ok { signer } else { None };
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
    Ok(SignatureInfo {
        state: if ok {
            SignatureState::Valid
        } else {
            SignatureState::Invalid
        },
        fingerprint,
        detail,
    })
}

/// How long GnuPG may take for one step; it reads keys and signatures that
/// came with an untrusted file.
const GPG_LIMIT: std::time::Duration = std::time::Duration::from_secs(20);
/// How much of GnuPG's output is read.
const GPG_OUTPUT: usize = 64 * 1024;

/// Imports the armoured keys in `keys` into a fresh `keyring` (GnuPG's
/// folder is the throwaway `home`) and returns GnuPG's listing of them in
/// `--with-colons` form, or `None` when the keys cannot be read.
fn import_keys(gpg: &Path, home: &Path, keyring: &Path, keys: &Path) -> Result<Option<String>> {
    let base = || {
        let mut c = Command::new(gpg);
        c.args(["--batch", "--quiet", "--no-options", "--homedir"])
            .arg(home)
            .args(["--no-default-keyring", "--keyring"])
            .arg(keyring);
        c
    };
    let (st, _) =
        sam_core::util::output_within(base().arg("--import").arg(keys), GPG_LIMIT, GPG_OUTPUT)?;
    if !st.success() {
        return Ok(None);
    }
    let (st, out) = sam_core::util::output_within(
        base().args(["--with-colons", "--list-keys", "--fingerprint"]),
        GPG_LIMIT,
        GPG_OUTPUT,
    )?;
    Ok(st
        .success()
        .then(|| String::from_utf8_lossy(&out).into_owned()))
}

/// Fingerprints of the primary keys in a `--with-colons` listing (the
/// `fpr:` line right after each `pub:` line; subkeys are not counted).
fn primary_fingerprints(listing: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut after_pub = false;
    for l in listing.lines() {
        if l.starts_with("pub:") {
            after_pub = true;
        } else if l.starts_with("sub:") {
            after_pub = false;
        } else if after_pub && l.starts_with("fpr:") {
            if let Some(f) = l.split(':').nth(9) {
                out.push(f.to_ascii_uppercase());
            }
            after_pub = false;
        }
    }
    out
}

/// Runs gpgv on `sig` over `data` with `keyring` and returns the primary
/// fingerprint of the key that made the signature, as gpgv reports it, or
/// `None` when the signature is not good.
fn verify(
    gpgv: &Path,
    home: &Path,
    keyring: &Path,
    sig: &Path,
    data: &Path,
) -> Result<Option<String>> {
    let (st, out) = sam_core::util::output_within(
        Command::new(gpgv)
            .arg("--homedir")
            .arg(home)
            .arg("--keyring")
            .arg(keyring)
            .args(["--status-fd", "1"])
            .arg(sig)
            .arg(data),
        GPG_LIMIT,
        GPG_OUTPUT,
    )?;
    Ok(if st.success() {
        signer_from_status(&String::from_utf8_lossy(&out))
    } else {
        None
    })
}

/// The signer in gpgv's machine-readable status lines: the primary-key
/// fingerprint of the one `VALIDSIG` line (the signing key's own when the
/// primary is not given). Anything unclear (no or several good signatures,
/// a bad or unverifiable one next to it, a malformed fingerprint) gives
/// `None`: SAM then treats the signature as not valid.
pub fn signer_from_status(status: &str) -> Option<String> {
    let lines: Vec<Vec<&str>> = status
        .lines()
        .filter_map(|l| l.strip_prefix("[GNUPG:] "))
        .map(|l| l.split_whitespace().collect())
        .collect();
    let bad = ["BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG"];
    if lines
        .iter()
        .any(|f| f.first().is_some_and(|k| bad.contains(k)))
    {
        return None;
    }
    let valid: Vec<&Vec<&str>> = lines
        .iter()
        .filter(|f| f.first() == Some(&"VALIDSIG"))
        .collect();
    let [fields] = valid.as_slice() else {
        return None;
    };
    let fpr = fields.get(10).or_else(|| fields.get(1))?;
    let is_fpr = matches!(fpr.len(), 40 | 64) && fpr.chars().all(|c| c.is_ascii_hexdigit());
    is_fpr.then(|| fpr.to_ascii_uppercase())
}

/// Test material for the GnuPG contract: two throwaway keys (A, then B) and
/// a signature by B. gpgv accepts it with both keys in its keyring; SAM must
/// still name B.
const CONTRACT_KEY_A: &str = include_str!("../contract/a.asc");
const CONTRACT_KEY_B: &str = include_str!("../contract/b.asc");
pub const CONTRACT_MSG: &str = include_str!("../contract/msg");
const CONTRACT_SIG: &str = include_str!("../contract/msg.sig");
/// Key B's fingerprint.
pub const CONTRACT_SIGNER: &str = "1B861E7D695D2668FD5DA11DE9F8CB684282E921";

/// Checks, with the installed GnuPG, what SAM relies on: gpgv accepts a
/// signature by any key in its keyring (the reason SAM refuses files with
/// more than one key), and its status output names the key that really
/// signed. Used by `sam-jail doctor` and the tests. The error says what
/// differs. `msg` and `expected` are the contract material's message and
/// signer (`CONTRACT_MSG`, `CONTRACT_SIGNER`); the tests pass others to
/// show that the check notices a bad signature and a wrong signer.
pub fn gnupg_contract(msg: &str, expected: &str) -> std::result::Result<(), String> {
    let run = || -> Result<std::result::Result<(), String>> {
        let gpg = sam_core::util::which("gpg").context("gpg is not installed")?;
        let gpgv = sam_core::util::which("gpgv").context("gpgv is not installed")?;
        let tmp = tempfile::tempdir()?;
        let home = tmp.path();
        std::fs::write(
            home.join("keys.asc"),
            format!("{CONTRACT_KEY_A}{CONTRACT_KEY_B}"),
        )?;
        std::fs::write(home.join("msg"), msg)?;
        std::fs::write(home.join("msg.sig"), CONTRACT_SIG)?;
        let keyring = home.join("keyring.gpg");
        let Some(listing) = import_keys(&gpg, home, &keyring, &home.join("keys.asc"))? else {
            return Ok(Err("gpg could not import two plain public keys".into()));
        };
        if primary_fingerprints(&listing).len() != 2 {
            return Ok(Err(
                "gpg's --with-colons listing no longer shows one pub/fpr pair per key".into(),
            ));
        }
        Ok(
            match verify(
                &gpgv,
                home,
                &keyring,
                &home.join("msg.sig"),
                &home.join("msg"),
            )? {
                Some(s) if s == expected => Ok(()),
                Some(s) => Err(format!("gpgv names {s} as the signer, not {expected}")),
                None => Err("gpgv no longer reports one VALIDSIG line for a good signature".into()),
            },
        )
    };
    run().map_err(|e| format!("{e:#}"))?
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
    SignatureInfo {
        state: SignatureState::Unsigned,
        fingerprint: None,
        detail: sam_core::i18n::tr(detail),
    }
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

/// Like `sign_for_test`, but writes `key_block` (any armoured keys) into
/// the key section instead of the signer's own key; for the tests of files
/// that carry other keys than their signer's.
#[doc(hidden)]
pub fn sign_with_key_block_for_test(
    path: &Path,
    gpg_home: &Path,
    key_id: &str,
    key_block: &[u8],
) -> Result<()> {
    sign_inner(path, Some(gpg_home), key_id, Some(key_block))
}

/// Signs an AppImage the way AppImage tools check it: the SHA-256 of the
/// file with both signature sections empty is signed with `key_id`, and the
/// signature and the public key are written into those sections. GnuPG
/// asks for the passphrase itself. `gpg_home` is GnuPG's own folder when
/// not given.
pub fn sign_embedded(path: &Path, gpg_home: Option<&Path>, key_id: &str) -> Result<()> {
    sign_inner(path, gpg_home, key_id, None)
}

fn sign_inner(
    path: &Path,
    gpg_home: Option<&Path>,
    key_id: &str,
    key_block: Option<&[u8]>,
) -> Result<()> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;
    let (sig_range, key_range) =
        sections(&data).context(sam_core::i18n::tr("no signature sections"))?;
    let gpg = sam_core::util::which("gpg").context(sam_core::i18n::tr("gpg missing"))?;
    let gpg_cmd = || {
        let mut c = Command::new(&gpg);
        if let Some(h) = gpg_home {
            c.arg("--homedir").arg(h);
        }
        c
    };
    let key = match key_block {
        Some(k) => k.to_vec(),
        None => {
            gpg_cmd()
                .args(["--batch", "--armor", "--export", key_id])
                .output()?
                .stdout
        }
    };
    anyhow::ensure!(
        !key.is_empty(),
        "{}",
        sam_core::i18n::trf("GnuPG has no key {key}", &[("key", &key_id)])
    );
    anyhow::ensure!(key.len() <= key_range.len(), "key too large");
    let mut zeroed = data.clone();
    zeroed[sig_range.clone()].fill(0);
    zeroed[key_range.clone()].fill(0);
    let digest = sam_core::util::hex(&Sha256::digest(&zeroed));
    let mut child = gpg_cmd()
        .args([
            "--batch",
            "--yes",
            "--armor",
            "--detach-sign",
            "--local-user",
            key_id,
            "--output",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("stdin")?
        .write_all(digest.as_bytes())?;
    let sig = child.wait_with_output()?.stdout;
    anyhow::ensure!(
        !sig.is_empty() && sig.len() <= sig_range.len(),
        "{}",
        sam_core::i18n::tr("signature missing or too large")
    );
    data[key_range.start..key_range.start + key.len()].copy_from_slice(&key);
    data[sig_range.start..sig_range.start + sig.len()].copy_from_slice(&sig);
    std::fs::write(path, data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "50383F6AEEDD9F43E1DB6CEF5BF470364B01B57E";
    const B: &str = "1B861E7D695D2668FD5DA11DE9F8CB684282E921";

    fn validsig(signing: &str, primary: &str) -> String {
        format!("[GNUPG:] VALIDSIG {signing} 2026-11-18 1795019682 0 4 0 22 10 00 {primary}\n")
    }

    /// The signer is read from gpgv's own report of the signature it
    /// checked: the primary key, or the signing key when no primary is
    /// given. Anything unclear names nobody, so the signature is not valid.
    #[test]
    fn the_signer_is_what_gpgv_reports_and_nothing_unclear_counts() {
        let good = format!(
            "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG E9F8CB684282E921 B\n{}",
            validsig(B, B)
        );
        assert_eq!(signer_from_status(&good).as_deref(), Some(B));
        // Signed by a subkey: the primary key is named.
        assert_eq!(signer_from_status(&validsig(B, A)).as_deref(), Some(A));
        // Without the primary field: the signing key.
        assert_eq!(
            signer_from_status(&format!(
                "[GNUPG:] VALIDSIG {B} 2026-11-18 1 0 4 0 22 10 00\n"
            ))
            .as_deref(),
            Some(B)
        );
        assert_eq!(
            signer_from_status(&validsig(&B.to_lowercase(), &B.to_lowercase())).as_deref(),
            Some(B)
        );
        // No good signature, two good ones, or a bad one beside a good one.
        assert_eq!(signer_from_status("[GNUPG:] NEWSIG\n"), None);
        assert_eq!(
            signer_from_status(&format!("{}{}", validsig(A, A), validsig(B, B))),
            None
        );
        assert_eq!(
            signer_from_status(&format!("[GNUPG:] BADSIG X y\n{}", validsig(B, B))),
            None
        );
        assert_eq!(
            signer_from_status(&format!("[GNUPG:] ERRSIG X\n{}", validsig(B, B))),
            None
        );
        // Text that only looks like a status line, and malformed fingerprints.
        assert_eq!(signer_from_status(&format!("note: VALIDSIG {B}\n")), None);
        assert_eq!(signer_from_status(&validsig(B, "1234")), None);
        assert_eq!(signer_from_status(&validsig(B, &"Z".repeat(40))), None);
    }

    /// Primary keys are counted from GnuPG's listing; subkeys are not keys
    /// of their own (a signer with a signing subkey carries one key).
    #[test]
    fn primary_keys_are_counted_without_their_subkeys() {
        let one_with_sub = format!(
            "pub:u:255:22:X:1::u:::cC:::::ed25519:::0:\nfpr:::::::::{A}:\nuid:u::::1::H::Sub <s>::::::::::0:\nsub:u:255:22:Y:1::::::s:::::ed25519::\nfpr:::::::::{B}:\n"
        );
        assert_eq!(primary_fingerprints(&one_with_sub), vec![A.to_string()]);
        let two = format!("pub:-:255:22:X:1:::::scSC:\nfpr:::::::::{A}:\npub:-:255:22:Y:1:::::scSC:\nfpr:::::::::{}:\n", B.to_lowercase());
        assert_eq!(
            primary_fingerprints(&two),
            vec![A.to_string(), B.to_string()]
        );
        assert!(primary_fingerprints("").is_empty());
    }

    /// The fixed test material of the GnuPG contract is what its comments
    /// say: key B's fingerprint is the one recorded.
    #[test]
    fn the_contract_material_names_key_b() {
        assert_eq!(CONTRACT_SIGNER, B);
        assert!(CONTRACT_KEY_A.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert!(CONTRACT_SIG.contains("BEGIN PGP SIGNATURE"));
    }
}
