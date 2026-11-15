//! Who may update SAM itself.
//!
//! SAM guards every other app, so an update of SAM must come from SAM's
//! makers, not just from wherever the update information points. An app's
//! embedded signature carries its own key, so a valid signature alone says
//! only that nobody changed the file since someone signed it. For SAM,
//! that someone must be one of the release keys below: their fingerprints
//! are built into SAM, so an attacker who controls the download cannot
//! bring their own.
//!
//! As long as the list is empty (no release key exists yet), SAM does not
//! update itself at all and points to the release page instead.

use anyhow::{bail, Result};
use sam_core::model::{SignatureInfo, SignatureState};

/// Fingerprints (40 hex characters) of the keys that sign SAM's releases.
/// Add a new key here, in a release signed with the old one, before
/// switching to it.
pub const RELEASE_KEYS: &[&str] = &[
    // SAM release key, created 2026-11-15, expires 2029-11-14.
    "AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6",
];

/// Whether `sig` (the checked signature of a downloaded SAM) comes from one
/// of `keys`. The error says why not, in a sentence for people.
pub fn check(sig: &SignatureInfo, keys: &[&str]) -> Result<()> {
    if keys.is_empty() {
        bail!("{}", sam_core::i18n::tr("this SAM was built without a release key, so it cannot check where an update comes from and does not update itself; download new versions from the release page or use your package manager"));
    }
    match sig.state {
        SignatureState::Valid => {
            let fp = sig.fingerprint.as_deref().unwrap_or("").to_ascii_uppercase();
            if keys.iter().any(|k| k.eq_ignore_ascii_case(&fp)) {
                Ok(())
            } else {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "the update is signed, but not with SAM's release key ({key}); it was not installed",
                        &[("key", &if fp.is_empty() { sam_core::i18n::tr("unknown key") } else { fp.clone() })]
                    )
                )
            }
        }
        SignatureState::Unsigned => bail!("{}", sam_core::i18n::tr("the update is not signed, so its origin cannot be checked; it was not installed")),
        SignatureState::Invalid => {
            bail!("{}", sam_core::i18n::tr("the update's signature does not match the file, so it was changed after signing; it was not installed"))
        }
        SignatureState::Unchecked => {
            bail!("{}", sam_core::i18n::trf("the update's signature could not be checked ({reason}); it was not installed", &[("reason", &sig.detail)]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every built-in release key is a full fingerprint (40 hex
    /// characters), never a short key id that another key could share.
    #[test]
    fn release_keys_are_full_fingerprints() {
        assert!(!RELEASE_KEYS.is_empty(), "SAM has a release key");
        for k in RELEASE_KEYS {
            assert!(k.len() == 40 && k.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()), "{k}");
        }
    }

    const OURS: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    fn sig(state: SignatureState, fp: Option<&str>) -> SignatureInfo {
        SignatureInfo { state, fingerprint: fp.map(str::to_string), detail: "gpgv missing".into() }
    }

    /// SAM accepts an update of itself only with a valid signature from one
    /// of its release keys; unsigned, changed, unchecked or otherwise
    /// signed updates are refused (regression: self-update installed any
    /// AppImage the update information pointed to).
    #[test]
    fn sam_updates_itself_only_with_its_release_key() {
        assert!(check(&sig(SignatureState::Valid, Some(OURS)), &[OURS]).is_ok());
        assert!(check(&sig(SignatureState::Valid, Some(&OURS.to_lowercase())), &[OURS]).is_ok(), "case does not matter");
        let other = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
        let e = check(&sig(SignatureState::Valid, Some(other)), &[OURS]).unwrap_err().to_string();
        assert!(e.contains("not with SAM's release key"), "{e}");
        assert!(check(&sig(SignatureState::Valid, None), &[OURS]).is_err(), "a valid signature without a readable key");
        assert!(check(&sig(SignatureState::Unsigned, None), &[OURS]).unwrap_err().to_string().contains("not signed"));
        assert!(check(&sig(SignatureState::Invalid, Some(OURS)), &[OURS]).unwrap_err().to_string().contains("changed after signing"));
        assert!(check(&sig(SignatureState::Unchecked, Some(OURS)), &[OURS]).unwrap_err().to_string().contains("gpgv missing"));
    }

    /// Without a built-in release key, SAM never updates itself, whatever
    /// the download looks like.
    #[test]
    fn without_a_release_key_sam_never_updates_itself() {
        let e = check(&sig(SignatureState::Valid, Some(OURS)), &[]).unwrap_err().to_string();
        assert!(e.contains("without a release key"), "{e}");
    }
}
