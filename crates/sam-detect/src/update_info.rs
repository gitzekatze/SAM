//! The update information an AppImage carries in its `.upd_info` section,
//! as written by appimagetool: where newer versions of the app are
//! published. Read from the file; nothing is run.
//!
//! Supported forms:
//! - `zsync|https://example.org/App-latest-x86_64.AppImage.zsync`
//! - `gh-releases-zsync|owner|repo|latest|App-*x86_64.AppImage.zsync`
//!   (`latest`, or a fixed tag)

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Where to look for a newer version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum UpdateSource {
    /// A `.zsync` file at a fixed address.
    Zsync { url: String },
    /// A `.zsync` file among the assets of a GitHub release.
    GithubRelease {
        owner: String,
        repo: String,
        tag: String,
        pattern: String,
    },
}

/// How much of the start of an AppImage holds its `.upd_info` section (in
/// the runtime, which comes first).
pub const HEAD_BYTES: usize = 8 * 1024 * 1024;

/// Reads and parses `.upd_info`. `None` when the AppImage has none, or
/// uses a form SAM does not know.
pub fn read(path: &Path) -> Option<UpdateSource> {
    let mut head = Vec::new();
    File::open(path)
        .ok()?
        .take(HEAD_BYTES as u64)
        .read_to_end(&mut head)
        .ok()?;
    from_head(&head)
}

/// Parses `.upd_info` from the first bytes of an AppImage (at most
/// [`HEAD_BYTES`] are looked at). For a caller that has already read the
/// file and checked what it read: the address then comes from exactly the
/// bytes that were checked, not from a second read that another program
/// could change in between (review B2 S6, R88).
pub fn from_head(head: &[u8]) -> Option<UpdateSource> {
    let head = head.get(..HEAD_BYTES).unwrap_or(head);
    let elf = goblin::elf::Elf::parse(head).ok()?;
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".upd_info"))?;
    let (off, size) = (sh.sh_offset as usize, sh.sh_size as usize);
    let raw = head.get(off..off.checked_add(size)?)?;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    parse(std::str::from_utf8(&raw[..end]).ok()?)
}

/// Writes `info` into the `.upd_info` section of an AppImage runtime (the
/// AppImage type 2 runtime reserves 1024 bytes for it). Used when building
/// SAM's own AppImage.
pub fn write(path: &Path, info: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::{Seek, SeekFrom, Write};
    anyhow::ensure!(
        parse(info).is_some(),
        "{}",
        sam_core::i18n::trf(
            "not an update information string SAM understands: {info}",
            &[("info", &info)]
        )
    );
    let data = std::fs::read(path)?;
    let elf = goblin::elf::Elf::parse(&data).context(sam_core::i18n::tr("not an ELF file"))?;
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".upd_info"))
        .context(sam_core::i18n::tr("the runtime has no .upd_info section"))?;
    anyhow::ensure!(
        info.len() < sh.sh_size as usize,
        ".upd_info holds only {} bytes",
        sh.sh_size
    );
    let mut buf = vec![0u8; sh.sh_size as usize];
    buf[..info.len()].copy_from_slice(info.as_bytes());
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.seek(SeekFrom::Start(sh.sh_offset))?;
    f.write_all(&buf)?;
    Ok(())
}

/// Parses an update information string.
pub fn parse(s: &str) -> Option<UpdateSource> {
    let s = s.trim();
    let parts: Vec<&str> = s.split('|').collect();
    match parts.as_slice() {
        ["zsync", url] if !url.is_empty() => Some(UpdateSource::Zsync {
            url: url.to_string(),
        }),
        ["gh-releases-zsync", owner, repo, tag, pattern] => {
            // Names only: they become parts of a GitHub API address. "." and
            // ".." are not names: they would climb in the address
            // (`repos/../..`, audit I-F13).
            let safe = |p: &str| {
                !p.is_empty()
                    && p != "."
                    && p != ".."
                    && p.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            };
            let pattern_ok = !pattern.is_empty() && !pattern.contains('/');
            (safe(owner) && safe(repo) && safe(tag) && pattern_ok).then(|| {
                UpdateSource::GithubRelease {
                    owner: owner.to_string(),
                    repo: repo.to_string(),
                    tag: tag.to_string(),
                    pattern: pattern.to_string(),
                }
            })
        }
        _ => None,
    }
}

/// `*` matches any run of characters (the only wildcard appimagetool uses).
pub fn matches(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !name.starts_with(first) || !name.ends_with(last) || name.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both forms of update information (a direct zsync address and GitHub releases) are understood.
    #[test]
    fn both_forms_of_update_information_are_understood() {
        assert_eq!(
            parse("zsync|https://example.org/App.AppImage.zsync"),
            Some(UpdateSource::Zsync {
                url: "https://example.org/App.AppImage.zsync".into()
            })
        );
        assert_eq!(
            parse("gh-releases-zsync|neovim|neovim|latest|nvim-linux-x86_64.appimage.zsync"),
            Some(UpdateSource::GithubRelease {
                owner: "neovim".into(),
                repo: "neovim".into(),
                tag: "latest".into(),
                pattern: "nvim-linux-x86_64.appimage.zsync".into()
            })
        );
        assert_eq!(parse("pling-v1-zsync|1234|App.zsync"), None);
        assert_eq!(
            parse("gh-releases-zsync|a/../b|repo|latest|x.zsync"),
            None,
            "no paths in owner"
        );
        assert_eq!(parse(""), None);
        // "." and ".." would climb in the GitHub API address (audit I-F13).
        for bad in [
            "gh-releases-zsync|..|repo|latest|x.zsync",
            "gh-releases-zsync|owner|..|latest|x.zsync",
            "gh-releases-zsync|owner|repo|..|x.zsync",
            "gh-releases-zsync|.|repo|latest|x.zsync",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        assert!(
            parse("gh-releases-zsync|my.org|repo.rs|v1.2|x.zsync").is_some(),
            "dots inside names stay allowed"
        );
    }

    /// Wildcards in update information match the right file name and not the build for another processor.
    #[test]
    fn update_wildcards_match_only_the_right_build() {
        assert!(matches(
            "KeePassXC-*-x86_64.AppImage.zsync",
            "KeePassXC-2.8.1-x86_64.AppImage.zsync"
        ));
        assert!(matches(
            "App-*x86_64.AppImage.zsync",
            "App-1.2-x86_64.AppImage.zsync"
        ));
        assert!(!matches(
            "App-*x86_64.AppImage.zsync",
            "App-1.2-aarch64.AppImage.zsync"
        ));
        assert!(matches("exact.zsync", "exact.zsync"));
        assert!(!matches("a*b*c", "ab"));
    }
}
