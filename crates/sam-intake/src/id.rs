//! App id generation.
//!
//! `appimage-<slug>-<hash>`: human-readable slug from the app name (or file
//! name without version/arch noise) plus a checksum prefix. The hash grows
//! until the id is unique.

use std::path::Path;

use sam_core::util::slugify;

const NOISE: &[&str] = &[
    "x86", "64", "x86-64", "x64", "amd64", "aarch64", "arm64", "armhf", "i386", "i686", "linux", "appimage", "release", "stable", "portable", "glibc", "setup",
];

pub fn slug_from_filename(path: &Path) -> String {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let words: Vec<String> = stem.split(['-', '_', '.', ' ', '+']).map(|w| w.to_lowercase()).filter(|w| !w.is_empty()).collect();
    let mut kept = Vec::new();
    for w in &words {
        let is_version =
            w.chars().next().is_some_and(|c| c.is_ascii_digit()) || (w.starts_with('v') && w[1..].chars().next().is_some_and(|c| c.is_ascii_digit()));
        if is_version || NOISE.contains(&w.as_str()) {
            // Stop at the first version token: everything after is noise.
            if is_version && !kept.is_empty() {
                break;
            }
            continue;
        }
        kept.push(w.clone());
    }
    slugify(&kept.join("-"))
}

pub fn generate_id(name: &str, source: &Path, sha256: &str, taken: impl Fn(&str) -> bool) -> String {
    let mut slug = slugify(name);
    if slug.is_empty() {
        slug = slug_from_filename(source);
    }
    if slug.is_empty() {
        slug = "app".into();
    }
    if slug.len() > 32 {
        slug.truncate(32);
        while slug.ends_with('-') {
            slug.pop();
        }
    }
    let hash: String = if sha256.len() >= 8 { sha256.to_string() } else { format!("{sha256:0>16}") };
    let mut len = 4;
    loop {
        let id = format!("appimage-{slug}-{}", &hash[..len.min(hash.len())]);
        if !taken(&id) || len >= hash.len() {
            return id;
        }
        len += 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A readable name is taken from an AppImage's file name, without version and architecture.
    #[test]
    fn a_readable_name_is_taken_from_the_file_name() {
        assert_eq!(slug_from_filename(Path::new("krita-5.2.6-x86_64.AppImage")), "krita");
        assert_eq!(slug_from_filename(Path::new("Obsidian-1.6.7.AppImage")), "obsidian");
        assert_eq!(slug_from_filename(Path::new("Some_Great_App-v2-linux-amd64.AppImage")), "some-great-app");
    }

    /// App IDs are stable and unique, also when two AppImages have the same name.
    #[test]
    fn app_ids_stay_unique_when_names_collide() {
        let id = generate_id("Krita", Path::new("x.AppImage"), "9f3c11223344", |_| false);
        assert_eq!(id, "appimage-krita-9f3c");
        let id2 = generate_id("Krita", Path::new("x.AppImage"), "9f3c11223344", |i| i == "appimage-krita-9f3c");
        assert_eq!(id2, "appimage-krita-9f3c11");
        let id3 = generate_id("", Path::new("krita-5.2.AppImage"), "abcd0000", |_| false);
        assert_eq!(id3, "appimage-krita-abcd");
    }
}
