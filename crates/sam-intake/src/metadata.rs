//! Desktop metadata and icon discovery.

use sam_core::util::display_safe;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use sam_core::AppImageMetadata;

use crate::normalize::safe_resolve;

/// Parse the `[Desktop Entry]` group of a .desktop file (unlocalized keys only).
pub fn parse_desktop(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut in_entry = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            if !k.contains('[') {
                map.entry(k.to_string())
                    .or_insert_with(|| unescape(v.trim()));
            }
        }
    }
    map
}

fn unescape(v: &str) -> String {
    let mut out = String::new();
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('s') => out.push(' '),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some(o) => {
                    out.push('\\');
                    out.push(o);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn split_list(v: Option<&String>) -> Vec<String> {
    v.map(|s| {
        s.split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    })
    .unwrap_or_default()
}

/// Locate the desktop file: AppDir root first, then usr/share/applications.
pub fn find_desktop_file(appdir: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    for dir in [Path::new(""), Path::new("usr/share/applications")] {
        if let Ok(rd) = fs::read_dir(appdir.join(dir)) {
            let mut v: Vec<PathBuf> = rd
                .flatten()
                .map(|e| dir.join(e.file_name()))
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("desktop"))
                .collect();
            v.sort();
            candidates.extend(v);
        }
    }
    candidates
        .into_iter()
        .find(|rel| safe_resolve(appdir, rel).is_some_and(|p| p.is_file()))
}

pub fn read_metadata(appdir: &Path) -> Result<AppImageMetadata> {
    let Some(rel) = find_desktop_file(appdir) else {
        return Ok(AppImageMetadata::default());
    };
    let Some(path) = safe_resolve(appdir, &rel) else {
        return Ok(AppImageMetadata::default());
    };
    // The first 256 KiB, read as such (not the whole file first).
    let text =
        String::from_utf8_lossy(&sam_core::util::read_regular(&path, 256 * 1024)?).into_owned();
    Ok(metadata_from_desktop(&text, &rel.display().to_string()))
}

/// Metadata from the text of an AppImage's top-level desktop file.
/// `type/subtype` made of safe characters only.
fn valid_mime(t: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-._".contains(c))
    };
    t.split_once('/').is_some_and(|(a, b)| ok(a) && ok(b))
}

pub fn metadata_from_desktop(text: &str, rel: &str) -> AppImageMetadata {
    let mut md = AppImageMetadata::default();
    let m = parse_desktop(text);
    md.desktop_file = Some(rel.to_string());
    // Everything here comes from the (untrusted) AppImage: neutralize
    // markup and control characters and cap lengths before it is stored or
    // shown anywhere.
    let safe = |k: &str, max: usize| m.get(k).map(|v| display_safe(v, max)).unwrap_or_default();
    md.name = safe("Name", 128);
    md.comment = m
        .get("Comment")
        .or_else(|| m.get("GenericName"))
        .map(|v| display_safe(v, 300))
        .unwrap_or_default();
    md.icon_name = m
        .get("Icon")
        .map(|v| v.chars().filter(|c| !c.is_control()).take(256).collect())
        .unwrap_or_default();
    md.categories = split_list(m.get("Categories"))
        .iter()
        .take(32)
        .map(|c| display_safe(c, 64))
        .collect();
    md.mime_types = split_list(m.get("MimeType"))
        .into_iter()
        .take(256)
        .filter(|t| valid_mime(t))
        .collect();
    md.exec = safe("Exec", 512);
    md.version = safe("X-AppImage-Version", 64);
    md.terminal = m
        .get("Terminal")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    md.startup_wm_class = safe("StartupWMClass", 128);
    md
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconFormat {
    Png,
    Svg,
    Xpm,
}

impl IconFormat {
    pub fn ext(self) -> &'static str {
        match self {
            IconFormat::Png => "png",
            IconFormat::Svg => "svg",
            IconFormat::Xpm => "xpm",
        }
    }
}

pub fn sniff_icon(data: &[u8]) -> Option<IconFormat> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(IconFormat::Png);
    }
    let head = String::from_utf8_lossy(&data[..data.len().min(2048)]).to_lowercase();
    if head.contains("<svg") {
        return Some(IconFormat::Svg);
    }
    if head.contains("/* xpm */") {
        return Some(IconFormat::Xpm);
    }
    None
}

/// Where an AppDir may keep the icon named in its desktop file, best first.
pub fn icon_candidates(icon_name: &str) -> Vec<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    let name = Path::new(icon_name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !name.is_empty() {
        cands.push(PathBuf::from(&name));
        for ext in ["png", "svg", "svgz", "xpm"] {
            cands.push(PathBuf::from(format!("{name}.{ext}")));
        }
        for size in [
            "512x512", "256x256", "scalable", "192x192", "128x128", "96x96", "64x64", "48x48",
            "32x32",
        ] {
            for ext in ["png", "svg"] {
                cands.push(PathBuf::from(format!(
                    "usr/share/icons/hicolor/{size}/apps/{name}.{ext}"
                )));
            }
        }
        for ext in ["png", "svg", "xpm"] {
            cands.push(PathBuf::from(format!("usr/share/pixmaps/{name}.{ext}")));
        }
    }
    cands.push(PathBuf::from(".DirIcon"));
    cands
}

/// Find the best icon inside the AppDir.
pub fn find_icon(appdir: &Path, icon_name: &str) -> Option<(PathBuf, IconFormat)> {
    for rel in icon_candidates(icon_name) {
        let Some(p) = safe_resolve(appdir, &rel) else {
            continue;
        };
        let Ok(meta) = fs::metadata(&p) else { continue };
        if !meta.is_file() || meta.len() == 0 || meta.len() > 10 * 1024 * 1024 {
            continue;
        }
        let Ok(data) = fs::read(&p) else { continue };
        if let Some(fmt) = sniff_icon(&data) {
            return Some((p, fmt));
        }
    }
    None
}

/// Copy the icon into SAM's caches. Returns the cached icon path.
pub fn cache_icon(
    appdir: &Path,
    icon_name: &str,
    id: &str,
    icons_dir: &Path,
    extraction_root: &Path,
) -> Result<Option<PathBuf>> {
    let Some((src, fmt)) = find_icon(appdir, icon_name) else {
        return Ok(None);
    };
    fs::create_dir_all(icons_dir)?;
    // Remove stale icons with other extensions.
    for ext in ["png", "svg", "xpm"] {
        let _ = fs::remove_file(icons_dir.join(format!("sam-{id}.{ext}")));
    }
    let dest = icons_dir.join(format!("sam-{id}.{}", fmt.ext()));
    fs::copy(&src, &dest)?;
    if let Ok(data) = fs::read(&src) {
        let _ =
            sam_core::util::write_new(&extraction_root.join(format!("icon.{}", fmt.ext())), &data);
    }
    Ok(Some(dest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The desktop file inside an AppImage is read with name, translations, categories and file types.
    #[test]
    fn the_desktop_file_inside_an_appimage_is_read() {
        let t = "[Desktop Entry]\nName=Krita\nName[de]=Krita DE\nComment=Digital painting\nIcon=krita\nExec=krita %F\nCategories=Graphics;2DGraphics;\nMimeType=image/png;\n[Desktop Action new]\nName=New\n";
        let m = parse_desktop(t);
        assert_eq!(m["Name"], "Krita");
        assert_eq!(m["Exec"], "krita %F");
        assert_eq!(
            split_list(m.get("Categories")),
            vec!["Graphics", "2DGraphics"]
        );
    }

    /// Name, icon and categories are read from the unpacked app.
    #[test]
    fn reads_metadata_and_icon() {
        let d = tempfile::tempdir().unwrap();
        fs::write(
            d.path().join("hello.desktop"),
            "[Desktop Entry]\nName=Hello\nIcon=hello\nExec=hello\nCategories=Utility;\n",
        )
        .unwrap();
        fs::write(d.path().join("hello.png"), crate::testkit::TINY_PNG).unwrap();
        let md = read_metadata(d.path()).unwrap();
        assert_eq!(md.name, "Hello");
        assert_eq!(md.categories, vec!["Utility"]);
        let (p, fmt) = find_icon(d.path(), "hello").unwrap();
        assert_eq!(fmt, IconFormat::Png);
        assert!(p.ends_with("hello.png"));
    }
}
