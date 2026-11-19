// SPDX-License-Identifier: GPL-3.0-or-later
//! App icons: which ones SAM hands to image decoders at all.

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

/// The largest icon SAM takes from an app.
pub const MAX_ICON_BYTES: usize = 1024 * 1024;
/// The largest width and height of a PNG icon SAM shows.
const MAX_ICON_SIDE: u32 = 1024;
/// The largest SVG icon SAM shows.
const MAX_SVG_BYTES: usize = 512 * 1024;

/// An app's icon in a form that is safe to hand to the desktop's image
/// decoders: a PNG of at most 1024×1024 pixels (read from its header, so a
/// tiny file announcing a huge picture, a "decode bomb", is refused before
/// anything is decoded) or a small SVG, within [`MAX_ICON_BYTES`]. XPM,
/// whose decoders have a long list of security bugs, is not taken (audit
/// G-F8, I-F18).
pub fn safe_icon(data: &[u8]) -> Option<IconFormat> {
    if data.is_empty() || data.len() > MAX_ICON_BYTES {
        return None;
    }
    match sniff_icon(data)? {
        IconFormat::Png => {
            let side = |at: usize| Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?));
            let (w, h) = (side(16)?, side(20)?);
            (data.get(12..16) == Some(b"IHDR")
                && (1..=MAX_ICON_SIDE).contains(&w)
                && (1..=MAX_ICON_SIDE).contains(&h))
            .then_some(IconFormat::Png)
        }
        IconFormat::Svg => (data.len() <= MAX_SVG_BYTES).then_some(IconFormat::Svg),
        IconFormat::Xpm => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A PNG of `w` × `h` pixels as far as its header says, `extra` bytes long.
    fn png(w: u32, h: u32, extra: usize) -> Vec<u8> {
        let mut d = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        d.extend(w.to_be_bytes());
        d.extend(h.to_be_bytes());
        d.extend([8, 6, 0, 0, 0]);
        d.resize(d.len() + extra, 0);
        d
    }

    /// Only icons that are safe to decode reach the desktop's image code:
    /// a PNG whose header announces more than 1024×1024 pixels (a decode
    /// bomb: a small file that asks for gigabytes) is refused before
    /// anything decodes it, and so are oversized files, large SVGs and XPM
    /// (audit G-F8, I-F18).
    #[test]
    fn only_icons_that_are_safe_to_decode_are_taken() {
        assert_eq!(safe_icon(&png(256, 256, 100)), Some(IconFormat::Png));
        assert_eq!(safe_icon(&png(1024, 1024, 0)), Some(IconFormat::Png));
        assert_eq!(safe_icon(&png(65535, 65535, 0)), None, "a decode bomb");
        assert_eq!(safe_icon(&png(1025, 16, 0)), None);
        assert_eq!(safe_icon(&png(16, 0, 0)), None);
        assert_eq!(
            safe_icon(&png(16, 16, MAX_ICON_BYTES)),
            None,
            "too big a file"
        );
        let mut no_ihdr = png(16, 16, 0);
        no_ihdr[12..16].copy_from_slice(b"IDAT");
        assert_eq!(safe_icon(&no_ihdr), None);
        assert_eq!(safe_icon(b"\x89PNG\r\n\x1a\n"), None, "cut short");
        let svg = b"<svg xmlns='http://www.w3.org/2000/svg'/>".to_vec();
        assert_eq!(safe_icon(&svg), Some(IconFormat::Svg));
        let mut big = svg.clone();
        big.resize(600 * 1024, b' ');
        assert_eq!(safe_icon(&big), None);
        assert_eq!(safe_icon(b"/* XPM */\nstatic char *x[] = {};"), None);
        assert_eq!(safe_icon(b""), None);
    }
}
