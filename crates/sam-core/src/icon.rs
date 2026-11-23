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

/// The format of an icon, from its first bytes only: a PNG starts with the
/// PNG signature, an SVG is text whose first element is `<svg`, after at
/// most an XML declaration, comments, processing instructions and a
/// DOCTYPE. The desktop's image code chooses its decoder from the content,
/// so a file that merely contains the text `<svg` somewhere (an XPM or ICO
/// with it in a comment or its pixels) is not an SVG: taken as one, it
/// reached the decoders SAM keeps away from (review 2026-11-23, F3).
pub fn sniff_icon(data: &[u8]) -> Option<IconFormat> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(IconFormat::Png);
    }
    if data.starts_with(b"/* XPM */") {
        return Some(IconFormat::Xpm);
    }
    svg_root(data).then_some(IconFormat::Svg)
}

/// Whether `data` is text (UTF-8, no NUL) whose first element is `<svg`.
fn svg_root(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    if text.contains('\0') {
        return false;
    }
    let mut rest = text.strip_prefix('\u{feff}').unwrap_or(text);
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        if let Some(r) = rest.strip_prefix("<?") {
            let Some(end) = r.find("?>") else {
                return false;
            };
            rest = &r[end + 2..];
        } else if let Some(r) = rest.strip_prefix("<!--") {
            let Some(end) = r.find("-->") else {
                return false;
            };
            rest = &r[end + 3..];
        } else if let Some(r) = rest.strip_prefix("<!DOCTYPE") {
            // Up to the closing `>`, past an internal subset in `[...]`.
            let close = match (r.find('['), r.find('>')) {
                (Some(open), Some(gt)) if open < gt => r[open..].find(']').and_then(|e| {
                    let after = open + e + 1;
                    r[after..].find('>').map(|g| after + g)
                }),
                (_, gt) => gt,
            };
            let Some(end) = close else {
                return false;
            };
            rest = &r[end + 1..];
        } else {
            let Some(r) = rest.strip_prefix("<svg") else {
                return false;
            };
            return r.starts_with([' ', '\t', '\r', '\n', '>', '/']);
        }
    }
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
        // Up to the limit itself, a large icon is fine.
        let at_limit = png(1024, 1024, MAX_ICON_BYTES - png(1, 1, 0).len());
        assert_eq!(at_limit.len(), MAX_ICON_BYTES);
        assert_eq!(safe_icon(&at_limit), Some(IconFormat::Png));
        let mut no_ihdr = png(16, 16, 0);
        no_ihdr[12..16].copy_from_slice(b"IDAT");
        assert_eq!(safe_icon(&no_ihdr), None);
        assert_eq!(safe_icon(b"\x89PNG\r\n\x1a\n"), None, "cut short");
        let svg = b"<svg xmlns='http://www.w3.org/2000/svg'/>".to_vec();
        assert_eq!(safe_icon(&svg), Some(IconFormat::Svg));
        let mut big = svg.clone();
        big.resize(600 * 1024, b' ');
        assert_eq!(safe_icon(&big), None);
        big.truncate(400 * 1024);
        assert_eq!(
            safe_icon(&big),
            Some(IconFormat::Svg),
            "a detailed SVG is fine"
        );
        assert_eq!(safe_icon(b"/* XPM */\nstatic char *x[] = {};"), None);
        assert_eq!(safe_icon(b""), None);
    }

    /// Regression (review 2026-11-23, F3): any file with the text `<svg`
    /// in its first 2 KiB counted as an SVG, so an XPM, ICO or TGA icon
    /// carrying it in a comment or its pixels was installed as `.svg` and
    /// reached the desktop's decoder for its real format. Only a file whose
    /// first element is `<svg` is an SVG now; real SVG headers still are.
    #[test]
    fn only_a_real_svg_counts_as_one() {
        // Look-alikes: other formats with the text inside.
        let xpm = b"/* XPM */\n/* <svg */\nstatic char *x[] = {\"1 1 1 1\"};";
        assert_eq!(sniff_icon(xpm), Some(IconFormat::Xpm));
        assert_eq!(safe_icon(xpm), None, "an XPM with <svg in a comment");
        let mut ico = vec![0, 0, 1, 0, 1, 0, 16, 16, 0, 0];
        ico.extend(b"<svg xmlns='http://www.w3.org/2000/svg'/>");
        assert_eq!(safe_icon(&ico), None, "an ICO with <svg in its data");
        let mut tga = vec![0, 0, 2, 0];
        tga.extend(b"<svg>");
        assert_eq!(safe_icon(&tga), None, "a TGA with <svg in its data");
        for fake in [
            &b"GIF89a<svg>"[..],
            b"<html><svg></svg></html>",
            b"text before <svg/>",
            b"<svgfoo/>",
            b"<?xml version='1.0'?><!-- not closed <svg>",
            b"<svg\0>",
            b"<!-- <svg> -->",
        ] {
            assert_eq!(safe_icon(fake), None, "{}", String::from_utf8_lossy(fake));
        }
        // Real SVG headers, as editors write them.
        for real in [
            &b"<svg/>"[..],
            b"\xef\xbb\xbf<svg xmlns='http://www.w3.org/2000/svg'></svg>",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n<!-- Created with Inkscape -->\n\n<svg\n  width=\"48\">",
            b"<?xml version=\"1.0\"?>\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n<svg version=\"1.1\">",
            b"<?xml version=\"1.0\"?>\n<!DOCTYPE svg [\n<!ENTITY ns_svg \"http://www.w3.org/2000/svg\">\n]>\n<svg xmlns=\"&ns_svg;\">",
            b"  \r\n<svg>",
        ] {
            assert_eq!(
                safe_icon(real),
                Some(IconFormat::Svg),
                "{}",
                String::from_utf8_lossy(real)
            );
        }
    }
}
