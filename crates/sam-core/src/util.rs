//! Small helpers shared across crates.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Current time as unix seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix seconds as calendar time: local (`localtime_r`) or UTC (`gmtime_r`).
/// The C library knows the time zone; SAM needs no date library for this.
fn calendar(ts: i64, local: bool) -> Option<libc::tm> {
    // time_t is 64 bits on the systems SAM runs on; a conversion keeps it
    // correct where it is not.
    #[allow(clippy::useless_conversion)]
    let t: libc::time_t = ts.try_into().ok()?;
    // SAFETY: tm is a plain C struct for which all-zero bytes are valid.
    let mut out: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; the _r variants write
    // only into `out` and keep no reference to it.
    let r = unsafe {
        if local {
            libc::localtime_r(&t, &mut out)
        } else {
            libc::gmtime_r(&t, &mut out)
        }
    };
    (!r.is_null()).then_some(out)
}

/// Format unix seconds as a local, human readable timestamp.
pub fn format_ts(ts: i64) -> String {
    match calendar(ts, true) {
        Some(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.tm_year + 1900,
            t.tm_mon + 1,
            t.tm_mday,
            t.tm_hour,
            t.tm_min,
            t.tm_sec
        ),
        None => ts.to_string(),
    }
}

/// Unix seconds as an e-mail/HTTP style UTC date, "Thu, 01 Jan 1970 00:00:00
/// +0000" (English names, as the formats require).
pub fn format_utc_date(ts: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    match calendar(ts, false) {
        Some(t) => format!(
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
            DAYS.get(t.tm_wday as usize).unwrap_or(&"Sun"),
            t.tm_mday,
            MONTHS.get(t.tm_mon as usize).unwrap_or(&"Jan"),
            t.tm_year + 1900,
            t.tm_hour,
            t.tm_min,
            t.tm_sec
        ),
        None => ts.to_string(),
    }
}

/// Expand a leading `~` / `~/` and `$HOME` to the user's home directory.
pub fn expand_home(p: &str) -> PathBuf {
    let home = home_dir();
    if p == "~" {
        return home;
    }
    if let Some(rest) = p.strip_prefix("~/") {
        return home.join(rest);
    }
    if let Some(rest) = p.strip_prefix("$HOME/") {
        return home.join(rest);
    }
    PathBuf::from(p)
}

/// Replace the home prefix of a path with `~` for display.
pub fn tildify(p: &Path) -> String {
    let home = home_dir();
    match p.strip_prefix(&home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".into(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Write a file atomically (write to temp file in same dir, then rename).
/// Reads at most `limit` bytes of a regular file. Files inside an unpacked
/// AppImage are the AppImage's choice: a link to `/dev/zero` or a huge file
/// must not fill SAM's memory. The type is checked on the opened file, so a
/// swap between check and read changes nothing.
pub fn read_regular(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut data = Vec::with_capacity(meta.len().min(limit) as usize);
    f.take(limit).read_to_end(&mut data)?;
    Ok(data)
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .context(crate::i18n::tr("path has no parent"))?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(OsStr::to_str).unwrap_or("file"),
        std::process::id()
    ));
    {
        let mut f =
            fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

/// The AppImage file SAM itself runs from, when this program was started
/// from SAM's own AppImage (its runtime sets `$APPIMAGE` and `$APPDIR`, and
/// the program lies inside `$APPDIR`). Menu entries must then call the
/// AppImage file: the folder it is mounted at changes on every start.
pub fn own_appimage() -> Option<PathBuf> {
    let appimage = PathBuf::from(std::env::var_os("APPIMAGE")?);
    let appdir = PathBuf::from(std::env::var_os("APPDIR")?);
    let exe = std::env::current_exe().ok()?;
    (exe.starts_with(&appdir) && appimage.is_file()).then_some(appimage)
}

/// Find an executable in `$PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return is_executable(&p).then_some(p);
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| is_executable(p))
}

pub fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Quote a single argument for display as a POSIX shell word.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

pub fn shell_join<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .map(|a| shell_quote(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Lowercase ASCII slug: `Krita 5.2 (x86_64)` -> `krita-5-2-x86-64`.
/// Text from an untrusted source (an AppImage's desktop file, an app's
/// output, a file name) made safe to show: control characters removed,
/// length capped, and `<`/`>` replaced by look-alikes so no UI toolkit can
/// mistake it for markup (some render HTML automatically, including remote
/// images).
pub fn display_safe(s: &str, max_chars: usize) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '<' => '‹',
            '>' => '›',
            c => c,
        })
        .take(max_chars)
        .collect();
    if s.chars().filter(|c| !c.is_control()).count() > max_chars {
        out.push('…');
    }
    out
}

pub fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Times are shown without a date library: UTC dates exactly, local
    /// times in the computer's own zone and shape (chrono was dropped when
    /// it became unmaintained, RUSTSEC-2026-0543).
    #[test]
    fn times_are_shown_without_a_date_library() {
        assert_eq!(format_utc_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(
            format_utc_date(1_794_885_600),
            "Tue, 17 Nov 2026 03:20:00 +0000"
        );
        assert_eq!(
            format_utc_date(951_782_400),
            "Tue, 29 Feb 2000 00:00:00 +0000",
            "a leap day"
        );
        let local = format_ts(1_794_885_600);
        let b = local.as_bytes();
        assert_eq!(b.len(), 19, "{local}");
        assert!(local.starts_with("2026-11-1"), "{local}");
        assert!(
            b[4] == b'-' && b[7] == b'-' && b[10] == b' ' && b[13] == b':' && b[16] == b':',
            "{local}"
        );
        let n = now();
        assert!(n > 1_794_000_000 && n < 4_000_000_000, "{n}");
    }

    /// A link to a device that never ends, or a file larger than the limit,
    /// cannot fill SAM's memory (regression: an AppImage whose AppRun links
    /// to /dev/zero made adding it grow without end).
    #[test]
    fn reading_a_file_of_an_appimage_is_bounded() {
        let t = tempfile::tempdir().unwrap();
        let link = t.path().join("AppRun");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert!(read_regular(&link, 1024).is_err(), "a device is not read");
        let big = t.path().join("big");
        std::fs::write(&big, vec![7u8; 5000]).unwrap();
        assert_eq!(read_regular(&big, 1000).unwrap().len(), 1000);
        assert_eq!(read_regular(&big, 9000).unwrap().len(), 5000);
    }

    /// Names become safe identifiers made of lowercase letters, digits and dashes.
    #[test]
    fn names_become_safe_identifiers() {
        assert_eq!(slugify("Krita 5.2 (x86_64)"), "krita-5-2-x86-64");
        assert_eq!(slugify("--Hello__World--"), "hello-world");
    }

    /// Shell quoting keeps spaces, quotes and empty strings intact.
    #[test]
    fn shell_quoting_keeps_spaces_and_quotes_intact() {
        assert_eq!(shell_quote("abc"), "abc");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }
}

#[cfg(test)]
mod display_safe_tests {
    use super::display_safe;

    /// Text from an app is shown without markup or control characters, and long text is shortened.
    #[test]
    fn neutralizes_markup_and_controls() {
        assert_eq!(display_safe("<b>X</b>\u{7}", 100), "‹b›X‹/b›");
        assert_eq!(display_safe("abcdef", 3), "abc…");
    }
}
