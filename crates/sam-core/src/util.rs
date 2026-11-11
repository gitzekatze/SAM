//! Small helpers shared across crates.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Current time as unix seconds.
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Format unix seconds as a local, human readable timestamp.
pub fn format_ts(ts: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(ts, 0) {
        chrono::LocalResult::Single(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => ts.to_string(),
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
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

/// Write a file atomically (write to temp file in same dir, then rename).
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(".{}.tmp-{}", path.file_name().and_then(OsStr::to_str).unwrap_or("file"), std::process::id()));
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
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
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| is_executable(p))
}

pub fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// Quote a single argument for display as a POSIX shell word.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c)) {
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
    args.into_iter().map(|a| shell_quote(a.as_ref())).collect::<Vec<_>>().join(" ")
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

    #[test]
    fn slug() {
        assert_eq!(slugify("Krita 5.2 (x86_64)"), "krita-5-2-x86-64");
        assert_eq!(slugify("--Hello__World--"), "hello-world");
    }

    #[test]
    fn quote() {
        assert_eq!(shell_quote("abc"), "abc");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }
}

#[cfg(test)]
mod display_safe_tests {
    use super::display_safe;

    #[test]
    fn neutralizes_markup_and_controls() {
        assert_eq!(display_safe("<b>X</b>\u{7}", 100), "‹b›X‹/b›");
        assert_eq!(display_safe("abcdef", 3), "abc…");
    }
}
