//! Menu entries that other tools made for AppImages (AppImageLauncher,
//! Gear Lever, hand-written ones). They start the AppImage **without** a
//! sandbox, so SAM can hide them once the app has a sandboxed launcher, and
//! put them back when the sandbox is removed.
//!
//! - A user-level entry (`~/.local/share/applications`) is edited in place:
//!   `NoDisplay=true` plus an `X-SAM-HiddenBy=<app id>` marker.
//! - A system-level entry is never touched; SAM writes a user-level override
//!   with the same file name instead, which the desktop prefers.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sam_core::util::atomic_write;
use sam_core::HiddenEntry;

use crate::desktop::refresh_desktop_database;

const GROUP: &str = "[Desktop Entry]";
const MARKER: &str = "X-SAM-HiddenBy";

/// A menu entry that starts an AppImage directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignEntry {
    pub file: PathBuf,
    pub appimage: PathBuf,
    pub name: String,
    /// Already hidden by SAM (for this app id).
    pub hidden_by: Option<String>,
    /// Hidden by the user or the tool that made it (not by SAM).
    pub hidden_elsewhere: bool,
}

/// Where menu entries live, user level first.
pub fn entry_dirs(user_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![user_dir.to_path_buf()];
    let data_dirs = std::env::var("XDG_DATA_DIRS").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    for d in data_dirs.split(':').filter(|d| !d.is_empty()) {
        dirs.push(Path::new(d).join("applications"));
    }
    dirs.dedup();
    dirs
}

/// All menu entries (not SAM's own) whose command is an AppImage file.
/// An override in `user_dir` shadows the system entry of the same name.
pub fn foreign_entries(user_dir: &Path) -> Vec<ForeignEntry> {
    let mut out: Vec<ForeignEntry> = Vec::new();
    let mut seen_names = std::collections::HashSet::new();
    for dir in entry_dirs(user_dir) {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "desktop")).collect();
        files.sort();
        for file in files {
            let name = file.file_name().map(|n| n.to_os_string()).unwrap_or_default();
            if !seen_names.insert(name) {
                continue; // shadowed by a user-level file
            }
            let Ok(text) = fs::read_to_string(&file) else { continue };
            let keys = group_keys(&text);
            let get = |k: &str| keys.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());
            if get("X-SAM-Managed").is_some() {
                continue;
            }
            let Some(appimage) = get("TryExec").and_then(appimage_in).or_else(|| get("Exec").and_then(appimage_in)) else { continue };
            let hidden_by = get(MARKER).map(str::to_string);
            let hidden_elsewhere = hidden_by.is_none()
                && (get("NoDisplay").is_some_and(|v| v.eq_ignore_ascii_case("true")) || get("Hidden").is_some_and(|v| v.eq_ignore_ascii_case("true")));
            out.push(ForeignEntry { file, appimage, name: get("Name").unwrap_or_default().to_string(), hidden_by, hidden_elsewhere });
        }
    }
    out
}

/// The AppImage an `Exec=`/`TryExec=` value starts, if any.
fn appimage_in(cmd: &str) -> Option<PathBuf> {
    for tok in split_exec(cmd) {
        if tok.starts_with('%') || (tok.contains('=') && !tok.starts_with('/')) || tok == "env" {
            continue;
        }
        let p = PathBuf::from(&tok);
        if !p.is_absolute() {
            return None; // a command on $PATH, not an AppImage file
        }
        let is_appimage = tok.to_lowercase().ends_with(".appimage") || sam_detect::appimage::looks_like_appimage(&p);
        return is_appimage.then(|| fs::canonicalize(&p).unwrap_or(p));
    }
    None
}

/// Split an Exec value into arguments (desktop entry quoting rules).
fn split_exec(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut escaped, mut any) = (false, false, false);
    for c in cmd.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
        } else if c == '\\' && quoted {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
            any = true;
        } else if c.is_whitespace() && !quoted {
            if any || !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
                any = false;
            }
        } else {
            cur.push(c);
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `key=value` pairs of the `[Desktop Entry]` group (no localized keys).
fn group_keys(text: &str) -> Vec<(String, String)> {
    let mut in_group = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_group = t == GROUP;
        } else if in_group {
            if let Some((k, v)) = t.split_once('=') {
                if !k.contains('[') {
                    out.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        }
    }
    out
}

/// Rewrite the `[Desktop Entry]` group: drop `NoDisplay` and SAM's marker,
/// then insert `extra` lines right after the group header.
fn rewrite(text: &str, extra: &[String]) -> (String, Option<String>) {
    let mut out = String::new();
    let mut in_group = false;
    let mut previous = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_group = t == GROUP;
            out.push_str(line);
            out.push('\n');
            if in_group {
                for e in extra {
                    out.push_str(e);
                    out.push('\n');
                }
            }
            continue;
        }
        if in_group {
            if let Some((k, v)) = t.split_once('=') {
                match k.trim() {
                    "NoDisplay" => {
                        previous = Some(v.trim().to_string());
                        continue;
                    }
                    MARKER => continue,
                    _ => {}
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, previous)
}

/// Hide a foreign entry from the menu on behalf of `app_id`.
pub fn hide(entry: &Path, user_dir: &Path, app_id: &str) -> Result<HiddenEntry> {
    let text = fs::read_to_string(entry).with_context(|| format!("reading {}", entry.display()))?;
    if !text.contains(GROUP) {
        bail!("{} is not a desktop entry", entry.display());
    }
    let extra = vec!["NoDisplay=true".to_string(), format!("{MARKER}={app_id}")];
    let (new_text, previous) = rewrite(&text, &extra);
    let in_user_dir = entry.parent().is_some_and(|d| same_dir(d, user_dir));
    let modified = if in_user_dir { entry.to_path_buf() } else { user_dir.join(entry.file_name().context("entry without file name")?) };
    if !in_user_dir && modified.exists() {
        bail!("{} already exists; not overwriting it", modified.display());
    }
    fs::create_dir_all(user_dir)?;
    atomic_write(&modified, new_text.as_bytes())?;
    refresh_desktop_database(user_dir);
    Ok(HiddenEntry { original: entry.to_path_buf(), modified, created_override: !in_user_dir, previous_nodisplay: if in_user_dir { previous } else { None } })
}

/// Undo [`hide`]. Leaves files alone that no longer carry SAM's marker for
/// this app (the user or another tool changed them since).
pub fn restore(h: &HiddenEntry, app_id: &str) -> Result<()> {
    let Ok(text) = fs::read_to_string(&h.modified) else { return Ok(()) };
    if !group_keys(&text).iter().any(|(k, v)| k == MARKER && v == app_id) {
        return Ok(());
    }
    if h.created_override {
        fs::remove_file(&h.modified)?;
    } else {
        let extra: Vec<String> = h.previous_nodisplay.iter().map(|v| format!("NoDisplay={v}")).collect();
        atomic_write(&h.modified, rewrite(&text, &extra).0.as_bytes())?;
    }
    if let Some(dir) = h.modified.parent() {
        refresh_desktop_database(dir);
    }
    Ok(())
}

fn same_dir(a: &Path, b: &Path) -> bool {
    fs::canonicalize(a).ok().zip(fs::canonicalize(b).ok()).is_some_and(|(a, b)| a == b) || a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_appimage(dir: &Path) -> PathBuf {
        let p = dir.join("Tool.AppImage");
        fs::write(&p, b"\x7fELF").unwrap();
        fs::canonicalize(p).unwrap()
    }

    #[test]
    fn exec_parsing() {
        assert_eq!(split_exec(r#""/a b/X.AppImage" --flag %U"#), vec!["/a b/X.AppImage", "--flag", "%U"]);
        assert_eq!(appimage_in("firefox %u"), None);
        assert_eq!(appimage_in("env FOO=1 /nope/X.AppImage %U"), Some(PathBuf::from("/nope/X.AppImage")));
    }

    #[test]
    fn hide_and_restore_user_entry() {
        let d = tempfile::tempdir().unwrap();
        let apps = d.path().join("applications");
        fs::create_dir_all(&apps).unwrap();
        let img = fake_appimage(d.path());
        let entry = apps.join("appimagekit_x-Tool.desktop");
        let original = format!("[Desktop Entry]\nName=Tool\nExec=\"{}\" %U\nNoDisplay=false\n\n[Desktop Action New]\nName=New\nNoDisplay=x\n", img.display());
        fs::write(&entry, &original).unwrap();

        let found = foreign_entries(&apps);
        let f = found.iter().find(|f| f.file == entry).expect("entry found");
        assert_eq!(f.appimage, img);
        assert!(f.hidden_by.is_none() && !f.hidden_elsewhere);

        let h = hide(&entry, &apps, "appimage-tool-1").unwrap();
        assert!(!h.created_override);
        let hidden = fs::read_to_string(&entry).unwrap();
        assert!(hidden.contains("NoDisplay=true\nX-SAM-HiddenBy=appimage-tool-1"));
        assert!(hidden.contains("[Desktop Action New]\nName=New\nNoDisplay=x"), "other groups untouched");
        assert_eq!(foreign_entries(&apps).iter().find(|f| f.file == entry).unwrap().hidden_by.as_deref(), Some("appimage-tool-1"));

        restore(&h, "appimage-tool-1").unwrap();
        let back = fs::read_to_string(&entry).unwrap();
        assert!(back.contains("NoDisplay=false") && !back.contains("NoDisplay=true") && !back.contains(MARKER), "{back}");
    }

    #[test]
    fn system_entry_gets_override() {
        let d = tempfile::tempdir().unwrap();
        let (sys, user) = (d.path().join("sys"), d.path().join("user"));
        fs::create_dir_all(&sys).unwrap();
        let img = fake_appimage(d.path());
        let entry = sys.join("tool.desktop");
        fs::write(&entry, format!("[Desktop Entry]\nName=Tool\nExec={}\n", img.display())).unwrap();
        let h = hide(&entry, &user, "appimage-tool-1").unwrap();
        assert!(h.created_override && h.modified == user.join("tool.desktop"));
        assert_eq!(fs::read_to_string(&entry).unwrap(), format!("[Desktop Entry]\nName=Tool\nExec={}\n", img.display()), "system file untouched");
        restore(&h, "appimage-tool-1").unwrap();
        assert!(!h.modified.exists());
    }
}
