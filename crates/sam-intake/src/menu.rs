//! Menu entries that other tools made for AppImages (AppImageLauncher,
//! Gear Lever, hand-written ones). They start the AppImage **without** a
//! sandbox, so SAM can hide them once the app has a sandboxed launcher, and
//! put them back when the sandbox is removed.
//!
//! - A user-level entry (`~/.local/share/applications`) is edited in place:
//!   `NoDisplay=true`, `Hidden=true` plus an `X-SAM-HiddenBy=<app id>`
//!   marker.
//! - A system-level entry is never touched; SAM writes a user-level override
//!   with the same file name instead, which the desktop prefers.
//!
//! `NoDisplay=true` alone takes an entry out of the menu only: it still
//! opens the files it names in `MimeType=`, and stays the default where
//! `mimeapps.list` names it, so a double-click on such a file started the
//! AppImage without its sandbox (review 2026-11-23, F4). `Hidden=true`
//! counts as if the entry did not exist, for the menu and for opening files
//! alike. For the same reason, an entry another tool marked `NoDisplay`
//! while it still opens files counts as a way to start the app without its
//! sandbox, not as hidden.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sam_core::util::atomic_write;
use sam_core::HiddenEntry;

use crate::desktop::refresh_desktop_database;

const GROUP: &str = "[Desktop Entry]";
const MARKER: &str = "X-SAM-HiddenBy";
const NO_DISPLAY: &str = "NoDisplay";
const HIDDEN: &str = "Hidden";

/// A menu entry that starts an AppImage directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignEntry {
    pub file: PathBuf,
    pub appimage: PathBuf,
    pub name: String,
    /// Already hidden by SAM (for this app id), from the menu and from
    /// opening files. An entry an older SAM took out of the menu only
    /// (`NoDisplay` without `Hidden`) does not count: it still opens files.
    pub hidden_by: Option<String>,
    /// Hidden by the user or the tool that made it (not by SAM): deleted
    /// (`Hidden=true`), or out of the menu and opening no files.
    pub hidden_elsewhere: bool,
}

/// Where menu entries live, user level first.
pub fn entry_dirs(user_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![user_dir.to_path_buf()];
    let data_dirs = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
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
        let mut files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "desktop"))
            .collect();
        files.sort();
        for file in files {
            let name = file
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default();
            if !seen_names.insert(name) {
                continue; // shadowed by a user-level file
            }
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            let keys = group_keys(&text);
            let get = |k: &str| {
                keys.iter()
                    .find(|(key, _)| key == k)
                    .map(|(_, v)| v.as_str())
            };
            if get("X-SAM-Managed").is_some() {
                continue;
            }
            let Some(appimage) = get("TryExec")
                .and_then(appimage_in)
                .or_else(|| get("Exec").and_then(appimage_in))
            else {
                continue;
            };
            let is_true = |k: &str| get(k).is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
            let opens_files = get("MimeType").is_some_and(|v| v.split(';').any(|t| !t.trim().is_empty()));
            let hidden_by = get(MARKER)
                .filter(|_| is_true(HIDDEN))
                .map(str::to_string);
            let hidden_elsewhere = hidden_by.is_none()
                && get(MARKER).is_none()
                && (is_true(HIDDEN) || (is_true(NO_DISPLAY) && !opens_files));
            out.push(ForeignEntry {
                file,
                appimage,
                name: get("Name").unwrap_or_default().to_string(),
                hidden_by,
                hidden_elsewhere,
            });
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
        let is_appimage = tok.to_lowercase().ends_with(".appimage")
            || sam_detect::appimage::looks_like_appimage(&p);
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

/// What [`rewrite`] took out of the `[Desktop Entry]` group.
#[derive(Default)]
struct Removed {
    no_display: Option<String>,
    hidden: Option<String>,
    marker: bool,
}

/// Rewrite the `[Desktop Entry]` group: drop `NoDisplay`, `Hidden` and SAM's
/// marker, then insert `extra` lines right after the group header.
fn rewrite(text: &str, extra: &[String]) -> (String, Removed) {
    let mut out = String::new();
    let mut in_group = false;
    let mut previous = Removed::default();
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
                    NO_DISPLAY => {
                        previous.no_display = Some(v.trim().to_string());
                        continue;
                    }
                    HIDDEN => {
                        previous.hidden = Some(v.trim().to_string());
                        continue;
                    }
                    MARKER => {
                        previous.marker = true;
                        continue;
                    }
                    _ => {}
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, previous)
}

/// Hide a foreign entry on behalf of `app_id`: from the menu and from
/// opening files. On an entry an older SAM took out of the menu only, the
/// `NoDisplay` there is SAM's own, so the value from before is not known
/// here: the earlier record has it (see [`merge_hidden`]).
pub fn hide(entry: &Path, user_dir: &Path, app_id: &str) -> Result<HiddenEntry> {
    let text = fs::read_to_string(entry).with_context(|| format!("reading {}", entry.display()))?;
    if !text.contains(GROUP) {
        bail!(
            "{}",
            sam_core::i18n::trf("{file} is not a menu entry", &[("file", &entry.display())])
        );
    }
    let extra = vec![
        format!("{NO_DISPLAY}=true"),
        format!("{HIDDEN}=true"),
        format!("{MARKER}={app_id}"),
    ];
    let (new_text, previous) = rewrite(&text, &extra);
    let in_user_dir = entry.parent().is_some_and(|d| same_dir(d, user_dir));
    let modified = if in_user_dir {
        entry.to_path_buf()
    } else {
        user_dir.join(
            entry
                .file_name()
                .context(sam_core::i18n::tr("entry without file name"))?,
        )
    };
    if !in_user_dir && modified.exists() {
        bail!(
            "{}",
            sam_core::i18n::trf(
                "{file} already exists; it was not overwritten",
                &[("file", &modified.display())]
            )
        );
    }
    fs::create_dir_all(user_dir)?;
    atomic_write(&modified, new_text.as_bytes())?;
    refresh_desktop_database(user_dir);
    let (previous_nodisplay, previous_hidden) = match (in_user_dir, previous.marker) {
        (true, false) => (previous.no_display, previous.hidden),
        // Hidden by an older SAM: its NoDisplay is SAM's, its Hidden the
        // entry's own (that SAM did not set one).
        (true, true) => (None, previous.hidden),
        (false, _) => (None, None),
    };
    Ok(HiddenEntry {
        original: entry.to_path_buf(),
        modified,
        created_override: !in_user_dir,
        previous_nodisplay,
        previous_hidden,
    })
}

/// Adds what [`hide`] returned to an app's records. An entry hidden again
/// (an older SAM had taken it out of the menu only) keeps its earlier
/// record, which knows the `NoDisplay` from before SAM, and gains the
/// `Hidden` from before.
pub fn merge_hidden(records: &mut Vec<HiddenEntry>, h: HiddenEntry) {
    match records.iter_mut().find(|r| r.modified == h.modified) {
        Some(r) => {
            if !r.created_override {
                r.previous_hidden = h.previous_hidden;
            }
        }
        None => records.push(h),
    }
}

/// Undo [`hide`]. Leaves files alone that no longer carry SAM's marker for
/// this app (the user or another tool changed them since).
pub fn restore(h: &HiddenEntry, app_id: &str) -> Result<()> {
    let Ok(text) = fs::read_to_string(&h.modified) else {
        return Ok(());
    };
    if !group_keys(&text)
        .iter()
        .any(|(k, v)| k == MARKER && v == app_id)
    {
        return Ok(());
    }
    if h.created_override {
        fs::remove_file(&h.modified)?;
    } else {
        let extra: Vec<String> = h
            .previous_nodisplay
            .iter()
            .map(|v| format!("{NO_DISPLAY}={v}"))
            .chain(h.previous_hidden.iter().map(|v| format!("{HIDDEN}={v}")))
            .collect();
        atomic_write(&h.modified, rewrite(&text, &extra).0.as_bytes())?;
    }
    if let Some(dir) = h.modified.parent() {
        refresh_desktop_database(dir);
    }
    Ok(())
}

fn same_dir(a: &Path, b: &Path) -> bool {
    fs::canonicalize(a)
        .ok()
        .zip(fs::canonicalize(b).ok())
        .is_some_and(|(a, b)| a == b)
        || a == b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    fn fake_appimage(dir: &Path) -> PathBuf {
        let p = dir.join("Tool.AppImage");
        fs::write(&p, b"\x7fELF").unwrap();
        fs::canonicalize(p).unwrap()
    }

    /// The AppImage a foreign menu entry starts is found in its Exec line, also behind env and with quotes.
    #[test]
    fn the_appimage_behind_a_foreign_menu_entry_is_found() {
        assert_eq!(
            split_exec(r#""/a b/X.AppImage" --flag %U"#),
            vec!["/a b/X.AppImage", "--flag", "%U"]
        );
        assert_eq!(appimage_in("firefox %u"), None);
        assert_eq!(
            appimage_in("env FOO=1 /nope/X.AppImage %U"),
            Some(PathBuf::from("/nope/X.AppImage"))
        );
    }

    /// Regression (audit I-F15): a menu entry whose `Exec=` names a named
    /// pipe hung the overview, which opened it to look for an AppImage and
    /// waited for a writer that never came. Now it is passed over at once.
    #[test]
    fn a_menu_entry_naming_a_pipe_does_not_hang_the_search() {
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        let apps = d.path().join("applications");
        fs::create_dir_all(&apps).unwrap();
        let pipe = d.path().join("tool");
        let c = std::ffi::CString::new(pipe.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a NUL-terminated path; mkfifo only creates the pipe.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        fs::write(
            apps.join("tool.desktop"),
            format!("[Desktop Entry]\nName=Tool\nExec={} %F\n", pipe.display()),
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let dir = apps.clone();
        std::thread::spawn(move || {
            let _ = tx.send(foreign_entries(&dir));
        });
        // Generous: without the fix it never returns at all.
        let got = rx.recv_timeout(std::time::Duration::from_secs(30));
        if got.is_err() {
            // Let the stuck search go before failing.
            let _ = fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&pipe);
        }
        let found = got.expect("the search waited on the named pipe");
        assert!(
            found.iter().all(|f| f.appimage != pipe),
            "a pipe is no AppImage: {found:?}"
        );
    }

    /// An unsandboxed menu entry in the user's folder is hidden on request and restored exactly as it was.
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
        assert!(hidden.contains("NoDisplay=true\nHidden=true\nX-SAM-HiddenBy=appimage-tool-1"));
        assert!(
            hidden.contains("[Desktop Action New]\nName=New\nNoDisplay=x"),
            "other groups untouched"
        );
        assert_eq!(
            foreign_entries(&apps)
                .iter()
                .find(|f| f.file == entry)
                .unwrap()
                .hidden_by
                .as_deref(),
            Some("appimage-tool-1")
        );

        restore(&h, "appimage-tool-1").unwrap();
        let back = fs::read_to_string(&entry).unwrap();
        assert!(
            back.contains("NoDisplay=false")
                && !back.contains("NoDisplay=true")
                && !back.contains(MARKER),
            "{back}"
        );
    }

    /// Which programs `gio`, the desktop's own file opener (GLib), would
    /// offer for `mime`, with only `data` as the desktop's data folder.
    /// GLib finds them through the file-type cache that
    /// `update-desktop-database` writes, as SAM does after every change.
    fn openers(data: &Path, mime: &str) -> Option<String> {
        let gio = sam_core::util::which("gio")?;
        sam_core::util::which("update-desktop-database")?;
        let out = std::process::Command::new(gio)
            .args(["mime", mime])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", data)
            .env("XDG_DATA_HOME", data)
            .env("XDG_DATA_DIRS", data.join("none"))
            .env("XDG_CONFIG_HOME", data.join("config"))
            .env("XDG_CONFIG_DIRS", data.join("none"))
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Regression (review 2026-11-23, F4): hiding an unsandboxed entry set
    /// only `NoDisplay=true`, which takes it out of the menu but leaves it
    /// a handler for its file types, so opening a file still started the
    /// AppImage without its sandbox. Checked with GLib's own `gio`: a
    /// hidden entry opens nothing, and restoring makes it a handler again,
    /// with the file as it was.
    #[test]
    fn a_hidden_entry_no_longer_opens_files() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let apps = data.join("applications");
        fs::create_dir_all(&apps).unwrap();
        let img = fake_appimage(d.path());
        fs::set_permissions(&img, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let entry = apps.join("appimagekit_x-Editor.desktop");
        let original = format!(
            "[Desktop Entry]\nType=Application\nName=Editor\nExec={} %F\nMimeType=text/markdown;\n",
            img.display()
        );
        fs::write(&entry, &original).unwrap();
        refresh_desktop_database(&apps);
        let Some(before) = openers(&data, "text/markdown") else {
            assert!(
                std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
                "SAM_REQUIRE_SANDBOX=1, but GLib's gio or update-desktop-database is not installed"
            );
            sam_core::errln!("skipped: GLib's gio or update-desktop-database is not installed");
            return;
        };
        let name = "appimagekit_x-Editor.desktop";
        assert!(before.contains(name), "the control: it opens files: {before}");

        // Why NoDisplay alone is not enough: out of the menu, still opening.
        fs::write(&entry, original.replace("Name=Editor\n", "Name=Editor\nNoDisplay=true\n")).unwrap();
        refresh_desktop_database(&apps);
        let menu_only = openers(&data, "text/markdown").unwrap();
        assert!(menu_only.contains(name), "{menu_only}");
        fs::write(&entry, &original).unwrap();
        refresh_desktop_database(&apps);

        let h = hide(&entry, &apps, "appimage-editor-1").unwrap();
        let hidden = openers(&data, "text/markdown").unwrap();
        assert!(!hidden.contains(name), "a hidden entry still opens files: {hidden}");
        let found = foreign_entries(&apps);
        let f = found.iter().find(|f| f.file == entry).unwrap();
        assert_eq!(f.hidden_by.as_deref(), Some("appimage-editor-1"));

        restore(&h, "appimage-editor-1").unwrap();
        assert_eq!(fs::read_to_string(&entry).unwrap(), original);
        let back = openers(&data, "text/markdown").unwrap();
        assert!(back.contains(name), "{back}");
    }

    /// An entry out of the menu that still opens files is a way to start
    /// the AppImage without its sandbox, so it is offered for hiding; one
    /// deleted (`Hidden=true`) or opening nothing counts as hidden
    /// elsewhere. An entry an older SAM took out of the menu only is
    /// offered again, and hiding it again keeps what is needed to put back
    /// the file as it was before SAM (review 2026-11-23, F4).
    #[test]
    fn entries_that_still_open_files_are_not_taken_for_hidden() {
        let d = tempfile::tempdir().unwrap();
        let apps = d.path().join("applications");
        fs::create_dir_all(&apps).unwrap();
        let img = fake_appimage(d.path());
        let write = |name: &str, extra: &str| {
            let p = apps.join(name);
            let text = format!(
                "[Desktop Entry]\nName=Tool\nExec={} %F\n{extra}",
                img.display()
            );
            fs::write(&p, &text).unwrap();
            (p, text)
        };
        let (files_only, _) = write("a.desktop", "NoDisplay=true\nMimeType=text/markdown;\n");
        let (nothing, _) = write("b.desktop", "NoDisplay=true\nMimeType=;\n");
        let (deleted, _) = write("c.desktop", "Hidden=true\nMimeType=text/markdown;\n");
        let (old_sam, _) = write(
            "d.desktop",
            "NoDisplay=true\nX-SAM-HiddenBy=appimage-tool-1\nMimeType=text/markdown;\n",
        );
        let found = foreign_entries(&apps);
        let get = |p: &Path| found.iter().find(|f| f.file == p).unwrap().clone();
        assert!(!get(&files_only).hidden_elsewhere && get(&files_only).hidden_by.is_none());
        assert!(get(&nothing).hidden_elsewhere);
        assert!(get(&deleted).hidden_elsewhere);
        let old = get(&old_sam);
        assert!(old.hidden_by.is_none() && !old.hidden_elsewhere, "{old:?}");

        // The older SAM's record knows the NoDisplay from before it.
        let mut records = vec![HiddenEntry {
            original: old_sam.clone(),
            modified: old_sam.clone(),
            created_override: false,
            previous_nodisplay: Some("false".into()),
            previous_hidden: None,
        }];
        let h = hide(&old_sam, &apps, "appimage-tool-1").unwrap();
        assert_eq!(h.previous_nodisplay, None, "SAM's own NoDisplay is not the entry's");
        merge_hidden(&mut records, h);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].previous_nodisplay.as_deref(), Some("false"));
        let found = foreign_entries(&apps);
        assert_eq!(
            found.iter().find(|f| f.file == old_sam).unwrap().hidden_by.as_deref(),
            Some("appimage-tool-1")
        );
        restore(&records[0], "appimage-tool-1").unwrap();
        let back = fs::read_to_string(&old_sam).unwrap();
        assert!(
            back.contains("NoDisplay=false")
                && !back.contains("Hidden")
                && !back.contains(MARKER)
                && back.contains("MimeType=text/markdown;"),
            "{back}"
        );
    }

    /// An unsandboxed menu entry in a system folder is hidden through an entry in the user's folder, without touching the system file.
    #[test]
    fn system_entry_gets_override() {
        let d = tempfile::tempdir().unwrap();
        let (sys, user) = (d.path().join("sys"), d.path().join("user"));
        fs::create_dir_all(&sys).unwrap();
        let img = fake_appimage(d.path());
        let entry = sys.join("tool.desktop");
        fs::write(
            &entry,
            format!("[Desktop Entry]\nName=Tool\nExec={}\n", img.display()),
        )
        .unwrap();
        let h = hide(&entry, &user, "appimage-tool-1").unwrap();
        assert!(h.created_override && h.modified == user.join("tool.desktop"));
        assert_eq!(
            fs::read_to_string(&entry).unwrap(),
            format!("[Desktop Entry]\nName=Tool\nExec={}\n", img.display()),
            "system file untouched"
        );
        restore(&h, "appimage-tool-1").unwrap();
        assert!(!h.modified.exists());
    }
}
