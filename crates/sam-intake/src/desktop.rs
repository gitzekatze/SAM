//! Desktop launcher integration.
//!
//! Launchers always go through `sam-jail-run`, never the original AppImage.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use sam_core::util::{atomic_write, which};
use sam_core::{AppEntry, Paths};

/// Command used in `Exec=` lines, always a whole path: SAM's own AppImage
/// file when SAM runs from one (it hands `--app-id` on to sam-jail-run),
/// else the `sam-jail-run` next to this program, else the one on `$PATH`
/// that the user cannot change. A bare name would be looked up by the
/// desktop on its own `$PATH`, where a copy an app put into
/// `~/.cargo/bin` could come first and run unsandboxed (audit G-F10).
pub fn runner_command() -> String {
    if let Some(a) = sam_core::util::own_appimage() {
        return a.display().to_string();
    }
    let here = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("sam-jail-run")));
    if let Some(h) = here.as_ref().filter(|h| h.exists()) {
        return h.display().to_string();
    }
    if let Some(p) = which("sam-jail-run") {
        return p.display().to_string();
    }
    // None installed: the place it belongs, so the check below names it.
    here.unwrap_or_else(|| PathBuf::from("/nonexistent").join("sam-jail-run"))
        .display()
        .to_string()
}

/// Quote an argument for the desktop-entry `Exec` key.
pub fn exec_quote(arg: &str) -> String {
    let reserved = |c: char| " \t\n\"'\\><~|&;$*?#()`".contains(c);
    let s = if arg.chars().any(reserved) {
        let mut q = String::from("\"");
        for c in arg.chars() {
            if matches!(c, '"' | '`' | '$' | '\\') {
                q.push('\\');
            }
            q.push(c);
        }
        q.push('"');
        q
    } else {
        arg.to_string()
    };
    // Backslashes are additionally escaped at the string-value level, and
    // a `%` would start a field code (`%F`): a literal one is `%%` (audit
    // G-F17: `%` in SAM's own path broke every menu entry).
    s.replace('\\', "\\\\").replace('%', "%%")
}

/// A category or file type ("Graphics", "image/png"): letters, digits and
/// "-_.+/" only.
fn list_item_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.+/".contains(c))
}

fn value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "")
}

pub fn launcher_contents(entry: &AppEntry, runner: &str) -> String {
    let name = if entry.metadata.name.is_empty() {
        entry.display_name().to_string()
    } else {
        entry.metadata.name.clone()
    };
    let icon = entry
        .metadata
        .icon_path
        .as_ref()
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "application-x-executable".into());
    let comment = if entry.metadata.comment.is_empty() {
        format!("{name} (sandboxed by SAM)")
    } else {
        format!("{} (sandboxed by SAM)", entry.metadata.comment)
    };
    let mut s = String::from("[Desktop Entry]\nType=Application\n");
    s += &format!("Name={}\n", value(&name));
    s += &format!("Comment={}\n", value(&comment));
    s += &format!("Exec={} --app-id {} %F\n", exec_quote(runner), entry.id);
    s += &format!("Icon={}\n", value(&icon));
    // List values keep only the characters categories and file types use:
    // a line break or "=" from a changed record could otherwise add a line
    // (a second Exec=) to SAM's own menu entry.
    let categories: Vec<&String> = entry
        .metadata
        .categories
        .iter()
        .filter(|c| list_item_ok(c))
        .collect();
    if !categories.is_empty() {
        s += &format!(
            "Categories={};\n",
            categories
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(";")
        );
    }
    let mimes: Vec<String> = launcher_mime_types(&entry.metadata.mime_types)
        .into_iter()
        .filter(|m| list_item_ok(m))
        .collect();
    if !mimes.is_empty() {
        s += &format!("MimeType={};\n", mimes.join(";"));
    }
    if !entry.metadata.startup_wm_class.is_empty() {
        s += &format!(
            "StartupWMClass={}\n",
            value(&entry.metadata.startup_wm_class)
        );
    }
    s += &format!("Terminal={}\n", entry.metadata.terminal);
    s += &format!("X-SAM-AppId={}\n", entry.id);
    s += "X-SAM-Managed=true\n";
    s
}

/// File types a sandboxed launcher may register for. The list comes from the
/// (untrusted) AppImage, so URL schemes (`x-scheme-handler/https`, `mailto`),
/// directories, executables, desktop files and AppImages are dropped: an app
/// must not make itself the handler for web links or the file manager, or
/// receive the user's files by declaring broad types. `all/all` and
/// `all/allfiles` are the desktops' names for "every file" (and folder).
pub fn launcher_mime_types(declared: &[String]) -> Vec<String> {
    // `x-directory/normal` is an old name of `inode/directory`.
    const BLOCKED_PREFIX: &[&str] = &[
        "x-scheme-handler/",
        "inode/",
        "x-content/",
        "x-directory/",
        "all/",
    ];
    const BLOCKED: &[&str] = &[
        "application/x-desktop",
        "application/x-executable",
        "application/x-pie-executable",
        "application/x-sharedlib",
        "application/x-shellscript",
        "application/x-sh",
        "text/x-sh",
        "text/x-shellscript",
        "application/vnd.appimage",
        "application/x-iso9660-appimage",
        "application/octet-stream",
        "text/plain",
        "text/html",
        "application/xhtml+xml",
    ];
    // File types are case-insensitive: `X-Scheme-Handler/https` and
    // `Text/HTML` are the same as the blocked ones (audit I-F10).
    declared
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .filter(|t| {
            !BLOCKED_PREFIX.iter().any(|p| t.starts_with(p))
                && !BLOCKED.contains(&t.as_str())
                && !t.contains('*')
        })
        .take(64)
        .collect()
}

/// Install (or update) the launcher. Returns its path.
pub fn install_launcher(paths: &Paths, entry: &AppEntry) -> Result<PathBuf> {
    let contents = launcher_contents(entry, &runner_command());
    let path = paths.launcher_file(&entry.id);
    atomic_write(&path, contents.as_bytes())?;
    atomic_write(
        &paths
            .desktop_dir()
            .join(format!("sam-{}.desktop", entry.id)),
        contents.as_bytes(),
    )?;
    // Remove duplicates that point at the same app id under other names.
    for dup in find_duplicates(paths, &entry.id) {
        if dup != path {
            let _ = fs::remove_file(dup);
        }
    }
    refresh_desktop_database(&paths.applications_dir);
    Ok(path)
}

pub fn remove_launcher(paths: &Paths, id: &str) -> Result<bool> {
    let mut removed = false;
    for p in [
        paths.launcher_file(id),
        paths.desktop_dir().join(format!("sam-{id}.desktop")),
    ] {
        if fs::remove_file(&p).is_ok() {
            removed = true;
        }
    }
    for dup in find_duplicates(paths, id) {
        removed |= fs::remove_file(dup).is_ok();
    }
    refresh_desktop_database(&paths.applications_dir);
    Ok(removed)
}

/// Rewrites installed launchers whose contents are outdated, e.g. because
/// SAM's AppImage was moved. Returns how many changed.
pub fn refresh_launchers(paths: &Paths, entries: &[AppEntry]) -> usize {
    let runner = runner_command();
    let mut changed = 0;
    for e in entries {
        let path = paths.launcher_file(&e.id);
        let Ok(old) = fs::read_to_string(&path) else {
            continue;
        };
        let new = launcher_contents(e, &runner);
        if old != new && install_launcher(paths, e).is_ok() {
            changed += 1;
        }
    }
    changed
}

/// Other SAM-managed desktop files carrying this app id.
pub fn find_duplicates(paths: &Paths, id: &str) -> Vec<PathBuf> {
    let needle = format!("X-SAM-AppId={id}\n");
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(&paths.applications_dir) {
        for e in rd.flatten() {
            let p = e.path();
            let is_sam = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("sam-") && n.ends_with(".desktop"));
            if is_sam && fs::read_to_string(&p).is_ok_and(|s| s.contains(&needle)) {
                out.push(p);
            }
        }
    }
    out
}

/// Problems with an installed launcher, empty when valid.
pub fn validate_launcher(path: &Path, id: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let Ok(text) = fs::read_to_string(path) else {
        return vec![sam_core::i18n::tr("the menu entry file is missing")];
    };
    let m = crate::metadata::parse_desktop(&text);
    match m.get("Exec") {
        // Only SAM's own launcher, by its whole path: an entry that names
        // `sam-jail-run` alone (written by older versions) is rewritten when
        // the window starts.
        Some(exec)
            if exec.starts_with(&exec_quote(&runner_command()))
                && exec.contains(&format!("--app-id {id}")) => {}
        Some(_) => problems.push(sam_core::i18n::tr(
            "the menu entry does not start the app through sam-jail-run",
        )),
        None => problems.push(sam_core::i18n::tr("the menu entry has no Exec line")),
    }
    if let Some(icon) = m.get("Icon") {
        if icon.starts_with('/') && !Path::new(icon).exists() {
            problems.push(format!("icon {icon} is missing"));
        }
    }
    let runner = runner_command();
    if runner.starts_with('/') && !Path::new(&runner).exists() {
        problems.push(sam_core::i18n::trf(
            "runner {runner} does not exist",
            &[("runner", &runner)],
        ));
    }
    problems
}

/// SAM's own menu entries (`sam-*.desktop` carrying `X-SAM-AppId`).
pub fn sam_launchers(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let named = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("sam-") && n.ends_with(".desktop"));
            if named && fs::read_to_string(&p).is_ok_and(|s| s.contains("X-SAM-AppId=")) {
                out.push(p);
            }
        }
    }
    out
}

/// Updates the desktop's menu cache after changes.
pub fn refresh(dir: &Path) {
    refresh_desktop_database(dir);
}

pub(crate) fn refresh_desktop_database(dir: &Path) {
    if let Some(udd) = which("update-desktop-database") {
        #[expect(
            clippy::disallowed_methods,
            reason = "way out: update-desktop-database"
        )]
        let _ = Command::new(udd).arg("-q").arg(dir).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SAM's menu entry starts the app only through SAM's sandbox: no value
    /// taken from the app (name, comment, categories, file types, window
    /// class) can add a line such as a second "Exec=" to it, even from a
    /// record changed outside SAM.
    #[test]
    fn app_metadata_cannot_add_lines_to_sams_menu_entry() {
        let mut e = AppEntry {
            id: "appimage-x-1".into(),
            ..Default::default()
        };
        let evil = "x\nExec=/tmp/evil\r\nTerminal=true";
        e.metadata.name = evil.into();
        e.metadata.comment = evil.into();
        e.metadata.startup_wm_class = evil.into();
        e.metadata.categories = vec!["Graphics".into(), evil.into(), "A=B".into()];
        e.metadata.mime_types = vec!["image/png".into(), format!("image/x{evil}")];
        let text = launcher_contents(&e, "sam-jail-run");
        let exec: Vec<&str> = text.lines().filter(|l| l.starts_with("Exec=")).collect();
        assert_eq!(
            exec,
            vec!["Exec=sam-jail-run --app-id appimage-x-1 %F"],
            "{text}"
        );
        assert_eq!(
            text.lines().filter(|l| l.starts_with("Terminal=")).count(),
            1,
            "{text}"
        );
        assert!(
            text.contains("Categories=Graphics;\n"),
            "only clean categories stay: {text}"
        );
        assert!(
            text.contains("MimeType=image/png;\n"),
            "only clean file types stay: {text}"
        );
    }

    /// Program paths in menu entries are quoted so spaces and dollar signs cannot change the command.
    #[test]
    fn menu_entry_paths_are_quoted_against_spaces_and_dollar_signs() {
        assert_eq!(exec_quote("sam-jail-run"), "sam-jail-run");
        assert_eq!(
            exec_quote("/opt/My Apps/sam-jail-run"),
            "\"/opt/My Apps/sam-jail-run\""
        );
        assert_eq!(exec_quote("a$b"), "\"a\\\\$b\"");
    }

    /// A menu entry names SAM's launcher by its whole path, so the desktop
    /// never looks it up on a `$PATH` an app may have put a copy into
    /// (audit G-F10); an older entry that names it alone is reported, and
    /// the window rewrites it at its next start.
    #[test]
    fn menu_entries_name_sams_launcher_by_its_whole_path() {
        assert!(runner_command().starts_with('/'), "{}", runner_command());
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let mut e = AppEntry {
            id: "appimage-hello-1234".into(),
            ..Default::default()
        };
        e.metadata.name = "Hello".into();
        let p = install_launcher(&paths, &e).unwrap();
        let text = fs::read_to_string(&p).unwrap();
        assert!(
            text.contains(&format!("Exec={} --app-id", exec_quote(&runner_command()))),
            "{text}"
        );
        fs::write(
            &p,
            text.replace(&exec_quote(&runner_command()), "sam-jail-run"),
        )
        .unwrap();
        assert!(
            validate_launcher(&p, &e.id)
                .iter()
                .any(|m| m.contains("through sam-jail-run")),
            "{:?}",
            validate_launcher(&p, &e.id)
        );
        assert_eq!(refresh_launchers(&paths, std::slice::from_ref(&e)), 1);
        assert!(!validate_launcher(&p, &e.id)
            .iter()
            .any(|m| m.contains("through sam-jail-run")));
    }

    /// A `%` in SAM's own path is written `%%` in the menu entry, where a
    /// single one would start a field code like `%F` (audit G-F17).
    #[test]
    fn a_percent_sign_in_sams_path_stays_a_percent_sign() {
        assert_eq!(
            exec_quote("/opt/100%sam/sam-jail-run"),
            "/opt/100%%sam/sam-jail-run"
        );
        assert_eq!(
            exec_quote("/home/a b/50% off/sam-jail-run"),
            "\"/home/a b/50%% off/sam-jail-run\""
        );
    }

    /// SAM's menu entry starts the app through sam-jail-run, never the AppImage directly.
    #[test]
    fn sams_menu_entry_starts_the_app_only_through_sam() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let mut e = AppEntry {
            id: "appimage-hello-1234".into(),
            name: "Hello".into(),
            ..Default::default()
        };
        e.metadata.name = "Hello".into();
        e.metadata.categories = vec!["Utility".into()];
        let p = install_launcher(&paths, &e).unwrap();
        let text = fs::read_to_string(&p).unwrap();
        assert!(text.contains("--app-id appimage-hello-1234 %F"), "{text}");
        assert!(text.contains("Categories=Utility;"));
        assert!(validate_launcher(&p, &e.id)
            .iter()
            .all(|p| p.contains("runner")));
        assert!(remove_launcher(&paths, &e.id).unwrap());
        assert!(!p.exists());
    }

    /// SAM's menu entry never claims links, folders or desktop files, so a sandboxed app cannot take over opening them.
    /// The blocked file types hold in any letter case and under their old
    /// names, so an app cannot claim web links, folders or programs by
    /// writing `X-Scheme-Handler/https`, `Text/HTML` or
    /// `x-directory/normal` (audit I-F10), and cannot claim every file with
    /// the desktops' catch-all types `all/all` and `all/allfiles` (audit
    /// 2026-11-18, low).
    #[test]
    fn blocked_file_types_hold_in_any_case_and_old_names() {
        let declared: Vec<String> = [
            "all/all",
            "All/AllFiles",
            "X-Scheme-Handler/https",
            "Text/HTML",
            "x-directory/normal",
            "INODE/directory",
            "application/x-pie-executable",
            "text/x-sh",
            "Image/PNG",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(launcher_mime_types(&declared), vec!["image/png"]);
    }

    #[test]
    fn launcher_mime_types_drop_hijack_targets() {
        let d: Vec<String> = [
            "x-scheme-handler/https",
            "inode/directory",
            "text/html",
            "application/pdf",
            "image/png",
            "application/x-desktop",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            launcher_mime_types(&d),
            vec!["application/pdf", "image/png"]
        );
    }
}
