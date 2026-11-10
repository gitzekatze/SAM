//! Desktop launcher integration (§2.12).
//!
//! Launchers always go through `sam-jail-run`, never the original AppImage.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use sam_core::util::{atomic_write, which};
use sam_core::{AppEntry, Paths};

/// Command used in `Exec=` lines: SAM's own AppImage file when SAM runs
/// from one (it hands `--app-id` on to sam-jail-run), else `sam-jail-run` if
/// it is on `$PATH` (packaged install), otherwise the absolute path next to
/// the current binary.
pub fn runner_command() -> String {
    if let Some(a) = sam_core::util::own_appimage() {
        return a.display().to_string();
    }
    if let Some(p) = which("sam-jail-run") {
        if p.starts_with("/usr") {
            return "sam-jail-run".into();
        }
        return p.display().to_string();
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("sam-jail-run");
            if cand.exists() {
                return cand.display().to_string();
            }
        }
    }
    "sam-jail-run".into()
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
    // Backslashes are additionally escaped at the string-value level.
    s.replace('\\', "\\\\")
}

fn value(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "")
}

pub fn launcher_contents(entry: &AppEntry, runner: &str) -> String {
    let name = if entry.metadata.name.is_empty() { entry.display_name().to_string() } else { entry.metadata.name.clone() };
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
    if !entry.metadata.categories.is_empty() {
        s += &format!("Categories={};\n", entry.metadata.categories.join(";"));
    }
    let mimes = launcher_mime_types(&entry.metadata.mime_types);
    if !mimes.is_empty() {
        s += &format!("MimeType={};\n", mimes.join(";"));
    }
    if !entry.metadata.startup_wm_class.is_empty() {
        s += &format!("StartupWMClass={}\n", value(&entry.metadata.startup_wm_class));
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
/// receive the user's files by declaring broad types.
pub fn launcher_mime_types(declared: &[String]) -> Vec<String> {
    const BLOCKED_PREFIX: &[&str] = &["x-scheme-handler/", "inode/", "x-content/"];
    const BLOCKED: &[&str] = &[
        "application/x-desktop", "application/x-executable", "application/x-sharedlib", "application/x-shellscript",
        "application/x-sh", "application/vnd.appimage", "application/x-iso9660-appimage", "application/octet-stream",
        "text/plain", "text/html", "application/xhtml+xml",
    ];
    declared
        .iter()
        .filter(|t| !BLOCKED_PREFIX.iter().any(|p| t.starts_with(p)) && !BLOCKED.contains(&t.as_str()) && !t.contains('*'))
        .take(64)
        .cloned()
        .collect()
}

/// Install (or update) the launcher. Returns its path.
pub fn install_launcher(paths: &Paths, entry: &AppEntry) -> Result<PathBuf> {
    let contents = launcher_contents(entry, &runner_command());
    let path = paths.launcher_file(&entry.id);
    atomic_write(&path, contents.as_bytes())?;
    atomic_write(&paths.desktop_dir().join(format!("sam-{}.desktop", entry.id)), contents.as_bytes())?;
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
    for p in [paths.launcher_file(id), paths.desktop_dir().join(format!("sam-{id}.desktop"))] {
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
        let Ok(old) = fs::read_to_string(&path) else { continue };
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
            let is_sam = p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("sam-") && n.ends_with(".desktop"));
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
        return vec!["launcher file is missing".into()];
    };
    let m = crate::metadata::parse_desktop(&text);
    match m.get("Exec") {
        Some(exec) if (exec.contains("sam-jail-run") || exec.starts_with(&exec_quote(&runner_command()))) && exec.contains(&format!("--app-id {id}")) => {}
        Some(_) => problems.push("launcher does not start the app through sam-jail-run".into()),
        None => problems.push("launcher has no Exec line".into()),
    }
    if let Some(icon) = m.get("Icon") {
        if icon.starts_with('/') && !Path::new(icon).exists() {
            problems.push(format!("icon {icon} is missing"));
        }
    }
    let runner = runner_command();
    if runner.starts_with('/') && !Path::new(&runner).exists() {
        problems.push(format!("runner {runner} does not exist"));
    }
    problems
}

/// SAM's own menu entries (`sam-*.desktop` carrying `X-SAM-AppId`).
pub fn sam_launchers(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let named = p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("sam-") && n.ends_with(".desktop"));
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
        let _ = Command::new(udd).arg("-q").arg(dir).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_quoting() {
        assert_eq!(exec_quote("sam-jail-run"), "sam-jail-run");
        assert_eq!(exec_quote("/opt/My Apps/sam-jail-run"), "\"/opt/My Apps/sam-jail-run\"");
        assert_eq!(exec_quote("a$b"), "\"a\\\\$b\"");
    }

    #[test]
    fn launcher_uses_runner() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let mut e = AppEntry { id: "appimage-hello-1234".into(), name: "Hello".into(), ..Default::default() };
        e.metadata.name = "Hello".into();
        e.metadata.categories = vec!["Utility".into()];
        let p = install_launcher(&paths, &e).unwrap();
        let text = fs::read_to_string(&p).unwrap();
        assert!(text.contains("--app-id appimage-hello-1234 %F"), "{text}");
        assert!(text.contains("Categories=Utility;"));
        assert!(validate_launcher(&p, &e.id).iter().all(|p| p.contains("runner")));
        assert!(remove_launcher(&paths, &e.id).unwrap());
        assert!(!p.exists());
    }

    #[test]
    fn launcher_mime_types_drop_hijack_targets() {
        let d: Vec<String> = ["x-scheme-handler/https", "inode/directory", "text/html", "application/pdf", "image/png", "application/x-desktop"].iter().map(|s| s.to_string()).collect();
        assert_eq!(launcher_mime_types(&d), vec!["application/pdf", "image/png"]);
    }

}
