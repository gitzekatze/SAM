//! Desktop launcher integration (§2.12).
//!
//! Launchers always go through `appseal-run`, never the original AppImage.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use appseal_core::util::{atomic_write, which};
use appseal_core::{AppEntry, Paths};

/// Command used in `Exec=` lines: `appseal-run` if it is on `$PATH`
/// (packaged install), otherwise the absolute path next to the current binary.
pub fn runner_command() -> String {
    if let Some(p) = which("appseal-run") {
        if p.starts_with("/usr") {
            return "appseal-run".into();
        }
        return p.display().to_string();
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("appseal-run");
            if cand.exists() {
                return cand.display().to_string();
            }
        }
    }
    "appseal-run".into()
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
        format!("{name} (sandboxed by Appseal)")
    } else {
        format!("{} (sandboxed by Appseal)", entry.metadata.comment)
    };
    let mut s = String::from("[Desktop Entry]\nType=Application\n");
    s += &format!("Name={}\n", value(&name));
    s += &format!("Comment={}\n", value(&comment));
    s += &format!("Exec={} --app-id {} %F\n", exec_quote(runner), entry.id);
    s += &format!("Icon={}\n", value(&icon));
    if !entry.metadata.categories.is_empty() {
        s += &format!("Categories={};\n", entry.metadata.categories.join(";"));
    }
    if !entry.metadata.mime_types.is_empty() {
        s += &format!("MimeType={};\n", entry.metadata.mime_types.join(";"));
    }
    if !entry.metadata.startup_wm_class.is_empty() {
        s += &format!("StartupWMClass={}\n", value(&entry.metadata.startup_wm_class));
    }
    s += &format!("Terminal={}\n", entry.metadata.terminal);
    s += &format!("X-Appseal-AppId={}\n", entry.id);
    s += "X-Appseal-Managed=true\n";
    s
}

/// Install (or update) the launcher. Returns its path.
pub fn install_launcher(paths: &Paths, entry: &AppEntry) -> Result<PathBuf> {
    let contents = launcher_contents(entry, &runner_command());
    let path = paths.launcher_file(&entry.id);
    atomic_write(&path, contents.as_bytes())?;
    atomic_write(&paths.desktop_dir().join(format!("appseal-{}.desktop", entry.id)), contents.as_bytes())?;
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
    for p in [paths.launcher_file(id), paths.desktop_dir().join(format!("appseal-{id}.desktop"))] {
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

/// Other Appseal-managed desktop files carrying this app id.
pub fn find_duplicates(paths: &Paths, id: &str) -> Vec<PathBuf> {
    let needle = format!("X-Appseal-AppId={id}\n");
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(&paths.applications_dir) {
        for e in rd.flatten() {
            let p = e.path();
            let is_appseal = p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("appseal-") && n.ends_with(".desktop"));
            if is_appseal && fs::read_to_string(&p).is_ok_and(|s| s.contains(&needle)) {
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
        Some(exec) if exec.contains("appseal-run") && exec.contains(&format!("--app-id {id}")) => {}
        Some(_) => problems.push("launcher does not start the app through appseal-run".into()),
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

fn refresh_desktop_database(dir: &Path) {
    if let Some(udd) = which("update-desktop-database") {
        let _ = Command::new(udd).arg("-q").arg(dir).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_quoting() {
        assert_eq!(exec_quote("appseal-run"), "appseal-run");
        assert_eq!(exec_quote("/opt/My Apps/appseal-run"), "\"/opt/My Apps/appseal-run\"");
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
}
