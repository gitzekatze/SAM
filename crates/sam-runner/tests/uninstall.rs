//! `sam-jail uninstall`: lists first, then removes every trace of SAM (a
//! sandbox, its menu entry, SAM's own entry and icon, settings and data),
//! restores the menu entry SAM hid, and never touches the AppImage. Uses a
//! fake `$HOME`; needs no Bubblewrap (nothing is started).

use std::fs;

use sam_core::Paths;
use sam_intake::testkit::{build, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

/// Both tests change $HOME: one at a time.
static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Uninstalling SAM removes all of its files and restores the menu entries it had hidden.
#[test]
fn uninstall_removes_everything_and_restores_menus() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("home/tester");
    let apps_dir = home.join(".local/share/applications");
    fs::create_dir_all(&apps_dir).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
    std::env::set_var("XDG_RUNTIME_DIR", root.join("run"));

    let img = root.join("Tool-1.0-x86_64.AppImage");
    build(&img, &FixtureSpec::hello("Tool")).unwrap();
    // Another tool's menu entry for the same AppImage (unsandboxed).
    let foreign = apps_dir.join("appimagekit-tool.desktop");
    fs::write(&foreign, format!("[Desktop Entry]\nType=Application\nName=Tool\nExec=\"{}\" %U\n", img.display())).unwrap();
    // SAM's own taskbar entry and icon, as the window writes them.
    fs::write(apps_dir.join("io.github.gitzekatze.SAM.desktop"), "[Desktop Entry]\nName=SAM\nX-SAM-Self=true\n").unwrap();
    let icon = home.join(".local/share/icons/hicolor/scalable/apps/io.github.gitzekatze.SAM.svg");
    fs::create_dir_all(icon.parent().unwrap()).unwrap();
    fs::write(&icon, "<svg/>").unwrap();

    let paths = Paths { config_dir: home.join(".config/sam"), data_dir: home.join(".local/share/sam"), applications_dir: apps_dir.clone() };
    let app = Sam::with_paths(paths.clone()).unwrap();
    app.config.save(&paths).unwrap();
    let id = app.add(&img, &AddOptions { launcher: Some(true), hide_duplicates: true, ..Default::default() }).unwrap().entry.id;
    let launcher = paths.launcher_file(&id);
    assert!(launcher.exists());
    assert!(fs::read_to_string(&foreign).unwrap().contains("NoDisplay=true"), "SAM hid the other entry");

    // Without --yes: a list, nothing removed.
    let dry = app.uninstall(false, true).unwrap();
    assert_eq!(dry.apps, vec!["Tool".to_string()]);
    assert!(dry.files.contains(&apps_dir.join("io.github.gitzekatze.SAM.desktop")) && dry.files.contains(&icon));
    assert!(dry.dirs.contains(&paths.config_dir) && dry.dirs.contains(&paths.data_dir));
    assert!(!dry.dirs.iter().any(|d| d.starts_with(&paths.data_dir) && *d != paths.data_dir), "nested folders not listed twice");
    assert!(launcher.exists() && paths.config_dir.exists(), "dry run changes nothing");

    let done = app.uninstall(false, false).unwrap();
    assert!(done.problems.is_empty(), "{:?}", done.problems);
    assert!(!launcher.exists(), "SAM's menu entry removed");
    assert!(!fs::read_to_string(&foreign).unwrap().contains("NoDisplay=true"), "the hidden entry is back");
    assert!(!apps_dir.join("io.github.gitzekatze.SAM.desktop").exists() && !icon.exists(), "SAM's own entry and icon removed");
    assert!(!paths.config_dir.exists() && !paths.data_dir.exists(), "settings and data removed");
    assert!(img.exists(), "the AppImage stays");
    assert!(home.exists() && apps_dir.exists(), "nothing else removed");
}

/// Uninstalling refuses to delete a folder that is not SAM's, such as the home folder.
#[test]
fn uninstall_refuses_folders_that_are_not_sams() {
    let _one = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home/tester");
    fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    // A misconfigured data folder: the home itself.
    let paths = Paths { config_dir: home.join(".config/sam"), data_dir: home.clone(), applications_dir: home.join("apps") };
    let app = Sam::with_paths(paths).unwrap();
    let err = app.uninstall(false, true).unwrap_err().to_string();
    assert!(err.contains("refusing"), "{err}");
    assert!(home.exists());
}
