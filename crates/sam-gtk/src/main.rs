// SPDX-License-Identifier: GPL-3.0-or-later
//! SAM's GUI (GTK 4 / libadwaita).
//!
//!   sam-jail-gui [--page app|file|permissions|presets|preferences|diagnostics|language] [--app <id>[,<id>…]] [FILES…]
//!
//! Development builds also take --screenshot and its options (screenshot.rs).

// The privacy check (crates/sam-jail-cli/tests/network_use.rs): every way
// this program could reach the network or start a program is an #[expect]
// listed there (clippy.toml: disallowed-methods, disallowed-types).
#![cfg_attr(not(test), deny(clippy::disallowed_methods, clippy::disallowed_types))]
// GTK callbacks (Box<dyn Fn(&Rc<…>)>) are complex types by nature.
#![allow(clippy::type_complexity)]

mod all_perms;
mod app_page;
mod backend;
mod guide;
mod i18n;
mod pages;
mod perms;
// --screenshot and its options: development builds and the dev-tools
// feature only, never release builds or packages.
#[cfg(any(debug_assertions, feature = "dev-tools"))]
mod screenshot;
mod util;
mod window;

use adw::prelude::*;
use gtk::{gdk, gio, glib};
use sam_core::{errln, outln};

const APP_ID: &str = "io.github.gitzekatze.SAM";

/// SAM's own green accent (buttons, switches, links), independent of the
/// desktop's accent colour, which may be grey or black.
const ACCENT_CSS: &str = r#"
@define-color accent_bg_color #26a269;
@define-color accent_fg_color #ffffff;
@define-color accent_color @success_color;
"#;
/// The same for libadwaita 1.6+ (GTK 4.16+), which uses CSS variables.
const ACCENT_VARS_CSS: &str = r#"
:root {
    --accent-bg-color: #26a269;
    --accent-fg-color: #ffffff;
    --accent-color: var(--success-color);
}
"#;

const CSS: &str = r#"
/* Tags and badges use fixed colors, so they look the same with every
   desktop theme. The text keeps the theme's text color and stays readable
   in light and dark style; the tint and the border carry the meaning. */
/* One color per meaning throughout SAM. Risk has three levels, shared by
   permission tags (.sam-tag-*) and risk badges (.sam-badge-*): harmless
   (grey), think twice (amber), dangerous (red). Status badges reuse the
   same hues: green = protected, amber = needs attention, red = broken,
   blue = the sandbox technology. Tags: filled = read & write, outline =
   read-only or limited. */
.sam-tag, .sam-badge {
    padding: 1px 8px;
    border-radius: 999px;
    font-size: 0.8em;
    font-weight: 600;
    border: 1px solid transparent;
}
.sam-badge { font-weight: 700; padding: 2px 9px; }
.sam-tag-harmless, .sam-badge-harmless, .sam-badge-neutral { background-color: rgba(128, 128, 128, 0.32); border-color: rgba(128, 128, 128, 0.6); }
.sam-tag-caution, .sam-badge-caution, .sam-badge-warn      { background-color: rgba(229, 165, 10, 0.32);  border-color: rgb(200, 140, 0); }
.sam-tag-danger, .sam-badge-danger, .sam-badge-bad         { background-color: rgba(224, 27, 36, 0.30);   border-color: rgb(214, 40, 57); }
.sam-badge-good, .sam-badge-accent                          { background-color: rgba(38, 162, 105, 0.28);  border-color: rgb(38, 162, 105); }
.sam-badge-blue                                             { background-color: rgba(53, 132, 228, 0.28);  border-color: rgb(53, 132, 228); }
.sam-tag-outline { background-color: transparent; }
/* Logo and main menu button in the header bar: the same square size. */
.sam-header-square { min-width: 40px; min-height: 40px; padding: 2px; }
/* The round trash button on the app page. */
button.sam-trash { color: rgb(214, 40, 57); border-radius: 9999px; padding: 0 13px; }
button.sam-trash:hover { background-color: rgba(224, 27, 36, 0.15); }
/* The drop-downs of the group permissions: one font size for all. */
.sam-perm-choice { font-size: 0.9em; }
.sam-tag-button { padding: 2px; min-height: 0; }
.sam-tag-button.sam-filter-has .sam-tag { border-width: 2px; }
.sam-tag-button.sam-filter-not .sam-tag { background-color: transparent; border-style: dashed; opacity: 0.75; }

.sam-chip {
    padding: 1px 2px 1px 10px;
    border-radius: 999px;
    background-color: alpha(@window_fg_color, 0.08);
}
.sam-chip button { min-width: 22px; min-height: 22px; padding: 0; }

.sam-location-list row { min-height: 30px; }
.sam-location-list button.circular { min-width: 24px; min-height: 24px; padding: 0; }

.sam-mono { font-size: 0.86em; background: transparent; }


/* User guide */
.sam-guide label { line-height: 1.35; }
.sam-callout {
    background-color: alpha(@accent_bg_color, 0.12);
    border-left: 4px solid @accent_bg_color;
    border-radius: 8px;
    padding: 12px 16px;
}
.sam-code { padding: 12px 14px; }
.sam-bullet { color: @accent_color; font-weight: 700; }
.sam-table .sam-td { padding: 8px 12px; border-bottom: 1px solid alpha(@window_fg_color, 0.08); }
.sam-table .sam-td-last { border-bottom: none; }
.sam-table .sam-th { font-weight: 700; background-color: alpha(@window_fg_color, 0.05); }
textview.sam-mono text { background: transparent; }
"#;

struct Options {
    startup: window::Startup,
    #[cfg(any(debug_assertions, feature = "dev-tools"))]
    shot: screenshot::Options,
}

fn parse_args() -> Options {
    let mut o = Options {
        startup: window::Startup::default(),
        #[cfg(any(debug_assertions, feature = "dev-tools"))]
        shot: screenshot::Options::default(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--page" => o.startup.page = args.next().unwrap_or_default(),
            "--app" => o.startup.app = args.next().unwrap_or_default(),
            #[cfg(any(debug_assertions, feature = "dev-tools"))]
            s if o.shot.parse(s, &mut args) => {}
            "-h" | "--help" => {
                outln!("Usage: sam-jail-gui [--page app|file|permissions|presets|preferences|diagnostics|language] [--app ID] [FILES…]");
                std::process::exit(0);
            }
            "--version" => {
                outln!("sam-jail-gui {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            f => o.startup.files.push(
                std::fs::canonicalize(f)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| f.to_string()),
            ),
        }
    }
    o
}

fn main() -> glib::ExitCode {
    i18n::apply_language_setting();
    i18n::init();
    let opts = parse_args();
    glib::set_application_name("SAM - Sandboxed AppImage Manager");
    // One window per set of SAM data: starting SAM again brings the open
    // window forward (and hands over AppImages given on the command line),
    // so two windows never write the same configuration. Screenshot runs and
    // runs whose folders a developer switch moves (tests) stay separate; a
    // release build ignores those switches, so it never stays separate on
    // the normal folders.
    #[cfg(any(debug_assertions, feature = "dev-tools"))]
    let screenshot_run = opts.shot.file.is_some();
    #[cfg(not(any(debug_assertions, feature = "dev-tools")))]
    let screenshot_run = false;
    let separate = screenshot_run || sam_core::paths::folders_moved_by_a_developer_switch();
    let flags = if separate {
        gio::ApplicationFlags::NON_UNIQUE
    } else {
        gio::ApplicationFlags::HANDLES_OPEN
    };
    let app = adw::Application::builder()
        .application_id(APP_ID)
        .flags(flags)
        .build();
    // Connected before `register`: registering the first instance emits
    // "startup" at once, and a handler connected later never runs (SAM's
    // style sheet and icon folder were then missing on every normal start).
    app.connect_startup(|_| {
        desktop_identity();
        gtk::Window::set_default_icon_name(APP_ID);
        let css = gtk::CssProvider::new();
        let mut all = String::from(ACCENT_CSS);
        if gtk::check_version(4, 16, 0).is_none() {
            all.push_str(ACCENT_VARS_CSS);
        }
        all.push_str(CSS);
        css.load_from_string(&all);
        if let Some(display) = gdk::Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &css,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
            // SAM's own icon, from a folder only SAM writes. The user's icon
            // folder may hold an outdated icon-theme.cache, and GTK ignores
            // every icon that cache does not list.
            // It goes first, so an older copy elsewhere never wins.
            if let Some(dir) = own_icon_dir() {
                let theme = gtk::IconTheme::for_display(&display);
                let mut paths = theme.search_path();
                paths.insert(0, dir);
                let refs: Vec<&std::path::Path> = paths.iter().map(|p| p.as_path()).collect();
                theme.set_search_path(&refs);
            }
            // Debug builds started from a checkout: also look next to the
            // sources, so a changed icon shows without reinstalling. Release
            // builds never contain the build folder's path.
            #[cfg(debug_assertions)]
            gtk::IconTheme::for_display(&display)
                .add_search_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../../data"));
        }
    });
    if !separate && app.register(gio::Cancellable::NONE).is_ok() && app.is_remote() {
        if opts.startup.files.is_empty() {
            app.activate();
        } else {
            let files: Vec<gio::File> =
                opts.startup.files.iter().map(gio::File::for_path).collect();
            app.open(&files, "");
        }
        return glib::ExitCode::SUCCESS;
    }
    let opts = std::rc::Rc::new(std::cell::RefCell::new(Some(opts)));
    // The window, once open: a second start brings it forward.
    let current: std::rc::Rc<std::cell::RefCell<Option<std::rc::Rc<window::App>>>> =
        Default::default();
    let cur = current.clone();
    app.connect_open(move |app, files, _| {
        let paths: Vec<String> = files
            .iter()
            .filter_map(|f| f.path())
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        match cur.borrow().as_ref() {
            Some(win) => {
                win.window.present();
                win.add_files(paths);
            }
            None => app.activate(),
        }
    });
    app.connect_activate(move |app| {
        let Some(o) = opts.borrow_mut().take() else {
            if let Some(win) = current.borrow().as_ref() {
                win.window.present();
            }
            return;
        };
        let win = window::App::new(app);
        *current.borrow_mut() = Some(win.clone());
        #[cfg(any(debug_assertions, feature = "dev-tools"))]
        o.shot.size_window(&win.window);
        win.window.present();
        win.start(o.startup);
        #[cfg(any(debug_assertions, feature = "dev-tools"))]
        o.shot.take_later(win.window.clone(), app.clone());
        // Keep the window state alive for the lifetime of the window.
        let keep = std::cell::RefCell::new(Some(win.clone()));
        let cur = current.clone();
        win.window.connect_close_request(move |_| {
            keep.borrow_mut().take();
            cur.borrow_mut().take();
            glib::Propagation::Proceed
        });
    });
    let code = app.run_with_args::<&str>(&[]);
    drop(app);
    // A new language: start the window again, with the same arguments, so
    // every text is loaded in that language. Apps keep running.
    if i18n::RESTART.load(std::sync::atomic::Ordering::SeqCst) {
        use std::os::unix::process::CommandExt;
        if let Ok(exe) = std::env::current_exe() {
            #[expect(clippy::disallowed_methods, reason = "way out: this window again")]
            let mut cmd = std::process::Command::new(exe);
            cmd.args(std::env::args_os().skip(1));
            #[expect(clippy::disallowed_methods, reason = "way out: this window again")]
            let err = cmd.exec();
            errln!("sam-jail-gui: {err}");
        }
    }
    code
}

/// On Wayland the taskbar finds a window's icon through the desktop file
/// named after the app ID. Installed packages ship it; when SAM runs from a
/// source checkout there is none and the taskbar shows a generic icon. So
/// SAM then registers a hidden desktop entry and its icon for itself in the
/// user's data folder, and removes them again once a system-wide desktop
/// file exists. Skipped when SAM runs with its own folders (tests).
const ICON_SVG: &[u8] = include_bytes!("../../../data/io.github.gitzekatze.SAM.svg");

/// `<SAM data>/theme`, holding hicolor/scalable/apps/<app id>.svg (written
/// when missing or outdated). No icon-theme.cache, so GTK always scans it.
fn own_icon_dir() -> Option<std::path::PathBuf> {
    let root = sam_core::Paths::from_env().data_dir.join("theme");
    let file = root
        .join("hicolor/scalable/apps")
        .join(format!("{APP_ID}.svg"));
    install_icon(&file, &root.join("hicolor"), ICON_SVG)?;
    Some(root)
}

/// Writes an icon so that desktops notice a new one. Icon caches (GTK's
/// icon-theme.cache, KDE's icon cache) look only at the folders' change
/// times, and overwriting a file in place changes none of them: the
/// taskbar kept showing SAM's old icon. So the icon is written as a new
/// file, and every folder from the icon up to `theme_root` that is older
/// than the icon is marked as changed (this also repairs an icon that was
/// replaced in place before).
fn install_icon(file: &std::path::Path, theme_root: &std::path::Path, svg: &[u8]) -> Option<()> {
    if std::fs::read(file).ok().as_deref() != Some(svg) {
        std::fs::create_dir_all(file.parent()?).ok()?;
        let tmp = file.with_extension("svg.new");
        std::fs::write(&tmp, svg).ok()?;
        std::fs::rename(&tmp, file).ok()?;
    }
    let icon_time = std::fs::metadata(file).and_then(|m| m.modified()).ok()?;
    for dir in file.ancestors().skip(1) {
        if !dir.starts_with(theme_root) {
            break;
        }
        if std::fs::metadata(dir)
            .and_then(|m| m.modified())
            .is_ok_and(|t| t < icon_time)
        {
            let _ =
                std::fs::File::open(dir).and_then(|d| d.set_modified(std::time::SystemTime::now()));
        }
    }
    Some(())
}

fn desktop_identity() {
    // A run whose folders a developer switch moves (tests) leaves the
    // desktop's entry for SAM alone.
    if sam_core::paths::folders_moved_by_a_developer_switch() {
        return;
    }
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    let name = format!("{APP_ID}.desktop");
    let ours = data_home.join("applications").join(&name);
    let icon = data_home
        .join("icons/hicolor/scalable/apps")
        .join(format!("{APP_ID}.svg"));
    let system = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into())
        .split(':')
        .any(|d| {
            std::path::Path::new(d)
                .join("applications")
                .join(&name)
                .is_file()
        });
    let is_ours = std::fs::read_to_string(&ours).is_ok_and(|t| t.contains("X-SAM-Self=true"));
    if system {
        if is_ours {
            let _ = std::fs::remove_file(&ours);
            let _ = std::fs::remove_file(&icon);
        }
        return;
    }
    if ours.exists() && !is_ours {
        return; // A desktop file the user made: leave it alone.
    }
    // From SAM's AppImage: the AppImage file (its mount folder changes).
    let Some(exe) = sam_core::util::own_appimage().or_else(|| std::env::current_exe().ok()) else {
        return;
    };
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=SAM\nComment=Sandbox AppImages and manage their permissions\nExec=\"{}\" %F\nIcon={APP_ID}\nTerminal=false\nNoDisplay=true\nStartupWMClass={APP_ID}\nX-SAM-Self=true\n",
        exe.display()
    );
    if std::fs::read_to_string(&ours).ok().as_deref() != Some(entry.as_str()) {
        if let Some(dir) = ours.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&ours, entry);
    }
    let _ = install_icon(&icon, &data_home.join("icons/hicolor"), ICON_SVG);
}

#[cfg(test)]
mod tests {
    /// A new icon is noticed by the desktop's icon caches: the folders
    /// from the icon up to the theme are marked as changed, also when an
    /// earlier version had replaced the icon in place; once they are newer
    /// than the icon, nothing is touched again (regression: the taskbar
    /// kept SAM's old icon).
    #[test]
    fn a_new_icon_marks_its_folders_as_changed() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("icons/hicolor");
        let apps = root.join("scalable/apps");
        std::fs::create_dir_all(&apps).unwrap();
        let file = apps.join("app.svg");
        std::fs::write(&file, b"<svg>old</svg>").unwrap();
        let long_ago =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        let age = |p: &std::path::Path| std::fs::metadata(p).unwrap().modified().unwrap();
        let set_old = || {
            for d in [&root, &root.join("scalable"), &apps] {
                std::fs::File::open(d)
                    .unwrap()
                    .set_modified(long_ago)
                    .unwrap();
            }
        };
        set_old();
        super::install_icon(&file, &root, b"<svg>new</svg>").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"<svg>new</svg>");
        for d in [&root, &root.join("scalable"), &apps] {
            assert!(
                age(d) > long_ago,
                "{} was not marked as changed",
                d.display()
            );
        }
        assert!(
            age(t.path()) <= age(&root),
            "folders above the theme are not touched"
        );
        // The icon was already replaced in place earlier: the folders are
        // still marked, because they are older than the icon.
        set_old();
        super::install_icon(&file, &root, b"<svg>new</svg>").unwrap();
        assert!(age(&root) > long_ago);
        // Up to date: nothing changes on the next start.
        let before = age(&root);
        std::thread::sleep(std::time::Duration::from_millis(20));
        super::install_icon(&file, &root, b"<svg>new</svg>").unwrap();
        assert_eq!(age(&root), before);
        assert!(!apps.join("app.svg.new").exists());
    }

    use super::CSS;

    /// Regression: the "startup" handler that loads SAM's style sheet was
    /// connected after `register()`, which emits "startup" for the first
    /// instance at once. On every normal start, tags and badges had no
    /// colors. The handler must be connected before `register()`.
    #[test]
    fn the_style_sheet_handler_is_connected_before_register() {
        let src = include_str!("main.rs");
        let main = &src[src.find("fn main()").expect("main")..];
        let startup = main.find("app.connect_startup(").expect("startup handler");
        let register = main.find("app.register(").expect("register");
        assert!(
            startup < register,
            "connect_startup must come before register"
        );
    }

    /// Every color SAM's window uses has a style rule: the badge tones in
    /// the code, the three risk levels of tags and badges, and the outline.
    #[test]
    fn every_color_in_use_has_a_style_rule() {
        let tones = [
            "bad", "blue", "good", "neutral", "warn", "harmless", "caution", "danger", "accent",
        ];
        for t in tones {
            assert!(
                CSS.contains(&format!(".sam-badge-{t}")),
                "no rule for badge tone {t}"
            );
        }
        for level in ["harmless", "caution", "danger"] {
            assert!(
                CSS.contains(&format!(".sam-tag-{level}")),
                "no rule for tag level {level}"
            );
            assert_eq!(
                crate::util::risk_tone(match level {
                    "harmless" => "medium",
                    "caution" => "high",
                    _ => "dangerous",
                }),
                level,
                "badges and tags share the risk colors"
            );
        }
        assert!(CSS.contains(".sam-tag-outline"));
        // Fixed colors: a theme without a named color must not drop a rule.
        let tag_rules: String = CSS
            .lines()
            .filter(|l| l.contains(".sam-tag-") || l.contains(".sam-badge-"))
            .collect();
        assert!(
            !tag_rules.contains('@'),
            "tag and badge colors must not depend on theme colors"
        );
    }
}
