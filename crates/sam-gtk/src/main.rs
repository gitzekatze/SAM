// SPDX-License-Identifier: GPL-3.0-or-later
//! SAM's GUI (GTK 4 / libadwaita).
//!
//!   sam-jail-gui [--page app|file|permissions|presets|preferences|diagnostics] [--app <id>[,<id>…]] [FILES…]
//!   sam-jail-gui --screenshot out.png [--size 1180x800] [--delay 3000] [--page …] [--focus-walk]
//!
//! --screenshot renders the window once it has loaded, saves it as PNG and
//! exits; used for documentation and UI checks.

// GTK callbacks (Box<dyn Fn(&Rc<…>)>) are complex types by nature.
#![allow(clippy::type_complexity)]

mod all_perms;
mod app_page;
mod backend;
mod guide;
mod i18n;
mod pages;
mod perms;
mod util;
mod window;

use adw::prelude::*;
use gtk::{gdk, gio, glib};

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
/* Permission tags: color = risk, filled = read & write, outline = read-only. */
.sam-tag {
    padding: 1px 8px;
    border-radius: 999px;
    font-size: 0.8em;
    font-weight: 600;
    border: 1px solid transparent;
}
.sam-tag-harmless { background-color: alpha(@window_fg_color, 0.09); color: alpha(@window_fg_color, 0.85); }
.sam-tag-caution  { background-color: alpha(@warning_color, 0.20); color: mix(@warning_color, @window_fg_color, 0.45); }
.sam-tag-danger   { background-color: alpha(@error_color, 0.18);   color: mix(@error_color, @window_fg_color, 0.3); }
.sam-tag-outline  { background-color: transparent; border-color: currentColor; }
.sam-tag-button { padding: 2px; min-height: 0; }
.sam-tag-button.sam-filter-has .sam-tag { border-color: currentColor; }
.sam-tag-button.sam-filter-not .sam-tag { background-color: alpha(@window_fg_color, 0.08); color: alpha(@window_fg_color, 0.7); }
.sam-perms-side { background-color: @sidebar_bg_color; }
.sam-badge {
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 0.82em;
    font-weight: 700;
}
.sam-badge-accent  { background-color: alpha(@accent_color, 0.15);  color: @accent_color; }
.sam-badge-good    { background-color: alpha(@success_color, 0.15); color: @success_color; }
.sam-badge-warn    { background-color: alpha(@warning_color, 0.18); color: @warning_color; }
.sam-badge-bad     { background-color: alpha(@error_color, 0.15);   color: @error_color; }
.sam-badge-danger  { background-color: @error_bg_color;             color: @error_fg_color; }
.sam-badge-neutral { background-color: alpha(@window_fg_color, 0.10); color: alpha(@window_fg_color, 0.85); }
/* Text mixed towards the window text colour: darker in light style, lighter
   in dark style, so it keeps a contrast of at least 4.5:1 in both. */
.sam-badge-blue    { background-color: alpha(#3584e4, 0.20);        color: mix(#3584e4, @window_fg_color, 0.45); }

.sam-chip {
    padding: 1px 2px 1px 10px;
    border-radius: 999px;
    background-color: alpha(@window_fg_color, 0.08);
}
.sam-chip button { min-width: 22px; min-height: 22px; padding: 0; }

.sam-location-list row { min-height: 30px; }
.sam-location-list button.circular { min-width: 24px; min-height: 24px; padding: 0; }

.sam-mono { font-size: 0.86em; background: transparent; }

button.sam-remove { color: @error_color; font-size: 0.9em; padding: 2px 10px; }

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
button.sam-remove:hover { background-color: alpha(@error_color, 0.12); }
textview.sam-mono text { background: transparent; }
"#;

struct Options {
    startup: window::Startup,
    screenshot: Option<String>,
    /// With --screenshot: also walk the keyboard focus with Tab and print
    /// every stop (a check that everything is reachable by keyboard).
    focus_walk: bool,
    size: (i32, i32),
    delay: u64,
}

fn parse_args() -> Options {
    let mut o = Options { startup: window::Startup::default(), screenshot: None, focus_walk: false, size: (1180, 800), delay: 3000 };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--page" => o.startup.page = args.next().unwrap_or_default(),
            "--app" => o.startup.app = args.next().unwrap_or_default(),
            "--screenshot" => o.screenshot = args.next(),
            "--size" => {
                if let Some((w, h)) = args.next().and_then(|s| s.split_once('x').map(|(w, h)| (w.parse().unwrap_or(1180), h.parse().unwrap_or(800)))) {
                    o.size = (w, h);
                }
            }
            "--delay" => o.delay = args.next().and_then(|s| s.parse().ok()).unwrap_or(3000),
            "--focus-walk" => o.focus_walk = true,
            "-h" | "--help" => {
                println!("Usage: sam-jail-gui [--page app|file|permissions|presets|preferences|diagnostics] [--app ID] [FILES…]");
                std::process::exit(0);
            }
            "--version" => {
                println!("sam-jail-gui {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            f => o.startup.files.push(std::fs::canonicalize(f).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| f.to_string())),
        }
    }
    o
}

fn main() -> glib::ExitCode {
    i18n::init();
    let opts = parse_args();
    glib::set_application_name("SAM - Sandboxed AppImage Manager");
    // One window per set of SAM data: starting SAM again brings the open
    // window forward (and hands over AppImages given on the command line),
    // so two windows never write the same configuration. Screenshot runs and
    // runs with their own data folders (tests) stay separate.
    let separate = opts.screenshot.is_some() || std::env::var_os("SAM_CONFIG_DIR").is_some() || std::env::var_os("SAM_DATA_DIR").is_some();
    let flags = if separate { gio::ApplicationFlags::NON_UNIQUE } else { gio::ApplicationFlags::HANDLES_OPEN };
    let app = adw::Application::builder().application_id(APP_ID).flags(flags).build();
    if !separate && app.register(gio::Cancellable::NONE).is_ok() && app.is_remote() {
        if opts.startup.files.is_empty() {
            app.activate();
        } else {
            let files: Vec<gio::File> = opts.startup.files.iter().map(gio::File::for_path).collect();
            app.open(&files, "");
        }
        return glib::ExitCode::SUCCESS;
    }
    let opts = std::rc::Rc::new(std::cell::RefCell::new(Some(opts)));
    // The window, once open: a second start brings it forward.
    let current: std::rc::Rc<std::cell::RefCell<Option<std::rc::Rc<window::App>>>> = Default::default();
    let cur = current.clone();
    app.connect_open(move |app, files, _| {
        let paths: Vec<String> = files.iter().filter_map(|f| f.path()).map(|p| p.to_string_lossy().into_owned()).collect();
        match cur.borrow().as_ref() {
            Some(win) => {
                win.window.present();
                win.add_files(paths);
            }
            None => app.activate(),
        }
    });
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
            gtk::style_context_add_provider_for_display(&display, &css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
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
            gtk::IconTheme::for_display(&display).add_search_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../../data"));
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
        if o.screenshot.is_some() {
            win.window.set_default_size(o.size.0, o.size.1);
        }
        win.window.present();
        win.start(o.startup);
        if let Some(file) = o.screenshot {
            let w = win.clone();
            let app = app.clone();
            let focus_walk = o.focus_walk;
            glib::timeout_add_local_once(std::time::Duration::from_millis(o.delay), move || {
                save_screenshot(&w.window, &file);
                if focus_walk {
                    walk_focus(&w.window, app.clone());
                } else {
                    app.quit();
                }
            });
        }
        // Keep the window state alive for the lifetime of the window.
        let keep = std::cell::RefCell::new(Some(win.clone()));
        let cur = current.clone();
        win.window.connect_close_request(move |_| {
            keep.borrow_mut().take();
            cur.borrow_mut().take();
            glib::Propagation::Proceed
        });
    });
    app.run_with_args::<&str>(&[])
}

/// Saves the window, plus (as `<file>-content.png`) the full scrollable
/// content of the right column, which is often taller than the screen.
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
    let file = root.join("hicolor/scalable/apps").join(format!("{APP_ID}.svg"));
    if std::fs::read(&file).ok().as_deref() != Some(ICON_SVG) {
        std::fs::create_dir_all(file.parent()?).ok()?;
        std::fs::write(&file, ICON_SVG).ok()?;
    }
    Some(root)
}

fn desktop_identity() {
    if std::env::var_os("SAM_CONFIG_DIR").is_some() || std::env::var_os("SAM_DATA_DIR").is_some() {
        return;
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
    let data_home = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()).map(std::path::PathBuf::from).unwrap_or_else(|| home.join(".local/share"));
    let name = format!("{APP_ID}.desktop");
    let ours = data_home.join("applications").join(&name);
    let icon = data_home.join("icons/hicolor/scalable/apps").join(format!("{APP_ID}.svg"));
    let system = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into())
        .split(':')
        .any(|d| std::path::Path::new(d).join("applications").join(&name).is_file());
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
    let Some(exe) = sam_core::util::own_appimage().or_else(|| std::env::current_exe().ok()) else { return };
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=SAM\nComment=Sandbox AppImages and manage their permissions\nExec=\"{}\" %F\nIcon={APP_ID}\nTerminal=false\nNoDisplay=true\nStartupWMClass={APP_ID}\nX-SAM-Self=true\n",
        exe.display()
    );
    if std::fs::read_to_string(&ours).ok().as_deref() != Some(entry.as_str()) {
        let _ = std::fs::create_dir_all(ours.parent().unwrap());
        let _ = std::fs::write(&ours, entry);
    }
    if std::fs::read(&icon).ok().as_deref() != Some(ICON_SVG) {
        let _ = std::fs::create_dir_all(icon.parent().unwrap());
        let _ = std::fs::write(&icon, ICON_SVG);
    }
}

fn save_screenshot(window: &adw::ApplicationWindow, file: &str) {
    render_widget(window.upcast_ref(), window.upcast_ref(), file);
    if let Some(content) = window.content().and_then(|c| last_viewport_child(&c)) {
        render_widget(window.upcast_ref(), &content, &file.replace(".png", "-content.png"));
    }
}

fn last_viewport_child(w: &gtk::Widget) -> Option<gtk::Widget> {
    let mut found = None;
    let mut child = w.first_child();
    while let Some(c) = child {
        if c.is::<gtk::Viewport>() && c.is_mapped() {
            found = c.first_child();
        }
        if let Some(f) = last_viewport_child(&c) {
            found = Some(f);
        }
        child = c.next_sibling();
    }
    found
}

fn render_widget(window: &gtk::Widget, widget: &gtk::Widget, file: &str) {
    let paintable = gtk::WidgetPaintable::new(Some(widget));
    // Cairo (GTK's renderer on Broadway and older systems) cannot make
    // images taller than 32767 px; very long pages are cut at 16384.
    let (w, h) = (widget.width() as f64, (widget.height() as f64).min(16384.0));
    if w < 1.0 || h < 1.0 {
        return;
    }
    let snapshot = gtk::Snapshot::new();
    paintable.snapshot(&snapshot, w, h);
    let Some(node) = snapshot.to_node() else { return };
    let Some(renderer) = window.native().and_then(|n| n.renderer()) else { return };
    let texture = renderer.render_texture(&node, Some(&gtk::graphene::Rect::new(0.0, 0.0, w as f32, h as f32)));
    if let Err(e) = texture.save_to_png(file) {
        eprintln!("screenshot: {e}");
    }
}

/// Moves the focus forward with Tab, a step every 1.5 s (time for a page
/// the focus opened to load, as for a person), until it comes back to the
/// start, printing each stop; then quits.
fn walk_focus(window: &adw::ApplicationWindow, app: adw::Application) {
    use gtk::prelude::*;
    fn name(w: &gtk::Widget) -> String {
        let label = w
            .downcast_ref::<gtk::Button>()
            .and_then(|b| b.label())
            .map(|l| l.to_string())
            .or_else(|| w.downcast_ref::<adw::PreferencesRow>().map(|r| r.title().to_string()))
            .or_else(|| w.downcast_ref::<gtk::ListBoxRow>().map(|_| "list row".to_string()))
            .or_else(|| w.tooltip_text().map(|t| t.to_string()))
            .unwrap_or_default();
        let mut page = String::new();
        let mut a = w.parent();
        while let Some(p) = a {
            if let Some(np) = p.downcast_ref::<adw::NavigationPage>() {
                page = np.title().to_string();
                break;
            }
            a = p.parent();
        }
        format!("{} \"{}\" [page {page}]", w.type_().name(), label.replace('\n', " "))
    }
    let window = window.clone();
    let seen: std::rc::Rc<std::cell::RefCell<Vec<String>>> = Default::default();
    let step = std::rc::Rc::new(std::cell::Cell::new(0u32));
    glib::timeout_add_local(std::time::Duration::from_millis(1500), move || {
        let n = step.get();
        step.set(n + 1);
        // At the end of the chain Tab wraps around to the start.
        let moved = window.child_focus(gtk::DirectionType::TabForward) || {
            gtk::prelude::GtkWindowExt::set_focus(&window, None::<&gtk::Widget>);
            window.child_focus(gtk::DirectionType::TabForward)
        };
        let focus = gtk::prelude::GtkWindowExt::focus(&window);
        let id = focus.as_ref().map(|f| format!("{:p}", f.as_ptr())).unwrap_or_default();
        if !moved || focus.is_none() || n >= 300 || seen.borrow().contains(&id) {
            println!("FOCUS stopped after {n} steps (moved={moved}, now at {})", focus.as_ref().map(name).unwrap_or_default());
            if let Some(f) = &focus {
                let mut chain = Vec::new();
                let mut w = Some(f.clone());
                while let Some(x) = w {
                    chain.push(format!("{}#{}", x.type_().name(), x.widget_name()));
                    w = x.parent();
                    if chain.len() > 12 {
                        break;
                    }
                }
                println!("FOCUS chain: {}", chain.join(" < "));
            }
            app.quit();
            return glib::ControlFlow::Break;
        }
        seen.borrow_mut().push(id);
        if let Some(f) = focus {
            println!("FOCUS {n:3} {}", name(&f));
        }
        glib::ControlFlow::Continue
    });
}
