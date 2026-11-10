// SPDX-License-Identifier: GPL-3.0-or-later
//! SAM's GUI (GTK 4 / libadwaita).
//!
//!   sam-jail-gui [--page app|file|presets|preferences|diagnostics] [--app <id>] [FILES…]
//!   sam-jail-gui --screenshot out.png [--size 1180x800] [--delay 3000] [--page …]
//!
//! --screenshot renders the window once it has loaded, saves it as PNG and
//! exits; used for documentation and UI checks.

// GTK callbacks (Box<dyn Fn(&Rc<…>)>) are complex types by nature.
#![allow(clippy::type_complexity)]

mod app_page;
mod backend;
mod pages;
mod perms;
mod util;
mod window;

use adw::prelude::*;
use gtk::{gdk, gio, glib};

const APP_ID: &str = "io.github.gitzekatze.SAM";

const CSS: &str = r#"
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
.sam-badge-neutral { background-color: alpha(@window_fg_color, 0.08); color: alpha(@window_fg_color, 0.7); }

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
button.sam-remove:hover { background-color: alpha(@error_color, 0.12); }
textview.sam-mono text { background: transparent; }
"#;

struct Options {
    startup: window::Startup,
    screenshot: Option<String>,
    size: (i32, i32),
    delay: u64,
}

fn parse_args() -> Options {
    let mut o = Options { startup: window::Startup::default(), screenshot: None, size: (1180, 800), delay: 3000 };
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
            "-h" | "--help" => {
                println!("Usage: sam-jail-gui [--page app|file|presets|preferences|diagnostics] [--app ID] [FILES…]");
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
    let opts = parse_args();
    glib::set_application_name("SAM");
    let app = adw::Application::builder().application_id(APP_ID).flags(gio::ApplicationFlags::NON_UNIQUE).build();
    let opts = std::rc::Rc::new(std::cell::RefCell::new(Some(opts)));
    app.connect_startup(|_| {
        let css = gtk::CssProvider::new();
        css.load_from_string(CSS);
        if let Some(display) = gdk::Display::default() {
            gtk::style_context_add_provider_for_display(&display, &css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
            // Debug builds started from a checkout: find the app icon next to
            // the sources. Release builds use the installed icon, so the
            // build folder's path never ends up in a packaged binary.
            #[cfg(debug_assertions)]
            gtk::IconTheme::for_display(&display).add_search_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../../data"));
        }
    });
    app.connect_activate(move |app| {
        let Some(o) = opts.borrow_mut().take() else { return };
        let win = window::App::new(app);
        if o.screenshot.is_some() {
            win.window.set_default_size(o.size.0, o.size.1);
        }
        win.window.present();
        win.start(o.startup);
        if let Some(file) = o.screenshot {
            let w = win.clone();
            let app = app.clone();
            glib::timeout_add_local_once(std::time::Duration::from_millis(o.delay), move || {
                save_screenshot(&w.window, &file);
                app.quit();
            });
        }
        // Keep the window state alive for the lifetime of the window.
        let keep = std::cell::RefCell::new(Some(win.clone()));
        win.window.connect_close_request(move |_| {
            keep.borrow_mut().take();
            glib::Propagation::Proceed
        });
    });
    app.run_with_args::<&str>(&[])
}

/// Saves the window, plus (as `<file>-content.png`) the full scrollable
/// content of the right column, which is often taller than the screen.
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
    let (w, h) = (widget.width() as f64, widget.height() as f64);
    if w < 1.0 || h < 1.0 {
        return;
    }
    let snapshot = gtk::Snapshot::new();
    // The window background, so transparent content stays readable.
    let bg = widget.color();
    let _ = bg;
    paintable.snapshot(&snapshot, w, h);
    let Some(node) = snapshot.to_node() else { return };
    let Some(renderer) = window.native().and_then(|n| n.renderer()) else { return };
    let texture = renderer.render_texture(&node, Some(&gtk::graphene::Rect::new(0.0, 0.0, w as f32, h as f32)));
    if let Err(e) = texture.save_to_png(file) {
        eprintln!("screenshot: {e}");
    }
}

