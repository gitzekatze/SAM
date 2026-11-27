// SPDX-License-Identifier: GPL-3.0-or-later
//! Window screenshots for documentation and UI checks:
//!
//!   sam-jail-gui --screenshot out.png [--size 1180x800] [--delay 3000] [--page …] [--focus-walk]
//!
//! --screenshot renders the window once it has loaded, saves it as PNG and
//! exits. Only development builds and builds with the `dev-tools` feature
//! have these options; release builds and packages never do.

use adw::prelude::*;
use gtk::glib;
use sam_core::{errln, outln};

pub(crate) struct Options {
    /// The PNG to write; None for an ordinary start.
    pub(crate) file: Option<String>,
    /// Also walk the keyboard focus with Tab and print every stop (a check
    /// that everything is reachable by keyboard).
    focus_walk: bool,
    size: (i32, i32),
    delay: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            file: None,
            focus_walk: false,
            size: (1180, 800),
            delay: 3000,
        }
    }
}

impl Options {
    /// Takes `a` (and its value from `args`) when it is one of the
    /// screenshot options.
    pub(crate) fn parse(&mut self, a: &str, args: &mut impl Iterator<Item = String>) -> bool {
        match a {
            "--screenshot" => self.file = args.next(),
            "--size" => {
                if let Some((w, h)) = args.next().and_then(|s| {
                    s.split_once('x')
                        .map(|(w, h)| (w.parse().unwrap_or(1180), h.parse().unwrap_or(800)))
                }) {
                    self.size = (w, h);
                }
            }
            "--delay" => self.delay = args.next().and_then(|s| s.parse().ok()).unwrap_or(3000),
            "--focus-walk" => self.focus_walk = true,
            _ => return false,
        }
        true
    }

    /// A screenshot run: the window gets the asked size before it shows.
    pub(crate) fn size_window(&self, window: &adw::ApplicationWindow) {
        if self.file.is_some() {
            window.set_default_size(self.size.0, self.size.1);
        }
    }

    /// A screenshot run: saves the window after the delay, then walks the
    /// focus (--focus-walk) or quits.
    pub(crate) fn take_later(self, window: adw::ApplicationWindow, app: adw::Application) {
        let Some(file) = self.file else {
            return;
        };
        let focus_walk = self.focus_walk;
        glib::timeout_add_local_once(std::time::Duration::from_millis(self.delay), move || {
            save_screenshot(&window, &file);
            if focus_walk {
                walk_focus(&window, app);
            } else {
                app.quit();
            }
        });
    }
}

/// Saves the window, plus (as `<file>-content.png`) the full scrollable
/// content of the right column, which is often taller than the screen.
fn save_screenshot(window: &adw::ApplicationWindow, file: &str) {
    render_widget(window.upcast_ref(), window.upcast_ref(), file);
    if let Some(content) = window.content().and_then(|c| last_viewport_child(&c)) {
        render_widget(
            window.upcast_ref(),
            &content,
            &file.replace(".png", "-content.png"),
        );
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
    // Each way to save nothing says so: a smoke test must name the reason,
    // not only "no screenshot".
    if w < 1.0 || h < 1.0 {
        errln!("screenshot {file}: nothing to draw, the widget is {w}x{h} (not shown?)");
        return;
    }
    let snapshot = gtk::Snapshot::new();
    paintable.snapshot(&snapshot, w, h);
    let Some(node) = snapshot.to_node() else {
        errln!("screenshot {file}: the widget drew nothing");
        return;
    };
    let Some(renderer) = window.native().and_then(|n| n.renderer()) else {
        errln!("screenshot {file}: the window has no renderer (not shown?)");
        return;
    };
    let texture = renderer.render_texture(
        &node,
        Some(&gtk::graphene::Rect::new(0.0, 0.0, w as f32, h as f32)),
    );
    if let Err(e) = texture.save_to_png(file) {
        errln!("screenshot: {e}");
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
            .or_else(|| {
                w.downcast_ref::<adw::PreferencesRow>()
                    .map(|r| r.title().to_string())
            })
            .or_else(|| {
                w.downcast_ref::<gtk::ListBoxRow>()
                    .map(|_| "list row".to_string())
            })
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
        format!(
            "{} \"{}\" [page {page}]",
            w.type_().name(),
            label.replace('\n', " ")
        )
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
        let id = focus
            .as_ref()
            .map(|f| format!("{:p}", f.as_ptr()))
            .unwrap_or_default();
        if !moved || focus.is_none() || n >= 300 || seen.borrow().contains(&id) {
            outln!(
                "FOCUS stopped after {n} steps (moved={moved}, now at {})",
                focus.as_ref().map(name).unwrap_or_default()
            );
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
                outln!("FOCUS chain: {}", chain.join(" < "));
            }
            app.quit();
            return glib::ControlFlow::Break;
        }
        seen.borrow_mut().push(id);
        if let Some(f) = focus {
            outln!("FOCUS {n:3} {}", name(&f));
        }
        glib::ControlFlow::Continue
    });
}
