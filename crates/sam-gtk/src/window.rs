// SPDX-License-Identifier: GPL-3.0-or-later
//! The main window: a Flatseal-style split view. Left: where SAM looks for
//! AppImages (pinned) and every AppImage it found. Right: the selected app,
//! or SAM's preferences, presets or diagnostics.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::{Rc, Weak};

use adw::prelude::*;
use gtk::{gdk, gio, glib};
use serde_json::{json, Value};

use crate::app_page::AppPage;
use crate::backend::Backend;
use crate::perms::{self, Catalog};
use crate::util::{self, esc};

/// Startup options from the command line.
#[derive(Default, Clone)]
pub struct Startup {
    pub page: String,
    pub app: String,
    pub files: Vec<String>,
}

/// One line in the app list: a found AppImage, a sandboxed app, or both.
#[derive(Clone, Default)]
pub struct Row {
    pub key: String,
    pub id: String,
    pub path: String,
    pub name: String,
    pub icon: String,
    pub sandboxed: bool,
    pub badge: String,
    pub problem: String,
    pub unsandboxed_entry: bool,
    pub moved: bool,
}

#[derive(Default)]
pub struct State {
    pub config: Value,
    pub catalog: Catalog,
    pub apps: Vec<Value>,
    pub discovered: Vec<Value>,
    pub selected: String,
    pub loaded: bool,
    pub filter: String,
    pub search: String,
}

pub struct App {
    pub window: adw::ApplicationWindow,
    pub backend: Backend,
    pub toasts: adw::ToastOverlay,
    pub split: adw::NavigationSplitView,
    /// Keeps the pinned areas at the top of both columns the same height.
    pub top_sizes: gtk::SizeGroup,
    pub state: RefCell<State>,
    sidebar: OnceCell<Sidebar>,
    /// The page shown on the right, kept alive while it is shown.
    current: RefCell<Option<Rc<dyn std::any::Any>>>,
    spinner: adw::Spinner,
}

struct Sidebar {
    locations: gtk::ListBox,
    downloads: gtk::Switch,
    list: gtk::ListBox,
    stack: gtk::Stack,
    empty: adw::StatusPage,
    rows: RefCell<Vec<Row>>,
    selecting: std::cell::Cell<bool>,
}

impl App {
    pub fn new(app: &adw::Application) -> Rc<App> {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("SAM")
            .default_width(1180)
            .default_height(800)
            .width_request(360)
            .height_request(400)
            .build();
        let split = adw::NavigationSplitView::builder().min_sidebar_width(300.0).max_sidebar_width(460.0).sidebar_width_fraction(0.38).build();
        let toasts = adw::ToastOverlay::new();
        toasts.set_child(Some(&split));
        window.set_content(Some(&toasts));
        let bp = adw::Breakpoint::new(adw::BreakpointCondition::parse("max-width: 720sp").unwrap());
        bp.add_setter(&split, "collapsed", Some(&true.to_value()));
        window.add_breakpoint(bp);

        let spinner = adw::Spinner::builder().visible(false).build();
        let sp = spinner.clone();
        let backend = Backend::new(move |busy| sp.set_visible(busy));
        let me = Rc::new(App {
            window,
            backend,
            toasts,
            split,
            top_sizes: gtk::SizeGroup::new(gtk::SizeGroupMode::Vertical),
            state: RefCell::new(State { filter: "all".into(), ..Default::default() }),
            sidebar: OnceCell::new(),
            current: RefCell::new(None),
            spinner,
        });
        me.build_sidebar();
        me.install_actions();
        me.install_drop();
        me.show_welcome();
        me
    }

    // ------------------------------------------------------------ feedback

    pub fn toast(&self, text: &str) {
        if !text.is_empty() {
            self.toasts.add_toast(adw::Toast::builder().title(esc(text)).timeout(4).build());
        }
    }

    pub fn report_error(&self, e: &str) {
        eprintln!("sam-jail: {e}");
        let t = adw::Toast::builder().title(esc(e)).timeout(8).build();
        self.toasts.add_toast(t);
    }

    // ------------------------------------------------------------ data

    pub async fn load_catalog(self: &Rc<Self>) {
        if let Ok(v) = self.backend.call(&["permissions"], None).await {
            self.state.borrow_mut().catalog = Rc::new(perms::parse_catalog(&v));
        }
    }

    pub async fn load_config(self: &Rc<Self>) {
        match self.backend.call(&["config", "show"], None).await {
            Ok(v) => {
                apply_theme(util::str_of(&v, "general.theme"));
                self.state.borrow_mut().config = v;
                self.refresh_locations();
            }
            Err(e) => self.report_error(&e),
        }
    }

    pub async fn set_config(self: &Rc<Self>, key: &str, value: &str) {
        if let Err(e) = self.backend.call(&["config", "set", key, value], None).await {
            self.report_error(&e);
        }
        self.load_config().await;
    }

    pub async fn refresh_apps(self: &Rc<Self>) {
        match self.backend.call(&["list"], None).await {
            Ok(v) => self.state.borrow_mut().apps = v.as_array().cloned().unwrap_or_default(),
            Err(e) => self.report_error(&e),
        }
        if let Ok(d) = self.backend.call(&["discover"], None).await {
            self.state.borrow_mut().discovered = d.get("apps").and_then(Value::as_array).cloned().unwrap_or_default();
        }
        self.state.borrow_mut().loaded = true;
        self.rebuild_list();
    }

    /// Refresh in the background (for callbacks that are not async).
    pub fn refresh_apps_later(self: &Rc<Self>) {
        let me = self.clone();
        glib::spawn_future_local(async move { me.refresh_apps().await });
    }

    fn rows(&self) -> Vec<Row> {
        let st = self.state.borrow();
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for d in &st.discovered {
            let sid = util::str_of(d, "sandboxed");
            let a = if sid.is_empty() { None } else { st.apps.iter().find(|x| util::str_of(x, "id") == sid) };
            let r = Row {
                key: a.map(|a| util::str_of(a, "id").to_string()).unwrap_or_else(|| util::str_of(d, "path").to_string()),
                id: a.map(|a| util::str_of(a, "id").to_string()).unwrap_or_default(),
                path: util::str_of(d, "path").to_string(),
                name: a.map(|a| util::str_of(a, "name")).unwrap_or(util::str_of(d, "name")).to_string(),
                icon: a.map(|a| util::str_of(a, "icon_path")).filter(|s| !s.is_empty()).unwrap_or(util::str_of(d, "icon")).to_string(),
                sandboxed: a.is_some(),
                badge: a.map(|a| util::str_of(a, "badge").to_string()).unwrap_or_default(),
                problem: a.map(|a| util::str_of(a, "last_problem").to_string()).unwrap_or_default(),
                unsandboxed_entry: d.get("menu_entries").and_then(Value::as_array).is_some_and(|m| !m.is_empty()),
                moved: d.get("moved_from").is_some_and(|m| !m.is_null()),
            };
            if a.is_some() {
                seen.insert(r.id.clone());
            }
            out.push(r);
        }
        // Sandboxed apps whose AppImage file is missing.
        for a in &st.apps {
            let id = util::str_of(a, "id");
            if !seen.contains(id) {
                out.push(Row {
                    key: id.into(),
                    id: id.into(),
                    path: util::str_of(a, "source_path").into(),
                    name: util::str_of(a, "name").into(),
                    icon: util::str_of(a, "icon_path").into(),
                    sandboxed: true,
                    badge: util::str_of(a, "badge").into(),
                    problem: util::str_of(a, "last_problem").into(),
                    ..Default::default()
                });
            }
        }
        let q = st.search.to_lowercase();
        let filter = st.filter.clone();
        out.retain(|r| {
            (q.is_empty() || r.name.to_lowercase().contains(&q) || r.path.to_lowercase().contains(&q))
                && match filter.as_str() {
                    "sandboxed" => r.sandboxed,
                    "unsandboxed" => !r.sandboxed,
                    _ => true,
                }
        });
        out.sort_by(|a, b| b.sandboxed.cmp(&a.sandboxed).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        out
    }

    // ------------------------------------------------------------ sidebar

    fn build_sidebar(self: &Rc<Self>) {
        let view = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        header.set_title_widget(Some(&adw::WindowTitle::new("SAM", "")));
        let menu = gio::Menu::new();
        let sect = gio::Menu::new();
        sect.append(Some("Presets"), Some("win.show-presets"));
        sect.append(Some("Diagnostics"), Some("win.show-diagnostics"));
        sect.append(Some("Preferences"), Some("win.show-preferences"));
        menu.append_section(None, &sect);
        let about = gio::Menu::new();
        about.append(Some("About SAM"), Some("win.about"));
        menu.append_section(None, &about);
        let menu_btn = gtk::MenuButton::builder().icon_name("open-menu-symbolic").menu_model(&menu).tooltip_text("Main menu").primary(true).build();
        header.pack_end(&menu_btn);
        let refresh = gtk::Button::builder().icon_name("view-refresh-symbolic").tooltip_text("Search the locations again").action_name("win.refresh").build();
        header.pack_start(&refresh);
        header.pack_start(&self.spinner);
        view.add_top_bar(&header);

        // Pinned: AppImage locations.
        let loc_box = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(6).margin_start(12).margin_end(12).margin_top(6).margin_bottom(10).build();
        loc_box.add_css_class("sam-locations");
        let loc_head = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        let loc_title = gtk::Label::builder().label("AppImage locations").xalign(0.0).hexpand(true).build();
        loc_title.add_css_class("heading");
        loc_head.append(&loc_title);
        let add_folder = gtk::Button::builder().icon_name("folder-new-symbolic").tooltip_text("Search a folder for AppImages").build();
        add_folder.add_css_class("flat");
        let add_file = gtk::Button::builder().icon_name("list-add-symbolic").tooltip_text("Add a single AppImage file").build();
        add_file.add_css_class("flat");
        loc_head.append(&add_folder);
        loc_head.append(&add_file);
        loc_box.append(&loc_head);
        let locations = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();
        locations.add_css_class("boxed-list");
        locations.add_css_class("sam-location-list");
        let loc_scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .propagate_natural_height(true)
            .max_content_height(104)
            .child(&locations)
            .build();
        loc_box.append(&loc_scroll);
        let dl_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let dl_label = gtk::Label::builder().label("Also search the Downloads folder").xalign(0.0).hexpand(true).build();
        dl_label.add_css_class("caption");
        let downloads = gtk::Switch::builder().valign(gtk::Align::Center).build();
        dl_row.append(&dl_label);
        dl_row.append(&downloads);
        loc_box.append(&dl_row);
        view.add_top_bar(&loc_box);
        self.top_sizes.add_widget(&loc_box);

        // Pinned: search and filter.
        let filter_box = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(8).margin_start(12).margin_end(12).margin_bottom(6).build();
        let search = gtk::SearchEntry::builder().placeholder_text("Search AppImages").build();
        filter_box.append(&search);
        let toggles = adw::ToggleGroup::new();
        toggles.add_css_class("round");
        for (name, label) in [("all", "All"), ("sandboxed", "Sandboxed"), ("unsandboxed", "Unsandboxed")] {
            toggles.add(adw::Toggle::builder().name(name).label(label).build());
        }
        toggles.set_active_name(Some("all"));
        filter_box.append(&toggles);
        view.add_top_bar(&filter_box);

        // The app list.
        let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::Single).build();
        list.add_css_class("navigation-sidebar");
        let empty = adw::StatusPage::builder()
            .icon_name("system-search-symbolic")
            .title("No AppImages Found")
            .description("Add a folder or a single AppImage file above, or drop an AppImage onto this window.")
            .build();
        empty.add_css_class("compact");
        let stack = gtk::Stack::builder().transition_type(gtk::StackTransitionType::Crossfade).build();
        stack.add_named(&list, Some("list"));
        stack.add_named(&empty, Some("empty"));
        let scroll = gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).vexpand(true).child(&stack).build();
        view.set_content(Some(&scroll));

        let page = adw::NavigationPage::builder().title("SAM").child(&view).build();
        self.split.set_sidebar(Some(&page));

        // Signals.
        let w = Rc::downgrade(self);
        add_folder.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.pick_location(true);
            }
        });
        let w = Rc::downgrade(self);
        add_file.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.pick_location(false);
            }
        });
        let w = Rc::downgrade(self);
        downloads.connect_state_set(move |_, on| {
            if let Some(me) = w.upgrade() {
                let cur = util::bool_of(&me.state.borrow().config, "general.scan_downloads");
                if cur != on {
                    glib::spawn_future_local(async move {
                        me.set_config("general.scan_downloads", if on { "true" } else { "false" }).await;
                        me.refresh_apps().await;
                    });
                }
            }
            glib::Propagation::Proceed
        });
        let w = Rc::downgrade(self);
        search.connect_search_changed(move |s| {
            if let Some(me) = w.upgrade() {
                me.state.borrow_mut().search = s.text().to_string();
                me.rebuild_list();
            }
        });
        let w = Rc::downgrade(self);
        toggles.connect_active_name_notify(move |t| {
            if let Some(me) = w.upgrade() {
                me.state.borrow_mut().filter = t.active_name().map(|s| s.to_string()).unwrap_or_else(|| "all".into());
                me.rebuild_list();
            }
        });
        let w = Rc::downgrade(self);
        list.connect_row_selected(move |_, row| {
            let (Some(me), Some(row)) = (w.upgrade(), row) else { return };
            let sb = me.sidebar.get().unwrap();
            if sb.selecting.get() {
                return;
            }
            let r = sb.rows.borrow().get(row.index() as usize).cloned();
            if let Some(r) = r {
                me.select_row(&r);
            }
        });
        let w = Rc::downgrade(self);
        list.set_header_func(move |row, before| {
            let Some(me) = w.upgrade() else { return };
            let Some(sb) = me.sidebar.get() else { return };
            if me.state.borrow().filter != "all" {
                row.set_header(None::<&gtk::Widget>);
                return;
            }
            let rows = sb.rows.borrow();
            let cur = rows.get(row.index() as usize).map(|r| r.sandboxed);
            let prev = before.and_then(|b| rows.get(b.index() as usize)).map(|r| r.sandboxed);
            if cur.is_some() && cur != prev {
                let l = gtk::Label::builder()
                    .label(if cur == Some(true) { "Sandboxed" } else { "Not sandboxed" })
                    .xalign(0.0)
                    .margin_start(12)
                    .margin_top(if prev.is_some() { 14 } else { 4 })
                    .margin_bottom(4)
                    .build();
                l.add_css_class("heading");
                l.add_css_class("dim-label");
                l.add_css_class("caption-heading");
                row.set_header(Some(&l));
            } else {
                row.set_header(None::<&gtk::Widget>);
            }
        });

        let _ = self.sidebar.set(Sidebar {
            locations,
            downloads,
            list,
            stack,
            empty,
            rows: RefCell::new(Vec::new()),
            selecting: std::cell::Cell::new(false),
        });
    }

    fn refresh_locations(self: &Rc<Self>) {
        let Some(sb) = self.sidebar.get() else { return };
        while let Some(c) = sb.locations.first_child() {
            sb.locations.remove(&c);
        }
        let cfg = self.state.borrow().config.clone();
        let mut locs: Vec<(String, bool)> = util::list_of(&cfg, "general.scan_directories").into_iter().map(|p| (p, false)).collect();
        locs.extend(util::list_of(&cfg, "general.scan_files").into_iter().map(|p| (p, true)));
        for (path, file) in locs {
            let row = gtk::ListBoxRow::builder().activatable(false).build();
            let b = gtk::Box::builder().spacing(8).margin_start(10).margin_end(4).margin_top(3).margin_bottom(3).build();
            b.append(&gtk::Image::from_icon_name(if file { "application-vnd.appimage" } else { "folder-symbolic" }));
            let l = gtk::Label::builder().label(util::plain(&util::tildify(&path))).xalign(0.0).hexpand(true).ellipsize(gtk::pango::EllipsizeMode::Middle).build();
            l.add_css_class("caption");
            b.append(&l);
            row.set_tooltip_text(Some(&util::plain(&util::tildify(&path))));
            let rm = gtk::Button::builder().icon_name("window-close-symbolic").tooltip_text("Stop searching here").valign(gtk::Align::Center).build();
            rm.add_css_class("flat");
            rm.add_css_class("circular");
            let w = Rc::downgrade(self);
            rm.connect_clicked(move |_| {
                if let Some(me) = w.upgrade() {
                    me.remove_location(&path, file);
                }
            });
            b.append(&rm);
            row.set_child(Some(&b));
            sb.locations.append(&row);
        }
        if sb.locations.first_child().is_none() {
            let row = gtk::ListBoxRow::builder().activatable(false).build();
            let l = gtk::Label::builder().label("No locations yet: add a folder or a file.").margin_top(8).margin_bottom(8).build();
            l.add_css_class("dim-label");
            l.add_css_class("caption");
            row.set_child(Some(&l));
            sb.locations.append(&row);
        }
        sb.downloads.set_state(util::bool_of(&cfg, "general.scan_downloads"));
        sb.downloads.set_active(util::bool_of(&cfg, "general.scan_downloads"));
    }

    fn set_locations(self: &Rc<Self>, dirs: Vec<String>, files: Vec<String>) {
        let me = self.clone();
        glib::spawn_future_local(async move {
            me.set_config("general.scan_directories", &serde_json::to_string(&dirs).unwrap()).await;
            me.set_config("general.scan_files", &serde_json::to_string(&files).unwrap()).await;
            me.refresh_apps().await;
        });
    }

    fn remove_location(self: &Rc<Self>, path: &str, file: bool) {
        let cfg = self.state.borrow().config.clone();
        let mut dirs = util::list_of(&cfg, "general.scan_directories");
        let mut files = util::list_of(&cfg, "general.scan_files");
        if file { files.retain(|p| p != path) } else { dirs.retain(|p| p != path) }
        self.set_locations(dirs, files);
    }

    fn pick_location(self: &Rc<Self>, folder: bool) {
        let me = self.clone();
        glib::spawn_future_local(async move {
            let home = gio::File::for_path(util::home());
            let picked = if folder {
                let d = gtk::FileDialog::builder().title("Search a folder for AppImages").initial_folder(&home).build();
                d.select_folder_future(Some(&me.window)).await.ok()
            } else {
                let filter = gtk::FileFilter::new();
                filter.set_name(Some("AppImages"));
                filter.add_pattern("*.AppImage");
                filter.add_pattern("*.appimage");
                let filters = gio::ListStore::new::<gtk::FileFilter>();
                filters.append(&filter);
                let d = gtk::FileDialog::builder().title("Add an AppImage").initial_folder(&home).filters(&filters).build();
                d.open_future(Some(&me.window)).await.ok()
            };
            let Some(p) = picked.and_then(|f| f.path()) else { return };
            let p = util::tildify(&p.to_string_lossy());
            let cfg = me.state.borrow().config.clone();
            let mut dirs = util::list_of(&cfg, "general.scan_directories");
            let mut files = util::list_of(&cfg, "general.scan_files");
            let target = if folder { &mut dirs } else { &mut files };
            if !target.contains(&p) {
                target.push(p);
            }
            me.set_locations(dirs, files);
        });
    }

    pub fn rebuild_list(self: &Rc<Self>) {
        let Some(sb) = self.sidebar.get() else { return };
        let rows = self.rows();
        sb.selecting.set(true);
        while let Some(c) = sb.list.first_child() {
            sb.list.remove(&c);
        }
        let selected = self.state.borrow().selected.clone();
        let mut select_idx = None;
        for (i, r) in rows.iter().enumerate() {
            sb.list.append(&app_row(r));
            if r.key == selected || (!selected.is_empty() && r.path == selected) {
                select_idx = Some(i);
            }
        }
        *sb.rows.borrow_mut() = rows;
        let loaded = self.state.borrow().loaded;
        let any = !sb.rows.borrow().is_empty();
        sb.stack.set_visible_child_name(if any || !loaded { "list" } else { "empty" });
        let filtered = !self.state.borrow().search.is_empty() || self.state.borrow().filter != "all";
        if filtered {
            sb.empty.set_title("No AppImages Match");
            sb.empty.set_description(Some("Try another search or filter."));
        } else {
            sb.empty.set_title("No AppImages Found");
            sb.empty.set_description(Some("Add a folder or a single AppImage file above, or drop an AppImage onto this window."));
        }
        match select_idx.and_then(|i| sb.list.row_at_index(i as i32)) {
            Some(r) => sb.list.select_row(Some(&r)),
            None => sb.list.unselect_all(),
        }
        sb.list.invalidate_headers();
        sb.selecting.set(false);
    }

    // ------------------------------------------------------------ navigation

    fn show(self: &Rc<Self>, page: &adw::NavigationPage, keep: Option<Rc<dyn std::any::Any>>) {
        self.split.set_content(Some(page));
        self.split.set_show_content(true);
        *self.current.borrow_mut() = keep;
    }

    pub fn show_welcome(self: &Rc<Self>) {
        let status = adw::StatusPage::builder()
            .icon_name("io.github.gitzekatze.SAM")
            .title("Select an AppImage")
            .description("SAM lists the AppImages in the locations on the left. Pick one to see the settings SAM recommends, adjust them, and create a sandbox. Nothing is unpacked or run before you click Create Sandbox.")
            .build();
        let view = adw::ToolbarView::new();
        view.add_top_bar(&adw::HeaderBar::builder().show_title(false).build());
        view.set_content(Some(&status));
        let page = adw::NavigationPage::builder().title("Welcome").child(&view).build();
        self.split.set_content(Some(&page));
        *self.current.borrow_mut() = None;
    }

    /// Shows one AppImage on the right.
    pub fn select_row(self: &Rc<Self>, r: &Row) {
        self.state.borrow_mut().selected = r.key.clone();
        let page = AppPage::new(self, if r.sandboxed { &r.id } else { "" }, &r.path);
        let nav = page.page.clone();
        self.show(&nav, Some(page));
        self.rebuild_list();
    }

    pub fn open_app(self: &Rc<Self>, id: &str) {
        let path = self.state.borrow().apps.iter().find(|a| util::str_of(a, "id") == id).map(|a| util::str_of(a, "source_path").to_string()).unwrap_or_default();
        self.select_row(&Row { key: id.into(), id: id.into(), path, sandboxed: true, ..Default::default() });
    }

    pub fn open_file(self: &Rc<Self>, path: &str) {
        let d = self.state.borrow().discovered.iter().find(|d| util::str_of(d, "path") == path).cloned();
        match d.map(|d| util::str_of(&d, "sandboxed").to_string()).filter(|s| !s.is_empty()) {
            Some(id) => self.open_app(&id),
            None => self.select_row(&Row { key: path.into(), path: path.into(), ..Default::default() }),
        }
    }

    pub fn show_section(self: &Rc<Self>, section: &str) {
        self.state.borrow_mut().selected.clear();
        self.rebuild_list();
        match section {
            "preferences" => {
                let p = crate::pages::preferences(self);
                self.show(&p, None);
            }
            "presets" => {
                let p = crate::pages::presets(self);
                self.show(&p.0, Some(p.1));
            }
            "diagnostics" => {
                let p = crate::pages::diagnostics(self);
                self.show(&p, None);
            }
            _ => self.show_welcome(),
        }
    }

    /// Shows a page that is not tied to an app (preset editor).
    pub fn show_page(self: &Rc<Self>, page: &adw::NavigationPage, keep: Option<Rc<dyn std::any::Any>>) {
        self.show(page, keep);
    }

    // ------------------------------------------------------------ actions

    fn install_actions(self: &Rc<Self>) {
        let add = |name: &str, f: Box<dyn Fn(&Rc<App>)>| {
            let a = gio::SimpleAction::new(name, None);
            let w = Rc::downgrade(self);
            a.connect_activate(move |_, _| {
                if let Some(me) = w.upgrade() {
                    f(&me);
                }
            });
            self.window.add_action(&a);
        };
        add("show-presets", Box::new(|me| me.show_section("presets")));
        add("show-diagnostics", Box::new(|me| me.show_section("diagnostics")));
        add("show-preferences", Box::new(|me| me.show_section("preferences")));
        add("refresh", Box::new(|me| me.refresh_apps_later()));
        add("about", Box::new(|me| {
            let d = adw::AboutDialog::builder()
                .application_name("SAM")
                .application_icon("io.github.gitzekatze.SAM")
                .version(env!("CARGO_PKG_VERSION"))
                .comments("Sandboxed AppImage Manager: sandbox AppImages with Bubblewrap and manage their permissions.")
                .website("https://github.com/gitzekatze/SAM")
                .license_type(gtk::License::Gpl30)
                .build();
            d.present(Some(&me.window));
        }));
        if let Some(app) = self.window.application() {
            app.set_accels_for_action("win.refresh", &["<primary>r", "F5"]);
            app.set_accels_for_action("window.close", &["<primary>w"]);
        }
    }

    fn install_drop(self: &Rc<Self>) {
        let target = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
        let w = Rc::downgrade(self);
        target.connect_drop(move |_, value, _, _| {
            let (Some(me), Ok(list)) = (w.upgrade(), value.get::<gdk::FileList>()) else { return false };
            let paths: Vec<String> = list.files().iter().filter_map(|f| f.path()).map(|p| p.to_string_lossy().into_owned()).collect();
            me.add_files(paths);
            true
        });
        self.window.add_controller(target);
    }

    /// Adds AppImage files (dropped or opened with SAM) to the locations
    /// and selects the first one.
    pub fn add_files(self: &Rc<Self>, paths: Vec<String>) {
        if paths.is_empty() {
            return;
        }
        let me = self.clone();
        glib::spawn_future_local(async move {
            let mut files = util::list_of(&me.state.borrow().config, "general.scan_files");
            for p in &paths {
                let t = util::tildify(p);
                if !files.contains(&t) {
                    files.push(t);
                }
            }
            me.set_config("general.scan_files", &serde_json::to_string(&files).unwrap()).await;
            me.refresh_apps().await;
            me.open_file(&paths[0]);
        });
    }

    pub fn launch(self: &Rc<Self>, id: &str) {
        let w = Rc::downgrade(self);
        let id2 = id.to_string();
        match self.backend.launch(id, &[], move |code| {
            let Some(me) = w.upgrade() else { return };
            me.refresh_apps_later();
            if code != 0 {
                let t = adw::Toast::builder().title(format!("The app stopped with an error (code {code}).")).button_label("Fix It").timeout(8).build();
                let w2 = Rc::downgrade(&me);
                t.connect_button_clicked(move |_| {
                    if let Some(me) = w2.upgrade() {
                        me.open_app(&id2);
                    }
                });
                me.toasts.add_toast(t);
            }
        }) {
            Ok(()) => self.toast("Starting in sandbox…"),
            Err(e) => self.report_error(&e),
        }
    }

    /// Applies a preset, with SAM's compatibility check.
    pub async fn apply_preset(self: &Rc<Self>, name: &str, app_id: &str) -> bool {
        let r = match self.backend.call(&["preset", "apply", name, app_id], None).await {
            Ok(r) => r,
            Err(e) => {
                self.report_error(&e);
                return false;
            }
        };
        if util::bool_of(&r, "applied") {
            self.toast(&format!("Applied “{name}”"));
            self.refresh_apps().await;
            return true;
        }
        let c = r.get("check").cloned().unwrap_or(json!({}));
        let mut text = String::new();
        let removes = util::list_of(&c, "removes_needed");
        if !removes.is_empty() {
            text.push_str(&format!("This preset removes permissions the app likely needs: {}.\n\n", removes.join(", ")));
        }
        let adds = util::list_of(&c, "adds_dangerous");
        if !adds.is_empty() {
            text.push_str(&format!("It adds high-risk permissions: {}.\n\n", adds.join(", ")));
        }
        text.push_str(&format!("Risk changes from {} to {}.", util::str_of(&c, "risk_before"), util::str_of(&c, "risk_after")));
        if !confirm(&self.window, &format!("Apply “{name}” Anyway?"), &text, "Apply", false).await {
            return false;
        }
        match self.backend.call(&["preset", "apply", name, app_id, "--yes"], None).await {
            Ok(_) => self.toast(&format!("Applied “{name}”")),
            Err(e) => self.report_error(&e),
        }
        self.refresh_apps().await;
        true
    }

    /// Re-extracts an app (after the AppImage changed).
    pub async fn reextract(self: &Rc<Self>, id: &str, consent: bool) {
        let mut args = vec!["reextract", id];
        if consent {
            args.push("--allow-fallback");
        }
        match self.backend.call(&args, None).await {
            Ok(r) => {
                self.toast("Re-extracted");
                let pending = util::list_of(&r, "pending_changes");
                if !pending.is_empty() {
                    self.toast(&format!("The update likely needs: {}", pending.join(", ")));
                }
            }
            Err(e) => self.report_error(&e),
        }
        self.refresh_apps().await;
    }

    // ------------------------------------------------------------ startup

    pub fn start(self: &Rc<Self>, s: Startup) {
        let me = self.clone();
        glib::spawn_future_local(async move {
            me.load_catalog().await;
            me.load_config().await;
            me.refresh_apps().await;
            let st = me.state.borrow();
            let first_app = st.apps.first().map(|a| util::str_of(a, "id").to_string());
            let first_file = st.discovered.iter().find(|d| util::str_of(d, "sandboxed").is_empty()).or(st.discovered.first()).map(|d| util::str_of(d, "path").to_string());
            drop(st);
            match s.page.as_str() {
                "app" | "app-repair" if !s.app.is_empty() => me.open_app(&s.app),
                "app" => {
                    if let Some(id) = first_app {
                        me.open_app(&id)
                    }
                }
                "file" => {
                    if let Some(p) = first_file {
                        me.open_file(&p)
                    }
                }
                "presets" | "preferences" | "settings" | "diagnostics" => me.show_section(if s.page == "settings" { "preferences" } else { &s.page }),
                _ => {}
            }
            me.add_files(s.files);
        });
    }
}

/// One row of the app list: icon, name, dim path, status badge.
fn app_row(r: &Row) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    let b = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(12).margin_top(6).margin_bottom(6).margin_start(4).margin_end(4).build();
    b.append(&app_icon(&r.icon, 36));
    let v = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(2).hexpand(true).valign(gtk::Align::Center).build();
    let name = gtk::Label::builder().label(util::plain(&r.name)).xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
    name.add_css_class("heading");
    let sub_text = if r.badge == "missing" {
        format!("File missing: {}", util::tildify(&r.path))
    } else if r.moved {
        "Moved copy of a sandboxed app".to_string()
    } else {
        // The file name; the full path is in the tooltip and on the right.
        r.path.rsplit('/').next().unwrap_or(&r.path).to_string()
    };
    let sub = gtk::Label::builder().label(util::plain(&sub_text)).xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::Middle).build();
    sub.add_css_class("caption");
    sub.add_css_class("dim-label");
    v.append(&name);
    v.append(&sub);
    b.append(&v);
    if !r.problem.is_empty() || r.unsandboxed_entry || r.badge == "missing" {
        let warn = gtk::Image::from_icon_name("dialog-warning-symbolic");
        warn.add_css_class("warning");
        warn.set_tooltip_text(Some(&if r.badge == "missing" {
            "The AppImage file is missing".to_string()
        } else if !r.problem.is_empty() {
            format!("Didn't work last time: {}", util::plain(&r.problem))
        } else {
            "Has a menu entry that starts it without a sandbox".to_string()
        }));
        b.append(&warn);
    }
    // Status, or what needs attention.
    let (text, tone) = match (r.sandboxed, r.badge.as_str()) {
        (false, _) => ("Not sandboxed", "neutral"),
        (true, "needs-review") => ("Needs review", "warn"),
        (true, "compatibility-risk") => ("Compatibility", "warn"),
        (true, "unsafe") => ("Unsafe", "danger"),
        (true, "stale") => ("Changed", "warn"),
        (true, "broken") => ("Broken", "bad"),
        (true, "missing") => ("Missing", "bad"),
        (true, _) => ("Sandboxed", "accent"),
    };
    b.append(&util::badge(text, tone));
    row.set_child(Some(&b));
    row.set_tooltip_text(Some(&util::plain(&util::tildify(&r.path))));
    row
}

/// An app icon from SAM's icon cache, or a generic one.
pub fn app_icon(path: &str, size: i32) -> gtk::Image {
    let img = if !path.is_empty() && std::path::Path::new(path).is_file() {
        gtk::Image::from_file(path)
    } else {
        gtk::Image::from_icon_name("application-x-executable")
    };
    img.set_pixel_size(size);
    img.add_css_class("sam-app-icon");
    img
}

pub fn apply_theme(theme: &str) {
    let sm = adw::StyleManager::default();
    sm.set_color_scheme(match theme {
        "light" => adw::ColorScheme::ForceLight,
        "dark" => adw::ColorScheme::ForceDark,
        _ => adw::ColorScheme::Default,
    });
}

/// Asks a yes/no question; true when the user accepted.
pub async fn confirm(win: &adw::ApplicationWindow, heading: &str, body: &str, accept: &str, destructive: bool) -> bool {
    let d = adw::AlertDialog::new(Some(heading), Some(body));
    d.add_responses(&[("cancel", "Cancel"), ("ok", accept)]);
    d.set_response_appearance("ok", if destructive { adw::ResponseAppearance::Destructive } else { adw::ResponseAppearance::Suggested });
    d.set_default_response(Some("cancel"));
    d.set_close_response("cancel");
    d.choose_future(Some(win)).await == "ok"
}

#[allow(dead_code)]
pub type WeakApp = Weak<App>;
#[allow(dead_code)]
pub type Map = HashMap<String, Value>;
