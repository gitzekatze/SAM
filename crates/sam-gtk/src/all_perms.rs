// SPDX-License-Identifier: GPL-3.0-or-later
//! The Permissions page ("Permissions of All Apps"). It covers the whole
//! window: on the left (two thirds) every sandboxed app with tags for what
//! it may access, a filter bar and a check column; on the right (one third)
//! the switches for the selected apps.
//!
//! - Nothing selected: a short explanation.
//! - One app: the same permission editor as on the app's own page.
//! - Several apps: only the permissions that make sense for a group. Where
//!   the apps differ, a permission is shown once per value, with the apps
//!   that have it below (each with a small switch of its own).
//!
//! Changes apply at once. SAM asks first only when its analysis says that an
//! app would stop working; every change gets one toast with Undo.

use crate::i18n::tr;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::{Rc, Weak};

use adw::prelude::*;
use gtk::{gdk, glib};
use serde_json::Value;

use crate::perms::Editor;
use crate::util::{self, esc};
use crate::window::{self, App};

/// The values of a permission that can be changed for a group, with the
/// words of its switch. A permission with on/off values is drawn as a switch.
type Opts = &'static [(&'static str, &'static str)];
const SWITCH: Opts = &[("false", "Off"), ("true", "On")];
const NETWORK: Opts = &[("none", "No network"), ("localhost", "Local network only"), ("full", "Full network")];
const FOLDER: Opts = &[("none", "No access"), ("ro", "Read-only"), ("rw", "Read & write")];
const BUS: Opts = &[("none", "No access"), ("filtered", "Filtered"), ("full", "Full access")];

/// The permissions that make sense for several apps at once. Technical
/// ones (GPU, nested sandbox, syscall filter, all of /usr) stay per app.
const GROUPS: &[(&str, &[(&str, Opts)])] = &[
    ("Network", &[("network.mode", NETWORK)]),
    (
        "Personal Folders",
        &[
            ("filesystem.documents", FOLDER),
            ("filesystem.downloads", FOLDER),
            ("filesystem.pictures", FOLDER),
            ("filesystem.music", FOLDER),
            ("filesystem.videos", FOLDER),
            ("filesystem.desktop", FOLDER),
        ],
    ),
    ("Sound and Devices", &[("audio.enabled", SWITCH), ("devices.webcam", SWITCH), ("devices.gamepads", SWITCH)]),
    ("Desktop", &[("display.x11", SWITCH), ("dbus.session.mode", BUS)]),
];

const STATUS: &[(&str, &str, &str)] = &[
    ("running", "Running", "Show only apps that are running now"),
    ("needs_review", "Needs review", "Show only apps whose settings nobody has confirmed yet"),
    ("may_not_start", "May not start", "Show only apps whose last start failed or whose AppImage is missing"),
];

pub struct PermsPage {
    app: Weak<App>,
    pub root: adw::ToolbarView,
    apps: RefCell<Vec<Value>>,
    /// Tag filters: permission key → true (has it) or false (has it not).
    tag_filter: RefCell<BTreeMap<String, bool>>,
    status_filter: RefCell<BTreeSet<&'static str>>,
    search: RefCell<String>,
    selected: RefCell<BTreeSet<String>>,
    /// The app clicked last: Shift-click selects from here.
    anchor: RefCell<Option<String>>,
    /// Modifier keys of the last click in the list.
    modifiers: Cell<gdk::ModifierType>,
    /// Ids of the apps shown, in list order.
    shown: RefCell<Vec<String>>,
    checks: RefCell<Vec<gtk::CheckButton>>,
    filter_bar: gtk::FlowBox,
    list: gtk::ListBox,
    list_stack: gtk::Stack,
    select_all: gtk::CheckButton,
    count: gtk::Label,
    split: adw::OverlaySplitView,
    side: gtk::Stack,
    banner: adw::Banner,
    // One app selected.
    single_title: adw::ActionRow,
    single_icon: RefCell<Option<gtk::Image>>,
    editor: Rc<Editor>,
    editor_app: RefCell<String>,
    // Several apps selected.
    many_page: adw::PreferencesPage,
    many_groups: RefCell<Vec<adw::PreferencesGroup>>,
    /// Unfolded rows ("key=value"), kept across changes.
    unfolded: RefCell<BTreeSet<String>>,
    updating: Cell<bool>,
}

fn value_token(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn opt_label(opts: Opts, token: &str) -> String {
    opts.iter().find(|o| o.0 == token).map(|o| o.1.to_string()).unwrap_or_else(|| token.to_string())
}

/// A permission tag: the words of the switch, colored by risk, outlined
/// for read-only access.
pub fn tag_label(t: &Value) -> gtk::Label {
    let l = gtk::Label::new(Some(util::str_of(t, "label")));
    l.add_css_class("sam-tag");
    l.add_css_class(&format!("sam-tag-{}", util::str_of(t, "level")));
    if util::bool_of(t, "read_only") {
        l.add_css_class("sam-tag-outline");
    }
    l.set_valign(gtk::Align::Center);
    l
}

impl PermsPage {
    pub fn new(app: &Rc<App>) -> Rc<PermsPage> {
        let root = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        let back = gtk::Button::builder().icon_name("go-previous-symbolic").tooltip_text(tr("Back to the AppImages")).build();
        header.pack_start(&back);
        header.set_title_widget(Some(&adw::WindowTitle::new(
            &tr("Permissions"),
            &tr("What your sandboxed apps may access. Select several to change them together."),
        )));
        let show_side = gtk::ToggleButton::builder().icon_name("sidebar-show-right-symbolic").tooltip_text(tr("Show the switches")).visible(false).build();
        header.pack_end(&show_side);
        root.add_top_bar(&header);
        let banner = adw::Banner::new("");
        root.add_top_bar(&banner);

        // Left: filters, select all, the list.
        let left = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(8).margin_start(12).margin_end(12).margin_top(6).build();
        let search = gtk::SearchEntry::builder().placeholder_text(tr("Search apps")).hexpand(true).build();
        search.update_property(&[gtk::accessible::Property::Label(&tr("Search apps"))]);
        left.append(&search);
        // Wraps in narrow windows.
        let status_box = gtk::FlowBox::builder().selection_mode(gtk::SelectionMode::None).column_spacing(4).row_spacing(4).max_children_per_line(3).build();
        status_box.update_property(&[gtk::accessible::Property::Label(&tr("Filter by state"))]);
        left.append(&status_box);
        let filter_bar = gtk::FlowBox::builder().selection_mode(gtk::SelectionMode::None).column_spacing(4).row_spacing(4).max_children_per_line(30).build();
        filter_bar.update_property(&[gtk::accessible::Property::Label(&tr("Filter by permission"))]);
        left.append(&filter_bar);
        let sel_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let select_all = gtk::CheckButton::builder().label(tr("Select all")).hexpand(true).build();
        let count = gtk::Label::new(None);
        count.add_css_class("dim-label");
        count.add_css_class("caption");
        sel_row.append(&select_all);
        sel_row.append(&count);
        left.append(&sel_row);
        let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).name("permissions-list").build();
        list.add_css_class("boxed-list");
        list.set_margin_bottom(12);
        let empty = adw::StatusPage::builder()
            .icon_name("system-search-symbolic")
            .title(tr("No Apps Match"))
            .description(tr("Click a tag again to change or turn off its filter."))
            .build();
        empty.add_css_class("compact");
        let none = adw::StatusPage::builder()
            .icon_name("io.github.gitzekatze.SAM")
            .title(tr("No Sandboxed Apps Yet"))
            .description(tr("Create a sandbox for an AppImage first. Its permissions then appear here."))
            .build();
        let list_stack = gtk::Stack::builder().valign(gtk::Align::Start).vhomogeneous(false).build();
        list_stack.add_named(&list, Some("list"));
        list_stack.add_named(&empty, Some("empty"));
        list_stack.add_named(&none, Some("none"));
        left.append(&list_stack);
        let left_scroll = gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).vexpand(true).hexpand(true).child(&left).build();

        // Right: the switches.
        let side = gtk::Stack::builder().transition_type(gtk::StackTransitionType::Crossfade).build();
        side.add_css_class("sam-perms-side");
        let intro = adw::StatusPage::builder()
            .icon_name("io.github.gitzekatze.SAM")
            .title(tr("Permissions"))
            .description(tr(
                "Select an app on the left to see what it may access. Select several apps to change a permission for all of them at once. Changes apply immediately and can be undone.",
            ))
            .build();
        intro.add_css_class("compact");
        side.add_named(&intro, Some("none"));
        let catalog = app.state.borrow().catalog.clone();
        let editor = Editor::new(catalog, &app.window);
        let single_page = adw::PreferencesPage::new();
        let single_group = adw::PreferencesGroup::new();
        let single_title = adw::ActionRow::new();
        let open_btn = gtk::Button::builder().label(tr("Open App Page")).valign(gtk::Align::Center).build();
        single_title.add_suffix(&open_btn);
        single_group.add(&single_title);
        single_page.add(&single_group);
        editor.add_to(&single_page);
        side.add_named(&single_page, Some("one"));
        let many_page = adw::PreferencesPage::new();
        side.add_named(&many_page, Some("many"));

        let split = adw::OverlaySplitView::builder()
            .sidebar_position(gtk::PackType::End)
            .sidebar_width_fraction(1.0 / 3.0)
            .min_sidebar_width(300.0)
            .max_sidebar_width(900.0)
            .content(&left_scroll)
            .sidebar(&side)
            .build();
        let bin = adw::BreakpointBin::builder().width_request(360).height_request(300).child(&split).build();
        let bp = adw::Breakpoint::new(adw::BreakpointCondition::parse("max-width: 720px").unwrap());
        bp.add_setter(&split, "collapsed", Some(&true.to_value()));
        bp.add_setter(&show_side, "visible", Some(&true.to_value()));
        bin.add_breakpoint(bp);
        split.bind_property("show-sidebar", &show_side, "active").bidirectional().sync_create().build();
        root.set_content(Some(&bin));

        let me = Rc::new(PermsPage {
            app: Rc::downgrade(app),
            root,
            apps: RefCell::default(),
            tag_filter: RefCell::default(),
            status_filter: RefCell::default(),
            search: RefCell::default(),
            selected: RefCell::default(),
            anchor: RefCell::default(),
            modifiers: Cell::new(gdk::ModifierType::empty()),
            shown: RefCell::default(),
            checks: RefCell::default(),
            filter_bar,
            list,
            list_stack,
            select_all,
            count,
            split,
            side,
            banner,
            single_title,
            single_icon: RefCell::default(),
            editor,
            editor_app: RefCell::default(),
            many_page,
            many_groups: RefCell::default(),
            unfolded: RefCell::default(),
            updating: Cell::new(false),
        });

        // Status filters.
        for &(id, label, tip) in STATUS {
            let b = gtk::ToggleButton::builder().label(tr(label)).tooltip_text(tr(tip)).build();
            b.add_css_class("sam-status-filter");
            let w = Rc::downgrade(&me);
            b.connect_toggled(move |b| {
                if let Some(me) = w.upgrade() {
                    if b.is_active() {
                        me.status_filter.borrow_mut().insert(id);
                    } else {
                        me.status_filter.borrow_mut().remove(id);
                    }
                    me.render_list();
                }
            });
            status_box.append(&b);
        }
        let wa = Rc::downgrade(app);
        back.connect_clicked(move |_| {
            if let Some(app) = wa.upgrade() {
                app.close_permissions();
            }
        });
        let w = Rc::downgrade(&me);
        search.connect_search_changed(move |s| {
            if let Some(me) = w.upgrade() {
                *me.search.borrow_mut() = s.text().to_lowercase();
                me.render_list();
            }
        });
        let w = Rc::downgrade(&me);
        me.select_all.connect_toggled(move |b| {
            let Some(me) = w.upgrade() else { return };
            if me.updating.get() {
                return;
            }
            let shown = me.shown.borrow().clone();
            {
                let mut sel = me.selected.borrow_mut();
                if b.is_active() {
                    sel.extend(shown);
                } else {
                    for id in &shown {
                        sel.remove(id);
                    }
                }
            }
            me.selection_changed();
        });
        // Modifier keys of clicks in the list, for Shift and Ctrl.
        let click = gtk::GestureClick::new();
        click.set_propagation_phase(gtk::PropagationPhase::Capture);
        let w = Rc::downgrade(&me);
        click.connect_pressed(move |g, _, _, _| {
            if let Some(me) = w.upgrade() {
                me.modifiers.set(g.current_event_state());
            }
        });
        me.list.add_controller(click);
        let w = Rc::downgrade(&me);
        me.list.connect_row_activated(move |_, row| {
            let Some(me) = w.upgrade() else { return };
            let Some(id) = me.shown.borrow().get(row.index() as usize).cloned() else { return };
            let m = me.modifiers.replace(gdk::ModifierType::empty());
            if m.contains(gdk::ModifierType::SHIFT_MASK) {
                me.select_range(&id, true);
            } else if m.contains(gdk::ModifierType::CONTROL_MASK) {
                let on = !me.selected.borrow().contains(&id);
                me.set_selected(&id, on);
            } else {
                *me.selected.borrow_mut() = [id.clone()].into();
                *me.anchor.borrow_mut() = Some(id);
            }
            me.selection_changed();
        });
        let w = Rc::downgrade(&me);
        open_btn.connect_clicked(move |_| {
            let Some(me) = w.upgrade() else { return };
            let (Some(app), id) = (me.app.upgrade(), me.editor_app.borrow().clone()) else { return };
            app.close_permissions();
            app.open_app(&id);
        });
        let w = Rc::downgrade(&me);
        me.editor.connect_edited(move |p| {
            if let Some(me) = w.upgrade() {
                me.save_single(p);
            }
        });
        util::name_icon_buttons(&me.root);
        me.reload();
        me
    }

    /// Selects these apps (startup option `--page permissions --app a,b`).
    pub fn preselect(self: &Rc<Self>, ids: Vec<String>) {
        self.selected.borrow_mut().extend(ids);
        self.selection_changed();
    }

    fn app(&self) -> Option<Rc<App>> {
        self.app.upgrade()
    }

    /// Reads all sandboxed apps again and redraws the page.
    pub fn reload(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            match app.backend.call(&["group", "list"], None).await {
                Ok(v) => {
                    let apps = v.as_array().cloned().unwrap_or_default();
                    let ids: BTreeSet<String> = apps.iter().map(|a| util::str_of(a, "id").to_string()).collect();
                    me.selected.borrow_mut().retain(|id| ids.contains(id));
                    *me.apps.borrow_mut() = apps;
                    me.render_filter_bar();
                    me.render_list();
                }
                Err(e) => app.report_error(&e),
            }
        });
    }

    fn find(&self, id: &str) -> Option<Value> {
        self.apps.borrow().iter().find(|a| util::str_of(a, "id") == id).cloned()
    }

    fn name_of(&self, id: &str) -> String {
        self.find(id).map(|a| util::plain(util::str_of(&a, "name"))).unwrap_or_else(|| id.to_string())
    }

    // ------------------------------------------------------------ filters

    fn render_filter_bar(self: &Rc<Self>) {
        while let Some(c) = self.filter_bar.first_child() {
            self.filter_bar.remove(&c);
        }
        // Every tag any app has, in family order, then in switch order.
        let mut tags: BTreeMap<(u8, u64), Value> = BTreeMap::new();
        for a in self.apps.borrow().iter() {
            for t in a.get("tags").and_then(Value::as_array).into_iter().flatten() {
                let fam = match util::str_of(t, "family") {
                    "network" => 0,
                    "files" => 1,
                    "devices" => 2,
                    _ => 3,
                };
                let order = t.get("order").and_then(Value::as_u64).unwrap_or(0);
                tags.entry((fam, order)).or_insert_with(|| t.clone());
            }
        }
        let keys: BTreeSet<String> = tags.values().map(|t| util::str_of(t, "key").to_string()).collect();
        self.tag_filter.borrow_mut().retain(|k, _| keys.contains(k));
        for t in tags.values() {
            let key = util::str_of(t, "key").to_string();
            let label = util::str_of(t, "label").to_string();
            let l = tag_label(t);
            l.remove_css_class("sam-tag-outline");
            let b = gtk::Button::builder().child(&l).build();
            b.add_css_class("flat");
            b.add_css_class("sam-tag-button");
            self.style_filter(&b, &l, &key, &label);
            let w = Rc::downgrade(self);
            b.connect_clicked(move |b| {
                let Some(me) = w.upgrade() else { return };
                {
                    let mut f = me.tag_filter.borrow_mut();
                    // Has → has not → off.
                    match f.get(&key).copied() {
                        None => {
                            f.insert(key.clone(), true);
                        }
                        Some(true) => {
                            f.insert(key.clone(), false);
                        }
                        Some(false) => {
                            f.remove(&key);
                        }
                    }
                }
                me.style_filter(b, &l, &key, &label);
                me.render_list();
            });
            self.filter_bar.append(&b);
        }
    }

    fn style_filter(&self, b: &gtk::Button, l: &gtk::Label, key: &str, label: &str) {
        let state = self.tag_filter.borrow().get(key).copied();
        for c in ["sam-filter-has", "sam-filter-not"] {
            b.remove_css_class(c);
        }
        let (markup, tip) = match state {
            None => (esc(label), format!("Show only apps with {label}")),
            Some(true) => {
                b.add_css_class("sam-filter-has");
                (format!("✓ {}", esc(label)), format!("Showing apps with {label}. Click to show apps without it."))
            }
            Some(false) => {
                b.add_css_class("sam-filter-not");
                (format!("✗ <s>{}</s>", esc(label)), format!("Showing apps without {label}. Click to turn this filter off."))
            }
        };
        l.set_markup(&markup);
        b.set_tooltip_text(Some(&tip));
        b.update_property(&[gtk::accessible::Property::Label(&tip)]);
    }

    fn matches(&self, a: &Value) -> bool {
        let q = self.search.borrow();
        if !q.is_empty() && !util::str_of(a, "name").to_lowercase().contains(q.as_str()) {
            return false;
        }
        if self.status_filter.borrow().iter().any(|s| !util::bool_of(a, s)) {
            return false;
        }
        let tags = a.get("tags").and_then(Value::as_array).cloned().unwrap_or_default();
        self.tag_filter.borrow().iter().all(|(k, want)| tags.iter().any(|t| util::str_of(t, "key") == k) == *want)
    }

    // ------------------------------------------------------------ list

    fn render_list(self: &Rc<Self>) {
        self.list.remove_all();
        self.checks.borrow_mut().clear();
        let apps: Vec<Value> = self.apps.borrow().iter().filter(|a| self.matches(a)).cloned().collect();
        *self.shown.borrow_mut() = apps.iter().map(|a| util::str_of(a, "id").to_string()).collect();
        self.list_stack.set_visible_child_name(if self.apps.borrow().is_empty() {
            "none"
        } else if apps.is_empty() {
            "empty"
        } else {
            "list"
        });
        for a in &apps {
            let id = util::str_of(a, "id").to_string();
            let name = util::plain(util::str_of(a, "name"));
            let row = gtk::ListBoxRow::builder().activatable(true).build();
            let b = gtk::Box::builder().spacing(10).margin_start(8).margin_end(10).margin_top(6).margin_bottom(6).build();
            let check = gtk::CheckButton::builder().valign(gtk::Align::Center).build();
            check.update_property(&[gtk::accessible::Property::Label(&format!("Select {name}"))]);
            b.append(&check);
            b.append(&window::app_icon(util::str_of(a, "icon_path"), 32));
            let text = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(4).hexpand(true).valign(gtk::Align::Center).build();
            let title = gtk::Label::builder().label(&name).xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
            title.add_css_class("heading");
            text.append(&title);
            let tags = gtk::FlowBox::builder().selection_mode(gtk::SelectionMode::None).column_spacing(4).row_spacing(4).max_children_per_line(30).build();
            tags.set_can_target(false);
            tags.set_can_focus(false);
            let list = a.get("tags").and_then(Value::as_array).cloned().unwrap_or_default();
            for t in &list {
                tags.append(&tag_label(t));
            }
            if list.is_empty() {
                let l = gtk::Label::builder().label(tr("Only a window, nothing else")).xalign(0.0).build();
                l.add_css_class("dim-label");
                l.add_css_class("caption");
                tags.append(&l);
            }
            text.append(&tags);
            b.append(&text);
            for &(key, label, _) in STATUS {
                if util::bool_of(a, key) {
                    b.append(&util::badge(&tr(label), if key == "running" { "accent" } else { "warn" }));
                }
            }
            row.set_child(Some(&b));
            let tag_text: Vec<&str> = list.iter().map(|t| util::str_of(t, "label")).collect();
            row.update_property(&[gtk::accessible::Property::Label(&format!(
                "{name}: {}",
                if tag_text.is_empty() { "no extra access".into() } else { tag_text.join(", ") }
            ))]);
            let w = Rc::downgrade(self);
            let cid = id.clone();
            check.connect_toggled(move |c| {
                let Some(me) = w.upgrade() else { return };
                if me.updating.get() {
                    return;
                }
                let m = me.modifiers.replace(gdk::ModifierType::empty());
                if m.contains(gdk::ModifierType::SHIFT_MASK) {
                    me.select_range(&cid, c.is_active());
                } else {
                    me.set_selected(&cid, c.is_active());
                }
                me.selection_changed();
            });
            self.checks.borrow_mut().push(check);
            self.list.append(&row);
        }
        self.selection_changed();
    }

    fn set_selected(&self, id: &str, on: bool) {
        if on {
            self.selected.borrow_mut().insert(id.to_string());
        } else {
            self.selected.borrow_mut().remove(id);
        }
        *self.anchor.borrow_mut() = Some(id.to_string());
    }

    /// Selects (or clears) every app shown between the anchor and `id`.
    fn select_range(&self, id: &str, on: bool) {
        let shown = self.shown.borrow();
        let to = shown.iter().position(|s| s == id);
        let from = self.anchor.borrow().as_ref().and_then(|a| shown.iter().position(|s| s == a)).or(to);
        if let (Some(a), Some(b)) = (from, to) {
            let mut sel = self.selected.borrow_mut();
            for s in &shown[a.min(b)..=a.max(b)] {
                if on {
                    sel.insert(s.clone());
                } else {
                    sel.remove(s);
                }
            }
        }
    }

    fn selection_changed(self: &Rc<Self>) {
        self.updating.set(true);
        let sel = self.selected.borrow().clone();
        let shown = self.shown.borrow().clone();
        for (c, id) in self.checks.borrow().iter().zip(&shown) {
            c.set_active(sel.contains(id));
        }
        let n_shown_sel = shown.iter().filter(|id| sel.contains(*id)).count();
        self.select_all.set_active(n_shown_sel > 0 && n_shown_sel == shown.len());
        self.select_all.set_inconsistent(n_shown_sel > 0 && n_shown_sel < shown.len());
        let filtered = !(self.tag_filter.borrow().is_empty() && self.status_filter.borrow().is_empty() && self.search.borrow().is_empty());
        self.select_all.set_label(Some(&match (shown.len(), filtered) {
            (1, _) => "Select this app".to_string(),
            (n, false) => format!("Select all {n} apps"),
            (n, true) => format!("Select all {n} apps shown"),
        }));
        self.select_all.set_sensitive(!shown.is_empty());
        self.count.set_label(&match sel.len() {
            0 => String::new(),
            1 => "1 app selected".into(),
            n => format!("{n} apps selected"),
        });
        self.updating.set(false);
        self.render_side();
    }

    // ------------------------------------------------------------ side

    fn render_side(self: &Rc<Self>) {
        let sel: Vec<String> = self.selected.borrow().iter().cloned().collect();
        let running: Vec<String> = sel.iter().filter(|id| self.find(id).is_some_and(|a| util::bool_of(&a, "running"))).map(|id| self.name_of(id)).collect();
        match running.len() {
            0 => self.banner.set_revealed(false),
            1 => {
                self.banner.set_title(&esc(&format!("{} is running. It uses changed settings the next time it starts.", running[0])));
                self.banner.set_revealed(true);
            }
            n => {
                self.banner.set_title(&format!("{n} of the selected apps are running. They use changed settings the next time they start."));
                self.banner.set_revealed(true);
            }
        }
        if self.split.is_collapsed() && !sel.is_empty() {
            self.split.set_show_sidebar(true);
        }
        match sel.len() {
            0 => self.side.set_visible_child_name("none"),
            1 => self.render_single(&sel[0]),
            _ => self.render_many(&sel),
        }
    }

    fn render_single(self: &Rc<Self>, id: &str) {
        self.side.set_visible_child_name("one");
        let Some(a) = self.find(id) else { return };
        self.single_title.set_title(&esc(util::str_of(&a, "name")));
        self.single_title.set_subtitle(&tr("The same settings as on the app's own page."));
        if let Some(old) = self.single_icon.borrow_mut().take() {
            self.single_title.remove(&old);
        }
        let icon = window::app_icon(util::str_of(&a, "icon_path"), 32);
        self.single_title.add_prefix(&icon);
        *self.single_icon.borrow_mut() = Some(icon);
        if *self.editor_app.borrow() == id {
            return;
        }
        *self.editor_app.borrow_mut() = id.to_string();
        let Some(app) = self.app() else { return };
        let me = self.clone();
        let id = id.to_string();
        glib::spawn_future_local(async move {
            if let Ok(i) = app.backend.call(&["info", &id], None).await {
                if *me.editor_app.borrow() != id {
                    return;
                }
                let perms = util::get(&i, "entry.profile.permissions").cloned();
                me.editor.set_data(perms.clone(), util::get(&i, "entry.recommended").cloned(), None);
                if let Some(p) = perms {
                    if let Ok(ev) = app.backend.call(&["evaluate", &id], Some(p.to_string())).await {
                        me.editor.set_evaluation(Some(ev));
                    }
                }
            }
        });
    }

    /// Saves an edit made in the one-app editor.
    fn save_single(self: &Rc<Self>, p: Value) {
        let Some(app) = self.app() else { return };
        let id = self.editor_app.borrow().clone();
        let me = self.clone();
        glib::spawn_future_local(async move {
            if let Err(e) = app.backend.call(&["profile", "set", &id], Some(p.to_string())).await {
                app.report_error(&e);
            }
            if let Ok(ev) = app.backend.call(&["evaluate", &id], Some(p.to_string())).await {
                me.editor.set_evaluation(Some(ev));
            }
            me.reload();
        });
    }

    fn render_many(self: &Rc<Self>, sel: &[String]) {
        self.side.set_visible_child_name("many");
        *self.editor_app.borrow_mut() = String::new();
        for g in self.many_groups.borrow_mut().drain(..) {
            self.many_page.remove(&g);
        }
        let apps: Vec<Value> = sel.iter().filter_map(|id| self.find(id)).collect();
        let total = apps.len();
        let catalog = self.app().map(|a| a.state.borrow().catalog.clone()).unwrap_or_default();
        let head = adw::PreferencesGroup::builder()
            .title(format!("{total} Apps Selected"))
            .description(tr(
                "Where the selected apps differ, a permission appears once for each value, with the apps that have it below. The switch of a row changes all its apps; the small switch next to an app changes only that app.",
            ))
            .build();
        self.many_page.add(&head);
        self.many_groups.borrow_mut().push(head);
        for (title, perms) in GROUPS {
            let g = adw::PreferencesGroup::builder().title(tr(title)).build();
            for &(key, opts) in perms.iter() {
                let ptitle = catalog.get(key).map(|i| i.title.clone()).unwrap_or_else(|| key.to_string());
                // Value → apps with it, in the order of the values.
                let mut by_value: Vec<(String, Vec<Value>)> = opts.iter().map(|o| (o.0.to_string(), Vec::new())).collect();
                for a in &apps {
                    let tok = util::get(a, &format!("permissions.{key}")).map(value_token).unwrap_or_default();
                    match by_value.iter_mut().find(|(v, _)| *v == tok) {
                        Some((_, list)) => list.push(a.clone()),
                        None => by_value.push((tok, vec![a.clone()])),
                    }
                }
                for (tok, members) in by_value.into_iter().filter(|(_, m)| !m.is_empty()) {
                    g.add(&self.value_row(key, &ptitle, opts, &tok, &members, total));
                }
            }
            self.many_page.add(&g);
            self.many_groups.borrow_mut().push(g);
        }
    }

    /// One row of a permission for the apps that have value `tok`: a big
    /// control for all of them and, when unfolded, a small one per app.
    fn value_row(self: &Rc<Self>, key: &'static str, ptitle: &str, opts: Opts, tok: &str, members: &[Value], total: usize) -> adw::ExpanderRow {
        let n = members.len();
        let vlabel = opt_label(opts, tok);
        let subtitle = if n == total { format!("{vlabel} for all {n} apps") } else { format!("{vlabel} for {n} of {total} apps") };
        let row = adw::ExpanderRow::builder().title(esc(ptitle)).subtitle(esc(&subtitle)).build();
        let icons = gtk::Box::builder().spacing(2).valign(gtk::Align::Center).build();
        for a in members.iter().take(3) {
            icons.append(&window::app_icon(util::str_of(a, "icon_path"), 16));
        }
        if n > 3 {
            let more = gtk::Label::new(Some(&format!("+{}", n - 3)));
            more.add_css_class("caption");
            more.add_css_class("dim-label");
            icons.append(&more);
        }
        row.add_prefix(&icons);
        let ids: Vec<String> = members.iter().map(|a| util::str_of(a, "id").to_string()).collect();
        let what = match n {
            _ if n == total => format!("{ptitle} for all selected apps"),
            1 => format!("{ptitle} for 1 app"),
            _ => format!("{ptitle} for {n} apps"),
        };
        row.add_suffix(&self.control(key, opts, tok, ids, &what));
        for a in members {
            let name = util::plain(util::str_of(a, "name"));
            let r = adw::ActionRow::builder().title(esc(&name)).build();
            r.add_prefix(&window::app_icon(util::str_of(a, "icon_path"), 16));
            r.add_suffix(&self.control(key, opts, tok, vec![util::str_of(a, "id").to_string()], &format!("{ptitle} for {name}")));
            row.add_row(&r);
        }
        let fold_key = format!("{key}={tok}");
        row.set_expanded(self.unfolded.borrow().contains(&fold_key));
        let w = Rc::downgrade(self);
        row.connect_expanded_notify(move |r| {
            if let Some(me) = w.upgrade() {
                if r.is_expanded() {
                    me.unfolded.borrow_mut().insert(fold_key.clone());
                } else {
                    me.unfolded.borrow_mut().remove(&fold_key);
                }
            }
        });
        row
    }

    /// A switch (on/off) or a drop-down (several values) set to `tok`;
    /// changing it changes `ids`.
    fn control(self: &Rc<Self>, key: &'static str, opts: Opts, tok: &str, ids: Vec<String>, accessible: &str) -> gtk::Widget {
        let w = Rc::downgrade(self);
        if opts == SWITCH {
            let sw = gtk::Switch::builder().active(tok == "true").valign(gtk::Align::Center).build();
            sw.update_property(&[gtk::accessible::Property::Label(accessible)]);
            sw.connect_state_set(move |_, on| {
                if let Some(me) = w.upgrade() {
                    me.change(key, opts, if on { "true" } else { "false" }, ids.clone());
                }
                glib::Propagation::Stop
            });
            sw.upcast()
        } else {
            let labels: Vec<&str> = opts.iter().map(|o| o.1).collect();
            let dd = gtk::DropDown::from_strings(&labels);
            dd.set_valign(gtk::Align::Center);
            if let Some(i) = opts.iter().position(|o| o.0 == tok) {
                dd.set_selected(i as u32);
            }
            // The name says which permission of which apps it changes.
            // GTK names it after its value through a "labelled by"
            // relation, which wins over a label; drop that relation.
            dd.reset_relation(gtk::AccessibleRelation::LabelledBy);
            dd.update_property(&[gtk::accessible::Property::Label(accessible)]);
            dd.connect_selected_notify(move |d| {
                if let (Some(me), Some(o)) = (w.upgrade(), opts.get(d.selected() as usize)) {
                    me.change(key, opts, o.0, ids.clone());
                }
            });
            dd.upcast()
        }
    }

    // ------------------------------------------------------------ changes

    /// Sets `key` to `tok` for `ids`: asks first only when SAM's analysis
    /// says an app would stop working, then offers one Undo.
    fn change(self: &Rc<Self>, key: &'static str, opts: Opts, tok: &'static str, ids: Vec<String>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            let mut args = vec!["group", "set", key, tok];
            args.extend(ids.iter().map(String::as_str));
            let mut dry = args.clone();
            dry.push("--dry-run");
            let check = match app.backend.call(&dry, None).await {
                Ok(c) => c,
                Err(e) => {
                    app.report_error(&e);
                    me.render_side();
                    return;
                }
            };
            let entries = check.get("apps").and_then(Value::as_array).cloned().unwrap_or_default();
            let at_risk: Vec<&Value> = entries.iter().filter(|a| util::bool_of(a, "changed") && !util::list_of(a, "check.removes_needed").is_empty()).collect();
            let mut chosen = ids.clone();
            if !at_risk.is_empty() {
                let lines: Vec<String> = at_risk
                    .iter()
                    .map(|a| {
                        format!(
                            "{} may stop working: it likely needs {}.",
                            util::plain(util::str_of(a, "name")),
                            util::list_of(a, "check.removes_needed").join(", ")
                        )
                    })
                    .collect();
                let others = entries.iter().filter(|a| util::bool_of(a, "changed")).count() - at_risk.len();
                let d = adw::AlertDialog::new(Some(&tr("Some Apps May Stop Working")), Some(&lines.join("\n")));
                d.add_response("cancel", &tr("Cancel"));
                if others > 0 {
                    d.add_response("skip", &tr("Skip These Apps"));
                }
                d.add_response("all", &if at_risk.len() == 1 && others == 0 { tr("Change Anyway") } else { tr("Change All Apps") });
                d.set_response_appearance("all", adw::ResponseAppearance::Destructive);
                d.set_default_response(Some("cancel"));
                d.set_close_response("cancel");
                match d.choose_future(Some(&app.window)).await.as_str() {
                    "all" => {}
                    "skip" => {
                        let skip: BTreeSet<&str> = at_risk.iter().map(|a| util::str_of(a, "id")).collect();
                        chosen.retain(|id| !skip.contains(id.as_str()));
                    }
                    _ => {
                        me.render_side();
                        return;
                    }
                }
            }
            let mut args = vec!["group", "set", key, tok];
            args.extend(chosen.iter().map(String::as_str));
            match app.backend.call(&args, None).await {
                Ok(r) => {
                    let previous = r.get("previous").cloned().unwrap_or_default();
                    let n = previous.as_object().map(|o| o.len()).unwrap_or(0);
                    if n > 0 {
                        let title = app.state.borrow().catalog.get(key).map(|i| i.title.clone()).unwrap_or_else(|| key.to_string());
                        let text = if n == 1 {
                            format!("{title}: {} for {}", opt_label(opts, tok), me.name_of(previous.as_object().unwrap().keys().next().unwrap()))
                        } else {
                            format!("{title}: {} for {n} apps", opt_label(opts, tok))
                        };
                        me.toast_undo(&text, previous);
                    }
                }
                Err(e) => app.report_error(&e),
            }
            me.reload();
        });
    }

    fn toast_undo(self: &Rc<Self>, text: &str, previous: Value) {
        let Some(app) = self.app() else { return };
        let t = adw::Toast::builder().title(esc(text)).button_label(tr("Undo")).timeout(10).build();
        let w = Rc::downgrade(self);
        t.connect_button_clicked(move |_| {
            let (Some(me), Some(app)) = (w.upgrade(), w.upgrade().and_then(|m| m.app())) else { return };
            let previous = previous.clone();
            glib::spawn_future_local(async move {
                match app.backend.call(&["group", "restore"], Some(previous.to_string())).await {
                    Ok(_) => app.toast(&tr("Change undone")),
                    Err(e) => app.report_error(&e),
                }
                me.reload();
            });
        });
        app.toasts.add_toast(t);
    }
}
