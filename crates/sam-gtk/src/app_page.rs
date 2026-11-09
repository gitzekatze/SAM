// SPDX-License-Identifier: GPL-3.0-or-later
//! Right column for one AppImage: a pinned header with the app and its main
//! button (Launch, or Create Sandbox), then every setting, always visible.
//! Without a sandbox yet, the settings are SAM's recommendation and can be
//! adjusted before the sandbox is created.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use adw::prelude::*;
use gtk::{gio, glib};
use serde_json::Value;

use crate::perms::Editor;
use crate::util::{self, esc};
use crate::window::{self, App};

pub struct AppPage {
    pub page: adw::NavigationPage,
    app: Weak<App>,
    app_id: String,
    path: String,
    info: RefCell<Option<Value>>,
    preview: RefCell<Option<Value>>,
    pending: RefCell<Option<Value>>,
    hide_duplicates: Cell<bool>,
    // Header.
    icon_slot: gtk::Box,
    title: gtk::Label,
    subtitle: gtk::Label,
    status_badge: gtk::Label,
    risk_badge: gtk::Label,
    sandbox_badge: gtk::Label,
    main_button: gtk::Button,
    remove_button: gtk::Button,
    menu_button: gtk::MenuButton,
    // Content.
    editor: Rc<Editor>,
    notices: adw::PreferencesGroup,
    hints: adw::PreferencesGroup,
    findings: adw::PreferencesGroup,
    preset_group: adw::PreferencesGroup,
    preset_row: adw::ComboRow,
    save_preset_row: adw::EntryRow,
    presets: RefCell<Vec<Value>>,
    trouble: adw::PreferencesGroup,
    details: adw::PreferencesGroup,
    command_group: adw::PreferencesGroup,
    command_view: gtk::TextView,
    log_group: adw::PreferencesGroup,
    log_view: gtk::TextView,
    dynamic_rows: RefCell<Vec<(adw::PreferencesGroup, gtk::Widget)>>,
    updating: Cell<bool>,
}

impl AppPage {
    pub fn new(app: &Rc<App>, app_id: &str, path: &str) -> Rc<AppPage> {
        let catalog = app.state.borrow().catalog.clone();
        let editor = Editor::new(catalog, &app.window);

        // ---- header bar + pinned app header
        let view = adw::ToolbarView::new();
        let header = adw::HeaderBar::builder().show_title(false).build();
        let menu_button = gtk::MenuButton::builder().icon_name("view-more-symbolic").tooltip_text("More").build();
        header.pack_end(&menu_button);
        view.add_top_bar(&header);

        let hero = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(18).margin_start(24).margin_end(24).margin_top(4).margin_bottom(14).build();
        hero.add_css_class("sam-hero");
        let icon_slot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        icon_slot.set_valign(gtk::Align::Center);
        hero.append(&icon_slot);
        let meta = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(4).hexpand(true).valign(gtk::Align::Center).build();
        let title = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
        title.add_css_class("title-1");
        let subtitle = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::Middle).build();
        subtitle.add_css_class("caption");
        subtitle.add_css_class("dim-label");
        let badges = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        badges.set_margin_top(4);
        let status_badge = util::badge("", "neutral");
        let risk_badge = util::badge("", "neutral");
        let sandbox_badge = util::badge("Bubblewrap", "neutral");
        badges.append(&status_badge);
        badges.append(&risk_badge);
        badges.append(&sandbox_badge);
        meta.append(&title);
        meta.append(&subtitle);
        meta.append(&badges);
        hero.append(&meta);
        // Launch (or Create Sandbox), with Remove Sandbox right under it.
        let buttons = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(6).valign(gtk::Align::Center).build();
        let main_button = gtk::Button::builder().name("main-button").build();
        main_button.add_css_class("suggested-action");
        main_button.add_css_class("pill");
        let remove_button = gtk::Button::builder()
            .child(&button_content("user-trash-symbolic", "Remove Sandbox"))
            .tooltip_text("Remove the sandbox (the AppImage file is kept)")
            .name("remove-button")
            .build();
        remove_button.add_css_class("flat");
        remove_button.add_css_class("sam-remove");
        buttons.append(&main_button);
        buttons.append(&remove_button);
        hero.append(&buttons);
        view.add_top_bar(&hero);
        app.top_sizes.add_widget(&hero);

        // ---- settings
        let pref = adw::PreferencesPage::new();
        pref.add_css_class("sam-wide");
        let notices = adw::PreferencesGroup::new();
        let hints = adw::PreferencesGroup::builder().title("Worth Checking").description("Things that often stop apps from working in a sandbox.").build();
        let findings = adw::PreferencesGroup::builder().title("What Went Wrong Last Time").build();
        let preset_group = adw::PreferencesGroup::builder()
            .title("Presets")
            .description("Reuse settings between apps. Manage all presets from the main menu → Presets.")
            .build();
        let preset_row = adw::ComboRow::builder().title("Start from a preset").subtitle("Replaces the settings below.").build();
        preset_row.set_widget_name("preset-picker");
        let save_preset_row = adw::EntryRow::builder().title("Save these settings as a preset (name)").show_apply_button(true).name("save-preset").build();
        preset_group.add(&preset_row);
        preset_group.add(&save_preset_row);
        pref.add(&notices);
        pref.add(&hints);
        pref.add(&findings);
        pref.add(&preset_group);
        editor.add_to(&pref);
        let trouble = adw::PreferencesGroup::builder().title("Troubleshooting").description("When the app does not start or does not work as expected.").build();
        let details = adw::PreferencesGroup::builder().title("Details").build();
        let command_group = adw::PreferencesGroup::builder().title("Sandbox Command").description("The Bubblewrap command SAM runs for this app.").build();
        let command_view = mono_view();
        command_group.add(&framed(&command_view, 120));
        let copy_cmd = gtk::Button::builder().icon_name("edit-copy-symbolic").tooltip_text("Copy").valign(gtk::Align::Center).build();
        copy_cmd.add_css_class("flat");
        command_group.set_header_suffix(Some(&copy_cmd));
        let log_group = adw::PreferencesGroup::builder().title("Log of the Last Start").build();
        let log_view = mono_view();
        log_group.add(&framed(&log_view, 260));
        let log_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        let refresh_log = gtk::Button::builder().icon_name("view-refresh-symbolic").tooltip_text("Refresh").valign(gtk::Align::Center).build();
        let copy_log = gtk::Button::builder().icon_name("edit-copy-symbolic").tooltip_text("Copy").valign(gtk::Align::Center).build();
        refresh_log.add_css_class("flat");
        copy_log.add_css_class("flat");
        log_buttons.append(&refresh_log);
        log_buttons.append(&copy_log);
        log_group.set_header_suffix(Some(&log_buttons));
        pref.add(&trouble);
        pref.add(&details);
        pref.add(&command_group);
        pref.add(&log_group);
        view.set_content(Some(&pref));

        let page = adw::NavigationPage::builder().title("App").child(&view).build();
        let me = Rc::new(AppPage {
            page,
            app: Rc::downgrade(app),
            app_id: app_id.to_string(),
            path: path.to_string(),
            info: RefCell::new(None),
            preview: RefCell::new(None),
            pending: RefCell::new(None),
            hide_duplicates: Cell::new(true),
            icon_slot,
            title,
            subtitle,
            status_badge,
            risk_badge,
            sandbox_badge,
            main_button,
            remove_button,
            menu_button,
            editor,
            notices,
            hints,
            findings,
            preset_group,
            preset_row,
            save_preset_row,
            presets: RefCell::new(Vec::new()),
            trouble,
            details,
            command_group,
            command_view,
            log_group,
            log_view,
            dynamic_rows: RefCell::new(Vec::new()),
            updating: Cell::new(false),
        });
        for (btn, view) in [(&copy_cmd, &me.command_view), (&copy_log, &me.log_view)] {
            let (w, view) = (Rc::downgrade(&me), view.clone());
            btn.connect_clicked(move |_| {
                let Some(app) = w.upgrade().and_then(|m| m.app()) else { return };
                let b = view.buffer();
                app.window.clipboard().set_text(&b.text(&b.start_iter(), &b.end_iter(), false));
                app.toast("Copied");
            });
        }
        let w = Rc::downgrade(&me);
        refresh_log.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                glib::spawn_future_local(async move { me.load_log().await });
            }
        });
        me.wire();
        me.render();
        me.reload();
        me
    }

    fn sandboxed(&self) -> bool {
        !self.app_id.is_empty()
    }

    fn app(&self) -> Option<Rc<App>> {
        self.app.upgrade()
    }

    fn entry(&self) -> Option<Value> {
        self.info.borrow().as_ref().and_then(|i| i.get("entry").cloned())
    }

    fn found(&self) -> Option<Value> {
        let app = self.app()?;
        let path = if self.sandboxed() { self.entry().map(|e| util::str_of(&e, "source_path").to_string()).unwrap_or_default() } else { self.path.clone() };
        let st = app.state.borrow();
        st.discovered.iter().find(|d| util::str_of(d, "path") == path).cloned()
    }

    fn name(&self) -> String {
        if self.sandboxed() {
            self.info.borrow().as_ref().map(|i| util::str_of(i, "app.name").to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| self.app_id.clone())
        } else {
            self.found().map(|f| util::str_of(&f, "name").to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| self.path.rsplit('/').next().unwrap_or("").to_string())
        }
    }

    fn perms(&self) -> Option<Value> {
        if self.sandboxed() {
            self.entry().and_then(|e| util::get(&e, "profile.permissions").cloned())
        } else {
            self.pending.borrow().clone()
        }
    }

    // ------------------------------------------------------------ wiring

    fn wire(self: &Rc<Self>) {
        let w = Rc::downgrade(self);
        self.editor.connect_edited(move |p| {
            if let Some(me) = w.upgrade() {
                me.on_perms_edited(p);
            }
        });
        let w = Rc::downgrade(self);
        self.main_button.connect_clicked(move |_| {
            let Some(me) = w.upgrade() else { return };
            let Some(app) = me.app() else { return };
            if me.sandboxed() {
                app.launch(&me.app_id);
            } else {
                me.create_sandbox();
            }
        });
        let w = Rc::downgrade(self);
        self.remove_button.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.remove_sandbox();
            }
        });
        let w = Rc::downgrade(self);
        self.preset_row.connect_selected_notify(move |r| {
            let Some(me) = w.upgrade() else { return };
            if me.updating.get() || r.selected() == 0 {
                return;
            }
            let preset = me.presets.borrow().get(r.selected() as usize - 1).cloned();
            me.updating.set(true);
            r.set_selected(0);
            me.updating.set(false);
            let (Some(preset), Some(app)) = (preset, me.app()) else { return };
            let name = util::str_of(&preset, "name").to_string();
            if me.sandboxed() {
                let id = me.app_id.clone();
                glib::spawn_future_local(async move {
                    if app.apply_preset(&name, &id).await {
                        me.reload();
                    }
                });
            } else if let Some(p) = preset.get("permissions").cloned() {
                // No sandbox yet: the preset replaces the settings shown.
                app.toast(&format!("Settings from “{name}”"));
                me.on_perms_edited(p);
            }
        });
        let w = Rc::downgrade(self);
        self.save_preset_row.connect_apply(move |row| {
            if let Some(me) = w.upgrade() {
                let name = row.text().trim().to_string();
                me.save_as_preset(name);
            }
        });

        // Secondary actions in the ⋮ menu.
        let group = gio::SimpleActionGroup::new();
        let add = |name: &str, f: Box<dyn Fn(&Rc<AppPage>)>| {
            let a = gio::SimpleAction::new(name, None);
            let w = Rc::downgrade(self);
            a.connect_activate(move |_, _| {
                if let Some(me) = w.upgrade() {
                    f(&me);
                }
            });
            group.add_action(&a);
        };
        add("open-folder", Box::new(|me| me.open_private_folder()));
        add("reset", Box::new(|me| {
            if me.sandboxed() {
                me.simple(vec!["profile".into(), "reset".into(), me.app_id.clone()], "Settings reset");
            } else {
                me.reload();
            }
        }));
        add("reextract", Box::new(|me| {
            let Some(app) = me.app() else { return };
            let (id, me) = (me.app_id.clone(), me.clone());
            glib::spawn_future_local(async move {
                app.reextract(&id, false).await;
                me.reload();
            });
        }));
        add("remove", Box::new(|me| me.remove_sandbox()));
        self.page.insert_action_group("page", Some(&group));
        let menu = gio::Menu::new();
        if self.sandboxed() {
            menu.append(Some("Files This App Saved"), Some("page.open-folder"));
            menu.append(Some("Reset to Recommended"), Some("page.reset"));
            menu.append(Some("Re-extract AppImage"), Some("page.reextract"));
            let danger = gio::Menu::new();
            danger.append(Some("Remove Sandbox…"), Some("page.remove"));
            menu.append_section(None, &danger);
        } else {
            menu.append(Some("Reset to Recommended"), Some("page.reset"));
        }
        self.menu_button.set_menu_model(Some(&menu));

        self.load_presets();
    }

    /// Fills the preset picker.
    fn load_presets(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let w = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            if let Ok(list) = app.backend.call(&["preset", "list"], None).await {
                if let Some(me) = w.upgrade() {
                    let presets: Vec<Value> = list.as_array().cloned().unwrap_or_default();
                    let mut labels = vec!["Choose…".to_string()];
                    labels.extend(presets.iter().map(|p| util::str_of(p, "name").to_string()));
                    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
                    me.updating.set(true);
                    me.preset_row.set_model(Some(&gtk::StringList::new(&refs)));
                    me.preset_row.set_selected(0);
                    me.updating.set(false);
                    *me.presets.borrow_mut() = presets;
                }
            }
        });
    }

    /// Saves the settings shown as a user preset (asks before replacing one).
    fn save_as_preset(self: &Rc<Self>, name: String) {
        let Some(app) = self.app() else { return };
        if name.is_empty() {
            app.toast("Type a name for the preset first");
            return;
        }
        let Some(perms) = self.perms() else { return };
        let existing = self.presets.borrow().iter().find(|p| util::str_of(p, "name").eq_ignore_ascii_case(&name)).cloned();
        let me = self.clone();
        let app_name = util::plain(&self.name());
        glib::spawn_future_local(async move {
            if let Some(e) = &existing {
                if util::bool_of(e, "builtin") {
                    app.toast(&format!("“{name}” is a built-in preset. Choose another name."));
                    return;
                }
                if !window::confirm(&app.window, &format!("Replace “{name}”?"), "A preset with this name exists. Its settings are replaced by the ones shown here. Apps that used it keep their current settings.", "Replace", true).await {
                    return;
                }
            }
            let preset = serde_json::json!({
                "name": name,
                "description": format!("Saved from {app_name}"),
                "permissions": perms,
                "risk": "low",
                "created_at": 0,
                "modified_at": 0,
                "compatibility_notes": "",
            });
            match app.backend.call(&["preset", "put"], Some(preset.to_string())).await {
                Ok(_) => {
                    app.toast(&format!("Saved preset “{name}”. Apply it to any app from its Presets section."));
                    me.save_preset_row.set_text("");
                    me.load_presets();
                }
                Err(e) => app.report_error(&e),
            }
        });
    }

    // ------------------------------------------------------------ data

    pub fn reload(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            if me.sandboxed() {
                match app.backend.call(&["info", &me.app_id], None).await {
                    Ok(i) => {
                        let perms = util::get(&i, "entry.profile.permissions").cloned();
                        *me.info.borrow_mut() = Some(i);
                        me.render();
                        if let Some(p) = perms {
                            me.evaluate(p).await;
                        }
                        me.load_side_info().await;
                    }
                    Err(e) => {
                        app.report_error(&e);
                        me.show_load_error(&e);
                    }
                }
            } else {
                match app.backend.call(&["preview", &me.path], None).await {
                    Ok(p) => {
                        *me.pending.borrow_mut() = p.get("permissions").cloned();
                        *me.preview.borrow_mut() = Some(p);
                        me.render();
                    }
                    Err(e) => {
                        app.report_error(&e);
                        me.show_load_error(&e);
                    }
                }
            }
        });
    }

    async fn evaluate(self: &Rc<Self>, p: Value) {
        let Some(app) = self.app() else { return };
        if let Ok(ev) = app.backend.call(&["evaluate", &self.app_id], Some(p.to_string())).await {
            self.editor.set_evaluation(Some(ev.clone()));
            self.set_risk_badge(&ev);
        }
    }

    async fn load_side_info(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let cmd = app.backend.call(&["command", &self.app_id], None).await;
        set_mono_text(&self.command_view, &match cmd {
            Ok(c) => util::str_of(&c, "command").to_string(),
            Err(e) => e,
        });
        self.load_log().await;
    }

    async fn load_log(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let log = app.backend.call(&["logs", &self.app_id, "--kind", "launch", "--tail", "200"], None).await;
        let text = log.ok().map(|l| util::str_of(&l, "text").to_string()).filter(|t| !t.is_empty()).unwrap_or_else(|| "No logs yet.".into());
        set_mono_text(&self.log_view, &text);
    }

    fn on_perms_edited(self: &Rc<Self>, p: Value) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        if self.sandboxed() {
            glib::spawn_future_local(async move {
                me.evaluate(p.clone()).await;
                if let Err(e) = app.backend.call(&["profile", "set", &me.app_id], Some(p.to_string())).await {
                    app.report_error(&e);
                }
                me.reload();
                app.refresh_apps().await;
            });
        } else {
            *self.pending.borrow_mut() = Some(p.clone());
            glib::spawn_future_local(async move {
                match app.backend.call(&["preview", &me.path, "--permissions-stdin"], Some(p.to_string())).await {
                    Ok(pv) => {
                        *me.preview.borrow_mut() = Some(pv);
                        me.render();
                    }
                    Err(e) => app.report_error(&e),
                }
            });
        }
    }

    fn create_sandbox(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let Some(perms) = self.pending.borrow().clone() else { return };
        let mut args: Vec<String> = vec!["add".into(), self.path.clone(), "--accept".into(), "--permissions-stdin".into()];
        if self.hide_duplicates.get() && self.found().and_then(|f| f.get("menu_entries").and_then(Value::as_array).map(|m| !m.is_empty())).unwrap_or(false) {
            args.push("--hide-duplicates".into());
        }
        let name = self.name();
        app.toast(&format!("Creating the sandbox for {}…", util::plain(&name)));
        self.main_button.set_sensitive(false);
        let me = self.clone();
        glib::spawn_future_local(async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let r = app.backend.call(&refs, Some(perms.to_string())).await;
            me.main_button.set_sensitive(true);
            match r {
                Ok(r) => {
                    let id = util::str_of(&r, "entry.id").to_string();
                    app.refresh_apps().await;
                    app.open_app(&id);
                    if util::bool_of(&r, "needs_fallback_consent") {
                        let body = format!("SAM could not unpack {} without running it. It can try the AppImage's own extractor instead. That runs code from the AppImage, inside a sandbox with no network and no access to your files.\n\nOnly continue if you trust where this file came from.", util::plain(&name));
                        if window::confirm(&app.window, "Static Extraction Failed", &body, "Use the AppImage's Extractor", false).await {
                            app.reextract(&id, true).await;
                            app.open_app(&id);
                        }
                    } else {
                        app.toast(&format!("Sandbox created for {}", util::plain(&name)));
                    }
                }
                Err(e) => app.report_error(&e),
            }
        });
    }

    fn remove_sandbox(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        let name = util::plain(&self.name());
        glib::spawn_future_local(async move {
            if !window::confirm(&app.window, &format!("Remove the Sandbox for {name}?"), "The extracted copy, SAM's menu entry, logs and the app's private settings are deleted. The AppImage file itself is kept, and any menu entry SAM hid is shown again.", "Remove Sandbox", true).await {
                return;
            }
            match app.backend.call(&["remove", &me.app_id], None).await {
                Ok(r) => {
                    let warnings = util::list_of(&r, "warnings");
                    app.toast(&if warnings.is_empty() { format!("Removed the sandbox for {name}") } else { format!("Removed the sandbox, but: {}", warnings.join("; ")) });
                    let path = me.entry().map(|e| util::str_of(&e, "source_path").to_string()).unwrap_or_default();
                    app.refresh_apps().await;
                    if path.is_empty() { app.show_welcome() } else { app.open_file(&path) }
                }
                Err(e) => app.report_error(&e),
            }
        });
    }

    fn open_private_folder(&self) {
        let p = self.info.borrow().as_ref().map(|i| util::str_of(i, "private_home").to_string()).unwrap_or_default();
        if !p.is_empty() {
            let _ = std::fs::create_dir_all(&p);
            let launcher = gtk::FileLauncher::new(Some(&gio::File::for_path(&p)));
            let win = self.app().map(|a| a.window.clone());
            glib::spawn_future_local(async move {
                let _ = launcher.launch_future(win.as_ref()).await;
            });
        }
    }

    /// Runs a command that changes the app, then reloads.
    fn simple(self: &Rc<Self>, args: Vec<String>, ok_text: &'static str) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            match app.backend.call(&refs, None).await {
                Ok(_) => app.toast(ok_text),
                Err(e) => app.report_error(&e),
            }
            me.reload();
            app.refresh_apps().await;
        });
    }

    fn apply_suggestion(self: &Rc<Self>, sug: Value, as_repair: bool, then_run: bool) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            let title = util::str_of(&sug, "title").to_string();
            let explanation = util::str_of(&sug, "explanation").to_string();
            let risk = util::str_of(&sug, "risk");
            let ask = if util::bool_of(&sug, "from_app_output") {
                Some(format!("This suggestion is based on messages the app printed itself. A malicious app can print messages to get more access.\n\n{explanation}"))
            } else if risk == "high" || risk == "dangerous" || util::str_of(&sug, "action.kind") == "compat" {
                Some(explanation.clone())
            } else {
                None
            };
            if let Some(body) = ask {
                if !window::confirm(&app.window, &format!("Apply “{title}”?"), &body, "Apply", false).await {
                    return;
                }
            }
            let id = util::str_of(&sug, "id").to_string();
            let args = if as_repair { vec!["repair", &me.app_id, "--apply", &id] } else { vec!["hints", &me.app_id, "--apply", &id] };
            match app.backend.call(&args, None).await {
                Ok(_) => {
                    app.toast(&format!("Applied: {title}"));
                    if then_run {
                        app.launch(&me.app_id);
                    }
                }
                Err(e) => app.report_error(&e),
            }
            me.reload();
            app.refresh_apps().await;
        });
    }

    // ------------------------------------------------------------ rendering

    fn show_load_error(self: &Rc<Self>, e: &str) {
        self.clear_dynamic();
        let row = adw::ActionRow::builder().title("The settings could not be loaded").subtitle(esc(e)).build();
        row.add_prefix(&status_icon("dialog-error-symbolic", "error"));
        let retry = gtk::Button::builder().label("Try Again").valign(gtk::Align::Center).build();
        let w = Rc::downgrade(self);
        retry.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.reload();
            }
        });
        row.add_suffix(&retry);
        self.add_dynamic(&self.notices, &row);
    }

    fn set_risk_badge(&self, ev: &Value) {
        let level = util::str_of(ev, "risk.level").to_string();
        let score = util::get(ev, "risk.score").and_then(Value::as_i64).unwrap_or(-1);
        self.risk_badge.set_visible(!level.is_empty());
        util::set_badge(&self.risk_badge, &format!("{}{}", util::risk_label(&level), if score >= 0 { format!(" · {score}") } else { String::new() }), util::risk_tone(&level));
    }

    fn add_dynamic(&self, g: &adw::PreferencesGroup, w: &impl IsA<gtk::Widget>) {
        g.add(w);
        self.dynamic_rows.borrow_mut().push((g.clone(), w.clone().upcast()));
    }

    fn clear_dynamic(&self) {
        for (g, w) in self.dynamic_rows.borrow_mut().drain(..) {
            g.remove(&w);
        }
    }

    fn render(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let sandboxed = self.sandboxed();
        let entry = self.entry();
        let info = self.info.borrow().clone();
        let summary = info.as_ref().and_then(|i| i.get("app").cloned());
        let found = self.found();

        // Header.
        let name = self.name();
        self.page.set_title(&util::plain(&name));
        self.title.set_text(&util::plain(&name));
        let file_path = if sandboxed { entry.as_ref().map(|e| util::str_of(e, "source_path").to_string()).unwrap_or_default() } else { self.path.clone() };
        self.subtitle.set_text(&util::plain(&util::tildify(&file_path)));
        let icon = if sandboxed {
            summary.as_ref().map(|s| util::str_of(s, "icon_path").to_string()).filter(|s| !s.is_empty()).or_else(|| found.as_ref().map(|f| util::str_of(f, "icon").to_string())).unwrap_or_default()
        } else {
            found.as_ref().map(|f| util::str_of(f, "icon").to_string()).unwrap_or_default()
        };
        while let Some(c) = self.icon_slot.first_child() {
            self.icon_slot.remove(&c);
        }
        self.icon_slot.append(&window::app_icon(&icon, 64));
        if sandboxed {
            util::set_badge(&self.status_badge, "Sandboxed", "accent");
        } else {
            util::set_badge(&self.status_badge, "Not sandboxed", "neutral");
        }
        let selection = if sandboxed { info.as_ref().and_then(|i| i.get("selection").cloned()) } else { self.preview.borrow().as_ref().and_then(|p| p.get("selection").cloned()) };
        let have_data = if sandboxed { info.is_some() } else { self.preview.borrow().is_some() };
        if have_data && selection.as_ref().is_none_or(Value::is_null) {
            util::set_badge(&self.sandbox_badge, "Sandbox unavailable", "bad");
            self.sandbox_badge.set_tooltip_text(Some("Bubblewrap cannot run on this system; see Diagnostics"));
        } else {
            util::set_badge(&self.sandbox_badge, "Bubblewrap", "neutral");
            self.sandbox_badge.set_tooltip_text(Some("Runs in a Bubblewrap sandbox"));
        }
        if !sandboxed {
            if let Some(pv) = self.preview.borrow().as_ref() {
                self.set_risk_badge(pv);
            } else {
                self.risk_badge.set_visible(false);
            }
        } else if info.is_none() {
            self.risk_badge.set_visible(false);
        }
        let badge = summary.as_ref().map(|s| util::str_of(s, "badge").to_string()).unwrap_or_default();
        self.remove_button.set_visible(sandboxed);
        if sandboxed {
            self.main_button.set_child(Some(&button_content("media-playback-start-symbolic", "Launch")));
            self.main_button.set_sensitive(summary.is_some() && badge != "missing");
        } else {
            self.main_button.set_child(Some(&button_content("security-high-symbolic", "Create Sandbox")));
            self.main_button.set_sensitive(self.pending.borrow().is_some());
        }

        // Editor.
        let recommended = if sandboxed { entry.as_ref().and_then(|e| e.get("recommended").cloned()) } else { self.preview.borrow().as_ref().and_then(|p| p.get("recommended").cloned()) };
        let evaluation = if sandboxed {
            None
        } else {
            self.preview.borrow().as_ref().map(|p| serde_json::json!({ "risk": p.get("risk").cloned().unwrap_or_default(), "warnings": p.get("warnings").cloned().unwrap_or_default() }))
        };
        if sandboxed {
            self.editor.set_data(self.perms(), recommended, None);
        } else {
            self.editor.set_data(self.perms(), recommended, evaluation);
        }

        // Dynamic groups.
        self.clear_dynamic();
        if !have_data {
            let row = adw::ActionRow::builder().title("Loading settings…").build();
            row.add_prefix(&adw::Spinner::new());
            self.add_dynamic(&self.notices, &row);
        }
        if !sandboxed {
            let row = adw::ActionRow::builder()
                .title("Not sandboxed yet")
                .subtitle("These are the settings SAM recommends for this app. Adjust them below, then click Create Sandbox. Nothing is unpacked or run before that.")
                .build();
            row.add_prefix(&status_icon("dialog-information-symbolic", "accent"));
            self.add_dynamic(&self.notices, &row);
            if found.as_ref().and_then(|f| f.get("menu_entries")).and_then(Value::as_array).is_some_and(|m| !m.is_empty()) {
                let sw = adw::SwitchRow::builder()
                    .title("Hide the unsandboxed menu entry")
                    .subtitle("This AppImage already has a menu entry that starts it without a sandbox. SAM hides it when the sandbox is created and puts it back if you remove the sandbox.")
                    .active(self.hide_duplicates.get())
                    .build();
                let w = Rc::downgrade(self);
                sw.connect_active_notify(move |s| {
                    if let Some(me) = w.upgrade() {
                        me.hide_duplicates.set(s.is_active());
                    }
                });
                self.add_dynamic(&self.notices, &sw);
            }
        }
        if let (Some(e), Some(s)) = (entry.as_ref(), summary.as_ref()) {
            let badge = util::str_of(s, "badge");
            if ["stale", "broken", "missing"].contains(&badge) {
                let text = match badge {
                    "stale" => "The AppImage changed since it was extracted. Re-extract it to use the new version.".to_string(),
                    "missing" => "The AppImage file is missing. Point SAM at its new location, or remove the sandbox.".to_string(),
                    _ => util::plain(util::get(e, "last_error").and_then(Value::as_str).unwrap_or("This app cannot start.")),
                };
                let row = adw::ActionRow::builder().title(esc(&text)).build();
                row.add_prefix(&status_icon(if badge == "stale" { "dialog-warning-symbolic" } else { "dialog-error-symbolic" }, if badge == "stale" { "warning" } else { "error" }));
                let btn = gtk::Button::builder().label(if badge == "missing" { "Locate…" } else { "Re-extract" }).valign(gtk::Align::Center).build();
                let w = Rc::downgrade(self);
                let missing = badge == "missing";
                btn.connect_clicked(move |_| {
                    if let Some(me) = w.upgrade() {
                        if missing { me.relocate() } else { me.menu_button.activate_action("page.reextract", None).ok(); }
                    }
                });
                row.add_suffix(&btn);
                self.add_dynamic(&self.notices, &row);
            }
            let pending = util::list_of(e, "pending_changes");
            if !pending.is_empty() {
                let row = adw::ActionRow::builder().title(esc(&format!("The updated AppImage likely needs: {}. Your settings were kept.", pending.join(", ")))).build();
                row.add_prefix(&status_icon("dialog-information-symbolic", "accent"));
                let btn = gtk::Button::builder().label("Got It").valign(gtk::Align::Center).build();
                let w = Rc::downgrade(self);
                btn.connect_clicked(move |_| {
                    if let Some(me) = w.upgrade() {
                        me.simple(vec!["review".into(), me.app_id.clone()], "");
                    }
                });
                row.add_suffix(&btn);
                self.add_dynamic(&self.notices, &row);
            }
        }

        let hints: Vec<Value> = info.as_ref().and_then(|i| i.get("hints")).and_then(Value::as_array).cloned().unwrap_or_default();
        for h in &hints {
            let row = self.suggestion_row(h, "dialog-information-symbolic", false, false);
            self.add_dynamic(&self.hints, &row);
        }
        self.hints.set_visible(!hints.is_empty());
        let findings: Vec<Value> = entry.as_ref().and_then(|e| util::get(e, "last_launch.findings")).and_then(Value::as_array).cloned().unwrap_or_default();
        for f in &findings {
            let row = self.suggestion_row(f, "tools-symbolic", true, true);
            self.add_dynamic(&self.findings, &row);
        }
        self.findings.set_visible(!findings.is_empty());
        self.notices.set_visible(true);

        self.preset_group.set_visible(have_data);
        if let Some(e) = entry.as_ref() {
            let p = util::get(e, "profile.preset").and_then(Value::as_str).map(String::from);
            self.preset_row.set_subtitle(&match p {
                Some(p) => format!("Current settings come from “{}”.", esc(&p)),
                None => "Replaces the settings below.".into(),
            });
        }

        // Troubleshooting and details (sandboxed apps).
        for g in [&self.trouble, &self.details, &self.command_group, &self.log_group] {
            g.set_visible(sandboxed);
        }
        if let Some(e) = entry.as_ref() {
            self.render_troubleshooting(e, &info);
            self.render_details(e);
        }
        let _ = app;
    }

    fn suggestion_row(self: &Rc<Self>, s: &Value, icon: &str, as_repair: bool, then_run: bool) -> adw::ActionRow {
        let none = util::str_of(s, "action.kind") == "none";
        let row = adw::ActionRow::builder()
            .title(esc(util::str_of(s, "title")))
            .subtitle(esc(util::str_of(s, "explanation")))
            .activatable(!none)
            .build();
        row.add_prefix(&status_icon(icon, "accent"));
        if !none {
            row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
            let w = Rc::downgrade(self);
            let s = s.clone();
            row.connect_activated(move |_| {
                if let Some(me) = w.upgrade() {
                    me.apply_suggestion(s.clone(), as_repair, then_run);
                }
            });
        }
        row
    }

    fn button_row(self: &Rc<Self>, g: &adw::PreferencesGroup, icon: &str, title: &str, subtitle: &str, f: impl Fn(&Rc<AppPage>) + 'static) {
        let row = adw::ActionRow::builder().title(esc(title)).subtitle(esc(subtitle)).activatable(true).build();
        row.add_prefix(&gtk::Image::from_icon_name(icon));
        row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        let w = Rc::downgrade(self);
        row.connect_activated(move |_| {
            if let Some(me) = w.upgrade() {
                f(&me);
            }
        });
        self.add_dynamic(g, &row);
    }

    fn render_troubleshooting(self: &Rc<Self>, e: &Value, info: &Option<Value>) {
        let g = self.trouble.clone();
        let last = e.get("last_launch").filter(|l| !l.is_null());
        let last_text = match last {
            Some(l) => {
                let mut t = format!("{} — {}", util::format_time(util::get(l, "started_at").and_then(Value::as_i64).unwrap_or(0)), util::plain(util::str_of(l, "summary")));
                if let Some(en) = l.get("enforcement").and_then(Value::as_str) {
                    t.push_str(&format!("\nEnforced: {}", util::plain(en)));
                }
                t
            }
            None => "Not started yet".into(),
        };
        let row = adw::ActionRow::builder().title("Last start").subtitle(esc(&last_text)).build();
        row.add_prefix(&gtk::Image::from_icon_name("document-open-recent-symbolic"));
        self.add_dynamic(&g, &row);
        let steps: Vec<Value> = info.as_ref().and_then(|i| i.get("repair_steps")).and_then(Value::as_array).cloned().unwrap_or_default();
        if let Some(first) = steps.first().cloned() {
            let sub = format!("Next: {}. {}", util::str_of(&first, "title"), util::str_of(&first, "explanation"));
            self.button_row(&g, "media-playback-start-symbolic", "Try the next fix and start", &sub, move |me| me.apply_suggestion(first.clone(), true, true));
        }
        for s in steps.into_iter().skip(1) {
            let (t, x) = (util::str_of(&s, "title").to_string(), util::str_of(&s, "explanation").to_string());
            self.button_row(&g, "applications-utilities-symbolic", &t, &x, move |me| me.apply_suggestion(s.clone(), true, false));
        }
        if e.get("repair_backup").is_some_and(|b| !b.is_null()) {
            let applied = util::list_of(e, "repairs_applied").join(", ");
            self.button_row(&g, "edit-undo-symbolic", "Undo all repairs", &format!("Applied: {applied}"), |me| me.simple(vec!["repair".into(), me.app_id.clone(), "--undo".into()], "Repairs undone"));
        }
        self.button_row(&g, "folder-open-symbolic", "Files this app saved", "The app's private folder, where it keeps settings and files it saved outside your granted folders.", |me| me.open_private_folder());
        self.button_row(&g, "system-run-symbolic", "Diagnose missing resources", "Runs the app once under strace (if installed) and suggests fixes.", |me| {
            if let Some(app) = me.app() {
                app.toast("Starting a diagnostic run (closes after 30 s)…");
                me.simple(vec!["diagnose".into(), me.app_id.clone(), "--apply".into()], "Diagnostic run finished");
            }
        });
        self.button_row(&g, "edit-copy-symbolic", "Copy bug report", "A redacted report (home path, user and host names removed).", |me| {
            let Some(app) = me.app() else { return };
            let id = me.app_id.clone();
            glib::spawn_future_local(async move {
                match app.backend.call(&["report", &id], None).await {
                    Ok(r) => {
                        app.window.clipboard().set_text(util::str_of(&r, "report"));
                        app.toast("Bug report copied");
                    }
                    Err(e) => app.report_error(&e),
                }
            });
        });
    }

    fn render_details(self: &Rc<Self>, e: &Value) {
        let g = self.details.clone();
        let text_row = |title: &str, value: &str| {
            let r = adw::ActionRow::builder().title(esc(title)).subtitle(esc(value)).subtitle_selectable(true).build();
            r.add_css_class("property");
            r
        };
        self.add_dynamic(&g, &text_row("Category", &util::category_label(util::str_of(e, "category"))));
        self.add_dynamic(&g, &text_row("AppImage type", util::str_of(e, "appimage_type")));
        let extraction = match e.get("extraction").filter(|x| !x.is_null()) {
            Some(x) => format!("{} files via {}", util::get(x, "file_count").and_then(Value::as_u64).unwrap_or(0), util::str_of(x, "method")),
            None => "Not extracted".into(),
        };
        self.add_dynamic(&g, &text_row("Extraction", &extraction));
        let desktop = e.get("desktop_entry").and_then(Value::as_str).map(String::from);
        let menu = adw::SwitchRow::builder()
            .title("Menu entry")
            .subtitle(esc(&desktop.as_deref().map(util::tildify).unwrap_or_else(|| "No menu entry".into())))
            .active(desktop.is_some())
            .build();
        let w = Rc::downgrade(self);
        menu.connect_active_notify(move |s| {
            if let Some(me) = w.upgrade() {
                let on = s.is_active();
                me.simple(vec!["desktop".into(), me.app_id.clone(), if on { "install".into() } else { "remove".into() }], "Menu entry updated");
            }
        });
        self.add_dynamic(&g, &menu);
        self.add_dynamic(&g, &text_row("SHA-256", util::str_of(e, "source.sha256")));
    }

    fn relocate(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            let d = gtk::FileDialog::builder().title("Locate the AppImage").build();
            if let Ok(f) = d.open_future(Some(&app.window)).await {
                if let Some(p) = f.path() {
                    me.simple(vec!["relocate".into(), me.app_id.clone(), p.to_string_lossy().into_owned()], "Location updated");
                }
            }
        });
    }
}

fn button_content(icon: &str, label: &str) -> adw::ButtonContent {
    adw::ButtonContent::builder().icon_name(icon).label(label).build()
}

fn status_icon(name: &str, class: &str) -> gtk::Image {
    let i = gtk::Image::from_icon_name(name);
    i.add_css_class(class);
    i
}

fn mono_view() -> gtk::TextView {
    let v = gtk::TextView::builder().editable(false).monospace(true).wrap_mode(gtk::WrapMode::Char).top_margin(10).bottom_margin(10).left_margin(12).right_margin(12).build();
    v.add_css_class("sam-mono");
    v
}

/// Monospace text that wraps anywhere without inserting hyphens.
fn set_mono_text(v: &gtk::TextView, text: &str) {
    let b = v.buffer();
    b.set_text(text);
    let tag = b.tag_table().lookup("nohyphen").unwrap_or_else(|| {
        let t = gtk::TextTag::builder().name("nohyphen").insert_hyphens(false).build();
        b.tag_table().add(&t);
        t
    });
    b.apply_tag(&tag, &b.start_iter(), &b.end_iter());
}

fn framed(v: &gtk::TextView, height: i32) -> gtk::Widget {
    let s = gtk::ScrolledWindow::builder().child(v).min_content_height(height).max_content_height(height).hscrollbar_policy(gtk::PolicyType::Never).build();
    s.add_css_class("card");
    s.set_overflow(gtk::Overflow::Hidden);
    s.upcast()
}
