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

/// Header width from which Check and Launch sit side by side.
const HERO_SIDE_BY_SIDE: i32 = 720;

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
    state_badge: gtk::Label,
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
    launch_group: adw::PreferencesGroup,
    args_row: gtk::ListBoxRow,
    args_chips: gtk::FlowBox,
    args_entry: gtk::Entry,
    args_add: gtk::Button,
    compat_row: adw::ActionRow,
    compat_switch: gtk::Switch,
    compat_badge: gtk::Label,
    sam_menu_row: adw::ActionRow,
    sam_menu_switch: gtk::Switch,
    hide_row: adw::ActionRow,
    hide_switch: gtk::Switch,
    menu_state: RefCell<Option<Value>>,
    check_group: adw::PreferencesGroup,
    check_summary: adw::ActionRow,
    check_button: gtk::Button,
    check_badge: gtk::Label,
    check_rows: RefCell<Vec<gtk::Widget>>,
    check_report: RefCell<Option<Value>>,
    /// For an AppImage without a sandbox: the settings the last check tested.
    check_settings: RefCell<Option<Value>>,
    trouble: adw::PreferencesGroup,
    details: adw::PreferencesGroup,
    command_group: adw::PreferencesGroup,
    command_view: gtk::TextView,
    log_group: adw::PreferencesGroup,
    log_view: gtk::TextView,
    log_drop: gtk::DropDown,
    log_files: RefCell<Vec<Value>>,
    /// Saves run one after another; only the newest pending one is sent.
    saving: Cell<bool>,
    queued: RefCell<Option<Value>>,
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
        // Wraps onto a second line when the column is narrow.
        let badges = gtk::FlowBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .column_spacing(6)
            .row_spacing(6)
            .max_children_per_line(8)
            .homogeneous(false)
            .halign(gtk::Align::Start)
            .margin_top(4)
            .build();
        let status_badge = util::badge("", "neutral");
        let state_badge = util::badge("", "warn");
        state_badge.set_visible(false);
        let risk_badge = util::badge("", "neutral");
        let sandbox_badge = util::badge("Bubblewrap", "blue");
        let check_badge = util::badge("", "good");
        badges.append(&status_badge);
        status_badge.parent().unwrap().set_can_focus(false);
        badges.append(&state_badge);
        state_badge.parent().unwrap().set_can_focus(false);
        badges.append(&risk_badge);
        risk_badge.parent().unwrap().set_can_focus(false);
        badges.append(&sandbox_badge);
        badges.append(&check_badge);
        sandbox_badge.parent().unwrap().set_can_focus(false);
        meta.append(&title);
        meta.append(&subtitle);
        meta.append(&badges);
        hero.append(&meta);
        // Check and Launch (or Create Sandbox), Remove Sandbox under them.
        let buttons = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(6).valign(gtk::Align::Center).build();
        // Side by side; Check moves above Launch when the header is narrow
        // (the breakpoint below).
        let top_buttons = gtk::Box::builder().spacing(8).halign(gtk::Align::End).build();
        let check_button = gtk::Button::builder()
            .child(&button_content("security-high-symbolic", "Check"))
            .tooltip_text("Start the sandbox with a test program and confirm that every setting applies")
            .name("check-button")
            .build();
        check_button.add_css_class("pill");
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
        remove_button.set_halign(gtk::Align::End);
        top_buttons.append(&check_button);
        top_buttons.append(&main_button);
        buttons.append(&top_buttons);
        buttons.append(&remove_button);
        hero.append(&buttons);
        let hero_bin = adw::BreakpointBin::builder().width_request(320).height_request(96).child(&hero).build();
        let narrow = adw::Breakpoint::new(adw::BreakpointCondition::parse(&format!("max-width: {}px", HERO_SIDE_BY_SIDE)).unwrap());
        narrow.add_setter(&top_buttons, "orientation", Some(&gtk::Orientation::Vertical.to_value()));
        narrow.add_setter(&top_buttons, "spacing", Some(&6.to_value()));
        narrow.add_setter(&remove_button, "halign", Some(&gtk::Align::Center.to_value()));
        hero_bin.add_breakpoint(narrow);
        view.add_top_bar(&hero_bin);
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

        // Launching: how SAM starts this app.
        let launch_group = adw::PreferencesGroup::builder().title("Launching").description("How SAM starts this app.").build();
        let (args_row, args_chips, args_entry, args_add) = chip_editor(
            "Launch arguments",
            "Passed to the app every time it starts, e.g. --no-sandbox for Electron apps that cannot start their own sandbox.",
            "Argument, e.g. --disable-gpu",
        );
        launch_group.add(&args_row);
        let compat_row = adw::ActionRow::builder().title("Compatibility mode").build();
        let compat_badge = util::badge("High risk", "bad");
        compat_badge.set_visible(false);
        let compat_switch = gtk::Switch::builder().valign(gtk::Align::Center).name("compat-switch").build();
        compat_row.add_suffix(&compat_badge);
        compat_row.add_suffix(&compat_switch);
        compat_row.set_activatable_widget(Some(&compat_switch));
        launch_group.add(&compat_row);
        pref.add(&launch_group);

        // Menu entries: SAM's own, and other tools' entries for this AppImage.
        let menu_group = adw::PreferencesGroup::builder().title("Menu Entries").description("How this app appears in your application menu.").build();
        let sam_menu_row = adw::ActionRow::builder().title("Menu entry from SAM").build();
        let sam_menu_switch = gtk::Switch::builder().valign(gtk::Align::Center).build();
        sam_menu_row.add_suffix(&sam_menu_switch);
        sam_menu_row.set_activatable_widget(Some(&sam_menu_switch));
        let hide_row = adw::ActionRow::builder().title("Hide other menu entries for this AppImage").build();
        let hide_switch = gtk::Switch::builder().valign(gtk::Align::Center).name("hide-switch").build();
        hide_row.add_suffix(&hide_switch);
        hide_row.set_activatable_widget(Some(&hide_switch));
        menu_group.add(&sam_menu_row);
        menu_group.add(&hide_row);
        pref.add(&menu_group);

        // Sandbox check: start the sandbox with a probe and confirm every setting.
        let check_group = adw::PreferencesGroup::builder()
            .title("Sandbox Check")
            .description("Starts this app's sandbox with a test program instead of the app and confirms from inside that every setting really applies. Nothing is changed.")
            .build();
        let check_summary = adw::ActionRow::builder().title("Not checked yet").build();
        check_summary.add_prefix(&gtk::Image::from_icon_name("security-high-symbolic"));
        check_group.add(&check_summary);
        pref.add(&check_group);

        let trouble = adw::PreferencesGroup::builder().title("Troubleshooting").description("When the app does not start or does not work as expected.").build();
        let details = adw::PreferencesGroup::builder().title("Details").build();
        let command_group = adw::PreferencesGroup::builder().title("Sandbox Command").description("The Bubblewrap command SAM runs for this app.").build();
        let command_view = mono_view();
        command_group.add(&framed(&command_view, 120));
        let copy_cmd = gtk::Button::builder().icon_name("edit-copy-symbolic").tooltip_text("Copy").valign(gtk::Align::Center).build();
        copy_cmd.add_css_class("flat");
        command_group.set_header_suffix(Some(&copy_cmd));
        let log_group = adw::PreferencesGroup::builder().title("Logs").description("Unpacking, detection and start logs.").build();
        let log_view = mono_view();
        log_group.add(&framed(&log_view, 260));
        let log_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        let refresh_log = gtk::Button::builder().icon_name("view-refresh-symbolic").tooltip_text("Refresh").valign(gtk::Align::Center).build();
        let copy_log = gtk::Button::builder().icon_name("edit-copy-symbolic").tooltip_text("Copy").valign(gtk::Align::Center).build();
        refresh_log.add_css_class("flat");
        copy_log.add_css_class("flat");
        let log_drop = gtk::DropDown::from_strings(&["No logs yet"]);
        log_drop.set_valign(gtk::Align::Center);
        log_drop.set_widget_name("log-picker");
        log_drop.set_tooltip_text(Some("Which log to show"));
        log_buttons.append(&log_drop);
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
            state_badge,
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
            check_group,
            check_summary,
            check_button,
            check_badge,
            check_rows: RefCell::new(Vec::new()),
            check_report: RefCell::new(None),
            check_settings: RefCell::new(None),
            launch_group,
            args_row,
            args_chips,
            args_entry,
            args_add,
            compat_row,
            compat_switch,
            compat_badge,
            sam_menu_row,
            sam_menu_switch,
            hide_row,
            hide_switch,
            menu_state: RefCell::new(None),
            trouble,
            details,
            command_group,
            command_view,
            log_group,
            log_view,
            log_drop,
            log_files: RefCell::new(Vec::new()),
            saving: Cell::new(false),
            queued: RefCell::new(None),
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
                glib::spawn_future_local(async move { me.load_log_list().await });
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

        // Sandbox check.
        let w = Rc::downgrade(self);
        self.check_button.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.run_check();
            }
        });

        // Launch arguments.
        let w = Rc::downgrade(self);
        let add_args = move || {
            let Some(me) = w.upgrade() else { return };
            let text = me.args_entry.text().to_string();
            let mut args = me.args();
            args.extend(text.split_whitespace().map(String::from));
            if args.len() != me.args().len() {
                me.args_entry.set_text("");
                me.save_args(args);
            }
        };
        let a2 = add_args.clone();
        self.args_entry.connect_activate(move |_| a2());
        self.args_add.connect_clicked(move |_| add_args());

        // Compatibility mode.
        let w = Rc::downgrade(self);
        self.compat_switch.connect_active_notify(move |sw| {
            let Some(me) = w.upgrade() else { return };
            if me.updating.get() {
                return;
            }
            let on = sw.is_active();
            me.render();
            me.set_compat(on);
        });

        // Menu entries.
        let w = Rc::downgrade(self);
        self.sam_menu_switch.connect_active_notify(move |sw| {
            let Some(me) = w.upgrade() else { return };
            if me.updating.get() || !me.sandboxed() {
                return;
            }
            let on = sw.is_active();
            me.simple(vec!["desktop".into(), me.app_id.clone(), if on { "install".into() } else { "remove".into() }], if on { "Menu entry added" } else { "Menu entry removed" });
        });
        let w = Rc::downgrade(self);
        self.hide_switch.connect_active_notify(move |sw| {
            let Some(me) = w.upgrade() else { return };
            if me.updating.get() {
                return;
            }
            let on = sw.is_active();
            if me.sandboxed() {
                me.simple_with(vec!["menu".into(), if on { "hide".into() } else { "restore".into() }, me.app_id.clone()], if on { "Other menu entries hidden" } else { "Other menu entries restored" }, true);
            } else {
                // No sandbox yet: decides what Create Sandbox does.
                me.hide_duplicates.set(on);
                me.render();
            }
        });

        // Log picker.
        let w = Rc::downgrade(self);
        self.log_drop.connect_selected_notify(move |d| {
            let Some(me) = w.upgrade() else { return };
            if me.updating.get() {
                return;
            }
            let file = me.log_files.borrow().get(d.selected() as usize).map(|f| util::str_of(f, "path").to_string());
            if let Some(f) = file {
                glib::spawn_future_local(async move { me.show_log_file(&f).await });
            }
        });

        self.load_presets();
    }

    fn run_check(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let sandboxed = self.sandboxed();
        let settings = if sandboxed { None } else { self.pending.borrow().clone() };
        if !sandboxed && settings.is_none() {
            return;
        }
        self.check_button.set_sensitive(false);
        self.check_summary.set_title("Checking…");
        self.check_summary.set_subtitle("Starting the sandbox with the test program.");
        let me = self.clone();
        glib::spawn_future_local(async move {
            let reply = if sandboxed {
                app.backend.call(&["verify", &me.app_id], None).await
            } else {
                let input = settings.as_ref().map(|v| v.to_string());
                app.backend.call(&["verify", &me.path, "--permissions-stdin"], input).await
            };
            match reply {
                Ok(r) => {
                    let failed = r.get("record").and_then(|x| x.get("failed")).and_then(Value::as_array).map(Vec::len).unwrap_or(0);
                    app.toast(&if failed == 0 { "Sandbox check passed: every setting applies".to_string() } else { format!("Sandbox check: {failed} setting(s) do not apply") });
                    *me.check_report.borrow_mut() = r.get("report").cloned();
                    *me.check_settings.borrow_mut() = settings;
                }
                Err(e) => app.report_error(&e),
            }
            me.check_button.set_sensitive(true);
            if sandboxed {
                me.reload();
                app.refresh_registered().await;
            } else {
                me.render_check();
            }
        });
    }

    /// Status row, header badge and the results of the last check.
    fn render_check(self: &Rc<Self>) {
        for w in self.check_rows.borrow_mut().drain(..) {
            self.check_group.remove(&w);
        }
        if !self.sandboxed() {
            self.render_check_preview();
            return;
        }
        let sandboxed = self.entry().is_some();
        self.check_button.set_sensitive(sandboxed);
        self.check_group.set_description(Some("Starts this app's sandbox with a test program instead of the app and confirms from inside that every setting really applies. Nothing is changed. Use the Check button at the top."));
        if !sandboxed {
            self.check_summary.set_title("Not checked yet");
            self.check_summary.set_subtitle("");
            set_badge_visible(&self.check_badge, false);
            return;
        }
        let rec = self.entry().and_then(|e| e.get("last_check").cloned()).filter(|v| !v.is_null());
        let current = self.info.borrow().as_ref().is_some_and(|i| util::bool_of(i, "check_current"));
        match &rec {
            None => {
                self.check_summary.set_title("Not checked yet");
                self.check_summary.set_subtitle("Check that the sandbox gives the app exactly what its settings say.");
                set_badge_visible(&self.check_badge, false);
            }
            Some(r) => {
                let passed = util::get(r, "passed").and_then(Value::as_u64).unwrap_or(0);
                let failed = util::list_of(r, "failed");
                let when = util::format_time(util::get(r, "at").and_then(Value::as_i64).unwrap_or(0));
                let total = passed as usize + failed.len();
                if !current {
                    self.check_summary.set_title("Out of date");
                    self.check_summary.set_subtitle(&esc(&format!("The settings, SAM or this computer changed since the last check ({when}). Check again.")));
                    set_badge_visible(&self.check_badge, false);
                } else if failed.is_empty() {
                    self.check_summary.set_title(&format!("All {total} checks passed"));
                    self.check_summary.set_subtitle(&esc(&format!("Every setting applies. Checked {when}.")));
                    set_badge_visible(&self.check_badge, true);
                    util::set_badge(&self.check_badge, "Checked", "good");
                    self.check_badge.set_tooltip_text(Some("The sandbox check confirmed that every setting applies; see Sandbox Check below"));
                } else {
                    self.check_summary.set_title(&format!("{} of {total} checks failed", failed.len()));
                    self.check_summary.set_subtitle(&esc(&format!("Not applied: {}. Checked {when}.", failed.join(", "))));
                    set_badge_visible(&self.check_badge, true);
                    util::set_badge(&self.check_badge, "Check failed", "bad");
                    self.check_badge.set_tooltip_text(Some("The sandbox check found settings that do not apply; see Sandbox Check below"));
                }
            }
        }
        // Results of the check run in this session.
        let Some(report) = self.check_report.borrow().clone() else { return };
        self.render_check_results(&report);
    }

    /// An AppImage without a sandbox: the check tests the settings shown
    /// on the page, before anything is unpacked.
    fn render_check_preview(self: &Rc<Self>) {
        let pending = self.pending.borrow().clone();
        self.check_button.set_sensitive(pending.is_some());
        self.check_group.set_description(Some("Starts the sandbox this AppImage would get with a test program and confirms from inside that every setting below really applies. The AppImage is not unpacked or run. Use the Check button at the top."));
        let report = self.check_report.borrow().clone();
        let current = report.is_some() && *self.check_settings.borrow() == pending;
        match report.as_ref() {
            None => {
                self.check_summary.set_title("Not checked yet");
                self.check_summary.set_subtitle("You can check the settings before you create the sandbox.");
                set_badge_visible(&self.check_badge, false);
            }
            Some(_) if !current => {
                self.check_summary.set_title("Out of date");
                self.check_summary.set_subtitle("The settings changed since the last check. Check again.");
                set_badge_visible(&self.check_badge, false);
            }
            Some(r) => {
                let results: Vec<Value> = r.get("results").and_then(Value::as_array).cloned().unwrap_or_default();
                let failed: Vec<String> = results.iter().filter(|x| util::get(x, "ok") == Some(&Value::Bool(false))).map(|x| util::str_of(x, "title").to_string()).collect();
                let total = results.iter().filter(|x| matches!(util::get(x, "ok"), Some(Value::Bool(_)))).count();
                if failed.is_empty() {
                    self.check_summary.set_title(&format!("All {total} checks passed"));
                    self.check_summary.set_subtitle("Every setting below applies. Not stored: the sandbox does not exist yet.");
                    set_badge_visible(&self.check_badge, true);
                    util::set_badge(&self.check_badge, "Checked", "good");
                    self.check_badge.set_tooltip_text(Some("The sandbox check confirmed that every setting applies; see Sandbox Check below"));
                } else {
                    self.check_summary.set_title(&format!("{} of {total} checks failed", failed.len()));
                    self.check_summary.set_subtitle(&esc(&format!("Not applied: {}.", failed.join(", "))));
                    set_badge_visible(&self.check_badge, true);
                    util::set_badge(&self.check_badge, "Check failed", "bad");
                    self.check_badge.set_tooltip_text(Some("The sandbox check found settings that do not apply; see Sandbox Check below"));
                }
            }
        }
        if let (true, Some(r)) = (current, report) {
            self.render_check_results(&r);
        }
    }

    /// Failed and not-applicable checks as rows, confirmed ones folded away.
    fn render_check_results(self: &Rc<Self>, report: &Value) {
        let results: Vec<Value> = report.get("results").and_then(Value::as_array).cloned().unwrap_or_default();
        let row_for = |r: &Value, icon: &str, class: &str| {
            let row = adw::ActionRow::builder()
                .title(esc(&format!("{} · {}", util::str_of(r, "group"), util::str_of(r, "title"))))
                .subtitle(esc(util::str_of(r, "observed")))
                .build();
            let img = gtk::Image::from_icon_name(icon);
            img.add_css_class(class);
            row.add_prefix(&img);
            row
        };
        for r in results.iter().filter(|r| util::get(r, "ok") == Some(&Value::Bool(false))) {
            let row = row_for(r, "dialog-error-symbolic", "error");
            self.check_group.add(&row);
            self.check_rows.borrow_mut().push(row.upcast());
        }
        for r in results.iter().filter(|r| util::get(r, "ok").is_none_or(Value::is_null)) {
            let row = row_for(r, "dialog-information-symbolic", "dim-label");
            self.check_group.add(&row);
            self.check_rows.borrow_mut().push(row.upcast());
        }
        let passed: Vec<&Value> = results.iter().filter(|r| util::get(r, "ok") == Some(&Value::Bool(true))).collect();
        if !passed.is_empty() {
            let exp = adw::ExpanderRow::builder().title(format!("{} confirmed settings", passed.len())).subtitle("What the test program found inside the sandbox").build();
            exp.add_prefix(&{
                let i = gtk::Image::from_icon_name("emblem-ok-symbolic");
                i.add_css_class("success");
                i
            });
            for r in passed {
                let row = adw::ActionRow::builder()
                    .title(esc(&format!("{} · {}", util::str_of(r, "group"), util::str_of(r, "title"))))
                    .subtitle(esc(util::str_of(r, "observed")))
                    .build();
                exp.add_row(&row);
            }
            self.check_group.add(&exp);
            self.check_rows.borrow_mut().push(exp.upcast());
        }
    }

    fn args(&self) -> Vec<String> {
        self.entry().map(|e| util::list_of(&e, "profile.args")).unwrap_or_default()
    }

    fn save_args(self: &Rc<Self>, args: Vec<String>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            match app.backend.call(&["args", &me.app_id, "--stdin"], Some(serde_json::to_string(&args).unwrap())).await {
                Ok(_) => app.toast("Launch arguments saved"),
                Err(e) => app.report_error(&e),
            }
            me.reload();
        });
    }

    fn set_compat(self: &Rc<Self>, on: bool) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            if on && !window::confirm(
                &app.window,
                "Turn On Compatibility Mode?",
                "The app gets broad access: the network, the whole session bus, all of /usr, X11, the GPU and sound. Use it when nothing else helps.\n\nYour current settings are remembered and come back when you turn it off.",
                "Turn On",
                true,
            ).await {
                return;
            }
            match app.backend.call(&["compat", &me.app_id, if on { "on" } else { "off" }], None).await {
                Ok(_) => app.toast(if on { "Compatibility mode on" } else { "Compatibility mode off: your previous settings are back" }),
                Err(e) => app.report_error(&e),
            }
            me.reload();
            app.refresh_registered().await;
        });
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
        *self.menu_state.borrow_mut() = app.backend.call(&["menu", "list", &self.app_id], None).await.ok();
        self.render_menu_group();
        self.load_log_list().await;
    }

    /// Fills the log picker (newest first) and shows the newest start log.
    async fn load_log_list(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let mut files: Vec<Value> = app.backend.call(&["logs", &self.app_id, "--list"], None).await.ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
        files.sort_by_key(|f| std::cmp::Reverse(util::get(f, "modified").and_then(Value::as_i64).unwrap_or(0)));
        let labels: Vec<String> = files
            .iter()
            .map(|f| {
                let kind = match util::str_of(f, "kind") {
                    "launch" => "Start",
                    "extract" => "Unpacking",
                    "detect" => "Detection",
                    "diagnose" => "Diagnostic run",
                    other => other,
                };
                format!("{kind} · {}", util::format_time(util::get(f, "modified").and_then(Value::as_i64).unwrap_or(0)))
            })
            .collect();
        let pick = files.iter().position(|f| util::str_of(f, "kind") == "launch").unwrap_or(0);
        self.updating.set(true);
        if labels.is_empty() {
            self.log_drop.set_model(Some(&gtk::StringList::new(&["No logs yet"])));
            self.log_drop.set_sensitive(false);
        } else {
            let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
            self.log_drop.set_model(Some(&gtk::StringList::new(&refs)));
            self.log_drop.set_sensitive(true);
            self.log_drop.set_selected(pick as u32);
        }
        self.updating.set(false);
        let first = files.get(pick).map(|f| util::str_of(f, "path").to_string());
        *self.log_files.borrow_mut() = files;
        match first {
            Some(f) => self.show_log_file(&f).await,
            None => set_mono_text(&self.log_view, "No logs yet."),
        }
    }

    async fn show_log_file(self: &Rc<Self>, file: &str) {
        let Some(app) = self.app() else { return };
        let text = match app.backend.call(&["logs", &self.app_id, "--file", file, "--tail", "400"], None).await {
            Ok(l) => util::str_of(&l, "text").to_string(),
            Err(e) => e,
        };
        set_mono_text(&self.log_view, if text.is_empty() { "(empty)" } else { &text });
    }

    /// Saves (or previews) changed settings. Changes are sent one after
    /// another, and while one is being saved only the newest waiting change
    /// is kept, so a quick series of edits can never be saved out of order.
    fn on_perms_edited(self: &Rc<Self>, p: Value) {
        if !self.sandboxed() {
            *self.pending.borrow_mut() = Some(p.clone());
            self.render_check();
        }
        *self.queued.borrow_mut() = Some(p);
        if self.saving.get() {
            return;
        }
        let Some(app) = self.app() else { return };
        self.saving.set(true);
        let me = self.clone();
        glib::spawn_future_local(async move {
            let mut saved = false;
            loop {
                let next = me.queued.borrow_mut().take();
                let Some(p) = next else { break };
                if me.sandboxed() {
                    if let Err(e) = app.backend.call(&["profile", "set", &me.app_id], Some(p.to_string())).await {
                        app.report_error(&e);
                    }
                    saved = true;
                } else {
                    match app.backend.call(&["preview", &me.path, "--permissions-stdin"], Some(p.to_string())).await {
                        Ok(pv) => {
                            if me.queued.borrow().is_none() {
                                *me.preview.borrow_mut() = Some(pv);
                                me.render();
                            }
                        }
                        Err(e) => app.report_error(&e),
                    }
                }
            }
            me.saving.set(false);
            if saved {
                me.reload();
                app.refresh_registered().await;
            }
        });
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
            // Asked fresh: the app may have been started or closed meanwhile.
            let running = app.backend.call(&["info", &me.app_id], None).await.ok().and_then(|i| i.get("running").and_then(Value::as_u64)).unwrap_or(0) > 0;
            let body = if running {
                format!("{name} is running right now (maybe only in the system tray). It is closed first and gets the chance to save. Then the unpacked app and SAM's menu entry are deleted. The AppImage file itself is kept, and any menu entry SAM hid is shown again.")
            } else {
                "The unpacked app and SAM's menu entry are deleted. The AppImage file itself is kept, and any menu entry SAM hid is shown again.".to_string()
            };
            let d = adw::AlertDialog::new(Some(&format!("Remove the Sandbox for {name}?")), Some(&body));
            let keep = gtk::CheckButton::builder()
                .label("Keep the app's settings and files")
                .tooltip_text("Its private folder (logins, settings, saved files) and logs stay. A new sandbox for this AppImage picks them up again.")
                .name("keep-data")
                .build();
            d.set_extra_child(Some(&keep));
            d.add_responses(&[("cancel", "Cancel"), ("ok", if running { "Close and Remove" } else { "Remove Sandbox" })]);
            d.set_response_appearance("ok", adw::ResponseAppearance::Destructive);
            d.set_default_response(Some("cancel"));
            d.set_close_response("cancel");
            if d.choose_future(Some(&app.window)).await != "ok" {
                return;
            }
            let keep_data = keep.is_active();
            let mut args = vec!["remove", &me.app_id];
            if keep_data {
                args.push("--keep-data");
            }
            if running {
                args.push("--stop");
            }
            match app.backend.call(&args, None).await {
                Ok(r) => {
                    let warnings = util::list_of(&r, "warnings");
                    let kept = if keep_data { " Its settings and files were kept." } else { "" };
                    app.toast(&if warnings.is_empty() { format!("Removed the sandbox for {name}.{kept}") } else { format!("Removed the sandbox, but: {}", warnings.join("; ")) });
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
        self.simple_with(args, ok_text, false)
    }

    /// `full`: the change affects what is found on disk (menu entries),
    /// so every AppImage is looked at again.
    fn simple_with(self: &Rc<Self>, args: Vec<String>, ok_text: &'static str, full: bool) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            match app.backend.call(&refs, None).await {
                Ok(_) => app.toast(ok_text),
                Err(e) => app.report_error(&e),
            }
            me.reload();
            if full {
                app.refresh_apps().await;
            } else {
                app.refresh_registered().await;
            }
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
            app.refresh_registered().await;
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
        set_badge_visible(&self.risk_badge, !level.is_empty());
        util::set_badge(&self.risk_badge, &format!("{}{}", util::risk_label(&level), if score >= 0 { format!(" · {score}") } else { String::new() }), util::risk_tone(&level));
        self.risk_badge.set_tooltip_text(Some("How much this app can reach with the settings below, from 0 (almost nothing) to 100 (everything). Details under Overview"));
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
            util::set_badge(&self.status_badge, "Sandboxed", "good");
            self.status_badge.set_tooltip_text(Some("SAM runs this app in its sandbox, with exactly the access listed below"));
        } else {
            util::set_badge(&self.status_badge, "Not sandboxed", "neutral");
            self.status_badge.set_tooltip_text(Some("No sandbox yet. Nothing has been unpacked or run; below are the settings SAM recommends"));
        }
        // Anything that needs attention, next to the status.
        let compat_on = entry.as_ref().is_some_and(|e| util::bool_of(e, "profile.compatibility_mode"));
        let badge_state = summary.as_ref().map(|s| util::str_of(s, "badge").to_string()).unwrap_or_default();
        let state = match badge_state.as_str() {
            "needs-review" => Some(("Needs review", "warn", "Look over the settings below; SAM chose them automatically or the app asks for new access")),
            "compatibility-risk" if compat_on => Some(("Compatibility mode", "warn", "Compatibility mode gives this app broad access; turn it off under Launching when it is no longer needed")),
            "compatibility-risk" => Some(("Compatibility risk", "warn", "These settings give the app broad access, similar to compatibility mode")),
            "unsafe" => Some(("Unsafe", "danger", "These settings let the app reach far outside its sandbox")),
            "stale" => Some(("AppImage changed", "warn", "The AppImage file changed since it was unpacked; SAM still runs the previous version until you update the sandbox")),
            "broken" => Some(("Broken", "bad", "The last start failed; see Troubleshooting below")),
            "missing" => Some(("File missing", "bad", "The AppImage file is gone; SAM can still run the unpacked copy")),
            _ => None,
        };
        set_badge_visible(&self.state_badge, state.is_some());
        if let Some((t, tone, tip)) = state {
            util::set_badge(&self.state_badge, t, tone);
            self.state_badge.set_tooltip_text(Some(tip));
        }
        let selection = if sandboxed { info.as_ref().and_then(|i| i.get("selection").cloned()) } else { self.preview.borrow().as_ref().and_then(|p| p.get("selection").cloned()) };
        let have_data = if sandboxed { info.is_some() } else { self.preview.borrow().is_some() };
        if have_data && selection.as_ref().is_none_or(Value::is_null) {
            util::set_badge(&self.sandbox_badge, "Sandbox unavailable", "bad");
            self.sandbox_badge.set_tooltip_text(Some("Bubblewrap cannot run on this system; see Diagnostics"));
        } else {
            util::set_badge(&self.sandbox_badge, "Bubblewrap", "blue");
            self.sandbox_badge.set_tooltip_text(Some("The sandbox technology: Bubblewrap gives the app its own view of the system with only the folders, devices and services allowed below"));
        }
        if !sandboxed {
            if let Some(pv) = self.preview.borrow().as_ref() {
                self.set_risk_badge(pv);
            } else {
                set_badge_visible(&self.risk_badge, false);
            }
        } else if info.is_none() {
            set_badge_visible(&self.risk_badge, false);
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
            row.add_prefix(&gtk::Spinner::builder().spinning(true).build());
            self.add_dynamic(&self.notices, &row);
        }
        if !sandboxed {
            let row = adw::ActionRow::builder()
                .title("Not sandboxed yet")
                .subtitle("These are the settings SAM recommends for this app. Adjust them below, then click Create Sandbox. Nothing is unpacked or run before that.")
                .build();
            row.add_prefix(&status_icon("dialog-information-symbolic", "accent"));
            self.add_dynamic(&self.notices, &row);

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
            if badge == "needs-review" && pending.is_empty() {
                let row = adw::ActionRow::builder()
                    .title("Settings not reviewed yet")
                    .subtitle("SAM chose these settings for you. Look through them, then confirm.")
                    .build();
                row.add_prefix(&status_icon("dialog-information-symbolic", "accent"));
                let btn = gtk::Button::builder().label("Mark as Reviewed").valign(gtk::Align::Center).name("review-button").build();
                btn.add_css_class("suggested-action");
                let w = Rc::downgrade(self);
                btn.connect_clicked(move |_| {
                    if let Some(me) = w.upgrade() {
                        me.simple(vec!["review".into(), me.app_id.clone()], "Marked as reviewed");
                    }
                });
                row.add_suffix(&btn);
                self.add_dynamic(&self.notices, &row);
            }
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

        self.render_launch_group(entry.as_ref(), &app);
        self.render_menu_group();
        self.render_check();

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

    /// Launch arguments and compatibility mode (sandboxed apps; shown greyed
    /// out before the sandbox exists).
    fn render_launch_group(self: &Rc<Self>, entry: Option<&Value>, app: &Rc<App>) {
        let sandboxed = self.sandboxed() && entry.is_some();
        self.launch_group.set_description(Some(if self.sandboxed() { "How SAM starts this app." } else { "How SAM starts this app. Available once the sandbox exists." }));
        self.args_row.set_sensitive(sandboxed);
        while let Some(c) = self.args_chips.first_child() {
            self.args_chips.remove(&c);
        }
        let args = self.args();
        for (i, a) in args.iter().enumerate() {
            let w = Rc::downgrade(self);
            let chip = util::chip(a, false, move || {
                if let Some(me) = w.upgrade() {
                    let mut args = me.args();
                    if i < args.len() {
                        args.remove(i);
                        me.save_args(args);
                    }
                }
            });
            self.args_chips.insert(&gtk::FlowBoxChild::builder().child(&chip).halign(gtk::Align::Start).focusable(false).build(), -1);
        }
        self.args_chips.set_visible(!args.is_empty());

        let on = entry.is_some_and(|e| util::bool_of(e, "profile.compatibility_mode"));
        let never = util::str_of(&app.state.borrow().config, "compatibility.behavior") == "never";
        self.updating.set(true);
        self.compat_switch.set_active(on);
        self.updating.set(false);
        self.compat_badge.set_visible(on);
        self.compat_row.set_sensitive(sandboxed && (on || !never));
        let mut sub = String::from("Broad access (network, the whole session bus, all of /usr, X11, GPU, sound) for apps that work no other way. Turning it off restores your previous settings.");
        if never && !on {
            sub.push_str(" Turned off in Preferences → Repair.");
        }
        self.compat_row.set_subtitle(&esc(&sub));
    }

    /// SAM's menu entry and other tools' entries for this AppImage.
    fn render_menu_group(self: &Rc<Self>) {
        self.updating.set(true);
        let entry = self.entry();
        if self.sandboxed() {
            let desktop = entry.as_ref().and_then(|e| e.get("desktop_entry")).and_then(Value::as_str).map(String::from);
            self.sam_menu_row.set_sensitive(entry.is_some());
            self.sam_menu_switch.set_active(desktop.is_some());
            self.sam_menu_row.set_subtitle(&esc(&match &desktop {
                Some(d) => format!("Starts the app through SAM. {}", util::tildify(d)),
                None => "No menu entry: start the app from SAM.".into(),
            }));
            let st = self.menu_state.borrow().clone();
            let visible: Vec<Value> = st.as_ref().and_then(|s| s.get("visible")).and_then(Value::as_array).cloned().unwrap_or_default();
            let hidden: Vec<Value> = st.as_ref().and_then(|s| s.get("hidden")).and_then(Value::as_array).cloned().unwrap_or_default();
            let names: Vec<String> = visible
                .iter()
                .map(|v| util::tildify(util::str_of(v, "file")))
                .chain(hidden.iter().map(|h| util::tildify(util::str_of(h, "original"))))
                .collect();
            self.hide_switch.set_active(!hidden.is_empty() && visible.is_empty());
            self.hide_row.set_sensitive(!names.is_empty());
            self.hide_row.set_subtitle(&esc(&if names.is_empty() {
                "No other menu entry starts this AppImage.".to_string()
            } else if !visible.is_empty() {
                format!("These start the AppImage without a sandbox: {}", names.join(", "))
            } else {
                format!("Hidden by SAM, shown again when you turn this off or remove the sandbox: {}", names.join(", "))
            }));
        } else {
            self.sam_menu_row.set_sensitive(false);
            self.sam_menu_switch.set_active(false);
            self.sam_menu_row.set_subtitle("Created together with the sandbox (see Preferences → Menu Entries).");
            let entries: Vec<String> = self
                .found()
                .and_then(|f| f.get("menu_entries").and_then(Value::as_array).cloned())
                .unwrap_or_default()
                .iter()
                .map(|m| util::tildify(m.as_str().map(String::from).unwrap_or_else(|| util::str_of(m, "file").to_string()).as_str()))
                .collect();
            self.hide_switch.set_active(self.hide_duplicates.get() && !entries.is_empty());
            self.hide_row.set_sensitive(!entries.is_empty());
            self.hide_row.set_subtitle(&esc(&if entries.is_empty() {
                "No other menu entry starts this AppImage.".to_string()
            } else {
                format!("These start the AppImage without a sandbox; SAM hides them when it creates the sandbox: {}", entries.join(", "))
            }));
        }
        self.updating.set(false);
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
        self.button_row(&g, "system-search-symbolic", "Re-run detection", "Inspects the app again and updates SAM's recommendation. Your settings are kept; anything new is listed above.", |me| {
            me.simple(vec!["redetect".into(), me.app_id.clone()], "Detection finished");
        });
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

/// A list editor row: title, description, chips, and an add field.
fn chip_editor(title: &str, description: &str, placeholder: &str) -> (gtk::ListBoxRow, gtk::FlowBox, gtk::Entry, gtk::Button) {
    let row = gtk::ListBoxRow::builder().activatable(false).selectable(false).build();
    let vbox = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(6).margin_top(10).margin_bottom(10).margin_start(12).margin_end(12).build();
    let t = gtk::Label::builder().label(title).xalign(0.0).wrap(true).build();
    let d = gtk::Label::builder().label(description).xalign(0.0).wrap(true).build();
    d.add_css_class("dim-label");
    d.add_css_class("caption");
    vbox.append(&t);
    vbox.append(&d);
    let chips = gtk::FlowBox::builder().selection_mode(gtk::SelectionMode::None).column_spacing(6).row_spacing(6).max_children_per_line(30).build();
    vbox.append(&chips);
    let add_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let entry = gtk::Entry::builder().placeholder_text(placeholder).hexpand(true).name("args-entry").build();
    let add = gtk::Button::builder().icon_name("list-add-symbolic").tooltip_text("Add").valign(gtk::Align::Center).build();
    add.add_css_class("flat");
    add_box.append(&entry);
    add_box.append(&add);
    vbox.append(&add_box);
    row.set_child(Some(&vbox));
    (row, chips, entry, add)
}

/// Shows or hides a header badge together with its FlowBox slot.
fn set_badge_visible(b: &gtk::Label, v: bool) {
    b.set_visible(v);
    if let Some(slot) = b.parent() {
        slot.set_visible(v);
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
