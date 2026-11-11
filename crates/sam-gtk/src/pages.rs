// SPDX-License-Identifier: GPL-3.0-or-later
//! SAM's own pages in the right column: preferences, presets (with the
//! preset editor) and diagnostics.

use crate::i18n::tr;
use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gio, glib};
use serde_json::Value;

use crate::perms::Editor;
use crate::util::{self, esc};
use crate::window::{self, App};

fn page_with(title: &str, content: &impl IsA<gtk::Widget>, header: &adw::HeaderBar) -> adw::NavigationPage {
    let view = adw::ToolbarView::new();
    view.add_top_bar(header);
    view.set_content(Some(content));
    adw::NavigationPage::builder().title(title).child(&view).build()
}

// ---------------------------------------------------------------- preferences

pub fn preferences(app: &Rc<App>) -> adw::NavigationPage {
    let pref = adw::PreferencesPage::new();
    let header = adw::HeaderBar::new();
    let page = page_with("Preferences", &pref, &header);
    let cfg = app.state.borrow().config.clone();

    let switch = |g: &adw::PreferencesGroup, key: &'static str, title: &str, subtitle: &str| {
        let row = adw::SwitchRow::builder().title(esc(title)).subtitle(esc(subtitle)).active(util::bool_of(&cfg, key)).build();
        let w = Rc::downgrade(app);
        row.connect_active_notify(move |r| {
            if let Some(app) = w.upgrade() {
                let v = if r.is_active() { "true" } else { "false" };
                glib::spawn_future_local(async move { app.set_config(key, v).await });
            }
        });
        g.add(&row);
    };
    let choice = |g: &adw::PreferencesGroup, key: &'static str, title: &str, opts: &'static [(&'static str, &'static str)]| {
        let labels: Vec<&str> = opts.iter().map(|o| o.1).collect();
        let cur = util::str_of(&cfg, key);
        let row = adw::ComboRow::builder()
            .title(esc(title))
            .model(&gtk::StringList::new(&labels))
            .selected(opts.iter().position(|o| o.0 == cur).unwrap_or(0) as u32)
            .build();
        let w = Rc::downgrade(app);
        row.connect_selected_notify(move |r| {
            if let (Some(app), Some(o)) = (w.upgrade(), opts.get(r.selected() as usize)) {
                let v = o.0;
                glib::spawn_future_local(async move { app.set_config(key, v).await });
            }
        });
        g.add(&row);
    };
    let number = |g: &adw::PreferencesGroup, key: &'static str, title: &str, min: f64, max: f64, step: f64| {
        let cur = util::get(&cfg, key).and_then(Value::as_f64).unwrap_or(min);
        let row = adw::SpinRow::with_range(min, max, step);
        row.set_title(&esc(title));
        row.set_value(cur);
        let w = Rc::downgrade(app);
        let pending: Rc<RefCell<Option<glib::SourceId>>> = Rc::default();
        row.connect_value_notify(move |r| {
            let v = r.value();
            if let Some(id) = pending.borrow_mut().take() {
                id.remove();
            }
            let (w, p2) = (w.clone(), pending.clone());
            // Save once the value stops changing.
            let id = glib::timeout_add_local_once(std::time::Duration::from_millis(600), move || {
                p2.borrow_mut().take();
                if let Some(app) = w.upgrade() {
                    let s = format!("{}", v as i64);
                    glib::spawn_future_local(async move { app.set_config(key, &s).await });
                }
            });
            *pending.borrow_mut() = Some(id);
        });
        g.add(&row);
    };

    let g = adw::PreferencesGroup::builder().title(tr("Appearance")).build();
    choice(&g, "general.theme", "Style", &[("system", "Follow system"), ("light", "Light"), ("dark", "Dark")]);
    pref.add(&g);

    let g = adw::PreferencesGroup::builder().title(tr("Menu Entries")).build();
    switch(
        &g,
        "general.desktop_integration",
        "Create menu entries",
        "Sandboxed apps appear in your application menu and always start through SAM. AppImage locations are managed in the left column.",
    );
    pref.add(&g);

    let g = adw::PreferencesGroup::builder().title(tr("Repair")).build();
    choice(&g, "compatibility.behavior", "Compatibility mode", &[("ask", "Offer in repair options"), ("never", "Never offer")]);
    pref.add(&g);

    let g = adw::PreferencesGroup::builder().title(tr("Warnings")).build();
    switch(&g, "security.warn_x11", "Warn about X11 access", "");
    switch(&g, "security.warn_full_home", "Warn about full home access", "");
    pref.add(&g);

    let g = adw::PreferencesGroup::builder().title(tr("Kernel Security Features")).description(tr("Extra layers inside every sandbox.")).build();
    switch(&g, "security.experimental_landlock", "Landlock write protection", "Kernel-enforced write restrictions inside the sandbox. Also blocks connections to abstract sockets outside the sandbox (such as XWayland's). Skipped on kernels without Landlock.");
    switch(&g, "security.baseline_seccomp", "Baseline syscall filter", "Blocks kernel interfaces no desktop app needs (modules, BPF, perf, keyrings, io_uring, terminal injection). Individual apps can turn it off in their repair steps.");
    switch(
        &g,
        "security.experimental_seccomp",
        "Allow strict syscall filters (experimental)",
        "Lets apps use the strict syscall filter from their Advanced settings. Can break apps.",
    );
    pref.add(&g);

    let g = adw::PreferencesGroup::builder().title(tr("Sandbox Check")).build();
    switch(&g, "security.check_before_launch", "Check the sandbox before each start", "Confirms that every setting applies before an app starts. Runs only when its settings, SAM or this computer changed since the last passing check, and takes about a second. A failed check stops the start.");
    pref.add(&g);

    let g = adw::PreferencesGroup::builder()
        .title(tr("Updates"))
        .description(tr("SAM goes online only for update checks. Each check asks the source an AppImage names (GitHub or the app's own server) whether a newer version is published; nothing is downloaded."))
        .build();
    switch(
        &g,
        "updates.check_on_start",
        "Check for updates when SAM opens",
        "At most once a day, for every sandboxed app. Otherwise only when you click Check on an app's page.",
    );
    pref.add(&g);

    let g = adw::PreferencesGroup::builder().title(tr("Dependency Detection")).build();
    switch(
        &g,
        "dependencies.static_analysis",
        "Analyze AppImages when creating a sandbox",
        "Inspects the bundled programs and libraries without running them.",
    );
    switch(
        &g,
        "dependencies.dynamic_fallback",
        "Allow diagnostic runs",
        "Run an app once under strace to find missing resources (app → Troubleshooting → Diagnose missing resources).",
    );
    switch(
        &g,
        "dependencies.automatic_low_risk_fixes",
        "Apply low-risk fixes automatically",
        "Read-only system data such as fonts or themes found during a diagnostic run is granted without asking.",
    );
    pref.add(&g);

    let g = adw::PreferencesGroup::builder().title(tr("Extraction")).build();
    // Where new sandboxes are unpacked. Existing ones stay where they are
    // until they are unpacked again (Re-extract).
    let loc = util::str_of(&cfg, "extraction.location").to_string();
    let loc_text = |l: &str| if l.trim().is_empty() { "Default: ~/.local/share/sam/extracted".to_string() } else { l.to_string() };
    let row = adw::ActionRow::builder()
        .title(tr("Location"))
        .subtitle(esc(&format!(
            "{}\nNew sandboxes are unpacked here; existing ones move when you re-extract them. Pick a folder no sandboxed app may write to.",
            loc_text(&loc)
        )))
        .build();
    let choose = gtk::Button::builder().icon_name("folder-open-symbolic").tooltip_text(tr("Choose a folder")).valign(gtk::Align::Center).build();
    choose.add_css_class("flat");
    let reset = gtk::Button::builder()
        .icon_name("edit-undo-symbolic")
        .tooltip_text(tr("Back to the default folder"))
        .valign(gtk::Align::Center)
        .sensitive(!loc.trim().is_empty())
        .build();
    reset.add_css_class("flat");
    row.add_suffix(&choose);
    row.add_suffix(&reset);
    let set_loc = {
        let (w, row, reset) = (Rc::downgrade(app), row.clone(), reset.clone());
        move |value: String| {
            let Some(app) = w.upgrade() else { return };
            let (row, reset) = (row.clone(), reset.clone());
            glib::spawn_future_local(async move {
                app.set_config("extraction.location", &value).await;
                let now = util::str_of(&app.state.borrow().config, "extraction.location").to_string();
                row.set_subtitle(&esc(&format!(
                    "{}\nNew sandboxes are unpacked here; existing ones move when you re-extract them. Pick a folder no sandboxed app may write to.",
                    loc_text(&now)
                )));
                reset.set_sensitive(!now.trim().is_empty());
            });
        }
    };
    let set_loc = Rc::new(set_loc);
    {
        let (w, set_loc) = (Rc::downgrade(app), set_loc.clone());
        choose.connect_clicked(move |_| {
            let Some(app) = w.upgrade() else { return };
            let set_loc = set_loc.clone();
            glib::spawn_future_local(async move {
                let d = gtk::FileDialog::builder().title(tr("Folder for unpacked AppImages")).modal(true).build();
                if let Ok(f) = d.select_folder_future(Some(&app.window)).await {
                    if let Some(p) = f.path() {
                        set_loc(p.to_string_lossy().into_owned());
                    }
                }
            });
        });
    }
    reset.connect_clicked(move |_| set_loc(String::new()));
    g.add(&row);
    switch(&g, "extraction.cleanup_stale", "Clean up stale extractions", "");
    switch(
        &g,
        "extraction.allow_fallback",
        "Offer the AppImage's own extractor as fallback",
        "Only used after asking you, and only inside a restricted sandbox.",
    );
    number(&g, "extraction.max_size_mb", "Maximum extracted size (MiB)", 64.0, 1048576.0, 256.0);
    number(&g, "extraction.max_files", "Maximum number of files", 1000.0, 10000000.0, 10000.0);
    number(&g, "extraction.max_seconds", "Maximum extraction time (s)", 10.0, 7200.0, 30.0);
    pref.add(&g);

    let g = adw::PreferencesGroup::builder().title(tr("Diagnostics")).build();
    switch(&g, "diagnostics.verbose_logging", "Verbose logging", "");
    number(&g, "diagnostics.keep_logs", "Launch logs to keep per app", 1.0, 500.0, 1.0);
    pref.add(&g);
    page
}

// ---------------------------------------------------------------- presets

pub struct Presets {
    app: std::rc::Weak<App>,
    list: adw::PreferencesGroup,
    rows: RefCell<Vec<adw::ActionRow>>,
    presets: RefCell<Vec<Value>>,
}

pub fn presets(app: &Rc<App>) -> (adw::NavigationPage, Rc<dyn std::any::Any>) {
    let pref = adw::PreferencesPage::new();
    let header = adw::HeaderBar::new();
    let new_btn = gtk::Button::builder().icon_name("list-add-symbolic").tooltip_text(tr("New preset")).build();
    let import_btn = gtk::Button::builder().icon_name("document-open-symbolic").tooltip_text(tr("Import a preset")).build();
    header.pack_start(&new_btn);
    header.pack_end(&import_btn);
    let list = adw::PreferencesGroup::builder()
        .title(tr("Presets"))
        .description(tr("Ready-made sets of permissions. Apply one to an app from its page, or from the menu of a preset."))
        .build();
    pref.add(&list);
    let page = page_with("Presets", &pref, &header);
    let me = Rc::new(Presets { app: Rc::downgrade(app), list, rows: RefCell::default(), presets: RefCell::default() });

    let w = Rc::downgrade(&me);
    new_btn.connect_clicked(move |_| {
        if let Some(me) = w.upgrade() {
            let base = me.presets.borrow().iter().find(|p| util::str_of(p, "name") == "Untrusted Utility").or(me.presets.borrow().first()).cloned();
            if let Some(mut p) = base {
                p["name"] = "".into();
                p["description"] = "".into();
                p["builtin"] = false.into();
                p["compatibility_notes"] = "".into();
                p["created_at"] = 0.into();
                me.edit(p, true);
            }
        }
    });
    let w = Rc::downgrade(&me);
    import_btn.connect_clicked(move |_| {
        let Some(me) = w.upgrade() else { return };
        let Some(app) = me.app.upgrade() else { return };
        glib::spawn_future_local(async move {
            let d = gtk::FileDialog::builder().title(tr("Import a preset")).build();
            if let Ok(f) = d.open_future(Some(&app.window)).await {
                if let Some(p) = f.path() {
                    match app.backend.call(&["preset", "import", &p.to_string_lossy()], None).await {
                        Ok(r) => app.toast(&format!("Imported “{}”", util::str_of(&r, "name"))),
                        Err(e) => app.report_error(&e),
                    }
                    me.reload();
                }
            }
        });
    });
    me.reload();
    (page, me)
}

impl Presets {
    fn reload(self: &Rc<Self>) {
        let Some(app) = self.app.upgrade() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            match app.backend.call(&["preset", "list"], None).await {
                Ok(v) => {
                    *me.presets.borrow_mut() = v.as_array().cloned().unwrap_or_default();
                    me.render();
                }
                Err(e) => app.report_error(&e),
            }
        });
    }

    fn render(self: &Rc<Self>) {
        for r in self.rows.borrow_mut().drain(..) {
            self.list.remove(&r);
        }
        let Some(app) = self.app.upgrade() else { return };
        let apps = app.state.borrow().apps.clone();
        for (i, p) in self.presets.borrow().iter().enumerate() {
            let builtin = util::bool_of(p, "builtin");
            let row = adw::ActionRow::builder().title(esc(util::str_of(p, "name"))).subtitle(esc(util::str_of(p, "description"))).activatable(true).build();
            row.add_prefix(&gtk::Image::from_icon_name(if builtin { "starred-symbolic" } else { "document-edit-symbolic" }));
            let risk = util::str_of(p, "risk");
            row.add_suffix(&util::badge(&util::risk_label(risk), util::risk_tone(risk)));
            let kind = gtk::Label::new(Some(if builtin { "Built-in" } else { "Custom" }));
            kind.add_css_class("dim-label");
            kind.add_css_class("caption");
            row.add_suffix(&kind);

            // Row menu.
            let group = gio::SimpleActionGroup::new();
            let menu = gio::Menu::new();
            let apply_menu = gio::Menu::new();
            for a in &apps {
                let item = gio::MenuItem::new(Some(&util::plain(util::str_of(a, "name"))), None);
                item.set_action_and_target_value(Some("row.apply"), Some(&util::str_of(a, "id").to_variant()));
                apply_menu.append_item(&item);
            }
            if !apps.is_empty() {
                menu.append_submenu(Some("Apply to"), &apply_menu);
            }
            let edit = gio::Menu::new();
            edit.append(Some(if builtin { "View" } else { "Edit" }), Some("row.edit"));
            edit.append(Some(&tr("Duplicate")), Some("row.duplicate"));
            edit.append(Some(&tr("Export…")), Some("row.export"));
            menu.append_section(None, &edit);
            if !builtin {
                let del = gio::Menu::new();
                del.append(Some(&tr("Delete")), Some("row.delete"));
                menu.append_section(None, &del);
            }
            let w = Rc::downgrade(self);
            let act = |name: &str, ty: Option<&glib::VariantTy>, f: Box<dyn Fn(&Rc<Presets>, Option<String>)>| {
                let a = gio::SimpleAction::new(name, ty);
                let w = w.clone();
                a.connect_activate(move |_, param| {
                    if let Some(me) = w.upgrade() {
                        f(&me, param.and_then(|v| v.get::<String>()));
                    }
                });
                group.add_action(&a);
            };
            act("apply", Some(glib::VariantTy::STRING), Box::new(move |me, id| me.apply(i, id.unwrap_or_default())));
            act(
                "edit",
                None,
                Box::new(move |me, _| {
                    let p = me.presets.borrow()[i].clone();
                    me.edit(p, false)
                }),
            );
            act("duplicate", None, Box::new(move |me, _| me.duplicate(i)));
            act("export", None, Box::new(move |me, _| me.export(i)));
            act("delete", None, Box::new(move |me, _| me.delete(i)));
            row.insert_action_group("row", Some(&group));
            let mb = gtk::MenuButton::builder()
                .icon_name("view-more-symbolic")
                .tooltip_text(tr("More actions"))
                .menu_model(&menu)
                .valign(gtk::Align::Center)
                .build();
            mb.add_css_class("flat");
            row.add_suffix(&mb);
            let w = Rc::downgrade(self);
            row.connect_activated(move |_| {
                if let Some(me) = w.upgrade() {
                    let p = me.presets.borrow()[i].clone();
                    me.edit(p, false);
                }
            });
            self.list.add(&row);
            self.rows.borrow_mut().push(row);
        }
    }

    fn name(&self, i: usize) -> String {
        self.presets.borrow().get(i).map(|p| util::str_of(p, "name").to_string()).unwrap_or_default()
    }

    fn apply(self: &Rc<Self>, i: usize, app_id: String) {
        let Some(app) = self.app.upgrade() else { return };
        let name = self.name(i);
        glib::spawn_future_local(async move {
            app.apply_preset(&name, &app_id).await;
        });
    }

    fn duplicate(self: &Rc<Self>, i: usize) {
        let Some(app) = self.app.upgrade() else { return };
        let base = self.name(i);
        let names: Vec<String> = self.presets.borrow().iter().map(|p| util::str_of(p, "name").to_string()).collect();
        let mut name = format!("{base} (copy)");
        let mut n = 2;
        while names.contains(&name) {
            name = format!("{base} (copy {n})");
            n += 1;
        }
        let me = self.clone();
        glib::spawn_future_local(async move {
            match app.backend.call(&["preset", "duplicate", &base, &name], None).await {
                Ok(_) => app.toast(&format!("Created “{name}”")),
                Err(e) => app.report_error(&e),
            }
            me.reload();
        });
    }

    fn export(self: &Rc<Self>, i: usize) {
        let Some(app) = self.app.upgrade() else { return };
        let name = self.name(i);
        glib::spawn_future_local(async move {
            let d = gtk::FileDialog::builder().title(tr("Export preset")).initial_name(format!("{name}.toml")).build();
            if let Ok(f) = d.save_future(Some(&app.window)).await {
                if let Some(p) = f.path() {
                    match app.backend.call(&["preset", "export", &name, &p.to_string_lossy()], None).await {
                        Ok(_) => app.toast(&tr("Exported")),
                        Err(e) => app.report_error(&e),
                    }
                }
            }
        });
    }

    fn delete(self: &Rc<Self>, i: usize) {
        let Some(app) = self.app.upgrade() else { return };
        let name = self.name(i);
        let me = self.clone();
        glib::spawn_future_local(async move {
            if window::confirm(&app.window, &format!("Delete “{name}”?"), "Apps that use this preset keep their current permissions.", "Delete", true).await
            {
                if let Err(e) = app.backend.call(&["preset", "delete", &name], None).await {
                    app.report_error(&e);
                }
                me.reload();
            }
        });
    }

    fn edit(self: &Rc<Self>, preset: Value, is_new: bool) {
        let Some(app) = self.app.upgrade() else { return };
        let ed = PresetEditor::new(&app, self, preset, is_new);
        let page = ed.page.clone();
        app.show_page(&page, Some(ed));
    }
}

struct PresetEditor {
    page: adw::NavigationPage,
    preset: RefCell<Value>,
    editor: Rc<Editor>,
}

impl PresetEditor {
    fn new(app: &Rc<App>, list: &Rc<Presets>, preset: Value, is_new: bool) -> Rc<PresetEditor> {
        let read_only = util::bool_of(&preset, "builtin");
        let catalog = app.state.borrow().catalog.clone();
        let editor = Editor::new(catalog, &app.window);
        let pref = adw::PreferencesPage::new();
        let header = adw::HeaderBar::new();
        let back = gtk::Button::builder().icon_name("go-previous-symbolic").tooltip_text(tr("Back to presets")).build();
        header.pack_start(&back);
        let save = gtk::Button::builder().label(tr("Save")).build();
        save.add_css_class("suggested-action");
        if !read_only {
            header.pack_end(&save);
        }
        let g = adw::PreferencesGroup::builder()
            .title(if is_new { "New Preset" } else { "Preset" })
            .description(if read_only { "Built-in presets cannot be changed. Duplicate it to make your own version." } else { "" })
            .build();
        let name = adw::EntryRow::builder().title(tr("Name")).text(util::str_of(&preset, "name")).sensitive(!read_only && is_new).build();
        let desc = adw::EntryRow::builder().title(tr("Description")).text(util::str_of(&preset, "description")).sensitive(!read_only).build();
        let notes = adw::EntryRow::builder().title(tr("Compatibility notes")).text(util::str_of(&preset, "compatibility_notes")).sensitive(!read_only).build();
        g.add(&name);
        g.add(&desc);
        g.add(&notes);
        pref.add(&g);
        editor.add_to(&pref);
        let title = if is_new { "New Preset".to_string() } else { util::str_of(&preset, "name").to_string() };
        let page = page_with(&title, &pref, &header);
        let me = Rc::new(PresetEditor { page, preset: RefCell::new(preset), editor });
        me.editor.set_editable(!read_only);
        me.refresh(app);

        let (w, wa) = (Rc::downgrade(&me), Rc::downgrade(app));
        me.editor.connect_edited(move |p| {
            if let (Some(me), Some(app)) = (w.upgrade(), wa.upgrade()) {
                me.preset.borrow_mut()["permissions"] = p;
                me.refresh(&app);
            }
        });
        let (wl, wa) = (Rc::downgrade(list), Rc::downgrade(app));
        back.connect_clicked(move |_| {
            if let (Some(_), Some(app)) = (wl.upgrade(), wa.upgrade()) {
                app.show_section("presets");
            }
        });
        let (w, wa) = (Rc::downgrade(&me), Rc::downgrade(app));
        save.connect_clicked(move |_| {
            let (Some(me), Some(app)) = (w.upgrade(), wa.upgrade()) else { return };
            let mut p = me.preset.borrow().clone();
            p["name"] = name.text().trim().into();
            p["description"] = desc.text().trim().into();
            p["compatibility_notes"] = notes.text().trim().into();
            if util::str_of(&p, "name").is_empty() {
                app.toast(&tr("Give the preset a name"));
                return;
            }
            glib::spawn_future_local(async move {
                match app.backend.call(&["preset", "put"], Some(p.to_string())).await {
                    Ok(_) => {
                        app.toast(&format!("Preset “{}” saved", util::str_of(&p, "name")));
                        app.show_section("presets");
                    }
                    Err(e) => app.report_error(&e),
                }
            });
        });
        me
    }

    fn refresh(self: &Rc<Self>, app: &Rc<App>) {
        let perms = self.preset.borrow().get("permissions").cloned();
        self.editor.set_data(perms.clone(), None, None);
        let (ed, app) = (self.editor.clone(), app.clone());
        glib::spawn_future_local(async move {
            if let Some(p) = perms {
                if let Ok(ev) = app.backend.call(&["evaluate"], Some(p.to_string())).await {
                    ed.set_evaluation(Some(ev));
                }
            }
        });
    }
}

// ---------------------------------------------------------------- diagnostics

pub fn diagnostics(app: &Rc<App>) -> adw::NavigationPage {
    let pref = adw::PreferencesPage::new();
    let header = adw::HeaderBar::new();
    let refresh = gtk::Button::builder().icon_name("view-refresh-symbolic").tooltip_text(tr("Check again")).build();
    let report = gtk::Button::builder().icon_name("edit-copy-symbolic").tooltip_text(tr("Copy a redacted bug report")).build();
    header.pack_end(&refresh);
    header.pack_end(&report);
    let system = adw::PreferencesGroup::builder().title(tr("System")).description(tr("What SAM needs from this computer.")).build();
    pref.add(&system);
    let maint = adw::PreferencesGroup::builder().title(tr("Maintenance")).build();
    pref.add(&maint);
    let page = page_with("Diagnostics", &pref, &header);

    let rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::default();
    let load = {
        let (w, system, rows) = (Rc::downgrade(app), system.clone(), rows.clone());
        move || {
            let (Some(app), system, rows) = (w.upgrade(), system.clone(), rows.clone()) else { return };
            glib::spawn_future_local(async move {
                match app.backend.call(&["doctor"], None).await {
                    Ok(r) => {
                        for row in rows.borrow_mut().drain(..) {
                            system.remove(&row);
                        }
                        for c in r.get("checks").and_then(Value::as_array).cloned().unwrap_or_default() {
                            let status = util::str_of(&c, "status");
                            let mut sub = esc(util::str_of(&c, "detail"));
                            if let Some(h) = c.get("hint").and_then(Value::as_str) {
                                sub.push_str(&format!("\n<i>→ {}</i>", esc(h)));
                            }
                            let row = adw::ActionRow::builder().title(esc(util::str_of(&c, "label"))).subtitle(sub).build();
                            let (icon, class) = match status {
                                "ok" => ("emblem-ok-symbolic", "success"),
                                "info" => ("dialog-information-symbolic", "dim-label"),
                                "warn" => ("dialog-warning-symbolic", "warning"),
                                _ => ("dialog-error-symbolic", "error"),
                            };
                            let img = gtk::Image::from_icon_name(icon);
                            img.add_css_class(class);
                            row.add_prefix(&img);
                            system.add(&row);
                            rows.borrow_mut().push(row);
                        }
                    }
                    Err(e) => app.report_error(&e),
                }
            });
        }
    };
    load();
    refresh.connect_clicked(move |_| load());
    let w = Rc::downgrade(app);
    report.connect_clicked(move |_| {
        let Some(app) = w.upgrade() else { return };
        glib::spawn_future_local(async move {
            match app.backend.call(&["report"], None).await {
                Ok(r) => {
                    app.window.clipboard().set_text(util::str_of(&r, "report"));
                    app.toast(&tr("Redacted report copied"));
                }
                Err(e) => app.report_error(&e),
            }
        });
    });

    let button = |title: &str, icon: &str, f: Box<dyn Fn(Rc<App>)>| {
        let row = adw::ActionRow::builder().title(title).activatable(true).build();
        row.add_prefix(&gtk::Image::from_icon_name(icon));
        row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        let w = Rc::downgrade(app);
        row.connect_activated(move |_| {
            if let Some(app) = w.upgrade() {
                f(app);
            }
        });
        maint.add(&row);
    };
    button(
        "Check all AppImages for changes",
        "view-refresh-symbolic",
        Box::new(|app| {
            glib::spawn_future_local(async move {
                let r = app.backend.call(&["refresh", "--deep"], None).await;
                app.refresh_apps().await;
                if let Ok(r) = r {
                    let n = r.as_array().map(|a| a.iter().filter(|i| ["stale", "missing"].contains(&util::str_of(i, "status"))).count()).unwrap_or(0);
                    app.toast(&if n > 0 { format!("{n} app(s) changed or are missing") } else { "All AppImages are unchanged".into() });
                }
            });
        }),
    );
    button(
        "Remove unused extractions",
        "edit-clear-all-symbolic",
        Box::new(|app| {
            glib::spawn_future_local(async move {
                if let Ok(r) = app.backend.call(&["cleanup"], None).await {
                    app.toast(&format!("Removed {} unused extraction(s)", r.as_array().map(Vec::len).unwrap_or(0)));
                }
            });
        }),
    );
    // Space used by the sandboxed apps, biggest first.
    let space = adw::ActionRow::builder().title(tr("Disk space of sandboxed apps")).subtitle(tr("Checking…")).build();
    space.add_prefix(&gtk::Image::from_icon_name("drive-harddisk-symbolic"));
    maint.add(&space);
    {
        let (w, row) = (Rc::downgrade(app), space.clone());
        glib::spawn_future_local(async move {
            let Some(app) = w.upgrade() else { return };
            if let Ok(v) = app.backend.call(&["space"], None).await {
                let mut apps = v.get("apps").and_then(Value::as_array).cloned().unwrap_or_default();
                apps.sort_by_key(|a| std::cmp::Reverse(util::get(a, "total").and_then(Value::as_u64).unwrap_or(0)));
                let total = util::get(&v, "total").and_then(Value::as_u64).unwrap_or(0);
                let top: Vec<String> = apps
                    .iter()
                    .take(3)
                    .map(|a| {
                        format!("{} {}", util::plain(util::str_of(a, "name")), glib::format_size(util::get(a, "total").and_then(Value::as_u64).unwrap_or(0)))
                    })
                    .collect();
                row.set_subtitle(&esc(&if apps.is_empty() {
                    "No sandboxed apps.".to_string()
                } else {
                    format!("{} for {} app(s). Largest: {}. Free space from an app's page → Details.", glib::format_size(total), apps.len(), top.join(", "))
                }));
            }
        });
    }
    // Data kept when sandboxes were removed with "Keep the app's settings and files".
    let leftover = adw::ActionRow::builder().title(tr("Data of removed sandboxes")).subtitle(tr("Checking…")).activatable(true).name("leftover-data").build();
    leftover.add_prefix(&gtk::Image::from_icon_name("user-trash-symbolic"));
    let leftover_btn = gtk::Button::builder().label(tr("Delete")).valign(gtk::Align::Center).sensitive(false).build();
    leftover_btn.add_css_class("destructive-action");
    leftover.add_suffix(&leftover_btn);
    leftover.set_activatable_widget(Some(&leftover_btn));
    maint.add(&leftover);
    let load_leftover = {
        let (w, row, btn) = (Rc::downgrade(app), leftover.clone(), leftover_btn.clone());
        move || {
            let (Some(app), row, btn) = (w.upgrade(), row.clone(), btn.clone()) else { return };
            glib::spawn_future_local(async move {
                match app.backend.call(&["cleanup", "--data", "--list"], None).await {
                    Ok(r) => {
                        let n = r.get("apps").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
                        let total = util::get(&r, "total").and_then(Value::as_u64).unwrap_or(0);
                        row.set_subtitle(&if n == 0 {
                            "Nothing left behind.".to_string()
                        } else {
                            format!(
                                "Settings and files of {n} app(s) whose sandbox was removed: {}. A new sandbox for the same AppImage would use them again.",
                                glib::format_size(total)
                            )
                        });
                        btn.set_sensitive(n > 0);
                    }
                    Err(e) => row.set_subtitle(&esc(&e)),
                }
            });
        }
    };
    load_leftover();
    let w = Rc::downgrade(app);
    let reload = load_leftover.clone();
    leftover_btn.connect_clicked(move |_| {
        let Some(app) = w.upgrade() else { return };
        let reload = reload.clone();
        glib::spawn_future_local(async move {
            if !window::confirm(
                &app.window,
                "Delete Data of Removed Sandboxes?",
                "The settings, logins and saved files of apps whose sandbox was removed are deleted. This cannot be undone.",
                "Delete",
                true,
            )
            .await
            {
                return;
            }
            match app.backend.call(&["cleanup", "--data"], None).await {
                Ok(r) => app.toast(&format!("Deleted {}", glib::format_size(util::get(&r, "total").and_then(Value::as_u64).unwrap_or(0)))),
                Err(e) => app.report_error(&e),
            }
            reload();
        });
    });

    let cli = adw::ActionRow::builder().title(tr("Command line")).subtitle(esc(&app.backend.cli.to_string_lossy())).subtitle_selectable(true).build();
    cli.add_css_class("property");
    maint.add(&cli);
    page
}
