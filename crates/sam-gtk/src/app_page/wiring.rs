// SPDX-License-Identifier: GPL-3.0-or-later
//! Signals of the app page, the sandbox check, launch arguments,
//! compatibility mode and saving the settings as a preset.

use super::*;

impl AppPage {
    // ------------------------------------------------------------ wiring

    pub(super) fn wire(self: &Rc<Self>) {
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
                me.watch_running();
            } else {
                me.create_sandbox();
            }
        });
        // Restart: close the app (it may save first), then start it again
        // with the changed settings.
        let w = Rc::downgrade(self);
        self.running_banner.connect_button_clicked(move |_| {
            let Some(me) = w.upgrade() else { return };
            let Some(app) = me.app() else { return };
            glib::spawn_future_local(async move {
                match app.backend.call(&["stop", &me.app_id], None).await {
                    Ok(_) => {
                        me.running_banner.set_revealed(false);
                        app.launch(&me.app_id);
                        me.watch_running();
                    }
                    Err(e) => app.report_error(&e),
                }
            });
        });
        let w = Rc::downgrade(self);
        self.remove_button.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.remove_sandbox();
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
        add(
            "reset",
            Box::new(|me| {
                if me.sandboxed() {
                    me.simple(vec!["profile".into(), "reset".into(), me.app_id.clone()], "Settings reset");
                } else {
                    me.reload();
                }
            }),
        );
        add(
            "reextract",
            Box::new(|me| {
                let Some(app) = me.app() else { return };
                let (id, me) = (me.app_id.clone(), me.clone());
                glib::spawn_future_local(async move {
                    app.reextract(&id, false).await;
                    me.reload();
                });
            }),
        );
        add("remove", Box::new(|me| me.remove_sandbox()));
        self.page.insert_action_group("page", Some(&group));
        let menu = gio::Menu::new();
        if self.sandboxed() {
            menu.append(Some(&tr("Files This App Saved")), Some("page.open-folder"));
            menu.append(Some(&tr("Reset to Recommended")), Some("page.reset"));
            menu.append(Some(&tr("Re-extract AppImage")), Some("page.reextract"));
            let danger = gio::Menu::new();
            danger.append(Some(&tr("Remove Sandbox…")), Some("page.remove"));
            menu.append_section(None, &danger);
        } else {
            menu.append(Some(&tr("Reset to Recommended")), Some("page.reset"));
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
            me.simple(
                vec!["desktop".into(), me.app_id.clone(), if on { "install".into() } else { "remove".into() }],
                if on { "Menu entry added" } else { "Menu entry removed" },
            );
        });
        let w = Rc::downgrade(self);
        self.hide_switch.connect_active_notify(move |sw| {
            let Some(me) = w.upgrade() else { return };
            if me.updating.get() {
                return;
            }
            let on = sw.is_active();
            if me.sandboxed() {
                me.simple_with(
                    vec!["menu".into(), if on { "hide".into() } else { "restore".into() }, me.app_id.clone()],
                    if on { "Other menu entries hidden" } else { "Other menu entries restored" },
                    true,
                );
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

    pub(super) fn run_check(self: &Rc<Self>) {
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
                    app.toast(&if failed == 0 {
                        "Sandbox check passed: every setting applies".to_string()
                    } else {
                        format!("Sandbox check: {failed} setting(s) do not apply")
                    });
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
    pub(super) fn render_check(self: &Rc<Self>) {
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
    pub(super) fn render_check_preview(self: &Rc<Self>) {
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
                let failed: Vec<String> =
                    results.iter().filter(|x| util::get(x, "ok") == Some(&Value::Bool(false))).map(|x| util::str_of(x, "title").to_string()).collect();
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
    pub(super) fn render_check_results(self: &Rc<Self>, report: &Value) {
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
            let exp = adw::ExpanderRow::builder()
                .title(format!("{} confirmed settings", passed.len()))
                .subtitle(tr("What the test program found inside the sandbox"))
                .build();
            exp.add_prefix(&{
                let i = gtk::Image::from_icon_name("object-select-symbolic");
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

    pub(super) fn args(&self) -> Vec<String> {
        self.entry().map(|e| util::list_of(&e, "profile.args")).unwrap_or_default()
    }

    pub(super) fn save_args(self: &Rc<Self>, args: Vec<String>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            match app.backend.call(&["args", &me.app_id, "--stdin"], Some(serde_json::to_string(&args).unwrap())).await {
                Ok(_) => app.toast(&tr("Launch arguments saved")),
                Err(e) => app.report_error(&e),
            }
            me.reload();
        });
    }

    pub(super) fn set_compat(self: &Rc<Self>, on: bool) {
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

    /// Reads the user's presets (to ask before replacing one by name).
    pub(super) fn load_presets(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let w = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            if let Ok(list) = app.backend.call(&["preset", "list"], None).await {
                if let Some(me) = w.upgrade() {
                    *me.presets.borrow_mut() = list.as_array().cloned().unwrap_or_default();
                }
            }
        });
    }

    /// Saves the settings shown as a user preset (asks before replacing one).
    pub(super) fn save_as_preset(self: &Rc<Self>, name: String) {
        let Some(app) = self.app() else { return };
        if name.is_empty() {
            app.toast(&tr("Type a name for the preset first"));
            return;
        }
        let Some(perms) = self.perms() else { return };
        let exists = self.presets.borrow().iter().any(|p| util::str_of(p, "name").eq_ignore_ascii_case(&name));
        let me = self.clone();
        let app_name = util::plain(&self.name());
        glib::spawn_future_local(async move {
            if exists
                && !window::confirm(
                    &app.window,
                    &format!("Replace “{name}”?"),
                    "A preset with this name exists. Its settings are replaced by the ones shown here. Apps that used it keep their current settings.",
                    "Replace",
                    true,
                )
                .await
            {
                return;
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
                    app.toast(&format!("Saved preset “{name}”. Apply it to other apps from the main menu → My Presets."));
                    me.save_preset_row.set_text("");
                    me.load_presets();
                }
                Err(e) => app.report_error(&e),
            }
        });
    }
}
