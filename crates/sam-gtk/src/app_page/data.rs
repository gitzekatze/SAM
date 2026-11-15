// SPDX-License-Identifier: GPL-3.0-or-later
//! Loading the app's data, creating and removing the sandbox, and commands
//! that change it.

use super::*;

impl AppPage {
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

    pub(super) async fn evaluate(self: &Rc<Self>, p: Value) {
        let Some(app) = self.app() else { return };
        if let Ok(ev) = app.backend.call(&["evaluate", &self.app_id], Some(p.to_string())).await {
            self.editor.set_evaluation(Some(ev.clone()));
            self.set_tags(Some(&ev));
        }
    }

    pub(super) async fn load_side_info(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let cmd = app.backend.call(&["command", &self.app_id], None).await;
        set_mono_text(
            &self.command_view,
            &match cmd {
                Ok(c) => util::str_of(&c, "command").to_string(),
                Err(e) => e.message,
            },
        );
        *self.menu_state.borrow_mut() = app.backend.call(&["menu", "list", &self.app_id], None).await.ok();
        self.render_menu_group();
        self.load_log_list().await;
    }

    /// Fills the log picker (newest first) and shows the newest start log.
    pub(super) async fn load_log_list(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let mut files: Vec<Value> =
            app.backend.call(&["logs", &self.app_id, "--list"], None).await.ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
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

    pub(super) async fn show_log_file(self: &Rc<Self>, file: &str) {
        let Some(app) = self.app() else { return };
        let text = match app.backend.call(&["logs", &self.app_id, "--file", file, "--tail", "400"], None).await {
            Ok(l) => util::str_of(&l, "text").to_string(),
            Err(e) => e.message,
        };
        set_mono_text(&self.log_view, if text.is_empty() { "(empty)" } else { &text });
    }

    /// Saves (or previews) changed settings. Changes are sent one after
    /// another, and while one is being saved only the newest waiting change
    /// is kept, so a quick series of edits can never be saved out of order.
    pub(super) fn on_perms_edited(self: &Rc<Self>, p: Value) {
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

    pub(super) fn create_sandbox(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let Some(perms) = self.pending.borrow().clone() else { return };
        let mut args: Vec<String> = vec!["add".into(), self.path.clone(), "--accept".into(), "--permissions-stdin".into()];
        if self.hide_duplicates.get() && self.found().and_then(|f| f.get("menu_entries").and_then(Value::as_array).map(|m| !m.is_empty())).unwrap_or(false) {
            args.push("--hide-duplicates".into());
        }
        args.push("--progress".into());
        let name = self.name();
        self.main_button.set_sensitive(false);
        // The settings below would not take effect while it is created.
        self.content.set_sensitive(false);
        self.progress.start();
        let me = self.clone();
        glib::spawn_future_local(async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let shown = me.clone();
            let r = app.backend.call_with_progress(&refs, Some(perms.to_string()), move |p| shown.progress.update(p)).await;
            me.progress.finish();
            me.content.set_sensitive(true);
            me.main_button.set_sensitive(true);
            match r {
                Ok(r) => {
                    let id = util::str_of(&r, "entry.id").to_string();
                    app.refresh_apps().await;
                    app.open_app(&id);
                    if util::bool_of(&r, "needs_fallback_consent") {
                        // DwarFS AppImages (\"anylinux\", uruntime) need the dwarfs tools for
                        // SAM to unpack them itself: say so, it avoids the question.
                        let dwarfs = util::str_of(&r, "missing_tool") == "dwarfs";
                        let why = if dwarfs {
                            format!("{} is packed in the newer DwarFS format. SAM can unpack it by itself once the dwarfs tools are installed (package \u{201c}dwarfs\u{201d}).", util::plain(&name))
                        } else {
                            format!("SAM could not unpack {} by itself.", util::plain(&name))
                        };
                        let body = format!(
                            "{why}\n\nInstead, the AppImage can unpack itself. That runs code from the AppImage, inside a sandbox with no network and no access to your files. Only continue if you trust where this file came from."
                        );
                        if window::confirm(&app.window, &tr("Let the AppImage Unpack Itself?"), &body, &tr("Unpack"), false).await {
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

    pub(super) fn remove_sandbox(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        let name = util::plain(&self.name());
        glib::spawn_future_local(async move {
            // Asked fresh: the app may have been started or closed meanwhile.
            let running = app.backend.call(&["info", &me.app_id], None).await.ok().and_then(|i| i.get("running").and_then(Value::as_u64)).unwrap_or(0) > 0;
            // Three clearly named choices; nothing is preselected, and the
            // button names the chosen action.
            let body = if running {
                format!("{name} is running right now (maybe only in the system tray). It is closed first and gets the chance to save. Choose what to remove; the AppImage file itself is always kept.")
            } else {
                "Choose what to remove. The AppImage file itself is always kept, and any menu entry SAM hid is shown again when the sandbox goes.".to_string()
            };
            let d = adw::AlertDialog::new(Some(&format!("Remove {name}?")), Some(&body));
            let choices = [
                ("unpacked", "Only the unpacked copy", "Frees disk space. The sandbox and the app's settings stay; SAM unpacks the app again at its next start.", "Free Space"),
                ("sandbox", "The sandbox, but keep the app's settings and files", "Removes the sandbox and SAM's menu entry. The app's private folder (logins, settings, saved files) stays, and a new sandbox for this AppImage picks it up again.", "Remove Sandbox"),
                ("everything", "Everything", "Removes the sandbox and the app's private folder with its logins, settings and saved files.", "Delete Everything"),
            ];
            let list = gtk::Box::new(gtk::Orientation::Vertical, 10);
            let mut first: Option<gtk::CheckButton> = None;
            let chosen = Rc::new(std::cell::RefCell::new(String::new()));
            d.add_responses(&[("cancel", "Cancel"), ("ok", "Choose an option")]);
            d.set_response_enabled("ok", false);
            for (key, title, detail, action) in choices {
                let label = gtk::Label::builder()
                    .label(format!("<b>{}</b>\n<small>{}</small>", esc(title), esc(detail)))
                    .use_markup(true)
                    .wrap(true)
                    .xalign(0.0)
                    .build();
                let b = gtk::CheckButton::builder().child(&label).name(format!("remove-{key}")).build();
                b.update_property(&[gtk::accessible::Property::Label(title)]);
                if let Some(f) = &first {
                    b.set_group(Some(f));
                } else {
                    first = Some(b.clone());
                }
                let (d2, chosen) = (d.clone(), chosen.clone());
                let action = if running { format!("Close and {action}") } else { action.to_string() };
                b.connect_toggled(move |b| {
                    if b.is_active() {
                        *chosen.borrow_mut() = key.to_string();
                        d2.set_response_label("ok", &action);
                        d2.set_response_enabled("ok", true);
                    }
                });
                list.append(&b);
            }
            d.set_extra_child(Some(&list));
            d.set_response_appearance("ok", adw::ResponseAppearance::Destructive);
            d.set_default_response(Some("cancel"));
            d.set_close_response("cancel");
            if d.choose_future(Some(&app.window)).await != "ok" {
                return;
            }
            let choice = chosen.borrow().clone();
            if choice == "unpacked" {
                if running {
                    let _ = app.backend.call(&["stop", &me.app_id], None).await;
                }
                match app.backend.call(&["free-space", &me.app_id], None).await {
                    Ok(_) => app.toast(&format!("Freed the space of the unpacked copy of {name}. SAM unpacks it again at the next start.")),
                    Err(e) => app.report_error(&e),
                }
                me.reload();
                return;
            }
            let keep_data = choice == "sandbox";
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
                    app.toast(&if warnings.is_empty() {
                        format!("Removed the sandbox for {name}.{kept}")
                    } else {
                        format!("Removed the sandbox, but: {}", warnings.join("; "))
                    });
                    let path = me.entry().map(|e| util::str_of(&e, "source_path").to_string()).unwrap_or_default();
                    app.refresh_apps().await;
                    if path.is_empty() {
                        app.show_welcome()
                    } else {
                        app.open_file(&path)
                    }
                }
                Err(e) => app.report_error(&e),
            }
        });
    }

    pub(super) fn open_private_folder(&self) {
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
    pub(super) fn simple(self: &Rc<Self>, args: Vec<String>, ok_text: &'static str) {
        self.simple_with(args, ok_text, false)
    }

    /// `full`: the change affects what is found on disk (menu entries),
    /// so every AppImage is looked at again.
    pub(super) fn simple_with(self: &Rc<Self>, args: Vec<String>, ok_text: &'static str, full: bool) {
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

    pub(super) fn apply_suggestion(self: &Rc<Self>, sug: Value, as_repair: bool, then_run: bool) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            let title = util::str_of(&sug, "title").to_string();
            let explanation = util::str_of(&sug, "explanation").to_string();
            let risk = util::str_of(&sug, "risk");
            let ask = if util::bool_of(&sug, "from_app_output") {
                Some(format!(
                    "This suggestion is based on messages the app printed itself. A malicious app can print messages to get more access.\n\n{explanation}"
                ))
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

    /// Downloads and installs the newest version (`sam-jail update`), after
    /// asking; asks again when the new file is signed with another key.
    pub(super) fn run_update(self: &Rc<Self>, button: &gtk::Button) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        let button = button.clone();
        glib::spawn_future_local(async move {
            let latest =
                me.entry().map(|e| util::str_of(&e, "update.latest").to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "the newest version".into());
            let body = format!(
                "SAM downloads {} from the address the AppImage names, checks it against the published checksum, and puts it in place of the current file. The current version is kept, so you can go back. Settings and files stay.",
                util::plain(&latest)
            );
            if !window::confirm(&app.window, &tr("Update Now?"), &body, &tr("Update"), false).await {
                return;
            }
            button.set_sensitive(false);
            app.toast(&tr("Downloading the update…"));
            let mut args = vec!["update".to_string(), me.app_id.clone()];
            let mut result = app.backend.call(&args.iter().map(String::as_str).collect::<Vec<_>>(), None).await;
            if let Err(e) = &result {
                if e.is("signing-key-changed") {
                    let ok = window::confirm(&app.window, &tr("Signed With Another Key"), e, &tr("Update Anyway"), true).await;
                    if ok {
                        args.push("--accept-key-change".into());
                        result = app.backend.call(&args.iter().map(String::as_str).collect::<Vec<_>>(), None).await;
                    } else {
                        result = Ok(Value::Null);
                    }
                }
            }
            match result {
                Ok(v) if !v.is_null() => app.toast(&tr("Updated; the previous version is kept")),
                Ok(_) => {}
                Err(e) => app.report_error(&e),
            }
            button.set_sensitive(true);
            me.reload();
            app.refresh_apps().await;
        });
    }
}
