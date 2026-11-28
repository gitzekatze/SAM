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
                        if !me.saving.get() {
                            *me.saved.borrow_mut() = perms.clone();
                        }
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
        if let Ok(ev) = app
            .backend
            .call(&["evaluate", &self.app_id], Some(p.to_string()))
            .await
        {
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
        *self.menu_state.borrow_mut() = app
            .backend
            .call(&["menu", "list", &self.app_id], None)
            .await
            .ok();
        self.render_menu_group();
        self.load_log_list().await;
    }

    /// Fills the log picker (newest first) and shows the newest start log.
    pub(super) async fn load_log_list(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let mut files: Vec<Value> = app
            .backend
            .call(&["logs", &self.app_id, "--list"], None)
            .await
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        files.sort_by_key(|f| {
            std::cmp::Reverse(
                util::get(f, "modified")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
            )
        });
        let labels: Vec<String> = files
            .iter()
            .map(|f| {
                let kind = match util::str_of(f, "kind") {
                    "launch" => crate::i18n::n_("Start"),
                    "extract" => crate::i18n::n_("Unpacking"),
                    "detect" => crate::i18n::n_("Detection"),
                    "diagnose" => crate::i18n::n_("Diagnostic run"),
                    other => other,
                };
                format!(
                    "{kind} · {}",
                    util::format_time(
                        util::get(f, "modified")
                            .and_then(Value::as_i64)
                            .unwrap_or(0)
                    )
                )
            })
            .collect();
        let pick = files
            .iter()
            .position(|f| util::str_of(f, "kind") == "launch")
            .unwrap_or(0);
        self.updating.set(true);
        if labels.is_empty() {
            self.log_drop
                .set_model(Some(&gtk::StringList::new(&[crate::i18n::tr(
                    "No logs yet",
                )
                .as_str()])));
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
            None => set_mono_text(&self.log_view, &crate::i18n::tr("No logs yet.")),
        }
    }

    pub(super) async fn show_log_file(self: &Rc<Self>, file: &str) {
        let Some(app) = self.app() else { return };
        let text = match app
            .backend
            .call(
                &["logs", &self.app_id, "--file", file, "--tail", "400"],
                None,
            )
            .await
        {
            Ok(l) => util::str_of(&l, "text").to_string(),
            Err(e) => e.message,
        };
        set_mono_text(
            &self.log_view,
            if text.is_empty() { "(empty)" } else { &text },
        );
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
                    // Only what this edit changed, on top of what the app
                    // has now (audit G-F4).
                    let from = me.saved.borrow().clone().or_else(|| {
                        me.info
                            .borrow()
                            .as_ref()
                            .and_then(|i| util::get(i, "entry.profile.permissions").cloned())
                    });
                    let Some(from) = from else { break };
                    let change = serde_json::json!({"from": from, "to": p});
                    match app
                        .backend
                        .call(
                            &["profile", "change", &me.app_id, "--yes"],
                            Some(change.to_string()),
                        )
                        .await
                    {
                        Ok(_) => *me.saved.borrow_mut() = Some(p),
                        Err(e) => {
                            // Changed elsewhere meanwhile, or refused: the
                            // page shows the settings as they are now.
                            app.report_error(&e);
                            me.queued.borrow_mut().take();
                            *me.saved.borrow_mut() = None;
                        }
                    }
                    saved = true;
                } else {
                    match app
                        .backend
                        .call(
                            &["preview", &me.path, "--permissions-stdin"],
                            Some(p.to_string()),
                        )
                        .await
                    {
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
        let Some(perms) = self.pending.borrow().clone() else {
            return;
        };
        let mut args: Vec<String> = vec![
            "add".into(),
            self.path.clone(),
            "--accept".into(),
            "--permissions-stdin".into(),
        ];
        if self.hide_duplicates.get()
            && self
                .found()
                .and_then(|f| {
                    f.get("menu_entries")
                        .and_then(Value::as_array)
                        .map(|m| !m.is_empty())
                })
                .unwrap_or(false)
        {
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
            let r = app
                .backend
                .call_with_progress(&refs, Some(perms.to_string()), move |p| {
                    shown.progress.update(p)
                })
                .await;
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
                            crate::i18n::trf("{app} is packed in the newer DwarFS format. SAM can unpack it by itself once the dwarfs tools are installed (package \u{201c}dwarfs\u{201d}).", &[("app", &util::plain(&name))])
                        } else {
                            crate::i18n::trf(
                                "SAM could not unpack {app} by itself.",
                                &[("app", &util::plain(&name))],
                            )
                        };
                        let body = crate::i18n::trf("{why}\n\nInstead, the AppImage can unpack itself. That runs code from the AppImage, inside a sandbox with no network, no access to your files and the same limits on kernel calls as an app. Only continue if you trust where this file came from.", &[("why", &why)]);
                        if window::confirm(
                            &app.window,
                            &tr("Let the AppImage Unpack Itself?"),
                            &body,
                            &tr("Unpack"),
                            false,
                        )
                        .await
                        {
                            app.reextract(&id, true).await;
                            app.open_app(&id);
                        }
                    } else {
                        app.toast(&crate::i18n::trf(
                            "Sandbox created for {app}.",
                            &[("app", &util::plain(&name))],
                        ));
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
            let running = app
                .backend
                .call(&["info", &me.app_id], None)
                .await
                .ok()
                .and_then(|i| i.get("running").and_then(Value::as_u64))
                .unwrap_or(0)
                > 0;
            // Three clearly named choices; nothing is preselected, and the
            // button names the chosen action.
            let body = if running {
                crate::i18n::trf("{name} is running right now (maybe only in the system tray). It is closed first and gets the chance to save. Choose what to remove; the AppImage file itself is always kept.", &[("name", &name)])
            } else {
                crate::i18n::tr(
                    "Choose what to remove. The AppImage file itself is always kept, and any menu entry SAM hid is shown again when the sandbox goes.",
                )
            };
            let d = adw::AlertDialog::new(
                Some(&crate::i18n::trf("Remove {name}?", &[("name", &name)])),
                Some(&body),
            );
            // Each button text is a whole text: translations cannot be glued
            // from pieces ("Close and" + the action).
            let choices = [
                ("unpacked", tr("Only the unpacked copy"), tr("Frees disk space. The sandbox and the app's settings stay; SAM unpacks the app again at its next start."), if running { tr("Close and Free Space") } else { tr("Free Space") }),
                ("sandbox", tr("The sandbox, but keep the app's settings and files"), tr("Removes the sandbox and SAM's menu entry. The app's private folder (logins, settings, saved files) stays, and a new sandbox for this AppImage picks it up again."), if running { tr("Close and Remove the Sandbox") } else { tr("Remove Sandbox") }),
                ("everything", tr("Everything"), tr("Removes the sandbox and the app's private folder with its logins, settings and saved files."), if running { tr("Close and Delete Everything") } else { tr("Delete Everything") }),
            ];
            let list = gtk::Box::new(gtk::Orientation::Vertical, 10);
            let mut first: Option<gtk::CheckButton> = None;
            let chosen = Rc::new(std::cell::RefCell::new(String::new()));
            d.add_responses(&[("cancel", &tr("Cancel")), ("ok", &tr("Choose an option"))]);
            d.set_response_enabled("ok", false);
            for (key, title, detail, action) in choices {
                let label = gtk::Label::builder()
                    .label(format!(
                        "<b>{}</b>\n<small>{}</small>",
                        esc(&title),
                        esc(&detail)
                    ))
                    .use_markup(true)
                    .wrap(true)
                    .xalign(0.0)
                    .build();
                let b = gtk::CheckButton::builder()
                    .child(&label)
                    .name(format!("remove-{key}"))
                    .build();
                b.update_property(&[gtk::accessible::Property::Label(&title)]);
                if let Some(f) = &first {
                    b.set_group(Some(f));
                } else {
                    first = Some(b.clone());
                }
                let (d2, chosen) = (d.clone(), chosen.clone());
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
                    Ok(_) => app.toast(&crate::i18n::trf(
                        "Freed the space of the unpacked copy of {name}. SAM unpacks it again at the next start.",
                        &[("name", &name)],
                    )),
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
                    let kept = if keep_data {
                        " Its settings and files were kept."
                    } else {
                        ""
                    };
                    app.toast(&if warnings.is_empty() {
                        crate::i18n::trf(
                            "Removed the sandbox for {name}.{kept}",
                            &[("name", &name), ("kept", &kept)],
                        )
                    } else {
                        crate::i18n::trf(
                            "The sandbox was removed, but: {problems}",
                            &[("problems", &warnings.join("; "))],
                        )
                    });
                    let path = me
                        .entry()
                        .map(|e| util::str_of(&e, "source_path").to_string())
                        .unwrap_or_default();
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
        let p = self
            .info
            .borrow()
            .as_ref()
            .map(|i| util::str_of(i, "private_home").to_string())
            .unwrap_or_default();
        if !p.is_empty() {
            let _ = std::fs::create_dir_all(&p);
            #[expect(
                clippy::disallowed_methods,
                reason = "way out: a local folder, opened on a click"
            )]
            let launcher = gtk::FileLauncher::new(Some(&gio::File::for_path(&p)));
            let win = self.app().map(|a| a.window.clone());
            glib::spawn_future_local(async move {
                let _ = launcher.launch_future(win.as_ref()).await;
            });
        }
    }

    /// The review fingerprint of the app as this page shows it (from
    /// `info`); empty when the page has none, which no record matches.
    pub(super) fn shown_fingerprint(&self) -> String {
        self.info
            .borrow()
            .as_ref()
            .map(|i| util::str_of(i, "review_fingerprint").to_string())
            .unwrap_or_default()
    }

    /// `review` for what this page shows: refused when the app changed
    /// since the page drew it, so no button confirms a notice or a setting
    /// the person never saw (review L4). The refusal is reported and the
    /// page drawn again, as for any failed command.
    pub(super) fn review_args(&self) -> Vec<String> {
        review_args(&self.app_id, &self.shown_fingerprint())
    }

    /// Runs a command that changes the app, then reloads.
    pub(super) fn simple(self: &Rc<Self>, args: Vec<String>, ok_text: &str) {
        self.simple_with(args, ok_text, false)
    }

    /// `full`: the change affects what is found on disk (menu entries),
    /// so every AppImage is looked at again.
    pub(super) fn simple_with(self: &Rc<Self>, args: Vec<String>, ok_text: &str, full: bool) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        let ok_text = ok_text.to_string();
        glib::spawn_future_local(async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let r = app.backend.call(&refs, None).await;
            me.after_simple(&app, r, &ok_text, full).await;
        });
    }

    /// What [`Self::simple_with`] does after its command: tells the result
    /// and reloads. The update buttons use it after `call_online`.
    pub(super) async fn after_simple(
        self: &Rc<Self>,
        app: &Rc<App>,
        r: crate::backend::Reply,
        ok_text: &str,
        full: bool,
    ) {
        match r {
            Ok(_) => app.toast(ok_text),
            Err(e) => app.report_error(&e),
        }
        self.reload();
        if full {
            app.refresh_apps().await;
        } else {
            app.refresh_registered().await;
        }
    }

    pub(super) fn apply_suggestion(self: &Rc<Self>, sug: Value, as_repair: bool, then_run: bool) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            let title = util::str_of(&sug, "title").to_string();
            let explanation = util::str_of(&sug, "explanation").to_string();
            let asked = window_asks(&sug);
            let ask = if util::bool_of(&sug, "from_app_output") {
                Some(crate::i18n::trf(
                    "This suggestion is based on messages the app printed itself. A malicious app can print messages to get more access.\n\n{explanation}",
                    &[("explanation", &explanation)],
                ))
            } else {
                asked.then(|| explanation.clone())
            };
            if let Some(body) = ask {
                if !window::confirm(
                    &app.window,
                    &crate::i18n::trf("Apply “{step}”?", &[("step", &title)]),
                    &body,
                    &if then_run {
                        crate::i18n::tr("Apply and Start")
                    } else {
                        crate::i18n::tr("Apply")
                    },
                    false,
                )
                .await
                {
                    return;
                }
            }
            let id = util::str_of(&sug, "id").to_string();
            let args = apply_args(&me.app_id, &id, as_repair, asked);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            match app.backend.call(&args, None).await {
                Ok(_) => {
                    app.toast(&crate::i18n::trf("Applied: {step}", &[("step", &title)]));
                    if then_run {
                        app.launch(&me.app_id);
                    }
                }
                Err(e) => match stale_rating_notice(&e) {
                    Some(text) => app.toast(&text),
                    None => app.report_error(&e),
                },
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
            let latest = me
                .entry()
                .map(|e| util::str_of(&e, "update.latest").to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| crate::i18n::tr("the newest version"));
            let body = crate::i18n::trf("SAM downloads {version} from where the update source publishes it, checks it against the published checksum, and puts it in place of the current file. The current version is kept, so you can go back. Settings and files stay.", &[("version", &util::plain(&latest))]);
            if !window::confirm(&app.window, &tr("Update Now?"), &body, &tr("Update"), false).await
            {
                return;
            }
            button.set_sensitive(false);
            app.toast(&tr("Downloading the update…"));
            let mut args = vec!["update".to_string(), me.app_id.clone()];
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            // The person said Update in the dialog just before.
            #[expect(
                clippy::disallowed_methods,
                reason = "way out: update, after the person said Update"
            )]
            let mut result = app.backend.call_online(&refs, None).await;
            if let Err(e) = &result {
                if e.is("signing-key-changed")
                    || e.is("signature-unchecked")
                    || e.is("signing-time-unknown")
                {
                    let title = if e.is("signing-key-changed") {
                        tr("Signed With Another Key")
                    } else if e.is("signing-time-unknown") {
                        // Checked and the same key, but when it was signed
                        // could not be read (review B2 S6, R94).
                        tr("Signing Time Unknown")
                    } else {
                        tr("Signature Not Checked")
                    };
                    let ok =
                        window::confirm(&app.window, &title, e, &tr("Update Anyway"), true).await;
                    if ok {
                        args.push("--accept-key-change".into());
                        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                        // The person said Update Anyway just before.
                        #[expect(
                            clippy::disallowed_methods,
                            reason = "way out: update, after the person said Update Anyway"
                        )]
                        let r = app.backend.call_online(&refs, None).await;
                        result = r;
                    } else {
                        // Said no: the download kept for this answer is
                        // deleted now, not left in SAM's folder.
                        args.push("--decline-key-change".into());
                        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                        // Offline: deletes the kept download.
                        #[expect(
                            clippy::disallowed_methods,
                            reason = "way out: update --decline-key-change, offline"
                        )]
                        let r = app.backend.call_online(&refs, None).await;
                        result = r.map(|_| Value::Null);
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

/// Whether the window asks before applying a hint or repair step that is
/// not from the app's own output: rated Think twice or Dangerous, or
/// turning on compatibility mode. By SAM's one rule
/// (`sam_core::risk::waits_for_yes`), by which the command line refuses
/// such a hint without --yes (owner decision 13 of 2026-11-23).
pub(super) fn asks_first(sug: &Value) -> bool {
    // The level as the command line lists it; an unknown one is Harmless.
    let level = serde_json::from_value(sug["risk"].clone()).unwrap_or_default();
    let compat = util::str_of(sug, "action.kind") == "compat";
    sam_core::risk::waits_for_yes(level, compat, false)
}

/// Whether the window asks before applying a hint or repair step, and so
/// confirms it for the command line with --yes: one from the app's own
/// output always (the command line refuses it without --yes, audit U-M2;
/// regression #69), any other by [`asks_first`].
pub(super) fn window_asks(sug: &Value) -> bool {
    util::bool_of(sug, "from_app_output") || asks_first(sug)
}

/// What the window says when the command line refuses a hint or repair
/// step for a yes the window did not give: the page showed an older,
/// lower rating, or a step that did not come from the app's own output
/// (the settings or the last start changed since). SAM draws the page
/// again, so the next click asks first; the command line's advice to add
/// --yes does not fit here.
pub(super) fn stale_rating_notice(e: &crate::backend::CliError) -> Option<String> {
    if e.is("hint-needs-yes") {
        Some(crate::i18n::tr("The rating of this hint changed. SAM shows the page again; apply it once more to be asked first."))
    } else if e.is("step-needs-yes") || e.is("repair-needs-yes") {
        Some(crate::i18n::tr("The rating of this repair step changed. SAM shows the page again; apply it once more to be asked first."))
    } else {
        None
    }
}

/// The command that applies hint or repair step `id` to app `app_id`.
/// The window confirms it for the command line with --yes exactly when it
/// has asked first: a hint or repair step rated Think twice or Dangerous,
/// one that turns on compatibility mode, or one from the app's own output.
/// The command line refuses each of those without --yes (`hints --apply`:
/// owner decision 13 of 2026-11-23; `repair --apply`: decision A of
/// 2026-11-25, and audit U-M2 for the app's own output), so a step the
/// page showed with an older, lower rating is refused instead of being
/// applied unasked, and the page is drawn again.
pub(super) fn apply_args(app_id: &str, id: &str, as_repair: bool, asked: bool) -> Vec<String> {
    let command = if as_repair { "repair" } else { "hints" };
    let mut args: Vec<String> = vec![command.into(), app_id.into(), "--apply".into(), id.into()];
    if asked {
        args.push("--yes".into());
    }
    args
}

/// The arguments of `review` for app `id` as shown with the review
/// fingerprint `seen`.
pub(super) fn review_args(id: &str, seen: &str) -> Vec<String> {
    vec!["review".into(), id.into(), "--seen".into(), seen.into()]
}
