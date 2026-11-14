// SPDX-License-Identifier: GPL-3.0-or-later
//! Drawing the app page from its data: header, settings, launching, menu
//! entries, troubleshooting and details.

use super::*;

impl AppPage {
    // ------------------------------------------------------------ rendering

    pub(super) fn show_load_error(self: &Rc<Self>, e: &str) {
        self.clear_dynamic();
        let row = adw::ActionRow::builder().title(tr("The settings could not be loaded")).subtitle(esc(e)).build();
        row.add_prefix(&status_icon("dialog-error-symbolic", "error"));
        let retry = gtk::Button::builder().label(tr("Try Again")).valign(gtk::Align::Center).build();
        let w = Rc::downgrade(self);
        retry.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.reload();
            }
        });
        row.add_suffix(&retry);
        self.add_dynamic(&self.notices, &row);
    }

    pub(super) fn set_risk_badge(&self, ev: &Value) {
        let risk = ev.get("risk").cloned().unwrap_or_default();
        let level = util::str_of(&risk, "level").to_string();
        set_badge_visible(&self.risk_badge, !level.is_empty());
        util::set_badge(&self.risk_badge, &util::risk_headline(&risk), util::risk_tone(&level));
        self.risk_badge.set_tooltip_text(Some(&util::risk_tooltip(&risk)));
    }

    pub(super) fn add_dynamic(&self, g: &adw::PreferencesGroup, w: &impl IsA<gtk::Widget>) {
        g.add(w);
        self.dynamic_rows.borrow_mut().push((g.clone(), w.clone().upcast()));
    }

    pub(super) fn clear_dynamic(&self) {
        for (g, w) in self.dynamic_rows.borrow_mut().drain(..) {
            g.remove(&w);
        }
    }

    pub(super) fn render(self: &Rc<Self>) {
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
            summary
                .as_ref()
                .map(|s| util::str_of(s, "icon_path").to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| found.as_ref().map(|f| util::str_of(f, "icon").to_string()))
                .unwrap_or_default()
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
        let badge_state = summary.as_ref().map(|s| util::str_of(s, "badge").to_string()).unwrap_or_default();
        let state = match badge_state.as_str() {
            "needs-review" => Some(("Needs review", "warn", "Look over the settings below; SAM chose them automatically or the app asks for new access".to_string())),
            "compatibility-mode" => Some(("Compatibility mode", "warn", "Compatibility mode is on: so that the app works, it gets broad access (internet, the whole session bus, all of /usr, X11, GPU and sound). Turn it off under Launching → Compatibility mode once a narrower setting works; your previous settings come back".to_string())),
            "compatibility-risk" => Some(compat_risk_label(entry.as_ref())),
            "unsafe" => Some(("Unsafe", "danger", "These settings let the app reach far outside its sandbox".to_string())),
            "stale" => Some(("AppImage changed", "warn", "The AppImage file changed since it was unpacked; SAM still runs the previous version until you update the sandbox".to_string())),
            "broken" => Some(("Broken", "bad", "The last start failed; see Troubleshooting below".to_string())),
            "missing" => Some(("File missing", "bad", "The AppImage file is gone; SAM can still run the unpacked copy".to_string())),
            _ => None,
        };
        set_badge_visible(&self.state_badge, state.is_some());
        if let Some((t, tone, tip)) = state {
            util::set_badge(&self.state_badge, t, tone);
            self.state_badge.set_tooltip_text(Some(&tip));
        }
        let selection = if sandboxed {
            info.as_ref().and_then(|i| i.get("selection").cloned())
        } else {
            self.preview.borrow().as_ref().and_then(|p| p.get("selection").cloned())
        };
        let have_data = if sandboxed { info.is_some() } else { self.preview.borrow().is_some() };
        if have_data && selection.as_ref().is_none_or(Value::is_null) {
            util::set_badge(&self.sandbox_badge, "Sandbox unavailable", "bad");
            self.sandbox_badge.set_tooltip_text(Some("Bubblewrap cannot run on this system; see Diagnostics"));
        } else {
            util::set_badge(&self.sandbox_badge, "Bubblewrap", "blue");
            self.sandbox_badge.set_tooltip_text(Some(
                "The sandbox technology: Bubblewrap gives the app its own view of the system with only the folders, devices and services allowed below",
            ));
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
        let recommended = if sandboxed {
            entry.as_ref().and_then(|e| e.get("recommended").cloned())
        } else {
            self.preview.borrow().as_ref().and_then(|p| p.get("recommended").cloned())
        };
        let evaluation = if sandboxed {
            None
        } else {
            self.preview
                .borrow()
                .as_ref()
                .map(|p| serde_json::json!({ "risk": p.get("risk").cloned().unwrap_or_default(), "warnings": p.get("warnings").cloned().unwrap_or_default() }))
        };
        if sandboxed {
            self.editor.set_data(self.perms(), recommended, None);
        } else {
            self.editor.set_data(self.perms(), recommended, evaluation);
        }

        // Dynamic groups.
        self.clear_dynamic();
        if !have_data {
            let row = adw::ActionRow::builder().title(tr("Loading settings…")).build();
            row.add_prefix(&gtk::Spinner::builder().spinning(true).build());
            self.add_dynamic(&self.notices, &row);
        }
        if !sandboxed {
            let row = adw::ActionRow::builder()
                .title(tr("Not sandboxed yet"))
                .subtitle(tr(
                    "These are the settings SAM recommends for this app. Adjust them below, then click Create Sandbox. Nothing is unpacked or run before that.",
                ))
                .build();
            row.add_prefix(&status_icon("dialog-information-symbolic", "accent"));
            self.add_dynamic(&self.notices, &row);
        }
        // A newer version is published (last update check).
        if let Some(e) = entry.as_ref().filter(|e| util::str_of(e, "update.state") == "available") {
            let row = adw::ActionRow::builder().title(tr("Update available")).subtitle(esc(util::str_of(e, "update.detail"))).build();
            row.add_prefix(&status_icon("software-update-available-symbolic", "accent"));
            if let Some(page) = Some(util::str_of(e, "update.download_page")).filter(|p| p.starts_with("https://")) {
                let open = gtk::Button::builder().label(tr("Open Download Page")).valign(gtk::Align::Center).build();
                let (page, w) = (page.to_string(), Rc::downgrade(self));
                open.connect_clicked(move |_| {
                    if let Some(app) = w.upgrade().and_then(|me| me.app()) {
                        gtk::UriLauncher::new(&page).launch(Some(&app.window), gio::Cancellable::NONE, |_| {});
                    }
                });
                row.add_suffix(&open);
            }
            let now = gtk::Button::builder().label(tr("Update Now")).valign(gtk::Align::Center).build();
            now.add_css_class("suggested-action");
            let w = Rc::downgrade(self);
            now.connect_clicked(move |b| {
                if let Some(me) = w.upgrade() {
                    me.run_update(b);
                }
            });
            row.add_suffix(&now);
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
                row.add_prefix(&status_icon(
                    if badge == "stale" { "dialog-warning-symbolic" } else { "dialog-error-symbolic" },
                    if badge == "stale" { "warning" } else { "error" },
                ));
                let btn = gtk::Button::builder().label(if badge == "missing" { "Locate…" } else { "Re-extract" }).valign(gtk::Align::Center).build();
                let w = Rc::downgrade(self);
                let missing = badge == "missing";
                btn.connect_clicked(move |_| {
                    if let Some(me) = w.upgrade() {
                        if missing {
                            me.relocate()
                        } else {
                            me.menu_button.activate_action("page.reextract", None).ok();
                        }
                    }
                });
                row.add_suffix(&btn);
                self.add_dynamic(&self.notices, &row);
            }
            let pending = util::list_of(e, "pending_changes");
            if badge == "needs-review" && pending.is_empty() {
                let row = adw::ActionRow::builder()
                    .title(tr("Settings not reviewed yet"))
                    .subtitle(tr("SAM chose these settings for you. Look through them, then confirm."))
                    .build();
                row.add_prefix(&status_icon("dialog-information-symbolic", "accent"));
                let btn = gtk::Button::builder().label(tr("Mark as Reviewed")).valign(gtk::Align::Center).name("review-button").build();
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
                let row = adw::ActionRow::builder()
                    .title(esc(&format!("The updated AppImage likely needs: {}. Your settings were kept.", pending.join(", "))))
                    .build();
                row.add_prefix(&status_icon("dialog-information-symbolic", "accent"));
                let btn = gtk::Button::builder().label(tr("Got It")).valign(gtk::Align::Center).build();
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
            let row = self.suggestion_row(f, "dialog-warning-symbolic", true, true);
            self.add_dynamic(&self.findings, &row);
        }
        self.findings.set_visible(!findings.is_empty());
        self.notices.set_visible(true);

        self.preset_group.set_visible(have_data);

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
    pub(super) fn render_launch_group(self: &Rc<Self>, entry: Option<&Value>, app: &Rc<App>) {
        let sandboxed = self.sandboxed() && entry.is_some();
        self.launch_group.set_description(Some(if self.sandboxed() {
            "How SAM starts this app."
        } else {
            "How SAM starts this app. Available once the sandbox exists."
        }));
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
    pub(super) fn render_menu_group(self: &Rc<Self>) {
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

    pub(super) fn suggestion_row(self: &Rc<Self>, s: &Value, icon: &str, as_repair: bool, then_run: bool) -> adw::ActionRow {
        let none = util::str_of(s, "action.kind") == "none";
        let row = adw::ActionRow::builder().title(esc(util::str_of(s, "title"))).subtitle(esc(util::str_of(s, "explanation"))).activatable(!none).build();
        // Problems from the last start in amber, general hints in the accent.
        row.add_prefix(&status_icon(icon, if as_repair { "warning" } else { "accent" }));
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

    pub(super) fn button_row(self: &Rc<Self>, g: &adw::PreferencesGroup, icon: &str, title: &str, subtitle: &str, f: impl Fn(&Rc<AppPage>) + 'static) {
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

    pub(super) fn render_troubleshooting(self: &Rc<Self>, e: &Value, info: &Option<Value>) {
        let g = self.trouble.clone();
        let last = e.get("last_launch").filter(|l| !l.is_null());
        let last_text = match last {
            Some(l) => {
                let mut t = format!(
                    "{} — {}",
                    util::format_time(util::get(l, "started_at").and_then(Value::as_i64).unwrap_or(0)),
                    util::plain(util::str_of(l, "summary"))
                );
                if let Some(en) = l.get("enforcement").and_then(Value::as_str) {
                    t.push_str(&format!("\nEnforced: {}", util::plain(en)));
                }
                t
            }
            None => "Not started yet".into(),
        };
        let row = adw::ActionRow::builder().title(tr("Last start")).subtitle(esc(&last_text)).build();
        row.add_prefix(&gtk::Image::from_icon_name("document-open-recent-symbolic"));
        self.add_dynamic(&g, &row);
        // Going back after an update (the replaced version is kept).
        if let Some(prev) = entry_backup_name(e) {
            self.button_row(
                &g,
                "edit-undo-symbolic",
                "Go back to the previous version",
                &format!("Puts {prev} back in place of the updated AppImage. The updated file is kept, so you can switch again."),
                |me| me.simple_with(vec!["update".into(), me.app_id.clone(), "--undo".into()], "Back to the previous version", true),
            );
        }
        // Check the setup (sam-jail doctor <app>), results right below.
        self.button_row(
            &g,
            "emblem-system-symbolic",
            "Check the setup",
            "Is the AppImage still there, unpacked and intact, is the menu entry valid, and how did the last start end.",
            |me| me.run_setup_check(),
        );
        if let Some(r) = self.setup_report.borrow().as_ref() {
            for c in r.get("checks").and_then(Value::as_array).into_iter().flatten() {
                let status = util::str_of(c, "status");
                let row = adw::ActionRow::builder().title(esc(util::str_of(c, "label"))).subtitle(esc(util::str_of(c, "detail"))).build();
                let (icon, class) = match status {
                    "ok" => ("object-select-symbolic", "success"),
                    "warn" => ("dialog-warning-symbolic", "warning"),
                    "fail" | "error" => ("dialog-error-symbolic", "error"),
                    _ => ("dialog-information-symbolic", "dim-label"),
                };
                let img = gtk::Image::from_icon_name(icon);
                img.add_css_class(class);
                img.set_margin_start(24);
                row.add_prefix(&img);
                self.add_dynamic(&g, &row);
            }
        }
        // Test start (sam-jail selftest <app>): a short real start.
        self.button_row(
            &g,
            "media-playback-start-symbolic",
            "Test start",
            &format!(
                "Starts the app for {TEST_SECONDS} seconds (its window opens) and reports whether it keeps running. A quick way to see if a change helped."
            ),
            |me| me.run_test_start(),
        );
        if let Some(r) = self.test_result.borrow().as_ref() {
            let ok = util::str_of(r, "status") == "ok";
            let row = adw::ActionRow::builder()
                .title(match (ok, util::str_of(r, "detail").starts_with("ran in its sandbox")) {
                    (true, true) => "The program ran in its sandbox",
                    (true, false) => "The app started and kept running",
                    (false, _) => "The app did not keep running",
                })
                .subtitle(esc(util::str_of(r, "detail")))
                .build();
            let img = gtk::Image::from_icon_name(if ok { "object-select-symbolic" } else { "dialog-error-symbolic" });
            img.add_css_class(if ok { "success" } else { "error" });
            img.set_margin_start(24);
            row.add_prefix(&img);
            self.add_dynamic(&g, &row);
        }
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
            self.button_row(&g, "edit-undo-symbolic", "Undo all repairs", &format!("Applied: {applied}"), |me| {
                me.simple(vec!["repair".into(), me.app_id.clone(), "--undo".into()], "Repairs undone")
            });
        }
        self.button_row(
            &g,
            "folder-open-symbolic",
            "Files this app saved",
            "The app's private folder, where it keeps settings and files it saved outside your granted folders.",
            |me| me.open_private_folder(),
        );
        self.button_row(
            &g,
            "system-search-symbolic",
            "Re-run detection",
            "Inspects the app again and updates SAM's recommendation. Your settings are kept; anything new is listed above.",
            |me| {
                me.simple(vec!["redetect".into(), me.app_id.clone()], "Detection finished");
            },
        );
        self.button_row(&g, "system-run-symbolic", "Diagnose missing resources", "Runs the app once under strace (if installed) and suggests fixes.", |me| {
            if let Some(app) = me.app() {
                app.toast(&tr("Starting a diagnostic run (closes after 30 s)…"));
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
                        app.toast(&tr("Bug report copied"));
                    }
                    Err(e) => app.report_error(&e),
                }
            });
        });
    }

    pub(super) fn run_setup_check(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            match app.backend.call(&["doctor", &me.app_id], None).await {
                Ok(r) => {
                    let bad = r
                        .get("checks")
                        .and_then(Value::as_array)
                        .map(|c| c.iter().filter(|x| matches!(util::str_of(x, "status"), "warn" | "fail" | "error")).count())
                        .unwrap_or(0);
                    app.toast(&if bad == 0 { "Setup check: everything is in order".to_string() } else { format!("Setup check: {bad} thing(s) to look at") });
                    *me.setup_report.borrow_mut() = Some(r);
                    me.reload();
                }
                Err(e) => app.report_error(&e),
            }
        });
    }

    pub(super) fn run_test_start(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        app.toast(&format!("Starting {} for {TEST_SECONDS} seconds…", util::plain(&self.name())));
        glib::spawn_future_local(async move {
            let secs = TEST_SECONDS.to_string();
            match app.backend.call(&["selftest", &me.app_id, "--seconds", &secs], None).await {
                Ok(r) => {
                    let first = r.get("results").and_then(Value::as_array).and_then(|a| a.first().cloned());
                    *me.test_result.borrow_mut() = first;
                    me.reload();
                    app.refresh_registered().await;
                }
                Err(e) => app.report_error(&e),
            }
        });
    }

    pub(super) fn render_details(self: &Rc<Self>, e: &Value) {
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

        let signature = match util::str_of(e, "signature.state") {
            "" => "Not checked".to_string(),
            _ => util::str_of(e, "signature.detail").to_string(),
        };
        self.add_dynamic(&g, &text_row("Signature", &signature));

        // Updates: the last check, and a button to check now.
        let checked = util::get(e, "update.checked_at").and_then(Value::as_i64).unwrap_or(0);
        let update = adw::ActionRow::builder()
            .title(tr("Updates"))
            .subtitle(esc(&if checked == 0 {
                "Not checked yet. Checking contacts the update source this AppImage names (GitHub or its own server).".to_string()
            } else {
                format!(
                    "{} (checked {})",
                    util::str_of(e, "update.detail"),
                    glib::DateTime::from_unix_local(checked).and_then(|d| d.format("%x %H:%M")).map(|s| s.to_string()).unwrap_or_default()
                )
            }))
            .build();
        update.add_css_class("property");
        let check = gtk::Button::builder()
            .label(tr("Check"))
            .valign(gtk::Align::Center)
            .tooltip_text(tr("Ask the update source whether a newer version is published"))
            .build();
        update.add_suffix(&check);
        self.add_dynamic(&g, &update);
        let w = Rc::downgrade(self);
        check.connect_clicked(move |b| {
            if let Some(me) = w.upgrade() {
                b.set_sensitive(false);
                me.simple(vec!["updates".into(), me.app_id.clone()], "Update check done");
            }
        });

        // Disk space, with "Free Space" for the unpacked copy.
        let space = adw::ActionRow::builder().title(tr("Disk space")).subtitle(tr("Checking…")).build();
        space.add_css_class("property");
        let free = gtk::Button::builder()
            .label(tr("Free Space"))
            .valign(gtk::Align::Center)
            .visible(false)
            .tooltip_text(tr("Delete the unpacked copy. Settings and files stay; the next start unpacks the AppImage again."))
            .build();
        space.add_suffix(&free);
        self.add_dynamic(&g, &space);
        let w = Rc::downgrade(self);
        free.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.simple(vec!["free-space".into(), me.app_id.clone()], "Space freed; the next start unpacks the AppImage again");
            }
        });
        if let Some(app) = self.app() {
            let id = self.app_id.clone();
            glib::spawn_future_local(async move {
                if let Ok(v) = app.backend.call(&["space", &id], None).await {
                    let Some(u) = v.get("apps").and_then(|a| a.get(0)) else { return };
                    let size = |k: &str| glib::format_size(util::get(u, k).and_then(Value::as_u64).unwrap_or(0)).to_string();
                    space.set_subtitle(&format!(
                        "{} in total: unpacked app {}, private home {}, logs {}",
                        size("total"),
                        size("unpacked"),
                        size("home"),
                        size("logs")
                    ));
                    free.set_visible(util::get(u, "can_free").and_then(Value::as_bool).unwrap_or(false));
                }
            });
        }
        self.add_dynamic(&g, &text_row("SHA-256", util::str_of(e, "source.sha256")));
    }

    pub(super) fn relocate(self: &Rc<Self>) {
        let Some(app) = self.app() else { return };
        let me = self.clone();
        glib::spawn_future_local(async move {
            let d = gtk::FileDialog::builder().title(tr("Locate the AppImage")).build();
            if let Ok(f) = d.open_future(Some(&app.window)).await {
                if let Some(p) = f.path() {
                    me.simple(vec!["relocate".into(), me.app_id.clone(), p.to_string_lossy().into_owned()], "Location updated");
                }
            }
        });
    }
}

/// File name of the version the last update replaced, if it is kept.
fn entry_backup_name(e: &Value) -> Option<String> {
    let f = util::str_of(e, "update_backup.original_path");
    (!f.is_empty()).then(|| util::plain(f.rsplit('/').next().unwrap_or(f)))
}
