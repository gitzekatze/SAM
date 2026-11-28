// SPDX-License-Identifier: GPL-3.0-or-later
//! Right column for one AppImage: a pinned header with the app and its main
//! button (Launch, or Create Sandbox), then every setting, always visible.
//! Without a sandbox yet, the settings are SAM's recommendation and can be
//! adjusted before the sandbox is created.

use crate::i18n::tr;
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use adw::prelude::*;
use gtk::{gio, glib};
use serde_json::Value;

use crate::perms::Editor;
use crate::util::{self, esc};
use crate::window::{self, App};

mod data;
mod render;
mod wiring;

/// How long "Test start" lets the app run.
const TEST_SECONDS: u64 = 8;

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
    /// The permission tags, the same as on the Permissions page.
    tags_box: gtk::Box,
    sandbox_badge: gtk::Label,
    main_button: gtk::Button,
    remove_button: gtk::Button,
    menu_button: gtk::MenuButton,
    /// While a sandbox is being created: step, bar and details.
    progress: CreationProgress,
    /// "<App> is running. Changed settings apply the next time it starts."
    running_banner: adw::Banner,
    /// The page checks every few seconds whether the app still runs.
    watching: std::cell::Cell<bool>,
    // Content.
    content: adw::PreferencesPage,
    editor: Rc<Editor>,
    notices: adw::PreferencesGroup,
    /// One place for advice: what went wrong, the repair switches, hints
    /// and the warning about unsandboxed menu entries.
    hints: adw::PreferencesGroup,
    files_row: adw::ActionRow,
    findings: adw::PreferencesGroup,
    /// "This AppImage can still be started without its sandbox …".
    dup_row: adw::ActionRow,
    preset_group: adw::PreferencesGroup,
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
    /// Results of "Check the setup" and "Test start" in this session.
    setup_report: RefCell<Option<Value>>,
    test_result: RefCell<Option<Value>>,
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
    /// The settings as last loaded or saved: each change is sent as the
    /// difference from these, so a change made elsewhere meanwhile stays
    /// (audit G-F4).
    saved: RefCell<Option<Value>>,
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
        let menu_button = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .tooltip_text(tr("More"))
            .build();
        header.pack_end(&menu_button);
        view.add_top_bar(&header);

        let hero = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(18)
            .margin_start(24)
            .margin_end(24)
            .margin_top(4)
            .margin_bottom(14)
            .build();
        hero.add_css_class("sam-hero");
        let icon_slot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        // Icon, title and buttons line up at the top.
        icon_slot.set_valign(gtk::Align::Start);
        hero.append(&icon_slot);
        let meta = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(4)
            .hexpand(true)
            .valign(gtk::Align::Start)
            .build();
        let title = gtk::Label::builder()
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .build();
        title.add_css_class("title-1");
        let subtitle = gtk::Label::builder()
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::Middle)
            .build();
        subtitle.add_css_class("caption");
        subtitle.add_css_class("dim-label");
        // Wraps onto a second line when the column is narrow.
        let badges = util::wrap_box(6, 6);
        badges.set_margin_top(4);
        let status_badge = util::badge("", "neutral");
        let state_badge = util::badge("", "warn");
        state_badge.set_visible(false);
        let sandbox_badge = util::badge("Bubblewrap", "blue");
        let check_badge = util::badge("", "good");
        badges.append(&status_badge);
        badges.append(&state_badge);
        badges.append(&sandbox_badge);
        badges.append(&check_badge);
        // The labels are not controls: none takes the keyboard focus.
        badges.set_can_focus(false);
        meta.append(&title);
        meta.append(&subtitle);
        meta.append(&badges);
        // What the app may access, in the words of the switches below.
        let tags_box = util::wrap_box(6, 6);
        tags_box.set_margin_top(2);
        meta.append(&tags_box);
        hero.append(&meta);
        // The trash button, Check and Launch (or Create Sandbox). The trash
        // button stays away from Launch, so it is not hit by mistake.
        let buttons = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .valign(gtk::Align::Start)
            .build();
        // Side by side; Check moves above Launch when the header is narrow
        // (the breakpoint below).
        let top_buttons = gtk::Box::builder()
            .spacing(8)
            .halign(gtk::Align::End)
            .build();
        let check_button = gtk::Button::builder()
            .child(&button_content("security-high-symbolic", &crate::i18n::tr("Test")))
            .tooltip_text(tr("Test the sandbox: confirm from inside that every setting applies, then start the app for a few seconds to see that it runs"))
            .name("check-button")
            .build();
        check_button.add_css_class("pill");
        let main_button = gtk::Button::builder().name("main-button").build();
        main_button.add_css_class("suggested-action");
        main_button.add_css_class("pill");
        let remove_button = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text(tr(
                "Remove the sandbox. SAM asks first; the AppImage file is kept.",
            ))
            .name("remove-button")
            .build();
        remove_button.add_css_class("sam-trash");
        // The trash button, Test and Launch have the same height.
        let same_height = gtk::SizeGroup::new(gtk::SizeGroupMode::Vertical);
        same_height.add_widget(&remove_button);
        same_height.add_widget(&check_button);
        same_height.add_widget(&main_button);
        top_buttons.append(&remove_button);
        top_buttons.append(&check_button);
        top_buttons.append(&main_button);
        buttons.append(&top_buttons);
        hero.append(&buttons);
        let hero_bin = adw::BreakpointBin::builder()
            .width_request(320)
            .height_request(96)
            .child(&hero)
            .build();
        let narrow = adw::Breakpoint::new(
            adw::BreakpointCondition::parse(&format!("max-width: {}px", HERO_SIDE_BY_SIDE))
                .expect("a fixed breakpoint condition parses"),
        );
        narrow.add_setter(
            &top_buttons,
            "orientation",
            Some(&gtk::Orientation::Vertical.to_value()),
        );
        narrow.add_setter(&top_buttons, "spacing", Some(&6.to_value()));
        hero_bin.add_breakpoint(narrow);
        view.add_top_bar(&util::natural_height::Bin::new(&hero_bin));
        let progress = CreationProgress::new();
        view.add_top_bar(&progress.panel);
        let running_banner = adw::Banner::new("");
        view.add_top_bar(&running_banner);

        // ---- settings
        let pref = adw::PreferencesPage::new();
        pref.add_css_class("sam-wide");
        let notices = adw::PreferencesGroup::new();
        let hints = adw::PreferencesGroup::builder()
            .title(tr("Advice"))
            .description(tr(
                "What can stop this app from working in its sandbox, and how to fix it. Fixes are switches: each says what protection it costs, and you can switch it off again.",
            ))
            .build();
        let dup_row = adw::ActionRow::builder()
            .title(tr("This AppImage can also start without its sandbox"))
            .visible(false)
            .build();
        dup_row.add_prefix(&gtk::Image::from_icon_name("dialog-warning-symbolic"));
        let dup_hide = gtk::Button::builder()
            .label(tr("Hide It"))
            .valign(gtk::Align::Center)
            .tooltip_text(tr(
                "Hide the other menu entries that start this AppImage without a sandbox",
            ))
            .build();
        dup_row.add_suffix(&dup_hide);
        hints.add(&dup_row);
        let findings = adw::PreferencesGroup::builder()
            .title(tr("What Went Wrong Last Time"))
            .build();
        let preset_group = adw::PreferencesGroup::builder()
            .title(tr("My Presets"))
            .description(tr("Save these settings under a name to use them for other apps. Apply and edit your presets from the main menu → My Presets."))
            .build();
        let save_preset_row = adw::EntryRow::builder()
            .title(tr("Name for the new preset"))
            .show_apply_button(true)
            .name("save-preset")
            .build();
        preset_group.add(&save_preset_row);
        pref.add(&notices);
        // What went wrong comes first: after a failed start it holds the fix
        // (and stays hidden otherwise).
        pref.add(&findings);
        pref.add(&hints);
        editor.add_to(&pref);

        // Launching: how SAM starts this app.
        let launch_group = adw::PreferencesGroup::builder()
            .title(tr("Launching"))
            .description(tr("How SAM starts this app."))
            .build();
        let (args_row, args_chips, args_entry, args_add) = chip_editor(
            &crate::i18n::tr("Launch arguments"),
            "Passed to the app every time it starts, e.g. --no-sandbox for Electron apps that cannot start their own sandbox.",
            "Argument, e.g. --disable-gpu",
        );
        // Where the app keeps what it saved outside the granted folders.
        let files_row = adw::ActionRow::builder()
            .title(tr("Files This App Saved"))
            .build();
        files_row.add_prefix(&gtk::Image::from_icon_name("folder-open-symbolic"));
        let files_open = gtk::Button::builder()
            .label(tr("Open"))
            .valign(gtk::Align::Center)
            .tooltip_text(tr("Open the app's private folder in the file manager"))
            .build();
        files_row.add_suffix(&files_open);
        launch_group.add(&files_row);
        launch_group.add(&args_row);
        let compat_row = adw::ActionRow::builder()
            .title(tr("Compatibility mode"))
            .build();
        let compat_badge = util::badge(&crate::i18n::tr("High risk"), "bad");
        compat_badge.set_visible(false);
        let compat_switch = gtk::Switch::builder()
            .valign(gtk::Align::Center)
            .name("compat-switch")
            .build();
        compat_row.add_suffix(&compat_badge);
        compat_row.add_suffix(&compat_switch);
        compat_row.set_activatable_widget(Some(&compat_switch));
        launch_group.add(&compat_row);
        pref.add(&launch_group);

        // Menu entries: SAM's own, and other tools' entries for this AppImage.
        let menu_group = adw::PreferencesGroup::builder()
            .title(tr("Menu Entries"))
            .description(tr("How this app appears in your application menu."))
            .build();
        let sam_menu_row = adw::ActionRow::builder()
            .title(tr("Menu entry from SAM"))
            .build();
        let sam_menu_switch = gtk::Switch::builder().valign(gtk::Align::Center).build();
        sam_menu_row.add_suffix(&sam_menu_switch);
        sam_menu_row.set_activatable_widget(Some(&sam_menu_switch));
        let hide_row = adw::ActionRow::builder()
            .title(tr("Hide other menu entries for this AppImage"))
            .build();
        let hide_switch = gtk::Switch::builder()
            .valign(gtk::Align::Center)
            .name("hide-switch")
            .build();
        hide_row.add_suffix(&hide_switch);
        hide_row.set_activatable_widget(Some(&hide_switch));
        menu_group.add(&sam_menu_row);
        menu_group.add(&hide_row);
        pref.add(&menu_group);
        // Saving a preset is for later: it comes after every setting, so a
        // first look at an app starts with what it may do.
        pref.add(&preset_group);

        // Sandbox check: start the sandbox with a probe and confirm every setting.
        let check_group = adw::PreferencesGroup::builder()
            .title(tr("Test"))
            .description(tr("Starts this app's sandbox with a test program instead of the app and confirms from inside that every setting really applies. Nothing is changed."))
            .build();
        let check_summary = adw::ActionRow::builder()
            .title(tr("Not checked yet"))
            .build();
        check_summary.add_prefix(&gtk::Image::from_icon_name("security-high-symbolic"));
        check_group.add(&check_summary);
        pref.add(&check_group);

        let trouble = adw::PreferencesGroup::builder()
            .title(tr("Troubleshooting"))
            .description(tr(
                "When the app does not start or does not work as expected.",
            ))
            .build();
        let details = adw::PreferencesGroup::builder()
            .title(tr("Details"))
            .build();
        let command_group = adw::PreferencesGroup::builder()
            .title(tr("Sandbox Command"))
            .description(tr("The Bubblewrap command SAM runs for this app."))
            .build();
        let command_view = mono_view();
        command_group.add(&framed(&command_view, 120));
        let copy_cmd = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text(tr("Copy"))
            .valign(gtk::Align::Center)
            .build();
        copy_cmd.add_css_class("flat");
        command_group.set_header_suffix(Some(&copy_cmd));
        let log_group = adw::PreferencesGroup::builder()
            .title(tr("Logs"))
            .description(tr("Unpacking, detection and start logs."))
            .build();
        let log_view = mono_view();
        log_group.add(&framed(&log_view, 260));
        let log_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        let refresh_log = gtk::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text(tr("Refresh"))
            .valign(gtk::Align::Center)
            .build();
        let copy_log = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text(tr("Copy"))
            .valign(gtk::Align::Center)
            .build();
        refresh_log.add_css_class("flat");
        copy_log.add_css_class("flat");
        let log_drop = gtk::DropDown::from_strings(&[crate::i18n::tr("No logs yet").as_str()]);
        log_drop.set_valign(gtk::Align::Center);
        log_drop.set_widget_name("log-picker");
        log_drop.set_tooltip_text(Some(&crate::i18n::tr("Which log to show")));
        log_buttons.append(&log_drop);
        log_buttons.append(&refresh_log);
        log_buttons.append(&copy_log);
        log_group.set_header_suffix(Some(&log_buttons));
        pref.add(&trouble);
        pref.add(&details);
        pref.add(&command_group);
        pref.add(&log_group);
        view.set_content(Some(&pref));

        let page = adw::NavigationPage::builder()
            .title(tr("App"))
            .child(&view)
            .build();
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
            tags_box,
            sandbox_badge,
            main_button,
            remove_button,
            menu_button,
            progress,
            running_banner,
            watching: std::cell::Cell::new(false),
            content: pref.clone(),
            editor,
            notices,
            hints,
            findings,
            dup_row,
            preset_group,
            save_preset_row,
            presets: RefCell::new(Vec::new()),
            check_group,
            check_summary,
            check_button,
            check_badge,
            check_rows: RefCell::new(Vec::new()),
            check_report: RefCell::new(None),
            check_settings: RefCell::new(None),
            setup_report: RefCell::new(None),
            test_result: RefCell::new(None),
            launch_group,
            files_row,
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
            saved: RefCell::new(None),
            dynamic_rows: RefCell::new(Vec::new()),
            updating: Cell::new(false),
        });
        for (btn, view) in [(&copy_cmd, &me.command_view), (&copy_log, &me.log_view)] {
            let (w, view) = (Rc::downgrade(&me), view.clone());
            btn.connect_clicked(move |_| {
                let Some(app) = w.upgrade().and_then(|m| m.app()) else {
                    return;
                };
                let b = view.buffer();
                app.window
                    .clipboard()
                    .set_text(&b.text(&b.start_iter(), &b.end_iter(), false));
                app.toast(&tr("Copied"));
            });
        }
        let w = Rc::downgrade(&me);
        refresh_log.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                glib::spawn_future_local(async move { me.load_log_list().await });
            }
        });
        me.wire();
        let w = Rc::downgrade(&me);
        files_open.connect_clicked(move |_| {
            if let Some(me) = w.upgrade() {
                me.open_private_folder();
            }
        });
        let w = Rc::downgrade(&me);
        dup_hide.connect_clicked(move |_| {
            let Some(me) = w.upgrade() else { return };
            let Some(app) = me.app() else { return };
            glib::spawn_future_local(async move {
                match app.backend.call(&["menu", "hide", &me.app_id], None).await {
                    Ok(_) => app.toast(&tr(
                        "The other menu entries are hidden; the app now starts only in its sandbox",
                    )),
                    Err(e) => app.report_error(&e),
                }
                me.reload();
            });
        });
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
        self.info
            .borrow()
            .as_ref()
            .and_then(|i| i.get("entry").cloned())
    }

    fn found(&self) -> Option<Value> {
        let app = self.app()?;
        let path = if self.sandboxed() {
            self.entry()
                .map(|e| util::str_of(&e, "source_path").to_string())
                .unwrap_or_default()
        } else {
            self.path.clone()
        };
        let st = app.state.borrow();
        st.discovered
            .iter()
            .find(|d| util::str_of(d, "path") == path)
            .cloned()
    }

    fn name(&self) -> String {
        if self.sandboxed() {
            self.info
                .borrow()
                .as_ref()
                .map(|i| util::str_of(i, "app.name").to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| self.app_id.clone())
        } else {
            self.found()
                .map(|f| util::str_of(&f, "name").to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| self.path.rsplit('/').next().unwrap_or("").to_string())
        }
    }

    fn perms(&self) -> Option<Value> {
        if self.sandboxed() {
            self.entry()
                .and_then(|e| util::get(&e, "profile.permissions").cloned())
        } else {
            self.pending.borrow().clone()
        }
    }
}

/// A list editor row: title, description, chips, and an add field.
fn chip_editor(
    title: &str,
    description: &str,
    placeholder: &str,
) -> (gtk::ListBoxRow, gtk::FlowBox, gtk::Entry, gtk::Button) {
    let row = gtk::ListBoxRow::builder()
        .activatable(false)
        .selectable(false)
        .build();
    let vbox = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(6)
        .margin_top(10)
        .margin_bottom(10)
        .margin_start(12)
        .margin_end(12)
        .build();
    let t = gtk::Label::builder()
        .label(title)
        .xalign(0.0)
        .wrap(true)
        .build();
    let d = gtk::Label::builder()
        .label(description)
        .xalign(0.0)
        .wrap(true)
        .build();
    d.add_css_class("dim-label");
    d.add_css_class("caption");
    vbox.append(&t);
    vbox.append(&d);
    let chips = gtk::FlowBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .column_spacing(6)
        .row_spacing(6)
        .max_children_per_line(30)
        .build();
    vbox.append(&chips);
    let add_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let entry = gtk::Entry::builder()
        .placeholder_text(placeholder)
        .hexpand(true)
        .name("args-entry")
        .build();
    let add = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text(tr("Add"))
        .valign(gtk::Align::Center)
        .build();
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
}

fn button_content(icon: &str, label: &str) -> adw::ButtonContent {
    adw::ButtonContent::builder()
        .icon_name(icon)
        .label(label)
        .build()
}

fn status_icon(name: &str, class: &str) -> gtk::Image {
    let i = gtk::Image::from_icon_name(name);
    i.add_css_class(class);
    i
}

fn mono_view() -> gtk::TextView {
    let v = gtk::TextView::builder()
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::Char)
        .top_margin(10)
        .bottom_margin(10)
        .left_margin(12)
        .right_margin(12)
        .build();
    v.add_css_class("sam-mono");
    v
}

/// Monospace text that wraps anywhere without inserting hyphens.
fn set_mono_text(v: &gtk::TextView, text: &str) {
    let b = v.buffer();
    b.set_text(text);
    let tag = b.tag_table().lookup("nohyphen").unwrap_or_else(|| {
        let t = gtk::TextTag::builder()
            .name("nohyphen")
            .insert_hyphens(false)
            .build();
        b.tag_table().add(&t);
        t
    });
    b.apply_tag(&tag, &b.start_iter(), &b.end_iter());
}

fn framed(v: &gtk::TextView, height: i32) -> gtk::Widget {
    let s = gtk::ScrolledWindow::builder()
        .child(v)
        .min_content_height(height)
        .max_content_height(height)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    s.add_css_class("card");
    s.set_overflow(gtk::Overflow::Hidden);
    s.upcast()
}

/// The question "Confirm Settings" asks before an app whose record (or
/// AppImage file) changed outside SAM may start again, and whether the
/// settings hold anything rated Think twice or Dangerous. SAM can tell
/// that something changed, not what: so the question names what the
/// settings let the app do (audit G-F12/13: one click confirmed them,
/// without showing anything).
fn confirm_outside_text(perms: Option<&Value>, file: bool) -> (String, bool) {
    let mut body = if file {
        crate::i18n::tr("The AppImage file was replaced by something other than a SAM update. Confirm only if you replaced it yourself or know who did.")
    } else {
        crate::i18n::tr("Something other than SAM changed these settings. SAM can tell that they changed, not what changed. Confirm only if you made the change yourself or know who did.")
    };
    body.push_str("\n\n");
    let parsed = perms.and_then(|p| {
        serde_json::from_value::<sam_core::permissions::PermissionSet>(p.clone()).ok()
    });
    let Some(p) = parsed else {
        body.push_str(&crate::i18n::tr(
            "SAM cannot read these settings. Look through them below before you confirm.",
        ));
        return (body, true);
    };
    let mut lines: Vec<String> = Vec::new();
    for i in sam_core::risk::assess(&p).items {
        if i.level >= sam_core::risk::RiskLevel::High {
            let line = format!("• {} ({})", i.title, i.level.words());
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    if lines.is_empty() {
        body.push_str(&crate::i18n::tr(
            "None of these settings is rated Think twice or Dangerous.",
        ));
        (body, false)
    } else {
        body.push_str(&crate::i18n::tr("These settings let the app use:"));
        body.push('\n');
        body.push_str(&lines.join("\n"));
        (body, true)
    }
}

/// The note of an update's needs, for the question of "Confirm Settings":
/// the page hides that note while settings changed outside SAM wait for
/// a look, but confirming accepts it too, so the question names it (review
/// L4: no button confirms a notice its page never showed). None without
/// such a note.
fn pending_note(pending: &[String]) -> Option<String> {
    (!pending.is_empty()).then(|| {
        crate::i18n::trf(
            "Confirming also accepts the note about the updated AppImage, which likely needs: {needs}.",
            &[("needs", &pending.join(", "))],
        )
    })
}

/// The protection layers the app's last start lacked although its
/// settings ask for them (an older kernel, or SAM's helper not found).
fn missing_layers(entry: Option<&Value>) -> Vec<String> {
    entry
        .and_then(|e| util::get(e, "last_launch.missing_layers"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// The status badge in the page's header: text, tone and explanation. The
/// green "Sandboxed" only while the last start had every layer the
/// settings ask for (audit G-F15: it stayed green while the list said
/// "Protection missing").
fn status_label(sandboxed: bool, missing: &[String]) -> (String, &'static str, String) {
    if !sandboxed {
        (
            crate::i18n::tr("Not sandboxed"),
            "neutral",
            crate::i18n::tr("No sandbox yet. Nothing has been unpacked or run; below are the settings SAM recommends"),
        )
    } else if !missing.is_empty() {
        (
            crate::i18n::tr("Sandboxed"),
            "warn",
            crate::i18n::trf(
                "SAM runs this app in its sandbox, but its last start lacked {layers}, which its settings ask for",
                &[("layers", &missing.join(", "))],
            ),
        )
    } else {
        (
            crate::i18n::tr("Sandboxed"),
            "good",
            crate::i18n::tr(
                "SAM runs this app in its sandbox, with exactly the access listed below",
            ),
        )
    }
}

/// "May not start": what SAM's analysis found, in words, for the header label.
fn compat_risk_label(entry: Option<&Value>) -> (String, &'static str, String) {
    let det = entry
        .and_then(|e| e.get("detection"))
        .cloned()
        .unwrap_or_default();
    let likely_broken = util::str_of(&det, "compatibility") == "likely-broken";
    // The warnings that set the label (not notices about optional features).
    let found: Vec<String> = det
        .get("warnings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|w| {
            util::str_of(w, "severity") != "info"
                && !util::str_of(w, "code").starts_with("feature-")
        })
        .map(|w| util::str_of(w, "message").to_string())
        .collect();
    let mut tip = if found.is_empty() {
        crate::i18n::tr("SAM's analysis found possible problems.")
    } else {
        found.join(" ")
    };
    tip.push(' ');
    tip.push_str(&crate::i18n::tr(
        "Just launch it: if it starts, this label goes away. If not, see Troubleshooting below.",
    ));
    if likely_broken {
        (crate::i18n::tr("Likely won't start"), "bad", tip)
    } else {
        (crate::i18n::tr("May not start"), "warn", tip)
    }
}

/// The panel under the header while a sandbox is being created: which step
/// runs, a bar for the whole operation, and what the step is doing.
pub(super) struct CreationProgress {
    pub panel: gtk::Box,
    step: gtk::Label,
    bar: gtk::ProgressBar,
    detail: gtk::Label,
}

impl CreationProgress {
    fn new() -> Self {
        let panel = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .margin_start(24)
            .margin_end(24)
            .margin_top(6)
            .margin_bottom(12)
            .visible(false)
            .name("creation-progress")
            .build();
        let step = gtk::Label::builder().xalign(0.0).wrap(true).build();
        step.add_css_class("heading");
        let bar = gtk::ProgressBar::builder().show_text(true).build();
        bar.update_property(&[gtk::accessible::Property::Label(&tr(
            "Creating the sandbox",
        ))]);
        let detail = gtk::Label::builder().xalign(0.0).wrap(true).build();
        detail.add_css_class("dim-label");
        let note = gtk::Label::builder()
            .label(tr("Large apps take a minute or two. You can keep using SAM meanwhile; you will see a message when it is done."))
            .xalign(0.0)
            .wrap(true)
            .build();
        note.add_css_class("dim-label");
        note.add_css_class("caption");
        panel.append(&step);
        panel.append(&bar);
        panel.append(&detail);
        panel.append(&note);
        CreationProgress {
            panel,
            step,
            bar,
            detail,
        }
    }

    /// Shows the panel at the start.
    pub fn start(&self) {
        self.step.set_label(&tr("Creating the sandbox…"));
        self.bar.set_fraction(0.0);
        self.bar.set_text(Some("0 %"));
        self.detail.set_label("");
        self.panel.set_visible(true);
    }

    /// One `{"step", "steps", "title", "detail", "fraction"}` report.
    pub fn update(&self, p: &Value) {
        let n = p.get("step").and_then(Value::as_u64).unwrap_or(0);
        let total = p.get("steps").and_then(Value::as_u64).unwrap_or(0);
        let fraction = p
            .get("fraction")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        self.step.set_label(&crate::i18n::trf(
            "Step {n} of {total}: {step}",
            &[
                ("n", &n),
                ("total", &total),
                ("step", &tr(util::str_of(p, "title"))),
            ],
        ));
        self.bar.set_fraction(fraction);
        self.bar
            .set_text(Some(&format!("{:.0} %", fraction * 100.0)));
        self.detail.set_label(util::str_of(p, "detail"));
    }

    pub fn finish(&self) {
        self.panel.set_visible(false);
    }
}

/// A check's results hold a note SAM adds ([`sam_core::CHECK_NOTE_IDS`]),
/// such as the incomplete socket limit of a 32-bit app: then a passed check
/// does not mean that every setting applies in full.
fn check_has_note(results: &[Value]) -> bool {
    results
        .iter()
        .any(|r| sam_core::CHECK_NOTE_IDS.contains(&util::str_of(r, "id")))
}

/// What a passed check says: its title, the subtitle under it and the
/// tooltip of its badge. `when` is the time of a stored test; `None` is a
/// check of an AppImage without a sandbox, which is not stored. `noted`:
/// the check holds a note SAM adds, so no text says that every setting
/// applies in full.
fn passed_check_texts(total: u64, when: Option<&str>, noted: bool) -> (String, String, String) {
    use crate::i18n::{trf, trn};
    match (when, noted) {
        (Some(when), false) => (
            trn("The setting applies", "All {n} settings apply", total, &[]),
            trf("Tested {when}.", &[("when", &when)]),
            tr("The test confirmed that every setting applies; see Test below"),
        ),
        (Some(when), true) => (
            trn(
                "The setting applies, with a note",
                "All {n} settings apply, with a note",
                total,
                &[],
            ),
            trf(
                "Tested {when}. Every setting applies, except where a note of the test says otherwise.",
                &[("when", &when)],
            ),
            tr("The test confirmed every setting, except where a note says otherwise; see Test below"),
        ),
        (None, false) => (
            trn("The check passed", "All {n} checks passed", total, &[]),
            tr("Every setting below applies. Not stored: the sandbox does not exist yet."),
            tr("The sandbox check confirmed that every setting applies; see Sandbox Check below"),
        ),
        (None, true) => (
            trn("The check passed", "All {n} checks passed", total, &[]),
            tr("Every setting below applies, except where a note below says otherwise. Not stored: the sandbox does not exist yet."),
            tr("The sandbox check confirmed every setting, except where a note says otherwise; see Sandbox Check below"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    /// A passed check with a note SAM adds never says, in its title,
    /// subtitle or badge tooltip, that every setting applies in full; one
    /// without a note does, both for a stored test and for a check of an
    /// AppImage without a sandbox.
    #[test]
    fn a_passed_check_with_a_note_says_so_in_every_text() {
        for when in [Some("today"), None] {
            let (title, subtitle, tooltip) = super::passed_check_texts(20, when, true);
            let plain = super::passed_check_texts(20, when, false);
            for t in [&subtitle, &tooltip] {
                assert!(t.contains("except where a note"), "{when:?}: {t}");
            }
            for t in [&plain.1, &plain.2] {
                assert!(!t.contains("note"), "{when:?}: {t}");
            }
            assert!(plain.2.contains("every setting applies"), "{}", plain.2);
            if when.is_some() {
                assert_eq!(title, "All 20 settings apply, with a note");
                assert_eq!(plain.0, "All 20 settings apply");
                assert!(subtitle.contains("today") && plain.1.contains("today"));
            } else {
                assert!(subtitle.contains("Not stored") && plain.1.contains("Not stored"));
            }
        }
    }

    /// The window qualifies "every setting applies" exactly when the check
    /// holds a note SAM adds, not for a check that could not run.
    #[test]
    fn a_passed_check_with_a_note_is_not_called_complete() {
        let passed = json!({"id": "userns", "ok": true});
        let not_here = json!({"id": "webcam", "ok": null});
        let note = json!({"id": "seccomp-32-bit-sockets", "ok": null});
        assert!(!super::check_has_note(&[passed.clone(), not_here.clone()]));
        assert!(super::check_has_note(&[passed, note, not_here]));
    }

    /// "Confirm Settings" names the note of an update's needs, which the
    /// page hides meanwhile but confirming accepts (review L4).
    #[test]
    fn the_question_names_the_update_note_that_confirming_accepts() {
        assert_eq!(super::pending_note(&[]), None);
        let note = super::pending_note(&["sound".into(), "webcam".into()]).unwrap();
        assert!(note.contains("sound, webcam"), "{note}");
    }

    /// The arguments of a review always carry what the page showed, so
    /// SAM can refuse it when the app changed since (review L4).
    #[test]
    fn a_review_from_the_page_names_what_it_showed() {
        assert_eq!(
            super::data::review_args("app-1a2b", "f00d"),
            ["review", "app-1a2b", "--seen", "f00d"]
        );
    }

    /// The window confirms a hint for the command line with --yes exactly
    /// when it has asked: a hint rated Think twice or Dangerous, or one
    /// that turns on compatibility mode, but not a Medium one (owner
    /// decision 13 of 2026-11-23: `hints --apply` refuses a risky hint
    /// without --yes).
    #[test]
    fn the_window_confirms_a_hint_exactly_when_it_asked() {
        use super::data::{apply_args, asks_first};
        let hint =
            |risk: &str, kind: &str| json!({"id": "h", "risk": risk, "action": {"kind": kind}});
        assert!(asks_first(&hint("high", "set")));
        assert!(asks_first(&hint("dangerous", "set")));
        assert!(asks_first(&hint("medium", "compat")));
        assert!(!asks_first(&hint("medium", "set")));
        assert!(!asks_first(&hint("low", "add-arg")));
        for (risk, kind) in [("high", "set"), ("medium", "set"), ("medium", "compat")] {
            let asked = asks_first(&hint(risk, kind));
            let args = apply_args("app-1", "h", false, asked);
            assert_eq!(&args[..4], ["hints", "app-1", "--apply", "h"]);
            assert_eq!(
                args.iter().any(|a| a == "--yes"),
                asked,
                "{risk} {kind}: {args:?}"
            );
        }
        // A refusal for a rating the page did not show yet: a short
        // notice, then the page is drawn again; other errors as before.
        use crate::backend::CliError;
        let stale = super::data::stale_rating_notice(&CliError::coded("hint-needs-yes", "x"));
        assert!(stale.is_some_and(|t| !t.contains("--yes")));
        assert!(
            super::data::stale_rating_notice(&CliError::coded("change-needs-yes", "x")).is_none()
        );
    }

    /// The window confirms a repair step for the command line with --yes
    /// exactly when it has asked, as it does for a hint: a step rated
    /// Think twice or Dangerous, one that turns on compatibility mode, or
    /// one from the app's own output. A step it did not ask about goes
    /// without --yes, so where SAM now rates it higher than the page showed
    /// (review of PR #149: the window passed --yes for every repair step),
    /// the command line refuses it and the window draws the page again
    /// with a short notice instead of applying it unasked.
    #[test]
    fn the_window_confirms_a_repair_step_exactly_when_it_asked() {
        use super::data::{apply_args, stale_rating_notice, window_asks};
        use crate::backend::CliError;
        let step = |risk: &str, kind: &str, from_app: bool| json!({"id": "s", "risk": risk, "action": {"kind": kind}, "from_app_output": from_app});
        for (risk, kind, from_app, expect) in [
            ("high", "set", false, true),
            ("dangerous", "set", false, true),
            ("medium", "compat", false, true),
            ("medium", "set", false, false),
            ("low", "set", false, false),
            // From the app's own output: always asked, and so confirmed,
            // whatever its rating (regression #69: the command line
            // refuses it without --yes, and the window would be stuck).
            ("low", "set", true, true),
            ("medium", "set", true, true),
        ] {
            let asked = window_asks(&step(risk, kind, from_app));
            assert_eq!(asked, expect, "{risk} {kind} from app {from_app}");
            let args = apply_args("app-1", "s", true, asked);
            assert_eq!(&args[..4], ["repair", "app-1", "--apply", "s"]);
            assert_eq!(
                args.iter().any(|a| a == "--yes"),
                expect,
                "{risk} {kind} from app {from_app}: {args:?}"
            );
        }
        // Not asked: no --yes, whatever step it is.
        assert_eq!(
            apply_args("app-1", "x11", true, false),
            ["repair", "app-1", "--apply", "x11"]
        );
        assert_eq!(
            apply_args("app-1", "x11", true, true),
            ["repair", "app-1", "--apply", "x11", "--yes"]
        );
        // The command line's refusal of a step the window did not ask
        // about becomes the short notice, never advice to add --yes.
        for code in ["step-needs-yes", "repair-needs-yes"] {
            let notice = stale_rating_notice(&CliError::coded(code, "x"));
            assert!(notice.is_some_and(|t| !t.contains("--yes")), "{code}");
        }
    }

    /// "Confirm Settings" names what the changed settings let the app do
    /// before it may start again: full home and X11 written into the record
    /// from outside appear in the question (audit G-F12/13: one click
    /// confirmed them unseen).
    #[test]
    fn confirming_changed_settings_names_what_they_allow() {
        use sam_core::permissions::PermissionSet;
        let mut p = PermissionSet::default();
        let (calm, risky) =
            super::confirm_outside_text(Some(&serde_json::to_value(&p).unwrap()), false);
        assert!(!risky, "{calm}");
        assert!(calm.contains("not what changed"), "{calm}");
        p.set_key("filesystem.home", "true").unwrap();
        p.set_key("filesystem.home_access", "rw").unwrap();
        p.set_key("display.x11", "true").unwrap();
        let (body, risky) =
            super::confirm_outside_text(Some(&serde_json::to_value(&p).unwrap()), false);
        assert!(risky);
        assert!(body.contains("X11"), "{body}");
        assert!(body.contains("Dangerous"), "{body}");
        let (file, _) = super::confirm_outside_text(Some(&serde_json::to_value(&p).unwrap()), true);
        assert!(file.contains("AppImage file was replaced"), "{file}");
        // Settings it cannot read are never called harmless.
        assert!(super::confirm_outside_text(Some(&json!({"filesystem": 3})), false).1);
        assert!(super::confirm_outside_text(None, false).1);
    }

    /// The header's "Sandboxed" is green only while the last start had
    /// every protection layer; with one missing it is amber and names the
    /// layer (audit G-F15: it stayed green).
    #[test]
    fn the_header_is_not_green_while_a_protection_layer_was_missing() {
        let full = json!({"last_launch": {"missing_layers": []}});
        let lacking = json!({"last_launch": {"missing_layers": ["Landlock"]}});
        let tone = |e: &serde_json::Value| {
            let m = super::missing_layers(Some(e));
            super::status_label(true, &m)
        };
        assert_eq!(tone(&full).1, "good");
        assert_eq!(tone(&json!({})).1, "good");
        let (_, t, tip) = tone(&lacking);
        assert_eq!(t, "warn");
        assert!(tip.contains("Landlock"), "{tip}");
        assert_eq!(super::status_label(false, &[]).1, "neutral");
    }
}
