// SPDX-License-Identifier: GPL-3.0-or-later
//! Flatseal-style permission editor, shared by the app page and the preset
//! editor. Every setting is always visible; settings that do not apply right
//! now are insensitive (greyed out), never hidden. Changes go to `on_edit`;
//! the owner saves them and feeds back `set_data`.

use crate::i18n::tr;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;
use serde_json::{json, Value};

use crate::util::{self, esc};

/// Permission catalog entry from `sam-jail permissions`.
#[derive(Clone, Default)]
pub struct Info {
    pub title: String,
    pub description: String,
    pub risk: String,
}

pub type Catalog = Rc<HashMap<String, Info>>;

pub fn parse_catalog(v: &Value) -> HashMap<String, Info> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| {
                    Some((
                        p.get("key")?.as_str()?.to_string(),
                        Info {
                            title: util::str_of(p, "title").to_string(),
                            description: util::str_of(p, "description").to_string(),
                            risk: util::str_of(p, "risk").to_string(),
                        },
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Clone, Copy, PartialEq)]
enum Avail {
    Always,
    LocalNet,
    FullHome,
    FilteredBus,
    AnyBus,
    NotAllInput,
}

#[derive(Clone)]
struct Opt {
    value: Value,
    /// In the user's language.
    text: String,
    description: String,
}

/// An option of a drop-down, translated here.
fn opt(value: Value, text: &str, description: &str) -> Opt {
    Opt {
        value,
        text: crate::i18n::tr(text),
        description: crate::i18n::tr(description),
    }
}

enum Ctl {
    Switch {
        key: &'static str,
        row: adw::ActionRow,
        sw: gtk::Switch,
        badge: gtk::Label,
        avail: Avail,
    },
    Choice {
        key: &'static str,
        row: adw::ActionRow,
        drop: gtk::DropDown,
        opts: Vec<Opt>,
        badge: gtk::Label,
        avail: Avail,
    },
    List {
        key: &'static str,
        row: gtk::ListBoxRow,
        title: gtk::Label,
        subtitle: gtk::Label,
        chips: gtk::FlowBox,
        badge: gtk::Label,
        avail: Avail,
        folders: bool,
        map: bool,
    },
}

pub struct Editor {
    catalog: Catalog,
    window: adw::ApplicationWindow,
    perms: RefCell<Option<Value>>,
    recommended: RefCell<Option<Value>>,
    evaluation: RefCell<Option<Value>>,
    updating: Cell<bool>,
    on_edit: RefCell<Option<Box<dyn Fn(Value)>>>,
    ctls: RefCell<Vec<Ctl>>,
    overview: adw::PreferencesGroup,
    risk_row: adw::ActionRow,
    risk_badge: gtk::Label,
    warning_rows: RefCell<Vec<gtk::Widget>>,
    groups: RefCell<Vec<adw::PreferencesGroup>>,
}

impl Editor {
    pub fn new(catalog: Catalog, window: &adw::ApplicationWindow) -> Rc<Editor> {
        let overview = adw::PreferencesGroup::builder()
            .title(tr("Overview"))
            .description(tr("How much this app can reach with the settings below."))
            .build();
        let risk_row = adw::ActionRow::builder()
            .title(tr("Risk of these settings"))
            .build();
        let risk_badge = util::badge("", "neutral");
        risk_row.add_suffix(&risk_badge);
        overview.add(&risk_row);
        let ed = Rc::new(Editor {
            catalog,
            window: window.clone(),
            perms: RefCell::new(None),
            recommended: RefCell::new(None),
            evaluation: RefCell::new(None),
            updating: Cell::new(false),
            on_edit: RefCell::new(None),
            ctls: RefCell::new(Vec::new()),
            overview,
            risk_row,
            risk_badge,
            warning_rows: RefCell::new(Vec::new()),
            groups: RefCell::new(Vec::new()),
        });
        ed.build();
        ed
    }

    /// Adds the overview and permission groups to `page`, in order.
    pub fn add_to(&self, page: &adw::PreferencesPage) {
        page.add(&self.overview);
        for g in self.groups.borrow().iter() {
            page.add(g);
        }
    }

    pub fn connect_edited(&self, f: impl Fn(Value) + 'static) {
        *self.on_edit.borrow_mut() = Some(Box::new(f));
    }

    pub fn set_data(
        self: &Rc<Self>,
        perms: Option<Value>,
        recommended: Option<Value>,
        evaluation: Option<Value>,
    ) {
        *self.perms.borrow_mut() = perms;
        *self.recommended.borrow_mut() = recommended;
        *self.evaluation.borrow_mut() = evaluation;
        self.refresh();
    }

    pub fn set_evaluation(&self, evaluation: Option<Value>) {
        *self.evaluation.borrow_mut() = evaluation;
        self.refresh_overview();
    }

    // ------------------------------------------------------------ helpers

    fn value(&self, key: &str) -> Value {
        self.perms
            .borrow()
            .as_ref()
            .and_then(|p| util::get(p, key).cloned())
            .unwrap_or(Value::Null)
    }
    fn info(&self, key: &str) -> Info {
        if key == "environment.set" {
            return Info {
                title: crate::i18n::tr("Environment variables"),
                description: crate::i18n::tr(
                    "Variables set inside the sandbox, as NAME=value, for example QT_SCALE_FACTOR=1.5. They override variables passed through.",
                ),
                risk: "medium".into(),
            };
        }
        self.catalog.get(key).cloned().unwrap_or(Info {
            title: key.into(),
            ..Default::default()
        })
    }
    fn full_home(&self) -> bool {
        self.value("filesystem.home") == json!(true)
    }
    fn available(&self, a: Avail) -> bool {
        match a {
            Avail::Always => true,
            Avail::LocalNet => self.value("network.mode") == json!("localhost"),
            Avail::FullHome => self.full_home(),
            Avail::FilteredBus => self.value("dbus.session.mode") == json!("filtered"),
            Avail::AnyBus => self.value("dbus.session.mode") != json!("none"),
            Avail::NotAllInput => self.value("devices.input") != json!(true),
        }
    }

    /// Risk shown as a badge next to a setting: only while it is in use and
    /// its risk is high or dangerous, so the list stays calm.
    fn active_risk(&self, key: &str) -> String {
        let v = self.value(key);
        let risky: &[&str] = match key {
            "network.mode" | "dbus.session.mode" | "dbus.system.mode" => &["full"],
            "filesystem.home_access" => &["rw"],
            _ => &[],
        };
        let mut on = if !risky.is_empty() {
            v.as_str().is_some_and(|s| risky.contains(&s))
        } else {
            v == json!(true)
                || v.as_str()
                    .is_some_and(|s| !["none", "minimal", "ro"].contains(&s))
                || v.as_array().is_some_and(|a| !a.is_empty())
        };
        if matches!(
            key,
            "filesystem.home_access"
                | "filesystem.ssh"
                | "filesystem.gnupg"
                | "filesystem.hidden_files"
        ) {
            on = on && self.full_home();
        }
        let r = self.info(key).risk;
        if on && (r == "high" || r == "dangerous") {
            r
        } else {
            String::new()
        }
    }

    fn value_label(v: &Value) -> String {
        match v {
            Value::Bool(true) => crate::i18n::tr("on"),
            Value::Bool(false) => crate::i18n::tr("off"),
            Value::String(s) => match s.as_str() {
                "none" => crate::i18n::tr("none"),
                "ro" => crate::i18n::tr("read-only"),
                "rw" => crate::i18n::tr("read & write"),
                "full" => crate::i18n::tr("full"),
                "localhost" => crate::i18n::tr("this computer only"),
                "filtered" => crate::i18n::tr("filtered"),
                "minimal" => crate::i18n::tr("minimal"),
                o => o.to_string(),
            },
            Value::Null => crate::i18n::tr("default"),
            o => o.to_string(),
        }
    }

    /// Grey subtitle (markup): the description, plus SAM's recommendation
    /// when the current value differs from it.
    fn describe(&self, key: &str, text: &str) -> String {
        let mut s = esc(&util::explain(key, text));
        if let Some(rec) = self.recommended.borrow().as_ref() {
            if let Some(rv) = util::get(rec, key) {
                if !rv.is_object() && !rv.is_array() && *rv != self.value(key) {
                    s.push_str(&format!(
                        "\n<i>SAM recommends: {}</i>",
                        esc(&Self::value_label(rv))
                    ));
                }
            }
        }
        s
    }

    // ------------------------------------------------------------ building

    fn group(&self, title: &str, description: &str) -> adw::PreferencesGroup {
        let g = adw::PreferencesGroup::builder()
            .title(title)
            .description(description)
            .build();
        self.groups.borrow_mut().push(g.clone());
        g
    }

    fn switch(self: &Rc<Self>, g: &adw::PreferencesGroup, key: &'static str, avail: Avail) {
        let row = adw::ActionRow::builder()
            .title(esc(&self.info(key).title))
            .build();
        let badge = util::badge("", "bad");
        badge.set_visible(false);
        let sw = gtk::Switch::builder()
            .valign(gtk::Align::Center)
            .name(format!("perm:{key}"))
            .build();
        row.add_suffix(&badge);
        row.add_suffix(&sw);
        row.set_activatable_widget(Some(&sw));
        let me = Rc::downgrade(self);
        sw.connect_active_notify(move |s| {
            if let Some(me) = me.upgrade() {
                if !me.updating.get() {
                    me.request(key, Value::Bool(s.is_active()));
                }
            }
        });
        g.add(&row);
        self.ctls.borrow_mut().push(Ctl::Switch {
            key,
            row,
            sw,
            badge,
            avail,
        });
    }

    fn choice(
        self: &Rc<Self>,
        g: &adw::PreferencesGroup,
        key: &'static str,
        opts: Vec<Opt>,
        avail: Avail,
    ) {
        // A drop-down keeps its full width; the description wraps instead
        // (a combo row would shorten the selected value to "…").
        let labels: Vec<&str> = opts.iter().map(|o| o.text.as_str()).collect();
        let row = adw::ActionRow::builder()
            .title(esc(&self.info(key).title))
            .build();
        let badge = util::badge("", "bad");
        badge.set_visible(false);
        row.add_suffix(&badge);
        let drop = gtk::DropDown::from_strings(&labels);
        drop.set_valign(gtk::Align::Center);
        drop.set_widget_name(&format!("perm:{key}"));
        drop.add_css_class("flat");
        // GTK names a drop-down after its value ("No access") through a
        // "labelled by" relation; a screen reader should hear the setting.
        drop.reset_relation(gtk::AccessibleRelation::LabelledBy);
        drop.update_property(&[gtk::accessible::Property::Label(&self.info(key).title)]);
        row.add_suffix(&drop);
        row.set_activatable_widget(Some(&drop));
        let me = Rc::downgrade(self);
        let values: Vec<Value> = opts.iter().map(|o| o.value.clone()).collect();
        drop.connect_selected_notify(move |r| {
            if let Some(me) = me.upgrade() {
                if !me.updating.get() {
                    if let Some(v) = values.get(r.selected() as usize) {
                        me.request(key, v.clone());
                    }
                }
            }
        });
        g.add(&row);
        self.ctls.borrow_mut().push(Ctl::Choice {
            key,
            row,
            drop,
            opts,
            badge,
            avail,
        });
    }

    /// A string list (folders, ports, bus names, variables): entries as
    /// removable chips, then an inline field to add one. Always visible.
    fn list(
        self: &Rc<Self>,
        g: &adw::PreferencesGroup,
        key: &'static str,
        placeholder: &str,
        folders: bool,
        avail: Avail,
    ) {
        self.list_or_map(g, key, placeholder, folders, false, avail)
    }

    /// `map`: the setting is a NAME → value map, edited as NAME=value.
    fn list_or_map(
        self: &Rc<Self>,
        g: &adw::PreferencesGroup,
        key: &'static str,
        placeholder: &str,
        folders: bool,
        map: bool,
        avail: Avail,
    ) {
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
        let head = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let texts = gtk::Box::new(gtk::Orientation::Vertical, 2);
        texts.set_hexpand(true);
        let title = gtk::Label::builder().xalign(0.0).wrap(true).build();
        let subtitle = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .use_markup(true)
            .build();
        subtitle.add_css_class("dim-label");
        subtitle.add_css_class("caption");
        texts.append(&title);
        texts.append(&subtitle);
        head.append(&texts);
        let badge = util::badge("", "bad");
        badge.set_visible(false);
        head.append(&badge);
        vbox.append(&head);

        let chips = gtk::FlowBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .column_spacing(6)
            .row_spacing(6)
            .max_children_per_line(30)
            .homogeneous(false)
            .build();
        vbox.append(&chips);

        let add_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let entry = gtk::Entry::builder()
            .placeholder_text(placeholder)
            .hexpand(true)
            .name(format!("perm-entry:{key}"))
            .build();
        add_box.append(&entry);
        if folders {
            let pick = gtk::Button::builder()
                .icon_name("folder-open-symbolic")
                .tooltip_text(tr("Choose a folder"))
                .valign(gtk::Align::Center)
                .build();
            pick.add_css_class("flat");
            let me = Rc::downgrade(self);
            pick.connect_clicked(move |_| {
                let Some(me) = me.upgrade() else { return };
                let dialog = gtk::FileDialog::builder()
                    .title(tr("Choose a folder"))
                    .build();
                let win = me.window.clone();
                glib::spawn_future_local(async move {
                    if let Ok(f) = dialog.select_folder_future(Some(&win)).await {
                        if let Some(p) = f.path() {
                            me.add_item(key, &util::tildify(&p.to_string_lossy()));
                        }
                    }
                });
            });
            add_box.append(&pick);
        }
        let add = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text(tr("Add"))
            .valign(gtk::Align::Center)
            .build();
        add.add_css_class("flat");
        add_box.append(&add);
        vbox.append(&add_box);
        let me = Rc::downgrade(self);
        let e2 = entry.clone();
        let commit = move || {
            if let Some(me) = me.upgrade() {
                let t = e2.text().trim().to_string();
                if !t.is_empty() {
                    let ok = if map {
                        me.add_pair(key, &t)
                    } else {
                        me.add_item(key, &t);
                        true
                    };
                    if ok {
                        e2.set_text("");
                    }
                }
            }
        };
        let c2 = commit.clone();
        entry.connect_activate(move |_| c2());
        add.connect_clicked(move |_| commit());

        row.set_child(Some(&vbox));
        g.add(&row);
        self.ctls.borrow_mut().push(Ctl::List {
            key,
            row,
            title,
            subtitle,
            chips,
            badge,
            avail,
            folders,
            map,
        });
    }

    fn add_item(self: &Rc<Self>, key: &'static str, item: &str) {
        if key == "sockets.custom" {
            let p = sam_core::util::expand_home(item);
            if !p.is_absolute() {
                self.notify(&crate::i18n::tr(
                    "Give the full path of the socket, for example /run/user/1000/app.sock",
                ));
                return;
            }
            use std::os::unix::fs::FileTypeExt;
            if let Ok(md) = std::fs::metadata(&p) {
                if !md.file_type().is_socket() {
                    self.notify(&crate::i18n::trf(
                        "{path} is not a socket. Use the Files settings to share folders or files.",
                        &[("path", &item)],
                    ));
                    return;
                }
            }
        }
        let mut items: Vec<Value> = self.value(key).as_array().cloned().unwrap_or_default();
        if !items.iter().any(|v| v.as_str() == Some(item)) {
            items.push(json!(item));
            self.request(key, Value::Array(items));
        }
    }

    /// Adds NAME=value to a map setting; false (with a message) if invalid.
    fn add_pair(self: &Rc<Self>, key: &'static str, text: &str) -> bool {
        let Some((name, value)) = text.split_once('=') else {
            self.notify(&crate::i18n::tr("Write it as NAME=value"));
            return false;
        };
        let name = name.trim();
        let valid = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            self.notify(&crate::i18n::tr(
                "A variable name has only letters, digits and _, and does not start with a digit",
            ));
            return false;
        }
        let mut m = self.value(key).as_object().cloned().unwrap_or_default();
        m.insert(name.to_string(), json!(value));
        self.request(key, Value::Object(m));
        true
    }

    fn remove_pair(self: &Rc<Self>, key: &'static str, name: &str) {
        let mut m = self.value(key).as_object().cloned().unwrap_or_default();
        if m.remove(name).is_some() {
            self.request(key, Value::Object(m));
        }
    }

    fn notify(&self, text: &str) {
        let toast = adw::Toast::new(&esc(text));
        if let Some(overlay) = self.window.content().and_downcast::<adw::ToastOverlay>() {
            overlay.add_toast(toast);
        }
    }

    fn remove_item(self: &Rc<Self>, key: &'static str, idx: usize) {
        let mut items: Vec<Value> = self.value(key).as_array().cloned().unwrap_or_default();
        if idx < items.len() {
            items.remove(idx);
            self.request(key, Value::Array(items));
        }
    }

    fn build(self: &Rc<Self>) {
        use Avail::*;
        let access = || {
            vec![
                opt(json!("none"), "No access", "Hidden from the app."),
                opt(
                    json!("ro"),
                    "Read-only",
                    "The app can open files here but not change or delete them.",
                ),
                opt(
                    json!("rw"),
                    "Read & write",
                    "The app can open, change and delete files here.",
                ),
            ]
        };

        let g = self.group(
            &crate::i18n::tr("Network"),
            &crate::i18n::tr("Internet and connections to services on this computer."),
        );
        self.choice(
            &g,
            "network.mode",
            vec![
                opt(json!("none"), "No network", "No connection at all, not even to this computer."),
                opt(
                    json!("localhost"),
                    "This computer only",
                    &crate::i18n::tr(
                        "No internet. The app can reach the services on this computer you list below, and its own web page opens in your browser.",
                    ),
                ),
                opt(json!("full"), "Full network", "The app uses your internet connection like any other program."),
            ],
            Always,
        );
        self.list(
            &g,
            "network.host_ports",
            &crate::i18n::tr("Port on this computer, for example 11434 for Ollama"),
            false,
            LocalNet,
        );
        self.list(
            &g,
            "network.app_ports",
            &crate::i18n::tr("Port of the app (empty = automatic)"),
            false,
            LocalNet,
        );

        let g = self.group(
            &crate::i18n::tr("Display"),
            &crate::i18n::tr("How the app shows its windows."),
        );
        self.switch(&g, "display.wayland", Always);
        self.switch(&g, "display.x11", Always);
        self.switch(&g, "display.wayland_privileged", Always);

        let g = self.group(
            &crate::i18n::tr("Sound and devices"),
            &crate::i18n::tr("Audio and hardware the app may use."),
        );
        self.switch(&g, "audio.enabled", Always);
        self.switch(&g, "devices.gpu", Always);
        self.switch(&g, "devices.webcam", Always);
        self.switch(&g, "devices.gamepads", NotAllInput);
        self.switch(&g, "devices.input", Always);
        self.switch(&g, "devices.usb", Always);
        self.switch(&g, "devices.bluetooth", Always);
        self.switch(&g, "audio.pipewire", Always);
        self.switch(&g, "audio.alsa_raw", Always);

        let g = self.group(
            &crate::i18n::tr("Files"),
            &crate::i18n::tr("Folders the app can see. Everything else in your home stays hidden."),
        );
        for k in [
            "filesystem.documents",
            "filesystem.downloads",
            "filesystem.pictures",
            "filesystem.music",
            "filesystem.videos",
            "filesystem.desktop",
        ] {
            self.choice(&g, k, access(), Always);
        }
        self.choice(
            &g,
            "filesystem.opened_files",
            vec![
                opt(
                    json!("ro"),
                    "Read-only",
                    "The app can view the files but not save changes.",
                ),
                opt(
                    json!("rw"),
                    "Read & write",
                    "The app can view and save the files.",
                ),
            ],
            Always,
        );
        self.list(
            &g,
            "filesystem.custom_read",
            &crate::i18n::tr("Folder path, e.g. ~/Projects"),
            true,
            Always,
        );
        self.list(
            &g,
            "filesystem.custom_write",
            &crate::i18n::tr("Folder path, e.g. ~/Projects"),
            true,
            Always,
        );
        self.switch(&g, "filesystem.home", Always);
        self.choice(
            &g,
            "filesystem.home_access",
            vec![
                opt(
                    json!("ro"),
                    "Read-only",
                    "The app can read your whole home but not change it.",
                ),
                opt(
                    json!("rw"),
                    "Read & write",
                    "The app can change and delete anything in your home.",
                ),
            ],
            FullHome,
        );
        self.switch(&g, "filesystem.ssh", FullHome);
        self.switch(&g, "filesystem.gnupg", FullHome);
        self.switch(&g, "filesystem.hidden_files", FullHome);

        let g = self.group(
            &crate::i18n::tr("Desktop integration"),
            &crate::i18n::tr("Desktop services the app may use. Needs the filtered session bus."),
        );
        self.switch(&g, "integrations.file_manager", FilteredBus);
        self.switch(&g, "integrations.media_controls", FilteredBus);
        self.switch(&g, "integrations.screen_sharing", FilteredBus);
        self.switch(&g, "integrations.keyring", FilteredBus);
        self.switch(&g, "integrations.input_method", AnyBus);

        let g = self.group(
            &crate::i18n::tr("D-Bus"),
            &crate::i18n::tr("How the app talks to other programs on your desktop."),
        );
        self.choice(
            &g,
            "dbus.session.mode",
            vec![
                opt(json!("none"), "No access", "No desktop services: no file dialogs, notifications or tray icon."),
                opt(json!("filtered"), "Filtered", "File dialogs, notifications, the tray and the services you allow below. Everything else is blocked."),
                opt(json!("full"), "Full access", "Every desktop service, including ones that can act outside the sandbox."),
            ],
            Always,
        );
        self.list(
            &g,
            "dbus.session.allow",
            &crate::i18n::tr("Bus name, e.g. org.example.Service"),
            false,
            FilteredBus,
        );
        self.list(
            &g,
            "dbus.session.own",
            &crate::i18n::tr("Bus name, e.g. org.example.App"),
            false,
            FilteredBus,
        );
        self.list(
            &g,
            "dbus.session.deny",
            &crate::i18n::tr("Bus name, e.g. org.freedesktop.secrets"),
            false,
            FilteredBus,
        );
        self.choice(
            &g,
            "dbus.system.mode",
            vec![
                opt(
                    json!("none"),
                    "No access",
                    "The system bus controls hardware, networking and power.",
                ),
                opt(
                    json!("full"),
                    "Full access",
                    "The app can talk to every system service.",
                ),
            ],
            Always,
        );

        let g = self.group(
            &crate::i18n::tr("Sockets and environment"),
            &crate::i18n::tr("Other services and settings passed into the sandbox."),
        );
        self.switch(&g, "sockets.ssh_agent", Always);
        self.switch(&g, "sockets.cups", Always);
        self.list(
            &g,
            "sockets.custom",
            &crate::i18n::tr("Socket path, e.g. /run/user/1000/app.sock"),
            false,
            Always,
        );
        self.list(
            &g,
            "environment.passthrough",
            &crate::i18n::tr("Variable name, e.g. LANG"),
            false,
            Always,
        );
        self.list_or_map(
            &g,
            "environment.set",
            &crate::i18n::tr("NAME=value, e.g. QT_SCALE_FACTOR=1.5"),
            false,
            true,
            Always,
        );

        let g = self.group(
            &crate::i18n::tr("Advanced"),
            &crate::i18n::tr("Change these only if an app does not work."),
        );
        self.choice(
            &g,
            "advanced.host_runtime",
            vec![
                opt(json!("minimal"), "Minimal", "System libraries plus a short list of shared data (fonts, icons, themes)."),
                opt(json!("full"), "All of /usr", "Everything installed on the system, read-only. For apps that look for programs or data elsewhere."),
            ],
            Always,
        );
        self.switch(&g, "advanced.persistent_home", Always);
        self.switch(&g, "advanced.writable_appdir", Always);
        self.switch(&g, "advanced.host_themes", Always);
        self.switch(&g, "advanced.allow_userns", Always);
        self.list(
            &g,
            "advanced.extra_bwrap_args",
            &crate::i18n::tr("Raw bwrap argument, e.g. --setenv FOO 1"),
            false,
            Always,
        );

        // The security engine's extra layers, apart from the other expert
        // settings and with an explanation: turning one off weakens the
        // sandbox for every permission at once.
        let g = self.group(
            &crate::i18n::tr("Extra Protection Layers"),
            &crate::i18n::tr("Protection on top of the sandbox: a filter that blocks dangerous system calls, and Landlock, which lets the kernel itself stop writes outside the granted folders. They cost nothing while an app works. Turn one off only when an app's log shows it fails because of it, and only for that app; SAM's repair steps say so when that is the case."),
        );
        self.switch(&g, "advanced.seccomp_baseline", Always);
        self.choice(
            &g,
            "advanced.landlock",
            vec![
                opt(
                    Value::Null,
                    &crate::i18n::tr("Follow global setting"),
                    &crate::i18n::tr("Uses the setting in SAM's preferences."),
                ),
                opt(
                    json!(true),
                    "Enforce",
                    "Kernel-enforced write restrictions for this app.",
                ),
                opt(
                    json!(false),
                    "Off",
                    "No Landlock restrictions for this app.",
                ),
            ],
            Always,
        );
        self.switch(&g, "advanced.seccomp_strict", Always);
    }

    // ------------------------------------------------------------ refresh

    pub fn refresh(self: &Rc<Self>) {
        self.updating.set(true);
        let has = self.perms.borrow().is_some();
        let editable = has;
        for c in self.ctls.borrow().iter() {
            match c {
                Ctl::Switch {
                    key,
                    row,
                    sw,
                    badge,
                    avail,
                } => {
                    let info = self.info(key);
                    sw.set_active(self.value(key) == json!(true));
                    row.set_subtitle(&self.describe(key, &info.description));
                    set_usable(row.upcast_ref(), editable && self.available(*avail));
                    self.set_risk_badge(badge, key);
                }
                Ctl::Choice {
                    key,
                    row,
                    drop,
                    opts,
                    badge,
                    avail,
                } => {
                    let v = self.value(key);
                    let idx = opts.iter().position(|o| o.value == v).unwrap_or(0);
                    drop.set_selected(idx as u32);
                    let d = opts
                        .get(idx)
                        .map(|o| o.description.clone())
                        .filter(|d| !d.is_empty())
                        .unwrap_or_else(|| self.info(key).description);
                    row.set_subtitle(&self.describe(key, &d));
                    set_usable(row.upcast_ref(), editable && self.available(*avail));
                    self.set_risk_badge(badge, key);
                }
                Ctl::List {
                    key,
                    row,
                    title,
                    subtitle,
                    chips,
                    badge,
                    avail,
                    folders,
                    map,
                } => {
                    let info = self.info(key);
                    title.set_text(&info.title);
                    subtitle.set_markup(&self.describe(key, &info.description));
                    set_usable(row.upcast_ref(), editable && self.available(*avail));
                    self.set_risk_badge(badge, key);
                    while let Some(ch) = chips.first_child() {
                        chips.remove(&ch);
                    }
                    let count = if *map {
                        let m = self.value(key).as_object().cloned().unwrap_or_default();
                        for (name, v) in &m {
                            let text = format!(
                                "{name}={}",
                                v.as_str()
                                    .map(String::from)
                                    .unwrap_or_else(|| v.to_string())
                            );
                            let (me, name, k): (_, String, &'static str) =
                                (Rc::downgrade(self), name.clone(), key);
                            let w = self.chip_with(&text, false, move || {
                                if let Some(me) = me.upgrade() {
                                    me.remove_pair(k, &name)
                                }
                            });
                            chips.insert(
                                &gtk::FlowBoxChild::builder()
                                    .child(&w)
                                    .halign(gtk::Align::Start)
                                    .focusable(false)
                                    .build(),
                                -1,
                            );
                        }
                        m.len()
                    } else {
                        let items = self.value(key).as_array().cloned().unwrap_or_default();
                        for (i, it) in items.iter().enumerate() {
                            let text = it
                                .as_str()
                                .map(String::from)
                                .unwrap_or_else(|| it.to_string());
                            let child = gtk::FlowBoxChild::builder()
                                .child(&self.chip(key, i, &text, *folders))
                                .halign(gtk::Align::Start)
                                .focusable(false)
                                .build();
                            chips.insert(&child, -1);
                        }
                        items.len()
                    };
                    chips.set_visible(count > 0);
                }
            }
        }
        self.updating.set(false);
        self.refresh_overview();
    }

    fn chip(
        self: &Rc<Self>,
        key: &'static str,
        idx: usize,
        text: &str,
        folder: bool,
    ) -> gtk::Widget {
        let me = Rc::downgrade(self);
        self.chip_with(text, folder, move || {
            if let Some(me) = me.upgrade() {
                me.remove_item(key, idx);
            }
        })
    }

    fn chip_with(&self, text: &str, folder: bool, on_remove: impl Fn() + 'static) -> gtk::Widget {
        crate::util::chip(text, folder, on_remove)
    }

    fn set_risk_badge(&self, badge: &gtk::Label, key: &str) {
        let r = self.active_risk(key);
        badge.set_visible(!r.is_empty());
        if !r.is_empty() {
            util::set_badge(badge, &util::risk_label(&r), util::risk_tone(&r));
        }
    }

    fn refresh_overview(&self) {
        for r in self.warning_rows.borrow_mut().drain(..) {
            self.overview.remove(&r);
        }
        let ev = self.evaluation.borrow();
        let risk = ev
            .as_ref()
            .and_then(|e| e.get("risk").cloned())
            .unwrap_or_default();
        let level = util::str_of(&risk, "level").to_string();
        self.risk_badge.set_visible(!level.is_empty());
        util::set_badge(
            &self.risk_badge,
            &util::risk_label(&level),
            util::risk_tone(&level),
        );
        self.risk_badge
            .set_tooltip_text(Some(&util::risk_tooltip(&risk)));
        let mut warnings: Vec<Value> = ev
            .as_ref()
            .and_then(|e| e.get("warnings"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let order = |s: &str| match s {
            "danger" => 0,
            "warning" => 1,
            _ => 2,
        };
        warnings.sort_by_key(|w| order(util::str_of(w, "severity")));
        let serious = warnings
            .iter()
            .filter(|w| util::str_of(w, "severity") != "info")
            .count();
        // Which permission sets the level, in words.
        let items = util::risk_items(&risk);
        let top: Vec<&str> = items
            .iter()
            .filter(|(_, l)| *l == level)
            .map(|(t, _)| t.as_str())
            .collect();
        let why = match top.len() {
            0 => crate::i18n::tr(
                "Only harmless basics: fonts, its own window and folders you share read-only.",
            ),
            1 => crate::i18n::trf(
                "Set by the riskiest permission: {permission}.",
                &[("permission", &top[0])],
            ),
            _ => crate::i18n::trf(
                "Set by the riskiest permissions: {permissions}.",
                &[("permissions", &top.join(", "))],
            ),
        };
        let watch = match serious {
            0 => "",
            1 => " One thing to watch out for, listed below.",
            _ => " Several things to watch out for, listed below.",
        };
        self.risk_row.set_subtitle(&esc(&format!("{why}{watch}")));
        // Everything that raises the risk, riskiest first.
        if !items.is_empty() {
            let exp = adw::ExpanderRow::builder()
                .title(tr("What raises the risk"))
                .subtitle(crate::i18n::trn(
                    "{n} permission beyond the basics. The level is set by the riskiest one, not by how many there are.",
                    "{n} permissions beyond the basics. The level is set by the riskiest one, not by how many there are.",
                    items.len() as u64,
                    &[],
                ))
                .build();
            for (title, lvl) in &items {
                let row = adw::ActionRow::builder().title(esc(title)).build();
                let b = util::badge(
                    util::risk_label(lvl).trim_end_matches(" risk"),
                    util::risk_tone(lvl),
                );
                row.add_suffix(&b);
                exp.add_row(&row);
            }
            self.overview.add(&exp);
            self.warning_rows.borrow_mut().push(exp.upcast());
        }
        for w in warnings {
            let sev = util::str_of(&w, "severity");
            let row = adw::ActionRow::builder()
                .title(esc(util::str_of(&w, "title")))
                .subtitle(esc(util::str_of(&w, "message")))
                .build();
            let icon = gtk::Image::from_icon_name(match sev {
                "danger" => "dialog-error-symbolic",
                "warning" => "dialog-warning-symbolic",
                _ => "dialog-information-symbolic",
            });
            icon.add_css_class(match sev {
                "danger" => "error",
                "warning" => "warning",
                _ => "dim-label",
            });
            row.add_prefix(&icon);
            self.overview.add(&row);
            self.warning_rows.borrow_mut().push(row.upcast());
        }
    }

    // ------------------------------------------------------------ changes

    fn is_enabling(&self, key: &str, v: &Value) -> bool {
        let cur = self.value(key);
        match key {
            "dbus.session.mode" => *v == json!("full") && cur != json!("full"),
            "dbus.system.mode" => *v != json!("none") && cur == json!("none"),
            "filesystem.home_access" => *v == json!("rw") && cur != json!("rw"),
            _ => *v == json!(true) && cur != json!(true),
        }
    }

    /// Applies a change, asking first for high-risk grants. A refused or
    /// pending change leaves the controls showing the saved value.
    fn request(self: &Rc<Self>, key: &'static str, v: Value) {
        let Some(mut p) = self.perms.borrow().clone() else {
            return;
        };
        let mut ask: Option<(String, String, String)> = None;
        if key == "dbus.session.allow" {
            let before: Vec<String> = util::list_of(&p, key);
            let added: Vec<String> = v
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .filter(|n| {
                            !before.contains(n)
                                && sam_core::permissions::dangerous_bus_name(n).is_some()
                        })
                        .collect()
                })
                .unwrap_or_default();
            if !added.is_empty() {
                ask = Some((
                    crate::i18n::trf("Allow “{permissions}”?", &[("permissions", &added.join(", "))]),
                    crate::i18n::tr("This service can act outside the sandbox: start programs, run scripts in the desktop shell or change any setting. An app with access to it can escape the sandbox."),
                    crate::i18n::tr("Allow Anyway"),
                ));
            }
        }
        if key == "dbus.session.own" || key == "sockets.custom" {
            let before: Vec<String> = util::list_of(&p, key);
            let added: Vec<String> = v
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .filter(|n| !before.contains(n))
                        .collect()
                })
                .unwrap_or_default();
            let why: Vec<String> = added
                .iter()
                .filter_map(|n| {
                    if key == "sockets.custom" {
                        sam_core::permissions::dangerous_socket(n)
                    } else {
                        sam_core::permissions::dangerous_bus_name(n)
                    }
                })
                .collect();
            if !why.is_empty() {
                ask = Some((
                    crate::i18n::trf("Allow “{permissions}”?", &[("permissions", &added.join(", "))]),
                    format!(
                        "{}.\n\n{}",
                        why.join(". "),
                        crate::i18n::tr("An app with this can act outside the sandbox. Only allow it for apps you trust completely.")
                    ),
                    crate::i18n::tr("Allow Anyway"),
                ));
            }
        }
        let info = self.info(key);
        if ask.is_none()
            && self.is_enabling(key, &v)
            && (info.risk == "dangerous"
                || key == "dbus.session.mode"
                || key == "integrations.keyring")
        {
            ask = Some((
                crate::i18n::trf("Grant “{permission}”?", &[("permission", &info.title)]),
                format!(
                    "{}\n\n{}",
                    info.description,
                    crate::i18n::tr(
                        "This is a high-risk permission. Only grant it to apps you trust."
                    )
                ),
                crate::i18n::tr("Grant"),
            ));
        }
        util::set(&mut p, key, v);
        let me = self.clone();
        match ask {
            None => me.emit(p),
            Some((heading, body, accept)) => {
                me.refresh();
                glib::spawn_future_local(async move {
                    if crate::window::confirm(&me.window, &heading, &body, &accept, true).await {
                        me.emit(p);
                    }
                });
            }
        }
    }

    fn emit(self: &Rc<Self>, p: Value) {
        *self.perms.borrow_mut() = Some(p.clone());
        self.refresh();
        if let Some(f) = self.on_edit.borrow().as_ref() {
            f(p);
        }
    }
}

/// Greys a setting's row out, and takes it out of the keyboard focus chain
/// while it is greyed out: GTK's list otherwise moves the focus to the
/// insensitive row, which refuses it, and Tab stops there.
fn set_usable(row: &gtk::Widget, on: bool) {
    row.set_sensitive(on);
    row.set_can_focus(on);
}
