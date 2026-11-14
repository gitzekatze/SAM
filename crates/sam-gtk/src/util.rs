// SPDX-License-Identifier: GPL-3.0-or-later
//! Small helpers shared by the views.

use crate::i18n::tr;
use serde_json::Value;

/// The user's home directory.
pub fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

/// `~/…` form of a path, for display and for stored locations.
pub fn tildify(path: &str) -> String {
    let h = home();
    if !h.is_empty() && path.starts_with(&h) && (path.len() == h.len() || path[h.len()..].starts_with('/')) {
        format!("~{}", &path[h.len()..])
    } else {
        path.to_string()
    }
}

/// Text from AppImages, apps or file names: no control characters, capped
/// length. GTK labels show it as plain text (markup is never enabled for it).
/// The folder behind a personal-folder permission (`filesystem.documents`
/// → `~/Documents`), as this computer names it (it may be translated).
pub fn folder_path(key: &str) -> Option<String> {
    use gtk::glib::UserDirectory as D;
    let (dir, fallback) = match key {
        "filesystem.documents" => (D::Documents, "Documents"),
        "filesystem.downloads" => (D::Downloads, "Downloads"),
        "filesystem.pictures" => (D::Pictures, "Pictures"),
        "filesystem.music" => (D::Music, "Music"),
        "filesystem.videos" => (D::Videos, "Videos"),
        "filesystem.desktop" => (D::Desktop, "Desktop"),
        _ => return None,
    };
    let path = gtk::glib::user_special_dir(dir).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| format!("{}/{fallback}", home()));
    Some(tildify(&path))
}

/// The explanation of a permission for a tooltip or subtitle: the switch's
/// description, with the folder's path for personal folders.
pub fn explain(key: &str, description: &str) -> String {
    match folder_path(key) {
        Some(p) => format!("{description} Folder: {p}"),
        None => description.to_string(),
    }
}

pub fn plain(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control() || *c == '\n').take(400).collect();
    if s.chars().count() > 400 {
        out.push('…');
    }
    out
}

/// Escape for the few places that use Pango markup on purpose.
pub fn esc(s: &str) -> String {
    gtk::glib::markup_escape_text(s).to_string()
}

pub fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.').try_fold(v, |cur, part| cur.get(part))
}

pub fn set(v: &mut Value, key: &str, val: Value) {
    let parts: Vec<&str> = key.split('.').collect();
    let mut cur = v;
    for p in &parts[..parts.len() - 1] {
        if !cur.get(*p).is_some_and(Value::is_object) {
            cur[*p] = Value::Object(Default::default());
        }
        cur = cur.get_mut(*p).unwrap();
    }
    cur[parts[parts.len() - 1]] = val;
}

pub fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    get(v, key).and_then(Value::as_str).unwrap_or("")
}

pub fn bool_of(v: &Value, key: &str) -> bool {
    get(v, key).and_then(Value::as_bool).unwrap_or(false)
}

pub fn list_of(v: &Value, key: &str) -> Vec<String> {
    get(v, key).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// SAM shows risk in three levels everywhere (tags, badges, lists): the
/// four levels of the risk model map onto them the same way as the
/// permission tags do (sam-profile::tags::TagLevel).
pub fn risk_label(level: &str) -> String {
    match level {
        "low" | "medium" => "Harmless",
        "high" => "Think twice",
        "dangerous" => "Dangerous",
        _ => "",
    }
    .to_string()
}

pub fn category_label(c: &str) -> String {
    match c {
        "browser" => "Browser",
        "media-player" => "Media player",
        "image-editor" => "Image editor",
        "video-editor" => "Video editor",
        "audio-editor" => "Audio editor",
        "game" => "Game",
        "text-editor" => "Text editor",
        "office" => "Office",
        "terminal" => "Terminal",
        "development" => "Development",
        "communication" => "Communication",
        "utility" => "Utility",
        "" => "Unknown",
        other => other,
    }
    .to_string()
}

/// Local date and time of a Unix timestamp.
pub fn format_time(secs: i64) -> String {
    gtk::glib::DateTime::from_unix_local(secs).and_then(|d| d.format("%x %H:%M")).map(|s| s.to_string()).unwrap_or_default()
}

/// A tinted status label ("Sandboxed", "High risk").
pub fn badge(text: &str, tone: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.add_css_class("sam-badge");
    l.add_css_class(&format!("sam-badge-{tone}"));
    l.set_valign(gtk::Align::Center);
    l
}

/// Tone of a risk level, for `badge`.
fn risk_rank(level: &str) -> u8 {
    match level {
        "dangerous" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

/// Permissions that raise the risk (everything but the harmless basics),
/// riskiest first: (title, level).
pub fn risk_items(risk: &Value) -> Vec<(String, String)> {
    let mut items: Vec<(String, String)> = risk
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|i| !str_of(i, "key").starts_with("baseline.") && str_of(i, "level") != "low")
        .map(|i| (str_of(i, "title").to_string(), str_of(i, "level").to_string()))
        .collect();
    items.sort_by_key(|(_, l)| std::cmp::Reverse(risk_rank(l)));
    items
}

/// Hover text: what each level means for this app.
pub fn risk_tooltip(risk: &Value) -> String {
    let items = risk_items(risk);
    if items.is_empty() {
        return "Low risk: the app only gets harmless basics such as fonts, its own window and the folders you share read-only.".into();
    }
    let mut lines = vec!["The risk is set by the riskiest permission:".to_string()];
    for lvl in ["dangerous", "high", "medium"] {
        let names: Vec<&str> = items.iter().filter(|(_, l)| l == lvl).map(|(t, _)| t.as_str()).collect();
        if !names.is_empty() {
            lines.push(format!("{}: {}", risk_label(lvl).trim_end_matches(" risk"), names.join(", ")));
        }
    }
    lines.push("Details under Overview.".into());
    lines.join("\n")
}

pub fn risk_tone(level: &str) -> &'static str {
    match level {
        "low" | "medium" => "harmless",
        "high" => "caution",
        "dangerous" => "danger",
        _ => "neutral",
    }
}

use gtk::prelude::*;

/// Replaces a badge's text and tone in place.
pub fn set_badge(l: &gtk::Label, text: &str, tone: &str) {
    for t in ["good", "warn", "bad", "danger", "neutral", "accent", "blue"] {
        l.remove_css_class(&format!("sam-badge-{t}"));
    }
    l.add_css_class(&format!("sam-badge-{tone}"));
    l.set_text(text);
}

/// A removable chip ("org.example.Name ✕") for list settings.
pub fn chip(text: &str, folder: bool, on_remove: impl Fn() + 'static) -> gtk::Widget {
    let b = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    b.add_css_class("sam-chip");
    b.set_halign(gtk::Align::Start);
    if folder {
        b.append(&gtk::Image::from_icon_name("folder-symbolic"));
    }
    let l = gtk::Label::builder().label(plain(text)).ellipsize(gtk::pango::EllipsizeMode::Middle).max_width_chars(40).build();
    b.append(&l);
    let x = gtk::Button::builder().icon_name("window-close-symbolic").tooltip_text(tr("Remove")).valign(gtk::Align::Center).build();
    x.update_property(&[gtk::accessible::Property::Label(&format!("Remove {}", plain(text)))]);
    x.add_css_class("flat");
    x.add_css_class("circular");
    x.connect_clicked(move |_| on_remove());
    b.append(&x);
    b.upcast()
}

/// Gives every button that shows only an icon an accessible name (its
/// tooltip), so screen readers announce what it does instead of "button".
/// Walks the whole tree below `root`; buttons with a text label keep theirs.
pub fn name_icon_buttons(root: &impl IsA<gtk::Widget>) {
    let mut stack = vec![root.as_ref().clone()];
    while let Some(w) = stack.pop() {
        let named = |w: &gtk::Widget, has_label: bool| {
            if !has_label {
                if let Some(t) = w.tooltip_text() {
                    w.update_property(&[gtk::accessible::Property::Label(&t)]);
                }
            }
        };
        if let Some(b) = w.downcast_ref::<gtk::Button>() {
            named(&w, b.label().is_some_and(|l| !l.is_empty()));
        } else if let Some(b) = w.downcast_ref::<gtk::MenuButton>() {
            named(&w, b.label().is_some_and(|l| !l.is_empty()));
        }
        let mut c = w.first_child();
        while let Some(ch) = c {
            c = ch.next_sibling();
            stack.push(ch);
        }
    }
}

/// A container whose minimum height is its child's natural height (for the
/// width it gets). The header of the app page sits in an `AdwBreakpointBin`,
/// which reports only its fixed minimum height, and a pinned top bar gets no
/// more than the minimum; without this wrapper a second row of labels under
/// the app name would be cut off.
pub mod natural_height {
    use gtk::glib;
    use gtk::prelude::*;
    use gtk::subclass::prelude::*;

    mod imp {
        use super::*;

        #[derive(Default)]
        pub struct Bin;

        #[glib::object_subclass]
        impl ObjectSubclass for Bin {
            const NAME: &'static str = "SamNaturalHeightBin";
            type Type = super::Bin;
            type ParentType = gtk::Widget;
        }

        impl ObjectImpl for Bin {
            fn dispose(&self) {
                while let Some(c) = self.obj().first_child() {
                    c.unparent();
                }
            }
        }

        impl WidgetImpl for Bin {
            // Height for width: the parent then asks for the height at the
            // real width, where the labels may wrap (AdwBreakpointBin itself
            // reports a constant size).
            fn request_mode(&self) -> gtk::SizeRequestMode {
                gtk::SizeRequestMode::HeightForWidth
            }
            fn measure(&self, orientation: gtk::Orientation, for_size: i32) -> (i32, i32, i32, i32) {
                let Some(c) = self.obj().first_child() else { return (0, 0, -1, -1) };
                let (min, nat, _, _) = c.measure(orientation, for_size);
                if orientation == gtk::Orientation::Vertical {
                    // AdwBreakpointBin reports a constant size, so GTK measures
                    // it without the width; ask its content at the real width.
                    let inner = c.first_child().map(|i| i.measure(orientation, for_size).1).unwrap_or(nat);
                    let h = min.max(nat).max(inner);
                    (h, h, -1, -1)
                } else {
                    (min, nat, -1, -1)
                }
            }
            fn size_allocate(&self, width: i32, height: i32, baseline: i32) {
                if let Some(c) = self.obj().first_child() {
                    c.allocate(width, height, baseline, None);
                }
            }
            // Keyboard focus goes on to the content (a plain widget would
            // keep Tab from ever reaching the buttons inside).
            fn focus(&self, direction: gtk::DirectionType) -> bool {
                self.obj().first_child().is_some_and(|c| c.child_focus(direction))
            }
            fn grab_focus(&self) -> bool {
                self.obj().first_child().is_some_and(|c| c.grab_focus())
            }
        }
    }

    glib::wrapper! {
        pub struct Bin(ObjectSubclass<imp::Bin>)
            @extends gtk::Widget,
            @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
    }

    impl Bin {
        pub fn new(child: &impl IsA<gtk::Widget>) -> Self {
            let bin: Self = glib::Object::new();
            child.set_parent(&bin);
            bin
        }
    }
}

/// A container that lines its children up like words in a sentence and
/// starts a new line when the next one does not fit (for tags). GTK's flow
/// box would align them in columns, and libadwaita's wrap box needs
/// libadwaita 1.7, newer than SAM requires.
pub fn wrap_box(hspace: i32, vspace: i32) -> gtk::Box {
    let b = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    b.set_layout_manager(Some(wrap::WrapLayout::new(hspace, vspace)));
    b
}

pub mod wrap {
    use gtk::glib;
    use gtk::prelude::*;
    use gtk::subclass::prelude::*;
    use std::cell::Cell;

    mod imp {
        use super::*;

        #[derive(Default)]
        pub struct WrapLayout {
            pub hspace: Cell<i32>,
            pub vspace: Cell<i32>,
        }

        #[glib::object_subclass]
        impl ObjectSubclass for WrapLayout {
            const NAME: &'static str = "SamWrapLayout";
            type Type = super::WrapLayout;
            type ParentType = gtk::LayoutManager;
        }

        impl ObjectImpl for WrapLayout {}

        impl WrapLayout {
            fn children(w: &gtk::Widget) -> Vec<gtk::Widget> {
                let mut out = Vec::new();
                let mut c = w.first_child();
                while let Some(ch) = c {
                    c = ch.next_sibling();
                    if ch.should_layout() {
                        out.push(ch);
                    }
                }
                out
            }

            /// Positions (x, y, width, height) for `width`, and the height used.
            fn lines(&self, w: &gtk::Widget, width: i32) -> (Vec<(i32, i32, i32, i32)>, i32) {
                let (hs, vs) = (self.hspace.get(), self.vspace.get());
                let (mut x, mut y, mut line_h) = (0, 0, 0);
                let mut out = Vec::new();
                for ch in Self::children(w) {
                    let (min_w, nat_w, _, _) = ch.measure(gtk::Orientation::Horizontal, -1);
                    let cw = nat_w.min(width.max(min_w));
                    let (_, ch_h, _, _) = ch.measure(gtk::Orientation::Vertical, cw);
                    if x > 0 && x + cw > width {
                        x = 0;
                        y += line_h + vs;
                        line_h = 0;
                    }
                    out.push((x, y, cw, ch_h));
                    x += cw + hs;
                    line_h = line_h.max(ch_h);
                }
                (out, y + line_h)
            }
        }

        impl LayoutManagerImpl for WrapLayout {
            fn request_mode(&self, _widget: &gtk::Widget) -> gtk::SizeRequestMode {
                gtk::SizeRequestMode::HeightForWidth
            }

            fn measure(&self, widget: &gtk::Widget, orientation: gtk::Orientation, for_size: i32) -> (i32, i32, i32, i32) {
                if orientation == gtk::Orientation::Horizontal {
                    let kids = Self::children(widget);
                    let min = kids.iter().map(|c| c.measure(gtk::Orientation::Horizontal, -1).0).max().unwrap_or(0);
                    let gaps = self.hspace.get() * (kids.len() as i32 - 1).max(0);
                    let nat: i32 = kids.iter().map(|c| c.measure(gtk::Orientation::Horizontal, -1).1).sum::<i32>() + gaps;
                    (min, nat.max(min), -1, -1)
                } else {
                    let width = if for_size < 0 { i32::MAX / 2 } else { for_size };
                    let h = self.lines(widget, width).1;
                    (h, h, -1, -1)
                }
            }

            fn allocate(&self, widget: &gtk::Widget, width: i32, _height: i32, _baseline: i32) {
                let (pos, _) = self.lines(widget, width);
                for (ch, (x, y, w, h)) in Self::children(widget).iter().zip(pos) {
                    ch.size_allocate(&gtk::Allocation::new(x, y, w, h), -1);
                }
            }
        }
    }

    glib::wrapper! {
        pub struct WrapLayout(ObjectSubclass<imp::WrapLayout>) @extends gtk::LayoutManager;
    }

    impl WrapLayout {
        pub fn new(hspace: i32, vspace: i32) -> Self {
            let l: Self = glib::Object::new();
            l.imp().hspace.set(hspace);
            l.imp().vspace.set(vspace);
            l
        }
    }
}

/// Removes every child of a box.
pub fn clear_box(b: &gtk::Box) {
    while let Some(c) = b.first_child() {
        b.remove(&c);
    }
}
