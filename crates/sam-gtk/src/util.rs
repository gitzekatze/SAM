// SPDX-License-Identifier: GPL-3.0-or-later
//! Small helpers shared by the views.

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
    get(v, key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

pub fn risk_label(level: &str) -> String {
    match level {
        "low" => "Low risk",
        "medium" => "Medium risk",
        "high" => "High risk",
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
    gtk::glib::DateTime::from_unix_local(secs)
        .and_then(|d| d.format("%x %H:%M"))
        .map(|s| s.to_string())
        .unwrap_or_default()
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
pub fn risk_tone(level: &str) -> &'static str {
    match level {
        "low" => "good",
        "medium" => "warn",
        "high" => "bad",
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
    let x = gtk::Button::builder().icon_name("window-close-symbolic").tooltip_text("Remove").valign(gtk::Align::Center).build();
    x.add_css_class("flat");
    x.add_css_class("circular");
    x.connect_clicked(move |_| on_remove());
    b.append(&x);
    b.upcast()
}
