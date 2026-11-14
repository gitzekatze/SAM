//! Permission tags: a short overview of what an app may reach, for the
//! Permissions page. A tag uses the same words as the switch it stands for,
//! belongs to one of four families in a fixed order, has a color for its
//! risk and is filled for read & write or outlined for read-only access.
//!
//! Only granted permissions get a tag. The permissions every window app has
//! (Wayland, typing through an input method, and the files you open with
//! it) get none, and neither do the low-risk expert settings: a tag that
//! every app carries would tell the reader nothing.

use sam_core::permissions::{permission_catalog, PermissionSet};
use sam_core::risk::RiskLevel;
use serde::Serialize;
use serde_json::Value;

/// The four tag families, in the order they are shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Network,
    Files,
    Devices,
    Desktop,
}

/// The color of a tag: harmless, think twice, or dangerous. Folders, sound
/// and the GPU count as harmless here: they are ordinary, limited grants.
/// Full network, X11, the webcam or the keyring make one think twice, and
/// full home access or raw devices are dangerous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TagLevel {
    Harmless,
    Caution,
    Danger,
}

impl From<RiskLevel> for TagLevel {
    fn from(r: RiskLevel) -> Self {
        match r {
            RiskLevel::Low | RiskLevel::Medium => TagLevel::Harmless,
            RiskLevel::High => TagLevel::Caution,
            RiskLevel::Dangerous => TagLevel::Danger,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tag {
    /// The permission key (`filesystem.documents`).
    pub key: String,
    /// The words of the switch ("Documents", "Full network").
    pub label: String,
    pub family: Family,
    pub level: TagLevel,
    /// Read-only (or otherwise limited) access: drawn as an outline.
    pub read_only: bool,
    /// Position of the switch among all switches, for a stable order.
    pub order: usize,
}

/// Keys that never get a tag: every window app has them, or they only
/// refine another permission.
const NO_TAG: &[&str] =
    &["display.wayland", "filesystem.opened_files", "integrations.input_method", "filesystem.home_access", "network.host_ports", "network.app_ports"];

/// Keys that only matter together with full home access.
const WITH_HOME: &[&str] = &["filesystem.ssh", "filesystem.gnupg", "filesystem.hidden_files"];

fn family(category: &str, key: &str) -> Option<Family> {
    Some(match category {
        "Network" => Family::Network,
        "Filesystem" => Family::Files,
        "Devices" | "Audio" => Family::Devices,
        "Sockets" if key == "sockets.cups" => Family::Devices,
        "Display" | "D-Bus" | "Desktop integration" | "Sockets" => Family::Desktop,
        _ => return None,
    })
}

/// The tags of a set of permissions, in family order, then in the order of
/// the switches.
pub fn permission_tags(p: &PermissionSet) -> Vec<Tag> {
    let mut out = Vec::new();
    for (order, info) in permission_catalog().into_iter().enumerate() {
        let Some(family) = family(info.category, info.key) else { continue };
        if NO_TAG.contains(&info.key) || (info.advanced && info.risk < RiskLevel::High) {
            continue;
        }
        if WITH_HOME.contains(&info.key) && !p.filesystem.home {
            continue;
        }
        let Ok(v) = p.get_key(info.key) else { continue };
        let (granted, read_only, label) = match (info.key, &v) {
            ("network.mode", Value::String(m)) => match m.as_str() {
                "full" => (true, false, "Full network"),
                "localhost" => (true, true, "Local network only"),
                _ => (false, false, ""),
            },
            ("filesystem.home", Value::Bool(on)) => (*on, p.filesystem.home_access == sam_core::permissions::Access::Ro, info.title),
            ("filesystem.custom_read", Value::Array(a)) => (!a.is_empty(), true, info.title),
            (_, Value::Bool(on)) => (*on, false, info.title),
            (_, Value::Array(a)) => (!a.is_empty(), false, info.title),
            (_, Value::String(s)) => match s.as_str() {
                "rw" | "full" => (true, false, info.title),
                "ro" => (true, true, info.title),
                _ => (false, false, info.title),
            },
            _ => (false, false, info.title),
        };
        if granted {
            out.push(Tag { key: info.key.to_string(), label: label.to_string(), family, level: info.risk.into(), read_only, order });
        }
    }
    out.sort_by_key(|t| t.family);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::permissions::{Access, DbusMode, NetworkMode};

    fn labels(p: &PermissionSet) -> Vec<String> {
        permission_tags(p).into_iter().map(|t| t.label).collect()
    }

    #[test]
    fn a_strict_window_app_has_no_tags() {
        assert!(labels(&PermissionSet::strict_gui()).is_empty(), "{:?}", labels(&PermissionSet::strict_gui()));
    }

    #[test]
    fn tags_follow_the_family_order_and_mark_read_only() {
        let mut p = PermissionSet::strict_gui();
        p.display.x11 = true;
        p.audio.enabled = true;
        p.filesystem.documents = Access::Ro;
        p.filesystem.pictures = Access::Rw;
        p.network.mode = NetworkMode::Full;
        let tags = permission_tags(&p);
        let fams: Vec<Family> = tags.iter().map(|t| t.family).collect();
        let mut sorted = fams.clone();
        sorted.sort();
        assert_eq!(fams, sorted);
        assert_eq!(tags[0].label, "Full network");
        let docs = tags.iter().find(|t| t.key == "filesystem.documents").unwrap();
        assert!(docs.read_only);
        assert_eq!(docs.label, "Documents");
        assert!(!tags.iter().find(|t| t.key == "filesystem.pictures").unwrap().read_only);
        assert!(tags.iter().any(|t| t.label == "Sound" && t.family == Family::Devices));
        assert!(tags.iter().any(|t| t.key == "display.x11" && t.family == Family::Desktop));
    }

    #[test]
    fn dangerous_access_is_red_and_filtered_bus_has_no_tag() {
        let mut p = PermissionSet::strict_gui();
        p.dbus.session.mode = DbusMode::Filtered;
        assert!(labels(&p).is_empty());
        p.filesystem.home = true;
        p.filesystem.ssh = true;
        let tags = permission_tags(&p);
        assert!(tags.iter().all(|t| t.level == TagLevel::Danger), "{tags:?}");
        assert_eq!(tags.len(), 2);
        p.network.mode = NetworkMode::Localhost;
        assert!(permission_tags(&p)[0].read_only);
    }
}
