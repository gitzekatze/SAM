//! Which D-Bus names an app may own (owner decision of 2026-11-18,
//! "option D"): the name the app really asked for, learned from the
//! D-Bus filter's own record, is allowed when nobody on this computer uses
//! it. Before, SAM guessed the name from the menu file; a wrong guess left
//! four apps of the night run unable to start and 21 without single
//! instance, media keys or tray icons.
//!
//! Every start checks the fixed rules for every name the app may own (a
//! name of an installed app, a desktop protocol, a service that starts on
//! demand, another SAM app's); a name the app asks for is learned only if
//! it also is not in use right now.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sam_core::model::AppEntry;
use sam_core::permissions::{is_bus_name, is_media_player_name, refuse_own_name};
use sam_core::{HostInfo, Paths};

/// What a name is checked against.
#[derive(Debug, Default, Clone)]
pub struct NameCheck {
    /// Services on this computer that start on demand.
    pub activatable: BTreeSet<String>,
    /// The ids of the installed apps' menu entries (`org.gnome.Terminal`).
    pub desktop_ids: BTreeSet<String>,
    /// Names other apps in SAM may own.
    pub others: BTreeSet<String>,
    /// The person's session bus, to ask whether a name is in use now.
    pub bus: Option<String>,
    /// The app has the media controls switch (its own player's name).
    pub media: bool,
}

impl NameCheck {
    /// The check for `app` on this computer.
    pub fn for_app(app: &AppEntry, host: &HostInfo, paths: &Paths) -> NameCheck {
        let others = sam_storage::Registry::new(paths)
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.id != app.id)
            .flat_map(|e| e.profile.permissions.dbus.session.own)
            .collect();
        NameCheck {
            activatable: sam_core::host::activatable_bus_names(&host.home),
            desktop_ids: desktop_ids(&host.home),
            others,
            bus: host.sockets.dbus_session_address.clone(),
            media: app.profile.permissions.integrations.media_controls,
        }
    }

    /// Why the app may not own `name` at a start, if it may not: the rules
    /// that hold whether or not the name is in use right now.
    pub fn refused(&self, name: &str) -> Option<String> {
        let wildcard = name.ends_with('*');
        if !wildcard && !is_bus_name(name) {
            return Some(sam_core::i18n::trf(
                "{name} is not a valid bus name",
                &[("name", &name)],
            ));
        }
        if let Some(why) = refuse_own_name(name, &self.activatable) {
            return Some(why);
        }
        if is_media_player_name(name) && !self.media {
            return Some(sam_core::i18n::trf(
                "{name} is a media player's name; the app may own it only with the media controls switch",
                &[("name", &name)],
            ));
        }
        let prefix = name.trim_end_matches('*').trim_end_matches('.');
        if let Some(id) = self.desktop_ids.iter().find(|id| {
            *id == prefix
                || id.starts_with(&format!("{prefix}."))
                || prefix.starts_with(&format!("{id}."))
                || (wildcard && id.starts_with(prefix))
        }) {
            return Some(sam_core::i18n::trf(
                "{name} belongs to {id}, an app installed on this computer; owning it would take its messages",
                &[("name", &name), ("id", id)],
            ));
        }
        if self.others.contains(name) {
            return Some(sam_core::i18n::trf(
                "another app in SAM may own {name}",
                &[("name", &name)],
            ));
        }
        None
    }

    /// Why a name the app asked for is not learned, if it is not: the
    /// rules of [`NameCheck::refused`], and it must not be in use right now.
    pub fn not_learned(&self, name: &str) -> Option<String> {
        if name.ends_with('*') {
            return Some(sam_core::i18n::trf(
                "{name} is a pattern, not a name",
                &[("name", &name)],
            ));
        }
        if let Some(why) = self.refused(name) {
            return Some(why);
        }
        let in_use = self.bus.as_deref().is_some_and(|bus| {
            crate::dbus_check::name_reachable(bus, name, Duration::from_secs(2)).unwrap_or(true)
        });
        in_use.then(|| {
            sam_core::i18n::trf(
                "{name} is in use on this computer right now",
                &[("name", &name)],
            )
        })
    }
}

/// The ids of the installed menu entries (file names without `.desktop`;
/// in a subfolder, joined with `-` as the menu does), in the person's and
/// the system's application folders. Only names are read.
pub fn desktop_ids(home: &Path) -> BTreeSet<String> {
    desktop_ids_in(
        home,
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
        std::env::var("XDG_DATA_DIRS").ok(),
    )
}

/// [`desktop_ids`] with the data folders given.
fn desktop_ids_in(
    home: &Path,
    data_home: Option<PathBuf>,
    data_dirs: Option<String>,
) -> BTreeSet<String> {
    let mut dirs: Vec<PathBuf> = vec![home.join(".local/share/applications")];
    if let Some(d) = data_home.filter(|d| d.is_absolute()) {
        dirs.push(d.join("applications"));
    }
    let data = data_dirs
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    dirs.extend(
        data.split(':')
            .filter(|d| d.starts_with('/'))
            .map(|d| Path::new(d).join("applications")),
    );
    let mut ids = BTreeSet::new();
    for d in dirs {
        collect_ids(&d, "", &mut ids, 0);
    }
    ids
}

fn collect_ids(dir: &Path, prefix: &str, ids: &mut BTreeSet<String>, depth: u32) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let kind = e.file_type();
        if kind.as_ref().is_ok_and(|t| t.is_dir()) && depth < 2 {
            collect_ids(&e.path(), &format!("{prefix}{name}-"), ids, depth + 1);
        } else if let Some(id) = name.strip_suffix(".desktop") {
            ids.insert(format!("{prefix}{id}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check() -> NameCheck {
        NameCheck {
            activatable: ["org.kde.kwalletd6".to_string()].into(),
            desktop_ids: [
                "org.gnome.Terminal".to_string(),
                "org.kde.konsole".to_string(),
            ]
            .into(),
            others: ["org.example.Other".to_string()].into(),
            bus: None,
            media: false,
        }
    }

    /// A name the app asks for is refused when it belongs to an installed
    /// app (audit D-M6: a terminal's name runs host commands), to a desktop
    /// protocol, to an on-demand service (also through a wildcard, L-F13),
    /// or to another app in SAM; its own name passes; a media player's
    /// name passes with the media switch (L-Q1).
    #[test]
    fn a_name_is_allowed_only_when_nobody_else_has_it() {
        let mut c = check();
        for bad in [
            "org.gnome.Terminal",
            "org.gnome.Terminal.Factory",
            "org.kde.konsole",
            "org.kde.*",
            "org.freedesktop.Notifications",
            "org.kde.kwalletd6",
            "org.example.Other",
            "org.mpris.MediaPlayer2.myplayer",
            "org.mpris.MediaPlayer2",
            "x",
            ":1.42",
            "org.example.9bad",
        ] {
            assert!(c.refused(bad).is_some(), "{bad}");
        }
        // A prefix of installed apps' ids is theirs too.
        assert!(c.refused("org.gnome").is_some());
        for good in ["org.example.Mine", "com.github.someone.App"] {
            assert_eq!(c.refused(good), None, "{good}");
            assert_eq!(c.not_learned(good), None, "{good}");
        }
        // A wildcard you add for the app's own names is fine.
        assert_eq!(c.refused("org.example.App.*"), None);
        assert_eq!(c.refused("org.example.my_app-2"), None);
        c.media = true;
        assert_eq!(c.refused("org.mpris.MediaPlayer2.myplayer"), None);
        assert!(
            c.refused("org.mpris.MediaPlayer2.*").is_some(),
            "never the wildcard"
        );
        assert!(
            c.not_learned("org.example.*").is_some(),
            "a pattern is never learned"
        );
    }

    /// Menu entry ids come from file names, subfolders joined with `-`;
    /// only `.desktop` files count.
    #[test]
    fn menu_ids_are_the_file_names() {
        let t = tempfile::tempdir().unwrap();
        let apps = t.path().join(".local/share/applications");
        std::fs::create_dir_all(apps.join("kde4")).unwrap();
        std::fs::write(apps.join("org.gnome.Terminal.desktop"), "").unwrap();
        std::fs::write(apps.join("kde4/konsole.desktop"), "").unwrap();
        std::fs::write(apps.join("readme.txt"), "").unwrap();
        std::fs::create_dir_all(apps.join("a/b/c")).unwrap();
        std::fs::write(apps.join("a/b/two.desktop"), "").unwrap();
        std::fs::write(apps.join("a/b/c/three.desktop"), "").unwrap();
        // The system's folders as XDG_DATA_DIRS names them; an empty value
        // means the usual ones.
        let sys = t.path().join("sys");
        std::fs::create_dir_all(sys.join("applications")).unwrap();
        std::fs::write(sys.join("applications/org.example.Sys.desktop"), "").unwrap();
        let ids = desktop_ids_in(t.path(), None, Some(sys.display().to_string()));
        assert!(ids.contains("org.gnome.Terminal"), "{ids:?}");
        assert!(ids.contains("kde4-konsole"), "{ids:?}");
        assert!(ids.contains("a-b-two"), "two folders deep: {ids:?}");
        assert!(
            !ids.iter().any(|i| i.contains("three")),
            "not three: {ids:?}"
        );
        assert!(ids.contains("org.example.Sys"), "{ids:?}");
        assert!(!ids.iter().any(|i| i.contains("readme")));
        let usual = desktop_ids_in(t.path(), None, Some(String::new()));
        assert!(!usual.contains("org.example.Sys"));
        // XDG_DATA_HOME elsewhere.
        let data = t.path().join("data");
        std::fs::create_dir_all(data.join("applications")).unwrap();
        std::fs::write(data.join("applications/org.example.Mine.desktop"), "").unwrap();
        assert!(desktop_ids_in(t.path(), Some(data), None).contains("org.example.Mine"));
    }
}
