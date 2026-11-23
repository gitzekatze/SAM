//! sam-profile: category inference, recommended profiles, the user's
//! presets, checks of changed settings, and the permission tags.

pub mod tags;

use anyhow::Result;
use sam_core::permissions::*;
use sam_core::risk::{assess, RiskLevel};
use sam_core::{AppEntry, AppImageMetadata, DependencyReport, Paths, Preset};
use sam_storage::PresetStore;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Browser,
    MediaPlayer,
    ImageEditor,
    VideoEditor,
    AudioEditor,
    Game,
    TextEditor,
    Office,
    Terminal,
    Development,
    Communication,
    Utility,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Browser => "browser",
            Category::MediaPlayer => "media-player",
            Category::ImageEditor => "image-editor",
            Category::VideoEditor => "video-editor",
            Category::AudioEditor => "audio-editor",
            Category::Game => "game",
            Category::TextEditor => "text-editor",
            Category::Office => "office",
            Category::Terminal => "terminal",
            Category::Development => "development",
            Category::Communication => "communication",
            Category::Utility => "utility",
        }
    }
    /// The category's name, in the user's language.
    pub fn label(self) -> String {
        sam_core::i18n::tr(match self {
            Category::Browser => sam_core::i18n::n_("Browser"),
            Category::MediaPlayer => sam_core::i18n::n_("Media player"),
            Category::ImageEditor => sam_core::i18n::n_("Image editor"),
            Category::VideoEditor => sam_core::i18n::n_("Video editor"),
            Category::AudioEditor => sam_core::i18n::n_("Audio editor"),
            Category::Game => sam_core::i18n::n_("Game"),
            Category::TextEditor => sam_core::i18n::n_("Text editor"),
            Category::Office => sam_core::i18n::n_("Office"),
            Category::Terminal => sam_core::i18n::n_("Terminal"),
            Category::Development => sam_core::i18n::n_("Development"),
            Category::Communication => sam_core::i18n::n_("Communication"),
            Category::Utility => sam_core::i18n::n_("Utility"),
        })
    }
    pub fn parse(s: &str) -> Option<Self> {
        ALL_CATEGORIES.iter().copied().find(|c| c.as_str() == s)
    }
    /// Whether apps in this category normally need the network.
    pub fn needs_network(self) -> bool {
        matches!(self, Category::Browser | Category::Communication)
    }
}

pub const ALL_CATEGORIES: [Category; 12] = [
    Category::Browser,
    Category::MediaPlayer,
    Category::ImageEditor,
    Category::VideoEditor,
    Category::AudioEditor,
    Category::Game,
    Category::TextEditor,
    Category::Office,
    Category::Terminal,
    Category::Development,
    Category::Communication,
    Category::Utility,
];

/// Infer a category from desktop categories, name and binary.
pub fn infer_category(
    md: &AppImageMetadata,
    file_name: &str,
    report: Option<&DependencyReport>,
) -> Category {
    let cats: Vec<String> = md.categories.iter().map(|c| c.to_lowercase()).collect();
    let has = |c: &str| cats.iter().any(|x| x == c);
    let text = format!("{} {} {} {}", md.name, md.exec, file_name, md.comment).to_lowercase();
    let word = |w: &str| text.contains(w);

    // Desktop categories (freedesktop menu spec) first.
    if has("webbrowser") {
        return Category::Browser;
    }
    if has("terminalemulator") {
        return Category::Terminal;
    }
    if has("game") {
        return Category::Game;
    }
    if has("instantmessaging")
        || has("chat")
        || has("email")
        || has("videoconference")
        || has("telephony")
    {
        return Category::Communication;
    }
    if has("audiovideoediting") && (has("video") || word("video")) {
        return Category::VideoEditor;
    }
    if has("audiovideoediting")
        || (has("audio") && (has("recorder") || has("sequencer") || has("midi")))
    {
        return Category::AudioEditor;
    }
    let graphics = [
        "graphics",
        "rastergraphics",
        "vectorgraphics",
        "2dgraphics",
        "3dgraphics",
        "photography",
    ];
    let has_graphics = graphics.iter().any(|c| has(c));
    // A bare `AudioVideo` next to graphics categories is a creative tool, not a player.
    if has("player")
        || has("tv")
        || (has("audiovideo") && !has("audiovideoediting") && !has_graphics)
    {
        return Category::MediaPlayer;
    }
    if has_graphics {
        return Category::ImageEditor;
    }
    if has("office") || has("wordprocessor") || has("spreadsheet") || has("presentation") {
        return Category::Office;
    }
    if has("texteditor") {
        return Category::TextEditor;
    }
    if has("development") || has("ide") {
        return Category::Development;
    }
    if has("network") && (has("filetransfer") || has("p2p")) {
        return Category::Communication;
    }

    // Name heuristics.
    for (words, cat) in [
        (
            &[
                "browser",
                "firefox",
                "chromium",
                "librewolf",
                "brave",
                "vivaldi",
                "waterfox",
                "floorp",
            ][..],
            Category::Browser,
        ),
        (
            &[
                "discord",
                "signal",
                "telegram",
                "slack",
                "element",
                "zoom",
                "teams",
                "thunderbird",
                "whatsapp",
                "e-mail",
                "email",
                "mail client",
                "tuta",
                "proton mail",
            ][..],
            Category::Communication,
        ),
        (
            &[
                "vlc",
                "mpv",
                "player",
                "jellyfin",
                "spotify",
                "strawberry",
                "audacious",
                "celluloid",
            ][..],
            Category::MediaPlayer,
        ),
        (
            &[
                "kdenlive",
                "shotcut",
                "olive",
                "openshot",
                "davinci",
                "flowblade",
            ][..],
            Category::VideoEditor,
        ),
        (
            &["audacity", "ardour", "lmms", "tenacity", "reaper", "bitwig"][..],
            Category::AudioEditor,
        ),
        (
            &[
                "krita",
                "gimp",
                "inkscape",
                "darktable",
                "rawtherapee",
                "pinta",
                "blender",
                "photo",
            ][..],
            Category::ImageEditor,
        ),
        (
            &[
                "game",
                "minecraft",
                "steam",
                "heroic",
                "lutris",
                "emulator",
                "retroarch",
                "dolphin-emu",
                "pcsx",
                "rpcs3",
                "yuzu",
                "ryujinx",
            ][..],
            Category::Game,
        ),
        (
            &[
                "libreoffice",
                "onlyoffice",
                "office",
                "writer",
                "calc",
                "obsidian",
                "logseq",
                "zotero",
                "joplin",
                "notes",
            ][..],
            Category::Office,
        ),
        (
            &[
                "code", "vscodium", "editor", "notepad", "kate", "sublime", "zed", "neovim",
                "lapce",
            ][..],
            Category::TextEditor,
        ),
        (
            &["terminal", "kitty", "alacritty", "wezterm", "konsole"][..],
            Category::Terminal,
        ),
        (
            &[
                "studio",
                "ide",
                "idea",
                "pycharm",
                "godot",
                "arduino",
                "qtcreator",
            ][..],
            Category::Development,
        ),
    ] {
        if words.iter().any(|w| word(w)) {
            return cat;
        }
    }
    // `Network` alone (no more specific category) marks an app whose job
    // needs the network: mail clients, feed readers, sync tools.
    if has("network") {
        return Category::Communication;
    }
    if let Some(r) = report {
        if matches!(r.requirements.toolkit.as_str(), "SDL2" | "SDL3") {
            return Category::Game;
        }
    }
    Category::Utility
}

#[derive(Debug, Clone, Serialize)]
pub struct Recommendation {
    pub category: Category,
    pub permissions: PermissionSet,
    pub notes: Vec<String>,
}

fn base_for(cat: Category) -> PermissionSet {
    let mut p = PermissionSet::strict_gui();
    let fs = &mut p.filesystem;
    match cat {
        Category::Browser => {
            p.network.mode = NetworkMode::Full;
            fs.downloads = Access::Rw;
            p.audio.enabled = true;
            p.devices.gpu = true;
        }
        Category::MediaPlayer => {
            fs.music = Access::Rw;
            fs.videos = Access::Rw;
            fs.pictures = Access::Ro;
            p.audio.enabled = true;
            p.devices.gpu = true;
        }
        Category::ImageEditor => {
            fs.pictures = Access::Rw;
            fs.documents = Access::Rw;
            p.devices.gpu = true;
        }
        Category::VideoEditor => {
            fs.videos = Access::Rw;
            fs.music = Access::Ro;
            fs.pictures = Access::Ro;
            p.audio.enabled = true;
            p.devices.gpu = true;
        }
        Category::AudioEditor => {
            fs.music = Access::Rw;
            fs.documents = Access::Rw;
            p.audio.enabled = true;
        }
        Category::Game => {
            p.devices.gpu = true;
            p.devices.gamepads = true;
            p.audio.enabled = true;
        }
        Category::TextEditor | Category::Office => {
            fs.documents = Access::Rw;
        }
        Category::Development => {
            // Not ~/Projects: the AppImage names its category itself, and a
            // writable project folder lets an app plant code that runs
            // outside the sandbox (git hooks, .envrc). The person can grant
            // one as an extra folder.
            fs.documents = Access::Rw;
        }
        Category::Terminal => {
            fs.documents = Access::Rw;
        }
        Category::Communication => {
            p.network.mode = NetworkMode::Full;
            fs.downloads = Access::Rw;
            p.audio.enabled = true;
            p.devices.gpu = true;
        }
        Category::Utility => {}
    }
    p
}

/// Generate the recommended profile for an app.
/// The app's own D-Bus names: its desktop file ID and its window class
/// (`StartupWMClass`, which GTK and Flutter apps set to their application
/// ID) when they are reverse-DNS names (`com.example.App`). Names of the
/// D-Bus protocols and services SAM treats as dangerous are left out here;
/// services this computer starts on demand are refused at every start
/// (`refuse_own_name`).
pub fn own_bus_names(md: &AppImageMetadata) -> Vec<String> {
    let id = md.desktop_file.as_deref().and_then(|f| {
        std::path::Path::new(f)
            .file_name()?
            .to_str()?
            .strip_suffix(".desktop")
            .map(str::to_string)
    });
    let mut names = Vec::new();
    for cand in id.into_iter().chain(Some(md.startup_wm_class.clone())) {
        let parts: Vec<&str> = cand.split('.').collect();
        let valid = parts.len() >= 3
            && cand.len() <= 200
            && parts.iter().all(|p| {
                !p.is_empty()
                    && !p.starts_with(|c: char| c.is_ascii_digit())
                    && p.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            });
        if valid
            && sam_core::permissions::refuse_own_name(&cand, &Default::default()).is_none()
            && !names.contains(&cand)
        {
            names.push(cand);
        }
    }
    names
}

pub fn recommend(
    md: &AppImageMetadata,
    file_name: &str,
    report: Option<&DependencyReport>,
) -> Recommendation {
    let category = infer_category(md, file_name, report);
    let mut p = base_for(category);
    let mut notes = vec![sam_core::i18n::trf(
        "Category: {category} (from desktop metadata and name)",
        &[("category", &category.label())],
    )];

    if let Some(r) = report {
        let req = &r.requirements;
        if req.gpu && !p.devices.gpu {
            p.devices.gpu = true;
            notes.push(sam_core::i18n::tr(
                "GPU enabled: the app links OpenGL/Vulkan libraries",
            ));
        }
        if req.audio && !p.audio.enabled {
            p.audio.enabled = true;
            notes.push(sam_core::i18n::tr(
                "Audio enabled: the app links audio libraries",
            ));
        }
        if req.x11 && !req.wayland {
            p.display.x11 = true;
            notes.push(sam_core::i18n::tr(
                "X11 enabled: no Wayland support detected (uses XWayland)",
            ));
        } else if req.x11
            && (req.java || matches!(req.toolkit.as_str(), "Electron" | "Java" | "Unknown"))
        {
            // Java's AWT and JavaFX draw through X11 only, whatever toolkit
            // they load (JavaFX uses GTK on X11).
            p.display.x11 = true;
            notes.push(sam_core::i18n::trf(
                "X11 enabled: {toolkit} apps usually need XWayland",
                &[(
                    "toolkit",
                    &if req.java {
                        "Java"
                    } else {
                        req.toolkit.as_str()
                    },
                )],
            ));
        }
        if !req.x11 && !req.wayland && r.elf_count > 0 && req.toolkit == "Unknown" {
            // Nothing linked: the app loads its graphics stack at start
            // (Rust/wgpu, game engines). Those need the GPU to open a window.
            if !p.devices.gpu {
                p.devices.gpu = true;
                notes.push(sam_core::i18n::tr("GPU enabled: the app loads its graphics libraries at start (common for Rust apps and game engines)"));
            }
            notes.push(sam_core::i18n::tr(
                "No display libraries detected; if the window does not appear, enable X11",
            ));
        }
        if req.network && p.network.mode == NetworkMode::None {
            if category == Category::Game {
                p.network.mode = NetworkMode::Full;
                notes.push(sam_core::i18n::tr(
                    "Network enabled: game links networking libraries (multiplayer is likely)",
                ));
            } else if !needs_network_by_purpose(md, file_name) {
                notes.push(sam_core::i18n::tr("The app links networking libraries but its category does not need the network; network stays off"));
            }
        }
        if req.electron {
            p.advanced.allow_userns = true;
            notes.push(sam_core::i18n::tr(
                "Electron app: nested namespaces allowed so Chromium's own sandbox can start",
            ));
        } else if req.nested_sandbox {
            p.advanced.allow_userns = true;
            notes.push(sam_core::i18n::tr("Nested namespaces allowed: the app's web engine (Chromium or WebKit) starts its own sandbox"));
        }
        // Only when the program the app starts is 32-bit itself: the
        // architecture of an app started by a script is that of most of its
        // files, so 32-bit decoys next to a 64-bit program switched the
        // filter off (audit M5/I-F4). Otherwise the filter stays on, and a
        // real 32-bit app that fails gets the step in its repair ladder.
        if r.arch == "i686" && !r.entry_is_script && r.entry_binary.is_some() {
            // The syscall filter is built for 64-bit programs; a 32-bit one
            // is stopped by its architecture check at the first call.
            p.advanced.seccomp_baseline = false;
            notes.push(sam_core::i18n::tr("32-bit app: the baseline syscall filter is off, because it only supports 64-bit programs and would stop the app"));
        }
        if r.compatibility != sam_core::Compatibility::Good {
            notes.push(sam_core::i18n::tr(
                "Compatibility issues were detected; see the dependency report",
            ));
        }
    }
    // Terminal programs run in the terminal that starts them: no window,
    // no graphics, no desktop services.
    if md.terminal {
        p.display.wayland = false;
        p.display.x11 = false;
        p.devices.gpu = false;
        p.dbus.session.mode = sam_core::permissions::DbusMode::None;
        notes.push(sam_core::i18n::tr(
            "Terminal program: no display, GPU or desktop services; it runs in a terminal window",
        ));
    }
    if p.network.mode == NetworkMode::None && needs_network_by_purpose(md, file_name) {
        p.network.mode = NetworkMode::Full;
        notes.push(sam_core::i18n::tr("Network enabled: this looks like an AI, web-UI or server app, which talks to models or services over the network. If it only uses local models, 'This computer only' blocks the internet but keeps local servers reachable."));
    }
    // Desktop integrations.
    if category == Category::MediaPlayer {
        // Players only need to read the files they are given.
        p.filesystem.opened_files = Access::Ro;
        p.integrations.media_controls = true;
        notes.push(sam_core::i18n::tr(
            "Media controls enabled: media keys, 'now playing' and keeping the screen awake",
        ));
    }
    if XDG_DIR_KEYS
        .iter()
        .any(|k| p.filesystem.xdg_access(k).is_granted())
    {
        p.integrations.file_manager = true;
    }
    // The app may own the D-Bus name of its own ID (as Flatpak allows): many
    // apps register it to hand a second start over to the first one.
    for name in own_bus_names(md) {
        if !p.dbus.session.own.contains(&name) {
            notes.push(sam_core::i18n::trf(
                "D-Bus: may own its own name {name}",
                &[("name", &name)],
            ));
            p.dbus.session.own.push(name);
        }
    }
    Recommendation {
        category,
        permissions: p,
        notes,
    }
}

/// Apps whose purpose is talking to models, servers or services: local AI
/// tools, web UIs, API routers, sync clients. Their category is often just
/// "Utility", so without this they would start offline and seem broken.
pub fn needs_network_by_purpose(md: &AppImageMetadata, file_name: &str) -> bool {
    let text = format!(" {} {} {} {} ", md.name, md.comment, md.exec, file_name).to_lowercase();
    let text: String = text
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    let words = [
        " llm",
        " llms ",
        " ai ",
        " gpt",
        " ollama",
        " openai",
        " webui ",
        " web ui ",
        " comfyui",
        " stable diffusion",
        " diffusion ",
        " server ",
        " api ",
        " router ",
        " proxy ",
        " sync ",
        " cloud ",
        " client ",
        " chat ",
        " assistant ",
        " model ",
        " models ",
        " inference ",
    ];
    if words.iter().any(|w| text.contains(w)) {
        return true;
    }
    // Compound names: "FreeLLMAPI", "OpenWebUI", "LocalGPT".
    text.split_whitespace().any(|t| {
        (t.contains("llm") && !t.contains("ullm"))
            || t.ends_with("api")
            || t.ends_with("gpt")
            || t.ends_with("webui")
    })
}

/// Compatibility mode: broader access for apps that otherwise break.
pub fn compatibility_profile(base: &PermissionSet) -> PermissionSet {
    let mut p = base.clone();
    p.advanced.host_runtime = HostRuntime::Full;
    p.advanced.host_themes = true;
    p.devices.gpu = true;
    p.display.x11 = true;
    p.display.wayland = true;
    p.audio.enabled = true;
    p.dbus.session.mode = DbusMode::Full;
    p.network.mode = NetworkMode::Full;
    p
}

/// Translated where it is shown (`tr`).
pub const COMPAT_WARNING: &str = sam_core::i18n::n_(
    "Compatibility mode gives broad access for apps that work no other way: full network, all of /usr and the full session bus, through which the app can start programs outside its sandbox. Use it only for apps you trust.",
);

/// The user's own presets. SAM ships none: the recommendation already
/// fits each app, and a ready-made category set would only replace it with
/// a guess.
pub fn all_presets(paths: &Paths) -> Result<Vec<Preset>> {
    PresetStore::new(paths).list()
}

pub fn find_preset(paths: &Paths, name: &str) -> Result<Option<Preset>> {
    Ok(all_presets(paths)?
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name)))
}

/// A new preset starts from SAM's strictest settings for a window app.
pub fn preset_template() -> Preset {
    let permissions = PermissionSet::strict_gui();
    Preset {
        risk: assess(&permissions).level,
        permissions,
        ..Default::default()
    }
}

/// What SAM's analysis says about new settings for an app: what the app
/// would lose that it likely needs, and what dangerous access it would gain.
/// Used before a preset or a change on the Permissions page is applied.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ChangeCheck {
    /// Things the app likely needs to work that the new settings remove
    /// ("network access", "X11 display", …): the app may stop working.
    pub removes_needed: Vec<String>,
    /// Folders the app was recommended that the new settings hide. The app
    /// keeps working, but cannot open or save files there.
    pub removes_folders: Vec<String>,
    /// High-risk permissions the new settings add compared to the current profile.
    pub adds_dangerous: Vec<String>,
    pub risk_before: RiskLevel,
    pub risk_after: RiskLevel,
}

impl ChangeCheck {
    pub fn needs_confirmation(&self) -> bool {
        !self.removes_needed.is_empty()
            || !self.removes_folders.is_empty()
            || !self.adds_dangerous.is_empty()
    }
}

/// Compares new settings against what the app likely needs (its
/// recommendation) and against its current profile.
pub fn check_change(app: &AppEntry, new: &PermissionSet) -> ChangeCheck {
    let need = &app.recommended;
    let cur = &app.profile.permissions;
    let mut c = ChangeCheck {
        risk_before: assess(cur).level,
        risk_after: assess(new).level,
        ..Default::default()
    };
    let mut removed = |cond: bool, what: &str| {
        if cond {
            c.removes_needed.push(what.to_string());
        }
    };
    removed(need.devices.gpu && !new.devices.gpu, "GPU acceleration");
    removed(need.audio.enabled && !new.audio.enabled, "sound");
    removed(
        need.network.mode == NetworkMode::Full && new.network.mode != NetworkMode::Full,
        "network access",
    );
    removed(
        need.network.mode == NetworkMode::Localhost && new.network.mode == NetworkMode::None,
        &sam_core::i18n::tr("connections to this computer"),
    );
    removed(
        need.display.x11
            && !new.display.x11
            && !(need.display.wayland && new.display.wayland && !needs_x11_only(app)),
        "X11 display",
    );
    removed(
        !new.display.x11 && !new.display.wayland && (need.display.x11 || need.display.wayland),
        &sam_core::i18n::tr("any display access"),
    );
    removed(
        need.dbus.session.mode != DbusMode::None && new.dbus.session.mode == DbusMode::None,
        "desktop services (D-Bus)",
    );
    for key in XDG_DIR_KEYS {
        if need.filesystem.xdg_access(key).is_granted()
            && !new.filesystem.xdg_access(key).is_granted()
        {
            c.removes_folders.push(format!("{key} folder"));
        }
    }

    for item in sam_core::risk::new_risks(cur, new) {
        c.adds_dangerous.push(item.title);
    }
    c
}

fn needs_x11_only(app: &AppEntry) -> bool {
    app.detection
        .as_ref()
        .is_some_and(|d| d.requirements.x11 && !d.requirements.wayland)
}

/// A change made from a copy that may be old: `from` is what the change
/// was made on, `to` what it should become. Only the settings that differ
/// between the two are applied to `current`, so a change made elsewhere in
/// the meantime (in the other view of the window, on the command line, by
/// a repair step) stays (audit G-F4: whole sets were written back). A
/// setting that was changed both here and elsewhere, to different values,
/// is not decided silently: the result lists those settings.
pub fn apply_change(
    current: &PermissionSet,
    from: &PermissionSet,
    to: &PermissionSet,
) -> Result<std::result::Result<PermissionSet, Vec<String>>> {
    let mut cur = serde_json::to_value(current)?;
    let (f, t) = (serde_json::to_value(from)?, serde_json::to_value(to)?);
    let mut clashes = Vec::new();
    merge_into(&mut cur, &f, &t, "", &mut clashes);
    if !clashes.is_empty() {
        return Ok(Err(clashes));
    }
    Ok(Ok(serde_json::from_value(cur)?))
}

/// Settings are compared one by one: a nested object goes one level
/// deeper, anything else (a value, a list) is one setting.
fn merge_into(
    cur: &mut serde_json::Value,
    from: &serde_json::Value,
    to: &serde_json::Value,
    path: &str,
    clashes: &mut Vec<String>,
) {
    use serde_json::Value;
    if from == to {
        return;
    }
    if let (Value::Object(f), Value::Object(t), Value::Object(c)) = (from, to, &mut *cur) {
        let keys: std::collections::BTreeSet<&String> = f.keys().chain(t.keys()).collect();
        for k in keys {
            let null = Value::Null;
            let (fv, tv) = (f.get(k).unwrap_or(&null), t.get(k).unwrap_or(&null));
            let sub = if path.is_empty() {
                k.clone()
            } else {
                format!("{path}.{k}")
            };
            // A key the saved form leaves out (a setting at its default)
            // stays out: never written back as null, which no setting reads.
            let had = c.contains_key(k.as_str());
            let mut cv = c.remove(k.as_str()).unwrap_or(Value::Null);
            merge_into(&mut cv, fv, tv, &sub, clashes);
            if !cv.is_null() || (had && t.contains_key(k.as_str())) {
                c.insert(k.clone(), cv);
            }
        }
        return;
    }
    if *cur == *from || *cur == *to {
        *cur = to.clone();
    } else {
        clashes.push(path.to_string());
    }
}

#[cfg(test)]
mod tests {

    /// A setting the saved form leaves out while at its default (Room
    /// service is written only when off) can be changed back: turned off,
    /// then on again from an old copy, it is left out again, never null.
    #[test]
    fn a_left_out_setting_can_be_turned_back_on() {
        use serde_json::json;
        let mut cur = json!({"advanced": {"room_service": false, "x": 1}});
        let from = json!({"advanced": {"room_service": false, "x": 1}});
        let to = json!({"advanced": {"x": 1}});
        let mut clashes = Vec::new();
        super::merge_into(&mut cur, &from, &to, "", &mut clashes);
        assert!(clashes.is_empty());
        assert_eq!(cur, json!({"advanced": {"x": 1}}));
        // Keys nobody changed are not made up either.
        let mut cur = json!({"a": 1});
        let from = json!({"a": 1, "b": 2});
        let to = json!({"a": 2, "b": 2});
        super::merge_into(&mut cur, &from, &to, "", &mut clashes);
        assert_eq!(cur, json!({"a": 2}));
        // Turned off from a record that leaves it out: written as off.
        let mut cur = json!({"advanced": {"x": 1}});
        let from = json!({"advanced": {"x": 1}});
        let to = json!({"advanced": {"room_service": false, "x": 1}});
        super::merge_into(&mut cur, &from, &to, "", &mut clashes);
        assert_eq!(cur, json!({"advanced": {"room_service": false, "x": 1}}));
        let set: sam_core::permissions::PermissionSet =
            serde_json::from_value(json!({"advanced": {}})).unwrap_or_default();
        assert!(set.advanced.room_service);
    }

    /// A change made on an old copy applies only what it changed: another
    /// setting changed meanwhile stays; the same setting changed elsewhere
    /// to another value is named, not overwritten (audit G-F4).
    #[test]
    fn a_change_from_an_old_copy_keeps_what_changed_meanwhile() {
        let from = PermissionSet::strict_gui();
        let mut current = from.clone();
        current.devices.webcam = true; // changed elsewhere meanwhile
        let mut to = from.clone();
        to.network.mode = NetworkMode::Full; // the change made here
        let merged = apply_change(&current, &from, &to).unwrap().unwrap();
        assert!(merged.devices.webcam, "the other change stays");
        assert_eq!(
            merged.network.mode,
            NetworkMode::Full,
            "this change is made"
        );
        // Undo is a change too: back from `to` to `from` on what is there now.
        let undone = apply_change(&merged, &to, &from).unwrap().unwrap();
        assert!(undone.devices.webcam, "undo keeps the other change");
        assert_eq!(undone.network.mode, from.network.mode);
        // The same setting changed elsewhere to a third value: named.
        let mut other = current.clone();
        other.network.mode = NetworkMode::Localhost;
        let clash = apply_change(&other, &from, &to).unwrap().unwrap_err();
        assert_eq!(clash, vec!["network.mode".to_string()]);
        // Changed elsewhere to the same value: nothing to decide.
        let mut same = from.clone();
        same.network.mode = NetworkMode::Full;
        assert_eq!(apply_change(&same, &from, &to).unwrap().unwrap(), same);
        // A list counts as one setting.
        let mut with_folder = from.clone();
        with_folder.filesystem.custom_read.push("~/Music".into());
        let merged = apply_change(&current, &from, &with_folder)
            .unwrap()
            .unwrap();
        assert_eq!(merged.filesystem.custom_read, vec!["~/Music".to_string()]);
        assert!(merged.devices.webcam);
    }

    /// Terminal programs get no display, GPU or desktop bus access.
    #[test]
    fn terminal_programs_get_no_display() {
        let md = AppImageMetadata {
            name: "Neovim".into(),
            categories: vec!["Utility".into(), "TextEditor".into()],
            terminal: true,
            ..Default::default()
        };
        let r = recommend(&md, "nvim.appimage", None);
        assert!(
            !r.permissions.display.wayland
                && !r.permissions.display.x11
                && !r.permissions.devices.gpu
        );
        assert_eq!(
            r.permissions.dbus.session.mode,
            sam_core::permissions::DbusMode::None
        );
    }

    use super::*;
    use sam_core::Requirements;

    /// An app that calls itself a development tool gets Documents, but no
    /// writable project folder: the category is the AppImage's own claim, and
    /// a project folder lets an app plant code that runs outside the sandbox
    /// (git hooks, .envrc).
    #[test]
    fn a_development_tool_gets_no_project_folder_on_its_own_word() {
        let r = recommend(
            &md("Some IDE", &["Development", "IDE"]),
            "ide.appimage",
            None,
        );
        assert_eq!(
            r.category,
            Category::Development,
            "recognized as a development tool"
        );
        assert_eq!(r.permissions.filesystem.documents, Access::Rw);
        assert!(
            r.permissions.filesystem.custom_write.is_empty(),
            "{:?}",
            r.permissions.filesystem.custom_write
        );
        assert!(r.permissions.filesystem.custom_read.is_empty());
    }

    fn md(name: &str, cats: &[&str]) -> AppImageMetadata {
        AppImageMetadata {
            name: name.into(),
            categories: cats.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// The category of an app is recognized from its desktop categories.
    #[test]
    fn the_app_category_is_recognized_from_its_desktop_categories() {
        assert_eq!(
            infer_category(&md("Firefox", &["Network", "WebBrowser"]), "", None),
            Category::Browser
        );
        assert_eq!(
            infer_category(&md("Krita", &["Graphics", "2DGraphics"]), "", None),
            Category::ImageEditor
        );
        assert_eq!(
            infer_category(&md("VLC", &["AudioVideo", "Player"]), "", None),
            Category::MediaPlayer
        );
        assert_eq!(
            infer_category(
                &md("Kdenlive", &["AudioVideo", "AudioVideoEditing", "Video"]),
                "",
                None
            ),
            Category::VideoEditor
        );
        assert_eq!(
            infer_category(&md("Thing", &[]), "SuperTux-0.6.AppImage", None),
            Category::Utility
        );
        assert_eq!(
            infer_category(&md("SuperTux", &["Game"]), "", None),
            Category::Game
        );
        assert_eq!(
            infer_category(&md("Tuta", &["Network"]), "", None),
            Category::Communication
        );
        assert!(needs_network_by_purpose(
            &md("Open WebUI", &[]),
            "open-webui_x86_64.AppImage"
        ));
        assert!(
            needs_network_by_purpose(&md("FreeLLMAPI", &[]), ""),
            "LLM in name"
        );
        assert!(!needs_network_by_purpose(
            &md("ZFontManager", &[]),
            "ZFontManager_0.9.0_amd64.AppImage"
        ));
        assert!(!needs_network_by_purpose(
            &md("Krita", &["Graphics"]),
            "krita-5.2.AppImage"
        ));
        assert_eq!(
            infer_category(
                &md("Comfy Desktop", &["AudioVideo", "Graphics", "3DGraphics"]),
                "",
                None
            ),
            Category::ImageEditor
        );
        assert_eq!(
            infer_category(&md("Obsidian", &[]), "", None),
            Category::Office
        );
    }

    /// Recommended permissions fit the category: a browser gets the network and Downloads, an editor no network.
    #[test]
    fn recommendations_fit_the_category() {
        let r = recommend(&md("Firefox", &["WebBrowser"]), "", None);
        let p = &r.permissions;
        assert_eq!(p.network.mode, NetworkMode::Full);
        assert_eq!(p.filesystem.downloads, Access::Rw);
        assert!(p.audio.enabled && p.devices.gpu && p.display.wayland);
        assert!(!p.filesystem.home);

        let r = recommend(&md("Kate", &["TextEditor"]), "", None);
        assert_eq!(r.permissions.network.mode, NetworkMode::None);
        assert_eq!(r.permissions.filesystem.documents, Access::Rw);
    }

    /// What SAM finds in the app (GPU, X11-only toolkit) adjusts the recommendation.
    #[test]
    fn what_sam_finds_in_the_app_adjusts_the_recommendation() {
        let rep = DependencyReport {
            requirements: Requirements {
                gpu: true,
                x11: true,
                toolkit: "Qt5".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let r = recommend(&md("Tool", &["Utility"]), "", Some(&rep));
        assert!(r.permissions.devices.gpu);
        assert!(r.permissions.display.x11, "X11-only app gets XWayland");
        assert_eq!(r.permissions.network.mode, NetworkMode::None);
    }

    /// The syscall filter is switched off only for an app whose start
    /// program is 32-bit itself: 32-bit files next to a script that starts
    /// a 64-bit program do not switch it off (audit M5/I-F4).
    #[test]
    fn only_a_32_bit_start_program_switches_the_filter_off() {
        let report = |script: bool, entry: Option<&str>| DependencyReport {
            arch: "i686".into(),
            entry_is_script: script,
            entry_binary: entry.map(String::from),
            ..Default::default()
        };
        let filter = |r: DependencyReport| {
            recommend(&md("Game", &["Game"]), "", Some(&r))
                .permissions
                .advanced
                .seccomp_baseline
        };
        assert!(
            !filter(report(false, Some("usr/bin/game32"))),
            "a 32-bit program"
        );
        assert!(
            filter(report(true, Some("AppRun"))),
            "a script, mostly 32-bit files"
        );
        assert!(filter(report(false, None)), "no start program known");
    }

    /// The change check names what an app would lose that it needs, and the dangerous access it would gain.
    #[test]
    fn change_check_flags_removals_and_additions() {
        let recommended = recommend(&md("Firefox", &["WebBrowser"]), "", None).permissions;
        let app = AppEntry {
            profile: sam_core::SandboxProfile {
                permissions: recommended.clone(),
                ..Default::default()
            },
            recommended,
            ..Default::default()
        };
        let mut offline = app.profile.permissions.clone();
        offline.network.mode = NetworkMode::None;
        let c = check_change(&app, &offline);
        assert!(c.removes_needed.iter().any(|s| s == "network access"));
        assert!(c.needs_confirmation());
        assert!(
            !check_change(&app, &app.profile.permissions).needs_confirmation(),
            "no change, nothing to report"
        );

        let app2 = AppEntry {
            recommended: PermissionSet::strict_gui(),
            profile: sam_core::SandboxProfile {
                permissions: PermissionSet::strict_gui(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut x11 = PermissionSet::strict_gui();
        x11.display.x11 = true;
        let c2 = check_change(&app2, &x11);
        assert!(!c2.adds_dangerous.is_empty(), "{:?}", c2.adds_dangerous);
    }

    /// A preset (or any change) that adds a function of a service asks
    /// first, as one that adds the X11 display does (audit D-H2: a preset
    /// with "may call systemd" applied without a question).
    #[test]
    fn a_change_that_adds_a_service_function_asks_first() {
        let mut cur = PermissionSet::strict_gui();
        cur.dbus.session.mode = DbusMode::Filtered;
        let app = AppEntry {
            recommended: cur.clone(),
            profile: sam_core::SandboxProfile {
                permissions: cur.clone(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut new = cur.clone();
        new.dbus.session.calls = vec!["org.freedesktop.systemd1=*".into()];
        let c = check_change(&app, &new);
        assert!(c.needs_confirmation(), "{c:?}");
        assert!(
            c.adds_dangerous.iter().any(|t| t.contains("systemd1")),
            "{:?}",
            c.adds_dangerous
        );
    }

    /// A hidden folder is not a reason to warn that an app stops working:
    /// it is listed apart (regression for the group warning, which only
    /// interrupts for breakage).
    #[test]
    fn folders_are_not_breakage_but_lost_local_network_and_bus_are() {
        let mut need = PermissionSet::strict_gui();
        need.filesystem.documents = Access::Rw;
        need.network.mode = NetworkMode::Localhost;
        need.dbus.session.mode = DbusMode::Filtered;
        let app = AppEntry {
            recommended: need.clone(),
            profile: sam_core::SandboxProfile {
                permissions: need.clone(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut new = need.clone();
        new.filesystem.documents = Access::None;
        let c = check_change(&app, &new);
        assert!(c.removes_needed.is_empty(), "{:?}", c.removes_needed);
        assert_eq!(c.removes_folders, vec!["documents folder"]);
        new.network.mode = NetworkMode::None;
        new.dbus.session.mode = DbusMode::None;
        let c = check_change(&app, &new);
        assert!(c
            .removes_needed
            .iter()
            .any(|s| s == &sam_core::i18n::tr("connections to this computer")));
        assert!(c.removes_needed.iter().any(|s| s.contains("D-Bus")));
    }

    /// An app that needs sound is warned about in the switch's word.
    #[test]
    fn lost_sound_is_named_sound() {
        let mut need = PermissionSet::strict_gui();
        need.audio.enabled = true;
        let app = AppEntry {
            recommended: need.clone(),
            profile: sam_core::SandboxProfile {
                permissions: need.clone(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut new = need;
        new.audio.enabled = false;
        assert_eq!(check_change(&app, &new).removes_needed, vec!["sound"]);
    }

    /// A new preset starts without home, network or system bus access.
    #[test]
    fn preset_template_is_strict() {
        let p = preset_template().permissions;
        assert!(!p.filesystem.home);
        assert_eq!(p.network.mode, NetworkMode::None);
        assert_eq!(p.dbus.system.mode, DbusMode::None);
    }
}

#[cfg(test)]
mod own_name_tests {
    use super::own_bus_names;
    use sam_core::model::AppImageMetadata;

    fn md(file: &str, wm_class: &str) -> AppImageMetadata {
        AppImageMetadata {
            desktop_file: Some(file.into()),
            startup_wm_class: wm_class.into(),
            ..Default::default()
        }
    }

    /// The bus names an app may own come from its application ID and window class, never from protocol or desktop-service names.
    #[test]
    fn own_names_from_the_id_and_the_window_class() {
        assert_eq!(
            own_bus_names(&md(
                "usr/share/applications/com.nextcloud.desktopclient.nextcloud.desktop",
                ""
            )),
            vec!["com.nextcloud.desktopclient.nextcloud"]
        );
        // GTK and Flutter apps register their application ID, the window class.
        assert_eq!(
            own_bus_names(&md("hiddify.desktop", "app.hiddify.com")),
            vec!["app.hiddify.com"]
        );
        // KDE apps own org.kde.<app> (services that start on demand are
        // refused at launch, against this computer's service files).
        assert_eq!(
            own_bus_names(&md("org.kde.kdenlive.desktop", "kdenlive")),
            vec!["org.kde.kdenlive"]
        );
        assert!(
            own_bus_names(&md("nheko.desktop", "nheko")).is_empty(),
            "not reverse DNS"
        );
        assert!(
            own_bus_names(&md("org.freedesktop.Notifications.desktop", "")).is_empty(),
            "D-Bus protocol names"
        );
        assert!(
            own_bus_names(&md("org.kde.KWin.desktop", "")).is_empty(),
            "dangerous desktop services"
        );
        assert!(own_bus_names(&AppImageMetadata::default()).is_empty());
    }
}
