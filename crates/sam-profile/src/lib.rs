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
pub fn infer_category(md: &AppImageMetadata, file_name: &str, report: Option<&DependencyReport>) -> Category {
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
    if has("instantmessaging") || has("chat") || has("email") || has("videoconference") || has("telephony") {
        return Category::Communication;
    }
    if has("audiovideoediting") && (has("video") || word("video")) {
        return Category::VideoEditor;
    }
    if has("audiovideoediting") || (has("audio") && (has("recorder") || has("sequencer") || has("midi"))) {
        return Category::AudioEditor;
    }
    let graphics = ["graphics", "rastergraphics", "vectorgraphics", "2dgraphics", "3dgraphics", "photography"];
    let has_graphics = graphics.iter().any(|c| has(c));
    // A bare `AudioVideo` next to graphics categories is a creative tool, not a player.
    if has("player") || has("tv") || (has("audiovideo") && !has("audiovideoediting") && !has_graphics) {
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
        (&["browser", "firefox", "chromium", "librewolf", "brave", "vivaldi", "waterfox", "floorp"][..], Category::Browser),
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
        (&["vlc", "mpv", "player", "jellyfin", "spotify", "strawberry", "audacious", "celluloid"][..], Category::MediaPlayer),
        (&["kdenlive", "shotcut", "olive", "openshot", "davinci", "flowblade"][..], Category::VideoEditor),
        (&["audacity", "ardour", "lmms", "tenacity", "reaper", "bitwig"][..], Category::AudioEditor),
        (&["krita", "gimp", "inkscape", "darktable", "rawtherapee", "pinta", "blender", "photo"][..], Category::ImageEditor),
        (&["game", "minecraft", "steam", "heroic", "lutris", "emulator", "retroarch", "dolphin-emu", "pcsx", "rpcs3", "yuzu", "ryujinx"][..], Category::Game),
        (&["libreoffice", "onlyoffice", "office", "writer", "calc", "obsidian", "logseq", "zotero", "joplin", "notes"][..], Category::Office),
        (&["code", "vscodium", "editor", "notepad", "kate", "sublime", "zed", "neovim", "lapce"][..], Category::TextEditor),
        (&["terminal", "kitty", "alacritty", "wezterm", "konsole"][..], Category::Terminal),
        (&["studio", "ide", "idea", "pycharm", "godot", "arduino", "qtcreator"][..], Category::Development),
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
            fs.documents = Access::Rw;
            fs.custom_write.push("~/Projects".into());
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
    let id = md.desktop_file.as_deref().and_then(|f| std::path::Path::new(f).file_name()?.to_str()?.strip_suffix(".desktop").map(str::to_string));
    let mut names = Vec::new();
    for cand in id.into_iter().chain(Some(md.startup_wm_class.clone())) {
        let parts: Vec<&str> = cand.split('.').collect();
        let valid = parts.len() >= 3
            && cand.len() <= 200
            && parts
                .iter()
                .all(|p| !p.is_empty() && !p.starts_with(|c: char| c.is_ascii_digit()) && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
        if valid && sam_core::permissions::refuse_own_name(&cand, &Default::default()).is_none() && !names.contains(&cand) {
            names.push(cand);
        }
    }
    names
}

pub fn recommend(md: &AppImageMetadata, file_name: &str, report: Option<&DependencyReport>) -> Recommendation {
    let category = infer_category(md, file_name, report);
    let mut p = base_for(category);
    let mut notes = vec![sam_core::i18n::trf("Category: {category} (from desktop metadata and name)", &[("category", &category.label())])];

    if let Some(r) = report {
        let req = &r.requirements;
        if req.gpu && !p.devices.gpu {
            p.devices.gpu = true;
            notes.push(sam_core::i18n::tr("GPU enabled: the app links OpenGL/Vulkan libraries"));
        }
        if req.audio && !p.audio.enabled {
            p.audio.enabled = true;
            notes.push(sam_core::i18n::tr("Audio enabled: the app links audio libraries"));
        }
        if req.x11 && !req.wayland {
            p.display.x11 = true;
            notes.push(sam_core::i18n::tr("X11 enabled: no Wayland support detected (uses XWayland)"));
        } else if req.x11 && (req.java || matches!(req.toolkit.as_str(), "Electron" | "Java" | "Unknown")) {
            // Java's AWT and JavaFX draw through X11 only, whatever toolkit
            // they load (JavaFX uses GTK on X11).
            p.display.x11 = true;
            notes.push(sam_core::i18n::trf(
                "X11 enabled: {toolkit} apps usually need XWayland",
                &[("toolkit", &if req.java { "Java" } else { req.toolkit.as_str() })],
            ));
        }
        if !req.x11 && !req.wayland && r.elf_count > 0 && req.toolkit == "Unknown" {
            // Nothing linked: the app loads its graphics stack at start
            // (Rust/wgpu, game engines). Those need the GPU to open a window.
            if !p.devices.gpu {
                p.devices.gpu = true;
                notes.push(sam_core::i18n::tr("GPU enabled: the app loads its graphics libraries at start (common for Rust apps and game engines)"));
            }
            notes.push(sam_core::i18n::tr("No display libraries detected; if the window does not appear, enable X11"));
        }
        if req.network && p.network.mode == NetworkMode::None {
            if category == Category::Game {
                p.network.mode = NetworkMode::Full;
                notes.push(sam_core::i18n::tr("Network enabled: game links networking libraries (multiplayer is likely)"));
            } else if !needs_network_by_purpose(md, file_name) {
                notes.push(sam_core::i18n::tr("The app links networking libraries but its category does not need the network; network stays off"));
            }
        }
        if req.electron {
            p.advanced.allow_userns = true;
            notes.push(sam_core::i18n::tr("Electron app: nested namespaces allowed so Chromium's own sandbox can start"));
        } else if req.nested_sandbox {
            p.advanced.allow_userns = true;
            notes.push(sam_core::i18n::tr("Nested namespaces allowed: the app's web engine (Chromium or WebKit) starts its own sandbox"));
        }
        if r.arch == "i686" {
            // The syscall filter is built for 64-bit programs; a 32-bit one
            // is stopped by its architecture check at the first call.
            p.advanced.seccomp_baseline = false;
            notes.push(sam_core::i18n::tr("32-bit app: the baseline syscall filter is off, because it only supports 64-bit programs and would stop the app"));
        }
        if r.compatibility != sam_core::Compatibility::Good {
            notes.push(sam_core::i18n::tr("Compatibility issues were detected; see the dependency report"));
        }
    }
    // Terminal programs run in the terminal that starts them: no window,
    // no graphics, no desktop services.
    if md.terminal {
        p.display.wayland = false;
        p.display.x11 = false;
        p.devices.gpu = false;
        p.dbus.session.mode = sam_core::permissions::DbusMode::None;
        notes.push(sam_core::i18n::tr("Terminal program: no display, GPU or desktop services; it runs in a terminal window"));
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
        notes.push(sam_core::i18n::tr("Media controls enabled: media keys, 'now playing' and keeping the screen awake"));
    }
    if XDG_DIR_KEYS.iter().any(|k| p.filesystem.xdg_access(k).is_granted()) {
        p.integrations.file_manager = true;
    }
    // The app may own the D-Bus name of its own ID (as Flatpak allows): many
    // apps register it to hand a second start over to the first one.
    for name in own_bus_names(md) {
        if !p.dbus.session.own.contains(&name) {
            notes.push(sam_core::i18n::trf("D-Bus: may own its own name {name}", &[("name", &name)]));
            p.dbus.session.own.push(name);
        }
    }
    Recommendation { category, permissions: p, notes }
}

/// Apps whose purpose is talking to models, servers or services: local AI
/// tools, web UIs, API routers, sync clients. Their category is often just
/// "Utility", so without this they would start offline and seem broken.
pub fn needs_network_by_purpose(md: &AppImageMetadata, file_name: &str) -> bool {
    let text = format!(" {} {} {} {} ", md.name, md.comment, md.exec, file_name).to_lowercase();
    let text: String = text.chars().map(|c| if c.is_alphanumeric() { c } else { ' ' }).collect();
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
    text.split_whitespace().any(|t| (t.contains("llm") && !t.contains("ullm")) || t.ends_with("api") || t.ends_with("gpt") || t.ends_with("webui"))
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
    "This AppImage may require broader host access to function correctly. SAM can grant additional permissions, but this reduces isolation.",
);

/// The user's own presets. SAM ships none: the recommendation already
/// fits each app, and a ready-made category set would only replace it with
/// a guess.
pub fn all_presets(paths: &Paths) -> Result<Vec<Preset>> {
    PresetStore::new(paths).list()
}

pub fn find_preset(paths: &Paths, name: &str) -> Result<Option<Preset>> {
    Ok(all_presets(paths)?.into_iter().find(|p| p.name.eq_ignore_ascii_case(name)))
}

/// A new preset starts from SAM's strictest settings for a window app.
pub fn preset_template() -> Preset {
    let permissions = PermissionSet::strict_gui();
    Preset { risk: assess(&permissions).level, permissions, ..Default::default() }
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
        !self.removes_needed.is_empty() || !self.removes_folders.is_empty() || !self.adds_dangerous.is_empty()
    }
}

/// Compares new settings against what the app likely needs (its
/// recommendation) and against its current profile.
pub fn check_change(app: &AppEntry, new: &PermissionSet) -> ChangeCheck {
    let need = &app.recommended;
    let cur = &app.profile.permissions;
    let mut c = ChangeCheck { risk_before: assess(cur).level, risk_after: assess(new).level, ..Default::default() };
    let mut removed = |cond: bool, what: &str| {
        if cond {
            c.removes_needed.push(what.to_string());
        }
    };
    removed(need.devices.gpu && !new.devices.gpu, "GPU acceleration");
    removed(need.audio.enabled && !new.audio.enabled, "sound");
    removed(need.network.mode == NetworkMode::Full && new.network.mode != NetworkMode::Full, "network access");
    removed(need.network.mode == NetworkMode::Localhost && new.network.mode == NetworkMode::None, &sam_core::i18n::tr("connections to this computer"));
    removed(need.display.x11 && !new.display.x11 && !(need.display.wayland && new.display.wayland && !needs_x11_only(app)), "X11 display");
    removed(!new.display.x11 && !new.display.wayland && (need.display.x11 || need.display.wayland), &sam_core::i18n::tr("any display access"));
    removed(need.dbus.session.mode != DbusMode::None && new.dbus.session.mode == DbusMode::None, "desktop services (D-Bus)");
    for key in XDG_DIR_KEYS {
        if need.filesystem.xdg_access(key).is_granted() && !new.filesystem.xdg_access(key).is_granted() {
            c.removes_folders.push(format!("{key} folder"));
        }
    }

    let before = assess(cur);
    for item in assess(new).items {
        if item.level >= RiskLevel::High && !before.items.iter().any(|b| b.key == item.key && b.level >= item.level) {
            c.adds_dangerous.push(item.title);
        }
    }
    c
}

fn needs_x11_only(app: &AppEntry) -> bool {
    app.detection.as_ref().is_some_and(|d| d.requirements.x11 && !d.requirements.wayland)
}

#[cfg(test)]
mod tests {

    /// Terminal programs get no display, GPU or desktop bus access.
    #[test]
    fn terminal_programs_get_no_display() {
        let md = AppImageMetadata { name: "Neovim".into(), categories: vec!["Utility".into(), "TextEditor".into()], terminal: true, ..Default::default() };
        let r = recommend(&md, "nvim.appimage", None);
        assert!(!r.permissions.display.wayland && !r.permissions.display.x11 && !r.permissions.devices.gpu);
        assert_eq!(r.permissions.dbus.session.mode, sam_core::permissions::DbusMode::None);
    }

    use super::*;
    use sam_core::Requirements;

    fn md(name: &str, cats: &[&str]) -> AppImageMetadata {
        AppImageMetadata { name: name.into(), categories: cats.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }

    /// The category of an app is recognized from its desktop categories.
    #[test]
    fn the_app_category_is_recognized_from_its_desktop_categories() {
        assert_eq!(infer_category(&md("Firefox", &["Network", "WebBrowser"]), "", None), Category::Browser);
        assert_eq!(infer_category(&md("Krita", &["Graphics", "2DGraphics"]), "", None), Category::ImageEditor);
        assert_eq!(infer_category(&md("VLC", &["AudioVideo", "Player"]), "", None), Category::MediaPlayer);
        assert_eq!(infer_category(&md("Kdenlive", &["AudioVideo", "AudioVideoEditing", "Video"]), "", None), Category::VideoEditor);
        assert_eq!(infer_category(&md("Thing", &[]), "SuperTux-0.6.AppImage", None), Category::Utility);
        assert_eq!(infer_category(&md("SuperTux", &["Game"]), "", None), Category::Game);
        assert_eq!(infer_category(&md("Tuta", &["Network"]), "", None), Category::Communication);
        assert!(needs_network_by_purpose(&md("Open WebUI", &[]), "open-webui_x86_64.AppImage"));
        assert!(needs_network_by_purpose(&md("FreeLLMAPI", &[]), ""), "LLM in name");
        assert!(!needs_network_by_purpose(&md("ZFontManager", &[]), "ZFontManager_0.9.0_amd64.AppImage"));
        assert!(!needs_network_by_purpose(&md("Krita", &["Graphics"]), "krita-5.2.AppImage"));
        assert_eq!(infer_category(&md("Comfy Desktop", &["AudioVideo", "Graphics", "3DGraphics"]), "", None), Category::ImageEditor);
        assert_eq!(infer_category(&md("Obsidian", &[]), "", None), Category::Office);
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
        let rep = DependencyReport { requirements: Requirements { gpu: true, x11: true, toolkit: "Qt5".into(), ..Default::default() }, ..Default::default() };
        let r = recommend(&md("Tool", &["Utility"]), "", Some(&rep));
        assert!(r.permissions.devices.gpu);
        assert!(r.permissions.display.x11, "X11-only app gets XWayland");
        assert_eq!(r.permissions.network.mode, NetworkMode::None);
    }

    /// The change check names what an app would lose that it needs, and the dangerous access it would gain.
    #[test]
    fn change_check_flags_removals_and_additions() {
        let recommended = recommend(&md("Firefox", &["WebBrowser"]), "", None).permissions;
        let app = AppEntry { profile: sam_core::SandboxProfile { permissions: recommended.clone(), ..Default::default() }, recommended, ..Default::default() };
        let mut offline = app.profile.permissions.clone();
        offline.network.mode = NetworkMode::None;
        let c = check_change(&app, &offline);
        assert!(c.removes_needed.iter().any(|s| s == "network access"));
        assert!(c.needs_confirmation());
        assert!(!check_change(&app, &app.profile.permissions).needs_confirmation(), "no change, nothing to report");

        let app2 = AppEntry {
            recommended: PermissionSet::strict_gui(),
            profile: sam_core::SandboxProfile { permissions: PermissionSet::strict_gui(), ..Default::default() },
            ..Default::default()
        };
        let mut x11 = PermissionSet::strict_gui();
        x11.display.x11 = true;
        let c2 = check_change(&app2, &x11);
        assert!(!c2.adds_dangerous.is_empty(), "{:?}", c2.adds_dangerous);
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
        let app =
            AppEntry { recommended: need.clone(), profile: sam_core::SandboxProfile { permissions: need.clone(), ..Default::default() }, ..Default::default() };
        let mut new = need.clone();
        new.filesystem.documents = Access::None;
        let c = check_change(&app, &new);
        assert!(c.removes_needed.is_empty(), "{:?}", c.removes_needed);
        assert_eq!(c.removes_folders, vec!["documents folder"]);
        new.network.mode = NetworkMode::None;
        new.dbus.session.mode = DbusMode::None;
        let c = check_change(&app, &new);
        assert!(c.removes_needed.iter().any(|s| s == &sam_core::i18n::tr("connections to this computer")));
        assert!(c.removes_needed.iter().any(|s| s.contains("D-Bus")));
    }

    /// An app that needs sound is warned about in the switch's word.
    #[test]
    fn lost_sound_is_named_sound() {
        let mut need = PermissionSet::strict_gui();
        need.audio.enabled = true;
        let app =
            AppEntry { recommended: need.clone(), profile: sam_core::SandboxProfile { permissions: need.clone(), ..Default::default() }, ..Default::default() };
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
        AppImageMetadata { desktop_file: Some(file.into()), startup_wm_class: wm_class.into(), ..Default::default() }
    }

    /// The bus names an app may own come from its application ID and window class, never from protocol or desktop-service names.
    #[test]
    fn own_names_from_the_id_and_the_window_class() {
        assert_eq!(
            own_bus_names(&md("usr/share/applications/com.nextcloud.desktopclient.nextcloud.desktop", "")),
            vec!["com.nextcloud.desktopclient.nextcloud"]
        );
        // GTK and Flutter apps register their application ID, the window class.
        assert_eq!(own_bus_names(&md("hiddify.desktop", "app.hiddify.com")), vec!["app.hiddify.com"]);
        // KDE apps own org.kde.<app> (services that start on demand are
        // refused at launch, against this computer's service files).
        assert_eq!(own_bus_names(&md("org.kde.kdenlive.desktop", "kdenlive")), vec!["org.kde.kdenlive"]);
        assert!(own_bus_names(&md("nheko.desktop", "nheko")).is_empty(), "not reverse DNS");
        assert!(own_bus_names(&md("org.freedesktop.Notifications.desktop", "")).is_empty(), "D-Bus protocol names");
        assert!(own_bus_names(&md("org.kde.KWin.desktop", "")).is_empty(), "dangerous desktop services");
        assert!(own_bus_names(&AppImageMetadata::default()).is_empty());
    }
}
