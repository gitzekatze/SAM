//! sam-profile: category inference, recommended profiles (§2.17),
//! built-in and user presets (§2.18) and preset compatibility checks.

use anyhow::Result;
use sam_core::permissions::*;
use sam_core::risk::{assess, RiskLevel};
use sam_core::{AppEntry, AppImageMetadata, BackendChoice, DependencyReport, Paths, Preset};
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
    pub fn label(self) -> &'static str {
        match self {
            Category::Browser => "Browser",
            Category::MediaPlayer => "Media player",
            Category::ImageEditor => "Image editor",
            Category::VideoEditor => "Video editor",
            Category::AudioEditor => "Audio editor",
            Category::Game => "Game",
            Category::TextEditor => "Text editor",
            Category::Office => "Office",
            Category::Terminal => "Terminal",
            Category::Development => "Development",
            Category::Communication => "Communication",
            Category::Utility => "Utility",
        }
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

/// Infer a category from desktop categories, name and binary (§2.17 sources 1-3).
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
        (&["discord", "signal", "telegram", "slack", "element", "zoom", "teams", "thunderbird", "whatsapp", "e-mail", "email", "mail client", "tuta", "proton mail"][..], Category::Communication),
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
    pub backend: BackendChoice,
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

/// Generate the recommended profile for an app (§2.17).
pub fn recommend(md: &AppImageMetadata, file_name: &str, report: Option<&DependencyReport>) -> Recommendation {
    let category = infer_category(md, file_name, report);
    let mut p = base_for(category);
    let mut notes = vec![format!("Category: {} (from desktop metadata and name)", category.label())];

    if let Some(r) = report {
        let req = &r.requirements;
        if req.gpu && !p.devices.gpu {
            p.devices.gpu = true;
            notes.push("GPU enabled: the app links OpenGL/Vulkan libraries".into());
        }
        if req.audio && !p.audio.enabled {
            p.audio.enabled = true;
            notes.push("Audio enabled: the app links audio libraries".into());
        }
        if req.x11 && !req.wayland {
            p.display.x11 = true;
            notes.push("X11 enabled: no Wayland support detected (uses XWayland)".into());
        } else if req.x11 && matches!(req.toolkit.as_str(), "Electron" | "Java" | "Unknown") {
            p.display.x11 = true;
            notes.push(format!("X11 enabled: {} apps usually need XWayland", req.toolkit));
        }
        if !req.x11 && !req.wayland && r.elf_count > 0 && req.toolkit == "Unknown" {
            // Can't tell; keep Wayland only but note it.
            notes.push("No display libraries detected; if the window does not appear, enable X11".into());
        }
        if req.network && p.network.mode == NetworkMode::None {
            if category == Category::Game {
                p.network.mode = NetworkMode::Full;
                notes.push("Network enabled: game links networking libraries (multiplayer is likely)".into());
            } else if !needs_network_by_purpose(md, file_name) {
                notes.push("The app links networking libraries but its category does not need the network; network stays off".into());
            }
        }
        if req.electron {
            p.advanced.allow_userns = true;
            notes.push("Electron app: nested namespaces allowed so Chromium's own sandbox can start".into());
        }
        if r.compatibility != sam_core::Compatibility::Good {
            notes.push("Compatibility issues were detected; see the dependency report".into());
        }
    }
    if p.network.mode == NetworkMode::None && needs_network_by_purpose(md, file_name) {
        p.network.mode = NetworkMode::Full;
        notes.push("Network enabled: this looks like an AI, web-UI or server app, which talks to models or services over the network. If it only uses local models, 'Local network only' blocks the internet but keeps local servers reachable.".into());
    }
    // Desktop integrations.
    if category == Category::MediaPlayer {
        // Players only need to read the files they are given.
        p.filesystem.opened_files = Access::Ro;
        p.integrations.media_controls = true;
        notes.push("Media controls enabled: media keys, 'now playing' and keeping the screen awake".into());
    }
    if XDG_DIR_KEYS.iter().any(|k| p.filesystem.xdg_access(k).is_granted()) {
        p.integrations.file_manager = true;
    }
    Recommendation { category, permissions: p, notes, backend: BackendChoice::Auto }
}

/// Apps whose purpose is talking to models, servers or services: local AI
/// tools, web UIs, API routers, sync clients. Their category is often just
/// "Utility", so without this they would start offline and seem broken.
pub fn needs_network_by_purpose(md: &AppImageMetadata, file_name: &str) -> bool {
    let text = format!(" {} {} {} {} ", md.name, md.comment, md.exec, file_name).to_lowercase();
    let text: String = text.chars().map(|c| if c.is_alphanumeric() { c } else { ' ' }).collect();
    let words = [
        " llm", " llms ", " ai ", " gpt", " ollama", " openai", " webui ", " web ui ", " comfy", " comfyui",
        " stable diffusion", " diffusion ", " server ", " api ", " router ", " proxy ", " sync ", " cloud ",
        " client ", " chat ", " assistant ", " model ", " models ", " inference ", " unsloth", " anythingllm",
    ];
    if words.iter().any(|w| text.contains(w)) {
        return true;
    }
    // Compound names: "FreeLLMAPI", "OpenWebUI", "LocalGPT".
    text.split_whitespace().any(|t| (t.contains("llm") && !t.contains("ullm")) || t.ends_with("api") || t.ends_with("gpt") || t.ends_with("webui"))
}

/// Compatibility mode (§2.16.4): broader access for apps that otherwise break.
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

pub const COMPAT_WARNING: &str = "This AppImage may require broader host access to function correctly. SAM can grant additional permissions, but this reduces isolation.";

/// Built-in presets (§2.18 examples).
pub fn builtin_presets() -> Vec<Preset> {
    let mk = |name: &str, desc: &str, notes: &str, p: PermissionSet| {
        let risk = assess(&p, None).level;
        Preset {
            name: name.into(),
            description: desc.into(),
            permissions: p,
            backend: None,
            risk,
            created_at: 0,
            modified_at: 0,
            compatibility_notes: notes.into(),
            builtin: true,
        }
    };
    let mut strict_browser = base_for(Category::Browser);
    strict_browser.display.x11 = true;
    let mut media = base_for(Category::MediaPlayer);
    media.network.mode = NetworkMode::None;
    let mut game = base_for(Category::Game);
    game.network.mode = NetworkMode::Full;
    game.display.x11 = true;
    game.devices.input = false;
    let mut untrusted = PermissionSet::strict_gui();
    untrusted.dbus.session.mode = DbusMode::None;
    untrusted.advanced.persistent_home = false;
    untrusted.advanced.host_themes = false;
    let office = base_for(Category::Office);
    let image = base_for(Category::ImageEditor);
    vec![
        mk("Strict Browser", "Browser profile with no home access except Downloads", "Enables X11 for browsers without native Wayland.", strict_browser),
        mk("Media Player Safe", "Offline playback of local Music and Videos", "Streaming services need network access.", media),
        mk("Game Performance", "GPU, audio, network and XWayland for games", "Controllers need 'Input devices', which is not enabled by default.", game),
        mk("Untrusted Utility", "Wayland window only: no files, network, audio or D-Bus. Fresh home on each run.", "Settings are not kept between runs.", untrusted),
        mk("Office Documents Only", "Read and write Documents, nothing else", "", office),
        mk("Image Editor", "Pictures and Documents with GPU acceleration, offline", "", image),
    ]
}

/// Built-in + user presets. User presets with the same name shadow built-ins.
pub fn all_presets(paths: &Paths) -> Result<Vec<Preset>> {
    let user = PresetStore::new(paths).list()?;
    let mut out: Vec<Preset> = builtin_presets()
        .into_iter()
        .filter(|b| !user.iter().any(|u| u.name.eq_ignore_ascii_case(&b.name)))
        .collect();
    out.extend(user);
    Ok(out)
}

pub fn find_preset(paths: &Paths, name: &str) -> Result<Option<Preset>> {
    Ok(all_presets(paths)?.into_iter().find(|p| p.name.eq_ignore_ascii_case(name)))
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PresetCheck {
    /// Permissions the app likely needs that the preset removes.
    pub removes_needed: Vec<String>,
    /// High-risk permissions the preset adds compared to the current profile.
    pub adds_dangerous: Vec<String>,
    pub risk_before: RiskLevel,
    pub risk_after: RiskLevel,
}

impl PresetCheck {
    pub fn needs_confirmation(&self) -> bool {
        !self.removes_needed.is_empty() || !self.adds_dangerous.is_empty()
    }
}

/// Compare a preset against what the app likely needs (its recommendation)
/// and against its current profile (§2.18 "When applying a preset").
pub fn check_preset(app: &AppEntry, preset: &Preset) -> PresetCheck {
    let need = &app.recommended;
    let new = &preset.permissions;
    let cur = &app.profile.permissions;
    let mut c = PresetCheck {
        risk_before: assess(cur, app.profile.backend.fixed()).level,
        risk_after: assess(new, preset.backend.or(Some(app.profile.backend)).and_then(|b| b.fixed())).level,
        ..Default::default()
    };
    let mut removed = |cond: bool, what: &str| {
        if cond {
            c.removes_needed.push(what.to_string());
        }
    };
    removed(need.devices.gpu && !new.devices.gpu, "GPU acceleration");
    removed(need.audio.enabled && !new.audio.enabled, "audio");
    removed(need.network.mode == NetworkMode::Full && new.network.mode != NetworkMode::Full, "network access");
    removed(need.display.x11 && !new.display.x11 && !(need.display.wayland && new.display.wayland && !needs_x11_only(app)), "X11 display");
    removed(!new.display.x11 && !new.display.wayland && (need.display.x11 || need.display.wayland), "any display access");
    for key in XDG_DIR_KEYS {
        if need.filesystem.xdg_access(key).is_granted() && !new.filesystem.xdg_access(key).is_granted() {
            c.removes_needed.push(format!("{key} folder"));
        }
    }

    let before = assess(cur, None);
    for item in assess(new, None).items {
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
    use super::*;
    use sam_core::Requirements;

    fn md(name: &str, cats: &[&str]) -> AppImageMetadata {
        AppImageMetadata { name: name.into(), categories: cats.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn categories() {
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

    #[test]
    fn recommendations_follow_whitepaper() {
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

    #[test]
    fn detection_adjusts_profile() {
        let mut rep = DependencyReport::default();
        rep.requirements = Requirements { gpu: true, x11: true, toolkit: "Qt5".into(), ..Default::default() };
        let r = recommend(&md("Tool", &["Utility"]), "", Some(&rep));
        assert!(r.permissions.devices.gpu);
        assert!(r.permissions.display.x11, "X11-only app gets XWayland");
        assert_eq!(r.permissions.network.mode, NetworkMode::None);
    }

    #[test]
    fn preset_check_flags_removals_and_additions() {
        let mut app = AppEntry::default();
        app.recommended = recommend(&md("Firefox", &["WebBrowser"]), "", None).permissions;
        app.profile.permissions = app.recommended.clone();
        let untrusted = builtin_presets().into_iter().find(|p| p.name == "Untrusted Utility").unwrap();
        let c = check_preset(&app, &untrusted);
        assert!(c.removes_needed.iter().any(|s| s == "network access"));
        assert!(c.needs_confirmation());

        let mut app2 = AppEntry::default();
        app2.recommended = PermissionSet::strict_gui();
        app2.profile.permissions = PermissionSet::strict_gui();
        let browser = builtin_presets().into_iter().find(|p| p.name == "Strict Browser").unwrap();
        let c2 = check_preset(&app2, &browser);
        assert!(c2.adds_dangerous.iter().any(|s| s == "Network"), "{:?}", c2.adds_dangerous);
    }

    #[test]
    fn builtin_presets_are_sane() {
        let all = builtin_presets();
        assert_eq!(all.len(), 6);
        for p in &all {
            assert!(!p.permissions.filesystem.home, "{} must not grant full home", p.name);
            assert_eq!(p.permissions.dbus.system.mode, DbusMode::None);
        }
    }
}
