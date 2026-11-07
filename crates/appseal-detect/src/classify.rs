//! Library and resource classification (whitepaper §2.16.2).

use appseal_core::ResourceClass;

/// What a library tells us about the app's needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Gpu,
    Audio,
    Network,
    X11,
    Wayland,
    Fonts,
    Certificates,
    Dbus,
}

pub struct LibInfo {
    pub class: ResourceClass,
    pub signals: Vec<Signal>,
    pub toolkit: Option<&'static str>,
}

/// glibc and the GCC runtime are on the AppImage excludelist: AppImages are
/// built to use the host copies, so these are expected, not dangerous.
const SYSTEM: &[&str] = &[
    "libc.so", "libm.so", "libdl.so", "libpthread.so", "librt.so", "libresolv.so", "libutil.so",
    "libanl.so", "libmvec.so", "libnsl.so", "libBrokenLocale.so", "ld-linux", "libgcc_s.so",
    "libstdc++.so", "libz.so", "libcrypt.so", "libnss_", "libthread_db.so",
];

/// ABI-sensitive host libraries that must not be silently exposed (§2.16.2).
const DANGEROUS: &[(&str, Option<&str>)] = &[
    ("libgtk-3.so", Some("GTK3")),
    ("libgtk-4.so", Some("GTK4")),
    ("libgtk-x11-2.0.so", Some("GTK2")),
    ("libgdk-3.so", Some("GTK3")),
    ("libgdk-x11-2.0.so", Some("GTK2")),
    ("libQt5", Some("Qt5")),
    ("libQt6", Some("Qt6")),
    ("libssl.so", None),
    ("libcrypto.so", None),
    ("libsystemd.so", None),
    ("libpolkit", None),
];

const GRAPHICS: &[&str] = &[
    "libGL.so", "libEGL.so", "libGLX.so", "libGLESv1", "libGLESv2.so", "libOpenGL.so",
    "libvulkan.so", "libdrm.so", "libgbm.so", "libnvidia", "libva.so", "libva-", "libvdpau.so",
    "libGLdispatch.so",
];

const DISPLAY_X11: &[&str] = &[
    "libX11.so", "libX11-xcb.so", "libxcb", "libXext.so", "libXrender.so", "libXi.so", "libXrandr.so",
    "libXcursor.so", "libXfixes.so", "libXcomposite.so", "libXdamage.so", "libXinerama.so",
    "libXtst.so", "libXss.so", "libXxf86vm.so", "libICE.so", "libSM.so", "libXau.so", "libXdmcp.so",
    "libXmu.so", "libXt.so", "libXpm.so", "libXft.so",
];

const DISPLAY_WAYLAND: &[&str] = &["libwayland-client.so", "libwayland-cursor.so", "libwayland-egl.so", "libdecor"];

const AUDIO: &[&str] = &[
    "libasound.so", "libpulse.so", "libpulse-simple.so", "libpulse-mainloop", "libpipewire",
    "libjack.so", "libportaudio.so", "libopenal.so",
];

const NETWORK: &[&str] = &[
    "libcurl", "libssl.so", "libnss3.so", "libQt5Network.so", "libQt6Network.so", "libsoup",
    "libgnutls.so", "libnghttp2.so", "libwebkit", "libQt5WebEngine", "libQt6WebEngine",
];

const FONTS: &[&str] = &["libfontconfig.so", "libfreetype.so", "libharfbuzz.so", "libpango"];

const DBUS: &[&str] = &["libdbus-1.so", "libQt5DBus.so", "libQt6DBus.so", "libgio-2.0.so"];

const TOOLKITS: &[(&str, &str)] = &[
    ("libQt5Core.so", "Qt5"),
    ("libQt6Core.so", "Qt6"),
    ("libgtk-4.so", "GTK4"),
    ("libgtk-3.so", "GTK3"),
    ("libgtk-x11-2.0.so", "GTK2"),
    ("libSDL2-2.0.so", "SDL2"),
    ("libSDL3.so", "SDL3"),
    ("libjvm.so", "Java"),
    ("libwx_", "wxWidgets"),
    ("libfltk", "FLTK"),
];

fn starts(name: &str, list: &[&str]) -> bool {
    list.iter().any(|p| name.starts_with(p))
}

pub fn toolkit_of(name: &str) -> Option<&'static str> {
    TOOLKITS.iter().find(|(p, _)| name.starts_with(p)).map(|(_, t)| *t)
}

/// Classify a shared library by its file/soname.
pub fn classify_library(name: &str) -> LibInfo {
    let mut signals: Vec<Signal> = Vec::new();
    if starts(name, GRAPHICS) {
        signals.push(Signal::Gpu);
    }
    if starts(name, AUDIO) {
        signals.push(Signal::Audio);
    }
    if starts(name, NETWORK) {
        signals.push(Signal::Network);
    }
    if starts(name, DISPLAY_X11) {
        signals.push(Signal::X11);
    }
    if starts(name, DISPLAY_WAYLAND) {
        signals.push(Signal::Wayland);
    }
    if starts(name, FONTS) {
        signals.push(Signal::Fonts);
    }
    if starts(name, DBUS) {
        signals.push(Signal::Dbus);
    }
    if name.starts_with("libssl") || name.starts_with("libnss3") || name.starts_with("libgnutls") || name.starts_with("libcurl") {
        signals.push(Signal::Certificates);
    }
    let class = if starts(name, SYSTEM) {
        ResourceClass::System
    } else if DANGEROUS.iter().any(|(p, _)| name.starts_with(p)) {
        ResourceClass::Dangerous
    } else if starts(name, GRAPHICS) {
        ResourceClass::Graphics
    } else if starts(name, DISPLAY_X11) || starts(name, DISPLAY_WAYLAND) || starts(name, AUDIO) || starts(name, DBUS) {
        ResourceClass::Controlled
    } else if starts(name, FONTS) {
        ResourceClass::Safe
    } else {
        ResourceClass::Unknown
    };
    LibInfo {
        class,
        signals,
        toolkit: toolkit_of(name),
    }
}

/// Read-only host resources that are always safe to expose (§2.16.2).
pub const SAFE_HOST_RESOURCES: &[(&str, &str)] = &[
    ("/usr/share/fonts", "fonts"),
    ("~/.local/share/fonts", "user fonts"),
    ("/etc/fonts", "font configuration"),
    ("/usr/share/icons", "icon themes"),
    ("/usr/share/locale", "translations"),
    ("/usr/share/zoneinfo", "timezone data"),
    ("/etc/ssl/certs", "TLS certificates"),
    ("/usr/share/themes", "GTK themes"),
    ("/usr/share/mime", "MIME database"),
];

/// GPU driver resources: medium risk, often required.
pub const GRAPHICS_HOST_RESOURCES: &[(&str, &str)] = &[
    ("/dev/dri", "GPU device nodes"),
    ("/usr/lib/dri", "Mesa DRI drivers"),
    ("/usr/share/vulkan", "Vulkan ICD metadata"),
    ("/etc/vulkan", "Vulkan configuration"),
    ("/usr/share/glvnd", "GL vendor dispatch metadata"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(classify_library("libc.so.6").class, ResourceClass::System);
        assert_eq!(classify_library("libQt5Core.so.5").class, ResourceClass::Dangerous);
        assert_eq!(classify_library("libGL.so.1").class, ResourceClass::Graphics);
        assert_eq!(classify_library("libX11.so.6").class, ResourceClass::Controlled);
        assert_eq!(classify_library("libfontconfig.so.1").class, ResourceClass::Safe);
        assert_eq!(classify_library("libfoo.so.1").class, ResourceClass::Unknown);
        assert!(classify_library("libpulse.so.0").signals.contains(&Signal::Audio));
        assert!(classify_library("libssl.so.3").signals.contains(&Signal::Network));
        assert_eq!(classify_library("libQt6Core.so.6").toolkit, Some("Qt6"));
    }
}
