//! The three backends translate the same permission set independently.
//! These checks make sure the core restrictions mean the same thing in each:
//! network, X11, GPU, sound, private home and the portal filter.

use sam_core::backend::sample_context;
use sam_core::permissions::*;
use sam_core::{Backend, LaunchContext};

fn bwrap(ctx: &LaunchContext) -> Vec<String> {
    sam_backend_bubblewrap::Bubblewrap.build(ctx).unwrap().args
}
fn firejail(ctx: &LaunchContext) -> Vec<String> {
    sam_backend_firejail::Firejail.build(ctx).unwrap().args
}
fn bubblejail(ctx: &LaunchContext) -> toml::Table {
    sam_backend_bubblejail::services_toml(ctx).0
}
fn has(a: &[String], s: &str) -> bool {
    a.iter().any(|x| x == s)
}

#[test]
fn strict_profile_is_strict_everywhere() {
    let ctx = sample_context(); // strict GUI: Wayland only, no network/GPU/sound, private home
    let (b, f, j) = (bwrap(&ctx), firejail(&ctx), bubblejail(&ctx));
    // Network off.
    assert!(has(&b, "--unshare-net"));
    assert!(has(&f, "--net=none"));
    assert!(!j.contains_key("network"));
    // No X11.
    assert!(!b.iter().any(|x| x.contains(".X11-unix")));
    assert!(has(&f, "--x11=none"));
    assert!(!j.contains_key("x11"));
    // No GPU, no sound.
    assert!(!b.iter().any(|x| x == "/dev/dri"));
    assert!(has(&f, "--no3d") && has(&f, "--nosound"));
    assert!(!j.contains_key("direct_rendering") && !j.contains_key("pulse_audio") && !j.contains_key("pipewire"));
    // Private home.
    assert!(b.windows(3).any(|w| w[0] == "--bind" && w[2] == "/home/tester"));
    assert!(f.iter().any(|x| x.starts_with("--private=")));
    // Portal: never granted wholesale.
    assert!(!f.iter().any(|x| x == "--dbus-user.talk=org.freedesktop.portal.Desktop"));
    assert!(f.iter().any(|x| x.starts_with("--dbus-user.call=org.freedesktop.portal.Desktop=org.freedesktop.portal.OpenURI")));
    assert!(!f.iter().any(|x| x.contains("portal.Screenshot") || x.contains("portal.Background")));
    let raw = j["debug"]["raw_dbus_session_args"].as_array().unwrap();
    assert!(!raw.iter().any(|v| v.as_str() == Some("--talk=org.freedesktop.portal.Desktop")));
}

#[test]
fn granted_permissions_are_granted_everywhere() {
    let mut ctx = sample_context();
    let p = &mut ctx.permissions;
    p.network.mode = NetworkMode::Full;
    p.display.x11 = true;
    p.devices.gpu = true;
    p.audio.enabled = true;
    let (b, f, j) = (bwrap(&ctx), firejail(&ctx), bubblejail(&ctx));
    assert!(!has(&b, "--unshare-net") && !has(&f, "--net=none") && j.contains_key("network"));
    assert!(b.iter().any(|x| x.contains(".X11-unix")) && !has(&f, "--x11=none") && j.contains_key("x11"));
    assert!(b.iter().any(|x| x == "/dev/dri") && !has(&f, "--no3d") && j.contains_key("direct_rendering"));
    assert!(b.iter().any(|x| x.contains("pipewire")) && !has(&f, "--nosound") && j.contains_key("pipewire"));
}

#[test]
fn limitations_are_reported_for_other_backends() {
    let cfg = sam_core::Config::default();
    let mut p = PermissionSet::strict_gui();
    p.network.mode = NetworkMode::Localhost;
    assert!(sam_runner::select::limitations(&p, sam_core::BackendKind::Bubblewrap, &cfg).is_empty());
    let l = sam_runner::select::limitations(&p, sam_core::BackendKind::Firejail, &cfg);
    assert!(l.iter().any(|x| x.contains("Local network only")), "{l:?}");
    assert!(l.iter().any(|x| x.contains("Landlock")));
}
