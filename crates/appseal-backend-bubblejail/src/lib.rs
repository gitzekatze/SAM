//! Bubblejail backend (optional, §2.13.2).
//!
//! Appseal generates a Bubblejail instance named `appseal-<app-id>` whose
//! `services.toml` mirrors the permission set, then runs it with
//! `bubblejail run`. Bubblejail drives xdg-dbus-proxy itself, which gives
//! better D-Bus filtering than plain Bubblewrap.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use appseal_core::permissions::*;
use appseal_core::util::{atomic_write, expand_home};
use appseal_core::{Backend, BackendKind, BackendStatus, HostInfo, LaunchContext, SandboxCommand};
use toml::{Table, Value};

pub struct Bubblejail;

pub fn instance_name(app_id: &str) -> String {
    format!("appseal-{app_id}")
}

pub fn instances_dir() -> PathBuf {
    let data = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| appseal_core::util::home_dir().join(".local/share"));
    data.join("bubblejail/instances")
}

fn strs<I: IntoIterator<Item = S>, S: Into<String>>(v: I) -> Value {
    Value::Array(v.into_iter().map(|s| Value::String(s.into())).collect())
}

/// Build the `services.toml` table for a launch.
pub fn services_toml(ctx: &LaunchContext) -> (Table, Vec<String>) {
    let p = &ctx.permissions;
    let home = &ctx.host.home;
    let mut notes = Vec::new();
    let mut t = Table::new();
    let empty = || Value::Table(Table::new());

    let appdir = ctx.appdir.to_string_lossy().into_owned();
    let mut common = Table::new();
    common.insert("executable_name".into(), strs([format!("{appdir}/{}", ctx.entry)]));
    t.insert("common".into(), Value::Table(common));

    if p.display.x11 {
        t.insert("x11".into(), empty());
    }
    if p.display.wayland {
        t.insert("wayland".into(), empty());
    }
    match p.network.mode {
        NetworkMode::Full => {
            t.insert("network".into(), empty());
        }
        NetworkMode::None => {}
        m => notes.push(format!("network mode '{}' is experimental; network disabled", m.as_str())),
    }
    if p.audio.enabled {
        t.insert("pulse_audio".into(), empty());
        t.insert("pipewire".into(), empty());
    }
    if p.devices.gpu {
        t.insert("direct_rendering".into(), empty());
    }
    if p.devices.webcam {
        t.insert("v4l".into(), empty());
    }
    if p.devices.input {
        t.insert("joystick".into(), empty());
    }
    if p.dbus.session.mode != DbusMode::None {
        t.insert("notify".into(), empty());
        t.insert("xdg_desktop_portal".into(), empty());
        t.insert("systray".into(), empty());
    }

    // Home and root shares.
    let rel = |path: &Path| path.strip_prefix(home).ok().map(|r| r.to_string_lossy().into_owned());
    let mut home_rw: Vec<String> = Vec::new();
    let mut home_ro: Vec<String> = Vec::new();
    let mut root_rw: Vec<String> = Vec::new();
    let mut root_ro: Vec<String> = vec![appdir.clone()];
    if p.filesystem.home {
        notes.push("full home access: bubblejail binds the home directory; ~/.ssh and ~/.gnupg masking is not available with this backend".into());
        if p.filesystem.home_access == Access::Rw {
            home_rw.push(".".into());
        } else {
            home_ro.push(".".into());
        }
    } else {
        for key in XDG_DIR_KEYS {
            let acc = p.filesystem.xdg_access(key);
            if let (true, Some(dir)) = (acc.is_granted(), ctx.host.xdg_dir(key)) {
                if dir.exists() {
                    if let Some(r) = rel(dir) {
                        if acc == Access::Rw { home_rw.push(r) } else { home_ro.push(r) }
                    }
                }
            }
        }
    }
    let mut add_path = |raw: &str, rw: bool| {
        let path = expand_home(raw);
        if !path.exists() {
            return;
        }
        match rel(&path) {
            Some(r) if rw => home_rw.push(r),
            Some(r) => home_ro.push(r),
            None if rw => root_rw.push(path.to_string_lossy().into_owned()),
            None => root_ro.push(path.to_string_lossy().into_owned()),
        }
    };
    for c in &p.filesystem.custom_read {
        add_path(c, false);
    }
    for c in &p.filesystem.custom_write {
        add_path(c, true);
    }
    for (host_p, _, rw) in &ctx.extra_binds {
        add_path(&host_p.to_string_lossy(), *rw);
    }
    if !home_rw.is_empty() || !home_ro.is_empty() {
        let mut hs = Table::new();
        hs.insert("home_paths".into(), strs(home_rw));
        hs.insert("home_paths_read_only".into(), strs(home_ro));
        t.insert("home_share".into(), Value::Table(hs));
    }
    let mut rs = Table::new();
    rs.insert("paths".into(), strs(root_rw));
    rs.insert("read_only_paths".into(), strs(root_ro));
    t.insert("root_share".into(), Value::Table(rs));

    // Environment via raw bwrap args; D-Bus extras via raw proxy args.
    let mut raw_bwrap: Vec<String> = Vec::new();
    for (k, v) in ctx.resolved_app_env(&appdir) {
        raw_bwrap.extend(["--setenv".into(), k, v]);
    }
    for (k, v) in &p.environment.set {
        raw_bwrap.extend(["--setenv".into(), k.clone(), v.clone()]);
    }
    raw_bwrap.extend(p.advanced.extra_backend_args.iter().cloned());
    let mut raw_dbus: Vec<String> = Vec::new();
    match p.dbus.session.mode {
        DbusMode::Filtered => {
            raw_dbus.extend(p.dbus.session.allow.iter().filter(|n| !n.starts_with("org.freedesktop.portal")).map(|n| format!("--talk={n}")));
            raw_dbus.extend(p.dbus.session.own.iter().map(|n| format!("--own={n}")));
        }
        DbusMode::Full => notes.push("bubblejail always filters the session bus; 'full' is treated as filtered".into()),
        DbusMode::None => {}
    }
    if p.dbus.system.mode != DbusMode::None {
        notes.push("system D-Bus is not granted through the bubblejail backend".into());
    }
    let mut debug = Table::new();
    debug.insert("raw_bwrap_args".into(), strs(raw_bwrap));
    debug.insert("raw_dbus_session_args".into(), strs(raw_dbus));
    t.insert("debug".into(), Value::Table(debug));
    (t, notes)
}

impl Backend for Bubblejail {
    fn kind(&self) -> BackendKind {
        BackendKind::Bubblejail
    }

    fn status(&self, host: &HostInfo) -> BackendStatus {
        let tool = host.tools.bubblejail.as_ref();
        BackendStatus {
            kind: BackendKind::Bubblejail,
            installed: tool.is_some(),
            path: tool.map(|t| t.path.clone()),
            version: tool.and_then(|t| t.version.clone()),
            usable: tool.is_some() && host.userns.usable(),
            recommended: false,
            risks: vec!["Permission mapping is coarser than Bubblewrap (no per-dotfile masking under full home).".into()],
            notes: if tool.is_some() {
                vec!["Optional advanced backend with better D-Bus filtering.".into()]
            } else {
                vec!["Not installed. Install 'bubblejail' to use it.".into()]
            },
        }
    }

    fn build(&self, ctx: &LaunchContext) -> Result<SandboxCommand> {
        let tool = ctx.host.tools.bubblejail.as_ref().context("bubblejail is not installed")?;
        let name = instance_name(&ctx.app_id);
        let dir = instances_dir().join(&name);
        fs::create_dir_all(dir.join("home")).with_context(|| format!("creating {}", dir.display()))?;
        let (table, mut notes) = services_toml(ctx);
        let services = dir.join("services.toml");
        atomic_write(&services, toml::to_string_pretty(&table)?.as_bytes())?;
        if ctx.helper.is_some() {
            notes.push("Landlock helper is not used with the bubblejail backend".into());
        }
        if ctx.seccomp_fd.is_some() {
            notes.push("custom seccomp filter is not used with the bubblejail backend".into());
        }
        let mut args = vec!["run".to_string(), name, "--".to_string()];
        if let Some(tr) = &ctx.tracer {
            args.extend(tr.iter().cloned());
        }
        args.push(format!("{}/{}", ctx.appdir.display(), ctx.entry));
        args.extend(ctx.args.iter().cloned());
        Ok(SandboxCommand {
            program: tool.path.clone(),
            args,
            env: vec![],
            clear_env: false,
            keep_fds: vec![],
            notes,
            generated_files: vec![services],
        })
    }
}

/// Remove the generated instance when an app is removed.
pub fn remove_instance(app_id: &str) -> Result<bool> {
    let dir = instances_dir().join(instance_name(app_id));
    if dir.join("services.toml").exists() {
        fs::remove_dir_all(&dir)?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use appseal_core::backend::sample_context;

    #[test]
    fn maps_permissions_to_services() {
        let mut ctx = sample_context();
        ctx.permissions.network.mode = NetworkMode::Full;
        ctx.permissions.audio.enabled = true;
        ctx.permissions.devices.gpu = true;
        let (t, _) = services_toml(&ctx);
        for s in ["common", "wayland", "network", "pulse_audio", "pipewire", "direct_rendering", "root_share", "debug"] {
            assert!(t.contains_key(s), "missing {s}");
        }
        assert!(!t.contains_key("x11"));
        let ro = t["root_share"]["read_only_paths"].as_array().unwrap();
        assert_eq!(ro[0].as_str().unwrap(), "/data/extracted/appimage-hello-1234/AppDir");
        let raw = t["debug"]["raw_bwrap_args"].as_array().unwrap();
        assert!(raw.iter().any(|v| v.as_str() == Some("/data/extracted/appimage-hello-1234/AppDir")), "APPDIR resolved to host path");
    }

    #[test]
    fn strict_has_no_network() {
        let (t, _) = services_toml(&sample_context());
        assert!(!t.contains_key("network"));
        assert!(!t.contains_key("home_share"));
    }
}
