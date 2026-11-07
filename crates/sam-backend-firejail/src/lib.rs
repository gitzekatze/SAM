//! Firejail backend (optional compatibility backend, disabled by default).
//!
//! Firejail is a setuid-root program; SAM only uses it when the user has
//! enabled it in settings *and* confirmed it for the app (§2.13.2).
//!
//! Firejail runs the **original AppImage** with `--appimage`: it mounts the
//! image read-only itself. SAM's extracted copy cannot be used, because it
//! lives under the home directory (or /tmp), which `--private` and
//! `--private-tmp` replace inside the sandbox.

use anyhow::{Context, Result};
use sam_core::permissions::*;
use sam_core::util::expand_home;
use sam_core::{Backend, BackendKind, BackendStatus, HostInfo, LaunchContext, SandboxCommand};

pub struct Firejail;

pub const FIREJAIL_RISK: &str =
    "Firejail is a setuid-root program. Bugs in it have historically allowed local privilege escalation.";

impl Backend for Firejail {
    fn kind(&self) -> BackendKind {
        BackendKind::Firejail
    }

    fn status(&self, host: &HostInfo) -> BackendStatus {
        let tool = host.tools.firejail.as_ref();
        BackendStatus {
            kind: BackendKind::Firejail,
            installed: tool.is_some(),
            path: tool.map(|t| t.path.clone()),
            version: tool.and_then(|t| t.version.clone()),
            usable: tool.is_some(),
            recommended: false,
            risks: vec![FIREJAIL_RISK.into()],
            notes: vec!["Compatibility backend: runs the original AppImage file (firejail --appimage). SAM's Landlock layer and minimal /usr view are not used.".into()],
        }
    }

    fn build(&self, ctx: &LaunchContext) -> Result<SandboxCommand> {
        let tool = ctx.host.tools.firejail.as_ref().context("firejail is not installed")?;
        let appimage = ctx
            .appimage_path
            .as_ref()
            .context("the Firejail backend runs the original AppImage file, which is missing; relocate it or use Bubblewrap")?;
        let p = &ctx.permissions;
        let home = &ctx.host.home;
        let mut a: Vec<String> = vec![
            "--noprofile".into(),
            "--quiet".into(),
            "--caps.drop=all".into(),
            "--nonewprivs".into(),
            "--noroot".into(),
            "--private-tmp".into(),
            "--private-dev".into(),
            "--disable-mnt".into(),
        ];
        let mut notes = Vec::new();
        // Firejail's default seccomp filter blocks chroot, which Chromium's own
        // sandbox (Electron apps) needs; the zygote then dies at start. Exempt
        // only that syscall when nested sandboxes are allowed.
        a.push(if p.advanced.allow_userns { "--seccomp=!chroot".into() } else { "--seccomp".into() });

        match p.network.mode {
            NetworkMode::Full => {}
            NetworkMode::None => a.push("--net=none".into()),
            NetworkMode::Localhost => {
                a.push("--net=none".into());
                notes.push("'Local network only' is implemented by the Bubblewrap backend; with Firejail the app has no network".into());
            }
            m => {
                a.push("--net=none".into());
                notes.push(format!("network mode '{}' is experimental; network disabled", m.as_str()));
            }
        }
        if !p.devices.gpu {
            a.push("--no3d".into());
        }
        if !p.audio.enabled {
            a.push("--nosound".into());
        }
        if !p.devices.webcam {
            a.push("--novideo".into());
        }
        if !p.devices.input {
            a.push("--noinput".into());
        }
        if !p.display.x11 {
            a.push("--x11=none".into());
        }
        if !p.display.wayland {
            a.push(format!("--blacklist=/run/user/{}/wayland-*", ctx.host.uid));
        }
        a.push(match p.dbus.session.mode {
            DbusMode::None => "--dbus-user=none".into(),
            DbusMode::Filtered => "--dbus-user=filter".into(),
            DbusMode::Full => "--dbus-user=allow".into(),
        });
        if p.dbus.session.mode == DbusMode::Filtered {
            let bus = p.effective_session_bus();
            for n in &bus.allow {
                a.push(format!("--dbus-user.talk={n}"));
            }
            for n in &bus.own {
                a.push(format!("--dbus-user.own={n}"));
            }
            for r in &bus.calls {
                a.push(format!("--dbus-user.call={r}"));
            }
            for r in &bus.broadcasts {
                a.push(format!("--dbus-user.broadcast={r}"));
            }
        }
        a.push(if p.dbus.system.mode == DbusMode::Full { "--dbus-system=allow".into() } else { "--dbus-system=none".into() });

        // Filesystem.
        let fsp = &p.filesystem;
        let hs = home.to_string_lossy();
        if fsp.home {
            if !fsp.ssh {
                a.push(format!("--blacklist={hs}/.ssh"));
            }
            if !fsp.gnupg {
                a.push(format!("--blacklist={hs}/.gnupg"));
            }
            if fsp.home_access == Access::Ro {
                a.push(format!("--read-only={hs}"));
            }
            a.push(format!("--blacklist={hs}/.config/sam"));
            a.push(format!("--blacklist={hs}/.local/share/sam"));
        } else {
            let mut whitelisted = false;
            for key in XDG_DIR_KEYS {
                let acc = fsp.xdg_access(key);
                if let (true, Some(dir)) = (acc.is_granted(), ctx.host.xdg_dir(key)) {
                    a.push(format!("--whitelist={}", dir.display()));
                    if acc == Access::Ro {
                        a.push(format!("--read-only={}", dir.display()));
                    }
                    whitelisted = true;
                }
            }
            for c in &fsp.custom_write {
                let path = expand_home(c);
                if path.starts_with(home) {
                    a.push(format!("--whitelist={}", path.display()));
                    whitelisted = true;
                }
            }
            for c in &fsp.custom_read {
                let path = expand_home(c);
                if path.starts_with(home) {
                    a.push(format!("--whitelist={}", path.display()));
                    whitelisted = true;
                }
                a.push(format!("--read-only={}", path.display()));
            }
            if whitelisted {
                notes.push("firejail: home is a temporary filesystem with only granted folders; app settings are not kept".into());
            } else {
                a.push(format!("--private={}", ctx.private_home.display()));
            }
        }
        // Firejail sets APPDIR/APPIMAGE for the mounted image itself; only
        // pass variables that do not point into SAM's extracted copy.
        for (k, v) in &ctx.app_env {
            if !v.contains("@APPDIR@") && k != "APPIMAGE" {
                a.push(format!("--env={k}={v}"));
            }
        }
        for (k, v) in &p.environment.set {
            a.push(format!("--env={k}={v}"));
        }
        a.extend(p.advanced.extra_backend_args.iter().cloned());
        if ctx.tracer.is_some() {
            notes.push("diagnostic tracing is not supported with the firejail backend".into());
        }
        a.push("--appimage".into());
        a.push(appimage.to_string_lossy().into_owned());
        a.extend(ctx.args.iter().cloned());
        if ctx.helper.is_some() {
            notes.push("Landlock helper is not used with the firejail backend".into());
        }
        Ok(SandboxCommand {
            program: tool.path.clone(),
            args: a,
            env: vec![],
            clear_env: false,
            keep_fds: vec![],
            notes,
            generated_files: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::backend::sample_context;

    #[test]
    fn strict_mapping() {
        let cmd = Firejail.build(&sample_context()).unwrap();
        let a = &cmd.args;
        for f in ["--net=none", "--no3d", "--nosound", "--x11=none", "--dbus-system=none", "--dbus-user=filter", "--seccomp=!chroot"] {
            assert!(a.iter().any(|x| x == f), "missing {f}");
        }
        assert!(a.iter().any(|x| x.starts_with("--private=")));
        let i = a.iter().position(|x| x == "--appimage").expect("runs the AppImage itself");
        assert!(a[i + 1].ends_with("Hello.AppImage"));
        assert!(!a.iter().any(|x| x.contains("/AppDir")), "no paths into the extracted copy: {a:?}");
    }

    #[test]
    fn full_seccomp_without_nested_sandboxes() {
        let mut ctx = sample_context();
        ctx.permissions.advanced.allow_userns = false;
        assert!(Firejail.build(&ctx).unwrap().args.iter().any(|x| x == "--seccomp"));
    }

    #[test]
    fn needs_the_original_file() {
        let mut ctx = sample_context();
        ctx.appimage_path = None;
        assert!(Firejail.build(&ctx).is_err());
    }
}
