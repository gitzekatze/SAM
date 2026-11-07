//! Firejail backend (optional compatibility backend, disabled by default).
//!
//! Firejail is a setuid-root program; Appseal only uses it when the user has
//! enabled it in settings *and* confirmed it for the app (§2.13.2).

use anyhow::{Context, Result};
use appseal_core::permissions::*;
use appseal_core::util::expand_home;
use appseal_core::{Backend, BackendKind, BackendStatus, HostInfo, LaunchContext, SandboxCommand};

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
            notes: vec!["Disabled by default. Enable it in Settings -> Security to use it as a compatibility backend.".into()],
        }
    }

    fn build(&self, ctx: &LaunchContext) -> Result<SandboxCommand> {
        let tool = ctx.host.tools.firejail.as_ref().context("firejail is not installed")?;
        let p = &ctx.permissions;
        let home = &ctx.host.home;
        let mut a: Vec<String> = vec![
            "--noprofile".into(),
            "--quiet".into(),
            "--caps.drop=all".into(),
            "--nonewprivs".into(),
            "--noroot".into(),
            "--seccomp".into(),
            "--private-tmp".into(),
            "--private-dev".into(),
            "--disable-mnt".into(),
        ];
        let mut notes = Vec::new();

        match p.network.mode {
            NetworkMode::Full => {}
            NetworkMode::None => a.push("--net=none".into()),
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
            for n in &p.dbus.session.allow {
                a.push(format!("--dbus-user.talk={n}"));
            }
            for n in &p.dbus.session.own {
                a.push(format!("--dbus-user.own={n}"));
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
            a.push(format!("--blacklist={hs}/.config/appseal"));
            a.push(format!("--blacklist={hs}/.local/share/appseal"));
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
        a.push(format!("--read-only={}", ctx.appdir.display()));

        let appdir = ctx.appdir.to_string_lossy().into_owned();
        for (k, v) in ctx.resolved_app_env(&appdir) {
            a.push(format!("--env={k}={v}"));
        }
        for (k, v) in &p.environment.set {
            a.push(format!("--env={k}={v}"));
        }
        a.extend(p.advanced.extra_backend_args.iter().cloned());
        a.push("--".into());
        if let Some(tr) = &ctx.tracer {
            a.extend(tr.iter().cloned());
        }
        a.push(format!("{appdir}/{}", ctx.entry));
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
    use appseal_core::backend::sample_context;

    #[test]
    fn strict_mapping() {
        let cmd = Firejail.build(&sample_context()).unwrap();
        let a = &cmd.args;
        for f in ["--net=none", "--no3d", "--nosound", "--x11=none", "--dbus-system=none", "--dbus-user=filter"] {
            assert!(a.iter().any(|x| x == f), "missing {f}");
        }
        assert!(a.iter().any(|x| x.starts_with("--private=")));
        assert!(a.last().unwrap().ends_with("/AppDir/AppRun"));
    }
}
