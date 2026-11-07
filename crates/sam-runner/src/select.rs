//! Backend selection (§2.13.3).
//!
//! Automatic selection prefers:
//! 1. Bubblewrap if available and functional.
//! 2. Bubblejail if D-Bus filtering is required and only Bubblejail can provide it.
//! 3. Firejail only if the user enabled it (never chosen automatically).
//! 4. Unsandboxed only as an explicit, confirmed fallback.

use anyhow::{bail, Result};
use sam_core::permissions::DbusMode;
use sam_core::{BackendChoice, BackendKind, BackendStatus, Config, HostInfo, SandboxProfile};
use serde::Serialize;

use crate::backend_for;

#[derive(Debug, Clone, Serialize)]
pub struct Selection {
    pub kind: BackendKind,
    pub reason: String,
    pub risks: Vec<String>,
}

pub fn statuses(host: &HostInfo, cfg: &Config) -> Vec<BackendStatus> {
    let mut v: Vec<BackendStatus> = [BackendKind::Bubblewrap, BackendKind::Bubblejail, BackendKind::Firejail]
        .iter()
        .filter_map(|k| backend_for(*k))
        .map(|b| b.status(host))
        .collect();
    for s in &mut v {
        if s.kind == BackendKind::Firejail && !cfg.security.allow_firejail {
            s.usable = false;
            if s.installed {
                s.notes.insert(0, "Installed but disabled in settings. Enable it in Settings -> Security (security.allow_firejail).".into());
            }
        }
    }
    v.push(BackendStatus {
        kind: BackendKind::Unsandboxed,
        installed: true,
        path: None,
        version: None,
        usable: true,
        recommended: false,
        risks: vec!["No isolation at all. The app runs with all of your permissions.".into()],
        notes: vec!["Last resort; requires explicit confirmation per app.".into()],
    });
    v
}

fn status_of(all: &[BackendStatus], k: BackendKind) -> Option<&BackendStatus> {
    all.iter().find(|s| s.kind == k)
}

pub fn select(profile: &SandboxProfile, cfg: &Config, host: &HostInfo) -> Result<Selection> {
    let all = statuses(host, cfg);
    let usable = |k| status_of(&all, k).is_some_and(|s| s.usable);
    let risks_of = |k| status_of(&all, k).map(|s| s.risks.clone()).unwrap_or_default();

    if let Some(k) = profile.backend.fixed() {
        match k {
            BackendKind::Unsandboxed => {
                if !profile.unsandboxed_confirmed {
                    bail!("running unsandboxed requires explicit confirmation (sam-jail backend <app> unsandboxed --confirm)");
                }
                return Ok(Selection { kind: k, reason: "chosen by you (explicitly confirmed)".into(), risks: risks_of(k) });
            }
            BackendKind::Firejail => {
                if !cfg.security.allow_firejail {
                    bail!("Firejail is disabled. Enable it in Settings -> Security (security.allow_firejail) first.");
                }
                if !profile.firejail_confirmed {
                    bail!("Firejail must be confirmed for this app (sam-jail backend <app> firejail --confirm)");
                }
            }
            _ => {}
        }
        if !usable(k) {
            let status = status_of(&all, k);
            if !status.is_some_and(|s| s.installed) {
                bail!("the {} backend is not available: it is not installed on this system", k.label());
            }
            let why = status.map(|s| s.notes.join(" ")).unwrap_or_default();
            bail!("the {} backend is not available: {why}", k.label());
        }
        return Ok(Selection { kind: k, reason: "chosen by you for this app".into(), risks: risks_of(k) });
    }

    // Automatic choice, per app, for best compatibility.
    let allowed = |k: BackendKind| usable(k) && (k != BackendKind::Firejail || cfg.security.allow_firejail);
    // 1. Features only Bubblewrap implements.
    let p = &profile.permissions;
    if usable(BackendKind::Bubblewrap) {
        let need = if p.network.mode == sam_core::permissions::NetworkMode::Localhost {
            Some("'Local network only' is implemented by Bubblewrap")
        } else if p.advanced.writable_appdir {
            Some("the writable app folder is implemented by Bubblewrap")
        } else {
            None
        };
        if let Some(why) = need {
            return Ok(Selection { kind: BackendKind::Bubblewrap, reason: why.into(), risks: risks_of(BackendKind::Bubblewrap) });
        }
    }
    // 2. What worked for this app before.
    if let Some(l) = &profile.auto_backend {
        if allowed(l.kind) {
            return Ok(Selection { kind: l.kind, reason: format!("picked for this app: {}", l.reason), risks: risks_of(l.kind) });
        }
    }

    let wants_filtering = profile.permissions.dbus.session.mode == DbusMode::Filtered;
    if wants_filtering && host.tools.xdg_dbus_proxy.is_none() && usable(BackendKind::Bubblejail) {
        return Ok(Selection {
            kind: BackendKind::Bubblejail,
            reason: "D-Bus filtering is required, xdg-dbus-proxy is missing and Bubblejail is installed".into(),
            risks: risks_of(BackendKind::Bubblejail),
        });
    }
    let default = match cfg.general.default_backend {
        BackendChoice::Auto | BackendChoice::Unsandboxed => BackendKind::Bubblewrap,
        other => other.fixed().unwrap_or(BackendKind::Bubblewrap),
    };
    if usable(default) && (default != BackendKind::Firejail || cfg.security.allow_firejail) {
        let reason = if default == BackendKind::Bubblewrap {
            "Bubblewrap is the default backend and is available".to_string()
        } else {
            format!("{} is your configured default backend", default.label())
        };
        return Ok(Selection { kind: default, reason, risks: risks_of(default) });
    }
    for k in [BackendKind::Bubblewrap, BackendKind::Bubblejail, BackendKind::Firejail] {
        if allowed(k) {
            return Ok(Selection {
                kind: k,
                reason: format!("{} is the first available backend", k.label()),
                risks: risks_of(k),
            });
        }
    }
    let hint = if !host.userns.usable() {
        host.userns.explain()
    } else {
        "Bubblewrap is not installed. Install the 'bubblewrap' package.".into()
    };
    bail!("no sandbox backend is available. {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sam_core::backend::sample_context;

    #[test]
    fn auto_prefers_bubblewrap() {
        let host = sample_context().host;
        let s = select(&SandboxProfile::default(), &Config::default(), &host).unwrap();
        assert_eq!(s.kind, BackendKind::Bubblewrap);
    }

    #[test]
    fn bubblejail_when_filtering_without_proxy() {
        let mut host = sample_context().host;
        host.tools.xdg_dbus_proxy = None;
        let s = select(&SandboxProfile::default(), &Config::default(), &host).unwrap();
        assert_eq!(s.kind, BackendKind::Bubblejail);
    }

    #[test]
    fn firejail_and_unsandboxed_need_confirmation() {
        let host = sample_context().host;
        let mut p = SandboxProfile { backend: BackendChoice::Firejail, ..Default::default() };
        let mut cfg = Config::default();
        assert!(select(&p, &cfg, &host).is_err(), "disabled by default");
        cfg.security.allow_firejail = true;
        assert!(select(&p, &cfg, &host).is_err(), "needs per-app confirmation");
        p.firejail_confirmed = true;
        assert_eq!(select(&p, &cfg, &host).unwrap().kind, BackendKind::Firejail);

        let mut u = SandboxProfile { backend: BackendChoice::Unsandboxed, ..Default::default() };
        assert!(select(&u, &cfg, &host).is_err());
        u.unsandboxed_confirmed = true;
        assert_eq!(select(&u, &cfg, &host).unwrap().kind, BackendKind::Unsandboxed);
    }

    #[test]
    fn no_backend_gives_guidance() {
        let mut host = sample_context().host;
        host.tools.bwrap = None;
        host.tools.bubblejail = None;
        let err = select(&SandboxProfile::default(), &Config::default(), &host).unwrap_err();
        assert!(err.to_string().contains("Bubblewrap is not installed"));
    }

    #[test]
    fn automatic_choice_is_per_app() {
        let host = sample_context().host;
        let cfg = Config::default();
        let mut p = SandboxProfile::default();
        p.auto_backend = Some(sam_core::LearnedBackend { kind: BackendKind::Bubblejail, reason: "Bubblewrap failed".into() });
        let s = select(&p, &cfg, &host).unwrap();
        assert_eq!(s.kind, BackendKind::Bubblejail);
        assert!(s.reason.contains("Bubblewrap failed"));
        // Features only Bubblewrap implements win over the learned choice.
        p.permissions.network.mode = sam_core::permissions::NetworkMode::Localhost;
        assert_eq!(select(&p, &cfg, &host).unwrap().kind, BackendKind::Bubblewrap);
        // A learned Firejail choice is only used while Firejail is allowed.
        p.permissions.network.mode = sam_core::permissions::NetworkMode::None;
        p.auto_backend = Some(sam_core::LearnedBackend { kind: BackendKind::Firejail, reason: "x".into() });
        assert_eq!(select(&p, &cfg, &host).unwrap().kind, BackendKind::Bubblewrap);
        let mut cfg2 = Config::default();
        cfg2.security.allow_firejail = true;
        assert_eq!(select(&p, &cfg2, &host).unwrap().kind, BackendKind::Firejail);
        // A backend the user picked always wins.
        p.backend = sam_core::BackendChoice::Bubblejail;
        assert_eq!(select(&p, &cfg2, &host).unwrap().kind, BackendKind::Bubblejail);
    }
}
