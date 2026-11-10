//! Environment checks, diagnostics screen data (§2.26) and redacted bug
//! reports (§2.20.7).

use std::process::{Command, Stdio};

use sam_core::util::{format_ts, now, tildify};
use sam_core::*;
use sam_intake::desktop::validate_launcher;
use sam_storage::{LogKind, Logs};

use crate::ops::Sam;

fn check(id: &str, label: &str, status: CheckStatus, detail: impl Into<String>) -> DiagnosticCheck {
    DiagnosticCheck::new(id, label, status, detail)
}

/// Quick functional test: can bwrap actually create a sandbox here?
pub fn bwrap_functional(host: &HostInfo) -> Result<(), String> {
    let Some(b) = &host.tools.bwrap else { return Err("not installed".into()) };
    let out = Command::new(&b.path)
        .args(["--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr"])
        .args(["--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin"])
        .args(["--proc", "/proc", "--dev", "/dev", "--", "/usr/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn system_report(app: &Sam, host: &HostInfo) -> DiagnosticReport {
    let mut c = Vec::new();
    let cfg = &app.config;

    match &host.tools.bwrap {
        Some(t) => {
            c.push(check("bwrap", "Bubblewrap", CheckStatus::Ok, format!("installed ({})", t.version.clone().unwrap_or_else(|| t.path.display().to_string()))));
            match bwrap_functional(host) {
                Ok(()) => c.push(check("bwrap-run", "Sandbox test", CheckStatus::Ok, "a test sandbox started successfully")),
                Err(e) => c.push(check("bwrap-run", "Sandbox test", CheckStatus::Fail, format!("bubblewrap failed: {e}")).hint("Check that user namespaces are enabled, or that AppArmor allows bwrap.")),
            }
        }
        None => c.push(check("bwrap", "Bubblewrap", CheckStatus::Fail, "Bubblewrap is not installed.").hint("Install it: sudo pacman -S bubblewrap")),
    }
    c.push(if host.userns.usable() {
        check("userns", "User namespaces", CheckStatus::Ok, format!("enabled (max {})", host.userns.max_user_namespaces.map(|v| v.to_string()).unwrap_or_else(|| "?".into())))
    } else {
        check("userns", "User namespaces", CheckStatus::Fail, host.userns.explain())
    });
    if host.userns.apparmor_restricted == Some(true) {
        c.push(check("apparmor", "AppArmor userns restriction", CheckStatus::Warn, host.userns.explain()));
    }
    c.push(match host.landlock_abi {
        Some(v) => check("landlock", "Landlock", CheckStatus::Ok, format!("ABI v{v} available{}", if cfg.security.experimental_landlock { ", enabled" } else { ", disabled in settings" })),
        None => check("landlock", "Landlock", CheckStatus::Info, "not available on this kernel (optional)"),
    });
    c.push(check("seccomp", "Seccomp", if host.seccomp { CheckStatus::Ok } else { CheckStatus::Info }, if host.seccomp { format!("available; strict mode {}", if cfg.security.experimental_seccomp { "enabled" } else { "disabled (experimental)" }) } else { "not detected".into() }));
    c.push(check("ebpf", "eBPF network filtering", CheckStatus::Info, "experimental, not implemented in this release"));

    c.push(match &host.tools.xdg_dbus_proxy {
        Some(_) => check("dbus-proxy", "xdg-dbus-proxy", CheckStatus::Ok, "installed: filtered session D-Bus available"),
        None => check("dbus-proxy", "xdg-dbus-proxy", CheckStatus::Warn, "not installed: filtered D-Bus falls back to no D-Bus").hint("Install xdg-dbus-proxy."),
    });

    let mut extract_tools = vec!["built-in SquashFS reader (gzip, xz, zstd)".to_string()];
    if host.tools.unsquashfs.is_some() {
        extract_tools.push("unsquashfs".into());
    }
    if host.tools.bsdtar.is_some() {
        extract_tools.push("bsdtar (Type 1)".into());
    }
    c.push(check("extract", "AppImage extraction", if host.tools.bsdtar.is_some() { CheckStatus::Ok } else { CheckStatus::Warn }, extract_tools.join(", ")));
    c.push(match &host.tools.strace {
        Some(_) => check("strace", "Dynamic diagnosis", CheckStatus::Ok, "strace installed"),
        None => check("strace", "Dynamic diagnosis", CheckStatus::Info, "strace not installed (optional, used by 'sam-jail diagnose')"),
    });

    let s = &host.sockets;
    c.push(check("session", "Session", CheckStatus::Info, format!("{} {} on {} ({})", host.session_type, host.desktop, host.distro, host.kernel)));
    c.push(match &s.wayland {
        Some(p) => check("wayland", "Wayland socket", CheckStatus::Ok, tildify(p)),
        None => check("wayland", "Wayland socket", if host.session_type == "wayland" { CheckStatus::Warn } else { CheckStatus::Info }, "The Wayland socket is not available."),
    });
    c.push(match (&s.x11, &s.x11_display) {
        (Some(p), _) => check("x11", "X11 display", CheckStatus::Ok, format!("{} ({})", s.x11_display.clone().unwrap_or_default(), p.display())),
        (None, Some(d)) => check("x11", "X11 display", CheckStatus::Warn, format!("DISPLAY={d} but no socket in /tmp/.X11-unix")),
        (None, None) => check("x11", "X11 display", CheckStatus::Info, "no X11 display"),
    });
    c.push(match (&s.pipewire, &s.pulse) {
        (Some(_), Some(_)) => check("audio", "Audio", CheckStatus::Ok, "PipeWire and PulseAudio sockets found"),
        (Some(_), None) => check("audio", "Audio", CheckStatus::Ok, "PipeWire socket found"),
        (None, Some(_)) => check("audio", "Audio", CheckStatus::Ok, "PulseAudio socket found"),
        (None, None) => check("audio", "Audio", CheckStatus::Warn, "PipeWire socket not found. Audio may not work."),
    });
    c.push(match &s.dbus_session {
        Some(_) => check("dbus", "Session D-Bus", CheckStatus::Ok, "available"),
        None => check("dbus", "Session D-Bus", CheckStatus::Warn, "session bus socket not found"),
    });
    c.push(check("gpu", "GPU devices", if host.gpu_devices.is_empty() { CheckStatus::Warn } else { CheckStatus::Ok }, if host.gpu_devices.is_empty() { "no /dev/dri devices".to_string() } else { host.gpu_devices.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ") }));
    c.push(match crate::find_helper() {
        Some(p) => check("helper", "sam-jail-run", CheckStatus::Ok, tildify(&p)),
        None => check("helper", "sam-jail-run", CheckStatus::Fail, "sam-jail-run not found; launchers and Landlock will not work"),
    });

    if let Ok(apps) = app.registry().list() {
        let count = |b: Badge| apps.iter().filter(|a| a.badge() == b).count();
        let detail = format!(
            "{} registered; {} ready, {} need review, {} stale, {} broken, {} missing",
            apps.len(), count(Badge::Ready), count(Badge::NeedsReview), count(Badge::Stale), count(Badge::Broken), count(Badge::Missing)
        );
        let st = if count(Badge::Broken) + count(Badge::Missing) > 0 { CheckStatus::Warn } else { CheckStatus::Ok };
        c.push(check("apps", "Registered apps", st, detail));
    }
    // Files SAM could not read and moved aside (see sam_core::format).
    let p = &app.paths;
    let damaged = sam_core::format::damaged_files(&[p.config_dir.as_path(), p.apps_dir().as_path(), p.presets_dir().as_path()]);
    c.push(if damaged.is_empty() {
        check("damaged", "Damaged files", CheckStatus::Ok, "none")
    } else {
        check(
            "damaged",
            "Damaged files",
            CheckStatus::Warn,
            format!(
                "SAM could not read these and moved them aside (nothing was deleted); restore one by fixing it and removing the .damaged-… ending, or delete it: {}",
                damaged.iter().map(|d| tildify(d)).collect::<Vec<_>>().join(", ")
            ),
        )
    });
    DiagnosticReport { generated_at: now(), sam_version: SAM_VERSION.into(), checks: c }
}

pub fn app_report(_app: &Sam, e: &AppEntry, host: &HostInfo) -> DiagnosticReport {
    let mut c = Vec::new();
    c.push(if e.source_path.exists() {
        check("source", "Source AppImage", CheckStatus::Ok, tildify(&e.source_path))
    } else {
        check("source", "Source AppImage", CheckStatus::Warn, format!("The selected AppImage no longer exists ({})", tildify(&e.source_path)))
    });
    match &e.extraction {
        Some(x) if x.appdir.join(&x.entry).exists() => c.push(check("extraction", "AppImage extraction", CheckStatus::Ok, format!("success via {} ({} files)", x.method, x.file_count))),
        Some(_) => c.push(check("extraction", "AppImage extraction", CheckStatus::Fail, "extracted payload is missing").hint("Re-extract the AppImage.")),
        None => c.push(check("extraction", "AppImage extraction", CheckStatus::Fail, e.last_error.clone().unwrap_or_else(|| "not extracted".into())).hint("Re-extract the AppImage (optionally allowing the fallback extractor).")),
    }
    if let Some(d) = &e.detection {
        let host_res = d.resources.iter().filter(|r| !r.auto).count();
        let st = match d.compatibility {
            Compatibility::Good => CheckStatus::Ok,
            Compatibility::Risk => CheckStatus::Warn,
            Compatibility::LikelyBroken => CheckStatus::Fail,
        };
        c.push(check("detect", "Dependency detection", st, format!("{host_res} controlled host resources required; toolkit {}; {} libraries expected from the host", d.requirements.toolkit, d.missing.len())));
    }
    match crate::select::select(host) {
        Ok(s) => c.push(check("backend", "Sandbox", CheckStatus::Ok, format!("Bubblewrap ({})", s.reason))),
        Err(err) => c.push(check("backend", "Sandbox", CheckStatus::Fail, err.to_string())),
    }
    match &e.desktop_entry {
        Some(p) => {
            let problems = validate_launcher(p, &e.id);
            c.push(if problems.is_empty() {
                check("launcher", "Desktop entry", CheckStatus::Ok, tildify(p))
            } else {
                check("launcher", "Desktop entry", CheckStatus::Warn, problems.join("; ")).hint("Reinstall the launcher (sam-jail desktop <app> install).")
            });
        }
        None => c.push(check("launcher", "Desktop entry", CheckStatus::Info, "no launcher installed")),
    }
    if let Some(l) = &e.last_launch {
        let st = if l.sandbox_failure { CheckStatus::Fail } else if l.success { CheckStatus::Ok } else { CheckStatus::Warn };
        c.push(check("last-launch", "Last launch", st, format!("{} — {}", format_ts(l.started_at), l.summary)));
    }
    DiagnosticReport { generated_at: now(), sam_version: SAM_VERSION.into(), checks: c }
}

/// Replace identifying information before a report leaves the machine.
pub fn redact(s: &str, host: &HostInfo) -> String {
    let mut out = s.replace(&host.home.display().to_string(), "~");
    if host.user.len() > 2 {
        out = out.replace(&host.user, "<user>");
    }
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let h = h.trim();
        if h.len() > 2 {
            out = out.replace(h, "<host>");
        }
    }
    out
}

/// Markdown bug report for one app (or the system), redacted.
pub fn bug_report(app: &Sam, e: Option<&AppEntry>, host: &HostInfo) -> String {
    let mut s = format!("## SAM bug report\n\n- SAM: {}\n- Generated: {}\n- System: {} / kernel {} / {} {}\n\n", SAM_VERSION, format_ts(now()), host.distro, host.kernel, host.desktop, host.session_type);
    s += "### Environment\n\n";
    for ch in system_report(app, host).checks {
        s += &format!("- [{:?}] {}: {}\n", ch.status, ch.label, ch.detail);
    }
    if let Some(e) = e {
        s += &format!("\n### App: {} ({})\n\n- Type: {}\n- Category: {}\n- State: {:?} / badge {}\n", e.display_name(), e.id, e.appimage_type.label(), e.category, e.state, e.badge().label());
        if let Some(x) = &e.extraction {
            s += &format!("- Extraction: {} ({}), {} files\n", x.method, x.compression, x.file_count);
        }
        if let Some(d) = &e.detection {
            s += &format!("- Toolkit: {}; compatibility {:?}; verdict {:?}\n", d.requirements.toolkit, d.compatibility, d.verdict);
        }
        for ch in app_report(app, e, host).checks {
            s += &format!("- [{:?}] {}: {}\n", ch.status, ch.label, ch.detail);
        }
        s += "\n#### Permissions\n\n```toml\n";
        s += &toml_string(&e.profile.permissions);
        s += "```\n";
        let logs = Logs::new(&app.paths);
        if let Ok(Some(l)) = logs.latest(&e.id, Some(LogKind::Launch)) {
            s += "\n#### Last launch log (tail)\n\n```\n";
            s += &crate::launch::tail(&l.path, 60);
            s += "\n```\n";
        }
    }
    redact(&s, host)
}

fn toml_string<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .map(|j| serde_json::to_string_pretty(&j).unwrap_or_default())
        .unwrap_or_default()
        + "\n"
}
