//! Environment checks, diagnostics screen data and redacted bug
//! reports.

use sam_core::i18n::tr;
use std::process::{Command, Stdio};

use sam_core::util::{format_ts, now, tildify};
use sam_core::*;
use sam_intake::desktop::validate_launcher;
use sam_storage::{LogKind, Logs};

use crate::ops::Sam;

fn check(id: &str, label: &str, status: CheckStatus, detail: impl Into<String>) -> DiagnosticCheck {
    DiagnosticCheck::new(id, &tr(label), status, tr(&detail.into()))
}

/// Quick functional test: can bwrap actually create a sandbox here?
pub fn bwrap_functional(host: &HostInfo) -> Result<(), String> {
    let Some(b) = &host.tools.bwrap else {
        return Err("not installed".into());
    };
    let out = Command::new(&b.path)
        .args([
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/usr",
            "/usr",
        ])
        .args([
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--symlink",
            "usr/bin",
            "/bin",
        ])
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
            c.push(check(
                "bwrap",
                "Bubblewrap",
                CheckStatus::Ok,
                format!(
                    "installed ({})",
                    t.version
                        .clone()
                        .unwrap_or_else(|| t.path.display().to_string())
                ),
            ));
            match bwrap_functional(host) {
                Ok(()) => c.push(check(
                    "bwrap-run",
                    "Sandbox test",
                    CheckStatus::Ok,
                    "a test sandbox started successfully",
                )),
                Err(e) => c.push(
                    check(
                        "bwrap-run",
                        "Sandbox test",
                        CheckStatus::Fail,
                        format!("bubblewrap failed: {e}"),
                    )
                    .hint(sam_core::i18n::tr(
                        "See the check \"User namespaces\": it says what keeps Bubblewrap from working here and how to fix it without making the system less safe.",
                    )),
                ),
            }
        }
        None => c.push(
            check(
                "bwrap",
                "Bubblewrap",
                CheckStatus::Fail,
                "Bubblewrap is not installed.",
            )
            .hint(sam_core::host::install_hint("bubblewrap")),
        ),
    }
    // A helper installed only in the home is skipped on purpose (an app
    // with write access to the home could replace it): say so, instead of
    // only "not installed".
    let skipped: Vec<String> = HELPERS
        .iter()
        .filter_map(|n| sam_core::util::skipped_copy(n))
        .map(|p| sam_core::util::tildify(&p))
        .collect();
    if !skipped.is_empty() {
        c.push(
            check(
                "home-programs",
                "Programs in your home",
                CheckStatus::Warn,
                sam_core::i18n::trf(
                    "SAM does not use {programs}: an app with access to your home could replace them.",
                    &[("programs", &skipped.join(", "))],
                ),
            )
            .hint(sam_core::i18n::tr(
                "Install these programs for the whole system, with your distribution's package manager.",
            )),
        );
    }
    c.push(if host.userns.usable() {
        check(
            "userns",
            "User namespaces",
            CheckStatus::Ok,
            format!(
                "enabled (max {})",
                host.userns
                    .max_user_namespaces
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into())
            ),
        )
    } else {
        check(
            "userns",
            "User namespaces",
            CheckStatus::Fail,
            host.userns.explain(),
        )
    });
    if host.userns.apparmor_restricted == Some(true) {
        c.push(check(
            "apparmor",
            "AppArmor userns restriction",
            CheckStatus::Warn,
            host.userns.explain(),
        ));
    }
    c.push(match host.landlock_abi {
        // Before Linux 6.12 (ABI 6) Landlock cannot fence abstract sockets
        // (review K-1): said here once, not hidden in "partially enforced".
        Some(v) if v < 6 && cfg.security.experimental_landlock => check(
            "landlock",
            "Landlock",
            CheckStatus::Warn,
            sam_core::i18n::trf(
                "ABI v{abi} available, enabled. It cannot fence abstract sockets (that needs Linux 6.12): an app with full network can reach services of your desktop through them, such as the X server, even with X11 off. Apps without network or with 'This computer only' are not affected.",
                &[("abi", &v)],
            ),
        ),
        Some(v) => check(
            "landlock",
            "Landlock",
            CheckStatus::Ok,
            format!(
                "ABI v{v} available{}",
                if cfg.security.experimental_landlock {
                    ", enabled"
                } else {
                    ", disabled in settings"
                }
            ),
        ),
        None => check(
            "landlock",
            "Landlock",
            CheckStatus::Info,
            "not available on this kernel (optional)",
        ),
    });
    c.push(check(
        "seccomp",
        "Seccomp",
        if host.seccomp {
            CheckStatus::Ok
        } else {
            CheckStatus::Info
        },
        if host.seccomp {
            "available; the strict filter is switched on per app".to_string()
        } else {
            "not detected".into()
        },
    ));

    c.push(match &host.tools.xdg_dbus_proxy {
        Some(_) => check(
            "dbus-proxy",
            "xdg-dbus-proxy",
            CheckStatus::Ok,
            "installed: filtered session D-Bus available",
        ),
        None => check(
            "dbus-proxy",
            "xdg-dbus-proxy",
            CheckStatus::Warn,
            "not installed: filtered D-Bus falls back to no D-Bus",
        )
        .hint(sam_core::i18n::tr("Install xdg-dbus-proxy.")),
    });

    let mut extract_tools = vec!["built-in SquashFS reader (gzip, xz, zstd)".to_string()];
    if host.tools.unsquashfs.is_some() {
        extract_tools.push("unsquashfs".into());
    }
    if host.tools.bsdtar.is_some() {
        extract_tools.push("bsdtar (Type 1)".into());
    }
    c.push(check(
        "extract",
        "Unpacking the AppImage",
        if host.tools.bsdtar.is_some() {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        extract_tools.join(", "),
    ));
    c.push(match &host.tools.strace {
        Some(_) => check(
            "strace",
            "Dynamic diagnosis",
            CheckStatus::Ok,
            "strace installed",
        ),
        None => check(
            "strace",
            "Dynamic diagnosis",
            CheckStatus::Info,
            "strace not installed (optional, used by 'sam-jail diagnose')",
        ),
    });

    let s = &host.sockets;
    c.push(check(
        "session",
        "Session",
        CheckStatus::Info,
        format!(
            "{} {} on {} ({})",
            host.session_type, host.desktop, host.distro, host.kernel
        ),
    ));
    c.push(match &s.wayland {
        Some(p) => check("wayland", "Wayland socket", CheckStatus::Ok, tildify(p)),
        None => check(
            "wayland",
            "Wayland socket",
            if host.session_type == "wayland" {
                CheckStatus::Warn
            } else {
                CheckStatus::Info
            },
            "The Wayland socket is not available.",
        ),
    });
    if let Some(display) = &s.wayland {
        c.push(if crate::wayland_ctx::supported(display) {
            check("wayland-context", "Wayland security context", CheckStatus::Ok, "supported: sandboxed apps do not see privileged Wayland functions")
        } else {
            check(
                "wayland-context",
                "Wayland security context",
                CheckStatus::Info,
                "not supported by this desktop: sandboxed apps see every Wayland function it offers",
            )
        });
    }
    c.push(match (&s.x11, &s.x11_display) {
        (Some(p), _) => check(
            "x11",
            "X11 display",
            CheckStatus::Ok,
            format!(
                "{} ({})",
                s.x11_display.clone().unwrap_or_default(),
                p.display()
            ),
        ),
        (None, Some(d)) => check(
            "x11",
            "X11 display",
            CheckStatus::Warn,
            sam_core::i18n::trf(
                "DISPLAY is {display}, but there is no socket for it in /tmp/.X11-unix",
                &[("display", &d)],
            ),
        ),
        (None, None) => check("x11", "X11 display", CheckStatus::Info, "no X11 display"),
    });
    c.push(match (crate::sound_relay::relay_possible(host), &s.pipewire, &s.pulse) {
        (true, _, _) => check("audio", "Audio", CheckStatus::Ok, "PipeWire runs: apps get sound through SAM's relay, which cannot load modules into the sound server"),
        (false, Some(_), _) => check("audio", "Audio", CheckStatus::Warn, "PipeWire runs, but its program was not found, so SAM cannot run its sound relay and apps get no sound. Install the pipewire package"),
        (false, None, Some(_)) => check("audio", "Audio", CheckStatus::Warn, "The sound server is not PipeWire, so SAM cannot run its sound relay and apps get no sound. An app gets sound only with \"Sound without SAM's relay\", which lets it load code into the sound server outside the sandbox"),
        (false, None, None) => check("audio", "Audio", CheckStatus::Warn, "No sound server found. Audio may not work."),
    });
    c.push(match &s.dbus_session {
        Some(_) => check("dbus", "Session D-Bus", CheckStatus::Ok, "available"),
        None => check(
            "dbus",
            "Session D-Bus",
            CheckStatus::Warn,
            "session bus socket not found",
        ),
    });
    c.push(check(
        "gpu",
        "GPU devices",
        if host.gpu_devices.is_empty() {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        },
        if host.gpu_devices.is_empty() {
            "no /dev/dri devices".to_string()
        } else {
            host.gpu_devices
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
    ));
    let overlays = app.paths.overlays_dir();
    c.push(if sam_core::host::overlay_works_in(&overlays) {
        check("overlay", "Writable app folder", CheckStatus::Ok, "Bubblewrap supports overlays")
    } else if sam_core::host::bwrap_supports_overlay() {
        check(
            "overlay",
            "Writable app folder",
            CheckStatus::Info,
            sam_core::i18n::trf("{folder} is on a filesystem that cannot hold an overlay; app folders stay read-only", &[("folder", &tildify(&overlays))]),
        )
    } else {
        check("overlay", "Writable app folder", CheckStatus::Info, "needs Bubblewrap 0.11 or newer; app folders stay read-only")
    });
    c.push(match crate::netns::pasta_usable() {
        Ok(p) => check(
            "pasta",
            "This computer only",
            CheckStatus::Ok,
            format!("pasta with --splice-only ({})", tildify(&p)),
        ),
        Err(e) => check(
            "pasta",
            "This computer only",
            CheckStatus::Warn,
            format!("{e:#}"),
        ),
    });
    c.push(match crate::find_helper() {
        Some(p) => check("helper", "sam-jail-run", CheckStatus::Ok, tildify(&p)),
        None => check(
            "helper",
            "sam-jail-run",
            CheckStatus::Fail,
            "sam-jail-run not found; launchers and Landlock will not work",
        ),
    });

    if let Ok(apps) = app.registry().list() {
        let count = |b: Badge| apps.iter().filter(|a| a.badge() == b).count();
        let detail = format!(
            "{} registered; {} ready, {} need review, {} stale, {} broken, {} missing",
            apps.len(),
            count(Badge::Ready),
            count(Badge::NeedsReview),
            count(Badge::Stale),
            count(Badge::Broken),
            count(Badge::Missing)
        );
        let st = if count(Badge::Broken) + count(Badge::Missing) > 0 {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        };
        c.push(check("apps", "Registered apps", st, detail));
        c.push(tmp_grants(&apps));
    }
    // Files SAM could not read and moved aside (see sam_core::format).
    let p = &app.paths;
    let damaged = sam_core::format::damaged_files(&[
        p.config_dir.as_path(),
        p.apps_dir().as_path(),
        p.presets_dir().as_path(),
    ]);
    c.push(if damaged.is_empty() {
        check("damaged", "Damaged files", CheckStatus::Ok, "none")
    } else {
        check(
            "damaged",
            "Damaged files",
            CheckStatus::Warn,
            sam_core::i18n::trf(
                "SAM could not read these and moved them aside (nothing was deleted); restore one by fixing it and removing the .damaged-… ending, or delete it: {files}",
                &[("files", &damaged.iter().map(|d| tildify(d)).collect::<Vec<_>>().join(", "))],
            ),
        )
    });
    DiagnosticReport {
        generated_at: now(),
        sam_version: SAM_VERSION.into(),
        checks: c,
    }
}

pub fn app_report(_app: &Sam, e: &AppEntry, host: &HostInfo) -> DiagnosticReport {
    let mut c = Vec::new();
    c.push(if e.source_path.exists() {
        check(
            "source",
            "Source AppImage",
            CheckStatus::Ok,
            tildify(&e.source_path),
        )
    } else {
        check(
            "source",
            "Source AppImage",
            CheckStatus::Warn,
            sam_core::i18n::trf(
                "The selected AppImage no longer exists ({file}).",
                &[("file", &tildify(&e.source_path))],
            ),
        )
    });
    match &e.extraction {
        Some(x) if x.appdir.join(&x.entry).exists() => c.push(check(
            "extraction",
            "Unpacking the AppImage",
            CheckStatus::Ok,
            format!("success via {} ({} files)", x.method, x.file_count),
        )),
        Some(_) => c.push(
            check(
                "extraction",
                "Unpacking the AppImage",
                CheckStatus::Fail,
                "the unpacked app is missing",
            )
            .hint(sam_core::i18n::tr("Unpack the AppImage again.")),
        ),
        None => c.push(
            check(
                "extraction",
                "Unpacking the AppImage",
                CheckStatus::Fail,
                e.last_error
                    .clone()
                    .unwrap_or_else(|| "not extracted".into()),
            )
            .hint(sam_core::i18n::tr(
                "Unpack the AppImage again (if SAM cannot, allow the AppImage to unpack itself).",
            )),
        ),
    }
    if let Some(d) = &e.detection {
        let host_res = d.resources.iter().filter(|r| !r.auto).count();
        let st = match d.compatibility {
            Compatibility::Good => CheckStatus::Ok,
            Compatibility::Risk => CheckStatus::Warn,
            Compatibility::LikelyBroken => CheckStatus::Fail,
        };
        c.push(check(
            "detect",
            "Dependency detection",
            st,
            sam_core::i18n::trf(
                "{resources} controlled host resources required; toolkit {toolkit}; {libraries} libraries expected from the host",
                &[("resources", &host_res), ("toolkit", &d.requirements.toolkit), ("libraries", &d.missing.len())],
            ),
        ));
    }
    match crate::bwrap::check(host) {
        Ok(s) => c.push(check(
            "backend",
            "Sandbox",
            CheckStatus::Ok,
            format!("Bubblewrap ({})", s.reason),
        )),
        Err(err) => c.push(check(
            "backend",
            "Sandbox",
            CheckStatus::Fail,
            err.to_string(),
        )),
    }
    match &e.desktop_entry {
        Some(p) => {
            let problems = validate_launcher(p, &e.id);
            c.push(if problems.is_empty() {
                check("launcher", "Desktop entry", CheckStatus::Ok, tildify(p))
            } else {
                check(
                    "launcher",
                    "Desktop entry",
                    CheckStatus::Warn,
                    problems.join("; "),
                )
                .hint(sam_core::i18n::tr(
                    "Create the menu entry again (sam-jail desktop <app> install).",
                ))
            });
        }
        None => c.push(check(
            "launcher",
            "Desktop entry",
            CheckStatus::Info,
            "no menu entry",
        )),
    }
    if let Some(l) = &e.last_launch {
        let st = if l.sandbox_failure {
            CheckStatus::Fail
        } else if l.success {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        };
        c.push(check(
            "last-launch",
            "Last launch",
            st,
            format!("{} — {}", format_ts(l.started_at), l.summary),
        ));
    }
    DiagnosticReport {
        generated_at: now(),
        sam_version: SAM_VERSION.into(),
        checks: c,
    }
}

/// The programs SAM runs outside the sandbox, by name.
const HELPERS: &[&str] = &[
    "bwrap",
    "pasta",
    "xdg-dbus-proxy",
    "unsquashfs",
    "bsdtar",
    "dwarfsextract",
    "gpg",
    "gpgv",
    "curl",
    "strace",
    "sam-jail-run",
];

/// Replace identifying information before a report leaves the machine: the
/// home folder, other users' folders, the user and computer names, email
/// addresses, logins and query strings in links, and IPv4 addresses (apps
/// print all of these into their logs).
pub fn redact(s: &str, host: &HostInfo) -> String {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    redact_with(
        s,
        &host.home.display().to_string(),
        &host.user,
        hostname.trim(),
    )
}

fn redact_with(s: &str, home: &str, user: &str, hostname: &str) -> String {
    let mut out = redact_links(s);
    out = redact_secrets(&out);
    out = redact_emails(&out);
    if home.len() > 1 {
        out = out.replace(home, "~");
    }
    for root in ["/home/", "/run/media/", "/media/"] {
        out = redact_user_folders(&out, root);
    }
    // The computer's name first: it often contains the user name.
    if hostname.len() > 1 {
        out = replace_word(&out, hostname, "<host>");
    }
    if user.len() > 1 {
        out = replace_word(&out, user, "<user>");
    }
    redact_ipv4(&out)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Replaces `word` where it stands as a whole word.
fn replace_word(s: &str, word: &str, with: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(word) {
        let before = rest[..i].chars().next_back();
        let after = rest[i + word.len()..].chars().next();
        out.push_str(&rest[..i]);
        if before.is_some_and(is_word_char) || after.is_some_and(is_word_char) {
            out.push_str(word);
        } else {
            out.push_str(with);
        }
        rest = &rest[i + word.len()..];
    }
    out.push_str(rest);
    out
}

/// `/home/<anyone>` becomes `/home/<user>` (also /run/media and /media).
fn redact_user_folders(s: &str, root: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(root) {
        out.push_str(&rest[..i + root.len()]);
        rest = &rest[i + root.len()..];
        let end = rest
            .find(|c: char| c == '/' || c.is_whitespace() || "\"'`)]>,;:".contains(c))
            .unwrap_or(rest.len());
        if end > 0 && !rest[..end].starts_with('<') {
            out.push_str("<user>");
        } else {
            out.push_str(&rest[..end]);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// In links: a login (`user:password@`), the query string and the part
/// after `#` (sign-in pages put tokens there), and path parts that look
/// like a key (`/hooks/T0123/B0456/x9Yk2mQ...`).
fn redact_links(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        out.push_str(&rest[..i + 3]);
        rest = &rest[i + 3..];
        let end = rest
            .find(|c: char| c.is_whitespace() || "\"'`<>)]".contains(c))
            .unwrap_or(rest.len());
        let mut link = rest[..end].to_string();
        let path_start = link.find('/').unwrap_or(link.len());
        if let Some(at) = link[..path_start].rfind('@') {
            link.replace_range(..at, "<login>");
        }
        if let Some(q) = link.find(['?', '#']) {
            let mark = if link[q..].starts_with('?') { "?" } else { "#" };
            link.replace_range(q.., &format!("{mark}<hidden>"));
        }
        let path_start = link.find('/').unwrap_or(link.len());
        let path = link[path_start..]
            .split('/')
            .map(|part| {
                if looks_like_a_key(part) {
                    "<hidden>"
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        link.replace_range(path_start.., &path);
        out.push_str(&link);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// The shape of a token or key: 20 or more letters, digits, `-` and `_`
/// mixing digits with upper and lower case letters, or 32 or more with
/// digits (hex keys). File names (they have dots), versions and dates
/// rarely look like that.
fn looks_like_a_key(w: &str) -> bool {
    let w = w.trim_end_matches('=');
    let has = |f: fn(&char) -> bool| w.chars().any(|c| f(&c));
    w.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && has(char::is_ascii_digit)
        && (w.len() >= 32
            || (w.len() >= 20 && has(char::is_ascii_uppercase) && has(char::is_ascii_lowercase)))
}

/// Names of values that give access: `Authorization: Bearer x`,
/// `token=x`, `"api_key": "x"`, `PASSWORD=x`.
const SECRET_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "api-key",
    "access_key",
    "private_key",
    "credential",
    "session_id",
    "sessionid",
    "session_key",
];

/// Hides the value after a name from [`SECRET_NAMES`] (as part of a longer
/// name too: `X-Auth-Token`, `GITHUB_TOKEN`), and after an authorization
/// scheme (`Bearer x`, `Basic x`).
fn redact_secrets(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let b = s.as_bytes();
    let name_char = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
    let mut hide: Vec<(usize, usize)> = Vec::new();
    // The value after `name =`, `name:` or `"name": "`.
    let mut from = 0;
    while let Some(i) = SECRET_NAMES
        .iter()
        .filter_map(|n| lower[from..].find(n).map(|i| (from + i, n.len())))
        .min()
        .map(|(i, len)| (i, i + len))
    {
        let (_, mut j) = i;
        from = j;
        while j < b.len() && name_char(b[j]) {
            j += 1;
        }
        j += usize::from(j < b.len() && b[j] == b'"');
        while j < b.len() && b[j] == b' ' {
            j += 1;
        }
        if j >= b.len() || !(b[j] == b'=' || b[j] == b':') {
            continue;
        }
        j += 1;
        while j < b.len() && (b[j] == b' ' || b[j] == b'"' || b[j] == b'\'') {
            j += 1;
        }
        let end = |k: usize| {
            (k..b.len())
                .find(|&k| b[k].is_ascii_whitespace() || b"\"'&;,".contains(&b[k]))
                .unwrap_or(b.len())
        };
        let mut e = end(j);
        // `Bearer x`: the scheme stays readable, the credential is hidden.
        let word = lower[j..e].to_string();
        if ["bearer", "basic", "token", "digest", "negotiate"].contains(&word.as_str())
            && e < b.len()
            && b[e] == b' '
        {
            j = e + 1;
            e = end(j);
        }
        if e > j {
            hide.push((j, e));
        }
        from = from.max(e);
    }
    // `Bearer x` anywhere else.
    for scheme in ["bearer "] {
        let mut k = 0;
        while let Some(i) = lower[k..].find(scheme) {
            let j = k + i + scheme.len();
            let e = (j..b.len())
                .find(|&k| b[k].is_ascii_whitespace() || b"\"'&;,".contains(&b[k]))
                .unwrap_or(b.len());
            if e > j {
                hide.push((j, e));
            }
            k = j;
        }
    }
    hide.sort_unstable();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (j, e) in hide {
        if j < last {
            continue;
        }
        out.push_str(&s[last..j]);
        out.push_str("<hidden>");
        last = e;
    }
    out.push_str(&s[last..]);
    out
}

fn redact_emails(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('@') {
        let left_ok = |c: char| c.is_alphanumeric() || "._%+-".contains(c);
        let right_ok = |c: char| c.is_alphanumeric() || ".-".contains(c);
        let start = rest[..i]
            .char_indices()
            .rev()
            .take_while(|&(_, c)| left_ok(c))
            .last()
            .map(|(j, _)| j)
            .unwrap_or(i);
        let end = rest[i + 1..]
            .char_indices()
            .take_while(|&(_, c)| right_ok(c))
            .last()
            .map(|(j, c)| i + 1 + j + c.len_utf8())
            .unwrap_or(i + 1);
        let domain = rest[i + 1..end].trim_end_matches('.');
        if start < i && domain.contains('.') && !domain.starts_with('.') {
            out.push_str(&rest[..start]);
            out.push_str("<email>");
            rest = &rest[i + 1 + domain.len()..];
        } else {
            out.push_str(&rest[..i + 1]);
            rest = &rest[i + 1..];
        }
    }
    out.push_str(rest);
    out
}

/// IPv4 addresses, except the local ones (127.x, 0.0.0.0).
fn redact_ipv4(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let mut k = 0;
    let mut last = 0;
    while k < chars.len() {
        let (i, c) = chars[k];
        // A run of digits and dots swallows its dots, so only a letter or
        // digit before it can glue it to another word.
        let starts = c.is_ascii_digit() && (k == 0 || !chars[k - 1].1.is_alphanumeric());
        if starts {
            let mut j = k;
            while j < chars.len() && (chars[j].1.is_ascii_digit() || chars[j].1 == '.') {
                j += 1;
            }
            let end_byte = if j < chars.len() { chars[j].0 } else { s.len() };
            let cand = s[i..end_byte].trim_end_matches('.');
            let parts: Vec<&str> = cand.split('.').collect();
            let next_ok = j >= chars.len() || !chars[j].1.is_alphanumeric();
            // Each part is 0 to 255, written with at most three digits.
            let is_ip = next_ok
                && parts.len() == 4
                && parts
                    .iter()
                    .all(|p| p.len() <= 3 && p.parse::<u8>().is_ok());
            if is_ip && !cand.starts_with("127.") && cand != "0.0.0.0" {
                out.push_str(&s[last..i]);
                out.push_str("<ip>");
                last = i + cand.len();
            }
            k = j;
            continue;
        }
        k += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Markdown bug report for one app (or the system), redacted.
pub fn bug_report(app: &Sam, e: Option<&AppEntry>, host: &HostInfo) -> String {
    let mut s = format!(
        "## SAM bug report\n\n- SAM: {}\n- Generated: {}\n- System: {} / kernel {} / {} {}\n\n",
        SAM_VERSION,
        format_ts(now()),
        host.distro,
        host.kernel,
        host.desktop,
        host.session_type
    );
    s += "### Environment\n\n";
    for ch in system_report(app, host).checks {
        s += &format!("- [{:?}] {}: {}\n", ch.status, ch.label, ch.detail);
    }
    // Contracts with the outside world that do not hold here, and the
    // versions of the components: they name the part that changed.
    let contracts = crate::contracts::check_all(host);
    s += "\n### Contracts (docs/contracts.md)\n\n";
    let off: Vec<_> = contracts
        .contracts
        .iter()
        .filter(|c| {
            matches!(
                c.state,
                crate::contracts::State::Broken | crate::contracts::State::Absent
            )
        })
        .collect();
    if off.is_empty() {
        s += "- every contract with a quick check holds\n";
    }
    for c in off {
        s += &format!("- {:?}: {} ({})\n", c.state, c.id, c.detail);
    }
    let versions: Vec<String> = contracts
        .components
        .iter()
        .filter_map(|v| v.version.as_ref().map(|ver| format!("{} {ver}", v.id)))
        .collect();
    s += &format!("- Versions: {}\n", versions.join(", "));
    if let Some(e) = e {
        s += &format!(
            "\n### App: {} ({})\n\n- Type: {}\n- Category: {}\n- State: {:?} / badge {}\n",
            e.display_name(),
            e.id,
            e.appimage_type.label(),
            e.category,
            e.state,
            e.badge().label()
        );
        if let Some(x) = &e.extraction {
            s += &format!(
                "- Extraction: {} ({}), {} files\n",
                x.method, x.compression, x.file_count
            );
        }
        if let Some(d) = &e.detection {
            s += &format!(
                "- Toolkit: {}; compatibility {:?}; verdict {:?}\n",
                d.requirements.toolkit, d.compatibility, d.verdict
            );
        }
        for ch in app_report(app, e, host).checks {
            s += &format!("- [{:?}] {}: {}\n", ch.status, ch.label, ch.detail);
        }
        s += "\n#### Permissions\n\n";
        s += &fenced("json", &permissions_for_report(&e.profile.permissions));
        let logs = Logs::new(&app.paths);
        if let Ok(Some(l)) = logs.latest(&e.id, Some(LogKind::Launch)) {
            s += "\n#### Last launch log (tail)\n\n";
            s += &fenced("", &crate::launch::tail(&l.path, 60));
        }
    }
    redact(&s, host)
}

/// `body` as a Markdown code block whose fence is longer than any run of
/// backticks in it: an app's log line cannot end the block and add its own
/// text to the report.
fn fenced(lang: &str, body: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in body.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest.max(2) + 1);
    format!("{fence}{lang}\n{}\n{fence}\n", body.trim_end_matches('\n'))
}

/// An app's permissions for a bug report: values given to the app as
/// environment variables (often API keys or tokens) are hidden; their names
/// stay, because they help to find the problem.
fn permissions_for_report(p: &sam_core::permissions::PermissionSet) -> String {
    let mut p = p.clone();
    for v in p.environment.set.values_mut() {
        *v = "<hidden>".into();
    }
    toml_string(&p)
}

fn toml_string<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .map(|j| serde_json::to_string_pretty(&j).unwrap_or_default())
        .unwrap_or_default()
        + "\n"
}
/// The apps that see `/tmp` or a known socket folder in it through an
/// older grant SAM keeps until the person replaces it (owner decision 10
/// of 2026-11-23): a warning naming them. Judged as written: a grant
/// through a link to `/tmp` is left out at each start.
fn tmp_grants(apps: &[AppEntry]) -> DiagnosticCheck {
    let home = sam_core::util::home_dir();
    let names: Vec<String> = apps
        .iter()
        .filter(|a| {
            let f = &a.profile.permissions.filesystem;
            f.custom_write
                .iter()
                .chain(&f.custom_read)
                .any(|p| sam_core::risk::shows_host_sockets_in(p, &home))
        })
        .map(|a| sam_core::util::display_safe(a.display_name(), 80))
        .collect();
    if names.is_empty() {
        return check("tmp-grants", "Folders in /tmp", CheckStatus::Ok, "none");
    }
    DiagnosticCheck::new(
        "tmp-grants",
        &tr("Folders in /tmp"),
        CheckStatus::Warn,
        sam_core::i18n::trf(
            "These apps see /tmp or a known socket folder in it (tmux, SSH, the X server …), where programs outside the sandbox listen: {apps}. Replace each grant with a folder of the app's own on the app's page, or with sam-jail hints APP --apply tmp-own-folder.",
            &[("apps", &names.join(", "))],
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Diagnostics name each app that sees /tmp or a known socket folder in
    /// it through an older grant, and no other app (one with a grant
    /// through a link to /tmp, which each start leaves out, neither);
    /// without one, the check is fine.
    #[test]
    fn doctor_names_apps_with_an_older_tmp_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(sam_core::Paths::rooted(tmp.path())).unwrap();
        let host = sam_core::sandbox::sample_context().host;
        let check = |sam: &Sam| {
            system_report(sam, &host)
                .checks
                .into_iter()
                .find(|c| c.id == "tmp-grants")
                .unwrap()
        };
        let mut plain = AppEntry {
            id: "appimage-plain-1a2b".into(),
            name: "Plain".into(),
            ..Default::default()
        };
        // A grant through a link to /tmp is left out at each start.
        let link = tmp.path().join("t");
        std::os::unix::fs::symlink("/tmp", &link).unwrap();
        plain.profile.permissions.filesystem.custom_write =
            vec!["/tmp/exchange".into(), link.display().to_string()];
        sam.registry().save(&mut plain).unwrap();
        assert_eq!(check(&sam).status, CheckStatus::Ok);
        let mut older = AppEntry {
            id: "appimage-older-1a2b".into(),
            name: "Older".into(),
            ..Default::default()
        };
        older.profile.permissions.filesystem.custom_read = vec!["/tmp/tmux-1000".into()];
        sam.registry().save(&mut older).unwrap();
        let c = check(&sam);
        assert_eq!(c.status, CheckStatus::Warn, "{}", c.detail);
        assert!(
            c.detail.contains("Older") && !c.detail.contains("Plain"),
            "{}",
            c.detail
        );
        assert!(c.detail.contains("tmp-own-folder"), "{}", c.detail);
    }

    /// A bug report never contains the user's name or home path: both are
    /// replaced before the text is shown for copying.
    #[test]
    fn bug_reports_hide_the_user_name_and_home_path() {
        let mut host = sam_core::sandbox::sample_context().host;
        host.user = "erika".into();
        host.home = "/home/erika".into();
        let text = redact(
            "open /home/erika/Documents/x.png failed for erika (uid of erika)",
            &host,
        );
        assert!(!text.contains("erika"), "{text}");
        assert!(
            text.contains("~/Documents/x.png"),
            "paths stay readable: {text}"
        );
    }

    /// Review K-1: before Linux 6.12 Landlock cannot fence abstract
    /// sockets, and diagnostics say so (it read "available" as if all was
    /// well); from 6.12 on it is fine.
    #[test]
    fn diagnostics_say_when_landlock_cannot_fence_abstract_sockets() {
        let tmp = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(sam_core::Paths::rooted(tmp.path())).unwrap();
        let mut host = sam_core::sandbox::sample_context().host;
        let landlock = |host: &HostInfo| {
            system_report(&sam, host)
                .checks
                .into_iter()
                .find(|c| c.id == "landlock")
                .unwrap()
        };
        host.landlock_abi = Some(4);
        let c = landlock(&host);
        assert_eq!(c.status, CheckStatus::Warn, "{}", c.detail);
        assert!(
            c.detail.contains("6.12") && c.detail.contains("X server"),
            "{}",
            c.detail
        );
        host.landlock_abi = Some(6);
        assert_eq!(landlock(&host).status, CheckStatus::Ok);
    }

    /// Diagnostics warn about a missing Wayland socket on a Wayland
    /// session and only mention it elsewhere; they list the GPU devices
    /// found, and warn when there are none.
    #[test]
    fn diagnostics_warn_about_what_this_session_lacks() {
        let tmp = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(sam_core::Paths::rooted(tmp.path())).unwrap();
        let mut host = sam_core::sandbox::sample_context().host;
        // No socket to look into on this computer.
        host.sockets.wayland = None;
        let check = |host: &HostInfo, id: &str| {
            system_report(&sam, host)
                .checks
                .into_iter()
                .find(|c| c.id == id)
                .unwrap()
        };
        let gpu = check(&host, "gpu");
        assert_eq!(gpu.status, CheckStatus::Ok, "{}", gpu.detail);
        assert_eq!(
            gpu.detail,
            "/dev/dri/card0, /dev/dri/renderD128, /dev/nvidia0, /dev/nvidiactl"
        );
        assert_eq!(check(&host, "wayland").status, CheckStatus::Warn);
        host.session_type = "x11".into();
        assert_eq!(check(&host, "wayland").status, CheckStatus::Info);
        host.gpu_devices.clear();
        let gpu = check(&host, "gpu");
        assert_eq!(gpu.status, CheckStatus::Warn);
        assert_eq!(gpu.detail, "no /dev/dri devices");
    }

    /// A whole bug report (the system part) is produced and redacted: it
    /// names SAM's version and never the home folder or user name.
    #[test]
    fn a_bug_report_is_complete_and_redacted() {
        let tmp = tempfile::tempdir().unwrap();
        let sam = Sam::with_paths(sam_core::Paths::rooted(tmp.path())).unwrap();
        let mut host = sam_core::sandbox::sample_context().host;
        host.user = "erika".into();
        host.home = "/home/erika".into();
        let text = bug_report(&sam, None, &host);
        assert!(
            text.starts_with("## SAM bug report") && text.contains(SAM_VERSION),
            "{text}"
        );
        assert!(text.contains("### Environment"), "{text}");
        assert!(
            !text.contains("/home/erika") && !text.contains("erika"),
            "{text}"
        );
    }

    /// Secrets whose name goes on after the known word (`GITHUB_TOKEN_2`,
    /// `password-hash`, `secret2`), with spaces or quotes around the value,
    /// and empty values (mutation run P14: these forms were untested).
    #[test]
    fn bug_reports_hide_secrets_in_every_spelling() {
        let r = |s: &str| redact_with(s, "/home/jo", "jo", "jo-laptop");
        for (given, shown) in [
            (
                "GITHUB_TOKEN_2=ghp_abc make",
                "GITHUB_TOKEN_2=<hidden> make",
            ),
            (
                "{\"password-hash\": \"x1\"}",
                "{\"password-hash\": \"<hidden>\"}",
            ),
            ("secret2=abc", "secret2=<hidden>"),
            ("password   :   hunter2 ok", "password   :   <hidden> ok"),
            ("password=  \"hunter2\" ok", "password=  \"<hidden>\" ok"),
            (
                "sent with bearer abc;next",
                "sent with bearer <hidden>;next",
            ),
            (
                "sent with bearer abc,next",
                "sent with bearer <hidden>,next",
            ),
            // A scheme with nothing after it: the scheme word is the value.
            ("Authorization: Bearer", "Authorization: <hidden>"),
            // Nothing to hide; a secret word at the very end is no reason
            // to crash (reading past the text went unnoticed).
            ("password=", "password="),
            ("ask for the password", "ask for the password"),
            ("ask for the password  ", "ask for the password  "),
            ("the \"password", "the \"password"),
            ("sent with bearer ", "sent with bearer "),
        ] {
            assert_eq!(r(given), shown, "{given}");
        }
    }

    /// Bug reports hide what identifies the user or gives access: a home
    /// folder with spaces, other users' folders, short user names, the
    /// computer's name, email addresses, logins and tokens in links, IPv4
    /// addresses, and the values of environment variables given to the app.
    /// Ordinary words, versions and local addresses stay readable.
    #[test]
    fn bug_reports_hide_names_addresses_and_secrets() {
        let r = |s: &str| redact_with(s, "/home/jo smith", "jo", "jo-laptop");
        assert_eq!(r("open /home/jo smith/Docs/a b.txt"), "open ~/Docs/a b.txt");
        assert_eq!(r("jo started the journal"), "<user> started the journal");
        assert_eq!(
            r("copied from /home/bob/.config and /run/media/jo/USB"),
            "copied from /home/<user>/.config and /run/media/<user>/USB"
        );
        assert_eq!(
            r("connected to jo-laptop.local"),
            "connected to <host>.local"
        );
        assert_eq!(
            r("signed in as erika.m+sam@example.org."),
            "signed in as <email>."
        );
        assert_eq!(
            r("GET https://alice:s3cret@api.example.com/v1/x?token=abc123 failed"),
            "GET https://<login>@api.example.com/v1/x?<hidden> failed"
        );
        assert_eq!(
            r("from 192.168.1.20:8080 to 127.0.0.1 and 0.0.0.0"),
            "from <ip>:8080 to 127.0.0.1 and 0.0.0.0"
        );
        assert_eq!(
            r("glibc 2.38, GTK 4.14.5, libfoo.so.1.2"),
            "glibc 2.38, GTK 4.14.5, libfoo.so.1.2"
        );
        assert_eq!(
            r("an @ sign and user@localhost"),
            "an @ sign and user@localhost"
        );

        // Edges: at the start or end of a text, glued to other words.
        assert_eq!(
            r("a@b.de wrote to x.y@mail.example.com"),
            "<email> wrote to <email>"
        );
        assert_eq!(r("10.0.0.7 answered"), "<ip> answered");
        assert_eq!(
            r("build v192.168.1.1 and 192.168.1.1x and 1.192.168.1.1"),
            "build v192.168.1.1 and 192.168.1.1x and 1.192.168.1.1"
        );
        assert_eq!(
            r("at /home/ and /home/<user>/x"),
            "at /home/ and /home/<user>/x"
        );
        assert_eq!(
            r("http://example.org/plain stays"),
            "http://example.org/plain stays"
        );
        // A one-letter user name is not hidden: it would mangle every word.
        assert_eq!(redact_with("a cat", "/home/a", "a", "h"), "a cat");
        assert_eq!(
            redact_with("h is /usr/bin", "/", "erika", "h"),
            "h is /usr/bin",
            "no one-letter computer name, no home of /"
        );
        assert_eq!(r("1.2.3.0001 and 1.2.3.256"), "1.2.3.0001 and 1.2.3.256");

        let mut p = sam_core::permissions::PermissionSet::strict_gui();
        p.environment
            .set
            .insert("OPENAI_API_KEY".into(), "sk-very-secret".into());
        let text = permissions_for_report(&p);
        assert!(
            text.contains("OPENAI_API_KEY") && !text.contains("sk-very-secret"),
            "{text}"
        );
    }

    /// Bug reports also hide what gives access in other shapes (audit
    /// U-L5): a token after `#` or inside a link's path, `Authorization`
    /// and cookie lines, and named secrets in settings and logs. The names
    /// stay, so the report still says what was there.
    #[test]
    fn bug_reports_hide_tokens_in_every_shape() {
        let r = |s: &str| redact_with(s, "/home/jo", "jo", "box");
        assert_eq!(
            r("https://example.org/cb#access_token=abc123&state=1 ok"),
            "https://example.org/cb#<hidden> ok"
        );
        assert_eq!(
            r("POST https://hooks.example.com/services/T0123/B0456/x9Yk2mQpL7rT4vW8zA1b failed"),
            "POST https://hooks.example.com/services/T0123/B0456/<hidden> failed"
        );
        assert_eq!(
            r("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"),
            "Authorization: Bearer <hidden>"
        );
        assert_eq!(
            r("authorization: Basic dXNlcjpwYXNz"),
            "authorization: Basic <hidden>"
        );
        assert_eq!(
            r("curl -H 'X-Auth-Token: s3cr3t' url"),
            "curl -H 'X-Auth-Token: <hidden>' url"
        );
        assert_eq!(
            r("Cookie: sid=abc; theme=dark"),
            "Cookie: <hidden>; theme=dark"
        );
        assert_eq!(
            r("GITHUB_TOKEN=ghp_abcdef123 make"),
            "GITHUB_TOKEN=<hidden> make"
        );
        assert_eq!(
            r("{\"api_key\": \"k-123\", \"n\": 1}"),
            "{\"api_key\": \"<hidden>\", \"n\": 1}"
        );
        assert_eq!(r("password = hunter2"), "password = <hidden>");
        assert_eq!(r("sent with bearer abc.def"), "sent with bearer <hidden>");
        // Words, versions and settings without a value stay.
        for same in [
            "the token was refused",
            "Session: wayland",
            "libsecret 0.21.4 loaded",
            "https://example.org/releases/v1.2.3/App-1.2.3-x86_64.AppImage",
            "https://example.org/a/2026-11-19/b",
            "https://example.org/build_2026_release_candidate/x",
        ] {
            assert_eq!(r(same), same);
        }
        for key in [
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
            "aGVsbG8gd29ybGQgdGhpcyBpcw==",
        ] {
            assert_eq!(
                r(&format!("https://x.org/k/{key}")),
                "https://x.org/k/<hidden>"
            );
        }
        // A key may have `-` in it; a file name with dots is not one.
        assert_eq!(
            r("https://x.org/k/x9Yk2mQp-L7rT4vW8zA1b"),
            "https://x.org/k/<hidden>"
        );
        let file = "https://x.org/k/Report2026.Final.Version.pdf";
        assert_eq!(r(file), file);
        // Letters only: a word, not a key.
        let word = "https://x.org/k/abcdefghijklmnopqrstuvwxyz";
        assert_eq!(r(word), word);
    }

    /// An app's log cannot end the report's code block and add text of its
    /// own after it: the fence is always longer than any run of backticks
    /// inside.
    #[test]
    fn a_log_cannot_break_out_of_its_code_block() {
        let body = "line\n```\n## Fake heading\n````more";
        let block = fenced("", body);
        assert!(
            block.starts_with("`````\n") && block.ends_with("\n`````\n"),
            "{block}"
        );
        assert!(block.contains(body));
        assert_eq!(fenced("json", "{}"), "```json\n{}\n```\n");
    }
}
