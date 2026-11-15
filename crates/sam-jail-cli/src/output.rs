//! Output helpers: the JSON envelope, colours and the human-readable views.

use super::*;

/// Output: human text plus the JSON value.
pub(crate) struct Out {
    pub(crate) json: bool,
}

impl Out {
    pub(crate) fn emit<T: Serialize>(&self, data: &T, human: impl FnOnce()) {
        if self.json {
            println!("{}", json!({"ok": true, "data": data}));
        } else {
            human();
        }
    }
}

pub(crate) fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

pub(crate) fn paint(s: &str, code: &str) -> String {
    if color() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub(crate) fn badge_str(b: Badge) -> String {
    let code = match b {
        Badge::Ready => "32",
        Badge::NeedsReview => "36",
        Badge::CompatibilityMode | Badge::CompatibilityRisk | Badge::Stale => "33",
        Badge::Broken | Badge::Unsafe | Badge::Missing | Badge::ChangedOutside => "31",
    };
    paint(b.label(), code)
}

pub(crate) fn risk_str(r: RiskLevel) -> String {
    let code = match r {
        RiskLevel::Low => "32",
        RiskLevel::Medium => "33",
        RiskLevel::High => "31",
        RiskLevel::Dangerous => "1;31",
    };
    paint(r.label(), code)
}

pub(crate) fn sev_str(s: Severity) -> String {
    match s {
        Severity::Info => paint("info", "36"),
        Severity::Warning => paint("warning", "33"),
        Severity::Danger => paint("danger", "1;31"),
    }
}

pub(crate) fn print_warnings(ws: &[Warning]) {
    for w in ws {
        println!("  [{}] {}: {}", sev_str(w.severity), w.title, w.message);
    }
}

pub(crate) fn read_stdin() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

pub(crate) fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

/// Break a long bwrap command into readable lines.
pub(crate) fn pretty_command(argv: &[String]) -> String {
    let mut out = String::new();
    let mut i = 0;
    let q = |s: &String| sam_core::util::shell_quote(s);
    if let Some(first) = argv.first() {
        out += &q(first);
        i = 1;
    }
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            out += " \\\n  -- ";
            out += &argv[i + 1..].iter().map(q).collect::<Vec<_>>().join(" ");
            break;
        }
        let n = match a.as_str() {
            "--bind" | "--bind-try" | "--ro-bind" | "--ro-bind-try" | "--dev-bind"
            | "--dev-bind-try" | "--symlink" | "--setenv" => 2,
            "--proc" | "--dev" | "--tmpfs" | "--dir" | "--perms" | "--hostname" | "--chdir"
            | "--cap-drop" | "--seccomp" => 1,
            _ => 0,
        };
        out += " \\\n  ";
        out += &argv[i..(i + 1 + n).min(argv.len())]
            .iter()
            .map(q)
            .collect::<Vec<_>>()
            .join(" ");
        i += 1 + n;
    }
    out
}

pub(crate) fn print_info(
    e: &AppEntry,
    s: &AppSummary,
    warnings: &[Warning],
    sel: Option<&sam_runner::bwrap::SandboxInfo>,
) {
    println!("{}  [{}]", paint(e.display_name(), "1"), badge_str(s.badge));
    if !e.metadata.comment.is_empty() {
        println!("  {}", e.metadata.comment);
    }
    println!("  id:          {}", e.id);
    println!(
        "  source:      {}{}",
        tildify(&e.source_path),
        if e.source_path.exists() {
            ""
        } else {
            "  (missing)"
        }
    );
    println!("  sha256:      {}", e.source.sha256);
    println!("  type:        {}", e.appimage_type.label());
    if let Some(sig) = &e.signature {
        println!("  signature:   {}", sig.detail);
    }
    println!("  category:    {}", e.category);
    println!("  state:       {:?}", e.state);
    match sel {
        Some(sel) => println!("  sandbox:     Bubblewrap ({})", sel.reason),
        None => println!("  sandbox:     not available (see sam-jail doctor)"),
    }
    println!("  risk:        {}", risk_line(&s.risk));
    if let Some(p) = &e.profile.preset {
        println!("  preset:      {p}");
    }
    if let Some(x) = &e.extraction {
        println!(
            "  extraction:  {} files, {} via {} ({})",
            x.file_count,
            human_size(x.total_size),
            x.method,
            x.compression
        );
    } else {
        println!("  extraction:  {}", paint("not extracted", "31"));
    }
    println!(
        "  launcher:    {}",
        e.desktop_entry
            .as_ref()
            .map(|p| tildify(p))
            .unwrap_or_else(|| "none".into())
    );
    println!(
        "  last run:    {}",
        e.last_launch
            .as_ref()
            .map(|l| format!("{} — {}", format_ts(l.started_at), l.summary))
            .unwrap_or_else(|| "never".into())
    );

    let p = &e.profile.permissions;
    println!("\n{}", paint("Permissions", "1"));
    let fs = &p.filesystem;
    let mut dirs: Vec<String> = XDG_DIR_KEYS
        .iter()
        .filter(|k| fs.xdg_access(k).is_granted())
        .map(|k| format!("{k} ({})", fs.xdg_access(k).as_str()))
        .collect();
    dirs.extend(fs.custom_read.iter().map(|c| format!("{c} (ro)")));
    dirs.extend(fs.custom_write.iter().map(|c| format!("{c} (rw)")));
    println!(
        "  filesystem:  {}",
        if fs.home {
            format!("FULL HOME ({})", fs.home_access.as_str())
        } else if dirs.is_empty() {
            sam_core::i18n::tr("private home only")
        } else {
            dirs.join(", ")
        }
    );
    println!("  network:     {}", p.network.mode.as_str());
    println!(
        "  display:     wayland={} x11={}",
        p.display.wayland, p.display.x11
    );
    println!(
        "  audio:       {}{}{}",
        p.audio.enabled,
        if p.audio.pipewire {
            " + direct PipeWire"
        } else {
            ""
        },
        if p.audio.alsa_raw { " + raw ALSA" } else { "" }
    );
    println!(
        "  devices:     gpu={} webcam={} gamepads={} input={} usb={}",
        p.devices.gpu, p.devices.webcam, p.devices.gamepads, p.devices.input, p.devices.usb
    );
    println!(
        "  desktop:     input_method={} keyring={} media_controls={} screen_sharing={} file_manager={}",
        p.integrations.input_method, p.integrations.keyring, p.integrations.media_controls, p.integrations.screen_sharing, p.integrations.file_manager
    );
    println!(
        "  d-bus:       session={} system={}",
        p.dbus.session.mode.as_str(),
        p.dbus.system.mode.as_str()
    );
    if let Some(d) = &e.detection {
        println!("\n{}", paint("Dependencies", "1"));
        print_detection(d);
    }
    if !e.recommendation_notes.is_empty() {
        println!("\n{}", paint(&sam_core::i18n::tr("Why this profile"), "1"));
        for n in &e.recommendation_notes {
            println!("  - {n}");
        }
    }
    if !warnings.is_empty() {
        println!("\n{}", paint("Warnings", "1"));
        print_warnings(warnings);
    }
}

pub(crate) fn print_detection(d: &DependencyReport) {
    println!(
        "  toolkit: {}   arch: {}   ELF files: {}   bundled libs: {}",
        d.requirements.toolkit, d.arch, d.elf_count, d.bundled_libraries
    );
    println!(
        "  compatibility: {:?}{}",
        d.compatibility,
        d.verdict
            .map(|v| format!("   ({})", v.message()))
            .unwrap_or_default()
    );
    let host_libs: Vec<&str> = d
        .missing
        .iter()
        .filter(|m| m.class == ResourceClass::System)
        .map(|m| m.name.as_str())
        .collect();
    if !host_libs.is_empty() {
        println!("  host system libraries: {}", host_libs.join(", "));
    }
    for m in d
        .missing
        .iter()
        .filter(|m| m.class != ResourceClass::System)
    {
        println!(
            "  host library {} [{:?}]{}",
            m.name,
            m.class,
            if m.host_available { "" } else { "  NOT FOUND" }
        );
    }
    for r in d.resources.iter().filter(|r| !r.auto) {
        println!("  needs {} ({})", r.resource, r.reason);
    }
    for n in &d.notes {
        println!("  note: {n}");
    }
}

/// "High (Network, Webcam)": the level and the permissions that set it.
pub(crate) fn risk_line(r: &sam_core::risk::RiskAssessment) -> String {
    let names: Vec<&str> = r.deciding().iter().map(|i| i.title.as_str()).collect();
    if names.is_empty() {
        risk_str(r.level)
    } else {
        format!("{} ({})", risk_str(r.level), names.join(", "))
    }
}
