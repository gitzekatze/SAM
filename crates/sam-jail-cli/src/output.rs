//! Output helpers: the JSON envelope, colours and the human-readable views.

use super::*;

/// Output: human text plus the JSON value.
pub(crate) struct Out {
    pub(crate) json: bool,
}

impl Out {
    pub(crate) fn emit<T: Serialize>(&self, data: &T, human: impl FnOnce()) {
        if self.json {
            sam_core::terminal::print_json(&json!({"ok": true, "data": data}).to_string());
        } else {
            human();
        }
    }
}

pub(crate) fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// `s` in a colour; only [`sam_core::terminal::SCREEN_COLOURS`] reach the
/// terminal, so any other code is left out.
pub(crate) fn paint(s: &str, code: &str) -> String {
    if color() && sam_core::terminal::SCREEN_COLOURS.contains(&code) {
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
        Badge::Broken
        | Badge::Unsafe
        | Badge::Missing
        | Badge::ChangedOutside
        | Badge::ProtectionMissing => "31",
    };
    paint(b.label(), code)
}

/// Risk in the window's words (Harmless / Think twice / Dangerous), colored.
pub(crate) fn risk_str(r: RiskLevel) -> String {
    let code = match r {
        RiskLevel::Low | RiskLevel::Medium => "32",
        RiskLevel::High => "33",
        RiskLevel::Dangerous => "1;31",
    };
    paint(&r.words(), code)
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
        outln!("  [{}] {}: {}", sev_str(w.severity), w.title, w.message);
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
    outln!("{}  [{}]", paint(e.display_name(), "1"), badge_str(s.badge));
    if !e.metadata.comment.is_empty() {
        outln!("  {}", e.metadata.comment);
    }
    outln!("  id:          {}", e.id);
    outln!(
        "  source:      {}{}",
        tildify(&e.source_path),
        if e.source_path.exists() {
            ""
        } else {
            "  (missing)"
        }
    );
    outln!("  sha256:      {}", e.source.sha256);
    outln!("  type:        {}", e.appimage_type.label());
    if let Some(sig) = &e.signature {
        outln!("  signature:   {}", sig.detail);
    }
    outln!("  category:    {}", e.category);
    outln!("  state:       {:?}", e.state);
    match sel {
        Some(sel) => outln!("  sandbox:     Bubblewrap ({})", sel.reason),
        None => outln!("  sandbox:     not available (see sam-jail doctor)"),
    }
    outln!("  risk:        {}", risk_line(&s.risk));
    if let Some(p) = &e.profile.preset {
        outln!("  preset:      {p}");
    }
    if let Some(x) = &e.extraction {
        outln!(
            "  extraction:  {} files, {} via {} ({})",
            x.file_count,
            human_size(x.total_size),
            x.method,
            x.compression
        );
    } else {
        outln!("  extraction:  {}", paint("not extracted", "31"));
    }
    outln!(
        "  launcher:    {}",
        e.desktop_entry
            .as_ref()
            .map(|p| tildify(p))
            .unwrap_or_else(|| "none".into())
    );
    outln!(
        "  last run:    {}",
        e.last_launch
            .as_ref()
            .map(|l| format!("{} — {}", format_ts(l.started_at), l.summary))
            .unwrap_or_else(|| "never".into())
    );

    outln!("\n{}", paint("Permissions", "1"));
    let mut category = "";
    for (cat, title, value) in permission_lines(&e.profile.permissions) {
        if cat != category {
            outln!("  {}", paint(&sam_core::i18n::tr(cat), "1"));
            category = cat;
        }
        outln!("    {title:<40} {value}");
    }
    if let Some(d) = &e.detection {
        outln!("\n{}", paint("Dependencies", "1"));
        print_detection(d);
    }
    if !e.recommendation_notes.is_empty() {
        outln!("\n{}", paint(&sam_core::i18n::tr("Why this profile"), "1"));
        for n in &e.recommendation_notes {
            outln!("  - {n}");
        }
    }
    if !warnings.is_empty() {
        outln!("\n{}", paint("Warnings", "1"));
        print_warnings(warnings);
    }
}

/// Every permission of the catalogue with its value, in the catalogue's
/// order: the one list of permissions, so `info` leaves nothing out (audit
/// G-F14: it left out Bluetooth, the SSH agent, the key folders, bus names,
/// variables and all advanced settings).
pub(crate) fn permission_lines(
    p: &sam_core::permissions::PermissionSet,
) -> Vec<(&'static str, String, String)> {
    use serde_json::Value;
    fn show(v: &Value) -> String {
        match v {
            Value::Bool(true) => "on".into(),
            Value::Bool(false) => "off".into(),
            // Unset: the global setting decides (Landlock).
            Value::Null => "global setting".into(),
            Value::String(s) => s.clone(),
            Value::Array(a) if a.is_empty() => "–".into(),
            Value::Array(a) => a.iter().map(show).collect::<Vec<_>>().join(", "),
            Value::Object(m) if m.is_empty() => "–".into(),
            Value::Object(m) => m
                .iter()
                .map(|(k, v)| format!("{k}={}", show(v)))
                .collect::<Vec<_>>()
                .join(", "),
            other => other.to_string(),
        }
    }
    let mut catalog = sam_core::permissions::permission_catalog();
    // One heading per group, in the order the groups first appear.
    let order: Vec<&str> = catalog.iter().fold(Vec::new(), |mut o, i| {
        if !o.contains(&i.category) {
            o.push(i.category);
        }
        o
    });
    catalog.sort_by_key(|i| order.iter().position(|c| *c == i.category));
    catalog
        .into_iter()
        .map(|i| {
            let value = p
                .get_key(i.key)
                .map(|v| sam_core::util::display_safe(&show(&v), 200))
                .unwrap_or_else(|_| "?".into());
            (i.category, i.title, value)
        })
        .collect()
}

pub(crate) fn print_detection(d: &DependencyReport) {
    outln!(
        "  toolkit: {}   arch: {}   ELF files: {}   bundled libs: {}",
        d.requirements.toolkit,
        d.arch,
        d.elf_count,
        d.bundled_libraries
    );
    outln!(
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
        outln!("  host system libraries: {}", host_libs.join(", "));
    }
    for m in d
        .missing
        .iter()
        .filter(|m| m.class != ResourceClass::System)
    {
        outln!(
            "  host library {} [{:?}]{}",
            m.name,
            m.class,
            if m.host_available { "" } else { "  NOT FOUND" }
        );
    }
    for r in d.resources.iter().filter(|r| !r.auto) {
        outln!("  needs {} ({})", r.resource, r.reason);
    }
    for n in &d.notes {
        outln!("  note: {n}");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `info` shows every permission of the catalogue with its value, also
    /// the ones it left out before (audit G-F14).
    #[test]
    fn info_shows_every_permission_with_its_value() {
        let mut p = sam_core::permissions::PermissionSet::strict_gui();
        p.devices.bluetooth = true;
        p.sockets.ssh_agent = true;
        p.environment.passthrough = vec!["LANG".into()];
        p.advanced.seccomp_baseline = false;
        let lines = permission_lines(&p);
        assert_eq!(
            lines.len(),
            sam_core::permissions::permission_catalog().len()
        );
        let value = |title: &str| {
            lines
                .iter()
                .find(|(_, t, _)| t == title)
                .map(|(_, _, v)| v.clone())
                .unwrap_or_else(|| panic!("{title} is missing"))
        };
        assert_eq!(value("Bluetooth"), "on");
        assert_eq!(value("SSH agent"), "on");
        assert_eq!(value("Passed-through variables"), "LANG");
        assert_eq!(value("Baseline syscall filter"), "off");
        assert_eq!(value("Webcam"), "off");
        assert_eq!(
            value("Single functions of services"),
            "–",
            "left out while empty"
        );
        assert_eq!(value("Landlock enforcement"), "global setting");
        assert_eq!(value("Environment variables"), "–", "none set");
        // Each group once, all its permissions together.
        let mut seen: Vec<&str> = Vec::new();
        for (cat, _, _) in &lines {
            if seen.last() != Some(cat) {
                assert!(!seen.contains(cat), "{cat} appears twice");
                seen.push(cat);
            }
        }
    }
}
