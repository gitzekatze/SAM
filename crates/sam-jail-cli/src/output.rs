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
    for line in warning_lines(ws) {
        outln!("{line}");
    }
}

/// One line per warning: its severity tag, title and message.
pub(crate) fn warning_lines(ws: &[Warning]) -> Vec<String> {
    ws.iter()
        .map(|w| format!("  [{}] {}: {}", sev_str(w.severity), w.title, w.message))
        .collect()
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

/// How many values follow a Bubblewrap option, as bwrap 0.13's `--help`
/// lists them, so an option and its values stay on one line.
fn bwrap_arity(option: &str) -> usize {
    match option {
        "--overlay" => 3,
        "--bind" | "--bind-try" | "--ro-bind" | "--ro-bind-try" | "--dev-bind"
        | "--dev-bind-try" | "--bind-fd" | "--ro-bind-fd" | "--symlink" | "--setenv" | "--file"
        | "--bind-data" | "--ro-bind-data" | "--chmod" => 2,
        "--proc" | "--dev" | "--tmpfs" | "--mqueue" | "--dir" | "--perms" | "--size"
        | "--hostname" | "--chdir" | "--unsetenv" | "--uid" | "--gid" | "--userns"
        | "--userns2" | "--pidns" | "--args" | "--argv0" | "--lock-file" | "--sync-fd"
        | "--remount-ro" | "--overlay-src" | "--tmp-overlay" | "--ro-overlay" | "--exec-label"
        | "--file-label" | "--cap-add" | "--cap-drop" | "--seccomp" | "--add-seccomp-fd"
        | "--block-fd" | "--userns-block-fd" | "--info-fd" | "--json-status-fd" => 1,
        _ => 0,
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
        let n = bwrap_arity(a);
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
    for line in info_lines(e, s, warnings, sel) {
        outln!("{line}");
    }
}

/// The lines of `info`: the app, its state and risk, every permission, the
/// dependency report, why the profile is what it is, and the warnings.
pub(crate) fn info_lines(
    e: &AppEntry,
    s: &AppSummary,
    warnings: &[Warning],
    sel: Option<&sam_runner::bwrap::SandboxInfo>,
) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!(
        "{}  [{}]",
        paint(e.display_name(), "1"),
        badge_str(s.badge)
    ));
    if !e.metadata.comment.is_empty() {
        out.push(format!("  {}", e.metadata.comment));
    }
    out.push(format!("  id:          {}", e.id));
    out.push(format!(
        "  source:      {}{}",
        tildify(&e.source_path),
        if e.source_path.exists() {
            ""
        } else {
            "  (missing)"
        }
    ));
    out.push(format!("  sha256:      {}", e.source.sha256));
    out.push(format!("  type:        {}", e.appimage_type.label()));
    if let Some(sig) = &e.signature {
        out.push(format!("  signature:   {}", sig.detail));
    }
    out.push(format!("  category:    {}", e.category));
    out.push(format!("  state:       {:?}", e.state));
    match sel {
        Some(sel) => out.push(format!("  sandbox:     Bubblewrap ({})", sel.reason)),
        None => out.push("  sandbox:     not available (see sam-jail doctor)".into()),
    }
    out.push(format!("  risk:        {}", risk_line(&s.risk)));
    if let Some(p) = &e.profile.preset {
        out.push(format!("  preset:      {p}"));
    }
    if let Some(x) = &e.extraction {
        out.push(format!(
            "  extraction:  {} files, {} via {} ({})",
            x.file_count,
            human_size(x.total_size),
            x.method,
            x.compression
        ));
    } else {
        out.push(format!("  extraction:  {}", paint("not extracted", "31")));
    }
    out.push(format!(
        "  launcher:    {}",
        e.desktop_entry
            .as_ref()
            .map(|p| tildify(p))
            .unwrap_or_else(|| "none".into())
    ));
    out.push(format!(
        "  last run:    {}",
        e.last_launch
            .as_ref()
            .map(|l| format!("{} — {}", format_ts(l.started_at), l.summary))
            .unwrap_or_else(|| "never".into())
    ));

    out.push(format!("\n{}", paint("Permissions", "1")));
    let mut category = "";
    for (cat, title, value) in permission_lines(&e.profile.permissions) {
        if cat != category {
            out.push(format!("  {}", paint(&sam_core::i18n::tr(cat), "1")));
            category = cat;
        }
        out.push(format!("    {title:<40} {value}"));
    }
    if let Some(d) = &e.detection {
        out.push(format!("\n{}", paint("Dependencies", "1")));
        out.extend(detection_lines(d));
    }
    if !e.recommendation_notes.is_empty() {
        out.push(format!(
            "\n{}",
            paint(&sam_core::i18n::tr("Why this profile"), "1")
        ));
        for n in &e.recommendation_notes {
            out.push(format!("  - {n}"));
        }
    }
    if !warnings.is_empty() {
        out.push(format!("\n{}", paint("Warnings", "1")));
        out.extend(warning_lines(warnings));
    }
    out
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
    for line in detection_lines(d) {
        outln!("{line}");
    }
}

/// The dependency report: toolkit, compatibility, the libraries missing in
/// the app, what it still needs from the host, and the notes.
pub(crate) fn detection_lines(d: &DependencyReport) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!(
        "  toolkit: {}   arch: {}   ELF files: {}   bundled libs: {}",
        d.requirements.toolkit, d.arch, d.elf_count, d.bundled_libraries
    ));
    out.push(format!(
        "  compatibility: {:?}{}",
        d.compatibility,
        d.verdict
            .map(|v| format!("   ({})", v.message()))
            .unwrap_or_default()
    ));
    let host_libs: Vec<&str> = d
        .missing
        .iter()
        .filter(|m| m.class == ResourceClass::System)
        .map(|m| m.name.as_str())
        .collect();
    if !host_libs.is_empty() {
        out.push(format!("  host system libraries: {}", host_libs.join(", ")));
    }
    for m in d
        .missing
        .iter()
        .filter(|m| m.class != ResourceClass::System)
    {
        out.push(format!(
            "  host library {} [{:?}]{}",
            m.name,
            m.class,
            if m.host_available { "" } else { "  NOT FOUND" }
        ));
    }
    for r in d.resources.iter().filter(|r| !r.auto) {
        out.push(format!("  needs {} ({})", r.resource, r.reason));
    }
    for n in &d.notes {
        out.push(format!("  note: {n}"));
    }
    out
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

    const ALL_BADGES: [Badge; 10] = [
        Badge::Ready,
        Badge::NeedsReview,
        Badge::CompatibilityMode,
        Badge::CompatibilityRisk,
        Badge::Stale,
        Badge::Broken,
        Badge::Unsafe,
        Badge::Missing,
        Badge::ChangedOutside,
        Badge::ProtectionMissing,
    ];

    /// No two of `v` are the same.
    fn all_different(v: &[String]) -> bool {
        v.iter()
            .enumerate()
            .all(|(i, a)| v[i + 1..].iter().all(|b| a != b))
    }

    /// Every state, risk level and warning severity is shown in its own
    /// words: `list`, `info`, `add`, `set` and `evaluate` tell the user an
    /// app is Unsafe, Dangerous or lacks its protection only through these.
    #[test]
    fn every_state_risk_and_severity_is_shown_in_its_own_words() {
        let badges: Vec<String> = ALL_BADGES.iter().map(|b| badge_str(*b)).collect();
        for (b, shown) in ALL_BADGES.iter().zip(&badges) {
            assert!(shown.contains(b.label()), "{b:?} shown as {shown:?}");
        }
        assert!(all_different(&badges), "{badges:?}");

        let levels = [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Dangerous,
        ];
        for r in levels {
            let shown = risk_str(r);
            assert!(!r.words().is_empty());
            assert!(shown.contains(&r.words()), "{r:?} shown as {shown:?}");
        }
        assert_ne!(risk_str(RiskLevel::Dangerous), risk_str(RiskLevel::Low));
        assert_ne!(risk_str(RiskLevel::Dangerous), risk_str(RiskLevel::High));

        let sevs = [Severity::Info, Severity::Warning, Severity::Danger];
        let shown: Vec<String> = sevs.iter().map(|s| sev_str(*s)).collect();
        for (word, s) in ["info", "warning", "danger"].iter().zip(&shown) {
            assert!(s.contains(word), "{word} shown as {s:?}");
        }
        assert!(all_different(&shown), "{shown:?}");
    }

    /// The risk line names the level and the permissions that set it.
    #[test]
    fn the_risk_line_names_the_level_and_what_sets_it() {
        let mut p = sam_core::permissions::PermissionSet::strict_gui();
        p.network.mode = sam_core::permissions::NetworkMode::Full;
        let r = sam_core::risk::assess(&p);
        assert!(r.level >= RiskLevel::High, "{r:?}");
        let deciding: Vec<String> = r.deciding().iter().map(|i| i.title.clone()).collect();
        assert!(!deciding.is_empty());
        assert_eq!(
            risk_line(&r),
            format!("{} ({})", risk_str(r.level), deciding.join(", "))
        );
        let low = sam_core::risk::RiskAssessment::default();
        assert_eq!(risk_line(&low), risk_str(RiskLevel::Low));
        assert!(risk_line(&low).contains(&RiskLevel::Low.words()));
    }

    /// Every warning is shown with its severity, title and message.
    #[test]
    fn every_warning_is_shown_with_its_severity_title_and_message() {
        let ws = [
            Warning::new(
                "a",
                Severity::Danger,
                "Home folder",
                "It can read your files.",
            ),
            Warning::new("b", Severity::Info, "Fonts", "Shared read-only."),
        ];
        assert_eq!(
            warning_lines(&ws),
            [
                format!(
                    "  [{}] Home folder: It can read your files.",
                    sev_str(Severity::Danger)
                ),
                format!("  [{}] Fonts: Shared read-only.", sev_str(Severity::Info)),
            ]
        );
    }

    /// A name longer than its column is cut to the column with "…", so an
    /// app cannot push SAM's real risk and state out of their columns with
    /// a long name of its own (a fake "Harmless  Ready" in the name would
    /// line up under them). Counted in characters, not bytes.
    #[test]
    fn a_long_name_is_cut_to_its_column() {
        assert_eq!(truncate("Firefox", 24), "Firefox");
        assert_eq!(truncate("abcd", 4), "abcd", "exactly the column");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("äöüß", 3), "äö…");
        let long = format!("Calc{}Harmless    Ready", " ".repeat(40));
        let cut = truncate(&long, 24);
        assert_eq!(cut.chars().count(), 24);
        assert_eq!(cut, format!("{}…", &long[..23]));
        assert_eq!(truncate(&"x".repeat(24), 24), "x".repeat(24));
    }

    /// `sam-jail command` shows the sandbox command one option with its
    /// values per line, every token in order, and after the real `--` the
    /// program with its arguments; joined again it is exactly the command
    /// that runs.
    #[test]
    fn the_shown_command_is_the_one_that_runs() {
        let argv: Vec<String> = [
            "bwrap",
            "--unshare-all",
            "--ro-bind",
            "/usr",
            "/usr",
            "--tmpfs",
            "/tmp",
            "--setenv",
            "A",
            "--",
            "--die-with-parent",
            "--new-session",
            "--",
            "/app/AppRun",
            "a b",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let shown = pretty_command(&argv);
        assert_eq!(
            shown,
            [
                "bwrap",
                "--unshare-all",
                "--ro-bind /usr /usr",
                "--tmpfs /tmp",
                "--setenv A --",
                "--die-with-parent",
                "--new-session",
                "-- /app/AppRun 'a b'",
            ]
            .join(" \\\n  ")
        );
        assert_eq!(
            shown.replace(" \\\n  ", " "),
            sam_core::util::shell_join(&argv)
        );
        assert_eq!(pretty_command(&[]), "");
        // A value cut off at the end stays shown.
        let short: Vec<String> = ["bwrap", "--ro-bind", "/usr"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(pretty_command(&short), "bwrap \\\n  --ro-bind /usr");
    }

    /// Every option of Bubblewrap stays on one line with its values, also
    /// those SAM's own command has that were split across lines before
    /// (`--uid 1000`, `--overlay-src`, `--overlay` with three values,
    /// `--remount-ro /`, `--json-status-fd 3`).
    #[test]
    fn every_option_keeps_its_values_on_its_line() {
        let groups: [&[&str]; 10] = [
            &["--uid", "1000"],
            &["--gid", "1000"],
            &["--overlay-src", "/app"],
            &["--overlay", "/rw", "/work", "/app"],
            &["--remount-ro", "/"],
            &["--json-status-fd", "3"],
            &["--unsetenv", "X"],
            &["--chmod", "0700", "/x"],
            &["--ro-bind-data", "4", "/etc/x"],
            &["--add-seccomp-fd", "5"],
        ];
        for group in groups {
            let argv: Vec<String> = ["bwrap"]
                .iter()
                .chain(group)
                .chain(&["--new-session", "--", "/app/AppRun"])
                .map(|s| s.to_string())
                .collect();
            assert_eq!(
                pretty_command(&argv),
                format!(
                    "bwrap \\\n  {} \\\n  --new-session \\\n  -- /app/AppRun",
                    group.join(" ")
                ),
                "{group:?}"
            );
        }
    }

    fn report() -> DependencyReport {
        let lib = |name: &str, class, host_available| MissingLibrary {
            name: name.into(),
            class,
            host_available,
            needed_by: vec![],
        };
        let res = |resource: &str, auto| HostResource {
            resource: resource.into(),
            class: ResourceClass::Controlled,
            reason: "plays sound".into(),
            auto,
        };
        DependencyReport {
            arch: "x86_64".into(),
            missing: vec![
                lib("libc.so.6", ResourceClass::System, true),
                lib("libm.so.6", ResourceClass::System, true),
                lib("libfoo.so.1", ResourceClass::Unknown, false),
                lib("libGL.so.1", ResourceClass::Graphics, true),
            ],
            resources: vec![res("pulseaudio", false), res("fonts", true)],
            notes: vec!["uses Qt".into()],
            ..Default::default()
        }
    }

    /// The dependency report shows the system libraries on one line, every
    /// other missing library on its own (NOT FOUND when the host lacks it),
    /// only what the user still has to grant, and the notes.
    #[test]
    fn the_dependency_report_shows_what_is_missing_and_still_needed() {
        let lines = detection_lines(&report());
        assert_eq!(
            lines[2..],
            [
                "  host system libraries: libc.so.6, libm.so.6",
                "  host library libfoo.so.1 [Unknown]  NOT FOUND",
                "  host library libGL.so.1 [Graphics]",
                "  needs pulseaudio (plays sound)",
                "  note: uses Qt",
            ]
        );
        assert!(lines[0].starts_with("  toolkit: "), "{lines:?}");
        assert!(lines[1].starts_with("  compatibility: Good"), "{lines:?}");
        // Without missing system libraries, no empty line about them.
        let none = DependencyReport::default();
        assert_eq!(
            detection_lines(&none).len(),
            2,
            "{:?}",
            detection_lines(&none)
        );
    }

    /// `info` shows the app's comment, why its profile is what it is, its
    /// dependency report and its warnings when it has them, and no empty
    /// sections when it has none.
    #[test]
    fn info_shows_comment_reasons_dependencies_and_warnings() {
        let mut e = AppEntry {
            id: "calc".into(),
            name: "Calc".into(),
            ..Default::default()
        };
        let bare = info_lines(&e, &AppSummary::from_entry(&e), &[], None);
        let why = sam_core::i18n::tr("Why this profile");
        assert!(bare[1].starts_with("  id:"), "no comment line: {bare:?}");
        for heading in [why.as_str(), "Warnings", "Dependencies"] {
            assert!(
                !bare.iter().any(|l| l.contains(heading)),
                "{heading}: {bare:?}"
            );
        }

        e.metadata.comment = "Adds numbers".into();
        e.recommendation_notes = vec!["Network off: it needs none".into()];
        e.detection = Some(report());
        let ws = [Warning::new(
            "x",
            Severity::Danger,
            "Home folder",
            "It can read your files.",
        )];
        let lines = info_lines(&e, &AppSummary::from_entry(&e), &ws, None);
        assert_eq!(lines[1], "  Adds numbers");
        let after = |heading: &str| {
            let i = lines
                .iter()
                .position(|l| l == &format!("\n{}", paint(heading, "1")))
                .unwrap_or_else(|| panic!("{heading} missing: {lines:?}"));
            lines[i + 1].clone()
        };
        assert_eq!(after(&why), "  - Network off: it needs none");
        assert_eq!(after("Warnings"), warning_lines(&ws)[0]);
        assert_eq!(after("Dependencies"), detection_lines(&report())[0]);
        let deps = detection_lines(&report());
        assert!(deps.iter().all(|d| lines.contains(d)), "{lines:?}");
    }
}
