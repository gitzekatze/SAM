//! The privacy check: SAM goes online only when the person asks
//! (docs/security.md, "Network use by SAM itself"). Each test here says
//! exactly what it proves; the limits are named in
//! docs/reports/privacy-check-*.md.
//!
//! - The static gate: clippy refuses, in SAM's program code, every direct
//!   call that starts a program, opens a socket, looks up a name or an
//!   account, hands a link or a remote file to the desktop, or enters the
//!   update chain (clippy.toml, `disallowed-methods` and
//!   `disallowed-types`). Each place that needs one carries an
//!   `#[expect(...)]`, and [`WAYS_OUT`] lists each of them word for word.
//! - Pinned texts: the update module, the window's start and `AppRun`.
//! - The list of libraries SAM is built from.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

// ------------------------------------------------------------------ parser

/// `text` with every comment, string literal (also raw and byte strings)
/// and character literal replaced by spaces, line breaks kept, so braces,
/// brackets and words are found only in code and every line keeps its
/// number. Block comments nest, as in Rust.
fn code_only(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let blank = |ch: char| if ch == '\n' { '\n' } else { ' ' };
    let ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut i = 0;
    while i < c.len() {
        let prev = if i > 0 { c[i - 1] } else { ' ' };
        // A raw string: r"…", r#"…"#, br"…".
        if c[i] == 'r' && !ident(prev)
            || (c[i] == 'b' && c.get(i + 1) == Some(&'r') && !ident(prev))
        {
            let start = i;
            let mut j = if c[i] == 'b' { i + 2 } else { i + 1 };
            let mut hashes = 0;
            while c.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if c.get(j) == Some(&'"') {
                j += 1;
                loop {
                    if j >= c.len() {
                        break;
                    }
                    if c[j] == '"' && (1..=hashes).all(|k| c.get(j + k) == Some(&'#')) {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                out.extend(c[start..j.min(c.len())].iter().map(|&ch| blank(ch)));
                i = j;
                continue;
            }
        }
        match c[i] {
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                let mut depth = 0;
                while i < c.len() {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        out.push_str("  ");
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        out.push_str("  ");
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        out.push(blank(c[i]));
                        i += 1;
                    }
                }
            }
            '"' => {
                out.push(' ');
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        out.push(' ');
                        i += 1;
                    }
                    if i < c.len() {
                        out.push(blank(c[i]));
                        i += 1;
                    }
                }
                out.push(' ');
                i += 1;
            }
            // A character literal ('x', '\n', '\''), not a lifetime ('a).
            '\'' if c.get(i + 1) == Some(&'\\') => {
                out.push_str("  ");
                i += 2;
                while i < c.len() && c[i] != '\'' {
                    out.push(' ');
                    i += 1;
                }
                out.push(' ');
                i += 1;
            }
            '\'' if c.get(i + 2) == Some(&'\'') => {
                out.push_str("   ");
                i += 3;
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// One attribute, joined from `#[` to its matching `]` (rustfmt wraps long
/// ones over several lines), and the line of the statement it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attr {
    /// 1-based line of its `#`.
    line: usize,
    inner: bool,
    /// The attribute as written, its lines joined with single spaces.
    text: String,
    /// The same with strings and comments blanked: what the compiler reads
    /// as lint names.
    code: String,
    /// The first line after it that holds code (comments between, such
    /// as a `// SAFETY:` note, are passed over): (line, trimmed text,
    /// trimmed code).
    next: Option<(usize, String, String)>,
}

/// Lines joined into one attribute text: trimmed, with single spaces, and
/// without the spaces rustfmt's wrapping leaves inside the brackets.
fn join(lines: &[&str]) -> String {
    let t = lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    t.replace("( ", "(").replace(" )", ")").replace(",)", ")")
}

/// Every attribute in `text` outside items marked `#[cfg(test)]`, which
/// no program contains.
fn attributes(text: &str) -> Vec<Attr> {
    let code = code_only(text);
    let orig: Vec<&str> = text.lines().collect();
    let lines: Vec<&str> = code.lines().collect();
    let mut skip = vec![false; lines.len()];
    // Items under #[cfg(test)]: their other attributes, then up to their
    // `;` or the brace that closes their body.
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "#[cfg(test)]" {
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim().starts_with("#[") {
                j += 1;
            }
            let (mut depth, mut opened) = (0i64, false);
            while j < lines.len() {
                for ch in lines[j].chars() {
                    match ch {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if (!opened && lines[j].trim_end().ends_with(';')) || (opened && depth <= 0) {
                    break;
                }
                j += 1;
            }
            for s in skip.iter_mut().take((j + 1).min(lines.len())).skip(i) {
                *s = true;
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        if skip[i] || !(t.starts_with("#[") || t.starts_with("#![")) {
            i += 1;
            continue;
        }
        let mut depth = 0i64;
        let mut end = i;
        'outer: for (j, l) in lines.iter().enumerate().skip(i) {
            for ch in l.chars() {
                match ch {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break 'outer;
                        }
                    }
                    _ => {}
                }
            }
        }
        let next = (end + 1..lines.len())
            .find(|&k| !lines[k].trim().is_empty())
            .map(|k| {
                (
                    k + 1,
                    orig[k].trim().to_string(),
                    lines[k].trim().to_string(),
                )
            });
        out.push(Attr {
            line: i + 1,
            inner: t.starts_with("#!["),
            text: join(&orig[i..=end]),
            code: join(&lines[i..=end]),
            next,
        });
        i = end + 1;
    }
    out
}

/// Whether `word` stands in `code` as a whole word.
fn has_word(code: &str, word: &str) -> bool {
    code.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == word)
}

/// The one-line rule for a statement under a listed `#[expect]` (its code,
/// strings and comments blanked): a `let` or expression statement ending
/// in `;`, or a match arm ending in `,`, starting and ending on this line,
/// with no closure, no block (other than one `unsafe { … }` around the
/// call) and no `if`, `match`, `loop`, `while` or `for`. So the listed line
/// is the whole call and everything it runs. `None` when it obeys.
fn one_line_problem(code: &str) -> Option<&'static str> {
    let count = |c: char| code.matches(c).count();
    if !(code.ends_with(';') || (code.ends_with(',') && code.contains("=>"))) {
        return Some("it is not one statement ending in `;` or one match arm ending in `,`");
    }
    if count('(') != count(')') || count('[') != count(']') {
        return Some("its brackets do not close on this line");
    }
    if code.contains('|') {
        return Some("it holds a closure (`|`)");
    }
    let unsafe_blocks = code.matches("unsafe {").count();
    if count('{') != unsafe_blocks || count('}') != unsafe_blocks || unsafe_blocks > 1 {
        return Some("it holds a block (`{`) other than one `unsafe { … }`");
    }
    for w in ["if", "match", "loop", "while", "for"] {
        if has_word(code, w) {
            return Some("it holds `if`, `match`, `loop`, `while` or `for`");
        }
    }
    None
}

/// The lint names of the gate. A substring, so the old singular names
/// (`disallowed_method`, `disallowed_type`) count too.
fn names_gate(code: &str) -> bool {
    code.contains("disallowed_method") || code.contains("disallowed_type")
}

/// What may never stand in program code: a way to switch the gate off
/// for a whole module or for every lint at once.
fn switches_lints_off(code: &str) -> bool {
    (has_word(code, "allow") || has_word(code, "expect") || has_word(code, "warn"))
        && (code.contains("clippy::all")
            || code.contains("clippy::style")
            || code.contains("clippy::restriction")
            || has_word(code, "warnings")
            || code.contains("renamed_and_removed_lints"))
}

/// The attribute every program crate root carries: the gate is an error
/// in program code and off in its tests.
const ROOT_ATTR: &str =
    "#![cfg_attr(not(test), deny(clippy::disallowed_methods, clippy::disallowed_types))]";

/// What the gate finds in one file: its listed places as (attribute,
/// statement), and its problems.
fn read_file(rel: &str, text: &str, is_root: bool) -> (Vec<(String, String)>, Vec<String>) {
    let mut places = Vec::new();
    let mut problems = Vec::new();
    let mut roots = 0;
    for a in attributes(text) {
        let at = format!("{rel}:{}", a.line);
        if a.inner && a.text == ROOT_ATTR && is_root {
            roots += 1;
            continue;
        }
        if switches_lints_off(&a.code) {
            problems.push(format!(
                "{at}: `{}` switches off lints in program code, and with them the privacy check's gate; name the one lint instead",
                a.text
            ));
            continue;
        }
        if !names_gate(&a.code) {
            continue;
        }
        if a.inner || !a.code.starts_with("#[expect(") {
            problems.push(format!(
                "{at}: `{}`: only an outer #[expect(...)] on one statement may name the privacy check's lints in program code",
                a.text
            ));
            continue;
        }
        let Some((n, stmt, code)) = a.next else {
            problems.push(format!("{at}: `{}` stands on nothing", a.text));
            continue;
        };
        if code.starts_with('#') {
            problems.push(format!(
                "{rel}:{n}: another attribute follows `{}`; put the expect directly on its statement",
                a.text
            ));
            continue;
        }
        if let Some(why) = one_line_problem(&code) {
            problems.push(format!(
                "{rel}:{n}: `{stmt}` under `{}`: {why}. Move the call into its own one-line `let`, with no change in what it does.",
                a.text
            ));
            continue;
        }
        places.push((a.text, stmt));
    }
    if is_root && roots != 1 {
        problems.push(format!(
            "{rel}: a program crate's root must carry `{ROOT_ATTR}` once, not {roots} times"
        ));
    }
    (places, problems)
}

// ------------------------------------------------------------ the gate

/// clippy.toml's `disallowed-methods` and `disallowed-types`: removing one
/// fails here (and its places' expects go unfulfilled).
const GATED: &[&str] = &[
    // Starting a program.
    "std::process::Command::new",
    "std::os::unix::process::CommandExt::exec",
    "libc::fork",
    "libc::vfork",
    "libc::execve",
    "libc::execv",
    "libc::execvp",
    "libc::execvpe",
    "libc::fexecve",
    "libc::posix_spawn",
    "libc::posix_spawnp",
    "libc::system",
    "libc::popen",
    "libc::syscall",
    "gio::Subprocess::newv",
    "gio::SubprocessLauncher::spawn",
    "glib::spawn_async",
    "glib::spawn_async_with_pipes",
    "glib::spawn_command_line_async",
    "gio::AppInfo::create_from_commandline",
    // Sockets.
    "std::net::TcpStream::connect",
    "std::net::TcpStream::connect_timeout",
    "std::net::UdpSocket::bind",
    "std::net::TcpListener::bind",
    "std::os::unix::net::UnixStream::connect",
    "std::os::unix::net::UnixStream::connect_addr",
    "std::os::unix::net::UnixDatagram::connect",
    "std::os::unix::net::UnixDatagram::send_to",
    "libc::socket",
    "libc::connect",
    "libc::sendto",
    "gio::bus_get",
    "gio::bus_get_sync",
    "gio::bus_get_future",
    // Name and account lookups.
    "std::net::ToSocketAddrs::to_socket_addrs",
    "libc::getaddrinfo",
    "libc::getnameinfo",
    "libc::getpwuid",
    "libc::getpwuid_r",
    "libc::getpwnam",
    "libc::getpwnam_r",
    "libc::getgrgid",
    "libc::getgrgid_r",
    "libc::getgrnam",
    "libc::getgrnam_r",
    "std::env::home_dir",
    // Links and remote files.
    "gtk4::UriLauncher::new",
    "gtk4::show_uri",
    "gtk4::show_uri_full",
    "gtk4::FileLauncher::new",
    "gio::AppInfo::launch_default_for_uri",
    "gio::AppInfo::launch_default_for_uri_async",
    "gio::File::for_uri",
    "gtk4::LinkButton::new",
    "gtk4::LinkButton::with_label",
    "libadwaita::builders::AboutDialogBuilder::website",
    "libadwaita::builders::AboutDialogBuilder::issue_url",
    "libadwaita::builders::AboutDialogBuilder::support_url",
    "libadwaita::builders::AboutDialogBuilder::license_type",
    "libadwaita::AboutDialog::set_website",
    "libadwaita::AboutDialog::set_issue_url",
    "libadwaita::AboutDialog::set_support_url",
    "libadwaita::AboutDialog::set_license_type",
    "libadwaita::AboutDialog::add_link",
    // The update chain.
    "sam_runner::updates::check",
    "sam_runner::updates::check_unpacked",
    "sam_runner::updates::newest",
    "sam_runner::updates::download_update",
    "sam_runner::updates::download_update_within",
    "sam_runner::ops::Sam::check_updates",
    "sam_runner::ops::Sam::update",
    "sam_runner::ops::Sam::update_in",
    "sam_runner::ops::Sam::self_update",
    "sam_runner::ops::Sam::self_update_with_keys",
    "sam_runner::ops::Sam::self_update_from",
    // The window's network commands.
    "sam_jail_gui::backend::Backend::call_online",
    // Types (disallowed-types).
    "gio::SocketClient",
    "gio::Resolver",
    "gio::NetworkMonitor",
    "gio::SocketConnection",
    "gio::DBusConnection",
    "gio::DBusProxy",
];

/// Every place in SAM's program code that starts a program, opens a
/// socket, hands something to the desktop or enters the update chain:
/// (file, its `#[expect]`, its one-line statement, what runs, when, and
/// what it sends). A new place, a changed line or a place that went away
/// fails [`every_way_out_of_sams_code_is_listed`] until this list is
/// changed with it, which a review then judges. Only curl's requests go
/// off this computer (crates/sam-runner/src/updates.rs).
const WAYS_OUT: &[(&str, &str, &str, &str)] = &[
    (
        "crates/sam-core/src/host.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, the Landlock version query\")]",
        "let r = unsafe { libc::syscall(nr, attr, 0usize, version) };",
        "A plain syscall (Landlock's version query); in doctor and before a sandbox starts; nothing leaves this computer.",
    ),
    (
        "crates/sam-core/src/host.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a tool's version option\")]",
        "let out = Command::new(path).args(args).output().ok()?;",
        "A local tool's version option (bwrap, strace, pipewire and others, `host::probe_full`); in doctor and the bug report; runs on this computer.",
    ),
    (
        "crates/sam-core/src/host.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap --help, to read its options\")]",
        "let mut cmd = std::process::Command::new(bwrap);",
        "bwrap --help, to see which options this Bubblewrap knows; before a sandbox is built and in doctor; runs on this computer.",
    ),
    (
        "crates/sam-core/src/host.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap with a test overlay\")]",
        "let mut cmd = std::process::Command::new(bwrap);",
        "bwrap with a test overlay in a temporary folder; once per Bubblewrap, before the first app with a writable app folder; runs on this computer.",
    ),
    (
        "crates/sam-core/src/util.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, close_range\")]",
        "let r = unsafe { libc::syscall(nr, 3u32, u32::MAX, flags) };",
        "A plain syscall (close_range sets close-on-exec on SAM's own descriptors); before SAM starts a program; nothing is sent.",
    ),
    (
        "crates/sam-detect/src/signature.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: gpg or gpgv without the unpack sandbox\")]",
        "GnuPg::Direct => Ok(Command::new(program)),",
        "gpg or gpgv directly with --batch --no-options and a throwaway home (doctor's GnuPG check on SAM's test keys, SAM's own update when no unpack sandbox can be built, developer builds); no key server is asked.",
    ),
    (
        "crates/sam-detect/src/signature.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: gpg to sign with a developer's key\")]",
        "let mut c = Command::new(&gpg);",
        "gpg to export the developer's key and sign, with the developer's own GnuPG configuration; only the dev tool sign-appimage; runs on this computer.",
    ),
    (
        "crates/sam-gtk/src/app_page/data.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a local folder, opened on a click\")]",
        "let launcher = gtk::FileLauncher::new(Some(&gio::File::for_path(&p)));",
        "Hands a local folder (an app's folder) to the file manager; when the person clicks the button; no web address.",
    ),
    (
        "crates/sam-gtk/src/app_page/data.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: update --decline-key-change, offline\")]",
        "let r = app.backend.call_online(&refs, None).await;",
        "sam-jail update --decline-key-change: deletes the download kept for the answer; after the person said no; offline.",
    ),
    (
        "crates/sam-gtk/src/app_page/data.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: update, after the person said Update Anyway\")]",
        "let r = app.backend.call_online(&refs, None).await;",
        "sam-jail update --accept-key-change: downloads the update; after the person said Update Anyway; curl's requests only.",
    ),
    (
        "crates/sam-gtk/src/app_page/data.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: update, after the person said Update\")]",
        "let mut result = app.backend.call_online(&refs, None).await;",
        "sam-jail update <id>: downloads the update; after the person said Update in the dialog; curl's requests only.",
    ),
    (
        "crates/sam-gtk/src/app_page/render.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: the app's download page\")]",
        "let launcher = gtk::UriLauncher::new(&page);",
        "Hands the app's download page to the browser; when the person clicks Open Download Page; SAM sends nothing itself.",
    ),
    (
        "crates/sam-gtk/src/app_page/render.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: update --undo, offline\")]",
        "let r = app.backend.call_online(&args, None).await;",
        "sam-jail update <id> --undo: puts the kept version back; when the person clicks the button; offline.",
    ),
    (
        "crates/sam-gtk/src/app_page/render.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: updates <id>, on a click\")]",
        "let r = app.backend.call_online(&args, None).await;",
        "sam-jail updates <id>: an update check; when the person clicks Check for Updates; curl's requests only.",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail, SAM's command line tool\")]",
        "let started = gio::Subprocess::newv(&argv_ref, flags);",
        "sam-jail --json <command>, SAM's command line tool, for every page of the window; the three commands that go online are refused here (call_online runs them).",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail, SAM's command line tool\")]",
        "let started = gio::Subprocess::newv(&argv_ref, flags);",
        "sam-jail --json <command> with progress lines, for adding an app; the three commands that go online are refused here.",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail-run, to start an app\")]",
        "let started = gio::Subprocess::newv(&argv_ref, gio::SubprocessFlags::NONE);",
        "sam-jail-run --app-id <id>: starts an app in its sandbox; when the person starts it; the app's network is its own permission.",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: the terminal GIO picks\")]",
        "let info = gio::AppInfo::create_from_commandline(&cmd, Some(name), flags);",
        "The terminal emulator GIO picks, running sam-jail-run for a terminal app; when the person starts it; runs on this computer.",
    ),
    (
        "crates/sam-gtk/src/i18n.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail config get\")]",
        "let mut cmd = std::process::Command::new(cli);",
        "sam-jail --json config get general.language, before the window opens; runs on this computer.",
    ),
    (
        "crates/sam-gtk/src/main.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: this window again\")]",
        "let err = cmd.exec();",
        "Replaces the window with a new one (same program, same arguments) after the person changed the language; runs on this computer.",
    ),
    (
        "crates/sam-gtk/src/main.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: this window again\")]",
        "let mut cmd = std::process::Command::new(exe);",
        "Builds the command that starts the window again after a language change; runs on this computer.",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: /bin/sh, to start the new SAM\")]",
        "let started = gio::Subprocess::newv(&argv, gio::SubprocessFlags::NONE);",
        "/bin/sh -c 'sleep 1; exec <new SAM>': starts the updated SAM; after the person said Restart; runs on this computer.",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: SAM's release page\")]",
        "let launcher = gtk::UriLauncher::new(&page);",
        "Hands SAM's release page to the browser; after the person said Yes in the dialog; SAM sends nothing itself.",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a link, opened on a click\")]",
        "let d = d.license_type(gtk::License::Gpl30);",
        "The About dialog's licence link (libadwaita's GPL page), opened by the browser only on a click.",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a link, opened on a click\")]",
        "let d = d.website(\"https://github.com/gitzekatze/SAM\");",
        "The About dialog's link to SAM's website, opened by the browser only on a click.",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: self-update --check, from the menu\")]",
        "let r = me.backend.call_online(&args, None).await;",
        "sam-jail self-update --check: SAM's own update check; when the person chooses Check for SAM Updates; curl's requests only.",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: self-update, after the person said Update\")]",
        "let r = me.backend.call_online(&[\"self-update\"], None).await;",
        "sam-jail self-update: downloads SAM's update; after the person said Update; curl's requests only.",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: updates --if-due\")]",
        "let r = me.backend.call_online(&args, None).await;",
        "sam-jail updates --if-due at every window start; it returns at once unless the person switched on the daily check (off by default), then curl's requests only.",
    ),
    (
        "crates/sam-intake/src/desktop.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: update-desktop-database\")]",
        "let _ = Command::new(udd).arg(\"-q\").arg(dir).status();",
        "update-desktop-database -q for SAM's menu folder; when menu entries change; runs on this computer.",
    ),
    (
        "crates/sam-intake/src/extract.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bsdtar without the unpack sandbox\")]",
        "None => Command::new(&b),",
        "bsdtar to unpack an AppImage, without the unpack sandbox (developer builds or when none can be built); runs on this computer.",
    ),
    (
        "crates/sam-intake/src/extract.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap, the unpack sandbox\")]",
        "let mut c = Command::new(&iso.bwrap);",
        "bwrap, the unpack sandbox (--unshare-all, no network); when an AppImage is unpacked; runs on this computer.",
    ),
    (
        "crates/sam-intake/src/extract.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap, the unpack sandbox\")]",
        "let mut cmd = Command::new(&iso.bwrap);",
        "bwrap, the unpack sandbox (--unshare-all, no network) for SAM's own extractor; when an AppImage is unpacked; runs on this computer.",
    ),
    (
        "crates/sam-intake/src/extract.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: dwarfsextract without the unpack sandbox\")]",
        "None => Command::new(&d),",
        "dwarfsextract to unpack an AppImage, without the unpack sandbox (developer builds or when none can be built); runs on this computer.",
    ),
    (
        "crates/sam-intake/src/extract.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: unsquashfs without the unpack sandbox\")]",
        "None => Command::new(&u),",
        "unsquashfs to unpack an AppImage, without the unpack sandbox (developer builds or when none can be built); runs on this computer.",
    ),
    (
        "crates/sam-intake/src/testkit.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: objcopy, for test AppImages\")]",
        "let mut cmd = std::process::Command::new(\"objcopy\");",
        "objcopy to write sections of test AppImages; developer builds and dev tools only; runs on this computer.",
    ),
    (
        "crates/sam-jail-cli/src/bin/sam-jail-run.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: /bin/sh for a desktop notice\")]",
        "let mut cmd = Command::new(\"/bin/sh\");",
        "/bin/sh for kdialog, zenity or notify-send: a desktop dialog when a start from the menu fails; runs on this computer.",
    ),
    (
        "crates/sam-jail-cli/src/bin/sam-jail-run.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: /bin/sh for a desktop notice\")]",
        "let mut cmd = Command::new(\"/bin/sh\");",
        "/bin/sh for kdialog, zenity or notify-send: a desktop notice when a start from the menu fails; runs on this computer.",
    ),
    (
        "crates/sam-jail-cli/src/bin/sam-jail-run.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: notify-send\")]",
        "let mut cmd = Command::new(n);",
        "notify-send: a desktop notification when a start from the menu fails; the notification daemon shows it on this computer.",
    ),
    (
        "crates/sam-jail-cli/src/main.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail self-update\")]",
        "let r = app.self_update(&appimage, check)?;",
        "sam-jail self-update [--check]: SAM's own update, when the person runs it; curl's requests only.",
    ),
    (
        "crates/sam-jail-cli/src/main.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail update\")]",
        "let e = app.update(&q, accept_key_change)?;",
        "sam-jail update <id>: an app's update, when the person runs it; curl's requests only.",
    ),
    (
        "crates/sam-jail-cli/src/main.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail updates\")]",
        "let results = app.check_updates(q.as_deref(), if_due)?;",
        "sam-jail updates [<id>] [--if-due]: update checks, when the person runs it (--if-due checks only with the daily check switched on); curl's requests only.",
    ),
    (
        "crates/sam-runner/src/contracts.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a tool a contract names\")]",
        "let mut cmd = Command::new(path);",
        "A tool a contract check names, with fixed arguments (pactl info, gpg --version and others); doctor --contracts and the bug report; runs on this computer.",
    ),
    (
        "crates/sam-runner/src/dbus_check.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a D-Bus socket\")]",
        "let connected = UnixStream::connect(path);",
        "Connects to a D-Bus socket on this computer (Hello, GetNameOwner, RequestName for tests' private buses); the sandbox check.",
    ),
    (
        "crates/sam-runner/src/dbus_proxy.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: the proxy's own socket\")]",
        "let connected = std::os::unix::net::UnixStream::connect(path);",
        "Connects to xdg-dbus-proxy's own socket to see that it listens; when an app with the filtered session bus starts.",
    ),
    (
        "crates/sam-runner/src/dbus_proxy.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: xdg-dbus-proxy\")]",
        "let mut cmd = Command::new(&program);",
        "xdg-dbus-proxy, the filtered session bus; when an app starts; local sockets only.",
    ),
    (
        "crates/sam-runner/src/device_watch.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a fork of the device watcher\")]",
        "let pid = unsafe { libc::fork() };",
        "A child of the device watcher that takes an unplugged device out of a running app's sandbox; it runs no program.",
    ),
    (
        "crates/sam-runner/src/device_watch.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, pidfd_open\")]",
        "let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;",
        "A plain syscall (pidfd_open); the device watcher; nothing is sent.",
    ),
    (
        "crates/sam-runner/src/device_watch.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, pidfd_send_signal\")]",
        "let _ = unsafe { libc::syscall(nr, fd, libc::SIGKILL, info, 0) };",
        "A plain syscall (pidfd_send_signal, SIGKILL); the device watcher ends a sandbox; nothing is sent.",
    ),
    (
        "crates/sam-runner/src/doctor.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap, a test sandbox\")]",
        "let mut cmd = Command::new(&b.path);",
        "bwrap with --unshare-all, a test sandbox that runs /usr/bin/true; doctor; runs on this computer.",
    ),
    (
        "crates/sam-runner/src/kernel.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: the program a sandbox runs\")]",
        "let mut cmd = Command::new(prog);",
        "The program an app's sandbox runs, as its child (sam-jail-run inside the sandbox); the app's network is its own permission.",
    ),
    (
        "crates/sam-runner/src/launch.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap --version\")]",
        "let mut cmd = Command::new(bwrap);",
        "bwrap --version, before Room service is set up; runs on this computer.",
    ),
    (
        "crates/sam-runner/src/launch.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap, an app's sandbox\")]",
        "let mut cmd = Command::new(&prepared.command.program);",
        "bwrap (or pasta around it for \"This computer only\"), an app's sandbox; when the person starts an app; the app's network is its own permission.",
    ),
    (
        "crates/sam-runner/src/netns.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: pasta --help\")]",
        "let mut cmd = Command::new(&pasta);",
        "pasta --help, to see whether it knows --splice-only; doctor and before an app with \"This computer only\" starts; pasta opens a socket to probe the kernel and connects nowhere.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: SAM's own update check\")]",
        "return self.self_update_from(appimage, appimage, true, keys);",
        "SAM's own update check, reading the running file; through sam-jail self-update --check only.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: SAM's own update\")]",
        "Ok(_) => self.self_update_from(appimage, &installed, false, keys),",
        "SAM's own update; through sam-jail self-update only.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: SAM's own update\")]",
        "let r = self.self_update_with_keys(appimage, check_only, keys);",
        "SAM's own update with its release keys; through sam-jail self-update only.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: SAM's update download\")]",
        "let fetched = crate::updates::download_update(&p, installed, &tmp)?;",
        "Downloads SAM's update with curl; through sam-jail self-update only.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: SAM's update source\")]",
        "let newest = crate::updates::newest(installed)?;",
        "Asks SAM's update source what it publishes, with curl; through sam-jail self-update only.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: an app's update check\")]",
        "Some(x) => crate::updates::check_unpacked(&e.source_path, &x.source),",
        "An app's update check with curl; through sam-jail updates only.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: an app's update download\")]",
        "_ => (crate::updates::download_update(&p, &installed, &tmp)?, None),",
        "Downloads an app's update with curl; through sam-jail update only.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: an app's update source\")]",
        "let newest = crate::updates::newest(&installed)?;",
        "Asks an app's update source what it publishes, with curl; through sam-jail update only.",
    ),
    (
        "crates/sam-runner/src/ops/maintain.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: an app's update\")]",
        "let result = self.update_in(&entry, &work, accept_key_change);",
        "An app's update; through sam-jail update only.",
    ),
    (
        "crates/sam-runner/src/ops/mod.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, pidfd_open\")]",
        "let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };",
        "A plain syscall (pidfd_open); when SAM stops an app; nothing is sent.",
    ),
    (
        "crates/sam-runner/src/ops/mod.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, pidfd_send_signal\")]",
        "let _ = unsafe { libc::syscall(nr, fd, sig, info, 0) };",
        "A plain syscall (pidfd_send_signal); when SAM stops an app; nothing is sent.",
    ),
    (
        "crates/sam-runner/src/probe.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a TCP connect to 127.0.0.1\")]",
        "let open = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok();",
        "A TCP connect to 127.0.0.1:<port>, inside an app's sandbox with \"This computer only\", to each port the settings list and one they do not; the sandbox check; never leaves this computer.",
    ),
    (
        "crates/sam-runner/src/probe.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, keyctl, expected refused\")]",
        "let r = unsafe { libc::syscall(libc::SYS_keyctl, 0, -3, 0) };",
        "A plain syscall (keyctl, expected to be refused); the sandbox check inside the app's sandbox; nothing is sent.",
    ),
    (
        "crates/sam-runner/src/probe.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: an abstract Unix socket\")]",
        "Ok(a) => std::os::unix::net::UnixStream::connect_addr(&a).is_ok(),",
        "Connects to an abstract Unix socket inside the app's sandbox, expected refused or allowed as its settings say; the sandbox check.",
    ),
    (
        "crates/sam-runner/src/room_service.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: Room service's socket\")]",
        "let connected = UnixStream::connect(socket);",
        "Connects to Room service's socket on this computer; when an app's helper asks for a room.",
    ),
    (
        "crates/sam-runner/src/room_service.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a fork of Room service\")]",
        "let pid = unsafe { libc::fork() };",
        "A fork of Room service, which then runs the room helper in its room; when an app's helper asks for a room.",
    ),
    (
        "crates/sam-runner/src/room_service.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a helper in its room\")]",
        "libc::execve(path.as_ptr(), argv_ptrs.as_ptr(), envp.as_ptr());",
        "The room helper (sam-room-exec) in its room, after the fork; when an app's helper asks for a room.",
    ),
    (
        "crates/sam-runner/src/room_service.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, close_range\")]",
        "let r = unsafe { libc::syscall(libc::SYS_close_range, from, to, CLOSE_RANGE_CLOEXEC) };",
        "A plain syscall (close_range sets close-on-exec); Room service before it runs a helper; nothing is sent.",
    ),
    (
        "crates/sam-runner/src/room_service.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, getdents64\")]",
        "let n = unsafe { libc::syscall(libc::SYS_getdents64, dir, buf.as_mut_ptr(), buf.len()) };",
        "A plain syscall (getdents64, reading a folder of descriptors); Room service; nothing is sent.",
    ),
    (
        "crates/sam-runner/src/sound_relay.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap, the sound relay's sandbox\")]",
        "let mut c = Command::new(bwrap);",
        "bwrap, the sound relay's sandbox (pipewire-pulse); when an app with sound starts; local sockets only.",
    ),
    (
        "crates/sam-runner/src/sound_relay.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: the relay's own socket\")]",
        "let connected = std::os::unix::net::UnixStream::connect(&socket);",
        "Connects to the sound relay's own socket to see that it is ready; when an app with sound starts.",
    ),
    (
        "crates/sam-runner/src/testenv.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a program a test starts\")]",
        "let mut c = std::process::Command::new(program);",
        "A program a test starts (dbus-daemon, ssh-agent for tests' private services); only tests call it.",
    ),
    (
        "crates/sam-runner/src/testenv.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: a syscall, close_range\")]",
        "let marked = libc::syscall(nr, 3u32, u32::MAX, flags);",
        "A plain syscall (close_range) in a test's service; only tests call it.",
    ),
    (
        "crates/sam-runner/src/updates.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: an update download\")]",
        "let r = download_update_within(p, old, dest, UPDATE_TIME_LIMIT);",
        "Downloads an update within the update's time limit; through download_update only.",
    ),
    (
        "crates/sam-runner/src/updates.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: curl, for an update request\")]",
        "let mut cmd = Command::new(curl);",
        "curl with curl_args: SAM's one way off this computer; an update check or an update the person asked for (or the daily check, off by default); sends the address, the server's name, SAM's user agent, Accept and, for part of a file, Range.",
    ),
    (
        "crates/sam-runner/src/verify.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: bwrap, the sandbox check\")]",
        "let mut command = Command::new(&cmd.program);",
        "bwrap, the sandbox check of an app; when the person or the window checks an app; the app's network is its own permission.",
    ),
    (
        "crates/sam-runner/src/wayland_ctx.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: the Wayland socket\")]",
        "let attempt = UnixStream::connect(display);",
        "Connects to the Wayland socket on this computer; when an app with Wayland starts.",
    ),
];

/// The program crates: their roots carry [`ROOT_ATTR`]. The test guard is
/// a test-only crate, part of no program.
fn program_files() -> Vec<(String, bool)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    for c in fs::read_dir(root().join("crates")).unwrap().flatten() {
        if c.file_name() == "sam-test-guard" {
            continue;
        }
        walk(&c.path().join("src"), &mut files);
    }
    let mut out: Vec<(String, bool)> = files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root())
                .unwrap()
                .to_string_lossy()
                .replace("/../..", "")
                .to_string();
            let rel = rel.trim_start_matches("./").to_string();
            let tail = rel.splitn(3, '/').nth(2).unwrap_or_default().to_string();
            let is_root = tail == "src/lib.rs"
                || tail == "src/main.rs"
                || (tail.starts_with("src/bin/") && tail.matches('/').count() == 2);
            (rel, is_root)
        })
        .collect();
    out.sort();
    out
}

/// The paths of clippy.toml's list named `key`.
fn clippy_paths(toml_text: &str, key: &str) -> Vec<String> {
    let v: toml::Value = toml::from_str(toml_text).unwrap();
    v.get(key)
        .and_then(|l| l.as_array())
        .map(|l| {
            l.iter()
                .map(|e| e["path"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The `[lints]` part of a Cargo.toml: from its header to the next one.
fn lints_section(toml_text: &str, header: &str) -> Option<String> {
    let start = toml_text.lines().position(|l| l.trim() == header)?;
    Some(
        toml_text
            .lines()
            .skip(start + 1)
            .take_while(|l| !l.trim_start().starts_with('['))
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// The static gate holds, and every way out of SAM's program code is
/// listed: clippy.toml gates exactly [`GATED`]; every program crate root
/// denies the gate's lints outside its tests, and nothing in the build
/// settings switches that off; and in program code every attribute that
/// names the gate's lints is an outer `#[expect]` on one statement that
/// obeys the one-line rule, and each such pair is in [`WAYS_OUT`], with
/// multiplicity. Together with clippy (CI runs it with `-D warnings`), a
/// new direct call of a gated method or type in program code, or a changed
/// listed line, fails until [`WAYS_OUT`] says what it runs, when, and
/// what it sends.
#[test]
fn every_way_out_of_sams_code_is_listed() {
    let mut problems = Vec::new();
    // clippy.toml gates exactly GATED.
    let clippy = read("clippy.toml");
    let mut gated = clippy_paths(&clippy, "disallowed-methods");
    gated.extend(clippy_paths(&clippy, "disallowed-types"));
    let want: Vec<String> = GATED.iter().map(|s| s.to_string()).collect();
    if gated != want {
        problems.push(format!(
            "clippy.toml's disallowed-methods and disallowed-types are not GATED in crates/sam-jail-cli/tests/network_use.rs:\n  clippy.toml: {gated:?}\n  GATED:       {want:?}"
        ));
    }
    // The lint levels: allowed for the workspace (tests), denied at each
    // program crate root (read_file), never capped or switched off.
    let ws = lints_section(&read("Cargo.toml"), "[workspace.lints.clippy]").unwrap_or_default();
    for want in [
        "disallowed_methods = \"allow\"",
        "disallowed_types = \"allow\"",
    ] {
        if !ws.lines().any(|l| l.trim() == want) {
            problems.push(format!("Cargo.toml [workspace.lints.clippy] lost `{want}`"));
        }
    }
    for c in fs::read_dir(root().join("crates")).unwrap().flatten() {
        let manifest = c.path().join("Cargo.toml");
        let text = fs::read_to_string(&manifest).unwrap();
        let name = c.file_name().to_string_lossy().to_string();
        if lints_section(&text, "[lints]").as_deref() != Some("workspace = true")
            || text.lines().any(|l| l.trim_start().starts_with("[lints."))
        {
            problems.push(format!(
                "crates/{name}/Cargo.toml: its [lints] must be exactly `workspace = true`"
            ));
        }
    }
    for cfg in [".cargo/config.toml", ".cargo/config"] {
        if fs::read_to_string(root().join(cfg)).is_ok_and(|t| t.contains("cap-lints")) {
            problems.push(format!("{cfg} caps lints, which switches the gate off"));
        }
    }
    let ci = read(".github/workflows/ci.yml");
    for want in [
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "does not refer to",
    ] {
        if !ci.contains(want) {
            problems.push(format!(
                ".github/workflows/ci.yml lost `{want}`: CI must run clippy with -D warnings and fail on a clippy.toml path that names nothing"
            ));
        }
    }
    // Every program file.
    let mut found: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut roots = 0;
    for (rel, is_root) in program_files() {
        roots += usize::from(is_root);
        let (places, p) = read_file(&rel, &read(&rel), is_root);
        problems.extend(p);
        for (attr, stmt) in places {
            *found.entry((rel.clone(), attr, stmt)).or_default() += 1;
        }
    }
    assert!(roots >= 10, "only {roots} program crate roots found");
    let mut listed: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (f, a, s, _) in WAYS_OUT {
        *listed
            .entry((f.to_string(), a.to_string(), s.to_string()))
            .or_default() += 1;
    }
    for (k, n) in &found {
        let m = listed.get(k).copied().unwrap_or(0);
        if m != *n {
            problems.push(format!(
                "{} holds {n} time(s), WAYS_OUT lists {m}:\n    {:?}, {:?}, {:?},\n  a way out of SAM's code that nobody has looked at: add it to WAYS_OUT in crates/sam-jail-cli/tests/network_use.rs with what it runs, when, and what it sends.",
                k.0, k.0, k.1, k.2
            ));
        }
    }
    for (k, m) in &listed {
        if !found.contains_key(k) {
            problems.push(format!(
                "WAYS_OUT lists {m} time(s) a place that is no longer in {}: {:?} {:?}; remove it from WAYS_OUT.",
                k.0, k.1, k.2
            ));
        }
    }
    for (_, a, _, what) in WAYS_OUT {
        if !a.contains("reason = \"way out: ") || what.len() < 20 {
            problems.push(format!("WAYS_OUT entry {a:?} says too little about itself"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The shared parser reads what the compiler reads: a gate lint named in
/// a raw string, a block comment or a `#[cfg(test)]` module does not
/// count, the code after them does; a wrapped attribute is joined; an old
/// lint name, an inner allow and a blanket allow are refused; an expect on
/// a closure, an `if` or a two-line statement is refused; an expect on a
/// one-line statement with an `unsafe { … }` passes.
#[test]
fn the_way_out_parser_reads_what_the_compiler_reads() {
    let sample = r####"
fn a() {
    let s = r#"#[allow(clippy::disallowed_methods)] { ] "#;
    /* #[allow(clippy::disallowed_methods)] /* nested */ { */
    #[expect(
        clippy::disallowed_methods,
        reason = "way out: a test"
    )]
    // SAFETY: a comment between is passed over.
    let pid = unsafe { libc::fork() };
}
#[cfg(test)]
mod tests {
    #[allow(clippy::disallowed_methods)]
    fn t() { let c = '{'; }
}
#[allow(clippy::disallowed_method)]
fn b() {}
fn c() {
    #[expect(clippy::disallowed_methods, reason = "way out: closure")]
    let f = || Command::new("x");
    #[expect(clippy::disallowed_methods, reason = "way out: if")]
    if Command::new("x").status().is_ok() {}
    #[expect(clippy::disallowed_methods, reason = "way out: two lines")]
    let o = Command::new("x")
        .output();
    #[expect(clippy::disallowed_methods, reason = "way out: arm")]
    Some(p) => Command::new(p),
}
mod d {
    #![allow(clippy::disallowed_methods)]
}
#[allow(clippy::style)]
fn e() {}
"####;
    let (places, problems) = read_file("x.rs", sample, false);
    assert_eq!(
        places,
        [
            (
                "#[expect(clippy::disallowed_methods, reason = \"way out: a test\")]".to_string(),
                "let pid = unsafe { libc::fork() };".to_string()
            ),
            (
                "#[expect(clippy::disallowed_methods, reason = \"way out: arm\")]".to_string(),
                "Some(p) => Command::new(p),".to_string()
            ),
        ]
    );
    let lines: Vec<&str> = problems
        .iter()
        .map(|p| p.split(':').nth(1).unwrap_or_default())
        .collect();
    // The old singular name (17), the closure (21), the `if` (23), the
    // two-line statement (25), the inner allow (31), the blanket allow (33).
    assert_eq!(lines, ["17", "21", "23", "25", "31", "33"], "{problems:#?}");
    // A root without its attribute, and one with it.
    assert_eq!(read_file("r.rs", "fn main() {}\n", true).1.len(), 1);
    let (_, p) = read_file("r.rs", &format!("{ROOT_ATTR}\nfn main() {{}}\n"), true);
    assert!(p.is_empty(), "{p:?}");
}

// -------------------------------------------------------- pinned texts

/// SHA-256 of `text` without its comment lines (`//`, `///`, `//!`), so a
/// changed comment needs no new review.
fn pin(text: &str) -> String {
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    let mut h = Sha256::new();
    h.update(kept.join("\n").as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The function `name` in `text`: from its `fn` line to the first line
/// that holds only `}` at the same indent (rustfmt keeps it so). There
/// must be exactly one.
fn function<'a>(text: &'a str, name: &str) -> &'a str {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let starts: Vec<usize> = (0..lines.len())
        .filter(|&i| {
            let t = lines[i].trim_start();
            let t = t.strip_prefix("pub ").unwrap_or(t);
            let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
            let t = t.strip_prefix("pub(super) ").unwrap_or(t);
            let t = t.strip_prefix("async ").unwrap_or(t);
            t.starts_with(&format!("fn {name}("))
        })
        .collect();
    assert_eq!(starts.len(), 1, "fn {name}: {} found", starts.len());
    let s = starts[0];
    let indent = &lines[s][..lines[s].len() - lines[s].trim_start().len()];
    let e = (s..lines.len())
        .find(|&i| lines[i].trim_end() == format!("{indent}}}"))
        .unwrap();
    let from: usize = lines[..s].iter().map(|l| l.len()).sum();
    let to: usize = lines[..=e].iter().map(|l| l.len()).sum();
    &text[from..to]
}

/// The program part of the update module: everything before its tests.
fn update_module_program() -> String {
    let t = read("crates/sam-runner/src/updates.rs");
    let at = t.find("\n#[cfg(test)]\nmod tests {").unwrap();
    t[..at].to_string()
}

/// The `AppRun` of SAM's AppImage, as scripts/make-appimage.sh writes it.
fn apprun() -> String {
    let t = read("scripts/make-appimage.sh");
    let from = t.find("cat > \"$app/AppRun\" <<'EOF'").unwrap();
    let to = from + t[from..].find("\nEOF\n").unwrap();
    t[from..to].to_string()
}

/// The update module's program part, which builds every request SAM sends
/// (its curl arguments are fixed word for word by the unit test
/// `every_update_request_has_exactly_these_curl_arguments` in
/// crates/sam-runner/src/updates.rs).
const UPDATE_MODULE: &str = "03e16fb9d8001a6813c062638e0b782dd68b1a2ee2259903a78c25646b829a31";

/// The functions the window runs at its start; they run these commands
/// (each traced by `everyday_commands_open_no_internet_socket` as W1-W11):
/// `config get general.language`, `version`, `permissions`,
/// `desktop all refresh`, `config show` (and the two `config set` of an
/// old settings file), `list`, `discover`, `scan <Downloads>`,
/// `updates --if-due`, `list`.
const WINDOW_START: &[(&str, &str, &str)] = &[
    (
        "crates/sam-gtk/src/window.rs",
        "start",
        "a774819c74261b402db0d12b42ba7ef803393dcfafc1e2691d793063a3c018bc",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "check_cli_version",
        "0c37fc360221ecbb1dc0d3d2c83ed5cde235a4f5ec304bf2382053cbba1e40ee",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "load_catalog",
        "1a07634c663e65d5630c7a7125d052b345a58fc7dd42b44c154d3fd4a28436a8",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "load_config",
        "000437eb4b11b4f14e65e864887f1af24a9de22c1422ff62f2e19fcf52ba948a",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "refresh_apps",
        "e5e1357249c08e8a1a4f977cb5983bd87c39a17ded395739aa433db62b2bb64f",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "count_downloads",
        "66d3a16e830cdaf7f744b91461c58e10611371dc4d95f16605ae1886983618e9",
    ),
    (
        "crates/sam-gtk/src/window.rs",
        "refresh_registered",
        "b2181b7cdf3ffb0c209d8e29dd02ed28c4ce8e887269233367ff7285ac9d59f3",
    ),
    (
        "crates/sam-gtk/src/i18n.rs",
        "apply_language_setting",
        "aef64072cc09b5970cfbeeea9d3745c4e85932ef15c25f64e67570bb793b0a13",
    ),
    (
        "crates/sam-gtk/src/i18n.rs",
        "configured_language",
        "05eb38743dc640de6404b3be6078fa35dde2c5b56cc483941a60eea4bbf2e628",
    ),
    (
        "crates/sam-gtk/src/main.rs",
        "main",
        "76c0a19f79f3698cff06c09adbea15f3aa2d040b7bf64f82a8e06ce5907b75d5",
    ),
];

/// `AppRun` runs getconf, `sam-jail-gui --version`, kdialog, zenity and
/// notify-send, all on this computer.
const APPRUN: &str = "d9015dfc7470d7c75d37c51b26608ae90e5e8afb6c0f0fab545ab25e5c44183e";

/// The texts that decide when SAM goes online and what it sends are the
/// reviewed ones: the update module's program part, the functions the
/// window runs at its start, and `AppRun`. Any change to them, other than
/// in comments, fails here until the hash is renewed in the same review
/// that checks the change against docs/security.md ("Network use by SAM
/// itself").
#[test]
fn the_update_module_the_window_start_and_apprun_are_as_reviewed() {
    let mut problems = Vec::new();
    let got = pin(&update_module_program());
    if got != UPDATE_MODULE {
        problems.push(format!(
            "crates/sam-runner/src/updates.rs (before its tests) changed: review whether SAM now sends another request, to another address or with another argument, then set UPDATE_MODULE to \"{got}\""
        ));
    }
    for (file, name, want) in WINDOW_START {
        let got = pin(function(&read(file), name));
        if got != *want {
            problems.push(format!(
                "{file}: fn {name} changed: review whether the window's start now runs another command, then set its hash in WINDOW_START to \"{got}\""
            ));
        }
    }
    let got = pin(&apprun());
    if got != APPRUN {
        problems.push(format!(
            "scripts/make-appimage.sh: the AppRun text changed: review which programs it runs, then set APPRUN to \"{got}\""
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// ----------------------------------------------------------- libraries

/// Every library SAM is built from: (name, version, source) of each
/// `[[package]]` in Cargo.lock; SAM's own crates have no source.
fn lock_packages(lock: &str) -> Vec<(String, String, String)> {
    let v: toml::Value = toml::from_str(lock).unwrap();
    let mut out: Vec<(String, String, String)> = v["package"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let s = |k: &str| p.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            (s("name"), s("version"), s("source"))
        })
        .collect();
    out.sort();
    out
}

/// Cargo.lock's packages, sorted: (name, version, source).
const LIBRARIES: &[(&str, &str, &str)] = &[
    (
        "anstream",
        "1.0.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anstyle",
        "1.0.14",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anstyle-parse",
        "1.0.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anstyle-query",
        "1.1.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anstyle-wincon",
        "3.0.11",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anyhow",
        "1.0.104",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "autocfg",
        "1.5.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "backhand",
        "0.25.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "bitflags",
        "2.13.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "bitvec",
        "1.1.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "block-buffer",
        "0.12.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cairo-rs",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cairo-sys-rs",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cc",
        "1.11.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cfg-expr",
        "0.20.10",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cfg-if",
        "1.0.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap",
        "4.6.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap_builder",
        "4.6.7",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap_derive",
        "4.6.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap_lex",
        "1.1.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap_mangen",
        "0.3.4",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "colorchoice",
        "1.0.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "const-oid",
        "0.10.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cpufeatures",
        "0.3.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "crypto-common",
        "0.2.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "darling",
        "0.21.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "darling_core",
        "0.21.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "darling_macro",
        "0.21.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "deku",
        "0.20.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "deku_derive",
        "0.20.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "digest",
        "0.11.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "downcast-rs",
        "1.2.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "enumflags2",
        "0.7.12",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "enumflags2_derive",
        "0.7.12",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "equivalent",
        "1.0.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "errno",
        "0.3.14",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "fastrand",
        "2.5.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "field-offset",
        "0.3.6",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "find-msvc-tools",
        "0.1.15",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "flate2",
        "1.1.11",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "fnv",
        "1.0.7",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "funty",
        "2.0.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-channel",
        "0.3.34",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-core",
        "0.3.34",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-executor",
        "0.3.34",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-io",
        "0.3.34",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-macro",
        "0.3.34",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-task",
        "0.3.34",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-util",
        "0.3.34",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gdk-pixbuf",
        "0.22.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gdk-pixbuf-sys",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gdk4",
        "0.11.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gdk4-sys",
        "0.11.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "getrandom",
        "0.4.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gio",
        "0.22.10",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gio-sys",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "glib",
        "0.22.10",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "glib-macros",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "glib-sys",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gobject-sys",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "goblin",
        "0.10.7",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "graphene-rs",
        "0.22.8",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "graphene-sys",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gsk4",
        "0.11.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gsk4-sys",
        "0.11.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gtk4",
        "0.11.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gtk4-macros",
        "0.11.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gtk4-sys",
        "0.11.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "hashbrown",
        "0.17.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "heck",
        "0.5.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "hybrid-array",
        "0.4.15",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "ident_case",
        "1.0.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "indexmap",
        "2.14.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "is_terminal_polyfill",
        "1.70.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "itoa",
        "1.0.18",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "jobserver",
        "0.1.35",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "landlock",
        "0.4.7",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "libadwaita",
        "0.9.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "libadwaita-sys",
        "0.9.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "libc",
        "0.2.191",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "liblzma",
        "0.4.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "liblzma-sys",
        "0.4.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "linux-raw-sys",
        "0.12.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "log",
        "0.4.35",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "lz4_flex",
        "0.14.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "md4",
        "0.11.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "memchr",
        "2.8.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "memoffset",
        "0.9.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "no_std_io2",
        "0.9.4",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "once_cell",
        "1.21.4",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "once_cell_polyfill",
        "1.70.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pango",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pango-sys",
        "0.22.9",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pin-project-lite",
        "0.2.17",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pkg-config",
        "0.3.34",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "plain",
        "0.2.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "proc-macro-crate",
        "3.5.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "proc-macro2",
        "1.0.107",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pulldown-cmark",
        "0.13.6",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "quick-xml",
        "0.41.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "quote",
        "1.0.47",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "r-efi",
        "6.0.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "radium",
        "0.7.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "roff",
        "1.1.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "rustc_version",
        "0.4.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "rustix",
        "1.1.6",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "rustversion",
        "1.0.23",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    ("sam-core", "0.1.0", ""),
    ("sam-detect", "0.1.0", ""),
    ("sam-gtk", "0.1.0", ""),
    ("sam-intake", "0.1.0", ""),
    ("sam-jail-cli", "0.1.0", ""),
    ("sam-profile", "0.1.0", ""),
    ("sam-runner", "0.1.0", ""),
    ("sam-sandbox", "0.1.0", ""),
    ("sam-storage", "0.1.0", ""),
    ("sam-test-guard", "0.1.0", ""),
    (
        "scroll",
        "0.13.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "scroll_derive",
        "0.13.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "seccompiler",
        "0.5.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "semver",
        "1.0.28",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde",
        "1.0.229",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde_core",
        "1.0.229",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde_derive",
        "1.0.229",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde_json",
        "1.0.154",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde_spanned",
        "1.1.3",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "sha1",
        "0.11.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "sha2",
        "0.11.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "shlex",
        "2.0.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "slab",
        "0.4.12",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "smallvec",
        "1.16.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "solana-nohash-hasher",
        "0.2.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "strsim",
        "0.11.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "syn",
        "2.0.119",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "syn",
        "3.0.10",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "system-deps",
        "7.0.8",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "system-deps",
        "9.0.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "tap",
        "1.0.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "target-lexicon",
        "0.13.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "tempfile",
        "3.27.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "thiserror",
        "2.0.21",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "thiserror-impl",
        "2.0.21",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml",
        "1.2.1+spec-1.1.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml_datetime",
        "1.1.3+spec-1.1.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml_edit",
        "0.25.19+spec-1.1.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml_parser",
        "1.1.5+spec-1.1.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml_writer",
        "1.2.0+spec-1.1.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "typenum",
        "1.20.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "unicase",
        "2.10.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "unicode-ident",
        "1.0.27",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "utf8parse",
        "0.2.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "version-compare",
        "0.2.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-backend",
        "0.3.17",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-client",
        "0.31.15",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-protocols",
        "0.32.13",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-scanner",
        "0.31.11",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-sys",
        "0.31.11",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "windows-link",
        "0.2.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "windows-sys",
        "0.61.2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "winnow",
        "1.0.5",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wyz",
        "0.5.1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "xxhash-rust",
        "0.8.19",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zlib-rs",
        "0.6.8",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zmij",
        "1.0.23",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zstd",
        "0.13.4",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zstd-safe",
        "7.4.0",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zstd-sys",
        "2.1.2+zstd.1.5.7",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
];

/// Only listed libraries are part of SAM: the name, version and source of
/// every package in Cargo.lock equal [`LIBRARIES`]. A new library, another
/// version or another source (a git fork, a `[patch]`) fails until the
/// list is changed with it, which a review then judges. A listed library
/// is trusted, not proven offline.
#[test]
fn only_listed_libraries_are_part_of_sam() {
    let got = lock_packages(&read("Cargo.lock"));
    let want: Vec<(String, String, String)> = LIBRARIES
        .iter()
        .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
        .collect();
    if got != want {
        let list: Vec<String> = got
            .iter()
            .map(|(n, v, s)| format!("    ({n:?}, {v:?}, {s:?}),"))
            .collect();
        panic!(
            "Cargo.lock's libraries changed (updating dependencies does this): review each new name, version and source, then set LIBRARIES in crates/sam-jail-cli/tests/network_use.rs to:\n{}",
            list.join("\n")
        );
    }
}

/// The library check reads a Cargo.lock's name, version and source, so
/// another version of a listed library is a change.
#[test]
fn the_library_check_sees_a_changed_version() {
    let lock = "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"sam-core\"\nversion = \"0.1.0\"\n";
    let a = lock_packages(lock);
    assert_eq!(
        a,
        [
            ("sam-core".into(), "0.1.0".into(), String::new()),
            (
                "serde".into(),
                "1.0.0".into(),
                "registry+https://github.com/rust-lang/crates.io-index".into()
            ),
        ]
    );
    assert_ne!(a, lock_packages(&lock.replace("1.0.0", "1.0.1")));
}
