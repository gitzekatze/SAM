//! The privacy check: SAM goes online only when the person asks
//! (docs/security.md, "Network use by SAM itself"). Each test here says
//! exactly what it proves; the limits are named in
//! docs/reports/privacy-check-*.md.
//!
//! - The build gate. A safety net, not a proof: in the code CI's clippy
//!   compiles (the debug build for x86_64 with default features), a new
//!   direct call of a function listed in clippy.toml fails CI — clippy
//!   without an `#[expect]`, the pin test without its exact line in the
//!   reviewed list ([`WAYS_OUT`]). It catches accidental new network or
//!   program calls in SAM's own code, not code written to get around it;
//!   the traced run and the request tests are the proof of what SAM does.
//!   Not covered: functions not listed; macros, function pointers and
//!   generic helpers; foreign functions called through a path
//!   (`self::NAME`) or declared in a listed block; code outside the `src`
//!   folders or reached through attributes (`cfg_attr(…, path = …)`, a
//!   `rustfmt::skip` hidden there), and modules of a crate root outside
//!   `src`; `asm!` and `naked_asm!`; release-only and aarch64-only code;
//!   `build.rs` and the room helper; libraries' own behaviour.
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
    /// 1-based line of its closing `]`.
    end: usize,
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

/// The lines of `text` that no program contains: a module marked
/// `#[cfg(test)]` (`mod NAME { … }` up to its closing brace, or
/// `mod NAME;`). Only modules: `#[cfg(test)]` on anything else (a field, a
/// function) is read like program code, so it cannot hide what follows.
fn test_modules(lines: &[&str]) -> Vec<bool> {
    let mut skip = vec![false; lines.len()];
    let is_mod = |l: &str| {
        let t = l.trim();
        let t = t
            .strip_prefix("pub ")
            .or_else(|| t.strip_prefix("pub(crate) "))
            .unwrap_or(t);
        let rest = t.strip_prefix("mod ")?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let after = rest[name.len()..].trim();
        if name.is_empty() {
            None
        } else if after == "{" {
            Some(true)
        } else if after == ";" {
            Some(false)
        } else {
            None
        }
    };
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() != "#[cfg(test)]" {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().starts_with("#[") && lines[j].trim().ends_with(']')
        {
            j += 1;
        }
        let Some(block) = lines.get(j).and_then(|l| is_mod(l)) else {
            i += 1;
            continue;
        };
        let mut end = j;
        if block {
            let mut depth = 0i64;
            'outer: for (k, l) in lines.iter().enumerate().skip(j) {
                for ch in l.chars() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = k;
                                break 'outer;
                            }
                        }
                        _ => {}
                    }
                }
                end = k;
            }
        }
        for s in skip.iter_mut().take(end + 1).skip(i) {
            *s = true;
        }
        i = end + 1;
    }
    skip
}

/// Every attribute that starts a line of `text`, outside test modules
/// ([`test_modules`]).
fn attributes(text: &str) -> Vec<Attr> {
    let code = code_only(text);
    let orig: Vec<&str> = text.lines().collect();
    let lines: Vec<&str> = code.lines().collect();
    let skip = test_modules(&lines);
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
            end: end + 1,
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

/// What the gate finds in one file: its places as (attribute, statement),
/// and its problems. Besides each `#[expect]` and its statement, a place
/// is every line (with an empty attribute) that holds `#[rustfmt::skip]`,
/// `include!`, `#[path`, `asm!`, `global_asm!`, `naked_asm!`, an `extern` block of
/// SAM's own declarations, or a call of a function such a block declares:
/// clippy does not see through them, so each must be listed too. A gate
/// lint named anywhere but in an `#[expect]` that starts its line (inside
/// a macro, after another attribute on the same line) is refused.
fn read_file(rel: &str, text: &str, is_root: bool) -> (Vec<(String, String)>, Vec<String>) {
    let mut places = Vec::new();
    let mut problems = Vec::new();
    let mut roots = 0;
    let code = code_only(text);
    let orig: Vec<&str> = text.lines().collect();
    let lines: Vec<&str> = code.lines().collect();
    let skip = test_modules(&lines);
    // The lines of every attribute that starts a line: judged here.
    let mut judged = vec![false; lines.len()];
    for a in attributes(text) {
        if names_gate(&a.code) {
            for j in judged.iter_mut().take(a.end).skip(a.line - 1) {
                *j = true;
            }
            if !lines[a.end - 1].trim_end().ends_with(']') {
                problems.push(format!(
                    "{rel}:{}: code follows `{}` on its line",
                    a.end, a.text
                ));
            }
        }
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
    // SAM's own `extern` blocks: the functions they declare.
    let mut declared: Vec<String> = Vec::new();
    let mut in_extern = vec![false; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        let words: Vec<&str> = t.split_whitespace().collect();
        let opens = !skip[i]
            && t.ends_with('{')
            && (words.first() == Some(&"extern") || words.get(1) == Some(&"extern"))
            && !has_word(t, "fn");
        if !opens {
            i += 1;
            continue;
        }
        let mut depth = 0i64;
        let mut k = i;
        while k < lines.len() {
            in_extern[k] = true;
            if let Some(name) = lines[k].trim().strip_prefix("fn ") {
                declared.push(
                    name.chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect(),
                );
            }
            depth += lines[k].matches('{').count() as i64 - lines[k].matches('}').count() as i64;
            if depth <= 0 {
                break;
            }
            k += 1;
        }
        places.push((String::new(), orig[i].trim().to_string()));
        i = k + 1;
    }
    for (k, l) in lines.iter().enumerate() {
        if skip[k] {
            continue;
        }
        let t = l.trim();
        if names_gate(t) && !judged[k] {
            problems.push(format!(
                "{rel}:{}: a privacy check lint is named outside an #[expect(...)] that starts its line: `{}`",
                k + 1,
                orig[k].trim()
            ));
        }
        let hidden = t.contains("#[rustfmt::skip")
            || t.contains("include!")
            || t.contains("#[path")
            || has_word(t, "asm")
            || has_word(t, "global_asm")
            || has_word(t, "naked_asm");
        let calls = !in_extern[k]
            && declared.iter().any(|d| {
                t.match_indices(&format!("{d}(")).any(|(at, _)| {
                    t[..at]
                        .chars()
                        .next_back()
                        .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '.' || c == ':'))
                })
            });
        if hidden || calls {
            places.push((String::new(), orig[k].trim().to_string()));
        }
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
    "sam_runner::updates::curl_command",
    "sam_runner::ops::Sam::check_updates",
    "sam_runner::ops::Sam::update",
    "sam_runner::ops::Sam::update_in",
    "sam_runner::ops::Sam::self_update",
    "sam_runner::ops::Sam::self_update_with_keys",
    "sam_runner::ops::Sam::self_update_from",
    // The window's network commands.
    "sam_jail_gui::backend::Backend::call_online",
    // Added after review round 1: more ways to start a program, open a
    // socket, look up an account or hand over a link, and the window
    // backend's inner methods, so a new method cannot skip the refusal.
    "libc::execl",
    "libc::execle",
    "libc::execlp",
    "libc::dlopen",
    "libc::getpwent",
    "libc::getgrent",
    "libc::getgrouplist",
    "libc::initgroups",
    "libc::getspnam",
    "libc::getservbyname",
    "libc::res_init",
    "glib::spawn_async_with_fds",
    "gio::Socket::new",
    "gio::prelude::SocketExt::connect",
    "gio::prelude::SocketListenerExt::add_inet_port",
    "gio::prelude::AppInfoExt::launch",
    "gio::prelude::AppInfoExt::launch_uris",
    "gio::AppInfo::launch_default_for_uri_future",
    "gtk4::UriLauncher::builder",
    "gio::File::for_commandline_arg",
    "gio::File::for_parse_name",
    "sam_jail_gui::backend::Backend::counted",
    "sam_jail_gui::backend::Backend::call_inner",
    "sam_jail_gui::backend::Backend::call_progress_inner",
    // Types (disallowed-types).
    "gio::SocketClient",
    "gio::Resolver",
    "gio::NetworkMonitor",
    "gio::SocketConnection",
    "gio::DBusConnection",
    "gio::DBusProxy",
    "gio::NetworkAddress",
];

/// Every place in SAM's program code that calls a function clippy.toml
/// lists, and every line the parser refuses unless listed: (file, its
/// `#[expect]` or nothing, its one-line statement, what runs, when, and
/// what it sends). A new place, a changed line or a place that went away
/// fails [`each_listed_call_in_program_code_is_a_listed_place`] until this list is
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
    (
        "crates/sam-core/src/i18n.rs",
        "",
        "CStr::from_ptr(dngettext(",
        "dngettext: a translated text with a plural, from SAM's translation files on this computer.",
    ),
    (
        "crates/sam-core/src/i18n.rs",
        "",
        "bind_textdomain_codeset(domain.as_ptr(), c\"UTF-8\".as_ptr());",
        "bind_textdomain_codeset: asks for UTF-8 translations; nothing is sent.",
    ),
    (
        "crates/sam-core/src/i18n.rs",
        "",
        "bindtextdomain(domain.as_ptr(), dir.as_ptr());",
        "bindtextdomain: names the folder of SAM's translation files on this computer.",
    ),
    (
        "crates/sam-core/src/i18n.rs",
        "",
        "let out = unsafe { CStr::from_ptr(dgettext(domain.as_ptr(), id.as_ptr())) };",
        "dgettext: a translated text, from SAM's translation files on this computer.",
    ),
    (
        "crates/sam-core/src/i18n.rs",
        "",
        "unsafe extern \"C\" {",
        "SAM's own declarations of four gettext functions of the C library (dgettext, dngettext, bindtextdomain, bind_textdomain_codeset); they read SAM's translation files on this computer.",
    ),
    (
        "crates/sam-core/src/place_check.rs",
        "",
        "let r = unsafe { statx(fd.as_raw_fd(), c\"\".as_ptr(), AT_EMPTY_PATH, 0, &mut st) };",
        "statx on an opened place, to see whether it is the root of a mount; nothing is sent.",
    ),
    (
        "crates/sam-core/src/place_check.rs",
        "",
        "syscall(",
        "syscall for openat2, opening a place without following links; nothing is sent.",
    ),
    (
        "crates/sam-core/src/place_check.rs",
        "",
        "unsafe extern \"C\" {",
        "SAM's own declarations of syscall and statx of the C library, for the place check (also built into the room helper, which has no libc crate).",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail with progress, after the refusal\")]",
        "let r = self.call_progress_inner(args, input, on_progress).await;",
        "call_progress_inner: sam-jail --json <command> with progress lines; only call_with_progress runs it, after the refusal of the commands that go online.",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail, after the refusal\")]",
        "let r = self.counted(args, input).await;",
        "counted: sam-jail --json <command> for Backend::call, after the refusal of the commands that go online.",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail, counted\")]",
        "let r = self.call_inner(args, input).await;",
        "call_inner: starts sam-jail --json <command>; only counted runs it.",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: sam-jail, for the listed update actions\")]",
        "let r = self.counted(args, input).await;",
        "counted: sam-jail --json <command> for Backend::call_online, whose every caller is listed here.",
    ),
    (
        "crates/sam-gtk/src/backend.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: the terminal GIO picks\")]",
        "let launched = info.launch(&[], gio::AppLaunchContext::NONE);",
        "Starts the terminal emulator GIO picks, running sam-jail-run for a terminal app; when the person starts it; runs on this computer.",
    ),
    (
        "crates/sam-runner/src/contracts.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: curl in its sandbox, no network\")]",
        "let mut cmd = crate::updates::curl_command(false).ok()?;",
        "curl --version in its sandbox without network, for the contract check's list of versions (doctor --contracts and the bug report); runs on this computer.",
    ),
    (
        "crates/sam-runner/src/updates.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: curl in its sandbox\")]",
        "let mut cmd = Command::new(bwrap);",
        "bwrap around curl (curl_command): curl sees the computer read-only, an empty /tmp and its own host name localhost, so its libraries never send this computer's name to a DNS server; SAM's one way off this computer for update requests, which send the address, the server's name, SAM's user agent, Accept and, for part of a file, Range.",
    ),
    (
        "crates/sam-runner/src/updates.rs",
        "#[expect(clippy::disallowed_methods, reason = \"way out: curl in its sandbox, for an update request\")]",
        "let mut cmd = curl_command(true)?;",
        "curl in its sandbox with the shared network, for an update check or an update the person asked for (or the daily check, off by default); sends what curl_args builds.",
    ),
];

/// The roots of SAM's programs and libraries, as cargo builds them: every
/// target of every workspace package except its tests, benchmarks and
/// build scripts, by the path `cargo metadata` names (so a binary in
/// `src/bin/NAME/main.rs` or at a `path = …` counts too). The test guard is
/// a test-only crate, part of no program.
fn crate_roots() -> Vec<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--manifest-path",
        ])
        .arg(root().join("Cargo.toml"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let top = fs::canonicalize(root()).unwrap();
    let mut roots = Vec::new();
    for p in v["packages"].as_array().unwrap() {
        if p["name"] == "sam-test-guard" {
            continue;
        }
        for t in p["targets"].as_array().unwrap() {
            let kinds: Vec<&str> = t["kind"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|k| k.as_str())
                .collect();
            if kinds
                .iter()
                .all(|k| ["test", "bench", "custom-build"].contains(k))
            {
                continue;
            }
            let path = fs::canonicalize(t["src_path"].as_str().unwrap()).unwrap();
            let rel = path
                .strip_prefix(&top)
                .unwrap()
                .to_string_lossy()
                .to_string();
            roots.push(rel);
        }
    }
    roots.sort();
    roots
}

/// Every Rust file of SAM's programs and libraries: below each crate's
/// `src` and each crate root, with whether it is a root.
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
    let roots = crate_roots();
    let top = fs::canonicalize(root()).unwrap();
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
            let p = fs::canonicalize(p).unwrap();
            p.strip_prefix(&top).unwrap().to_string_lossy().to_string()
        })
        .chain(roots.iter().cloned())
        .map(|rel| {
            let is_root = roots.contains(&rel);
            (rel, is_root)
        })
        .collect();
    out.sort();
    out.dedup();
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

/// A safety net, not a proof: in the code CI's clippy compiles (the debug
/// build for x86_64 with default features), a new direct call of a
/// function listed in clippy.toml fails CI — clippy without an `#[expect]`,
/// the pin test without its exact line in the reviewed list (the privacy
/// report names what this does not cover). It catches
/// accidental new network or program calls in SAM's own code, not code
/// written to get around it; the traced run and the request tests are the
/// proof of what SAM does. This test holds the pin's parts: clippy.toml gates
/// exactly [`GATED`]; every crate root `cargo metadata` names denies the
/// gate's lints outside its tests, and nothing in the build settings
/// switches that off; in program code a gate lint is named only in an
/// outer `#[expect]` that starts its line and stands on one statement that
/// obeys the one-line rule; and each such pair, and each line the parser
/// refuses unless listed (`extern` blocks and their calls, `asm!`,
/// `naked_asm!`, `include!`, `#[path`, `#[rustfmt::skip]`), is in
/// [`WAYS_OUT`], with
/// multiplicity.
#[test]
fn each_listed_call_in_program_code_is_a_listed_place() {
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
        "          cargo clippy --workspace --all-targets --locked -- -D warnings 2>&1 | tee \"$RUNNER_TEMP/clippy.log\"",
        "          if grep -E -q \"does not refer to|expected a .*, found\" \"$RUNNER_TEMP/clippy.log\"; then",
    ] {
        if !ci.lines().any(|l| l == want) {
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
        if !(a.is_empty() || a.contains("reason = \"way out: ")) || what.len() < 20 {
            problems.push(format!("WAYS_OUT entry {a:?} says too little about itself"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// A safety net, not a proof: for the cases its self-test lists, the build
/// gate's shared parser reads code as the compiler does. A gate lint named in
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
    // Review round 1: `#[cfg(test)]` on a field hides nothing after it; a
    // lint named after another attribute on its line or inside a macro is
    // refused; what clippy cannot see through is a place to list.
    let hidden = r####"
struct S {
    #[cfg(test)]
    pub a: bool,
}
#[expect(clippy::disallowed_methods, reason = "way out: x")]
fn fetch() {
    let _ = Command::new("curl");
}
#[rustfmt::skip] fn f() { #[allow(clippy::disallowed_methods)] let _ = 1; }
macro_rules! m { () => { #[allow(clippy::disallowed_methods)] () }; }
include!("x.rs");
#[path = "y.rs"]
mod y;
unsafe extern "C" {
    fn syscall(n: i64, ...) -> i64;
}
fn g() { let _ = unsafe { syscall(1) }; }
fn h() { std::arch::asm!("nop"); let _ = libc::syscall(2); }
fn n() { core::arch::naked_asm!("ret"); }
"####;
    let (places, problems) = read_file("h.rs", hidden, false);
    let lines: Vec<&str> = problems
        .iter()
        .map(|p| p.split(':').nth(1).unwrap_or_default())
        .collect();
    // The expect on a whole function (7), the allow after rustfmt::skip
    // (10: code follows the joined attribute, and it is no expect), the
    // allow in a macro (11).
    assert_eq!(lines, ["7", "10", "10", "11"], "{problems:#?}");
    let listed: Vec<&str> = places.iter().map(|(_, l)| l.as_str()).collect();
    assert_eq!(
        listed,
        [
            "unsafe extern \"C\" {",
            "#[rustfmt::skip] fn f() { #[allow(clippy::disallowed_methods)] let _ = 1; }",
            "include!(\"x.rs\");",
            "#[path = \"y.rs\"]",
            "fn g() { let _ = unsafe { syscall(1) }; }",
            "fn h() { std::arch::asm!(\"nop\"); let _ = libc::syscall(2); }",
            "fn n() { core::arch::naked_asm!(\"ret\"); }",
        ]
    );
    assert!(places.iter().all(|(a, _)| a.is_empty()));
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

/// The reviewed hashes of the update module's program part (which builds
/// every request SAM sends; its curl arguments are fixed word for word by
/// `every_update_request_has_exactly_these_curl_arguments` in
/// crates/sam-runner/src/updates.rs), of the functions below and of
/// `AppRun`. They are in a file that is not protected, network_use_pins.toml
/// next to this one: renewing a hash is routine review.
const PINS: &str = include_str!("network_use_pins.toml");

/// The functions the window runs at its start; they run these commands
/// (each traced by `everyday_commands_make_no_internet_connection` as W1-W11):
/// `config get general.language`, `version`, `permissions`,
/// `desktop all refresh`, `config show` (and the two `config set` of an
/// old settings file), `list`, `discover`, `scan <Downloads>`,
/// `updates --if-due`, `list`.
const WINDOW_START: &[(&str, &str)] = &[
    ("crates/sam-gtk/src/window.rs", "start"),
    ("crates/sam-gtk/src/window.rs", "check_cli_version"),
    ("crates/sam-gtk/src/window.rs", "load_catalog"),
    ("crates/sam-gtk/src/window.rs", "load_config"),
    ("crates/sam-gtk/src/window.rs", "refresh_apps"),
    ("crates/sam-gtk/src/window.rs", "count_downloads"),
    ("crates/sam-gtk/src/window.rs", "refresh_registered"),
    ("crates/sam-gtk/src/i18n.rs", "apply_language_setting"),
    ("crates/sam-gtk/src/i18n.rs", "configured_language"),
    ("crates/sam-gtk/src/main.rs", "main"),
];

/// The texts that decide when SAM goes online and what it sends are the
/// reviewed ones: the update module's program part, the functions the
/// window runs at its start, and `AppRun`. Any change to them, other than
/// in comments, fails here until the hash is renewed in the same review
/// that checks the change against docs/security.md ("Network use by SAM
/// itself").
#[test]
fn the_update_module_the_window_start_and_apprun_are_as_reviewed() {
    let pins: toml::Value = toml::from_str(PINS).unwrap();
    let want = |k: &str| {
        pins.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let mut problems = Vec::new();
    let got = pin(&update_module_program());
    if got != want("update_module") {
        problems.push(format!(
            "crates/sam-runner/src/updates.rs (before its tests) changed: review whether SAM now sends another request, to another address or with another argument, then set update_module in crates/sam-jail-cli/tests/network_use_pins.toml to \"{got}\""
        ));
    }
    for (file, name) in WINDOW_START {
        let key = format!("{file} {name}");
        let had = pins["window_start"]
            .get(&key)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let got = pin(function(&read(file), name));
        if got != had {
            problems.push(format!(
                "{file}: fn {name} changed: review whether the window's start now runs another command, then set \"{key}\" in crates/sam-jail-cli/tests/network_use_pins.toml to \"{got}\""
            ));
        }
    }
    // `AppRun` runs getconf, `sam-jail-gui --version`, kdialog, zenity and
    // notify-send, all on this computer.
    let got = pin(&apprun());
    if got != want("apprun") {
        problems.push(format!(
            "scripts/make-appimage.sh: the AppRun text changed: review which programs it runs, then set apprun in crates/sam-jail-cli/tests/network_use_pins.toml to \"{got}\""
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

/// The libraries in Cargo.lock, by name and source (SAM's own crates have
/// none), sorted. Versions are left out: a version bump of a listed
/// library is the lock file's own business.
const LIBRARIES: &[(&str, &str)] = &[
    (
        "anstream",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anstyle",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anstyle-parse",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anstyle-query",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anstyle-wincon",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "anyhow",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "autocfg",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "backhand",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "bitflags",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "bitvec",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "block-buffer",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cairo-rs",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cairo-sys-rs",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cc",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cfg-expr",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cfg-if",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap_builder",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap_derive",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap_lex",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "clap_mangen",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "colorchoice",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "const-oid",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "cpufeatures",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "crypto-common",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "darling",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "darling_core",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "darling_macro",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "deku",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "deku_derive",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "digest",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "downcast-rs",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "enumflags2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "enumflags2_derive",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "equivalent",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "errno",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "fastrand",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "field-offset",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "find-msvc-tools",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "flate2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "fnv",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "funty",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-channel",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-core",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-executor",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-io",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-macro",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-task",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "futures-util",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gdk-pixbuf",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gdk-pixbuf-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gdk4",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gdk4-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "getrandom",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gio",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gio-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "glib",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "glib-macros",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "glib-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gobject-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "goblin",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "graphene-rs",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "graphene-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gsk4",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gsk4-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gtk4",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gtk4-macros",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "gtk4-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "hashbrown",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "heck",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "hybrid-array",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "ident_case",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "indexmap",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "is_terminal_polyfill",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "itoa",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "jobserver",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "landlock",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "libadwaita",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "libadwaita-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "libc",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "liblzma",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "liblzma-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "linux-raw-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "log",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "lz4_flex",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "md4",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "memchr",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "memoffset",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "no_std_io2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "once_cell",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "once_cell_polyfill",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pango",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pango-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pin-project-lite",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pkg-config",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "plain",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "proc-macro-crate",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "proc-macro2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "pulldown-cmark",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "quick-xml",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "quote",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "r-efi",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "radium",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "roff",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "rustc_version",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "rustix",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "rustversion",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    ("sam-core", ""),
    ("sam-detect", ""),
    ("sam-gtk", ""),
    ("sam-intake", ""),
    ("sam-jail-cli", ""),
    ("sam-profile", ""),
    ("sam-runner", ""),
    ("sam-sandbox", ""),
    ("sam-storage", ""),
    ("sam-test-guard", ""),
    (
        "scroll",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "scroll_derive",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "seccompiler",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "semver",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde_core",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde_derive",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde_json",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "serde_spanned",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "sha1",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "sha2",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "shlex",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "slab",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "smallvec",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "solana-nohash-hasher",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "strsim",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "syn",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "system-deps",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "tap",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "target-lexicon",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "tempfile",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "thiserror",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "thiserror-impl",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml_datetime",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml_edit",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml_parser",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "toml_writer",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "typenum",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "unicase",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "unicode-ident",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "utf8parse",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "version-compare",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-backend",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-client",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-protocols",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-scanner",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wayland-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "windows-link",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "windows-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "winnow",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "wyz",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "xxhash-rust",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zlib-rs",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zmij",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zstd",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zstd-safe",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
    (
        "zstd-sys",
        "registry+https://github.com/rust-lang/crates.io-index",
    ),
];

/// The (name, source) pairs of a Cargo.lock's packages.
fn lock_libraries(lock: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = lock_packages(lock)
        .into_iter()
        .map(|(n, _, s)| (n, s))
        .collect();
    v.dedup();
    v
}

/// Only listed libraries are part of SAM: the name and source of every
/// package in Cargo.lock equal [`LIBRARIES`]. A new library or another
/// source (a git fork, a `[patch]`) fails until the list is changed with
/// it, which a review then judges; a new version of a listed library does
/// not. A listed library is trusted, not proven offline, and a new direct
/// use of a library already in Cargo.lock is not seen here.
#[test]
fn only_listed_libraries_are_part_of_sam() {
    let got = lock_libraries(&read("Cargo.lock"));
    let want: Vec<(String, String)> = LIBRARIES
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    if got != want {
        let list: Vec<String> = got
            .iter()
            .map(|(n, s)| format!("    ({n:?}, {s:?}),"))
            .collect();
        panic!(
            "Cargo.lock names another library or source: review each new name and source, then set LIBRARIES in crates/sam-jail-cli/tests/network_use.rs to:\n{}",
            list.join("\n")
        );
    }
}

/// The library check reads a Cargo.lock's names and sources: another
/// source or a new name is a change, another version is not.
#[test]
fn the_library_check_sees_a_new_name_or_source() {
    let lock = "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"sam-core\"\nversion = \"0.1.0\"\n";
    let a = lock_libraries(lock);
    assert_eq!(
        a,
        [
            ("sam-core".into(), String::new()),
            (
                "serde".into(),
                "registry+https://github.com/rust-lang/crates.io-index".into()
            ),
        ]
    );
    assert_eq!(a, lock_libraries(&lock.replace("1.0.0", "1.0.1")));
    assert_ne!(
        a,
        lock_libraries(&lock.replace("registry+https", "git+https"))
    );
    assert_ne!(a, lock_libraries(&lock.replace("\"serde\"", "\"serde2\"")));
}

// ----------------------------------------------------------- traced run

/// What strace records: every process SAM starts (`-f`), the programs they
/// run and every socket they open or connect. Without `--seccomp-bpf`, so a
/// call SAM's own filter refuses is still seen.
const TRACED_CALLS: &str =
    "trace=socket,connect,sendto,sendmsg,sendmmsg,io_uring_setup,execve,execveat,clone,clone3,fork,vfork";

/// Name-service sockets: a connect to one is a name or account lookup that
/// can leave this computer (resolved, nscd, SSSD, Avahi, nslcd, winbind,
/// systemd's user database).
const NAME_SERVICE_SOCKETS: &[&str] = &[
    "/run/systemd/resolve/",
    "/run/systemd/userdb/",
    "/run/nslcd/socket",
    "/var/run/nslcd/socket",
    "/run/samba/winbindd/",
    "/var/run/samba/winbindd/",
    "/run/winbindd/",
    "/run/nscd/socket",
    "/var/run/nscd/socket",
    "/var/lib/sss/pipes/nss",
    "/run/avahi-daemon/socket",
];

/// The two things a traced command may do that look like a way out but
/// are not, each seen in the first traced run and named in the privacy
/// report's limits. Each holds only for a process whose last successful
/// `execve` ran a program with this file name (the last part of the path
/// it ran; for pasta also `pasta.*`, its builds for one processor) and
/// exactly these arguments:
/// - pasta's `--help` and `--version` open one TCP socket to read the
///   kernel's buffer sizes; that process may connect nowhere and send
///   nothing (checked);
/// - `curl --version`, which doctor's contracts and the bug report run,
///   loads libraries that look up the user's account and this computer's
///   name through the name service; its connects to nscd's socket are
///   allowed, nothing else.
fn allowed(ran: &(String, Vec<String>), line: &str) -> bool {
    let (path, argv) = ran;
    let name = path.rsplit('/').next().unwrap_or(path);
    // pasta starts itself again as pasta.avx2 (or another build for this
    // processor) with the same arguments.
    let prog = if name == "pasta" || name.starts_with("pasta.") {
        Some("pasta")
    } else {
        Some(name)
    };
    let rest: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    let probe = rest == ["--help"] || rest == ["--version"];
    match prog {
        Some("pasta") if probe => line.contains("socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)"),
        Some("curl") if rest == ["--version"] => {
            line.contains("connect(")
                && (line.contains("sun_path=\"/run/nscd/socket\"")
                    || line.contains("sun_path=\"/var/run/nscd/socket\""))
        }
        _ => false,
    }
}

/// Whether a process runs curl in the sandbox SAM starts it in
/// (`updates::curl_command`): its program's file name is `curl`, and its
/// parent ran Bubblewrap with that sandbox's own host name. There glibc
/// checks the order of `localhost`'s two addresses: a UDP socket connected
/// to `127.0.0.1` or `::1` with port 0, which sends nothing (the one more
/// exception [`read_trace`] makes, and it requires that nothing is sent).
fn in_curls_sandbox(ran: &(String, Vec<String>), parent: Option<&(String, Vec<String>)>) -> bool {
    let name = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    let Some((ppath, pargs)) = parent else {
        return false;
    };
    name(&ran.0) == "curl"
        && name(ppath) == "bwrap"
        && pargs
            .windows(2)
            .any(|w| w[0] == "--hostname" && w[1] == "localhost")
        && pargs.iter().any(|a| a == "--unshare-uts")
}

/// The argument list of an `execve(...)` line as strace writes it.
fn exec_argv(line: &str) -> Vec<String> {
    let Some(start) = line.find(", [") else {
        return Vec::new();
    };
    let c: Vec<char> = line[start + 3..].chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() && c[i] == '"' {
        let mut s = String::new();
        i += 1;
        while i < c.len() && c[i] != '"' {
            if c[i] == '\\' && i + 1 < c.len() {
                i += 1;
            }
            s.push(c[i]);
            i += 1;
        }
        out.push(s);
        i += 1;
        if c.get(i) == Some(&',') {
            i += 2;
        } else {
            break;
        }
    }
    out
}

/// What one traced command did, from its strace log.
#[derive(Default, Debug)]
struct Seen {
    /// Every successful `execve`: (pid, its line).
    execs: Vec<(String, String)>,
    /// The Unix sockets it connected to.
    unix: std::collections::BTreeSet<String>,
    /// Internet connects: (address, port).
    inet: Vec<(String, u16)>,
    /// Whether any process opened an internet socket.
    inet_socket: bool,
    /// The processes that opened one.
    inet_socket_pids: Vec<String>,
    problems: Vec<String>,
}

/// Reads an strace log of `-f` (each line starts with its process id):
/// no process may open a socket other than a Unix or netlink one, set up
/// io_uring (through which a socket could open unseen) or connect to a
/// name-service socket, other than what [`allowed`] names.
fn read_trace(cmd: &str, log: &str) -> Seen {
    let mut seen = Seen::default();
    // Each process's program: (the path its last successful execve ran,
    // its arguments). An execve strace shows unfinished counts only once
    // its resumed line says it succeeded.
    let mut argv: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    let mut pending: BTreeMap<String, (String, Vec<String>, String)> = BTreeMap::new();
    // The probe sockets: (process, descriptor).
    let mut probes: Vec<(String, String)> = Vec::new();
    // Each process's parent, from the clone, fork and vfork results.
    let mut parent: BTreeMap<String, String> = BTreeMap::new();
    let mut cloning: Vec<String> = Vec::new();
    // glibc's address-order check in curl's sandbox: (process, descriptor)
    // of each UDP socket it opens, until the descriptor is used again.
    let mut order_checks: Vec<(String, String)> = Vec::new();
    for line in log.lines() {
        let (pid, call) = line.trim_start().split_once(' ').unwrap_or(("?", line));
        let call = call.trim_start();
        let who = argv.get(pid).cloned().unwrap_or_default();
        let named = || {
            if who.1.is_empty() {
                format!("process {pid} (SAM's own)")
            } else {
                format!("process {pid} ({})", who.1.join(" "))
            }
        };
        if call.starts_with("execve(") || call.starts_with("execveat(") {
            let path = call.split('"').nth(1).unwrap_or("").to_string();
            if call.ends_with("<unfinished ...>") {
                pending.insert(pid.to_string(), (path, exec_argv(call), call.to_string()));
            } else if call.trim_end().ends_with(") = 0") {
                argv.insert(pid.to_string(), (path, exec_argv(call)));
                seen.execs.push((pid.to_string(), call.to_string()));
            }
            continue;
        }
        if call.starts_with("<... execve resumed>") || call.starts_with("<... execveat resumed>") {
            if let Some((path, a, first)) = pending.remove(pid) {
                if call.trim_end().ends_with("= 0") {
                    argv.insert(pid.to_string(), (path, a));
                    seen.execs.push((pid.to_string(), first));
                }
            }
            continue;
        }
        let forks = ["clone(", "clone3(", "fork(", "vfork("];
        let resumed = [
            "<... clone resumed>",
            "<... clone3 resumed>",
            "<... fork resumed>",
            "<... vfork resumed>",
        ];
        if forks.iter().any(|f| call.starts_with(f)) || resumed.iter().any(|r| call.starts_with(r))
        {
            if call.ends_with("<unfinished ...>") {
                cloning.push(pid.to_string());
            } else if let Some(child) = call
                .rsplit("= ")
                .next()
                .and_then(|c| c.trim().parse::<u32>().ok())
            {
                cloning.retain(|c| c != pid);
                parent.insert(child.to_string(), pid.to_string());
            }
            continue;
        }
        if call.starts_with("io_uring_setup(") {
            seen.problems
                .push(format!("{cmd}: {} set up io_uring: {line}", named()));
        }
        let fd_of = |c: &str| c.split(['(', ',']).nth(1).unwrap_or("").trim().to_string();
        if let Some(rest) = call.strip_prefix("socket(") {
            let fd = call.rsplit("= ").next().unwrap_or("").trim().to_string();
            order_checks.retain(|(p, f)| !(p == pid && *f == fd));
            if in_curls_sandbox(&who, parent.get(pid).and_then(|p| argv.get(p)))
                && (rest.starts_with("AF_INET, SOCK_DGRAM")
                    || rest.starts_with("AF_INET6, SOCK_DGRAM"))
            {
                seen.inet_socket = true;
                order_checks.push((pid.to_string(), fd));
                continue;
            }
            let family = rest.split([',', ' ']).next().unwrap_or("");
            if !matches!(family, "AF_UNIX" | "AF_LOCAL" | "AF_NETLINK") {
                if family.starts_with("AF_INET") {
                    seen.inet_socket = true;
                    seen.inet_socket_pids.push(pid.to_string());
                }
                if allowed(&who, call) {
                    let fd = call.rsplit("= ").next().unwrap_or("").trim().to_string();
                    probes.push((pid.to_string(), fd));
                } else {
                    seen.problems.push(format!(
                        "{cmd}: {} opened a {family} socket: {line}",
                        named()
                    ));
                }
            }
        }
        let checked = order_checks
            .iter()
            .any(|(p, f)| p == pid && *f == fd_of(call));
        let sends = ["sendto(", "sendmsg(", "sendmmsg("]
            .iter()
            .any(|c| call.starts_with(c));
        if checked && sends {
            seen.problems.push(format!(
                "{cmd}: {}, which may only check the order of addresses, sent on it: {line}",
                named()
            ));
        }
        if checked && call.starts_with("connect(") {
            let loopback_port_0 = call
                .contains("sin_port=htons(0), sin_addr=inet_addr(\"127.0.0.1\")")
                || (call.contains("sin6_port=htons(0)")
                    && call.contains("inet_pton(AF_INET6, \"::1\""));
            if !loopback_port_0 {
                seen.problems.push(format!(
                    "{cmd}: {}, which may only check the order of addresses, connected elsewhere: {line}",
                    named()
                ));
            }
            continue;
        }
        if call.starts_with("connect(") {
            if let Some(p) = call.split("sun_path=\"").nth(1) {
                let path = p.split('"').next().unwrap_or("").to_string();
                if NAME_SERVICE_SOCKETS.iter().any(|n| path.starts_with(n)) && !allowed(&who, call)
                {
                    seen.problems.push(format!(
                        "{cmd}: {} connected to the name service: {line}",
                        named()
                    ));
                }
                seen.unix.insert(path);
            }
            if call.contains("sa_family=AF_INET") {
                let port = call
                    .split("port=htons(")
                    .nth(1)
                    .and_then(|p| p.split(')').next())
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0);
                let addr = call
                    .split("inet_addr(\"")
                    .nth(1)
                    .or_else(|| call.split("inet_pton(AF_INET6, \"").nth(1))
                    .and_then(|a| a.split('"').next())
                    .unwrap_or("?")
                    .to_string();
                seen.inet.push((addr, port));
            }
        }
    }
    // A probe's process may open its socket, but never use it, and
    // connect nowhere on the internet.
    for line in log.lines() {
        let (pid, call) = line.trim_start().split_once(' ').unwrap_or(("?", line));
        let call = call.trim_start();
        let on = |fd: &str| {
            ["connect(", "sendto(", "sendmsg(", "sendmmsg("]
                .iter()
                .any(|c| call.starts_with(&format!("{c}{fd},")))
        };
        let uses = probes.iter().any(|(p, fd)| p == pid && on(fd))
            || (probes.iter().any(|(p, _)| p == pid)
                && call.starts_with("connect(")
                && call.contains("sa_family=AF_INET"));
        if uses {
            seen.problems.push(format!(
                "{cmd}: process {pid}, which may only open its probe socket, used it: {line}"
            ));
        }
    }
    seen
}

/// The trace check reads strace's lines as strace writes them: an internet
/// socket, io_uring and a name-service connect are found in any process;
/// pasta's probe socket and `curl --version`'s nscd connect pass only for
/// a program of that file name after a successful execve, with those
/// arguments, and the probe's process may not use its socket (its log
/// lines to a closed descriptor are no use).
#[test]
fn the_trace_check_reads_strace_lines() {
    let log = r#"10 execve("/usr/bin/pasta.avx2", ["/usr/bin/pasta", "--help"], 0x1 /* 3 vars */) = 0
10 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
10 sendto(-1, "<6> : Usage", 15, 0, NULL, 0) = -1 EBADF (Bad file descriptor)
11 execve("/usr/bin/curl", ["/usr/bin/curl", "--version"], 0x1 /* 3 vars */) = 0
11 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
12 connect(3, {sa_family=AF_UNIX, sun_path="/run/user/1000/bus"}, 110) = 0
"#;
    let seen = read_trace("x", log);
    assert!(seen.problems.is_empty(), "{:?}", seen.problems);
    assert_eq!(seen.execs.len(), 2);
    assert!(seen.unix.contains("/run/user/1000/bus"));
    for bad in [
        "13 socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 5",
        "14 io_uring_setup(8, 0x7ffd) = 3",
        "15 connect(3, {sa_family=AF_UNIX, sun_path=\"/run/systemd/resolve/io.systemd.Resolve\"}, 110) = 0",
        "11 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4",
        "10 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"192.0.2.1\")}, 16) = 0",
        "10 sendto(4, \"x\", 1, 0, NULL, 0) = 1",
        "10 sendmsg(4, {msg_name=NULL}, 0) = 1",
    ] {
        let seen = read_trace("x", &format!("{log}{bad}\n"));
        assert_eq!(seen.problems.len(), 1, "{bad}: {:?}", seen.problems);
    }
    let other = log.replace("\"--help\"", "\"--splice-only\"");
    assert_eq!(read_trace("x", &other).problems.len(), 1);
    // The exception goes by the program that ran, not by what it calls
    // itself, and only after an execve that succeeded.
    let renamed = log.replace("execve(\"/usr/bin/curl\"", "execve(\"/tmp/x\"");
    assert_eq!(read_trace("x", &renamed).problems.len(), 1);
    let failed = "20 execve(\"/usr/bin/curl\", [\"/usr/bin/curl\", \"--version\"], 0x1 /* 3 vars */ <unfinished ...>\n20 <... execve resumed>) = -1 ENOENT (No such file or directory)\n20 connect(3, {sa_family=AF_UNIX, sun_path=\"/var/run/nscd/socket\"}, 110) = -1 ENOENT\n";
    assert_eq!(read_trace("x", failed).problems.len(), 1);
    let resumed = failed.replace(") = -1 ENOENT (No such file or directory)", ") = 0");
    assert!(read_trace("x", &resumed).problems.is_empty());
    // curl in its sandbox may check the order of localhost's addresses
    // (UDP, port 0, nothing sent); nothing else, and nowhere else.
    let sandboxed = r#"30 execve("/usr/bin/bwrap", ["/usr/bin/bwrap", "--ro-bind", "/", "/", "--unshare-uts", "--hostname", "localhost", "--", "/usr/bin/curl", "--version"], 0x1 /* 3 vars */) = 0
30 clone3({flags=CLONE_NEWUSER|CLONE_NEWUTS, exit_signal=SIGCHLD}, 88) = 31
31 execve("/usr/bin/curl", ["/usr/bin/curl", "--version"], 0x1 /* 3 vars */) = 0
31 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
31 connect(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
31 socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
31 connect(3, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0
"#;
    let seen = read_trace("x", sandboxed);
    assert!(seen.problems.is_empty(), "{:?}", seen.problems);
    assert!(seen.inet.is_empty());
    for bad in [
        "31 sendmmsg(3, [{msg_hdr={}}], 2, MSG_NOSIGNAL) = 2",
        "31 connect(3, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, \"::1\", &sin6_addr), sin6_scope_id=0}, 28) = 0",
    ] {
        let seen = read_trace("x", &format!("{sandboxed}{bad}\n"));
        assert_eq!(seen.problems.len(), 1, "{bad}: {:?}", seen.problems);
    }
    // The same without the sandbox's host name is an internet socket.
    let outside = sandboxed.replace("\"--hostname\", \"localhost\", ", "");
    assert_eq!(read_trace("x", &outside).problems.len(), 2);
    let seen = read_trace(
        "x",
        "16 connect(3, {sa_family=AF_INET, sin_port=htons(8443), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = 0\n",
    );
    assert_eq!(seen.inet, [("127.0.0.1".to_string(), 8443)]);
}

/// Whether Bubblewrap can build a sandbox here.
fn bwrap_works() -> bool {
    std::process::Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-user",
            "--unshare-pid",
            "true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A host name no name service answers: `sam-unknown-` and digits that
/// differ for each run.
fn unknown_host_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("sam-unknown-{}-{nanos}", std::process::id())
}

/// What a traced command left: its exit status, output and trace.
struct Ran {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    seen: Seen,
}

/// Runs `sam-jail ARGS` under strace with its own folders and home, no
/// desktop session and no proxy variables, `input` on stdin. A command
/// still running after two minutes fails the test. It runs inside an outer
/// Bubblewrap whose host name no name service knows, so a lookup of this
/// computer's name goes to the DNS server wherever the test runs (in the
/// test container `/etc/hosts` names the container, and on some CI runners
/// it names the runner), and the trace sees it.
fn traced(root: &Path, args: &[&str], input: Option<&str>) -> Ran {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let log = root.join("trace.log");
    let _ = fs::remove_file(&log);
    let strace = sam_core::util::which("strace").unwrap();
    let mut cmd = Command::new(strace);
    cmd.args([
        "-f",
        "-qq",
        "-e",
        TRACED_CALLS,
        "-e",
        "signal=none",
        "-s",
        "256",
        "-o",
    ])
    .arg(&log)
    .arg("--")
    .arg(sam_core::util::which("bwrap").unwrap())
    .args(["--dev-bind", "/", "/", "--unshare-uts", "--hostname"])
    .arg(unknown_host_name())
    .arg("--")
    .arg(env!("CARGO_BIN_EXE_sam-jail"))
    .args(args)
    .env("SAM_CONFIG_DIR", root.join("config"))
    .env("SAM_DATA_DIR", root.join("data"))
    .env("SAM_APPLICATIONS_DIR", root.join("applications"))
    .env("HOME", root.join("home"))
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    for v in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ] {
        cmd.env_remove(v);
    }
    sam_runner::testenv::isolate_command(&mut cmd, &root.join("sam"));
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    if let Some(i) = input {
        stdin.write_all(i.as_bytes()).unwrap();
    }
    drop(stdin);
    let reader = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            r.read_to_end(&mut v).ok();
            String::from_utf8_lossy(&v).into_owned()
        })
    };
    let o = reader(Box::new(child.stdout.take().unwrap()));
    let e = reader(Box::new(child.stderr.take().unwrap()));
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(120) {
            child.kill().ok();
            child.wait().ok();
            panic!("sam-jail {args:?} still ran after two minutes");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let name = args
        .iter()
        .filter(|a| **a != "--json")
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    Ran {
        status: status.code(),
        stdout: o.join().unwrap(),
        stderr: e.join().unwrap(),
        seen: read_trace(&name, &fs::read_to_string(&log).unwrap_or_default()),
    }
}

/// A test home with SAM's folders, a test AppImage (network "none", its
/// update source a recorder on this computer, so no name lookup is
/// needed) and a copy of it in Downloads.
fn traced_home(apprun: &str, update_port: u16) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    for d in ["config", "home/Downloads"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let img = root.join("Everyday-1.0-x86_64.AppImage");
    let mut spec = sam_intake::testkit::FixtureSpec::hello("Everyday");
    spec.apprun = apprun.into();
    spec.update_info = Some(format!(
        "zsync|https://127.0.0.1:{update_port}/Everyday-x86_64.AppImage.zsync"
    ));
    sam_intake::testkit::build(&img, &spec).unwrap();
    fs::copy(
        &img,
        root.join("home/Downloads/Everyday-1.0-x86_64.AppImage"),
    )
    .unwrap();
    (tmp, root, img)
}

/// The traced run needs strace, Bubblewrap and objcopy (for the test
/// AppImage's update source); without them it fails under
/// SAM_REQUIRE_SANDBOX=1, as in CI and the test container.
fn traced_run_possible() -> bool {
    for (tool, why) in [
        ("strace", "strace traces SAM's commands"),
        (
            "objcopy",
            "objcopy writes the test AppImage's update source",
        ),
    ] {
        if sam_core::util::which(tool).is_none() {
            sam_runner::contracts::skip(&format!("{why}, and {tool} is not installed"))
                .unwrap_or_else(|e| panic!("{e}"));
            return false;
        }
    }
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return false;
    }
    true
}

/// A listener on this computer that takes every connection and closes it
/// at once: the update source of the test AppImage.
struct Recorder {
    port: u16,
}

impl Recorder {
    fn start() -> Recorder {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in listener.incoming() {
                drop(c);
            }
        });
        Recorder { port }
    }
}

/// One traced command: (label, arguments, the exit statuses it may end
/// with, the programs one of which must appear in its trace).
type Step = (
    &'static str,
    Vec<String>,
    &'static [i32],
    &'static [&'static str],
);

/// The commands traced: the window's start (W1-W11, from
/// `crates/sam-gtk/src/main.rs`, `i18n.rs` and `window.rs`, pinned by
/// [`WINDOW_START`]) and the everyday commands of its pages (E1-E22).
/// Each: (label, arguments, the exit statuses it may end with, a program
/// that must appear in its trace). Exit status 3 is "not passed": the
/// sandbox check, doctor and its contracts report this computer's state
/// with it; the marker shows they ran.
fn steps(img: &str, downloads: &str, id: &str) -> Vec<Step> {
    let s = |v: &[&str]| v.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    const OK: &[i32] = &[0];
    const STATE: &[i32] = &[0, 3];
    const NONE: &[&str] = &[];
    const BWRAP: &[&str] = &["/bwrap\""];
    let unpack: &'static [&'static str] = &[
        "/unsquashfs\"",
        "/bsdtar\"",
        "/dwarfsextract\"",
        "\"extract-squashfs\"",
    ];
    let mut v = vec![
        (
            "W1",
            s(&["--json", "config", "get", "general.language"]),
            OK,
            NONE,
        ),
        ("W2", s(&["--json", "version"]), OK, NONE),
        ("W3", s(&["--json", "permissions"]), OK, NONE),
        ("W4", s(&["--json", "desktop", "all", "refresh"]), OK, NONE),
        ("W5", s(&["--json", "config", "show"]), OK, NONE),
        (
            "W6",
            s(&[
                "--json",
                "config",
                "set",
                "general.scan_directories",
                "[\"~/Downloads\"]",
            ]),
            OK,
            NONE,
        ),
        (
            "W6",
            s(&["--json", "config", "set", "general.scan_downloads", "false"]),
            OK,
            NONE,
        ),
        ("W6", s(&["--json", "config", "show"]), OK, NONE),
        ("W7", s(&["--json", "list"]), OK, NONE),
        ("W8", s(&["--json", "discover"]), OK, NONE),
        ("W9", s(&["--json", "scan", downloads]), OK, NONE),
        ("W10", s(&["--json", "updates", "--if-due"]), OK, NONE),
        ("W11", s(&["--json", "list"]), OK, NONE),
    ];
    if id.is_empty() {
        v.push((
            "E1",
            s(&["--json", "add", img, "--no-launcher", "--accept"]),
            OK,
            unpack,
        ));
        return v;
    }
    v.extend([
        ("E2", s(&["--json", "preview", img]), OK, NONE),
        ("E3", s(&["--json", "info", id]), OK, NONE),
        ("E4", s(&["--json", "get", id]), OK, NONE),
        ("E5", s(&["--json", "command", id]), OK, NONE),
        ("E6", s(&["--json", "menu", "list", id]), OK, NONE),
        ("E7", s(&["--json", "evaluate", id]), OK, NONE),
        ("E8", s(&["--json", "logs", id, "--list"]), OK, NONE),
        ("E9", s(&["--json", "space"]), OK, NONE),
        ("E10", s(&["--json", "run", id]), OK, BWRAP),
        ("E11", s(&["--json", "logs", id]), OK, NONE),
        ("E12", s(&["--json", "verify", id]), STATE, BWRAP),
        ("E13", s(&["--json", "doctor"]), STATE, BWRAP),
        ("E14", s(&["--json", "doctor", id]), STATE, NONE),
        (
            "E15",
            s(&["--json", "doctor", "--contracts"]),
            STATE,
            &["/gpg\"", "/gpgv\""],
        ),
        ("E16", s(&["--json", "report"]), OK, NONE),
        ("E17", s(&["--json", "report", id]), OK, NONE),
        ("E18", s(&["--json", "preset", "list"]), OK, NONE),
        ("E19", s(&["--json", "group", "list"]), OK, NONE),
        (
            "E20",
            s(&["--json", "cleanup", "--data", "--list"]),
            OK,
            NONE,
        ),
        ("E21", s(&["--json", "refresh", "--deep"]), OK, NONE),
        ("E22", s(&["--json", "stop", id]), OK, NONE),
    ]);
    v
}

/// The command a traced argument list runs, as its man page is named
/// (`config-get`, `doctor`).
fn page_of(args: &[String]) -> String {
    let words: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--json")
        .collect();
    match words.as_slice() {
        [g @ ("config" | "group" | "preset" | "profile"), sub, ..] => format!("{g}-{sub}"),
        [c, ..] => c.to_string(),
        [] => String::new(),
    }
}

/// The commands the traced run covers, by their man page names: kept equal
/// to [`steps`] and P1 by [`everyday_commands_make_no_internet_connection`].
const TRACED: &[&str] = &[
    "add",
    "cleanup",
    "command",
    "config-get",
    "config-set",
    "config-show",
    "desktop",
    "discover",
    "doctor",
    "evaluate",
    "get",
    "group-list",
    "info",
    "list",
    "logs",
    "menu",
    "permissions",
    "preset-list",
    "preview",
    "refresh",
    "report",
    "run",
    "scan",
    "space",
    "stop",
    "updates",
    "verify",
    "version",
];

/// Commands the traced run does not cover. Their direct calls of gated
/// methods are still listed (WAYS_OUT); calls through SAM's generic helpers
/// are not traced. `man` and `dev` are hidden commands; the groups have
/// their commands classified one by one.
const UNTRACED: &[&str] = &[
    "args",
    "compat",
    "config",
    "config-path",
    "config-put",
    "dev",
    "diagnose",
    "free-space",
    "group",
    "group-restore",
    "group-set",
    "hints",
    "man",
    "onboarding",
    "preset",
    "preset-apply",
    "preset-delete",
    "preset-duplicate",
    "preset-export",
    "preset-import",
    "preset-put",
    "preset-save",
    "preset-show",
    "preset-template",
    "profile",
    "profile-change",
    "profile-get",
    "profile-reset",
    "profile-set",
    "redetect",
    "reextract",
    "relocate",
    "remove",
    "repair",
    "review",
    "selftest",
    "self-update",
    "set",
    "uninstall",
    "update",
];

/// Forms of traced commands that differ by an option and are not traced
/// themselves: (command, option).
const UNTRACED_FORMS: &[(&str, &str)] = &[
    ("update", "--undo"),
    ("update", "--decline-key-change"),
    ("update", "--accept-key-change"),
    ("self-update", "--check"),
    ("cleanup", "--data"),
    ("verify", "--permissions-stdin"),
    // `desktop <id> <action>` for one app (only `desktop all refresh` is
    // traced): its page names the ACTION argument.
    ("desktop", "ACTION"),
];

/// Every command and subcommand of sam-jail, at any depth, is either in
/// the traced run or named as untraced: the list comes from `sam-jail man`,
/// which writes a page for each visible one, so a new command fails here
/// until it is classified, and each named one must still exist. The
/// untraced forms' options must still exist too.
#[test]
fn every_command_is_traced_or_named_untraced() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("man");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sam-jail"))
        .arg("man")
        .arg(&dir)
        .env("SAM_CONFIG_DIR", tmp.path().join("config"))
        .env("SAM_DATA_DIR", tmp.path().join("data"))
        .env("HOME", tmp.path().join("home"))
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut pages = BTreeMap::new();
    for e in fs::read_dir(&dir).unwrap().flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if let Some(c) = n
            .strip_prefix("sam-jail-")
            .and_then(|n| n.strip_suffix(".1"))
        {
            pages.insert(c.to_string(), fs::read_to_string(e.path()).unwrap());
        }
    }
    assert!(pages.len() > 40, "only {} pages", pages.len());
    let mut problems = Vec::new();
    for c in pages.keys() {
        if !TRACED.contains(&c.as_str()) && !UNTRACED.contains(&c.as_str()) {
            problems.push(format!(
                "sam-jail {} is neither traced nor named untraced in crates/sam-jail-cli/tests/network_use.rs: trace it (steps) or name it in UNTRACED",
                c.replace('-', " ")
            ));
        }
    }
    for c in TRACED.iter().chain(UNTRACED) {
        if !pages.contains_key(*c) && !["man", "dev"].contains(c) {
            problems.push(format!("`{c}` is listed but sam-jail has no such command"));
        }
        if TRACED.contains(c) && UNTRACED.contains(c) {
            problems.push(format!("`{c}` is listed as traced and as untraced"));
        }
    }
    for (c, opt) in UNTRACED_FORMS {
        let has = pages
            .get(*c)
            .is_some_and(|p| p.contains(&opt.replace('-', "\\-")) || p.contains(opt));
        if !has {
            problems.push(format!(
                "`{c} {opt}` is listed but its page names no such option"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// During the window's start (W1-W11, twice: before and after an app is
/// added) and the everyday commands (E1-E22), in a test home with an app
/// whose network is "none", each command did its work (its exit status,
/// and the program that shows it ran: an unpack tool for `add`, Bubblewrap
/// for `run`, `verify` and `doctor`, GnuPG for `doctor --contracts`), and
/// no process SAM started made an internet connection: none opened an
/// internet socket, set up io_uring or connected to a name-service socket,
/// other than the two named in [`allowed`] (pasta's probe socket, which
/// connects nowhere on the internet, and `curl --version`'s connect to
/// nscd). Only these commands must show a program: `add`, `run`, `verify`,
/// `doctor` and `doctor --contracts`; exit status 3 ("not passed") counts
/// as ran for `verify` and the doctor commands. The programs each command
/// ran and the Unix sockets it connected to are printed for the privacy
/// report.
#[test]
fn everyday_commands_make_no_internet_connection() {
    if !traced_run_possible() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let recorder = Recorder::start();
    let (_tmp, root, img) = traced_home("#!/bin/sh\necho started\n", recorder.port);
    let img = img.to_str().unwrap().to_string();
    let downloads = root.join("home/Downloads").to_str().unwrap().to_string();
    let mut problems = Vec::new();
    let mut covered = std::collections::BTreeSet::new();
    covered.insert("updates".to_string()); // W10, and P1 with an app id
    let mut id = String::new();
    for round in 0..2 {
        for (label, args, ok, marker) in steps(&img, &downloads, &id) {
            covered.insert(page_of(&args));
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let input = if label == "E7" {
                let got = traced(&root, &["--json", "get", &id], None);
                let v: serde_json::Value = serde_json::from_str(&got.stdout).unwrap();
                Some(v["data"].to_string())
            } else {
                None
            };
            let ran = traced(&root, &refs, input.as_deref());
            let name = refs.join(" ");
            if !ran.status.is_some_and(|s| ok.contains(&s)) {
                problems.push(format!(
                    "{label} `{name}` ended with {:?}, not {ok:?}: {}",
                    ran.status,
                    ran.stderr.trim()
                ));
            }
            if !marker.is_empty()
                && !ran
                    .seen
                    .execs
                    .iter()
                    .any(|(_, l)| marker.iter().any(|m| l.contains(m)))
            {
                problems.push(format!(
                    "{label} `{name}` ran none of {marker:?}, so the trace does not show it did its work"
                ));
            }
            problems.extend(ran.seen.problems.iter().cloned());
            let progs: std::collections::BTreeSet<String> = ran
                .seen
                .execs
                .iter()
                .filter_map(|(_, l)| l.split('"').nth(1))
                .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
                .collect();
            sam_core::outln!(
                "{label} `{name}`: exit {:?}; programs {progs:?}; Unix sockets {:?}; internet socket: {}",
                ran.status,
                ran.seen.unix,
                if ran.seen.inet_socket { "yes" } else { "none" }
            );
            if label == "E1" {
                let list = traced(&root, &["--json", "list"], None);
                let v: serde_json::Value = serde_json::from_str(&list.stdout).unwrap();
                id = v["data"][0]["id"].as_str().unwrap().to_string();
            }
        }
        if round == 0 {
            assert!(!id.is_empty(), "the test app was not added: {problems:?}");
        }
    }
    let traced_pages: std::collections::BTreeSet<String> =
        TRACED.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        covered, traced_pages,
        "TRACED must name exactly the traced commands"
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The tracer sees SAM's real way out: an update check the person asks for
/// (`updates <id>`) ends with 0, runs curl, and opens an internet socket,
/// whose only internet connect goes to the address the app names
/// (127.0.0.1 and the recorder's port).
#[test]
fn the_trace_sees_an_update_check() {
    if !traced_run_possible() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "updates-curl"])
        .unwrap_or_else(|e| panic!("{e}"));
    let recorder = Recorder::start();
    let (_tmp, root, img) = traced_home("#!/bin/sh\necho started\n", recorder.port);
    let added = traced(
        &root,
        &[
            "--json",
            "add",
            img.to_str().unwrap(),
            "--no-launcher",
            "--accept",
        ],
        None,
    );
    assert_eq!(added.status, Some(0), "{}", added.stderr);
    let v: serde_json::Value = serde_json::from_str(&added.stdout).unwrap();
    let id = v["data"]["app"]["id"].as_str().unwrap().to_string();
    let ran = traced(&root, &["--json", "updates", &id], None);
    assert_eq!(ran.status, Some(0), "{}", ran.stderr);
    assert!(
        ran.seen.execs.iter().any(|(_, l)| l.contains("/curl\"")),
        "no curl in the trace of an update check: {:?}",
        ran.seen.execs
    );
    assert!(
        ran.seen.inet_socket,
        "the trace shows no internet socket for an update check"
    );
    assert!(
        !ran.seen.inet.is_empty(),
        "the trace shows no internet connect"
    );
    for (addr, port) in &ran.seen.inet {
        assert_eq!(
            (addr.as_str(), *port),
            ("127.0.0.1", recorder.port),
            "an update check connected elsewhere than the address the app names"
        );
    }
}

/// The tracer follows into an app's sandbox, inside Bubblewrap's
/// namespaces: an app whose start script runs `getent hosts`, started with
/// network "none", shows getent's start and its internet socket in the
/// trace (the app's own network is its permission; here it only proves
/// the tracer sees that far).
#[test]
fn the_trace_sees_inside_an_apps_sandbox() {
    if !traced_run_possible() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let (_tmp, root, img) =
        traced_home("#!/bin/sh\ngetent hosts example.invalid\necho started\n", 9);
    let added = traced(
        &root,
        &[
            "--json",
            "add",
            img.to_str().unwrap(),
            "--no-launcher",
            "--accept",
        ],
        None,
    );
    assert_eq!(added.status, Some(0), "{}", added.stderr);
    let v: serde_json::Value = serde_json::from_str(&added.stdout).unwrap();
    let id = v["data"]["app"]["id"].as_str().unwrap().to_string();
    let ran = traced(&root, &["run", &id], None);
    assert_eq!(ran.status, Some(0), "{}", ran.stderr);
    assert!(ran.stdout.contains("started"), "{}", ran.stderr);
    let getent: Vec<&String> = ran
        .seen
        .execs
        .iter()
        .filter(|(_, l)| l.contains("/getent\""))
        .map(|(pid, _)| pid)
        .collect();
    assert!(
        !getent.is_empty(),
        "the trace does not show the app's getent: {:?}",
        ran.seen.execs
    );
    assert!(
        ran.seen.inet_socket_pids.iter().any(|p| getent.contains(&p)),
        "the trace does not show getent's internet socket inside the sandbox: sockets from {:?}, getent {getent:?}",
        ran.seen.inet_socket_pids
    );
}
