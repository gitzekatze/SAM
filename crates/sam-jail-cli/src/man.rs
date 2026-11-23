//! Man pages generated from the command definitions (`sam-jail man DIR`).

use super::*;

/// `sam-jail.1` plus `sam-jail-<command>.1` for every visible command,
/// generated from the same definitions as `--help`. Commands of a command
/// (`sam-jail config get`) get a page too, `sam-jail-config-get.1`: the
/// page of `config` names it (audit: 27 pages named that did not exist).
pub(crate) fn write_man_pages(dir: &std::path::Path) -> Result<()> {
    use clap::CommandFactory;
    std::fs::create_dir_all(dir)?;
    // The release script sets the release date; otherwise today.
    let date = std::env::var("SAM_MAN_DATE").unwrap_or_else(|_| {
        sam_core::util::format_ts(sam_core::util::now())
            .chars()
            .take(10)
            .collect()
    });
    let render = |cmd: clap::Command, file: &str| -> Result<()> {
        let mut buf = Vec::new();
        clap_mangen::Man::new(cmd)
            .date(date.clone())
            .source(format!("SAM {}", env!("CARGO_PKG_VERSION")))
            .manual("SAM - Sandboxed AppImage Manager")
            .render(&mut buf)?;
        std::fs::write(dir.join(file), buf)?;
        Ok(())
    };
    // `sam-jail help …` repeats `--help`, which every page lists; a page
    // of its own for it and for each command's `help` would only repeat
    // the page it is on.
    let root = without_help_commands(Cli::command());
    let mut pages = Vec::new();
    commands_below(&root, "sam-jail", "sam-jail", &mut pages);
    for (cmd, name) in pages {
        render(cmd, &format!("{name}.1"))?;
    }
    render(root, "sam-jail.1")
}

/// `cmd` and every command below it without clap's `help` command (the
/// command line keeps it; only the man pages leave it out).
fn without_help_commands(cmd: clap::Command) -> clap::Command {
    cmd.disable_help_subcommand(true)
        .mut_subcommands(without_help_commands)
}

/// Every visible command below `parent`, at any depth, named for its page
/// (`sam-jail-config-get`) and for typing (`sam-jail config get`).
fn commands_below(
    parent: &clap::Command,
    name: &str,
    typed: &str,
    out: &mut Vec<(clap::Command, String)>,
) {
    for sub in parent.get_subcommands().filter(|s| !s.is_hide_set()) {
        let page = format!("{name}-{}", sub.get_name());
        let words = format!("{typed} {}", sub.get_name());
        // A one-off command: the names may live until it exits.
        let page_s: &'static str = Box::leak(page.clone().into_boxed_str());
        let words_s: &'static str = Box::leak(words.clone().into_boxed_str());
        out.push((
            sub.clone().name(page_s).display_name(page_s).bin_name(words_s),
            page.clone(),
        ));
        commands_below(sub, &page, &words, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every page a man page names (`sam-jail-config-get(1)`) is written
    /// too (audit: `sam-jail-config.1` named six pages that did not exist).
    #[test]
    fn every_man_page_named_is_written() {
        let d = tempfile::tempdir().unwrap();
        write_man_pages(d.path()).unwrap();
        let mut named = std::collections::BTreeSet::new();
        for e in std::fs::read_dir(d.path()).unwrap().flatten() {
            let text = std::fs::read_to_string(e.path()).unwrap().replace("\\-", "-");
            for (i, _) in text.match_indices("(1)") {
                let start = text[..i]
                    .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                    .map_or(0, |s| s + 1);
                let page = &text[start..i];
                if page.starts_with("sam-jail") {
                    named.insert(page.to_string());
                }
            }
        }
        assert!(named.contains("sam-jail-config-get"), "{named:?}");
        let missing: Vec<&String> = named
            .iter()
            .filter(|p| !d.path().join(format!("{p}.1")).is_file())
            .collect();
        assert!(missing.is_empty(), "named but not written: {missing:?}");
    }
}
