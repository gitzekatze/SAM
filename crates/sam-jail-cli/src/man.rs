//! Man pages generated from the command definitions (`sam-jail man DIR`).

use super::*;

/// `sam-jail.1` plus `sam-jail-<command>.1` for every visible command,
/// generated from the same definitions as `--help`.
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
    let root = Cli::command();
    for sub in root.get_subcommands().filter(|s| !s.is_hide_set()) {
        // A one-off command: the names may live until it exits.
        let name: &'static str = Box::leak(format!("sam-jail-{}", sub.get_name()).into_boxed_str());
        let typed: &'static str =
            Box::leak(format!("sam-jail {}", sub.get_name()).into_boxed_str());
        render(
            sub.clone().name(name).display_name(name).bin_name(typed),
            &format!("{name}.1"),
        )?;
    }
    render(root, "sam-jail.1")
}
