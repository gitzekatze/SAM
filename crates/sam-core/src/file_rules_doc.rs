//! Test helpers: the section *What an app sees: the file rules* of
//! `docs/security.md`, cut into its rules and their gap paragraphs.
//! Compiled for tests only: sam-core declares it under `#[cfg(test)]`, and
//! sam-sandbox includes this file with `#[path]` under `#[cfg(test)]`.

/// The heading of the section.
pub const HEADING: &str = "## What an app sees: the file rules";

/// The words that start a rule's gap paragraph.
pub const GAP_START: &str = "*Not given yet:*";

/// `docs/security.md` as it is in the source tree.
pub fn page() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/security.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The section, from its heading to the next `---` or `## `; panics when
/// the page has no such section.
pub fn section(page: &str) -> &str {
    let start = page
        .find(HEADING)
        .unwrap_or_else(|| panic!("docs/security.md has no section {HEADING:?}"));
    let body = &page[start + HEADING.len()..];
    let end = [body.find("\n---"), body.find("\n## ")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(body.len());
    &page[start..start + HEADING.len() + end]
}

/// Rule `id` (`"C3"`): from `- **C3,` to the next `- **` or the section's
/// end; panics when the section has no such rule.
pub fn rule<'a>(page: &'a str, id: &str) -> &'a str {
    let sec = section(page);
    let mark = format!("- **{id},");
    let start = sec
        .find(&mark)
        .unwrap_or_else(|| panic!("the file rules have no rule {id} ({mark:?})"));
    let rest = &sec[start + mark.len()..];
    let end = rest.find("\n- **").unwrap_or(rest.len());
    &sec[start..start + mark.len() + end]
}

/// The gap paragraph of `rule`: from `*Not given yet:*` to the rule's end,
/// with every run of white space as one space (a marker may break across
/// lines); empty when the rule names no gap.
pub fn gap(rule: &str) -> String {
    match rule.find(GAP_START) {
        Some(i) => one_line(&rule[i..]),
        None => String::new(),
    }
}

/// `text` with every run of white space as one space.
pub fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
