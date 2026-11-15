//! The relations between SAM's parts, checked against the rules of the C4
//! overview (docs/architecture.md). A part that starts to depend on one it
//! must not, or a diagram that no longer shows the real dependencies, fails
//! here.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Each SAM part and the SAM parts it depends on (normal dependencies, as
/// written in its Cargo.toml).
fn dependencies() -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for e in fs::read_dir(root().join("crates")).unwrap().flatten() {
        let Ok(text) = fs::read_to_string(e.path().join("Cargo.toml")) else {
            continue;
        };
        let name = e.file_name().to_string_lossy().into_owned();
        let mut deps = BTreeSet::new();
        let mut in_deps = false;
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with('[') {
                in_deps = l == "[dependencies]";
                continue;
            }
            if in_deps {
                if let Some(dep) = l
                    .split(['.', ' ', '='])
                    .next()
                    .filter(|d| d.starts_with("sam-"))
                {
                    deps.insert(dep.to_string());
                }
            }
        }
        out.insert(name, deps);
    }
    out
}

fn deps_of(name: &str) -> BTreeSet<String> {
    dependencies()
        .remove(name)
        .unwrap_or_else(|| panic!("no part {name}"))
}

fn set(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The permission model is the base: it depends on no other SAM part, so
/// every other part can use it without creating a cycle.
#[test]
fn the_permission_model_depends_on_no_other_part() {
    assert!(deps_of("sam-core").is_empty(), "{:?}", deps_of("sam-core"));
}

/// The window contains no sandbox logic: it depends only on the permission
/// model and reaches everything else through `sam-jail --json`, so the
/// window and the command line always behave the same.
#[test]
fn the_window_reaches_sam_only_through_the_command_line() {
    assert_eq!(deps_of("sam-gtk"), set(&["sam-core"]));
}

/// The parts that handle untrusted AppImage content or build the sandbox
/// depend only on the parts below them, never on the operations layer, the
/// command line or the window.
#[test]
fn lower_parts_never_depend_on_higher_ones() {
    let higher = set(&["sam-runner", "sam-jail-cli", "sam-gtk"]);
    for part in [
        "sam-core",
        "sam-detect",
        "sam-intake",
        "sam-profile",
        "sam-sandbox",
        "sam-storage",
    ] {
        let bad: Vec<_> = deps_of(part).intersection(&higher).cloned().collect();
        assert!(bad.is_empty(), "{part} depends on {bad:?}");
    }
    assert!(
        !deps_of("sam-runner").contains("sam-jail-cli")
            && !deps_of("sam-runner").contains("sam-gtk")
    );
    assert!(!deps_of("sam-jail-cli").contains("sam-gtk"));
}

/// The sandbox command builder depends only on the permission model, so
/// what it builds follows from the permissions alone.
#[test]
fn the_sandbox_builder_depends_only_on_the_permission_model() {
    assert_eq!(deps_of("sam-sandbox"), set(&["sam-core"]));
}

/// The component diagram in docs/architecture.md shows exactly the real
/// dependencies between the parts: no arrow is missing and none is invented.
#[test]
fn the_component_diagram_shows_the_real_dependencies() {
    let doc = fs::read_to_string(root().join("docs/architecture.md")).unwrap();
    let start = doc
        .find("## Level 3: Components")
        .expect("component section");
    let block = &doc[start..];
    let block = &block[block.find("```mermaid").unwrap()..];
    let block = &block[..block[3..].find("```").unwrap() + 3];
    // Diagram names: short ids mapped to parts.
    let ids: BTreeMap<&str, &str> = [
        ("gtk", "sam-gtk"),
        ("clic", "sam-jail-cli"),
        ("runner", "sam-runner"),
        ("intake", "sam-intake"),
        ("detect", "sam-detect"),
        ("profile", "sam-profile"),
        ("sandbox", "sam-sandbox"),
        ("storage", "sam-storage"),
        ("core", "sam-core"),
    ]
    .into();
    let mut drawn: BTreeSet<(String, String)> = BTreeSet::new();
    for line in block.lines() {
        let l = line.trim();
        if l.contains("-->|JSON|") {
            continue; // the window talks to the command line, not a Cargo dependency
        }
        if let Some((a, b)) = l.split_once("-->") {
            let (a, b) = (a.trim(), b.trim());
            if let (Some(a), Some(b)) = (ids.get(a), ids.get(b)) {
                drawn.insert((a.to_string(), b.to_string()));
            }
        }
    }
    let real: BTreeSet<(String, String)> = dependencies()
        .into_iter()
        .flat_map(|(p, ds)| ds.into_iter().map(move |d| (p.clone(), d)))
        .collect();
    let missing: Vec<_> = real.difference(&drawn).collect();
    let invented: Vec<_> = drawn.difference(&real).collect();
    assert!(
        missing.is_empty() && invented.is_empty(),
        "diagram lacks {missing:?}, diagram invents {invented:?}"
    );
}

/// Every box and arrow label in the documents' diagrams is quoted, so
/// GitHub draws them: unquoted brackets or semicolons inside a label are a
/// parse error there (the component diagram once failed that way).
#[test]
fn diagram_labels_are_quoted_so_github_draws_them() {
    let mut bad = Vec::new();
    for entry in fs::read_dir(root().join("docs")).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let doc = fs::read_to_string(&path).unwrap();
        let mut in_diagram = false;
        for line in doc.lines() {
            let l = line.trim();
            if l.starts_with("```") {
                in_diagram = l == "```mermaid";
                continue;
            }
            if !in_diagram || l.is_empty() || l == "end" || l.starts_with("flowchart") {
                continue;
            }
            // A node: id[...], id(...), id{...}, optionally after "subgraph".
            let node = l.strip_prefix("subgraph ").unwrap_or(l);
            let opens = node
                .find(['[', '(', '{'])
                .filter(|&i| i > 0 && node[..i].chars().all(|c| c.is_alphanumeric() || c == '_'));
            if let Some(i) = opens {
                let label = node[i..].trim_start_matches(['[', '(', '{']);
                if !label.starts_with('"') {
                    bad.push(format!("{}: {l}", path.display()));
                }
            }
            // An arrow label: -->|...|, except the plain word JSON.
            if let Some(i) = l.find("|") {
                let rest = &l[i + 1..];
                if !rest.starts_with('"') && !rest.starts_with("JSON|") {
                    bad.push(format!("{}: {l}", path.display()));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "quote these diagram labels:\n{}",
        bad.join("\n")
    );
}
