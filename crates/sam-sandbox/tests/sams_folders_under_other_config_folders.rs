//! SAM's own folders by name under other config and data folders
//! (`XDG_CONFIG_HOME=~/cfg`, `XDG_DATA_HOME=~/dat`: `~/cfg/sam`,
//! `~/dat/sam`) are hidden as SAM's own are, never only locked read-only,
//! also while this SAM keeps its own elsewhere (`SAM_CONFIG_DIR`,
//! `SAM_DATA_DIR`). In its own file because it sets these variables for
//! the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::path::{Path, PathBuf};

use sam_core::permissions::Access;
use sam_core::sandbox::sample_context;
use sam_sandbox::Bubblewrap;

fn has_seq(v: &[String], seq: &[&str]) -> bool {
    v.windows(seq.len())
        .any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
}

/// Where `seq` starts in `v`, every time.
fn at_seq(v: &[String], seq: &[&str]) -> Vec<usize> {
    v.windows(seq.len())
        .enumerate()
        .filter(|(_, w)| w.iter().zip(seq).all(|(a, b)| a == b))
        .map(|(i, _)| i)
        .collect()
}

/// Whether an empty folder on `dir` comes after the read-only grant of
/// `grant` inside it: a later mount covers an earlier one, so an empty
/// folder before the grant would leave the grant showing what lies there.
fn hidden_after(a: &[String], dir: &str, grant: &str) -> bool {
    let bind = at_seq(a, &["--ro-bind-try", grant, grant]);
    let hide = at_seq(a, &["--tmpfs", dir]);
    !bind.is_empty() && hide.iter().any(|h| *h > bind[0])
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// With the whole home writable, the sandbox puts an empty folder in place
/// of `~/cfg/sam` and `~/dat/sam` by name, also when its list of SAM's
/// folders is empty, and a writable grant inside one is not bound: the
/// sandbox check expects that grant hidden. Without the whole home, the
/// list of SAM's folders (`Paths::sam_dirs`) holds them, so a read-only
/// grant inside one is hidden too and a terminal app's start line leaves
/// it out. Before, `~/cfg/sam` was only locked read-only, so the app could
/// read SAM's settings there and the check failed a sandbox that did what
/// it should (independent re-review of decision 9).
#[test]
fn sams_folders_under_other_config_folders_are_hidden_not_only_read_only() {
    let t = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(t.path()).unwrap();
    let home = base.join("home");
    for d in ["cfg/sam/x", "dat/sam/y", "notes"] {
        std::fs::create_dir_all(home.join(d)).unwrap();
    }
    std::env::set_var("XDG_CONFIG_HOME", home.join("cfg"));
    std::env::set_var("XDG_DATA_HOME", home.join("dat"));
    let paths = sam_core::Paths {
        config_dir: base.join("elsewhere/config"),
        data_dir: base.join("elsewhere/data"),
        applications_dir: base.join("elsewhere/applications"),
        runtime_root: None,
    };
    let named: Vec<PathBuf> = ["cfg/sam", "dat/sam"]
        .iter()
        .map(|d| home.join(d))
        .collect();

    let mut ctx = sample_context();
    ctx.host.home = home.clone();
    ctx.host.xdg_dirs.clear();
    ctx.owd = home.clone();
    ctx.sam_dirs = vec![];
    ctx.permissions.filesystem.home = true;
    ctx.permissions.filesystem.home_access = Access::Rw;
    ctx.permissions.filesystem.custom_write = vec![s(&home.join("cfg/sam/x"))];
    ctx.permissions.filesystem.custom_read = vec![s(&home.join("dat/sam/y"))];
    let a = Bubblewrap.build(&ctx).unwrap().args;
    for d in &named {
        let d = s(d);
        assert!(has_seq(&a, &["--tmpfs", &d]), "{d}: {a:?}");
        assert!(!has_seq(&a, &["--ro-bind-try", &d, &d]), "{d}: {a:?}");
    }
    assert!(!a.contains(&s(&home.join("cfg/sam/x"))), "{a:?}");
    // The sandbox's own hiding by name comes after the grant inside.
    assert!(
        hidden_after(&a, &s(&home.join("dat/sam")), &s(&home.join("dat/sam/y"))),
        "{a:?}"
    );

    ctx.permissions.filesystem.home = false;
    ctx.permissions.filesystem.custom_write.clear();
    ctx.permissions.filesystem.custom_read = ["cfg/sam/x", "dat/sam/y", "notes"]
        .iter()
        .map(|g| s(&home.join(g)))
        .collect();
    ctx.sam_dirs = paths.sam_dirs("", &home);
    let a = Bubblewrap.build(&ctx).unwrap().args;
    for d in &named {
        let d = s(d);
        assert!(has_seq(&a, &["--tmpfs", &d]), "{d}: {a:?}");
    }
    // The hiding of SAM's folders from its list comes after the grants.
    for (d, g) in [("cfg/sam", "cfg/sam/x"), ("dat/sam", "dat/sam/y")] {
        assert!(
            hidden_after(&a, &s(&home.join(d)), &s(&home.join(g))),
            "{d}: {a:?}"
        );
    }
    assert_eq!(
        sam_sandbox::shown_extra_folders(&ctx),
        vec![s(&home.join("notes"))]
    );
}
