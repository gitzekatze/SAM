//! The machinery around SAM: how a release is signed and tagged, how the
//! owner's approval counts, and what the CI scripts let pass (AUTOMATION.md,
//! docs/releasing.md). Each test runs the real script, or the real command
//! of a workflow step, with stand-ins only for what lives on GitHub or needs
//! a person (gh, the release key) and for the build tools around it.
//! The rules every workflow file keeps are checked by
//! scripts/workflow-check.py.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::ops::Range;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn write_exec(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// PATH with the stand-ins in `bin` first.
fn path_with(bin: &Path) -> String {
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// Runs `cmd` with a time limit; its output goes through files, so a full
/// pipe can never stall it.
fn run(mut cmd: Command, secs: u64) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let (o, e) = (dir.path().join("out"), dir.path().join("err"));
    cmd.stdin(Stdio::null())
        .stdout(fs::File::create(&o).unwrap())
        .stderr(fs::File::create(&e).unwrap());
    let mut child = cmd.spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(secs);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} did not end within {secs} s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: fs::read(&o).unwrap(),
        stderr: fs::read(&e).unwrap(),
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn sha256(path: &Path) -> String {
    let out = Command::new("sha256sum").arg(path).output().unwrap();
    assert!(out.status.success(), "sha256sum {}", path.display());
    text(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The `run:` command of the step named `step` in a workflow, as the shell
/// gets it.
fn run_block(workflow: &str, step: &str) -> String {
    let file = root().join(".github/workflows").join(workflow);
    let all = fs::read_to_string(&file).unwrap();
    let lines: Vec<&str> = all.lines().collect();
    let want = format!("name: {step}");
    let at = lines
        .iter()
        .position(|l| l.trim_start().trim_start_matches("- ").trim() == want)
        .unwrap_or_else(|| panic!("no step {step:?} in {workflow}"));
    let step_indent = indent(lines[at]);
    for (i, l) in lines.iter().enumerate().skip(at + 1) {
        if l.trim().is_empty() {
            continue;
        }
        if indent(l) <= step_indent {
            break;
        }
        let Some(rest) = l.trim_start().strip_prefix("run:") else {
            continue;
        };
        if rest.trim() != "|" {
            return format!("{}\n", rest.trim());
        }
        let body: Vec<&str> = lines[i + 1..]
            .iter()
            .take_while(|b| b.trim().is_empty() || indent(b) > indent(l))
            .copied()
            .collect();
        let k = body
            .iter()
            .filter(|b| !b.trim().is_empty())
            .map(|b| indent(b))
            .min()
            .unwrap();
        return body
            .iter()
            .map(|b| b.get(k..).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
    }
    panic!("the step {step:?} in {workflow} has no run: command")
}

/// A workflow step's command, run as GitHub runs it (bash -eo pipefail).
fn step_command(dir: &Path, block: &str) -> Command {
    let script = dir.join("step.sh");
    fs::write(&script, block).unwrap();
    let mut cmd = Command::new("bash");
    cmd.args(["--noprofile", "--norc", "-eo", "pipefail"])
        .arg(&script)
        .env("HOME", dir);
    cmd
}

#[test]
fn release_builds_use_one_fixed_rust_and_stop_on_overflow() {
    let cargo: toml::Value =
        toml::from_str(&fs::read_to_string(root().join("Cargo.toml")).unwrap()).unwrap();
    assert_eq!(
        cargo["profile"]["release"].get("overflow-checks"),
        Some(&toml::Value::Boolean(true)),
        "release builds must stop on arithmetic overflow (Cargo.toml [profile.release])"
    );
    let release = fs::read_to_string(root().join(".github/workflows/release.yml")).unwrap();
    let version = release
        .lines()
        .find_map(|l| l.trim().strip_prefix("RUST_VERSION:"))
        .expect("release.yml names its Rust version (RUST_VERSION)")
        .trim()
        .trim_matches('"');
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()),
        "release builds use one exact Rust version, not {version:?}"
    );
    let rust = run_block("release.yml", "Rust");
    assert!(
        rust.contains("rustup toolchain install \"$RUST_VERSION\"")
            && rust.contains("rustup default \"$RUST_VERSION\""),
        "the release build installs and uses RUST_VERSION:\n{rust}"
    );
}

/// The keys anywhere in `table` (a `[profile.release]` with its package
/// overrides) that turn debug assertions on.
fn debug_assertions_on(table: &toml::Value, at: &str, out: &mut Vec<String>) {
    if let Some(t) = table.as_table() {
        for (k, v) in t {
            let here = format!("{at}.{k}");
            if k == "debug-assertions" && v.as_bool() != Some(false) {
                out.push(format!("{here} = {v}"));
            }
            debug_assertions_on(v, &here, out);
        }
    }
}

/// Every file under `dir`, folders followed.
fn files_below(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            files_below(&p, out);
        } else {
            out.push(p);
        }
    }
}

const PKGBUILD: &str = "packaging/arch/PKGBUILD";
const SPEC: &str = "packaging/fedora/sam-jail.spec";

/// The lines of the package recipe `recipe` (a path below the repository).
fn recipe_text(recipe: &str) -> String {
    fs::read_to_string(root().join(recipe)).unwrap_or_else(|e| panic!("{recipe}: {e}"))
}

/// The body of the shell function `name` in the Arch recipe: the lines (as
/// indices into `lines`) between its `name() {` line and the first `}` at
/// the start of a line. Fails, naming the file and line, when the recipe
/// does not define the function exactly once in that form or never closes
/// it.
fn pkgbuild_function(lines: &[&str], name: &str) -> Range<usize> {
    let defines = |l: &str| {
        let l = l.trim_start();
        match l.strip_prefix("function") {
            Some(rest) if rest.starts_with([' ', '\t']) => rest
                .trim_start()
                .strip_prefix(name)
                .is_some_and(|r| r.is_empty() || r.starts_with([' ', '\t', '(', '{'])),
            _ => l
                .strip_prefix(name)
                .is_some_and(|r| r.trim_start().starts_with('(')),
        }
    };
    let defined: Vec<usize> = (0..lines.len()).filter(|&i| defines(lines[i])).collect();
    let &[at] = defined.as_slice() else {
        panic!(
            "{PKGBUILD}: {name}() must be defined exactly once, found at lines {:?}",
            defined.iter().map(|i| i + 1).collect::<Vec<_>>()
        );
    };
    let header = format!("{name}() {{");
    assert!(
        lines[at] == header,
        "{PKGBUILD}:{}: {name}() must start with the line `{header}`, not {:?}",
        at + 1,
        lines[at]
    );
    let end = (at + 1..lines.len())
        .find(|&i| lines[i] == "}")
        .unwrap_or_else(|| {
            panic!(
                "{PKGBUILD}:{}: {name}() has no closing `}}` at the start of a line",
                at + 1
            )
        });
    at + 1..end
}

/// The section names of an RPM spec file: a line whose first word is one of
/// them starts a new section.
const SPEC_SECTIONS: &str = "%prep %generate_buildrequires %conf %build \
    %install %check %clean %files %changelog %package %description %pre %post \
    %preun %postun %pretrans %posttrans %preuntrans %postuntrans %triggerprein \
    %triggerin %triggerun %triggerpostun %filetriggerin %filetriggerun \
    %filetriggerpostun %transfiletriggerin %transfiletriggerun \
    %transfiletriggerpostun %verifyscript %sourcelist %patchlist";

/// The body of the section `name` (for example `%check`) of the Fedora
/// recipe: the lines (as indices into `lines`) after its header, up to the
/// next section header or the end of the file. Fails, naming the file and
/// line, when the section is not there exactly once or its header carries
/// more than its name.
fn spec_section(lines: &[&str], name: &str) -> Range<usize> {
    assert!(
        SPEC_SECTIONS.split_whitespace().any(|s| s == name),
        "{name} is no spec section"
    );
    let section = |l: &str| -> Option<&'static str> {
        let first = l.split_whitespace().next()?;
        SPEC_SECTIONS.split_whitespace().find(|s| *s == first)
    };
    let headers: Vec<usize> = (0..lines.len())
        .filter(|&i| section(lines[i]) == Some(name))
        .collect();
    let &[at] = headers.as_slice() else {
        panic!(
            "{SPEC}: {name} must be there exactly once, found at lines {:?}",
            headers.iter().map(|i| i + 1).collect::<Vec<_>>()
        );
    };
    assert!(
        lines[at] == name,
        "{SPEC}:{}: the line must be just `{name}`, not {:?}",
        at + 1,
        lines[at]
    );
    let end = (at + 1..lines.len())
        .find(|&i| section(lines[i]).is_some())
        .unwrap_or(lines.len());
    at + 1..end
}

/// Whether `line` sets an optimisation level other than a literal 1, 2, 3,
/// s or z in any spelling (`-C opt-level=0`, `-Copt-level=0`,
/// `opt-level = 0`, `opt_level: "0"`, `CARGO_PROFILE_RELEASE_OPT_LEVEL=0`),
/// or a level this test cannot read, such as `opt-level=$LEVEL`.
fn sets_a_level_that_may_be_zero(line: &str) -> bool {
    let line = line.to_lowercase().replace('_', "-");
    line.match_indices("opt-level").any(|(at, word)| {
        let mut value = line[at + word.len()..]
            .trim_start_matches([' ', '\t', '=', ':', '"', '\'', '\\'])
            .chars();
        let level = value.next();
        let after = value.next();
        !(matches!(level, Some('1' | '2' | '3' | 's' | 'z'))
            && after.is_none_or(|c| c.is_whitespace() || "\"',;)]}\\".contains(c)))
    })
}

/// SAM's developer variables and test hooks (SAM_CLI, SAM_RUN,
/// SAM_LOCALE_DIR, SAM_DBUS_LOG, SAM_TRUST_TOOLS_IN, and the folder
/// variables SAM_CONFIG_DIR, SAM_DATA_DIR, SAM_APPLICATIONS_DIR and
/// SAM_RUNTIME_DIR) work only where debug assertions are on (owner decision
/// 16 of 2026-11-23). A release build with them on would honour every one
/// of them, silently. So the release profile never turns them on, and no
/// packaging recipe, the Makefile, the release and signing scripts, the
/// release guide's build commands or the shipped AppImage's test script
/// turn them on by a flag (`-C debug-assertions`,
/// `--config profile.release.debug-assertions=true`) or a variable
/// (`CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS`), and the repository keeps no
/// Cargo configuration file (`.cargo/config.toml`), which every build in it
/// would read. Settings from outside the repository are left to
/// `scripts/check-release-build.sh`, which asks the built program itself
/// (`release_build_paths_check_the_programs_they_build`).
///
/// An optimisation level of 0 turns them on too: Cargo passes no
/// debug-assertions flag for a release build, so rustc derives them from
/// the last `-C opt-level` it gets, and one from `RUSTFLAGS` comes after
/// the profile's. So no such file sets level 0, in any spelling, except the
/// test steps of the Arch and Fedora recipes (check() and %check), which
/// build only SAM's tests and never in release mode. The profile variable
/// `CARGO_PROFILE_RELEASE_OPT_LEVEL=0` would be safe (Cargo then passes
/// `-C debug-assertions=off` itself), but no shipped build needs level 0, so
/// the one rule covers it too. A level this test cannot read (a variable)
/// counts as 0.
#[test]
fn release_builds_never_turn_on_debug_assertions() {
    let cargo: toml::Value =
        toml::from_str(&fs::read_to_string(root().join("Cargo.toml")).unwrap()).unwrap();
    let release = &cargo["profile"]["release"];
    let mut on = Vec::new();
    debug_assertions_on(release, "profile.release", &mut on);
    assert!(
        on.is_empty(),
        "Cargo.toml turns debug assertions on: {on:?}"
    );
    let mut files = vec![
        root().join("Makefile"),
        root().join("scripts/make-appimage.sh"),
        // It writes the Cargo configuration of the vendored source that the
        // package recipes build with.
        root().join("scripts/make-release.sh"),
        root().join("scripts/release.sh"),
        root().join(".github/workflows/release.yml"),
        // The signing tool's build command, which the maintainer copies by
        // hand, and the test tool of the shipped AppImage's container test.
        root().join("scripts/sign-release.sh"),
        root().join("docs/releasing.md"),
        root().join("scripts/test-shipped.sh"),
    ];
    // A Cargo configuration in the repository would reach every build made
    // in it, and the source tarball through `git archive`: none is kept,
    // so no setting can hide there from this test.
    for config in [".cargo/config.toml", ".cargo/config"] {
        assert!(
            !root().join(config).exists(),
            "{config} exists: a Cargo configuration in the repository reaches \
             every release build made from it; put build settings into \
             Cargo.toml or the scripts this test reads"
        );
    }
    let before = files.len();
    files_below(&root().join("packaging"), &mut files);
    // The recipes that build SAM with --release are among them: a moved
    // folder must not leave this test checking nothing.
    for recipe in [PKGBUILD, SPEC] {
        assert!(files.contains(&root().join(recipe)), "{recipe} is gone");
    }
    assert!(files.len() > before + 1);

    let arch = recipe_text(PKGBUILD);
    let arch: Vec<&str> = arch.lines().collect();
    let spec = recipe_text(SPEC);
    let spec: Vec<&str> = spec.lines().collect();
    let test_steps = [
        (PKGBUILD, pkgbuild_function(&arch, "check")),
        (SPEC, spec_section(&spec, "%check")),
    ];
    let mut level_zero = Vec::new();
    for f in &files {
        let raw = fs::read_to_string(f).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let name = f.strip_prefix(root()).unwrap_or(f).display().to_string();
        assert!(
            !raw.to_lowercase()
                .replace('_', "-")
                .contains("debug-assertions"),
            "{name} turns debug assertions on for a release build (or names them): \
             SAM's developer variables would work there"
        );
        let test_step = test_steps
            .iter()
            .find(|(recipe, _)| root().join(recipe) == *f)
            .map(|(_, body)| body.clone());
        for (i, line) in raw.lines().enumerate() {
            let allowed = test_step.as_ref().is_some_and(|body| body.contains(&i));
            if !allowed && sets_a_level_that_may_be_zero(line) {
                level_zero.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        level_zero.is_empty(),
        "optimisation level 0 (or a level this test cannot read) outside the \
         test steps of the package recipes: a release build at level 0 has debug \
         assertions and honours SAM's developer variables (SAM_DATA_DIR, SAM_CLI, \
         SAM_TRUST_TOOLS_IN, ...):\n{}",
        level_zero.join("\n")
    );

    // The test steps may build at level 0 only because they build no
    // release: a release build there would overwrite the programs that
    // package() installs on Arch.
    for (recipe, body) in &test_steps {
        let lines = if *recipe == PKGBUILD { &arch } else { &spec };
        for i in body.clone() {
            let code = lines[i].trim();
            let release = !code.starts_with('#')
                && code
                    .split_whitespace()
                    .any(|w| w == "-r" || w.starts_with("--release") || w.starts_with("--profile"));
            assert!(
                !release,
                "{recipe}:{}: the test step builds at optimisation level 0 and must \
                 not build in release mode: {code}",
                i + 1
            );
        }
    }

    // The build steps hand on the distribution's flags and add no level.
    let calls: Vec<&str> = arch[pkgbuild_function(&arch, "build")]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with('#') && l.contains("_rustflags"))
        .collect();
    assert_eq!(
        calls,
        ["_rustflags"],
        "build() in {PKGBUILD} must call _rustflags without arguments"
    );
    let flags: Vec<&str> = spec[spec_section(&spec, "%build")]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with('#') && l.to_lowercase().contains("rustflags"))
        .collect();
    assert!(
        flags.len() == 1
            && !flags[0]
                .to_lowercase()
                .replace('_', "-")
                .contains("opt-level"),
        "%build in {SPEC} must set RUSTFLAGS once, without an optimisation level: {flags:?}"
    );
}

/// Runs scripts/check-release-build.sh on the program `sam`.
fn check_release_build(sam: &Path) -> Output {
    let mut cmd = Command::new("sh");
    cmd.arg(root().join("scripts/check-release-build.sh"))
        .arg(sam);
    run(cmd, 60)
}

/// The release stand-in's answer to `config path` (the lines of SAM below
/// its `"config path")` case), as a shell script of its own.
fn stand_in_answer() -> String {
    let answer = SAM
        .split("\"config path\")")
        .nth(1)
        .and_then(|rest| rest.split(";;").next())
        .expect("the release stand-in answers config path");
    format!("#!/bin/sh\n{}\n", answer.trim())
}

/// The release-build check cannot reach the real home folder or the real
/// SAM folders even when the built program is wrong: the program starts in
/// an empty environment, inside a temporary folder of the check's own, with
/// HOME, every XDG folder, TMPDIR and SAM's folder switches pointing into
/// it, and nothing of the caller's environment besides PATH. The folder is
/// gone afterwards.
#[test]
fn the_release_build_check_keeps_the_program_inside_a_temporary_folder() {
    let dir = tempfile::tempdir().unwrap();
    let seen = dir.path().join("seen");
    let program = dir.path().join("release/sam-jail");
    write_exec(
        &program,
        &format!(
            "#!/bin/sh\nenv > '{env}'\npwd > '{pwd}'\n{answer}",
            env = seen.join("env").display(),
            pwd = seen.join("pwd").display(),
            answer = &stand_in_answer()["#!/bin/sh\n".len()..],
        ),
    );
    fs::create_dir_all(&seen).unwrap();
    let mut cmd = Command::new("sh");
    cmd.arg(root().join("scripts/check-release-build.sh"))
        .arg(&program)
        // The caller's own folders and switches: none may reach the program.
        .env("XDG_CONFIG_HOME", dir.path().join("caller-config"))
        .env("XDG_DATA_HOME", dir.path().join("caller-data"))
        .env("XDG_RUNTIME_DIR", dir.path().join("caller-runtime"))
        .env("SAM_CLI", dir.path().join("caller-cli"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("TMPDIR", dir.path());
    let out = run(cmd, 60);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let env = fs::read_to_string(seen.join("env")).unwrap();
    let vars: Vec<(&str, &str)> = env.lines().filter_map(|l| l.split_once('=')).collect();
    let var = |name: &str| -> &str {
        vars.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
            .unwrap_or_else(|| panic!("the program got no {name}:\n{env}"))
    };
    let home = Path::new(var("HOME"));
    let work = home
        .parent()
        .expect("the home folder is below the check's folder");
    assert!(
        work.starts_with(dir.path()) && work != dir.path(),
        "the check's folder {} is not a new folder below TMPDIR",
        work.display()
    );
    for name in [
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_DIRS",
        "XDG_DATA_DIRS",
        "TMPDIR",
        "SAM_CONFIG_DIR",
        "SAM_DATA_DIR",
        "SAM_APPLICATIONS_DIR",
        "SAM_RUNTIME_DIR",
    ] {
        assert!(
            Path::new(var(name)).starts_with(work),
            "{name}={} is outside the check's temporary folder {}",
            var(name),
            work.display()
        );
    }
    // Only these, PATH, the language and what the shell adds itself.
    let allowed = ["HOME", "PATH", "LC_ALL", "PWD", "OLDPWD", "SHLVL", "_"];
    let unexpected: Vec<&str> = vars
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| {
            !allowed.contains(k)
                && !k.starts_with("XDG_")
                && !k.starts_with("SAM_")
                && *k != "TMPDIR"
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "the caller's environment reached the program: {unexpected:?}"
    );
    assert!(
        !env.contains("caller-"),
        "a caller's folder reached the program:\n{env}"
    );
    let pwd = fs::read_to_string(seen.join("pwd")).unwrap();
    assert_eq!(
        Path::new(pwd.trim()),
        work,
        "the program did not start in the check's folder"
    );
    assert!(!work.exists(), "the check left {} behind", work.display());
}

/// The release-build check asks the built program itself, because Cargo
/// takes profile settings from outside the repository too. A program that
/// follows SAM's folder switches (here SAM's real developer build) is
/// refused, as is one that answers with other folders or not at all; a
/// program that ignores them and names the standard folders below the fresh
/// home folder (the release stand-in) passes.
#[test]
fn the_release_build_check_refuses_a_program_that_follows_developer_variables() {
    let out = check_release_build(Path::new(env!("CARGO_BIN_EXE_sam-jail")));
    assert!(
        !out.status.success(),
        "a developer build passed the release-build check:\n{}",
        text(&out.stdout)
    );
    assert!(
        text(&out.stderr).contains("follows SAM's developer variables"),
        "{}",
        text(&out.stderr)
    );

    let dir = tempfile::tempdir().unwrap();
    let release = dir.path().join("release/sam-jail");
    write_exec(&release, SAM);
    let out = check_release_build(&release);
    assert!(
        out.status.success(),
        "the release stand-in was refused:\n{}",
        text(&out.stderr)
    );

    // An answer with another folder, no answer, or no program: refused,
    // never passed without checking.
    let other = dir.path().join("other/sam-jail");
    write_exec(
        &other,
        "#!/bin/sh\nprintf '%-14s %s\\n' config_file \"$HOME/.config/sam/config.toml\" \
         data_dir /var/lib/sam applications \"$HOME/.local/share/applications\"\n",
    );
    let silent = dir.path().join("silent/sam-jail");
    write_exec(&silent, "#!/bin/sh\nexit 0\n");
    let failing = dir.path().join("failing/sam-jail");
    write_exec(&failing, "#!/bin/sh\nexit 1\n");
    // The three folders right, but one more line naming a folder outside
    // the temporary folder, or a line that is not `KEY /path`.
    let outside = dir.path().join("outside/sam-jail");
    write_exec(
        &outside,
        &format!(
            "{}printf '%-14s %s\\n' logs /var/log/sam\n",
            stand_in_answer()
        ),
    );
    let stray = dir.path().join("stray/sam-jail");
    write_exec(
        &stray,
        &format!("{}echo 'warning: something else'\n", stand_in_answer()),
    );
    for (what, program) in [
        ("another data folder", other),
        ("a folder outside the temporary folder", outside),
        ("a line that names no folder", stray),
        ("no answer", silent),
        ("a failing program", failing),
        ("no program", dir.path().join("missing/sam-jail")),
    ] {
        let out = check_release_build(&program);
        assert!(!out.status.success(), "{what} passed the check");
        assert!(
            text(&out.stderr).starts_with("check-release-build: "),
            "{what}: {}",
            text(&out.stderr)
        );
    }
}

/// The release stand-in's answer to `config path` is laid out as the real
/// `sam-jail` lays out its own: the check reads the real program's lines,
/// not only the stand-in's.
#[test]
fn the_release_stand_in_answers_like_the_real_program() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let stand_in = dir.path().join("stand-in/sam-jail");
    write_exec(&stand_in, SAM);
    let answer = |program: &Path| -> Vec<String> {
        let mut cmd = Command::new(program);
        cmd.args(["config", "path"])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("LC_ALL", "C");
        let out = run(cmd, 60);
        assert!(out.status.success(), "{}", text(&out.stderr));
        text(&out.stdout).lines().map(String::from).collect()
    };
    let real = answer(Path::new(env!("CARGO_BIN_EXE_sam-jail")));
    let stand_in = answer(&stand_in);
    assert_eq!(stand_in.len(), 3, "{stand_in:?}");
    for line in &stand_in {
        assert!(
            real.contains(line),
            "the real sam-jail does not answer {line:?}:\n{}",
            real.join("\n")
        );
    }
}

/// Cargo also takes profile settings and compiler flags from outside the
/// repository (the builder's environment, Cargo configuration files in
/// CARGO_HOME or above the source), which no test of the source can read.
/// So every path that builds or uses a program SAM ships or signs asks that
/// program, with scripts/check-release-build.sh, after building it and
/// before the program is shipped, installed or used: the AppImage build (its
/// release tools and the shipped sam-jail), which CI's release workflow runs
/// through `make appimage`, the signing script (before the release key is
/// used), the release script and the build steps of the Arch and Fedora
/// recipes (build() and %build, not their test steps, which builders often
/// skip). Exactly these: the check starts sam-jail, and SAM's own programs
/// never run on the owner's desktop, so no target or script a developer runs
/// there to build for local use (the Makefile's `cli` target above all) runs
/// it.
#[test]
fn release_build_paths_check_the_programs_they_build() {
    const CHECK: &str = "scripts/check-release-build.sh";
    // The file, the program checked, and the lines the check must come
    // after and before.
    let cases = [
        (
            "scripts/make-appimage.sh",
            r#""$tools""#,
            r#"--target-dir "$root/target/appimage-tools" "#,
            r#""$tools" dev "#,
        ),
        (
            "scripts/make-appimage.sh",
            r#""$bin/sam-jail""#,
            r#"--target-dir "$root/target/appimage" "#,
            r#"install -Dm755 "$bin/sam-jail""#,
        ),
        (
            "scripts/sign-release.sh",
            r#""$sam""#,
            r#"sam="$root/target/sign-tools/release/sam-jail""#,
            "gpg ",
        ),
        (
            "scripts/release.sh",
            "target/release/sam-jail",
            "cargo build --release --locked -p sam-jail-cli",
            "target/release/sam-jail man",
        ),
        // The build steps, right after the release build: builders often
        // skip the test steps (makepkg --nocheck, rpmbuild --nocheck), and
        // the check would be skipped with them.
        (
            PKGBUILD,
            "target/release/sam-jail",
            "cargo build --frozen --offline --release ",
            "check() {",
        ),
        (
            SPEC,
            "target/release/sam-jail",
            "cargo build --frozen --offline --release ",
            "%install",
        ),
    ];
    for (file, program, after, before) in cases {
        let raw = fs::read_to_string(root().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let code: Vec<&str> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#') && !l.starts_with("@#"))
            .collect();
        let first = |needle: &str| {
            code.iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{file}: no line with {needle:?}"))
        };
        let (from, to) = (first(after), first(before));
        let checked = (from + 1..to).any(|i| {
            let words: Vec<&str> = code[i].split_whitespace().collect();
            words.iter().any(|w| w.trim_matches('"').ends_with(CHECK)) && words.contains(&program)
        });
        assert!(
            checked,
            "{file}: no `sh {CHECK} {program}` between the line with {after:?} and \
             the line with {before:?}: Cargo settings from outside the repository could \
             turn SAM's developer variables on in that release build unseen"
        );
    }

    // Exactly these files run the check, none other: not the Makefile (its
    // `cli` target is what a developer runs on the desktop), not a test or
    // developer script, not a CI workflow of its own.
    let mut files = vec![root().join("Makefile")];
    for dir in ["scripts", "packaging", "tests", ".github"] {
        files_below(&root().join(dir), &mut files);
    }
    let mut running: Vec<String> = files
        .iter()
        .filter(|f| **f != root().join(CHECK))
        .filter(|f| {
            text(&fs::read(f).unwrap())
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#') && !l.starts_with("@#") && !l.starts_with("//"))
                .any(|l| l.contains("check-release-build"))
        })
        .map(|f| f.strip_prefix(root()).unwrap().display().to_string())
        .collect();
    running.sort();
    assert!(
        !running.iter().any(|f| f == "Makefile"),
        "the Makefile runs {CHECK}: `make cli` and the other targets a developer runs \
         on the desktop must not start SAM's programs; only the paths that build a \
         shipped or signed program run the check"
    );
    assert_eq!(
        running,
        [
            PKGBUILD,
            SPEC,
            "scripts/make-appimage.sh",
            "scripts/release.sh",
            "scripts/sign-release.sh"
        ],
        "the files that run {CHECK} are not exactly the paths that build a shipped or \
         signed program"
    );

    // CI's release workflow builds the shipped AppImages through `make
    // appimage`, which is scripts/make-appimage.sh: the check above covers it.
    let workflow = fs::read_to_string(root().join(".github/workflows/release.yml")).unwrap();
    assert!(
        workflow
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .any(|l| l.contains("make appimage")),
        "the release workflow no longer builds the AppImages with `make appimage`: \
         check that it still runs {CHECK} on the programs it ships"
    );
    let makefile = fs::read_to_string(root().join("Makefile")).unwrap();
    let recipe: Vec<&str> = makefile
        .lines()
        .skip_while(|l| !l.starts_with("appimage:"))
        .skip(1)
        .take_while(|l| l.starts_with('\t'))
        .map(str::trim)
        .collect();
    assert_eq!(
        recipe,
        ["scripts/make-appimage.sh dist"],
        "`make appimage` must be scripts/make-appimage.sh alone, which runs {CHECK}"
    );
}

/// A release build ignores SAM's developer variables (folders and tools),
/// so a test built in release mode would reach the real SAM folders or real
/// tools. One test-only crate, `sam-test-guard`, stops every build without
/// debug assertions; every other crate of the workspace lists it under
/// `[dev-dependencies]`, so its tests cannot be built in release mode, while
/// `cargo build --release` of the shipped programs never compiles it.
#[test]
fn release_test_builds_stop_at_the_test_guard() {
    const GUARD: &str = "sam-test-guard";
    let read = |p: PathBuf| -> toml::Value {
        let text = fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    };
    let names = |v: Option<&toml::Value>| -> Vec<String> {
        v.and_then(|v| v.as_array())
            .expect("the workspace lists its members")
            .iter()
            .map(|m| m.as_str().expect("a member is a path").to_string())
            .collect()
    };
    let workspace = read(root().join("Cargo.toml"));
    let members = names(workspace["workspace"].get("members"));
    let guard_dir = format!("crates/{GUARD}");
    assert!(
        members.contains(&guard_dir),
        "{GUARD} is not a workspace member"
    );
    // A plain `cargo build --release` in the workspace builds the default
    // members: the guard is not one of them, or that build would stop.
    let defaults = names(workspace["workspace"].get("default-members"));
    assert!(
        !defaults.contains(&guard_dir),
        "{GUARD} is a default member: a plain cargo build --release would stop at it"
    );

    // The guard itself: one compile_error under cfg(not(debug_assertions)),
    // and nothing else that could switch the crate off.
    let lib = root().join(&guard_dir).join("src/lib.rs");
    let text = fs::read_to_string(&lib).unwrap_or_else(|e| panic!("{}: {e}", lib.display()));
    let code: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .collect();
    assert!(
        code.first() == Some(&"#[cfg(not(debug_assertions))]")
            && code
                .get(1)
                .is_some_and(|l| l.starts_with("compile_error!("))
            && code.last().is_some_and(|l| l.ends_with(");"))
            && code.iter().filter(|l| l.contains('#')).count() == 1
            && code.iter().filter(|l| l.contains("compile_error!")).count() == 1,
        "{} no longer holds exactly one compile_error! under \
         #[cfg(not(debug_assertions))]:\n{}",
        lib.display(),
        code.join("\n")
    );
    let guard = read(root().join(&guard_dir).join("Cargo.toml"));
    for table in ["dependencies", "build-dependencies"] {
        assert!(guard.get(table).is_none(), "{GUARD} has [{table}]");
    }

    // Every other crate lists the guard as a test-only dependency, and only
    // there: in [dependencies] it would stop the release build of SAM.
    let mut missing = Vec::new();
    let others: Vec<&String> = members.iter().filter(|m| **m != guard_dir).collect();
    assert!(others.len() >= 9, "the workspace lists only {others:?}");
    for member in others {
        let manifest = read(root().join(member).join("Cargo.toml"));
        for table in ["dependencies", "build-dependencies"] {
            assert!(
                manifest.get(table).and_then(|t| t.get(GUARD)).is_none(),
                "{member} lists {GUARD} in [{table}]: only [dev-dependencies] may"
            );
        }
        if manifest
            .get("dev-dependencies")
            .and_then(|t| t.get(GUARD))
            .is_none()
        {
            missing.push(member.as_str());
        }
    }
    assert!(
        missing.is_empty(),
        "these crates do not list {GUARD} in [dev-dependencies], so their tests \
         could be built in release mode, where SAM ignores the variables that \
         keep tests away from the real folders and tools: {missing:?}"
    );
}

/// Unless debug assertions are set explicitly, rustc turns them off at every
/// optimisation level above 0, and the distributions' flags may set one
/// (Fedora's set `-Copt-level=3`). So the test steps of the Arch and Fedora
/// recipes add `-C opt-level=0` after the distribution's flags (the last
/// level wins); without it, a test build of a package may stop at the test
/// guard. On Arch it is a safety net: build() already unsets makepkg's
/// `RUSTFLAGS`, which check() then no longer sees.
#[test]
fn package_test_steps_build_at_optimisation_level_zero() {
    let code = |lines: &[&str]| -> Vec<String> {
        lines
            .iter()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    };
    // The flag lines of a test step, up to its `cargo test`.
    let flags_before_test = |step: &[String], recipe: &str| -> Vec<String> {
        let at = step
            .iter()
            .position(|l| l.starts_with("cargo test"))
            .unwrap_or_else(|| panic!("the test step of {recipe} no longer runs cargo test"));
        step[..at]
            .iter()
            .filter(|l| l.to_lowercase().contains("rustflags"))
            .cloned()
            .collect()
    };

    // Arch: check() hands the flag to _rustflags, which adds its arguments
    // after makepkg's RUSTFLAGS.
    let pkgbuild = recipe_text(PKGBUILD);
    let pkgbuild: Vec<&str> = pkgbuild.lines().collect();
    let function = |name: &str| code(&pkgbuild[pkgbuild_function(&pkgbuild, name)]);
    assert_eq!(
        flags_before_test(&function("check"), "PKGBUILD"),
        ["_rustflags -C opt-level=0"],
        "check() in {PKGBUILD} must build the tests with \
         `_rustflags -C opt-level=0`: makepkg's RUSTFLAGS may set a higher level"
    );
    let helper = function("_rustflags");
    let inherited = helper.iter().position(|l| l.contains("${RUSTFLAGS"));
    let added = helper
        .iter()
        .position(|l| l.starts_with("flags+=(") && l.ends_with("\"$@\")"));
    assert!(
        matches!((inherited, added), (Some(i), Some(a)) if i < a),
        "_rustflags in packaging/arch/PKGBUILD no longer adds its arguments \
         after makepkg's RUSTFLAGS:\n{}",
        helper.join("\n")
    );

    // Fedora: %check sets RUSTFLAGS once, with the level after the
    // distribution's flags.
    let spec = recipe_text(SPEC);
    let spec: Vec<&str> = spec.lines().collect();
    let check = code(&spec[spec_section(&spec, "%check")]);
    assert_eq!(
        flags_before_test(&check, "sam-jail.spec"),
        [r#"export RUSTFLAGS="%{?build_rustflags} -C opt-level=0""#],
        "%check in {SPEC} must build the tests with \
         -C opt-level=0 after %{{build_rustflags}}, which set -Copt-level=3"
    );
}

const TAG: &str = "v1.2.3";
const WORKFLOW: &str = "gitzekatze/SAM/.github/workflows/release.yml";
const APPIMAGE: &str = "SAM-1.2.3-x86_64.AppImage";
const SOURCE: &str = "sam-1.2.3.tar.gz";
const VENDOR: &str = "sam-1.2.3-vendor.tar.xz";
const SBOM: &str = "sam-v1.2.3.spdx.json";

/// GitHub's command line: the draft release is a folder, uploads land in
/// another, and build provenance is a list of "sha256 workflow ref" lines.
/// `gh attestation verify` checks the file's digest and only the
/// constraints it is asked for, as the real one does.
const GH: &str = r#"#!/bin/sh
set -eu
case "$1 $2" in
"release view") echo true ;;
"release download")
    shift 2; dir=
    while [ $# -gt 0 ]; do case "$1" in --dir) dir=$2; shift 2 ;; *) shift ;; esac; done
    cp "$FAKE/draft/"* "$dir/" ;;
"release upload")
    shift 3; mkdir -p "$FAKE/uploaded"
    for f in "$@"; do [ "$f" = --clobber ] || cp "$f" "$FAKE/uploaded/"; done ;;
"attestation verify")
    shift 2; file=$1; shift; wf=; ref=
    while [ $# -gt 0 ]; do
        case "$1" in
            --signer-workflow) wf=$2; shift 2 ;;
            --source-ref) ref=$2; shift 2 ;;
            *) shift ;;
        esac
    done
    sum=$(sha256sum "$file" | cut -d' ' -f1)
    while read -r s w r; do
        [ "$s" = "$sum" ] || continue
        [ -z "$wf" ] || [ "$w" = "$wf" ] || continue
        [ -z "$ref" ] || [ "$r" = "$ref" ] || continue
        exit 0
    done < "$FAKE/attestations"
    echo "no attestation matches $file" >&2; exit 1 ;;
*) echo "gh stand-in: unexpected: $*" >&2; exit 2 ;;
esac
"#;

/// GnuPG with the release key: a detached signature records the checksum
/// of what it signed, and every signed file is written down.
const GPG: &str = r#"#!/bin/sh
case "$*" in
*--list-secret-keys*) exit 0 ;;
*--detach-sign*)
    for f; do :; done
    echo "signed $(sha256sum "$f" | cut -d' ' -f1)" > "$f.asc"
    echo "$f" >> "$FAKE/signed" ;;
*) echo "gpg stand-in: unexpected: $*" >&2; exit 2 ;;
esac
"#;

/// A release build of `sam-jail` with SAM's release tools: its signing and
/// .zsync commands, which the signing script calls, `man`, which the
/// release script calls, and its answer to `config path`, which
/// scripts/check-release-build.sh reads. Like a
/// release build, it ignores SAM's folder switches and names the standard
/// folders below `$HOME`, in the real program's layout
/// (`the_release_stand_in_answers_like_the_real_program`).
const SAM: &str = r#"#!/bin/sh
case "$1 $2" in
"dev sign-appimage") printf 'release-signature' >> "$3" ;;
"dev make-zsync") echo "zsync of $(sha256sum "$3" | cut -d' ' -f1)" > "$3.zsync" ;;
"man "*) ;;
"config path")
    printf '%-14s %s\n' applications "$HOME/.local/share/applications" \
        config_file "$HOME/.config/sam/config.toml" data_dir "$HOME/.local/share/sam" ;;
*) exit 2 ;;
esac
"#;

/// A draft release as the release workflow leaves it, the signing script
/// in a copy of the repository, and the stand-ins.
struct Draft {
    tmp: tempfile::TempDir,
}

impl Draft {
    fn new() -> Draft {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let repo = t.join("repo");
        fs::create_dir_all(repo.join("scripts")).unwrap();
        for script in ["sign-release.sh", "check-release-build.sh"] {
            fs::copy(
                root().join("scripts").join(script),
                repo.join("scripts").join(script),
            )
            .unwrap();
        }
        // The signing tool: a release build with the release tools on
        // (sign-release.sh, owner decision of 2026-11-27).
        write_exec(&repo.join("target/sign-tools/release/sam-jail"), SAM);
        write_exec(&t.join("bin/gh"), GH);
        write_exec(&t.join("bin/gpg"), GPG);
        let draft = t.join("draft");
        fs::create_dir_all(&draft).unwrap();
        for (name, content) in [
            (APPIMAGE, "the AppImage the build made"),
            (
                &format!("{APPIMAGE}.zsync") as &str,
                "zsync of the unsigned file",
            ),
            (
                &format!("{APPIMAGE}.sha256"),
                "0000  SAM-1.2.3-x86_64.AppImage\n",
            ),
            (SOURCE, "source tarball"),
            (VENDOR, "vendored crates"),
            ("SHA256SUMS", "0000  sam-1.2.3.tar.gz\n"),
            (SBOM, "{\"spdxVersion\": \"SPDX-2.3\"}"),
        ] {
            fs::write(draft.join(name), content).unwrap();
        }
        fs::write(t.join("attestations"), "").unwrap();
        let d = Draft { tmp };
        // The checksums release.sh wrote into the package recipe.
        let pkgbuild = format!(
            "pkgver=1.2.3\nsha256sums=('{}'\n            '{}')\n",
            sha256(&draft.join(SOURCE)),
            sha256(&draft.join(VENDOR))
        );
        fs::create_dir_all(repo.join("packaging/arch")).unwrap();
        fs::write(repo.join("packaging/arch/PKGBUILD"), pkgbuild).unwrap();
        d
    }

    fn path(&self, p: &str) -> PathBuf {
        self.tmp.path().join(p)
    }

    /// GitHub's build provenance for a file of the draft, made by the
    /// release workflow from `git_ref`.
    fn attest(&self, name: &str, git_ref: &str) {
        self.attest_by(name, WORKFLOW, git_ref);
    }

    /// Build provenance made by `workflow` (another workflow of the
    /// repository, say) from `git_ref`.
    fn attest_by(&self, name: &str, workflow: &str, git_ref: &str) {
        let line = format!(
            "{} {workflow} {git_ref}\n",
            sha256(&self.path("draft").join(name))
        );
        let mut all = fs::read_to_string(self.path("attestations")).unwrap();
        all.push_str(&line);
        fs::write(self.path("attestations"), all).unwrap();
    }

    /// Every file the release workflow made, attested for this tag.
    fn attest_all(&self) {
        self.attest(APPIMAGE, &format!("refs/tags/{TAG}"));
        self.attest(SBOM, &format!("refs/tags/{TAG}"));
    }

    fn sign(&self) -> Output {
        let mut cmd = Command::new("sh");
        cmd.arg(self.path("repo/scripts/sign-release.sh"))
            .arg(TAG)
            .env("SIGN_KEY", "AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6")
            .env("FAKE", self.tmp.path())
            .env("HOME", self.tmp.path())
            .env("PATH", path_with(&self.path("bin")))
            .current_dir(self.tmp.path());
        run(cmd, 60)
    }

    /// Nothing got the release key, and nothing went back to the draft.
    fn assert_nothing_signed(&self, out: &Output) {
        assert!(
            !out.status.success(),
            "the signing went through:\n{}",
            text(&out.stdout)
        );
        assert!(
            !self.path("signed").exists(),
            "the release key signed: {}",
            fs::read_to_string(self.path("signed")).unwrap_or_default()
        );
        assert!(!self.path("uploaded").exists(), "files went to the draft");
    }
}

/// The release key signs no AppImage that the release build did not make:
/// a draft can be edited by anyone with access, and GitHub's build
/// provenance is what tells a changed file apart (audit P1).
#[test]
fn the_release_key_signs_no_appimage_the_release_build_did_not_make() {
    // The draft's AppImage was replaced: no provenance matches its content;
    // or another workflow of the repository vouches for it, not the
    // release build.
    for other in [None, Some("gitzekatze/SAM/.github/workflows/ci.yml")] {
        let d = Draft::new();
        d.attest(SBOM, &format!("refs/tags/{TAG}"));
        if let Some(workflow) = other {
            d.attest_by(APPIMAGE, workflow, &format!("refs/tags/{TAG}"));
        }
        let out = d.sign();
        d.assert_nothing_signed(&out);
        assert!(
            text(&out.stderr).contains(&format!("{APPIMAGE} is not a file the release build")),
            "{other:?}: {}",
            text(&out.stderr)
        );
    }
}

/// An AppImage that the release build made for an older tag is refused:
/// only provenance from this tag's run counts, so an older, perhaps
/// vulnerable version cannot be signed as the new one (audit P1, a replay).
#[test]
fn an_appimage_built_for_an_older_release_is_not_signed() {
    let d = Draft::new();
    d.attest(APPIMAGE, "refs/tags/v1.2.2");
    d.attest(SBOM, &format!("refs/tags/{TAG}"));
    let out = d.sign();
    d.assert_nothing_signed(&out);
}

/// Only the signing tool signs: a release build with SAM's release tools
/// on (owner decision of 2026-11-27), so signing runs like the shipped
/// program, with developer variables off. With only a developer build or
/// a plain release build present, the script stops before it uses the
/// release key and says how to build the tool; it used to fall back to
/// them.
#[test]
fn only_the_signing_tool_signs_a_release() {
    for other in ["target/debug/sam-jail", "target/release/sam-jail"] {
        let d = Draft::new();
        d.attest_all();
        let dest = d.path("repo").join(other);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::rename(d.path("repo/target/sign-tools/release/sam-jail"), &dest).unwrap();
        let out = d.sign();
        d.assert_nothing_signed(&out);
        assert!(
            text(&out.stderr).contains("build the signing tool first"),
            "{other}: {}",
            text(&out.stderr)
        );
    }
}

/// A signing tool that follows SAM's developer variables, a developer
/// build or a release build whose debug assertions Cargo settings from
/// outside the repository turned on, signs nothing: the script asks the
/// tool before it uses the release key. Here the tool is SAM's real
/// developer build.
#[test]
fn a_signing_tool_that_follows_developer_variables_signs_nothing() {
    let d = Draft::new();
    d.attest_all();
    fs::copy(
        env!("CARGO_BIN_EXE_sam-jail"),
        d.path("repo/target/sign-tools/release/sam-jail"),
    )
    .unwrap();
    let out = d.sign();
    d.assert_nothing_signed(&out);
    let err = text(&out.stderr);
    assert!(
        err.contains("follows SAM's developer variables") && err.contains("nothing signed"),
        "{err}"
    );
}

/// A file someone added to the draft stops the signing: the release key
/// signs only files that were checked or written here, so neither a new
/// file nor a .sha256 without its AppImage gets SAM's signature (audit P1).
#[test]
fn a_file_added_to_a_draft_release_stops_the_signing() {
    for added in ["install-me.sh", "SAM-9.9.9-x86_64.AppImage.sha256"] {
        let d = Draft::new();
        d.attest_all();
        fs::write(d.path("draft").join(added), "added later").unwrap();
        let out = d.sign();
        d.assert_nothing_signed(&out);
        assert!(text(&out.stderr).contains(added), "{}", text(&out.stderr));
    }
}

/// Source tarballs that differ from the ones the maintainer built (their
/// checksums in the PKGBUILD) are refused before anything is signed
/// (audit P13).
#[test]
fn source_files_that_differ_from_the_package_recipe_are_not_signed() {
    let d = Draft::new();
    d.attest_all();
    fs::write(d.path("draft").join(SOURCE), "changed source").unwrap();
    let out = d.sign();
    d.assert_nothing_signed(&out);
    assert!(
        text(&out.stderr).contains("PKGBUILD"),
        "{}",
        text(&out.stderr)
    );
}

/// A draft whose files all check out is signed, and the checksum lists the
/// release key signs are written here from the checked files: a swapped
/// SHA256SUMS or .sha256 in the draft never gets SAM's signature (audit
/// P1).
#[test]
fn a_checked_draft_is_signed_with_its_checksum_lists_written_again() {
    let d = Draft::new();
    d.attest_all();
    let out = d.sign();
    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    let up = d.path("uploaded");
    let appimage = fs::read_to_string(up.join(APPIMAGE)).unwrap();
    assert!(appimage.ends_with("release-signature"), "{appimage}");
    let signed = sha256(&up.join(APPIMAGE));
    assert_eq!(
        fs::read_to_string(up.join(format!("{APPIMAGE}.sha256"))).unwrap(),
        format!("{signed}  {APPIMAGE}\n")
    );
    assert_eq!(
        fs::read_to_string(up.join(format!("{APPIMAGE}.zsync"))).unwrap(),
        format!("zsync of {signed}\n")
    );
    assert_eq!(
        fs::read_to_string(up.join("SHA256SUMS")).unwrap(),
        format!(
            "{}  {SOURCE}\n{}  {VENDOR}\n",
            sha256(&up.join(SOURCE)),
            sha256(&up.join(VENDOR))
        )
    );
    let mut files: Vec<String> = fs::read_dir(&up)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with(".asc"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 7, "{files:?}");
    for f in files {
        assert_eq!(
            fs::read_to_string(up.join(format!("{f}.asc"))).unwrap_or_default(),
            format!("signed {}\n", sha256(&up.join(&f))),
            "{f}: its signature is not for the uploaded file"
        );
    }
}

/// A repository with the base branch's approval checker on `origin`, and a
/// pull request whose own copy of the checker always says yes.
struct Approval {
    tmp: tempfile::TempDir,
}

const BASE_VERIFIER: &str = r#"import os, pathlib, sys
# The real checker reads keeper.toml next to its own folder.
keeper = (pathlib.Path(__file__).resolve().parent.parent / "keeper.toml").read_text().strip()
with open(os.environ["CALLS"], "a") as f:
    f.write("base " + " ".join(sys.argv[1:]) + "\n")
    f.write("keeper " + keeper + "\n")
print("the base branch's verdict")
sys.exit(0 if "--approved" in sys.argv else 1)
"#;

const PR_VERIFIER: &str = r#"import os, sys
with open(os.environ["CALLS"], "a") as f:
    f.write("pull-request " + " ".join(sys.argv[1:]) + "\n")
sys.exit(0)
"#;

fn git(dir: &Path, home: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("GIT_CONFIG_GLOBAL", home.join("gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1");
    let out = run(cmd, 60);
    assert!(out.status.success(), "git {args:?}: {}", text(&out.stderr));
}

fn git_home(home: &Path) {
    fs::write(
        home.join("gitconfig"),
        "[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgSign = false\n[tag]\n\tgpgSign = false\n",
    )
    .unwrap();
}

impl Approval {
    fn new() -> Approval {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        git_home(t);
        git(t, t, &["init", "-q", "--bare", "origin.git"]);
        let work = t.join("work");
        fs::create_dir_all(work.join("scripts")).unwrap();
        git(&work, t, &["init", "-q"]);
        git(&work, t, &["remote", "add", "origin", "../origin.git"]);
        fs::write(work.join("scripts/contract-verifier.py"), BASE_VERIFIER).unwrap();
        fs::write(work.join("keeper.toml"), "[verifier] # the base branch's\n").unwrap();
        git(&work, t, &["add", "-A"]);
        git(&work, t, &["commit", "-q", "-m", "base"]);
        git(&work, t, &["push", "-q", "origin", "main"]);
        git(&work, t, &["checkout", "-q", "-b", "pr"]);
        fs::write(work.join("scripts/contract-verifier.py"), PR_VERIFIER).unwrap();
        // ... and its own settings, which protect nothing.
        fs::write(work.join("keeper.toml"), "# the pull request's\n").unwrap();
        git(&work, t, &["commit", "-q", "-am", "a pull request"]);
        Approval { tmp }
    }

    /// The approval workflow's check for one event: (passed, the checkers
    /// that ran with their arguments).
    fn check(&self, action: &str, labels: &str) -> (bool, String) {
        let t = self.tmp.path();
        let calls = t.join("calls");
        let _ = fs::remove_file(&calls);
        let block = run_block("approval.yml", "What in this change needs the owner");
        let mut cmd = step_command(t, &block);
        cmd.current_dir(t.join("work"))
            .env("BASE", "main")
            .env("ACTION", action)
            .env("LABELS", labels)
            .env("CALLS", &calls)
            .env("GITHUB_STEP_SUMMARY", t.join("summary.md"))
            .env("GIT_CONFIG_GLOBAL", t.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1");
        let out = run(cmd, 60);
        (
            out.status.success(),
            fs::read_to_string(&calls).unwrap_or_default(),
        )
    }
}

/// The owner's label counts only on the event of setting or removing a
/// label, i.e. for the version the owner looked at: after a push, a
/// reopening or on opening, a label still on the pull request is ignored,
/// and a separate job takes it off (audit P3).
#[test]
fn the_owners_label_counts_only_right_after_it_is_set() {
    let a = Approval::new();
    for (action, labels, counts) in [
        ("synchronize", "owner-approved", false),
        ("reopened", "owner-approved", false),
        ("opened", "owner-approved", false),
        ("labeled", "bug,owner-approved", true),
        ("unlabeled", "owner-approved", true),
        ("labeled", "bug", false),
        ("labeled", "owner-approved-later", false),
    ] {
        let (passed, calls) = a.check(action, labels);
        assert_eq!(
            passed, counts,
            "{action} with labels {labels:?}: checker calls:\n{calls}"
        );
        assert_eq!(
            calls.contains("--approved"),
            counts,
            "{action} with labels {labels:?}: {calls}"
        );
    }
    // The job that takes the label off on a push or a reopening.
    let flow = fs::read_to_string(root().join(".github/workflows/approval.yml")).unwrap();
    let job = flow
        .split("\n  forget-approval:\n")
        .nth(1)
        .expect("approval.yml has the forget-approval job");
    let job = job.split("\n  owner-approval:\n").next().unwrap();
    let when = job
        .lines()
        .find_map(|l| l.trim().strip_prefix("if:"))
        .expect("forget-approval runs on a condition");
    for needed in ["'synchronize'", "'reopened'", "'owner-approved'"] {
        assert!(when.contains(needed), "forget-approval if: {when}");
    }
    assert!(
        job.contains("--remove-label owner-approved"),
        "forget-approval does not take the label off:\n{job}"
    );
}

/// The approval check runs the checker, with its settings (keeper.toml), as
/// the base branch has them, never the pull request's own copies: a change
/// cannot rewrite the check that judges it (audit P2, the part a pull
/// request's workflow run can keep).
#[test]
fn the_approval_check_runs_the_base_branchs_checker() {
    let a = Approval::new();
    let (passed, calls) = a.check("synchronize", "");
    assert!(!passed, "the pull request's own checker decided:\n{calls}");
    assert!(calls.starts_with("base origin/main --head HEAD"), "{calls}");
    assert!(!calls.contains("pull-request"), "{calls}");
    assert!(
        calls.contains("keeper [verifier] # the base branch's\n"),
        "the checker read the pull request's keeper.toml:\n{calls}"
    );
}

/// A release whose build fails after the release commit leaves no tag
/// behind: the tag starts the release workflow, so it is set only after
/// everything was built (audit P14).
#[test]
fn a_release_that_fails_to_build_leaves_no_tag() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    git_home(t);
    let repo = t.join("repo");
    for (name, content) in [
        ("Cargo.toml", "[workspace.package]\nversion = \"0.1.0\"\n"),
        (
            "CHANGELOG.md",
            "# Changelog\n\n## Unreleased\n\n### A change\n\n- something\n\n## 0.1.0 - 2026-01-01\n\n- first\n",
        ),
        ("changes/README.md", "# Notes\n"),
        (
            "data/io.github.gitzekatze.SAM.metainfo.xml",
            "<component>\n  <releases>\n  </releases>\n</component>\n",
        ),
        (
            "packaging/fedora/sam-jail.spec",
            "Version:        0.1.0\nRelease:        1%{?dist}\n%changelog\n",
        ),
        (
            "packaging/arch/PKGBUILD",
            "pkgver=0.1.0\npkgrel=1\nsha256sums=('a'\n            'b')\n",
        ),
        ("data/man/sam-jail-run.1", ".TH sam-jail-run 1 \"2026-01-01\"\n"),
        ("data/man/sam-jail-gui.1", ".TH sam-jail-gui 1 \"2026-01-01\"\n"),
        (".gitignore", "target/\ndist/\n"),
    ] {
        let p = repo.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }
    for s in ["release.sh", "changes.py", "check-release-build.sh"] {
        fs::create_dir_all(repo.join("scripts")).unwrap();
        fs::copy(root().join("scripts").join(s), repo.join("scripts").join(s)).unwrap();
    }
    // The build tools: cargo builds a release sam-jail that writes man
    // pages, and `make dist` breaks.
    write_exec(&t.join("release-sam-jail"), SAM);
    write_exec(
        &t.join("bin/cargo"),
        "#!/bin/sh\nif [ \"$1\" = build ]; then mkdir -p target/release; cp \"$RELEASE_SAM\" target/release/sam-jail; fi\nexit 0\n",
    );
    write_exec(&t.join("bin/appstreamcli"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &t.join("bin/make"),
        "#!/bin/sh\necho \"make $*: the build broke\" >&2\nexit 2\n",
    );
    git(&repo, t, &["init", "-q"]);
    git(&repo, t, &["add", "-A"]);
    git(&repo, t, &["commit", "-q", "-m", "0.1.0"]);
    let mut cmd = Command::new("sh");
    cmd.arg("scripts/release.sh")
        .arg("0.2.0")
        .current_dir(&repo)
        .env("UNSIGNED", "1")
        .env("SKIP_TESTS", "1")
        .env("RELEASE_SAM", t.join("release-sam-jail"))
        .env_remove("SIGN_KEY")
        .env_remove("RUNTIME")
        .env("HOME", t)
        .env("GIT_CONFIG_GLOBAL", t.join("gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("PATH", path_with(&t.join("bin")));
    let out = run(cmd, 120);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(!out.status.success(), "the release went through:\n{stdout}");
    assert!(stderr.contains("the build broke"), "{stdout}{stderr}");
    let q = |args: &[&str]| {
        let o = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_GLOBAL", t.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        text(&o.stdout).trim().to_string()
    };
    // It stopped after the release commit, the case this is about.
    assert_eq!(q(&["log", "-1", "--format=%s"]), "Release 0.2.0");
    assert_eq!(q(&["tag", "-l"]), "", "a tag was left behind");
    assert!(stderr.contains("stopped before the tag"), "{stderr}");
}

/// The sandbox tests in the desktop session are judged by cargo's exit
/// status: a run that does not even build prints no "FAILED" and must still
/// fail (audit D-M11).
#[test]
fn a_desktop_test_run_that_does_not_build_fails() {
    for (cargo_test, passes) in [
        (
            "echo 'error[E0425]: cannot find value `x` in this scope'; echo 'error: could not compile `sam-runner`'; exit 101",
            false,
        ),
        ("echo 'test result: ok. 3 passed'; exit 0", true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let run_dir = t.join("run");
        fs::create_dir_all(&run_dir).unwrap();
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _display = std::os::unix::net::UnixListener::bind(run_dir.join("wayland-9")).unwrap();
        write_exec(
            &t.join("bin/cargo"),
            &format!("#!/bin/sh\n[ \"$1\" = test ] || exit 0\n{cargo_test}\n"),
        );
        let mut cmd = Command::new("sh");
        cmd.arg(root().join("tests/gui/desktop-sandbox.sh"))
            .arg(t.join("out"))
            .env("INSIDE", "1")
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env("WAYLAND_DISPLAY", "wayland-9")
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
            .env_remove("SAM_TEST_AUDIO")
            .env("HOME", t)
            .env("PATH", path_with(&t.join("bin")));
        let out = run(cmd, 60);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.success(), passes, "{stdout}{}", text(&out.stderr));
        let result = if passes { "RESULT pass" } else { "RESULT fail" };
        assert!(stdout.contains(result), "{stdout}");
    }
}

/// The website serves its diagram script only when it is exactly the one
/// checked: a changed download stops the build before the site is made
/// (audit P8).
#[test]
fn the_website_is_not_built_with_a_changed_diagram_script() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let built = t.join("site-built");
    write_exec(&t.join("bin/sudo"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &t.join("bin/curl"),
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2 ;; *) shift ;; esac; done\necho 'alert(\"not the checked script\")' > \"$out\"\n",
    );
    write_exec(
        &t.join("bin/python3"),
        &format!("#!/bin/sh\necho \"$*\" > '{}'\n", built.display()),
    );
    let work = t.join("work");
    fs::create_dir_all(&work).unwrap();
    let mut cmd = step_command(t, &run_block("pages.yml", "Build the site"));
    cmd.current_dir(&work)
        .env("PATH", path_with(&t.join("bin")));
    let out = run(cmd, 60);
    assert!(
        !out.status.success(),
        "the build went on:\n{}",
        text(&out.stdout)
    );
    assert!(
        !built.exists(),
        "the site was built with the changed script"
    );
    assert!(
        text(&out.stderr).contains("FAILED") || text(&out.stdout).contains("FAILED"),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
}
