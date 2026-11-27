//! The machinery around SAM: how a release is signed and tagged, how the
//! owner's approval counts, and what the CI scripts let pass (AUTOMATION.md,
//! docs/releasing.md). Each test runs the real script, or the real command
//! of a workflow step, with stand-ins only for what lives on GitHub or needs
//! a person (gh, the release key) and for the build tools around it.
//! The rules every workflow file keeps are checked by
//! scripts/workflow-check.py.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
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

/// SAM's developer variables and test hooks (SAM_CLI, SAM_RUN,
/// SAM_LOCALE_DIR, SAM_DBUS_LOG, SAM_TRUST_TOOLS_IN) work only where debug
/// assertions are on (owner decision 16 of 2026-11-23). A release build
/// with them on would honour every one of them, silently. So the release
/// profile never turns them on, and no packaging recipe, the Makefile or
/// the release scripts turn them on by a flag (`-C debug-assertions`,
/// `--config profile.release.debug-assertions=true`) or a variable
/// (`CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS`).
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
        root().join("scripts/release.sh"),
        root().join(".github/workflows/release.yml"),
    ];
    let before = files.len();
    files_below(&root().join("packaging"), &mut files);
    // The recipes that build SAM with --release are among them: a moved
    // folder must not leave this test checking nothing.
    for recipe in ["packaging/arch/PKGBUILD", "packaging/fedora/sam-jail.spec"] {
        assert!(files.contains(&root().join(recipe)), "{recipe} is gone");
    }
    assert!(files.len() > before + 1);
    for f in &files {
        let text = fs::read_to_string(f)
            .unwrap_or_else(|e| panic!("{}: {e}", f.display()))
            .to_lowercase()
            .replace('_', "-");
        assert!(
            !text.contains("debug-assertions"),
            "{} turns debug assertions on for a release build (or names them): \
             SAM's developer variables would work there",
            f.display()
        );
    }
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

/// SAM's own signing and .zsync commands, which the script calls.
const SAM: &str = r#"#!/bin/sh
case "$1 $2" in
"dev sign-appimage") printf 'release-signature' >> "$3" ;;
"dev make-zsync") echo "zsync of $(sha256sum "$3" | cut -d' ' -f1)" > "$3.zsync" ;;
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
        fs::copy(
            root().join("scripts/sign-release.sh"),
            repo.join("scripts/sign-release.sh"),
        )
        .unwrap();
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
    for s in ["release.sh", "changes.py"] {
        fs::create_dir_all(repo.join("scripts")).unwrap();
        fs::copy(root().join("scripts").join(s), repo.join("scripts").join(s)).unwrap();
    }
    // The build tools: cargo builds a sam-jail that writes man pages, and
    // `make dist` breaks.
    write_exec(
        &t.join("bin/cargo"),
        "#!/bin/sh\nif [ \"$1\" = build ]; then mkdir -p target/release; printf '#!/bin/sh\\nexit 0\\n' > target/release/sam-jail; chmod 755 target/release/sam-jail; fi\nexit 0\n",
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
