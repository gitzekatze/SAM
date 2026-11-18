//! Quick checks of SAM's contracts with the outside world
//! (docs/contracts.toml): `sam-jail doctor --contracts` and bug reports run
//! them on any computer, so a breakage after an update names the contract
//! and the component version instead of "something broke".
//!
//! Every check only reads: it asks a program for its version or its help,
//! looks for a socket, a file or a kernel feature. Nothing is started that
//! could change the system. Contracts without a quick check are covered by
//! the tests named in the map.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use sam_core::util::which;
use sam_core::HostInfo;

/// The contract map, built into SAM so the checks and the map cannot differ.
const MAP: &str = include_str!("../../../docs/contracts.toml");

#[derive(Debug, Clone, Deserialize)]
struct Map {
    component: Vec<Component>,
    contract: Vec<Contract>,
}

#[derive(Debug, Clone, Deserialize)]
struct Component {
    id: String,
    name: String,
    #[serde(default)]
    program: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Contract {
    id: String,
    component: String,
    assumes: String,
    on_break: String,
    probe: String,
    playbook: String,
}

/// What a quick check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// The assumption holds on this computer.
    Holds,
    /// The component is there, but does not behave as SAM assumes.
    Broken,
    /// The component is not installed (SAM then does what `on_break` says).
    Absent,
    /// Not checkable here (no quick check, or it does not apply to this
    /// session, for example X11 checks in a Wayland-only session).
    NotHere,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractState {
    pub id: String,
    pub component: String,
    pub state: State,
    /// What was found, in a few words (a version, a missing option).
    pub detail: String,
    /// What SAM does when the contract is broken (refuse, safer, warn,
    /// feature, none).
    pub on_break: String,
    pub assumes: String,
    pub playbook: String,
}

/// The version each component reports, for the record of a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentVersion {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractReport {
    pub contracts: Vec<ContractState>,
    pub components: Vec<ComponentVersion>,
}

fn map() -> Map {
    // The map is checked by a test at build time (`the_built_in_contract_map_parses`).
    toml::from_str(MAP).unwrap_or(Map {
        component: Vec::new(),
        contract: Vec::new(),
    })
}

/// The quick checks this module knows; a contract naming another one fails
/// the test `every_contract_probe_is_known`.
pub const PROBES: &[&str] = &[
    "none",
    "bwrap-runs",
    "bwrap-option:",
    "pasta-splice-only",
    "dbus-proxy-present",
    "program:",
    "userns",
    "landlock",
    "seccomp",
    "wayland-socket",
    "wayland-security-context",
    "audio-sockets",
    "dbus-buses",
    "portal-interfaces",
    "x11-socket",
    "fs-layout",
    "name-resolution",
    "dbus-services-dir",
    "gnupg-signer",
];

/// Runs `program args`, returning its output (stdout and stderr) when it ran.
fn output(program: &str, args: &[&str]) -> Option<String> {
    let path = which(program)?;
    let out = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    Some(format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// The version a program reports, as its first line with digits.
fn version_of(program: &str) -> Option<String> {
    // Most tools answer --version; a few use another spelling.
    let args: &[&str] = match program {
        "unsquashfs" => &["-version"],
        "strace" => &["-V"],
        "Xwayland" => &["-version"],
        _ => &["--version"],
    };
    let text = output(program, args)?;
    // The first word that starts with a digit: "bubblewrap 0.13.1" -> 0.13.1,
    // "pasta 2026_10_02.cba3570" -> 2026_10_02.cba3570.
    text.split_whitespace()
        .find(|w| w.starts_with(|c: char| c.is_ascii_digit()))
        .map(|w| {
            w.trim_end_matches([',', ')', ';'])
                .chars()
                .take(40)
                .collect()
        })
}

fn probe(name: &str, host: &HostInfo) -> (State, String) {
    let holds = |d: &str| (State::Holds, d.to_string());
    let broken = |d: String| (State::Broken, d);
    match name {
        "none" => (State::NotHere, "checked by the tests only".into()),
        "bwrap-runs" => match &host.tools.bwrap {
            None => (State::Absent, "bwrap is not installed".into()),
            Some(_) => match crate::doctor::bwrap_functional(host) {
                Ok(()) => holds("a test sandbox starts"),
                Err(e) => broken(e),
            },
        },
        p if p.starts_with("bwrap-option:") => {
            let opt = &p["bwrap-option:".len()..];
            match output("bwrap", &["--help"]) {
                None => (State::Absent, "bwrap is not installed".into()),
                Some(help) if help.contains(opt) => holds(&format!("bwrap knows {opt}")),
                Some(_) => broken(format!("bwrap does not know {opt}")),
            }
        }
        "pasta-splice-only" => {
            if which("pasta").is_none() {
                return (State::Absent, "pasta is not installed".into());
            }
            match crate::netns::pasta_usable() {
                Ok(_) => holds("pasta has --splice-only"),
                Err(e) => broken(format!("{e:#}")),
            }
        }
        "dbus-proxy-present" => match &host.tools.xdg_dbus_proxy {
            Some(_) => holds("installed"),
            None => (State::Absent, "xdg-dbus-proxy is not installed".into()),
        },
        p if p.starts_with("program:") => {
            let prog = &p["program:".len()..];
            match which(prog) {
                Some(_) => holds("installed"),
                None => (State::Absent, format!("{prog} is not installed")),
            }
        }
        "userns" => {
            if host.userns.usable() {
                holds("user namespaces are available")
            } else {
                broken(host.userns.explain())
            }
        }
        "landlock" => match host.landlock_abi {
            Some(abi) => holds(&format!("Landlock ABI {abi}")),
            None => broken("the kernel offers no Landlock".into()),
        },
        "seccomp" => {
            if host.seccomp {
                holds("seccomp filters can be loaded")
            } else {
                broken("the kernel does not allow seccomp filters".into())
            }
        }
        "wayland-socket" => match &host.sockets.wayland {
            Some(_) => holds("the compositor's socket is there"),
            None if host.session_type == "wayland" => {
                broken("a Wayland session without a usable socket".into())
            }
            None => (State::NotHere, "not a Wayland session".into()),
        },
        "wayland-security-context" => match &host.sockets.wayland {
            Some(sock) => {
                if crate::wayland_ctx::supported(sock) {
                    holds("the compositor offers wp_security_context_manager_v1")
                } else {
                    broken("the compositor does not offer security contexts".into())
                }
            }
            None => (State::NotHere, "not a Wayland session".into()),
        },
        "audio-sockets" => {
            if host.sockets.pipewire.is_some() || host.sockets.pulse.is_some() {
                holds("a sound socket is there")
            } else {
                (State::Absent, "no PipeWire or PulseAudio socket".into())
            }
        }
        "dbus-buses" => match (&host.sockets.dbus_session, &host.sockets.dbus_system) {
            (Some(_), Some(_)) => holds("session and system bus"),
            (Some(_), None) => holds("session bus (no system bus)"),
            (None, _) => (State::Absent, "no session bus".into()),
        },
        "portal-interfaces" => portal_interfaces(Path::new("/usr/share/dbus-1/interfaces")),
        "x11-socket" => match (&host.sockets.x11_display, &host.sockets.x11) {
            (Some(_), Some(_)) => holds("the X11 socket is there"),
            (Some(d), None) => broken(format!("DISPLAY={d}, but no socket in /tmp/.X11-unix")),
            (None, _) => (State::NotHere, "no X11 display in this session".into()),
        },
        "fs-layout" => {
            let sh = Path::new("/bin/sh").exists();
            let libs = ["/usr/lib", "/usr/lib64"]
                .iter()
                .any(|d| Path::new(d).is_dir());
            if sh && libs {
                holds("/bin/sh and the libraries under /usr are there")
            } else {
                broken(format!("/bin/sh: {sh}, libraries under /usr: {libs}"))
            }
        }
        "name-resolution" => {
            // openSUSE keeps the vendor default in /usr/etc.
            let nss = ["/etc/nsswitch.conf", "/usr/etc/nsswitch.conf"]
                .into_iter()
                .find(|f| Path::new(f).exists());
            match (Path::new("/etc/hosts").exists(), nss) {
                (true, Some(n)) => holds(&format!("/etc/hosts and {n} are there")),
                _ => broken("/etc/hosts, or nsswitch.conf in /etc or /usr/etc, is missing".into()),
            }
        }
        "dbus-services-dir" => {
            if Path::new("/usr/share/dbus-1/services").is_dir() {
                holds("/usr/share/dbus-1/services is there")
            } else {
                broken(
                    "no /usr/share/dbus-1/services: on-demand services cannot be recognized".into(),
                )
            }
        }
        "gnupg-signer" => {
            if which("gpg").is_none() || which("gpgv").is_none() {
                return (State::Absent, "GnuPG (gpg, gpgv) is not installed".into());
            }
            match sam_detect::signature::gnupg_contract(
                sam_detect::signature::CONTRACT_MSG,
                sam_detect::signature::CONTRACT_SIGNER,
            ) {
                Ok(()) => holds("gpgv names the key that really signed"),
                Err(e) => broken(e),
            }
        }
        other => broken(format!("unknown quick check {other}")),
    }
}

/// Every portal interface SAM may allow must be described by the installed
/// xdg-desktop-portal (one XML file per interface).
pub fn portal_interfaces(dir: &Path) -> (State, String) {
    if !dir.join("org.freedesktop.portal.FileChooser.xml").exists() {
        return (State::Absent, "xdg-desktop-portal is not installed".into());
    }
    let mut all = sam_core::permissions::PermissionSet::default();
    all.devices.webcam = true;
    all.integrations.screen_sharing = true;
    let missing: Vec<&str> = sam_core::permissions::portal_interfaces(&all)
        .into_iter()
        .filter(|i| !dir.join(format!("org.freedesktop.portal.{i}.xml")).exists())
        .collect();
    if missing.is_empty() {
        (
            State::Holds,
            "every interface SAM allows is described".into(),
        )
    } else {
        (
            State::Broken,
            format!("not described: {}", missing.join(", ")),
        )
    }
}

/// Runs every quick check, with the versions of the components involved.
pub fn check_all(host: &HostInfo) -> ContractReport {
    let m = map();
    let contracts = m
        .contract
        .iter()
        .map(|c| {
            let (state, detail) = probe(&c.probe, host);
            ContractState {
                id: c.id.clone(),
                component: c.component.clone(),
                state,
                detail,
                on_break: c.on_break.clone(),
                assumes: c.assumes.clone(),
                playbook: c.playbook.clone(),
            }
        })
        .collect();
    let mut versions: BTreeMap<String, ComponentVersion> = BTreeMap::new();
    for comp in &m.component {
        let version = match comp.id.as_str() {
            "kernel" => Some(host.kernel.clone()),
            "distribution" => Some(host.distro.clone()),
            _ => comp.program.as_deref().and_then(version_of),
        };
        versions.insert(
            comp.id.clone(),
            ComponentVersion {
                id: comp.id.clone(),
                name: comp.name.clone(),
                version,
            },
        );
    }
    ContractReport {
        contracts,
        components: versions.into_values().collect(),
    }
}

/// Named sections for the large sandbox tests (matrix, breakout, hostile
/// AppImages). Each section runs its checks; a failing one is recorded with
/// its name and message, and the next section still runs. `finish` lists
/// every failed section, so a failure names the exact part
/// ("CHECK FAIL network: ...") instead of stopping at the first assertion.
/// The sections share one sandbox setup, so the test stays one test (its
/// steps change the process environment and must not run in parallel).
pub struct Checks {
    test: String,
    failed: Vec<String>,
    passed: Vec<String>,
}

impl Checks {
    pub fn new(test: &str) -> Self {
        Checks {
            test: test.into(),
            failed: Vec::new(),
            passed: Vec::new(),
        }
    }

    pub fn section(&mut self, name: &str, f: impl FnOnce()) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        match result {
            Ok(()) => {
                println!("CHECK ok   {}/{name}", self.test);
                self.passed.push(name.into());
            }
            Err(e) => {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                println!("CHECK FAIL {}/{name}: {msg}", self.test);
                self.failed.push(format!("{name}: {msg}"));
            }
        }
    }

    /// Ok when every section passed; otherwise every failed section.
    pub fn finish(self) -> Result<(), String> {
        if self.failed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} of {} sections failed in {}:\n{}",
                self.failed.len(),
                self.failed.len() + self.passed.len(),
                self.test,
                self.failed.join("\n")
            ))
        }
    }
}

/// A test that does not apply to this computer at all (another processor,
/// a component version SAM itself refuses to use): never a failure, not even
/// in CI, but recorded like a skip, so a run still says it did not run here.
pub fn not_here(reason: &str) {
    eprintln!("not here: {reason}");
    record_skip(&format!("not here: {reason}"));
}

/// For tests that need something from the computer they run on (a working
/// Bubblewrap, kernel headers, a local HTTPS server). Locally a missing
/// requirement skips the test with a note. Where the run must prove
/// everything (CI sets `SAM_REQUIRE_SANDBOX=1`), it is an error instead: a
/// protected test that silently skips would turn a run green without
/// testing anything.
pub fn skip(reason: &str) -> Result<(), String> {
    let required = std::env::var("SAM_REQUIRE_SANDBOX").as_deref() == Ok("1");
    let verdict = judge_skip(required, reason);
    if verdict.is_ok() {
        eprintln!("skipped: {reason}");
        record_skip(reason);
    }
    verdict
}

/// Whether a test may skip: never where a run must prove everything (CI).
fn judge_skip(required: bool, reason: &str) -> Result<(), String> {
    if required {
        Err(format!(
            "this run must not skip (SAM_REQUIRE_SANDBOX=1), but: {reason}"
        ))
    } else {
        Ok(())
    }
}

/// Notes a skipped test in `$SAM_SKIP_LOG` (one line: the test, the
/// reason), so a run can say how many tests did not run instead of passing
/// them silently (`make test` prints the summary).
fn record_skip(reason: &str) {
    if let Some(path) = std::env::var_os("SAM_SKIP_LOG") {
        let test = std::thread::current()
            .name()
            .unwrap_or("a test")
            .to_string();
        record_skip_to(std::path::Path::new(&path), &test, reason);
    }
}

fn record_skip_to(path: &std::path::Path, test: &str, reason: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = std::io::Write::write_all(&mut f, format!("{test}: {reason}\n").as_bytes());
    }
}

/// For the sandbox tests: checks the contracts a test relies on before it
/// runs. A broken contract whose break makes SAM refuse to start a sandbox
/// fails the test at once with the contract's name and playbook ("the
/// outside world changed"), instead of a confusing failure deep inside. A
/// broken contract that SAM handles by falling back (safer, warn, feature)
/// is a normal state the test must check, so it is only noted. The returned
/// guard notes, if the test fails later, that its contracts held, so the
/// failure is in SAM's own code.
pub fn guard(ids: &[&str]) -> Result<Guard, String> {
    guard_with(&check_all(&HostInfo::probe()), ids)
}

/// `guard` with a report given (for testing the guard itself).
pub fn guard_with(report: &ContractReport, ids: &[&str]) -> Result<Guard, String> {
    let mut broken = Vec::new();
    for id in ids {
        match report.contracts.iter().find(|c| c.id == *id) {
            None => return Err(format!("no contract {id} in docs/contracts.toml")),
            Some(c) if c.state == State::Broken && c.on_break != "refuse" => eprintln!(
                "note: contract {} does not hold here ({}); SAM falls back ({}), which this test checks",
                c.id, c.detail, c.on_break
            ),
            Some(c) if c.state == State::Broken => broken.push(format!(
                "CONTRACT BROKEN: {} ({}) -> {}",
                c.id, c.detail, c.playbook
            )),
            Some(_) => {}
        }
    }
    if broken.is_empty() {
        Ok(Guard {
            ids: ids.iter().map(|s| s.to_string()).collect(),
        })
    } else {
        Err(format!(
            "the outside world changed, not SAM:\n{}",
            broken.join("\n")
        ))
    }
}

/// Says, when a test fails after its contracts were checked, that the
/// failure is SAM's own.
pub struct Guard {
    ids: Vec<String>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "SAM ERROR: the contracts this test relies on hold ({}); the failure is in SAM's own code, not in the outside world.",
                self.ids.join(", ")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(probe: &str) -> bool {
        PROBES.iter().any(|p| {
            probe == *p || (p.ends_with(':') && probe.starts_with(p) && probe.len() > p.len())
        })
    }

    /// A skipped test is written to the skip log with its name and reason,
    /// one line each, so a run can report it instead of passing it silently.
    #[test]
    fn a_skipped_test_is_recorded_with_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("skips.log");
        record_skip_to(&log, "verify", "bubblewrap cannot run here");
        record_skip_to(&log, "breakout", "python3 is missing");
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            text,
            "verify: bubblewrap cannot run here\nbreakout: python3 is missing\n"
        );
    }

    #[test]
    fn the_built_in_contract_map_parses() {
        let m: Map = toml::from_str(MAP).unwrap();
        assert!(m.contract.len() > 20, "the map lists the contracts");
    }

    #[test]
    fn every_contract_probe_is_known() {
        for c in map().contract {
            assert!(
                known(&c.probe),
                "contract {}: unknown quick check {}",
                c.id,
                c.probe
            );
        }
    }

    #[test]
    fn a_broken_contract_fails_a_test_with_its_name_and_playbook() {
        let state = |id: &str, state: State| ContractState {
            id: id.into(),
            component: "bubblewrap".into(),
            state,
            detail: "bwrap does not know --disable-userns".into(),
            on_break: if id == "pasta-splice-only" {
                "safer"
            } else {
                "refuse"
            }
            .into(),
            assumes: String::new(),
            playbook: "raise the minimum version".into(),
        };
        let report = ContractReport {
            contracts: vec![
                state("bwrap-core", State::Holds),
                state("bwrap-disable-userns", State::Broken),
                state("dwarfs", State::Absent),
                state("pasta-splice-only", State::Broken),
            ],
            components: Vec::new(),
        };
        let err = guard_with(&report, &["bwrap-core", "bwrap-disable-userns"])
            .err()
            .unwrap();
        assert!(
            err.contains("CONTRACT BROKEN: bwrap-disable-userns"),
            "{err}"
        );
        assert!(
            err.contains("raise the minimum version"),
            "the playbook: {err}"
        );
        assert!(
            guard_with(&report, &["bwrap-core", "dwarfs"]).is_ok(),
            "absent is not broken"
        );
        // An old pasta: SAM falls back to no network, and the test checks that.
        assert!(
            guard_with(&report, &["bwrap-core", "pasta-splice-only"]).is_ok(),
            "a broken contract SAM falls back from does not stop the test"
        );
        assert!(
            guard_with(&report, &["no-such-contract"]).is_err(),
            "a typo is caught"
        );
    }

    #[test]
    fn a_failing_section_is_named_and_the_next_still_runs() {
        let mut c = Checks::new("demo");
        let mut ran = false;
        c.section("first", || panic!("boom"));
        c.section("second", || ran = true);
        assert!(ran, "the second section ran after the first failed");
        let err = c.finish().unwrap_err();
        assert!(
            err.contains("1 of 2 sections failed") && err.contains("first: boom"),
            "{err}"
        );
        let mut ok = Checks::new("demo");
        ok.section("only", || {});
        assert!(ok.finish().is_ok());
    }

    /// Where a run must prove everything (CI), a skip is an error; locally it
    /// is a note. Judged without touching the environment: changing
    /// SAM_REQUIRE_SANDBOX here would switch CI's rule off for every other
    /// test in this process, and a real skip would land in the skip log.
    #[test]
    fn a_required_run_does_not_skip() {
        assert!(
            judge_skip(true, "bubblewrap cannot run here").is_err(),
            "CI must not skip"
        );
        assert!(
            judge_skip(false, "bubblewrap cannot run here").is_ok(),
            "locally a skip is fine"
        );
    }

    #[test]
    fn a_missing_portal_interface_breaks_the_portal_contract() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            portal_interfaces(d.path()).0,
            State::Absent,
            "no portal at all"
        );
        let mut all = sam_core::permissions::PermissionSet::default();
        all.devices.webcam = true;
        all.integrations.screen_sharing = true;
        for i in sam_core::permissions::portal_interfaces(&all) {
            std::fs::write(
                d.path().join(format!("org.freedesktop.portal.{i}.xml")),
                "<node/>",
            )
            .unwrap();
        }
        assert_eq!(portal_interfaces(d.path()).0, State::Holds);
        std::fs::remove_file(d.path().join("org.freedesktop.portal.ScreenCast.xml")).unwrap();
        let (state, detail) = portal_interfaces(d.path());
        assert_eq!(state, State::Broken);
        assert!(detail.contains("ScreenCast"), "{detail}");
    }
}
