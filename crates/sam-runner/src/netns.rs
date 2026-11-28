//! "This computer only" (`network.mode = localhost`) for the Bubblewrap
//! backend. `pasta --splice-only` creates the network namespace and starts
//! Bubblewrap inside it (Bubblewrap then does not create its own). The
//! namespace has only loopback, no route to the internet. pasta forwards:
//! - the app's own listening ports to the host (detected automatically), so
//!   its web page opens in the user's browser;
//! - only the host ports listed in `network.host_ports` into the sandbox
//!   (e.g. 11434 for Ollama). Other local services stay unreachable.
//!
//! (Attaching pasta to a namespace Bubblewrap already created fails with
//! EPERM when pasta isolates itself, so pasta has to be the outer process.)

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use anyhow::{bail, Result};
use sam_core::util::which;
use sam_core::SandboxCommand;

/// The pasta to use for "This computer only", or why there is none.
/// `--splice-only` is what keeps the app off the internet; pasta versions
/// without it (Ubuntu 24.04 ships one) would give the app internet access,
/// so they are not used: the launcher then starts the app with no network at
/// all. Checked once per process.
pub fn pasta_usable() -> Result<PathBuf> {
    static CHECKED: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    let r = CHECKED.get_or_init(|| {
        let pasta = which("pasta").ok_or_else(|| sam_core::i18n::tr("\"This computer only\" needs pasta (package \"passt\"), which is not installed"))?;
        #[expect(clippy::disallowed_methods, reason = "way out: pasta --help")]
        let mut cmd = Command::new(&pasta);
        let help = cmd.arg("--help").stdin(Stdio::null()).output().map_err(|e| format!("cannot run {}: {e}", pasta.display()))?;
        let text = format!("{}{}", String::from_utf8_lossy(&help.stdout), String::from_utf8_lossy(&help.stderr));
        if !text.contains("--splice-only") {
            return Err("'This computer only' needs a newer pasta (package 'passt'): the installed one has no --splice-only, which is what keeps the app off the internet. Update passt, or choose 'No network' or 'Full network' for this app".into());
        }
        Ok(pasta)
    });
    match r {
        Ok(p) => Ok(p.clone()),
        Err(e) => bail!("{e}"),
    }
}

/// Ports an app must never take over on the host's loopback when its ports
/// are detected automatically: privileged ports and local services whose
/// clients would talk to the app instead (and hand it passwords, keys or
/// control). An app that needs one of them gets it only when the person
/// lists it in `network.app_ports`.
const NEVER_FORWARD_FROM_APP: &[&str] = &[
    "~1-1023",
    "~1234",
    "~3306",
    "~5432",
    "~5984",
    "~6379",
    "~8384",
    "~9090",
    "~11211",
    "~11434",
    "~27017",
    // Proxies and anonymity: SOCKS, Privoxy, Tor.
    "~1080",
    "~8118",
    "~9050-9051",
    "~9150-9151",
    // The desktop: X11 over TCP, PulseAudio, VNC, KDE Connect, Barrier and
    // Synergy, MPD, Discord's local control, Steam, Dropbox, Syncthing.
    "~6000-6063",
    "~4713",
    "~5900-5910",
    "~1714-1764",
    "~24800",
    "~6600",
    "~6463-6472",
    "~27036-27037",
    "~17500",
    "~22000",
    // Remote control of programs: Chrome/Electron DevTools, Node.js
    // inspector, Android debugging, Docker, Kubernetes, Remote Desktop.
    "~9222",
    "~9229",
    "~5037",
    "~2375-2376",
    "~6443",
    "~3389",
    // Databases, queues and secret stores beyond the first ones.
    "~1433",
    "~1521",
    "~1883",
    "~8883",
    "~2379-2380",
    "~4369",
    "~5672",
    "~7687",
    "~8086",
    "~8200",
    "~8500",
    "~9200",
    "~9300",
    "~9100",
    "~2049",
];

/// Where pasta listens on the host for the app's ports: this computer's
/// loopback addresses only. Without them pasta listens on every address,
/// and the port shows up to anyone scanning the network (audit L-F7). ::1
/// only where the loopback has it: pasta cannot listen on a missing
/// address.
fn listen_addresses() -> Vec<&'static str> {
    let ipv6 = std::fs::read_to_string("/proc/net/if_inet6").is_ok_and(|t| has_ipv6_loopback(&t));
    if ipv6 {
        vec!["127.0.0.1", "::1"]
    } else {
        vec!["127.0.0.1"]
    }
}

/// Whether `/proc/net/if_inet6` lists ::1 on the loopback.
fn has_ipv6_loopback(if_inet6: &str) -> bool {
    if_inet6.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.first() == Some(&"00000000000000000000000000000001") && f.last() == Some(&"lo")
    })
}

/// pasta arguments: `app_ports` from the app to the host (empty = automatic
/// with exclusions), listening on `addresses` only; `host_ports` from the
/// host into the sandbox.
pub fn pasta_args(host_ports: &[u16], app_ports: &[u16], addresses: &[&str]) -> Vec<String> {
    let join = |v: &[u16]| v.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let to_host = if host_ports.is_empty() {
        "none".to_string()
    } else {
        join(host_ports)
    };
    let from_app = if app_ports.is_empty() {
        format!("auto,{}", NEVER_FORWARD_FROM_APP.join(","))
    } else {
        join(app_ports)
    };
    let mut args: Vec<String> = vec!["--quiet".into(), "--splice-only".into()];
    for a in addresses {
        args.push("-t".into());
        args.push(format!("{a}/{from_app}"));
    }
    for s in ["-T", &to_host, "-u", "none", "-U", "none"] {
        args.push(s.to_string());
    }
    args
}

/// Run `cmd` inside a pasta loopback-only network namespace.
pub fn wrap_localhost(
    cmd: &mut SandboxCommand,
    host_ports: &[u16],
    app_ports: &[u16],
) -> Result<()> {
    let pasta = pasta_usable()?;
    let mut args = pasta_args(host_ports, app_ports, &listen_addresses());
    args.push("--".into());
    args.push(cmd.program.to_string_lossy().into_owned());
    args.append(&mut cmd.args);
    cmd.program = pasta;
    cmd.args = args;
    cmd.notes.push(format!(
        "this computer only (pasta --splice-only): no internet, no DNS; host ports reachable: {}",
        if host_ports.is_empty() {
            "none".to_string()
        } else {
            host_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With "this computer only", the app reaches only the ports on this computer the user lists.
    #[test]
    fn only_listed_host_ports() {
        let a = pasta_args(&[], &[], &["127.0.0.1"]);
        assert_eq!(a[a.iter().position(|x| x == "-T").unwrap() + 1], "none");
        assert!(
            a[a.iter().position(|x| x == "-t").unwrap() + 1].starts_with("127.0.0.1/auto,~1-1023")
        );
        let a = pasta_args(&[11434, 1234], &[8080], &["127.0.0.1"]);
        assert_eq!(
            a[a.iter().position(|x| x == "-T").unwrap() + 1],
            "11434,1234"
        );
        assert_eq!(
            a[a.iter().position(|x| x == "-t").unwrap() + 1],
            "127.0.0.1/8080"
        );
    }

    /// The app's ports are offered on this computer's loopback addresses
    /// only, for IPv4 and IPv6 alike, never on every address (audit L-F7).
    #[test]
    fn the_apps_ports_listen_on_loopback_only() {
        let a = pasta_args(&[], &[8080, 9000], &["127.0.0.1", "::1"]);
        let specs: Vec<&String> = a
            .iter()
            .enumerate()
            .filter(|(i, _)| *i > 0 && a[i - 1] == "-t")
            .map(|(_, s)| s)
            .collect();
        assert_eq!(specs, ["127.0.0.1/8080,9000", "::1/8080,9000"]);
        for spec in pasta_args(&[], &[], &listen_addresses())
            .iter()
            .filter(|s| s.contains("auto"))
        {
            assert!(
                spec.starts_with("127.0.0.1/") || spec.starts_with("::1/"),
                "{spec}"
            );
        }
        let lo = "00000000000000000000000000000001 01 80 10 80       lo\n";
        let eth = "fe800000000000000000000000000001 02 40 20 80   enp1s0\n";
        assert!(has_ipv6_loopback(&format!("{eth}{lo}")));
        assert!(!has_ipv6_loopback(eth));
        assert!(!has_ipv6_loopback(""));
        // Both are needed: ::1 on another device, or another address on the
        // loopback, is not it (mutation run P14).
        let one_elsewhere = "00000000000000000000000000000001 05 80 10 80     tun0\n";
        let other_on_lo = "fe800000000000000000000000000001 01 40 20 80       lo\n";
        assert!(!has_ipv6_loopback(&format!("{one_elsewhere}{other_on_lo}")));
    }

    /// Local services whose clients would hand an app control or secrets
    /// are never taken over automatically.
    #[test]
    fn well_known_local_services_are_never_taken_over() {
        let auto = &pasta_args(&[], &[], &["127.0.0.1"])[3];
        for port in [
            22, 631, 9222, 9229, 6000, 4713, 5900, 9050, 2375, 11434, 3389, 1716,
        ] {
            let excluded = auto
                .split(',')
                .filter_map(|e| e.strip_prefix('~'))
                .any(|r| {
                    let (a, b) = r.split_once('-').unwrap_or((r, r));
                    (a.parse::<u16>().unwrap()..=b.parse::<u16>().unwrap()).contains(&port)
                });
            assert!(excluded, "port {port} can be taken over: {auto}");
        }
    }
}
