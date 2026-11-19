//! "This computer only" with the real thing: an app in its real sandbox
//! listens on its own port and on two ports of well-known local services,
//! and the test reads this computer's listening sockets (/proc/net/tcp and
//! tcp6) to see where SAM's pasta offers them. Skipped where Bubblewrap
//! cannot run; not run where pasta has no --splice-only (SAM then never
//! starts "This computer only").
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn bwrap_works() -> bool {
    Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-user",
            "--unshare-pid",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn pasta_with_splice_only() -> bool {
    Command::new("pasta")
        .arg("--help")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("--splice-only"))
}

fn cmd(root: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .env("LC_ALL", "C");
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    c
}

fn sam(root: &Path, args: &[&str]) -> Output {
    let o = cmd(root, args).stdin(Stdio::null()).output().unwrap();
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

/// Every listening TCP socket on this computer: (address as /proc writes
/// it, port). pasta shields itself (its open files cannot be read from
/// outside), so the test compares this list before and while the app runs.
fn listening() -> BTreeSet<(String, u16)> {
    let mut out = BTreeSet::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for line in fs::read_to_string(table)
            .unwrap_or_default()
            .lines()
            .skip(1)
        {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 || f[3] != "0A" {
                continue;
            }
            let (addr, port) = f[1].split_once(':').unwrap();
            out.insert((addr.to_string(), u16::from_str_radix(port, 16).unwrap()));
        }
    }
    out
}

/// A port between 20000 and the start of this computer's ephemeral range
/// that nothing on this computer listens on.
fn free_port_below_ephemeral() -> u16 {
    let first_ephemeral: u16 = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|r| r.split_whitespace().next()?.parse().ok())
        .unwrap_or(32768);
    let span = first_ephemeral.saturating_sub(20000).max(1);
    let start = (std::process::id() % u32::from(span)) as u16;
    (0..span)
        .map(|i| 20000 + (start + i) % span)
        .find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
        .expect("a free port below the ephemeral range")
}

/// 127.0.0.1 and ::1 as /proc/net/tcp(6) write them (in the byte order of
/// this computer).
fn is_loopback(addr: &str) -> bool {
    let v4 = format!("{:08X}", u32::from_ne_bytes([127, 0, 0, 1]));
    let v6 = format!("{:024X}{:08X}", 0u128, u32::from_ne_bytes([0, 0, 0, 1]));
    addr == v4 || addr == v6
}

#[test]
fn the_apps_ports_are_offered_on_this_computer_only() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    if !pasta_with_splice_only() {
        sam_runner::contracts::not_here(
            "no pasta with --splice-only, so SAM never starts \"This computer only\" here",
        );
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "pasta-splice-only"])
        .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["config", "home"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    // A free port below the "ephemeral" range (from 32768 up, used for
    // outgoing connections), which pasta never forwards: a port picked
    // from 20000-39999 landed there in about a third of all runs.
    let own = free_port_below_ephemeral();
    // Its own port, Chrome's remote debugging port and Ollama's, each on
    // every address inside the sandbox (IPv4 and IPv6 in one socket).
    let script = root.join("apprun");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nexec python3 -c '\nimport socket, time\nkeep = []\nfor port in ({own}, 9222, 11434):\n    s = socket.socket(socket.AF_INET6)\n    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n    s.bind((\"::\", port))\n    s.listen()\n    keep.append(s)\ntime.sleep(60)\n'\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let img = root.join("Server-1.0-x86_64.AppImage");
    let (img_s, script_s) = (img.to_str().unwrap(), script.to_str().unwrap());
    sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            "Server",
            "--apprun",
            script_s,
            img_s,
        ],
    );
    let add = sam(root, &["--json", "add", img_s, "--no-launcher", "--accept"]);
    let v: serde_json::Value = serde_json::from_slice(
        add.stdout
            .split(|b| *b == b'\n')
            .rfind(|l| !l.is_empty())
            .unwrap(),
    )
    .unwrap();
    let id = v["data"]["app"]["id"].as_str().unwrap().to_string();
    sam(root, &["set", &id, "network.mode", "localhost"]);

    let before = listening();
    let mut launcher = cmd(root, &["run", &id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // pasta looks for the app's ports once a second.
    let end = Instant::now() + Duration::from_secs(20);
    let mut seen = BTreeSet::new();
    while Instant::now() < end {
        seen = &listening() - &before;
        if seen.iter().any(|(_, p)| *p == own) {
            // A moment more, so the other ports would have been offered too.
            std::thread::sleep(Duration::from_secs(2));
            seen = &listening() - &before;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = launcher.kill();
    let _ = launcher.wait();

    let log = cmd(root, &["logs", &id, "--kind", "launch"])
        .output()
        .unwrap();
    assert!(
        seen.iter().any(|(_, p)| *p == own),
        "the app's own port was not offered on this computer: {seen:?}\n{}",
        String::from_utf8_lossy(&log.stdout)
    );
    for (addr, port) in seen.iter().filter(|(_, p)| [own, 9222, 11434].contains(p)) {
        assert!(
            is_loopback(addr),
            "port {port} is offered on {addr}, not only on this computer: {seen:?}"
        );
        assert!(
            *port != 9222 && *port != 11434,
            "the app took over the local service port {port}: {seen:?}"
        );
    }
}
