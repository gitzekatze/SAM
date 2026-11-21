//! Room service under "This computer only": a room that asks for the
//! network gets no more than its app, which reaches only the ports listed
//! for it. Needs a pasta with --splice-only (SAM never starts "This
//! computer only" without one).
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

mod rooms_common;

use std::net::TcpListener;
use std::process::{Command, Stdio};

use rooms_common::{check, World};
use sam_core::permissions::NetworkMode;

fn pasta_with_splice_only() -> bool {
    Command::new("pasta")
        .arg("--help")
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("--splice-only"))
}

/// Under "This computer only", a room that asks for the network gets an
/// empty network of its own: it reaches no port of the computer (not even
/// one listed for its app) and no socket outside the sandbox.
#[test]
fn under_this_computer_only_a_room_reaches_no_more_than_its_app() {
    if !rooms_common::require() {
        return;
    }
    if !pasta_with_splice_only() {
        sam_runner::contracts::not_here(
            "no pasta with --splice-only, so SAM never starts \"This computer only\" here",
        );
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core", "kernel-seccomp", "pasta-splice-only"])
            .unwrap_or_else(|e| panic!("{e}"));
    let w = World::new();
    // A port listed for the app: the control that its network works.
    let listed = TcpListener::bind("127.0.0.1:0").unwrap();
    let listed_port = listed.local_addr().unwrap().port();
    let id = w.add(
        "RoomLocal",
        &format!(
            r#"
say control "$(rv room -- /usr/bin/echo ok)"
say listed_app "$($P tcp {listed_port})"
say listed_room "$(rv room --share-net -- $P tcp {listed_port})"
say tcp_app "$($P tcp "$PORT")"
say tcp_room "$(rv room --share-net -- $P tcp "$PORT")"
say abstract_app "$($P abstract "$ABSTRACT")"
say abstract_room "$(rv room --share-net -- $P abstract "$ABSTRACT")"
"#
        ),
    );
    let log = w.start(
        &id,
        |p| {
            p.network.mode = NetworkMode::Localhost;
            p.network.host_ports = vec![listed_port.to_string()];
        },
        60,
    );
    // A room that asks for the network gets an empty one of its own here:
    // even the listed port is out of its reach (no more than the app, and
    // here less).
    let failures = check(
        &log,
        &[
            ("control", "ok"),
            ("listed_app", "allowed"),
            ("listed_room", "blocked"),
            ("tcp_app", "blocked"),
            ("tcp_room", "blocked"),
            ("abstract_app", "blocked"),
            ("abstract_room", "blocked"),
        ],
    );
    assert!(failures.is_empty(), "{}\nlog:\n{log}", failures.join("\n"));
}
