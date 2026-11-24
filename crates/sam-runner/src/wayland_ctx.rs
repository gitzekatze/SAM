//! Wayland security context (`wp_security_context_v1`).
//!
//! A sandboxed app normally gets the compositor's socket and with it every
//! protocol the compositor offers, including privileged ones: reading the
//! clipboard in the background (`data-control`), capturing the screen
//! (`screencopy`, `image-copy-capture`), virtual keyboards. With a security
//! context, SAM asks the compositor for a socket of its own: clients that
//! connect through it are marked as sandboxed (engine, app id, instance), and
//! the compositor hides privileged protocols from them, as it does for
//! Flatpak apps. KWin, Sway, Hyprland and GNOME 47+ support it.
//!
//! The compositor listens on the socket until the read end of a pipe it got
//! reports a hang-up; [`WaylandContext`] holds the write end for the
//! lifetime of the launch.

use std::io::PipeWriter;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::{Connection, Dispatch, QueueHandle};
use wayland_protocols::wp::security_context::v1::client::wp_security_context_manager_v1::WpSecurityContextManagerV1;
use wayland_protocols::wp::security_context::v1::client::wp_security_context_v1::WpSecurityContextV1;

/// Name SAM gives itself as the sandbox engine.
pub const ENGINE: &str = "io.github.gitzekatze.SAM";

/// A restricted Wayland socket for one launch.
pub struct WaylandContext {
    /// The socket to hand to the sandbox as its Wayland display.
    pub socket: PathBuf,
    /// Dropping it tells the compositor to stop listening.
    _close: PipeWriter,
}

/// How long the compositor may take to answer. Its answers take
/// milliseconds; a compositor that hangs must not hold up the start for
/// ever (audit: the start waited without end).
const ANSWER_LIMIT: Duration = Duration::from_secs(10);

/// Whether the compositor behind `display` offers security contexts.
pub fn supported(display: &Path) -> bool {
    talk(display, ANSWER_LIMIT, |(_, globals, _)| {
        Ok(globals.contents().with_list(|l| {
            l.iter()
                .any(|g| g.interface == "wp_security_context_manager_v1")
        }))
    })
    .unwrap_or(false)
}

/// Creates `<runtime_dir>/wayland-0`, a socket whose clients the compositor
/// treats as the sandboxed app `app_id`. `None` when the compositor does not
/// support security contexts.
pub fn start(
    display: &Path,
    runtime_dir: &Path,
    app_id: &str,
    instance: &str,
) -> Result<Option<WaylandContext>> {
    start_within(display, runtime_dir, app_id, instance, ANSWER_LIMIT)
}

/// [`start`], with the compositor's time to answer given.
fn start_within(
    display: &Path,
    runtime_dir: &Path,
    app_id: &str,
    instance: &str,
    limit: Duration,
) -> Result<Option<WaylandContext>> {
    let (runtime_dir, app_id, instance) = (
        runtime_dir.to_path_buf(),
        app_id.to_string(),
        instance.to_string(),
    );
    talk(display, limit, move |connected| {
        make_context(connected, &runtime_dir, &app_id, &instance)
    })
}

/// Talks to the compositor behind `display` with `work`, for at most
/// `limit`: the Wayland library waits for answers without a limit of its
/// own, so `work` runs beside, and when the time is up the connection is
/// shut, which ends its wait with an error.
fn talk<T: Send + 'static>(
    display: &Path,
    limit: Duration,
    work: impl FnOnce(Connected) -> Result<T> + Send + 'static,
) -> Result<T> {
    let stream = UnixStream::connect(display)
        .with_context(|| format!("connecting to {}", display.display()))?;
    let hang_up = stream.try_clone()?;
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(connected(stream).and_then(work));
    });
    match rx.recv_timeout(limit) {
        Ok(result) => {
            let _ = worker.join();
            result
        }
        Err(_) => {
            let _ = hang_up.shutdown(std::net::Shutdown::Both);
            let _ = worker.join();
            anyhow::bail!(
                "{}",
                sam_core::i18n::trf(
                    "the compositor did not answer within {seconds} seconds",
                    &[("seconds", &limit.as_secs())]
                )
            )
        }
    }
}

/// The security context on a connection to the compositor.
fn make_context(
    (_conn, globals, mut queue): Connected,
    runtime_dir: &Path,
    app_id: &str,
    instance: &str,
) -> Result<Option<WaylandContext>> {
    let qh = queue.handle();
    let Ok(manager) = globals.bind::<WpSecurityContextManagerV1, _, _>(&qh, 1..=1, ()) else {
        return Ok(None);
    };
    let socket = runtime_dir.join("wayland-0");
    let _ = std::fs::remove_file(&socket);
    let listener =
        UnixListener::bind(&socket).with_context(|| format!("creating {}", socket.display()))?;
    let (close_r, close_w) =
        std::io::pipe().context(sam_core::i18n::tr("creating the close pipe"))?;
    let ctx = manager.create_listener(listener.as_fd(), close_r.as_fd(), &qh, ());
    ctx.set_sandbox_engine(ENGINE.into());
    ctx.set_app_id(app_id.into());
    ctx.set_instance_id(instance.into());
    ctx.commit();
    ctx.destroy();
    manager.destroy();
    // The compositor answers a refused context (e.g. SAM itself running in
    // a sandbox) with a protocol error, which the round trip reports.
    queue.roundtrip(&mut State).context(sam_core::i18n::tr(
        "the compositor refused the security context",
    ))?;
    // The compositor keeps its own copies of the listening socket and the
    // read end; ours can go.
    drop(listener);
    drop(close_r);
    Ok(Some(WaylandContext {
        socket,
        _close: close_w,
    }))
}

type Connected = (
    Connection,
    wayland_client::globals::GlobalList,
    wayland_client::EventQueue<State>,
);

fn connected(stream: UnixStream) -> Result<Connected> {
    let conn = Connection::from_socket(stream).context(sam_core::i18n::tr("Wayland connection"))?;
    let (globals, queue) = registry_queue_init::<State>(&conn)
        .context(sam_core::i18n::tr("reading the compositor's globals"))?;
    Ok((conn, globals, queue))
}

struct State;

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: <WlRegistry as wayland_client::Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WpSecurityContextManagerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &WpSecurityContextManagerV1,
        _: <WpSecurityContextManagerV1 as wayland_client::Proxy>::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WpSecurityContextV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &WpSecurityContextV1,
        _: <WpSecurityContextV1 as wayland_client::Proxy>::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Security contexts count as supported only when a compositor says
    /// so: not where there is no compositor, nor where one hangs up
    /// without an answer (mutation run 2026-11-24: an answer of "always
    /// supported" went unnoticed; doctor and the contract check would then
    /// claim support wrongly).
    #[test]
    fn no_compositor_or_no_answer_means_no_security_context() {
        let t = tempfile::tempdir().unwrap();
        assert!(!supported(&t.path().join("wayland-0")), "no compositor");
        let path = t.path().join("wayland-1");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(listener.accept().is_ok());
        });
        assert!(!supported(&path), "a compositor that hangs up");
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(30)),
            Ok(true),
            "SAM asked the compositor"
        );
    }

    /// A compositor that takes the connection and never answers ends the
    /// attempt with an error once the time is up, instead of holding up
    /// the app's start for ever (audit: no time limit). The test waits far
    /// longer than the limit, so a slow computer cannot fail it.
    #[test]
    fn a_compositor_that_never_answers_does_not_hold_up_the_start() {
        let t = tempfile::tempdir().unwrap();
        let display = t.path().join("wayland-hung");
        // Listens, and never says a word.
        let _hung = UnixListener::bind(&display).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let (d, run) = (display.clone(), t.path().to_path_buf());
        std::thread::spawn(move || {
            let r = start_within(&d, &run, "x.desktop", "1", Duration::from_millis(500));
            let _ = tx.send(r.map(|c| c.is_some()).map_err(|e| format!("{e:#}")));
        });
        let got = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the attempt ended within the time limit");
        let e = got.expect_err("no security context from a compositor that never answered");
        assert!(e.contains("did not answer"), "{e}");
    }
}
