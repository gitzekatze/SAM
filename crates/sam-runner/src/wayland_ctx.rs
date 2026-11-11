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

/// Whether the compositor behind `display` offers security contexts.
pub fn supported(display: &Path) -> bool {
    connect(display).map(|(_, globals, _)| globals.contents().with_list(|l| l.iter().any(|g| g.interface == "wp_security_context_manager_v1"))).unwrap_or(false)
}

/// Creates `<runtime_dir>/wayland-0`, a socket whose clients the compositor
/// treats as the sandboxed app `app_id`. `None` when the compositor does not
/// support security contexts.
pub fn start(display: &Path, runtime_dir: &Path, app_id: &str, instance: &str) -> Result<Option<WaylandContext>> {
    let (_conn, globals, mut queue) = connect(display)?;
    let qh = queue.handle();
    let Ok(manager) = globals.bind::<WpSecurityContextManagerV1, _, _>(&qh, 1..=1, ()) else {
        return Ok(None);
    };
    let socket = runtime_dir.join("wayland-0");
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).with_context(|| format!("creating {}", socket.display()))?;
    let (close_r, close_w) = std::io::pipe().context("creating the close pipe")?;
    let ctx = manager.create_listener(listener.as_fd(), close_r.as_fd(), &qh, ());
    ctx.set_sandbox_engine(ENGINE.into());
    ctx.set_app_id(app_id.into());
    ctx.set_instance_id(instance.into());
    ctx.commit();
    ctx.destroy();
    manager.destroy();
    // The compositor answers a refused context (e.g. SAM itself running in
    // a sandbox) with a protocol error, which the round trip reports.
    queue.roundtrip(&mut State).context("the compositor refused the security context")?;
    // The compositor keeps its own copies of the listening socket and the
    // read end; ours can go.
    drop(listener);
    drop(close_r);
    Ok(Some(WaylandContext { socket, _close: close_w }))
}

type Connected = (Connection, wayland_client::globals::GlobalList, wayland_client::EventQueue<State>);

fn connect(display: &Path) -> Result<Connected> {
    let stream = UnixStream::connect(display).with_context(|| format!("connecting to {}", display.display()))?;
    let conn = Connection::from_socket(stream).context("Wayland connection")?;
    let (globals, queue) = registry_queue_init::<State>(&conn).context("reading the compositor's globals")?;
    Ok((conn, globals, queue))
}

struct State;

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(_: &mut Self, _: &WlRegistry, _: <WlRegistry as wayland_client::Proxy>::Event, _: &GlobalListContents, _: &Connection, _: &QueueHandle<Self>) {}
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
    fn event(_: &mut Self, _: &WpSecurityContextV1, _: <WpSecurityContextV1 as wayland_client::Proxy>::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {}
}
