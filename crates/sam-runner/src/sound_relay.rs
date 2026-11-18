//! SAM's sound relay: a private PulseAudio server per start, outside the
//! sandbox, that passes the app's sound to the person's PipeWire and lets
//! it play and record, but never load modules (audit S-F1).
//!
//! The sound server's own PulseAudio socket lets every client load modules:
//! an app with only sound on made the sound server outside the sandbox load
//! one (proven 2026-11-18). PipeWire can switch this off only for its whole
//! server, which SAM must not change. So SAM runs a second, small instance
//! of PipeWire's PulseAudio server (`pipewire -c` with SAM's own settings)
//! with module loading off, and shows the sandbox only its socket. It is
//! the same program the person's sound already runs through, connected to
//! their PipeWire as one more client.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use sam_core::HostInfo;

pub struct SoundRelay {
    child: Child,
    /// The relay's PulseAudio socket, for the sandbox.
    pub socket: PathBuf,
}

/// Whether this computer can run SAM's sound relay: PipeWire is installed
/// and running.
pub fn relay_possible(host: &HostInfo) -> bool {
    host.tools.pipewire.is_some() && host.sockets.pipewire.is_some()
}

/// Whether an app with these settings gets sound here: through the relay,
/// or straight from the sound server when the person allowed that.
pub fn sound_reaches_app(p: &sam_core::permissions::AudioPerms, host: &HostInfo) -> bool {
    p.enabled && (relay_possible(host) || (p.direct && host.sockets.pulse.is_some()))
}

/// SAM's settings for the relay: the parts of PipeWire's PulseAudio server
/// that pass sound on, listening on `socket` only, with module loading off,
/// no D-Bus name and none of the modules the normal server loads at start.
pub fn relay_config(socket: &Path) -> String {
    let addr = format!("unix:{}", socket.display())
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!(
        r#"# SAM's sound relay (written for each start).
context.properties = {{ }}
context.spa-libs = {{
    audio.convert.* = audioconvert/libspa-audioconvert
    support.*       = support/libspa-support
}}
context.modules = [
    {{ name = libpipewire-module-protocol-native }}
    {{ name = libpipewire-module-client-node }}
    {{ name = libpipewire-module-adapter }}
    {{ name = libpipewire-module-metadata }}
    {{ name = libpipewire-module-protocol-pulse args = {{ }} }}
]
pulse.properties = {{
    server.address = [ "{addr}" ]
    server.dbus-name = ""
    pulse.allow-module-loading = false
}}
"#
    )
}

impl SoundRelay {
    /// Starts the relay in `runtime_dir/sound` and waits until its socket
    /// accepts connections.
    pub fn start(host: &HostInfo, runtime_dir: &Path) -> Result<SoundRelay> {
        let tool = host.tools.pipewire.as_ref().context(sam_core::i18n::tr(
            "PipeWire is not installed, so SAM cannot run its sound relay",
        ))?;
        let remote = host.sockets.pipewire.as_ref().context(sam_core::i18n::tr(
            "PipeWire is not running, so SAM cannot run its sound relay",
        ))?;
        let dir = runtime_dir.join("sound");
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)?;
        }
        let socket = dir.join("native");
        let _ = std::fs::remove_file(&socket);
        let conf = dir.join("relay.conf");
        sam_core::util::atomic_write(&conf, relay_config(&socket).as_bytes())?;
        let mut cmd = Command::new(&tool.path);
        cmd.arg("-c")
            .arg(&conf)
            .env("PIPEWIRE_REMOTE", remote)
            .env_remove("PULSE_SERVER")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the pre_exec closure runs between fork and exec and calls only prctl, which is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                // Ends together with SAM's launcher.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let mut child = cmd
            .spawn()
            .context(sam_core::i18n::tr("starting SAM's sound relay"))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            if let Some(st) = child.try_wait()? {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "SAM's sound relay ended at its start ({status})",
                        &[("status", &st)]
                    )
                );
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "{}",
                    sam_core::i18n::tr("SAM's sound relay did not open its socket in time")
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(SoundRelay { child, socket })
    }
}

impl Drop for SoundRelay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relay's settings switch module loading off, listen only on SAM's
    /// socket, take no D-Bus name and load no modules at start; a path
    /// cannot break out of its quotes.
    #[test]
    fn the_relay_cannot_load_modules_and_listens_only_on_its_socket() {
        let c = relay_config(Path::new("/run/user/1000/sam/x/sound/native"));
        assert!(c.contains("pulse.allow-module-loading = false"), "{c}");
        assert!(c.contains(r#"server.address = [ "unix:/run/user/1000/sam/x/sound/native" ]"#));
        assert!(c.contains(r#"server.dbus-name = """#));
        assert!(!c.contains("pulse.cmd"), "no modules at start");
        assert!(!c.contains("load-module"));
        let c = relay_config(Path::new("/tmp/a\"b"));
        assert!(c.contains(r#""unix:/tmp/a\"b""#), "{c}");
    }

    /// A stand-in for PipeWire's program at `dir/pipewire` running `body`
    /// (a shell script; it gets SAM's `-c FILE` and ignores it), and a
    /// computer where PipeWire runs.
    fn host_with(dir: &Path, body: &str) -> HostInfo {
        use std::os::unix::fs::PermissionsExt;
        let prog = dir.join("pipewire");
        std::fs::write(&prog, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut h = HostInfo::default();
        h.tools.pipewire = Some(sam_core::host::Tool {
            path: prog,
            version: None,
        });
        h.sockets.pipewire = Some(dir.join("pipewire-0"));
        h
    }

    /// A relay that never opens its socket stops the start's sound within
    /// moments instead of holding the start; one that does is stopped,
    /// and its socket removed, when the start ends.
    #[test]
    fn a_hanging_relay_gives_up_and_a_finished_start_ends_its_relay() {
        let t = tempfile::tempdir().unwrap();
        let h = host_with(t.path(), "exec sleep 30");
        let begin = Instant::now();
        let e = SoundRelay::start(&h, &t.path().join("run"))
            .err()
            .expect("gives up");
        assert!(begin.elapsed() < Duration::from_secs(10), "{e:#}");
        assert!(format!("{e:#}").contains("in time"), "{e:#}");

        // A stand-in that listens where SAM's settings say (the last
        // argument is the settings file; the address is in it).
        let h = host_with(
            t.path(),
            r#"conf="$2"; sock=$(sed -n 's/.*"unix:\(.*\)".*/\1/p' "$conf"); exec python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(); time.sleep(30)' "$sock""#,
        );
        let r = SoundRelay::start(&h, &t.path().join("run2")).expect("starts");
        let socket = r.socket.clone();
        assert!(std::os::unix::net::UnixStream::connect(&socket).is_ok());
        drop(r);
        assert!(!socket.exists(), "socket removed");
        assert!(
            std::os::unix::net::UnixStream::connect(&socket).is_err(),
            "relay ended"
        );
    }

    /// Sound reaches the app through the relay where PipeWire runs; without
    /// PipeWire only when the person allowed sound without the relay.
    #[test]
    fn sound_reaches_the_app_through_the_relay_or_only_when_allowed() {
        let mut h = HostInfo::default();
        let mut p = sam_core::permissions::AudioPerms {
            enabled: true,
            ..Default::default()
        };
        h.sockets.pulse = Some("/run/user/1000/pulse/native".into());
        assert!(!sound_reaches_app(&p, &h), "PulseAudio alone: no relay");
        p.direct = true;
        assert!(sound_reaches_app(&p, &h), "allowed without the relay");
        p.direct = false;
        h.sockets.pipewire = Some("/run/user/1000/pipewire-0".into());
        assert!(!sound_reaches_app(&p, &h), "PipeWire's program missing");
        h.tools.pipewire = Some(sam_core::host::Tool {
            path: "/usr/bin/pipewire".into(),
            version: None,
        });
        assert!(sound_reaches_app(&p, &h));
        p.enabled = false;
        assert!(!sound_reaches_app(&p, &h));
    }
}
