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
//!
//! PipeWire before 1.2 ignores the setting (CI's Ubuntu 24.04 has 1.0.5:
//! the relay loaded the module). So the relay itself runs in a sandbox of
//! its own: it sees the system's programs, the person's PipeWire socket and
//! its own folder, nothing of the home or SAM's folders, and no network. A
//! module it loads on an older PipeWire loads there, where it can neither
//! read nor write the person's files.

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
/// and running, and Bubblewrap can hold the relay.
pub fn relay_possible(host: &HostInfo) -> bool {
    host.tools.pipewire.is_some() && host.sockets.pipewire.is_some() && host.tools.bwrap.is_some()
}

/// The relay's own sandbox: the system every SAM sandbox rests on
/// ([`sam_sandbox::helper_system_args`], the same view the apps get on every
/// distribution), the person's PipeWire socket, the relay's folder (its
/// settings and its socket), a private `/tmp`; no home, no SAM folders, no
/// network, no devices, a cleared environment.
fn relay_command(
    host: &HostInfo,
    bwrap: &Path,
    program: &Path,
    remote: &Path,
    dir: &Path,
    conf: &Path,
) -> Command {
    #[expect(
        clippy::disallowed_methods,
        reason = "way out: bwrap, the sound relay's sandbox"
    )]
    let mut c = Command::new(bwrap);
    c.args(["--unshare-all", "--die-with-parent", "--new-session"]);
    // Nothing in the relay may make a user namespace of its own: it reads
    // what the app sends, and on PipeWire before 1.2 loads the modules the
    // app asks for. A user namespace would give it full rights over a
    // fresh network namespace, the usual way into kernel bugs (as in the
    // unpack sandboxes, review K-2).
    c.args(["--unshare-user", "--disable-userns"]);
    c.args(["--cap-drop", "ALL", "--clearenv"]);
    c.args(sam_sandbox::helper_system_args(host));
    c.args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]);
    c.arg("--ro-bind").arg(program).arg(program);
    c.arg("--ro-bind").arg(remote).arg(remote);
    c.arg("--bind").arg(dir).arg(dir);
    c.arg("--setenv").arg("PIPEWIRE_REMOTE").arg(remote);
    c.args(["--setenv", "HOME", "/tmp"]);
    c.arg("--").arg(program).arg("-c").arg(conf);
    c
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
        let bwrap = host.tools.bwrap.as_ref().context(sam_core::i18n::tr(
            "Bubblewrap is not installed, so SAM cannot run its sound relay",
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
        // A Unix socket path has at most 107 characters; PipeWire ends with
        // an unclear crash on a longer one.
        if socket.as_os_str().len() > 107 {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "SAM's sound relay cannot run: the path for its socket is too long ({path})",
                    &[("path", &socket.display())]
                )
            );
        }
        let _ = std::fs::remove_file(&socket);
        let conf = dir.join("relay.conf");
        sam_core::util::atomic_write(&conf, relay_config(&socket).as_bytes())?;
        let mut cmd = relay_command(host, &bwrap.path, &tool.path, remote, &dir, &conf);
        cmd.stdin(Stdio::null())
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
        loop {
            #[expect(clippy::disallowed_methods, reason = "way out: the relay's own socket")]
            let connected = std::os::unix::net::UnixStream::connect(&socket);
            if connected.is_ok() {
                break;
            }
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

impl SoundRelay {
    /// Whether the running relay is held in its own sandbox: it sees the
    /// system's programs but not `home` (a module it loads on an older
    /// PipeWire can reach no file of the person's). Looked at from outside,
    /// through each of its processes' view of the file system.
    pub fn contained(&self, home: &Path) -> bool {
        let rel = home.strip_prefix("/").unwrap_or(home);
        let pids = descendants(self.child.id());
        !pids.is_empty()
            && pids.iter().all(|p| {
                let root = PathBuf::from(format!("/proc/{p}/root"));
                root.join("usr").is_dir() && !root.join(rel).exists()
            })
    }
}

/// The processes started by `pid`, children first.
fn descendants(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut todo = vec![pid];
    while let Some(p) = todo.pop() {
        let kids =
            std::fs::read_to_string(format!("/proc/{p}/task/{p}/children")).unwrap_or_default();
        for k in kids
            .split_whitespace()
            .filter_map(|k| k.parse::<u32>().ok())
        {
            out.push(k);
            todo.push(k);
        }
    }
    out
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

    /// The lock check fails a relay that runs outside a sandbox: it sees
    /// the person's folder (mutation run P14: an answer of always "held"
    /// went unnoticed, so `sam-jail doctor` would not see such a relay).
    #[test]
    fn a_relay_outside_a_sandbox_is_not_held() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let r = SoundRelay {
            child,
            socket: t.path().join("native"),
        };
        assert!(!r.contained(&home), "a plain process sees the home");
        // A relay whose program runs as a child (as Bubblewrap starts it):
        // the child sees the home, so it is not held either.
        let child = Command::new("sh")
            .args(["-c", "sleep 30 & wait"])
            .spawn()
            .unwrap();
        let mut parent = SoundRelay {
            child,
            socket: t.path().join("native"),
        };
        let until = Instant::now() + Duration::from_secs(5);
        while descendants(parent.child.id()).is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !descendants(parent.child.id()).is_empty(),
            "the child started"
        );
        assert!(!parent.contained(&home), "a child that sees the home");
        let _ = parent.child.kill();
        let _ = parent.child.wait();
        // Ended: no process left to look at, so it cannot count as held.
        let mut r = r;
        let _ = r.child.kill();
        let _ = r.child.wait();
        assert!(!r.contained(t.path().join("elsewhere").as_path()));
    }

    /// A socket path too long for Linux is refused with a clear reason
    /// before PipeWire starts (it ended with an unclear crash: the 240-app
    /// run of 2026-11-20).
    #[test]
    fn a_too_long_socket_path_is_named_before_the_relay_starts() {
        let t = tempfile::tempdir().unwrap();
        let mut h = host_with(t.path(), "touch \"$0.ran\"; exec sleep 30");
        // Never run: the check comes first.
        h.tools.bwrap = Some(sam_core::host::Tool {
            path: t.path().join("pipewire"),
            version: None,
        });
        let long = t.path().join("r".repeat(120));
        let e = SoundRelay::start(&h, &long).err().expect("refused");
        assert!(format!("{e:#}").contains("too long"), "{e:#}");
        assert!(!t.path().join("pipewire.ran").exists(), "nothing started");
        // The longest path Linux allows (107 characters) gets past the
        // check (and the stand-in fails later, in time).
        let base = t.path().join("run");
        let pad = 107 - base.join("sound/native").as_os_str().len() - 1;
        let exact = base.join("p".repeat(pad));
        assert_eq!(exact.join("sound/native").as_os_str().len(), 107);
        let e = SoundRelay::start(&h, &exact).err();
        assert!(e.is_none_or(|e| !format!("{e:#}").contains("too long")));
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
        h.tools.bwrap = HostInfo::probe().tools.bwrap;
        // The stand-in's PipeWire socket: any file the relay may see.
        let remote = dir.join("pipewire-0");
        std::fs::write(&remote, "").unwrap();
        h.sockets.pipewire = Some(remote);
        h
    }

    /// A relay that never opens its socket stops the start's sound within
    /// moments instead of holding the start; one that does is stopped,
    /// and its socket removed, when the start ends.
    #[test]
    fn a_hanging_relay_gives_up_and_a_finished_start_ends_its_relay() {
        if HostInfo::probe().tools.bwrap.is_none() {
            crate::contracts::skip("bubblewrap is not installed").unwrap_or_else(|e| panic!("{e}"));
            return;
        }
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
        // Held in its own sandbox: a folder next to its own is not there.
        std::fs::create_dir_all(t.path().join("elsewhere")).unwrap();
        assert!(
            r.contained(&t.path().join("elsewhere")),
            "the relay does not see other folders"
        );
        drop(r);
        assert!(!socket.exists(), "socket removed");
        assert!(
            std::os::unix::net::UnixStream::connect(&socket).is_err(),
            "relay ended"
        );
    }

    /// Nothing in the relay's sandbox can make a user namespace: the relay
    /// reads what the app sends and, on PipeWire before 1.2, loads the
    /// modules the app asks for, and its sandbox let it make one (found
    /// while checking review K-2). The stand-in for PipeWire tries and
    /// writes what happened into the relay's folder.
    #[test]
    fn nothing_in_the_sound_relay_can_make_a_user_namespace() {
        let bwrap_ok = HostInfo::probe().tools.bwrap.is_some();
        let outside = Command::new("unshare")
            .args(["--user", "true"])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !(bwrap_ok && outside) {
            // The control: without both, a "refused" would prove nothing.
            crate::contracts::skip("no Bubblewrap, or no user namespaces for ordinary users")
                .unwrap_or_else(|e| panic!("{e}"));
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let h = host_with(
            t.path(),
            r#"d=$(dirname "$2"); if unshare --user true 2>/dev/null; then echo made; else echo refused; fi > "$d/userns"; exit 1"#,
        );
        let run = t.path().join("run");
        let e = SoundRelay::start(&h, &run)
            .err()
            .expect("the stand-in ends");
        let got = std::fs::read_to_string(run.join("sound/userns"))
            .unwrap_or_else(|r| panic!("the stand-in did not run: {r}; {e:#}"));
        assert_eq!(got.trim(), "refused", "the relay made a user namespace");
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
        assert!(
            !sound_reaches_app(&p, &h),
            "no Bubblewrap to hold the relay"
        );
        h.tools.bwrap = Some(sam_core::host::Tool {
            path: "/usr/bin/bwrap".into(),
            version: None,
        });
        assert!(sound_reaches_app(&p, &h));
        p.enabled = false;
        assert!(!sound_reaches_app(&p, &h));
    }
}
