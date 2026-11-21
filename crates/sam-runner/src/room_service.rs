//! Room service: SAM builds a sandbox (a room) for a program inside an
//! app's sandbox that asks for one with Bubblewrap, from outside, under the
//! rule "no more than the app, no less than asked" (`room_rules`).
//!
//! Two sides:
//! - **the stand-in** ([`standin`]), SAM's helper inside the app's sandbox
//!   in place of `bwrap`: it reads Bubblewrap's arguments there, sends the
//!   small fixed form with the program's open connections to the service,
//!   and ends with the room's exit code;
//! - **the service** ([`RoomService`]), part of SAM's launcher for one
//!   start: it trusts nothing the stand-in checked, decides the room from
//!   the app's floor plan, opens every folder beneath the floor-plan folder
//!   that holds it, and starts the computer's Bubblewrap with SAM's helper
//!   inside, which puts SAM's layers in place before anything of the
//!   request runs.
//!
//! Lifetime: a room ends when its stand-in goes (its program ended or was
//! killed), and every room ends with the app's start.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::kernel::{LandlockSpec, SeccompSpec};
use crate::room_rules::{self, AppFacts, FloorPlan, RoomPlan, Source, Step};

/// Where the service listens inside the app's sandbox.
pub const SOCKET_INSIDE: &str = "/run/sam/rooms";
/// At most this many rooms of one app at once; more requests wait.
pub const MAX_ROOMS: usize = 16;
/// At most this many connections being read at once; more are closed.
const MAX_CONNECTIONS: usize = 64;
/// How long a connection may take to send its request.
const READ_LIMIT: Duration = Duration::from_secs(10);

/// What a room's SAM helper gets (as data, never as a file of the
/// computer): SAM's layers, then the program's own filters and its
/// environment, applied last.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomSpec {
    pub landlock: LandlockSpec,
    pub seccomp: SeccompSpec,
    /// Passed connections holding the program's own syscall filters.
    pub filters: Vec<i32>,
    /// The program's environment, exactly.
    pub env: BTreeMap<String, String>,
}

/// What the service needs to know about the app's start.
#[derive(Debug, Clone)]
pub struct RoomContext {
    pub plan: FloorPlan,
    pub facts: AppFacts,
    /// The computer's Bubblewrap (the one SAM checked).
    pub bwrap: PathBuf,
    /// SAM's helper on the computer.
    pub helper: PathBuf,
    /// The app's Landlock rules, as they are or would be with Landlock on.
    pub landlock: LandlockSpec,
    /// SAM's filter for rooms: the app's, never weaker than the baseline,
    /// never allowing nested sandboxes.
    pub seccomp: SeccompSpec,
}

#[derive(Default)]
struct State {
    stop: AtomicBool,
    connections: AtomicUsize,
    slots: Mutex<usize>,
    freed: Condvar,
    rooms: Mutex<Vec<Arc<Mutex<Child>>>>,
    records: Mutex<Vec<String>>,
}

impl State {
    fn record(&self, line: String) {
        if let Ok(mut r) = self.records.lock() {
            r.push(line);
        }
    }
}

/// Room service for one start.
pub struct RoomService {
    pub socket: PathBuf,
    listener: Option<UnixListener>,
    state: Arc<State>,
    accept: Option<JoinHandle<()>>,
}

impl RoomService {
    /// Opens the service's socket in the start's runtime folder (it must
    /// exist before the app's sandbox is built, which shows it).
    pub fn open(runtime_dir: &Path) -> Result<RoomService> {
        let socket = runtime_dir.join("rooms");
        if socket.as_os_str().len() > 107 {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "Room service cannot run: the path for its socket is too long ({path})",
                    &[("path", &socket.display())]
                )
            );
        }
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket)
            .with_context(|| format!("opening Room service's socket {}", socket.display()))?;
        listener.set_nonblocking(true)?;
        Ok(RoomService {
            socket,
            listener: Some(listener),
            state: Arc::new(State::default()),
            accept: None,
        })
    }

    /// Starts serving the app's requests.
    pub fn serve(&mut self, ctx: RoomContext) {
        let Some(listener) = self.listener.take() else {
            return;
        };
        let state = self.state.clone();
        let ctx = Arc::new(ctx);
        self.accept = Some(std::thread::spawn(move || {
            while !state.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if state.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                            state.connections.fetch_sub(1, Ordering::SeqCst);
                            continue; // closed: too many at once
                        }
                        let (state, ctx) = (state.clone(), ctx.clone());
                        std::thread::spawn(move || {
                            serve_one(stream, &state, &ctx);
                            state.connections.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        }));
    }

    /// Ends every room and the service; returns the start record's lines.
    pub fn stop(mut self) -> Vec<String> {
        self.halt();
        let records = self
            .state
            .records
            .lock()
            .map(|r| r.clone())
            .unwrap_or_default();
        records
    }

    fn halt(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        self.state.freed.notify_all();
        if let Some(t) = self.accept.take() {
            let _ = t.join();
        }
        if let Ok(rooms) = self.state.rooms.lock() {
            for r in rooms.iter() {
                if let Ok(mut c) = r.lock() {
                    let _ = c.kill();
                }
            }
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Drop for RoomService {
    fn drop(&mut self) {
        self.halt();
    }
}

fn answer(stream: &mut UnixStream, body: &serde_json::Value) {
    let data = body.to_string().into_bytes();
    let mut msg = (data.len() as u32).to_be_bytes().to_vec();
    msg.extend(data);
    let _ = stream.write_all(&msg);
}

fn program_name(req_command: &[String]) -> String {
    let p = req_command.first().map(String::as_str).unwrap_or("?");
    let name = Path::new(p)
        .file_name()
        .map_or(p.into(), |n| n.to_string_lossy());
    sam_core::util::display_safe(&name, 60)
}

fn serve_one(mut stream: UnixStream, state: &State, ctx: &RoomContext) {
    let refuse = |stream: &mut UnixStream, program: &str, why: &str| {
        state.record(format!(
            "sam-room: refused {program}: {}",
            sam_core::util::display_safe(why, 300)
        ));
        answer(stream, &serde_json::json!({ "error": why }));
    };
    // Only the app's own processes (the same user) reach this socket.
    // SAFETY: getuid has no arguments and cannot fail.
    if peer_uid(&stream) != Some(unsafe { libc::getuid() }) {
        return;
    }
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(READ_LIMIT));
    let (body, fds) = match read_message(&stream) {
        Ok(m) => m,
        Err(why) => return refuse(&mut stream, "?", &why),
    };
    let req = match room_rules::read_request(&body) {
        Ok(r) => r,
        Err(why) => return refuse(&mut stream, "?", &why),
    };
    let program = program_name(&req.command);
    if fds.len() != req.fds.len() {
        return refuse(
            &mut stream,
            &program,
            "the passed connections do not match the request",
        );
    }
    let room = match room_rules::plan_room(&ctx.plan, &req, ctx.facts) {
        Ok(r) => r,
        Err(why) => return refuse(&mut stream, &program, &why),
    };
    // A room slot (waits while 16 rooms run).
    {
        let Ok(mut used) = state.slots.lock() else {
            return;
        };
        while *used >= MAX_ROOMS && !state.stop.load(Ordering::SeqCst) {
            used = match state.freed.wait_timeout(used, Duration::from_millis(200)) {
                Ok((u, _)) => u,
                Err(_) => return,
            };
        }
        if state.stop.load(Ordering::SeqCst) {
            return;
        }
        *used += 1;
    }
    let result = run_room(&mut stream, state, ctx, &req.fds, fds, room, &program);
    if let Ok(mut used) = state.slots.lock() {
        *used -= 1;
    }
    state.freed.notify_one();
    match result {
        Ok(code) => answer(&mut stream, &serde_json::json!({ "exit": code })),
        Err(why) => refuse(&mut stream, &program, &format!("{why:#}")),
    }
}

fn run_room(
    stream: &mut UnixStream,
    state: &State,
    ctx: &RoomContext,
    req_fds: &[i32],
    passed: Vec<OwnedFd>,
    room: RoomPlan,
    program: &str,
) -> Result<i32> {
    let mut handles: Vec<OwnedFd> = Vec::new();
    let mut numbers: Vec<i32> = Vec::new();
    let mut next = 3;
    let mut number = |numbers: &mut Vec<i32>| -> i32 {
        while req_fds.contains(&next) || numbers.contains(&next) {
            next += 1;
        }
        numbers.push(next);
        next
    };
    // The room's fixed base: stricter than any request can ask.
    let mut args: Vec<String> = [
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if room.share_net {
        args.push("--share-net".into());
    }
    for step in &room.steps {
        match step {
            Step::Show {
                source,
                dst,
                writable,
                optional,
            } => {
                let fd = match open_source(source) {
                    Ok(fd) => fd,
                    Err(_) if *optional => continue,
                    Err(e) => bail!("{} cannot be shown: {e}", dst.display()),
                };
                let writable = *writable && !read_only_filesystem(&fd);
                let n = number(&mut numbers);
                args.push(
                    if writable {
                        "--bind-fd"
                    } else {
                        "--ro-bind-fd"
                    }
                    .into(),
                );
                args.push(n.to_string());
                args.push(dst.to_string_lossy().into_owned());
                handles.push(fd);
            }
            Step::Device { src, dst } => {
                args.push("--dev-bind-try".into());
                args.push(src.to_string_lossy().into_owned());
                args.push(dst.to_string_lossy().into_owned());
            }
            Step::Args(a) => args.extend(a.iter().cloned()),
        }
    }
    // SAM's helper and the room's rules (as data).
    let mut landlock = ctx.landlock.clone();
    landlock.write.extend(room.own.iter().cloned());
    let spec = RoomSpec {
        landlock,
        seccomp: ctx.seccomp.clone(),
        filters: room.filters.clone(),
        env: room.env.clone(),
    };
    let data = memfd_with(&serde_json::to_vec(&spec)?)?;
    let n = number(&mut numbers);
    args.extend([
        "--ro-bind-data".into(),
        n.to_string(),
        "/run/sam/room.json".into(),
    ]);
    handles.push(data);
    args.extend([
        "--ro-bind".into(),
        ctx.helper.to_string_lossy().into_owned(),
        "/run/sam/sam-jail-run".into(),
        "--chdir".into(),
        room.chdir.to_string_lossy().into_owned(),
        "--remount-ro".into(),
        "/".into(),
        "--".into(),
        "/run/sam/sam-jail-run".into(),
        "--room-exec".into(),
        "/run/sam/room.json".into(),
        "--".into(),
    ]);
    args.extend(room.command.iter().cloned());

    // Every needed connection at its number in the room, nothing else open.
    let mut map: Vec<(RawFd, RawFd)> = passed
        .iter()
        .zip(req_fds)
        .map(|(fd, n)| (fd.as_raw_fd(), *n))
        .collect();
    map.extend(
        handles
            .iter()
            .zip(&numbers)
            .map(|(fd, n)| (fd.as_raw_fd(), *n)),
    );
    let highest = map.iter().map(|(_, n)| *n).max().unwrap_or(2);
    let mut cmd = Command::new(&ctx.bwrap);
    cmd.args(&args).env_clear();
    // The program's standard streams only when it passed them.
    if !req_fds.contains(&0) {
        cmd.stdin(Stdio::null());
    }
    if !req_fds.contains(&1) {
        cmd.stdout(Stdio::null());
    }
    if !req_fds.contains(&2) {
        cmd.stderr(Stdio::null());
    }
    let mut targets: Vec<RawFd> = map.iter().map(|(_, n)| *n).collect();
    targets.sort_unstable();
    let mut temps: Vec<RawFd> = vec![0; map.len()];
    // SAFETY: only async-signal-safe calls (prctl, fcntl, dup2, close_range)
    // on buffers made before the fork.
    unsafe {
        cmd.pre_exec(move || {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
            // First above every target, then to the target: no connection
            // overwrites another on the way.
            for (i, (src, _)) in map.iter().enumerate() {
                let t = libc::fcntl(*src, libc::F_DUPFD_CLOEXEC, highest + 1);
                if t < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                temps[i] = t;
            }
            for (i, (_, dst)) in map.iter().enumerate() {
                if libc::dup2(temps[i], *dst) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Everything else from 3 on closes when Bubblewrap starts
            // (marked, not closed: Rust reports a failed start through one).
            let mut from: RawFd = 3;
            for t in &targets {
                if *t > from {
                    libc::syscall(
                        libc::SYS_close_range,
                        from as u32,
                        (*t - 1) as u32,
                        CLOSE_RANGE_CLOEXEC,
                    );
                }
                from = from.max(*t + 1);
            }
            libc::syscall(
                libc::SYS_close_range,
                from as u32,
                u32::MAX,
                CLOSE_RANGE_CLOEXEC,
            );
            Ok(())
        });
    }
    let child = cmd.spawn().context("starting Bubblewrap for the room")?;
    drop(passed);
    drop(handles);
    let child = Arc::new(Mutex::new(child));
    if let Ok(mut rooms) = state.rooms.lock() {
        rooms.push(child.clone());
    }
    let mut layers = vec!["landlock", "seccomp"];
    if !room.filters.is_empty() {
        layers.push("the program's own filter");
    }
    let capped = if room.capped.is_empty() {
        String::new()
    } else {
        format!(
            "; capped: {}",
            sam_core::util::display_safe(&room.capped.join(", "), 300)
        )
    };
    state.record(format!(
        "sam-room: built {program} (layers: {}{capped})",
        layers.join(", ")
    ));
    // The stand-in gone (its program ended or was killed): the room ends.
    let watcher = {
        let child = child.clone();
        let mut peer = stream.try_clone()?;
        let _ = peer.set_read_timeout(None);
        std::thread::spawn(move || {
            let mut b = [0u8; 1];
            let _ = peer.read(&mut b);
            if let Ok(mut c) = child.lock() {
                let _ = c.kill();
            }
        })
    };
    let status = loop {
        if let Ok(mut c) = child.lock() {
            if let Some(st) = c.try_wait()? {
                break st;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if let Ok(mut rooms) = state.rooms.lock() {
        rooms.retain(|r| !Arc::ptr_eq(r, &child));
    }
    drop(watcher); // ends when the stand-in closes its end
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}

const CLOSE_RANGE_CLOEXEC: u32 = 4;

/// The opened folder or file a room shows: `top` (a floor-plan folder SAM
/// chose), and `rel` strictly beneath it, through no link leading out and
/// no magic link of /proc.
fn open_source(source: &Source) -> std::io::Result<OwnedFd> {
    let Source::Beneath { top, rel } = source;
    let top_fd = open_path(top)?;
    if rel.as_os_str().is_empty() {
        return Ok(top_fd);
    }
    openat2_beneath(&top_fd, rel)
}

fn open_path(p: &Path) -> std::io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: a valid C string; the result is checked.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a new descriptor of our own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn openat2_beneath(dir: &OwnedFd, rel: &Path) -> std::io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(rel.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: openat2 with a valid descriptor, C string and struct size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a new descriptor of our own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn read_only_filesystem(fd: &OwnedFd) -> bool {
    // SAFETY: fstatvfs on a valid descriptor into a zeroed struct.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        libc::fstatvfs(fd.as_raw_fd(), &mut st) == 0 && st.f_flag & libc::ST_RDONLY != 0
    }
}

fn memfd_with(data: &[u8]) -> Result<OwnedFd> {
    // SAFETY: a static C string; the result is checked.
    let fd = unsafe { libc::memfd_create(c"sam-room".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        bail!("{}", std::io::Error::last_os_error());
    }
    // SAFETY: a new descriptor of our own.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    f.write_all(data)?;
    use std::io::Seek;
    f.seek(std::io::SeekFrom::Start(0))?;
    Ok(OwnedFd::from(f))
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    // SAFETY: ucred is plain integers; all zeros is a valid value.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt into a struct of the right size.
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (r == 0).then_some(cred.uid)
}

/// One receive, keeping the connections that come with it (close-on-exec).
/// Errors when more connections came than a request may pass.
fn recv_with_fds(
    stream: &UnixStream,
    buf: &mut [u8],
    fds: &mut Vec<OwnedFd>,
) -> std::io::Result<usize> {
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(((room_rules::MAX_FDS + 1) * 4) as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: msghdr pointing at live buffers of the given sizes.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    // SAFETY: msg points at the live buffers above, of the sizes given.
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: walking the control messages the kernel wrote.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c) as *const RawFd;
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / 4;
                for i in 0..count {
                    fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 || fds.len() > room_rules::MAX_FDS {
        return Err(std::io::Error::other("too many connections passed"));
    }
    Ok(n as usize)
}

/// A whole message: 4 bytes length, then the request; the connections
/// travel with the first bytes, so every read takes them.
fn read_message(stream: &UnixStream) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
    let mut fds = Vec::new();
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match recv_with_fds(stream, &mut head[got..], &mut fds) {
            Ok(0) => return Err("the request ended early".into()),
            Ok(n) => got += n,
            Err(e) => return Err(format!("reading the request: {e}")),
        }
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > room_rules::MAX_MESSAGE {
        return Err("the request is too large".into());
    }
    let mut body = vec![0u8; len];
    let mut got = 0;
    while got < len {
        match recv_with_fds(stream, &mut body[got..], &mut fds) {
            Ok(0) => return Err("the request ended early".into()),
            Ok(n) => got += n,
            Err(e) => return Err(format!("reading the request: {e}")),
        }
    }
    Ok((body, fds))
}

fn send_with_fds(stream: &UnixStream, data: &[u8], fds: &[RawFd]) -> std::io::Result<()> {
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut control = vec![0u8; space.max(1)];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: msghdr pointing at live buffers of the given sizes.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        // SAFETY: the control buffer has room for one header with every
        // connection number (CMSG_SPACE above).
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr(),
                libc::CMSG_DATA(c) as *mut RawFd,
                fds.len(),
            );
        }
    }
    // SAFETY: msg points at the live buffers above, of the sizes given.
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The rest without connections.
    let mut rest = &data[n as usize..];
    let mut s = stream;
    while !rest.is_empty() {
        let k = s.write(rest)?;
        rest = &rest[k..];
    }
    Ok(())
}

/// The stand-in: `bwrap ARGS…` inside an app's sandbox, served by Room
/// service; `version` is the computer's Bubblewrap version line. Returns
/// the exit code to end with.
pub fn standin(version: &str, argv: &[String]) -> i32 {
    let fail = |msg: &str| -> i32 {
        sam_core::errln!("bwrap: {msg} (SAM's Room service)");
        1
    };
    let (ops, command) = match room_rules::read_bwrap_args(argv) {
        Ok(room_rules::Asked::Version) => {
            sam_core::outln!("{version}");
            return 0;
        }
        Ok(room_rules::Asked::Room { ops, command }) => (ops, command),
        Err(e) => return fail(&e),
    };
    if ops.iter().any(|o| o[0] == "--die-with-parent") {
        // Asked for: the stand-in ends with the program that started it,
        // and the service ends the room then.
        // SAFETY: prctl and getppid have no memory arguments.
        unsafe {
            let parent = libc::getppid();
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
            if libc::getppid() != parent {
                return 1;
            }
        }
    }
    // Every open connection, at its number: the command may expect any of
    // them (glycin's loader gets its channel this way).
    let mut fds: Vec<RawFd> = std::fs::read_dir("/proc/self/fd")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    // SAFETY: F_GETFD only asks whether the number is an open connection.
    fds.retain(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0);
    fds.sort_unstable();
    let stream = match UnixStream::connect(SOCKET_INSIDE) {
        Ok(s) => s,
        Err(e) => return fail(&format!("no Room service here ({e})")),
    };
    fds.retain(|fd| *fd != stream.as_raw_fd());
    if fds.len() > room_rules::MAX_FDS {
        return fail("too many open connections to pass to a room");
    }
    let req = room_rules::Request {
        v: room_rules::VERSION,
        ops,
        flags: Vec::new(),
        command,
        env: std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect(),
        cwd: std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .filter(|p| room_rules::is_clean_absolute(p))
            .unwrap_or_else(|| "/".into()),
        fds: fds.clone(),
    };
    let body = match serde_json::to_vec(&req) {
        Ok(b) => b,
        Err(e) => return fail(&e.to_string()),
    };
    let mut msg = (body.len() as u32).to_be_bytes().to_vec();
    msg.extend(body);
    if let Err(e) = send_with_fds(&stream, &msg, &fds) {
        return fail(&format!("Room service did not take the request ({e})"));
    }
    let mut s = &stream;
    let mut head = [0u8; 4];
    if s.read_exact(&mut head).is_err() {
        return fail("Room service went away");
    }
    let mut body = vec![0u8; (u32::from_be_bytes(head) as usize).min(room_rules::MAX_MESSAGE)];
    if s.read_exact(&mut body).is_err() {
        return fail("Room service went away");
    }
    let ans: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    if let Some(code) = ans.get("exit").and_then(serde_json::Value::as_i64) {
        return code as i32;
    }
    fail(
        ans.get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("the room was refused"),
    )
}
