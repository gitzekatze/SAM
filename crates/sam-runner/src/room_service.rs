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
//!   the app's floor plan, shows every place from the source SAM opened
//!   when the app started (never found by name later), and starts the
//!   computer's Bubblewrap with SAM's room helper inside, which puts SAM's
//!   layers in place before anything of the request runs and confirms them.
//!
//! Lifetime: a room ends when its stand-in goes (its program ended or was
//! killed), and every room ends with the app's start. A stand-in asked to
//! quit (SIGTERM, as SAM asks an app's processes at Close and at logout)
//! passes it on: the program in its room is asked too and gets the same
//! time to save as the app, and the stand-in keeps waiting for its room.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::kernel::{LandlockSpec, SeccompSpec};
use crate::room_rules::{self, AppFacts, DeviceAccess, Entry, FloorPlan, RoomPlan, Source, Step};

/// Where the service listens inside the app's sandbox.
pub const SOCKET_INSIDE: &str = "/run/sam/rooms";
/// What a stand-in sends, after its request, when it is asked to quit: the
/// service then asks its room's program to quit ([`RoomProcess::ask_to_quit`]).
/// Anything else after the request, or the connection's end, ends the room.
const QUIT_ASK: u8 = b'q';
/// The stand-in (`bwrap` in SAM's helper folder, first on the app's PATH)
/// is a link to SAM's helper at this place inside the app's sandbox. No
/// script and no shell in between: a shell can leave its script's file
/// open in the program it starts (dash, /bin/sh on Debian and Ubuntu, does
/// once 10 or more files are open), and the stand-in passes every open
/// file to the room, so the room would get one its program never had.
pub const STANDIN_TARGET: &str = "/run/sam/sam-jail-run";
/// The name the stand-in is started under, as Bubblewrap is.
pub const STANDIN_NAME: &str = "bwrap";
/// The file beside the stand-in that holds the computer's Bubblewrap
/// version line, which the stand-in answers to `--version`.
pub const STANDIN_VERSION_FILE: &str = "bwrap.version";
/// SAM's helper folder inside the app's sandbox, holding the stand-in.
const STANDIN_FOLDER_INSIDE: &str = "/run/sam/bin";
/// At most this many rooms of one app at once; more requests wait.
pub const MAX_ROOMS: usize = 16;
/// At most this many connections open at once (requests being read and
/// rooms running); more are closed and recorded.
pub const MAX_CONNECTIONS: usize = 64;
/// At most this many passed connections held by the service at once, from
/// the first byte read until the room has started (a request beyond it is
/// refused). Everything held for rooms also stays within what the
/// launcher's own descriptor limit leaves free (`State::fd_budget`).
pub const MAX_HELD: usize = 512;
/// At most this many places of the app in one room.
const MAX_PLACES: usize = 2000;
/// Descriptors the launcher keeps free for itself and for the connections
/// (each holds its own, and a second one while its room runs).
const FD_RESERVE: usize = 128 + 2 * MAX_CONNECTIONS;
/// At most this many descriptors held for rooms at once, whatever the limit.
const MAX_SERVICE_FDS: usize = 16 * 1024;
/// SAM's own descriptors for one room while it is set up (its helper, the
/// status pipe, the filter, the rules, the watcher's connection, and what
/// starting Bubblewrap opens for a moment).
const ROOM_FDS: usize = 12;
/// How long a room waits for the descriptors it needs while rooms being
/// built before it hold them. A build holds them only from counting until
/// Bubblewrap has started (milliseconds, under a second on a busy
/// computer), and at most 16 rooms are built at once, so even one build at
/// a time leaves every room its turn well within this. Longer only when
/// the descriptors are held by connections of requests that themselves
/// wait, which no wait frees: then the room is refused, never left waiting
/// for good (the stop of the service ends the wait at once anyway).
const ROOM_FD_WAIT: Duration = Duration::from_secs(30);
/// At most this many refusals in one start record (the rest counted).
const MAX_RECORDS: usize = 200;
/// At most this many lines about rooms built or failed (kept apart).
const MAX_ROOM_RECORDS: usize = 500;
/// How long a connection may take to send its request.
const READ_LIMIT: Duration = Duration::from_secs(10);
/// SAM's room helper and the room's rules inside a room (room_rules::RESERVED).
const HELPER_INSIDE: &str = "/.sam-room/sam-room-exec";
const SPEC_INSIDE: &str = "/.sam-room/room.spec";

/// SAM's room helper (room-exec/main.rs, built statically by build.rs):
/// it starts inside a layout the request shapes, so it needs no loader and
/// no library. Empty when this build could not make it.
const ROOM_HELPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sam-room-exec"));

/// Whether an ELF program asks for a loader (a PT_INTERP program header).
pub fn needs_loader(elf: &[u8]) -> bool {
    let u16_at = |i: usize| {
        elf.get(i..i + 2)
            .map(|b| u16::from_ne_bytes([b[0], b[1]]) as usize)
    };
    let u64_at = |i: usize| {
        elf.get(i..i + 8)
            .and_then(|b| b.try_into().ok())
            .map(|b| u64::from_ne_bytes(b) as usize)
    };
    let (Some(phoff), Some(size), Some(count)) = (u64_at(0x20), u16_at(0x36), u16_at(0x38)) else {
        return true;
    };
    if !elf.starts_with(b"\x7fELF") || elf.get(4) != Some(&2) {
        return true;
    }
    (0..count).any(|k| {
        let at = phoff + k * size;
        elf.get(at..at + 4)
            .is_none_or(|t| u32::from_ne_bytes([t[0], t[1], t[2], t[3]]) == 3)
    })
}

/// What the service needs to know about the app's start.
#[derive(Debug, Clone)]
pub struct RoomContext {
    pub plan: FloorPlan,
    pub facts: AppFacts,
    /// The computer's Bubblewrap (the one SAM checked).
    pub bwrap: PathBuf,
    /// The app's Landlock rules, as they are or would be with Landlock on.
    pub landlock: LandlockSpec,
    /// SAM's filter for rooms: the app's, never weaker than the baseline,
    /// never allowing nested sandboxes.
    pub seccomp: SeccompSpec,
}

/// The context with the floor plan's sources, opened once when the app
/// started: a room shows exactly these, whatever the app renames later.
struct Served {
    ctx: RoomContext,
    sources: Vec<Option<SourceHandle>>,
    /// Set when no room can be built this start (shown in every refusal).
    refuse_all: Option<String>,
}

#[derive(Default)]
struct State {
    stop: AtomicBool,
    connections: AtomicUsize,
    /// Passed connections held (at most MAX_HELD).
    held: AtomicUsize,
    /// Every descriptor held for rooms: passed connections, places, SAM's
    /// own (at most `fd_budget`).
    fds: AtomicUsize,
    /// What the launcher's descriptor limit leaves free for rooms.
    fd_budget: AtomicUsize,
    /// Rooms whose own descriptors are counted and not yet given back
    /// (being built): they give them back moments later.
    building: AtomicUsize,
    /// Rooms waiting for descriptors, in the order they asked.
    fd_queue: Mutex<FdQueue>,
    /// Woken when descriptors held for rooms are given back, and at the stop.
    fds_freed: Condvar,
    /// One receive at a time: each reserves room for the most connections
    /// a request may pass and gives back what did not come, so requests
    /// read at the same moment never take each other's room.
    receiving: Mutex<()>,
    slots: Mutex<usize>,
    freed: Condvar,
    rooms: Mutex<Vec<Arc<Mutex<RoomProcess>>>>,
    records: Mutex<Vec<String>>,
    dropped_records: AtomicUsize,
    /// Rooms built or failed: kept apart, so refusals cannot push them out.
    room_records: Mutex<Vec<String>>,
    dropped_room_records: AtomicUsize,
}

/// The line of rooms waiting for descriptors: each takes a number.
#[derive(Default)]
struct FdQueue {
    next: u64,
    /// Each waiting room's number and how many descriptors it needs.
    waiting: std::collections::VecDeque<(u64, usize)>,
    /// Requests being read that wait for the rooms being built (no new
    /// room is built meanwhile).
    readers: usize,
}

/// Why a room got no descriptors for its places.
#[derive(Debug, PartialEq)]
enum NoRoom {
    /// More than the whole budget, even with nothing else held.
    Never,
    /// The app's start ended while it waited.
    Stopped,
    /// Its wait ran out.
    TimedOut,
}

impl State {
    /// Wakes the rooms waiting for descriptors (some were given back, or
    /// the service stops). Under the line's lock: a waiter looks and starts
    /// waiting under it, so it never misses this.
    fn wake_fd_waiters(&self) {
        let _line = self.fd_queue.lock().unwrap_or_else(|e| e.into_inner());
        self.fds_freed.notify_all();
    }

    /// The service stops: everything waiting ends now.
    fn stop_now(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.freed.notify_all();
        self.wake_fd_waiters();
    }

    /// A room built or failed (at most MAX_ROOM_RECORDS; the rest counted).
    fn record_room(&self, line: String) {
        if let Ok(mut r) = self.room_records.lock() {
            if r.len() < MAX_ROOM_RECORDS {
                r.push(line);
                return;
            }
        }
        self.dropped_room_records.fetch_add(1, Ordering::SeqCst);
    }

    /// A refusal (at most MAX_RECORDS; the rest counted).
    fn record(&self, line: String) {
        if let Ok(mut r) = self.records.lock() {
            if r.len() < MAX_RECORDS {
                r.push(line);
                return;
            }
        }
        self.dropped_records.fetch_add(1, Ordering::SeqCst);
    }
}

/// Descriptors one request holds, counted until released: passed
/// connections against [`MAX_HELD`], and everything against the budget
/// the launcher's own limit leaves free. Counted before they are taken,
/// so the launcher never runs out of descriptors.
struct Held<'a> {
    state: &'a State,
    passed: usize,
    all: usize,
    /// Counted among the rooms being built (`State::building`).
    building: bool,
}

/// Takes up to `want` of what `max` leaves in `counter`; how many it got.
fn take_up_to(counter: &AtomicUsize, want: usize, max: usize) -> usize {
    let mut cur = counter.load(Ordering::SeqCst);
    loop {
        let n = want.min(max.saturating_sub(cur));
        match counter.compare_exchange(cur, cur + n, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return n,
            Err(now) => cur = now,
        }
    }
}

impl<'a> Held<'a> {
    fn new(state: &'a State) -> Self {
        Held {
            state,
            passed: 0,
            all: 0,
            building: false,
        }
    }
    /// Reserves room for up to `want` passed connections; how many.
    fn reserve_passed(&mut self, want: usize) -> usize {
        let st = self.state;
        let n = take_up_to(&st.held, want, MAX_HELD);
        let m = take_up_to(&st.fds, n, st.fd_budget.load(Ordering::SeqCst));
        st.held.fetch_sub(n - m, Ordering::SeqCst);
        self.passed += m;
        self.all += m;
        m
    }
    /// Like `reserve_passed`; but when rooms being built hold part of what
    /// it wants, waits (until `end`) for them to give it back first, and no
    /// new room is built meanwhile: a request is never refused for
    /// descriptors held only for moments. What is left then is what it
    /// gets (what other requests' connections leave).
    fn reserve_passed_waiting(&mut self, want: usize, end: Instant) -> usize {
        let got = self.reserve_passed(want);
        if got == want {
            return got;
        }
        self.unreserve_passed(got);
        let st = self.state;
        let mut line = st.fd_queue.lock().unwrap_or_else(|e| e.into_inner());
        line.readers += 1;
        while st.building.load(Ordering::SeqCst) > 0 && !st.stop.load(Ordering::SeqCst) {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            line = match st.fds_freed.wait_timeout(line, left) {
                Ok((l, _)) => l,
                Err(e) => e.into_inner().0,
            };
        }
        // Under the line's lock: no room is counted in between. The rooms
        // waiting meanwhile are woken when the reading gives back what did
        // not come (`unreserve_passed`, right after the receive).
        let got = self.reserve_passed(want);
        line.readers -= 1;
        got
    }
    /// Gives back `n` reserved passed connections that did not come.
    fn unreserve_passed(&mut self, n: usize) {
        self.state.held.fetch_sub(n, Ordering::SeqCst);
        self.state.fds.fetch_sub(n, Ordering::SeqCst);
        self.passed -= n;
        self.all -= n;
        self.state.wake_fd_waiters();
    }
    /// Counts `n` more of SAM's own descriptors; false (nothing counted)
    /// when the budget has no room for all of them.
    fn add_own(&mut self, n: usize) -> bool {
        let st = self.state;
        // All or nothing: a room trying again while it waits never takes
        // part of the budget for a moment from a request being read.
        let max = st.fd_budget.load(Ordering::SeqCst);
        let mut cur = st.fds.load(Ordering::SeqCst);
        loop {
            let Some(all) = cur.checked_add(n).filter(|all| *all <= max) else {
                return false;
            };
            match st
                .fds
                .compare_exchange(cur, all, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    self.all += n;
                    return true;
                }
                Err(now) => cur = now,
            }
        }
    }
    /// Counts `n` of SAM's own descriptors for a room being built, waiting
    /// up to `limit` while other rooms hold them: rooms being built give
    /// theirs back as soon as their room has started. Rooms wait in line,
    /// so a big room is not passed again and again by small ones; only
    /// while nothing is being built and the first in line does not fit now
    /// (then nothing it waits for comes back soon) may a later room that
    /// fits go first. A room that cannot fit even with nothing else held
    /// is refused at once.
    fn wait_for_own(&mut self, n: usize, limit: Duration) -> Result<(), NoRoom> {
        let st = self.state;
        // What this request holds already counts too: it stays held.
        if n.saturating_add(self.all) > st.fd_budget.load(Ordering::SeqCst) {
            return Err(NoRoom::Never);
        }
        let end = Instant::now() + limit;
        let mut line = st.fd_queue.lock().unwrap_or_else(|e| e.into_inner());
        let ticket = line.next;
        line.next += 1;
        line.waiting.push_back((ticket, n));
        let got = loop {
            if st.stop.load(Ordering::SeqCst) {
                break Err(NoRoom::Stopped);
            }
            // Never while a request being read waits for the rooms built.
            // A later room goes before the first in line only when that
            // one cannot go now either: when it fits, it goes first (it
            // was woken by the same giving back), else a steady stream of
            // small rooms could keep a big one waiting until its time ran
            // out.
            let turn = line.readers == 0
                && line.waiting.front().is_some_and(|&(first, need)| {
                    first == ticket
                        || (st.building.load(Ordering::SeqCst) == 0
                            && st.fds.load(Ordering::SeqCst).saturating_add(need)
                                > st.fd_budget.load(Ordering::SeqCst))
                });
            if turn && self.add_own(n) {
                // Counted under the line's lock, so no other room sees
                // nothing being built while this one is.
                st.building.fetch_add(1, Ordering::SeqCst);
                self.building = true;
                break Ok(());
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err(NoRoom::TimedOut);
            }
            line = match st.fds_freed.wait_timeout(line, left) {
                Ok((l, _)) => l,
                Err(e) => e.into_inner().0,
            };
        };
        // The next in line is woken when this request gives back what it
        // holds (`release`, at the latest when it is dropped).
        line.waiting.retain(|(t, _)| *t != ticket);
        got
    }
    fn release(&mut self) {
        let st = self.state;
        st.held.fetch_sub(self.passed, Ordering::SeqCst);
        st.fds.fetch_sub(self.all, Ordering::SeqCst);
        if self.building {
            st.building.fetch_sub(1, Ordering::SeqCst);
        }
        self.passed = 0;
        self.all = 0;
        self.building = false;
        st.wake_fd_waiters();
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.release();
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
        if ROOM_HELPER.is_empty() || needs_loader(ROOM_HELPER) {
            bail!(
                "{}",
                sam_core::i18n::tr(
                    "this SAM was built without its static room helper, so Room service is off"
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

    /// Starts serving the app's requests. Opens the floor plan's sources
    /// now, before the app runs: a room shows what the app was shown.
    pub fn serve(&mut self, mut ctx: RoomContext) {
        let (plan, sources) = plan_at_start(std::mem::take(&mut ctx.plan));
        ctx.plan = plan;
        self.run(Served {
            ctx,
            sources,
            refuse_all: None,
        });
    }

    /// Keeps the socket the app's sandbox shows, but refuses every request
    /// (when no floor plan could be read this start).
    pub fn serve_refusing(&mut self, ctx: RoomContext, why: String) {
        self.run(Served {
            ctx,
            sources: Vec::new(),
            refuse_all: Some(why),
        });
    }

    fn run(&mut self, served: Served) {
        let Some(listener) = self.listener.take() else {
            return;
        };
        let budget = fd_budget();
        self.state.fd_budget.store(budget, Ordering::SeqCst);
        if budget < 64 {
            self.state.record(format!(
                "sam-room: the launcher's descriptor limit leaves {budget} for rooms, so most rooms are refused"
            ));
        }
        let state = self.state.clone();
        let served = Arc::new(served);
        let spawned = std::thread::Builder::new()
            .name("sam-rooms".into())
            .spawn(move || {
                while !state.stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if state.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                                state.connections.fetch_sub(1, Ordering::SeqCst);
                                state.record(format!(
                                    "sam-room: refused ? (asked by {}): more than {MAX_CONNECTIONS} requests and rooms at once",
                                    asked_by(&stream)
                                ));
                                continue; // closed
                            }
                            let (st, sv) = (state.clone(), served.clone());
                            let started = std::thread::Builder::new()
                                .name("sam-room".into())
                                .spawn(move || {
                                    serve_one(stream, &st, &sv);
                                    st.connections.fetch_sub(1, Ordering::SeqCst);
                                });
                            if started.is_err() {
                                state.connections.fetch_sub(1, Ordering::SeqCst);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(20)),
                    }
                }
            });
        self.accept = spawned.ok();
    }

    /// Ends every room and the service; returns the start record's lines.
    pub fn stop(mut self) -> Vec<String> {
        self.halt();
        // Requests still being read, waiting for a slot or with a room
        // ending now record themselves; a short wait lets them, and any
        // left after it are counted.
        let end = std::time::Instant::now() + Duration::from_secs(2);
        while self.state.connections.load(Ordering::SeqCst) > 0 && std::time::Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        let left = self.state.connections.load(Ordering::SeqCst);
        if left > 0 {
            self.state.record(format!(
                "sam-room: {left} requests still unfinished when the app's start ended"
            ));
        }
        let st = &self.state;
        let mut records = st
            .room_records
            .lock()
            .map(|r| r.clone())
            .unwrap_or_default();
        let dropped = st.dropped_room_records.load(Ordering::SeqCst);
        if dropped > 0 {
            records.push(format!("sam-room: {dropped} more rooms not recorded"));
        }
        records.extend(st.records.lock().map(|r| r.clone()).unwrap_or_default());
        let dropped = st.dropped_records.load(Ordering::SeqCst);
        if dropped > 0 {
            records.push(format!("sam-room: {dropped} more refusals not recorded"));
        }
        records
    }

    fn halt(&mut self) {
        self.state.stop_now();
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

/// The floor plan as it is when the app starts, with its sources opened
/// now: a place whose source does not exist now is not in the app either
/// (Bubblewrap skips such `-try` places), so it leaves the plan and
/// neither shows nor covers anything in a room. Device places are checked
/// the same way: one that appears later is never looked up by its name.
fn plan_at_start(plan: FloorPlan) -> (FloorPlan, Vec<Option<SourceHandle>>) {
    use std::os::unix::fs::MetadataExt;
    let fixed: Vec<u64> = [
        Some(PathBuf::from("/")),
        std::env::var_os("HOME").map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.dev()))
    .collect();
    plan_at_start_with(plan, |p, dev| may_be_unmounted(p, dev, &fixed))
}

/// Whether Bubblewrap at `bwrap` can build rooms: it must show places by
/// handle (`--bind-fd`, `--ro-bind-fd`, Bubblewrap 0.10 or a backport).
/// Without them no room could be built, and programs keep the computer's
/// own Bubblewrap as before Room service. Asked once per start.
pub fn bwrap_builds_rooms(bwrap: &Path) -> bool {
    std::process::Command::new(bwrap)
        .arg("--help")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok_and(|o| {
            let help = String::from_utf8_lossy(&o.stdout);
            help.contains("--ro-bind-fd") && help.contains("--bind-fd")
        })
}

/// Drives a person may want to unmount while the app runs: anything not
/// on the file system of the root or of the home (a second disk, a stick,
/// a network or FUSE mount), and anything under /media, /mnt, /run/media.
/// A source there is remembered by what it is, not held open (an open
/// handle in the launcher would keep the drive busy).
fn may_be_unmounted(p: &Path, dev: u64, fixed: &[u64]) -> bool {
    !fixed.contains(&dev)
        || ["/media/", "/mnt/", "/run/media/"]
            .iter()
            .any(|d| p.to_string_lossy().starts_with(d))
}

/// A floor-plan source as the service keeps it from the app's start.
pub(crate) enum SourceHandle {
    /// Held open (O_PATH): shown by this handle, whatever is renamed.
    Open(OwnedFd),
    /// On a drive that may be unmounted: what it was (device and inode),
    /// opened again for a room and refused unless it is still the same.
    Known { path: PathBuf, dev: u64, ino: u64 },
}

fn plan_at_start_with(
    mut plan: FloorPlan,
    removable: impl Fn(&Path, u64) -> bool,
) -> (FloorPlan, Vec<Option<SourceHandle>>) {
    let mut sources = Vec::new();
    let mut entries = Vec::new();
    for e in std::mem::take(&mut plan.entries) {
        match e.source() {
            Some(p) => {
                if let Ok(fd) = open_path(p) {
                    let Ok((dev, ino)) = identity(&fd) else {
                        continue;
                    };
                    let handle = if removable(p, dev) {
                        SourceHandle::Known {
                            path: p.to_path_buf(),
                            dev,
                            ino,
                        }
                    } else {
                        SourceHandle::Open(fd)
                    };
                    sources.push(Some(handle));
                    entries.push(e);
                }
            }
            None => {
                if let Entry::Dev { src, .. } = &e {
                    if std::fs::symlink_metadata(src).is_err() {
                        continue;
                    }
                }
                sources.push(None);
                entries.push(e);
            }
        }
    }
    plan.entries = entries;
    (plan, sources)
}

fn answer(stream: &mut UnixStream, body: &serde_json::Value) {
    let data = body.to_string().into_bytes();
    let mut msg = (data.len() as u32).to_be_bytes().to_vec();
    msg.extend(data);
    send_quietly(stream, &msg);
}

/// Sends all of `data`, never raising SIGPIPE: a stand-in that has
/// already gone must not end SAM's launcher (`sam-jail run` restores
/// SIGPIPE's default, which ends the process).
fn send_quietly(stream: &UnixStream, data: &[u8]) {
    let mut sent = 0;
    while sent < data.len() {
        // SAFETY: a live buffer of the given length.
        let n = unsafe {
            libc::send(
                stream.as_raw_fd(),
                data[sent..].as_ptr().cast(),
                data.len() - sent,
                libc::MSG_NOSIGNAL,
            )
        };
        if n > 0 {
            sent += n as usize;
            continue;
        }
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return; // the stand-in left (EPIPE) or the connection failed
    }
}

fn program_name(req_command: &[String]) -> String {
    let p = req_command.first().map(String::as_str).unwrap_or("?");
    let name = Path::new(p)
        .file_name()
        .map_or(p.into(), |n| n.to_string_lossy());
    sam_core::util::display_safe(&name, 60)
}

fn serve_one(mut stream: UnixStream, state: &State, served: &Served) {
    // Only the app's own processes (the same user) reach this socket.
    // SAFETY: getuid has no arguments and cannot fail.
    if peer_uid(&stream) != Some(unsafe { libc::getuid() }) {
        return;
    }
    let by = asked_by(&stream);
    let refuse = |stream: &mut UnixStream, program: &str, why: &str| {
        state.record(format!(
            "sam-room: refused {program} (asked by {by}): {}",
            sam_core::util::display_safe(why, 300)
        ));
        answer(stream, &serde_json::json!({ "error": why }));
    };
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(READ_LIMIT));
    let mut held = Held::new(state);
    let (body, fds) = match read_message(&stream, &mut held) {
        Ok(m) => m,
        Err(why) => return refuse(&mut stream, "?", &why),
    };
    let req = match room_rules::read_request(&body) {
        Ok(r) => r,
        Err(why) => return refuse(&mut stream, "?", &why),
    };
    let program = program_name(&req.command);
    if let Some(why) = &served.refuse_all {
        return refuse(&mut stream, &program, why);
    }
    if fds.len() != req.fds.len() {
        return refuse(
            &mut stream,
            &program,
            "the passed connections do not match the request",
        );
    }
    let room = match room_rules::plan_room(&served.ctx.plan, &req, served.ctx.facts) {
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
            drop(used);
            return refuse(
                &mut stream,
                &program,
                "the app's start ended before the room was built",
            );
        }
        *used += 1;
    }
    let result = run_room(&mut stream, state, served, &req, fds, held, room, &program);
    if let Ok(mut used) = state.slots.lock() {
        *used -= 1;
    }
    state.freed.notify_one();
    match result {
        Ok(code) => answer(&mut stream, &serde_json::json!({ "exit": code })),
        Err(why) => refuse(&mut stream, &program, &format!("{why:#}")),
    }
    // The room's watcher (waiting on this connection) ends now too.
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

#[allow(clippy::too_many_arguments)]
fn run_room(
    stream: &mut UnixStream,
    state: &State,
    served: &Served,
    req: &room_rules::Request,
    passed: Vec<OwnedFd>,
    mut held: Held<'_>,
    room: RoomPlan,
    program: &str,
) -> Result<i32> {
    let ctx = &served.ctx;
    let req_fds = &req.fds[..];
    // The program's lower limits and its umask, kept for the room.
    let limits: Vec<(i32, libc::rlimit)> = req
        .limits
        .iter()
        .map(|l| {
            (
                l[0] as i32,
                libc::rlimit {
                    rlim_cur: l[1] as libc::rlim_t,
                    rlim_max: l[2] as libc::rlim_t,
                },
            )
        })
        .collect();
    let umask = req.umask;
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
    // The request's places and SAM's own descriptors for the room, counted
    // before any is opened. When rooms being built hold what is needed,
    // the room waits for them to give it back (moments later).
    let places = room
        .steps
        .iter()
        .filter(|s| matches!(s, Step::Show { .. }))
        .count();
    if places > MAX_PLACES {
        bail!("the room asks for too many places ({places}, at most {MAX_PLACES})");
    }
    match held.wait_for_own(places + ROOM_FDS, ROOM_FD_WAIT) {
        Ok(()) => {}
        Err(NoRoom::Never) => {
            bail!("too many places held for rooms at once ({places} more do not fit)")
        }
        Err(NoRoom::TimedOut) => bail!(
            "too many places held for rooms at once ({places} more did not fit within {} s)",
            ROOM_FD_WAIT.as_secs()
        ),
        Err(NoRoom::Stopped) => bail!("the app's start ended before the room was built"),
    }
    // SAM's own things first, at the place no request may name: its room
    // helper and the room's rules, both as data in the room's own fresh
    // file system (nothing of the computer is shown for them).
    let helper = memfd_with(ROOM_HELPER)?;
    let n = number(&mut numbers);
    args.extend([
        "--perms".into(),
        "0555".into(),
        "--ro-bind-data".into(),
        n.to_string(),
        HELPER_INSIDE.into(),
    ]);
    handles.push(helper);
    let (status_read, status_write) = pipe()?;
    let status_n = number(&mut numbers);
    handles.push(status_write);
    // SAM's syscall filter, compiled here, applied by the helper.
    let filter = memfd_with(&crate::kernel::filter_bytes(&ctx.seccomp)?)?;
    let filter_n = number(&mut numbers);
    handles.push(filter);
    // The room's rules: written once every place is laid out (they name
    // what each place must be), passed now so they come before the request.
    let data = memfd_with(&[])?;
    let n = number(&mut numbers);
    args.extend(["--ro-bind-data".into(), n.to_string(), SPEC_INSIDE.into()]);
    let spec_at = handles.len();
    handles.push(data);
    // Each place shown by handle, with what it is (device, inode): SAM's
    // helper checks in the room that Bubblewrap showed exactly that (an
    // older Bubblewrap mounts the handle's path by name, which the app can
    // swap while the room is built).
    let mut shown_ids: Vec<(u64, u64, PathBuf)> = Vec::new();
    // The request's places and the room's own things, in order.
    // Writes the request asked for but the app cannot make (recorded).
    let mut capped_here: Vec<String> = Vec::new();
    for step in &room.steps {
        match step {
            Step::Show {
                source,
                dst,
                writable,
                optional,
            } => {
                let fd = match open_source(source, &served.sources) {
                    Ok(fd) => fd,
                    // Only a path the request named below a place may be
                    // missing (asked with -try); a place of the app that
                    // cannot be shown means no room, never one without it.
                    Err(e)
                        if *optional
                            && !source.rel.as_os_str().is_empty()
                            && e.raw_os_error() == Some(libc::ENOENT) =>
                    {
                        continue
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ELOOP) => bail!(
                        "{} leads through a link: a room never follows one",
                        dst.display()
                    ),
                    Err(e) => bail!("{} cannot be shown: {e}", dst.display()),
                };
                // Writable only where the app can write: its mount and its
                // Landlock rules (whatever Landlock the room gets).
                let can = !read_only_filesystem(&fd)
                    && ctx.landlock.write.iter().any(|w| dst.starts_with(w));
                if *writable && !can {
                    capped_here.push(format!(
                        "{}: not writable for the app, so read-only here",
                        dst.display()
                    ));
                }
                let writable = *writable && can;
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
                let (dev, ino) = identity(&fd)?;
                shown_ids.push((dev, ino, dst.clone()));
                handles.push(fd);
            }
            Step::Device { src, dst, access } => {
                args.push(
                    match access {
                        DeviceAccess::Devices => "--dev-bind-try",
                        DeviceAccess::NoDevices => "--bind-try",
                        DeviceAccess::ReadOnly => "--ro-bind-try",
                    }
                    .into(),
                );
                args.push(src.to_string_lossy().into_owned());
                args.push(dst.to_string_lossy().into_owned());
            }
            Step::Mask(at) => {
                args.push("--tmpfs".into());
                args.push(at.to_string_lossy().into_owned());
            }
            Step::Args(a) => args.extend(a.iter().cloned()),
        }
    }
    let spec = room_spec(ctx, &room, status_n, filter_n, &shown_ids)?;
    fill_memfd(&handles[spec_at], &spec)?;
    args.extend([
        "--chdir".into(),
        room.chdir.to_string_lossy().into_owned(),
        "--remount-ro".into(),
        "/".into(),
        "--".into(),
        HELPER_INSIDE.into(),
        SPEC_INSIDE.into(),
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
    // The program's standard streams only when it passed them.
    let null_std = [0, 1, 2].map(|n| !req_fds.contains(&n));
    // Everything that can fail is done before the room starts: once it
    // runs, it is never left untracked.
    let mut peer = stream.try_clone()?;
    let _ = peer.set_read_timeout(None);
    let child = spawn_room(&ctx.bwrap, &args, &map, highest, null_std, &limits, umask)
        .context("starting Bubblewrap for the room")?;
    // The room has its copies: the app's connections leave the budget.
    drop(passed);
    drop(handles);
    held.release();
    let child = Arc::new(Mutex::new(child));
    if let Ok(mut rooms) = state.rooms.lock() {
        rooms.push(child.clone());
    }
    // Started while the service was stopping: it ends now too.
    if state.stop.load(Ordering::SeqCst) {
        if let Ok(mut c) = child.lock() {
            let _ = c.kill();
        }
    }
    // The stand-in gone (its program ended or was killed): the room ends.
    let watcher = {
        let child = child.clone();
        std::thread::Builder::new()
            .name("sam-room-watch".into())
            .spawn(move || {
                let mut b = [0u8; 64];
                loop {
                    match peer.read(&mut b) {
                        // The stand-in was asked to quit: so is the room's
                        // program, which keeps its time to save.
                        Ok(n) if n > 0 && b[..n].iter().all(|c| *c == QUIT_ASK) => {
                            if let Ok(c) = child.lock() {
                                c.ask_to_quit();
                            }
                        }
                        // A signal that interrupts the wait is not the
                        // stand-in leaving (the launcher handles terminal
                        // resizes, say).
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        _ => break,
                    }
                }
                if let Ok(mut c) = child.lock() {
                    let _ = c.kill();
                }
            })
    };
    let end_room = |child: &Arc<Mutex<RoomProcess>>| {
        if let Ok(mut c) = child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Ok(mut rooms) = state.rooms.lock() {
            rooms.retain(|r| !Arc::ptr_eq(r, child));
        }
    };
    let Ok(watcher) = watcher else {
        end_room(&child);
        bail!("no watcher for the room could be started");
    };
    // What SAM's helper applied, in its own words (it closes the
    // connection before the program starts, or the room ends first).
    let mut status = String::new();
    let _ = std::io::BufRead::read_line(
        &mut std::io::BufReader::new(std::fs::File::from(status_read).take(512)),
        &mut status,
    );
    let status = sam_core::util::display_safe(status.trim(), 200);
    let all_capped: Vec<&String> = room.capped.iter().chain(&capped_here).collect();
    let capped = if all_capped.is_empty() {
        String::new()
    } else {
        let list: Vec<&str> = all_capped.iter().map(|c| c.as_str()).collect();
        format!(
            "; capped: {}",
            sam_core::util::display_safe(&list.join(", "), 300)
        )
    };
    if status.is_empty() {
        // Never a room without SAM's layers: it ends at once.
        end_room(&child);
        state.record_room(format!(
            "sam-room: failed {program}: SAM's layers were not confirmed{capped}"
        ));
    } else {
        // The program's own filter is loaded after the helper reports, so
        // it is named as asked for, not as confirmed.
        let own = if room.filters.is_empty() {
            ""
        } else {
            "; the program's own filter asked for"
        };
        state.record_room(format!(
            "sam-room: built {program} (layers: {status}{own}{capped})"
        ));
    }
    let status = loop {
        if let Ok(mut c) = child.lock() {
            match c.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) => {}
                Err(e) => {
                    drop(c);
                    end_room(&child);
                    return Err(e.into());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if let Ok(mut rooms) = state.rooms.lock() {
        rooms.retain(|r| !Arc::ptr_eq(r, &child));
    }
    drop(watcher); // ends when the connection closes
    Ok(exit_code(status))
}

/// The exit code a shell shows for a wait status (128 + signal when killed).
fn exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// A room's Bubblewrap, started by [`spawn_room`]: ended and waited for by
/// its process id.
pub(crate) struct RoomProcess {
    pid: libc::pid_t,
    status: Option<i32>,
}

impl RoomProcess {
    /// Asks the program in the room to quit (SIGTERM), as SAM asks an app:
    /// while the room is not waited for, its number cannot name another
    /// process.
    fn ask_to_quit(&self) {
        if self.status.is_none() {
            if let Ok(pid) = u32::try_from(self.pid) {
                crate::ops::ask_room_to_quit(pid);
            }
        }
    }
    fn kill(&mut self) -> std::io::Result<()> {
        if self.status.is_none() {
            // SAFETY: a signal to our own child, not yet waited for (so
            // its number cannot belong to another process).
            if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
    fn wait_with(&mut self, flags: libc::c_int) -> std::io::Result<Option<i32>> {
        if let Some(st) = self.status {
            return Ok(Some(st));
        }
        let mut st = 0;
        loop {
            // SAFETY: waits for our own child; st is a live int.
            let r = unsafe { libc::waitpid(self.pid, &mut st, flags) };
            if r == self.pid {
                self.status = Some(st);
                return Ok(Some(st));
            }
            if r == 0 {
                return Ok(None);
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        self.wait_with(libc::WNOHANG)
    }
    fn wait(&mut self) -> std::io::Result<i32> {
        self.wait_with(0).map(|s| s.unwrap_or(0))
    }
}

/// Starts the room's Bubblewrap with every connection of `map` at its
/// number in the room and nothing else open: the program's lower limits
/// and its umask applied, standard streams it did not pass on /dev/null.
/// SAM's own start, not Rust's: Rust reports a failed start through a pipe
/// at a number the moves could overwrite; here that pipe is moved above
/// every target first, so a failed start is always reported as one.
fn spawn_room(
    bwrap: &Path,
    args: &[String],
    map: &[(RawFd, RawFd)],
    highest: RawFd,
    null_std: [bool; 3],
    limits: &[(i32, libc::rlimit)],
    umask: Option<u32>,
) -> Result<RoomProcess> {
    use std::os::unix::ffi::OsStrExt;
    let bad = |_| std::io::Error::from(std::io::ErrorKind::InvalidInput);
    // Everything the child needs, made before the fork (it may only make
    // async-signal-safe calls).
    let path = std::ffi::CString::new(bwrap.as_os_str().as_bytes()).map_err(bad)?;
    let argv: Vec<std::ffi::CString> = std::iter::once(Ok(path.clone()))
        .chain(
            args.iter()
                .map(|a| std::ffi::CString::new(a.as_bytes()).map_err(bad)),
        )
        .collect::<std::io::Result<_>>()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let (err_read, err_write) = pipe()?;
    let mut targets: Vec<RawFd> = map.iter().map(|(_, n)| *n).collect();
    targets.sort_unstable();
    let mut temps: Vec<RawFd> = vec![0; map.len()];
    let (null_fd, err_fd) = (null.as_raw_fd(), err_write.as_raw_fd());
    // SAFETY: getpid has no arguments.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the child below makes only async-signal-safe calls on data
    // made before the fork, then execs or exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if pid == 0 {
        // SAFETY: the child, as said above.
        unsafe {
            let fail = |fd: RawFd| -> ! {
                let e: i32 = *libc::__errno_location();
                let b = e.to_ne_bytes();
                libc::write(fd, b.as_ptr().cast(), 4);
                libc::_exit(127)
            };
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
            if libc::getppid() != parent {
                libc::_exit(127);
            }
            // Signals as a new program expects them (Rust ignores SIGPIPE).
            let mut none: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            libc::pthread_sigmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            // Room for the moves above every target, for these few calls
            // only; the room keeps the launcher's own limit.
            let mut lim: libc::rlimit = std::mem::zeroed();
            let have = libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0;
            if have {
                let raised = libc::rlimit {
                    rlim_cur: lim.rlim_max,
                    rlim_max: lim.rlim_max,
                };
                libc::setrlimit(libc::RLIMIT_NOFILE, &raised);
            }
            // The error pipe and /dev/null above every target first, then
            // every connection above them, then to its target: nothing
            // overwrites another on the way.
            let err = libc::fcntl(err_fd, libc::F_DUPFD_CLOEXEC, highest + 1);
            if err < 0 {
                fail(err_fd);
            }
            let null = libc::fcntl(null_fd, libc::F_DUPFD_CLOEXEC, highest + 1);
            if null < 0 {
                fail(err);
            }
            for (i, (src, _)) in map.iter().enumerate() {
                let t = libc::fcntl(*src, libc::F_DUPFD_CLOEXEC, highest + 1);
                if t < 0 {
                    fail(err);
                }
                temps[i] = t;
            }
            for (i, (_, dst)) in map.iter().enumerate() {
                if libc::dup2(temps[i], *dst) < 0 {
                    fail(err);
                }
            }
            for (n, use_null) in null_std.iter().enumerate() {
                if *use_null && libc::dup2(null, n as RawFd) < 0 {
                    fail(err);
                }
            }
            if have {
                libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            }
            // The program's own limits where lower than the launcher's:
            // never raised by a request.
            for (res, want) in limits {
                let mut cur: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(*res as _, &mut cur) != 0 {
                    continue;
                }
                let hard = want.rlim_max.min(cur.rlim_max);
                let soft = want.rlim_cur.min(cur.rlim_cur).min(hard);
                if hard != cur.rlim_max || soft != cur.rlim_cur {
                    let new = libc::rlimit {
                        rlim_cur: soft,
                        rlim_max: hard,
                    };
                    libc::setrlimit(*res as _, &new);
                }
            }
            if let Some(m) = umask {
                libc::umask((m & 0o777) as libc::mode_t);
            }
            // Everything else from 3 on closes when Bubblewrap starts.
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
            libc::execve(path.as_ptr(), argv_ptrs.as_ptr(), envp.as_ptr());
            fail(err)
        }
    }
    drop(err_write);
    drop(null);
    let mut child = RoomProcess { pid, status: None };
    let mut errno = [0u8; 4];
    let mut got = 0;
    let mut f = std::fs::File::from(err_read);
    while got < 4 {
        match f.read(&mut errno[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.into());
            }
        }
    }
    if got == 0 {
        return Ok(child);
    }
    let _ = child.wait();
    Err(std::io::Error::from_raw_os_error(i32::from_ne_bytes(errno)).into())
}

const CLOSE_RANGE_CLOEXEC: u32 = 4;

/// The room's rules for SAM's room helper: `key=value` entries separated by
/// NUL bytes (see room-exec/main.rs). Landlock: the app's rules plus the
/// room's own new places.
fn room_spec(
    ctx: &RoomContext,
    room: &RoomPlan,
    status: i32,
    filter: i32,
    shown: &[(u64, u64, PathBuf)],
) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let mut out: Vec<u8> = Vec::new();
    let mut put = |key: &str, value: &[u8]| -> Result<()> {
        if value.contains(&0) {
            bail!("a value of the room holds a NUL byte");
        }
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(0);
        Ok(())
    };
    put("status", status.to_string().as_bytes())?;
    put("seccomp", filter.to_string().as_bytes())?;
    for fd in &room.filters {
        put("filter", fd.to_string().as_bytes())?;
    }
    for p in &ctx.landlock.read {
        put("read", p.as_os_str().as_bytes())?;
    }
    for p in ctx.landlock.write.iter().chain(&room.own) {
        put("write", p.as_os_str().as_bytes())?;
    }
    for (k, v) in &room.env {
        if k.is_empty() || k.contains('=') {
            bail!("an environment variable of the room has no valid name");
        }
        if k != "PWD" {
            put("env", format!("{k}={v}").as_bytes())?;
        }
    }
    // As Bubblewrap: PWD names the room's folder, whatever came before.
    let mut pwd = b"PWD=".to_vec();
    pwd.extend_from_slice(room.chdir.as_os_str().as_bytes());
    put("env", &pwd)?;
    for (dev, ino, dst) in shown {
        let mut v = format!("{dev}:{ino}:").into_bytes();
        v.extend_from_slice(dst.as_os_str().as_bytes());
        put("place", &v)?;
    }
    Ok(out)
}

/// A room's place: the floor-plan source SAM opened when the app started,
/// and `rel` strictly beneath it, through no link at all (a link the app
/// made could lead to a place the app sees protected or hidden).
fn open_source(source: &Source, sources: &[Option<SourceHandle>]) -> std::io::Result<OwnedFd> {
    let handle = sources
        .get(source.entry)
        .and_then(Option::as_ref)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let top = match handle {
        SourceHandle::Open(fd) => fd.try_clone()?,
        SourceHandle::Known { path, dev, ino } => {
            let fd = open_path(path)?;
            if identity(&fd)? != (*dev, *ino) {
                return Err(std::io::Error::other(
                    "it is no longer what the app was shown when it started",
                ));
            }
            fd
        }
    };
    if source.rel.as_os_str().is_empty() {
        return Ok(top);
    }
    openat2_beneath(&top, &source.rel)
}

/// Device and inode of an open file or folder.
fn identity(fd: &OwnedFd) -> std::io::Result<(u64, u64)> {
    // SAFETY: fstat writes the struct given.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat on our own descriptor writes the struct given.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((st.st_dev, st.st_ino))
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
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
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
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
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

/// Writes `data` into an empty memfd made by [`memfd_with`], from its start.
fn fill_memfd(fd: &OwnedFd, data: &[u8]) -> Result<()> {
    let mut f = std::fs::File::from(fd.try_clone()?);
    f.write_all(data)?;
    use std::io::Seek;
    f.seek(std::io::SeekFrom::Start(0))?;
    Ok(())
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

/// A pipe, both ends close-on-exec (the room gets the write end at its own
/// number, which the remapping leaves open).
fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 into a two-element array; the result is checked.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("{}", std::io::Error::last_os_error());
    }
    // SAFETY: two new descriptors of our own.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Who asked: the name of the program that started the stand-in (for the
/// start record only; never trusted for anything).
fn asked_by(stream: &UnixStream) -> String {
    let Some((pid, _)) = peer(stream) else {
        return "?".into();
    };
    let ppid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("PPid:").map(|v| v.trim().to_string()))
        });
    let name = ppid
        .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).ok())
        .unwrap_or_default();
    let name = sam_core::util::display_safe(name.trim(), 40);
    if name.is_empty() {
        "?".into()
    } else {
        name
    }
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    peer(stream).map(|(_, uid)| uid)
}

fn peer(stream: &UnixStream) -> Option<(i32, u32)> {
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
    (r == 0).then_some((cred.pid, cred.uid))
}

/// One receive of what is waiting, keeping at most `max` connections that
/// come with it (close-on-exec); the kernel closes any beyond them and
/// says so (MSG_CTRUNC), then this errors.
fn recv_with_fds(
    stream: &UnixStream,
    buf: &mut [u8],
    fds: &mut Vec<OwnedFd>,
    max: usize,
) -> std::io::Result<usize> {
    // SAFETY: CMSG_SPACE only computes a size.
    let space = if max == 0 {
        0
    } else {
        // SAFETY: CMSG_SPACE only computes a size.
        unsafe { libc::CMSG_SPACE((max * 4) as u32) as usize }
    };
    let mut control = vec![0u8; space.max(1)];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: msghdr pointing at live buffers of the given sizes.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    // Room for exactly `max` (CMSG_SPACE rounds up, and the kernel would
    // fill the rounding with one more).
    msg.msg_controllen = if max == 0 {
        0
    } else {
        // SAFETY: CMSG_LEN only computes a size.
        unsafe { libc::CMSG_LEN((max * 4) as u32) as usize }
    } as _;
    // SAFETY: msg points at the live buffers above, of the sizes given.
    let n = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &mut msg,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: walking the control messages the kernel wrote.
    unsafe {
        if space > 0 {
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
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(std::io::Error::other("more connections than room for them"));
    }
    Ok(n as usize)
}

/// Waits until the connection has something to read, at most `limit`.
fn wait_readable(stream: &UnixStream, limit: Duration, stop: &AtomicBool) -> Result<(), String> {
    let mut p = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let end = std::time::Instant::now() + limit;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err("the app's start ended while the request was read".into());
        }
        let left = end.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err("reading the request: it took too long".into());
        }
        // In short steps, so the end of the app's start is noticed.
        let ms = left.as_millis().min(200) as i32;
        // SAFETY: one pollfd that lives through the call.
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r > 0 {
            return Ok(());
        }
        if r == 0 {
            continue;
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("reading the request: {e}"));
        }
    }
}

/// A whole message: 4 bytes length, then the request; the connections
/// travel with the first bytes. Room for them is counted before each
/// receive (as much as the budgets leave), so no connection is ever taken
/// in beyond them.
fn read_message(
    stream: &UnixStream,
    held: &mut Held<'_>,
) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
    let mut fds = Vec::new();
    let end = std::time::Instant::now() + READ_LIMIT;
    let mut take = |buf: &mut [u8], fds: &mut Vec<OwnedFd>| -> Result<usize, String> {
        wait_readable(
            stream,
            end.saturating_duration_since(std::time::Instant::now()),
            &held.state.stop,
        )?;
        let want = room_rules::MAX_FDS - fds.len().min(room_rules::MAX_FDS);
        let state = held.state;
        let one = state
            .receiving
            .lock()
            .map_err(|_| "reading the request: the service failed".to_string())?;
        // May wait a moment for rooms being built (other requests wait
        // for this one meanwhile, as they do for every receive).
        let got = held.reserve_passed_waiting(want, end);
        let before = fds.len();
        // Never waits: something is ready to read.
        let r = recv_with_fds(stream, buf, fds, got);
        let came = fds.len() - before;
        held.unreserve_passed(got - came.min(got));
        drop(one);
        if came > got {
            // Never kept beyond what was counted.
            fds.truncate(before);
            return Err("the request passes too many connections".into());
        }
        match r {
            Ok(0) => Err("the request ended early".into()),
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(_) if got < want => Err("too many connections held for rooms at once".into()),
            Err(_) => Err("the request passes too many connections".into()),
        }
    };
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        got += take(&mut head[got..], &mut fds)?;
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > room_rules::MAX_MESSAGE {
        return Err("the request is too large".into());
    }
    let mut body = vec![0u8; len];
    let mut got = 0;
    while got < len {
        got += take(&mut body[got..], &mut fds)?;
    }
    Ok((body, fds))
}

/// What the launcher's descriptor limit leaves free for rooms: its soft
/// limit, less what is open now and what it keeps for itself.
fn fd_budget() -> usize {
    // SAFETY: getrlimit writes the struct given.
    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: getrlimit writes the struct given.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return 0;
    }
    let open = std::fs::read_dir("/proc/self/fd").map_or(1024, |d| d.count());
    budget_from(lim.rlim_cur, open)
}

/// The budget for a soft limit `soft` with `open` descriptors open.
fn budget_from(soft: libc::rlim_t, open: usize) -> usize {
    let soft = usize::try_from(soft).unwrap_or(usize::MAX);
    soft.saturating_sub(open + FD_RESERVE).min(MAX_SERVICE_FDS)
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

/// A Bubblewrap version line as the stand-in may answer it: only plain
/// characters (letters, digits, space, `.`, `_`, `-`), at most 60.
pub fn plain_version(line: &str) -> String {
    line.trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || " ._-".contains(*c))
        .take(60)
        .collect()
}

/// Is SAM's helper started as the stand-in? Yes when it was started under
/// Bubblewrap's name: the file name of the path the program started
/// (`exec_path`, the kernel's record of it) or of the name it gave the
/// program (`argv0`). The path counts too because a program may give any
/// name (`argv0`) when it starts `bwrap`.
pub fn is_standin_start(
    argv0: Option<&std::ffi::OsStr>,
    exec_path: Option<&std::ffi::OsStr>,
) -> bool {
    [argv0, exec_path]
        .into_iter()
        .flatten()
        .any(|p| Path::new(p).file_name() == Some(std::ffi::OsStr::new(STANDIN_NAME)))
}

/// [`is_standin_start`] for this process: its first argument and the path
/// it was started by.
pub fn started_as_standin() -> bool {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: getauxval only reads the process's start record; AT_EXECFN
    // is the address of a NUL-terminated path that lives as long as the
    // process (0 when the kernel gave none).
    let exec_path = unsafe {
        let p = libc::getauxval(libc::AT_EXECFN) as *const libc::c_char;
        (!p.is_null()).then(|| std::ffi::CStr::from_ptr(p))
    };
    let argv0 = std::env::args_os().next();
    is_standin_start(
        argv0.as_deref(),
        exec_path.map(|p| std::ffi::OsStr::from_bytes(p.to_bytes())),
    )
}

/// The computer's Bubblewrap version line, from the file beside the
/// stand-in (empty when it is missing), as plain characters only.
pub fn standin_version() -> String {
    std::fs::read_to_string(Path::new(STANDIN_FOLDER_INSIDE).join(STANDIN_VERSION_FILE))
        .map(|v| plain_version(&v))
        .unwrap_or_default()
}

/// The stand-in's connection to the service once its request is sent
/// (-1 before), for [`pass_quit_on`].
static QUIT_TO: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
/// Set when the stand-in was asked to quit, also before its request was sent.
static QUIT_ASKED: AtomicBool = AtomicBool::new(false);

/// Sends [`QUIT_ASK`] on `fd`, never waiting and never raising SIGPIPE.
fn send_quit_ask(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: send is async-signal-safe; one byte from a live buffer.
        unsafe {
            libc::send(
                fd,
                [QUIT_ASK].as_ptr().cast(),
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
    }
}

/// The stand-in's SIGTERM handler: SAM asks the app's processes to quit
/// (Close, logout), the stand-in among them; it passes that on to the
/// service, which asks its room's program, and keeps waiting for the room.
/// Ending here instead ended the room at once, with no time to save
/// (review of PR 95). Only atomics and send: async-signal-safe.
extern "C" fn pass_quit_on(_: libc::c_int) {
    // SAFETY: errno of this thread, read and put back around the send.
    let errno = unsafe { *libc::__errno_location() };
    QUIT_ASKED.store(true, Ordering::SeqCst);
    send_quit_ask(QUIT_TO.load(Ordering::SeqCst));
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = errno };
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
        // An option no room gets: Room service refuses it too and notes it
        // in the start record.
        Err(e) => match room_rules::first_unusable_option(argv) {
            Some(opt) => (vec![vec![opt]], vec!["?".to_string()]),
            None => return fail(&e),
        },
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
    // Asked to quit from now on: passed on once the request is sent.
    // SAFETY: sigaction with a zeroed struct whose handler is the
    // async-signal-safe function above; restarted calls go on waiting.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = pass_quit_on as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
    fds.retain(|fd| *fd != stream.as_raw_fd());
    if fds.len() > room_rules::MAX_FDS {
        return fail("too many open connections to pass to a room");
    }
    // A variable or the folder that is not text is never dropped or
    // changed: the request is refused as a whole, and recorded.
    let mut ops = ops;
    let mut env = std::collections::BTreeMap::new();
    let mut not_text = false;
    for (k, v) in std::env::vars_os() {
        match (k.into_string(), v.into_string()) {
            (Ok(k), Ok(v)) => {
                env.insert(k, v);
            }
            _ => not_text = true,
        }
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => match p.into_os_string().into_string() {
            Ok(p) if room_rules::is_clean_absolute(&p) => p,
            Ok(_) => "/".into(),
            Err(_) => {
                not_text = true;
                "/".into()
            }
        },
        Err(_) => "/".into(),
    };
    if not_text && ops.first().is_none_or(|o| o[0] != room_rules::NOT_TEXT) {
        ops.insert(0, vec![room_rules::NOT_TEXT.into()]);
    }
    // The program's resource limits and umask: a room keeps them, as
    // Bubblewrap's children do (glycin caps its loader's memory this way).
    let mut limits = Vec::new();
    for res in 0..16u32 {
        // SAFETY: getrlimit writes the struct given.
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: getrlimit writes the struct given.
        if unsafe { libc::getrlimit(res as _, &mut lim) } == 0 {
            limits.push([u64::from(res), lim.rlim_cur, lim.rlim_max]);
        }
    }
    // SAFETY: umask only swaps a number; set back at once.
    let umask = unsafe {
        let m = libc::umask(0o022);
        libc::umask(m);
        m
    };
    let req = room_rules::Request {
        v: room_rules::VERSION,
        ops,
        flags: Vec::new(),
        command,
        env,
        cwd,
        fds: fds.clone(),
        limits,
        umask: Some(umask),
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
    // Asked before the request went out: passed on now (passed twice when
    // the signal comes just between, which asks the room once more).
    QUIT_TO.store(stream.as_raw_fd(), Ordering::SeqCst);
    // Forgotten before the connection closes: its number is then free.
    struct Forget;
    impl Drop for Forget {
        fn drop(&mut self) {
            QUIT_TO.store(-1, Ordering::SeqCst);
        }
    }
    let _forget = Forget;
    if QUIT_ASKED.load(Ordering::SeqCst) {
        send_quit_ask(stream.as_raw_fd());
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

#[cfg(test)]
mod process_tests {
    //! The low-level parts of Room service: how a room's Bubblewrap is
    //! started, ended and waited for, how SAM opens its own descriptors,
    //! and how a request's bytes and connections are read.
    use super::*;
    use std::ffi::OsString;
    use std::os::fd::IntoRawFd;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn dev_null() -> OwnedFd {
        OwnedFd::from(std::fs::File::open("/dev/null").unwrap())
    }

    /// The variable that tells a copy of this test program which test it
    /// runs on its own.
    const OWN: &str = "SAM_TEST_OWN_PROCESS";

    /// Whether this is the copy of the test program that runs test `name`
    /// on its own.
    fn is_own_process(name: &str) -> bool {
        std::env::var(OWN).as_deref() == Ok(name)
    }

    /// A copy of this test program that runs only test `name`, started
    /// through `wrap` (a program and its arguments) when given. For tests
    /// that change what the whole process has (its descriptor limits, its
    /// standard input), which the other tests share.
    fn own_process(name: &str, wrap: &[OsString]) -> Command {
        let exe = std::env::current_exe().unwrap();
        let mut c = match wrap.split_first() {
            Some((first, rest)) => {
                let mut c = Command::new(first);
                c.args(rest).arg(&exe);
                c
            }
            None => Command::new(&exe),
        };
        c.args([
            "--exact",
            &format!("room_service::process_tests::{name}"),
            "--test-threads=1",
        ])
        .env(OWN, name);
        c
    }

    /// Checks that the copy found its test, ran it and it passed there.
    fn passed_alone(out: std::process::Output) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{:?}\n{stdout}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Runs test `name` on its own in a copy of this program: true in the
    /// copy (where the test's body runs), false here once the copy passed.
    fn alone(name: &str) -> bool {
        if is_own_process(name) {
            return true;
        }
        passed_alone(own_process(name, &[]).output().unwrap());
        false
    }

    /// Sets this process's descriptor limit (only in a copy of its own).
    fn set_nofile(soft: libc::rlim_t, hard: libc::rlim_t) {
        let lim = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        // SAFETY: setrlimit reads the struct given.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) }, 0);
    }

    const PT_LOAD: u32 = 1;
    const PT_INTERP: u32 = 3;

    /// A stand-in for a program, with only what `needs_loader` reads: a
    /// 64-bit ELF header and, right after it, program headers of these
    /// types.
    fn elf(types: &[u32]) -> Vec<u8> {
        let mut e = vec![0u8; 64];
        e[..4].copy_from_slice(b"\x7fELF");
        e[4] = 2; // 64-bit
        e[0x20..0x28].copy_from_slice(&64u64.to_ne_bytes()); // where they start
        e[0x36..0x38].copy_from_slice(&56u16.to_ne_bytes()); // the size of one
        e[0x38..0x3a].copy_from_slice(&(types.len() as u16).to_ne_bytes());
        for t in types {
            let mut header = vec![0u8; 56];
            header[..4].copy_from_slice(&t.to_ne_bytes());
            e.extend(header);
        }
        e
    }

    /// A program asks for a loader when any of its program headers says
    /// so, first or later; a program without one (as SAM's static room
    /// helper) needs none, also when it is as short as it can be. Anything
    /// that is not a 64-bit ELF program, or is cut short, counts as asking
    /// (SAM then builds no rooms rather than a helper that cannot start).
    #[test]
    fn a_program_needs_a_loader_only_when_a_program_header_asks_for_one() {
        assert!(needs_loader(&std::fs::read("/bin/sh").unwrap()), "/bin/sh");
        assert!(needs_loader(&elf(&[PT_INTERP])), "first and only");
        assert!(needs_loader(&elf(&[PT_INTERP, PT_LOAD])), "first of two");
        assert!(needs_loader(&elf(&[PT_LOAD, PT_INTERP])), "second of two");
        assert!(!needs_loader(&elf(&[PT_LOAD])), "a static program");
        assert!(
            !needs_loader(&elf(&[])),
            "a header alone, without program headers"
        );
        let mut bits32 = elf(&[]);
        bits32[4] = 1;
        assert!(needs_loader(&bits32), "a 32-bit program");
        let mut not_elf = elf(&[]);
        not_elf[0] = 0;
        assert!(needs_loader(&not_elf), "not an ELF program");
        let mut cut = elf(&[PT_LOAD]);
        cut.truncate(66);
        assert!(needs_loader(&cut), "a program header cut short");
        assert!(needs_loader(b""), "nothing");
    }

    /// What the launcher keeps for itself is never given to rooms: 128 of
    /// its own, and two for each connection it may have open (the
    /// connection itself, and a second one while its room runs).
    #[test]
    fn the_launcher_keeps_two_descriptors_for_each_connection_for_itself() {
        let soft: usize = 4096;
        for open in [0, 100, 500] {
            let budget = budget_from(soft as libc::rlim_t, open);
            assert!(
                budget + open + 128 + 2 * MAX_CONNECTIONS <= soft,
                "{budget} for rooms with {open} open"
            );
        }
    }

    /// Waits until the room has ended, at most 10 seconds, asking without
    /// waiting as the service does while a room runs.
    fn ended_within(p: &mut RoomProcess) -> Option<i32> {
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if let Some(st) = p.try_wait().unwrap() {
                return Some(st);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    /// A room SAM ends is killed at once and ends as killed (exit code
    /// 137, as a shell shows it); its status stays known, and ending it
    /// again changes nothing. A room that ends by itself is seen to end,
    /// with its own code.
    #[test]
    fn a_room_sam_ends_is_killed_and_ends_with_the_killed_code() {
        let (r, w) = pipe().unwrap();
        // The room waits for a line on its standard input that never comes.
        let mut p = spawn_room(
            Path::new("/bin/sh"),
            &s(&["-c", "read x"]),
            &[(r.as_raw_fd(), 0)],
            0,
            [false, true, true],
            &[],
            None,
        )
        .unwrap();
        drop(r);
        assert_eq!(p.try_wait().unwrap(), None, "the room has not ended yet");
        p.kill().expect("a running room is ended");
        let st = ended_within(&mut p).expect("the room ended when killed");
        assert_eq!(exit_code(st), 137);
        p.kill()
            .expect("ending a room that has ended changes nothing");
        assert_eq!(p.try_wait().unwrap(), Some(st));
        drop(w);

        let mut p = spawn_room(
            Path::new("/bin/sh"),
            &s(&["-c", "exit 5"]),
            &[],
            2,
            [true; 3],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(ended_within(&mut p).map(exit_code), Some(5));
    }

    /// Waiting for a process that is no room of this launcher fails at
    /// once (the kernel says it is no child), never waits on forever.
    #[test]
    fn waiting_for_a_process_that_is_no_child_fails_at_once() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // This test program itself: never its own child. Only waited
            // for, never signalled.
            // SAFETY: getpid has no arguments.
            let pid = unsafe { libc::getpid() };
            let mut p = RoomProcess { pid, status: None };
            let _ = tx.send(p.try_wait().map_err(|e| e.raw_os_error()));
        });
        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the wait returned");
        assert_eq!(r, Err(Some(libc::ECHILD)));
    }

    /// Starts a room that prints its descriptor limits (soft, then hard)
    /// and the numbers of its open connections, with `extra` connections
    /// at their numbers and its standard output to this test.
    fn room_limits_and_numbers(
        extra: &[(RawFd, RawFd)],
        highest: RawFd,
        limits: &[(i32, libc::rlimit)],
    ) -> Result<(u64, u64, Vec<RawFd>)> {
        let (r, w) = pipe()?;
        let mut map = vec![(w.as_raw_fd(), 1)];
        map.extend_from_slice(extra);
        let mut p = spawn_room(
            Path::new("/bin/sh"),
            &s(&[
                "-c",
                "ulimit -S -n; ulimit -H -n; exec /bin/ls /proc/self/fd",
            ]),
            &map,
            highest,
            [true, false, true],
            limits,
            None,
        )?;
        drop(w);
        let mut out = String::new();
        std::fs::File::from(r).read_to_string(&mut out)?;
        p.wait()?;
        let mut lines = out.lines();
        let soft = lines.next().unwrap_or("").parse()?;
        let hard = lines.next().unwrap_or("").parse()?;
        Ok((soft, hard, lines.filter_map(|l| l.parse().ok()).collect()))
    }

    /// Under a low descriptor limit a room still gets a connection at a
    /// number above it (the moves use the hard limit for a moment), then
    /// runs with the launcher's own limit; a program's lower limit is kept
    /// whether only its soft or only its hard limit is lower, and a higher
    /// one is never given. Runs on its own: it lowers this process's limit.
    #[test]
    fn a_room_under_a_low_limit_gets_its_connections_and_keeps_lower_limits() {
        if !alone("a_room_under_a_low_limit_gets_its_connections_and_keeps_lower_limits") {
            return;
        }
        set_nofile(64, 256);
        let x = dev_null();
        let (soft, hard, numbers) = room_limits_and_numbers(&[(x.as_raw_fd(), 200)], 200, &[])
            .expect("a room starts with a connection above the soft limit");
        assert_eq!((soft, hard), (64, 256), "the launcher's own limit");
        assert!(numbers.contains(&200), "{numbers:?}");
        let nofile = |soft, hard| {
            (
                libc::RLIMIT_NOFILE as i32,
                libc::rlimit {
                    rlim_cur: soft,
                    rlim_max: hard,
                },
            )
        };
        let only_soft = room_limits_and_numbers(&[], 1, &[nofile(32, 256)]).unwrap();
        assert_eq!((only_soft.0, only_soft.1), (32, 256), "only soft lower");
        let only_hard = room_limits_and_numbers(&[], 1, &[nofile(64, 128)]).unwrap();
        assert_eq!((only_hard.0, only_hard.1), (64, 128), "only hard lower");
        let higher = room_limits_and_numbers(&[], 1, &[nofile(128, 1024)]).unwrap();
        assert_eq!((higher.0, higher.1), (64, 256), "never raised");
    }

    /// A start that fails while the connections are moved is reported
    /// with its own cause, whichever move finds no number: never a room
    /// that seems started. Runs on its own: it lowers this process's hard
    /// limit to 256.
    #[test]
    fn a_start_that_fails_while_moving_connections_is_reported_with_its_cause() {
        if !alone("a_start_that_fails_while_moving_connections_is_reported_with_its_cause") {
            return;
        }
        // The last numbers below the limit free: this copy may have been
        // given a connection there by another test of the program that
        // started it, which nothing here owns.
        for fd in 240..256 {
            // SAFETY: closes a number nothing in this copy owns.
            unsafe { libc::close(fd) };
        }
        set_nofile(256, 256);
        let start = |map: &[(RawFd, RawFd)], highest: RawFd| {
            spawn_room(
                Path::new("/bin/true"),
                &[],
                map,
                highest,
                [false; 3],
                &[],
                None,
            )
            .map(|mut p| p.wait().unwrap())
        };
        // No number above the highest exists at all.
        let e = start(&[], 255).expect_err("no number for the error pipe");
        assert!(format!("{e:#}").contains("Invalid argument"), "{e:#}");
        // The error pipe takes the last number; /dev/null finds none.
        let e = start(&[], 254).expect_err("no number for /dev/null");
        assert!(format!("{e:#}").contains("Too many open files"), "{e:#}");
        // The error pipe and /dev/null take the last two; the connection
        // finds none.
        let x = dev_null();
        let e = start(&[(x.as_raw_fd(), 253)], 253).expect_err("no number for the connection");
        assert!(format!("{e:#}").contains("Too many open files"), "{e:#}");
        // One number more: the room starts.
        let st = start(&[(x.as_raw_fd(), 252)], 252).expect("room enough");
        assert_eq!(exit_code(st), 0);
    }

    /// A signal that comes while SAM waits to hear whether a room's
    /// Bubblewrap started (the launcher gets signals) is no failed start:
    /// the room starts, and SAM keeps track of it. Runs on its own: it
    /// sets how this process handles a signal and sends it many times.
    #[test]
    fn a_signal_while_a_room_starts_does_not_fail_the_start() {
        if !alone("a_signal_while_a_room_starts_does_not_fail_the_start") {
            return;
        }
        extern "C" fn nothing(_: libc::c_int) {}
        // SIGURG with a handler that does not restart calls: it interrupts
        // the wait for the start's answer.
        // SAFETY: sigaction with a zeroed struct filled as documented.
        unsafe {
            let mut new: libc::sigaction = std::mem::zeroed();
            new.sa_sigaction = nothing as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut new.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGURG, &new, std::ptr::null_mut()), 0);
        }
        // SAFETY: pthread_self has no arguments.
        let me = unsafe { libc::pthread_self() };
        let done = Arc::new(AtomicBool::new(false));
        let sender = {
            let done = done.clone();
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    // SAFETY: a signal to this test's thread, which waits
                    // for this one to end before it ends.
                    unsafe { libc::pthread_kill(me, libc::SIGURG) };
                    std::thread::sleep(Duration::from_micros(50));
                }
            })
        };
        // A long command line: the kernel copies it while the program
        // starts, so SAM waits a while for the answer, and signals come
        // during that wait.
        let args = vec!["x".repeat(100_000); 12];
        let results: Vec<String> = (0..50)
            .map(|_| {
                match spawn_room(Path::new("/bin/true"), &args, &[], 2, [true; 3], &[], None) {
                    Ok(mut p) => match p.wait() {
                        Ok(st) => format!("ended with {}", exit_code(st)),
                        Err(e) => format!("not waited for: {e}"),
                    },
                    Err(e) => format!("not started: {e:#}"),
                }
            })
            .collect();
        done.store(true, Ordering::SeqCst);
        sender.join().unwrap();
        assert!(results.iter().all(|r| r == "ended with 0"), "{results:?}");
    }

    /// A room's program has exactly its connections, each at its number,
    /// and /dev/null where it passed no standard stream: none is lost or
    /// overwritten by another on the way, and nothing else of the
    /// launcher stays open, also what would not close by itself when a
    /// program starts.
    #[test]
    fn a_room_gets_exactly_its_connections_and_none_overwrites_another() {
        let null = dev_null();
        // A descriptor of the launcher that a started program would keep
        // (not close-on-exec), at a number between the room's.
        // SAFETY: F_DUPFD copies our own open descriptor; checked below.
        let leak = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD, 500) };
        assert!(leak >= 500);
        // SAFETY: a new descriptor of our own.
        let leak = unsafe { OwnedFd::from_raw_fd(leak) };
        let (a_r, a_w) = pipe().unwrap();
        let (b_r, b_w) = pipe().unwrap();
        let (out_r, out_w) = pipe().unwrap();
        let map = [
            (a_w.as_raw_fd(), 900),
            (b_w.as_raw_fd(), 899),
            (out_w.as_raw_fd(), 1),
        ];
        let mut p = spawn_room(
            Path::new("/bin/ls"),
            &s(&["-l", "/proc/self/fd"]),
            &map,
            900,
            [true, false, true],
            &[],
            None,
        )
        .unwrap();
        drop(out_w);
        let mut out = String::new();
        std::fs::File::from(out_r.try_clone().unwrap())
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(exit_code(p.wait().unwrap()), 0, "{out}");
        // "… 899 -> pipe:[123]": each number and what it is.
        let seen: std::collections::BTreeMap<RawFd, String> = out
            .lines()
            .filter_map(|l| {
                let (left, target) = l.split_once(" -> ")?;
                Some((left.split_whitespace().last()?.parse().ok()?, target.into()))
            })
            // ls's own reading of the folder.
            .filter(|(_, target): &(RawFd, String)| !target.starts_with("/proc/"))
            .collect();
        let pipe_of = |fd: &OwnedFd| format!("pipe:[{}]", identity(fd).unwrap().1);
        let want: std::collections::BTreeMap<RawFd, String> = [
            (0, "/dev/null".to_string()),
            (1, pipe_of(&out_r)),
            (2, "/dev/null".to_string()),
            (899, pipe_of(&b_r)),
            (900, pipe_of(&a_r)),
        ]
        .into();
        assert_eq!(seen, want, "launcher's own at {}\n{out}", leak.as_raw_fd());
    }

    /// The room's rules never carry an environment variable without a
    /// valid name: none without a name, none whose name holds '=' (SAM's
    /// helper would read it as another variable).
    #[test]
    fn a_room_never_gets_a_variable_without_a_valid_name() {
        let ctx = RoomContext {
            plan: FloorPlan::default(),
            facts: AppFacts::default(),
            bwrap: PathBuf::from("/usr/bin/bwrap"),
            landlock: LandlockSpec::default(),
            seccomp: SeccompSpec::default(),
        };
        let room = |name: &str| RoomPlan {
            steps: Vec::new(),
            share_net: false,
            env: [(name.to_string(), "v".to_string())].into(),
            filters: Vec::new(),
            own: Vec::new(),
            chdir: PathBuf::from("/"),
            command: s(&["x"]),
            capped: Vec::new(),
        };
        let spec = room_spec(&ctx, &room("NAME"), 3, 4, &[]).unwrap();
        assert!(
            spec.split(|b| *b == 0).any(|e| e == b"env=NAME=v"),
            "{spec:?}"
        );
        for bad in ["", "A=B", "="] {
            let e = room_spec(&ctx, &room(bad), 3, 4, &[])
                .expect_err("a variable without a valid name");
            assert!(e.to_string().contains("no valid name"), "{bad:?}: {e}");
        }
    }

    /// A place beneath a source is opened as a handle only (never read,
    /// so also a file nobody may read), closed when a program starts, and
    /// only strictly beneath its source through no link: a link, a way
    /// out, or a missing path is an error with its own cause.
    #[test]
    fn a_place_is_opened_beneath_its_source_as_a_handle_through_no_link() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        let secret = tmp.path().join("sub/secret");
        std::fs::write(&secret, "x").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::os::unix::fs::symlink("sub", tmp.path().join("link")).unwrap();
        let handle_only = |fd: &OwnedFd| {
            // SAFETY: F_GETFL and F_GETFD only read our descriptor's flags.
            let (fl, fd_fl) = unsafe {
                (
                    libc::fcntl(fd.as_raw_fd(), libc::F_GETFL),
                    libc::fcntl(fd.as_raw_fd(), libc::F_GETFD),
                )
            };
            assert!(fl & libc::O_PATH != 0, "opened as a handle only");
            assert!(
                fd_fl & libc::FD_CLOEXEC != 0,
                "closed when a program starts"
            );
        };
        let top = open_path(tmp.path()).unwrap();
        handle_only(&top);
        let fd = openat2_beneath(&top, Path::new("sub/secret"))
            .expect("a file nobody may read is still shown by handle");
        handle_only(&fd);
        assert_eq!(identity(&fd).unwrap(), {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(&secret).unwrap();
            (m.dev(), m.ino())
        });
        for (rel, errno) in [
            ("link/secret", libc::ELOOP),
            ("../", libc::EXDEV),
            ("/etc", libc::EXDEV),
            ("missing", libc::ENOENT),
        ] {
            let e = openat2_beneath(&top, Path::new(rel)).expect_err(rel);
            assert_eq!(e.raw_os_error(), Some(errno), "{rel}: {e}");
        }
        let e = open_path(&tmp.path().join("missing")).expect_err("missing");
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
    }

    /// SAM's own descriptors (a place's handle, a room's data) work at any
    /// number the kernel gives, also 0 when the launcher was started
    /// without standard input; with no number left they are an error,
    /// never a handle that is not there. Runs on its own: it closes this
    /// process's standard input and lowers its limit.
    #[test]
    fn sams_own_descriptors_work_at_any_number_and_fail_when_none_is_left() {
        if !alone("sams_own_descriptors_work_at_any_number_and_fail_when_none_is_left") {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        let top = open_path(tmp.path()).unwrap();
        // SAFETY: closes this copy's standard input, which nothing uses.
        assert_eq!(unsafe { libc::close(0) }, 0);
        let fd = open_path(tmp.path()).expect("a handle at number 0");
        assert_eq!(fd.as_raw_fd(), 0);
        drop(fd);
        let fd = openat2_beneath(&top, Path::new("sub")).expect("a place at number 0");
        assert_eq!(fd.as_raw_fd(), 0);
        drop(fd);
        let fd = memfd_with(b"the room's rules").expect("data at number 0");
        assert_eq!(fd.as_raw_fd(), 0);
        let mut back = String::new();
        std::fs::File::from(fd).read_to_string(&mut back).unwrap();
        assert_eq!(back, "the room's rules");

        // No number left at all.
        let mut lim: libc::rlimit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes the struct given.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        set_nofile(0, lim.rlim_max);
        let handle = open_path(tmp.path()).map(|_| ());
        let place = openat2_beneath(&top, Path::new("sub")).map(|_| ());
        let data = memfd_with(b"x").map(|_| ());
        set_nofile(lim.rlim_cur, lim.rlim_max);
        for (what, r) in [
            ("handle", handle.map_err(anyhow::Error::from)),
            ("place", place.map_err(anyhow::Error::from)),
            ("data", data),
        ] {
            let e = r.expect_err(what);
            assert!(
                format!("{e:#}").contains("Too many open files"),
                "{what}: {e:#}"
            );
        }
    }

    /// A place on a read-only file system is known as one (a room never
    /// gets it writable), and one on a writable file system is not. The
    /// copy of this test runs in Bubblewrap with the whole computer shown
    /// read-only and a fresh writable /dev.
    #[test]
    fn a_place_on_a_read_only_file_system_is_known_as_one() {
        const NAME: &str = "a_place_on_a_read_only_file_system_is_known_as_one";
        if is_own_process(NAME) {
            let root = open_path(Path::new("/")).unwrap();
            assert!(read_only_filesystem(&root), "/ is shown read-only");
            let dev = open_path(Path::new("/dev")).unwrap();
            assert!(!read_only_filesystem(&dev), "/dev is writable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        assert!(!read_only_filesystem(&open_path(tmp.path()).unwrap()));
        let Some(bwrap) = sam_core::HostInfo::probe().tools.bwrap else {
            crate::contracts::skip("bubblewrap is not installed").unwrap_or_else(|e| panic!("{e}"));
            return;
        };
        let mut wrap: Vec<OsString> = vec![bwrap.path.into()];
        wrap.extend(
            [
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--die-with-parent",
                "--",
            ]
            .map(OsString::from),
        );
        passed_alone(own_process(NAME, &wrap).output().unwrap());
    }

    /// The start record names who asked: the program that started the
    /// requesting one (here this test program, which starts a copy of
    /// itself that connects).
    #[test]
    fn a_request_is_recorded_as_asked_by_the_program_that_started_the_requester() {
        const NAME: &str =
            "a_request_is_recorded_as_asked_by_the_program_that_started_the_requester";
        const AT: &str = "SAM_TEST_ASK_AT";
        if is_own_process(NAME) {
            // The requester: connects and waits until the other side is done.
            let mut c = UnixStream::connect(std::env::var(AT).unwrap()).unwrap();
            let mut rest = Vec::new();
            c.read_to_end(&mut rest).unwrap();
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let at = tmp.path().join("ask");
        let listener = UnixListener::bind(&at).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut child = own_process(NAME, &[])
            .env(AT, &at)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        let stream = loop {
            match listener.accept() {
                Ok((c, _)) => break c,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < end, "the requester never came");
                    assert!(child.try_wait().unwrap().is_none(), "the requester left");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        };
        let by = asked_by(&stream);
        drop(stream);
        passed_alone(child.wait_with_output().unwrap());
        let me = std::fs::read_to_string("/proc/self/comm").unwrap();
        assert_eq!(by, me.trim());
    }

    /// A room is named in the start record by its program's file name;
    /// "?" when the request names no program.
    #[test]
    fn a_room_is_named_by_its_programs_file_name() {
        assert_eq!(
            program_name(&s(&[
                "/usr/libexec/glycin-loaders/2+/glycin-image-rs",
                "--dbus-fd",
                "3"
            ])),
            "glycin-image-rs"
        );
        assert_eq!(program_name(&s(&["python3"])), "python3");
        assert_eq!(program_name(&[]), "?");
    }

    /// A received connection closes when a program starts (it reaches a
    /// room only at the number the service gives it); a receive with
    /// nothing waiting returns at once, and the end of the stream reads
    /// as no bytes, not as an error.
    #[test]
    fn a_receive_takes_connections_close_on_exec_and_never_waits() {
        let (a, b) = UnixStream::pair().unwrap();
        let null = dev_null();
        send_with_fds(&a, b"x", &[null.as_raw_fd()]).unwrap();
        let mut buf = [0u8; 4];
        let mut got = Vec::new();
        assert_eq!(recv_with_fds(&b, &mut buf, &mut got, 3).unwrap(), 1);
        assert_eq!(got.len(), 1);
        // SAFETY: F_GETFD only reads the descriptor's flags.
        let flags = unsafe { libc::fcntl(got[0].as_raw_fd(), libc::F_GETFD) };
        assert!(
            flags & libc::FD_CLOEXEC != 0,
            "closed when a program starts"
        );
        let e = recv_with_fds(&b, &mut buf, &mut got, 3).expect_err("nothing waits");
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        // The sender is done (a shutdown, not a close: a copy another
        // test's new process holds for a moment would delay the end).
        a.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(recv_with_fds(&b, &mut buf, &mut got, 3).unwrap(), 0);
        assert_eq!(got.len(), 1);
    }

    /// Only passed connections are taken from what comes with a request:
    /// the sender's credentials, which the kernel adds where the socket
    /// asks for them, are never taken for connections.
    #[test]
    fn credentials_that_come_with_a_request_are_never_taken_for_connections() {
        let (a, b) = UnixStream::pair().unwrap();
        let one: libc::c_int = 1;
        // SAFETY: setsockopt reads the int given, of the size given.
        let r = unsafe {
            libc::setsockopt(
                b.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(r, 0);
        (&a).write_all(b"x").unwrap();
        let mut buf = [0u8; 4];
        let mut got = Vec::new();
        assert_eq!(recv_with_fds(&b, &mut buf, &mut got, 3).unwrap(), 1);
        // Given up without closing: numbers that are no connections of
        // ours must not be closed.
        let taken: Vec<RawFd> = got.into_iter().map(IntoRawFd::into_raw_fd).collect();
        assert!(taken.is_empty(), "taken for connections: {taken:?}");
    }

    /// Waiting for a request ends with an error when nothing comes in
    /// time or when the app's start ends, and returns once something comes.
    #[test]
    fn waiting_for_a_request_ends_in_time_and_when_the_start_ends() {
        let (a, b) = UnixStream::pair().unwrap();
        let stop = AtomicBool::new(false);
        let begin = Instant::now();
        let e = wait_readable(&b, Duration::from_millis(500), &stop).expect_err("nothing came");
        assert!(e.contains("too long"), "{e}");
        assert!(begin.elapsed() >= Duration::from_millis(500));
        stop.store(true, Ordering::SeqCst);
        let e = wait_readable(&b, Duration::from_secs(10), &stop).expect_err("the start ended");
        assert!(e.contains("start ended"), "{e}");
        stop.store(false, Ordering::SeqCst);
        (&a).write_all(b"x").unwrap();
        assert_eq!(wait_readable(&b, Duration::from_secs(10), &stop), Ok(()));
    }

    /// A signal that interrupts the wait for a request (the launcher gets
    /// signals, such as one when a child ends) does not end the wait: the
    /// request is still read.
    #[test]
    fn a_signal_during_the_wait_for_a_request_does_not_end_it() {
        use std::os::unix::thread::JoinHandleExt;
        extern "C" fn nothing(_: libc::c_int) {}
        // SIGURG (ignored by default, sent by nothing else here) with a
        // handler that does not restart calls: it interrupts the wait.
        // SAFETY: sigaction with zeroed structs filled as documented.
        let old = unsafe {
            let mut new: libc::sigaction = std::mem::zeroed();
            new.sa_sigaction = nothing as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut new.sa_mask);
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGURG, &new, &mut old), 0);
            old
        };
        let (a, b) = UnixStream::pair().unwrap();
        let waiting = std::thread::spawn(move || {
            wait_readable(&b, Duration::from_secs(10), &AtomicBool::new(false))
        });
        let thread = waiting.as_pthread_t();
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(20));
            // SAFETY: a signal to a thread that is not joined yet.
            unsafe { libc::pthread_kill(thread, libc::SIGURG) };
        }
        // Fails only when the wait has ended already (its end of the
        // connection is gone); the check below then says why.
        let _ = (&a).write_all(b"x");
        let r = waiting.join().unwrap();
        // SAFETY: puts back the handling found before.
        unsafe { libc::sigaction(libc::SIGURG, &old, std::ptr::null_mut()) };
        assert_eq!(r, Ok(()));
    }

    /// A request never brings more connections than a request may have,
    /// also when they come in parts: once the most have come, a later
    /// part with one more is refused.
    #[test]
    fn a_request_never_brings_more_connections_than_allowed_in_parts() {
        let (a, b) = UnixStream::pair().unwrap();
        let null = dev_null();
        let body = b"{}";
        let mut msg = (body.len() as u32).to_be_bytes().to_vec();
        msg.extend(body);
        send_with_fds(&a, &msg[..1], &vec![null.as_raw_fd(); room_rules::MAX_FDS]).unwrap();
        send_with_fds(&a, &msg[1..], &[null.as_raw_fd()]).unwrap();
        let state = State::default();
        state.fd_budget.store(10_000, Ordering::SeqCst);
        let mut held = Held::new(&state);
        let e = read_message(&b, &mut held).expect_err("one more than allowed");
        assert!(e.contains("too many connections"), "{e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// A device place missing when the app starts is not in the app, so it
    /// leaves the floor plan: a device plugged in later never reaches a
    /// room by its name. One present stays.
    #[test]
    fn a_device_place_missing_at_the_start_leaves_the_floor_plan() {
        let plan = FloorPlan::from_bwrap_args(&s(&[
            "--dev-bind-try",
            "/dev/sam-test-not-here",
            "/dev/sam-test-not-here",
            "--dev-bind-try",
            "/dev/null",
            "/dev/null",
            "--",
            "x",
        ]))
        .unwrap();
        let (plan, sources) = plan_at_start(plan);
        let at: Vec<&Path> = plan.entries.iter().map(|e| e.at()).collect();
        assert_eq!(at, vec![Path::new("/dev/null")]);
        assert_eq!(sources.len(), plan.entries.len());
    }

    /// An answer to a stand-in that has already gone never ends SAM's
    /// launcher, also with SIGPIPE at its default (as `sam-jail run` has
    /// it). SAM sends without the signal on purpose; Rust's own socket
    /// writes do too today, so this guards against either changing.
    /// Checked in a child process: this test runs itself again.
    #[test]
    fn an_answer_to_a_stand_in_that_left_never_ends_the_launcher() {
        const NAME: &str =
            "room_service::tests::an_answer_to_a_stand_in_that_left_never_ends_the_launcher";
        if std::env::var_os("SAM_TEST_SIGPIPE_CHILD").is_some() {
            // SAFETY: sets one signal's handling to its default.
            unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
            let (mut a, b) = UnixStream::pair().unwrap();
            drop(b);
            answer(&mut a, &serde_json::json!({ "exit": 0 }));
            answer(&mut a, &serde_json::json!({ "exit": 0 }));
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--test-threads=1"])
            .env("SAM_TEST_SIGPIPE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success() && String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "{:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// A receive keeps at most the connections it has room for: one more
    /// is refused, never kept uncounted (CMSG_SPACE's rounding would fit
    /// it).
    #[test]
    fn a_receive_keeps_no_more_connections_than_counted() {
        let (a, b) = UnixStream::pair().unwrap();
        let nulls: Vec<OwnedFd> = (0..4)
            .map(|_| OwnedFd::from(std::fs::File::open("/dev/null").unwrap()))
            .collect();
        let raw: Vec<RawFd> = nulls.iter().map(|f| f.as_raw_fd()).collect();
        send_with_fds(&a, b"x", &raw).unwrap();
        let mut buf = [0u8; 1];
        let mut got = Vec::new();
        let r = recv_with_fds(&b, &mut buf, &mut got, 3);
        assert!(r.is_err(), "more connections than room for them were taken");
        assert!(got.len() <= 3, "{} kept", got.len());
    }

    /// A failed start of the room's Bubblewrap is reported as one even when
    /// the room's connections take every low number (where the report's
    /// own pipe would be): never a room that seems started.
    #[test]
    fn a_failed_start_is_reported_whatever_numbers_the_room_takes() {
        let open = || OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
        // Low numbers taken first, then the room's connections above them,
        // then the low ones freed again: the start's own pipe lands among
        // the numbers the room's connections are moved to.
        let low: Vec<OwnedFd> = (0..60).map(|_| open()).collect();
        let fds: Vec<OwnedFd> = (0..40).map(|_| open()).collect();
        drop(low);
        let map: Vec<(RawFd, RawFd)> = fds
            .iter()
            .enumerate()
            .map(|(i, f)| (f.as_raw_fd(), 3 + i as RawFd))
            .collect();
        let r = spawn_room(
            Path::new("/nonexistent/sam-test-bwrap"),
            &[],
            &map,
            42,
            [true; 3],
            &[],
            None,
        );
        let e = r
            .err()
            .expect("a start that cannot happen was reported as started");
        assert!(format!("{e:#}").contains("No such file"), "{e:#}");
    }

    /// The room's Bubblewrap gets each connection at its number, its
    /// standard streams on /dev/null when not passed, and its exit code.
    #[test]
    fn a_room_gets_its_connections_at_their_numbers() {
        let (r, w) = pipe().unwrap();
        let mut p = spawn_room(
            Path::new("/bin/sh"),
            &s(&["-c", "echo via-9 >&9; exit 3"]),
            &[(w.as_raw_fd(), 9)],
            9,
            [true; 3],
            &[],
            None,
        )
        .unwrap();
        drop(w);
        let mut out = String::new();
        std::fs::File::from(r).read_to_string(&mut out).unwrap();
        assert_eq!(out, "via-9\n");
        assert_eq!(exit_code(p.wait().unwrap()), 3);
    }

    /// A drive is one a person may unmount when it is not the file system
    /// of the root or the home, or lies under /media, /mnt, /run/media.
    #[test]
    fn drives_that_may_be_unmounted_are_known_by_their_file_system() {
        let fixed = [1, 2];
        assert!(!may_be_unmounted(Path::new("/usr/lib"), 1, &fixed));
        assert!(!may_be_unmounted(
            Path::new("/home/me/Documents"),
            2,
            &fixed
        ));
        assert!(may_be_unmounted(
            Path::new("/data/apps/x.AppImage"),
            7,
            &fixed
        ));
        assert!(may_be_unmounted(Path::new("/home/me/sshfs/f"), 9, &fixed));
        assert!(may_be_unmounted(Path::new("/mnt/stick"), 1, &fixed));
    }

    /// Room service starts only with a Bubblewrap that can show places by
    /// handle: with an older one, programs keep the computer's own
    /// Bubblewrap instead of a stand-in that could build no room.
    #[test]
    fn rooms_need_a_bubblewrap_that_shows_places_by_handle() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let fake = |name: &str, help: &str| {
            let p = tmp.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\ncat <<'EOF'\n{help}\nEOF\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let old = fake(
            "old",
            "usage: bwrap\n    --bind SRC DEST\n    --ro-bind SRC DEST",
        );
        let new = fake(
            "new",
            "usage: bwrap\n    --bind-fd FD DEST\n    --ro-bind-fd FD DEST",
        );
        assert!(!bwrap_builds_rooms(&old));
        assert!(bwrap_builds_rooms(&new));
        assert!(!bwrap_builds_rooms(&tmp.path().join("missing")));
    }

    /// A source on a drive that may be unmounted is not held open (the
    /// drive stays free to unmount while the app runs); a room still shows
    /// it, but never another folder put in its place since the start.
    #[test]
    fn a_source_on_a_removable_drive_is_remembered_not_held() {
        let tmp = tempfile::tempdir().unwrap();
        let stick = tmp.path().join("stick");
        std::fs::create_dir(&stick).unwrap();
        let plan = FloorPlan::from_bwrap_args(&s(&[
            "--ro-bind",
            stick.to_str().unwrap(),
            "/run/media/me/stick",
            "--",
            "x",
        ]))
        .unwrap();
        let (_, sources) = plan_at_start_with(plan, |p, _| p.starts_with(tmp.path()));
        assert!(matches!(sources[0], Some(SourceHandle::Known { .. })));
        let whole = Source {
            entry: 0,
            rel: PathBuf::new(),
        };
        assert!(open_source(&whole, &sources).is_ok());
        std::fs::rename(&stick, tmp.path().join("old")).unwrap();
        std::fs::create_dir(&stick).unwrap();
        let e = open_source(&whole, &sources).unwrap_err();
        assert!(
            e.to_string().contains("no longer what the app was shown"),
            "{e}"
        );
    }

    /// The descriptors held for rooms stay within what the launcher's
    /// limit leaves free, and a reservation gives back what did not come.
    #[test]
    fn descriptors_for_rooms_stay_within_the_launchers_limit() {
        assert_eq!(budget_from(1024, 100), 1024 - 100 - FD_RESERVE);
        assert_eq!(budget_from(200, 100), 0);
        assert_eq!(budget_from(libc::RLIM_INFINITY, 100), MAX_SERVICE_FDS);
        let state = State::default();
        state.fd_budget.store(300, Ordering::SeqCst);
        let mut a = Held::new(&state);
        assert_eq!(a.reserve_passed(253), 253);
        let mut b = Held::new(&state);
        // Only what is left: never more than the budget, in any order.
        assert_eq!(b.reserve_passed(253), 47);
        assert!(!b.add_own(1));
        b.unreserve_passed(47);
        assert!(b.add_own(40));
        assert!(!b.add_own(8));
        assert_eq!(state.fds.load(Ordering::SeqCst), 293);
        drop(a);
        drop(b);
        assert_eq!(state.fds.load(Ordering::SeqCst), 0);
        assert_eq!(state.held.load(Ordering::SeqCst), 0);
        // Passed connections stay within MAX_HELD too.
        state.fd_budget.store(10_000, Ordering::SeqCst);
        let mut c = Held::new(&state);
        assert_eq!(c.reserve_passed(MAX_HELD + 10), MAX_HELD);
    }

    /// Far longer than any wait in these tests should take: a wait that
    /// lasts this long missed what should have ended it.
    const LONG: Duration = Duration::from_secs(20);
    /// What "at once" may take on a busy computer.
    const QUICK: Duration = Duration::from_secs(5);

    fn state_with_budget(budget: usize) -> State {
        let state = State::default();
        state.fd_budget.store(budget, Ordering::SeqCst);
        state
    }

    /// How many rooms wait in line for descriptors.
    fn in_line(state: &State) -> usize {
        state.fd_queue.lock().unwrap().waiting.len()
    }

    /// Waits until `n` rooms wait in line.
    fn until_in_line(state: &State, n: usize) {
        let end = std::time::Instant::now() + QUICK;
        while in_line(state) != n {
            assert!(std::time::Instant::now() < end, "never {n} in line");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A room that waits for `n` descriptors in a thread of `scope`: what
    /// its wait ended with, and how long it took, arrive on the receiver.
    /// What it got is given back when the thread ends.
    fn waiter<'s>(
        scope: &'s std::thread::Scope<'s, '_>,
        state: &'s State,
        n: usize,
        limit: Duration,
    ) -> std::sync::mpsc::Receiver<(Result<(), NoRoom>, Duration)> {
        let (tx, rx) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let mut h = Held::new(state);
            let begin = std::time::Instant::now();
            let r = h.wait_for_own(n, limit);
            let _ = tx.send((r, begin.elapsed()));
        });
        rx
    }

    /// A room whose descriptors do not fit while another room is built
    /// waits, and goes as soon as that room gives them back (not when its
    /// wait runs out); everything is given back after.
    #[test]
    fn a_room_waiting_for_descriptors_goes_as_soon_as_a_build_gives_them_back() {
        let state = state_with_budget(100);
        let mut build = Held::new(&state);
        assert_eq!(build.wait_for_own(60, LONG), Ok(()));
        std::thread::scope(|s| {
            let w = waiter(s, &state, 50, LONG);
            until_in_line(&state, 1);
            assert!(
                w.recv_timeout(Duration::from_millis(300)).is_err(),
                "the room did not wait while the other was built"
            );
            build.release();
            let (r, took) = w.recv_timeout(LONG).unwrap();
            assert_eq!(r, Ok(()));
            assert!(took < QUICK, "the room went only after {took:?}");
        });
        assert_eq!(state.fds.load(Ordering::SeqCst), 0);
        assert_eq!(state.building.load(Ordering::SeqCst), 0);
        assert_eq!(in_line(&state), 0);
    }

    /// The stop of the service ends a room's wait for descriptors at once,
    /// and a room asking after the stop does not wait at all.
    #[test]
    fn a_wait_for_descriptors_ends_at_once_when_the_service_stops() {
        let state = state_with_budget(100);
        let mut build = Held::new(&state);
        assert_eq!(build.wait_for_own(60, LONG), Ok(()));
        std::thread::scope(|s| {
            let w = waiter(s, &state, 50, LONG);
            until_in_line(&state, 1);
            state.stop_now();
            let (r, took) = w.recv_timeout(LONG).unwrap();
            assert_eq!(r, Err(NoRoom::Stopped));
            assert!(took < QUICK, "the wait ended only after {took:?}");
        });
        let mut late = Held::new(&state);
        assert_eq!(late.wait_for_own(10, LONG), Err(NoRoom::Stopped));
        // Only the room being built still holds descriptors.
        assert_eq!(state.fds.load(Ordering::SeqCst), 60);
        assert_eq!(in_line(&state), 0);
    }

    /// A wait for descriptors that never come ends when its time is up,
    /// with nothing left counted for it.
    #[test]
    fn a_wait_for_descriptors_gives_up_at_its_deadline() {
        let state = state_with_budget(100);
        let mut build = Held::new(&state);
        assert_eq!(build.wait_for_own(60, LONG), Ok(()));
        let mut h = Held::new(&state);
        let begin = std::time::Instant::now();
        assert_eq!(
            h.wait_for_own(50, Duration::from_millis(300)),
            Err(NoRoom::TimedOut)
        );
        let took = begin.elapsed();
        assert!(
            took >= Duration::from_millis(300) && took < QUICK,
            "gave up after {took:?}"
        );
        assert_eq!(state.fds.load(Ordering::SeqCst), 60);
        assert_eq!(in_line(&state), 0);
    }

    /// A room that would not fit even with nothing else held (its own
    /// descriptors and the connections its request holds are more than the
    /// whole budget) is refused at once, without waiting; one that exactly
    /// fills the budget is not.
    #[test]
    fn a_room_that_cannot_fit_even_alone_is_refused_without_waiting() {
        let state = state_with_budget(100);
        let mut h = Held::new(&state);
        assert_eq!(h.reserve_passed(10), 10);
        let begin = std::time::Instant::now();
        assert_eq!(h.wait_for_own(91, LONG), Err(NoRoom::Never));
        assert!(begin.elapsed() < QUICK, "it waited {:?}", begin.elapsed());
        assert_eq!(state.fds.load(Ordering::SeqCst), 10);
        assert_eq!(h.wait_for_own(90, LONG), Ok(()));
        assert_eq!(state.fds.load(Ordering::SeqCst), 100);
    }

    /// Rooms wait in line while rooms are built: a later room waits behind
    /// the first even when it would fit now (so a big room is not passed
    /// again and again by small ones), and goes as soon as the first leaves
    /// the line (here: its wait ran out).
    #[test]
    fn rooms_waiting_for_descriptors_go_in_line_while_rooms_are_built() {
        let state = state_with_budget(100);
        let mut build = Held::new(&state);
        assert_eq!(build.wait_for_own(60, LONG), Ok(()));
        std::thread::scope(|s| {
            let first = waiter(s, &state, 50, Duration::from_secs(2));
            until_in_line(&state, 1);
            let second = waiter(s, &state, 30, LONG);
            assert!(
                second.recv_timeout(Duration::from_millis(300)).is_err(),
                "a later room went before the first in line"
            );
            // Both really waited in line (not a second that started late).
            until_in_line(&state, 2);
            let (r, _) = first.recv_timeout(LONG).unwrap();
            assert_eq!(r, Err(NoRoom::TimedOut));
            let left = std::time::Instant::now();
            let (r, _) = second.recv_timeout(LONG).unwrap();
            assert_eq!(r, Ok(()));
            assert!(
                left.elapsed() < QUICK,
                "the next in line went only after {:?}",
                left.elapsed()
            );
        });
        drop(build);
        assert_eq!(state.fds.load(Ordering::SeqCst), 0);
        assert_eq!(state.building.load(Ordering::SeqCst), 0);
    }

    /// While nothing is being built, nothing the first in line waits for
    /// comes back soon (here the connections of a request hold the
    /// budget): a later room that fits goes first instead of waiting
    /// behind it, and the first goes once enough is given back. A room
    /// built and finished before counts as built no more.
    #[test]
    fn while_nothing_is_being_built_a_room_that_fits_may_pass_one_that_waits() {
        let state = state_with_budget(100);
        let mut before = Held::new(&state);
        assert_eq!(before.wait_for_own(10, LONG), Ok(()));
        assert_eq!(state.building.load(Ordering::SeqCst), 1);
        before.release();
        drop(before);
        assert_eq!(state.building.load(Ordering::SeqCst), 0);
        let mut request = Held::new(&state);
        assert_eq!(request.reserve_passed(30), 30);
        std::thread::scope(|s| {
            let first = waiter(s, &state, 80, LONG);
            until_in_line(&state, 1);
            let second = waiter(s, &state, 20, LONG);
            let (r, took) = second.recv_timeout(LONG).unwrap();
            assert_eq!(r, Ok(()));
            assert!(took < QUICK, "the room that fits waited {took:?}");
            assert!(
                first.recv_timeout(Duration::from_millis(100)).is_err(),
                "the first room went while the connections held the budget"
            );
            request.release();
            let freed = std::time::Instant::now();
            let (r, _) = first.recv_timeout(LONG).unwrap();
            assert_eq!(r, Ok(()));
            assert!(
                freed.elapsed() < QUICK,
                "the first room went only after {:?}",
                freed.elapsed()
            );
        });
        assert_eq!(state.fds.load(Ordering::SeqCst), 0);
        assert_eq!(state.building.load(Ordering::SeqCst), 0);
    }

    /// While nothing is being built, a later room passes the first in line
    /// only when the first cannot go now: when what was given back lets
    /// the first go (here exactly), the later room waits for it, even
    /// though it would fit itself, and goes after it. Else a steady stream
    /// of small rooms could keep a big one waiting until its time ran out.
    #[test]
    fn a_later_room_never_passes_the_first_in_line_when_that_one_fits() {
        let state = state_with_budget(100);
        let mut request = Held::new(&state);
        assert_eq!(request.reserve_passed(70), 70);
        std::thread::scope(|s| {
            let first = waiter(s, &state, 50, LONG);
            until_in_line(&state, 1);
            // 20 of the request's 70 given back without waking anyone yet,
            // as when a later room looks between a giving back and its
            // wake-up: the first fits now (50 + 50 of 100), the later room
            // too (50 + 30), but not both.
            request.passed -= 20;
            request.all -= 20;
            state.held.fetch_sub(20, Ordering::SeqCst);
            state.fds.fetch_sub(20, Ordering::SeqCst);
            let second = waiter(s, &state, 30, LONG);
            if let Ok(r) = second.recv_timeout(Duration::from_millis(300)) {
                panic!("a later room passed the first in line, which fit: {r:?}");
            }
            // The later room really waits in line (or the first already
            // went: a wake-up of its own).
            let end = std::time::Instant::now() + QUICK;
            while in_line(&state) < 2 && state.building.load(Ordering::SeqCst) == 0 {
                assert!(
                    std::time::Instant::now() < end,
                    "the later room never waited"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            state.wake_fd_waiters();
            let (r, _) = first.recv_timeout(LONG).unwrap();
            assert_eq!(r, Ok(()));
            // The first's thread ends and gives back: the later room goes.
            let (r, _) = second.recv_timeout(LONG).unwrap();
            assert_eq!(r, Ok(()));
        });
        assert_eq!(state.fds.load(Ordering::SeqCst), 50);
        drop(request);
        assert_eq!(state.fds.load(Ordering::SeqCst), 0);
        assert_eq!(state.building.load(Ordering::SeqCst), 0);
        assert_eq!(in_line(&state), 0);
    }

    /// A request being read counts room for every connection it may pass
    /// before each receive, and gives back at once what did not come: a
    /// room that waited only for that room goes as soon as it is given
    /// back, not when some room is released later or its wait runs out.
    #[test]
    fn a_room_waiting_for_descriptors_goes_when_a_request_being_read_gives_back_what_did_not_come()
    {
        let state = state_with_budget(100);
        let mut reading = Held::new(&state);
        assert_eq!(reading.reserve_passed(80), 80);
        std::thread::scope(|s| {
            let room = waiter(s, &state, 30, LONG);
            until_in_line(&state, 1);
            assert!(
                room.recv_timeout(Duration::from_millis(300)).is_err(),
                "the room did not wait for the request being read"
            );
            // Three connections came, 77 did not.
            reading.unreserve_passed(77);
            let (r, _) = room
                .recv_timeout(QUICK)
                .expect("the room did not go when the request gave back what did not come");
            assert_eq!(r, Ok(()));
        });
        assert_eq!(state.fds.load(Ordering::SeqCst), 3);
        drop(reading);
        assert_eq!(state.fds.load(Ordering::SeqCst), 0);
    }

    /// How many requests being read wait for the rooms being built.
    fn readers(state: &State) -> usize {
        state.fd_queue.lock().unwrap().readers
    }

    /// A request being read when rooms being built hold part of what it
    /// may need waits for them to give it back, and gets all it asked for,
    /// not only what was left; no new room is built while it waits (one
    /// that would fit waits), and that room goes once the request has its
    /// share.
    #[test]
    fn a_request_being_read_waits_for_rooms_being_built_and_new_rooms_wait_for_it() {
        let state = state_with_budget(100);
        let mut build = Held::new(&state);
        assert_eq!(build.wait_for_own(60, LONG), Ok(()));
        std::thread::scope(|s| {
            let (tx, reader) = std::sync::mpsc::channel();
            let st = &state;
            s.spawn(move || {
                let mut h = Held::new(st);
                let got = h.reserve_passed_waiting(50, std::time::Instant::now() + LONG);
                let _ = tx.send(got);
            });
            let end = std::time::Instant::now() + QUICK;
            while readers(&state) != 1 {
                assert!(std::time::Instant::now() < end, "the request never waited");
                std::thread::sleep(Duration::from_millis(5));
            }
            let room = waiter(s, &state, 30, LONG);
            until_in_line(&state, 1);
            assert!(
                room.recv_timeout(Duration::from_millis(300)).is_err(),
                "a room was built while a request waited"
            );
            build.release();
            let freed = std::time::Instant::now();
            assert_eq!(reader.recv_timeout(LONG).unwrap(), 50);
            let (r, _) = room.recv_timeout(LONG).unwrap();
            assert_eq!(r, Ok(()));
            assert!(
                freed.elapsed() < QUICK,
                "the room went only after {:?}",
                freed.elapsed()
            );
        });
        assert_eq!(state.fds.load(Ordering::SeqCst), 0);
        assert_eq!(readers(&state), 0);
    }

    /// A request being read waits for rooms being built no longer than its
    /// reading may take, and not after the service stopped; then it gets
    /// what is left. While nothing is being built it does not wait at all:
    /// what the connections of other requests hold is not given back soon.
    #[test]
    fn a_request_being_read_waits_only_while_rooms_are_built_and_only_until_its_end() {
        let state = state_with_budget(100);
        let mut build = Held::new(&state);
        assert_eq!(build.wait_for_own(60, LONG), Ok(()));
        // Its reading ends.
        let mut h = Held::new(&state);
        let begin = std::time::Instant::now();
        let end = begin + Duration::from_millis(300);
        assert_eq!(h.reserve_passed_waiting(50, end), 40);
        let took = begin.elapsed();
        assert!(
            took >= Duration::from_millis(300) && took < QUICK,
            "waited {took:?}"
        );
        h.release();
        assert_eq!(readers(&state), 0);
        // The service stops.
        std::thread::scope(|s| {
            let (tx, reader) = std::sync::mpsc::channel();
            let st = &state;
            s.spawn(move || {
                let mut h = Held::new(st);
                let begin = std::time::Instant::now();
                let got = h.reserve_passed_waiting(50, begin + LONG);
                let _ = tx.send((got, begin.elapsed()));
            });
            let end = std::time::Instant::now() + QUICK;
            while readers(&state) != 1 {
                assert!(std::time::Instant::now() < end, "the request never waited");
                std::thread::sleep(Duration::from_millis(5));
            }
            state.stop_now();
            let (got, took) = reader.recv_timeout(LONG).unwrap();
            assert_eq!(got, 40);
            assert!(took < QUICK, "the stop ended the wait only after {took:?}");
        });
        // Nothing being built: the connections of a request hold the budget.
        let state = state_with_budget(100);
        let mut request = Held::new(&state);
        assert_eq!(request.reserve_passed(60), 60);
        let mut h = Held::new(&state);
        let begin = std::time::Instant::now();
        assert_eq!(h.reserve_passed_waiting(50, begin + LONG), 40);
        assert!(begin.elapsed() < QUICK, "waited {:?}", begin.elapsed());
        assert_eq!(readers(&state), 0);
    }
}

#[cfg(test)]
mod service_tests {
    //! The service itself: its start record, its stop, its socket, the
    //! answers it sends, and the rooms it runs. Rooms here are run by a
    //! stand-in for Bubblewrap that runs the room's command right here, so
    //! the service's own decisions show without a sandbox (the tests in
    //! tests/room_service*.rs run real rooms).
    use super::*;
    use crate::room_rules::{Request, VERSION};
    use std::time::Instant;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn request(ops: &[&[&str]], command: &[&str]) -> Request {
        Request {
            v: VERSION,
            ops: ops.iter().map(|o| s(o)).collect(),
            flags: vec![],
            command: s(command),
            env: Default::default(),
            cwd: "/".into(),
            fds: vec![],
            limits: vec![],
            umask: None,
        }
    }

    /// A test that changes something of its whole process (how a signal is
    /// handled, the descriptor limit) runs alone in a child process: this
    /// test program started again for just that test.
    fn in_own_process(name: &str, body: impl FnOnce()) {
        const VAR: &str = "SAM_TEST_SERVICE_OWN_PROCESS";
        if std::env::var(VAR).is_ok_and(|v| v == name) {
            body();
            return;
        }
        let full = format!("room_service::service_tests::{name}");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &full, "--test-threads=1", "--nocapture"])
            .env(VAR, name)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{:?}\n{stdout}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A service listening in `dir`, made as `RoomService::open` makes it
    /// (without its check for SAM's room helper, which the stand-in for
    /// Bubblewrap below never runs).
    fn service_in(dir: &Path) -> RoomService {
        let socket = dir.join("rooms");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        RoomService {
            socket,
            listener: Some(listener),
            state: Arc::new(State::default()),
            accept: None,
        }
    }

    /// An app that sees `app` (writable for its mount), and may write only
    /// in `write` by its Landlock rules.
    fn context(app: &Path, bwrap: &Path, write: &[PathBuf]) -> RoomContext {
        let a = app.to_str().unwrap();
        RoomContext {
            plan: FloorPlan::from_bwrap_args(&s(&["--bind", a, a, "--", "x"])).unwrap(),
            facts: AppFacts::default(),
            bwrap: bwrap.to_path_buf(),
            landlock: LandlockSpec {
                read: vec!["/".into()],
                write: write.to_vec(),
            },
            seccomp: SeccompSpec::default(),
        }
    }

    /// What `serve` keeps, with every source held open.
    fn served(ctx: RoomContext) -> Arc<Served> {
        let (plan, sources) = plan_at_start_with(ctx.plan.clone(), |_, _| false);
        Arc::new(Served {
            ctx: RoomContext { plan, ..ctx },
            sources,
            refuse_all: None,
        })
    }

    fn state_with_budget(n: usize) -> Arc<State> {
        let state = State::default();
        state.fd_budget.store(n, Ordering::SeqCst);
        Arc::new(state)
    }

    /// A stand-in for the computer's Bubblewrap: it writes its arguments
    /// down (one per line, in the file returned second), confirms SAM's
    /// layers the way SAM's room helper does (a line on the status
    /// connection the room's rules name), then runs the room's command
    /// right here. The command `unconfirmed` ends it with exit code 3
    /// before it confirms anything, as a room whose helper never reported.
    fn fake_bwrap(dir: &Path) -> (PathBuf, PathBuf) {
        let bwrap = dir.join("bwrap");
        let log = dir.join("bwrap-args");
        let script = format!(
            r#"export PATH=/usr/bin:/bin
printf '%s\n' "$@" > '{log}'
spec=; p2=; p1=
for a in "$@"; do
  if [ "$p2" = --ro-bind-data ] && [ "$a" = {SPEC_INSIDE} ]; then spec=$p1; fi
  p2=$p1; p1=$a
done
while [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done
shift 4
[ "$1" = unconfirmed ] && exit 3
status=$(tr '\0' '\n' < "/proc/self/fd/$spec" | sed -n 's/^status=//p')
echo "layers of the stand-in" > "/proc/self/fd/$status"
exec "$@"
"#,
            log = log.display()
        );
        write_program(&bwrap, &script);
        (bwrap, log)
    }

    /// Writes a shell script at `p` and makes it runnable. A program
    /// another test starts at that moment may hold the new file open for
    /// an instant, and Linux then refuses to run it ("Text file busy"); so
    /// this waits until the script runs (it ends at once when
    /// SAM_TEST_PROBE is set), for at most ten seconds.
    fn write_program(p: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let script = format!("#!/bin/sh\n[ -n \"$SAM_TEST_PROBE\" ] && exit 0\n{body}");
        std::fs::write(p, script).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let probe = std::process::Command::new(p)
                .env("SAM_TEST_PROBE", "1")
                .status();
            match probe {
                Err(e)
                    if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                        && Instant::now() < end =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                probe => {
                    assert!(probe.unwrap().success(), "{} does not run", p.display());
                    return;
                }
            }
        }
    }

    fn write_request(conn: &UnixStream, req: &Request) {
        let body = serde_json::to_vec(req).unwrap();
        let mut c = conn;
        c.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        c.write_all(&body).unwrap();
    }

    /// The service's answer on `conn` (null when none came in 20 seconds).
    fn answer_of(conn: &UnixStream) -> serde_json::Value {
        conn.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut c = conn;
        let mut head = [0u8; 4];
        if c.read_exact(&mut head).is_err() {
            return serde_json::Value::Null;
        }
        let mut body = vec![0u8; u32::from_be_bytes(head) as usize];
        if c.read_exact(&mut body).is_err() {
            return serde_json::Value::Null;
        }
        serde_json::from_slice(&body).unwrap_or_default()
    }

    fn ask_service(socket: &Path, req: &Request) -> serde_json::Value {
        let conn = UnixStream::connect(socket).unwrap();
        write_request(&conn, req);
        answer_of(&conn)
    }

    /// One request served on its own connection, as the service serves it.
    fn ask_directly(state: &Arc<State>, served: &Arc<Served>, req: &Request) -> serde_json::Value {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let (st, sv) = (state.clone(), served.clone());
        let t = std::thread::spawn(move || serve_one(theirs, &st, &sv));
        write_request(&ours, req);
        let a = answer_of(&ours);
        drop(ours);
        t.join().unwrap();
        a
    }

    fn last_room_record(state: &State) -> String {
        let r = state.room_records.lock().unwrap();
        r.last().cloned().unwrap_or_default()
    }

    /// A handler that does nothing, set without SA_RESTART: a call it
    /// interrupts ends with EINTR (as with the launcher's own handlers).
    fn interrupting(sig: libc::c_int) {
        extern "C" fn nothing(_: libc::c_int) {}
        // SAFETY: a zeroed sigaction is valid; the handler is a plain
        // function that does nothing; the old action is not asked for.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = nothing as extern "C" fn(libc::c_int) as usize;
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            assert_eq!(libc::sigaction(sig, &sa, std::ptr::null_mut()), 0);
        }
    }

    fn thread_id() -> libc::pid_t {
        // SAFETY: gettid has no arguments and cannot fail.
        unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
    }

    /// Sends `sig` to thread `tid` of this process; false when that thread
    /// has already ended (the test then says what that means).
    fn signal_thread(tid: libc::pid_t, sig: libc::c_int) -> bool {
        // SAFETY: a signal to a thread of this process, by its id.
        let r = unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, sig) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            assert_eq!(e.raw_os_error(), Some(libc::ESRCH), "{e}");
            return false;
        }
        true
    }

    /// Waits until thread `tid` of this process sleeps (blocked in a call);
    /// false when that thread has already ended.
    fn wait_until_blocked(tid: libc::pid_t) -> bool {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let Ok(stat) = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")) else {
                return false;
            };
            let state = stat.rsplit_once(") ").and_then(|(_, r)| r.chars().next());
            if state == Some('S') {
                return true;
            }
            assert!(Instant::now() < end, "thread {tid} never blocked ({stat})");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The start record keeps at most MAX_ROOM_RECORDS lines about rooms
    /// and MAX_RECORDS refusals, in that order, and counts the rest: one
    /// line more than fits is counted, never kept.
    #[test]
    fn the_start_record_keeps_its_room_lines_and_counts_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let service = service_in(tmp.path());
        for i in 0..=MAX_ROOM_RECORDS {
            service.state.record_room(format!("room {i}"));
        }
        for i in 0..=MAX_RECORDS {
            service.state.record(format!("refusal {i}"));
        }
        let lines = service.stop();
        let mut want: Vec<String> = (0..MAX_ROOM_RECORDS).map(|i| format!("room {i}")).collect();
        want.push("sam-room: 1 more rooms not recorded".into());
        want.extend((0..MAX_RECORDS).map(|i| format!("refusal {i}")));
        want.push("sam-room: 1 more refusals not recorded".into());
        assert_eq!(lines, want);
    }

    /// A stop with nothing left to wait for returns at once and adds no
    /// line of its own to the start record (no "0 more …", no "0 requests
    /// still unfinished").
    #[test]
    fn a_stop_with_nothing_left_is_quick_and_adds_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let service = service_in(tmp.path());
        let started = Instant::now();
        let lines = service.stop();
        let took = started.elapsed();
        assert!(lines.is_empty(), "{lines:?}");
        assert!(took < Duration::from_secs(1), "the stop took {took:?}");
    }

    /// A request still not finished when the service stops is named in the
    /// start record after the short wait, never lost.
    #[test]
    fn a_stop_names_requests_still_unfinished() {
        let tmp = tempfile::tempdir().unwrap();
        let service = service_in(tmp.path());
        // One connection whose request never finishes.
        service.state.connections.store(1, Ordering::SeqCst);
        let lines = service.stop();
        assert_eq!(
            lines,
            vec!["sam-room: 1 requests still unfinished when the app's start ended".to_string()]
        );
    }

    /// The service's socket may have a path of 107 bytes, the most a Unix
    /// socket's address holds (108 with its closing NUL byte); one byte
    /// more is refused as too long.
    #[test]
    fn a_socket_path_of_the_longest_length_still_opens() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().as_os_str().len();
        assert!(
            base + "/d/rooms".len() < 107,
            "the temporary folder's path is too long for this test: {}",
            tmp.path().display()
        );
        for (len, too_long) in [(107, false), (108, true)] {
            let dir = tmp.path().join("d".repeat(len - base - 1 - "/rooms".len()));
            std::fs::create_dir(&dir).unwrap();
            assert_eq!(dir.join("rooms").as_os_str().len(), len);
            let r = RoomService::open(&dir);
            let said = r
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("too long"));
            assert_eq!(said, too_long, "{len} bytes: {:?}", r.as_ref().err());
            // Where this build has its room helper, it really listens.
            if let Ok(service) = r {
                assert!(UnixStream::connect(&service.socket).is_ok());
            }
        }
    }

    /// A service that is dropped without a stop ends like one: it stops
    /// listening and its socket is gone.
    #[test]
    fn dropping_the_service_ends_it_like_a_stop() {
        let tmp = tempfile::tempdir().unwrap();
        let mut service = service_in(tmp.path());
        let socket = service.socket.clone();
        service.serve_refusing(
            context(tmp.path(), Path::new("/nonexistent"), &[]),
            "no floor plan".into(),
        );
        assert!(UnixStream::connect(&socket).is_ok());
        drop(service);
        assert!(!socket.exists(), "the socket outlived its service");
        assert!(UnixStream::connect(&socket).is_err());
    }

    /// A Bubblewrap that knows only one of the two options that show a
    /// place by handle builds no room either.
    #[test]
    fn rooms_need_both_options_that_show_places_by_handle() {
        let tmp = tempfile::tempdir().unwrap();
        for (name, help, builds) in [
            ("only-ro", "usage: bwrap\n    --ro-bind-fd FD DEST", false),
            ("only-rw", "usage: bwrap\n    --bind-fd FD DEST", false),
            (
                "both",
                "usage: bwrap\n    --bind-fd FD DEST\n    --ro-bind-fd FD DEST",
                true,
            ),
        ] {
            let p = tmp.path().join(name);
            write_program(&p, &format!("cat <<'EOF'\n{help}\nEOF\n"));
            assert_eq!(bwrap_builds_rooms(&p), builds, "{name}");
        }
    }

    /// The start record says so when the launcher's descriptor limit leaves
    /// rooms fewer than 64 descriptors (so most rooms are refused), and
    /// only then: at 64 it says nothing, at 63 it does.
    #[test]
    fn a_descriptor_limit_leaving_rooms_fewer_than_64_is_recorded() {
        in_own_process(
            "a_descriptor_limit_leaving_rooms_fewer_than_64_is_recorded",
            || {
                let tmp = tempfile::tempdir().unwrap();
                for (want, said) in [(64usize, false), (63, true)] {
                    let dir = tmp.path().join(want.to_string());
                    std::fs::create_dir(&dir).unwrap();
                    let mut service = service_in(&dir);
                    let ctx = context(&dir, Path::new("/nonexistent"), &[]);
                    // A soft limit the budget is not capped at, then lowered
                    // by what it leaves beyond `want`.
                    // SAFETY: getrlimit and setrlimit read and write the
                    // struct given.
                    unsafe {
                        let mut lim: libc::rlimit = std::mem::zeroed();
                        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
                        lim.rlim_cur = lim.rlim_max.min(4096);
                        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
                        let left = fd_budget();
                        assert!(left > want, "the hard limit is too low for this test");
                        lim.rlim_cur -= (left - want) as libc::rlim_t;
                        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
                    }
                    assert_eq!(fd_budget(), want);
                    service.serve_refusing(ctx, "no floor plan".into());
                    let lines = service.stop();
                    let named = lines
                        .iter()
                        .any(|l| l.contains(&format!("leaves {want} for rooms")));
                    assert_eq!(named, said, "{want}: {lines:?}");
                }
            },
        );
    }

    /// An answer reaches the stand-in whole even when the send stops part
    /// way (a signal while the connection is full) and when a signal
    /// interrupts it before anything went: never cut short, never more,
    /// never a part twice.
    #[test]
    fn a_long_answer_arrives_whole_through_partial_and_interrupted_sends() {
        in_own_process(
            "a_long_answer_arrives_whole_through_partial_and_interrupted_sends",
            || {
                interrupting(libc::SIGUSR1);
                let len = 4 << 20;
                // The answer, followed in memory by other bytes that must
                // never be sent.
                let pattern = |i: usize| (i % 251) as u8;
                let buf: Vec<u8> = (0..2 * len)
                    .map(|i| if i < len { pattern(i) } else { 0xEE })
                    .collect();
                let (a, mut b) = UnixStream::pair().unwrap();
                let (tx, rx) = std::sync::mpsc::channel();
                let sender = std::thread::spawn(move || {
                    tx.send(thread_id()).unwrap();
                    send_quietly(&a, &buf[..len]);
                });
                let tid = rx.recv().unwrap();
                // The connection is full: the first signal ends the send
                // part way, the second interrupts the next before anything
                // went. A send that gave up early has ended its thread; the
                // bytes that arrived below then show what went wrong.
                for _ in 0..2 {
                    std::thread::sleep(Duration::from_millis(200));
                    if !wait_until_blocked(tid) || !signal_thread(tid, libc::SIGUSR1) {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
                let mut got = Vec::new();
                let mut chunk = vec![0u8; 1 << 16];
                while got.len() <= len {
                    // Until the sender's end closes (once it is done).
                    match b.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&chunk[..n]),
                    }
                }
                drop(b);
                sender.join().unwrap();
                assert_eq!(got.len(), len, "bytes arrived");
                assert!(
                    got.iter().enumerate().all(|(i, x)| *x == pattern(i)),
                    "the answer arrived changed"
                );
            },
        );
    }

    /// An answer to a stand-in that has already gone gives up at once:
    /// the service never keeps trying.
    #[test]
    fn an_answer_to_a_stand_in_that_left_returns_at_once() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(b);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            send_quietly(&a, b"{\"exit\":0}");
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "the send to a gone stand-in never returned"
        );
    }

    /// A room may have exactly MAX_PLACES places: such a room passes the
    /// place limit (here it is then refused for the descriptors, as none
    /// are left for rooms), and only one more place is refused for their
    /// number.
    #[test]
    fn a_room_of_exactly_the_most_places_is_not_refused_for_their_number() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("top");
        std::fs::create_dir(&top).unwrap();
        let t = top.to_str().unwrap();
        for places in [MAX_PLACES, MAX_PLACES + 1] {
            // The app sees `top`, and below it places shown from it.
            let mut args = s(&["--ro-bind", t, t]);
            for i in 1..places {
                args.extend(s(&["--ro-bind", t, &format!("{t}/d{i}")]));
            }
            args.extend(s(&["--", "x"]));
            let plan = FloorPlan::from_bwrap_args(&args).unwrap();
            // Remembered, not held open: the test holds no 2000 descriptors.
            let (plan, sources) = plan_at_start_with(plan, |_, _| true);
            assert_eq!(plan.entries.len(), places);
            let mut ctx = context(&top, Path::new("/nonexistent"), &[]);
            ctx.plan = plan;
            let served = Arc::new(Served {
                ctx,
                sources,
                refuse_all: None,
            });
            let a = ask_directly(
                &state_with_budget(0),
                &served,
                &request(&[&["--ro-bind", t, t]], &["/bin/true"]),
            );
            let e = a["error"].as_str().unwrap_or_default().to_string();
            if places == MAX_PLACES {
                assert!(
                    e.contains("too many places held for rooms at once"),
                    "{places}: {a}"
                );
            } else {
                assert!(
                    e.contains(&format!("too many places ({places}, at most {MAX_PLACES})")),
                    "{places}: {a}"
                );
            }
        }
    }

    /// A path the request names below a place and asks for with `-try` is
    /// left out of the room when it is missing; missing without `-try`,
    /// the room is refused, never built without it. A path that leads
    /// through a link is refused as one, with `-try` too.
    #[test]
    fn a_room_leaves_out_only_missing_paths_asked_with_try_and_never_follows_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("app");
        std::fs::create_dir(&app).unwrap();
        std::os::unix::fs::symlink("/etc", app.join("link")).unwrap();
        let (bwrap, log) = fake_bwrap(tmp.path());
        let state = state_with_budget(1000);
        let served = served(context(&app, &bwrap, &[]));
        let missing = app.join("missing");
        let m = missing.to_str().unwrap();
        let link = app.join("link");
        let l = link.to_str().unwrap();
        let exit7 = ["/bin/sh", "-c", "exit 7"];
        let a = ask_directly(
            &state,
            &served,
            &request(&[&["--ro-bind-try", m, m]], &exit7),
        );
        assert_eq!(a["exit"], 7, "a room without a missing -try path: {a}");
        let args = std::fs::read_to_string(&log).unwrap();
        assert!(!args.lines().any(|x| x == m), "{args}");
        let a = ask_directly(&state, &served, &request(&[&["--ro-bind", m, m]], &exit7));
        let e = a["error"].as_str().unwrap_or_default();
        assert!(
            e.contains("cannot be shown") && !e.contains("leads through a link"),
            "a missing path without -try: {a}"
        );
        for op in ["--ro-bind", "--ro-bind-try"] {
            let a = ask_directly(&state, &served, &request(&[&[op, l, l]], &exit7));
            let e = a["error"].as_str().unwrap_or_default();
            assert!(
                e.contains("leads through a link"),
                "{op} through a link: {a}"
            );
        }
    }

    /// A place asked for writable is writable in the room only where the
    /// app can write (its Landlock rules); elsewhere it is read-only and
    /// the start record says so. A place asked for read-only is not named.
    #[test]
    fn a_place_is_writable_in_a_room_only_where_the_app_can_write() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("app");
        let (w, r) = (app.join("w"), app.join("r"));
        std::fs::create_dir_all(&w).unwrap();
        std::fs::create_dir_all(&r).unwrap();
        let (bwrap, log) = fake_bwrap(tmp.path());
        let state = state_with_budget(1000);
        let served = served(context(&app, &bwrap, std::slice::from_ref(&w)));
        for (op, place, shown_as, named) in [
            ("--bind", &w, "--bind-fd", false),
            ("--bind", &r, "--ro-bind-fd", true),
            ("--ro-bind", &r, "--ro-bind-fd", false),
        ] {
            let p = place.to_str().unwrap();
            let a = ask_directly(
                &state,
                &served,
                &request(&[&[op, p, p]], &["/bin/sh", "-c", "exit 7"]),
            );
            assert_eq!(a["exit"], 7, "{op} {p}: {a}");
            let args: Vec<String> = std::fs::read_to_string(&log)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect();
            let at = args.iter().position(|x| x == p).unwrap();
            assert_eq!(args[at - 2], shown_as, "{op} {p}: {args:?}");
            let record = last_room_record(&state);
            assert_eq!(
                record.contains(&format!("{p}: not writable for the app")),
                named,
                "{op} {p}: {record}"
            );
        }
    }

    /// Rooms one after another each give their slot back: more rooms than
    /// may run at once are all built, one by one.
    #[test]
    fn rooms_one_after_another_never_run_out_of_slots() {
        let tmp = tempfile::tempdir().unwrap();
        let (bwrap, _) = fake_bwrap(tmp.path());
        let mut service = service_in(tmp.path());
        service.serve(context(tmp.path(), &bwrap, &[]));
        for k in 0..=MAX_ROOMS {
            let a = ask_service(&service.socket, &request(&[], &["/bin/sh", "-c", "exit 7"]));
            assert_eq!(a["exit"], 7, "room {k}: {a}");
        }
        let lines = service.stop();
        let built = lines
            .iter()
            .filter(|l| l.starts_with("sam-room: built sh"))
            .count();
        assert_eq!(built, MAX_ROOMS + 1, "{lines:?}");
    }

    /// Every room still running ends with the app's start, also after
    /// other rooms ended before it: one whose layers were never confirmed,
    /// one whose program ended.
    #[test]
    fn every_room_ends_with_the_start_whatever_other_rooms_did_before() {
        let tmp = tempfile::tempdir().unwrap();
        let (bwrap, _) = fake_bwrap(tmp.path());
        let mut service = service_in(tmp.path());
        service.serve(context(tmp.path(), &bwrap, &[]));
        let long = UnixStream::connect(&service.socket).unwrap();
        write_request(&long, &request(&[], &["/bin/sleep", "60"]));
        let end = Instant::now() + Duration::from_secs(10);
        while !last_room_record(&service.state).starts_with("sam-room: built sleep") {
            assert!(Instant::now() < end, "the long room was never built");
            std::thread::sleep(Duration::from_millis(20));
        }
        let a = ask_service(&service.socket, &request(&[], &["unconfirmed"]));
        assert_eq!(a["exit"], 3, "{a}");
        assert!(
            last_room_record(&service.state).contains("layers were not confirmed"),
            "{}",
            last_room_record(&service.state)
        );
        let a = ask_service(&service.socket, &request(&[], &["/bin/sh", "-c", "exit 0"]));
        assert_eq!(a["exit"], 0, "{a}");
        let lines = service.stop();
        let a = answer_of(&long);
        assert_eq!(a["exit"], 128 + libc::SIGKILL, "the long room: {a}");
        assert!(
            !lines.iter().any(|l| l.contains("still unfinished")),
            "{lines:?}"
        );
    }

    /// A signal that interrupts the room's watcher (the launcher handles
    /// terminal resizes, say) is not its stand-in leaving: the room runs
    /// on to its own end.
    #[test]
    fn a_signal_to_the_rooms_watcher_never_ends_the_room() {
        in_own_process("a_signal_to_the_rooms_watcher_never_ends_the_room", || {
            interrupting(libc::SIGUSR1);
            let tmp = tempfile::tempdir().unwrap();
            let (bwrap, _) = fake_bwrap(tmp.path());
            let state = state_with_budget(1000);
            let served = served(context(tmp.path(), &bwrap, &[]));
            let go = tmp.path().join("go");
            let cmd = format!(
                "while [ ! -e '{}' ]; do sleep 0.05; done; exit 5",
                go.display()
            );
            let (ours, theirs) = UnixStream::pair().unwrap();
            let (st, sv) = (state.clone(), served.clone());
            let t = std::thread::spawn(move || serve_one(theirs, &st, &sv));
            write_request(&ours, &request(&[], &["/bin/sh", "-c", &cmd]));
            // The room's watcher, once it waits on the connection.
            let end = Instant::now() + Duration::from_secs(10);
            let tid = loop {
                let found = std::fs::read_dir("/proc/self/task")
                    .unwrap()
                    .flatten()
                    .find(|e| {
                        std::fs::read_to_string(e.path().join("comm"))
                            .is_ok_and(|c| c.trim() == "sam-room-watch")
                    })
                    .and_then(|e| e.file_name().to_str()?.parse::<libc::pid_t>().ok());
                if let Some(tid) = found {
                    break tid;
                }
                assert!(Instant::now() < end, "no watcher for the room");
                std::thread::sleep(Duration::from_millis(10));
            };
            let waited = wait_until_blocked(tid);
            let mut reached = 0;
            for _ in 0..3 {
                if signal_thread(tid, libc::SIGUSR1) {
                    reached += 1;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            std::fs::write(&go, "").unwrap();
            let a = answer_of(&ours);
            drop(ours);
            t.join().unwrap();
            assert_eq!(a["exit"], 5, "the room after a signal to its watcher: {a}");
            // The watcher was still waiting for every signal.
            assert!(waited && reached == 3, "the watcher ended early");
        });
    }
}

#[cfg(test)]
mod message_tests {
    //! How a request travels: the service reading it from its connection,
    //! the stand-in sending it, and what the stand-in does with
    //! Bubblewrap's arguments before it sends.
    use super::*;
    use std::os::unix::thread::JoinHandleExt;
    use std::time::Instant;

    fn dev_null() -> OwnedFd {
        OwnedFd::from(std::fs::File::open("/dev/null").unwrap())
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// A service state with room for `budget` descriptors.
    fn state_with_budget(budget: usize) -> State {
        let state = State::default();
        state.fd_budget.store(budget, Ordering::SeqCst);
        state
    }

    /// A message as the stand-in sends it: 4 bytes length, then the body.
    fn framed(body: &[u8]) -> Vec<u8> {
        let mut msg = (body.len() as u32).to_be_bytes().to_vec();
        msg.extend(body);
        msg
    }

    /// How many bytes wait to be read on `stream`.
    fn waiting(stream: &UnixStream) -> usize {
        let mut n: libc::c_int = 0;
        // SAFETY: FIONREAD writes one int.
        let r = unsafe { libc::ioctl(stream.as_raw_fd(), libc::FIONREAD, &mut n) };
        assert_eq!(r, 0, "FIONREAD");
        n as usize
    }

    /// A stray byte the program marks urgent (out of band) makes the
    /// connection look readable while there is nothing to read yet: the
    /// service waits on for the request and reads it, never takes that
    /// for a refusal.
    #[test]
    fn an_urgent_byte_before_the_request_does_not_end_its_reading() {
        let (a, b) = UnixStream::pair().unwrap();
        // SAFETY: send reads one byte of the buffer given.
        let r = unsafe { libc::send(a.as_raw_fd(), b"!".as_ptr().cast(), 1, libc::MSG_OOB) };
        assert_eq!(r, 1, "sending an urgent byte");
        let body = br#"{"after":"urgent"}"#.to_vec();
        let sent = body.clone();
        // The request itself only comes a moment after the reading began.
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            (&a).write_all(&framed(&sent)).unwrap();
            a
        });
        let state = state_with_budget(10_000);
        let mut held = Held::new(&state);
        let got = read_message(&b, &mut held);
        drop(sender.join().unwrap());
        let (got, fds) = got.expect("the request after the urgent byte");
        assert_eq!(got, body);
        assert!(fds.is_empty());
    }

    /// Too many connections are refused for what they are: more than one
    /// request may pass ("passes too many"), or more than the launcher has
    /// room for now ("held for rooms at once", which says the app is not
    /// at fault). The words matter: the start record shows them.
    #[test]
    fn too_many_connections_are_refused_with_the_right_reason() {
        // More than a request may pass, with room for all of them: the
        // first part brings the most a request may have, a later part one
        // more.
        let (a, b) = UnixStream::pair().unwrap();
        let null = dev_null();
        let msg = framed(b"{}");
        send_with_fds(&a, &msg[..1], &vec![null.as_raw_fd(); room_rules::MAX_FDS]).unwrap();
        send_with_fds(&a, &msg[1..], &[null.as_raw_fd()]).unwrap();
        let state = state_with_budget(10_000);
        let mut held = Held::new(&state);
        assert_eq!(
            read_message(&b, &mut held).expect_err("one more than a request may pass"),
            "the request passes too many connections"
        );
        // Within what a request may pass, but the launcher has room for
        // only one more descriptor: two are refused as held at once.
        let (a, b) = UnixStream::pair().unwrap();
        send_with_fds(&a, &msg, &[null.as_raw_fd(), null.as_raw_fd()]).unwrap();
        let state = state_with_budget(1);
        let mut held = Held::new(&state);
        assert_eq!(
            read_message(&b, &mut held).expect_err("more than the launcher has room for"),
            "too many connections held for rooms at once"
        );
        // Nothing stays counted for the refused request.
        drop(held);
        assert_eq!(state.held.load(Ordering::SeqCst), 0);
        assert_eq!(state.fds.load(Ordering::SeqCst), 0);
    }

    /// A request of exactly the largest size is read whole; one byte more
    /// is refused before it is read.
    #[test]
    fn a_request_of_the_largest_size_is_read_and_one_byte_more_is_refused() {
        let state = state_with_budget(10_000);
        for (len, ok) in [
            (room_rules::MAX_MESSAGE, true),
            (room_rules::MAX_MESSAGE + 1, false),
        ] {
            let (a, b) = UnixStream::pair().unwrap();
            let body = vec![b'x'; len];
            let sent = body.clone();
            // In its own thread: the message may not fit the connection's
            // buffer at once.
            let sender = std::thread::spawn(move || {
                let _ = (&a).write_all(&framed(&sent));
                a
            });
            let mut held = Held::new(&state);
            let got = read_message(&b, &mut held);
            // Ends the sender's write when the request was refused.
            b.shutdown(std::net::Shutdown::Both).unwrap();
            drop(sender.join().unwrap());
            if ok {
                assert_eq!(got.expect("the largest request").0, body);
            } else {
                assert_eq!(
                    got.expect_err("one byte more than the largest"),
                    "the request is too large"
                );
            }
        }
    }

    /// Sending nothing is done at once, and a send to a connection whose
    /// other end is gone says so (it never reads as sent).
    #[test]
    fn an_empty_send_succeeds_and_a_send_to_a_closed_connection_fails() {
        let (a, b) = UnixStream::pair().unwrap();
        send_with_fds(&a, b"", &[]).expect("nothing to send");
        // The other end is done (a shutdown, not a close: a copy another
        // test's new process holds for a moment would keep it open).
        b.shutdown(std::net::Shutdown::Both).unwrap();
        let e = send_with_fds(&a, b"x", &[]).expect_err("the other end is gone");
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// A send the kernel takes only in part (here a signal ends the wait
    /// for room in a full connection) still sends the rest: the other side
    /// gets every byte and the connection that came with the first part,
    /// and the send returns once all is sent.
    #[test]
    fn a_send_taken_in_part_still_sends_everything() {
        extern "C" fn nothing(_: libc::c_int) {}
        // SIGURG (ignored by default, sent by nothing else here) with a
        // handler that does not restart calls: it ends the wait for room.
        // SAFETY: sigaction with zeroed structs filled as documented.
        let old = unsafe {
            let mut new: libc::sigaction = std::mem::zeroed();
            new.sa_sigaction = nothing as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut new.sa_mask);
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGURG, &new, &mut old), 0);
            old
        };
        let (a, b) = UnixStream::pair().unwrap();
        b.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        // Far more than a connection holds: the send waits for room.
        let data: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let sent = data.clone();
        let null = dev_null();
        let (done_tx, done) = std::sync::mpsc::channel();
        let sender = std::thread::spawn(move || {
            let r = send_with_fds(&a, &sent, &[null.as_raw_fd()]);
            let _ = done_tx.send(r.map_err(|e| e.to_string()));
            drop(a);
        });
        // Once the first part has come, the sender waits for room: one
        // signal ends that wait with part of the message sent.
        let end = Instant::now() + Duration::from_secs(20);
        while waiting(&b) == 0 {
            assert!(Instant::now() < end, "nothing was sent");
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(200));
        // SAFETY: a signal to a thread that is not joined yet.
        unsafe { libc::pthread_kill(sender.as_pthread_t(), libc::SIGURG) };
        let mut got = vec![0u8; data.len()];
        let mut fds = Vec::new();
        let first = recv_with_fds(&b, &mut got, &mut fds, 1).unwrap();
        let rest = (&b).read_exact(&mut got[first..]);
        let finished = done.recv_timeout(Duration::from_secs(20));
        // SAFETY: puts back the handling found before.
        unsafe { libc::sigaction(libc::SIGURG, &old, std::ptr::null_mut()) };
        rest.expect("every byte of the message");
        assert!(got == data, "the message came changed");
        assert_eq!(fds.len(), 1, "the connection sent with the first part");
        assert_eq!(
            finished,
            Ok(Ok(())),
            "the send did not return once all was sent"
        );
        sender.join().unwrap();
    }

    /// The death signal the stand-in sets for itself, on this thread.
    fn death_signal() -> libc::c_int {
        let mut sig: libc::c_int = -1;
        // SAFETY: PR_GET_PDEATHSIG writes one int.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut sig) }, 0);
        sig
    }

    /// The stand-in ends with the program that started it exactly when
    /// Bubblewrap is asked to (`--die-with-parent`), not otherwise: it
    /// sets that before it even looks for Room service (here there is
    /// none, so it then ends with an error).
    #[test]
    fn the_standin_dies_with_its_parent_only_when_asked() {
        // In a thread of its own: the setting belongs to the thread.
        std::thread::spawn(|| {
            assert!(
                !Path::new(SOCKET_INSIDE).exists(),
                "this computer has a Room service at {SOCKET_INSIDE}"
            );
            // SAFETY: prctl with a number argument.
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0 as libc::c_ulong) };
            let plain = standin(
                "bwrap 0.11.0",
                &s(&["--ro-bind", "/usr", "/usr", "--", "/usr/bin/true"]),
            );
            let plain_sig = death_signal();
            let asked = standin(
                "bwrap 0.11.0",
                &s(&["--die-with-parent", "--", "/usr/bin/true"]),
            );
            let asked_sig = death_signal();
            // SAFETY: prctl with a number argument.
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0 as libc::c_ulong) };
            assert_eq!((plain, asked), (1, 1), "no Room service here");
            assert_eq!(plain_sig, 0, "set without --die-with-parent");
            assert_eq!(asked_sig, libc::SIGKILL, "not set with --die-with-parent");
        })
        .join()
        .unwrap();
    }

    /// SAM's helper is the stand-in exactly when it is started under
    /// Bubblewrap's name: by the path the program started (whatever name
    /// it gave) or by the name it gave (whatever path), never under its
    /// own name or a name that only contains Bubblewrap's.
    #[test]
    fn the_helper_is_the_stand_in_only_under_bubblewraps_name() {
        let o = |s: &'static str| Some(std::ffi::OsStr::new(s));
        for (argv0, path) in [
            (o("bwrap"), o("/run/sam/bin/bwrap")),
            (o("loader"), o("/run/sam/bin/bwrap")),
            (o("bwrap"), o("/run/sam/sam-jail-run")),
            (o("/usr/bin/bwrap"), None),
            (None, o("bwrap")),
        ] {
            assert!(is_standin_start(argv0, path), "{argv0:?} {path:?}");
        }
        for (argv0, path) in [
            (o("sam-jail-run"), o("/run/sam/sam-jail-run")),
            (None, None),
            (o("bwrap2"), o("/run/sam/bin/bwrap.version")),
            (o("/bwrap/sam-jail-run"), o("xbwrap")),
        ] {
            assert!(!is_standin_start(argv0, path), "{argv0:?} {path:?}");
        }
    }

    /// The Bubblewrap version line the stand-in answers keeps only plain
    /// characters (letters, digits, space, `.`, `_`, `-`), at most 60, and
    /// no space or line end around it.
    #[test]
    fn a_version_line_keeps_only_plain_characters_and_at_most_60() {
        assert_eq!(plain_version("bwrap 0.11.0\n"), "bwrap 0.11.0");
        assert_eq!(plain_version("  bwrap 0.9.0-rc_1 \n"), "bwrap 0.9.0-rc_1");
        assert_eq!(plain_version("bwrap '$(x)`;\"\\\n1ü"), "bwrap x1");
        assert_eq!(plain_version(&"a".repeat(80)), "a".repeat(60));
        assert_eq!(plain_version(&"b".repeat(60)), "b".repeat(60));
    }
}
