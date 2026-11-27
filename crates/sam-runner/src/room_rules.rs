//! Room service's rules: what a room may show and do, decided from the
//! app's floor plan (how SAM built the app's sandbox) and a program's
//! request. No input or output of its own: a floor plan and a request go
//! in, a room plan comes out (see `room_service` for the part that opens
//! folders, starts Bubblewrap and talks to the stand-in).
//!
//! The rule: **no more than the app, no less than asked.**
//! - A room shows only places of the app's floor plan, each at the same
//!   place as in the app, from the same source on the computer, writable
//!   only where the app's is, rebuilt as it is stacked in the app (the last
//!   mount over a place counts; SAM's hiding mounts come along). Sources
//!   are named by their floor-plan entry, never by a path at room time; a
//!   path the request names below one is opened without following links.
//! - The room's own new places (folders, links, file systems) only in its
//!   own space, never inside a place shown from the app, nor at or behind a
//!   link of the room's or one of the app's it has too, nor inside a /proc
//!   (or message queue file system) of the room's own, whose links lead
//!   out of the room while Bubblewrap builds it; SAM's own mounts come
//!   first, at a place no request may touch.
//! - Every restriction the request asks for (its Bubblewrap arguments) is
//!   kept; filters the program put on itself do not follow it into a room
//!   built from outside, which gets SAM's layers instead. An option the rules do
//!   not know is refused, never guessed.
//! - The network only when the app has the full network (and the request
//!   does not also give it up).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The version of the message between stand-in and service.
pub const VERSION: u32 = 1;
/// Upper limits of one request (beyond them it is refused).
pub const MAX_MESSAGE: usize = 64 * 1024;
pub const MAX_OPS: usize = 256;
/// Connections one request may pass: as many as Linux sends in one
/// message (SCM_MAX_FD). Real Bubblewrap passes on every open connection,
/// and programs started from large apps (Electron) hold many.
pub const MAX_FDS: usize = 253;
/// The numbers a passed connection may have: below this one (the usual
/// first limit of open connections a program gets). No program is known
/// that hands a room one numbered higher; a refusal names the number and
/// this limit, so one that does is easy to tell.
pub const FD_NUMBER_LIMIT: i32 = 1024;
pub const MAX_ARGS: usize = 256;
pub const MAX_TEXT: usize = 4096;

/// A program's request, in the small fixed form the stand-in sends: every
/// option in its order, as the option's name followed by its values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u32,
    pub ops: Vec<Vec<String>>,
    /// Options without values, treated as if they came first (older form;
    /// the stand-in puts everything in `ops`).
    #[serde(default)]
    pub flags: Vec<String>,
    pub command: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    /// The numbers the passed connections have in the program; they keep
    /// them in the room.
    pub fds: Vec<i32>,
    /// The program's resource limits, as `[resource, soft, hard]`: a room
    /// keeps every one that is lower than the launcher's own.
    #[serde(default)]
    pub limits: Vec<[u64; 3]>,
    /// The program's umask; a room keeps it.
    #[serde(default)]
    pub umask: Option<u32>,
}

/// Put first among a request's options by the stand-in when an argument,
/// a variable or the folder of the program is not text: the request is
/// then refused as a whole, never passed on changed.
pub const NOT_TEXT: &str = "--not-text";

/// What `bwrap ARGS…` asks for, read by the stand-in inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    /// `bwrap --version`.
    Version,
    /// A room (without env, cwd and fds, which the stand-in adds).
    Room {
        ops: Vec<Vec<String>>,
        command: Vec<String>,
    },
}

/// How many values each option the rules know takes, and what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Gives something up: always kept.
    Restriction,
    /// Asks for the network: given only where the app has the full one.
    ShareNet,
    /// Shows a place of the app (SRC DEST).
    Place,
    /// Makes something new inside the room (its own place, a link, a
    /// procfs…), or sets how the room's program starts.
    Own,
    /// The program's own syscall filter (a passed connection).
    Filter,
    /// Never in a room.
    Refused,
}

/// Every option of Bubblewrap 0.11–0.13: its kind and number of values.
fn option(name: &str) -> Option<(Kind, usize)> {
    use Kind::*;
    Some(match name {
        "--unshare-all"
        | "--unshare-user"
        | "--unshare-user-try"
        | "--unshare-ipc"
        | "--unshare-pid"
        | "--unshare-net"
        | "--unshare-uts"
        | "--unshare-cgroup"
        | "--unshare-cgroup-try"
        | "--disable-userns"
        | "--assert-userns-disabled"
        | "--clearenv"
        | "--new-session"
        | "--die-with-parent"
        | "--as-pid-1"
        | "--level-prefix" => (Restriction, 0),
        "--cap-drop" | "--remount-ro" => (Restriction, 1),
        "--share-net" => (ShareNet, 0),
        "--bind" | "--bind-try" | "--dev-bind" | "--dev-bind-try" | "--ro-bind"
        | "--ro-bind-try" => (Place, 2),
        "--hostname" | "--chdir" | "--unsetenv" | "--proc" | "--dev" | "--tmpfs" | "--mqueue"
        | "--dir" | "--perms" | "--size" => (Own, 1),
        "--setenv" | "--symlink" | "--chmod" => (Own, 2),
        "--seccomp" | "--add-seccomp-fd" => (Filter, 1),
        // Joining other namespaces, status and sync connections, other
        // users, overlays, places and files from connections, labels, more
        // options from a connection, extra powers.
        "--args" | "--argv0" | "--userns" | "--userns2" | "--pidns" | "--uid" | "--gid"
        | "--lock-file" | "--sync-fd" | "--overlay-src" | "--tmp-overlay" | "--ro-overlay"
        | "--exec-label" | "--file-label" | "--block-fd" | "--userns-block-fd" | "--info-fd"
        | "--json-status-fd" | "--cap-add" => (Refused, 1),
        "--bind-fd" | "--ro-bind-fd" | "--file" | "--bind-data" | "--ro-bind-data" => (Refused, 2),
        "--overlay" => (Refused, 3),
        "--not-a-security-boundary" | "--help" => (Refused, 0),
        _ => return None,
    })
}

/// Where Bubblewrap's own options end in `argv`, read the way Bubblewrap
/// reads them, each option with its values: the index of the `--` that
/// ends them, or of the first word that is not an option. A value that
/// reads `--` (an AppImage file called `--`, a variable set to it) is a
/// value, never the end (review F5). `None` for an option Bubblewrap does
/// not know or one whose values are missing.
pub fn options_end(argv: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" || !a.starts_with("--") {
            return Some(i);
        }
        let (_, n) = option(a)?;
        i += 1 + n;
    }
    (i == argv.len()).then_some(i)
}

/// Reads `bwrap`'s arguments the way Bubblewrap does: options until `--`
/// or the first word that is not an option, then the command. Refuses an
/// option a room never gets and any it does not know.
pub fn read_bwrap_args(argv: &[String]) -> Result<Asked, String> {
    if argv.first().map(String::as_str) == Some("--version") {
        return Ok(Asked::Version);
    }
    let mut ops: Vec<Vec<String>> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with("--") {
            break;
        }
        let Some((kind, n)) = option(a) else {
            return Err(format!("option {a} is not supported in a room"));
        };
        if kind == Kind::Refused {
            return Err(format!("option {a} is not allowed in a room"));
        }
        let end = i + 1 + n;
        if end > argv.len() {
            return Err(format!("{a} needs {n} values"));
        }
        ops.push(argv[i..end].to_vec());
        i = end;
    }
    let command = argv[i..].to_vec();
    if command.is_empty() {
        return Err("no command to run in the room".into());
    }
    Ok(Asked::Room { ops, command })
}

/// The first option in `argv` a room never gets or that the rules do not
/// know (the stand-in passes it on, so the refusal is in the start record).
pub fn first_unusable_option(argv: &[String]) -> Option<String> {
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" || !a.starts_with("--") {
            return None;
        }
        match option(a) {
            None | Some((Kind::Refused, _)) => return Some(a.clone()),
            Some((_, n)) => i += 1 + n,
        }
    }
    None
}

/// The request as the service reads it from a message: within the limits,
/// the right version, text only, absolute paths without `..`.
pub fn read_request(body: &[u8]) -> Result<Request, String> {
    if body.len() > MAX_MESSAGE {
        return Err("the request is too large".into());
    }
    let r: Request =
        serde_json::from_slice(body).map_err(|e| format!("the request is not valid: {e}"))?;
    if r.v != VERSION {
        return Err(format!("request version {} is not supported", r.v));
    }
    if r.ops.len() + r.flags.len() > MAX_OPS {
        return Err("the request has too many options".into());
    }
    if r.fds.len() > MAX_FDS {
        return Err("the request passes too many connections".into());
    }
    if r.command.is_empty() || r.command.len() > MAX_ARGS {
        return Err("the request has no command, or too long a one".into());
    }
    check_fd_numbers(&r.fds)?;
    let texts = r
        .ops
        .iter()
        .flatten()
        .chain(&r.flags)
        .chain(&r.command)
        .chain(r.env.keys())
        .chain(r.env.values())
        .chain(std::iter::once(&r.cwd));
    for t in texts {
        if t.len() > MAX_TEXT || t.contains('\0') {
            return Err("the request holds too long a text".into());
        }
    }
    if r.env.len() > MAX_ARGS {
        return Err("the request's environment is too large".into());
    }
    if r.limits.len() > 64 || r.limits.iter().any(|l| l[0] >= 64) {
        return Err("the request's resource limits are not valid".into());
    }
    if r.umask.is_some_and(|m| m > 0o777) {
        return Err("the request's umask is not valid".into());
    }
    if !is_clean_absolute(&r.cwd) {
        return Err("the request's folder is not a plain absolute path".into());
    }
    Ok(r)
}

/// The numbers of the passed connections: each below `FD_NUMBER_LIMIT`,
/// none negative, none twice. The refusal says which number is wrong and
/// why (the stand-in prints it as Bubblewrap's error), so a program that
/// holds a high-numbered connection learns what to change instead of
/// getting a reason that names nothing.
fn check_fd_numbers(fds: &[i32]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for &f in fds {
        if f < 0 {
            return Err(format!(
                "the request names connection {f}, and a connection number is never negative"
            ));
        }
        if f >= FD_NUMBER_LIMIT {
            return Err(format!(
                "the program passes connection {f}, but SAM's Room service accepts only \
                 connections numbered below {FD_NUMBER_LIMIT}; close it or move it to a \
                 lower number before starting bwrap"
            ));
        }
        if !seen.insert(f) {
            return Err(format!("the request names connection {f} twice"));
        }
    }
    Ok(())
}

/// An absolute path made only of plain names: no `.`, `..`, empty parts or
/// trailing `/` (`Path::components` would quietly drop a `.`).
pub fn is_clean_absolute(p: &str) -> bool {
    p == "/"
        || (p.starts_with('/')
            && p[1..]
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."))
}

/// One place of the app's floor plan, as SAM built its sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A folder or file of the computer, shown read-only.
    Ro { src: PathBuf, dst: PathBuf },
    /// … shown writable.
    Rw { src: PathBuf, dst: PathBuf },
    /// A device (or folder of devices) of the computer; `read_only` when
    /// the app's own `--remount-ro` covers it.
    Dev {
        src: PathBuf,
        dst: PathBuf,
        read_only: bool,
    },
    /// A link SAM made.
    Link { target: String, at: PathBuf },
    /// Bubblewrap's minimal /dev.
    DevFs { at: PathBuf },
    /// A file system that lives only in the app's sandbox (`--tmpfs`,
    /// `--proc`): it hides what lies below it. SAM hides `~/.ssh`, its own
    /// folders and more this way; a room gets the same hiding.
    Mask { at: PathBuf },
    /// A folder SAM made (`--dir`): mounts nothing.
    Dir { at: PathBuf },
}

impl Entry {
    pub fn at(&self) -> &Path {
        match self {
            Entry::Ro { dst, .. } | Entry::Rw { dst, .. } | Entry::Dev { dst, .. } => dst,
            Entry::Link { at, .. }
            | Entry::DevFs { at }
            | Entry::Mask { at }
            | Entry::Dir { at } => at,
        }
    }

    /// The folder or file of the computer it shows, if any.
    pub fn source(&self) -> Option<&Path> {
        match self {
            Entry::Ro { src, .. } | Entry::Rw { src, .. } => Some(src),
            _ => None,
        }
    }

    /// Whether it is a mount (covers what lies at and below its place).
    fn is_mount(&self) -> bool {
        !matches!(self, Entry::Link { .. } | Entry::Dir { .. })
    }
}

/// The app's floor plan: the places of its sandbox, in the order SAM made
/// them (a later mount covers an earlier one), and what it gives up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FloorPlan {
    pub entries: Vec<Entry>,
    /// The app's own sandbox has no network of the computer (SAM's setting
    /// or the person's own Bubblewrap arguments).
    pub no_network: bool,
}

/// Places of the app a room never gets: Room service's own socket (no room
/// asks for rooms).
pub const NOT_FOR_ROOMS: &[&str] = &["/run/sam/rooms"];

/// Where SAM puts its own things in a room (its helper and the room's
/// rules), mounted before anything the request asks for. No request may
/// make, show, change or enter anything there, point a link into it, or
/// lay anything over the folder that holds it (its program may read it).
pub const RESERVED: &str = "/.sam-room";

/// The empty file SAM lays read-only over a file the app must not read
/// (a credential store, a theme file with private settings).
const HIDING_FILE: &str = "/dev/null";

impl FloorPlan {
    /// Leaves the game controllers SAM watches out of the plan: SAM takes
    /// one out of the app's sandbox when it is unplugged, and a room would
    /// keep its own copy, reaching whatever device gets its number next
    /// (review R56). A room never gets a game controller.
    pub fn without_devices(mut self, watched: &[PathBuf]) -> FloorPlan {
        self.entries
            .retain(|e| !matches!(e, Entry::Dev { dst, .. } if watched.contains(dst)));
        self
    }

    /// Reads SAM's own Bubblewrap arguments for the app (up to `--`). An
    /// option SAM does not use is an error: then the start gets no rooms.
    pub fn from_bwrap_args(args: &[String]) -> Result<FloorPlan, String> {
        let mut entries = Vec::new();
        let mut i = 0;
        let mut overlay_src: Option<PathBuf> = None;
        // Bubblewrap shares the network unless told otherwise.
        let mut network = true;
        let mut read_only: Vec<(usize, PathBuf)> = Vec::new();
        // Entries asked with `-try`: Bubblewrap skips one whose source is
        // missing, and Room service then leaves it out of the floor plan.
        let mut tried: Vec<usize> = Vec::new();
        let at = |i: usize| -> Result<&String, String> {
            args.get(i)
                .ok_or_else(|| "SAM's own sandbox command ends early".to_string())
        };
        while i < args.len() {
            let o = args[i].as_str();
            if o == "--" {
                break;
            }
            let p = |k: usize| -> Result<PathBuf, String> { at(i + k).map(PathBuf::from) };
            if matches!(o, "--bind-try" | "--ro-bind-try" | "--dev-bind-try") {
                tried.push(entries.len());
            }
            i += match o {
                "--ro-bind" | "--ro-bind-try" => {
                    entries.push(Entry::Ro {
                        src: p(1)?,
                        dst: p(2)?,
                    });
                    3
                }
                "--bind" | "--bind-try" => {
                    entries.push(Entry::Rw {
                        src: p(1)?,
                        dst: p(2)?,
                    });
                    3
                }
                "--dev-bind" | "--dev-bind-try" => {
                    entries.push(Entry::Dev {
                        src: p(1)?,
                        dst: p(2)?,
                        read_only: false,
                    });
                    3
                }
                "--symlink" => {
                    entries.push(Entry::Link {
                        target: at(i + 1)?.clone(),
                        at: p(2)?,
                    });
                    3
                }
                "--dev" => {
                    entries.push(Entry::DevFs { at: p(1)? });
                    2
                }
                "--tmpfs" | "--proc" | "--mqueue" => {
                    entries.push(Entry::Mask { at: p(1)? });
                    2
                }
                "--dir" => {
                    entries.push(Entry::Dir { at: p(1)? });
                    2
                }
                "--overlay-src" => {
                    // One lower layer only: with several, a room would see
                    // one of them, which may hold what another covers in
                    // the app.
                    if overlay_src.is_some() {
                        return Err("an overlay of several layers, unknown to Room service".into());
                    }
                    overlay_src = Some(p(1)?);
                    2
                }
                "--overlay" => {
                    // The app's folder with its own changes on top: a room
                    // sees the unchanged app folder, read-only.
                    let src = overlay_src
                        .take()
                        .ok_or_else(|| "an overlay without its source".to_string())?;
                    entries.push(Entry::Ro { src, dst: p(3)? });
                    4
                }
                "--remount-ro" => {
                    // The mount at its place, as it stands now, becomes
                    // read-only (not recursive, as in Bubblewrap).
                    read_only.push((entries.len(), p(1)?));
                    2
                }
                "--unshare-net" | "--unshare-all" => {
                    network = false;
                    1
                }
                "--share-net" => {
                    network = true;
                    1
                }
                "--setenv" | "--chmod" => 3,
                "--perms" | "--uid" | "--gid" | "--chdir" | "--unsetenv" | "--seccomp"
                | "--json-status-fd" | "--cap-drop" | "--size" | "--hostname" => 2,
                _ if option(o).is_some_and(|(k, n)| n == 0 && k != Kind::Refused) => 1,
                _ => {
                    return Err(format!(
                        "SAM's own sandbox command has {o}, unknown to Room service"
                    ))
                }
            };
        }
        // A --remount-ro makes read-only the one mount at its place made
        // last before it: Bubblewrap's remount is not recursive, so mounts
        // below it made earlier keep their rights. SAM's own final
        // `--remount-ro /` finds no entry of SAM's at the root; it counts
        // for one the person's own arguments put there (`--bind / /`).
        // When the mount on top was asked with `-try`, its source may be
        // missing: Bubblewrap then remounts the mount below it, and Room
        // service leaves the skipped entry out. So every mount at the place
        // down to the first one not asked with `-try` becomes read-only;
        // the ones below a shown `-try` place are covered by it anyway.
        // (With `--bind / /`, rooms then show the computer's mounts below
        // the root read-only too, where the app keeps their rights: less,
        // never more.) Bubblewrap finds the place by following links and
        // `..`, and may find a mount of the computer below a shown folder
        // there: a remount below the root that names no place mounted
        // exactly there gives no rooms, never rooms without it.
        for (before, at) in read_only {
            if at != Path::new("/")
                && !entries
                    .iter()
                    .take(before)
                    .any(|e| e.is_mount() && e.at() == at)
            {
                return Err(format!(
                    "--remount-ro {} names no place mounted there, unknown to Room service",
                    at.display()
                ));
            }
            let mut end = before;
            while let Some(i) = entries
                .iter()
                .take(end)
                .rposition(|e| e.is_mount() && e.at() == at)
            {
                match &mut entries[i] {
                    Entry::Rw { src, dst } => {
                        entries[i] = Entry::Ro {
                            src: src.clone(),
                            dst: dst.clone(),
                        };
                    }
                    Entry::Dev { read_only, .. } => *read_only = true,
                    _ => {}
                }
                if !tried.contains(&i) {
                    break;
                }
                end = i;
            }
        }
        entries.retain(|e| !NOT_FOR_ROOMS.iter().any(|n| e.at() == Path::new(n)));
        Ok(FloorPlan {
            entries,
            no_network: !network,
        })
    }
}

/// Where a room's place comes from on the computer: `rel` below the source
/// of floor-plan entry `entry` (opened by Room service when the app
/// started; `rel` is opened without following any link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub entry: usize,
    pub rel: PathBuf,
}

/// How a device place is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAccess {
    /// The devices work (`--dev-bind`), as the request asked.
    Devices,
    /// Visible and writable, but the devices do not work (`--bind`).
    NoDevices,
    /// Visible, read-only, the devices do not work (`--ro-bind`).
    ReadOnly,
}

/// One step of a room, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Show `source` at `dst`, read-only or writable; `optional`: skipped
    /// when it does not exist (asked with `-try`, or a place inside the one
    /// asked for).
    Show {
        source: Source,
        dst: PathBuf,
        writable: bool,
        optional: bool,
    },
    /// Show a device place of the app's (a system path under /dev) at the
    /// same place.
    Device {
        src: PathBuf,
        dst: PathBuf,
        access: DeviceAccess,
    },
    /// Hide what lies at `at` (SAM's hiding in the app): an empty tmpfs.
    Mask(PathBuf),
    /// Bubblewrap arguments for the room's own things, as they are.
    Args(Vec<String>),
}

/// The room, decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomPlan {
    pub steps: Vec<Step>,
    pub share_net: bool,
    /// The program's environment (applied only when it starts).
    pub env: BTreeMap<String, String>,
    /// Passed connections holding the program's own syscall filters.
    pub filters: Vec<i32>,
    /// The room's own new places (writable, holding nothing of the app's).
    pub own: Vec<PathBuf>,
    pub chdir: PathBuf,
    pub command: Vec<String>,
    /// What was asked and not given, for the start record.
    pub capped: Vec<String>,
}

/// What the rules need to know about the app besides its floor plan.
#[derive(Debug, Clone, Copy, Default)]
pub struct AppFacts {
    /// The app has the full network setting (it shares the computer's).
    pub full_network: bool,
}

/// The devices in Bubblewrap's minimal /dev: a room may show these when
/// the app has such a /dev.
const DEVFS_NODES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

/// The links every /dev has (scripts use /dev/stdout), each with its
/// target: SAM makes them itself in a /dev asked for without devices.
const DEVFS_LINKS: &[(&str, &str)] = &[
    ("fd", "/proc/self/fd"),
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
];

/// The links Bubblewrap's own `--dev` makes besides those above.
const BWRAP_DEV_MORE_LINKS: &[(&str, &str)] = &[("core", "/proc/kcore"), ("ptmx", "pts/ptmx")];

/// The links Bubblewrap's `--dev` makes in a /dev at `at`, each with its
/// target: a room that asks for the app's /dev with working devices gets
/// them although no `--symlink` of the room names them.
fn bwrap_dev_links(at: &Path) -> Vec<(PathBuf, String)> {
    DEVFS_LINKS
        .iter()
        .chain(BWRAP_DEV_MORE_LINKS)
        .map(|(name, target)| (at.join(name), (*target).to_string()))
        .collect()
}

fn under(p: &Path, top: &Path) -> bool {
    p.starts_with(top)
}

/// A path at or below RESERVED.
fn reserved(p: &Path) -> bool {
    p.starts_with(RESERVED)
}

/// A place whose new mount would cover RESERVED: a folder that holds it.
fn covers_reserved(p: &Path) -> bool {
    Path::new(RESERVED).starts_with(p)
}

/// How a device place of the app is shown for a request that asked for
/// `asked`: never writable where the app's own `--remount-ro` made it
/// read-only (working devices stay working, read-only as in the app).
fn device_steps(
    src: PathBuf,
    dst: PathBuf,
    asked: DeviceAccess,
    read_only: bool,
    capped: &mut Vec<String>,
) -> Vec<Step> {
    if read_only && asked != DeviceAccess::ReadOnly {
        capped.push(format!(
            "{}: read-only for the app, so read-only here",
            dst.display()
        ));
    }
    match (asked, read_only) {
        (DeviceAccess::Devices, true) => vec![
            Step::Device {
                src,
                dst: dst.clone(),
                access: DeviceAccess::Devices,
            },
            Step::Args(vec!["--remount-ro".into(), path_arg(&dst)]),
        ],
        (DeviceAccess::NoDevices, true) => vec![Step::Device {
            src,
            dst,
            access: DeviceAccess::ReadOnly,
        }],
        _ => vec![Step::Device {
            src,
            dst,
            access: asked,
        }],
    }
}

/// Bubblewrap's minimal /dev of the app at `at`: as it is when the request
/// asked for working devices; otherwise the room's own empty folder with
/// the same few nodes shown as asked (their devices then do not work), as
/// Bubblewrap shows a /dev asked for without devices.
fn devfs_steps(at: &Path, asked: DeviceAccess) -> Vec<Step> {
    if asked == DeviceAccess::Devices {
        return vec![Step::Args(vec!["--dev".into(), path_arg(at)])];
    }
    let mut steps = vec![Step::Mask(at.to_path_buf())];
    steps.extend(DEVFS_NODES.iter().map(|n| Step::Device {
        src: Path::new("/dev").join(n),
        dst: at.join(n),
        access: asked,
    }));
    // The links and the folder every /dev has (scripts use /dev/stdout).
    for &(name, target) in DEVFS_LINKS {
        steps.push(Step::Args(vec![
            "--symlink".into(),
            target.into(),
            path_arg(&at.join(name)),
        ]));
    }
    steps.push(Step::Args(vec!["--dir".into(), path_arg(&at.join("shm"))]));
    steps
}

/// The room for `req`, or why there is none.
pub fn plan_room(plan: &FloorPlan, req: &Request, facts: AppFacts) -> Result<RoomPlan, String> {
    let mut room = RoomPlan {
        env: req.env.clone(),
        command: req.command.clone(),
        ..Default::default()
    };
    // Bubblewrap's order: the last of --share-net / --unshare-net /
    // --unshare-all decides; without any of them, Bubblewrap shares the
    // network (the room then gets the app's, if the app has the full one).
    let mut want_net = true;
    let mut chdir: Option<PathBuf> = None;
    // Places shown from the app (their place in the room), and the room's
    // own links: the room's own new things never go inside the first, and
    // nothing is shown through the second.
    let mut shown: Vec<PathBuf> = Vec::new();
    let mut own_links: Vec<PathBuf> = Vec::new();
    // The app's links the room has too: place() copies the links of the
    // app's view of a place (SAM's links, the links of the app's /dev, also
    // those Bubblewrap's `--dev` makes for one with working devices), and
    // Bubblewrap follows them like the room's own. Each with its target:
    // the same link again at its place changes nothing (a program that
    // asks for `/` and makes the system's links as this system has them).
    let mut app_links: Vec<(PathBuf, String)> = Vec::new();
    let mut late_links: Vec<Step> = Vec::new();
    let mut late_remounts: Vec<Step> = Vec::new();
    // The room's own file systems (--tmpfs): writable; the room's root is
    // read-only when it starts.
    let mut own_tmpfs: Vec<PathBuf> = Vec::new();
    // Flags of the older form first, then the options in order.
    let ops: Vec<Vec<String>> = req
        .flags
        .iter()
        .map(|f| vec![f.clone()])
        .chain(req.ops.iter().cloned())
        .collect();
    // The room's own /proc and message queue file systems, wherever the
    // request names them: nothing of the room lies inside one, in whatever
    // order. Bubblewrap mounts them while it builds the room, and the links
    // of a /proc (/proc/self/root, /proc/N/cwd, /proc/self/fd/N) lead out
    // of the room: to Bubblewrap's build stage, where the computer's root
    // is at /oldroot, and to the folders SAM hands Bubblewrap. A path
    // through them would make, change or show things on the computer.
    let own_procfs: Vec<PathBuf> = ops
        .iter()
        .filter(|o| o.len() == 2 && matches!(o[0].as_str(), "--proc" | "--mqueue"))
        .filter_map(|o| clean(&o[1]).ok())
        .collect();
    // A path the room makes something new at: never in SAM's reserved
    // place, never inside a place shown from the app (Bubblewrap would make
    // it on the computer, through any link the app left there), never
    // through one of the room's own links or one of the app's it has too
    // (only the same link again may stand at one: `link` is the target of
    // a link the room makes at `at`), never inside a /proc of its own.
    let own_place = |at: &Path,
                     link: Option<&str>,
                     shown: &[PathBuf],
                     own_links: &[PathBuf],
                     app_links: &[(PathBuf, String)]|
     -> Result<(), String> {
        if reserved(at) || covers_reserved(at) {
            return Err(format!("{} is SAM's own place in a room", at.display()));
        }
        if shown.iter().any(|s| under(at, s)) {
            return Err(format!(
                "{} is inside a place shown from the app: a room makes new things only in its own space",
                at.display()
            ));
        }
        if own_links.iter().any(|l| under(at, l)) {
            return Err(format!(
                "{} is at or behind a link of the room",
                at.display()
            ));
        }
        if let Some(l) = behind_app_link(at, link, app_links) {
            return Err(l);
        }
        if let Some(e) = inside_own_procfs(at, &own_procfs) {
            return Err(e);
        }
        Ok(())
    };
    let mut k = 0;
    while k < ops.len() {
        let op = &ops[k];
        let name = op.first().ok_or("an empty option")?.as_str();
        if name == NOT_TEXT {
            return Err(
                "an argument, a variable or the folder of the program is not text: a room gets them only unchanged"
                    .into(),
            );
        }
        let (kind, n) =
            option(name).ok_or_else(|| format!("option {name} is not supported in a room"))?;
        if kind == Kind::Refused {
            return Err(format!("option {name} is not allowed in a room"));
        }
        if op.len() != n + 1 {
            return Err(format!("{name} needs {n} values"));
        }
        let next = ops.get(k + 1).and_then(|o| o.first()).map(String::as_str);
        match kind {
            Kind::Refused => return Err(format!("option {name} is not allowed in a room")),
            Kind::Restriction => match name {
                "--unshare-net" | "--unshare-all" => want_net = false,
                "--clearenv" => room.env.clear(),
                "--remount-ro" => {
                    let at = clean(&op[1])?;
                    if reserved(&at) {
                        return Err(format!("{} is SAM's own place in a room", at.display()));
                    }
                    if let Some(e) = inside_own_procfs(&at, &own_procfs) {
                        return Err(e);
                    }
                    // (Not at or behind a link of the room's own, nor of
                    // the app's the room has too: checked once every link
                    // is known.)
                    // After the room's own links, as Bubblewrap would make
                    // them before a later remount (it only takes rights away).
                    late_remounts.push(Step::Args(vec![name.into(), path_arg(&at)]));
                }
                // Not passed on: without it Bubblewrap's own init stays the
                // room's first process, whose parent-death signal the
                // program cannot clear, so the room always ends with SAM.
                "--as-pid-1" => room
                    .capped
                    .push("--as-pid-1 (a room always keeps Bubblewrap's own first process)".into()),
                // The rest the room's fixed base has already (all namespaces
                // new, no nested sandboxes, no powers, a new session, ends
                // with its starter), or only changes how errors look.
                _ => {}
            },
            Kind::ShareNet => want_net = true,
            Kind::Filter => {
                let fd: i32 = op[1]
                    .parse()
                    .map_err(|_| format!("{name} needs a connection number"))?;
                if !req.fds.contains(&fd) {
                    return Err(format!("{name} {fd}: that connection was not passed"));
                }
                room.filters.push(fd);
            }
            Kind::Own => match name {
                "--setenv" => {
                    room.env.insert(op[1].clone(), op[2].clone());
                }
                "--unsetenv" => {
                    room.env.remove(&op[1]);
                }
                "--chdir" => {
                    let at = clean(&op[1])?;
                    if reserved(&at) {
                        return Err(format!("{} is SAM's own place in a room", at.display()));
                    }
                    chdir = Some(at);
                }
                "--hostname" => room.steps.push(Step::Args(op.clone())),
                "--proc" | "--dev" | "--tmpfs" | "--mqueue" | "--dir" => {
                    let at = clean(&op[1])?;
                    own_place(&at, None, &shown, &own_links, &app_links)?;
                    if name == "--tmpfs" {
                        own_tmpfs.push(at.clone());
                    }
                    if matches!(name, "--tmpfs" | "--dir") {
                        room.own.push(at.clone());
                    }
                    room.steps
                        .push(Step::Args(vec![name.into(), path_arg(&at)]));
                }
                "--symlink" => {
                    let at = clean(&op[2])?;
                    own_place(&at, Some(&op[1]), &shown, &own_links, &app_links)?;
                    // While Bubblewrap builds the room, /newroot is the room
                    // and /oldroot the computer: a link may not name them.
                    let target = Path::new(&op[1]);
                    if target
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                        || target.starts_with("/oldroot")
                        || target.starts_with("/newroot")
                        || {
                            // Nor into SAM's place, nor to a folder holding
                            // it (a path through the link would reach it).
                            let to = at.parent().unwrap_or(Path::new("/")).join(target);
                            reserved(&to) || covers_reserved(&to)
                        }
                    {
                        return Err(format!("a link to {} is not allowed in a room", op[1]));
                    }
                    own_links.push(at.clone());
                    // Made last, after every mount: Bubblewrap follows links,
                    // so nothing may be laid out through one.
                    late_links.push(Step::Args(vec![name.into(), op[1].clone(), path_arg(&at)]));
                }
                "--perms" | "--size" => {
                    // They shape the next new place only.
                    let ok = match name {
                        "--perms" => matches!(next, Some("--tmpfs" | "--dir")),
                        _ => next == Some("--tmpfs"),
                    };
                    if !ok {
                        return Err(format!("{name} only for the room's own new places"));
                    }
                    if name == "--perms"
                        && u32::from_str_radix(&op[1], 8).map_or(true, |m| m > 0o7777)
                    {
                        return Err("--perms needs an octal mode".into());
                    }
                    if name == "--size" && op[1].parse::<u64>().is_err() {
                        return Err("--size needs a number".into());
                    }
                    room.steps.push(Step::Args(op.clone()));
                }
                "--chmod" => {
                    let at = clean(&op[2])?;
                    own_place(&at, None, &shown, &own_links, &app_links)?;
                    if !room.own.iter().any(|o| under(&at, o)) {
                        return Err("--chmod only on the room's own new places".into());
                    }
                    if u32::from_str_radix(&op[1], 8).map_or(true, |m| m > 0o7777) {
                        return Err("--chmod needs an octal mode".into());
                    }
                    room.steps
                        .push(Step::Args(vec![name.into(), op[1].clone(), path_arg(&at)]));
                }
                _ => return Err(format!("option {name} is not supported in a room")),
            },
            Kind::Place => {
                let (src, dst) = (clean(&op[1])?, clean(&op[2])?);
                if src != dst {
                    return Err(format!(
                        "{} shown at another place ({}): not supported in a room",
                        src.display(),
                        dst.display()
                    ));
                }
                if reserved(&src) {
                    return Err(format!("{} is SAM's own place in a room", src.display()));
                }
                if own_links.iter().any(|l| under(&src, l)) {
                    return Err(format!("{} lies behind a link of the room", src.display()));
                }
                if let Some(e) = behind_app_link(&src, None, &app_links) {
                    return Err(e);
                }
                if let Some(e) = inside_own_procfs(&src, &own_procfs) {
                    return Err(e);
                }
                let optional = name.ends_with("-try");
                let asked = if name.starts_with("--ro-bind") {
                    DeviceAccess::ReadOnly
                } else if name.starts_with("--dev-bind") {
                    DeviceAccess::Devices
                } else {
                    DeviceAccess::NoDevices
                };
                let before = room.steps.len();
                let found = place(plan, &src, asked, optional, &mut room)?;
                // A place asked for read-only keeps the app's hiding places
                // and /dev inside it read-only too (their file systems are
                // the room's own): remounted right after this place is laid
                // out, so a later mount of the request's own is not hit.
                if asked == DeviceAccess::ReadOnly {
                    let masks: Vec<Step> = room.steps[before..]
                        .iter()
                        .filter_map(|st| match st {
                            Step::Mask(at) => {
                                Some(Step::Args(vec!["--remount-ro".into(), path_arg(at)]))
                            }
                            _ => None,
                        })
                        .collect();
                    room.steps.extend(masks);
                }
                // What is now mounted from the app (not the asked path: for
                // `/` that is the app's places inside it, not the root).
                for step in &room.steps[before..] {
                    if let Step::Args(a) = step {
                        match &a[..] {
                            [o, target, at] if o == "--symlink" => {
                                app_links.push((PathBuf::from(at), target.clone()));
                            }
                            // The app's /dev with working devices: Bubblewrap
                            // makes its links itself.
                            [o, at] if o == "--dev" => {
                                app_links.extend(bwrap_dev_links(Path::new(at)));
                            }
                            _ => {}
                        }
                    }
                    let at = match step {
                        Step::Show { dst, .. } | Step::Device { dst, .. } => Some(dst),
                        Step::Mask(at) => Some(at),
                        Step::Args(_) => None,
                    };
                    if let Some(at) = at {
                        if own_links.iter().any(|l| under(at, l)) {
                            return Err(format!(
                                "{} lies at or behind a link of the room",
                                at.display()
                            ));
                        }
                    }
                    // Nor inside a /proc of the room's own (a place of the
                    // app below the one asked for, a link copied with it).
                    if let Some(e) =
                        step_place(step).and_then(|at| inside_own_procfs(at, &own_procfs))
                    {
                        return Err(e);
                    }
                    if let Step::Show { dst, .. } | Step::Device { dst, .. } = step {
                        shown.push(dst.clone());
                    }
                }
                if !found && !optional {
                    return Err(format!("{} is not in the app's view", src.display()));
                }
            }
        }
        k += 1;
    }
    // The room's own links are made last, after every mount: none may lie
    // inside a place shown from the app, in whatever order they were named
    // (Bubblewrap would make it there, through any link in that place,
    // onto the computer).
    if let Some(l) = own_links.iter().find(|l| shown.iter().any(|s| under(l, s))) {
        return Err(format!(
            "{} is inside a place shown from the app: a room makes new things only in its own space",
            l.display()
        ));
    }
    // Nor is anything remounted at or behind one of the room's own links,
    // in whatever order they were named: Bubblewrap makes the links first
    // and follows them, so the remount would reach wherever a link leads
    // (into a /proc of the room's own, behind a link of the app's).
    for step in &late_remounts {
        if let Step::Args(a) = step {
            let at = Path::new(&a[1]);
            if own_links.iter().any(|l| under(at, l)) {
                return Err(format!(
                    "{} is at or behind a link of the room",
                    at.display()
                ));
            }
        }
    }
    room.steps.extend(late_links);
    room.steps.extend(late_remounts);
    // Nothing of the room lies at or behind a link of the app's it has
    // too, in whatever order it was named (a link copied with a later
    // place): Bubblewrap would make, show or change it wherever the link
    // leads. Only the same link may stand at one (the copied link itself).
    for step in &room.steps {
        let (at, link) = match step {
            Step::Args(a) if a.len() == 2 && a[0] == "--remount-ro" => (Path::new(&a[1]), None),
            Step::Args(a) if a.len() == 3 && a[0] == "--symlink" => {
                (Path::new(&a[2]), Some(a[1].as_str()))
            }
            _ => match step_place(step) {
                Some(at) => (at, None),
                None => continue,
            },
        };
        if let Some(e) = behind_app_link(at, link, &app_links) {
            return Err(e);
        }
    }
    nothing_inside_writable_places(plan, &room.steps)?;
    // SAM's own place stays as SAM laid it out: nothing of the room lands
    // in it or over it.
    if let Some(at) = room
        .steps
        .iter()
        .filter_map(step_place)
        .find(|p| reserved(p) || covers_reserved(p))
    {
        return Err(format!("{} is SAM's own place in a room", at.display()));
    }
    // An own place with a place of the app below it gives no write right
    // there (Landlock's rules reach down).
    // Nor one inside a place shown from the app, in whatever order. Both
    // are recorded, as is a new folder on the room's read-only root.
    let mut cut = Vec::new();
    room.own.retain(|o| {
        let keep = !shown.iter().any(|s| under(s, o) || under(o, s));
        if !keep {
            cut.push(format!(
                "{}: a place of the app lies inside or over it, so it gets no write rule of its own",
                o.display()
            ));
        } else if !own_tmpfs.iter().any(|t| under(o, t)) {
            cut.push(format!(
                "{}: on the room's read-only root, so not writable (an own --tmpfs is)",
                o.display()
            ));
        }
        keep
    });
    room.capped.extend(cut);
    if want_net {
        if facts.full_network && !plan.no_network {
            room.share_net = true;
        } else {
            room.capped
                .push("network (the app has no full network)".into());
        }
    }
    room.chdir = match chdir {
        Some(c) => c,
        None => {
            let cwd = PathBuf::from(&req.cwd);
            if shown.iter().any(|s| under(&cwd, s)) {
                cwd
            } else {
                PathBuf::from("/")
            }
        }
    };
    Ok(room)
}

/// Why `at` is refused when it lies at or behind one of the app's links the
/// room has too (`app_links`, each with its target), or `None`. `link` is
/// the target of a link made at `at`: the same link at the same place is
/// no change (Bubblewrap keeps a link that is already there as asked).
fn behind_app_link(
    at: &Path,
    link: Option<&str>,
    app_links: &[(PathBuf, String)],
) -> Option<String> {
    app_links
        .iter()
        .find(|(l, t)| under(at, l) && !(at == l && link == Some(t.as_str())))
        .map(|(l, _)| {
            format!(
                "{} is at or behind {}, a link of the app's that the room has too: a room makes, changes and shows nothing through such a link",
                at.display(),
                l.display()
            )
        })
}

/// Why `at` is refused when it lies inside one of the room's own /proc or
/// message queue file systems (`own_procfs`), or `None`. At one's own
/// place is fine (another file system over it, the same one again).
fn inside_own_procfs(at: &Path, own_procfs: &[PathBuf]) -> Option<String> {
    own_procfs
        .iter()
        .find(|p| at != p.as_path() && under(at, p))
        .map(|p| {
            format!(
                "{} lies inside {}, a /proc or message queue file system of the room's own: a room makes, changes and shows nothing inside one, since the links of a /proc lead out of the room while Bubblewrap builds it",
                at.display(),
                p.display()
            )
        })
}

/// Where a step puts or changes something in the room (`--remount-ro` only
/// takes rights away, so it does not count).
fn step_place(step: &Step) -> Option<&Path> {
    match step {
        Step::Show { dst, .. } | Step::Device { dst, .. } => Some(dst),
        Step::Mask(at) => Some(at),
        Step::Args(a) => match a.first().map(String::as_str) {
            Some("--tmpfs" | "--dir" | "--proc" | "--dev" | "--mqueue") => a.get(1).map(Path::new),
            Some("--symlink" | "--chmod") => a.get(2).map(Path::new),
            _ => None,
        },
    }
}

/// Whether a later step of the room mounts something at or above the
/// place of step `i`, so the room no longer shows what step `i` put there
/// (a room's own `--dev /dev` over the app's `/dev/dri`, a `--tmpfs` over
/// a folder of the app). `--dir`, `--symlink` and `--chmod` mount nothing.
pub(crate) fn covered_later(steps: &[Step], i: usize) -> bool {
    let Some(at) = steps.get(i).and_then(step_place) else {
        return false;
    };
    steps[i + 1..].iter().any(|s| {
        let mounts = match s {
            Step::Show { .. } | Step::Device { .. } | Step::Mask(_) => true,
            Step::Args(a) => matches!(
                a.first().map(String::as_str),
                Some("--tmpfs" | "--proc" | "--dev" | "--mqueue")
            ),
        };
        mounts && step_place(s).is_some_and(|p| under(at, p))
    })
}

/// Whether the app could move a protected or hidden place inside the
/// writable entry `w` to another name: true when a folder between `w` and
/// such a place is not a mount point of its own (pinned). A renamed folder
/// takes the app's hiding along in the app, but a room shows the folder
/// from the computer, where nothing hides it. A protection is a hiding
/// mount (an empty folder, or an empty file: SAM hides a credential file
/// reached through a link, `~/.netrc` into `~/dotfiles`, with `/dev/null`
/// over it, when what it hides lies in that folder), or a read-only (or
/// device) place showing part of that same writable folder with fewer
/// rights; a place brought in from elsewhere (the computer's theme
/// settings in an app's own home, and the private file SAM hides inside
/// them) protects nothing there: moved, a room sees only the app's own
/// files below it.
fn protections_movable(plan: &FloorPlan, w: usize) -> bool {
    let top = plan.entries[w].at();
    let Some(top_src) = plan.entries[w].source() else {
        return false;
    };
    let later = &plan.entries[w + 1..];
    // Whether the mount an empty file `j` lies on shows `w`'s folder:
    // the last mount before it at or above its place.
    let hides_in_w = |j: usize| {
        let at = plan.entries[j].at();
        plan.entries[..j]
            .iter()
            .rposition(|e| e.is_mount() && under(at, e.at()))
            .is_some_and(|k| {
                k == w || (k > w && plan.entries[k].source().is_some_and(|s| under(s, top_src)))
            })
    };
    let protects = |j: usize, e: &Entry| match e {
        Entry::Mask { .. } => true,
        Entry::Ro { src, .. } if src == Path::new(HIDING_FILE) => hides_in_w(j),
        Entry::Ro { src, .. } | Entry::Dev { src, .. } => under(src, top_src),
        _ => false,
    };
    later
        .iter()
        .enumerate()
        .filter(|(n, e)| protects(w + 1 + n, e))
        .map(|(_, e)| e)
        .any(|e| {
            let at = e.at();
            at != top
                && under(at, top)
                && at
                    .ancestors()
                    .skip(1)
                    .take_while(|a| *a != top)
                    .any(|a| !later.iter().any(|p| p.is_mount() && p.at() == a))
        })
}

/// Nothing is placed inside a place whose source the app can write, in
/// whatever order: Bubblewrap finds every place by its name, and inside
/// such a place the names are the app's to change (a folder renamed away
/// with its protection, a link planted to the computer's root). A room may
/// show such a place only as a whole, with nothing below it.
fn nothing_inside_writable_places(plan: &FloorPlan, steps: &[Step]) -> Result<(), String> {
    // A device place of the app counts too: shown by name, and possibly a
    // folder the app (or the person) can write.
    let writable: Vec<&Path> = steps
        .iter()
        .filter_map(|s| match s {
            Step::Show { source, dst, .. }
                if matches!(plan.entries.get(source.entry), Some(Entry::Rw { .. })) =>
            {
                Some(dst.as_path())
            }
            Step::Device { dst, .. } => Some(dst.as_path()),
            _ => None,
        })
        .collect();
    for step in steps {
        let Some(at) = step_place(step) else { continue };
        if let Some(w) = writable.iter().find(|w| at != **w && under(at, w)) {
            return Err(format!(
                "{} lies inside {}, a place the app can write: a room shows such a place only as a whole",
                at.display(),
                w.display()
            ));
        }
    }
    Ok(())
}

/// A path of the request: absolute, without `.` or `..`.
fn clean(p: &str) -> Result<PathBuf, String> {
    if is_clean_absolute(p) {
        Ok(PathBuf::from(p))
    } else {
        Err(format!("{p} is not a plain absolute path"))
    }
}

fn path_arg(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Shows the app's view of `src` (at the same place), rebuilt as it is
/// stacked in the app: the mount that is visible at `src` (the last one at
/// or above it), then every later mount below `src` in the floor plan's
/// order, SAM's hiding mounts and links included. False when the app sees
/// nothing there a room can share.
fn place(
    plan: &FloorPlan,
    src: &Path,
    asked: DeviceAccess,
    optional: bool,
    room: &mut RoomPlan,
) -> Result<bool, String> {
    let want_write = asked != DeviceAccess::ReadOnly;
    // The mount visible at src: the last one at or above it.
    let holder = plan
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.is_mount() && under(src, e.at()))
        .max_by_key(|(i, _)| *i);
    let after = holder.map_or(0, |(i, _)| i + 1);
    let mut shown = false;
    if let Some((i, e)) = holder {
        let rest = src
            .strip_prefix(e.at())
            .map(Path::to_path_buf)
            .unwrap_or_default();
        match e {
            Entry::Ro { .. } | Entry::Rw { .. } => {
                if matches!(e, Entry::Rw { .. })
                    && !rest.as_os_str().is_empty()
                    && protections_movable(plan, i)
                {
                    return Err(format!(
                        "{} lies in {}, a place the app can write where it could move a protected or hidden place (a folder above one is not pinned): a room shows nothing below it",
                        src.display(),
                        e.at().display()
                    ));
                }
                let writable = want_write && matches!(e, Entry::Rw { .. });
                if want_write && !writable {
                    room.capped.push(format!(
                        "{}: read-only for the app, so read-only here",
                        src.display()
                    ));
                }
                room.steps.push(Step::Show {
                    source: Source {
                        entry: i,
                        rel: rest,
                    },
                    dst: src.to_path_buf(),
                    writable,
                    optional,
                });
                shown = true;
            }
            Entry::Dev {
                src: top,
                read_only,
                ..
            } => {
                // Device places are shown by their name (Bubblewrap has no
                // way to show a device by handle): only as SAM or the
                // person named them, never a path below one, which could
                // lead through a link the app made (in /dev/shm, say).
                if !rest.as_os_str().is_empty() {
                    return Err(format!(
                        "{} lies below the device place {}: a room shows a device place only as a whole",
                        src.display(),
                        top.display()
                    ));
                }
                // (Never `top.join("")`: that adds a "/", which a device
                // file is not.)
                room.steps.extend(device_steps(
                    top.clone(),
                    src.to_path_buf(),
                    asked,
                    *read_only,
                    &mut room.capped,
                ));
                shown = true;
            }
            Entry::DevFs { .. } => {
                if rest.as_os_str().is_empty() {
                    room.steps.extend(devfs_steps(src, asked));
                    shown = true;
                } else if let Some(node) = rest.to_str().filter(|n| DEVFS_NODES.contains(n)) {
                    room.steps.push(Step::Device {
                        src: Path::new("/dev").join(node),
                        dst: src.to_path_buf(),
                        access: asked,
                    });
                    shown = true;
                }
            }
            // Lives only in the app's sandbox: nothing to share here; later
            // mounts below are shown on their own.
            Entry::Mask { .. } => {}
            Entry::Link { .. } | Entry::Dir { .. } => {}
        }
    }
    // Later mounts and links below src, in the floor plan's order (earlier
    // ones below src are covered by the holder, in the app as here).
    // A mount the app covers again later (at or above its place) is not
    // visible in the app: it is not opened for the room either.
    let covered_later = |i: usize, at: &Path| {
        plan.entries
            .iter()
            .skip(i + 1)
            .any(|l| l.is_mount() && under(at, l.at()))
    };
    for (i, e) in plan.entries.iter().enumerate().skip(after) {
        if !under(e.at(), src) || e.at() == src || covered_later(i, e.at()) {
            continue;
        }
        match e {
            Entry::Ro { dst, .. } | Entry::Rw { dst, .. } => {
                let writable = want_write && matches!(e, Entry::Rw { .. });
                if want_write && !writable {
                    room.capped.push(format!(
                        "{}: read-only for the app, so read-only here",
                        dst.display()
                    ));
                }
                room.steps.push(Step::Show {
                    source: Source {
                        entry: i,
                        rel: PathBuf::new(),
                    },
                    dst: dst.clone(),
                    writable,
                    optional: true,
                });
                shown = true;
            }
            Entry::Dev {
                src: from,
                dst,
                read_only,
            } => {
                room.steps.extend(device_steps(
                    from.clone(),
                    dst.clone(),
                    asked,
                    *read_only,
                    &mut room.capped,
                ));
                shown = true;
            }
            Entry::DevFs { at } => {
                room.steps.extend(devfs_steps(at, asked));
                shown = true;
            }
            // SAM's hiding: the same in the room, always.
            Entry::Mask { at } => room.steps.push(Step::Mask(at.clone())),
            Entry::Link { target, at } => {
                room.steps.push(Step::Args(vec![
                    "--symlink".into(),
                    target.clone(),
                    path_arg(at),
                ]));
            }
            Entry::Dir { .. } => {}
        }
    }
    Ok(shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn req(ops: &[&[&str]], command: &[&str]) -> Request {
        Request {
            v: VERSION,
            ops: ops.iter().map(|o| s(o)).collect(),
            flags: vec![],
            command: s(command),
            env: BTreeMap::new(),
            cwd: "/".into(),
            fds: vec![],
            limits: vec![],
            umask: None,
        }
    }

    /// A floor plan like SAM's: /usr in pieces, a private home with a
    /// protected place and a hidden ~/.ssh, a grant inside SAM's folder
    /// hidden by a later tmpfs over it, /tmp of its own, Bubblewrap's /dev
    /// with the GPU.
    fn plan() -> FloorPlan {
        FloorPlan::from_bwrap_args(&s(&[
            "--die-with-parent",
            "--unshare-net",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            "/usr/lib",
            "/usr/lib",
            "--ro-bind-try",
            "/usr/bin",
            "/usr/bin",
            "--symlink",
            "lib",
            "/usr/lib64",
            "--ro-bind",
            "/data/sam/apps",
            "/data/sam/apps",
            "--bind",
            "/data/homes/app",
            "/home/me",
            // Pinned, as SAM pins the folders above protected places.
            "--bind",
            "/data/homes/app/.config",
            "/home/me/.config",
            "--ro-bind",
            "/data/homes/app/.config/autostart",
            "/home/me/.config/autostart",
            "--tmpfs",
            "/home/me/.ssh",
            "--dir",
            "/home/me/.cache",
            "--tmpfs",
            "/data/sam",
            "--dev-bind-try",
            "/dev/dri",
            "/dev/dri",
            "--setenv",
            "A",
            "b",
            "--bind",
            "/rt/l1/rooms",
            "/run/sam/rooms",
            "--remount-ro",
            "/",
            "--",
            "/run/sam/sam-jail-run",
        ]))
        .unwrap()
    }

    fn index_of(at: &str) -> usize {
        plan()
            .entries
            .iter()
            .position(|e| e.at() == Path::new(at))
            .unwrap()
    }

    fn ok(ops: &[&[&str]]) -> RoomPlan {
        plan_room(&plan(), &req(ops, &["x"]), AppFacts::default()).unwrap()
    }

    fn refused(ops: &[&[&str]]) -> bool {
        plan_room(&plan(), &req(ops, &["x"]), AppFacts::default()).is_err()
    }

    /// A room's arguments and the person's raw arguments are read with the
    /// same number of values for every Bubblewrap option (independent
    /// review of PR 133: two tables could drift apart). `--version` is
    /// read on its own, before any option.
    #[test]
    fn rooms_and_raw_arguments_count_option_values_alike() {
        for (name, n) in sam_core::sandbox::BWRAP_OPTIONS {
            if *name == "--version" {
                continue;
            }
            assert_eq!(option(name).map(|(_, v)| v), Some(*n), "{name}");
        }
    }

    #[test]
    fn bwrap_args_are_read_as_bubblewrap_reads_them() {
        let a = read_bwrap_args(&s(&[
            "--ro-bind",
            "/usr",
            "/usr",
            "--unshare-all",
            "/usr/bin/true",
            "-x",
        ]))
        .unwrap();
        assert_eq!(
            a,
            Asked::Room {
                ops: vec![s(&["--ro-bind", "/usr", "/usr"]), s(&["--unshare-all"])],
                command: s(&["/usr/bin/true", "-x"])
            }
        );
        assert_eq!(read_bwrap_args(&s(&["--version"])).unwrap(), Asked::Version);
        let after = read_bwrap_args(&s(&["--", "--not-an-option"])).unwrap();
        assert_eq!(
            after,
            Asked::Room {
                ops: vec![],
                command: s(&["--not-an-option"])
            }
        );
    }

    #[test]
    fn options_a_room_never_gets_are_refused_by_name() {
        for o in [
            &["--cap-add", "ALL"][..],
            &["--userns", "3"],
            &["--uid", "0"],
            &["--bind-fd", "3", "/x"],
            &["--file", "3", "/x"],
            &["--args", "3"],
            &["--overlay", "/a", "/b", "/c"],
            &["--json-status-fd", "1"],
            &["--not-a-security-boundary"],
            &["--made-up"],
        ] {
            let mut argv = s(o);
            argv.push("/usr/bin/true".into());
            assert!(read_bwrap_args(&argv).is_err(), "{o:?} was accepted");
            assert!(refused(&[o]), "{o:?} was planned");
        }
        // By name: every option a room never gets is refused as such (not
        // as merely unknown), with its usual number of values.
        let named: [(&str, usize); 27] = [
            ("--args", 1),
            ("--argv0", 1),
            ("--userns", 1),
            ("--userns2", 1),
            ("--pidns", 1),
            ("--uid", 1),
            ("--gid", 1),
            ("--lock-file", 1),
            ("--sync-fd", 1),
            ("--overlay-src", 1),
            ("--tmp-overlay", 1),
            ("--ro-overlay", 1),
            ("--exec-label", 1),
            ("--file-label", 1),
            ("--block-fd", 1),
            ("--userns-block-fd", 1),
            ("--info-fd", 1),
            ("--json-status-fd", 1),
            ("--cap-add", 1),
            ("--bind-fd", 2),
            ("--ro-bind-fd", 2),
            ("--file", 2),
            ("--bind-data", 2),
            ("--ro-bind-data", 2),
            ("--overlay", 3),
            ("--not-a-security-boundary", 0),
            ("--help", 0),
        ];
        for (name, n) in named {
            let mut argv = vec![name.to_string()];
            argv.extend((0..n).map(|i| format!("/v{i}")));
            argv.push("/usr/bin/true".into());
            let e = read_bwrap_args(&argv).unwrap_err();
            assert!(e.contains("is not allowed in a room"), "{name}: {e}");
            assert_eq!(first_unusable_option(&argv).as_deref(), Some(name));
        }
        let e = read_bwrap_args(&s(&["--made-up", "/usr/bin/true"])).unwrap_err();
        assert!(e.contains("is not supported in a room"), "{e}");
    }

    /// The first option a room never gets is found where the stand-in
    /// looks for it: up to the end of the options, `--` or the command,
    /// never past the end of the arguments.
    #[test]
    fn the_first_unusable_option_is_found_where_bubblewrap_reads_options() {
        let first = |v: &[&str]| first_unusable_option(&s(v));
        assert_eq!(first(&["--ro-bind", "/a", "/a"]), None);
        assert_eq!(first(&["--ro-bind", "/a", "/a", "--", "--cap-add"]), None);
        assert_eq!(first(&["--ro-bind", "/a", "/a", "prog", "--cap-add"]), None);
        assert_eq!(
            first(&["--ro-bind", "/a", "/a", "--cap-add", "X", "prog"]).as_deref(),
            Some("--cap-add")
        );
        assert_eq!(first(&[]), None);
        // Places but no command: said as such, not as missing values.
        let e = read_bwrap_args(&s(&["--ro-bind", "/a", "/a"])).unwrap_err();
        assert_eq!(e, "no command to run in the room");
        // A message one byte over the limit is refused for its size.
        let big = vec![b' '; MAX_MESSAGE + 1];
        assert_eq!(read_request(&big).unwrap_err(), "the request is too large");
        let at_limit = vec![b' '; MAX_MESSAGE];
        assert!(read_request(&at_limit).unwrap_err().contains("not valid"));
    }

    #[test]
    fn missing_values_and_commands_are_refused() {
        assert!(read_bwrap_args(&s(&["--ro-bind", "/usr"])).is_err());
        assert!(read_bwrap_args(&s(&["--unshare-all"])).is_err());
        assert!(read_bwrap_args(&s(&["--setenv", "A"])).is_err());
    }

    #[test]
    fn a_request_message_is_read_strictly() {
        let good = br#"{"v":1,"ops":[["--ro-bind","/usr","/usr"]],"flags":[],"command":["/usr/bin/true"],"env":{},"cwd":"/","fds":[0,1,2]}"#;
        assert!(read_request(good).is_ok());
        for bad in [
            &br#"{"v":2,"ops":[],"command":["x"],"env":{},"cwd":"/","fds":[]}"#[..],
            br#"{"v":1,"ops":[],"command":["x"],"env":{},"cwd":"/","fds":[],"more":1}"#,
            br#"{"v":1,"ops":[],"command":["x"],"command":["y"],"env":{},"cwd":"/","fds":[]}"#,
            br#"{"v":1,"ops":[],"command":[],"env":{},"cwd":"/","fds":[]}"#,
            br#"{"v":1,"ops":[],"command":["x"],"env":{},"cwd":"rel","fds":[]}"#,
            br#"{"v":1,"ops":[],"command":["x"],"env":{},"cwd":"/","fds":[1,1]}"#,
            br#"{"v":1,"ops":[],"command":["x"],"env":{},"cwd":"/","fds":[4096]}"#,
            b"{\"v\":1,\"ops\":[[\"--ro-bind\",\"/u\xff\",\"/u\xff\"]],\"command\":[\"x\"],\"env\":{},\"cwd\":\"/\",\"fds\":[]}",
            b"nope",
        ] {
            assert!(read_request(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let many: Vec<i32> = (0..=MAX_FDS as i32).collect();
        let r = serde_json::to_vec(&Request {
            fds: many,
            ..req(&[], &["x"])
        })
        .unwrap();
        assert!(read_request(&r).is_err());
        let ops: Vec<String> = (0..300).map(|i| format!("[\"--dir\",\"/d{i}\"]")).collect();
        let r = format!(
            r#"{{"v":1,"ops":[{}],"command":["x"],"env":{{}},"cwd":"/","fds":[]}}"#,
            ops.join(",")
        );
        assert!(read_request(r.as_bytes()).is_err());
        assert!(read_request(&vec![b' '; MAX_MESSAGE + 1]).is_err());
    }

    /// A wrong connection number is refused with a reason that names it:
    /// one at or above the limit (with the limit and what the program can
    /// do), a negative one, one given twice. Numbers below the limit, each
    /// once, pass.
    #[test]
    fn a_wrong_connection_number_is_named_in_the_refusal() {
        let read = |fds: Vec<i32>| {
            let body = serde_json::to_vec(&Request {
                fds,
                ..req(&[], &["x"])
            })
            .unwrap();
            read_request(&body)
        };
        assert_eq!(FD_NUMBER_LIMIT, 1024);
        // Control: up to the last number below the limit, each once.
        assert_eq!(read(vec![0, 1, 2, 1023]).unwrap().fds, vec![0, 1, 2, 1023]);
        for high in [1024, 1500] {
            let e = read(vec![0, 1, high]).unwrap_err();
            assert_eq!(
                e,
                format!(
                    "the program passes connection {high}, but SAM's Room service accepts \
                     only connections numbered below 1024; close it or move it to a lower \
                     number before starting bwrap"
                )
            );
        }
        assert_eq!(
            read(vec![0, -1]).unwrap_err(),
            "the request names connection -1, and a connection number is never negative"
        );
        assert_eq!(
            read(vec![3, 5, 3]).unwrap_err(),
            "the request names connection 3 twice"
        );
    }

    #[test]
    fn paths_must_be_plain_and_absolute() {
        for p in [
            "/usr/../etc",
            "usr",
            "/usr/./lib",
            "",
            "/usr//lib",
            "/usr/.",
            "/usr/",
        ] {
            assert!(!is_clean_absolute(p), "{p}");
            assert!(refused(&[&["--ro-bind", p, p]]), "{p}");
        }
        assert!(is_clean_absolute("/usr/lib"));
    }

    #[test]
    fn a_place_is_shown_only_at_the_same_place() {
        assert!(refused(&[&["--ro-bind", "/usr/lib", "/elsewhere"]]));
    }

    #[test]
    fn a_place_comes_from_its_floor_plan_entry_not_a_name() {
        let room = ok(&[&["--ro-bind", "/usr/lib/x86_64", "/usr/lib/x86_64"]]);
        assert_eq!(
            room.steps,
            vec![Step::Show {
                source: Source {
                    entry: index_of("/usr/lib"),
                    rel: "x86_64".into()
                },
                dst: "/usr/lib/x86_64".into(),
                writable: false,
                optional: false
            }]
        );
    }

    /// `/usr` is not one place of the app but several: the room gets each,
    /// and SAM's links, in the floor plan's order.
    #[test]
    fn asking_for_a_parent_shows_the_apps_places_inside_it() {
        let room = ok(&[&["--ro-bind", "/usr", "/usr"]]);
        assert_eq!(
            room.steps,
            vec![
                Step::Show {
                    source: Source {
                        entry: index_of("/usr/lib"),
                        rel: "".into()
                    },
                    dst: "/usr/lib".into(),
                    writable: false,
                    optional: true
                },
                Step::Show {
                    source: Source {
                        entry: index_of("/usr/bin"),
                        rel: "".into()
                    },
                    dst: "/usr/bin".into(),
                    writable: false,
                    optional: true
                },
                Step::Args(s(&["--symlink", "lib", "/usr/lib64"])),
            ]
        );
    }

    #[test]
    fn writable_only_where_the_app_writes() {
        let room = ok(&[&["--bind", "/usr/lib", "/usr/lib"]]);
        assert!(matches!(
            room.steps[0],
            Step::Show {
                writable: false,
                ..
            }
        ));
        assert!(!room.capped.is_empty());
        let room = ok(&[&["--bind", "/home/me/.cache", "/home/me/.cache"]]);
        assert!(matches!(room.steps[0], Step::Show { writable: true, .. }));
    }

    /// A place the app can write is shown only as a whole: the home, with
    /// its protected and hidden places below it, is refused (Bubblewrap
    /// would place them by names the app can change); a folder inside it
    /// with nothing below is fine; the hidden place itself shows nothing.
    #[test]
    fn nothing_is_placed_inside_a_place_the_app_can_write() {
        assert!(refused(&[&["--bind", "/home/me", "/home/me"]]));
        assert!(refused(&[&["--ro-bind", "/home/me", "/home/me"]]));
        let room = ok(&[&["--bind", "/home/me/.cache", "/home/me/.cache"]]);
        assert!(matches!(
            room.steps[..],
            [Step::Show { writable: true, .. }]
        ));
        assert!(refused(&[&["--ro-bind", "/home/me/.ssh", "/home/me/.ssh"]]));
        // Own things inside it, in either order.
        for own in [
            &["--symlink", "/x", "/home/me/.cache/x/evil"][..],
            &["--dir", "/home/me/.cache/x"],
            &["--tmpfs", "/home/me/.cache/x"],
        ] {
            assert!(
                refused(&[own, &["--ro-bind", "/home/me/.cache", "/home/me/.cache"]]),
                "{own:?} first"
            );
            assert!(
                refused(&[&["--ro-bind", "/home/me/.cache", "/home/me/.cache"], own]),
                "{own:?} after"
            );
        }
    }

    /// A grant inside SAM's folder that a later tmpfs hides in the app
    /// (audit S-F13) stays hidden: the last mount over a place counts, not
    /// the deepest.
    #[test]
    fn a_place_the_app_has_hidden_by_a_later_mount_stays_hidden() {
        assert!(refused(&[&[
            "--ro-bind",
            "/data/sam/apps",
            "/data/sam/apps"
        ]]));
        assert!(refused(&[&[
            "--ro-bind",
            "/data/sam/apps/x",
            "/data/sam/apps/x"
        ]]));
        let room = ok(&[&["--ro-bind-try", "/data", "/data"]]);
        assert!(
            !room
                .steps
                .iter()
                .any(|s| matches!(s, Step::Show { dst, .. } if dst.starts_with("/data/sam"))),
            "{:?}",
            room.steps
        );
    }

    #[test]
    fn everything_asked_is_the_apps_view_without_its_private_places() {
        // With protections below the home, asking for everything is refused.
        assert!(refused(&[&["--bind", "/", "/"]]));
        // Without them: the app's view, its private places left out.
        let mut p = plan();
        p.entries
            .retain(|e| !e.at().starts_with("/home/me/") || e.at() == Path::new("/home/me"));
        let room = plan_room(
            &p,
            &req(&[&["--bind", "/", "/"]], &["x"]),
            AppFacts::default(),
        )
        .unwrap();
        let shown: Vec<PathBuf> = room
            .steps
            .iter()
            .filter_map(|s| match s {
                Step::Show { dst, .. } | Step::Device { dst, .. } => Some(dst.clone()),
                _ => None,
            })
            .collect();
        assert!(shown.contains(&"/home/me".into()));
        assert!(!shown
            .iter()
            .any(|p| p.starts_with("/tmp") || p.starts_with("/proc")));
        assert!(
            !shown.contains(&"/run/sam/rooms".into()),
            "a room got Room service's socket"
        );
        assert!(
            !shown.iter().any(|p| p.starts_with("/data/sam")),
            "{shown:?}"
        );
    }

    #[test]
    fn what_the_app_cannot_see_is_refused_or_skipped() {
        assert!(refused(&[&["--ro-bind", "/secret", "/secret"]]));
        assert!(ok(&[&["--ro-bind-try", "/secret", "/secret"]])
            .steps
            .is_empty());
        // The app's own /tmp lives only in its sandbox.
        assert!(refused(&[&["--bind", "/tmp", "/tmp"]]));
    }

    /// Devices only the app's, and only working where the request asked for
    /// working devices.
    #[test]
    fn devices_only_the_apps_and_only_as_asked() {
        let room = ok(&[&["--dev-bind", "/dev", "/dev"]]);
        assert_eq!(
            room.steps,
            vec![
                Step::Args(s(&["--dev", "/dev"])),
                Step::Device {
                    src: "/dev/dri".into(),
                    dst: "/dev/dri".into(),
                    access: DeviceAccess::Devices
                },
            ]
        );
        assert!(refused(&[&["--dev-bind", "/dev/input", "/dev/input"]]));
        let room = ok(&[&["--dev-bind", "/dev/null", "/dev/null"]]);
        assert_eq!(
            room.steps,
            vec![Step::Device {
                src: "/dev/null".into(),
                dst: "/dev/null".into(),
                access: DeviceAccess::Devices
            }]
        );
        let room = ok(&[&["--ro-bind", "/dev/dri", "/dev/dri"]]);
        assert!(matches!(
            room.steps[0],
            Step::Device {
                access: DeviceAccess::ReadOnly,
                ..
            }
        ));
        let room = ok(&[&["--bind", "/dev/dri", "/dev/dri"]]);
        assert!(matches!(
            room.steps[0],
            Step::Device {
                access: DeviceAccess::NoDevices,
                ..
            }
        ));
    }

    #[test]
    fn the_network_only_with_the_apps_full_network_and_never_when_given_up() {
        let facts = |full| AppFacts { full_network: full };
        let open = FloorPlan {
            no_network: false,
            ..plan()
        };
        let net = |p: &FloorPlan, ops: &[&[&str]], full| {
            plan_room(p, &req(ops, &["x"]), facts(full))
                .unwrap()
                .share_net
        };
        assert!(!net(&open, &[&["--share-net"]], false));
        // Bubblewrap shares the network unless told otherwise.
        assert!(net(&open, &[], true));
        assert!(!net(&open, &[&["--unshare-all"]], true));
        assert!(net(&open, &[&["--share-net"]], true));
        assert!(!net(&open, &[&["--share-net"], &["--unshare-net"]], true));
        // Bubblewrap's usual way: give up everything, then ask for the network.
        assert!(net(&open, &[&["--unshare-all"], &["--share-net"]], true));
        assert!(!net(&open, &[&["--share-net"], &["--unshare-all"]], true));
        // The app's own sandbox has no network (its own arguments say so).
        assert!(!net(&plan(), &[&["--share-net"]], true));
    }

    #[test]
    fn the_apps_own_restrictions_in_its_arguments_count() {
        let p = FloorPlan::from_bwrap_args(&s(&[
            "--bind",
            "/h",
            "/h",
            "--bind",
            "/h/docs",
            "/h/docs",
            "--remount-ro",
            "/h/docs",
            "--share-net",
            "--unshare-all",
        ]))
        .unwrap();
        assert!(p.no_network);
        let room = plan_room(
            &p,
            &req(&[&["--bind", "/h/docs", "/h/docs"]], &["x"]),
            AppFacts::default(),
        )
        .unwrap();
        assert!(matches!(
            room.steps[0],
            Step::Show {
                writable: false,
                ..
            }
        ));
        // /h itself holds the read-only /h/docs: shown only as a whole, so
        // not at all.
        assert!(plan_room(
            &p,
            &req(&[&["--bind", "/h", "/h"]], &["x"]),
            AppFacts::default()
        )
        .is_err());
    }

    #[test]
    fn the_environment_is_kept_in_order_for_the_program() {
        let mut r = req(
            &[
                &["--setenv", "A", "1"],
                &["--clearenv"],
                &["--setenv", "B", "2"],
                &["--unsetenv", "C"],
            ],
            &["x"],
        );
        r.env.insert("C".into(), "3".into());
        r.env.insert("D".into(), "4".into());
        let room = plan_room(&plan(), &r, AppFacts::default()).unwrap();
        assert_eq!(
            room.env,
            BTreeMap::from([("B".to_string(), "2".to_string())])
        );
    }

    #[test]
    fn the_programs_own_filter_must_be_a_passed_connection() {
        let mut r = req(&[&["--seccomp", "11"]], &["x"]);
        assert!(plan_room(&plan(), &r, AppFacts::default()).is_err());
        r.fds = vec![11];
        assert_eq!(
            plan_room(&plan(), &r, AppFacts::default()).unwrap().filters,
            vec![11]
        );
    }

    #[test]
    fn permissions_only_on_the_rooms_own_new_places() {
        assert!(!refused(&[
            &["--perms", "0700"],
            &["--tmpfs", "/scratch"],
            &["--chmod", "0755", "/scratch"]
        ]));
        assert!(refused(&[
            &["--bind", "/home/me", "/home/me"],
            &["--chmod", "0777", "/home/me"]
        ]));
        assert!(refused(&[
            &["--perms", "0777"],
            &["--bind", "/home/me", "/home/me"]
        ]));
        // An own place with a shown place below it: chmod would reach it.
        assert!(refused(&[
            &["--tmpfs", "/home"],
            &["--bind", "/home/me", "/home/me"],
            &["--chmod", "0777", "/home/me"]
        ]));
    }

    /// Bubblewrap makes folders and links on the computer when it is told to
    /// make them inside a shown folder, following any link the app left
    /// there: the room's own new things only in its own space.
    #[test]
    fn new_things_never_inside_a_place_shown_from_the_app() {
        for op in [
            &["--symlink", "/x", "/home/me/x/evil.desktop"][..],
            &["--dir", "/home/me/x/evil"],
            &["--tmpfs", "/home/me/x"],
            &["--proc", "/home/me/x"],
            &["--dev", "/home/me/x"],
            &["--mqueue", "/home/me/x"],
        ] {
            assert!(
                refused(&[&["--bind", "/home/me", "/home/me"], op]),
                "{op:?}"
            );
        }
        // In the room's own space they are fine.
        assert!(!refused(&[
            &["--tmpfs", "/tmp-home"],
            &["--dir", "/tmp-home/x"],
            &["--symlink", "/usr/lib", "/lib64"]
        ]));
        // Nothing is shown through the room's own links.
        assert!(refused(&[
            &["--symlink", "/home/me", "/h"],
            &["--ro-bind", "/h/x", "/h/x"]
        ]));
        assert!(refused(&[
            &["--symlink", "/home/me", "/h"],
            &["--dir", "/h/x"]
        ]));
        // … or at them.
        assert!(refused(&[
            &["--symlink", "/x", "/h"],
            &["--dir", "/h"],
            &["--chmod", "0777", "/h"]
        ]));
        // A link where a place of the app is mounted later: refused.
        assert!(refused(&[
            &["--symlink", "/x", "/home/me/.config/autostart"],
            &["--bind", "/home/me", "/home/me"]
        ]));
        // Links into Bubblewrap's build stage.
        for t in [
            "/oldroot/home",
            "/newroot/.sam-room",
            "../../.sam-room",
            "a/../b",
        ] {
            assert!(refused(&[&["--symlink", t, "/x"]]), "{t}");
        }
        // The room's own links come last, after every mount.
        let room = ok(&[
            &["--symlink", "usr/lib", "/lib64"],
            &["--ro-bind", "/usr/lib", "/usr/lib"],
        ]);
        assert!(matches!(room.steps.last(), Some(Step::Args(a)) if a[0] == "--symlink"));
    }

    /// An own place gives no Landlock write right over places of the app
    /// below it.
    #[test]
    fn an_own_place_above_the_apps_places_gives_no_write_right() {
        let room = ok(&[
            &["--dir", "/home"],
            &["--bind", "/home/me/.cache", "/home/me/.cache"],
        ]);
        assert!(
            !room.own.contains(&PathBuf::from("/home")),
            "{:?}",
            room.own
        );
        let room = ok(&[&["--tmpfs", "/scratch"]]);
        assert!(room.own.contains(&PathBuf::from("/scratch")));
    }

    /// SAM's own place in a room (its helper and the room's rules): no
    /// request may name it, cover it with a link, or make things in it.
    #[test]
    fn sams_own_place_in_a_room_is_out_of_reach() {
        for op in [
            &["--symlink", "/home/me/x", RESERVED][..],
            &["--tmpfs", RESERVED],
            &["--dir", "/.sam-room/x"],
            &["--ro-bind-try", RESERVED, RESERVED],
            &["--remount-ro", RESERVED],
            // A new file system over the folder that holds it.
            &["--tmpfs", "/"],
            &["--proc", "/"],
            &["--dev", "/"],
            &["--mqueue", "/"],
            &["--dir", "/"],
            // Its folder or a link into it.
            &["--chdir", RESERVED],
            &["--chdir", "/.sam-room/x"],
            &["--symlink", "/.sam-room/room.spec", "/x"],
            &["--symlink", ".sam-room", "/y"],
        ] {
            assert!(refused(&[op]), "{op:?}");
        }
        // Showing the app's places below the root is no new file system
        // over it: SAM's place stays.
        assert!(!refused(&[
            &["--ro-bind", "/usr/lib", "/usr/lib"],
            &["--remount-ro", "/"]
        ]));
    }

    /// The app's /dev asked for without working devices: the same few
    /// nodes, as Bubblewrap shows them without devices, never its /dev
    /// with working ones.
    #[test]
    fn a_dev_asked_for_without_devices_has_no_working_devices() {
        for (op, access) in [
            ("--ro-bind", DeviceAccess::ReadOnly),
            ("--bind", DeviceAccess::NoDevices),
        ] {
            let room = ok(&[&[op, "/dev", "/dev"]]);
            assert!(
                !room
                    .steps
                    .iter()
                    .any(|st| matches!(st, Step::Args(a) if a[0] == "--dev")),
                "{op}: {:?}",
                room.steps
            );
            assert_eq!(room.steps[0], Step::Mask("/dev".into()));
            assert!(room.steps.contains(&Step::Device {
                src: "/dev/null".into(),
                dst: "/dev/null".into(),
                access
            }));
            assert!(room.steps.contains(&Step::Device {
                src: "/dev/dri".into(),
                dst: "/dev/dri".into(),
                access
            }));
            assert!(room.steps.iter().all(|st| match st {
                Step::Device { access: a, .. } => *a == access,
                _ => true,
            }));
        }
        // A parent asked for read-only: the same, below it.
        let small = FloorPlan::from_bwrap_args(&s(&[
            "--ro-bind",
            "/usr",
            "/usr",
            "--dev",
            "/dev",
            "--",
            "x",
        ]))
        .unwrap();
        let room = plan_room(
            &small,
            &req(&[&["--ro-bind", "/", "/"]], &["x"]),
            AppFacts::default(),
        )
        .unwrap();
        assert!(room.steps.contains(&Step::Mask("/dev".into())));
        assert!(!room
            .steps
            .iter()
            .any(|st| matches!(st, Step::Args(a) if a[0] == "--dev")));
    }

    /// The app's own --remount-ro makes read-only only the mount at its
    /// place, as Bubblewrap's (not recursive): a place mounted below it
    /// before keeps its rights, in the app as in its rooms.
    #[test]
    fn the_apps_remount_is_not_recursive() {
        let plan = FloorPlan::from_bwrap_args(&s(&[
            "--bind",
            "/h",
            "/home/me",
            "--bind",
            "/h/c",
            "/home/me/c",
            "--remount-ro",
            "/home/me",
            "--",
            "x",
        ]))
        .unwrap();
        assert!(matches!(plan.entries[0], Entry::Ro { .. }));
        assert!(matches!(plan.entries[1], Entry::Rw { .. }));
    }

    /// A remount reaches whatever mount Bubblewrap finds on top at its
    /// place: also one at the root (the person's own `--bind / /` before
    /// SAM's final `--remount-ro /`), and the mount below a `-try` place,
    /// which Bubblewrap skips when its source is missing and Room service
    /// then leaves out. Several overlay layers give no rooms. Before, the
    /// root and the mount below a `-try` place stayed writable for rooms
    /// while the app had them read-only.
    #[test]
    fn a_remount_reaches_the_mount_bubblewrap_finds_on_top() {
        let fp = |a: &[&str]| FloorPlan::from_bwrap_args(&s(a));
        let root = fp(&["--bind", "/", "/", "--remount-ro", "/", "--", "x"]).unwrap();
        assert_eq!(
            root.entries,
            vec![Entry::Ro {
                src: "/".into(),
                dst: "/".into()
            }]
        );
        let req_x = req(&[&["--bind", "/x/f", "/x/f"]], &["x"]);
        for try_bind in ["--bind-try", "--ro-bind-try"] {
            let mut plan = fp(&[
                "--bind",
                "/a",
                "/x",
                try_bind,
                "/b",
                "/x",
                "--remount-ro",
                "/x",
                "--",
                "x",
            ])
            .unwrap();
            assert!(
                plan.entries.iter().all(|e| matches!(e, Entry::Ro { .. })),
                "{try_bind}: {:?}",
                plan.entries
            );
            // /b missing: Room service leaves it out, /a is on top.
            plan.entries.remove(1);
            let room = plan_room(&plan, &req_x, AppFacts::default()).unwrap();
            assert!(
                matches!(
                    room.steps[..],
                    [Step::Show {
                        writable: false,
                        ..
                    }]
                ),
                "{try_bind}: {:?}",
                room.steps
            );
        }
        // A place not asked with -try stops the remount there.
        let below = fp(&[
            "--bind",
            "/a",
            "/x",
            "--bind",
            "/b",
            "/x",
            "--remount-ro",
            "/x",
            "--",
            "x",
        ])
        .unwrap();
        assert!(matches!(below.entries[0], Entry::Rw { .. }));
        assert!(matches!(below.entries[1], Entry::Ro { .. }));
        let mut dev = fp(&[
            "--dev-bind",
            "/dev/a",
            "/dev/x",
            "--dev-bind-try",
            "/dev/b",
            "/dev/x",
            "--remount-ro",
            "/dev/x",
            "--",
            "x",
        ])
        .unwrap();
        dev.entries.remove(1);
        assert!(matches!(
            dev.entries[0],
            Entry::Dev {
                read_only: true,
                ..
            }
        ));
        // A remount Bubblewrap finds through a link, `..`, or at a mount
        // of the computer below a shown folder: no rooms.
        for args in [
            &[
                "--symlink",
                "usr/lib",
                "/lib",
                "--bind",
                "/data",
                "/usr/lib/x",
                "--remount-ro",
                "/lib/x",
                "--",
                "x",
            ][..],
            &["--bind", "/a", "/x", "--remount-ro", "/x/../x", "--", "x"],
            &[
                "--bind",
                "/mnt",
                "/mnt",
                "--remount-ro",
                "/mnt/disk",
                "--",
                "x",
            ],
        ] {
            let e = fp(args).unwrap_err();
            assert!(e.contains("names no place mounted there"), "{args:?}: {e}");
        }
        assert_eq!(
            fp(&[
                "--overlay-src",
                "/l1",
                "--overlay-src",
                "/l2",
                "--overlay",
                "/u",
                "/w",
                "/app",
                "--",
                "x"
            ])
            .unwrap_err(),
            "an overlay of several layers, unknown to Room service"
        );
    }

    /// The room's own link is never made inside a place shown from the
    /// app, also when it was named before that place (links are made last,
    /// after every mount, so a link in a read-only place of the app would
    /// lead it onto the computer).
    #[test]
    fn a_room_link_named_first_is_never_made_inside_a_later_place() {
        for place in [
            &["--ro-bind", "/usr/lib", "/usr/lib"][..],
            &["--bind", "/home/me/.cache", "/home/me/.cache"],
        ] {
            let at = format!("{}/x/home/me/.config/autostart/evil.desktop", place[1]);
            let e = plan_room(
                &plan(),
                &req(&[&["--symlink", "/x", &at], place], &["x"]),
                AppFacts::default(),
            )
            .unwrap_err();
            assert!(
                e.contains("inside a place shown from the app"),
                "{place:?}: {e}"
            );
        }
    }

    /// A place asked for read-only keeps what the room makes for it (the
    /// app's hiding places, its /dev) read-only; own new places that cannot
    /// be written are recorded.
    #[test]
    fn read_only_asks_and_unwritable_own_places_are_kept_and_said() {
        let room = ok(&[&["--ro-bind", "/dev", "/dev"]]);
        let at = room
            .steps
            .iter()
            .position(|st| matches!(st, Step::Args(a) if a == &s(&["--remount-ro", "/dev"])))
            .expect("/dev not remounted read-only");
        assert!(room.steps[..at]
            .iter()
            .any(|st| matches!(st, Step::Args(a) if a[0] == "--dir")));
        // An own mount laid later at the same place is not remounted.
        let room = ok(&[&["--ro-bind", "/dev", "/dev"], &["--tmpfs", "/dev"]]);
        let last_remount = room
            .steps
            .iter()
            .rposition(|st| matches!(st, Step::Args(a) if a == &s(&["--remount-ro", "/dev"])))
            .unwrap();
        let own = room
            .steps
            .iter()
            .position(|st| matches!(st, Step::Args(a) if a == &s(&["--tmpfs", "/dev"])))
            .unwrap();
        assert!(last_remount < own, "{:?}", room.steps);
        let room = ok(&[
            &["--dir", "/work"],
            &["--tmpfs", "/scratch"],
            &["--dir", "/scratch/a"],
        ]);
        assert!(room
            .capped
            .iter()
            .any(|c| c.starts_with("/work: on the room's read-only root")));
        assert!(
            !room.capped.iter().any(|c| c.starts_with("/scratch")),
            "{:?}",
            room.capped
        );
    }

    /// --as-pid-1 is not passed into a room (Bubblewrap's own first
    /// process stays, and the room ends with SAM), and says so; a
    /// request's --remount-ro comes after its own links, as Bubblewrap
    /// would apply them; a link to a folder holding SAM's place is refused.
    #[test]
    fn rooms_keep_their_first_process_and_their_order() {
        let room = ok(&[&["--as-pid-1"]]);
        assert!(!room
            .steps
            .iter()
            .any(|st| matches!(st, Step::Args(a) if a[0] == "--as-pid-1")));
        assert!(room.capped.iter().any(|c| c.starts_with("--as-pid-1")));
        let room = ok(&[
            &["--ro-bind", "/usr/lib", "/usr/lib"],
            &["--symlink", "usr/lib", "/lib"],
            &["--remount-ro", "/"],
        ]);
        let pos = |first: &str| {
            room.steps
                .iter()
                .position(|st| matches!(st, Step::Args(a) if a[0] == first))
                .unwrap()
        };
        assert!(pos("--symlink") < pos("--remount-ro"), "{:?}", room.steps);
        for target in ["/", "."] {
            assert!(refused(&[&["--symlink", target, "/a"]]), "{target}");
        }
    }

    /// A device place the app has (perhaps a folder it or the person can
    /// write) is shown only as a whole too: nothing of the room's own lies
    /// inside it in any order, and an own place inside it gets no
    /// Landlock write right.
    #[test]
    fn nothing_of_the_room_lies_inside_a_device_place() {
        let plan = FloorPlan::from_bwrap_args(&s(&[
            "--dev-bind",
            "/srv/shared",
            "/srv/shared",
            "--",
            "x",
        ]))
        .unwrap();
        let ask = |ops: &[&[&str]]| plan_room(&plan, &req(ops, &["x"]), AppFacts::default());
        let e = ask(&[
            &["--symlink", "/srv/shared/x.desktop", "/srv/shared/sub/evil"],
            &["--dev-bind", "/srv/shared", "/srv/shared"],
        ])
        .unwrap_err();
        assert!(
            e.contains("only as a whole") || e.contains("inside a place shown from the app"),
            "{e}"
        );
        assert!(ask(&[
            &["--dir", "/srv/shared/sub"],
            &["--dev-bind", "/srv/shared", "/srv/shared"],
        ])
        .is_err());
        // An own folder that lies under a place shown later gives no write
        // right there.
        let room = ok(&[
            &["--dir", "/usr/lib/x"],
            &["--ro-bind", "/usr/lib", "/usr/lib"],
        ]);
        assert!(
            !room.own.iter().any(|o| o.starts_with("/usr/lib")),
            "{:?}",
            room.own
        );
    }

    /// Places inside a request's place that the app has read-only are
    /// recorded as capped when the request asked for them writable.
    #[test]
    fn read_only_places_inside_a_writable_request_are_recorded() {
        let room = ok(&[&["--bind", "/usr", "/usr"]]);
        for p in ["/usr/lib:", "/usr/bin:"] {
            assert!(
                room.capped.iter().any(|c| c.starts_with(p)),
                "{p} {:?}",
                room.capped
            );
        }
    }

    /// A place below a folder the app can write is shown only when the app
    /// cannot move its protected or hidden places there: every folder
    /// between that folder and such a place is pinned (a mount point of
    /// its own). A `~/.ssh` kept in a dotfiles folder whose folders are not
    /// pinned could be renamed by the app and then shown unhidden.
    #[test]
    fn a_place_below_a_writable_folder_needs_its_protections_pinned() {
        let stow = |pinned: bool| {
            let mut a = s(&["--bind", "/h", "/home/me"]);
            if pinned {
                a.extend(s(&["--bind", "/h/dotfiles", "/home/me/dotfiles"]));
                a.extend(s(&["--bind", "/h/dotfiles/ssh", "/home/me/dotfiles/ssh"]));
            }
            a.extend(s(&["--tmpfs", "/home/me/dotfiles/ssh/.ssh", "--", "x"]));
            FloorPlan::from_bwrap_args(&a).unwrap()
        };
        let ask = |plan: &FloorPlan| {
            plan_room(
                plan,
                &req(
                    &[&["--ro-bind", "/home/me/Pictures", "/home/me/Pictures"]],
                    &["x"],
                ),
                AppFacts::default(),
            )
        };
        let e = ask(&stow(false)).unwrap_err();
        assert!(e.contains("could move a protected or hidden place"), "{e}");
        assert!(ask(&stow(true)).is_ok());
        // A read-only place re-showing part of the folder protects it; one
        // brought in from elsewhere (the computer's theme settings in an
        // app's own home) does not, and lets nothing out when moved.
        let with = |src: &str| {
            FloorPlan::from_bwrap_args(&s(&[
                "--bind",
                "/h",
                "/home/me",
                "--ro-bind",
                src,
                "/home/me/.config/gtk-3.0",
                "--",
                "x",
            ]))
            .unwrap()
        };
        assert!(ask(&with("/h/.config/gtk-3.0")).is_err());
        assert!(ask(&with("/real/.config/gtk-3.0")).is_ok());
    }

    /// SAM hides a credential file reached through a link (`~/.netrc`
    /// into `~/dotfiles`) with an empty file over it: that counts as a
    /// hiding as an empty folder does. With the folder above it not
    /// pinned, the app could rename it (`~/dotfiles` to `~/y`) and a room
    /// asking for `~/y` showed the real file (review B2 S2b).
    #[test]
    fn a_hidden_file_below_a_writable_folder_needs_its_folders_pinned() {
        let plan = |pinned: bool| {
            let mut a = s(&["--bind", "/h", "/home/me"]);
            if pinned {
                a.extend(s(&["--bind", "/h/dotfiles", "/home/me/dotfiles"]));
            }
            a.extend(s(&[
                "--ro-bind",
                "/dev/null",
                "/home/me/dotfiles/netrc",
                "--",
                "x",
            ]));
            FloorPlan::from_bwrap_args(&a).unwrap()
        };
        let ask = |plan: &FloorPlan, at: &str| {
            plan_room(
                plan,
                &req(&[&["--ro-bind", at, at]], &["x"]),
                AppFacts::default(),
            )
        };
        for at in ["/home/me/y", "/home/me/Pictures"] {
            let e = ask(&plan(false), at).unwrap_err();
            assert!(
                e.contains("could move a protected or hidden place"),
                "{at}: {e}"
            );
            assert!(ask(&plan(true), at).is_ok(), "{at}");
        }
        // The hidden file lies in another place showing part of the same
        // writable folder: the folder above that place is not pinned, so
        // the app could rename it, place and all, and a room asking for
        // the new name saw the real file.
        let nested = FloorPlan::from_bwrap_args(&s(&[
            "--bind",
            "/h",
            "/home/me",
            "--bind",
            "/h/a/x",
            "/home/me/a/x",
            "--ro-bind",
            "/dev/null",
            "/home/me/a/x/netrc",
            "--",
            "x",
        ]))
        .unwrap();
        let e = ask(&nested, "/home/me/y").unwrap_err();
        assert!(e.contains("could move a protected or hidden place"), "{e}");
        // The computer's theme settings in an app's own home, with their
        // private file hidden: moved, a room sees only the app's own empty
        // folder there, so rooms below the home stay possible (SAM's
        // defaults: own home, computer's themes).
        let themes = FloorPlan::from_bwrap_args(&s(&[
            "--bind",
            "/own/home",
            "/home/me",
            "--dir",
            "/home/me/.config",
            "--ro-bind-try",
            "/home/me/.config/gtk-3.0",
            "/home/me/.config/gtk-3.0",
            "--ro-bind",
            "/dev/null",
            "/home/me/.config/gtk-3.0/bookmarks",
            "--",
            "x",
        ]))
        .unwrap();
        assert!(ask(&themes, "/home/me/.cache/x").is_ok());
    }

    /// A device place is shown only as a whole: a path below it is never
    /// looked up by name (a link the app made in /dev/shm could lead to a
    /// file the app cannot see).
    #[test]
    fn a_device_place_is_shown_only_as_a_whole() {
        let plan =
            FloorPlan::from_bwrap_args(&s(&["--dev-bind", "/dev", "/dev", "--", "x"])).unwrap();
        let ask = |p: &str| {
            plan_room(
                &plan,
                &req(&[&["--dev-bind", p, p]], &["x"]),
                AppFacts::default(),
            )
        };
        assert!(ask("/dev").is_ok());
        for below in ["/dev/shm/evil", "/dev/dri", "/dev/null"] {
            let e = ask(below).unwrap_err();
            assert!(e.contains("only as a whole"), "{below}: {e}");
        }
    }

    /// A room never gets a game controller SAM watches: SAM could not take
    /// it out of the room when it is unplugged (review R56).
    #[test]
    fn a_room_never_gets_a_watched_game_controller() {
        let pad = "/dev/input/event5";
        let plan = FloorPlan::from_bwrap_args(&s(&[
            "--tmpfs",
            "/dev/input",
            "--dev-bind-try",
            pad,
            pad,
            "--remount-ro",
            "/dev/input",
            "--",
            "x",
        ]))
        .unwrap();
        let ask = |plan: &FloorPlan| {
            plan_room(
                plan,
                &req(&[&["--dev-bind", pad, pad]], &["x"]),
                AppFacts::default(),
            )
        };
        assert!(ask(&plan).is_ok(), "the request itself is a fair one");
        let without = plan.without_devices(&[PathBuf::from(pad)]);
        assert!(ask(&without).is_err(), "a room got the watched controller");
    }

    /// A device that is a single file, asked for at its own place, is shown
    /// by exactly its name (no "/" after it, which a file cannot have).
    #[test]
    fn a_single_device_file_is_shown_by_its_exact_name() {
        let plan = FloorPlan::from_bwrap_args(&s(&[
            "--dev-bind-try",
            "/dev/video0",
            "/dev/video0",
            "--",
            "x",
        ]))
        .unwrap();
        let room = plan_room(
            &plan,
            &req(&[&["--dev-bind", "/dev/video0", "/dev/video0"]], &["x"]),
            AppFacts::default(),
        )
        .unwrap();
        match &room.steps[0] {
            Step::Device { src, .. } => assert_eq!(src.to_string_lossy(), "/dev/video0"),
            st => panic!("{st:?}"),
        }
    }

    /// The app's own `--remount-ro` over a device place counts in rooms
    /// too: never writable there, working devices stay read-only.
    #[test]
    fn a_device_place_the_app_has_read_only_stays_read_only() {
        let plan = FloorPlan::from_bwrap_args(&s(&[
            "--dev-bind",
            "/srv/shared",
            "/srv/shared",
            "--remount-ro",
            "/srv/shared",
            "--",
            "x",
        ]))
        .unwrap();
        let full = |op: &str| {
            plan_room(
                &plan,
                &req(&[&[op, "/srv/shared", "/srv/shared"]], &["x"]),
                AppFacts::default(),
            )
            .unwrap()
        };
        let room = |op: &str| full(op).steps;
        // Said in the start record, as every cap is.
        assert!(full("--bind")
            .capped
            .iter()
            .any(|c| c.contains("/srv/shared: read-only for the app")));
        assert!(!full("--ro-bind")
            .capped
            .iter()
            .any(|c| c.contains("/srv/shared")));
        assert_eq!(
            room("--bind"),
            vec![Step::Device {
                src: "/srv/shared".into(),
                dst: "/srv/shared".into(),
                access: DeviceAccess::ReadOnly
            }]
        );
        assert_eq!(
            room("--dev-bind"),
            vec![
                Step::Device {
                    src: "/srv/shared".into(),
                    dst: "/srv/shared".into(),
                    access: DeviceAccess::Devices
                },
                Step::Args(s(&["--remount-ro", "/srv/shared"])),
            ]
        );
    }

    #[test]
    fn the_rooms_folder_is_asked_or_safe() {
        let mut r = req(&[&["--ro-bind", "/usr/lib", "/usr/lib"]], &["x"]);
        r.cwd = "/home/me".into();
        assert_eq!(
            plan_room(&plan(), &r, AppFacts::default()).unwrap().chdir,
            PathBuf::from("/")
        );
        r.cwd = "/usr/lib".into();
        assert_eq!(
            plan_room(&plan(), &r, AppFacts::default()).unwrap().chdir,
            PathBuf::from("/usr/lib")
        );
    }

    #[test]
    fn a_floor_plan_with_an_unknown_option_gives_no_rooms() {
        assert!(FloorPlan::from_bwrap_args(&s(&["--made-up", "/x"])).is_err());
        assert!(FloorPlan::from_bwrap_args(&s(&["--cap-add", "ALL"])).is_err());
    }

    /// Why the default floor plan gets no room for these options.
    fn why(ops: &[&[&str]]) -> String {
        plan_room(&plan(), &req(ops, &["x"]), AppFacts::default()).unwrap_err()
    }

    /// Every limit of a request holds at exactly its size: a request right
    /// at a limit is read, one a step over it is refused for that reason.
    /// Options of the older form count together with the others; a text
    /// with a zero byte in it is refused however short it is.
    #[test]
    fn a_request_is_read_up_to_each_limit_and_refused_one_beyond_it() {
        let read = |r: Request| read_request(&serde_json::to_vec(&r).unwrap());
        let base = || req(&[], &["x"]);
        // Options: both forms together.
        let options = |ops: usize, flags: usize| Request {
            ops: (0..ops).map(|i| s(&["--dir", &format!("/d{i}")])).collect(),
            flags: vec!["--die-with-parent".into(); flags],
            ..base()
        };
        assert!(read(options(200, MAX_OPS - 200)).is_ok());
        assert_eq!(
            read(options(200, MAX_OPS - 200 + 1)).unwrap_err(),
            "the request has too many options"
        );
        // The command's words.
        let command = |n: usize| Request {
            command: vec!["x".into(); n],
            ..base()
        };
        assert!(read(command(MAX_ARGS)).is_ok());
        assert_eq!(
            read(command(MAX_ARGS + 1)).unwrap_err(),
            "the request has no command, or too long a one"
        );
        // One text (here a variable's value).
        let text = |t: String| Request {
            env: BTreeMap::from([("A".to_string(), t)]),
            ..base()
        };
        assert!(read(text("a".repeat(MAX_TEXT))).is_ok());
        for long_or_cut in ["a".repeat(MAX_TEXT + 1), "a\0b".to_string()] {
            assert_eq!(
                read(text(long_or_cut)).unwrap_err(),
                "the request holds too long a text"
            );
        }
        // The environment's size.
        let env = |n: usize| Request {
            env: (0..n).map(|i| (format!("V{i}"), "1".to_string())).collect(),
            ..base()
        };
        assert!(read(env(MAX_ARGS)).is_ok());
        assert_eq!(
            read(env(MAX_ARGS + 1)).unwrap_err(),
            "the request's environment is too large"
        );
        // Resource limits: at most 64, each naming a resource below 64.
        let limits = |l: Vec<[u64; 3]>| Request {
            limits: l,
            ..base()
        };
        assert!(read(limits(vec![[0, 1, 1]; 64])).is_ok());
        assert!(read(limits(vec![[63, 1, 1]])).is_ok());
        for bad in [vec![[0, 1, 1]; 65], vec![[64, 1, 1]]] {
            assert_eq!(
                read(limits(bad)).unwrap_err(),
                "the request's resource limits are not valid"
            );
        }
        // The umask: permission bits only.
        let umask = |m: u32| Request {
            umask: Some(m),
            ..base()
        };
        assert!(read(umask(0o777)).is_ok());
        assert_eq!(
            read(umask(0o1000)).unwrap_err(),
            "the request's umask is not valid"
        );
    }

    /// The room's own new places take a mode (--perms, for the next --tmpfs
    /// or --dir) and a size (--size, for the next --tmpfs only) as
    /// Bubblewrap does, each checked in its own form; --chmod takes a mode
    /// up to 7777; a host name is passed on as asked.
    #[test]
    fn modes_sizes_and_host_names_of_the_rooms_own_places_are_checked_each_in_its_form() {
        let room = ok(&[&["--hostname", "box"]]);
        assert!(
            room.steps.contains(&Step::Args(s(&["--hostname", "box"]))),
            "{:?}",
            room.steps
        );
        for good in [
            &[&["--perms", "0700"][..], &["--dir", "/work"]][..],
            &[&["--perms", "7777"], &["--tmpfs", "/scratch"]],
            &[&["--size", "1048576"], &["--tmpfs", "/scratch"]],
            &[&["--tmpfs", "/scratch"], &["--chmod", "7777", "/scratch"]],
        ] {
            let room = plan_room(&plan(), &req(good, &["x"]), AppFacts::default());
            assert!(room.is_ok(), "{good:?}: {room:?}");
        }
        for (bad, e) in [
            (
                &[&["--size", "1048576"][..], &["--dir", "/work"]][..],
                "--size only for the room's own new places",
            ),
            (
                &[&["--size", "lots"], &["--tmpfs", "/scratch"]],
                "--size needs a number",
            ),
            (
                &[&["--perms", "9"], &["--tmpfs", "/scratch"]],
                "--perms needs an octal mode",
            ),
            (
                &[&["--perms", "10000"], &["--tmpfs", "/scratch"]],
                "--perms needs an octal mode",
            ),
            (
                &[&["--tmpfs", "/scratch"], &["--chmod", "10000", "/scratch"]],
                "--chmod needs an octal mode",
            ),
        ] {
            assert_eq!(why(bad), e, "{bad:?}");
        }
    }

    /// SAM's own arguments are read as Bubblewrap reads them: the app
    /// folder laid as an overlay is shown to rooms from its unchanged
    /// source, read-only; the last of the network options counts; an
    /// option a room never gets leaves the app without rooms.
    #[test]
    fn sams_own_arguments_are_read_into_the_floor_plan_as_bubblewrap_reads_them() {
        let fp = |a: &[&str]| FloorPlan::from_bwrap_args(&s(a));
        let p = fp(&[
            "--overlay-src",
            "/apps/x",
            "--overlay",
            "/layers/x/upper",
            "/layers/x/work",
            "/app",
            "--",
            "x",
        ])
        .unwrap();
        assert_eq!(
            p.entries,
            vec![Entry::Ro {
                src: "/apps/x".into(),
                dst: "/app".into()
            }]
        );
        let e = fp(&["--overlay", "/u", "/w", "/app", "--", "x"]).unwrap_err();
        assert_eq!(e, "an overlay without its source");
        assert!(
            !fp(&["--unshare-net", "--share-net", "--", "x"])
                .unwrap()
                .no_network
        );
        assert!(
            fp(&["--share-net", "--unshare-net", "--", "x"])
                .unwrap()
                .no_network
        );
        for never in ["--not-a-security-boundary", "--help"] {
            assert_eq!(
                fp(&[never, "--", "x"]).unwrap_err(),
                format!("SAM's own sandbox command has {never}, unknown to Room service")
            );
        }
    }

    /// SAM's own place stays out of reach also where a request reaches it
    /// only through the app's places (an app place over the root, or one
    /// inside SAM's place), and a refusal for it names it before anything
    /// else wrong in the request.
    #[test]
    fn sams_own_place_is_out_of_reach_through_the_apps_places_too() {
        let room_of = |args: &[&str]| {
            let p = FloorPlan::from_bwrap_args(&s(args)).unwrap();
            plan_room(
                &p,
                &req(&[&["--ro-bind", "/", "/"]], &["x"]),
                AppFacts::default(),
            )
        };
        assert_eq!(
            room_of(&["--ro-bind", "/", "/", "--", "x"]).unwrap_err(),
            "/ is SAM's own place in a room"
        );
        assert_eq!(
            room_of(&[
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/srv/x",
                "/.sam-room/x",
                "--",
                "x"
            ])
            .unwrap_err(),
            "/.sam-room/x is SAM's own place in a room"
        );
        assert!(room_of(&["--ro-bind", "/usr", "/usr", "--", "x"]).is_ok());
        // Named first, before what else is wrong.
        assert_eq!(
            why(&[&["--chmod", "0755", "/.sam-room/x"]]),
            "/.sam-room/x is SAM's own place in a room"
        );
        for first in [&["--dir", "/.sam-room/x"][..], &["--tmpfs", "/"]] {
            assert_eq!(
                why(&[first, &["--ro-bind", "/secret", "/secret"]]),
                format!("{} is SAM's own place in a room", first[1]),
                "{first:?}"
            );
        }
    }

    /// A mode change the room asks for never lies inside a place the app
    /// can write, also when it was named before that place.
    #[test]
    fn a_mode_change_named_first_never_lies_inside_a_place_the_app_can_write() {
        let p = FloorPlan::from_bwrap_args(&s(&["--bind", "/data/w", "/w", "--", "x"])).unwrap();
        let ask = |ops: &[&[&str]]| plan_room(&p, &req(ops, &["x"]), AppFacts::default());
        assert!(ask(&[&["--tmpfs", "/w"], &["--bind", "/w", "/w"]]).is_ok());
        // Refused for the mode change itself (another rule's message also
        // speaks of "a place the app can write", so the whole text counts).
        let e = ask(&[
            &["--tmpfs", "/w"],
            &["--chmod", "0755", "/w/c"],
            &["--bind", "/w", "/w"],
        ])
        .unwrap_err();
        assert_eq!(
            e,
            "/w/c lies inside /w, a place the app can write: a room shows such a place only as a whole"
        );
    }

    /// Only a place asked for writable and given read-only is recorded as
    /// given with fewer rights: one asked for read-only, or given writable
    /// as asked, is not.
    #[test]
    fn only_places_given_with_fewer_rights_than_asked_are_recorded() {
        let fewer = |ops: &[&[&str]]| -> Vec<String> {
            ok(ops)
                .capped
                .into_iter()
                .filter(|c| c.contains("read-only for the app"))
                .collect()
        };
        assert_eq!(
            fewer(&[&["--bind", "/usr/lib", "/usr/lib"]]),
            ["/usr/lib: read-only for the app, so read-only here"]
        );
        assert_eq!(
            fewer(&[&["--bind", "/usr", "/usr"]]),
            [
                "/usr/lib: read-only for the app, so read-only here",
                "/usr/bin: read-only for the app, so read-only here"
            ]
        );
        for as_asked in [
            &["--ro-bind", "/usr/lib", "/usr/lib"][..],
            &["--ro-bind", "/usr", "/usr"],
            &["--bind", "/home/me/.cache", "/home/me/.cache"],
        ] {
            assert_eq!(fewer(&[as_asked]), Vec::<String>::new(), "{as_asked:?}");
        }
    }

    /// The app's links that a room has too (copied with the app's view of a
    /// place that holds them: SAM's `/usr/lib64` link here, the links of
    /// the app's /dev) count like the room's own: nothing is made, changed
    /// or shown at or behind one, in whatever order it was named, since
    /// Bubblewrap would follow the link wherever it leads. The same option
    /// beside the link, or where the room has no such link, is fine.
    #[test]
    fn nothing_of_the_room_lies_at_or_behind_a_link_copied_from_the_app() {
        const SAID: &str = "a link of the app's that the room has too";
        let usr = &["--ro-bind", "/usr", "/usr"][..];
        // The room has the app's link, as a link.
        let room = ok(&[usr]);
        assert!(
            room.steps.iter().any(|s| matches!(s, Step::Args(a)
                if a == &["--symlink", "lib", "/usr/lib64"])),
            "{:?}",
            room.steps
        );
        // Asked twice, the link comes twice: still a room.
        ok(&[usr, usr]);
        let through: &[&[&str]] = &[
            &["--dir", "/usr/lib64/x"],
            &["--dir", "/usr/lib64"],
            &["--tmpfs", "/usr/lib64/x"],
            &["--proc", "/usr/lib64/x"],
            &["--dev", "/usr/lib64/x"],
            &["--mqueue", "/usr/lib64/x"],
            &["--symlink", "/x", "/usr/lib64/y"],
            &["--symlink", "lib64", "/usr/lib64"],
            &["--chmod", "0700", "/usr/lib64/x"],
            &["--remount-ro", "/usr/lib64"],
            &["--remount-ro", "/usr/lib64/x"],
            &["--ro-bind", "/usr/lib64/x", "/usr/lib64/x"],
            &["--ro-bind-try", "/usr/lib64/x", "/usr/lib64/x"],
            &["--bind-try", "/usr/lib64", "/usr/lib64"],
            &["--dev-bind-try", "/usr/lib64/x", "/usr/lib64/x"],
        ];
        for &op in through {
            let e = why(&[usr, op]);
            assert!(e.contains(SAID), "{op:?} after the link: {e}");
        }
        // Named before the place that brings the link: refused all the
        // same (Bubblewrap would make it first and the link then fail, or
        // make it through the link). A mode change named first has no own
        // place yet and is refused for that; a place of the app named
        // first finds nothing there.
        for &op in through
            .iter()
            .filter(|o| o[0] != "--chmod" && !o[0].contains("bind"))
        {
            let e = why(&[op, usr]);
            assert!(e.contains(SAID), "{op:?} before the link: {e}");
        }
        // The app's /dev, asked for without devices, has its links too.
        let dev = &["--ro-bind", "/dev", "/dev"][..];
        for op in [
            &["--dir", "/dev/fd/x"][..],
            &["--symlink", "/x", "/dev/stdout"],
        ] {
            let e = why(&[dev, op]);
            assert!(e.contains(SAID), "{op:?}: {e}");
            let e = why(&[op, dev]);
            assert!(e.contains(SAID), "{op:?} first: {e}");
        }
        // Asked for with working devices, the app's /dev is Bubblewrap's
        // own `--dev`, which makes these links itself: they count all the
        // same, whether the room asks for /dev or for everything.
        let mut all = plan();
        all.entries
            .retain(|e| !e.at().starts_with("/home/me/") || e.at() == Path::new("/home/me"));
        let why_all =
            |ops: &[&[&str]]| plan_room(&all, &req(ops, &["x"]), AppFacts::default()).unwrap_err();
        let dev_bind = &["--dev-bind", "/dev", "/dev"][..];
        let root_bind = &["--dev-bind", "/", "/"][..];
        for op in [
            &["--dir", "/dev/fd/x"][..],
            &["--symlink", "/x", "/dev/stdout"],
            &["--tmpfs", "/dev/stderr/x"],
            &["--remount-ro", "/dev/fd"],
            &["--dir", "/dev/ptmx/x"],
            &["--dir", "/dev/core/x"],
        ] {
            for ops in [
                [dev_bind, op],
                [op, dev_bind],
                [root_bind, op],
                [op, root_bind],
            ] {
                let e = why_all(&ops);
                assert!(e.contains(SAID), "{ops:?}: {e}");
            }
        }
        // Controls: Bubblewrap's own links again as they are, and places
        // beside them.
        plan_room(
            &all,
            &req(
                &[
                    root_bind,
                    &["--symlink", "/proc/self/fd", "/dev/fd"],
                    &["--symlink", "pts/ptmx", "/dev/ptmx"],
                    &["--dir", "/dev/fdx"],
                ],
                &["x"],
            ),
            AppFacts::default(),
        )
        .unwrap();
        ok(&[dev_bind, &["--dir", "/dev/stdoutx"]]);
        // Controls: beside the link, and without the link in the room.
        ok(&[
            usr,
            &["--perms", "0700"],
            &["--tmpfs", "/usr/lib64-own"],
            &["--chmod", "0700", "/usr/lib64-own"],
            &["--dir", "/usr/lib64-own/x"],
            &["--symlink", "lib", "/usr/lib32"],
            &["--remount-ro", "/usr/lib"],
        ]);
        ok(&[dev, &["--dir", "/dev/shm/x"], &["--dir", "/dev/fdx"]]);
        // Nor through a link of the room's own that leads to one of the
        // app's: a remount there, in whatever order (Bubblewrap makes the
        // link first and follows both). The link itself is fine.
        let link = &["--symlink", "usr/lib64", "/q"][..];
        for remount in [&["--remount-ro", "/q/x"][..], &["--remount-ro", "/q"]] {
            for ops in [
                [usr, link, remount],
                [remount, usr, link],
                [link, remount, usr],
            ] {
                let e = why(&ops);
                assert!(
                    e.contains("is at or behind a link of the room"),
                    "{ops:?}: {e}"
                );
            }
        }
        ok(&[usr, link, &["--remount-ro", "/usr/lib"]]);
        // The same link again at its place changes nothing (a program that
        // asks for everything and makes the system's links as it finds
        // them), in either order.
        let same = &["--symlink", "lib", "/usr/lib64"][..];
        ok(&[usr, same]);
        ok(&[same, usr]);
        ok(&[&["--tmpfs", "/usr"], &["--dir", "/usr/lib64/x"]]);
        ok(&[
            &["--ro-bind", "/usr/lib", "/usr/lib"],
            &["--symlink", "lib", "/usr/lib64"],
        ]);
    }

    /// A /proc of the room's own is mounted while Bubblewrap builds the
    /// room, and its links (/proc/self/root, /proc/N/root, /proc/self/fd/N)
    /// lead out of the room: to the build stage, where the computer's root
    /// is at /oldroot, and to the folders SAM hands Bubblewrap. Nothing of
    /// the room is made, changed or shown inside one (nor inside its own
    /// message queue file system), in whatever order it was named.
    #[test]
    fn nothing_of_the_room_lies_inside_a_proc_of_its_own() {
        const SAID: &str = "a /proc or message queue file system of the room's own";
        let proc = &["--proc", "/proc"][..];
        for op in [
            &["--dir", "/proc/self/root/oldroot/home/me/.config/autostart"][..],
            &["--dir", "/proc/self/root/x"],
            &["--symlink", "/x", "/proc/1/root/y"],
            &["--tmpfs", "/proc/self/fd/3/x"],
            &["--dev", "/proc/self/root/x"],
            &["--proc", "/proc/self/root/x"],
            &["--mqueue", "/proc/self/cwd/x"],
            &["--remount-ro", "/proc/self/root/x"],
            &["--ro-bind-try", "/proc/self/x", "/proc/self/x"],
            &[
                "--bind-try",
                "/proc/self/root/home/me",
                "/proc/self/root/home/me",
            ],
        ] {
            let e = why(&[proc, op]);
            assert!(e.contains(SAID), "{op:?} after the /proc: {e}");
            let e = why(&[op, proc]);
            assert!(e.contains(SAID), "{op:?} before the /proc: {e}");
        }
        // A mode change on the computer: a folder made there first, then
        // its mode.
        let e = why(&[
            proc,
            &["--dir", "/proc/self/root/oldroot/home/me"],
            &["--chmod", "0777", "/proc/self/root/oldroot/home/me"],
        ]);
        assert!(e.contains(SAID), "{e}");
        // The mode change alone: a /proc inside a room's own tmpfs, so the
        // mode change lies below the room's own new place and only the
        // rule for the room's /proc refuses it. The control beside it, a
        // mode change of the tmpfs itself, is allowed.
        let e = why(&[
            &["--tmpfs", "/a"],
            &["--proc", "/a/p"],
            &["--chmod", "0777", "/a/p/self/root/oldroot/home/me"],
        ]);
        assert!(e.contains(SAID), "{e}");
        ok(&[
            &["--tmpfs", "/a"],
            &["--proc", "/a/p"],
            &["--chmod", "0700", "/a"],
        ]);
        // The room's own message queue file system counts the same way.
        let mq = &["--mqueue", "/mq"][..];
        for ops in [[mq, &["--dir", "/mq/x"]], [&["--dir", "/mq/x"], mq]] {
            let e = why(&ops);
            assert!(e.contains(SAID), "{ops:?}: {e}");
        }
        // Places of the app laid out below the one asked for, and the
        // links copied with them, count too, in either order.
        let usr = &["--ro-bind", "/usr", "/usr"][..];
        for own in [&["--proc", "/usr"][..], &["--mqueue", "/usr"]] {
            for ops in [[own, usr], [usr, own]] {
                let e = why(&ops);
                assert!(e.contains(SAID), "{ops:?}: {e}");
            }
        }
        // Nor through a link of the room's own that leads into its /proc:
        // a remount there, in whatever order (Bubblewrap makes the link
        // first, then follows it into its build stage). The link itself
        // is fine.
        let link = &["--symlink", "proc/self/root", "/q"][..];
        for remount in [
            &["--remount-ro", "/q/oldroot/home/me"][..],
            &["--remount-ro", "/q"],
        ] {
            for ops in [
                [proc, link, remount],
                [remount, proc, link],
                [link, remount, proc],
            ] {
                let e = why(&ops);
                assert!(
                    e.contains("is at or behind a link of the room"),
                    "{ops:?}: {e}"
                );
            }
        }
        ok(&[proc, link, &["--remount-ro", "/proc"]]);
        // Controls: a room with its own /proc, beside it and at its place.
        ok(&[
            usr,
            proc,
            &["--dev", "/dev"],
            &["--dir", "/procx/y"],
            &["--symlink", "/proc/self/fd", "/fd"],
            &["--remount-ro", "/proc"],
            &["--tmpfs", "/proc"],
            &["--proc", "/proc"],
            mq,
            &["--dir", "/mqx"],
        ]);
        ok(&[proc, &["--ro-bind-try", "/proc", "/proc"]]);
    }
}
