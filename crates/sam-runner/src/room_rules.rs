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
//!   own space, never inside a place shown from the app; SAM's own mounts
//!   come first, at a place no request may touch.
//! - Every restriction the request asks for is kept. An option the rules do
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
}

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
    let mut seen = std::collections::BTreeSet::new();
    if r.fds
        .iter()
        .any(|f| !(0..1024).contains(f) || !seen.insert(*f))
    {
        return Err("the request's connection numbers are not valid".into());
    }
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
    if !is_clean_absolute(&r.cwd) {
        return Err("the request's folder is not a plain absolute path".into());
    }
    Ok(r)
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
    /// A device (or folder of devices) of the computer.
    Dev { src: PathBuf, dst: PathBuf },
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
/// name this place or anything in it.
pub const RESERVED: &str = "/.sam-room";

impl FloorPlan {
    /// Reads SAM's own Bubblewrap arguments for the app (up to `--`). An
    /// option SAM does not use is an error: then the start gets no rooms.
    pub fn from_bwrap_args(args: &[String]) -> Result<FloorPlan, String> {
        let mut entries = Vec::new();
        let mut i = 0;
        let mut overlay_src: Option<PathBuf> = None;
        // Bubblewrap shares the network unless told otherwise.
        let mut network = true;
        let mut read_only: Vec<(usize, PathBuf)> = Vec::new();
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
                    // Everything mounted so far at or below it is read-only.
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
        // A --remount-ro makes the mounts made before it read-only at and
        // below its place (SAM's own final `--remount-ro /` only concerns
        // the sandbox's root, which holds nothing of the computer).
        for (before, at) in read_only {
            if at == Path::new("/") {
                continue;
            }
            for e in entries.iter_mut().take(before) {
                if let Entry::Rw { src, dst } = e {
                    if dst.starts_with(&at) {
                        *e = Entry::Ro {
                            src: src.clone(),
                            dst: dst.clone(),
                        };
                    }
                }
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

fn under(p: &Path, top: &Path) -> bool {
    p.starts_with(top)
}

/// A path of the request at or below RESERVED (or RESERVED below it, as a
/// folder that would hold it).
fn reserved(p: &Path) -> bool {
    p.starts_with(RESERVED)
}

/// The room for `req`, or why there is none.
pub fn plan_room(plan: &FloorPlan, req: &Request, facts: AppFacts) -> Result<RoomPlan, String> {
    let mut room = RoomPlan {
        env: req.env.clone(),
        command: req.command.clone(),
        ..Default::default()
    };
    // Bubblewrap's order: the last of --share-net / --unshare-net /
    // --unshare-all decides (the room's base gives up everything first).
    let mut want_net = false;
    let mut chdir: Option<PathBuf> = None;
    // Places shown from the app (their place in the room), and the room's
    // own links: the room's own new things never go inside the first, and
    // nothing is shown through the second.
    let mut shown: Vec<PathBuf> = Vec::new();
    let mut own_links: Vec<PathBuf> = Vec::new();
    let mut late_links: Vec<Step> = Vec::new();
    // Flags of the older form first, then the options in order.
    let ops: Vec<Vec<String>> = req
        .flags
        .iter()
        .map(|f| vec![f.clone()])
        .chain(req.ops.iter().cloned())
        .collect();
    // A path the room makes something new at: never in SAM's reserved
    // place, never inside a place shown from the app (Bubblewrap would make
    // it on the computer, through any link the app left there), never
    // through one of the room's own links.
    let own_place = |at: &Path, shown: &[PathBuf], own_links: &[PathBuf]| -> Result<(), String> {
        if reserved(at) {
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
        Ok(())
    };
    let mut k = 0;
    while k < ops.len() {
        let op = &ops[k];
        let name = op.first().ok_or("an empty option")?.as_str();
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
                    room.steps
                        .push(Step::Args(vec![name.into(), path_arg(&at)]));
                }
                "--as-pid-1" => room.steps.push(Step::Args(vec![name.into()])),
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
                "--chdir" => chdir = Some(clean(&op[1])?),
                "--hostname" => room.steps.push(Step::Args(op.clone())),
                "--proc" | "--dev" | "--tmpfs" | "--mqueue" | "--dir" => {
                    let at = clean(&op[1])?;
                    own_place(&at, &shown, &own_links)?;
                    if matches!(name, "--tmpfs" | "--dir") {
                        room.own.push(at.clone());
                    }
                    room.steps
                        .push(Step::Args(vec![name.into(), path_arg(&at)]));
                }
                "--symlink" => {
                    let at = clean(&op[2])?;
                    own_place(&at, &shown, &own_links)?;
                    // While Bubblewrap builds the room, /newroot is the room
                    // and /oldroot the computer: a link may not name them.
                    let target = Path::new(&op[1]);
                    if target
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                        || target.starts_with("/oldroot")
                        || target.starts_with("/newroot")
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
                    own_place(&at, &shown, &own_links)?;
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
                // What is now mounted from the app (not the asked path: for
                // `/` that is the app's places inside it, not the root).
                for step in &room.steps[before..] {
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
    room.steps.extend(late_links);
    // An own place with a place of the app below it gives no write right
    // there (Landlock's rules reach down).
    room.own.retain(|o| !shown.iter().any(|s| under(s, o)));
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
            Entry::Dev { src: top, .. } => {
                room.steps.push(Step::Device {
                    src: top.join(&rest),
                    dst: src.to_path_buf(),
                    access: asked,
                });
                shown = true;
            }
            Entry::DevFs { .. } => {
                if rest.as_os_str().is_empty() {
                    room.steps
                        .push(Step::Args(vec!["--dev".into(), path_arg(src)]));
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
                room.steps.push(Step::Show {
                    source: Source {
                        entry: i,
                        rel: PathBuf::new(),
                    },
                    dst: dst.clone(),
                    writable: want_write && matches!(e, Entry::Rw { .. }),
                    optional: true,
                });
                shown = true;
            }
            Entry::Dev { src: from, dst } => {
                room.steps.push(Step::Device {
                    src: from.clone(),
                    dst: dst.clone(),
                    access: asked,
                });
                shown = true;
            }
            Entry::DevFs { at } => {
                room.steps
                    .push(Step::Args(vec!["--dev".into(), path_arg(at)]));
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
        let room = ok(&[&["--bind", "/home/me", "/home/me"]]);
        assert!(matches!(room.steps[0], Step::Show { writable: true, .. }));
    }

    /// The home shown writable keeps its protected place read-only and its
    /// hidden ~/.ssh hidden, mounted after it, in the app's order.
    #[test]
    fn protected_and_hidden_places_inside_a_shown_folder_stay_so() {
        let room = ok(&[&["--bind", "/home/me", "/home/me"]]);
        assert_eq!(
            room.steps[1..],
            [
                Step::Show {
                    source: Source {
                        entry: index_of("/home/me/.config/autostart"),
                        rel: "".into()
                    },
                    dst: "/home/me/.config/autostart".into(),
                    writable: false,
                    optional: true
                },
                Step::Mask("/home/me/.ssh".into()),
            ]
        );
        // Asking for the hidden place itself shows nothing of it.
        assert!(refused(&[&["--ro-bind", "/home/me/.ssh", "/home/me/.ssh"]]));
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
        let room = ok(&[&["--bind", "/", "/"]]);
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
        assert!(room.steps.contains(&Step::Mask("/home/me/.ssh".into())));
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
        let room = plan_room(
            &p,
            &req(&[&["--bind", "/h", "/h"]], &["x"]),
            AppFacts::default(),
        )
        .unwrap();
        assert!(matches!(room.steps[0], Step::Show { writable: true, .. }));
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
        let room = ok(&[&["--dir", "/home"], &["--bind", "/home/me", "/home/me"]]);
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
        ] {
            assert!(refused(&[op]), "{op:?}");
        }
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
}
