//! `sam-room-exec`: SAM's room helper, the first program in every room of
//! Room service (see `room_service.rs`).
//!
//! It is built statically (no loader, no libraries) and uses Rust's
//! standard library only, because it starts inside a file layout the
//! room's request shapes: nothing of that layout may run or be read before
//! SAM's layers are in place. It reads the room's rules from SAM's own
//! place (`/.sam-room/room.spec`), then, in this order:
//! 1. Landlock: read everywhere, write only where the rules say; abstract
//!    sockets outside the room blocked (kernels with Landlock 6 and newer);
//! 2. SAM's syscall filter (compiled by SAM, passed as a connection);
//! 3. the program's own syscall filters (passed connections);
//! 4. reports what is in place on the status connection, closes it;
//! 5. starts the program with exactly the environment it asked for.
//!
//! Any step that fails ends the room (exit 127) before the program starts.
//! On a kernel without Landlock the room has what the app has, and the
//! report says so.
//!
//!   sam-room-exec SPEC -- PROGRAM ARGS…
//!
//! SPEC holds `key=value` entries separated by NUL bytes: `status=N`,
//! `seccomp=N`, `filter=N` (any number), `read=PATH`, `write=PATH`,
//! `env=NAME=VALUE` (any number of each).

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::raw::{c_int, c_long, c_ulong};
use std::os::unix::ffi::OsStrExt;

extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> c_int;
}

#[cfg(target_arch = "x86_64")]
const SYS_SECCOMP: c_long = 317;
#[cfg(target_arch = "aarch64")]
const SYS_SECCOMP: c_long = 277;
const SYS_LANDLOCK_CREATE_RULESET: c_long = 444;
const SYS_LANDLOCK_ADD_RULE: c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: c_long = 446;

const PR_SET_NO_NEW_PRIVS: c_int = 38;
const O_PATH: c_int = 0o10000000;
const O_CLOEXEC: c_int = 0o2000000;

// Landlock's file rights, as SAM's app sandbox uses them (version 3).
const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REFER: u64 = 1 << 13; // Landlock 2
const TRUNCATE: u64 = 1 << 14; // Landlock 3
const ALL_V1: u64 = (1 << 13) - 1;
const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1; // Landlock 6

fn fail(msg: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "sam-room-exec: {msg}");
    std::process::exit(127);
}

fn errno() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// Reads a whole connection (at most `limit` bytes) and closes it.
fn read_fd(fd: c_int, limit: usize) -> Vec<u8> {
    // SAFETY: the connection was passed to the room for exactly this; it is
    // owned (and closed) here.
    let f = unsafe { File::from_raw_fd(fd) };
    let mut out = Vec::new();
    if f.take(limit as u64 + 1).read_to_end(&mut out).is_err() || out.len() > limit {
        fail("a passed syscall filter cannot be read");
    }
    out
}

/// Loads a classic BPF syscall filter from a connection.
fn load_filter(fd: c_int) {
    let prog = read_fd(fd, 4096 * 8);
    if prog.is_empty() || prog.len() % 8 != 0 {
        fail("a passed syscall filter is not valid");
    }
    #[repr(C)]
    struct Fprog {
        len: u16,
        filter: *const u8,
    }
    let p = Fprog { len: (prog.len() / 8) as u16, filter: prog.as_ptr() };
    // SAFETY: prctl and seccomp with a filter that lives until they return.
    unsafe {
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail(&format!("no_new_privs: {}", errno()));
        }
        if syscall(SYS_SECCOMP, 1 as c_long, 0 as c_long, &p as *const Fprog) != 0 {
            fail(&format!("loading a syscall filter: {}", errno()));
        }
    }
}

/// Landlock as in SAM's app sandbox. Returns what the report says.
fn landlock(read_paths: &[&[u8]], write_paths: &[&[u8]]) -> String {
    // SAFETY: asking for the version passes no memory.
    let abi = unsafe {
        syscall(SYS_LANDLOCK_CREATE_RULESET, std::ptr::null::<u8>(), 0usize, 1u32)
    };
    if abi < 1 {
        return "landlock not available on this kernel".into();
    }
    let mut all = ALL_V1;
    if abi >= 2 {
        all |= REFER;
    }
    if abi >= 3 {
        all |= TRUNCATE;
    }
    #[repr(C)]
    struct Attr {
        fs: u64,
        net: u64,
        scoped: u64,
    }
    let attr = Attr {
        fs: all,
        net: 0,
        scoped: if abi >= 6 { SCOPE_ABSTRACT_UNIX_SOCKET } else { 0 },
    };
    let size = if abi >= 6 { 24 } else if abi >= 4 { 16 } else { 8 };
    // SAFETY: a ruleset attribute struct of the size given.
    let ruleset = unsafe {
        syscall(SYS_LANDLOCK_CREATE_RULESET, &attr as *const Attr, size as usize, 0u32)
    } as c_int;
    if ruleset < 0 {
        fail(&format!("Landlock ruleset: {}", errno()));
    }
    let read_rights = (EXECUTE | READ_FILE | READ_DIR) & all;
    for (paths, rights) in [(read_paths, read_rights), (write_paths, all)] {
        for p in paths {
            // Never through a link: the request lays out the room, and a
            // link would turn a rule onto another place.
            let Some(f) = open_no_links(p) else {
                continue; // not in this room, or behind a link
            };
            let fd = f.as_raw_fd();
            let is_dir = f.metadata().is_ok_and(|m| m.is_dir());
            #[repr(C, packed)]
            struct Beneath {
                allowed: u64,
                parent_fd: i32,
            }
            let rule = Beneath {
                allowed: if is_dir { rights } else { rights & FILE_RIGHTS },
                parent_fd: fd,
            };
            // SAFETY: a path-beneath rule for an open descriptor.
            let r = unsafe { syscall(SYS_LANDLOCK_ADD_RULE, ruleset, 1 as c_int, &rule as *const Beneath, 0u32) };
            drop(f);
            if r != 0 {
                fail(&format!("Landlock rule for {}: {}", String::from_utf8_lossy(p), errno()));
            }
        }
    }
    // SAFETY: plain integer arguments.
    unsafe {
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail(&format!("no_new_privs: {}", errno()));
        }
        if syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0u32) != 0 {
            fail(&format!("Landlock: {}", errno()));
        }
        drop(File::from_raw_fd(ruleset));
    }
    format!("landlock {abi}")
}

const SYS_OPENAT2: c_long = 437;
const AT_FDCWD: c_int = -100;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// A path opened (O_PATH) without following any link in it.
fn open_no_links(path: &[u8]) -> Option<File> {
    let c = std::ffi::CString::new(path).ok()?;
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = How { flags: (O_PATH | O_CLOEXEC) as u64, mode: 0, resolve: RESOLVE_NO_SYMLINKS };
    // SAFETY: openat2 with a valid C string and a struct of the size given.
    let fd = unsafe {
        syscall(SYS_OPENAT2, AT_FDCWD, c.as_ptr(), &how as *const How, std::mem::size_of::<How>())
    } as c_int;
    // SAFETY: a new descriptor of our own.
    (fd >= 0).then(|| unsafe { File::from_raw_fd(fd) })
}

fn number(v: &[u8]) -> c_int {
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| fail("the room's rules are not valid"))
}

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let sep = args.iter().position(|a| a == "--").unwrap_or_else(|| fail("usage: sam-room-exec SPEC -- PROGRAM ARGS"));
    if sep != 2 || sep + 1 >= args.len() {
        fail("usage: sam-room-exec SPEC -- PROGRAM ARGS");
    }
    let spec = std::fs::read(&args[1]).unwrap_or_else(|e| fail(&format!("reading the room's rules: {e}")));
    let (mut status, mut seccomp) = (None, None);
    let (mut filters, mut reads, mut writes, mut env) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for entry in spec.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let at = entry.iter().position(|b| *b == b'=').unwrap_or_else(|| fail("the room's rules are not valid"));
        let (key, value) = (&entry[..at], &entry[at + 1..]);
        match key {
            b"status" => status = Some(number(value)),
            b"seccomp" => seccomp = Some(number(value)),
            b"filter" => filters.push(number(value)),
            b"read" => reads.push(value),
            b"write" => writes.push(value),
            b"env" => {
                let eq = value.iter().position(|b| *b == b'=').unwrap_or_else(|| fail("the room's rules are not valid"));
                env.push((OsStr::from_bytes(&value[..eq]), OsStr::from_bytes(&value[eq + 1..])));
            }
            _ => fail("the room's rules hold an unknown entry"),
        }
    }
    let status = status.unwrap_or_else(|| fail("the room's rules name no status connection"));
    let seccomp = seccomp.unwrap_or_else(|| fail("the room's rules carry no syscall filter"));
    // SAM's layers first, then the program's own filters.
    let mut report = landlock(&reads, &writes);
    load_filter(seccomp);
    report.push_str(", seccomp");
    for fd in &filters {
        load_filter(*fd);
    }
    if !filters.is_empty() {
        report.push_str(", the program's own filter");
    }
    report.push('\n');
    // SAFETY: the status connection was passed for exactly this; it is
    // written to and closed here, before the program starts.
    let mut f = unsafe { File::from_raw_fd(status) };
    let _ = f.write_all(report.as_bytes());
    drop(f);
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(&args[3])
        .args(&args[4..])
        .env_clear()
        .envs(env)
        .exec();
    fail(&format!("{}: {err}", args[3].to_string_lossy()));
}
