//! `sam-room-exec`: SAM's room helper, the first program in every room of
//! Room service (see `room_service.rs`).
//!
//! It is built statically (no loader, no libraries) and uses Rust's
//! standard library only, because it starts inside a file layout the
//! room's request shapes: nothing of that layout may run or be read before
//! SAM's layers are in place. It reads the room's rules from SAM's own
//! place (`/.sam-room/room.spec`), then, in this order:
//! 0. checks that every place of the app the room shows is exactly what
//!    SAM opened or checked (device and inode), reached without links and
//!    still the root of the mount Bubblewrap made there, whatever
//!    Bubblewrap did;
//! 1. Landlock: read everywhere, write only where the rules say; abstract
//!    sockets outside the room blocked (kernels with Landlock 6 and newer);
//! 2. SAM's syscall filter (compiled by SAM, passed as a connection);
//! 3. reports what is in place on the status connection, closes it;
//! 4. the program's own syscall filters (passed connections);
//! 5. starts the program with exactly the environment it asked for,
//!    finding it as Bubblewrap's execvp does.
//!
//! Any step that fails ends the room (exit 127) before the program starts.
//! On a kernel without Landlock the room has what the app has, and the
//! report says so.
//!
//!   sam-room-exec SPEC -- PROGRAM ARGS…
//!
//! SPEC holds `key=value` entries separated by NUL bytes: `status=N`,
//! `seccomp=N`, `filter=N` (any number), `read=PATH`, `write=PATH`,
//! `env=NAME=VALUE`, `place=DEV:INO:PATH` (any number of each).
//!
//! The place check and the opener without links are SAM's one copy in
//! sam-core (`place_check.rs`), included here as a file of this program:
//! it uses the standard library only, as this program must.

// No Rust start-up code: it would read /proc/self/maps (to find the main
// thread's stack), a file of the room's layout, before SAM's layers. The
// static C library's own start-up still asks once where this program lies
// (readlink of /proc/self/exe, for $ORIGIN); the answer is never used here
// and gives no right: nothing else of the layout is read before the layers.
#![no_main]

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::raw::{c_int, c_long, c_ulong};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// The helper uses the check and the opener without links; the rest of
// the file serves SAM's other parts.
#[allow(dead_code)]
#[path = "../../sam-core/src/place_check.rs"]
mod place_check;

extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> c_int;
    fn execve(
        path: *const std::os::raw::c_char,
        argv: *const *const std::os::raw::c_char,
        envp: *const *const std::os::raw::c_char,
    ) -> c_int;
}

#[cfg(target_arch = "x86_64")]
const SYS_SECCOMP: c_long = 317;
#[cfg(target_arch = "aarch64")]
const SYS_SECCOMP: c_long = 277;
const SYS_LANDLOCK_CREATE_RULESET: c_long = 444;
const SYS_LANDLOCK_ADD_RULE: c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: c_long = 446;

const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_SET_SECCOMP: c_int = 22;
const SECCOMP_MODE_FILTER: c_ulong = 2;

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

/// Reads a classic BPF syscall filter from a connection.
fn read_filter(fd: c_int) -> Vec<u8> {
    let prog = read_fd(fd, 4096 * 8);
    if prog.is_empty() || prog.len() % 8 != 0 {
        fail("a passed syscall filter is not valid");
    }
    prog
}

#[repr(C)]
struct Fprog {
    len: u16,
    filter: *const u8,
}

fn fprog(prog: &[u8]) -> Fprog {
    Fprog { len: (prog.len() / 8) as u16, filter: prog.as_ptr() }
}

/// Loads SAM's syscall filter from a connection (no_new_privs first).
fn load_filter(fd: c_int) {
    let prog = read_filter(fd);
    let p = fprog(&prog);
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
            let Ok(f) = place_check::open_no_link(Path::new(OsStr::from_bytes(p))).map(File::from) else {
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

fn number(v: &[u8]) -> c_int {
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| fail("the room's rules are not valid"))
}

/// Where to look for the program, in order, as glibc's execvp does with
/// the environment the program asked for: a name with `/` as it is;
/// otherwise each PATH entry (an empty one is the current folder), and
/// "/bin:/usr/bin" when there is no PATH. Never the bare name otherwise.
fn candidates(name: &OsStr, env: &[(&OsStr, &OsStr)]) -> Vec<Vec<u8>> {
    let bytes = name.as_bytes();
    if bytes.contains(&b'/') {
        return vec![bytes.to_vec()];
    }
    let path = env
        .iter()
        .rev()
        .find(|(k, _)| k.as_bytes() == b"PATH")
        .map_or(&b"/bin:/usr/bin"[..], |(_, v)| v.as_bytes());
    path.split(|b| *b == b':')
        .map(|dir| {
            if dir.is_empty() {
                return bytes.to_vec();
            }
            let mut full = dir.to_vec();
            if !full.ends_with(b"/") {
                full.push(b'/');
            }
            full.extend_from_slice(bytes);
            full
        })
        .collect()
}

/// A place `DEV:INO:PATH` of the room: where it is, and the device and
/// inode of the file, folder or device SAM opened or checked for it.
fn parse_place(entry: &[u8]) -> (&Path, place_check::Expect) {
    let mut parts = entry.splitn(3, |b| *b == b':');
    let (Some(dev), Some(ino), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
        fail("the room's rules are not valid");
    };
    let num = |v: &[u8]| -> u64 {
        std::str::from_utf8(v)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| fail("the room's rules are not valid"))
    };
    let (dev, ino) = (num(dev), num(ino));
    (Path::new(OsStr::from_bytes(path)), place_check::Expect::MountOf { dev, ino })
}

/// Errors after which execvp tries the next PATH entry.
fn try_next(e: c_int) -> bool {
    const ENOENT: c_int = 2;
    const EACCES: c_int = 13;
    const ENODEV: c_int = 19;
    const ENOTDIR: c_int = 20;
    const ETIMEDOUT: c_int = 110;
    const ESTALE: c_int = 116;
    matches!(e, ENOENT | EACCES | ENODEV | ENOTDIR | ETIMEDOUT | ESTALE)
}

#[no_mangle]
pub extern "C" fn main(_argc: c_int, _argv: *const *const std::os::raw::c_char) -> c_int {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let sep = args.iter().position(|a| a == "--").unwrap_or_else(|| fail("usage: sam-room-exec SPEC -- PROGRAM ARGS"));
    if sep != 2 || sep + 1 >= args.len() {
        fail("usage: sam-room-exec SPEC -- PROGRAM ARGS");
    }
    let spec = std::fs::read(&args[1]).unwrap_or_else(|e| fail(&format!("reading the room's rules: {e}")));
    let (mut status, mut seccomp) = (None, None);
    let (mut filters, mut reads, mut writes, mut env) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut places: Vec<&[u8]> = Vec::new();
    for entry in spec.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let at = entry.iter().position(|b| *b == b'=').unwrap_or_else(|| fail("the room's rules are not valid"));
        let (key, value) = (&entry[..at], &entry[at + 1..]);
        match key {
            b"status" if status.is_none() => status = Some(number(value)),
            b"seccomp" if seccomp.is_none() => seccomp = Some(number(value)),
            b"filter" => filters.push(number(value)),
            b"read" => reads.push(value),
            b"write" => writes.push(value),
            b"place" => places.push(value),
            b"env" => {
                let eq = value.iter().position(|b| *b == b'=').unwrap_or_else(|| fail("the room's rules are not valid"));
                env.push((OsStr::from_bytes(&value[..eq]), OsStr::from_bytes(&value[eq + 1..])));
            }
            _ => fail("the room's rules hold an unknown or doubled entry"),
        }
    }
    let status = status.unwrap_or_else(|| fail("the room's rules name no status connection"));
    let seccomp = seccomp.unwrap_or_else(|| fail("the room's rules carry no syscall filter"));
    // Every place SAM showed is exactly what SAM opened, reached without
    // links, and the root of the mount Bubblewrap made there: an older
    // Bubblewrap mounts a handle's path by name, which the app could swap
    // while the room was built, and a program outside the room that can
    // write a place's folder could move the mount away and put the same
    // file back at its name. Checked before anything else.
    for place in &places {
        let (at, expect) = parse_place(place);
        if let Err(why) = place_check::check(at, &expect) {
            fail(&format!(
                "{} is not the place SAM checked for this room ({why})",
                at.to_string_lossy()
            ));
        }
    }
    // SAM's layers first.
    let mut report = landlock(&reads, &writes);
    load_filter(seccomp);
    report.push_str(", seccomp");
    // Everything the program's start needs, prepared now: under its own
    // filter only the start itself (execve, as in Bubblewrap's execvp)
    // follows. Each place to try, with the shell's arguments for a script
    // without "#!" (as execvp runs it).
    let shell = CString::new("/bin/sh").unwrap_or_else(|_| fail("no shell"));
    let tries: Vec<(CString, Vec<CString>)> = candidates(&args[3], &env)
        .into_iter()
        .map(|c| {
            let path = CString::new(c).unwrap_or_else(|_| fail("the program's name is not valid"));
            let mut sh = vec![shell.clone(), path.clone()];
            sh.extend(args[4..].iter().map(|a| CString::new(a.as_bytes()).unwrap_or_else(|_| fail("an argument is not valid"))));
            (path, sh)
        })
        .collect();
    let argv: Vec<CString> = args[3..]
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap_or_else(|_| fail("an argument is not valid")))
        .collect();
    let envp: Vec<CString> = env
        .iter()
        .map(|(k, v)| {
            let mut e = k.as_bytes().to_vec();
            e.push(b'=');
            e.extend_from_slice(v.as_bytes());
            CString::new(e).unwrap_or_else(|_| fail("a variable is not valid"))
        })
        .collect();
    let mut argv_ptrs: Vec<*const std::os::raw::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const std::os::raw::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());
    // The program's own filters, read now and only loaded right before it
    // starts (as Bubblewrap does: one prctl each, then the start). Not in
    // the report: that names only what is in place when it is written.
    let programs: Vec<Vec<u8>> = filters.iter().map(|fd| read_filter(*fd)).collect();
    let progs: Vec<Fprog> = programs.iter().map(|p| fprog(p)).collect();
    let sh_ptrs: Vec<Vec<*const std::os::raw::c_char>> = tries
        .iter()
        .map(|(_, sh)| sh.iter().map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect())
        .collect();
    report.push('\n');
    // Report what SAM put in place, and close the connection, before the
    // program's own filter (which may refuse the calls this needs).
    // SAFETY: the status connection was passed for exactly this; it is
    // written to and closed here, before the program starts.
    let mut f = unsafe { File::from_raw_fd(status) };
    let _ = f.write_all(report.as_bytes());
    drop(f);
    for p in &progs {
        // SAFETY: a filter that lives until the call returns; no_new_privs
        // is set already (SAM's filter).
        if unsafe { prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, p as *const Fprog as c_ulong, 0, 0) } != 0 {
            fail(&format!("loading the program's syscall filter: {}", errno()));
        }
    }
    let mut denied = false;
    for ((path, _), sh) in tries.iter().zip(&sh_ptrs) {
        // SAFETY: NUL-terminated strings and arrays that live until the call.
        unsafe { execve(path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
        let mut e = errno().raw_os_error().unwrap_or(0);
        if e == 8 {
            // ENOEXEC: a script without "#!", run by the shell; when the
            // shell cannot start, glibc's execvp goes on as for any other
            // failed place, and so does this.
            // SAFETY: as above.
            unsafe { execve(shell.as_ptr(), sh.as_ptr(), envp_ptrs.as_ptr()) };
            e = errno().raw_os_error().unwrap_or(0);
        }
        if !try_next(e) {
            fail(&format!("{}: {}", args[3].to_string_lossy(), errno()));
        }
        denied |= e == 13;
    }
    let why = if denied { "Permission denied" } else { "No such file or directory" };
    fail(&format!("execvp {}: {why}", args[3].to_string_lossy()));
}
