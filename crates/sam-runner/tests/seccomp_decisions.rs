//! What the syscall filter decides, recorded once and compared on every run
//! (a characterization test). The filter program built on this processor is
//! run here, by a small interpreter of the kernel's filter language, under
//! each of the 16 filter settings, for calls named as x86_64, i386, aarch64
//! and 32-bit ARM calls. It asks about call numbers 0 to 1023, the same
//! numbers with the x32 bit set, and four extreme numbers. Where the
//! program reads an argument, each argument in turn takes each value of a
//! fixed list (every socket family up to 47, the terminal requests, the
//! user-namespace flag, values with a high half, the extremes) while the
//! others stay 0; combinations of arguments are not tried. The answers are
//! written as text and compared with `seccomp_decisions/<processor>.txt`,
//! one record per processor SAM builds for: a change within these calls,
//! arguments and settings in what the filter refuses, or with which error,
//! shows up as a difference there, however the program is put together.
//!
//! A deliberate change to the filter changes the record too: the test then
//! writes what it found to the target folder's `tmp/` and names the file;
//! review the difference, then copy it over the record.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sam_runner::kernel::{filter_bytes, SeccompSpec};

/// The architectures a call can name in `seccomp_data.arch`: the two SAM
/// filters for, the 32-bit x86 one, and 32-bit ARM as one more stranger.
const ARCHES: [(&str, u32); 4] = [
    ("x86_64", 0xC000_003E),
    ("i386", 0x4000_0003),
    ("aarch64", 0xC000_00B7),
    ("arm", 0x4000_0028),
];

/// The x32 bit of a call number.
const X32: u32 = 0x4000_0000;

/// One instruction of a classic BPF program, as `bwrap --seccomp` reads it.
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

fn decode(bytes: &[u8]) -> Vec<Insn> {
    assert!(bytes.len().is_multiple_of(8), "whole instructions");
    bytes
        .chunks(8)
        .map(|c| Insn {
            code: u16::from_ne_bytes([c[0], c[1]]),
            jt: c[2],
            jf: c[3],
            k: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
        })
        .collect()
}

/// What the kernel hands the filter for one call (`struct seccomp_data`).
struct Call {
    nr: u32,
    arch: u32,
    args: [u64; 6],
}

/// The 32-bit word at `offset` of `seccomp_data` (little endian, as on
/// x86_64 and aarch64), and whether it is part of an argument.
fn word(c: &Call, offset: u32) -> (u32, bool) {
    assert!(offset.is_multiple_of(4), "aligned load at {offset}");
    match offset {
        0 => (c.nr, false),
        4 => (c.arch, false),
        8 | 12 => (0, false), // the instruction pointer
        16..=60 => {
            let a = c.args[((offset - 16) / 8) as usize];
            let half = if (offset - 16).is_multiple_of(8) {
                a
            } else {
                a >> 32
            };
            (half as u32, true)
        }
        _ => panic!("load past seccomp_data at {offset}"),
    }
}

/// Runs the program as the kernel does: the answer, and whether it read an
/// argument on the way. A program that reads no argument for a call takes
/// the same path whatever the arguments are.
fn run(prog: &[Insn], c: &Call) -> (u32, bool) {
    assert!(
        prog.len() <= 4096,
        "the kernel takes at most 4096 instructions"
    );
    let (mut a, mut pc, mut read_arg) = (0u32, 0usize, false);
    loop {
        let i = prog.get(pc).expect("a jump inside the program");
        pc += 1;
        match i.code {
            0x20 => {
                // BPF_LD | BPF_W | BPF_ABS
                let (w, arg) = word(c, i.k);
                a = w;
                read_arg |= arg;
            }
            0x54 => a &= i.k,           // BPF_ALU | BPF_AND | BPF_K
            0x05 => pc += i.k as usize, // BPF_JMP | BPF_JA
            0x15 | 0x25 | 0x35 | 0x45 => {
                let hit = match i.code {
                    0x15 => a == i.k,  // JEQ
                    0x25 => a > i.k,   // JGT
                    0x35 => a >= i.k,  // JGE
                    _ => a & i.k != 0, // JSET
                };
                pc += usize::from(if hit { i.jt } else { i.jf });
            }
            0x06 => return (i.k, read_arg), // BPF_RET | BPF_K
            code => panic!("instruction {code:#06x} at {}", pc - 1),
        }
    }
}

/// An answer in words.
fn answer(ret: u32) -> String {
    match ret {
        0x7FFF_0000 => "ALLOW".into(),
        0x8000_0000 => "KILL_PROCESS".into(),
        r if r & 0xFFFF_0000 == 0x0005_0000 => match (r & 0xFFFF) as i32 {
            libc::EPERM => "EPERM".into(),
            libc::ENOSYS => "ENOSYS".into(),
            libc::EAFNOSUPPORT => "EAFNOSUPPORT".into(),
            e => format!("ERRNO({e})"),
        },
        r => format!("RET({r:#x})"),
    }
}

/// Argument values that touch every check the filter has: every socket
/// family number, the terminal requests (also with a high half the kernel
/// drops), the user-namespace flag (in the low and in the high half) and
/// the extremes.
fn arg_values() -> Vec<u64> {
    let mut v: Vec<u64> = (0..=47).collect(); // socket families
    v.extend([
        0x5412,             // TIOCSTI
        0x541C,             // TIOCLINUX
        0x5413,             // TIOCGWINSZ, a neighbour
        (1 << 32) | 0x5412, // TIOCSTI with a high half
        (1 << 32) | 0x541C, // TIOCLINUX with a high half
        (1 << 32) | 17,     // AF_PACKET with a high half
        (1 << 32) | 1,      // AF_UNIX with a high half
        1 << 32,            // a high half alone
        0x1000_0000,        // CLONE_NEWUSER
        0x1001_0000,        // CLONE_NEWUSER | CLONE_THREAD
        0x1000_0000 << 32,  // CLONE_NEWUSER in the high half
        0xEFFF_FFFF,        // every flag but CLONE_NEWUSER
        0xFFFF_FFFF,
        u64::MAX,
    ]);
    v
}

/// The answers for one call number: one answer when no argument matters,
/// else the answer with all arguments 0 and each argument value that
/// changes it.
fn decide(prog: &[Insn], arch: u32, nr: u32, values: &[u64]) -> String {
    let base = Call {
        nr,
        arch,
        args: [0; 6],
    };
    let (ret, read_arg) = run(prog, &base);
    let mut out = answer(ret);
    if !read_arg {
        return out;
    }
    for idx in 0..6 {
        for &v in values {
            let mut args = [0u64; 6];
            args[idx] = v;
            let (r, _) = run(prog, &Call { nr, arch, args });
            if r != ret {
                write!(out, " arg{idx}={v:#x}:{}", answer(r)).unwrap();
            }
        }
    }
    out
}

/// A call number as people read it: small ones in decimal.
fn number(nr: u32) -> String {
    if nr < 0x1000 {
        nr.to_string()
    } else {
        format!("{nr:#x}")
    }
}

/// Every refusal of one program for one architecture, consecutive numbers
/// with the same answer as one range. Numbers not named are allowed.
fn record_arch(prog: &[Insn], arch: u32, out: &mut String) {
    let values = arg_values();
    let mut nrs: Vec<u32> = (0..1024).collect();
    nrs.extend((0..1024).map(|n| X32 | n));
    nrs.extend([0x7FFF_FFFF, 0x8000_0000, 0xBFFF_FFFF, 0xFFFF_FFFF]);
    let mut runs: Vec<(u32, u32, String)> = Vec::new();
    for nr in nrs {
        let d = decide(prog, arch, nr, &values);
        if d == "ALLOW" {
            continue;
        }
        match runs.last_mut() {
            Some((_, last, prev)) if *prev == d && last.checked_add(1) == Some(nr) => *last = nr,
            _ => runs.push((nr, nr, d)),
        }
    }
    for (first, last, d) in runs {
        if first == last {
            writeln!(out, "{} {d}", number(first)).unwrap();
        } else {
            writeln!(out, "{}-{} {d}", number(first), number(last)).unwrap();
        }
    }
}

/// The 16 filter settings, by name. A new field of `SeccompSpec` breaks
/// this struct literal, so whoever adds one extends the settings here.
fn settings() -> BTreeMap<String, SeccompSpec> {
    let mut settings = BTreeMap::new();
    for bits in 0..16u8 {
        let spec = SeccompSpec {
            strict: bits & 1 != 0,
            allow_userns: bits & 2 != 0,
            bluetooth: bits & 4 != 0,
            i386: bits & 8 != 0,
        };
        let name = format!(
            "strict={} nested={} bluetooth={} i386={}",
            spec.strict, spec.allow_userns, spec.bluetooth, spec.i386
        );
        settings.insert(name, spec);
    }
    settings
}

/// The whole record: every filter setting, every architecture.
fn record() -> String {
    let mut out = String::from(
        "# What SAM's syscall filter answers, per filter setting and per\n\
         # architecture of the call (crates/sam-runner/tests/seccomp_decisions.rs).\n\
         # One line per call number or range that is not allowed; `argN=V:X`\n\
         # means the answer is X when argument N is V (all others 0).\n",
    );
    for (name, spec) in &settings() {
        let prog = decode(&filter_bytes(spec).unwrap());
        writeln!(out, "\n## {name}").unwrap();
        for (arch_name, arch) in ARCHES {
            writeln!(out, "# calls of {arch_name} ({arch:#x})").unwrap();
            record_arch(&prog, arch, &mut out);
        }
    }
    out
}

fn fixture(arch: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/seccomp_decisions")
        .join(format!("{arch}.txt"))
}

/// The filter built on this processor answers as recorded for it, under all
/// 16 settings: for call numbers 0 to 1023 of x86_64, i386, aarch64 and
/// 32-bit ARM, the same numbers with the x32 bit set and four extreme
/// numbers, each argument the filter reads varied alone over a fixed list
/// of values. A change to how the filter is written cannot change these
/// answers unnoticed. On x86_64 and aarch64, the processors SAM builds for,
/// a missing record is a failure.
#[test]
fn the_filter_decides_every_call_as_recorded() {
    let arch = std::env::consts::ARCH;
    let path = fixture(arch);
    let got = record();
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("seccomp_decisions-{arch}.txt"));
    let Ok(want) = std::fs::read_to_string(&path) else {
        // Each processor has its own numbers, so its record is made on it,
        // from the code before a change to the filter.
        std::fs::write(&out, &got).unwrap();
        let reason = format!(
            "no recorded filter decisions for {arch} ({}); this run's are in {}",
            path.display(),
            out.display()
        );
        // SAM builds for these two: without a record nothing is compared.
        assert!(!matches!(arch, "x86_64" | "aarch64"), "{reason}");
        sam_runner::contracts::not_here(&reason);
        return;
    };
    if got != want {
        std::fs::write(&out, &got).unwrap();
        let first = got
            .lines()
            .zip(want.lines())
            .position(|(g, w)| g != w)
            .unwrap_or(got.lines().count().min(want.lines().count()));
        panic!(
            "the filter decides differently from {}: first difference at line {} \
             (now {:?}, recorded {:?}); what it decides now is in {}",
            path.display(),
            first + 1,
            got.lines().nth(first),
            want.lines().nth(first),
            out.display()
        );
    }
}

/// The app page's and the sandbox check's socket note for 32-bit apps
/// (`SeccompSpec::socketcall_unlimited`, review R72) says what the built
/// filter does: under each of the 16 settings, the note appears exactly
/// where the program allows a 32-bit x86 socketcall (number 102) that opens
/// a socket (`SYS_SOCKET`, 1, in argument 0). A later filter that refuses
/// that call while the note still claims the gap, or the reverse, fails
/// here. On a processor without the filter's 32-bit part such a call ends
/// the process and the note is never shown.
#[test]
fn the_socket_note_matches_the_filters_answer_to_32_bit_socketcall() {
    for (name, spec) in &settings() {
        let prog = decode(&filter_bytes(spec).unwrap());
        let call = Call {
            nr: 102,
            arch: ARCHES[1].1,
            args: [1, 0, 0, 0, 0, 0],
        };
        let got = answer(run(&prog, &call).0);
        assert_eq!(
            spec.socketcall_unlimited(),
            got == "ALLOW",
            "the app page's socket note says the 32-bit socket limit is {} under {name}, \
             but the filter answers {got} to a 32-bit socketcall",
            if spec.socketcall_unlimited() {
                "incomplete"
            } else {
                "complete or not there"
            }
        );
    }
}
