//! Fuzz tests aimed at what the audit found the first ones missed: they
//! changed bytes at random, so the parts that matter were rarely hit, and a
//! guard in the preview hid the reader's panics. Here each target changes
//! the part its reader looks at:
//! - the ELF section table and the signature, key and update sections of an
//!   AppImage (inspect, signature check, update information);
//! - zsync control files, through parsing, planning and assembling;
//! - desktop files with a byte order mark and Windows line ends;
//! - the preview reader without its guard: a panic in SAM's code fails, a
//!   panic inside the SquashFS library is counted (the guard and the
//!   preview sandbox handle those).
//!
//! The terminal filter has its own model-based fuzz test
//! (sam-core/tests/terminal_fuzz.rs).
//!
//! `SAM_FUZZ_ITERS` sets the rounds per target (default 200), `SAM_FUZZ_SEED`
//! changes the seed.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::Mutex;

use sam_intake::testkit::{build, FixtureSpec};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn rounds() -> usize {
    std::env::var("SAM_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
}

fn rng(base: u64) -> Rng {
    let extra: u64 = std::env::var("SAM_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    Rng(match base ^ extra {
        0 => base,
        m => m,
    })
}

/// Where the last panic happened (file:line), by a panic hook: tells a
/// panic in SAM's code from one inside a library.
static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

fn watch_panics() {
    let shown = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        shown(info);
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        *LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()) = Some(at);
    }));
}

/// Runs `f`; on a panic, where it happened.
fn panicked(f: impl FnOnce()) -> Option<String> {
    *LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()) = None;
    catch_unwind(AssertUnwindSafe(f)).err().map(|_| {
        LAST_PANIC
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| "unknown place".into())
    })
}

fn u16_at(d: &[u8], i: usize) -> usize {
    u16::from_le_bytes([d[i], d[i + 1]]) as usize
}
fn u64_at(d: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(d[i..i + 8].try_into().unwrap())
}

/// The section headers of a 64-bit little-endian ELF file: (offset of the
/// header entry, name, sh_offset, sh_size).
fn sections(d: &[u8]) -> Vec<(usize, String, u64, u64)> {
    let shoff = u64_at(d, 0x28) as usize;
    let (entsize, num, strndx) = (u16_at(d, 0x3A), u16_at(d, 0x3C), u16_at(d, 0x3E));
    let entry = |i: usize| shoff + i * entsize;
    let strtab = u64_at(d, entry(strndx) + 0x18) as usize;
    (0..num)
        .map(|i| {
            let e = entry(i);
            let name_at = strtab + u32::from_le_bytes(d[e..e + 4].try_into().unwrap()) as usize;
            let end = d[name_at..].iter().position(|b| *b == 0).unwrap_or(0);
            let name = String::from_utf8_lossy(&d[name_at..name_at + end]).into_owned();
            (e, name, u64_at(d, e + 0x18), u64_at(d, e + 0x20))
        })
        .collect()
}

/// Changed ELF section tables and signature, key and update sections are
/// read or refused without a panic: inspect, the signature check and the
/// update information. Most changes must reach the sections themselves.
#[test]
fn changed_signature_and_update_sections_never_crash_the_readers() {
    watch_panics();
    let tmp = tempfile::tempdir().unwrap();
    let seed_img = tmp.path().join("Seed.AppImage");
    // Update information and empty signature sections, as appimagetool
    // leaves them (the test kit adds them with objcopy).
    let mut spec = FixtureSpec::hello("Seed");
    spec.update_info = Some("zsync|https://example.org/Seed.AppImage.zsync".into());
    spec.signature_sections = true;
    build(&seed_img, &spec).unwrap();
    let seed = fs::read(&seed_img).unwrap();
    let secs = sections(&seed);
    let wanted: Vec<_> = secs
        .iter()
        .filter(|s| [".sha256_sig", ".sig_key", ".upd_info"].contains(&s.1.as_str()))
        .cloned()
        .collect();
    assert_eq!(
        wanted.len(),
        3,
        "the fixture's runtime has the three sections: {secs:?}"
    );
    let mut r = rng(0x5161_0001);
    let mut problems = Vec::new();
    let mut reached = 0;
    let img = tmp.path().join("m.AppImage");
    let extremes = [
        0u64,
        1,
        0x7fff_ffff,
        0xffff_ffff,
        u64::MAX,
        seed.len() as u64,
        seed.len() as u64 - 1,
    ];
    for round in 0..rounds() {
        let mut d = seed.clone();
        let (entry, _, off, size) = wanted[r.below(wanted.len())].clone();
        match r.below(4) {
            // The section's place or size in the table.
            0 => {
                let field = entry + if r.below(2) == 0 { 0x18 } else { 0x20 };
                d[field..field + 8]
                    .copy_from_slice(&extremes[r.below(extremes.len())].to_le_bytes());
            }
            // Its contents: text a reader parses, or bytes.
            1 | 2 => {
                let texts: [&[u8]; 5] = [
                    b"gh-releases-zsync|owner|repo|latest|App-*.zsync",
                    b"zsync|https://example.org/a.zsync",
                    b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ",
                    b"-----BEGIN PGP SIGNATURE-----\n\niQ",
                    b"|||||",
                ];
                let mut body = texts[r.below(texts.len())].to_vec();
                for _ in 0..r.below(64) {
                    body.push((r.next() & 0xff) as u8);
                }
                let room = (size as usize).min(body.len());
                d[off as usize..off as usize + room].copy_from_slice(&body[..room]);
                if r.below(3) == 0 {
                    // Full to the last byte: no ending zero.
                    let end = off as usize + size as usize;
                    d[off as usize..end].iter_mut().for_each(|b| *b = b'A');
                }
            }
            // The table itself: where it is and how many entries.
            _ => {
                let (at, v) = match r.below(3) {
                    0 => (0x28, extremes[r.below(extremes.len())]),
                    1 => (0x3C, [0u64, 1, 0xffff][r.below(3)]),
                    _ => (0x3E, [0u64, 0xfffe, 0xffff][r.below(3)]),
                };
                let n = if at == 0x28 { 8 } else { 2 };
                d[at..at + n].copy_from_slice(&v.to_le_bytes()[..n]);
            }
        }
        fs::write(&img, &d).unwrap();
        let r_cut = r.below(80);
        if let Some(at) = panicked(|| {
            if let Ok(info) = sam_detect::inspect(&img) {
                reached += 1;
                let _ = info.payload_offset;
            }
            let _ = sam_detect::appimage::elf_end_offset(&d[..d.len().min(4096)]);
            // A header cut anywhere, also before its first fields.
            let _ = sam_detect::appimage::elf_end_offset(&d[..r_cut.min(d.len())]);
            let _ = sam_detect::update_info::read(&img);
            let _ = sam_detect::signature::check(&img, &sam_detect::signature::GnuPg::Direct);
        }) {
            let saved = tmp.path().join(format!("crash-{round}.AppImage"));
            let _ = fs::copy(&img, &saved);
            problems.push(format!("round {round}: panic at {at}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        reached * 2 > rounds(),
        "only {reached} of {} changed images were read at all",
        rounds()
    );
}

/// Changed zsync control files are refused, or planned and assembled
/// within their limits, without a panic: the parser, the block plan, the
/// missing ranges and the assembly all see them.
#[test]
fn changed_zsync_controls_never_crash_planning_or_assembly() {
    watch_panics();
    let tmp = tempfile::tempdir().unwrap();
    let mut data = Vec::new();
    for i in 0..9000u32 {
        data.extend(i.to_le_bytes());
    }
    let file = tmp.path().join("App.AppImage");
    fs::write(&file, &data).unwrap();
    let control = sam_runner::zsync::make(
        &file,
        "App.AppImage",
        "App.AppImage",
        "Tue, 10 Nov 2026 10:00:00 +0000",
    )
    .unwrap();
    let header_end = control.windows(2).position(|w| w == b"\n\n").unwrap() + 2;
    let mut r = rng(0x25c0_0002);
    let (mut problems, mut planned) = (Vec::new(), 0);
    let dest = tmp.path().join("new");
    for round in 0..rounds() {
        let mut c = control.clone();
        match r.below(3) {
            // A header value: sizes, counts and lengths at their edges.
            0 => {
                let fields = ["Blocksize", "Length", "Hash-Lengths"];
                let field = fields[r.below(fields.len())];
                let values = [
                    "0",
                    "1",
                    "3",
                    "4294967295",
                    "18446744073709551615",
                    "-1",
                    "2048",
                    "1,1,1",
                    "2,2,16",
                    "9,9,9",
                    "",
                ];
                let text = String::from_utf8_lossy(&c[..header_end]).into_owned();
                let new: String = text
                    .lines()
                    .map(|l| {
                        if l.starts_with(&format!("{field}:")) {
                            format!("{field}: {}", values[r.below(values.len())])
                        } else {
                            l.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n\n";
                c.splice(..header_end, new.into_bytes());
            }
            // The block table: changed, cut short or longer.
            1 => {
                let span = c.len() - header_end;
                for _ in 0..1 + r.below(16) {
                    let i = header_end + r.below(span);
                    c[i] ^= 1 << r.below(8);
                }
                if r.below(2) == 0 {
                    c.truncate(header_end + r.below(span));
                }
            }
            _ => {
                let extra: Vec<u8> = (0..r.below(512)).map(|_| (r.next() & 0xff) as u8).collect();
                c.extend(extra);
            }
        }
        if let Some(at) = panicked(|| {
            if let Ok(ctl) = sam_runner::zsync::parse(&c) {
                // An old file that shares some blocks, or none.
                let old = if r.below(2) == 0 {
                    data.clone()
                } else {
                    data[..data.len() / 2].to_vec()
                };
                let plan =
                    sam_runner::zsync::plan_within(&ctl, &old, std::time::Duration::from_secs(2));
                planned += 1;
                let ranges = sam_runner::zsync::missing_ranges(&ctl, &plan, 4096);
                if ctl.length <= 1024 * 1024 {
                    let _ =
                        sam_runner::zsync::assemble(&ctl, &old, &plan, &ranges, &dest, |s, e| {
                            Ok(data
                                .get(s as usize..(e as usize).min(data.len()))
                                .unwrap_or_default()
                                .to_vec())
                        });
                }
            }
        }) {
            let saved = tmp.path().join(format!("crash-{round}.zsync"));
            let _ = fs::write(&saved, &c);
            problems.push(format!("round {round}: panic at {at}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        planned * 4 > rounds(),
        "only {planned} of {} changed controls reached the planner",
        rounds()
    );
}

/// Desktop files with a byte order mark, Windows line ends, odd sections
/// and broken text are read without a panic, and the byte order mark and
/// line ends do not hide the name.
#[test]
fn changed_desktop_files_never_crash_the_reader() {
    watch_panics();
    let base = "[Desktop Entry]\nType=Application\nName=Seed\nName[de]=Saat\nExec=seed %F\nIcon=seed\nCategories=Graphics;\nMimeType=image/png;\n[Desktop Action new]\nName=New\n";
    for (text, why) in [
        (format!("\u{feff}{base}"), "byte order mark"),
        (base.replace('\n', "\r\n"), "Windows line ends"),
        (format!("\u{feff}{}", base.replace('\n', "\r\n")), "both"),
    ] {
        let md = sam_intake::metadata::metadata_from_desktop(&text, "seed.desktop");
        assert_eq!(md.name, "Seed", "{why}: {md:?}");
        assert_eq!(md.icon_name, "seed", "{why}");
    }
    let mut r = rng(0xde5c_0003);
    let mut problems = Vec::new();
    let pieces = [
        "\u{feff}",
        "\r\n",
        "\r",
        "\n",
        "[",
        "]",
        "=",
        "[Desktop Entry]",
        "Name=",
        "Name[",
        "Exec=",
        "%",
        "\\",
        ";",
        "\u{0}",
        "\u{202e}",
        "é",
        " ",
    ];
    for round in 0..rounds() {
        let mut t = base.to_string();
        for _ in 0..1 + r.below(12) {
            let at = r.below(t.len() + 1);
            let at = (0..=at).rev().find(|i| t.is_char_boundary(*i)).unwrap_or(0);
            t.insert_str(at, pieces[r.below(pieces.len())]);
        }
        if let Some(at) = panicked(|| {
            let _ = sam_intake::metadata::parse_desktop(&t);
            let _ = sam_intake::metadata::metadata_from_desktop(&t, "x.desktop");
        }) {
            problems.push(format!("round {round}: panic at {at}: {t:?}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The preview reader without its guard: a changed image must not make
/// SAM's own code panic. Panics inside the SquashFS library are counted
/// and reported, not failed: the guard and the preview sandbox stop them,
/// and the library's maintainers are the ones to fix them.
#[test]
fn the_preview_reader_panics_only_inside_the_squashfs_library() {
    watch_panics();
    let tmp = tempfile::tempdir().unwrap();
    let seed_img = tmp.path().join("Seed.AppImage");
    build(&seed_img, &FixtureSpec::hello("Seed")).unwrap();
    let seed = fs::read(&seed_img).unwrap();
    let start = sam_detect::inspect(&seed_img)
        .unwrap()
        .payload_offset
        .unwrap() as usize;
    let mut r = rng(0x9ee6_0004);
    let (mut ours, mut library, mut read) = (Vec::new(), 0, 0);
    let img = tmp.path().join("m.AppImage");
    for round in 0..rounds() {
        let mut d = seed.clone();
        for _ in 0..1 + r.below(6) {
            let i = start + r.below(d.len() - start);
            d[i] ^= 1 << r.below(8);
        }
        fs::write(&img, &d).unwrap();
        match panicked(|| {
            if sam_intake::peek::peek_unguarded(&img).is_ok() {
                read += 1;
            }
        }) {
            Some(at) if at.contains("/backhand") => library += 1,
            Some(at) => {
                let _ = fs::copy(&img, tmp.path().join(format!("crash-{round}.AppImage")));
                ours.push(format!("round {round}: panic at {at}"));
            }
            None => {}
        }
    }
    eprintln!(
        "preview fuzz: {read} read, {library} panics inside the SquashFS library, {} in SAM",
        ours.len()
    );
    assert!(ours.is_empty(), "{}", ours.join("\n"));
    let _ = Path::new("");
}

/// Room service's readers: changed messages and changed Bubblewrap argument
/// lists never crash the service's reader, the stand-in's reader or the
/// rules, and whatever the rules accept stays within them (every place a
/// plain absolute path, shown at the same place, from beneath a folder of
/// the app's floor plan).
#[test]
fn changed_room_requests_never_crash_the_readers() {
    use sam_runner::room_rules::{plan_room, read_bwrap_args, read_request, AppFacts, FloorPlan};
    watch_panics();
    let words = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    let plan = FloorPlan::from_bwrap_args(&words(&[
        "--ro-bind",
        "/usr/lib",
        "/usr/lib",
        "--ro-bind-try",
        "/usr/bin",
        "/usr/bin",
        "--symlink",
        "usr/lib",
        "/lib64",
        "--bind",
        "/data/w",
        "/w",
        // Read-only, with a hidden place inside and a place covered later.
        "--ro-bind",
        "/data/share",
        "/share",
        "--tmpfs",
        "/share/hidden",
        "--ro-bind",
        "/data/x",
        "/share/x",
        "--tmpfs",
        "/share/x",
        "--bind",
        "/data/homes/app",
        "/home/me",
        "--ro-bind",
        "/data/homes/app/.config/autostart",
        "/home/me/.config/autostart",
        "--dev",
        "/dev",
        "--dev-bind-try",
        "/dev/dri",
        "/dev/dri",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/home/me/.ssh",
        "--ro-bind",
        "/data/sam/apps",
        "/data/sam/apps",
        "--tmpfs",
        "/data/sam",
        "--bind",
        "/run/l1/rooms",
        "/run/sam/rooms",
    ]))
    .unwrap();
    let base = r#"{"v":1,"ops":[["--ro-bind","/usr","/usr"],["--bind","/home/me","/home/me"],["--tmpfs","/tmp-home"],["--perms","0700"],["--dir","/d"],["--setenv","HOME","/tmp-home"],["--seccomp","11"],["--share-net"],["--chmod","0755","/tmp-home"]],"flags":[],"command":["/usr/lib/glycin-loaders/2+/glycin-svg"],"env":{"A":"b"},"cwd":"/home/me","fds":[0,1,2,11]}"#;
    let pieces: [&[u8]; 22] = [
        b"\"",
        b"[",
        b"]",
        b"{",
        b"}",
        b",",
        b":",
        b"\\",
        b"\\u0000",
        b"..",
        b"/",
        b"//",
        b"--bind",
        b"--chmod",
        b"--ro-bind-try",
        b"--dev-bind",
        b"-1",
        b"99999999999",
        b"\xff",
        b"null",
        b"\"/\"",
        b"/home/me/../..",
    ];
    let mut r = rng(0x200f_0001);
    let mut problems = Vec::new();
    for round in 0..rounds() {
        let mut d = base.as_bytes().to_vec();
        for _ in 0..1 + r.below(8) {
            let at = r.below(d.len() + 1);
            match r.below(3) {
                0 => {
                    let p = pieces[r.below(pieces.len())];
                    d.splice(at..at, p.iter().copied());
                }
                1 if at < d.len() => {
                    d.remove(at);
                }
                _ if at < d.len() => d[at] = (r.below(256)) as u8,
                _ => {}
            }
        }
        let full_network = r.below(2) == 0;
        let text = String::from_utf8_lossy(&d).into_owned();
        let argv: Vec<String> = text
            .split([' ', '"', ','])
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect();
        if let Some(at) = panicked(|| {
            let _ = read_bwrap_args(&argv);
            let Ok(req) = read_request(&d) else { return };
            let Ok(room) = plan_room(&plan, &req, AppFacts { full_network }) else {
                return;
            };
            if let Err(e) = room_within_plan(&plan, &room, full_network) {
                panic!("{e}");
            }
        }) {
            problems.push(format!("round {round}: {at}: {text:?}"));
        }
    }
    // Well-formed requests built from every option with tricky values: the
    // rules decide them all without a crash and within themselves.
    // Each option with its usual number of values (sometimes another), and
    // mostly the same path twice, as a same-place request is.
    let names: [(&str, usize); 36] = [
        ("--bind", 2),
        ("--bind-try", 2),
        ("--ro-bind", 2),
        ("--ro-bind-try", 2),
        ("--dev-bind", 2),
        ("--dev-bind-try", 2),
        ("--symlink", 2),
        ("--tmpfs", 1),
        ("--dir", 1),
        ("--dev", 1),
        ("--proc", 1),
        ("--mqueue", 1),
        ("--perms", 1),
        ("--size", 1),
        ("--chmod", 2),
        ("--setenv", 2),
        ("--unsetenv", 1),
        ("--chdir", 1),
        ("--hostname", 1),
        ("--seccomp", 1),
        ("--add-seccomp-fd", 1),
        ("--share-net", 0),
        ("--unshare-net", 0),
        ("--unshare-all", 0),
        ("--clearenv", 0),
        ("--remount-ro", 1),
        ("--as-pid-1", 0),
        ("--cap-drop", 1),
        ("--die-with-parent", 0),
        ("--bind-fd", 2),
        ("--userns", 1),
        ("--file", 2),
        ("--cap-add", 1),
        ("--overlay", 3),
        ("--args", 1),
        ("--made-up", 0),
    ];
    let values = [
        "/",
        "/usr",
        "/usr/lib",
        "/usr/lib/x86_64",
        "/home/me",
        "/home/me/.config",
        "/home/me/.config/autostart",
        "/dev",
        "/dev/dri",
        "/dev/null",
        "/dev/input",
        "/tmp",
        "/tmp-home",
        "/run/sam/rooms",
        "/run/sam",
        "/proc",
        "/secret",
        "/usr/../etc",
        "usr",
        "//",
        "/home/me/",
        "11",
        "3",
        "-1",
        "0700",
        "0777",
        "99999",
        "x",
        "",
    ];
    let real = [
        "/usr",
        "/usr/lib",
        "/usr/bin",
        "/home/me",
        "/home/me/.config/autostart",
        "/dev/dri",
        "/dev/null",
        "/tmp",
        "/w",
        "/w/sub",
        "/share",
        "/share/hidden",
        "/share/x",
    ];
    // How often the rules got as far as each kind of step: the control that
    // the generated requests reach them at all.
    let (shown, devices) = (std::cell::Cell::new(0usize), std::cell::Cell::new(0usize));
    // Rooms with a writable place: the control that the "nothing inside a
    // writable place" invariant sees any.
    let writable_rooms = std::cell::Cell::new(0usize);
    // Rooms that rebuilt a hiding mount below a shown place: the control
    // that "hidden stays hidden" is ever checked.
    let hiding_rooms = std::cell::Cell::new(0usize);
    for round in 0..rounds() * 5 {
        let mut ops: Vec<Vec<String>> = Vec::new();
        for _ in 0..1 + r.below(4) {
            let (name, arity) = names[r.below(names.len())];
            let n = if r.below(10) == 0 { r.below(4) } else { arity };
            // Half the time a place of the app's: the rules decide whole
            // rooms often enough, not only the first broken value.
            let first = if r.below(2) == 0 {
                real[r.below(real.len())]
            } else {
                values[r.below(values.len())]
            };
            let mut op = vec![name.to_string()];
            for k in 0..n {
                let same = k == 0 || (k == 1 && r.below(4) != 0);
                op.push(
                    if same {
                        first
                    } else {
                        values[r.below(values.len())]
                    }
                    .to_string(),
                );
            }
            ops.push(op);
        }
        let req = sam_runner::room_rules::Request {
            v: sam_runner::room_rules::VERSION,
            ops,
            flags: vec![],
            command: vec!["/usr/bin/true".into()],
            env: Default::default(),
            cwd: values[r.below(values.len())].to_string(),
            fds: vec![0, 1, 2, 11],
            limits: vec![],
            umask: None,
        };
        let full_network = r.below(2) == 0;
        let text = format!("{:?}", req.ops);
        if let Some(at) = panicked(|| {
            let Ok(room) = plan_room(&plan, &req, AppFacts { full_network }) else {
                return;
            };
            if room.steps.iter().any(|st| {
                matches!(
                    st,
                    sam_runner::room_rules::Step::Show { writable: true, .. }
                )
            }) {
                writable_rooms.set(writable_rooms.get() + 1);
            }
            let shown_at: Vec<&std::path::Path> = room
                .steps
                .iter()
                .filter_map(|st| match st {
                    sam_runner::room_rules::Step::Show { dst, .. } => Some(dst.as_path()),
                    _ => None,
                })
                .collect();
            if room.steps.iter().any(|st| match st {
                sam_runner::room_rules::Step::Mask(at) => {
                    shown_at.iter().any(|d| at.starts_with(d) && at != *d)
                }
                _ => false,
            }) {
                hiding_rooms.set(hiding_rooms.get() + 1);
            }
            for step in &room.steps {
                match step {
                    sam_runner::room_rules::Step::Show { .. } => shown.set(shown.get() + 1),
                    sam_runner::room_rules::Step::Device { .. } => devices.set(devices.get() + 1),
                    _ => {}
                }
            }
            if let Err(e) = room_within_plan(&plan, &room, full_network) {
                panic!("{e}");
            }
        }) {
            problems.push(format!("built round {round}: {at}: {text}"));
        }
    }
    assert!(
        shown.get() > rounds() / 10 && devices.get() > rounds() / 100,
        "the generated requests hardly reach the rules: {} places, {} devices",
        shown.get(),
        devices.get()
    );
    assert!(
        writable_rooms.get() > 0,
        "no generated room had a writable place, so its invariant was never checked"
    );
    assert!(
        hiding_rooms.get() > 0,
        "no generated room rebuilt a hiding mount, so \"hidden stays hidden\" was never checked"
    );
    // A remount inside a writable place is no place of its own: the rules
    // accept it, and so does the invariant.
    let req = sam_runner::room_rules::Request {
        v: sam_runner::room_rules::VERSION,
        ops: vec![
            vec!["--bind".into(), "/w".into(), "/w".into()],
            vec!["--remount-ro".into(), "/w/sub".into()],
        ],
        flags: vec![],
        command: vec!["/usr/bin/true".into()],
        env: Default::default(),
        cwd: "/".into(),
        fds: vec![],
        limits: vec![],
        umask: None,
    };
    let room = plan_room(&plan, &req, AppFacts::default()).unwrap();
    room_within_plan(&plan, &room, false).unwrap();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// What every room the rules decide keeps to, whatever was asked: each
/// place comes from a floor-plan source, at the same place as in the app,
/// writable only where the app's is, and not under a mount the app laid
/// over it later (hidden stays hidden); devices only the app's, at their
/// place; nothing shown through raw arguments; never Room service's socket
/// or SAM's own place; nothing inside a place the app can write; the
/// network only with the app's full network.
fn room_within_plan(
    plan: &sam_runner::room_rules::FloorPlan,
    room: &sam_runner::room_rules::RoomPlan,
    full_network: bool,
) -> Result<(), String> {
    use sam_runner::room_rules::{is_clean_absolute, Entry, Source, Step, RESERVED};
    use std::path::Path;
    for step in &room.steps {
        match step {
            Step::Show {
                source: Source { entry, rel },
                dst,
                writable,
                ..
            } => {
                let e = plan
                    .entries
                    .get(*entry)
                    .ok_or("a source outside the floor plan")?;
                if e.source().is_none() {
                    return Err(format!("{dst:?} from an entry without a source: {e:?}"));
                }
                if *dst != e.at().join(rel) || !is_clean_absolute(&dst.to_string_lossy()) {
                    return Err(format!("{dst:?} not at its place ({e:?} + {rel:?})"));
                }
                if *writable && !matches!(e, Entry::Rw { .. }) {
                    return Err(format!("{dst:?} writable from a read-only place"));
                }
                let hidden_later = plan.entries.iter().skip(entry + 1).any(|m| {
                    !matches!(m, Entry::Link { .. } | Entry::Dir { .. }) && dst.starts_with(m.at())
                });
                if hidden_later {
                    return Err(format!("{dst:?} is hidden in the app by a later mount"));
                }
                if dst == Path::new("/run/sam/rooms") || dst.starts_with(RESERVED) {
                    return Err(format!("{dst:?} is Room service's own"));
                }
            }
            Step::Device { src, dst, .. } => {
                if !src.starts_with("/dev") || src.starts_with("/dev/input") || src != dst {
                    return Err(format!("a device {src:?} at {dst:?}"));
                }
            }
            Step::Mask(_) => {}
            Step::Args(a) => {
                let bad = [
                    "--bind-fd",
                    "--ro-bind-fd",
                    "--userns",
                    "--file",
                    "--cap-add",
                    "--overlay",
                    "--args",
                    "--made-up",
                    "--info-fd",
                    "--json-status-fd",
                    "--sync-fd",
                    "--block-fd",
                    "--userns-block-fd",
                    "--userns2",
                    "--pidns",
                    "--bind-data",
                    "--bind",
                    "--ro-bind",
                    "--dev-bind",
                    "--bind-try",
                    "--ro-bind-try",
                    "--dev-bind-try",
                ];
                if bad.contains(&a[0].as_str()) {
                    return Err(format!("passed on as it is: {a:?}"));
                }
                if a.iter().skip(1).any(|v| Path::new(v).starts_with(RESERVED)) {
                    return Err(format!("SAM's own place in {a:?}"));
                }
            }
        }
    }
    // Hidden stays hidden: every hiding mount of the app below a place the
    // room shows (and mounted after that place's source) is in the room
    // too, after it.
    for (k, step) in room.steps.iter().enumerate() {
        if let Step::Show {
            source: Source { entry, .. },
            dst,
            ..
        } = step
        {
            for (i, m) in plan.entries.iter().enumerate().skip(entry + 1) {
                if let Entry::Mask { at } = m {
                    let later_cover = plan.entries.iter().skip(i + 1).any(|l| {
                        !matches!(l, Entry::Link { .. } | Entry::Dir { .. })
                            && at.starts_with(l.at())
                    });
                    if at.starts_with(dst)
                        && at != dst
                        && !later_cover
                        && !room.steps[k + 1..].contains(&Step::Mask(at.clone()))
                    {
                        return Err(format!(
                            "{at:?} is hidden in the app but not in the room shown at {dst:?}"
                        ));
                    }
                }
            }
        }
    }
    // A place the app can write is shown only as a whole: nothing of the
    // room (a place, a device, a hiding mount, a thing of its own) lies
    // below it, in any order.
    let writable: Vec<&Path> = room
        .steps
        .iter()
        .filter_map(|s| match s {
            Step::Show {
                source: Source { entry, .. },
                dst,
                ..
            } if matches!(plan.entries.get(*entry), Some(Entry::Rw { .. })) => Some(dst.as_path()),
            _ => None,
        })
        .collect();
    for step in &room.steps {
        let places: Vec<&Path> = match step {
            Step::Show { dst, .. } | Step::Device { dst, .. } => vec![dst.as_path()],
            Step::Mask(at) => vec![at.as_path()],
            // Only what makes or changes a place counts (a link's target is
            // only text; --remount-ro only takes rights away).
            Step::Args(a) => match a[0].as_str() {
                "--tmpfs" | "--dir" | "--proc" | "--dev" | "--mqueue" => {
                    a.get(1).map(Path::new).into_iter().collect()
                }
                "--symlink" | "--chmod" => a.get(2).map(Path::new).into_iter().collect(),
                _ => Vec::new(),
            },
        };
        for p in places {
            if let Some(w) = writable.iter().find(|w| p.starts_with(w) && p != **w) {
                return Err(format!(
                    "{p:?} lies inside {w:?}, a place the app can write"
                ));
            }
        }
    }
    if room.share_net && !full_network {
        return Err("the network without the app's full network".into());
    }
    Ok(())
}
