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
            let _ = sam_detect::signature::check(&img);
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
