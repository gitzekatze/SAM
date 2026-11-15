//! Mutation fuzzing of the parsers that read untrusted input: valid
//! AppImages, desktop files, zsync files, update information and ELF
//! programs are changed at random (flipped bytes, overwritten blocks,
//! truncation, duplicated chunks) and fed to SAM's parsers. Every input must
//! be handled without a panic, unpacking must never write outside its
//! folder, and it must stay within its time limit.
//!
//! The mutations are deterministic (a fixed seed), so a failure can be
//! repeated. CI runs a few hundred rounds; `SAM_FUZZ_ITERS=100000` runs an
//! overnight session. An input that crashes a parser is saved to
//! target/fuzz-crashes/ so it can be turned into a regression test.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sam_intake::extract::{extract, ExtractRequest};
use sam_intake::normalize::Limits;
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};

/// xorshift64: small, fast and the same on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// One random change to `data`, from byte `from` on (to keep headers that
/// the parser needs to get far, such as the ELF part of an AppImage).
fn mutate(rng: &mut Rng, data: &[u8], from: usize) -> Vec<u8> {
    let mut d = data.to_vec();
    let from = from.min(d.len().saturating_sub(1));
    let span = d.len() - from;
    match rng.below(5) {
        0 => {
            for _ in 0..1 + rng.below(8) {
                let i = from + rng.below(span);
                d[i] ^= 1 << rng.below(8);
            }
        }
        1 => {
            let i = from + rng.below(span);
            let n = 1 + rng.below(64.min(d.len() - i));
            let fill = [0x00, 0xff, 0x7f, 0x80][rng.below(4)];
            d[i..i + n].iter_mut().for_each(|b| *b = fill);
        }
        2 => {
            let cut = from + rng.below(span);
            d.truncate(cut.max(1));
        }
        3 => {
            let i = from + rng.below(span);
            let n = 1 + rng.below(256.min(d.len() - i));
            let chunk = d[i..i + n].to_vec();
            let at = from + rng.below(span);
            d.splice(at..at, chunk);
        }
        _ => {
            // A 32-bit field set to an extreme (sizes, offsets, counts).
            let i = from + rng.below(span.saturating_sub(4).max(1));
            let v: u32 = [0, 1, 0x7fff_ffff, 0xffff_ffff, 0x8000_0000][rng.below(5)];
            if i + 4 <= d.len() {
                d[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
    }
    d
}

fn iterations() -> usize {
    std::env::var("SAM_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150)
}

/// Runs `f` and saves `input` when it panics; returns whether it panicked.
fn guarded(what: &str, round: usize, input: &[u8], f: impl FnOnce()) -> Option<String> {
    let r = catch_unwind(AssertUnwindSafe(f));
    if r.is_err() {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fuzz-crashes");
        let _ = fs::create_dir_all(&dir);
        let file = dir.join(format!("{what}-{round}.bin"));
        let _ = fs::write(&file, input);
        return Some(format!(
            "{what} round {round} panicked; input saved to {}",
            file.display()
        ));
    }
    None
}

/// Every file below `dir`, for checking that unpacking stayed inside.
fn all_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p.clone());
            }
            out.push(p);
        }
    }
    out
}

/// Changed AppImages are recognized or refused, and unpacked or refused,
/// without a panic; unpacking writes only inside its own folder and keeps
/// its time limit.
#[test]
fn changed_appimages_never_crash_or_escape_the_unpacker() {
    let tmp = tempfile::tempdir().unwrap();
    let seed_img = tmp.path().join("Seed.AppImage");
    let mut spec = FixtureSpec::hello("Seed");
    spec.files.push(FixtureFile {
        path: "usr/share/seed/data.txt".into(),
        data: b"hello world ".repeat(200),
        mode: 0o644,
    });
    spec.symlinks
        .push(("usr/share/seed/link".into(), "data.txt".into()));
    build(&seed_img, &spec).unwrap();
    let seed = fs::read(&seed_img).unwrap();
    let elf_end = sam_detect::inspect(&seed_img)
        .unwrap()
        .payload_offset
        .expect("payload offset") as usize;
    let work = tmp.path().join("work");
    let mut rng = Rng(0x5A11_F022_0000_0001);
    let mut problems = Vec::new();
    // How many changed images got as far as the unpacker: a fuzzer whose
    // inputs are all refused at the first check would test nothing.
    let unpacked = std::cell::Cell::new(0usize);
    for round in 0..iterations() {
        let data = mutate(&mut rng, &seed, if round % 4 == 0 { 0 } else { elf_end });
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work).unwrap();
        let img = work.join("m.AppImage");
        fs::write(&img, &data).unwrap();
        let root = work.join("out");
        let started = Instant::now();
        if let Some(p) = guarded("appimage", round, &data, || {
            let _ = sam_intake::peek::peek(&img);
            if let Ok(info) = sam_detect::inspect(&img) {
                let limits = Limits {
                    max_files: 2000,
                    max_bytes: 64 * 1024 * 1024,
                    max_seconds: 20,
                };
                let req = ExtractRequest {
                    source: &img,
                    info: &info,
                    root: &root,
                    limits,
                    allow_fallback: false,
                    isolation: None,
                };
                unpacked.set(unpacked.get() + 1);
                let _ = extract(&req, &mut Vec::new());
            }
        }) {
            problems.push(p);
        }
        if started.elapsed() > Duration::from_secs(25) {
            problems.push(format!(
                "appimage round {round} took {:?}",
                started.elapsed()
            ));
        }
        // Nothing written next to the unpack folder except the input.
        for f in all_files(&work) {
            if f != img && !f.starts_with(&root) {
                problems.push(format!(
                    "appimage round {round} wrote {} outside the unpack folder",
                    f.display()
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        unpacked.get() * 2 > iterations(),
        "only {} of {} changed images reached the unpacker",
        unpacked.get(),
        iterations()
    );
}

/// Changed desktop files, zsync files and update information are parsed or
/// refused without a panic.
#[test]
fn changed_text_inputs_never_crash_the_parsers() {
    let desktop = b"[Desktop Entry]\nType=Application\nName=Krita\nName[de]=Krita DE\nComment=Painting\nIcon=krita\nExec=krita %F\nCategories=Graphics;2DGraphics;\nMimeType=image/png;\nStartupWMClass=krita\nX-AppImage-Version=5.2\n[Desktop Action new]\nName=New\nExec=krita --new\n".to_vec();
    let zsync = b"zsync: 0.6.2\nFilename: App-2.0-x86_64.AppImage\nMTime: Tue, 10 Nov 2026 10:00:00 +0000\nBlocksize: 2048\nLength: 4096\nHash-Lengths: 2,2,5\nURL: App-2.0-x86_64.AppImage\nSHA-1: 0123456789abcdef0123456789abcdef01234567\n\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11".to_vec();
    let updates = [
        b"zsync|https://example.org/App.AppImage.zsync".to_vec(),
        b"gh-releases-zsync|owner|repo|latest|App-*x86_64.AppImage.zsync".to_vec(),
    ];
    let mut rng = Rng(0x5A11_F022_0000_0002);
    let mut problems = Vec::new();
    for round in 0..iterations() * 4 {
        let d = mutate(&mut rng, &desktop, 0);
        let text = String::from_utf8_lossy(&d).into_owned();
        problems.extend(guarded("desktop", round, &d, || {
            let _ = sam_intake::metadata::metadata_from_desktop(&text, "x.desktop");
        }));
        let z = mutate(&mut rng, &zsync, 0);
        problems.extend(guarded("zsync", round, &z, || {
            let _ = sam_runner::zsync::parse(&z);
        }));
        let u = mutate(&mut rng, &updates[round % 2], 0);
        let us = String::from_utf8_lossy(&u).into_owned();
        problems.extend(guarded("update-info", round, &u, || {
            let _ = sam_detect::update_info::parse(&us);
        }));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Changed ELF programs inside an unpacked app are analyzed or skipped
/// without a panic.
#[test]
fn changed_programs_never_crash_the_analysis() {
    let seed = fs::read("/bin/sh").unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("AppDir");
    fs::create_dir_all(dir.join("usr/bin")).unwrap();
    fs::write(
        dir.join("AppRun"),
        "#!/bin/sh\nexec \"$APPDIR/usr/bin/app\" \"$@\"\n",
    )
    .unwrap();
    let mut rng = Rng(0x5A11_F022_0000_0003);
    let mut problems = Vec::new();
    for round in 0..iterations() {
        let d = mutate(&mut rng, &seed, if round % 2 == 0 { 0 } else { 64 });
        fs::write(dir.join("usr/bin/app"), &d).unwrap();
        problems.extend(guarded("elf", round, &d, || {
            let _ = sam_detect::analyze_appdir(&dir, &sam_detect::AnalyzeOptions::default());
        }));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
