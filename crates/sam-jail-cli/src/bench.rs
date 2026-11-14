//! `sam-jail dev bench`: how long the parts of SAM take on a realistic test
//! AppImage, for the version report. Every measurement is repeated and the
//! median is reported, so one slow run does not distort the number. All
//! files go to a fresh folder under $TMPDIR, which is removed afterwards.

use super::*;
use std::fs;
use std::path::Path;
use std::time::Instant;

use sam_intake::testkit::{build, FixtureFile, FixtureSpec};

#[derive(Serialize)]
pub(crate) struct Measure {
    /// Short key, stable across versions ("unpack").
    key: &'static str,
    /// What was measured, in a complete sentence.
    what: &'static str,
    /// Median in milliseconds; None when the measurement could not run here.
    median_ms: Option<f64>,
    runs: usize,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Runs `f` `runs` times and returns the median in milliseconds.
fn time(runs: usize, mut f: impl FnMut() -> Result<()>) -> Result<f64> {
    let mut v = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t = Instant::now();
        f()?;
        v.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(median(v))
}

pub(crate) fn bench(apps: usize) -> Result<Vec<Measure>> {
    let dir = std::env::temp_dir().join(format!("sam-bench-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let r = run(&dir, apps);
    let _ = fs::remove_dir_all(&dir);
    r
}

fn run(dir: &Path, apps: usize) -> Result<Vec<Measure>> {
    let mut out = Vec::new();
    let mut m = |key, what, runs, ms: Option<f64>| out.push(Measure { key, what, median_ms: ms, runs });

    // A realistic AppImage: 2,000 files of 8 KB and a real program to analyze.
    let img = dir.join("Bench-1.0-x86_64.AppImage");
    let mut spec = FixtureSpec::hello("Bench");
    spec.host_binary = Some("/bin/sh".into());
    for i in 0..2000 {
        spec.files.push(FixtureFile { path: format!("usr/share/bench/{}/f{i}.dat", i % 40), data: vec![(i % 251) as u8; 8192], mode: 0o644 });
    }
    build(&img, &spec)?;

    let info = sam_detect::inspect(&img)?;
    m("detect", "Recognizing the AppImage format of a file (reading its headers).", 9, Some(time(9, || sam_detect::inspect(&img).map(|_| ()))?));

    let mut n = 0;
    let unpack = time(3, || {
        n += 1;
        let root = dir.join(format!("unpack-{n}"));
        let req = sam_intake::extract::ExtractRequest {
            source: &img,
            info: &info,
            root: &root,
            limits: sam_intake::normalize::Limits::default(),
            allow_fallback: false,
            isolation: None,
        };
        sam_intake::extract::extract(&req, &mut Vec::new())?;
        Ok(())
    })?;
    m("unpack", "Unpacking an AppImage with 2,000 files (16 MB) safely, without running it.", 3, Some(unpack));

    let appdir = dir.join("unpack-1/AppDir");
    let opts = sam_detect::AnalyzeOptions::default();
    m(
        "analyze",
        "Analyzing the unpacked app: its programs, libraries and toolkit.",
        5,
        Some(time(5, || sam_detect::analyze_appdir(&appdir, &opts).map(|_| ()))?),
    );

    let report = sam_detect::analyze_appdir(&appdir, &opts)?;
    let md = sam_core::AppImageMetadata { name: "Bench".into(), categories: vec!["Graphics".into()], ..Default::default() };
    m(
        "recommend",
        "Recommending permissions from the app's metadata and analysis.",
        50,
        Some(time(50, || {
            sam_profile::recommend(&md, "Bench.AppImage", Some(&report));
            Ok(())
        })?),
    );

    let ctx = sam_core::sandbox::sample_context();
    m(
        "sandbox-command",
        "Building the Bubblewrap command from a set of permissions.",
        50,
        Some(time(50, || sam_runner::bwrap::build_command(&ctx).map(|_| ()))?),
    );

    // Creating a sandbox end to end, each time in a fresh SAM folder.
    let mut k = 0;
    let add = time(3, || {
        k += 1;
        let sam = Sam::with_paths(Paths::rooted(&dir.join(format!("sam-{k}"))))?;
        sam.add(&img, &sam_runner::ops::AddOptions { accept: true, launcher: Some(false), ..Default::default() })?;
        Ok(())
    })?;
    m("add", "Creating a sandbox for that AppImage end to end (unpack, analyze, recommend, save).", 3, Some(add));

    // A real start: an app that exits at once, inside a real sandbox.
    let sam = Sam::with_paths(Paths::rooted(&dir.join("sam-start")))?;
    let quick = dir.join("Quick.AppImage");
    build(&quick, &FixtureSpec { apprun: "#!/bin/sh\nexit 0\n".into(), ..FixtureSpec::hello("Quick") })?;
    let id = sam.add(&quick, &sam_runner::ops::AddOptions { accept: true, launcher: Some(false), ..Default::default() })?.entry.id;
    let host = sam.host();
    let start = if sam_runner::bwrap::check(&host).is_ok() {
        Some(time(5, || {
            let mut e = sam.resolve(&id)?;
            sam_runner::launch::run(&mut e, &sam_runner::launch::LaunchOptions::default(), &sam.config, &sam.paths, &host).map(|_| ())
        })?)
    } else {
        None
    };
    m("start", "Starting an app in a real sandbox until it has exited (an app that exits at once).", 5, start);

    // The Permissions page's data with many apps.
    let many = Sam::with_paths(Paths::rooted(&dir.join("sam-many")))?;
    for i in 0..apps {
        let p = dir.join(format!("App{i}.AppImage"));
        build(&p, &FixtureSpec::hello(&format!("App{i}")))?;
        many.add(&p, &sam_runner::ops::AddOptions { accept: true, launcher: Some(false), ..Default::default() })?;
    }
    let what: &'static str = Box::leak(format!("Listing {apps} sandboxed apps with their tags for the Permissions page.").into_boxed_str());
    m("overview", what, 5, Some(time(5, || many.permission_overview().map(|_| ()))?));
    Ok(out)
}
