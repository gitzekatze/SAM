//! Progress of long operations (creating a sandbox), for a progress bar.
//!
//! An operation is a list of steps, each with a share of the whole bar.
//! Steps report how far they are (0..1) and a line of detail ("1.2 GB
//! unpacked"); [`ProgressSink`] turns that into one [`Progress`] value for
//! whoever listens (the command line prints it for the window).

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

/// Where an operation stands.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Progress {
    /// 1-based number of the current step.
    pub step: usize,
    pub steps: usize,
    /// What the step does ("Unpacking").
    pub title: String,
    /// What it is doing right now ("1.2 GB unpacked"); may be empty.
    pub detail: String,
    /// The whole operation, 0..1.
    pub fraction: f64,
}

/// The steps of an operation: title and share of the whole bar.
pub type Steps = &'static [(&'static str, f64)];

/// Creating a sandbox.
pub const ADD_STEPS: Steps = &[
    (sam_core::i18n::n_("Checking the file"), 0.04),
    (sam_core::i18n::n_("Unpacking"), 0.56),
    (sam_core::i18n::n_("Reading its name and icon"), 0.02),
    (sam_core::i18n::n_("Checking what the app needs"), 0.35),
    (sam_core::i18n::n_("Creating the menu entry"), 0.03),
];

/// Receives progress; does nothing when nobody listens (the default).
#[derive(Clone, Default)]
pub struct ProgressSink(Option<Arc<Listener>>);

/// Whoever listens to a [`ProgressSink`].
pub type Listener = dyn Fn(&Progress) + Send + Sync;

impl fmt::Debug for ProgressSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() { "ProgressSink(listening)" } else { "ProgressSink(none)" })
    }
}

impl ProgressSink {
    pub fn new(f: impl Fn(&Progress) + Send + Sync + 'static) -> Self {
        ProgressSink(Some(Arc::new(f)))
    }

    /// Step `index` (0-based) of `steps` is `within` (0..1) done.
    pub fn step(&self, steps: Steps, index: usize, within: f64, detail: impl Into<String>) {
        let Some(f) = &self.0 else { return };
        let index = index.min(steps.len().saturating_sub(1));
        let before: f64 = steps[..index].iter().map(|(_, w)| w).sum();
        let total: f64 = steps.iter().map(|(_, w)| w).sum();
        let fraction = ((before + steps[index].1 * within.clamp(0.0, 1.0)) / total).clamp(0.0, 1.0);
        f(&Progress { step: index + 1, steps: steps.len(), title: sam_core::i18n::tr(steps[index].0), detail: detail.into(), fraction });
    }
}

/// Runs `work` while a thread reports every 0.7 s how many bytes the files
/// below `dir` hold (for unpacking, which happens in a separate, sandboxed
/// process).
pub fn watch_bytes<T>(dir: &Path, on_bytes: impl Fn(u64) + Send + 'static, work: impl FnOnce() -> T) -> T {
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let dir = dir.to_path_buf();
    let watcher = std::thread::spawn(move || {
        while !s.load(Ordering::SeqCst) {
            on_bytes(bytes_below(&dir));
            for _ in 0..7 {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });
    let out = work();
    stop.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    out
}

/// The sizes of the regular files below `dir` (links not followed; files
/// that vanish meanwhile are skipped).
fn bytes_below(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(e.path()),
                Ok(t) if t.is_file() => total += e.metadata().map(|m| m.len()).unwrap_or(0),
                _ => {}
            }
        }
    }
    total
}

/// "1.2 GB", "340 MB", "12 KB".
pub fn size(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1e9 {
        format!("{:.1} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.0} MB", b / 1e6)
    } else {
        format!("{:.0} KB", b / 1e3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The progress bar follows the weights of the steps of creating a sandbox.
    #[test]
    fn fractions_follow_the_step_weights() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let sink = ProgressSink::new(move |p| s.lock().unwrap().push(p.clone()));
        sink.step(ADD_STEPS, 0, 0.0, "");
        sink.step(ADD_STEPS, 1, 0.5, "1.2 GB unpacked");
        sink.step(ADD_STEPS, 4, 1.0, "");
        sink.step(ADD_STEPS, 9, 2.0, "");
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].fraction, 0.0);
        assert!((seen[1].fraction - (0.04 + 0.28)).abs() < 1e-9);
        assert_eq!((seen[1].step, seen[1].steps, seen[1].title.as_str()), (2, 5, "Unpacking"));
        assert!((seen[2].fraction - 1.0).abs() < 1e-9);
        assert!((seen[3].fraction - 1.0).abs() < 1e-9, "out-of-range input is clamped");
        ProgressSink::default().step(ADD_STEPS, 1, 0.5, "nobody listens");
    }

    /// Unpacking progress counts the bytes written.
    #[test]
    fn bytes_written_are_counted() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        std::fs::write(d.path().join("a/b/f"), vec![0u8; 3000]).unwrap();
        std::fs::write(d.path().join("g"), vec![0u8; 500]).unwrap();
        std::os::unix::fs::symlink("/usr", d.path().join("link")).unwrap();
        assert_eq!(bytes_below(d.path()), 3500);
        let seen = Arc::new(Mutex::new(0u64));
        let s = seen.clone();
        let out = watch_bytes(
            d.path(),
            move |b| *s.lock().unwrap() = b,
            || {
                std::thread::sleep(Duration::from_millis(150));
                7
            },
        );
        assert_eq!(out, 7);
        assert_eq!(*seen.lock().unwrap(), 3500);
        assert_eq!(size(2_700_000_000), "2.7 GB");
        assert_eq!(size(340_000_000), "340 MB");
    }
}
