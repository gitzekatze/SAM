//! One lock per app between starting it and changing its sandbox.
//!
//! Steps that change an app's sandbox (unpack again, update, go back, free
//! space, remove) hold it exclusively from their running-check to their
//! end; a start holds it shared from before its checks until it ends, and
//! reads the app's record again once it has it. So a start never runs
//! with a record or an unpacked copy that a change replaced after the
//! start was checked (review L2: an "unpack again" that swapped in changed
//! content while a start was preparing skipped the "look at it first"
//! gate), and a change never begins under a start.
//!
//! The lock is a file beside the apps' runtime folders, `.<id>.lock`, never
//! inside one: removing a sandbox deletes the app's runtime folder, and a
//! lock on a deleted file no longer meets the lock on a new one.
//!
//! SAM's own update has one lock of its own ([`for_self_update`]), so two
//! updates of SAM never run at once.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sam_core::Paths;

/// How long a change waits for a start that is ending, or still in its
/// checks, before it gives up. A start never waits.
pub const CHANGE_WAIT: Duration = Duration::from_secs(2);

thread_local! {
    /// Apps this thread holds for a change, and how often: a change that
    /// is a step of another (an update unpacks again) takes it once more.
    static CHANGING: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
}

/// The lock file of app `id`.
pub fn path(paths: &Paths, id: &str) -> PathBuf {
    paths.runtime_dir(id).with_file_name(format!(".{id}.lock"))
}

fn open(paths: &Paths, id: &str) -> Result<fs::File> {
    let p = path(paths, id);
    if let Some(dir) = p.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)
        .with_context(|| format!("opening {}", p.display()))
}

/// Takes `how` on `f`: Ok(true) when taken, Ok(false) when another holds
/// it still after `wait`.
fn take(f: &fs::File, how: i32, wait: Duration) -> Result<bool> {
    let until = Instant::now() + wait;
    loop {
        // SAFETY: `f` is an open file; flock only takes its descriptor.
        if unsafe { libc::flock(f.as_raw_fd(), how | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                if Instant::now() < until =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            std::io::ErrorKind::WouldBlock => return Ok(false),
            _ => return Err(err).context("locking the app"),
        }
    }
}

/// A start of an app, held until dropped.
#[derive(Debug)]
pub struct StartLock {
    _file: fs::File,
}

/// Holds app `id` for a start, without waiting. None while its sandbox is
/// being changed.
pub fn for_start(paths: &Paths, id: &str) -> Result<Option<StartLock>> {
    let f = open(paths, id)?;
    Ok(take(&f, libc::LOCK_SH, Duration::ZERO)?.then_some(StartLock { _file: f }))
}

/// A change of an app's sandbox, held until dropped.
#[derive(Debug)]
pub struct ChangeLock {
    id: String,
    /// The lock file; None for a change inside another of the same app.
    _file: Option<fs::File>,
    /// Released on the thread that took it: the count of nested changes
    /// is that thread's (not `Send`).
    _here: std::marker::PhantomData<*const ()>,
}

impl Drop for ChangeLock {
    fn drop(&mut self) {
        CHANGING.with(|c| {
            let mut c = c.borrow_mut();
            if let Some(n) = c.get_mut(&self.id) {
                *n -= 1;
                if *n == 0 {
                    c.remove(&self.id);
                }
            }
        });
    }
}

/// Holds app `id` for a change of its sandbox, waiting at most
/// [`CHANGE_WAIT`]. None while it is starting, running or being changed
/// elsewhere.
pub fn for_change(paths: &Paths, id: &str) -> Result<Option<ChangeLock>> {
    for_change_within(paths, id, CHANGE_WAIT)
}

/// [`for_change`], waiting at most `wait`.
pub fn for_change_within(paths: &Paths, id: &str, wait: Duration) -> Result<Option<ChangeLock>> {
    let nested = CHANGING.with(|c| c.borrow().contains_key(id));
    let file = if nested {
        None
    } else {
        let f = open(paths, id)?;
        if !take(&f, libc::LOCK_EX, wait)? {
            return Ok(None);
        }
        Some(f)
    };
    CHANGING.with(|c| *c.borrow_mut().entry(id.to_string()).or_insert(0) += 1);
    Ok(Some(ChangeLock {
        id: id.to_string(),
        _file: file,
        _here: std::marker::PhantomData,
    }))
}

/// SAM's own update, held until dropped.
#[derive(Debug)]
pub struct SelfUpdateLock {
    _file: fs::File,
}

/// The lock file of SAM's own update: in SAM's data folder, never inside
/// `downloads/` or `update-backups/`, which the update empties (a lock on a
/// deleted file no longer meets the lock on a new one).
pub fn self_update_path(paths: &Paths) -> PathBuf {
    paths.data_dir.join(".self-update.lock")
}

/// Holds SAM's own update, without waiting. None while another update of
/// SAM runs (from the window or the command line): both would share
/// `downloads/sam` and `update-backups/sam` and delete each other's files,
/// the backup of the old SAM among them (review B2 S6, R95).
pub fn for_self_update(paths: &Paths) -> Result<Option<SelfUpdateLock>> {
    let p = self_update_path(paths);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&paths.data_dir)
        .with_context(|| format!("creating {}", paths.data_dir.display()))?;
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)
        .with_context(|| format!("opening {}", p.display()))?;
    Ok(take(&f, libc::LOCK_EX, Duration::ZERO)?.then_some(SelfUpdateLock { _file: f }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A start right after a lock was dropped. Another test of this
    /// process may fork at that moment; its child holds a copy of the lock
    /// until it runs its program (close-on-exec), so allow it a moment.
    fn start_soon(paths: &Paths, id: &str) -> bool {
        let until = Instant::now() + Duration::from_secs(1);
        loop {
            if for_start(paths, id).unwrap().is_some() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A start and a change of the same app never hold it together, in
    /// either order; another app is not held. A start is refused at once,
    /// a change only after its short wait.
    #[test]
    fn a_start_and_a_change_of_one_app_exclude_each_other() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let start = for_start(&paths, "app-1a2b").unwrap().unwrap();
        assert!(
            for_start(&paths, "app-1a2b").unwrap().is_some(),
            "two starts at once"
        );
        let t = Instant::now();
        let p = paths.clone();
        let change = std::thread::spawn(move || for_change(&p, "app-1a2b").unwrap().is_some());
        assert!(!change.join().unwrap(), "a change under a start");
        assert!(t.elapsed() >= CHANGE_WAIT, "the change waited first");
        assert!(
            for_change(&paths, "other-3c4d").unwrap().is_some(),
            "another app"
        );
        drop(start);

        let change = for_change(&paths, "app-1a2b").unwrap().unwrap();
        let p = paths.clone();
        let started = std::thread::spawn(move || {
            let t = Instant::now();
            (for_start(&p, "app-1a2b").unwrap().is_some(), t.elapsed())
        });
        let (started, took) = started.join().unwrap();
        assert!(!started, "a start under a change");
        assert!(
            took < Duration::from_secs(1),
            "refused at once, after {took:?}"
        );
        drop(change);
        assert!(start_soon(&paths, "app-1a2b"), "free again once dropped");
    }

    /// A change that is a step of another change of the same app (an
    /// update unpacks again) goes on in the same thread; another thread
    /// still has to wait until the outer change ends.
    #[test]
    fn a_change_inside_a_change_of_the_same_app_goes_on() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let outer = for_change(&paths, "app-1a2b").unwrap().unwrap();
        let inner = for_change(&paths, "app-1a2b").unwrap();
        assert!(inner.is_some(), "the inner step");
        drop(inner);
        let p = paths.clone();
        let other = std::thread::spawn(move || for_start(&p, "app-1a2b").unwrap().is_some());
        assert!(!other.join().unwrap(), "the outer change still holds it");
        drop(outer);
        assert!(start_soon(&paths, "app-1a2b"), "free again once dropped");
    }

    /// No program SAM starts inherits an app's lock: the lock files close
    /// when a child runs its program (close-on-exec), so an app never holds
    /// its own start lock and blocks changes for as long as it lives, and a
    /// helper of a change holds it only until it runs.
    #[test]
    fn programs_sam_starts_never_inherit_an_apps_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let start = for_start(&paths, "app-1a2b").unwrap().unwrap();
        let change = for_change(&paths, "other-3c4d").unwrap().unwrap();
        let change_file = change._file.as_ref().unwrap();
        for fd in [start._file.as_raw_fd(), change_file.as_raw_fd()] {
            // SAFETY: `fd` is an open descriptor; F_GETFD only reads its flags.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0, "flags {flags}");
        }
    }

    /// One update of SAM at a time: a second is refused at once, and free
    /// again once the first ends. Its lock file is outside the folders the
    /// update empties (review B2 S6, R95).
    #[test]
    fn one_update_of_sam_at_a_time() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let first = for_self_update(&paths).unwrap().expect("the first update");
        let t = Instant::now();
        let p = paths.clone();
        let second = std::thread::spawn(move || for_self_update(&p).unwrap().is_some());
        assert!(!second.join().unwrap(), "two updates of SAM at once");
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "refused at once, after {:?}",
            t.elapsed()
        );
        let lock = self_update_path(&paths);
        for emptied in ["downloads", "update-backups"] {
            assert!(!lock.starts_with(paths.data_dir.join(emptied)), "{lock:?}");
        }
        drop(first);
        // Another test of this process may fork right now; its child holds
        // a copy of the lock until it runs its program (see start_soon).
        let until = Instant::now() + Duration::from_secs(1);
        while for_self_update(&paths).unwrap().is_none() {
            assert!(Instant::now() < until, "free again once dropped");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The lock file lives beside the apps' runtime folders, so removing
    /// an app's runtime folder never removes it.
    #[test]
    fn the_lock_is_not_inside_the_apps_runtime_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(tmp.path());
        let lock = path(&paths, "app-1a2b");
        assert!(!lock.starts_with(paths.runtime_dir("app-1a2b")));
        assert_eq!(lock.parent(), paths.runtime_dir("app-1a2b").parent());
    }
}
