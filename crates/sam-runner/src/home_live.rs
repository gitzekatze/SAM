//! A writable home watched while the app runs. With full home read/write, a
//! startup file the app creates (`.bash_profile`, `.xprofile` …) cannot be
//! stopped by a mount, and before this it stayed until the app ended: a
//! terminal opened meanwhile would have run it. Now Linux reports every
//! change in the folders that hold the watched places (inotify), and SAM
//! looks again at once (`HomeWatch::settle`): the file is moved aside and a
//! replaced link put back within moments.
//!
//! Cost: the thread sleeps in `poll` until something changes in those few
//! folders or the app ends; no timer, no regular wake-ups.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::thread::JoinHandle;

use sam_sandbox::{HomeWatch, MovedAside};

/// The running watcher; [`LiveWatch::finish`] ends it and returns what it
/// moved aside.
pub struct LiveWatch {
    /// Written to end the thread (an eventfd).
    wake: i32,
    thread: Option<JoinHandle<Vec<MovedAside>>>,
}

impl LiveWatch {
    /// Starts watching the folders of `watch`; what is found goes to
    /// `aside`. The watch is `None` when there is nothing to watch or Linux
    /// refuses; the text says what is not watched while the app runs, so
    /// that is never silent (regression, audit L-F4: another app can use up
    /// the inotify instances, and one watched folder out of many counted as
    /// watching). What is not watched is still moved aside when the app ends.
    pub fn start(watch: &HomeWatch, aside: PathBuf) -> (Option<LiveWatch>, Option<String>) {
        let dirs = watch.watched_dirs();
        if dirs.is_empty() {
            return (None, None);
        }
        let not_watched = |what: String| {
            Some(sam_core::i18n::trf(
                "start files in {folders} are not watched while the app runs (Linux refused); SAM moves them aside when it ends",
                &[("folders", &what)],
            ))
        };
        // SAFETY: inotify_init1 takes flags only and returns a new descriptor or -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return (None, not_watched(sam_core::i18n::tr("the home folder")));
        }
        let mask = libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_MOVED_FROM | libc::IN_DELETE;
        let mut watching = false;
        let mut missed = Vec::new();
        for d in dirs {
            let Ok(path) = CString::new(d.as_os_str().as_bytes()) else {
                missed.push(sam_core::util::tildify(&d));
                continue;
            };
            // SAFETY: `fd` is the inotify descriptor above, `path` a valid C string for the call.
            if unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) } >= 0 {
                watching = true;
            } else {
                missed.push(sam_core::util::tildify(&d));
            }
        }
        let warning = (!missed.is_empty())
            .then(|| missed.join(", "))
            .and_then(not_watched);
        // SAFETY: eventfd takes an initial value and flags, returns a new descriptor or -1.
        let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if !watching || wake < 0 {
            // SAFETY: closing descriptors this function opened and nothing else holds.
            unsafe {
                libc::close(fd);
                if wake >= 0 {
                    libc::close(wake);
                }
            }
            return (
                None,
                warning.or_else(|| not_watched(sam_core::i18n::tr("the home folder"))),
            );
        }
        let w = watch.clone();
        let thread = std::thread::spawn(move || {
            let mut moved = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let mut fds = [
                    libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: wake,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                // SAFETY: `fds` is a valid array of two pollfd for the call; -1 waits without a timer.
                let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
                if n < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if fds[1].revents != 0 {
                    break;
                }
                if fds[0].revents != 0 {
                    // The events themselves do not matter: any change in these
                    // folders is the moment to look again.
                    // SAFETY: `buf` is writable for its length; the descriptor is non-blocking.
                    while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
                    moved.extend(w.settle(&aside));
                }
            }
            // SAFETY: the inotify descriptor belongs to this thread alone from here on.
            unsafe { libc::close(fd) };
            moved
        });
        (
            Some(LiveWatch {
                wake,
                thread: Some(thread),
            }),
            warning,
        )
    }

    /// Ends the watcher; returns what it moved aside while the app ran.
    pub fn finish(mut self) -> Vec<MovedAside> {
        self.stop();
        self.thread
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default()
    }

    fn stop(&mut self) {
        if self.wake >= 0 {
            let one: u64 = 1;
            // SAFETY: writes 8 bytes from a valid u64 to the eventfd this struct owns.
            unsafe { libc::write(self.wake, (&one as *const u64).cast(), 8) };
        }
    }
}

impl Drop for LiveWatch {
    fn drop(&mut self) {
        self.stop();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if self.wake >= 0 {
            // SAFETY: the eventfd is owned by this struct and closed once, after the thread ended.
            unsafe { libc::close(self.wake) };
            self.wake = -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, Instant};

    /// A startup file created while the app runs is moved aside at once,
    /// not only when the app ends; a removed link is put back at once.
    #[test]
    fn a_new_startup_file_is_moved_aside_while_the_app_runs() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(home.join(".config")).unwrap();
        fs::create_dir_all(home.join("dots/git")).unwrap();
        std::os::unix::fs::symlink(home.join("dots/git"), home.join(".config/git")).unwrap();
        let mut p = sam_core::permissions::PermissionSet::default();
        p.filesystem.home = true;
        p.filesystem.home_access = sam_core::permissions::Access::Rw;
        let watch = HomeWatch::before(&p, &home).unwrap();
        let (live, warning) = LiveWatch::start(&watch, t.path().join("aside"));
        assert_eq!(warning, None, "every folder is watched");
        let live = live.expect("watching");
        let gone = |path: &std::path::Path| {
            let end = Instant::now() + Duration::from_secs(5);
            while Instant::now() < end {
                if fs::symlink_metadata(path).is_err() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        };
        fs::write(home.join(".bash_profile"), "echo pwned").unwrap();
        assert!(
            gone(&home.join(".bash_profile")),
            "moved aside while the app runs"
        );
        fs::remove_file(home.join(".config/git")).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while fs::read_link(home.join(".config/git")).is_err() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_link(home.join(".config/git")).unwrap(),
            home.join("dots/git"),
            "the link is back"
        );
        let moved = live.finish();
        assert!(
            moved.iter().any(|m| m.place == ".bash_profile"),
            "{moved:?}"
        );
    }

    /// A folder Linux will not watch is said, not skipped silently (audit
    /// L-F4); what is in it is still moved aside when the app ends.
    #[test]
    fn a_folder_that_cannot_be_watched_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        std::fs::create_dir_all(home.join(".config")).unwrap();
        let mut p = sam_core::permissions::PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = sam_core::permissions::Access::Rw;
        let watch = sam_sandbox::HomeWatch::before(&p, &home).unwrap();
        std::fs::set_permissions(home.join(".config"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        let (live, warning) = LiveWatch::start(&watch, t.path().join("aside"));
        std::fs::set_permissions(home.join(".config"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let warning = warning.expect("a warning");
        assert!(warning.contains(".config"), "{warning}");
        if let Some(l) = live {
            l.finish();
        }
    }
}
