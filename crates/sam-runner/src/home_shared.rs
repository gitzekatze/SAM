//! The watched start places of every running launch that can write them
//! ([`HomeWatch`]), kept on disk in SAM's data folder, which no app ever
//! sees. One record per launch, locked by its launcher while it runs.
//!
//! Two things need it (review 2026-11-23):
//! - a launch that starts while others run takes over what they saw at
//!   their start, so a link another app planted meanwhile is never taken
//!   for the user's own and put back (F1);
//! - a launch whose launcher was killed (SIGKILL, a crash) still gets its
//!   last look: its record is no longer locked, and the next look moves
//!   aside what the app left, before anything can act on it (F2). Before,
//!   the watch lived only in the launcher's memory;
//! - launches look at the home one at a time ([`Turns`]), so a file one app
//!   plants in a place several launches watch is normally moved aside and
//!   reported once. A look waits at most about a second for another
//!   launch's turn and then looks anyway, so the live watches and final
//!   looks of running launches keep moving files aside while another
//!   launcher is stopped in the middle of its look (Ctrl+Z). That bound is
//!   only for the turn (`.settle`): a start, and the last look for a killed
//!   launcher, also need `.lock`, which [`Shared::open`] waits for without
//!   a limit, so they wait while a launcher is stopped in its start look.
//!   And a look on a home that hangs (a network home) hangs as well.

use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sam_core::Paths;
use sam_sandbox::{HomeWatch, MovedAside};

/// The first line of every record.
const HEADER: &str = "sam-home-watch 1";

/// The folder with the records, `<data>/home-watch`.
fn folder(paths: &Paths) -> PathBuf {
    paths.data_dir.join("home-watch")
}

/// This boot of the computer: a record from an earlier boot is not acted on.
fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn hex(p: &Path) -> String {
    p.as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn unhex(s: &str) -> Option<PathBuf> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

/// One launch's record, read back.
struct Record {
    boot: String,
    /// When the launch looked at the home, in nanoseconds since 1970.
    since: u128,
    aside: PathBuf,
    log: Option<PathBuf>,
    watch: HomeWatch,
}

impl Record {
    fn parse(text: &str) -> Option<Record> {
        let mut lines = text.lines();
        if lines.next()? != HEADER {
            return None;
        }
        let rest: Vec<&str> = lines.collect();
        let field = |key: &str| {
            rest.iter()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
        };
        Some(Record {
            boot: field("boot")?.to_string(),
            since: field("since")?.parse().ok()?,
            aside: unhex(field("aside")?).filter(|p| p.is_absolute())?,
            log: field("log").and_then(unhex).filter(|p| p.is_absolute()),
            watch: HomeWatch::from_lines(rest.iter().copied())?,
        })
    }
}

/// Takes `file`'s lock without waiting; false when another holds it.
fn try_lock(file: &fs::File) -> bool {
    // SAFETY: `file` is open; flock only takes its descriptor.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// How long a look waits for another launch's look before it looks anyway.
const TURN_WAIT: Duration = Duration::from_secs(1);

/// Where launches take turns to look at the home (`<records>/.settle`), and
/// how long one waits. A file of its own, not `.lock`: the start look and
/// the look for a killed launcher hold `.lock` already in this process, and
/// a second lock on it would wait for itself. Always taken after `.lock`,
/// never the other way round.
#[derive(Debug, Clone)]
pub struct Turns {
    dir: PathBuf,
    wait: Duration,
}

impl Turns {
    /// The turns of the launches of this SAM.
    pub fn of(paths: &Paths) -> Turns {
        Turns::at(&folder(paths))
    }

    fn at(dir: &Path) -> Turns {
        Turns {
            dir: dir.to_path_buf(),
            wait: TURN_WAIT,
        }
    }

    /// Turns in `dir` that wait up to `wait`: for tests.
    #[cfg(test)]
    pub(crate) fn waiting(dir: &Path, wait: Duration) -> Turns {
        Turns {
            dir: dir.to_path_buf(),
            wait,
        }
    }

    /// [`HomeWatch::settle`] in this launch's turn: two launches watching
    /// one place then never both act on the same file, so it is moved and
    /// reported once (before, the second look reported it as deleted or as
    /// still there, or moved aside a link of the person's that the first
    /// had just put back). The look always happens: after the wait, also
    /// when the turn could not be had (a launcher stopped mid-look) or the
    /// lock file cannot be opened. The watch is the protection; the turn
    /// only keeps the reports right.
    pub fn settle(&self, watch: &HomeWatch, aside: &Path) -> Vec<MovedAside> {
        // `std::fs` opens with O_CLOEXEC: no program SAM starts keeps it.
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(".settle"))
            .ok();
        let end = Instant::now() + self.wait;
        let turn = lock.filter(|f| loop {
            if try_lock(f) {
                break true;
            }
            if Instant::now() >= end {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        });
        let moved = watch.settle(aside);
        if let Some(f) = &turn {
            // Ended now, not when the file is closed: a program started in
            // this moment shares the open file until it runs its own, and
            // would keep the turn that long.
            // SAFETY: `f` is open; flock only takes its descriptor.
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        }
        moved
    }
}

/// The records' folder, locked for this process until dropped: one launch
/// at a time looks at the others and adds its own.
pub struct Shared {
    dir: PathBuf,
    _lock: fs::File,
    /// Where the looks take turns.
    turns: Turns,
}

impl Shared {
    pub fn open(paths: &Paths) -> Result<Shared> {
        use std::os::unix::fs::PermissionsExt;
        let dir = folder(paths);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        let lock = fs::File::create(dir.join(".lock"))
            .with_context(|| format!("creating {}", dir.join(".lock").display()))?;
        // SAFETY: `lock` is open; flock only takes its descriptor. Waits for
        // the launch that holds it (a moment: it only looks and writes).
        while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                anyhow::bail!(
                    "locking {}: {}",
                    dir.join(".lock").display(),
                    std::io::Error::last_os_error()
                );
            }
        }
        Ok(Shared {
            turns: Turns::at(&dir),
            dir,
            _lock: lock,
        })
    }

    /// The watches of the launches that run now, oldest first. Records of
    /// launches whose launcher is gone get their last look first: what their
    /// app left is moved aside, and said in their log.
    pub fn running(&self) -> Vec<HomeWatch> {
        let mut running: Vec<(u128, HomeWatch)> = Vec::new();
        let boot = boot_id();
        for e in fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            if e.file_name().as_bytes().starts_with(b".") {
                continue;
            }
            let Ok(file) = fs::File::open(e.path()) else {
                continue;
            };
            let record = fs::read_to_string(e.path())
                .ok()
                .and_then(|t| Record::parse(&t));
            if !try_lock(&file) {
                if let Some(r) = record {
                    running.push((r.since, r.watch));
                }
                continue;
            }
            // Its launcher is gone without its last look.
            if let Some(r) = record.filter(|r| r.boot == boot) {
                let moved = self.turns.settle(&r.watch, &r.aside);
                if let Some(log) = r.log.filter(|_| !moved.is_empty()) {
                    note_in_log(&log, &moved);
                }
            }
            let _ = fs::remove_file(e.path());
        }
        running.sort_by_key(|(since, _)| *since);
        running.into_iter().map(|(_, w)| w).collect()
    }

    /// Keeps `watch` on disk for the launch `name` until the returned
    /// record is dropped; what the app leaves goes to `aside`.
    pub fn register(&self, name: &str, watch: &HomeWatch, aside: &Path) -> Result<Registration> {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let mut text = format!(
            "{HEADER}\nboot {}\nsince {since}\naside {}\n",
            boot_id(),
            hex(aside)
        );
        for l in watch.to_lines() {
            text.push_str(&l);
            text.push('\n');
        }
        let path = self.dir.join(name);
        let new = self.dir.join(format!(".new-{name}"));
        let _ = fs::remove_file(&new);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&new)
            .with_context(|| format!("creating {}", new.display()))?;
        // Locked before anyone can see it under its name.
        if !try_lock(&file) {
            anyhow::bail!("locking {}", new.display());
        }
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&new, &path))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Registration {
            path,
            file: Some(file),
            watch: watch.clone(),
            aside: aside.to_path_buf(),
            armed: false,
            turns: self.turns.clone(),
        })
    }
}

/// Lines in the log of a launch whose launcher was killed: what its app
/// left, moved aside afterwards.
fn note_in_log(log: &Path, moved: &[MovedAside]) {
    let Ok(mut f) = fs::OpenOptions::new().append(true).open(log) else {
        return;
    };
    for m in moved {
        let what = crate::launch::describe_moved(m);
        let _ = writeln!(
            f,
            "# moved aside after SAM's launcher had ended (it would act outside the sandbox): {what}"
        );
    }
}

/// Looks at the records now: what the app of a launch whose launcher is
/// gone left in start places is moved aside. For `Sam::running`, which
/// finds such launches.
pub fn settle_left_behind(paths: &Paths) {
    if !folder(paths).is_dir() {
        return;
    }
    if let Ok(s) = Shared::open(paths) {
        s.running();
    }
}

/// One running launch's record. Removed when dropped; when the app had
/// started ([`Registration::arm`]) and the launch did not look a last time
/// ([`Registration::finish`]), the last look is taken first.
pub struct Registration {
    path: PathBuf,
    file: Option<fs::File>,
    watch: HomeWatch,
    aside: PathBuf,
    armed: bool,
    /// Where its last look takes its turn.
    turns: Turns,
}

impl Registration {
    /// The app is about to start; its log is `log`.
    pub fn arm(&mut self, log: &Path) {
        self.armed = true;
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "log {}", hex(log));
        }
    }

    /// The launch has taken its last look: the record goes.
    pub fn finish(mut self) {
        self.armed = false;
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if self.armed {
            self.turns.settle(&self.watch, &self.aside);
        }
        // Removed while still locked: nobody takes it for a killed launch.
        let _ = fs::remove_file(&self.path);
        self.file.take();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // a test: a panic is a failed test
    use super::*;

    /// A start of `p` with `home` as the home and no user folders.
    fn ctx_for(p: &sam_core::permissions::PermissionSet, home: &Path) -> sam_core::LaunchContext {
        let mut c = sam_core::sandbox::sample_context();
        c.host.home = home.to_path_buf();
        c.host.xdg_dirs.clear();
        c.permissions = p.clone();
        c
    }

    fn full_rw() -> sam_core::permissions::PermissionSet {
        let mut p = sam_core::permissions::PermissionSet::strict_gui();
        p.filesystem.home = true;
        p.filesystem.home_access = sam_core::permissions::Access::Rw;
        p
    }

    /// A launch as `prepare` starts it: looks at the others, then adds its
    /// own record.
    fn start(paths: &Paths, home: &Path, name: &str, aside: &Path) -> (HomeWatch, Registration) {
        let shared = Shared::open(paths).unwrap();
        let w = HomeWatch::before_alongside(&ctx_for(&full_rw(), home), &shared.running()).unwrap();
        let r = shared.register(name, &w, aside).unwrap();
        (w, r)
    }

    /// The lock of the turns in `dir`, held by the test until dropped, as
    /// another launch in the middle of its look holds it.
    fn hold_turn(dir: &Path) -> fs::File {
        fs::create_dir_all(dir).unwrap();
        let f = fs::File::create(dir.join(".settle")).unwrap();
        assert!(try_lock(&f), "the turn is free at first");
        f
    }

    /// A start of a launch that may write the whole home, on `home`.
    fn watch_of(home: &Path) -> HomeWatch {
        HomeWatch::before(&ctx_for(&full_rw(), home)).unwrap()
    }

    /// Two launches watching one place never look at the same moment: a
    /// look waits while another launch's look holds the turn, and goes on
    /// as soon as it ends (well before its bound). Before, both looked at
    /// once and the second reported a file the first had just moved as
    /// deleted or as still there. (`Turns` is new with this rule; the
    /// mutant that does not wait moves the file before the first check.)
    #[test]
    fn launches_look_at_a_home_one_at_a_time() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let w = watch_of(&home);
        let dir = t.path().join("records");
        let aside = t.path().join("aside");
        let held = hold_turn(&dir);
        fs::write(home.join(".bash_profile"), "plant").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let turns = Turns::waiting(&dir, Duration::from_secs(30));
        let (w2, aside2) = (w.clone(), aside.clone());
        let look = std::thread::spawn(move || {
            let _ = tx.send(turns.settle(&w2, &aside2));
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            home.join(".bash_profile").exists(),
            "looked while another launch had its turn"
        );
        assert!(rx.try_recv().is_err(), "the look did not wait");
        drop(held);
        let moved = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the look went on once the turn was free");
        look.join().unwrap();
        assert_eq!(moved.len(), 1, "{moved:?}");
        assert_eq!(moved[0].place, ".bash_profile");
        assert_eq!(moved[0].how, sam_sandbox::Aside::Moved);
        assert_eq!(fs::read_to_string(&moved[0].to).unwrap(), "plant");
        assert!(!home.join(".bash_profile").exists());
    }

    /// A look waits for another launch's turn at most its bound (about a
    /// second for SAM's launches), then looks anyway, so a launcher stopped
    /// in the middle of its look (Ctrl+Z) does not keep the live watches of
    /// running launches from moving a planted file aside; and a look also
    /// happens when the turn's lock cannot be opened. This covers only the
    /// wait for the turn: a start, and the last look for a killed launcher,
    /// also wait for the records' lock, without a limit. (The mutants that
    /// wait without a bound, or skip the look, fail here.)
    #[test]
    fn a_look_never_waits_long_for_another_launch() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let w = watch_of(&home);
        let dir = t.path().join("records");
        let aside = t.path().join("aside");
        let _held = hold_turn(&dir);
        // In a thread with a time limit: a look that waited without a
        // bound would hang the test.
        let look = |turns: Turns, text: &str| -> Vec<MovedAside> {
            fs::write(home.join(".bash_profile"), text).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let (w2, aside2) = (w.clone(), aside.clone());
            std::thread::spawn(move || {
                let _ = tx.send(turns.settle(&w2, &aside2));
            });
            let moved = rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("the look waited too long ({text})"));
            assert!(
                fs::symlink_metadata(home.join(".bash_profile")).is_err(),
                "the planted file stayed ({text})"
            );
            moved
        };
        let m = look(Turns::waiting(&dir, Duration::from_millis(200)), "one");
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(fs::read_to_string(&m[0].to).unwrap(), "one");
        // SAM's own bound.
        let m = look(Turns::at(&dir), "two");
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(fs::read_to_string(&m[0].to).unwrap(), "two");
        // The lock cannot be opened: its folder is a file.
        let not_a_folder = t.path().join("not-a-folder");
        fs::write(&not_a_folder, "").unwrap();
        let m = look(
            Turns::waiting(&not_a_folder, Duration::from_millis(200)),
            "three",
        );
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(fs::read_to_string(&m[0].to).unwrap(), "three");
    }

    /// The last look for a launch whose launcher was killed takes its turn
    /// like any other look: it waits while another launch is looking.
    /// (Fails when that look calls the watch directly, as before.)
    #[test]
    fn a_last_look_for_a_killed_launcher_takes_its_turn() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let paths = Paths::rooted(&t.path().join("sam"));
        let aside = t.path().join("aside");
        let (_, mut r) = start(&paths, &home, "killed", &aside);
        r.arm(&t.path().join("launch.log"));
        fs::write(home.join(".bash_profile"), "plant").unwrap();
        // Its launcher is gone: the record stays, no longer locked (as in
        // `a_start_file_left_by_a_killed_launcher_is_still_moved_aside`).
        drop(r.file.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !try_lock(&fs::File::open(&r.path).unwrap()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the record stayed locked"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        std::mem::forget(r);

        let held = hold_turn(&folder(&paths));
        let mut shared = Shared::open(&paths).unwrap();
        shared.turns = Turns::waiting(&folder(&paths), Duration::from_secs(30));
        let (tx, rx) = std::sync::mpsc::channel();
        let look = std::thread::spawn(move || {
            let _ = tx.send(shared.running().len());
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            home.join(".bash_profile").exists(),
            "looked while another launch had its turn"
        );
        drop(held);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10))
                .expect("the look went on once the turn was free"),
            0,
            "no launch runs"
        );
        look.join().unwrap();
        assert!(fs::symlink_metadata(home.join(".bash_profile")).is_err());
        assert_eq!(
            fs::read_to_string(aside.join(".bash_profile")).unwrap(),
            "plant"
        );
    }

    /// The look a record takes when it is dropped without its last look
    /// takes its turn too. (Fails when the drop calls the watch directly,
    /// as before.)
    #[test]
    fn a_dropped_record_takes_its_turn() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let paths = Paths::rooted(&t.path().join("sam"));
        let aside = t.path().join("aside");
        let (_, mut r) = start(&paths, &home, "dropped", &aside);
        r.arm(&t.path().join("launch.log"));
        r.turns = Turns::waiting(&folder(&paths), Duration::from_secs(30));
        fs::write(home.join(".bash_profile"), "plant").unwrap();
        let held = hold_turn(&folder(&paths));
        let (tx, rx) = std::sync::mpsc::channel();
        let look = std::thread::spawn(move || {
            drop(r);
            let _ = tx.send(());
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            home.join(".bash_profile").exists(),
            "looked while another launch had its turn"
        );
        drop(held);
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the look went on once the turn was free");
        look.join().unwrap();
        assert!(fs::symlink_metadata(home.join(".bash_profile")).is_err());
        assert_eq!(
            fs::read_to_string(aside.join(".bash_profile")).unwrap(),
            "plant"
        );
    }

    /// Review 2026-11-23 F1: app M plants `~/.bash_profile` (a link to its
    /// own script) while it runs; a second launch started meanwhile must
    /// not take that link for the user's own and put it back each time it
    /// is moved aside. A link the user had before stays the user's.
    #[test]
    fn a_second_launch_never_takes_a_link_planted_meanwhile_for_the_users_own() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(home.join(".cache")).unwrap();
        fs::create_dir_all(home.join(".config")).unwrap();
        fs::create_dir_all(home.join("dots/git")).unwrap();
        fs::write(home.join(".cache/x.sh"), "echo pwned").unwrap();
        std::os::unix::fs::symlink(home.join("dots/git"), home.join(".config/git")).unwrap();
        let paths = Paths::rooted(&t.path().join("sam"));
        let (aside_m, aside_b) = (t.path().join("aside-m"), t.path().join("aside-b"));

        // M starts: ~/.bash_profile does not exist.
        let (m, rm) = start(&paths, &home, "m", &aside_m);
        // M plants its link and replaces the user's.
        std::os::unix::fs::symlink(home.join(".cache/x.sh"), home.join(".bash_profile")).unwrap();
        fs::remove_file(home.join(".config/git")).unwrap();
        std::os::unix::fs::symlink(home.join(".cache"), home.join(".config/git")).unwrap();

        // B starts while M runs.
        let (b, rb) = start(&paths, &home, "b", &aside_b);
        // M's watch moves the link aside; B's never puts it back.
        m.settle(&aside_m);
        b.settle(&aside_b);
        assert!(
            fs::symlink_metadata(home.join(".bash_profile")).is_err(),
            "the planted link was put back"
        );
        // M plants it again and ends; B alone moves it aside.
        std::os::unix::fs::symlink(home.join(".cache/x.sh"), home.join(".bash_profile")).unwrap();
        drop(rm);
        let moved = b.settle(&aside_b);
        assert!(
            moved.iter().any(|x| x.place == ".bash_profile"),
            "{moved:?}"
        );
        assert!(fs::symlink_metadata(home.join(".bash_profile")).is_err());
        // The user's own link is the one put back.
        assert_eq!(
            fs::read_link(home.join(".config/git")).unwrap(),
            home.join("dots/git")
        );
        drop(rb);
        assert_eq!(
            fs::read_dir(folder(&paths))
                .unwrap()
                .flatten()
                .filter(|e| !e.file_name().as_bytes().starts_with(b"."))
                .count(),
            0,
            "no record stays after the launches"
        );
    }

    /// A launch that still runs keeps its record, and what it watches is
    /// left alone: only a record whose launcher is gone gets the last look
    /// (mutation run 2026-11-24: taking every record for a killed
    /// launcher's went unnoticed).
    #[test]
    fn a_running_launch_is_never_taken_for_a_killed_one() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let paths = Paths::rooted(&t.path().join("sam"));
        let aside = t.path().join("aside");
        let (_, r) = start(&paths, &home, "live", &aside);
        fs::write(home.join(".bash_profile"), "echo mine").unwrap();
        let running = Shared::open(&paths).unwrap().running();
        assert_eq!(running.len(), 1, "the running launch is listed");
        assert!(r.path.exists(), "its record stays");
        assert!(
            home.join(".bash_profile").exists(),
            "nothing is moved aside while it runs"
        );
    }

    /// Review 2026-11-23 F2: when SAM's launcher is killed (SIGKILL, a
    /// crash), its last look still happens: the next look at the running
    /// launches (`Sam::running`, which the window, `stop` and every start
    /// use) moves aside what the app left, and says so in its log.
    #[test]
    fn a_start_file_left_by_a_killed_launcher_is_still_moved_aside() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let paths = Paths::rooted(&t.path().join("sam"));
        let app = crate::ops::Sam::with_paths(paths.clone()).unwrap();
        let aside = t.path().join("aside");
        let log = t.path().join("launch.log");
        fs::write(&log, "# SAM launch log\n").unwrap();
        let (_, mut r) = start(&paths, &home, "killed", &aside);
        r.arm(&log);
        // A launch folder whose launcher is gone, as `Sam::running` finds it.
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let pid = gone.id();
        gone.wait().unwrap();
        let launch = paths.runtime_dir("someapp").join(format!("l{pid}-0"));
        fs::create_dir_all(&launch).unwrap();
        fs::write(launch.join("running.lock"), "").unwrap();
        // The app leaves a start file; its launcher is killed before its
        // last look: the record stays, no longer locked.
        fs::write(home.join(".bash_profile"), "echo pwned").unwrap();
        drop(r.file.take());
        // Another test of this process may have started a program in the
        // moment the record was open: until that program starts, its copy
        // holds the record's lock. Wait until the lock is free, as it is
        // for a launcher that is really gone (seen once under the load of
        // a whole-suite run, 2026-11-23).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !try_lock(&fs::File::open(&r.path).unwrap()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the record stayed locked"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::mem::forget(r);

        assert!(app.running("someapp").is_empty());
        assert!(
            fs::symlink_metadata(home.join(".bash_profile")).is_err(),
            "the start file stayed after the launcher was killed"
        );
        assert_eq!(
            fs::read_to_string(aside.join(".bash_profile")).unwrap(),
            "echo pwned"
        );
        let text = fs::read_to_string(&log).unwrap();
        assert!(
            text.contains("moved aside after SAM's launcher had ended"),
            "{text}"
        );
        assert!(
            !folder(&paths).join("killed").exists(),
            "the record is gone"
        );
    }
}
