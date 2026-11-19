//! Small helpers shared across crates.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Current time as unix seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix seconds as calendar time: local (`localtime_r`) or UTC (`gmtime_r`).
/// The C library knows the time zone; SAM needs no date library for this.
fn calendar(ts: i64, local: bool) -> Option<libc::tm> {
    // time_t is 64 bits on the systems SAM runs on; a conversion keeps it
    // correct where it is not.
    #[allow(clippy::useless_conversion)]
    let t: libc::time_t = ts.try_into().ok()?;
    // SAFETY: tm is a plain C struct for which all-zero bytes are valid.
    let mut out: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; the _r variants write
    // only into `out` and keep no reference to it.
    let r = unsafe {
        if local {
            libc::localtime_r(&t, &mut out)
        } else {
            libc::gmtime_r(&t, &mut out)
        }
    };
    (!r.is_null()).then_some(out)
}

/// Format unix seconds as a local, human readable timestamp.
pub fn format_ts(ts: i64) -> String {
    match calendar(ts, true) {
        Some(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.tm_year + 1900,
            t.tm_mon + 1,
            t.tm_mday,
            t.tm_hour,
            t.tm_min,
            t.tm_sec
        ),
        None => ts.to_string(),
    }
}

/// Unix seconds as an e-mail/HTTP style UTC date, "Thu, 01 Jan 1970 00:00:00
/// +0000" (English names, as the formats require).
pub fn format_utc_date(ts: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    match calendar(ts, false) {
        Some(t) => format!(
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
            DAYS.get(t.tm_wday as usize).unwrap_or(&"Sun"),
            t.tm_mday,
            MONTHS.get(t.tm_mon as usize).unwrap_or(&"Jan"),
            t.tm_year + 1900,
            t.tm_hour,
            t.tm_min,
            t.tm_sec
        ),
        None => ts.to_string(),
    }
}

/// Expand a leading `~` / `~/` and `$HOME` to the user's home directory.
pub fn expand_home(p: &str) -> PathBuf {
    let home = home_dir();
    if p == "~" {
        return home;
    }
    if let Some(rest) = p.strip_prefix("~/") {
        return home.join(rest);
    }
    if let Some(rest) = p.strip_prefix("$HOME/") {
        return home.join(rest);
    }
    PathBuf::from(p)
}

/// Replace the home prefix of a path with `~` for display.
pub fn tildify(p: &Path) -> String {
    let home = home_dir();
    match p.strip_prefix(&home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".into(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Write a file atomically (write to temp file in same dir, then rename).
/// Reads at most `limit` bytes of a regular file. Files inside an unpacked
/// AppImage are the AppImage's choice: a link to `/dev/zero` or a huge file
/// must not fill SAM's memory. The type is checked on the opened file, so a
/// swap between check and read changes nothing.
pub fn read_regular(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    // Without waiting: opening a named pipe for reading would block until
    // someone writes to it (audit I-F9, I-F15). For a regular file the
    // flag changes nothing; anything else is refused below.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut data = Vec::with_capacity(meta.len().min(limit) as usize);
    f.take(limit).read_to_end(&mut data)?;
    Ok(data)
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .context(crate::i18n::tr("path has no parent"))?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(OsStr::to_str).unwrap_or("file"),
        std::process::id()
    ));
    {
        // Readable by the user only: records hold environment values such
        // as API keys, which other people on the computer must not read
        // (audit U-L6). A leftover from a crash is replaced, not reused
        // with its old mode.
        use std::os::unix::fs::OpenOptionsExt;
        let _ = fs::remove_file(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    // The new name lasts a crash only once the folder is written too.
    if let Ok(d) = fs::File::open(dir) {
        d.sync_all().ok();
    }
    Ok(())
}

/// The AppImage file SAM itself runs from, when this program was started
/// from SAM's own AppImage (its runtime sets `$APPIMAGE` and `$APPDIR`, and
/// the program lies inside `$APPDIR`). Menu entries must then call the
/// AppImage file: the folder it is mounted at changes on every start.
pub fn own_appimage() -> Option<PathBuf> {
    let appimage = PathBuf::from(std::env::var_os("APPIMAGE")?);
    let appdir = PathBuf::from(std::env::var_os("APPDIR")?);
    let exe = std::env::current_exe().ok()?;
    (exe.starts_with(&appdir) && appimage.is_file()).then_some(appimage)
}

/// Finds a program SAM may run: the first one on `$PATH` that the user
/// cannot change. Every program SAM starts
/// runs outside the sandbox, and an app with write access to the home could
/// put its own `bwrap` or `pasta` into `~/.cargo/bin`, `~/go/bin` or
/// `~/.nix-profile/bin`, which are often on `$PATH` (audit L-F12): such a
/// copy is skipped ([`may_run`]).
///
/// The path returned has its folders resolved but keeps the program's own
/// name: some programs act by the name they are started under (`pasta` is
/// a link to `passt`, which without that name sets up a virtual machine's
/// network instead).
pub fn which(name: &str) -> Option<PathBuf> {
    candidates(name)
        .into_iter()
        .find(|p| may_run(p))
        .and_then(|p| {
            let dir = fs::canonicalize(p.parent()?).ok()?;
            Some(dir.join(p.file_name()?))
        })
}

/// The first copy of `name` that [`which`] skipped because the user can
/// change it, to name it in a message.
pub fn skipped_copy(name: &str) -> Option<PathBuf> {
    which(name)
        .is_none()
        .then(|| candidates(name).into_iter().find(|p| !may_run(p)))
        .flatten()
}

fn candidates(name: &str) -> Vec<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return if is_executable(&p) { vec![p] } else { vec![] };
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .filter(|p| is_executable(p))
        .collect()
}

/// Whether SAM may run the program at `p`: the user (and so every app,
/// which runs as the user) can change neither the file nor any folder on
/// its way, through links too. Not owned by the user (an owner can always
/// make it writable) and not writable for the user by group or others.
/// Run as root, the system's own files are root's: then no one else may
/// write them.
///
/// Tests name a folder of stand-in tools in `SAM_TRUST_TOOLS_IN`; its
/// programs may run although the user owns them. Whoever sets SAM's
/// environment can make it run anything anyway (`PATH` itself, for one),
/// and apps cannot set it.
pub fn may_run(p: &Path) -> bool {
    let Ok(real) = fs::canonicalize(p) else {
        return false;
    };
    // The folder holding a link, too: whoever can write there can point the
    // link elsewhere.
    let Some(folder) = p.parent().and_then(|d| fs::canonicalize(d).ok()) else {
        return false;
    };
    if let Some(dir) = std::env::var_os("SAM_TRUST_TOOLS_IN").filter(|d| !d.is_empty()) {
        if fs::canonicalize(dir).is_ok_and(|d| d == folder) {
            return true;
        }
    }
    unchanged_by_user(&real) && unchanged_by_user(&folder)
}

/// Whether the user can change neither `real` (links resolved) nor any
/// folder above it; see [`may_run`].
fn unchanged_by_user(real: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid has no preconditions and cannot fail.
    let me = unsafe { libc::getuid() };
    real.ancestors().all(|a| {
        let Ok(m) = fs::metadata(a) else {
            return false;
        };
        if me == 0 {
            return only_root_can_change(m.uid(), m.gid(), m.mode());
        }
        let Ok(c) = std::ffi::CString::new(a.as_os_str().as_encoded_bytes()) else {
            return false;
        };
        // SAFETY: `c` is a valid NUL-terminated path; access only reads it.
        let writable = unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0;
        m.uid() != me && !writable
    })
}

/// For SAM run as root: a file or folder only root can change, owned by
/// root and writable by no one else (a group other than root's counts as
/// someone else).
fn only_root_can_change(uid: u32, gid: u32, mode: u32) -> bool {
    let others_write = mode & 0o002 != 0 || (mode & 0o020 != 0 && gid != 0);
    uid == 0 && !others_write
}

pub fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Runs `cmd` (stdin closed, stderr dropped) and returns its exit status and
/// at most `max_out` bytes of its standard output. A program that is still
/// running after `limit` is killed and an error is returned: SAM hands
/// untrusted input to helper programs (GnuPG reads keys and signatures that
/// came with an AppImage) and must not hang with them. The program runs in a
/// process group of its own, and at the limit the whole group is killed, so
/// a program it started cannot keep SAM waiting either (regression: under
/// dash, `sh -c 'sleep 30'` kept the output open for 30 s after the shell
/// was killed). The rest of a longer output is read and dropped, so the
/// program never blocks on a full pipe.
pub fn output_within(
    cmd: &mut std::process::Command,
    limit: std::time::Duration,
    max_out: usize,
) -> Result<(std::process::ExitStatus, Vec<u8>)> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let group = child.id();
    let kill_group = || {
        if let Ok(g) = i32::try_from(group) {
            // SAFETY: kill(2) with a negative pid signals the process group
            // the child leads (it was started with process_group(0)); no
            // memory is involved.
            unsafe {
                libc::kill(-g, libc::SIGKILL);
            }
        }
    };
    let mut out = child.stdout.take().context("stdout")?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 {
                break;
            }
            let room = max_out.saturating_sub(kept.len());
            kept.extend_from_slice(buf.get(..n.min(room)).unwrap_or_default());
        }
        let _ = tx.send(kept);
    });
    let started = Instant::now();
    let stopped = || {
        anyhow::anyhow!(
            "{}",
            crate::i18n::trf(
                "{program} did not finish within {seconds} seconds and was stopped",
                &[
                    ("program", &cmd.get_program().to_string_lossy()),
                    ("seconds", &limit.as_secs())
                ]
            )
        )
    };
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if started.elapsed() > limit {
            kill_group();
            let _ = child.wait();
            return Err(stopped());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // The program ended; something it started may still hold its output.
    let left = limit.saturating_sub(started.elapsed());
    match rx.recv_timeout(left) {
        Ok(kept) => Ok((status, kept)),
        Err(_) => {
            kill_group();
            Err(stopped())
        }
    }
}

/// Writes `data` as a new file at `path`, never through a link: whatever is
/// at `path` (a file or a link, never a folder) is removed first, and the
/// file is created exclusively without following links. For files SAM
/// writes into folders an untrusted program could have touched (audit I-F2:
/// a planted `metadata.json` link made SAM write into `~/.bashrc`).
pub fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => anyhow::bail!("{} is a folder", path.display()),
        Ok(_) => fs::remove_file(path)?,
        Err(_) => {}
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

/// Makes sure `dir` is a real folder: a link in its place is removed (never
/// followed), a missing folder is created.
pub fn real_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => fs::remove_file(dir)?,
        Err(_) => {}
    }
    fs::create_dir(dir).with_context(|| format!("creating {}", dir.display()))
}

/// Quote a single argument for display as a POSIX shell word.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

pub fn shell_join<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .map(|a| shell_quote(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Characters that show nothing themselves but change what is around them:
/// control characters (also the 8-bit ones, U+0080 to U+009F), the marks
/// and overrides that turn the reading direction (`invoice\u{202E}fdp.exe`
/// shows as `invoiceexe.pdf`), and invisible ones (zero-width space, word
/// joiner, byte order mark, tag characters) that make two names look the
/// same. Zero-width joiner and non-joiner stay: some scripts and emoji
/// need them.
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'                    // soft hyphen
            | '\u{061C}'                  // Arabic letter mark
            | '\u{115F}' | '\u{1160}'     // Hangul fillers
            | '\u{180E}'                  // Mongolian vowel separator
            | '\u{200B}'                  // zero-width space
            | '\u{200E}' | '\u{200F}'     // left-to-right, right-to-left mark
            | '\u{202A}'..='\u{202E}'     // embeddings and overrides
            | '\u{2060}'..='\u{206F}'     // word joiner, isolates, invisible operators
            | '\u{3164}' | '\u{FFA0}'     // Hangul fillers
            | '\u{FEFF}'                  // byte order mark
            | '\u{FFF9}'..='\u{FFFB}'     // interlinear annotation
            | '\u{E0000}'..='\u{E007F}') // tag characters
}

/// Text from an untrusted source (an AppImage's desktop file, an app's
/// output, a file name) made safe to show: hidden characters
/// ([`is_hidden`]) removed, length capped, and `<`/`>` replaced by
/// look-alikes so no UI toolkit can mistake it for markup (some render HTML
/// automatically, including remote images).
pub fn display_safe(s: &str, max_chars: usize) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !is_hidden(*c))
        .map(|c| match c {
            '<' => '‹',
            '>' => '›',
            c => c,
        })
        .take(max_chars)
        .collect();
    if s.chars().filter(|c| !is_hidden(*c)).count() > max_chars {
        out.push('…');
    }
    out
}

/// Lowercase ASCII slug: `Krita 5.2 (x86_64)` -> `krita-5-2-x86-64`.
pub fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading a file from an untrusted app returns at once for anything
    /// that is not a regular file: a named pipe made SAM wait forever
    /// (audit I-F9, I-F15). A regular file is read up to the limit.
    #[test]
    fn a_named_pipe_is_refused_without_waiting() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("AppRun");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let f = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_regular(&f, 1024).is_err());
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)),
            Ok(true),
            "refused, and without waiting"
        );
        let file = tmp.path().join("plain");
        fs::write(&file, "0123456789").unwrap();
        assert_eq!(read_regular(&file, 4).unwrap(), b"0123");
        assert!(read_regular(tmp.path(), 4).is_err(), "a folder is refused");
    }

    /// SAM's own files in folders an untrusted program could have touched
    /// are written without following links: a planted link is replaced, the
    /// file it pointed to stays as it was, and a link in place of a folder
    /// becomes a real folder (audit I-F2).
    #[test]
    fn files_sam_writes_never_go_through_a_planted_link() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let victim = d.join("bashrc");
        fs::write(&victim, "the person's file").unwrap();
        let planted = d.join("metadata.json");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        write_new(&planted, b"{}").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "the person's file");
        assert!(fs::symlink_metadata(&planted).unwrap().is_file());
        assert_eq!(fs::read(&planted).unwrap(), b"{}");
        write_new(&planted, b"again").unwrap();
        assert_eq!(
            fs::read(&planted).unwrap(),
            b"again",
            "an old file is replaced"
        );
        assert!(write_new(d, b"x").is_err(), "a folder is not replaced");

        let elsewhere = d.join("autostart");
        fs::create_dir(&elsewhere).unwrap();
        let desktop = d.join("desktop");
        std::os::unix::fs::symlink(&elsewhere, &desktop).unwrap();
        real_dir(&desktop).unwrap();
        assert!(fs::symlink_metadata(&desktop).unwrap().is_dir());
        write_new(&desktop.join("app.desktop"), b"[Desktop Entry]").unwrap();
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
        real_dir(&desktop).unwrap();
        real_dir(&d.join("new")).unwrap();
        assert!(d.join("new").is_dir());
    }

    /// A helper program that hangs is stopped at the time limit instead of
    /// hanging SAM (GnuPG reads keys from untrusted AppImages), and a
    /// program that prints more than SAM keeps neither blocks nor floods
    /// SAM's memory.
    #[test]
    fn a_helper_program_is_stopped_at_its_time_limit() {
        use std::process::Command;
        use std::time::{Duration, Instant};
        // A hanging program, also one that hangs in a program it started
        // (`; true` makes every shell start `sleep` as a child of its own).
        for script in ["sleep 30", "sleep 30; true"] {
            let t = Instant::now();
            let e = output_within(
                Command::new("sh").args(["-c", script]),
                Duration::from_millis(300),
                100,
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains("did not finish"), "{script}: {e}");
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "{script}: {:?}",
                t.elapsed()
            );
        }
        // A program that ends but leaves a program behind that holds its
        // output: SAM still returns at the limit, and the leftover is ended.
        let t = Instant::now();
        // A sleep with a time no other program uses, to find it afterwards
        // (portable: dash, Ubuntu's sh, has no `exec -a`).
        let marker = format!("sleep 29.{}", std::process::id());
        let e = output_within(
            Command::new("sh").args(["-c", &format!("({marker}) & echo started")]),
            Duration::from_millis(500),
            100,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("did not finish"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        std::thread::sleep(Duration::from_millis(200));
        let left = Command::new("pgrep")
            .args(["-f", &marker])
            .output()
            .unwrap();
        assert!(left.stdout.is_empty(), "the leftover still runs");

        // 1 MiB of output, 10 bytes kept; the program still ends normally.
        let (st, out) = output_within(
            Command::new("sh").args(["-c", "head -c 1048576 /dev/zero; exit 3"]),
            Duration::from_secs(20),
            10,
        )
        .unwrap();
        assert_eq!(st.code(), Some(3));
        assert_eq!(out, vec![0u8; 10]);

        let (st, out) = output_within(
            Command::new("printf").arg("hello"),
            Duration::from_secs(20),
            100,
        )
        .unwrap();
        assert!(st.success());
        assert_eq!(out, b"hello");
    }

    /// Times are shown without a date library: UTC dates exactly, local
    /// times in the computer's own zone and shape (chrono was dropped when
    /// it became unmaintained, RUSTSEC-2026-0543).
    #[test]
    fn times_are_shown_without_a_date_library() {
        assert_eq!(format_utc_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(
            format_utc_date(1_794_885_600),
            "Tue, 17 Nov 2026 03:20:00 +0000"
        );
        assert_eq!(
            format_utc_date(951_782_400),
            "Tue, 29 Feb 2000 00:00:00 +0000",
            "a leap day"
        );
        let local = format_ts(1_794_885_600);
        let b = local.as_bytes();
        assert_eq!(b.len(), 19, "{local}");
        assert!(local.starts_with("2026-11-1"), "{local}");
        assert!(
            b[4] == b'-' && b[7] == b'-' && b[10] == b' ' && b[13] == b':' && b[16] == b':',
            "{local}"
        );
        let n = now();
        assert!(n > 1_794_000_000 && n < 4_000_000_000, "{n}");
    }

    /// A link to a device that never ends, or a file larger than the limit,
    /// cannot fill SAM's memory (regression: an AppImage whose AppRun links
    /// to /dev/zero made adding it grow without end).
    #[test]
    fn reading_a_file_of_an_appimage_is_bounded() {
        let t = tempfile::tempdir().unwrap();
        let link = t.path().join("AppRun");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert!(read_regular(&link, 1024).is_err(), "a device is not read");
        let big = t.path().join("big");
        std::fs::write(&big, vec![7u8; 5000]).unwrap();
        assert_eq!(read_regular(&big, 1000).unwrap().len(), 1000);
        assert_eq!(read_regular(&big, 9000).unwrap().len(), 5000);
    }

    /// Names become safe identifiers made of lowercase letters, digits and dashes.
    #[test]
    fn names_become_safe_identifiers() {
        assert_eq!(slugify("Krita 5.2 (x86_64)"), "krita-5-2-x86-64");
        assert_eq!(slugify("--Hello__World--"), "hello-world");
    }

    /// Shell quoting keeps spaces, quotes and empty strings intact.
    #[test]
    fn shell_quoting_keeps_spaces_and_quotes_intact() {
        assert_eq!(shell_quote("abc"), "abc");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }
}

#[cfg(test)]
mod may_run_tests {
    use super::*;

    /// Run as root, SAM takes a program only where root alone can change
    /// it: owned by root, not writable for others, and writable for a group
    /// only when that group is root's.
    #[test]
    fn as_root_only_what_no_one_else_can_change_may_run() {
        assert!(only_root_can_change(0, 0, 0o755));
        assert!(only_root_can_change(0, 0, 0o775));
        assert!(only_root_can_change(0, 50, 0o755));
        assert!(!only_root_can_change(0, 50, 0o775), "group staff may write");
        assert!(!only_root_can_change(0, 0, 0o757), "everyone may write");
        assert!(!only_root_can_change(0, 0, 0o777));
        assert!(!only_root_can_change(1000, 0, 0o755), "owned by a user");
        assert!(!only_root_can_change(1000, 1000, 0o555));
    }

    /// SAM runs only programs the user cannot change: one in a folder the
    /// user owns is refused, also behind a link, and a link there that
    /// leads to a system program is followed to it (audit L-F12).
    #[test]
    fn only_programs_the_user_cannot_change_may_run() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let own = tmp.path().join("bwrap");
        fs::write(&own, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&own, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!may_run(&own));
        let sh = fs::canonicalize("/bin/sh").unwrap();
        assert!(may_run(&sh), "{}", sh.display());
        // A link in a folder of the user's could be pointed elsewhere after
        // the check, even where it now leads to a system program.
        let link = tmp.path().join("sh");
        std::os::unix::fs::symlink(&sh, &link).unwrap();
        assert!(!may_run(&link));
        let to_own = tmp.path().join("to-own");
        std::os::unix::fs::symlink(&own, &to_own).unwrap();
        assert!(!may_run(&to_own));
        assert!(!may_run(&tmp.path().join("missing")));
        // A program the user owns, even where nobody may write it now: the
        // owner can make it writable again.
        let locked = tmp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        let prog = locked.join("bwrap");
        fs::write(&prog, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&prog, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::getuid() } != 0 {
            assert!(!may_run(&prog));
        }
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        // A system link keeps the name it was found under: some programs
        // act by it (pasta is a link to passt).
        if let Some(found) = which("sh") {
            assert_eq!(found.file_name().unwrap(), "sh", "{}", found.display());
        }
        // A folder the user can write, even owned by someone else: a
        // world-writable one like /tmp.
        let in_tmp = std::env::temp_dir();
        if fs::metadata(&in_tmp).is_ok_and(|m| m.permissions().mode() & 0o002 != 0) {
            assert!(!may_run(&in_tmp));
        }
    }
}

#[cfg(test)]
mod display_safe_tests {
    use super::display_safe;

    /// Text from an app is shown without markup or control characters, and long text is shortened.
    #[test]
    fn neutralizes_markup_and_controls() {
        assert_eq!(display_safe("<b>X</b>\u{7}", 100), "‹b›X‹/b›");
        assert_eq!(display_safe("abcdef", 3), "abc…");
    }

    /// Names that would show other than they are lose the characters that
    /// do it (audit I-F12): a direction override (`invoice\u{202E}fdp.exe` shows
    /// as `invoiceexe.pdf`), invisible spaces and joiners between letters,
    /// tag characters, 8-bit control codes. Joiners that scripts and emoji
    /// need stay.
    #[test]
    fn names_lose_direction_overrides_and_invisible_characters() {
        assert_eq!(
            display_safe("invoice\u{202E}fdp.exe", 100),
            "invoicefdp.exe"
        );
        for c in [
            '\u{200B}',
            '\u{200E}',
            '\u{200F}',
            '\u{202A}',
            '\u{2066}',
            '\u{2069}',
            '\u{2060}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{061C}',
            '\u{180E}',
            '\u{E0001}',
            '\u{E007F}',
            '\u{9B}',
            '\u{3164}',
            '\u{FFF9}',
        ] {
            assert_eq!(
                display_safe(&format!("pay{c}pal"), 100),
                "paypal",
                "{:04X}",
                c as u32
            );
        }
        let kept = "👩\u{200D}💻 می\u{200C}خواهم ❤\u{FE0F}";
        assert_eq!(display_safe(kept, 100), kept);
        assert_eq!(display_safe("a\u{202E}\u{202E}bc", 2), "ab…");
    }
}
