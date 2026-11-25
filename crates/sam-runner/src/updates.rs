//! Update checks: is a newer version of an AppImage published?
//!
//! The source comes from the AppImage itself (`.upd_info`, see
//! [`sam_detect::update_info`]). Every source ends in a `.zsync` file whose
//! header names the SHA-1 of the published AppImage; when it differs from the
//! file on this computer, an update is available. Only the header is read
//! (a few kilobytes), nothing is downloaded or replaced.
//!
//! The network is reached through `curl`: HTTPS only, also for redirects,
//! short time limits, a generic user agent, nothing about the user sent.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use sam_core::model::{UpdateState, UpdateStatus};
use sam_core::Fingerprint;
use sam_detect::update_info::{self, UpdateSource};
// SHA-1 only because the zsync format names the published file by it; it
// catches damaged downloads, not tampering (the signature check does that).
use sha1::{Digest, Sha1};
use sha2::Sha256;

/// The most read from a GitHub release description. It holds the release
/// notes and about 2 KB per file, so a release with a few hundred files
/// passes 512 KiB (review 2026-11-23, U-7); a longer answer is an error,
/// never read as if it were complete.
const MAX_RELEASE_ANSWER: usize = 16 << 20;
/// The largest update file SAM downloads when the server names no length.
pub const MAX_DOWNLOAD: u64 = 8 << 30;

/// curl as SAM uses it for every request (one place, so the three uses
/// cannot drift apart; audit: they had): never the person's ~/.curlrc (which
/// could switch off certificate checks or send the request elsewhere),
/// HTTPS only, also after redirects, a few redirects at most, no URL
/// patterns (`--globoff`: an update address with `[1-99999999]` would
/// otherwise make curl send that many requests), and a time limit for the
/// whole transfer, so a server that trickles cannot keep SAM busy forever
/// (audit U-M7).
fn curl(max_secs: u64) -> Result<Command> {
    let curl = sam_core::util::which("curl")
        .context(sam_core::i18n::tr("curl is not installed, so SAM cannot check for or download updates. Install the package curl."))?;
    let mut cmd = Command::new(curl);
    cmd.args([
        // First, or curl ignores it.
        "--disable",
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--globoff",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-redirs",
        "5",
        "--connect-timeout",
        "15",
        "--user-agent",
        "SAM-AppImage-update-check",
    ])
    .args(["--max-time", &max_secs.to_string()]);
    Ok(cmd)
}

/// Checks `appimage` against its published version, whatever file it is,
/// without comparing it with anything. SAM's own checks of its apps must use
/// [`check_unpacked`]: this one trusts the update address of any file.
pub fn check(appimage: &Path) -> UpdateStatus {
    check_read(appimage, None)
}

/// Checks `appimage` against its published version, but only when it is
/// still the file SAM unpacked last (`unpacked`, the fingerprint recorded
/// when it was unpacked). The update address
/// comes from the AppImage itself, and this check runs outside every
/// sandbox: another app that can write to the AppImage's folder could put
/// its own file there, naming its own server, and SAM would send that
/// address (a way out for data from an app without network) and offer that
/// app's page as the download page. So a file that changed outside SAM is
/// not checked; no server is asked (review B2 S6, R88).
pub fn check_unpacked(appimage: &Path, unpacked: &Fingerprint) -> UpdateStatus {
    check_read(appimage, Some(unpacked))
}

fn check_read(appimage: &Path, unpacked: Option<&Fingerprint>) -> UpdateStatus {
    let now = sam_core::util::now();
    let failed = |detail: String| UpdateStatus {
        state: UpdateState::Failed,
        detail,
        checked_at: now,
        ..Default::default()
    };
    let changed = || {
        failed(sam_core::i18n::tr(
            "The AppImage changed outside SAM since it was last unpacked, so SAM does not check it for updates. Use Unpack Again and look at the app first.",
        ))
    };
    // One read: the checksum compared below and the address used later
    // come from the same bytes, so the file cannot be swapped in between.
    let read = match unpacked {
        None => ReadOnce::of(appimage).map(Some),
        Some(fp) => ReadOnce::of_size(appimage, fp.size),
    };
    let read = match read {
        Ok(Some(r)) => r,
        // Not a plain file of the unpacked size: not read at all.
        Ok(None) => return changed(),
        Err(e) => {
            return failed(sam_core::i18n::trf(
                "The update check failed: {error}",
                &[("error", &format!("{e:#}"))],
            ))
        }
    };
    if unpacked.is_some_and(|fp| !read.sha256.eq_ignore_ascii_case(&fp.sha256)) {
        return changed();
    }
    let Some(source) = read.source else {
        return UpdateStatus {
            state: UpdateState::Unsupported,
            detail: sam_core::i18n::tr("This AppImage does not say where updates are published."),
            checked_at: now,
            ..Default::default()
        };
    };
    match check_source(&read.sha1, &source) {
        Ok(mut s) => {
            s.checked_at = now;
            s
        }
        Err(e) => failed(sam_core::i18n::trf(
            "The update check failed: {error}",
            &[("error", &format!("{e:#}"))],
        )),
    }
}

/// An AppImage read once, through one open file: its SHA-256 (to compare
/// with what SAM unpacked), its SHA-1 (to compare with the published file)
/// and the update information in its first bytes.
struct ReadOnce {
    sha256: String,
    sha1: String,
    source: Option<UpdateSource>,
}

impl ReadOnce {
    fn of(path: &Path) -> Result<ReadOnce> {
        let f = File::open(path).with_context(|| {
            sam_core::i18n::trf("reading {file}", &[("file", &path.display().to_string())])
        })?;
        Self::from_file(f, u64::MAX)
    }

    /// Like [`ReadOnce::of`], but `None`, without reading anything, unless
    /// `path` is a plain file of exactly `size` bytes, and never more than
    /// `size` bytes are read. Another app could otherwise put a link to
    /// `/dev/zero`, a named pipe or a huge sparse file in the AppImage's
    /// place, and every check (also the one when SAM opens) would read
    /// forever (review B2 S6, R88).
    fn of_size(path: &Path, size: u64) -> Result<Option<ReadOnce>> {
        use std::os::unix::fs::OpenOptionsExt;
        // Without waiting: opening a named pipe for reading would otherwise
        // wait for a writer that never comes. A plain file is not affected.
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .with_context(|| {
                sam_core::i18n::trf("reading {file}", &[("file", &path.display().to_string())])
            })?;
        // The open file itself (fstat), not the name, which could change.
        let meta = f.metadata()?;
        if !meta.file_type().is_file() || meta.len() != size {
            return Ok(None);
        }
        Self::from_file(f, size).map(Some)
    }

    fn from_file(f: File, limit: u64) -> Result<ReadOnce> {
        let mut f = f.take(limit);
        let (mut h256, mut h1) = (Sha256::new(), Sha1::new());
        let mut head = Vec::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h256.update(&buf[..n]);
            h1.update(&buf[..n]);
            let keep = update_info::HEAD_BYTES.saturating_sub(head.len()).min(n);
            head.extend_from_slice(&buf[..keep]);
        }
        Ok(ReadOnce {
            sha256: sam_core::util::hex(&h256.finalize()),
            sha1: sam_core::util::hex(&h1.finalize()),
            source: update_info::from_head(&head),
        })
    }
}

/// The newest published file, as its update description (.zsync) states it.
#[derive(Debug, Clone)]
pub struct Published {
    /// Where the AppImage itself is downloaded (https).
    pub file_url: String,
    /// SHA-1 of the published AppImage (lowercase hex).
    pub sha1: String,
    pub filename: Option<String>,
    pub length: Option<u64>,
    /// GitHub release tag, when the source is a release.
    pub release: Option<String>,
    /// A page for people (release page, or the file itself).
    pub page: Option<String>,
    /// The update description (.zsync) itself, for downloading only changes.
    pub zsync_url: String,
}

/// What the source publishes: `Ok(None)` when one of the published files
/// is exactly `appimage` (it is current).
pub fn newest(appimage: &Path) -> Result<Option<Published>> {
    let read = ReadOnce::of(appimage)?;
    let source = read.source.context(sam_core::i18n::tr(
        "this AppImage does not say where updates are published",
    ))?;
    newest_from(&read.sha1, &source)
}

/// What `source` publishes, compared with the local file's SHA-1 `local`
/// (taken by the caller from the same read as `source`).
fn newest_from(local: &str, source: &UpdateSource) -> Result<Option<Published>> {
    // Candidate .zsync files: one fixed address, or every matching file of
    // a GitHub release (releases often hold rebuilds or variants side by side).
    let (zsyncs, release, page) = match source {
        UpdateSource::Zsync { url } => (
            vec![url.clone()],
            None,
            url.strip_suffix(".zsync").map(str::to_string),
        ),
        UpdateSource::GithubRelease {
            owner,
            repo,
            tag,
            pattern,
        } => {
            let api = if tag == "latest" {
                format!("https://api.github.com/repos/{owner}/{repo}/releases/latest")
            } else {
                format!("https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}")
            };
            let json: serde_json::Value = serde_json::from_slice(&fetch(&api, None)?)
                .context(sam_core::i18n::tr("GitHub's answer"))?;
            let tag_name = json
                .get("tag_name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let page = json
                .get("html_url")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let urls = release_zsyncs(&json, pattern, sam_detect::appimage::host_arch());
            if urls.is_empty() {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "release {tag_name} has no file matching {pattern}",
                        &[("tag_name", &tag_name), ("pattern", &pattern)]
                    )
                );
            }
            (urls, Some(tag_name), page)
        }
    };
    let mut first = None;
    for url in &zsyncs {
        let h = zsync_header(&fetch(url, Some(16 * 1024))?)?;
        if h.sha1.eq_ignore_ascii_case(local) {
            return Ok(None);
        }
        if first.is_none() {
            first = Some((url.clone(), h));
        }
    }
    let (zsync_url, h) = first.context(sam_core::i18n::tr("no update description"))?;
    let file_url = resolve(
        &zsync_url,
        h.url
            .as_deref()
            .or(h.filename.as_deref())
            .context(sam_core::i18n::tr("the update description names no file"))?,
    )?;
    Ok(Some(Published {
        file_url,
        sha1: h.sha1.to_ascii_lowercase(),
        filename: h.filename,
        length: h.length,
        release,
        page: page.filter(|p| p.starts_with("https://")),
        zsync_url,
    }))
}

/// The update descriptions (.zsync) of a GitHub release whose names match
/// `pattern`, at most four, those for `host`'s processor first and those
/// naming another processor last: a pattern like `App-*.AppImage.zsync`
/// also matches the ARM build, and the first one that differs from the
/// installed file is taken (review 2026-11-23, U-8).
fn release_zsyncs(json: &serde_json::Value, pattern: &str, host: &str) -> Vec<String> {
    let mut found: Vec<(u8, String)> = json
        .get("assets")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .filter_map(|x| {
            let name = x.get("name").and_then(|n| n.as_str())?;
            let url = x.get("browser_download_url").and_then(|v| v.as_str())?;
            update_info::matches(pattern, name).then(|| (arch_rank(name, host), url.to_string()))
        })
        .collect();
    // Stable: within a rank, the release's own order.
    found.sort_by_key(|(rank, _)| *rank);
    found.into_iter().take(4).map(|(_, url)| url).collect()
}

/// 0 when `name` names `host`'s processor, 2 when it names only another
/// one, 1 when it names none.
fn arch_rank(name: &str, host: &str) -> u8 {
    const NAMES: [(&str, &[&str]); 5] = [
        ("x86_64", &["x86_64", "x86-64", "amd64", "x64"]),
        ("aarch64", &["aarch64", "arm64"]),
        ("armhf", &["armhf", "armv7", "armv7l"]),
        ("i686", &["i686", "i386"]),
        ("riscv64", &["riscv64"]),
    ];
    let lower = name.to_ascii_lowercase();
    // Whole words, so that "x64" is not found inside another word.
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .collect();
    let names = |arch: &str| {
        NAMES
            .iter()
            .filter(|(a, _)| *a == arch)
            .flat_map(|(_, n)| n.iter())
            .any(|n| words.contains(n) || (n.contains(['_', '-']) && lower.contains(n)))
    };
    if names(host) {
        0
    } else if NAMES.iter().any(|(a, _)| *a != host && names(a)) {
        2
    } else {
        1
    }
}

fn check_source(local_sha1: &str, source: &UpdateSource) -> Result<UpdateStatus> {
    Ok(match newest_from(local_sha1, source)? {
        None => UpdateStatus {
            state: UpdateState::Current,
            detail: sam_core::i18n::tr("This is the newest published version."),
            ..Default::default()
        },
        Some(p) => {
            let name = match (&p.filename, &p.release) {
                (Some(f), Some(r)) => sam_core::i18n::trf(
                    "{file} (release {release})",
                    &[("file", f), ("release", r)],
                ),
                (Some(f), None) => f.clone(),
                (None, Some(r)) => sam_core::i18n::trf("release {release}", &[("release", r)]),
                (None, None) => sam_core::i18n::tr("a newer version"),
            };
            UpdateStatus {
                state: UpdateState::Available,
                detail: sam_core::i18n::trf(
                    "{version} is published.",
                    &[("version", &sam_core::util::display_safe(&name, 160))],
                ),
                latest: p.filename.or(p.release),
                download_page: p.page,
                checked_at: 0,
            }
        }
    })
}

/// `file` relative to the address of the .zsync file (or absolute https).
fn resolve(zsync_url: &str, file: &str) -> Result<String> {
    if file.contains("://") {
        if file.starts_with("https://") {
            return Ok(file.to_string());
        }
        bail!(
            "{}",
            sam_core::i18n::tr("the update file is not offered over HTTPS")
        );
    }
    if file.is_empty() || file.contains("..") || file.starts_with('/') {
        bail!(
            "{}",
            sam_core::i18n::trf(
                "the update description names an unusable file ({file})",
                &[("file", &sam_core::util::display_safe(file, 80))]
            )
        );
    }
    let base = zsync_url
        .rsplit_once('/')
        .map(|(b, _)| b)
        .context(sam_core::i18n::tr("bad update address"))?;
    Ok(format!("{base}/{file}"))
}

/// Downloads the published file to `dest` (a new file next to the old one)
/// and checks it against the SHA-1 of the update description. A partial or
/// wrong file is removed.
/// How it was downloaded, for the log and the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// Only the changed parts: `bytes` of `total`.
    Delta {
        bytes: u64,
        total: u64,
    },
    Full {
        total: u64,
    },
}

/// The longest one update download may take: the partial download and the
/// whole file after it together (review B2 S6, R90).
pub const UPDATE_TIME_LIMIT: Duration = Duration::from_secs(3600);

/// Downloads the new version to `dest`, reusing unchanged blocks of `old`
/// (zsync) when that saves most of the download; otherwise, or when anything
/// goes wrong with that, the whole file. Either way the result must match the
/// published SHA-1, and all of it ends within [`UPDATE_TIME_LIMIT`]. Used
/// for app updates and for SAM's own update.
pub fn download_update(p: &Published, old: &Path, dest: &Path) -> Result<Fetched> {
    download_update_within(p, old, dest, UPDATE_TIME_LIMIT)
}

/// [`download_update`] with its time limit (tests use seconds). One
/// deadline covers everything: the partial download, then the whole file
/// if that fails, and each request gets at most the time left. Each request
/// had its own limit before, so up to 300 range requests of five minutes
/// each (about a day) and then another hour for the whole file, while the
/// app could not start (review B2 S6, R90).
pub fn download_update_within(
    p: &Published,
    old: &Path,
    dest: &Path,
    limit: Duration,
) -> Result<Fetched> {
    let deadline = Deadline::new(limit);
    match download_delta(p, old, dest, &deadline) {
        Ok(Some(f)) => return Ok(f),
        Ok(None) | Err(_) => {
            let _ = std::fs::remove_file(dest);
        }
    }
    // curl's own time-out at the end of the limit is named as the limit;
    // any other reason (a 404, say) stays what it is, also near the end.
    download(p, dest, &deadline).map_err(|e| {
        if deadline.is_over() && e.downcast_ref::<CurlTimedOut>().is_some() {
            deadline.passed()
        } else {
            e
        }
    })?;
    Ok(Fetched::Full {
        total: std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0),
    })
}

/// When an update download must be done (see [`download_update_within`]).
struct Deadline {
    end: Instant,
    limit: Duration,
}

impl Deadline {
    fn new(limit: Duration) -> Deadline {
        Deadline {
            end: Instant::now() + limit,
            limit,
        }
    }

    /// The time left, or the error once it is over. Less than a second
    /// counts as over: curl takes whole seconds.
    fn left(&self) -> Result<Duration> {
        if self.is_over() {
            return Err(self.passed());
        }
        Ok(self.end.saturating_duration_since(Instant::now()))
    }

    fn is_over(&self) -> bool {
        self.end.saturating_duration_since(Instant::now()) < Duration::from_secs(1)
    }

    fn passed(&self) -> anyhow::Error {
        let secs = self.limit.as_secs();
        // In minutes when it is whole minutes (SAM's hour); tests use seconds.
        let text = if secs >= 120 && secs.is_multiple_of(60) {
            sam_core::i18n::trf(
                "the update download did not finish within {minutes} minutes and was stopped",
                &[("minutes", &(secs / 60))],
            )
        } else {
            sam_core::i18n::trf(
                "the update download did not finish within {seconds} seconds and was stopped",
                &[("seconds", &secs)],
            )
        };
        anyhow::anyhow!("{text}")
    }
}

/// curl stopped at its time limit (exit code 28): the reason a download
/// ends at the update's deadline.
#[derive(Debug)]
struct CurlTimedOut(String);

impl std::fmt::Display for CurlTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CurlTimedOut {}

/// `Ok(None)` when a delta would not save enough (most of the file changed,
/// or it would take too many requests).
fn download_delta(
    p: &Published,
    old: &Path,
    dest: &Path,
    deadline: &Deadline,
) -> Result<Option<Fetched>> {
    let secs = deadline.left()?.min(Duration::from_secs(30)).as_secs();
    let ctl = crate::zsync::parse(&fetch_within(&p.zsync_url, Some(64 << 20), secs)?)?;
    if ctl.sha1 != p.sha1 {
        bail!(
            "{}",
            sam_core::i18n::tr("the update description changed while reading it")
        );
    }
    // Mapped, not read: the old AppImage can be several GB, and mapped
    // pages the system can drop again under pressure (review 2026-11-23, U-6).
    let mapped = Mapped::open(old)?;
    let old_data = mapped.bytes();
    let plan = crate::zsync::plan_within(
        &ctl,
        old_data,
        deadline.left()?.min(Duration::from_secs(60)),
    );
    let ranges = crate::zsync::missing_ranges(&ctl, &plan, 64 * 1024);
    let bytes: u64 = ranges.iter().map(|(s, e)| e - s).sum();
    if ranges.len() > 300 || bytes * 10 > ctl.length * 7 {
        return Ok(None);
    }
    crate::zsync::assemble(&ctl, old_data, &plan, &ranges, dest, |s, e| {
        fetch_range(&p.file_url, s, e, deadline)
    })?;
    Ok(Some(Fetched::Delta {
        bytes,
        total: ctl.length,
    }))
}

/// A file mapped into memory, read-only. Only for SAM's own copy of the
/// installed version, in SAM's own folder (0700), which nothing else
/// shortens while it is mapped.
struct Mapped {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Mapped {
    fn open(path: &Path) -> Result<Mapped> {
        use std::os::fd::AsRawFd;
        let f = File::open(path)?;
        let len = usize::try_from(f.metadata()?.len())?;
        if len == 0 {
            return Ok(Mapped {
                ptr: std::ptr::null_mut(),
                len: 0,
            });
        }
        // SAFETY: a new private read-only mapping of an open file; the
        // kernel picks the address, nothing else is touched. The result is
        // checked against MAP_FAILED before use.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                f.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Mapped { ptr, len })
    }

    fn bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `ptr` is a live read-only mapping of `len` bytes (see
        // `open`), unmapped only in `drop`, so it outlives the borrow.
        unsafe { std::slice::from_raw_parts(self.ptr.cast::<u8>(), self.len) }
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        if self.len > 0 {
            // SAFETY: unmaps exactly the mapping made in `open`, once; no
            // borrow of it outlives `self`.
            unsafe {
                libc::munmap(self.ptr, self.len);
            }
        }
    }
}

/// Bytes `start..end` of `url` (an HTTP range request), within the time
/// left of `deadline` (at most five minutes).
fn fetch_range(url: &str, start: u64, end: u64, deadline: &Deadline) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        bail!("{}", sam_core::i18n::tr("not HTTPS"));
    }
    let want = usize::try_from(end.saturating_sub(start))?;
    let limit = deadline.left()?.min(Duration::from_secs(300));
    let mut cmd = curl(limit.as_secs())?;
    cmd.args(["--speed-limit", "1024", "--speed-time", "60"])
        .args(["--range", &format!("{}-{}", start, end.saturating_sub(1))])
        .arg("--")
        .arg(url);
    read_range(cmd, limit, want)
}

/// Runs `cmd` (curl fetching one byte range) for at most `limit` and
/// returns what it prints, at most `want` bytes. One byte more means the
/// server ignores the range and sends the whole file: SAM stops reading,
/// ends curl at once and gives up the partial download. Before, the first
/// bytes were kept and the rest dropped silently, so every range "passed",
/// each one a whole download, and only the final checksum failed (review
/// B2 S6, R90). `output_within` keeps that behaviour for its other callers.
fn read_range(mut cmd: Command, limit: Duration, want: usize) -> Result<Vec<u8>> {
    use std::os::unix::process::CommandExt;
    let started = Instant::now();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .context(sam_core::i18n::tr("starting curl"))?;
    // The whole group, so that nothing curl (or a stand-in) started keeps
    // the output open.
    let stop = |child: &mut std::process::Child| {
        if let Ok(g) = i32::try_from(child.id()) {
            // SAFETY: kill(2) with a negative pid signals the process group
            // the child leads (it was started with process_group(0)); no
            // memory is involved.
            unsafe {
                libc::kill(-g, libc::SIGKILL);
            }
        }
        let _ = child.wait();
    };
    let mut out = child.stdout.take().context("stdout")?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let read = (&mut out)
            .take((want as u64).saturating_add(1))
            .read_to_end(&mut kept);
        let _ = tx.send(read.map(|_| kept));
    });
    let too_slow = || {
        anyhow::anyhow!(
            "{}",
            sam_core::i18n::trf(
                "{program} did not finish within {seconds} seconds and was stopped",
                &[("program", &"curl"), ("seconds", &limit.as_secs())]
            )
        )
    };
    let kept = match rx.recv_timeout(limit) {
        Ok(Ok(kept)) => kept,
        Ok(Err(e)) => {
            stop(&mut child);
            return Err(e.into());
        }
        Err(_) => {
            stop(&mut child);
            return Err(too_slow());
        }
    };
    if kept.len() > want {
        stop(&mut child);
        bail!(
            "{}",
            sam_core::i18n::tr(
                "the server sent more than the part SAM asked for, so it ignores range requests; the partial download was stopped"
            )
        );
    }
    // Everything arrived; curl is ending.
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if started.elapsed() > limit {
            stop(&mut child);
            return Err(too_slow());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !status.success() {
        bail!(
            "{}",
            sam_core::i18n::trf(
                "downloading the changed parts failed: {reason}",
                &[("reason", &format!("curl {status}"))]
            )
        );
    }
    Ok(kept)
}

fn download(p: &Published, dest: &Path, deadline: &Deadline) -> Result<()> {
    let res = download_inner(p, dest, deadline);
    if res.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    res
}

fn download_inner(p: &Published, dest: &Path, deadline: &Deadline) -> Result<()> {
    if !p.file_url.starts_with("https://") {
        bail!(
            "{}",
            sam_core::i18n::tr("the update file is not offered over HTTPS")
        );
    }
    // What is left of the update's hour (the partial download may have
    // used some); the speed limit ends a stalled one sooner.
    let mut cmd = curl(deadline.left()?.as_secs())?;
    cmd.args(["--speed-limit", "1024", "--speed-time", "60"]);
    cmd.arg("--").arg(&p.file_url);
    // The published length (or SAM's ceiling) is the most SAM keeps.
    let cap = p.length.unwrap_or(MAX_DOWNLOAD).min(MAX_DOWNLOAD);
    save_capped(cmd, dest, cap)?;
    let got = sha1_of(dest)?;
    if got != p.sha1 {
        bail!(
            "{}",
            sam_core::i18n::tr(
                "the downloaded file does not match the published checksum; it was deleted"
            )
        );
    }
    Ok(())
}

/// Runs `cmd`, which prints the file it downloads, and writes that into the
/// new file `dest` (never through a link), at most `cap` bytes: one byte
/// more stops the download, and the file is deleted. SAM counts itself
/// because curl's own `--max-filesize` does nothing before curl 8.4 when
/// the server names no length (Debian 12, Ubuntu 22.04), so a server could
/// fill the disk for an hour (review 2026-11-23, U-5).
fn save_capped(mut cmd: Command, dest: &Path, cap: u64) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(dest)
        .with_context(|| format!("creating {}", dest.display()))?;
    let res = (|| -> Result<()> {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(sam_core::i18n::tr("starting curl"))?;
        // Read alongside, so that curl never waits on a full pipe.
        let mut stderr = child.stderr.take().context("stderr")?;
        let errors = std::thread::spawn(move || {
            let mut kept = Vec::new();
            let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut kept);
            let _ = std::io::copy(&mut stderr, &mut std::io::sink());
            String::from_utf8_lossy(&kept).into_owned()
        });
        let mut out = child.stdout.take().context("stdout")?;
        let copied = std::io::copy(&mut (&mut out).take(cap.saturating_add(1)), &mut file);
        if !matches!(copied, Ok(n) if n <= cap) {
            // Closed first: a helper curl left holding the pipes then ends
            // too, instead of keeping SAM waiting for its error output.
            drop(out);
            let _ = child.kill();
            let _ = child.wait();
            let _ = errors.join();
            copied?;
            bail!(
                "{}",
                sam_core::i18n::tr(
                    "the server sent more than the update description announced; the download was stopped and deleted"
                )
            );
        }
        drop(out);
        let st = child.wait()?;
        let err = errors.join().unwrap_or_default();
        if !st.success() {
            let why = format!("download failed: {}", curl_error(&err));
            if st.code() == Some(28) {
                return Err(CurlTimedOut(why).into());
            }
            bail!("{why}");
        }
        file.sync_all()?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    res
}

/// curl's error, in words: HTTP status codes become sentences.
fn curl_error(stderr: &str) -> String {
    let e = stderr.trim();
    let status = e
        .rsplit("error: ")
        .next()
        .and_then(|n| n.trim().parse::<u16>().ok());
    match status {
        Some(404) => {
            sam_core::i18n::tr("the update source has nothing published at that address (yet)")
        }
        Some(403) | Some(429) => sam_core::i18n::tr(
            "the update source refused the request for now (rate limit); try again later",
        ),
        Some(s) if s >= 500 => sam_core::i18n::trf(
            "the update source has a problem (HTTP {status}); try again later",
            &[("status", &s)],
        ),
        _ if e.contains("Could not resolve host") || e.contains("Failed to connect") => {
            sam_core::i18n::tr("no connection to the update source; check the internet connection")
        }
        _ => sam_core::util::display_safe(e.trim_start_matches("curl: "), 200),
    }
}

/// The fields of a zsync header SAM needs.
struct ZsyncHeader {
    sha1: String,
    filename: Option<String>,
    url: Option<String>,
    length: Option<u64>,
}

fn zsync_header(data: &[u8]) -> Result<ZsyncHeader> {
    let text = String::from_utf8_lossy(data);
    let mut sha1 = None;
    let mut filename = None;
    let mut url = None;
    let mut length = None;
    for line in text.lines() {
        if line.is_empty() {
            break; // end of the header; block checksums follow
        }
        match line.split_once(": ") {
            Some(("SHA-1", v)) if v.len() == 40 && v.chars().all(|c| c.is_ascii_hexdigit()) => {
                sha1 = Some(v.to_string())
            }
            Some(("Filename", v)) => filename = Some(sam_core::util::display_safe(v, 200)),
            Some(("URL", v)) if url.is_none() => url = Some(v.trim().to_string()),
            Some(("Length", v)) => length = v.trim().parse().ok(),
            _ => {}
        }
    }
    let Some(sha1) = sha1 else {
        bail!(
            "{}",
            sam_core::i18n::tr("the update description (.zsync) has no SHA-1")
        )
    };
    Ok(ZsyncHeader {
        sha1,
        filename,
        url,
        length,
    })
}

fn sha1_of(path: &Path) -> Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha1::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(sam_core::util::hex(&h.finalize()))
}

/// GETs `url` (HTTPS only). With a limit, only that range is asked for
/// and at most that many bytes are returned (a server that ignores the
/// range sends everything: enough was read). Without one, the whole answer
/// up to `MAX_RELEASE_ANSWER`; a longer one is an error.
fn fetch(url: &str, limit: Option<usize>) -> Result<Vec<u8>> {
    fetch_within(url, limit, 30)
}

/// [`fetch`] with at most `max_secs` for the request.
fn fetch_within(url: &str, limit: Option<usize>, max_secs: u64) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        bail!(
            "{}",
            sam_core::i18n::trf(
                "the update address is not HTTPS ({address})",
                &[("address", &sam_core::util::display_safe(url, 120))]
            )
        );
    }
    let mut cmd = curl(max_secs)?;
    cmd.args(["--header", "Accept: application/json, */*"]);
    if let Some(n) = limit {
        cmd.args(["--range", &format!("0-{}", n - 1)]);
    }
    cmd.arg("--").arg(url);
    match limit {
        Some(n) => answer_of(cmd, n, false),
        None => answer_of(cmd, MAX_RELEASE_ANSWER, true),
    }
}

/// What `cmd` prints, at most `max` bytes. With `whole`, a longer answer
/// is an error: cut off, it would be read as if it were complete (review
/// 2026-11-23, U-7: a release with many files failed as "GitHub's answer").
fn answer_of(mut cmd: Command, max: usize, whole: bool) -> Result<Vec<u8>> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(sam_core::i18n::tr("starting curl"))?;
    let keep = if whole { max.saturating_add(1) } else { max };
    let mut out = Vec::new();
    child
        .stdout
        .take()
        .context(sam_core::i18n::tr("curl output"))?
        .take(keep as u64)
        .read_to_end(&mut out)?;
    if out.len() >= keep {
        let _ = child.kill();
        let _ = child.wait();
        if whole {
            bail!(
                "{}",
                sam_core::i18n::trf(
                    "the update source answered with more than {size}, more than SAM reads",
                    &[("size", &sam_core::util::human_size(max as u64))]
                )
            );
        }
        return Ok(out);
    }
    let mut err = String::new();
    let _ = child.stderr.take().map(|mut e| e.read_to_string(&mut err));
    let st = child.wait()?;
    if !st.success() {
        bail!("{}", curl_error(&err));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The download itself refuses an address that is not HTTPS, before
    /// curl runs: the check of the update description is one layer, this
    /// is the second (verification audit 2026-11-19: no test noticed it
    /// gone, as curl then failed with a different error).
    #[test]
    fn a_download_from_plain_http_is_refused_before_curl_runs() {
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("new.AppImage");
        for url in [
            "http://127.0.0.1:9/App.AppImage",
            "ftp://127.0.0.1:9/App.AppImage",
            "file:///etc/passwd",
        ] {
            let p = Published {
                file_url: url.into(),
                sha1: "0".repeat(40),
                filename: None,
                length: None,
                release: None,
                page: None,
                zsync_url: "https://127.0.0.1:9/App.AppImage.zsync".into(),
            };
            let err = download_inner(&p, &dest, &Deadline::new(UPDATE_TIME_LIMIT))
                .unwrap_err()
                .to_string();
            assert_eq!(
                err,
                sam_core::i18n::tr("the update file is not offered over HTTPS"),
                "{url}"
            );
            assert!(!dest.exists(), "nothing was written for {url}");
        }
    }

    /// The checksum of a downloaded update is SHA-1 of the whole file, read
    /// in pieces; a file larger than one piece gives the same result.
    #[test]
    fn the_download_checksum_is_sha1_of_the_whole_file() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("abc");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            sha1_of(&f).unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d",
            "SHA-1 test vector"
        );
        let big = t.path().join("big");
        std::fs::write(&big, vec![b'a'; 1_000_000]).unwrap();
        assert_eq!(
            sha1_of(&big).unwrap(),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
            "SHA-1 of a million a"
        );
    }

    /// The update check reads an AppImage once and takes both checksums of
    /// the whole file from that read, also past the first 8 MiB it keeps
    /// for the update information (review B2 S6, R88): a checksum of only
    /// the kept part would let a file changed further on pass as the one
    /// SAM unpacked.
    #[test]
    fn the_update_check_hashes_the_whole_file_in_one_read() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("big.AppImage");
        let mut data = vec![b'a'; update_info::HEAD_BYTES + (1 << 20) + 7];
        let last = data.len() - 1;
        data[last] = b'b';
        std::fs::write(&f, &data).unwrap();
        let read = ReadOnce::of(&f).unwrap();
        assert_eq!(read.sha1, sha1_of(&f).unwrap(), "SHA-1 of the whole file");
        assert_eq!(
            read.sha256,
            sam_intake::fingerprint::sha256_file(&f).unwrap(),
            "SHA-256 of the whole file"
        );
        assert!(read.source.is_none(), "no ELF file, no update information");
    }

    /// Runs `f` in a thread and gives its result, or fails after `secs`
    /// seconds: a check that reads forever is a failed assertion here, not
    /// a test that never ends.
    fn within<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(secs))
            .unwrap_or_else(|_| panic!("the update check did not end within {secs} s"))
    }

    /// The update check reads nothing of a file that is not a plain file of
    /// the size SAM unpacked (review B2 S6, R88, second review): another
    /// app could put a link to `/dev/zero`, a named pipe or a huge sparse
    /// file in the AppImage's place, and every check (also the one when SAM
    /// opens) would read forever. A file of the right size with other
    /// contents is refused by its checksum, before any server is asked.
    #[test]
    fn the_update_check_reads_nothing_of_a_file_that_is_not_the_unpacked_one() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().to_path_buf();
        let unpacked = Fingerprint {
            size: 4096,
            sha256: sam_core::util::hex(&Sha256::digest([1u8; 4096])),
            ..Default::default()
        };
        let sparse = dir.join("sparse.AppImage");
        File::create(&sparse).unwrap().set_len(1 << 40).unwrap();
        let zero = dir.join("zero.AppImage");
        std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
        let fifo = dir.join("fifo.AppImage");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid, NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
        let other = dir.join("other.AppImage");
        std::fs::write(&other, [2u8; 4096]).unwrap();
        for path in [sparse, zero, fifo, other] {
            let fp = unpacked.clone();
            let p = path.clone();
            let status = within(10, move || check_unpacked(&p, &fp));
            assert_eq!(
                status.state,
                UpdateState::Failed,
                "{}: {}",
                path.display(),
                status.detail
            );
            assert!(
                status.detail.contains("changed outside SAM"),
                "{}: {}",
                path.display(),
                status.detail
            );
        }
        // The unchanged file passes the comparison (it names no update
        // address, so there is nothing to ask).
        let same = dir.join("same.AppImage");
        std::fs::write(&same, [1u8; 4096]).unwrap();
        let status = within(10, move || check_unpacked(&same, &unpacked));
        assert_eq!(status.state, UpdateState::Unsupported, "{}", status.detail);
    }

    /// The header of a zsync file is read (file name, size, checksum).
    #[test]
    fn the_zsync_header_is_read() {
        let z = b"zsync: 0.6.2\nFilename: App-2.0-x86_64.AppImage\nMTime: Tue, 10 Nov 2026 10:00:00 +0000\nBlocksize: 2048\nLength: 123\nSHA-1: 0123456789abcdef0123456789abcdef01234567\n\n\x00\x01binary";
        let h = zsync_header(z).unwrap();
        assert_eq!(h.sha1, "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(h.filename.as_deref(), Some("App-2.0-x86_64.AppImage"));
        assert!(
            zsync_header(b"zsync: 0.6.2\n\nSHA-1: 0123456789abcdef0123456789abcdef01234567\n")
                .is_err(),
            "only the header counts"
        );
        // A checksum that is not 40 hexadecimal digits is no checksum: the
        // update description is refused rather than compared against junk.
        for bad in [
            "0123456789abcdef",                           // too short
            "0123456789abcdef0123456789abcdef0123456789", // too long
            "0123456789abcdefg123456789abcdef01234567",   // not hexadecimal
        ] {
            let z = format!("zsync: 0.6.2\nSHA-1: {bad}\n\n");
            assert!(zsync_header(z.as_bytes()).is_err(), "{bad}");
        }
    }

    /// Download addresses in zsync files are resolved, and plain-HTTP addresses are refused.
    #[test]
    fn update_download_addresses_are_resolved_and_http_refused() {
        let z = "https://github.com/o/r/releases/download/v1/App.AppImage.zsync";
        assert_eq!(
            resolve(z, "App.AppImage").unwrap(),
            "https://github.com/o/r/releases/download/v1/App.AppImage"
        );
        assert_eq!(
            resolve(z, "https://cdn.example.org/App.AppImage").unwrap(),
            "https://cdn.example.org/App.AppImage"
        );
        assert!(resolve(z, "http://cdn.example.org/App.AppImage").is_err());
        assert!(resolve(z, "../../evil").is_err());
        assert!(resolve(z, "").is_err());
    }

    /// A stand-in for curl: prints `n` zero bytes, as curl prints what it
    /// downloads (contract updates-curl: SAM's curl writes the file to its
    /// standard output).
    fn prints(n: usize) -> Command {
        let mut c = Command::new("head");
        c.args(["-c", &n.to_string(), "/dev/zero"]);
        c
    }

    /// Like `prints`, then leaves `done` behind if it was not stopped.
    fn prints_then_marks(n: usize, done: &Path) -> Command {
        let mut c = Command::new("sh");
        c.arg("-c")
            .arg(format!("head -c {n} /dev/zero && : > \"$1\""))
            .arg("sh")
            .arg(done);
        c
    }

    /// Regression (review 2026-11-23, U-5): the size limit of a full
    /// download was left to curl's `--max-filesize`, which before curl 8.4
    /// does nothing when the server names no length, so a server could
    /// stream into the home folder for an hour. SAM now counts what it
    /// writes: one byte more than the published length stops the download
    /// and deletes the file; exactly the length is kept.
    #[test]
    fn a_full_download_stops_at_the_published_length_whatever_the_server_sends() {
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("new.AppImage");
        let done = t.path().join("sent-everything");
        let err = save_capped(prints_then_marks(3_000_000, &done), &dest, 1_000_000)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("more than the update description announced"),
            "{err}"
        );
        assert!(!dest.exists(), "the partial file was deleted");
        assert!(
            !done.exists(),
            "the download was stopped, not read to its end"
        );
        save_capped(prints(1_000_000), &dest, 1_000_000).unwrap();
        assert_eq!(std::fs::metadata(&dest).unwrap().len(), 1_000_000);
        // Never written through a link someone placed there.
        let victim = t.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let link = t.path().join("link.AppImage");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(save_capped(prints(10), &link, 100).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }

    /// Regression (review B2 S6, R90): a range request answered with the
    /// whole file (a server that ignores ranges) kept the first bytes and
    /// read the rest to its end, so each of up to 300 ranges was a whole
    /// download. One byte more than asked for is now an error at once, and
    /// the download is stopped, not read to its end; exactly the asked-for
    /// bytes are taken; a request that runs too long is stopped at its limit.
    #[test]
    fn a_range_answered_with_more_bytes_stops_at_once() {
        let t = tempfile::tempdir().unwrap();
        let done = t.path().join("sent-everything");
        let limit = Duration::from_secs(60);
        let started = Instant::now();
        let err = read_range(prints_then_marks(30_000_000, &done), limit, 1000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ignores range requests"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert!(
            !done.exists(),
            "the download was stopped, not read to its end"
        );
        assert_eq!(read_range(prints(1000), limit, 1000).unwrap().len(), 1000);
        let mut slow = Command::new("sh");
        slow.args(["-c", "sleep 30"]);
        let started = Instant::now();
        let err = read_range(slow, Duration::from_secs(1), 1000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not finish within 1 seconds"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    /// The update's time limit is named in minutes when it is whole
    /// minutes (an hour for SAM's updates), in seconds otherwise; and only
    /// curl's own time-out is named as the limit, so a download that
    /// fails for another reason near the end keeps its reason (review B2
    /// S6, R90).
    #[test]
    fn the_time_limit_is_named_only_when_it_ended_the_download() {
        let hour = Deadline::new(UPDATE_TIME_LIMIT).passed().to_string();
        assert!(hour.contains("within 60 minutes"), "{hour}");
        let short = Deadline::new(Duration::from_secs(3)).passed().to_string();
        assert!(short.contains("within 3 seconds"), "{short}");
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("new.AppImage");
        let exits = |code: u8| {
            let mut c = Command::new("sh");
            c.args([
                "-c",
                &format!("echo 'curl: ({code}) failed' >&2; exit {code}"),
            ]);
            c
        };
        let e = save_capped(exits(28), &dest, 100).unwrap_err();
        assert!(e.downcast_ref::<CurlTimedOut>().is_some(), "{e:#}");
        let e = save_capped(exits(22), &dest, 100).unwrap_err();
        assert!(e.downcast_ref::<CurlTimedOut>().is_none(), "{e:#}");
    }

    /// A failed download says why, in words, also after up to 64 KiB of
    /// other error output (2000 bytes here, more than a cut to 1 KiB
    /// would keep): curl's last line is kept (mutation run 2026-11-24:
    /// losing it went unnoticed, leaving "download failed:" with no
    /// reason).
    #[test]
    fn a_failed_download_says_why() {
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("new.AppImage");
        for noise in [0, 2000] {
            let mut cmd = Command::new("sh");
            cmd.args([
                "-c",
                "head -c \"$1\" /dev/zero | tr '\\0' x >&2; echo >&2; \
                 echo 'curl: (22) The requested URL returned error: 404' >&2; exit 22",
                "sh",
                &noise.to_string(),
            ]);
            let err = save_capped(cmd, &dest, 100).unwrap_err().to_string();
            assert!(
                err.contains("nothing published at that address"),
                "{noise}: {err}"
            );
        }
    }

    /// A mapping of the installed version is undone when dropped: the
    /// window runs for days and maps a whole AppImage at every update
    /// (mutation run 2026-11-24).
    #[test]
    fn a_mapped_file_is_unmapped_when_dropped() {
        use std::os::unix::ffi::OsStrExt;
        let t = tempfile::tempdir().unwrap();
        let f = std::fs::canonicalize(t.path())
            .unwrap()
            .join("installed.AppImage");
        std::fs::write(&f, vec![7u8; 64 * 1024]).unwrap();
        let mapped = || {
            std::fs::read_to_string("/proc/self/maps")
                .unwrap()
                .lines()
                .any(|l| l.as_bytes().ends_with(f.as_os_str().as_bytes()))
        };
        let m = Mapped::open(&f).unwrap();
        assert_eq!(m.bytes(), &[7u8; 64 * 1024][..]);
        assert!(mapped(), "mapped while open");
        drop(m);
        assert!(!mapped(), "unmapped when dropped");
    }

    /// Regression (review 2026-11-23, U-7): an answer longer than SAM
    /// reads was cut off and handed on as if complete, so a GitHub release
    /// description over 512 KiB failed as "GitHub's answer" every time.
    /// Now a whole answer may be longer, and one longer still is an error;
    /// for a range request (the first part of a .zsync), the first bytes
    /// are all SAM needs, also from a server that ignores the range.
    #[test]
    fn a_whole_answer_is_never_cut_off_and_handed_on_as_complete() {
        let err = answer_of(prints(2000), 1000, true).unwrap_err().to_string();
        assert!(err.contains("more than"), "{err}");
        // A limit under 1 MiB is named as it is, not as "0 MB".
        assert!(err.contains("more than 1000 B,"), "{err}");
        assert_eq!(answer_of(prints(1000), 1000, true).unwrap().len(), 1000);
        assert_eq!(answer_of(prints(2000), 1000, false).unwrap().len(), 1000);
    }

    /// A release with 600 files: each file's entry carries its
    /// uploader, so the description is well over 512 KiB (review
    /// 2026-11-23, U-7). It is read whole and its update description found.
    #[test]
    fn a_release_with_hundreds_of_files_is_read_whole() {
        let uploader = serde_json::json!({
            "login": "builder", "id": 1, "node_id": "x".repeat(20),
            "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4",
            "url": "https://api.github.com/users/builder",
            "html_url": "https://github.com/builder",
            "followers_url": "https://api.github.com/users/builder/followers",
            "repos_url": "https://api.github.com/users/builder/repos",
            "events_url": "https://api.github.com/users/builder/events{/privacy}",
            "type": "User", "site_admin": false
        });
        let mut assets: Vec<serde_json::Value> = (0..600)
            .map(|i| {
                serde_json::json!({
                    "name": format!("App-1.0-plugin{i}-x86_64.tar.gz"),
                    "browser_download_url": format!("https://github.com/o/r/releases/download/v1/App-1.0-plugin{i}-x86_64.tar.gz"),
                    "uploader": uploader, "label": "", "state": "uploaded",
                    "content_type": "application/gzip", "size": 1000 + i,
                    "download_count": i, "created_at": "2026-11-10T10:00:00Z",
                    "updated_at": "2026-11-10T10:00:00Z"
                })
            })
            .collect();
        assets.push(serde_json::json!({
            "name": "App-1.0-x86_64.AppImage.zsync",
            "browser_download_url": "https://github.com/o/r/releases/download/v1/App-1.0-x86_64.AppImage.zsync",
            "uploader": uploader
        }));
        let release = serde_json::json!({
            "tag_name": "v1", "html_url": "https://github.com/o/r/releases/tag/v1",
            "body": "notes ".repeat(20_000), "assets": assets
        });
        let t = tempfile::tempdir().unwrap();
        let file = t.path().join("release.json");
        std::fs::write(&file, serde_json::to_vec(&release).unwrap()).unwrap();
        assert!(std::fs::metadata(&file).unwrap().len() > 512 * 1024);
        let mut cat = Command::new("cat");
        cat.arg(&file);
        let got = answer_of(cat, MAX_RELEASE_ANSWER, true).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&got).unwrap();
        assert_eq!(
            release_zsyncs(&json, "App-*x86_64.AppImage.zsync", "x86_64"),
            vec!["https://github.com/o/r/releases/download/v1/App-1.0-x86_64.AppImage.zsync"]
        );
    }

    /// Regression (review 2026-11-23, U-8): with a pattern that matches the
    /// builds for every processor, the release's first file was taken, so
    /// an x86-64 computer could get the ARM build. The builds for this
    /// computer's processor come first, those naming another one last.
    #[test]
    fn release_files_for_this_processor_come_first() {
        let release = serde_json::json!({ "assets": [
            {"name": "App-2.0-aarch64.AppImage.zsync", "browser_download_url": "https://x/arm"},
            {"name": "App-2.0.AppImage.zsync", "browser_download_url": "https://x/plain"},
            {"name": "App-2.0-x86_64.AppImage.zsync", "browser_download_url": "https://x/intel"},
            {"name": "App-2.0-x86_64.AppImage", "browser_download_url": "https://x/file"},
        ]});
        assert_eq!(
            release_zsyncs(&release, "App-*.AppImage.zsync", "x86_64"),
            vec!["https://x/intel", "https://x/plain", "https://x/arm"]
        );
        assert_eq!(
            release_zsyncs(&release, "App-*.AppImage.zsync", "aarch64"),
            vec!["https://x/arm", "https://x/plain", "https://x/intel"]
        );
        assert_eq!(arch_rank("App-amd64.AppImage", "x86_64"), 0);
        assert_eq!(arch_rank("App-arm64.AppImage", "x86_64"), 2);
        assert_eq!(
            arch_rank("Appx64tool.AppImage", "x86_64"),
            1,
            "whole words only"
        );
    }

    /// Update downloads use HTTPS only; HTTP and file addresses are refused.
    #[test]
    fn updates_are_downloaded_over_https_only() {
        assert!(fetch("http://example.org/App.zsync", None).is_err());
        assert!(fetch("file:///etc/passwd", None).is_err());
    }
}
