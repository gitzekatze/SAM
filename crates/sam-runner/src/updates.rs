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

use anyhow::{bail, Context, Result};
use sam_core::model::{UpdateState, UpdateStatus};
use sam_detect::update_info::{self, UpdateSource};
// SHA-1 only because the zsync format names the published file by it; it
// catches damaged downloads, not tampering (the signature check does that).
use sha1::{Digest, Sha1};

/// The most read from any answer.
const MAX_ANSWER: usize = 512 * 1024;
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

/// Checks `appimage` against its published version.
pub fn check(appimage: &Path) -> UpdateStatus {
    let now = sam_core::util::now();
    let Some(source) = update_info::read(appimage) else {
        return UpdateStatus {
            state: UpdateState::Unsupported,
            detail: sam_core::i18n::tr("This AppImage does not say where updates are published."),
            checked_at: now,
            ..Default::default()
        };
    };
    match check_source(appimage, &source) {
        Ok(mut s) => {
            s.checked_at = now;
            s
        }
        Err(e) => UpdateStatus {
            state: UpdateState::Failed,
            detail: sam_core::i18n::trf(
                "The update check failed: {error}",
                &[("error", &format!("{e:#}"))],
            ),
            checked_at: now,
            ..Default::default()
        },
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
    let source = update_info::read(appimage).context(sam_core::i18n::tr(
        "this AppImage does not say where updates are published",
    ))?;
    newest_from(appimage, &source)
}

fn newest_from(appimage: &Path, source: &UpdateSource) -> Result<Option<Published>> {
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
            let urls: Vec<String> = json
                .get("assets")
                .and_then(|a| a.as_array())
                .into_iter()
                .flatten()
                .filter(|x| {
                    x.get("name")
                        .and_then(|n| n.as_str())
                        .is_some_and(|n| update_info::matches(pattern, n))
                })
                .filter_map(|x| {
                    x.get("browser_download_url")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .take(4)
                .collect();
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
    let local = sha1_of(appimage)?;
    let mut first = None;
    for url in &zsyncs {
        let h = zsync_header(&fetch(url, Some(16 * 1024))?)?;
        if h.sha1.eq_ignore_ascii_case(&local) {
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

fn check_source(appimage: &Path, source: &UpdateSource) -> Result<UpdateStatus> {
    Ok(match newest_from(appimage, source)? {
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

/// Downloads the new version to `dest`, reusing unchanged blocks of `old`
/// (zsync) when that saves most of the download; otherwise, or when anything
/// goes wrong with that, the whole file. Either way the result must match the
/// published SHA-1.
pub fn download_update(p: &Published, old: &Path, dest: &Path) -> Result<Fetched> {
    match download_delta(p, old, dest) {
        Ok(Some(f)) => return Ok(f),
        Ok(None) | Err(_) => {
            let _ = std::fs::remove_file(dest);
        }
    }
    download(p, dest)?;
    Ok(Fetched::Full {
        total: std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0),
    })
}

/// `Ok(None)` when a delta would not save enough (most of the file changed,
/// or it would take too many requests).
fn download_delta(p: &Published, old: &Path, dest: &Path) -> Result<Option<Fetched>> {
    let ctl = crate::zsync::parse(&fetch(&p.zsync_url, Some(64 << 20))?)?;
    if ctl.sha1 != p.sha1 {
        bail!(
            "{}",
            sam_core::i18n::tr("the update description changed while reading it")
        );
    }
    let old_data = std::fs::read(old)?;
    let plan = crate::zsync::plan(&ctl, &old_data);
    let ranges = crate::zsync::missing_ranges(&ctl, &plan, 64 * 1024);
    let bytes: u64 = ranges.iter().map(|(s, e)| e - s).sum();
    if ranges.len() > 300 || bytes * 10 > ctl.length * 7 {
        return Ok(None);
    }
    crate::zsync::assemble(&ctl, &old_data, &plan, &ranges, dest, |s, e| {
        fetch_range(&p.file_url, s, e)
    })?;
    Ok(Some(Fetched::Delta {
        bytes,
        total: ctl.length,
    }))
}

/// Bytes `start..end` of `url` (an HTTP range request). At most that many
/// bytes are kept, whatever the server sends.
fn fetch_range(url: &str, start: u64, end: u64) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        bail!("{}", sam_core::i18n::tr("not HTTPS"));
    }
    let want = end.saturating_sub(start);
    let mut cmd = curl(300)?;
    cmd.args(["--speed-limit", "1024", "--speed-time", "60"])
        .args(["--range", &format!("{}-{}", start, end.saturating_sub(1))])
        .arg("--")
        .arg(url);
    let (st, out) = sam_core::util::output_within(
        &mut cmd,
        std::time::Duration::from_secs(310),
        usize::try_from(want).unwrap_or(usize::MAX),
    )?;
    if !st.success() {
        bail!(
            "{}",
            sam_core::i18n::trf(
                "downloading the changed parts failed: {reason}",
                &[("reason", &format!("curl {st}"))]
            )
        );
    }
    Ok(out)
}

pub fn download(p: &Published, dest: &Path) -> Result<()> {
    let res = download_inner(p, dest);
    if res.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    res
}

fn download_inner(p: &Published, dest: &Path) -> Result<()> {
    if !p.file_url.starts_with("https://") {
        bail!(
            "{}",
            sam_core::i18n::tr("the update file is not offered over HTTPS")
        );
    }
    // An hour for the whole file; the speed limit ends a stalled one sooner.
    let mut cmd = curl(3600)?;
    cmd.args(["--speed-limit", "1024", "--speed-time", "60"]);
    // A little more than the published length (or SAM's ceiling) is the
    // most curl writes; `saturating_add`: a Length of u64::MAX wrapped.
    let cap = p.length.unwrap_or(MAX_DOWNLOAD).min(MAX_DOWNLOAD);
    cmd.args(["--max-filesize", &cap.saturating_add(1).to_string()]);
    let out = cmd
        .arg("--output")
        .arg(dest)
        .arg("--")
        .arg(&p.file_url)
        .stdin(Stdio::null())
        .output()
        .context(sam_core::i18n::tr("starting curl"))?;
    if !out.status.success() {
        bail!(
            "download failed: {}",
            curl_error(&String::from_utf8_lossy(&out.stderr))
        );
    }
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

/// GETs `url` (HTTPS only) and returns at most `limit` bytes (or
/// `MAX_ANSWER`). With a limit, only that range is asked for.
fn fetch(url: &str, limit: Option<usize>) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        bail!(
            "{}",
            sam_core::i18n::trf(
                "the update address is not HTTPS ({address})",
                &[("address", &sam_core::util::display_safe(url, 120))]
            )
        );
    }
    let mut cmd = curl(30)?;
    cmd.args(["--header", "Accept: application/json, */*"]);
    if let Some(n) = limit {
        cmd.args(["--range", &format!("0-{}", n - 1)]);
    }
    cmd.arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context(sam_core::i18n::tr("starting curl"))?;
    let max = limit.unwrap_or(MAX_ANSWER);
    let mut out = Vec::new();
    child
        .stdout
        .take()
        .context(sam_core::i18n::tr("curl output"))?
        .take(max as u64)
        .read_to_end(&mut out)?;
    // Servers that ignore the range send everything: enough was read.
    if out.len() >= max {
        let _ = child.kill();
        let _ = child.wait();
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

    /// Update downloads use HTTPS only; HTTP and file addresses are refused.
    #[test]
    fn updates_are_downloaded_over_https_only() {
        assert!(fetch("http://example.org/App.zsync", None).is_err());
        assert!(fetch("file:///etc/passwd", None).is_err());
    }
}
