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
use sha1::{Digest, Sha1};

/// The most read from any answer.
const MAX_ANSWER: usize = 512 * 1024;

/// Checks `appimage` against its published version.
pub fn check(appimage: &Path) -> UpdateStatus {
    let now = sam_core::util::now();
    let Some(source) = update_info::read(appimage) else {
        return UpdateStatus {
            state: UpdateState::Unsupported,
            detail: "This AppImage does not say where updates are published.".into(),
            checked_at: now,
            ..Default::default()
        };
    };
    match check_source(appimage, &source) {
        Ok(mut s) => {
            s.checked_at = now;
            s
        }
        Err(e) => UpdateStatus { state: UpdateState::Failed, detail: format!("The update check failed: {e:#}"), checked_at: now, ..Default::default() },
    }
}

fn check_source(appimage: &Path, source: &UpdateSource) -> Result<UpdateStatus> {
    // Candidate .zsync files: one fixed address, or every matching file of
    // a GitHub release (releases often hold rebuilds or variants side by side).
    let (zsyncs, release, page) = match source {
        UpdateSource::Zsync { url } => (vec![url.clone()], None, url.strip_suffix(".zsync").map(str::to_string)),
        UpdateSource::GithubRelease { owner, repo, tag, pattern } => {
            let api = if tag == "latest" {
                format!("https://api.github.com/repos/{owner}/{repo}/releases/latest")
            } else {
                format!("https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}")
            };
            let json: serde_json::Value = serde_json::from_slice(&fetch(&api, None)?).context("GitHub's answer")?;
            let tag_name = json.get("tag_name").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let page = json.get("html_url").and_then(|v| v.as_str()).map(str::to_string);
            let urls: Vec<String> = json
                .get("assets")
                .and_then(|a| a.as_array())
                .into_iter()
                .flatten()
                .filter(|x| x.get("name").and_then(|n| n.as_str()).is_some_and(|n| update_info::matches(pattern, n)))
                .filter_map(|x| x.get("browser_download_url").and_then(|v| v.as_str()).map(str::to_string))
                .take(4)
                .collect();
            if urls.is_empty() {
                bail!("release {tag_name} has no file matching {pattern}");
            }
            (urls, Some(tag_name), page)
        }
    };
    let local = sha1_of(appimage)?;
    let mut newest = None;
    for url in &zsyncs {
        let header = zsync_header(&fetch(url, Some(16 * 1024))?)?;
        if header.sha1.eq_ignore_ascii_case(&local) {
            return Ok(UpdateStatus {
                state: UpdateState::Current,
                latest: header.filename.or(release),
                download_page: page.filter(|p| p.starts_with("https://")),
                detail: "This is the newest published version.".into(),
                checked_at: 0,
            });
        }
        newest.get_or_insert(header);
    }
    let file = newest.and_then(|h| h.filename);
    let name = match (&file, &release) {
        (Some(f), Some(r)) => format!("{f} (release {r})"),
        (Some(f), None) => f.clone(),
        (None, Some(r)) => format!("release {r}"),
        (None, None) => "a newer version".into(),
    };
    Ok(UpdateStatus {
        state: UpdateState::Available,
        detail: format!(
            "{} is published. Download it and replace the AppImage file; SAM then unpacks it again and keeps your settings.",
            sam_core::util::display_safe(&name, 160)
        ),
        latest: file.or(release),
        download_page: page.filter(|p| p.starts_with("https://")),
        checked_at: 0,
    })
}

/// The fields of a zsync header SAM needs.
struct ZsyncHeader {
    sha1: String,
    filename: Option<String>,
}

fn zsync_header(data: &[u8]) -> Result<ZsyncHeader> {
    let text = String::from_utf8_lossy(data);
    let mut sha1 = None;
    let mut filename = None;
    for line in text.lines() {
        if line.is_empty() {
            break; // end of the header; block checksums follow
        }
        match line.split_once(": ") {
            Some(("SHA-1", v)) if v.len() == 40 && v.chars().all(|c| c.is_ascii_hexdigit()) => sha1 = Some(v.to_string()),
            Some(("Filename", v)) => filename = Some(sam_core::util::display_safe(v, 200)),
            _ => {}
        }
    }
    let Some(sha1) = sha1 else { bail!("the update description (.zsync) has no SHA-1") };
    Ok(ZsyncHeader { sha1, filename })
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
    Ok(format!("{:x}", h.finalize()))
}

/// GETs `url` (HTTPS only) and returns at most `limit` bytes (or
/// `MAX_ANSWER`). With a limit, only that range is asked for.
fn fetch(url: &str, limit: Option<usize>) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        bail!("the update address is not HTTPS ({})", sam_core::util::display_safe(url, 120));
    }
    let curl = sam_core::util::which("curl").context("curl is not installed")?;
    let mut cmd = Command::new(curl);
    cmd.args(["--silent", "--show-error", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https"])
        .args(["--max-redirs", "5", "--connect-timeout", "10", "--max-time", "30"])
        .args(["--user-agent", "SAM-AppImage-update-check", "--header", "Accept: application/json, */*"]);
    if let Some(n) = limit {
        cmd.args(["--range", &format!("0-{}", n - 1)]);
    }
    cmd.arg("--").arg(url).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().context("starting curl")?;
    let max = limit.unwrap_or(MAX_ANSWER);
    let mut out = Vec::new();
    child.stdout.take().context("curl output")?.take(max as u64).read_to_end(&mut out)?;
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
        bail!("{}", sam_core::util::display_safe(err.trim().trim_start_matches("curl: "), 200));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_zsync_header() {
        let z = b"zsync: 0.6.2\nFilename: App-2.0-x86_64.AppImage\nMTime: Tue, 10 Nov 2026 10:00:00 +0000\nBlocksize: 2048\nLength: 123\nSHA-1: 0123456789abcdef0123456789abcdef01234567\n\n\x00\x01binary";
        let h = zsync_header(z).unwrap();
        assert_eq!(h.sha1, "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(h.filename.as_deref(), Some("App-2.0-x86_64.AppImage"));
        assert!(zsync_header(b"zsync: 0.6.2\n\nSHA-1: 0123456789abcdef0123456789abcdef01234567\n").is_err(), "only the header counts");
    }

    #[test]
    fn only_https() {
        assert!(fetch("http://example.org/App.zsync", None).is_err());
        assert!(fetch("file:///etc/passwd", None).is_err());
    }
}
