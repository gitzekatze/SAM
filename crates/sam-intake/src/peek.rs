//! Read an AppImage's name, description and icon **without** unpacking or
//! running it. Used by the overview, which lists AppImages before any of
//! them is sandboxed.
//!
//! Only Type 2 (SquashFS) images are read: the directory table plus the
//! top-level desktop file and one icon. Type 1 images fall back to the
//! file name.

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use backhand::{FilesystemReader, InnerNode};
use sam_core::model::AppImageMetadata;
use sam_core::AppImageType;
use sam_detect::appimage::inspect;

use crate::metadata::{
    choose_desktop_file, icon_candidates, metadata_from_desktop, safe_icon, IconFormat,
    MAX_ICON_BYTES,
};

const MAX_DESKTOP: u64 = 256 * 1024;
/// How long reading one AppImage's name and icon may take in its sandbox.
const PEEK_SECONDS: u64 = 15;
/// How much memory the sandbox that reads it may use.
const PEEK_MEMORY: u64 = 1024 * 1024 * 1024;

pub struct Peek {
    pub metadata: AppImageMetadata,
    pub icon: Option<(Vec<u8>, IconFormat)>,
}

pub fn peek(path: &Path) -> Result<Peek> {
    // The SquashFS reader may panic on a damaged or hostile image instead of
    // returning an error (found by tests/fuzz.rs). SAM reads names and icons
    // in its own process for every AppImage in the searched folders, so one
    // such file must not take down the whole list: treat it as unreadable.
    std::panic::catch_unwind(|| peek_unguarded(path)).unwrap_or_else(|_| {
        Err(anyhow!(
            "{}",
            sam_core::i18n::tr(
                "the AppImage's SquashFS image is damaged, so SAM cannot read its name and icon"
            )
        ))
    })
}

/// [`peek`] without its guard against panics of the SquashFS reader: for the
/// fuzz tests, which must see every panic to tell SAM's own from the
/// reader's (audit: the guard hid them from the tests).
#[doc(hidden)]
pub fn peek_unguarded(path: &Path) -> Result<Peek> {
    let info = inspect(path)?;
    // Names and icons are read from SquashFS only; DwarFS images show their
    // file name until they are unpacked.
    if info.kind != AppImageType::Type2
        || info.payload != sam_detect::appimage::PayloadFormat::Squashfs
    {
        return Ok(Peek {
            metadata: AppImageMetadata::default(),
            icon: None,
        });
    }
    let offset = info.payload_offset.context(sam_core::i18n::tr(
        "the app image inside the AppImage was not found",
    ))?;
    let reader = BufReader::new(std::fs::File::open(path)?);
    let sqfs =
        FilesystemReader::from_reader_with_offset(reader, offset).map_err(|e| anyhow!("{e}"))?;

    // Index the directory table: image path (relative, no leading `/`) -> node.
    let mut index = HashMap::new();
    for (i, node) in sqfs.files().enumerate() {
        if let Some(rel) = relative(&node.fullpath) {
            index.insert(rel, i);
        }
    }
    let nodes: Vec<_> = sqfs.files().collect();

    // Follow symlinks inside the image (a few hops, never outside it).
    let resolve = |start: &Path| -> Option<usize> {
        let mut cur = start.to_path_buf();
        for _ in 0..8 {
            let i = *index.get(&cur)?;
            match &nodes[i].inner {
                InnerNode::Symlink(s) => {
                    let base = if s.link.is_absolute() {
                        PathBuf::new()
                    } else {
                        cur.parent().unwrap_or(Path::new("")).to_path_buf()
                    };
                    cur = normalize(&base.join(&s.link))?;
                }
                InnerNode::File(_) => return Some(i),
                _ => return None,
            }
        }
        None
    };
    let read = |i: usize, max: u64| -> Option<Vec<u8>> {
        let InnerNode::File(f) = &nodes[i].inner else {
            return None;
        };
        let mut buf = Vec::new();
        sqfs.file(f)
            .reader()
            .take(max + 1)
            .read_to_end(&mut buf)
            .ok()?;
        (buf.len() as u64 <= max).then_some(buf)
    };

    // The same desktop file the unpacked app will use (audit I-F8).
    let metadata = choose_desktop_file(index.keys().cloned(), |rel| resolve(rel).is_some())
        .and_then(|rel| Some((resolve(&rel)?, rel)))
        .and_then(|(i, rel)| {
            Some(metadata_from_desktop(
                &String::from_utf8_lossy(&read(i, MAX_DESKTOP)?),
                &rel.display().to_string(),
            ))
        })
        .unwrap_or_default();

    let icon = icon_candidates(&metadata.icon_name)
        .iter()
        .filter_map(|rel| resolve(rel))
        .filter_map(|i| read(i, MAX_ICON_BYTES as u64))
        .find_map(|data| safe_icon(&data).map(|fmt| (data, fmt)));
    Ok(Peek { metadata, icon })
}

/// What the sandboxed reader hands back, next to the icon file.
#[derive(serde::Serialize, serde::Deserialize)]
struct PeekFile {
    metadata: AppImageMetadata,
    icon: Option<String>,
}

/// Entry point of `sam-jail dev peek FILE OUT` (runs inside the sandbox):
/// reads `file` and writes `peek.json` and the icon into `out`.
pub fn peek_entry(file: &Path, out: &Path) -> Result<()> {
    let p = peek(file)?;
    let icon = p.icon.map(|(data, fmt)| {
        let _ = std::fs::write(out.join("icon"), data);
        fmt.ext().to_string()
    });
    std::fs::write(
        out.join("peek.json"),
        serde_json::to_vec(&PeekFile {
            metadata: p.metadata,
            icon,
        })?,
    )?;
    Ok(())
}

/// Reads an AppImage's name and icon like [`peek`], but inside the sandbox
/// SAM unpacks in: no network, nothing of the home, the baseline syscall
/// filter, at most [`PEEK_SECONDS`] and [`PEEK_MEMORY`]. The overview reads
/// every AppImage in the scanned folders before anyone agreed to anything;
/// a crafted image that makes the reader run out of memory, hang or crash
/// then ends only that sandbox, not SAM (audit I-F7). What comes back is
/// checked again here.
pub fn peek_isolated(iso: &crate::extract::Isolation, file: &Path) -> Result<Peek> {
    use std::os::unix::process::CommandExt;
    let out = scratch_dir()?;
    let result = (|| {
        let mut c = crate::extract::isolated(iso, file, &out, &iso.self_exe)?;
        c.arg(&iso.self_exe)
            .args(["dev", "peek"])
            .arg(file)
            .arg(&out)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: runs between fork and exec and calls only setrlimit, which
        // is async-signal-safe.
        unsafe {
            c.pre_exec(|| {
                let lim = libc::rlimit {
                    rlim_cur: PEEK_MEMORY,
                    rlim_max: PEEK_MEMORY,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let limits = crate::normalize::Limits {
            max_seconds: PEEK_SECONDS,
            ..Default::default()
        };
        let st = crate::extract::wait_with_timeout(c.spawn()?, &limits, std::time::Instant::now())?;
        if !st.success() {
            return Err(anyhow!(
                "{}",
                sam_core::i18n::tr("SAM could not read the AppImage's name and icon")
            ));
        }
        let reply: PeekFile = serde_json::from_slice(&sam_core::util::read_regular(
            &out.join("peek.json"),
            64 * 1024,
        )?)?;
        let icon = reply
            .icon
            .and_then(|_| {
                sam_core::util::read_regular(&out.join("icon"), MAX_ICON_BYTES as u64).ok()
            })
            .and_then(|data| safe_icon(&data).map(|fmt| (data, fmt)));
        Ok(Peek {
            metadata: reply.metadata,
            icon,
        })
    })();
    let _ = std::fs::remove_dir_all(&out);
    result
}

/// A new, empty folder of SAM's own for one read.
fn scratch_dir() -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "sam-peek-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&d)?;
    Ok(d)
}

fn relative(p: &Path) -> Option<PathBuf> {
    normalize(p.strip_prefix("/").unwrap_or(p))
}

/// Lexically normalize a path inside the image; `None` if it climbs out.
fn normalize(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::CurDir | Component::RootDir => {}
            Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;

    /// The name and icon of an AppImage are read without unpacking or running it.
    #[test]
    fn peeks_name_and_icon_without_extracting() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("Hello.AppImage");
        let mut spec = testkit::FixtureSpec::hello("Hello");
        spec.categories = "Graphics;".into();
        testkit::build(&img, &spec).unwrap();
        let p = peek(&img).unwrap();
        assert_eq!(p.metadata.name, "Hello");
        assert_eq!(p.metadata.categories, vec!["Graphics"]);
        assert!(p.icon.is_some(), "icon via .DirIcon or the named icon");
    }

    /// Icon paths from the AppImage cannot climb out of the unpacked app.
    #[test]
    fn icon_paths_cannot_climb_out_of_the_app() {
        assert_eq!(
            normalize(Path::new("usr/../a.png")),
            Some(PathBuf::from("a.png"))
        );
        assert_eq!(normalize(Path::new("../etc/passwd")), None);
    }
}
