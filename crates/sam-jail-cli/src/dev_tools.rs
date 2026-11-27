//! The `sam-jail dev` commands only tests and the release process use:
//! test AppImages, the benchmark, update information, .zsync files and
//! signatures. They are built into development builds and into builds with
//! the `dev-tools` feature, never into release builds or packages (see
//! docs/testing.md). `dev peek` and `dev extract-squashfs` stay in every
//! build: SAM runs them inside its unpack sandbox.

use super::*;

#[derive(Subcommand)]
pub(crate) enum ToolCmd {
    /// Build a synthetic test AppImage.
    MakeFixture {
        path: PathBuf,
        #[arg(long, default_value = "Hello")]
        name: String,
        #[arg(long, default_value = "Utility;")]
        categories: String,
        /// Use this file as the AppRun script.
        #[arg(long)]
        apprun: Option<PathBuf>,
        /// A terminal program (`Terminal=true` in its menu entry).
        #[arg(long)]
        terminal: bool,
    },
    /// Time the parts of SAM on a realistic test AppImage (for the version
    /// report). Uses a fresh folder under $TMPDIR and removes it.
    Bench {
        /// How many apps to create for the Permissions-page measurement.
        #[arg(long, default_value_t = 120)]
        apps: usize,
    },
    /// Write update information into an AppImage runtime (release builds).
    SetUpdateInfo { runtime: PathBuf, info: String },
    /// Write the .zsync update description of a file (release builds).
    MakeZsync {
        file: PathBuf,
        /// Address of the file, relative to the .zsync (usually its name).
        #[arg(long)]
        url: Option<String>,
        /// Output (default: FILE.zsync).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Sign an AppImage with a GnuPG key (release builds): the signature
    /// goes into the AppImage, and is checked afterwards.
    SignAppimage {
        file: PathBuf,
        /// The key's full fingerprint.
        #[arg(long)]
        key: String,
    },
}

pub(crate) fn run(cmd: ToolCmd, out: &Out) -> Result<()> {
    match cmd {
        ToolCmd::Bench { apps } => {
            let r = crate::bench::bench(apps)?;
            out.emit(&r, || {
                for m in &r {
                    let ms = serde_json::to_value(m)
                        .ok()
                        .and_then(|v| v["best_ms"].as_f64());
                    let v = serde_json::to_value(m).unwrap_or_default();
                    match ms {
                        Some(ms) => outln!(
                            "{:<16} {:>10.3} ms  {}",
                            v["key"].as_str().unwrap_or(""),
                            ms,
                            v["what"].as_str().unwrap_or("")
                        ),
                        None => outln!(
                            "{:<16} {:>13}  {}",
                            v["key"].as_str().unwrap_or(""),
                            "not here",
                            v["what"].as_str().unwrap_or("")
                        ),
                    }
                }
            });
        }
        ToolCmd::SetUpdateInfo { runtime, info } => {
            sam_detect::update_info::write(&runtime, &info)?;
            out.emit(&json!({"runtime": runtime, "info": info}), || {
                outln!(
                    "{}",
                    trf(
                        "Update information written to {file}.",
                        &[("file", &runtime.display())]
                    )
                )
            });
        }
        ToolCmd::MakeZsync {
            file,
            url,
            out: dest,
        } => {
            let name = file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .context(sam_core::i18n::tr("no file name"))?;
            let modified = std::fs::metadata(&file)?
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let mtime = sam_core::util::format_utc_date(modified);
            let data =
                sam_runner::zsync::make(&file, &name, url.as_deref().unwrap_or(&name), &mtime)?;
            let dest = dest.unwrap_or_else(|| file.with_file_name(format!("{name}.zsync")));
            std::fs::write(&dest, data)?;
            out.emit(&json!({"zsync": dest}), || {
                outln!(
                    "{}",
                    sam_core::i18n::trf("Wrote {path}", &[("path", &dest.display())])
                )
            });
        }
        ToolCmd::SignAppimage { file, key } => {
            sam_detect::signature::sign_embedded(&file, None, &key)?;
            // SAM's own file, just signed here: GnuPG reads only our key.
            let sig = sam_detect::signature::check(&file, &sam_detect::signature::GnuPg::Direct);
            let fp = sig.fingerprint.clone().unwrap_or_default();
            if sig.state != sam_core::model::SignatureState::Valid || !fp.eq_ignore_ascii_case(&key)
            {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "the signature in {file} does not check out: {detail}",
                        &[("file", &file.display()), ("detail", &sig.detail)]
                    )
                );
            }
            out.emit(&json!({"path": file, "fingerprint": fp}), || {
                outln!(
                    "{}",
                    sam_core::i18n::trf(
                        "Signed {path} with {key}",
                        &[("path", &file.display()), ("key", &fp)]
                    )
                )
            });
        }
        ToolCmd::MakeFixture {
            path,
            name,
            categories,
            apprun,
            terminal,
        } => {
            let mut spec = sam_intake::testkit::FixtureSpec::hello(&name);
            spec.categories = categories;
            spec.terminal = terminal;
            if let Some(a) = apprun {
                spec.apprun = std::fs::read_to_string(a)?;
            }
            sam_intake::testkit::build(&path, &spec)?;
            out.emit(&json!({"path": path}), || {
                outln!(
                    "{}",
                    sam_core::i18n::trf("Wrote {path}", &[("path", &path.display())])
                )
            });
        }
    }
    Ok(())
}
