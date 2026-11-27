//! `sam-jail config …`

use super::*;

pub(crate) fn config_cmd(app: &Sam, out: &Out, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Show => {
            let c = &app.config;
            out.emit(c, || {
                out!("{}", toml::to_string_pretty(c).unwrap_or_default())
            });
        }
        ConfigCmd::Get { key } => {
            let v = app.config.get_key(&key)?;
            out.emit(&v, || outln!("{v}"));
        }
        ConfigCmd::Set { key, value, yes } => {
            let mut c = app.config.clone();
            c.set_key(&key, &value)?;
            confirm_turned_off(&app.config, &c, yes)?;
            c.save(&app.paths)?;
            let v = c.get_key(&key)?;
            out.emit(&json!({"key": key, "value": v}), || outln!("{key} = {v}"));
        }
        ConfigCmd::Put { yes } => {
            let c: Config = serde_json::from_str(&read_stdin()?).context(sam_core::i18n::tr(
                "expected the configuration as JSON on stdin",
            ))?;
            c.validate()?;
            confirm_turned_off(&app.config, &c, yes)?;
            c.save(&app.paths)?;
            out.emit(&c, || {
                outln!("{}", sam_core::i18n::tr("Configuration saved"))
            });
        }
        ConfigCmd::Path => {
            let v: Value = json!({
                "config_file": app.paths.config_file(),
                "data_dir": app.paths.data_dir,
                "extracted": app.extracted_root(),
                "presets": app.paths.presets_dir(),
                "logs": app.paths.logs_dir(),
                "applications": app.paths.applications_dir,
            });
            out.emit(&v, || {
                for (k, val) in v.as_object().into_iter().flatten() {
                    outln!("{k:<14} {}", val.as_str().unwrap_or_default());
                }
            });
        }
    }
    Ok(())
}

/// A change that turns off a protection for every app (Landlock, the
/// syscall filter) is saved only with `--yes`, as the window asks before
/// it (audit G-F11): one pasted line or a script turned it off unasked.
fn confirm_turned_off(old: &Config, new: &Config, yes: bool) -> Result<()> {
    let off = old.protections_turned_off(new);
    if off.is_empty() || yes {
        return Ok(());
    }
    let exposed: Vec<String> = off
        .iter()
        .map(|key| match *key {
            "security.experimental_landlock" => sam_core::i18n::tr("Landlock: apps lose its write protection and the block on abstract sockets outside the sandbox (such as XWayland's), so they can reach more of this computer than their settings say."),
            "security.baseline_seccomp" => sam_core::i18n::tr("The syscall filter: apps can use kernel interfaces no desktop app needs (modules, BPF, perf, keyrings, io_uring, terminal injection), which attacks on the kernel use."),
            other => other.to_string(),
        })
        .collect();
    Err(sam_core::error::CodedError::new(
        "config-needs-yes",
        sam_core::i18n::trf(
            "This change turns off a protection for every sandboxed app. {protections} Nothing was saved. Look at it, then repeat it with --yes, or make it in SAM's window, which asks.",
            &[("protections", &exposed.join(" "))],
        ),
    )
    .into())
}
