//! `sam-jail config …`

use super::*;

pub(crate) fn config_cmd(app: &Sam, out: &Out, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Show => {
            let c = &app.config;
            out.emit(c, || print!("{}", toml::to_string_pretty(c).unwrap_or_default()));
        }
        ConfigCmd::Get { key } => {
            let v = app.config.get_key(&key)?;
            out.emit(&v, || println!("{v}"));
        }
        ConfigCmd::Set { key, value } => {
            let mut c = app.config.clone();
            c.set_key(&key, &value)?;
            c.save(&app.paths)?;
            let v = c.get_key(&key)?;
            out.emit(&json!({"key": key, "value": v}), || println!("{key} = {v}"));
        }
        ConfigCmd::Put => {
            let c: Config = serde_json::from_str(&read_stdin()?).context("expected the configuration as JSON on stdin")?;
            c.validate()?;
            c.save(&app.paths)?;
            out.emit(&c, || println!("Configuration saved"));
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
                    println!("{k:<14} {}", val.as_str().unwrap_or_default());
                }
            });
        }
    }
    Ok(())
}
