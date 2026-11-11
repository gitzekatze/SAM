//! `sam-jail preset …`

use super::*;

pub(crate) fn preset_cmd(app: &Sam, out: &Out, cmd: PresetCmd) -> Result<()> {
    let store = PresetStore::new(&app.paths);
    match cmd {
        PresetCmd::List => {
            let all = sam_profile::all_presets(&app.paths)?;
            out.emit(&all, || {
                for p in &all {
                    println!("{:<26} {:<10} {}{}", p.name, risk_str(p.risk), p.description, if p.builtin { "  (built-in)" } else { "" });
                }
            });
        }
        PresetCmd::Show { name } => {
            let p = sam_profile::find_preset(&app.paths, &name)?.with_context(|| format!("unknown preset '{name}'"))?;
            out.emit(&p, || print!("{}", preset_to_toml(&p).unwrap_or_default()));
        }
        PresetCmd::Apply { name, app: q, yes } => {
            let r = app.apply_preset(&q, &name, yes)?;
            out.emit(&r, || {
                let c = &r.check;
                for s in &c.removes_needed {
                    println!("  {} removes {s}, which the app likely needs", paint("warning:", "33"));
                }
                for s in &c.adds_dangerous {
                    println!("  {} adds high-risk permission: {s}", paint("warning:", "31"));
                }
                if r.applied {
                    println!("Applied '{}' (risk {} → {})", r.preset, c.risk_before, c.risk_after);
                } else {
                    println!("Not applied. Re-run with --yes to confirm.");
                }
            });
        }
        PresetCmd::Check { name, appimage, current_stdin } => {
            let current: Option<PermissionSet> = if current_stdin { Some(serde_json::from_str(&read_stdin()?).context("expected a PermissionSet as JSON on stdin")?) } else { None };
            let (p, c) = app.check_preset_preview(&appimage, &name, current)?;
            out.emit(&json!({"preset": p.name, "permissions": p.permissions, "check": c, "needs_confirmation": c.needs_confirmation()}), || {
                for s in &c.removes_needed {
                    println!("  {} removes {s}, which the app likely needs", paint("warning:", "33"));
                }
                for s in &c.adds_dangerous {
                    println!("  {} adds high-risk permission: {s}", paint("warning:", "31"));
                }
                println!("'{}': risk {} → {}", p.name, c.risk_before, c.risk_after);
            });
        }
        PresetCmd::Save { app: q, name, description } => {
            let p = app.save_preset_from_app(&q, &name, &description)?;
            out.emit(&p, || println!("Saved preset '{}' ({})", p.name, p.risk));
        }
        PresetCmd::Delete { name } => {
            if sam_profile::builtin_presets().iter().any(|b| b.name.eq_ignore_ascii_case(&name)) && store.get(&name)?.is_none() {
                bail!("built-in presets cannot be deleted");
            }
            let ok = store.delete(&name)?;
            if !ok {
                bail!("no user preset named '{name}'");
            }
            out.emit(&json!({"deleted": name}), || println!("Deleted preset '{name}'"));
        }
        PresetCmd::Duplicate { name, new_name } => {
            let mut p = sam_profile::find_preset(&app.paths, &name)?.with_context(|| format!("unknown preset '{name}'"))?;
            if sam_profile::find_preset(&app.paths, &new_name)?.is_some() {
                bail!("a preset named '{new_name}' already exists");
            }
            p.name = new_name;
            p.builtin = false;
            p.created_at = 0;
            store.save(&mut p)?;
            out.emit(&p, || println!("Created preset '{}'", p.name));
        }
        PresetCmd::Import { file } => {
            let mut p = read_preset_file(&file)?;
            if sam_profile::builtin_presets().iter().any(|b| b.name.eq_ignore_ascii_case(&p.name)) {
                p.name = format!("{} (imported)", p.name);
            }
            let path = store.save(&mut p)?;
            out.emit(&p, || println!("Imported '{}' → {}", p.name, tildify(&path)));
        }
        PresetCmd::Export { name, file } => {
            let p = sam_profile::find_preset(&app.paths, &name)?.with_context(|| format!("unknown preset '{name}'"))?;
            let text = preset_to_toml(&p)?;
            match &file {
                Some(f) => std::fs::write(f, &text)?,
                None if !out.json => print!("{text}"),
                None => {}
            }
            out.emit(&json!({"toml": text, "file": file}), || {
                if let Some(f) = &file {
                    println!("Exported '{}' → {}", p.name, f.display());
                }
            });
        }
        PresetCmd::Put => {
            let input = read_stdin()?;
            let mut p: Preset = match serde_json::from_str::<Preset>(&input) {
                Ok(p) => p,
                Err(_) => parse_preset_toml(&input).context("expected a preset as JSON or TOML on stdin")?,
            };
            if sam_profile::builtin_presets().iter().any(|b| b.name.eq_ignore_ascii_case(&p.name)) {
                bail!("'{}' is a built-in preset; duplicate it to make changes", p.name);
            }
            if let Some(existing) = store.get(&p.name)? {
                p.created_at = existing.created_at;
            }
            store.save(&mut p)?;
            out.emit(&p, || println!("Saved preset '{}'", p.name));
        }
    }
    Ok(())
}
