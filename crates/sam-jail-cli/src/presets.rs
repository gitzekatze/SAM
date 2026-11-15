//! `sam-jail preset …`

use super::*;

pub(crate) fn preset_cmd(app: &Sam, out: &Out, cmd: PresetCmd) -> Result<()> {
    let store = PresetStore::new(&app.paths);
    match cmd {
        PresetCmd::List => {
            let all = sam_profile::all_presets(&app.paths)?;
            out.emit(&all, || {
                if all.is_empty() {
                    println!("You have no presets yet. Save an app's settings with `sam-jail preset save APP NAME`.");
                }
                for p in &all {
                    println!("{:<26} {:<10} {}", p.name, risk_str(p.risk), p.description);
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
        PresetCmd::Template => {
            let p = sam_profile::preset_template();
            out.emit(&p, || print!("{}", preset_to_toml(&p).unwrap_or_default()));
        }
        PresetCmd::Save { app: q, name, description } => {
            let p = app.save_preset_from_app(&q, &name, &description)?;
            out.emit(&p, || println!("Saved preset '{}' ({})", p.name, p.risk));
        }
        PresetCmd::Delete { name } => {
            let ok = store.delete(&name)?;
            if !ok {
                bail!("{}", sam_core::i18n::trf("no user preset named '{name}'", &[("name", &name)]));
            }
            out.emit(&json!({"deleted": name}), || println!("Deleted preset '{name}'"));
        }
        PresetCmd::Duplicate { name, new_name } => {
            let mut p = sam_profile::find_preset(&app.paths, &name)?.with_context(|| format!("unknown preset '{name}'"))?;
            if sam_profile::find_preset(&app.paths, &new_name)?.is_some() {
                bail!("{}", sam_core::i18n::trf("a preset named '{new_name}' already exists", &[("new_name", &new_name)]));
            }
            p.name = new_name;
            p.created_at = 0;
            store.save(&mut p)?;
            out.emit(&p, || println!("Created preset '{}'", p.name));
        }
        PresetCmd::Import { file } => {
            let mut p = read_preset_file(&file)?;
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
            if let Some(existing) = store.get(&p.name)? {
                p.created_at = existing.created_at;
            }
            store.save(&mut p)?;
            out.emit(&p, || println!("Saved preset '{}'", p.name));
        }
    }
    Ok(())
}

/// `sam-jail group …`
pub(crate) fn group_cmd(app: &Sam, out: &Out, cmd: GroupCmd) -> Result<()> {
    match cmd {
        GroupCmd::List => {
            let apps = app.permission_overview()?;
            out.emit(&apps, || {
                for a in &apps {
                    let tags: Vec<&str> = a.tags.iter().map(|t| t.label.as_str()).collect();
                    println!("{:<28} {}", truncate(&a.summary.name, 28), if tags.is_empty() { "-".to_string() } else { tags.join(", ") });
                }
            });
        }
        GroupCmd::Set { key, value, apps, dry_run } => {
            let r = app.group_change(&key, &value, &apps, dry_run)?;
            out.emit(&r, || {
                for a in &r.apps {
                    for s in &a.check.removes_needed {
                        println!("  {} {} loses {s}, which it likely needs", paint("warning:", "33"), a.name);
                    }
                }
                let n = r.apps.iter().filter(|a| a.changed).count();
                if dry_run {
                    println!("Would change {key} to {value} for {n} app(s)");
                } else {
                    println!("Changed {key} to {value} for {n} app(s)");
                    if r.apps.iter().any(|a| a.changed && a.running) {
                        println!("Running apps use the new settings the next time they start.");
                    }
                }
            });
        }
        GroupCmd::Restore => {
            let previous = serde_json::from_str(&read_stdin()?).context("expected the \"previous\" object of `group set` as JSON on stdin")?;
            let n = app.group_restore(previous)?;
            out.emit(&json!({"restored": n}), || println!("Restored the settings of {n} app(s)"));
        }
    }
    Ok(())
}
