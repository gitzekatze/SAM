//! `sam-jail preset …`

use super::*;

pub(crate) fn preset_cmd(app: &Sam, out: &Out, cmd: PresetCmd) -> Result<()> {
    let store = PresetStore::new(&app.paths);
    match cmd {
        PresetCmd::List => {
            let all = sam_profile::all_presets(&app.paths)?;
            out.emit(&all, || {
                if all.is_empty() {
                    outln!("{}", sam_core::i18n::tr("You have no presets yet. Save an app's settings with `sam-jail preset save APP NAME`."));
                }
                for p in &all {
                    outln!("{:<26} {:<10} {}", p.name, risk_str(p.risk), p.description);
                }
            });
        }
        PresetCmd::Show { name } => {
            let p = sam_profile::find_preset(&app.paths, &name)?
                .with_context(|| format!("unknown preset '{name}'"))?;
            out.emit(&p, || out!("{}", preset_to_toml(&p).unwrap_or_default()));
        }
        PresetCmd::Apply {
            name,
            app: q,
            yes,
            expect,
        } => {
            let r = app.apply_preset(&q, &name, yes, expect.as_deref())?;
            if !r.applied {
                crate::exit_with(crate::EXIT_NOT_PASSED);
            }
            out.emit(&r, || {
                let c = &r.check;
                for s in &c.removes_needed {
                    outln!(
                        "  {} removes {s}, which the app likely needs",
                        paint("warning:", "33")
                    );
                }
                for s in &c.adds_dangerous {
                    outln!(
                        "  {} adds high-risk permission: {s}",
                        paint("warning:", "31")
                    );
                }
                if r.applied {
                    outln!(
                        "{}",
                        sam_core::i18n::trf(
                            "Applied “{preset}” (risk {before} → {after})",
                            &[
                                ("preset", &r.preset),
                                ("before", &c.risk_before),
                                ("after", &c.risk_after)
                            ]
                        )
                    );
                } else {
                    outln!(
                        "{}",
                        sam_core::i18n::tr("Not applied. Run again with --yes to confirm.")
                    );
                }
            });
        }
        PresetCmd::Template => {
            let p = sam_profile::preset_template();
            out.emit(&p, || out!("{}", preset_to_toml(&p).unwrap_or_default()));
        }
        PresetCmd::Save {
            app: q,
            name,
            description,
        } => {
            let p = app.save_preset_from_app(&q, &name, &description)?;
            out.emit(&p, || {
                outln!(
                    "{}",
                    sam_core::i18n::trf(
                        "Saved the preset “{name}” ({risk})",
                        &[("name", &p.name), ("risk", &p.risk)]
                    )
                )
            });
        }
        PresetCmd::Delete { name } => {
            let ok = store.delete(&name)?;
            if !ok {
                bail!(
                    "{}",
                    sam_core::i18n::trf("no user preset named '{name}'", &[("name", &name)])
                );
            }
            out.emit(&json!({"deleted": name}), || {
                outln!(
                    "{}",
                    sam_core::i18n::trf("Deleted the preset “{name}”", &[("name", &name)])
                )
            });
        }
        PresetCmd::Duplicate { name, new_name } => {
            let mut p = sam_profile::find_preset(&app.paths, &name)?
                .with_context(|| format!("unknown preset '{name}'"))?;
            if sam_profile::find_preset(&app.paths, &new_name)?.is_some() {
                bail!(
                    "{}",
                    sam_core::i18n::trf(
                        "a preset named '{new_name}' already exists",
                        &[("new_name", &new_name)]
                    )
                );
            }
            p.name = new_name;
            p.created_at = 0;
            store.save(&mut p)?;
            out.emit(&p, || {
                outln!(
                    "{}",
                    sam_core::i18n::trf("Created the preset “{name}”", &[("name", &p.name)])
                )
            });
        }
        PresetCmd::Import { file } => {
            let mut p = read_preset_file(&file)?;
            let path = store.save(&mut p)?;
            out.emit(&p, || {
                outln!(
                    "{}",
                    sam_core::i18n::trf(
                        "Imported “{name}” → {path}",
                        &[("name", &p.name), ("path", &tildify(&path))]
                    )
                )
            });
        }
        PresetCmd::Export { name, file } => {
            let p = sam_profile::find_preset(&app.paths, &name)?
                .with_context(|| format!("unknown preset '{name}'"))?;
            let text = preset_to_toml(&p)?;
            match &file {
                Some(f) => std::fs::write(f, &text)?,
                None if !out.json => out!("{text}"),
                None => {}
            }
            out.emit(&json!({"toml": text, "file": file}), || {
                if let Some(f) = &file {
                    outln!(
                        "{}",
                        sam_core::i18n::trf(
                            "Exported “{name}” → {path}",
                            &[("name", &p.name), ("path", &f.display())]
                        )
                    );
                }
            });
        }
        PresetCmd::Put => {
            let input = read_stdin()?;
            let mut p: Preset = match serde_json::from_str::<Preset>(&input) {
                Ok(p) => p,
                Err(_) => parse_preset_toml(&input).context(sam_core::i18n::tr(
                    "expected a preset as JSON or TOML on stdin",
                ))?,
            };
            if let Some(existing) = store.get(&p.name)? {
                p.created_at = existing.created_at;
            }
            store.save(&mut p)?;
            out.emit(&p, || {
                outln!(
                    "{}",
                    sam_core::i18n::trf("Saved the preset “{name}”", &[("name", &p.name)])
                )
            });
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
                    outln!(
                        "{:<28} {}",
                        truncate(&a.summary.name, 28),
                        if tags.is_empty() {
                            "-".to_string()
                        } else {
                            tags.join(", ")
                        }
                    );
                }
            });
        }
        GroupCmd::Set {
            key,
            value,
            apps,
            dry_run,
            yes,
        } => {
            if !dry_run {
                // What the change adds to any of the apps, asked before
                // anything is changed.
                let preview = app.group_change(&key, &value, &apps, true)?;
                let mut added: Vec<sam_core::risk::RiskItem> = Vec::new();
                for a in preview.apps.iter().filter(|a| a.changed) {
                    let e = app.resolve(&a.id)?;
                    let mut new = e.profile.permissions.clone();
                    new.set_key(&key, &value)?;
                    for i in sam_core::risk::new_risks(&e.profile.permissions, &new) {
                        if !added.iter().any(|x| x.title == i.title) {
                            added.push(i);
                        }
                    }
                }
                crate::confirm_risks(&added, yes)?;
            }
            let r = app.group_change(&key, &value, &apps, dry_run)?;
            out.emit(&r, || {
                for a in &r.apps {
                    for s in &a.check.removes_needed {
                        outln!(
                            "  {} {} loses {s}, which it likely needs",
                            paint("warning:", "33"),
                            a.name
                        );
                    }
                }
                let n = r.apps.iter().filter(|a| a.changed).count();
                if dry_run {
                    outln!(
                        "{}",
                        sam_core::i18n::trn(
                            "Would change {key} to {value} for {n} app",
                            "Would change {key} to {value} for {n} apps",
                            n as u64,
                            &[("key", &key), ("value", &value)]
                        )
                    );
                } else {
                    outln!(
                        "{}",
                        sam_core::i18n::trn(
                            "Changed {key} to {value} for {n} app",
                            "Changed {key} to {value} for {n} apps",
                            n as u64,
                            &[("key", &key), ("value", &value)]
                        )
                    );
                    if r.apps.iter().any(|a| a.changed && a.running) {
                        outln!(
                            "{}",
                            sam_core::i18n::tr(
                                "Running apps use the new settings the next time they start."
                            )
                        );
                    }
                }
            });
        }
        GroupCmd::Restore { yes } => {
            let undo = serde_json::from_str(&read_stdin()?).context(sam_core::i18n::tr(
                "expected the \"undo\" object of `group set` as JSON on stdin",
            ))?;
            let n = app.group_restore(undo, |added| crate::confirm_risks(added, yes))?;
            out.emit(&json!({"restored": n}), || {
                outln!(
                    "{}",
                    sam_core::i18n::trn(
                        "Restored the settings of {n} app.",
                        "Restored the settings of {n} apps.",
                        n as u64,
                        &[]
                    )
                )
            });
        }
    }
    Ok(())
}
