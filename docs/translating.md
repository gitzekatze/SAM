# Translating SAM

SAM - Sandboxed AppImage Manager uses gettext (text domain `sam`).
Translations live in `po/`, one file per language, listed in `po/LINGUAS`.

## Add or update a language

```sh
make pot                                  # collect the strings into po/sam.pot, update every po/*.po
msginit -i po/sam.pot -o po/fr.po -l fr   # start a new language (then add "fr" to po/LINGUAS)
make mo                                   # compile into target/locale
LANG=fr_FR.UTF-8 target/release/sam-jail-gui
```

Edit the `.po` file with any PO editor (Poedit, Lokalize, GNOME
Translation Editor) or a text editor. `make mo` checks it (`msgfmt --check`),
and so does CI.

## What is translated

- **Done:** the window's own text: headings, buttons, menus, tooltips, the
  start page and messages (`crates/sam-gtk`, marked with `tr(…)`). German
  is complete for these.
- **Not yet:**
  - permission titles and explanations, hints, warnings and check results
    (they come from the command line tool, `sam-core` and `sam-runner`);
  - texts the window builds at run time with `format!`;
  - the user guide (`docs/guide.md`).

  These stay English for now.

When you add text to the window, wrap it in `tr("…")` (from
`crate::i18n`) so `make pot` finds it.
