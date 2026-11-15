# Translating SAM

SAM - Sandboxed AppImage Manager speaks English, German, Spanish and French.
It uses gettext (text domain `sam`). The translations live in `po/`, one
file per language, and `po/LINGUAS` lists the languages.

## What is translated

- **Everything in the window:** headings, buttons, menus, tooltips, the start
  page, toasts and dialogs.
- **Every message from SAM's core:** permission titles and explanations,
  warnings, hints, repair advice, check results, update and error messages.
  The window shows these, so they are translated where they are made
  (`sam-core`, `sam-runner`, `sam-sandbox` and the other crates).
- **The command line's sentences,** such as confirmations and error messages.

These stay English on purpose:

- log files, and the key/value tables of `sam-jail info`, `preview` and
  `report`, because they are technical and go into bug reports;
- the patterns SAM matches in an app's own output (apps print English);
- codes and keys in the JSON interface and in files;
- the user guide, the website and the other documents (a browser translates
  web pages well).

## Add or update a language

```sh
python3 scripts/i18n.py extract           # collect the texts into po/sam.pot and update every po/*.po
msginit -i po/sam.pot -o po/it.po -l it   # start a new language, then add "it" to po/LINGUAS
python3 scripts/i18n.py stats             # how much of each language is done
python3 scripts/i18n.py check             # complete, and placeholders kept
make mo                                   # compile into target/locale
LANGUAGE=it target/release/sam-jail-gui   # try it
```

Edit a `.po` file with any PO editor (Poedit, Lokalize, GNOME Translation
Editor) or a text editor.

German, Spanish and French must stay complete: CI runs
`scripts/i18n.py check`, which fails when one of their texts has no
translation or when a translation drops or invents a placeholder such as
`{name}`. A new language can start incomplete; untranslated texts show in
English. Once it is complete, add it to `COMPLETE` in `scripts/i18n.py` so it
stays that way.

## Words to keep

| English | Deutsch | Español | Français |
| --- | --- | --- | --- |
| sandbox | Sandbox | entorno aislado | bac à sable |
| preset | Vorlage | plantilla | modèle |
| unpack | entpacken | desempaquetar | décompresser |
| Unpack Again | Erneut entpacken | Desempaquetar de nuevo | Décompresser à nouveau |
| Test | Testen | Probar | Tester |
| Sandbox Check | Sandbox-Prüfung | Comprobación del entorno aislado | Vérification du bac à sable |
| menu entry | Menüeintrag | entrada del menú | entrée de menu |

Address the user informally, as a friend would: du in German, tú in Spanish, tu in French. `scripts/i18n.py check` fails on the formal forms (Sie, usted, vous).

## Marking texts in the code

Every text a person reads goes through one of these functions from
`sam_core::i18n` (in the window also `crate::i18n`):

- `tr("Text")` for a plain text;
- `trf("Copied {name}", &[("name", &name)])` for a text with values; give
  each placeholder a name that tells the translator what goes there;
- `trn("{n} app", "{n} apps", n, &[])` for a text that depends on a number
  (`{n}` is filled in for you);
- `n_("Text")` marks a text in a constant table; translate it with `tr` where
  it is shown.

Write whole sentences: never glue a sentence together from pieces, because
other languages put the words in another order. When code needs to know which
error happened, give the error a code (`sam_core::error::CodedError`) instead
of comparing its text.

`scripts/i18n.py` finds the texts. Some helpers translate their arguments
themselves (`Warning::new`, `perm!`, `opt` and others); the `CALLS` table at
the top of the script lists them.
