### Start places follow your config folder also through links

- SAM protects the start places below `XDG_CONFIG_HOME` and
  `XDG_DATA_HOME` when they point to other folders in your home. It
  compared them with the home as text, so a variable that named the
  home's real place (with the home kept behind a link) gave those places
  no protection. SAM now protects them under the name as written and
  under the place it leads to, so a link on the way stays watched too.
- Such a folder whose name is not valid text or holds `..` now stops the
  start with a message, instead of leaving the places below it
  unprotected.
- SAM acts only on plain folder names from its record of what it watches
  in the home. A name with `..`, which an earlier version could write,
  is left out; the rest of the record still counts.
