### Start places follow your config folder also through links and `..`

- SAM protects the start places below `XDG_CONFIG_HOME` and
  `XDG_DATA_HOME` when they point to other folders in your home. It
  compared them with the home as text, so a variable that named the
  home's real place (with the home kept behind a link) or held `..` gave
  those places no protection. SAM now compares where they lead.
- Such a folder whose name is not valid text now stops the start with a
  message, instead of leaving the places below it unprotected.
- SAM's record of what it watches in the home is read back with plain
  folder names only.
