### SAM locks the user folders file also when the config folder is the home

- When `XDG_CONFIG_HOME` names the home itself, SAM reads where Documents,
  Downloads and the other user folders are from `~/user-dirs.dirs`. SAM
  only locked `~/.config/user-dirs.dirs`, so an app with the whole home
  writable could rewrite the file SAM really reads and, at a later start
  or a start running at the same time, be shown other folders as its user
  folders.
- SAM now keeps `~/user-dirs.dirs` read-only there as well, and the app
  cannot rename it away. When the file is missing, SAM creates it empty
  before the start, as it does `~/.config/user-dirs.dirs`, so the app
  cannot write one there while it runs. SAM does the same for
  `~/cfg/user-dirs.dirs` when `XDG_CONFIG_HOME` names `~/cfg`.
- While another app runs that saw the file missing, SAM leaves it
  missing; a file an app writes there then is moved aside, within moments while
  the home is watched, otherwise when the app ends.
- The other start places at the top of the home (`~/autostart`) are still
  not locked when `XDG_CONFIG_HOME` names the home.
