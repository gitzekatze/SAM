### SAM locks the user folders file also when the config folder is the home

- When `XDG_CONFIG_HOME` names the home itself, SAM reads where Documents,
  Downloads and the other user folders are from `~/user-dirs.dirs`. SAM
  only locked `~/.config/user-dirs.dirs`, so an app with the whole home
  writable could rewrite the file SAM really reads and, at its next start,
  be shown other folders as its user folders.
- SAM now keeps `~/user-dirs.dirs` read-only there as well, and the app
  cannot rename it away. When the file is missing, one the app creates
  there does not stay after the start.
- The other start places at the top of the home (`~/autostart`) are still
  not locked when `XDG_CONFIG_HOME` names the home.
