### SAM locks the user folders file also when the config folder is the home

- When `XDG_CONFIG_HOME` names the home itself, SAM reads where Documents,
  Downloads and the other user folders are from `~/user-dirs.dirs`. SAM
  only locked `~/.config/user-dirs.dirs`, so an app with the whole home
  writable could rewrite the file SAM really reads and, at a later start
  or a start running at the same time, be shown other folders as its user
  folders.
- SAM now keeps `~/user-dirs.dirs` read-only there as well, and the app
  cannot rename it away. When the file is missing, SAM creates it empty
  before a start that shows it writable, as it does
  `~/.config/user-dirs.dirs`. SAM does the same for `~/cfg/user-dirs.dirs`
  when `XDG_CONFIG_HOME` names `~/cfg`.
- SAM promises this only when neither the file nor a folder on the way to
  it from the home is a link.
- While another app runs that saw the file missing, SAM leaves it missing.
- SAM reads `XDG_CONFIG_HOME` from the environment of each start, so a
  start whose environment does not set it leaves the file unlocked. Set
  the variable in the desktop session's environment, not only in a
  shell's startup file.
- Where `XDG_CONFIG_HOME` or `XDG_DATA_HOME` names the home, the start
  places at the top of the home (`~/autostart`, `~/applications`) are
  still not locked.
