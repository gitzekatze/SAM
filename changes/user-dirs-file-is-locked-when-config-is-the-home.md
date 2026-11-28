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
- SAM reads `XDG_CONFIG_HOME` from the environment of each start: set it
  in the desktop session's environment, not only in a shell's startup
  file.
- The security page's *Full home access* names where SAM does not promise
  this: a link on the way to the file, a start whose environment does not
  set the variable, another app running that saw the file missing, a
  folder outside the home, and the start places at the top of the home.
