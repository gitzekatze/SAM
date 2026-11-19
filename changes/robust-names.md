### Odd names and settings no longer break SAM

- A file or folder whose name is not valid text (Linux allows any bytes)
  stops the start with a message naming it. Before, SAM passed on a name
  with a replaced character, which names another file, and the menu
  launcher crashed on such a file.
- An AppImage file called `bin`, `sam-jail-run` or `sandbox.json` starts:
  inside the sandbox it is shown in a folder of its own, not on top of
  SAM's own files.
- The copy of the X11 key for an app is readable by you alone from the
  moment it exists, and never written through a link. SAM's file writes
  report a failed write to the disk instead of carrying on.
- A `%` in SAM's own path no longer breaks every menu entry.
- `sam-jail --json run`: the app's output goes to standard error, so
  standard output holds SAM's reply alone.
- Presets whose names share a file ("My Preset" and "my-preset") no
  longer overwrite each other: the second one is refused. Preset names
  starting with `-` work in the window.
- Empty or relative folder settings (`SAM_CONFIG_DIR=""`, `XDG_DATA_HOME=data`)
  are ignored instead of putting SAM's files into the current folder.
- Install hints name your distribution's package manager instead of
  always `pacman`; the AppArmor advice names Ubuntu's restricted profile
  for Bubblewrap, what it costs, and warns against lifting the
  restriction for every program.
