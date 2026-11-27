### An installed SAM ignores the variables that move its folders

- `SAM_CONFIG_DIR`, `SAM_DATA_DIR`, `SAM_APPLICATIONS_DIR` and
  `SAM_RUNTIME_DIR` now work only in developer builds, like SAM's other
  developer variables. A release build keeps its settings, app records,
  menu entries and runtime files in the standard folders, so a variable
  that something else put into the desktop's environment never makes an
  installed SAM use other settings and permissions.
- `XDG_CONFIG_HOME` and `XDG_DATA_HOME` still move SAM's folders in every
  build, as they do for other programs.
- With such a variable set, an installed window now behaves as without it:
  starting SAM again brings the open window forward instead of opening a
  second window on the same settings.
- If you set one of these variables for an installed SAM, it now uses the
  standard folders (`~/.config/sam`, `~/.local/share/sam` and
  `~/.local/share/applications`) instead, without a message: its window
  shows the apps recorded there, not the ones in your old folders. If you
  had set `SAM_DATA_DIR`, the menu entries SAM made start apps it no longer
  knows.
- To keep using the apps you added with the old folders, remove each app
  and add its AppImage again (its settings and permissions are then set up
  anew). Moving the old folders to the standard ones is not enough on its
  own: an app record keeps the full paths of its unpacked copy, its icon
  and its menu entry in the old folders, so after a move SAM refuses to
  start the app until it is unpacked again (Unpack Again, or `sam-jail
  reextract`), and until then the window shows a generic icon for it.
- `XDG_CONFIG_HOME` and `XDG_DATA_HOME` are no replacement for the old
  variables: they move the folders of every program started with them,
  not only SAM's, and SAM then uses `sam/` below each of them and
  `applications/` below `XDG_DATA_HOME`. Old folders used with them must
  be renamed or moved there, and, as after any move, each app must then be
  unpacked again.
