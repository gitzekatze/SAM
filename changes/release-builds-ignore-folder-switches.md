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
- If you set `SAM_CONFIG_DIR` or `SAM_DATA_DIR` for an installed SAM, it
  keeps nothing in the folders they name any more, but still hides those
  folders from every app, as it hides its own folders: an app that may see
  the folder above one of them (`~/Games` for `SAM_DATA_DIR=~/Games/sam`)
  cannot read the other apps' private homes there or change their app
  records. SAM hides such a folder only while the variable is still set,
  and not where hiding it would cover too much: where the folder is your
  home folder or a folder above it, or where it is a link and the app is
  shown only folders inside the place it leads to. So move the old folders
  as described below, or delete them, before you remove the variable.
- If you set one of these variables for an installed SAM, it now uses the
  standard folders (`~/.config/sam`, `~/.local/share/sam` and
  `~/.local/share/applications`) instead, without a message: its window
  shows the apps recorded there, not the ones in your old folders. If you
  had set `SAM_DATA_DIR`, the menu entries SAM made start apps it no longer
  knows.
- To keep using the apps you added with the old folders, together with
  their own files, first close SAM's window and every app started from SAM,
  then move the contents of the old configuration, data and menu folders
  into the standard ones. The old runtime folder (`SAM_RUNTIME_DIR`) holds
  only the files of running apps and need not be moved. The window and
  `sam-jail list` then show those apps again. Each
  app's private home (`homes/` in the data folder), where the app keeps its
  own files, moves with them. Then unpack each app again (Unpack Again, or
  `sam-jail reextract`): an app record keeps the full paths of its unpacked
  copy, its icon and its menu entry in the old folders, so until then SAM
  refuses to start the app and the window shows a generic icon for it.
- Adding an app's AppImage again instead, without moving the old folders,
  suits only apps whose own files you do not need: the new record starts
  with an empty private home and sets up its settings and permissions
  anew. The old home stays in the old folder, which SAM hides only while
  the variable is still set: delete it, or move it out of every folder an
  app may see, before you remove the variable. If it is the same
  AppImage file, the app gets the same id again, so its new menu entry
  replaces the old one in `~/.local/share/applications` instead of adding a
  second one. An AppImage that changed since (for example a newer version)
  gets a new id: then delete the old menu entry, `sam-<id>.desktop` with
  the old id, from that folder yourself.
- `XDG_CONFIG_HOME` and `XDG_DATA_HOME` are no replacement for the old
  variables: they move the folders of every program started with them,
  not only SAM's, and SAM then uses `sam/` below each of them and
  `applications/` below `XDG_DATA_HOME`. Old folders used with them must
  be moved there in the same way, and, as after any move, each app must
  then be unpacked again.
