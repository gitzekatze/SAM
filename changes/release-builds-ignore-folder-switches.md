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
  standard folders instead, without a message: its window shows the apps
  recorded there, and menu entries made in the old folder start apps SAM
  no longer knows. Move the folders' contents to the standard folders, or
  set `XDG_CONFIG_HOME` and `XDG_DATA_HOME` (SAM then uses `sam/` and
  `applications/` below them).
