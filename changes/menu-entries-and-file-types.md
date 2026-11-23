### Other tools' menu entries and file types

- Hiding another tool's menu entry for an AppImage took it out of the menu
  only: opening one of its file types (a double-click on a `.md` file, for
  example) still started the AppImage without its sandbox. SAM now hides
  such entries for opening files too, and puts them back as they were when
  you show them again. Entries an earlier version of SAM hid are shown as a
  warning again, so you can hide them properly.
- An entry that another tool took out of the menu but that still opens
  files is now shown as a way to start the app without its sandbox.
- An app can no longer claim every file by declaring the desktops'
  catch-all file types `all/all` or `all/allfiles`: SAM's menu entry leaves
  them out, like web links and folders.
- A menu entry whose command names a named pipe no longer hangs the list of
  AppImages.
- The README now says what SAM does: menu entries from other tools that
  start an app without its sandbox are shown as a warning, and SAM offers to
  hide them.
