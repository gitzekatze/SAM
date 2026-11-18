### Unpacking limits hold in the sandbox; a shared unpack folder is safe

- When SAM's own reader hit an unpacking limit inside the unpack sandbox,
  SAM tried the next tool (with only a time limit) and then offered to let
  the AppImage unpack itself. Now a limit reached in the sandbox stops
  unpacking, as it does outside.
- The unpack location can be any folder. If it was a folder that also held
  other things (for example `~/Documents`), *Remove unused unpacked copies*
  deleted every folder in it that was not an app, and uninstalling SAM
  deleted the folder entirely. Now SAM removes only what it put there, and
  the whole folder only when SAM created it.
- An app without `AppRun` starts only a program inside it, never
  `Exec=/usr/bin/…` or `../`; SAM never waits on a named pipe in an app.
