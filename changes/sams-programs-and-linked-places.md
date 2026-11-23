### SAM's own programs and places behind links stay protected

- SAM's AppImage (or its `sam-jail-run`), which every menu entry runs
  outside the sandbox, could be overwritten by an app with write access to
  the folder where you keep it, for example a browser allowed to write
  `~/Downloads`. The next click on any menu entry would have run the app's
  program unsandboxed. Inside the sandbox these files are now read-only,
  cannot be renamed or deleted, and the folders above them cannot be
  renamed away. A sandboxed app can therefore no longer save a download
  under the very name of SAM's AppImage.
- A key folder kept behind a link (`~/.gnupg` pointing to `~/Sync/gnupg`,
  `~/.ssh` to `~/Documents/ssh`) was shown, and writable, when the app was
  granted only the folder the link points into. It is now hidden there too.
- With `~/.config` (or `~/.local`) a link to another place, apps with full
  home access no longer fail to start, and when the link leads into a
  folder granted read-only, that folder stays read-only. With the home
  itself kept behind a link, links that name the home's real path are
  covered too: autostart stays read-only and key folders hidden there.
