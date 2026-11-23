### An app's name never captures a command, and the window shows what is stored

- A command such as `sam-jail set vlc network.mode full` changes an app only
  when `vlc` names that one app alone. An AppImage that calls itself `vlc`
  next to "VLC media player" used to win because its name matched exactly;
  now the command fails and lists both IDs, so you can pick one.
- Turning Landlock or the syscall filter off for every app in Preferences
  asks first, like the same switch on an app's page. Cancel keeps it on.
- A Preferences switch or choice whose setting could not be saved goes back
  to the stored value, instead of showing a change that did not happen.
- "Confirm Settings" for an app whose settings changed outside SAM now asks,
  and names what the settings let the app do (*Think twice* and
  *Dangerous*), because SAM can tell that they changed, not what changed.
- The app page's header is no longer green "Sandboxed" when the last start
  lacked a protection layer; it shows "Protection missing", as the list does.
- A finding of a failed start says "Fix and start": it applies the fix and
  starts the app again, and its question's button says so.
- The window applies only the preset it asked you about: a preset changed
  while the question was open is refused (`preset apply` replies with a
  `fingerprint`, and `--expect` takes it back).
- The release page of SAM's own update opens only when it is an https page,
  like an app's download page.
- Texts the window built itself ("3 apps selected", the Permission Manager's
  switch names, the space used by an app, …) are translated now.
