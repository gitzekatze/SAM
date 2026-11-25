### Rooms never show a credential file the app is not shown, also when it is kept through a link

- SAM hides credential files such as `~/.netrc` from an app. When such a
  file is a link to a file elsewhere in the home (`~/dotfiles/netrc`, as
  `stow` sets it up), SAM hides the file the link leads to. With the home
  granted read/write, an app could rename the folder above that file
  (`~/dotfiles` to `~/y`) and then ask a room for `~/y`: the room showed
  the real file. A room now refuses to show a place below a writable
  folder while such a hidden file could be moved that way, as it already
  did for hidden folders. The room's refusal says why. A file SAM
  hides inside a place brought in from elsewhere, such as the computer's
  theme settings in an app's own home, does not count: moved, it shows a
  room only the app's own files.
