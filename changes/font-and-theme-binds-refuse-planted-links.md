### SAM no longer follows a link an app could have planted in your fonts, theme, user or extra folders

- With the whole home writable, an app could turn a missing `~/.fonts`,
  `~/.config/fontconfig` or an extra folder not made yet into a link to a
  folder in `/tmp` where another program listens (tmux, an SSH agent) or
  to your runtime folder `/run/user/…`. At the next start SAM showed that
  folder, and the app could connect to those programs and run commands
  outside its sandbox. SAM now leaves out such a place and says why in
  the launch log.
- The rule is the same for your fonts, your fonts settings, your theme
  files, every extra folder, read-only or writable, and a user folder
  such as Documents that SAM shows on its own: a link in a folder the app
  can change is not followed out of what the app is shown, and a link to
  where programs outside the sandbox listen is never followed. A user
  folder inside a writable home counts as writable, and a writable extra
  folder follows such a link only where the app may write anyway, so a
  planted link can no longer make a read-only home writable.
  Your fonts and theme files are also never shown through a link to your
  home, your keys or SAM's own files.
- Links that stay inside what the app is shown keep working, for example
  `~/.fonts` as a link to `~/.local/share/fonts`. If you made a link to an
  extra folder yourself and the app has the whole home writable, list the
  place it leads to as an extra folder instead of the link. The sandbox
  check expects such a folder as the rest of the app's folders show the
  place it leads to.
