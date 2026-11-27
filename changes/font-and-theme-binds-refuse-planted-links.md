### SAM no longer follows a link that an app could plant with its current permissions in your fonts, theme, user or extra folders

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
  where programs outside the sandbox listen is never followed, whoever
  made it. Not covered: a program running alongside (also a running copy
  of the app) that swaps a part of the way between SAM's look and the
  mount. A user folder inside a writable home counts as writable, and a
  writable extra folder follows such a link only where the app may write
  anyway, so a planted link can no longer make a read-only home writable.
  Your fonts and theme files are also never shown through a link to your
  home, your keys or SAM's own files.
- A folder counts as one the app can change whenever any writable
  permission shows it, also where an extra read-only folder lies deeper:
  an app could make that read-only folder a link into such a folder and
  plant a second link there. A folder opened with the app while opened
  files are writable counts as well.
- Where programs outside the sandbox listen now means anything in `/tmp`
  and `/var/tmp`, a socket directly there (as PostgreSQL keeps its own)
  or a socket folder by any name, and your runtime folder and SAM's
  wherever they are, also outside `/run` (as on WSL). A place in your home
  stays judged by the other rules when your home itself lies in `/tmp`,
  as in a guest session.
- Links that stay inside what the app is shown keep working, for example
  `~/.fonts` as a link to `~/.local/share/fonts`. If you made a link to an
  extra folder yourself and the app has the whole home writable, list the
  place it leads to as an extra folder instead of the link. The sandbox
  check expects such a folder as the rest of the app's folders show the
  place it leads to.
- SAM judges such a link by the permissions of the start at hand. A link
  the app made in an earlier start, while it had more write access (the
  whole home or a folder writable), is still followed after you narrow
  its permissions, for example `~/.fonts` made a link to another drive.
  A link to where programs outside the sandbox listen stays refused in
  every start (with the limit above), and your fonts and theme files
  never lead to your home, your keys or SAM's own files. After you narrow
  an app's permissions, check that `~/.fonts`, `~/.config/fontconfig` and
  the extra folders are not links you did not make.
