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
  as in a guest session. A link whose way only passes such a place, such
  as a link in `/tmp` that points elsewhere (on WSLg `/tmp/.X11-unix`
  points to the X server's folder in `/mnt/wslg`), counts as well.
- An extra folder you name by its real place is shown as written and
  rated by its name: `/tmp` itself, the known socket folders such as
  `/tmp/tmux-1000` and anything in `/var/tmp` are rated *Dangerous*. Any
  other place in `/tmp`, such as `/tmp/tmate-1000`, is rated *Some
  access* when read-only, so SAM adds it without asking first, and
  *Think twice* when writable.
- Links that stay inside what the app is shown keep working, for example
  `~/.fonts` as a link to `~/.local/share/fonts`. If you made a link to an
  extra folder yourself and the app has the whole home writable, list the
  place it leads to as an extra folder instead of the link. The sandbox
  check expects such a folder as the rest of the app's folders show the
  place it leads to; where the sandbox shows its own folder there (a
  system folder, `/run`, `/proc`, `/dev`, `/sys`, or the fonts and theme
  files of a private home), it does not check that folder.
- For a writable extra or user folder left out this way, the launch log
  says that SAM leaves it out as a writable folder: with a read-only home
  the app may still read the place it leads to.
- For each place left out by these rules (a link the app may have
  planted, a link to where programs outside the sandbox listen, or fonts
  and theme files that lead to your home or your keys), the launch log
  says that SAM leaves out the extra or user folder, or does not bind the
  fonts or theme place on its own, and why: for a planted link, that the
  home and the user folders do not show the place it leads to; for the
  other two rules, where the link leads. It also says that the app still
  sees what its other folders show there. If you list the place a link
  in your fonts or theme files leads to as an extra folder, SAM still
  leaves out the fonts or theme place itself, and the app reaches that
  place through the link wherever its other folders show the link.
- SAM judges such a link by the permissions of the start at hand. A link
  the app made in an earlier start, while it had more write access (the
  whole home or a folder writable), is still followed after you narrow
  its permissions, for example `~/.fonts` made a link to another drive.
  A link to where programs outside the sandbox listen stays refused in
  every start (with the limit above), and your fonts and theme files
  never lead to your home, your keys or SAM's own files. After you narrow
  an app's permissions, check that `~/.fonts`, `~/.config/fontconfig` and
  the extra folders are not links you did not make.
