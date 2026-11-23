### An app gets its variables only after SAM's helper has set up its protection

- Variables from an app's settings (*Environment variables*, passed-through
  variables, also from an imported preset) and its AppImage variables are
  now set by SAM's helper for the app alone, once Landlock and the syscall
  filter are in place. Before, the helper itself started with them, so a
  setting such as `LD_PRELOAD=/opt/app/usr/lib/libfoo.so` or
  `LD_LIBRARY_PATH` made the helper's loader run the app's library before
  either layer existed. The app sees the same variables as before, and the
  sandbox check checks them where the app gets them. The launch log lists
  them on their own line (values you gave stay hidden), and so does
  `sam-jail command`; that line is in your language.
- A descriptor the program that started SAM left open (a terminal's or a
  launcher's, a shell's `exec 3<>/dev/tty`) no longer reaches the app, from
  the command line, the menu or SAM's window: SAM's programs mark
  everything above standard input, output and error close-on-exec before
  they start anything, as Flatpak does.
- `$OWD` names the folder the app was started from only when the app can
  see it; otherwise it is the app's home, where the app starts. Before,
  `cd ~/private/clientX && sam-jail run app` told the app that folder's
  name even without access to it.
- A start no longer breaks with a confusing Bubblewrap error when an
  option value reads `--` (an AppImage file called `--`, a terminal type
  set to it): SAM finds Bubblewrap's own separator the way Bubblewrap reads
  its options.
