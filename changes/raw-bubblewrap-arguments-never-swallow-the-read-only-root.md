### Extra Bubblewrap arguments that are incomplete or misplaced stop the start

- The advanced setting for extra Bubblewrap arguments is placed right
  before SAM's last steps, which make the sandbox's root read-only and
  start SAM's helper. When the list ended with an option still missing
  its value, that option took SAM's step as its value, and the root
  stayed writable without a word. A word where an option belongs (a
  value too many, or `--`) would have run instead of the app, before
  those steps.
- SAM now refuses to start the app and names the incomplete option, the
  misplaced word, or an option it does not know.
- Rooms and these arguments read Bubblewrap's options from one list.
