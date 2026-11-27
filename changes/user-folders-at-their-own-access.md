### A user folder keeps its own access when the whole home is shared

- With the whole home shared writable, a user folder set to read-only
  (Documents, Music, Downloads and the others) was still writable through
  the home, and a user folder outside the home was not shown at all. SAM
  now shows each user folder at its own access, inside or outside the
  home: a read-only Documents under a writable home is really read-only,
  and a start file kept as a link into it stays locked.
- An extra folder set to read and write inside a read-only user folder
  (`~/Documents/proj`) stays writable, as its switch says.
- SAM no longer shows a user folder set to `/tmp` or to a folder in it
  where programs outside the sandbox listen (terminal multiplexers, SSH
  agents, X11). The app sees its own empty `/tmp` there instead, so what it
  saves there is gone when it quits; a folder of its own such as
  `/tmp/downloads` keeps it.
- SAM no longer follows a user folder through a link that the app itself
  could have put there, for example `~/Downloads` turned into a link while
  the whole home was writable. SAM cannot tell such a link from one you
  made, so it refuses both and names the link.
- The start, the app page and `sam-jail info` now say when SAM does not
  show a user folder, and why, before the app starts.
- The folders above every folder SAM shows at an access of its own are
  kept in place, so a second copy of the same app cannot rename them and
  swap the folder for a link. Font folders, font settings and theme files
  stay read-only.
- When two user folders are set to the same real folder with different
  access (Music read and write, Pictures read-only, both `~/Media`), the
  stricter access now wins: the folder is read-only for both, whatever
  their order. The start, the app page and `sam-jail info` say so and how
  to change it: set both to read and write, or give them places of their
  own.
