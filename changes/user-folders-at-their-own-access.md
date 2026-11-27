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
- The start, the app page and `sam-jail info` now say before the app
  starts when SAM does not show a user folder because it is reached
  through a link the app could change, or because it is `/tmp` or a folder
  in it where programs outside the sandbox listen, and why. A user folder
  SAM does not show for another reason (set to the home or a folder above
  it, to a system folder, to a protected place, or inside SAM's own
  folders) is named only in the launch log, and only when the whole home
  is not shared. With the whole home shared, SAM says nothing about such a
  folder: SAM gives it no place of its own, and the app sees that place
  only where the home shows it, with the home's protections (key folders,
  SAM's own folders) as they are for the home.
- The folders above every folder SAM shows at an access of its own are
  kept in place, so a copy of the same app that is already running with
  the same settings cannot rename them and swap the folder for a link
  while SAM starts the app again. This holds only for folders that already
  existed when that copy started: a folder made later is not kept in place
  in it, so that copy can still swap it for a link while SAM starts the app
  again. A copy of the app started with other settings, like any other
  program that can write a folder above, can also still swap such a folder
  for a link while SAM starts the app. Checking each shown folder in the
  finished sandbox before the app starts, which closes this, is planned.
  Font folders, font settings and theme files stay read-only.
- When two user folders are set to the same real folder with different
  access (Music read and write, Pictures read-only, both `~/Media`), the
  stricter access now wins: the folder is read-only for both, whatever
  their order. The start, the app page and `sam-jail info` say so and how
  to change it: set both to read and write, or give them places of their
  own.
