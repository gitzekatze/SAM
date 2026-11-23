### Room service: programs get their own sandbox from SAM

- Programs inside an app that build a Bubblewrap sandbox of their own, such
  as GTK's image loader (glycin, in 16 of 240 tested apps), now get it from
  SAM, built outside the app's sandbox: never with more than the app, never
  with less than they asked, always with SAM's syscall filter and Landlock
  (where the kernel has Landlock), also where the app has them off. Before, they decoded pictures with no
  sandbox at all ("Glycin running without sandbox"), or the app crashed.
- No setting to change: Room service is on for every app.
  `advanced.room_service` turns it off for one app.
- Rooms asked for at the same moment wait a moment for each other when
  the launcher's descriptor limit is low (most desktops: 1024), instead of
  being refused; only a room that could never fit is refused at once.
- The start record names each room, the protection layers SAM's room
  helper confirmed, and what was capped or refused.
- Closing an app (Close, `sam-jail stop`, logging out) gives a program
  running in a room the same time to save and quit as the app: it is
  asked to quit, and its room ends only once it has quit or the time is
  over.
- With a Bubblewrap older than 0.10 (no `--ro-bind-fd`), Room service
  stays off and every start says so; programs keep the computer's own
  Bubblewrap as before.
- Building SAM now needs the static C library (Debian/Ubuntu: libc6-dev,
  Fedora: glibc-static, openSUSE: glibc-devel-static) for SAM's room
  helper, a small static program. Without it the build warns and Room
  service is off.
