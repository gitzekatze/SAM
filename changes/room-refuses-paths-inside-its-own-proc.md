### A room never makes anything through the links of its own /proc

- When a program in an app asks for a sandbox of its own (a room) with
  its own `/proc`, SAM now refuses a request that would make, change or
  show anything inside that `/proc` (a folder, a link, a file system, a
  mode change, a remount or a place of the app), whether it names it
  before or after the `/proc`, and says why. The same holds for a room's
  own message queue file system.
- Before, such a request was passed to Bubblewrap. The links of a `/proc`
  (such as `/proc/self/root`) lead out of the room while Bubblewrap builds
  it, so a program could make a folder or a link on the computer, for
  example an autostart entry outside the sandbox.
- A room may still have its own `/proc` and make things beside it.
