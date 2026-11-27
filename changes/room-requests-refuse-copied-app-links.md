### A room never makes anything through one of the app's own links

- When a program in an app asks for a sandbox of its own (a room) and
  names a place that holds one of the app's links (for example `/lib`,
  which is a link to `/usr/lib` on most systems, or the links in the
  app's `/dev`, also those Bubblewrap makes itself when the room asks
  for working devices), the room gets that link too. SAM now refuses a request
  that would make, change or show anything at or behind such a link (a
  folder, a link, a file system, a mode change, a remount or a place of
  the app), whether it names it before or after the place that brings
  the link, and says why.
- Before, such a request was passed to Bubblewrap, which would have
  followed the link. This could not be used to reach anything today,
  because SAM's links lead into read-only places or to targets that do
  not exist while a room is built. The new rule keeps it that way should
  that change.
- A program that asks for everything and then makes the system's links
  as it finds them still gets its room: the same link again changes
  nothing.
