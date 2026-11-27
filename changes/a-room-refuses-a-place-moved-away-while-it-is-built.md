### A room refuses a place that was moved away while it was built

- Room service, which builds the sandboxes that programs in an app ask for,
  now also ends a room when one of its places is no longer the mount
  Bubblewrap made there, or is reached through a link, as found when SAM's
  helper starts in the room. This is defence in depth against a program
  outside the app's sandbox that can write the folder holding a place: it
  could move the place away while the room was built and put the same file
  back at its name, so the room reached that file without its mount. A
  room lost nothing by that, because it shows nothing inside a place the
  app can write. A move made later, while the room's program runs, is
  still not detected (a known limitation in the security notes).
