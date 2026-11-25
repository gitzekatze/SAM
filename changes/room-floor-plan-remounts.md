### Rooms follow the app's read-only places also with raw Bubblewrap arguments

- With raw Bubblewrap arguments in an app's settings, a room could get a
  place writable that the app has read-only, in these cases:
  - `--bind / /` among them: SAM's own final `--remount-ro /` makes the
    app's root read-only, but rooms ignored that remount;
  - a place asked with `-try` over another at the same place, followed by
    `--remount-ro` there: when the `-try` source was missing, the app's
    place below it became read-only, but rooms showed it writable;
  - a `--remount-ro` that Bubblewrap finds through a link, through `..`,
    or at a mount of the computer below a shown folder.

  Rooms now get the first two read-only, as the app does. For the third,
  the app gets no rooms (the start says why). With `--bind / /`, rooms
  show the computer's mounts below the root read-only, where the app can
  still write them: a room gets less there, never more.
- An app whose raw arguments lay an overlay of several layers gets no
  rooms (the start says so), instead of rooms showing one of the layers.
