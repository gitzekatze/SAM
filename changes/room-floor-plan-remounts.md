### Rooms follow the app's read-only places also with raw Bubblewrap arguments

- With raw Bubblewrap arguments in an app's settings, a room could get a
  place writable that the app has read-only, in two cases:
  - `--bind / /` among them: SAM's own final `--remount-ro /` makes the
    app's root read-only, but rooms ignored that remount;
  - a place asked with `-try` over another at the same place, followed by
    `--remount-ro` there: when the `-try` source was missing, the app's
    place below it became read-only, but rooms showed it writable.

  Rooms now get such places read-only, as the app does.
- An app whose raw arguments lay an overlay of several layers gets no
  rooms (the start says so), instead of rooms showing one of the layers.
