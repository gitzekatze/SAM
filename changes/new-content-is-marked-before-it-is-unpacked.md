### SAM unpacks nothing new when it cannot first mark it, and marks a swapped file of an app it has not unpacked yet

- When *Unpack Again* cannot first save the "look at it first" mark of an
  AppImage that changed outside SAM, it now says so and that nothing was
  unpacked; the app keeps the unpacked copy it had.
- For an app whose first unpack failed, checking for changes or pointing
  SAM at another file no longer takes a swapped file for the one you
  added: the first *Unpack Again* of other content marks the app, and it
  does not start until you have looked at it.
