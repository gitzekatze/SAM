### Apps with long names keep their sound, bus and Wayland connection

- An app with a long name (GIMP, MuseScore, ONLYOFFICE, mpv, Audacity and
  others) could lose its sound, sometimes also its session bus or its own
  protected Wayland connection: the path of a connection SAM made for it was
  longer than Linux allows. In normal use this hit such apps when SAM
  restarted them for their bus name. Nothing became less safe: the app ran
  without sound or bus, or with the normal Wayland connection, as when it
  runs directly.
- Each start's own folder now has a short name, which leaves room for the
  longest name; a test checks every connection path for it.
- If a path is ever still too long, SAM says so instead of the sound relay
  crashing.
