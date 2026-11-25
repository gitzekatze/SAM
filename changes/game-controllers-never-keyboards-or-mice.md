### Game controllers never bring a keyboard or mouse along

- *Game controllers* promised that keyboards and mice stay hidden, but a
  device that reports itself as both a joystick and a keyboard (or a
  mouse) was passed to the app, which could then read what was typed on
  it. Now a device that udev also records as a keyboard, mouse, touchpad,
  touchscreen, tablet or pointing stick is never passed, whatever else it
  reports.
- A joystick node (`/dev/input/js*`) is now checked the same way as the
  other controller nodes. A node udev has no record for is no longer
  passed, as SAM cannot tell what it is.
- The setting's help says so.
- When SAM leaves a controller out for one of these reasons, the start's
  notes name it, instead of saying that no controller is plugged in.
- Known limit: a controller with a few typing keys of its own (such as a
  chat pad) that udev does not record as a keyboard is still shown, and
  the app can read those keys.
