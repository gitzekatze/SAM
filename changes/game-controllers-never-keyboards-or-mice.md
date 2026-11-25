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
