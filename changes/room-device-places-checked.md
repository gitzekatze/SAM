### A room shows a device only while it is the one the app was given

- Bubblewrap can show a device only by its name. Before, a room showed a
  device place of the app by name, whatever was at that name by then. With
  *Game controllers* (not *Input*), the app gets single controller nodes
  such as `/dev/input/event5`. When the controller was unplugged and a
  keyboard got the same number, a program in a room could read that
  keyboard, while the app itself could not (this needs the person to be in
  the `input` group, which some gaming setups use).
- Now Room service remembers what each device place was when the app
  started (device and inode) and shows it in a room only while it is still
  that device. SAM's helper checks in the room that Bubblewrap showed
  exactly it. A device unplugged since, or another one now at its name, is
  left out and named in the start record. Controllers plugged in later
  still need the app to be restarted, as before.
