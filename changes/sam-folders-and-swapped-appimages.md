### SAM's own folders stay hidden from opened folders, and a swapped AppImage asks first

- A folder you open with an app ("Open with", or a path on its command line)
  no longer shows SAM's own folders inside it. Before, if SAM's unpack folder
  was on the same drive, the app could change other apps' unpacked files.
- When an AppImage file was replaced by something other than a SAM update
  and you unpack it again, SAM marks it *Changed outside SAM* and does not
  start it until you have looked at it and confirmed. Before, the new file
  simply kept the old app's permissions.
