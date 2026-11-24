### "Look at it first" is no longer lost when two changes meet

- When an AppImage's content or its settings change outside SAM, the app
  waits until you have looked at it. A change of the app made at the same
  time (a refresh of the app list, a changed switch, moving the AppImage)
  could save its older copy of the app over that mark, and the app then
  started without asking. Now a save keeps the mark, and only your review
  clears it.
- When SAM cannot read an app's saved settings while saving them (damaged,
  or written by another app's id), it now saves them marked as changed
  outside SAM, so you look at the app first; settings written by a newer
  SAM are left unchanged.
