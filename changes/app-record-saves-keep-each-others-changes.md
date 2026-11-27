### SAM's saves of an app keep each other's changes

- When two parts of SAM save the same app at the same time (the window and
  a `sam-jail` command, or a refresh, a new detection or a change of the
  settings while the app is unpacked again or updated), the later save no
  longer writes back the whole record it read. Before, it could remove the
  "look at it first" mark of new content, the notice of a changed signing
  key or a switch you had just turned off.
- Every save of an app record now takes a short lock (the file
  `.records.lock` in SAM's apps folder), held only while the record is
  read, changed and written, never while SAM unpacks or downloads.
- Unpacking again, a refresh, a new detection, an update step and a change
  of the settings save only what they changed onto the record as it is
  then: a save keeps what others saved in other fields; for the same field
  the later save wins (a list, such as the granted folders, counts as one
  field).
- A change that replaces all settings at once (a preset, a reset, the
  compatibility mode, undoing the repair steps, a whole set you confirm)
  saves exactly that set, never mixed with a switch saved meanwhile.
- Applying or undoing one repair step works on the record as it is under
  the lock: a step applied at the same time elsewhere stays applied and
  listed, so it can be undone. Before, one of two steps applied at the
  same time was lost.
- Confirming from the app's page checks what the page showed and clears
  the marks under the same lock, so it never clears a mark saved while it
  waited. `sam-jail review` without `--seen` shows no page and confirms
  what is there when it gets the lock.
- When you confirm an app while SAM unpacks a newly changed AppImage of
  it again, the "look at it first" mark of the new content stays once the
  unpacking is saved, so SAM still asks before that new content starts.
- If another SAM process keeps the lock for more than 10 seconds, the save
  stops with a message that names the app and saves nothing; try again.
  Work done before that save stays: after "Unpack Again", the newly
  unpacked copy, which the app's record then does not describe. When the
  AppImage changed outside SAM, "Unpack Again" saves the "look at it
  first" mark before it unpacks, so that copy does not start until you
  confirm it (unless you confirmed the app while the unpacking still ran).
  If the unpacking then fails, SAM asks once more about the old content.
- Records written by older SAM versions read as before. An older SAM that
  runs at the same time does not take the lock, so close old SAM windows
  after updating SAM.
