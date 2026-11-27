### SAM's processes no longer write a whole app record over each other's changes

- When two parts of SAM save the same app at the same time (the window and
  a `sam-jail` command, or a refresh, a relocate or a change of the
  settings while the app is unpacked again or updated), the later save no
  longer writes back the whole record it read. Before, it could remove the
  "look at it first" mark of new content, the notice of a changed signing
  key or a switch you had just turned off.
- Every save of an app record now takes a short lock (the file
  `.records.lock` in SAM's apps folder), held only while the record is
  read, changed and written, never while SAM unpacks or downloads.
- Work that takes a while (unpacking again, a refresh, an update, a change
  of the settings) saves only what it changed onto the record as it is
  then; what another part of SAM saved meanwhile in other settings stays.
  When both change the same setting or the same list (such as the granted
  folders), the later save wins.
- A change that replaces all settings at once (a preset, a reset, the
  compatibility mode, undoing the repair steps, a whole set you confirm)
  saves exactly that set, never mixed with a switch saved meanwhile.
- Confirming that you looked at an app checks and clears the marks under
  the same lock, so it never clears a mark saved after the page was
  checked.
- When you confirm an app while SAM unpacks a newly changed AppImage of
  it again, the "look at it first" mark of the new content stays, so SAM
  still asks before that new content starts, and so does the note of what
  the new content asks for more.
- If another SAM process keeps the lock for more than 10 seconds, the save
  stops with a message that says so and saves nothing; try again.
- "Unpack Again" marks new content "look at it first" before it replaces
  the unpacked copy. If the record cannot be saved after the unpacking,
  SAM still asks before the new content starts, and the message says so;
  if the mark itself cannot be saved, SAM unpacks nothing. If the
  unpacking then fails, SAM asks once more before the app starts.
- Records written by older SAM versions read as before. An older SAM that
  runs at the same time does not take the lock, so close old SAM windows
  after updating SAM.
