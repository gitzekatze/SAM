### SAM's processes no longer undo each other's saves of an app

- When two parts of SAM save the same app at the same time (the window and
  a `sam-jail` command, or a refresh, a relocate or a change of the
  settings while the app is unpacked again or updated), the later save no
  longer undoes the earlier one. Before, it could remove the "look at it
  first" mark of new content, the notice of a changed signing key or a
  switch you had just turned off.
- Every save of an app record now takes a short lock (the file
  `.records.lock` in SAM's apps folder), held only while the record is
  read, changed and written, never while SAM unpacks or downloads.
- Work that takes a while (unpacking again, a refresh, an update, a change
  of the settings) saves only what it changed onto the record as it is
  then; everything else another part of SAM saved meanwhile stays.
- Confirming that you looked at an app checks and clears the marks under
  the same lock, so it never clears a mark saved after the page was
  checked.
- If another SAM process keeps the lock for more than 10 seconds, the save
  stops with a message that says so and changes nothing; try again.
- Records written by older SAM versions read as before. An older SAM that
  runs at the same time does not take the lock, so close old SAM windows
  after updating SAM.
