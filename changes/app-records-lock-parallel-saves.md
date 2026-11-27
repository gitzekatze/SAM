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
- The "look at it first" marks go further, on the safe side: a refresh, a
  new detection or an "unpack again" that worked on a copy carrying a
  mark saves it again. If you confirm the app while a refresh or a new
  detection runs, SAM may ask you once more.
- A change that replaces all settings at once (a preset, a reset, the
  compatibility mode, undoing the repair steps, a whole set you confirm)
  saves exactly that set, never mixed with a switch saved meanwhile.
- Confirming that you looked at an app checks and clears the marks under
  the same lock, so it never clears a mark saved after the page was
  checked.
- SAM refuses to confirm an app while it changes the app's sandbox
  (unpacks it again or updates it, for example) and says so; confirm it
  once that is done. Before, a confirmation at that moment could clear the
  "look at it first" mark of new content nobody had seen yet.
- If another SAM process keeps the lock for more than 10 seconds, the save
  stops with a message that says so and saves nothing; try again.
- "Unpack Again" marks new content "look at it first" before it replaces
  the unpacked copy. If the record cannot be saved or the unpacking cannot
  be finished and SAM reports an error, SAM removes what it unpacked, so
  the app does not start with it: it starts only after it has been
  unpacked again or, if you moved the unpack folder since the last
  unpacking and the earlier copy there is still complete, with that copy,
  and the message says which; if the mark itself cannot be saved, SAM
  unpacks nothing. If the unpacking then fails, SAM asks once more before
  the app starts.
- If SAM cannot remove what it unpacked either (a disk that became
  read-only, for example), the message says so. New content that is not
  SAM's own update still waits until you have looked at it; otherwise
  (SAM's own update, going back, the same content again) the app starts
  with what was left in place (or, if you moved the unpack folder, with its
  earlier copy there), under its settings from before, until you unpack it
  again, when that copy is complete; if it is not, the app starts only
  after it has been unpacked again.
- If SAM itself is stopped between unpacking and saving (closed, killed,
  a power loss), what it unpacked stays in place, as when it cannot be
  removed: new content that is not SAM's own update still waits until you
  have looked at it, and otherwise the app starts with it (or, if you
  moved the unpack folder, with its earlier copy there) under its
  settings from before until you unpack it again.
- Records written by older SAM versions read as before. An older SAM that
  runs at the same time does not take the lock, so close old SAM windows
  after updating SAM.
