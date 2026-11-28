### SAM counts the 32-bit socket note as a note, not as not applicable

- `sam-jail verify` used to count the note about the incomplete socket
  limit of a 32-bit app among the checks that do not apply, as
  "1 not applicable". It now counts it on its own ("1 note"). The note is
  still neither passed nor failed, so it never stops a start.
- A saved check result now also records the number of notes. Results
  saved by earlier versions of SAM load with no notes.
- When a check of an AppImage that has no sandbox yet passes with such a
  note, the window now says that every setting applies except where a note
  says otherwise.
- The help of the *Bluetooth* switch now names both conditions under
  which an app can open Bluetooth sockets with the switch off: its syscall
  filter is off, or its start program is 32-bit and it has full network
  access.
- The note itself now says that such sockets can be of families the
  filter would refuse, instead of "of any type".
