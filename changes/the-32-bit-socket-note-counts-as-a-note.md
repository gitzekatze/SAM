### SAM counts the 32-bit socket note as a note, not as not applicable

- `sam-jail verify` used to count the note about the incomplete socket
  limit of a 32-bit app among the checks that do not apply, as
  "1 not applicable". It now counts it on its own ("1 note"). The note is
  still neither passed nor failed, so it never stops a start.
- A saved check result now also records the number of notes, but only
  when there is one. Results saved by earlier versions of SAM load with no
  notes and stay unchanged, so no app looks changed outside SAM.
- When a passed check has such a note, the window no longer says that
  every setting applies in full: its summary and the badge's tooltip say
  "except where a note says otherwise", and the message after *Test* says
  only that the test passed.
- The help of the *Bluetooth* switch now says what the switch controls:
  Bluetooth sockets, which reach nearby devices only with full network
  access and which the syscall filter otherwise refuses while it is on,
  except for an app whose start program is 32-bit. An app that may reach
  the Bluetooth service on the system D-Bus can use Bluetooth devices
  through it, with or without the switch. The warning shown with the switch on no longer
  says that the switch is ignored without the system bus.
- The note itself now says that such sockets can be of families the
  filter would refuse, instead of "of any type".
