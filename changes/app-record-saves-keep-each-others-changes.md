### SAM's saves of an app keep what other saves changed in other fields

- Every save of an app record now takes one short record lock and writes
  only what it changes onto the record as it is then. When two saves
  change the same field, the later one wins; a list, such as the granted
  folders, counts as one field, and a change that replaces the whole set
  of settings writes that set as one value. Before, a save could write back a whole
  copy it had read earlier and undo what another part of SAM saved
  meanwhile, such as a "look at it first" mark.
- Only your confirmation clears a "look at it first" mark.
- The start's warning about a changed AppImage now says that the unpacked
  copy SAM starts may not be that file.
- A reset also takes off an argument that a listed repair step added, such
  as `--no-sandbox`. SAM does not promise this for apps repaired with SAM
  0.1.0.
- An older SAM that runs at the same time does not take the lock, so one
  of its saves can still undo a change this SAM saved; close old SAM
  windows after updating SAM.
- The security page's *App records saved by two SAM processes at once*
  has the details and the other limits: a save that waits more than 10
  seconds for the lock, what a start writes back, *Unpack Again* while you
  confirm the app, and records SAM cannot read.
