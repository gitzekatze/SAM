### SAM's saves of an app keep what other saves changed in other fields

- Every save of an app record now takes one short record lock (the file
  `.records.lock` in SAM's apps folder), held only while the record is
  read, changed and written.
- Each save writes only what it changes onto the record as it is then.
  When two saves change the same field, the later one wins; a list, such
  as the granted folders, counts as one field, and a change that replaces
  the whole set of settings writes that set as one value. Before, a save
  could write back a whole copy it had read earlier and undo what another
  part of SAM saved meanwhile, such as a "look at it first" mark.
- Only your confirmation clears a "look at it first" mark. A confirmation
  from the app's page checks under the lock that the page showed what it
  confirms; `sam-jail review` without `--seen` confirms what the record
  holds when it gets the lock.
- When the AppImage changed other than through a SAM update, "Unpack
  Again" saves the "look at it first" mark before it unpacks, so the new
  copy does not start unconfirmed when the closing save fails. SAM does
  not promise this when you confirm the app while it unpacks.
- The start's warning about a changed AppImage now says that the unpacked
  copy SAM starts may not be that file.
- A reset also takes off an argument that a listed repair step added, such
  as `--no-sandbox`. SAM does not promise this for apps repaired with SAM
  0.1.0.
- If a save does not get the lock within 10 seconds, it stops with a
  message that names the app and saves nothing; try again. Work done
  before it stays, such as a newly unpacked copy that the app's record
  then does not describe.
- A start writes the app's state and last error as it read or set them,
  so it can replace a notice another part of SAM saved there while the app
  ran.
- SAM does not promise any of this for a record it cannot read.
- Records written by older SAM versions read as before. An older SAM that
  runs at the same time does not take the lock, so one of its saves can
  still undo a change this SAM saved; close old SAM windows after updating
  SAM.
