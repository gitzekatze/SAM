### No extra folder can undo the home protections

- With full home access plus a grant of a folder that contains the home
  (`/home`), the grant was mounted after the protections and covered them:
  the app could read `~/.ssh` and write autostart. The protections now come
  after every grant.
- With write access to `~/.local` (or another folder above SAM's own), an
  app could rename `~/.local/share` away and create folders where SAM reads
  its records. The folders above SAM's own are now mount points that cannot
  be renamed.
- Grants are checked where they really lead: a granted link to `~/.local`
  no longer shows SAM's folders.
- A private home now has `.config`, `.local/share`, `.local/state` and
  `.cache`, like every home (some apps failed without them).
- SAM refuses to start an app when the home folder is not set (`HOME` empty
  or `/`): full home access would have meant the whole computer.
