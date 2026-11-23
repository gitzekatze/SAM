### Updates: your yes covers only the file you saw, and servers cannot fill the disk

- When an update is signed with another key (or its signature cannot be
  checked), the download now waits in SAM's own folder. *Update Anyway*
  (or `sam-jail update --accept-key-change`) installs exactly that file.
  Before, SAM downloaded again, and the server could hand out a different
  file, signed with any key, under the same yes. If something else is
  published meanwhile, SAM asks again. A yes counts once.
- SAM itself stops a download at the length the update description names.
  With curl older than 8.4 (Debian 12, Ubuntu 22.04), a server that sent no
  length could otherwise keep writing into your home folder for an hour.
- Updates from GitHub releases with hundreds of files work: the release
  description may now be up to 16 MiB, and one that is longer is reported
  as an error instead of failing as "GitHub's answer".
- An update built for another processor (for example the ARM build on an
  Intel or AMD computer) is refused, and nothing changes. Release files
  that name this computer's processor are tried first.
- A partial (zsync) update no longer reads the whole old AppImage into
  memory, and an update description with tiny blocks no longer makes SAM
  use gigabytes of memory: such an update is downloaded whole.
- Going back to the earlier version puts it into the app's own folder under
  the name it had, never to a place a changed app record names.
