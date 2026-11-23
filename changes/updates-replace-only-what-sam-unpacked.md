### Updates replace only the AppImage SAM unpacked

- An update no longer trusts whatever file is in the AppImage's place.
  Another app with access to that folder could put its own AppImage there,
  naming its own update server, and the update then gave its program this
  app's permissions without a review. Now SAM checks a copy of the installed
  file in its own folder first and refuses a file replaced outside SAM
  (*Unpack Again* asks you to look at it). Going back checks the current
  file the same way, on a copy only SAM can reach; when unpacking an update
  failed, going back still accepts the file the update put there.
- The sandbox is unpacked from the checked download in SAM's own folder,
  not from the AppImage's folder, where the file could be swapped in that
  moment.
- An update keeps its published file name only when that is a plain name
  ending in `.AppImage`. A server could otherwise name it `sudo` or `git`
  and, in `~/.local/bin`, replace a command outside any sandbox.
- An app added while GnuPG was missing no longer accepts any signing key on
  update: SAM checks the installed file again and compares the keys.
- Going back to a version kept by an older SAM asks you to look at the app
  once it is back.
