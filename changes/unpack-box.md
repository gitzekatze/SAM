### The unpacking sandbox can no longer reach the app's folder

- An unpacking tool tricked by a crafted AppImage (a bug in a SquashFS or
  DwarFS reader) could write the app's whole folder in SAM's data, and
  plant links there that SAM then wrote through outside any sandbox (for
  example `metadata.json` pointing to `~/.bashrc`). Now each unpacking
  attempt gets a fresh, empty folder, which is the only writable place, and
  SAM writes its own files there without following links.
