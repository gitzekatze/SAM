### Fuzz tests that reach what they name, and a fuller test desktop

- New fuzz tests change exactly what each reader looks at: the ELF section
  table and the signature, key and update sections of an AppImage, zsync
  control files through planning and assembly, desktop files with a byte
  order mark and Windows line ends, and the preview reader without its
  guard (a panic in SAM's own code fails; one inside the SquashFS library
  is counted). They run on every change, and longer every week.
- They found three bugs, now fixed: an AppImage header with impossible
  values or one cut short could end SAM (an overflow, now also in release
  builds, and an out-of-range read), and a desktop file starting with a
  byte order mark lost its name, icon and everything else.
- The real-AppImage runs give apps a silent sound output and a
  notification service, as a desktop does: apps that open sound or send a
  notification first no longer look broken there.
