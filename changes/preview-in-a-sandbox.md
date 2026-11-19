### SAM reads AppImages it has not unpacked only inside a sandbox

- The overview reads the name and icon of every AppImage in your folders
  inside a sandbox with a time and memory limit. Before, it read them in
  SAM's own process: an image crafted to exhaust memory or hang could stop
  the list at every start.
- Icons are taken only as PNG of at most 1024×1024 pixels or small SVG, at
  most 1 MiB; XPM is no longer taken. A PNG that announces a huge picture
  (a "decode bomb") is refused before anything decodes it, also when the
  window shows icons cached by older versions.
- The preview and the unpacked app read the same desktop file.
- Checking a dropped file no longer blocks the window when it is a named
  pipe.
- File types that menu entries may not claim (web links, folders,
  programs) are blocked in any letter case and under their old names.
