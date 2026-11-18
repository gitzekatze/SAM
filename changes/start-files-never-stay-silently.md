### A start file an app leaves never stays silently

- With full home access, SAM moves new start files aside. It gave up after
  1000 earlier copies, and did nothing (and said nothing) when its folder
  was on another drive or the disk was full. Now it moves them however many
  there are; when its folder cannot take them they are renamed in place to
  a name nothing reads, or deleted; and if even that fails, the command line
  and the log say so in capitals.
- When Linux refuses to watch a folder while the app runs, SAM says so, and
  still checks the folder when the app ends.
- A full disk can no longer stop the start record (what was missing, what
  was moved aside) from being saved.
- More places that start programs are protected: `systemd --user` units
  under `~/.local/share`, PipeWire and WirePlumber settings,
  `.bash_aliases`, `.bash_completion`, and the start files of Sway,
  Hyprland, i3, niri, labwc, river, Wayfire and Openbox; and all of them
  also under another `XDG_CONFIG_HOME` or `XDG_DATA_HOME` inside the home.
- The security page and the threat model no longer call Landlock a second
  layer for these files with the whole home writable: it is not.
