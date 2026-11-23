### Tests now notice more of what the inspection's mutation run found unchecked

The mutation run of the inspection (2026-11-23) changed small pieces of
SAM's core that no test noticed. Tests now notice, among others:

- a menu entry that would call another AppImage's program (one SAM was
  started from, like a terminal shipped as an AppImage) instead of SAM's
  own, or a program whose AppImage file is gone;
- a helper program the user can change through root's group or an ACL
  taken as safe to run outside the sandbox, or a file without an execute
  bit taken as a program;
- a badge that loses its name ("Unsafe", "Protection Missing") on the
  command line or in the JSON interface, an app marked broken, stale or
  unsafe shown as ready, and a crash right after starting that cleared the
  "May Not Start" badge;
- the reason given for a risk word naming harmless permissions instead of
  the risky ones, or none, and a writable home titled read-only;
- the warning and the status note for a missing `xdg-dbus-proxy`, which
  GPU device nodes the app gets, the user and group IDs inside the
  sandbox, and a sandbox check that would not be repeated after the
  computer changed;
- runtime folders put on the disk although the session has a runtime
  folder, translations not found next to SAM, icons kept outside SAM's
  folders, and the first-run mark;
- a size display that would crash on sizes from 1 PiB on (a sparse file
  can claim one).

Two small parts of the core were pulled out to be tested on their own
(which AppImage is SAM's own, and whether the user can change a file); they
work exactly as before.
