### The user guide says exactly what uninstalling SAM removes and keeps

- The user guide's new section *Removing SAM* lists what `sam-jail
  uninstall` removes, with and without `--keep-data`, what stays, and the
  cases it does not cover. The README, the command's help and the manual
  pages point there.
- Before you add `--yes`, `sam-jail uninstall` now says that anything you
  keep in the folders it lists can be removed with them. It no longer
  says that your AppImage files stay: an AppImage saved inside one of
  those folders goes with it, and without `--keep-data` so do the earlier
  versions that updates replaced.
