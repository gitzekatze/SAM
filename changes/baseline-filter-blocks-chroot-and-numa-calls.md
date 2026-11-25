### The baseline syscall filter blocks chroot and the NUMA memory calls

- The baseline filter, on by default, now also blocks the NUMA memory calls
  (`mbind`, `move_pages`, `migrate_pages`, `get_mempolicy`, `set_mempolicy`,
  `set_mempolicy_home_node`), as Flatpak's default filter does; no desktop
  app needs them, and before only the strict filter blocked them. `chroot`
  is blocked too, except for apps with nested sandboxes, whose own sandbox
  (Chromium's, in Electron apps) uses it.
- SAM's front page no longer calls the baseline "similar to Flatpak's": it
  says what SAM blocks beyond Flatpak (`io_uring`, BPF, `userfaultfd`,
  `kexec`, rare socket types) and what it leaves to the strict filter or
  allows (`ptrace`, `personality`, `modify_ldt`, which crash reporters and
  Wine use).
