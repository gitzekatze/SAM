### A new mount call is blocked like the calls it combines

- `open_tree_attr` (Linux 6.15) does what `open_tree` and
  `mount_setattr` do together. SAM's syscall filter blocked those two for
  apps without nested sandboxes, but not the new one; now it does, also
  for 32-bit apps.
