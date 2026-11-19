### The syscall filter shuts the kernel's rarely used doors, also while unpacking

- Sockets open only as local, internet or netlink (the kernel's status
  channel), as in Flatpak. Virtual-machine sockets (which no network
  setting stopped), raw-packet and kernel-crypto sockets are refused.
  Bluetooth sockets open only with the *Bluetooth* switch, which before
  granted nothing.
- Every call through the x32 ABI is refused. Before, the filter blocked a
  call only by its normal number, and x32 numbers some calls on its own
  (`ptrace` is 521 there).
- `clock_adjtime`, `quotactl_fd`, `fspick` and `mount_setattr` are blocked
  like their already blocked siblings.
- `docs/syscalls-reviewed.txt` says exactly what the filter does with each
  call (always blocked, blocked unless nested sandboxes, only with the
  strict filter, limited), and a test compares each status with the filter.
- Unpacking an AppImage, by SAM's reader or by the AppImage's own
  extractor, runs with the same filter and the same system view as an app;
  before, the AppImage's own extractor ran without any filter.
- *All input devices* says that the app can also type and move the mouse
  as you (`/dev/uinput`); *Bluetooth* says what it now allows.
- The question before an AppImage unpacks itself says that the sandbox also
  limits kernel calls.
