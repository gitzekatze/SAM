### Pairs of sockets keep to the same socket types

- SAM's syscall filter limited the socket types an app may open (local,
  internet and netlink; Bluetooth with its switch) only for `socket`.
  `socketpair` makes its sockets the same way, so an app could still make
  a pair of kernel-crypto, raw-packet or other rarely used sockets, and
  have the kernel load their module. A pair now answers "not supported"
  for the same types, also for 32-bit apps; local pairs work as before.
