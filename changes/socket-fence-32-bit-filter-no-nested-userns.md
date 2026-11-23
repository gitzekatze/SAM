### Kernel layers: socket fence reported, 32-bit apps filtered, unpacking without new namespaces

- Landlock's fence around abstract sockets (the X server's socket and
  others that have a name but no file) is reported on its own now. On a
  kernel before 6.12 it is not there, and Landlock only said "partially
  enforced". Diagnostics now warn about it, and the sandbox check tries to
  reach the X server and an abstract session bus from inside. A start that
  should have had the fence but did not is marked *Protection missing*.
- 32-bit apps keep the syscall filter. It used to be switched off for
  them, and any app could choose that by making the program it starts
  32-bit. The filter now answers their 32-bit calls like 64-bit ones.
  Apps already added keep their current setting.
- While SAM unpacks an AppImage, nothing inside can make a user namespace
  of its own, neither the AppImage's own extractor nor an unpacking tool.
  The same now holds for SAM's sound relay.
  The syscall filter also stops `clone` and `clone3` from doing it in
  every sandbox without nested sandboxes.
