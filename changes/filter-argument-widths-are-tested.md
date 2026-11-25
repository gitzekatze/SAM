### The syscall filter's argument widths are tested

Nothing changes for users; this is a test.

- A test now checks that the filter reads the terminal request of `ioctl`
  and the family of `socket` as the kernel does, as 32-bit numbers, so a
  value with extra upper bits cannot slip past it.
