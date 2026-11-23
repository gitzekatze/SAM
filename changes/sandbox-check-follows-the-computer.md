### The sandbox check runs again after a kernel or Bubblewrap update

- With *Check before every start*, a passing sandbox check is repeated
  after the kernel, Bubblewrap, pasta or SAM's helper changed, not only
  after SAM's version or the app's settings did. A rebuilt development
  version of SAM is checked again too.
- A desktop whose compositor stops answering no longer holds up a start:
  after ten seconds the app starts with the normal Wayland connection, and
  the start is marked as missing its Wayland security context.
