### Three promises get a test that would notice them broken

- Updates come over HTTPS only: a new end-to-end test publishes the newer
  version on a plain HTTP server as well and points SAM at it, once
  directly and once through a redirect from HTTPS. SAM refuses both. The
  download's own HTTPS check has a test of its own too.
- System secrets stay out of the sandbox: the test now checks that files
  like `/etc/shadow`, `/etc/pam.d` and `/etc/ssh` do not even exist inside
  it, after making sure they are there on the computer. Before, it only
  checked that `/etc/shadow` was unreadable, which it is for anyone. The
  contract for these files gets a quick check in `sam-jail doctor
  --contracts`.
- A syscall filter that fails to load stops the start: SAM's helper is
  started while the kernel refuses every new filter, and the app does not
  run.
