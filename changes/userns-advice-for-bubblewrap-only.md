### SAM no longer advises opening user namespaces to every program

- On systems that switch unprivileged user namespaces off, SAM used to
  suggest `sudo sysctl kernel.unprivileged_userns_clone=1`. That opens them
  to every program and makes the computer less safe than without SAM. SAM
  now advises keeping the setting and, if you want sandboxes there, a
  setuid Bubblewrap instead (Arch: `bubblewrap-suid`), which gives the
  right to Bubblewrap only. SAM never changes the system itself.
