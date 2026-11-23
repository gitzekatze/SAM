### Hidden credentials stay hidden behind links, pipes and sockets

- With the whole home granted, a credential file kept behind a link into a
  place SAM keeps read-only (for example `~/.git-credentials` pointing to
  `~/.config/git/credentials`) was shown again: the read-only place was
  mounted after the hiding. Credentials are now hidden after every other
  mount.
- A credential place that is a named pipe (`~/.netrc` fed by a password
  manager, so the secret never lies on disk) or a socket was left showing,
  and the app could read the secret from it. It is now replaced by an
  empty file, like a plain file.
- Tests now notice more of what the mutation run of 2026-11-23 found
  unchecked in the sandbox: what is shown with the network, sound, D-Bus,
  devices and host themes; the display variables and the X11 cookie; the
  notes about a missing bus; files named on the command line; and moving
  new start files aside.
- The test that system libraries replace only bundled ones by plain name
  looks for the C library in every folder SAM itself searches (also on
  64-bit ARM), and no longer skips silently where it finds none: a run
  that must prove everything fails instead.
