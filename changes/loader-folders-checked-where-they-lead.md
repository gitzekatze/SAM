### Extra library folders are checked where they lead

- SAM shows the system loader's extra library folders (below `/opt` or
  `/usr/local`) read-only in the sandbox. It checked their names as
  text, so a configured folder written with `..` or a link below `/opt`
  could have shown a system area such as `/run`. Only the system's
  administrator writes that configuration; SAM now checks where each
  folder leads as well, and leaves out a folder whose real place it
  cannot find. Where `/opt` or `/usr/local` itself leads elsewhere, as on
  Fedora Atomic (`/var/opt`), their folders are still shown.
