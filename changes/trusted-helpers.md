### SAM runs only helper programs you cannot change

- Bubblewrap, pasta, the D-Bus proxy, the unpack tools, GnuPG, SAM's own
  launcher and the other programs SAM runs outside the sandbox are taken
  from `$PATH` only where you cannot change them. Before, a copy in
  `~/.cargo/bin`, `~/go/bin` or `~/.nix-profile/bin` came first when that
  folder was first on `$PATH`, and an app with write access to your home
  could have put its own `bwrap` there.
- The window runs only the `sam-jail` next to itself. An installed window
  also looked in neighbouring `debug` and `release` folders, where such an
  app could have put one.
- Menu entries name SAM's launcher by its whole path. Older entries are
  rewritten when the window starts.
- The stand-in for `systemd-run` also covers it where it is a link.
