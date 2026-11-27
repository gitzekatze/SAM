### SAM hides Git's second credential file

- Git's credential store keeps your passwords in plain text, in
  `~/.git-credentials` and in a second file, `~/.config/git/credentials`
  (`$XDG_CONFIG_HOME/git/credentials` when you set `XDG_CONFIG_HOME`).
  SAM hid only the first one. The second one sat in a folder SAM keeps
  read-only, so an app with the whole home could not change it but could
  read it.
- It is now hidden like `~/.git-credentials`: with the whole home, read and
  write or read-only, with `~/.config/git` or `~/.config` as an extra
  folder, and where the file is a link into a dotfiles folder, where the
  link leads too. Git's settings beside it stay readable.
- With `XDG_CONFIG_HOME` or `XDG_DATA_HOME` set to another folder in your
  home (for example `~/cfg`), SAM now hides Git's file and the other
  password and login stores there too (`~/cfg/git/credentials`,
  `~/cfg/keepassxc`), and never shares one of them as a file you open
  with the app.
- A test starts a real app that tries to read the file in each of these
  ways.
