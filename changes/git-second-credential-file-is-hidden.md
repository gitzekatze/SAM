### SAM hides Git's second credential file

- Git keeps the passwords you save with its credential store in plain
  text, in `~/.git-credentials` or, when that file does not exist, in
  `~/.config/git/credentials`. SAM hid only the first one. The second one
  sat in `~/.config/git`, which SAM keeps read-only, so an app with the
  whole home could not change it but could read it.
- It is now hidden like `~/.git-credentials`: with the whole home, read and
  write or read-only, with `~/.config/git` or `~/.config` as an extra
  folder, and where the file is a link into a dotfiles folder, where the
  link leads too. Git's settings beside it stay readable.
- A test starts a real app that tries to read the file in each of these
  ways.
