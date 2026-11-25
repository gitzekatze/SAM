### Start files and credential stores kept through a link stay protected when the folder they lie in is renamed

- When a start file such as `~/.bashrc` or a credential store such as
  `~/.netrc` is a link into another folder of the home (`~/dotfiles`, as
  `stow` sets it up), SAM protects the file the link leads to. With the
  home granted read/write, an app could rename the folder above that file
  (`~/dotfiles` to `~/y`) and put a start file of its own in a new
  `~/dotfiles`: the unchanged link then led to the app's file, which ran
  outside the sandbox at the next shell or login. SAM now also makes every
  writable folder above the place a protection lands a mount point of its
  own, so the app cannot rename it. The same holds for SAM's own folders
  and programs reached through a link.
