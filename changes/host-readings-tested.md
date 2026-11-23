### Tests now check what SAM reads about the computer

- What SAM reads about this computer is now compared with the real
  kernel and tools: the Landlock version (also where a filter SAM runs
  under answers Landlock's question with a fake 0, which now counts as no
  Landlock in the tests too), whether Bubblewrap can give the writable
  app folder, the loader's library folders and the graphics devices.
- The logic behind each reading is tested on its own: the session's
  sockets follow its variables (an empty one counts as unset), only digits
  make an X11 display number, library folders below the home or in /etc,
  /var or /run are never shown, the user folders are read from
  `$XDG_CONFIG_HOME`, the user name, a setuid Bubblewrap and the kernel's
  user namespace settings.
- Nothing changes in how SAM behaves.
