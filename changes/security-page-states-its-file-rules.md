### SAM's security page lists its file rules and the protections it does not give yet

- The security page has a new section, *What an app sees: the file rules*:
  an index of nine rules, five for what an app may see (the private home,
  the whole home, user folders, extra folders, files you open) and four
  for the protections added after every grant (keys and credential
  stores, SAM's own folders, start places, SAM's own programs). Each rule
  points to the place on the page that states it in full and names the
  protections SAM does not give yet.
- The page now names limits it did not name before: the Vim, Neovim and
  Mercurial places that are not kept read-only, what a link inside a start
  place leads to, the files a start file names to run, a start file that
  a program outside the sandbox replaces while the app runs, second names
  of start files, stores and SAM's AppImage made with a hard link, key
  folders and stores that their own variable moves, stores and key folders
  missing when the app starts, starts whose environment does not name the
  folder that `XDG_CONFIG_HOME` or `XDG_DATA_HOME` moves (also for SAM's
  own folders), another copy of SAM that the menu entries run, and the new
  AppImage of SAM's update of itself until SAM has restarted.
- The page says once that SAM sets these protections up when the app
  starts and does not promise that they follow a change a program outside
  the sandbox makes while the app runs.
- With files opened with the app set to *No access*, the page now says
  that the app starts in the folder it was started from wherever a grant
  shows that folder, and in its home otherwise.
- The threat model points to these limits for apps that read keys, for
  apps that make themselves start later and for apps that replace SAM's
  own programs.
- Tests check that the rules stay numbered once each with working
  pointers, that rule C3 names the Vim, Neovim and Mercurial places, the
  start places at the top of the home and links inside start places, and
  that rule C1 names a store missing at the start, each exactly while
  SAM's code has that gap.
