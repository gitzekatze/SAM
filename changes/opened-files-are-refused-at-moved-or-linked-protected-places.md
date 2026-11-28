### SAM does not share an opened file at a start place or credential store that a folder variable moves or a link passes

Files and folders you name on an app's command line or open with it
("Open with") are judged against one list of places, which the security
page names under *Files named on the command line*:

- start places and credential stores are now also refused where
  `XDG_CONFIG_HOME` or `XDG_DATA_HOME` puts them outside the home
  (`/data/cfg/autostart/x.desktop`, `/data/cfg/gh/hosts.yml`) or at the top
  of the home when a variable names the home itself
  (`~/autostart/x.desktop`, `~/git/...`); before, such files were shared,
  writable with Read & write, so an app could add a login autostart entry
  that runs outside the sandbox;
- the folders the two variables name are refused as a whole, as
  `~/.config` and `~/.local` are, unless one names the home itself or a
  folder above it;
- a file reached through a link that lies in a protected place, or in the
  place a start place or store really leads to, is refused;
- a folder that holds such a moved place is not shared either (`~/d` while
  `XDG_CONFIG_HOME` is `~/d/cfg`);
- each path is judged on one walk and shared at the place judged;
- a home kept behind a link inside a system folder (`/home/ann` a link to
  `/var/home/ann`) no longer makes every file in it count as a system
  file, so those files can be opened again;
- a store an app made a link to the home no longer makes every file in the
  home unshared.

Who loses what: an editor can no longer open, from the command line, a
file inside a folder that `XDG_CONFIG_HOME` or `XDG_DATA_HOME` names
(`~/cfg/...`, `/data/cfg/...`), or a file under a moved start place at the
top of the home when a variable names the home (`~/git/...`). The file is
skipped without a note; the app reports it as missing. Edit such files
outside the sandbox; where a variable names the home, giving it a folder
of its own (the usual `~/.config`) also brings back the files at the top
of the home.

Not covered: a file that a link inside a protected place points to is
shared when you name it by its real place, and a second name made with a
hard link or a bind mount is not recognised. User folders (Documents,
Downloads, ...) are judged as before.
