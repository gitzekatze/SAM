### SAM gives one clear reason when two rules refuse a user folder

- SAM has two rules for a user folder (Documents, Downloads and the
  others) reached through a link: one refuses a link in a folder the app
  can change, the other refuses a link the app could have planted out of
  what the home shows, and any link to where programs outside the
  sandbox listen. Each rule refuses on its own, so SAM shows the folder
  only where both allow it.
- Where both refuse a folder, the launch log now gives the reason of the
  second rule: it names the danger or says that the link leads out of
  what the home shows, and tells you how to show the folder if you made
  the link yourself. The shorter note that only names the link stays for
  a link in a folder the app can change that leads to a place the home
  shows anyway.
- With the whole home writable and Downloads set to read-only, SAM mounts
  Downloads read-only over the home, so the app cannot plant a link in
  it, unless SAM refuses Downloads (for example because Downloads is
  itself a link in the writable home). Then the home shows it writable,
  as before. A link the app planted there, or in an earlier start while
  Downloads was still writable, is still not followed.

### The app page names every user folder SAM leaves out for a link

- The app page and `sam-jail info` now name, before the start, a user
  folder that SAM leaves out because it is a link to a folder in `/tmp`
  or a runtime folder, or because the app could have made the link, with
  the words of the launch note and how to show the folder. Before, a
  Downloads made a link to `/tmp/dl` (so downloads clear themselves) was
  left out and named only in the launch log, and what the app saved there
  was gone when it quit.
- A folder that only one start shows writable, such as a folder opened
  with the app, is not known on the app page: a user folder left out for
  a link in such a folder is named only in the launch log.

### SAM's fonts and theme binds also guard credential stores in a moved config folder

- With `XDG_CONFIG_HOME` or `XDG_DATA_HOME` set to another folder in your
  home (`~/cfg`), a fonts folder or theme file made a link to a
  credential store there (`~/cfg/gh`, where the GitHub tool keeps its
  token) is no longer shown to an app with a private home. Before, only
  the stores under `~/.config` and `~/.local/share` were guarded.
