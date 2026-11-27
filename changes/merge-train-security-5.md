### SAM gives one clear reason when two rules refuse a user folder

- SAM has two rules for a user folder (Documents, Downloads and the
  others) reached through a link: one refuses a link in a folder the app
  can change, the other refuses a link the app could have planted out of
  what the home shows, and any link to where programs outside the
  sandbox listen. Each rule refuses on its own, so SAM shows the folder
  only where both allow it.
- Where both refuse a folder, the launch log now gives the reason of the
  second rule. For a link to where programs outside the sandbox listen
  (a folder in `/tmp`, a runtime folder), it names that danger and gives
  no way out, also where the app could have made the link, as with the
  whole home writable. Otherwise it says that the link leads out of what
  the home shows and tells you how to show the folder if you made the
  link yourself. The shorter note that only names the link stays for
  a link in a folder the app can change that leads to a place the home
  shows anyway.
- The same holds for extra folders, fonts and theme files: a link to
  where programs outside the sandbox listen always gets the note that
  names the danger. Before, with the whole home writable, the note for
  such a link said to list or set the place it leads to, such as
  `/tmp/tmate-1000`, which SAM then showed as set.
- With the whole home writable and Downloads set to read-only, SAM mounts
  Downloads read-only over the home, so the app cannot plant a link in
  it, unless SAM refuses Downloads (for example because Downloads is
  itself a link in the writable home). Then the home shows it writable,
  as before. A link the app planted there, or in an earlier start while
  Downloads was still writable, is still not followed.

### SAM keeps your fonts read-only with the whole home writable

- The new rule that your fonts never lead to your keys, a credential
  store or another place SAM protects applies where the home does not
  show that place anyway. With the whole home writable, SAM keeps showing
  `~/.fonts`, `~/.local/share/fonts` and `~/.config/fontconfig`
  read-only where they exist when the app starts, also when one of them
  leads into such a place (for example
  after `~/.aws` was made a link to your home, with hidden files shown).
  Left out there, the writable home would show them writable, and the
  app could change the fonts and font settings your other programs load.
  The home's own protections still apply after the fonts are bound; a
  font place that leads to the home itself stays left out.
- SAM binds a font place there only where the app reaches it through
  what the home shows, which is where the bind lands. With your home kept
  behind a link (`/home/u` a link to `/data/u`), the sandbox shows the
  home only as `/home/u`. An app could make `~/.fonts` a link to the
  real place of your keys (`/data/u/.ssh`), and the next start would
  have bound that place beside the home, where the keys are not hidden.
  SAM now leaves such a font place out and says why in the launch log.
- The same holds wherever another folder you granted already shows the
  place writable, also in a private or read-only home: with `~/.config`
  or `~/.local/share` an extra writable folder, SAM keeps the fonts and
  the font settings inside it read-only, and the theme files too in a
  private home with host theme settings on. Before, an app
  could make a hidden-files place such as `~/.config/vivaldi` a link to
  `~/.config/fontconfig`, and in the next start the extra folder showed
  the font settings writable. A font place that the sandbox does not show
  itself, such as `~/.fonts` in a private home, still never leads to your
  keys or credential stores.
- Not covered, as before: a font or theme place that does not exist when
  the app starts is not bound, so the writable home or an extra writable
  folder that holds it lets the app create it. An extra writable folder
  named through a link (`~/.config` a link to `~/dots/config`) shows the
  font settings and theme files writable at the place the link leads to
  (`~/dots/config/fontconfig`). SAM binds no theme file read-only with
  any home grant (read-only or read and write) or with host theme
  settings off, so an extra writable `~/.config` shows the theme files in
  it (`~/.config/gtk-3.0`, `~/.config/kdeglobals` and the others)
  writable. After giving an app such a folder writable, check that the
  fonts and theme files in it are yours.

### The app page names every user folder SAM leaves out for a link

- The app page and `sam-jail info` now name, before the start, a user
  folder that SAM leaves out because it is a link to a folder in `/tmp`
  or a runtime folder, or because the app could have made the link, with
  the words of the launch note. For a link the app could have made, the
  note says how to show the folder if you made the link yourself; for a
  link to `/tmp` or a runtime folder it names the danger only. Before, a
  Downloads made a link to `/tmp/dl` (so downloads clear themselves) was
  left out and named only in the launch log, and what the app saved there
  was gone when it quit.
- A folder that only one start shows writable, such as a folder opened
  with the app, is not known on the app page: a user folder left out for
  a link in such a folder is named only in the launch log.

### SAM's fonts and theme binds also guard credential stores in a moved config folder

- With `XDG_CONFIG_HOME` or `XDG_DATA_HOME` set to another folder, in
  your home (`~/cfg`) or outside it (`/data/cfg`), a fonts folder or
  theme file made a link to a credential store there (`~/cfg/gh`, where
  the GitHub tool keeps its token) is no longer shown to an app with a
  private home. Before, only
  the stores under `~/.config` and `~/.local/share` were guarded.

### A link the app planted no longer makes a read-only user folder writable

- With the whole home writable and Documents set to read-only, an app
  could turn an extra writable folder into a link into Documents
  (`~/x` to `~/Documents/Taxes`). At the next start SAM followed the link
  and made that folder writable inside the read-only Documents. SAM now
  follows such a link only into what the sandbox really shows writable,
  so it leaves the folder out and says why in the launch log.
- The same holds for two user folders set to one place at different
  access (both read-only there) and for an extra read-only folder.
