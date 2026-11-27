### SAM shows your fonts and theme files on its own only where they are no link

- SAM shows an app your fonts (`~/.fonts`, `~/.local/share/fonts`,
  `~/.config/fontconfig`) and, in a private home with host theme settings
  on, your theme files, read-only. It now does so only where neither the
  place nor a folder on its way in your home is a link. Before, SAM
  followed such a link where it judged the place it leads to safe, so
  another app with the whole home writable, or an earlier start of this
  app with more rights, could make `~/.fonts` a link to any folder, and a
  later start with a private home showed that folder as the fonts.
- A home kept behind a link (`/home/u` a link to `/data/u`, or Fedora
  Atomic's `/home` a link to `/var/home`) keeps its fonts: only links
  below it count.
- Who loses fonts or theme files in apps with a private home: fonts and
  settings kept with GNU Stow or yadm, a whole `~/.config`, `~/.local` or
  `~/.local/share` kept as a link, fonts linked to a second disk, and
  places that home-manager or Guix keep as links into their store. Keep
  the real files at that place, or give the app the whole home. The
  common link `~/.fonts` to `~/.local/share/fonts` loses nothing, since
  SAM shows `~/.local/share/fonts` itself.
- Where a link you made leads to a place that a writable folder of the
  app shows (with the home read-only, `~/dotfiles` writable and
  `~/.config/fontconfig` a link to `../dotfiles/fontconfig`), SAM keeps
  that place read-only there, as before. The same holds with the whole
  home writable: `~/.fonts` a link to `~/myfonts` keeps `~/myfonts`
  read-only. This never shows the app anything new. Anyone who can write
  in your home can use this to make a folder inside a writable folder
  read-only for the app while the link exists; the launch log names it.
  Where the name of such a place is not valid text, the app does not
  start, and SAM names the place, rather than leave it writable.
- A link at a protected name can no longer keep the font settings
  writable where a granted folder shows them, also with your home kept
  behind a link. In a private home, a credential you keep as a link into
  a fonts folder (`~/.git-credentials` a link into `~/.fonts`) keeps that
  fonts folder out, so the credential stays hidden. This also holds with
  your home kept behind a link and an extra `~/.config`: SAM then shows
  the font settings only where that folder shows them, where the
  credential is hidden, and the launch log says why.
- The launch log names each such link and where it leads in one note,
  and the app page and `sam-jail info` show the same before the start,
  under *Fonts or theme files behind a link*. An app with the whole home
  sees no difference through the home, but gets this note at every start
  while such a link exists.
- The file chooser's bookmarks and server list are now kept out only
  below a theme folder SAM shows. Below one kept as a link, the empty
  stand-in followed the link and could leave an empty file in an app's
  private home kept on disk.
