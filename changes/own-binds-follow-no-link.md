### SAM shows your fonts and theme files on its own only where they are no link

- SAM shows an app your fonts (`~/.fonts`, `~/.local/share/fonts`,
  `~/.config/fontconfig`) and, without the whole home and with host theme
  settings on, your theme files, read-only. It now does so only where
  neither the place nor a folder on its way in your home is a link,
  whoever made the link. Before, SAM followed such a link where it judged
  the place it leads to safe, so another app with the whole home
  writable, or an earlier start of this app with more rights, could make
  `~/.fonts` a link to any folder, and a later start with a private home
  showed that folder as the fonts. A home kept behind a link (`/home/u` a
  link to `/data/u`) keeps its fonts.
- Who loses fonts or theme files in apps with a private home: fonts and
  settings kept with GNU Stow or yadm, a whole `~/.config`, `~/.local` or
  `~/.local/share` kept as a link, fonts linked to a second disk, and
  places that home-manager or Guix keep as links into their store. Keep
  the real files at that place. The common link `~/.fonts` to
  `~/.local/share/fonts` loses nothing.
- Where a link you made leads into a folder the app may write (with the
  home read-only, `~/dotfiles` writable and `~/.config/fontconfig` a link
  into it), SAM keeps the place it leads to read-only there, unless its
  name is not valid text, and the app can no longer rename a folder above
  it away with the read-only bind inside.
- A link at a protected name can no longer keep the font settings
  writable where a granted folder shows them, and a credential you keep
  as a link into a fonts folder keeps that folder out of a private home.
- The launch log names each such link and where it leads in one note,
  and the app page and `sam-jail info` show the same before the start,
  under *Fonts or theme files behind a link*.
- The security page's *Your fonts and theme files follow no link* has the
  full rule, what it costs with the whole home, and its limits, among
  them a program running alongside that swaps a folder on the way for a
  link while the app starts.
