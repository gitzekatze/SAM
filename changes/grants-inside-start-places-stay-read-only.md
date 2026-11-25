### SAM shows an extra folder inside a start place read-only

- An extra folder you allow the app to write that lies inside a place
  SAM protects because changing it can make your computer run programs
  (for example `~/.config/fish/conf.d`) is now always shown read-only,
  also when that folder itself is a link into another folder the app may
  write. Before, without full home access, the app could write there and
  plant a file that ran outside the sandbox at your next shell.
- The same holds for a start place granted itself, for one reached through
  a link or with `..`, and for the real folder a start place links to.
- The app page and `sam-jail info` say so before the start, and the start
  notes it.
- An extra folder that lies inside another folder the app may already
  write (for example `~/work/project` next to `~/work`, or below the
  writable home) is no longer bound a second time; the app still reaches
  it through the folder above it.
- An extra folder inside SAM's own folders is not shown, and SAM says so.
  The sandbox check, the app page and a terminal app's start line agree,
  also when SAM keeps its folders in a place you chose (for example
  `~/Games/sam`) or behind a link.
- The folders where SAM keeps its settings and data unless told otherwise
  (`~/.config/sam`, `~/.local/share/sam`, and the same below another
  config or data folder you set with `XDG_CONFIG_HOME` or `XDG_DATA_HOME`)
  are now hidden from apps also while SAM keeps its own elsewhere, with or
  without full home access, wherever they lead (for example another SAM's
  `~/.local/share/sam` kept as a link to `~/Sync/sam`). Before, an app
  could read them through an extra folder inside them, or through the home
  when they were below another config folder.
- A folder by those names is kept read-only instead where hiding it would
  cover too much: where it is your home or a folder above it, or where it
  is a link and the app is shown only folders inside the place it leads
  to. So an app cannot make SAM cover your home, or a folder you granted
  inside that place, with an empty folder by planting such a link. Where
  the app is shown that place itself, it stays hidden, as before.
- With such a link leading to your home and full home access granted
  read and write, the app now sees your whole home read-only (keys and
  SAM's own folders stay hidden). The start, the app page and
  `sam-jail info` name the link that leads to your home, and the sandbox
  check expects the home read-only. If you did not make that link, remove
  it.
- The app page and `sam-jail info` also say when an extra folder you allow
  the app to write lies inside SAM's own folders outside any start place
  (for example `~/Games/sam/saves`): SAM does not show it.
- The sandbox check and a terminal app's start line no longer count a user
  folder (for example Documents) set inside SAM's folders as shown; the
  sandbox never showed it.
- Not yet covered: a link inside a start place that you did not grant
  yourself (for example `~/.config/tmux/plugins` leading into a writable
  `~/work`) is not locked yet; the app can still write where it leads.
