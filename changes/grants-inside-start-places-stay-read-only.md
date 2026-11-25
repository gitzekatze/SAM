### SAM shows an extra folder inside a start place read-only

- An extra folder you allow the app to write that lies inside a place
  SAM protects because changing it can make your computer run programs
  (for example `~/.config/fish/conf.d`) is now always shown read-only,
  also when it is a link into another folder the app may write. Before,
  without full home access, the app could write there and plant a file
  that ran outside the sandbox at your next shell.
- The same holds for a start place granted itself, for one reached through
  a link or with `..`, and for the real folder a start place links to.
- The app page and `sam-jail info` say so before the start, and the start
  notes it.
- An extra folder that lies inside another folder the app may already
  write (for example `~/work/project` next to `~/work`, or below the
  writable home) is no longer bound a second time; the app still reaches
  it through the folder above it.
- An extra folder inside SAM's own folders is not shown, and SAM says so.
