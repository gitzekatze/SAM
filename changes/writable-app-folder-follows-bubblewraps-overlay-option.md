### The writable app folder follows Bubblewrap's overlay option

- SAM decides whether the writable app folder can work by whether the
  installed Bubblewrap lists the `--overlay-src` option in its help, not
  by its version number. Upstream Bubblewrap added overlays in 0.11, so
  with a plain Bubblewrap 0.10 or older the app folder stays read-only,
  and `doctor` and the warning at start say so; a distribution's
  Bubblewrap that offers the option gets the writable app folder.
- Room service, the contract check and the writable app folder now ask
  one shared test for Bubblewrap's options: it runs `bwrap --help`, needs
  a successful answer and counts an option only as a word of its own, so
  a look-alike such as `--overlay-srcs` never counts as `--overlay-src`.
