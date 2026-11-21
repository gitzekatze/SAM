### Tests now notice what the release mutation run found unchecked

The mutation run before the release (all code changed since the audit)
put 1,364 small faults into SAM; 171 went unnoticed. Most change only
wording, the window (tested by its own flows) or nothing at all. For the
rest, tests now notice:

- the sandbox check calling a sound relay that runs outside its own
  sandbox "held";
- a writable Documents folder that holds the real `~/.bashrc` (dotfiles
  linked into the home): the folder is shown, the start file stays
  read-only;
- a test's "skipped" or "not here" that goes unrecorded, or a skip that is
  allowed where CI must prove everything;
- secrets in a bug report written as `GITHUB_TOKEN_2=…`,
  `"password-hash": "…"`, with extra spaces or quotes, or `Bearer x;`, and
  a bug report that ends with a word like "password";
- a warning about missing protection layers or moved files printed when
  there is nothing to warn about;
- protected folders made in the home where the start does not show them;
- the hint to start without Chromium's own sandbox offered to any app
  other than an Electron app, or on a computer that does not block it; and
  SAM's reading of whether this computer blocks it is now compared with a
  real try;
- the graphics hint offered to an app that already has the graphics card;
- the "SAM moved it aside" message missing after a start that left a new
  start file in the home;
- a preset from a newer SAM moved aside like a damaged one;
- `sam-jail preset export` without a file;
- the IPv6 loopback check accepting `::1` on another device;
- tests that run inside another test no longer leave folders in /tmp.
