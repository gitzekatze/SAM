### A risky first-run hint is applied only after a yes

- `sam-jail hints APP --apply ID` applied any hint at once, also one that
  gives the app the network, the keyring or X11, while `sam-jail set`
  asks for `--yes` for the same change. Now a hint rated *Think twice* or
  *Dangerous*, or one that turns on compatibility mode, is refused
  without `--yes` (code `hint-needs-yes`). The message names the hint and
  what it turns on. A harmless hint, such as Downloads, still applies at
  once.
- SAM's window asks before such a hint, as before, and then confirms it
  for the command line.
- A hint is never rated below what applying it adds: the network next to
  a home or keyring the app already has is *Dangerous* together, so the
  hint says so.
