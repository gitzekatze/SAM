### A risky first-run hint is applied only after a yes

- `sam-jail hints APP --apply ID` applied any hint at once, also one that
  gives the app the network, the keyring or X11, while `sam-jail set`
  asks for `--yes` for the same change. Now a hint rated *Think twice* or
  *Dangerous*, or one that turns on compatibility mode, is refused
  without `--yes` (code `hint-needs-yes`). The message names the hint,
  what it turns on and what it adds. A harmless hint, such as Downloads,
  still applies at once.
- The same holds when such a hint is applied with `sam-jail repair APP
  --apply ID` or reached with `--next`: a repair step with the same id as
  a hint SAM offers for that app (for example `x11`) is the same change and
  needs `--yes` too. Other repair steps work as before.
- SAM's window asks before such a hint, as before, and then confirms it
  for the command line. If the hint's rating changed since the page was
  drawn, the window shows the page again so the next click asks.
- A hint or repair step is never rated below what applying it adds: the
  network next to a home or keyring the app already has is *Dangerous*
  together, and turning off the syscall filter is *Think twice*, so the
  window asks first.
