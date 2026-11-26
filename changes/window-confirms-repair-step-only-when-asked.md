### The window confirms a repair step for the command line only when it asked

- SAM's window passed `--yes` to `sam-jail repair --apply` for every
  repair step, also for one it had not asked about. Where SAM now rates a
  step higher than the page showed (the settings changed since the page
  was drawn), the step was applied unasked.
- Now the window passes `--yes` exactly when it asked first: a step rated
  *Think twice* or *Dangerous*, one that turns on compatibility mode, or
  one from the app's own output, as it already did for first-run hints.
  When the command line refuses a step for that reason, the window shows
  a short notice and draws the page again, so the next click asks first.
  Found by the independent review of PR #149.
