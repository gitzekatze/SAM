### A risky repair step is applied only after a yes

- `sam-jail repair APP --apply ID` and `sam-jail repair APP --next`
  applied any repair step at once, also one that turns off the syscall
  filter, turns on X11 or turns on compatibility mode, while `sam-jail
  set` and risky hints ask for `--yes` for the same change. Now a repair
  step rated *Think twice* or *Dangerous*, or one that turns on
  compatibility mode, is refused without `--yes` (code `step-needs-yes`).
  The message names the step, what it turns on or off and what it adds.
  A step rated Harmless or Some access, such as showing all of /usr,
  still applies at once.
- SAM judges the step on the app's current settings, by the highest of
  its own rating, its rating in the list SAM offers and what applying it
  adds, so a step handed in with a lower rating still needs the yes.
- SAM's window asks before a step its page rates *Think twice* or
  *Dangerous*, as before, and confirms repair steps for the command line.
