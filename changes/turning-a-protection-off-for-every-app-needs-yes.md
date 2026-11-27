### Turning a protection off for every app needs a yes on the command line too

- `sam-jail config set security.baseline_seccomp false` and the same for
  `security.experimental_landlock` turned the syscall filter or Landlock
  off for every sandboxed app at once, from one pasted line or a script,
  while SAM's window asks first. Now `config set` and `config put` refuse
  such a change without `--yes` (code `config-needs-yes`) and save
  nothing. The message names what goes off and what that exposes.
- Turning these protections on, and every other setting, needs no `--yes`.
- SAM's window asks before exactly these switches, by the same rule, and
  confirms the change for the command line only when it asked.
