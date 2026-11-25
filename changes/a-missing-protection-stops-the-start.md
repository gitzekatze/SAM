### A start that lacks a protection its settings ask for stops first

- When SAM's helper `sam-jail-run` is missing (so Landlock and the syscall
  filter cannot be applied), or the desktop offers the Wayland security
  context but making one fails, SAM no longer starts the app with a warning
  only. It says which protection is missing and why, and you decide: the
  notification of a start from the menu or SAM's window has a *Start
  anyway* button, and the command line takes `sam-jail run --start-anyway`.
  Your choice applies to that one start.
- A start you chose to make anyway is still marked *Protection missing* on
  the app's page and in the overview, as before.
