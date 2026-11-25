### A start that lacks a protection its settings ask for stops first

- When SAM's helper `sam-jail-run` is missing (so Landlock and the syscall
  filter cannot be applied), or the desktop offers the Wayland security
  context but making one fails, SAM no longer starts the app with a warning
  only. It says which protection is missing and why, and you decide: the
  notification of a start from the menu or SAM's window has a *Start
  anyway* button, a terminal program asks in its own window, and the
  command line takes `sam-jail run --start-anyway`. Your choice applies to
  that one start. SAM's window says the app was not started (not that it
  stopped with an error), and `sam-jail command` still shows the command.
- Notifications with a button (*Start anyway*, *Show the fix*) also appear
  where `notify-send` is too old for buttons, without the button.
- A start you chose to make anyway is still marked *Protection missing* on
  the app's page and in the overview, as before.
