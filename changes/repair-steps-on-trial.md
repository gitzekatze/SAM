### A repair step that did not help is undone by itself

- A repair step you turn on is tried at the next start: if the app then
  runs, the step stays; if it still fails, SAM puts back exactly what the
  step changed, says so, and does not offer it again (until *Switch off all
  repair steps*). Before, steps that did not help stayed: in the night run
  of 240 apps, an app had given up X11, all of /usr and nested namespaces
  for nothing. The app's page shows what the steps cost together.
- *Start without Chromium's own sandbox* is offered only where this
  computer keeps Chromium's sandbox from starting (AppArmor, or user
  namespaces switched off), and says what is lost: web pages are no longer
  kept apart from the rest of the app.
- Compatibility mode says that its whole session bus is a way out of the
  sandbox, is rated *Dangerous*, needs `--yes` on the command line, and is
  no longer suggested after every failed start. *Never offer compatibility
  mode* in Preferences keeps it out of the repair steps.
- The syscall filter is switched off for 32-bit apps only when the program
  the app starts is 32-bit itself; 32-bit files elsewhere in the package no
  longer switch it off.
