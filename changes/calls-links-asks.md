### Single D-Bus functions count, other programs' links ask, and the command line asks too

- Settings that let an app call single functions or hear signals of a
  service (`dbus.session.calls`, `dbus.session.broadcasts`) now count in the
  risk word, appear in the app's permissions and ask before a dangerous one
  is added: a function of systemd or the desktop shell is a way out, and a
  preset could add one without a question.
- A link to another program (`steam://`, `vscode://`) opened by an app asks
  first with the system's app chooser; web and mail links open as before.
  The security page says that links can carry data out, even with no
  network.
- `sam-jail repair APP --next` (or `--apply`) no longer applies a step
  suggested by what the app printed without `--yes`; the window already
  asked.
