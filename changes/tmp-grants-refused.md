### SAM gives no app new access to /tmp and offers a folder of its own

- In `/tmp`, programs outside the sandbox listen: terminal sessions, SSH
  connections and the X server. An app that sees `/tmp`, even read-only,
  could use them to run commands outside its sandbox. SAM now refuses a
  new grant of `/tmp` or of such a folder in it, also after a yes, for
  every change of an app's settings, for presets and when adding an app.
- Instead, SAM offers a folder of the app's own, `/tmp/sam-` followed by
  the app's id. SAM makes it at each start, for you only, and does not
  start the app when that folder is not one only you can open.
- An older grant of `/tmp` stays until you replace it. SAM warns about it,
  diagnostics name the app, and a hint on the app's page replaces it with
  the folder of the app's own.
- Not covered: the folder's name can be seen by every account on this
  computer, so it tells them which apps you use.
