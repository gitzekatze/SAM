### SAM gives no app new access to /tmp and offers a folder of its own

- In `/tmp`, programs outside the sandbox listen: terminal sessions, SSH
  connections and the X server. An app that sees `/tmp`, even read-only,
  could use them to run commands outside its sandbox. SAM now refuses a
  new grant of `/tmp` or of such a known folder in it, also after a yes,
  for every change of an app's settings, for presets and when adding an
  app. A new extra folder must be written with its full path: one written
  relative names a different place at each start, so SAM refuses it too.
- Instead, SAM offers a folder of the app's own, `/tmp/sam-` followed by
  the app's id. SAM makes it at each start, for you only, and does not
  start the app when that folder is a link, belongs to another account or
  others can open it.
- An older grant of `/tmp` stays until you replace it. SAM warns about it,
  diagnostics name the app, and a hint on the app's page replaces it with
  the folder of the app's own.
- What this does not cover, such as other programs running as you and
  the folder's name, which every account can see, is listed on the
  security page under "SAM gives no app new access to /tmp".
