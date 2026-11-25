### An unplugged game controller leaves the running app

- With *Game controllers*, the app gets each controller's device node by
  name, such as `/dev/input/event7`. After the controller was unplugged,
  that node stayed in the sandbox, and Linux gives the next device the
  freed number: a keyboard plugged in later could be read through it,
  with the controller's access rights, although the app could not open
  that keyboard when run without SAM.
- Now SAM watches the controllers it gave the app while the app runs.
  When one is unplugged, or another device appears at its name, SAM takes
  its node out of the running sandbox at once. The app keeps running.
- SAM takes a node out only where Landlock is in place and the app cannot
  make namespaces of its own; otherwise a handle the app holds could still
  reach the next device, so an unplug ends the app instead, and the start
  record says why. The same holds when SAM cannot take a node out.
- A controller plugged in or reconnected while the app runs is still seen
  only after a restart, as before.
- Known limit: a new device would have to appear at the same number in
  the milliseconds between the unplug and the removal. The threat model
  says so.
