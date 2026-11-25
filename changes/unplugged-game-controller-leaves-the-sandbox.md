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
- When SAM cannot take a node out, it ends the app and says why in the
  start record, rather than leave a node that could reach another device.
- A controller plugged in or reconnected while the app runs is still seen
  only after a restart, as before.
- Known limit: an app that kept a path-only handle to the node from before
  can still reach the next device with that number, as it could when run
  without SAM. The threat model says so.
