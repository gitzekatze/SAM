### An app gets the bus name it asks for when nobody else uses it

- SAM learns the D-Bus name an app really asks for from the D-Bus filter's
  own record and allows it when nobody on this computer uses it: no program
  holds it, no installed app has it, it is no desktop protocol name, no
  service that starts on demand and no other SAM app's. If the app did not
  start without it, SAM starts it once more at once. The app's page shows
  the name, and names SAM did not allow with the reason. Before, SAM only
  guessed the name: four apps did not start, and many lost single instance,
  media keys or their tray icon.
- Media players get their own player's name with the media controls switch;
  the switch asked for a name that was always refused before.
- Repair steps never suggest a bus name from what the app printed: an app
  could name a terminal's.
- Every name an app may own is checked again at every start; one an
  installed app or another SAM app has is left out, with a warning.
- Tray icons that count from 0 work; services under another data folder or
  in the runtime folder count as services that start on demand.
