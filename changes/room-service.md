### Room service: programs get their own sandbox from SAM

- Programs inside an app that build a Bubblewrap sandbox of their own, such
  as GTK's image loader (glycin, in 16 of 240 tested apps), now get it from
  SAM, built outside the app's sandbox: never with more than the app, never
  with less than they asked, always with SAM's Landlock and syscall filter,
  also where the app has them off. Before, they decoded pictures with no
  sandbox at all ("Glycin running without sandbox"), or the app crashed.
- No setting to change: Room service is on for every app.
  `advanced.room_service` turns it off for one app.
- The start record names each room and what was capped or refused.
