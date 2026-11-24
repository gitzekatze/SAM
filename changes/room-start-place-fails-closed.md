### Room service refuses rooms when a place of the app cannot be opened at the start

- When the app starts, Room service opens every place of the app once. A
  place that does not exist is left out, as Bubblewrap leaves it out of the
  app. Before, a place that exists but could not be opened was left out the
  same way. Bubblewrap itself stops the app on most such errors, but not
  when only SAM's launcher fails, for example because it has no descriptors
  left. If that place was a protection, for example a read-only file inside
  a writable home, a room could then get it writable while the app had it
  read-only. Now no room is built during that start, SAM shows the warning
  "Room service unavailable" when the app starts, and every refusal names
  the place.
