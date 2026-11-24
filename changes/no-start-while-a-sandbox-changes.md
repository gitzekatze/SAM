### An app no longer starts while its sandbox is being changed

- Starting an app while SAM was unpacking it again, updating it, going
  back to the earlier version, freeing its space or removing it could
  start it on files that were being replaced or deleted. An app whose
  file had changed outside SAM could even start once with the new content
  before you had looked at it. A start is now refused at once while such
  a step runs, and says to start the app when that is done.
- The other way round, removing, unpacking again, updating, going back or
  freeing space while the app is starting (its checks and preparation)
  waits a moment and is then refused with a message, as it already was
  while the app runs.
