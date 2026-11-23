### Closing an app finishes its launch, and start files stay watched

- Closing an app (Close, `sam-jail stop`, logging out) asks only the app's
  own processes inside its sandbox to quit. Before, pasta was asked too:
  an app set to "This computer only" was ended at once, with no time to
  save, and SAM's sound relay lost its sound server.
- An app that ignores the request is still ended after 10 seconds, but
  SAM's launcher is no longer killed 3 seconds into its own wait: the last
  look at the start places, the record and the end of the log now happen.
- What SAM watches in a writable home is kept on disk while the app runs.
  A second launch started meanwhile takes over what the first one saw, so
  a link an app planted in a start place is never taken for yours and put
  back. When SAM's launcher was killed, the next look at the running apps
  still moves aside what the app left, and says so in its log.
