### Closing an app leaves a launch started meanwhile alone

- When you closed an app (Close, Close and Remove, `sam-jail stop`) and
  started it again before it had finished closing, SAM waited for the new
  start too, then said after about 28 seconds that the app could not be
  closed. SAM now waits only for the launches that ran when you closed it,
  and the new start keeps running.
- SAM now holds on to each launcher it closes by a handle on that very
  process, so its later signals can never reach another program that got
  the same process number meanwhile, nor a program whose launch has
  already ended.
