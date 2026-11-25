### The D-Bus filter's record is read to its end

- SAM reads the D-Bus filter's record (from which it learns the bus name
  an app asks to own) to its end also when a line is not valid text. Such
  a line, which an app could cause, stopped the reading before; the filter
  then ended at its next line and the app lost its session bus.
- A D-Bus filter that does not get ready in time is ended and cleaned up
  at once, instead of lingering until SAM ends.
