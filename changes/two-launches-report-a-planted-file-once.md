### A file one app plants is reported once when two apps watch the same place

- When two apps that may write the home ran at once and one of them put a
  start file in a place both watch, both of SAM's watches acted on it. One
  moved it aside; the other then reported it as deleted, or in capitals as
  a file it could not remove, although it sat in the first one's folder. A
  link of yours that the first watch had just put back could also be moved
  aside by the second and reported.
- SAM's launches now take turns to look at the home, and a place that is
  already empty when SAM moves it is not reported. A planted file is
  normally reported once, with the folder it went to.
- A look waits at most about a second for its turn, then looks anyway, so
  two looks can then overlap. A running app's watch therefore keeps moving
  files aside while another launcher is stopped in the middle of its look.
- A known limit: a start of an app that may write the home's start places,
  and SAM's look for a launcher that was killed, first wait to read the
  records of the running apps, and that wait has no time limit yet.
