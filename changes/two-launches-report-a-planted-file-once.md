### A file one app plants is reported once when two apps watch the same place

- When two apps that may write the home ran at once and one of them put a
  start file in a place both watch, both of SAM's watches acted on it. One
  moved it aside; the other then reported it as deleted, or in capitals as
  a file it could not remove, although it sat in the first one's folder. A
  link of yours that the first watch had just put back could also be moved
  aside by the second and reported.
- SAM's launches now look at the home one at a time, and a place that is
  already empty when SAM moves it is not reported. A planted file is
  normally reported once, with the folder it went to.
- A launch waits at most about a second for another launch's look and then
  looks anyway, so a stopped launcher never stops the others from moving a
  file aside.
